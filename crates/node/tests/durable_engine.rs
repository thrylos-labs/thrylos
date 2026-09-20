//! `DurableEngine` against a real database on disk, and against a process
//! that is actually killed while it commits.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use chain_db::{Db, DbError};
use chain_engine_api::{
    Block, ChainView, Engine, ExecutedBlock, FinaliseErrorReason, MAX_BLOCK_SIZE_BYTES,
};
use chain_exec::genesis::{SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME, SYSTEM_PACKAGE_ADDRESS};
use chain_exec::genesis_config::GenesisConfig;
use chain_exec::native::{STAKE, STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS};
use chain_exec::{Executor, ExecutorError};
use chain_node::{DurableEngine, OpenError};
use chain_state::{StateDiff, StateKey, StateValue};
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, Hash, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

const CHAIN_ID: u64 = 1337;

fn config() -> GenesisConfig {
    chain_genesis::devnet::config().unwrap()
}

/// The devnet's funded accounts are seeds 101 to 104, its validators 1 to 4.
fn account(seed: u8) -> Address {
    Address::from_public_key(&chain_genesis::devnet::ed25519(seed).unwrap())
}

fn sign(seed: u8, sequence: u64, call: MoveCall) -> Transaction {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let body = TransactionBody {
        chain_id: ChainId(CHAIN_ID),
        sender: PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(5_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(10),
        declared_inputs: Vec::new(),
        call,
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
    }
}

fn add(seed: u8, sequence: u64, a: u64, b: u64) -> Transaction {
    sign(
        seed,
        sequence,
        MoveCall {
            module_address: Address::from_bytes(SYSTEM_PACKAGE_ADDRESS.into_bytes()),
            module_name: SYSTEM_MODULE_NAME.as_bytes().to_vec(),
            function_name: SYSTEM_FUNCTION_NAME.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![a.to_le_bytes().to_vec(), b.to_le_bytes().to_vec()],
        },
    )
}

/// Delegate `amount` from account `seed` to the devnet validator `validator`.
fn stake(seed: u8, sequence: u64, validator: u8, amount: u128) -> Transaction {
    sign(
        seed,
        sequence,
        MoveCall {
            module_address: Address::from_bytes(STAKING_PACKAGE_ADDRESS),
            module_name: STAKING_MODULE_NAME.as_bytes().to_vec(),
            function_name: STAKE.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![
                account(validator).as_bytes().to_vec(),
                amount.to_le_bytes().to_vec(),
            ],
        },
    )
}

/// Three blocks' transactions: calculator calls, and delegations, which
/// change validator and staking state as well as balances.
fn history() -> Vec<Vec<Transaction>> {
    vec![
        vec![add(101, 0, 2, 40), stake(102, 0, 1, 40_000)],
        vec![add(101, 1, 7, 8)],
        vec![stake(103, 0, 2, 5_000), add(101, 2, 1, 1)],
    ]
}

fn next_block<E: Engine + ChainView>(engine: &E, transactions: Vec<Transaction>) -> Block {
    let head = engine.head().unwrap();
    engine.propose_block(
        head.block_hash,
        head.state_root,
        BlockHeight(head.height.0 + 1),
        head.timestamp_ms + 1_000,
        transactions,
        engine.block_limits().unwrap(),
    )
}

fn commit<E: Engine + ChainView>(engine: &mut E, block: &Block) -> ExecutedBlock {
    let root = engine.head().unwrap().state_root;
    let executed = engine.execute_block(root, block).unwrap();
    engine.finalise_block(block, &executed).unwrap();
    executed
}

/// What a node reads of its chain: the head, the validators and the limits.
fn read<E: ChainView>(engine: &E) -> String {
    format!(
        "{:?} {:?} {:?}",
        engine.head().unwrap(),
        engine.validator_set().unwrap(),
        engine.block_limits().unwrap()
    )
}

fn open(dir: &std::path::Path) -> DurableEngine {
    DurableEngine::open(dir, &config()).unwrap()
}

/// The reason opening was refused. (`DurableEngine` is not `Debug`.)
fn refused(result: Result<DurableEngine, OpenError>) -> OpenError {
    result.err().expect("opening should have been refused")
}

// ---- starting and restarting ---------------------------------------------------

#[test]
fn a_new_directory_starts_from_genesis_and_reopening_finds_the_same_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (root, hash) = {
        let engine = open(dir.path());
        let head = engine.head().unwrap();
        assert_eq!(head.height, BlockHeight(0));
        assert_eq!(head.block_hash, config().hash(), "the first block's parent");
        assert_eq!(
            engine.database().genesis_hash().unwrap(),
            Some(config().hash())
        );
        (head.state_root, head.block_hash)
    };
    let engine = open(dir.path());
    let head = engine.head().unwrap();
    assert_eq!(head.state_root, root);
    assert_eq!(head.block_hash, hash);
    assert_eq!(head.height, BlockHeight(0));
    engine.executor().audit().unwrap();
}

#[test]
fn a_chain_is_the_same_after_a_restart_and_carries_on_identically() {
    let restarted_dir = tempfile::tempdir().unwrap();
    let steady_dir = tempfile::tempdir().unwrap();
    let mut restarted = open(restarted_dir.path());
    let mut steady = open(steady_dir.path());
    // The same chain with no database at all, to show that keeping it on
    // disk changes nothing about what it computes.
    let mut memory = Executor::from_genesis(&config()).unwrap();

    let blocks = history();
    let mut committed = Vec::new();
    for transactions in &blocks[..2] {
        let block = next_block(&steady, transactions.clone());
        commit(&mut steady, &block);
        commit(&mut restarted, &block);
        commit(&mut memory, &block);
        committed.push(block);
    }
    assert_eq!(read(&restarted), read(&steady));

    // Stop one of them and start it again from its directory.
    drop(restarted);
    let mut restarted = open(restarted_dir.path());
    assert_eq!(read(&restarted), read(&steady), "the chain came back whole");
    assert_eq!(read(&restarted), read(&memory));
    assert_eq!(
        restarted.executor().state_root(),
        steady.executor().state_root()
    );
    assert_eq!(restarted.executor().supply(), steady.executor().supply());
    restarted.executor().audit().unwrap();

    // The database holds what was committed.
    let db = restarted.database();
    assert_eq!(db.tip_height().unwrap(), Some(BlockHeight(2)));
    for block in &committed {
        assert_eq!(db.get_block(block.height).unwrap().as_ref(), Some(block));
    }

    // The next block, run by all three, gives the same result everywhere.
    let block = next_block(&steady, blocks[2].clone());
    let root = steady.head().unwrap().state_root;
    let by_steady = steady.execute_block(root, &block).unwrap();
    let by_restarted = restarted.execute_block(root, &block).unwrap();
    let by_memory = memory.execute_block(root, &block).unwrap();
    assert_eq!(by_restarted, by_steady);
    assert_eq!(by_memory, by_steady);
    steady.finalise_block(&block, &by_steady).unwrap();
    restarted.finalise_block(&block, &by_restarted).unwrap();
    memory.finalise_block(&block, &by_memory).unwrap();
    assert_eq!(read(&restarted), read(&steady));
    assert_eq!(read(&restarted), read(&memory));

    // And once more through a restart, now three blocks deep.
    drop(restarted);
    let restarted = open(restarted_dir.path());
    assert_eq!(read(&restarted), read(&steady));
    assert_eq!(
        restarted.database().tip_height().unwrap(),
        Some(BlockHeight(3))
    );
}

#[test]
fn a_block_is_final_in_the_database_before_the_engine_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = open(dir.path());
    for transactions in history() {
        let block = next_block(&engine, transactions);
        let executed = commit(&mut engine, &block);
        // As soon as finalise returned, a fresh reader finds all of it.
        let db = engine.database();
        assert_eq!(db.tip_height().unwrap(), Some(block.height));
        assert_eq!(
            db.get_root(block.height).unwrap(),
            Some(executed.state_root.as_hash())
        );
        assert_eq!(db.get_block(block.height).unwrap().as_ref(), Some(&block));
        assert_eq!(
            db.load_state().unwrap(),
            engine
                .executor()
                .state_entries()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>(),
            "the stored state is exactly the executor's"
        );
    }
}

// ---- a database that does not belong to this genesis -------------------------

#[test]
fn a_database_made_from_another_genesis_is_refused_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(dir.path()));

    let devnet = config();
    let other = GenesisConfig::new(
        ChainId(CHAIN_ID + 1),
        devnet.genesis_time_ms(),
        *devnet.parameters(),
        devnet.allocations().to_vec(),
        devnet.validators().to_vec(),
    )
    .unwrap();
    assert_ne!(other.hash(), devnet.hash());

    let error = refused(DurableEngine::open(dir.path(), &other));
    assert!(
        matches!(
            error,
            OpenError::WrongGenesis { stored, given }
                if stored == devnet.hash() && given == other.hash()
        ),
        "{error}"
    );
    assert!(error.to_string().contains("different chain"), "{error}");

    // The refusal changed nothing: the right genesis still opens it.
    open(dir.path()).executor().audit().unwrap();
}

// ---- a database that refuses a commit ----------------------------------------------

#[test]
fn a_finalisation_the_database_refuses_leaves_the_chain_where_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = open(dir.path());
    let blocks = history();
    let first = next_block(&engine, blocks[0].clone());
    commit(&mut engine, &first);
    let head_before = read(&engine);
    let state_before = engine.executor().state_root();

    // Put the database out of step with the engine, behind its back: block 2
    // is already there, so the engine's own block 2 cannot be committed.
    let intruder = Block {
        parent_block_hash: first.hash(),
        height: BlockHeight(2),
        timestamp_millis: first.timestamp_millis + 1,
        transactions: Vec::new(),
    };
    engine
        .database()
        .commit_block(&intruder, Hash::from_bytes([9; 32]), &StateDiff::empty())
        .unwrap();

    let second = next_block(&engine, blocks[1].clone());
    let root = engine.head().unwrap().state_root;
    let executed = engine.execute_block(root, &second).unwrap();
    let error = engine.finalise_block(&second, &executed).unwrap_err();
    assert_eq!(error.reason, FinaliseErrorReason::StorageUnavailable);

    // The in-memory chain did not move, and the reason is on record.
    assert_eq!(read(&engine), head_before);
    assert_eq!(engine.executor().state_root(), state_before);
    assert!(matches!(
        engine.last_storage_error(),
        Some(DbError::NonSequentialCommit { .. })
    ));

    // Restarting does not paper over it: the database now claims a block
    // that its state does not reflect.
    drop(engine);
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(matches!(error, OpenError::Executor(_)), "{error}");
}

// ---- a database that does not add up -----------------------------------------------

/// The genesis state, and its root, as a node would have recorded them.
fn genesis_state() -> (BTreeMap<StateKey, StateValue>, Hash) {
    let executor = Executor::from_genesis(&config()).unwrap();
    let state = executor
        .state_entries()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    (state, executor.state_root().as_hash())
}

fn prepare(dir: &std::path::Path) -> Db {
    Db::open(&dir.join("chain")).unwrap()
}

#[test]
fn blocks_with_no_record_of_a_genesis_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    {
        let db = prepare(dir.path());
        let block = Block {
            parent_block_hash: Hash::from_bytes([1; 32]),
            height: BlockHeight(1),
            timestamp_millis: 5,
            transactions: Vec::new(),
        };
        db.commit_block(&block, Hash::from_bytes([2; 32]), &StateDiff::empty())
            .unwrap();
    }
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(matches!(error, OpenError::Damaged(_)), "{error}");
    assert!(
        error.to_string().contains("no record of the genesis"),
        "{error}"
    );
}

#[test]
fn a_state_that_does_not_hash_to_its_recorded_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (state, _) = genesis_state();
        prepare(dir.path())
            .initialise(config().hash(), Hash::from_bytes([9; 32]), &state)
            .unwrap();
    }
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(
        matches!(error, OpenError::Executor(ExecutorError::Restore(_))),
        "{error}"
    );
    assert!(error.to_string().contains("recorded root"), "{error}");
}

#[test]
fn a_tip_block_the_state_does_not_reflect_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    {
        let (state, root) = genesis_state();
        let db = prepare(dir.path());
        db.initialise(config().hash(), root, &state).unwrap();
        // A block 1 whose recorded root is right (nothing changed) but whose
        // effects the state never received: the state's head is still 0.
        let block = Block {
            parent_block_hash: config().hash(),
            height: BlockHeight(1),
            timestamp_millis: config().genesis_time_ms() + 1_000,
            transactions: Vec::new(),
        };
        db.commit_block(&block, root, &StateDiff::empty()).unwrap();
    }
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(matches!(error, OpenError::Damaged(_)), "{error}");
    assert!(error.to_string().contains("head is not the tip"), "{error}");
}

#[test]
fn a_tip_block_recorded_at_another_time_than_the_state_says_is_refused() {
    // A real block 1 and its real effects...
    let real_dir = tempfile::tempdir().unwrap();
    let mut engine = open(real_dir.path());
    let block = next_block(&engine, vec![add(101, 0, 1, 2)]);
    let executed = commit(&mut engine, &block);

    // ...in a database that recorded the block at a different time.
    let dir = tempfile::tempdir().unwrap();
    {
        let (state, root) = genesis_state();
        let db = prepare(dir.path());
        db.initialise(config().hash(), root, &state).unwrap();
        let mut disguised = block.clone();
        disguised.timestamp_millis += 1;
        db.commit_block(
            &disguised,
            executed.state_root.as_hash(),
            &executed.state_diff,
        )
        .unwrap();
    }
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(matches!(error, OpenError::Damaged(_)), "{error}");
    assert!(error.to_string().contains("head time"), "{error}");
}

#[test]
fn a_state_that_hashes_correctly_but_is_out_of_balance_is_refused_by_the_audit() {
    let dir = tempfile::tempdir().unwrap();
    {
        let executor = Executor::from_genesis(&config()).unwrap();
        let mut state: BTreeMap<_, _> = executor
            .state_entries()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        // Value from nowhere, with the root recomputed so it is consistent.
        let owner = account(101);
        let mut balance = executor.read_account(owner).unwrap();
        balance.balance += 1;
        chain_state::account::write_account(&mut state, owner, balance);
        let root = chain_state::compute_root(&state).as_hash();
        prepare(dir.path())
            .initialise(config().hash(), root, &state)
            .unwrap();
    }
    let error = refused(DurableEngine::open(dir.path(), &config()));
    assert!(
        matches!(error, OpenError::Executor(ExecutorError::Audit(_))),
        "{error}"
    );
}

// ---- a process killed while it commits ---------------------------------------------

/// Parses `COMMITTED 12` (or `OPENED 12`) into 12.
fn height_in(line: &str) -> u64 {
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn a_node_killed_while_committing_restarts_at_a_block_boundary_every_time() {
    let dir = tempfile::tempdir().unwrap();
    // The highest height known to be committed. What a killed process leaves
    // is that height, or the next one if a commit landed just before the
    // kill and before its line was printed.
    let mut known = 0u64;

    // Each round starts a fresh process on the same directory (so every
    // start after the first is a restore from what the last kill left),
    // lets it commit a different number of blocks, and kills it.
    for blocks_to_wait_for in [1usize, 2, 3, 5, 8, 13, 4, 21, 2, 9] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_durable_engine_crash_helper"))
            .arg(dir.path())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn the helper");
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

        let opened = height_in(&lines.next().unwrap().unwrap());
        assert!(
            opened == known || opened == known + 1,
            "restored at {opened}, after a kill that had seen {known} committed"
        );
        let mut last = opened;
        for _ in 0..blocks_to_wait_for {
            last = height_in(&lines.next().unwrap().unwrap());
        }
        child.kill().expect("SIGKILL the helper");
        child.wait().expect("wait for it");
        // Whatever it managed to print before it died.
        for line in lines.map_while(Result::ok) {
            if line.starts_with("COMMITTED") {
                last = height_in(&line);
            }
        }
        assert!(last > known || blocks_to_wait_for == 0, "no progress");
        known = last;
    }

    // What is left opens, is whole, and can go on.
    let mut engine = open(dir.path());
    let height = engine.head().unwrap().height.0;
    assert!(
        height == known || height == known + 1,
        "{height} vs {known}"
    );
    engine.executor().audit().unwrap();
    assert_eq!(
        engine.database().tip_height().unwrap(),
        Some(BlockHeight(height))
    );
    let block = next_block(&engine, Vec::new());
    commit(&mut engine, &block);
    assert_eq!(engine.head().unwrap().height.0, height + 1);
    assert!(
        block.encoded_len().unwrap() < usize::try_from(MAX_BLOCK_SIZE_BYTES).unwrap(),
        "an empty block is small"
    );
}
