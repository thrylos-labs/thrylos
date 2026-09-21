//! How the host judges a block it has been given, one condition at a time.
//!
//! The end-to-end behaviour is in `tests/network.rs`; these pin down the
//! checks the host makes *itself*. The real executor happens to make several
//! of them too (height, parent, timestamp order), so the engine here is a
//! stub that accepts any block: `Engine::execute_block` is documented not to
//! check the parent, and the host must not lean on whichever implementation
//! sits behind it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use crate::types::{ConsensusAddress, ConsensusHeight};
use blst::min_pk::SecretKey;
use chain_engine_api::{
    Block, BlockLimits, BlockRejected, ChainView, ChainViewError, Engine, ExecutedBlock,
    FinaliseError, Head, ValidatorInfo,
};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_signer::{InMemoryStore, Signer};
use chain_state::{StateDiff, StateRoot};
use chain_types::beacon::beacon_message;
use chain_types::beacon::genesis_seed;
use chain_types::bls::DST_BEACON;
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{Address, BlockHeight, BlsPublicKey, ChainId, Hash, PublicKey};
use ed25519_dalek::SigningKey;
use malachite_core_types::CommitCertificate;
use malachite_core_types::Validity;

use super::*;

const GENESIS_TIME: u64 = 1_700_000_000_000;

/// A real chain that, for a block its own rules would refuse, pretends it
/// executed.
struct Lenient(Executor);

impl ChainView for Lenient {
    fn chain_id(&self) -> chain_types::ChainId {
        ChainView::chain_id(&self.0)
    }

    fn head(&self) -> Result<Head, ChainViewError> {
        ChainView::head(&self.0)
    }
    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError> {
        ChainView::validator_set(&self.0)
    }
    fn block_limits(&self) -> Result<BlockLimits, ChainViewError> {
        ChainView::block_limits(&self.0)
    }
}

impl Engine for Lenient {
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block {
        self.0.propose_block(
            parent_block_hash,
            parent_state_root,
            height,
            timestamp_millis,
            candidate_transactions,
            limits,
        )
    }
    fn execute_block(
        &self,
        parent_state_root: StateRoot,
        block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected> {
        // The real thing where it will do, and a made-up result where it
        // would refuse — so that only the host's own checks can stop a block.
        self.0.execute_block(parent_state_root, block).or_else(|_| {
            Ok(ExecutedBlock {
                state_root: parent_state_root,
                gas_used: 0,
                state_diff: StateDiff::default(),
                outcomes: Vec::new(),
            })
        })
    }
    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        self.0.finalise_block(block, executed)
    }
}

type HostWith<D> =
    Host<Lenient, NoTransactions, FixedClock, Signer<InMemoryStore>, MemorySignedLog, D>;

type TestHost = HostWith<MemoryStorage>;

fn hash_of(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn secret_for(n: u8) -> SecretKey {
    SecretKey::key_gen(&[n; 32], &[]).unwrap()
}

/// The host's own key: validator 1's.
fn secret() -> SecretKey {
    secret_for(1)
}

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

struct NoTransactions;

impl TransactionSource for NoTransactions {
    fn candidates(&mut self, _max: usize) -> Vec<Transaction> {
        Vec::new()
    }
    fn committed(&mut self, _block: &Block) {}
}

fn operator(seed: u8) -> PublicKey {
    let key = SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap()
}

/// Two validators, 1 and 2.
fn genesis() -> GenesisConfig {
    genesis_with(&[1, 2])
}

/// A genesis whose validators are the ones numbered in `numbers`.
fn genesis_with(numbers: &[u8]) -> GenesisConfig {
    let validator = |n: u8| {
        let secret = secret_for(n);
        let key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes()).unwrap();
        GenesisValidator {
            operator: operator(n),
            consensus_key: key,
            proof_of_possession: BlsSignature::from_bytes(
                secret
                    .sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
                    .to_bytes(),
            )
            .unwrap(),
            self_stake: GENESIS_PARAM_VALUES.min_self_stake,
        }
    };
    GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![Allocation {
            owner: operator(50),
            amount: 1_000,
        }],
        numbers.iter().map(|n| validator(*n)).collect(),
    )
    .unwrap()
}

/// A host for validator `n`, on `chain`, keeping what it keeps in `storage`.
fn host_on<D: Storage>(
    n: u8,
    now: u64,
    chain: Lenient,
    storage: D,
) -> Result<HostWith<D>, HaltReason> {
    Host::new(
        // No pace: these tests are about what a host does with a height, and
        // step it by hand. The pace has tests of its own.
        HostConfig {
            min_block_interval_ms: 0,
            ..HostConfig::default()
        },
        Address::from_public_key(&operator(n)),
        chain,
        Ports {
            source: NoTransactions,
            clock: FixedClock(now),
            signer: Signer::load(secret_for(n), InMemoryStore::new()).unwrap(),
            log: MemorySignedLog::new(),
            storage,
        },
        genesis_seed(&genesis().hash()),
    )
}

/// A chain with two validators and a host that is the first. Two, so that
/// the host cannot decide anything on its own.
fn host(now: u64) -> TestHost {
    host_on(
        1,
        now,
        Lenient(Executor::from_genesis(&genesis()).unwrap()),
        MemoryStorage::new(),
    )
    .unwrap()
}

/// The verdict on `block` once it is one the host holds.
fn judged(host: &mut TestHost, block: Block) -> Validity {
    let id = block.hash();
    host.env.blocks.insert(id, block);
    host.env.judge(id).unwrap().validity
}

/// An empty block that is right in every respect for a host at `head`.
fn good_block(head: &chain_engine_api::Head) -> Block {
    Block {
        parent_block_hash: head.block_hash,
        height: BlockHeight(head.height.0 + 1),
        timestamp_millis: head.timestamp_ms + 1,
        transactions: Vec::new(),
    }
}

#[test]
fn a_block_that_is_right_in_every_respect_is_valid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    assert_eq!(judged(&mut host, good_block(&head)), Validity::Valid);
}

#[test]
fn a_block_that_does_not_extend_our_chain_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    let mut block = good_block(&head);
    block.parent_block_hash = Hash::from_bytes([9; 32]);
    assert_eq!(judged(&mut host, block), Validity::Invalid);
}

#[test]
fn a_block_for_another_height_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    for height in [head.height.0, head.height.0 + 2] {
        let mut block = good_block(&head);
        block.height = BlockHeight(height);
        assert_eq!(
            judged(&mut host, block),
            Validity::Invalid,
            "height {height}"
        );
    }
}

#[test]
fn a_block_no_later_than_its_parent_is_invalid() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    for timestamp in [head.timestamp_ms, head.timestamp_ms - 1] {
        let mut block = good_block(&head);
        block.timestamp_millis = timestamp;
        assert_eq!(
            judged(&mut host, block),
            Validity::Invalid,
            "timestamp {timestamp}"
        );
    }
}

#[test]
fn a_block_from_beyond_the_clock_tolerance_is_invalid() {
    // The clock reads `GENESIS_TIME`; the tolerance is five seconds.
    let mut host = host(GENESIS_TIME);
    let head = host.env.exec.head().unwrap();
    for (offset, expected) in [(5_000, Validity::Valid), (5_001, Validity::Invalid)] {
        let mut block = good_block(&head);
        block.timestamp_millis = GENESIS_TIME + offset;
        assert_eq!(judged(&mut host, block), expected, "offset {offset}");
    }
}

#[test]
fn a_block_the_host_was_never_given_is_invalid() {
    let host = host(GENESIS_TIME + 1);
    let verdict = host.env.judge(Hash::from_bytes([1; 32])).unwrap();
    assert_eq!(verdict.validity, Validity::Invalid);
}

// ---- the pace ------------------------------------------------------------------

/// A clock a test moves.
struct SharedClock(std::rc::Rc<std::cell::Cell<u64>>);

impl Clock for SharedClock {
    fn now_ms(&self) -> u64 {
        self.0.get()
    }
}

/// A validator on a chain that has only it: nothing to wait for, so with no
/// pace it would decide every height inside one call.
fn alone(
    pace_ms: u64,
    time: &std::rc::Rc<std::cell::Cell<u64>>,
) -> Host<Lenient, NoTransactions, SharedClock, Signer<InMemoryStore>, MemorySignedLog, MemoryStorage>
{
    let genesis = genesis_with(&[1]);
    Host::new(
        HostConfig {
            min_block_interval_ms: pace_ms,
            ..HostConfig::default()
        },
        Address::from_public_key(&operator(1)),
        Lenient(Executor::from_genesis(&genesis).unwrap()),
        Ports {
            source: NoTransactions,
            clock: SharedClock(time.clone()),
            signer: Signer::load(secret_for(1), InMemoryStore::new()).unwrap(),
            log: MemorySignedLog::new(),
            storage: MemoryStorage::new(),
        },
        genesis_seed(&genesis.hash()),
    )
    .unwrap()
}

fn head_height<C: Clock>(
    host: &Host<Lenient, NoTransactions, C, Signer<InMemoryStore>, MemorySignedLog, MemoryStorage>,
) -> u64 {
    host.chain().head().unwrap().height.0
}

#[test]
fn a_validator_with_no_one_to_wait_for_commits_one_block_a_pace_and_hands_control_back() {
    let time = std::rc::Rc::new(std::cell::Cell::new(GENESIS_TIME + 1));
    let mut host = alone(1_000, &time);
    host.start();

    // It decided the first height on its own, and then stopped, saying when
    // it will go on: without the pace it would not have come back at all.
    assert_eq!(head_height(&host), 1);
    assert_eq!(host.take_outbox().committed.len(), 1);
    let mut due = time.get() + 1_000;
    assert_eq!(host.next_wake_ms(), Some(due));

    // Asked again before the time, it does nothing, however often.
    for _ in 0..3 {
        time.set(due - 1);
        host.tick();
    }
    assert_eq!(head_height(&host), 1);

    // Each time the pace has passed it commits exactly one more block.
    for expected in 2..=6 {
        time.set(due);
        host.tick();
        assert_eq!(head_height(&host), expected);
        assert_eq!(host.take_outbox().committed.len(), 1);
        due = time.get() + 1_000;
        assert_eq!(host.next_wake_ms(), Some(due));
    }
    // And the blocks are that far apart, on the chain's own clock.
    let head = host.chain().head().unwrap();
    assert_eq!(head.timestamp_ms, GENESIS_TIME + 1 + 5_000);
}

#[test]
fn a_host_waiting_out_the_pace_and_behind_wakes_for_whichever_comes_first() {
    let time = std::rc::Rc::new(std::cell::Cell::new(GENESIS_TIME + 1));
    let mut host = alone(1_000, &time);
    host.start();
    let start = time.get() + 1_000;
    assert_eq!(host.next_wake_ms(), Some(start));

    // Seen a peer past this height long enough ago that asking for what was
    // missed comes due before the next height starts ...
    host.env.lag.ahead.insert(Address::from_bytes([9; 32]), 99);
    host.env.lag.since_ms = Some(time.get() - 5_000);
    let asking = time.get() - 5_000 + host.env.config.sync_grace_ms;
    assert!(asking < start);
    assert_eq!(host.next_wake_ms(), Some(asking));

    // ... and, seen only just now, after it.
    host.env.lag.since_ms = Some(time.get() + 5_000);
    assert!(time.get() + 5_000 + host.env.config.sync_grace_ms > start);
    assert_eq!(host.next_wake_ms(), Some(start));
}

#[test]
fn the_pace_is_the_setting_and_a_different_one_gives_a_different_gap() {
    for pace in [250, 3_000] {
        let time = std::rc::Rc::new(std::cell::Cell::new(GENESIS_TIME + 1));
        let mut host = alone(pace, &time);
        host.start();
        assert_eq!(host.next_wake_ms(), Some(time.get() + pace));
        time.set(time.get() + pace - 1);
        host.tick();
        assert_eq!(head_height(&host), 1, "not yet, at {pace}");
        time.set(time.get() + 1);
        host.tick();
        assert_eq!(head_height(&host), 2, "then, at {pace}");
    }
}

// ---- blocks that arrive ------------------------------------------------------

/// A block message from the one validator, with a reveal that checks out for
/// `height` and the host's current seed. `variant` makes distinct blocks.
fn genuine<D: Storage>(host: &HostWith<D>, height: u64, variant: u64) -> ProposedBlock {
    let head = host.env.exec.head().unwrap();
    ProposedBlock {
        proposer: Address::from_public_key(&operator(1)),
        block: Block {
            parent_block_hash: head.block_hash,
            height: BlockHeight(height),
            timestamp_millis: head.timestamp_ms + 1 + variant,
            transactions: Vec::new(),
        },
        reveal: BlsSignature::from_bytes(
            secret()
                .sign(
                    &beacon_message(BlockHeight(height), host.seed()),
                    DST_BEACON,
                    &[],
                )
                .to_bytes(),
        )
        .unwrap(),
    }
}

#[test]
fn a_block_with_a_genuine_reveal_is_kept_and_one_with_a_forged_reveal_is_not() {
    let mut host = host(GENESIS_TIME + 1);
    let mut forged = genuine(&host, 1, 0);
    forged.reveal =
        BlsSignature::from_bytes(secret().sign(b"not a reveal", DST_BEACON, &[]).to_bytes())
            .unwrap();
    host.handle_message(Message::Block(forged));
    assert!(host.env.blocks.is_empty());
    assert!(host.env.reveals.is_empty());

    host.handle_message(Message::Block(genuine(&host, 1, 0)));
    assert_eq!(host.env.blocks.len(), 1);
    assert_eq!(host.env.reveals.len(), 1);
}

#[test]
fn a_block_from_someone_who_is_not_a_validator_is_dropped() {
    let mut host = host(GENESIS_TIME + 1);
    let mut stranger = genuine(&host, 1, 0);
    stranger.proposer = Address::from_public_key(&operator(7));
    host.handle_message(Message::Block(stranger));
    assert!(host.env.blocks.is_empty());
}

#[test]
fn blocks_held_for_the_height_are_capped() {
    let mut host = host(GENESIS_TIME + 1);
    let cap = host.env.config.max_pending_per_height;
    for variant in 0..u64::try_from(cap + 10).unwrap() {
        host.handle_message(Message::Block(genuine(&host, 1, variant)));
    }
    assert_eq!(host.env.blocks.len(), cap);
}

#[test]
fn blocks_for_later_heights_are_held_up_to_a_cap_and_a_window() {
    let mut host = host(GENESIS_TIME + 1);
    let cap = host.env.config.max_pending_per_height;
    let window = host.env.config.max_future_heights;
    for variant in 0..u64::try_from(cap + 10).unwrap() {
        host.handle_message(Message::Block(genuine(&host, 2, variant)));
    }
    assert_eq!(host.env.future_blocks[&2].len(), cap);

    // Inside the window, kept; beyond it, and behind the chain, dropped.
    host.handle_message(Message::Block(genuine(&host, 1 + window, 0)));
    assert!(host.env.future_blocks.contains_key(&(1 + window)));
    host.handle_message(Message::Block(genuine(&host, 2 + window, 0)));
    assert!(!host.env.future_blocks.contains_key(&(2 + window)));
    host.handle_message(Message::Block(genuine(&host, 0, 0)));
    assert!(!host.env.future_blocks.contains_key(&0));
    assert!(host.env.blocks.is_empty());
}

// ---- adopting what a peer says was decided ---------------------------------------

/// `block` with the proof this network would give it: both validators'
/// precommits as the certificate, and the reveal of whichever the draw picks
/// as the proposer of round 0.
fn certified<D: Storage>(host: &HostWith<D>, block: &Block) -> CommitRecord {
    use crate::types::ConsensusVote;
    use malachite_core_types::{CommitSignature, NilOrVal, VoteType};

    let id = block.hash();
    let address = |n: u8| ConsensusAddress(Address::from_public_key(&operator(n)));
    let commit_signatures = [1u8, 2]
        .map(|n| {
            let vote = ConsensusVote {
                height: ConsensusHeight(block.height),
                round: Round::new(0),
                value_id: NilOrVal::Val(id),
                vote_type: VoteType::Precommit,
                validator_address: address(n),
                extension: None,
            };
            CommitSignature {
                address: address(n),
                signature: BlsSignature::from_bytes(
                    secret_for(n)
                        .sign(&encoded(&vote), chain_types::bls::DST_VOTE, &[])
                        .to_bytes(),
                )
                .unwrap(),
            }
        })
        .to_vec();
    let proposer = host
        .env
        .ctx
        .select_proposer(
            &host.env.validators,
            ConsensusHeight(block.height),
            Round::new(0),
        )
        .address;
    let proposer = [1u8, 2]
        .into_iter()
        .find(|n| address(*n) == proposer)
        .unwrap();
    CommitRecord {
        block: block.clone(),
        certificate: CommitCertificate {
            height: ConsensusHeight(block.height),
            round: Round::new(0),
            value_id: id,
            commit_signatures,
        },
        reveal: BlsSignature::from_bytes(
            secret_for(proposer)
                .sign(&beacon_message(block.height, host.seed()), DST_BEACON, &[])
                .to_bytes(),
        )
        .unwrap(),
    }
}

fn adopting<D: Storage>(host: &mut HostWith<D>, record: CommitRecord) {
    let requester = Address::from_public_key(&operator(1));
    host.handle_message(Message::SyncResponse(SyncResponse {
        requester,
        commits: vec![record],
    }));
}

#[test]
fn a_certified_block_that_extends_the_chain_is_adopted() {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    let record = certified(&host, &good_block(&head));
    adopting(&mut host, record);
    assert!(host.halted().is_none());
    assert_eq!(host.chain().head().unwrap().height, BlockHeight(1));
}

#[test]
fn a_certified_block_that_does_not_extend_the_chain_halts_the_node() {
    // The network decided it and it is not a child of this node's head: the
    // node is on another chain and must stop, not skip the block.
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    let mut block = good_block(&head);
    block.parent_block_hash = Hash::from_bytes([9; 32]);
    let record = certified(&host, &block);
    adopting(&mut host, record);
    assert_eq!(
        host.halted(),
        Some(&HaltReason::CannotCommit {
            height: BlockHeight(1)
        })
    );
    assert_eq!(host.chain().head().unwrap().height, BlockHeight(0));
}

// ---- the write-ahead log and the commit log -----------------------------------

/// Storage that can be made to fail, or to return rubbish.
#[derive(Default)]
struct Flaky {
    inner: MemoryStorage,
    fail_append: bool,
    fail_flush: bool,
    fail_start: bool,
    fail_record: bool,
    rubbish: bool,
}

impl CommitLog for Flaky {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) -> Result<(), StorageError> {
        if self.fail_record {
            return Err(StorageError("disk full".into()));
        }
        self.inner.record(record, seed_after)
    }
    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        self.inner.range(from, max)
    }
    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.inner.seed_after(height)
    }
}

impl Wal for Flaky {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), StorageError> {
        if self.fail_append {
            return Err(StorageError("disk full".into()));
        }
        self.inner.append(height, entry)
    }
    fn flush(&mut self) -> Result<(), StorageError> {
        if self.fail_flush {
            return Err(StorageError("fsync failed".into()));
        }
        self.inner.flush()
    }
    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, StorageError> {
        if self.fail_start {
            return Err(StorageError("cannot read".into()));
        }
        if self.rubbish {
            return Ok(vec![vec![0xEE, 1, 2, 3]]);
        }
        self.inner.start_height(height)
    }
}

fn flaky(storage: Flaky) -> HostWith<Flaky> {
    host_on(
        1,
        GENESIS_TIME + 1,
        Lenient(Executor::from_genesis(&genesis()).unwrap()),
        storage,
    )
    .unwrap()
}

fn wal_failed<D: Storage>(host: &HostWith<D>) -> bool {
    matches!(host.halted(), Some(HaltReason::StorageFailed(_)))
}

#[test]
fn a_host_that_cannot_write_its_log_halts() {
    let mut host = flaky(Flaky {
        fail_append: true,
        ..Flaky::default()
    });
    host.start();
    host.handle_message(Message::Block(genuine(&host, 1, 0)));
    assert!(wal_failed(&host), "{:?}", host.halted());
}

#[test]
fn a_host_that_cannot_flush_its_log_lets_nothing_out() {
    // The validator the draw picks to propose at round 0, which has a block
    // and a proposal to send the moment it starts.
    let probe = host(GENESIS_TIME + 1);
    let picked = probe
        .env
        .ctx
        .select_proposer(
            &probe.env.validators,
            ConsensusHeight(BlockHeight(1)),
            Round::new(0),
        )
        .address;
    let n = [1u8, 2]
        .into_iter()
        .find(|n| Address::from_public_key(&operator(*n)) == picked.0)
        .unwrap();
    let start = |fail_flush| {
        let mut host = host_on(
            n,
            GENESIS_TIME + 1,
            Lenient(Executor::from_genesis(&genesis()).unwrap()),
            Flaky {
                fail_flush,
                ..Flaky::default()
            },
        )
        .unwrap();
        host.start();
        host
    };

    let mut fine = start(false);
    assert!(fine.halted().is_none());
    assert!(
        !fine.take_outbox().messages.is_empty(),
        "it has a block to send"
    );

    let mut failing = start(true);
    assert!(wal_failed(&failing));
    assert!(failing.take_outbox().messages.is_empty());
}

#[test]
fn a_log_entry_that_cannot_be_read_halts_the_host_at_start() {
    let mut host = flaky(Flaky {
        rubbish: true,
        ..Flaky::default()
    });
    host.start();
    assert!(wal_failed(&host));
}

#[test]
fn a_log_that_cannot_be_opened_halts_the_host_at_start() {
    let mut host = flaky(Flaky {
        fail_start: true,
        ..Flaky::default()
    });
    host.start();
    assert!(wal_failed(&host));
}

#[test]
fn a_log_that_fails_when_a_new_height_begins_halts_the_host() {
    let mut host = flaky(Flaky {
        fail_start: true,
        ..Flaky::default()
    });
    let head = host.env.exec.head().unwrap();
    let record = certified(&host, &good_block(&head));
    adopting(&mut host, record);
    assert!(wal_failed(&host));
}

#[test]
fn what_peers_can_make_the_log_hold_is_capped_but_what_the_host_holds_is_not() {
    let mut host = host(GENESIS_TIME + 1);
    host.env.config.max_wal_entries = 2;
    for variant in 0..5 {
        host.handle_message(Message::Block(genuine(&host, 1, variant)));
    }
    assert_eq!(host.env.storage.wal.len(), 2);
    assert_eq!(host.env.blocks.len(), 5);
}

/// A host that has committed block 1: the chain, what it kept, and the seed
/// it was then running on.
fn one_block_on() -> (Lenient, MemoryStorage, Hash) {
    let mut host = host(GENESIS_TIME + 1);
    let head = host.env.exec.head().unwrap();
    let record = certified(&host, &good_block(&head));
    adopting(&mut host, record);
    assert_eq!(host.chain().head().unwrap().height, BlockHeight(1));
    let seed = *host.seed();
    (host.env.exec, host.env.storage, seed)
}

#[test]
fn a_restarted_host_finds_its_seed_in_the_commit_log() {
    let (chain, storage, seed) = one_block_on();
    let host = host_on(1, GENESIS_TIME + 1, chain, storage).unwrap();
    assert_eq!(host.height(), BlockHeight(2));
    assert_eq!(host.seed(), &seed);
    assert_ne!(host.seed(), &genesis_seed(&genesis().hash()));
}

#[test]
fn a_host_past_genesis_with_no_record_of_the_seed_will_not_start() {
    let (chain, _, _) = one_block_on();
    let result = host_on(1, GENESIS_TIME + 1, chain, MemoryStorage::new());
    assert!(matches!(result, Err(HaltReason::SeedUnknown)));
}

// ---- certificates are logged too ------------------------------------------------

/// `n`'s signature on a vote of `vote_type` for `value` at `round` of
/// height 1.
fn vote_signature(
    n: u8,
    vote_type: malachite_core_types::VoteType,
    round: u32,
    value: malachite_core_types::NilOrVal<Hash>,
) -> (ConsensusAddress, BlsSignature) {
    let address = ConsensusAddress(Address::from_public_key(&operator(n)));
    let vote = crate::types::ConsensusVote {
        height: ConsensusHeight(BlockHeight(1)),
        round: Round::new(round),
        value_id: value,
        vote_type,
        validator_address: address,
        extension: None,
    };
    let signature = BlsSignature::from_bytes(
        secret_for(n)
            .sign(&encoded(&vote), chain_types::bls::DST_VOTE, &[])
            .to_bytes(),
    )
    .unwrap();
    (address, signature)
}

/// The messages in the host's log for height 1.
fn logged_messages(host: &mut TestHost) -> Vec<Message> {
    host.env
        .storage
        .start_height(BlockHeight(1))
        .unwrap()
        .iter()
        .filter_map(|bytes| match Entry::decode(bytes).unwrap() {
            Entry::Message(message) => Some(message),
            _ => None,
        })
        .collect()
}

#[test]
fn a_polka_certificate_that_checks_out_is_logged_and_one_that_does_not_is_not() {
    use malachite_core_types::{NilOrVal, PolkaCertificate, PolkaSignature, VoteType};

    let mut host = host(GENESIS_TIME + 1);
    host.start();
    let value = hash_of(7);
    let polka = |signers: [u8; 2], claimed: Hash| {
        Message::Liveness(LivenessMsg::PolkaCertificate(PolkaCertificate {
            height: ConsensusHeight(BlockHeight(1)),
            round: Round::new(0),
            value_id: claimed,
            polka_signatures: signers
                .map(|n| {
                    let (address, signature) =
                        vote_signature(n, VoteType::Prevote, 0, NilOrVal::Val(value));
                    PolkaSignature { address, signature }
                })
                .to_vec(),
        }))
    };

    // Signed for `value` but claiming another: not a polka.
    host.handle_message(polka([1, 2], hash_of(8)));
    assert!(logged_messages(&mut host)
        .iter()
        .all(|m| !matches!(m, Message::Liveness(LivenessMsg::PolkaCertificate(_)))));

    host.handle_message(polka([1, 2], value));
    assert!(logged_messages(&mut host)
        .iter()
        .any(|m| matches!(m, Message::Liveness(LivenessMsg::PolkaCertificate(_)))));
}

#[test]
fn a_round_certificate_that_checks_out_is_logged_and_one_that_does_not_is_not() {
    use malachite_core_types::{
        NilOrVal, RoundCertificate, RoundCertificateType, RoundSignature, VoteType,
    };

    let mut host = host(GENESIS_TIME + 1);
    host.start();
    let certificate = |signers: &[u8]| {
        Message::Liveness(LivenessMsg::SkipRoundCertificate(RoundCertificate {
            height: ConsensusHeight(BlockHeight(1)),
            round: Round::new(3),
            cert_type: RoundCertificateType::Skip,
            round_signatures: signers
                .iter()
                .map(|n| {
                    let (address, signature) =
                        vote_signature(*n, VoteType::Precommit, 3, NilOrVal::Nil);
                    RoundSignature {
                        vote_type: VoteType::Precommit,
                        value_id: NilOrVal::Nil,
                        address,
                        signature,
                    }
                })
                .collect(),
        }))
    };
    let is_certificate =
        |m: &Message| matches!(m, Message::Liveness(LivenessMsg::SkipRoundCertificate(_)));

    // No signatures: nothing to skip on.
    host.handle_message(certificate(&[]));
    assert!(logged_messages(&mut host)
        .iter()
        .all(|m| !is_certificate(m)));

    host.handle_message(certificate(&[1, 2]));
    assert!(logged_messages(&mut host).iter().any(is_certificate));
}

#[test]
fn a_host_that_cannot_record_a_commit_halts_before_finalising_it() {
    let mut host = flaky(Flaky {
        fail_record: true,
        ..Flaky::default()
    });
    let head = host.env.exec.head().unwrap();
    let record = certified(&host, &good_block(&head));
    adopting(&mut host, record);
    assert!(wal_failed(&host));
    assert_eq!(host.chain().head().unwrap().height, BlockHeight(0));
}
