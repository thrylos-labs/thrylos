//! A chain started from a `GenesisConfig`: the state it builds, what the
//! first block must satisfy, and that the chain then runs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::arithmetic_side_effects
)]

use blst::min_pk::SecretKey;
use chain_engine_api::{Block, BlockLimits, Engine, RejectionReason, TransactionOutcome};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::native::{STAKE, STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS, UNSTAKE};
use chain_exec::Executor;
use chain_modules::params::{GENESIS_PARAM_VALUES, MIN_UNBONDING_PERIOD_MS};
use chain_modules::{ValidatorId, DEAD_SHARES};
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{
    Address, BlockHeight, BlsPublicKey, ChainId, Encode, GasAmount, GasPrice, Hash, MoveCall,
    PublicKey, SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

const MIN: u128 = GENESIS_PARAM_VALUES.min_self_stake;
/// Half of it must be worth more than an unbonding entry's storage deposit.
const BIG_STAKE: u128 = 400_000_000;
const GENESIS_TIME: u64 = 1_700_000_000_000;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::from_ed25519_bytes(signing_key(seed).verifying_key().to_bytes()).unwrap()
}

fn address(seed: u8) -> Address {
    Address::from_public_key(&public(seed))
}

fn bls(seed: u8) -> (BlsPublicKey, BlsSignature) {
    let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    let key = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
    let proof = BlsSignature::from_bytes(
        sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .unwrap();
    (key, proof)
}

fn validator(seed: u8, stake: u128) -> GenesisValidator {
    let (consensus_key, proof_of_possession) = bls(seed);
    GenesisValidator {
        operator: public(seed),
        consensus_key,
        proof_of_possession,
        self_stake: stake,
    }
}

fn allocation(seed: u8, amount: u128) -> Allocation {
    Allocation {
        owner: public(seed),
        amount,
    }
}

fn config() -> GenesisConfig {
    GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(50, 1_000_000), allocation(51, 250_000)],
        vec![
            validator(1, 2 * MIN),
            validator(2, 5 * MIN),
            validator(3, MIN),
        ],
    )
    .unwrap()
}

fn call(seed: u8, sequence: u64, function: &str, arguments: Vec<Vec<u8>>) -> Transaction {
    let body = TransactionBody {
        chain_id: ChainId(1),
        sender: public(seed),
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(5_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(10),
        declared_inputs: Vec::new(),
        call: MoveCall {
            module_address: Address::from_bytes(STAKING_PACKAGE_ADDRESS),
            module_name: STAKING_MODULE_NAME.as_bytes().to_vec(),
            function_name: function.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments,
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    let signature = Signature::from_ed25519_bytes(signing_key(seed).sign(&bytes).to_bytes());
    Transaction { body, signature }
}

fn block_at(executor: &Executor, timestamp_ms: u64, transactions: Vec<Transaction>) -> Block {
    executor.propose_block(
        executor.tip_block_hash(),
        executor.state_root(),
        BlockHeight(executor.head_height().unwrap() + 1),
        timestamp_ms,
        transactions,
        BlockLimits {
            max_gas: u64::MAX,
            max_size_bytes: 4 * 1024 * 1024,
        },
    )
}

fn commit(executor: &mut Executor, block: &Block) -> chain_engine_api::ExecutedBlock {
    let executed = executor
        .execute_block(executor.state_root(), block)
        .unwrap();
    executor.finalise_block(block, &executed).unwrap();
    executed
}

// ---- the state it builds -------------------------------------------------

#[test]
fn allocations_become_balances_and_the_supply_is_everything_created() {
    let c = config();
    let executor = Executor::from_genesis(&c).unwrap();

    assert_eq!(
        executor.read_account(address(50)).unwrap().balance,
        1_000_000
    );
    assert_eq!(executor.read_account(address(51)).unwrap().balance, 250_000);
    assert_eq!(
        executor.read_account(address(1)).unwrap().balance,
        0,
        "a validator's stake is not a spendable balance"
    );
    assert_eq!(executor.supply(), Some(c.total_supply()));
    assert_eq!(
        c.total_supply(),
        1_250_000 + (2 + 5 + 1) * MIN + 3 * DEAD_SHARES
    );
    executor.audit().unwrap();
}

#[test]
fn the_validators_are_registered_bonded_and_ordered_by_stake() {
    let executor = Executor::from_genesis(&config()).unwrap();
    let set = executor.validator_set().unwrap();

    let stakes: Vec<u128> = set.iter().map(|v| v.stake).collect();
    assert_eq!(stakes, vec![5 * MIN, 2 * MIN, MIN]);
    assert_eq!(set[0].id, ValidatorId(address(2)));
    let (key, _) = bls(2);
    assert_eq!(set[0].consensus_key, key);
    assert_eq!(
        executor.with_registry(|r| r.stake_of(&ValidatorId(address(1)), &address(1)).unwrap()),
        2 * MIN,
        "the operator's own stake"
    );
}

#[test]
fn the_parameters_start_where_the_configuration_says() {
    let mut params = GENESIS_PARAM_VALUES;
    params.inflation_bps = 300;
    params.quorum_bps = 4_000;
    let c = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        params,
        vec![],
        vec![validator(1, MIN)],
    )
    .unwrap();
    let executor = Executor::from_genesis(&c).unwrap();
    assert_eq!(*executor.params().unwrap().values(), params);
}

#[test]
fn the_chain_starts_at_height_zero_and_the_configured_time() {
    let executor = Executor::from_genesis(&config()).unwrap();
    assert_eq!(executor.head_height(), Some(0));
    assert_eq!(executor.head_timestamp_millis(), Some(GENESIS_TIME));
}

#[test]
fn the_first_blocks_parent_is_the_genesis_hash() {
    let c = config();
    let executor = Executor::from_genesis(&c).unwrap();
    assert_eq!(executor.tip_block_hash(), c.hash());
    assert_ne!(executor.tip_block_hash(), Hash::from_bytes([0u8; 32]));
}

// ---- determinism ---------------------------------------------------------

#[test]
fn building_twice_or_from_a_reordered_configuration_gives_the_same_chain() {
    let a = Executor::from_genesis(&config()).unwrap();
    let b = Executor::from_genesis(&config()).unwrap();
    let reordered = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(51, 250_000), allocation(50, 1_000_000)],
        vec![
            validator(3, MIN),
            validator(1, 2 * MIN),
            validator(2, 5 * MIN),
        ],
    )
    .unwrap();
    let c = Executor::from_genesis(&reordered).unwrap();
    assert_eq!(a.state_root(), b.state_root());
    assert_eq!(a.state_root(), c.state_root());
    assert_eq!(a.tip_block_hash(), c.tip_block_hash());
}

#[test]
fn a_different_configuration_is_a_different_chain() {
    let base = Executor::from_genesis(&config()).unwrap();
    let richer = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(50, 1_000_001), allocation(51, 250_000)],
        vec![
            validator(1, 2 * MIN),
            validator(2, 5 * MIN),
            validator(3, MIN),
        ],
    )
    .unwrap();
    let other = Executor::from_genesis(&richer).unwrap();
    assert_ne!(base.state_root(), other.state_root());
    assert_ne!(base.tip_block_hash(), other.tip_block_hash());
}

#[test]
fn a_block_of_another_network_with_the_same_chain_id_is_not_a_block_here() {
    // Same chain id, different allocations: their first block names their
    // genesis hash as its parent, which this chain does not have as its tip.
    let here = Executor::from_genesis(&config()).unwrap();
    let there_config = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(50, 999)],
        vec![validator(1, MIN)],
    )
    .unwrap();
    let there = Executor::from_genesis(&there_config).unwrap();
    let foreign = block_at(&there, GENESIS_TIME + 1_000, Vec::new());
    let rejected = here.execute_block(here.state_root(), &foreign).unwrap_err();
    assert_eq!(rejected.reason, RejectionReason::MalformedBlock);
}

// ---- the first block -----------------------------------------------------

#[test]
fn the_first_block_must_be_strictly_after_the_genesis_time() {
    let executor = Executor::from_genesis(&config()).unwrap();
    for early in [0, GENESIS_TIME - 1, GENESIS_TIME] {
        let block = block_at(&executor, early, Vec::new());
        assert_eq!(
            executor
                .execute_block(executor.state_root(), &block)
                .unwrap_err()
                .reason,
            RejectionReason::InvalidBlockTimestamp,
            "timestamp {early}"
        );
    }
    let block = block_at(&executor, GENESIS_TIME + 1, Vec::new());
    assert!(executor
        .execute_block(executor.state_root(), &block)
        .is_ok());
}

// ---- running from genesis ------------------------------------------------

#[test]
fn an_allocated_account_can_transact_and_delegate_to_a_genesis_validator() {
    let mut executor = Executor::from_genesis(&config()).unwrap();
    // A first delegation creates a new entry, which costs a storage deposit
    // the genesis allocation alone is too small to cover.
    executor.credit_account(address(50), 100_000_000).unwrap();
    let supply = executor.supply().unwrap();

    let stake = call(
        50,
        0,
        STAKE,
        vec![
            address(1).as_bytes().to_vec(),
            40_000u128.to_le_bytes().to_vec(),
        ],
    );
    let block = block_at(&executor, GENESIS_TIME + 1_000, vec![stake]);
    let executed = commit(&mut executor, &block);
    // One delegation entry, priced per new entry.
    let deposit = chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
    assert_eq!(executed.outcomes[0], TransactionOutcome::Success);

    assert_eq!(
        executor.read_account(address(50)).unwrap().balance,
        1_000_000 + 100_000_000 - 40_000 - deposit - 1_000,
        "the stake, the storage deposit and the fee"
    );
    assert_eq!(
        executor.supply().unwrap(),
        supply - deposit - 1_000,
        "only the fee and the deposit left"
    );
    assert_eq!(
        executor
            .validator_set()
            .unwrap()
            .iter()
            .find(|v| v.id == ValidatorId(address(1)))
            .unwrap()
            .stake,
        2 * MIN + 40_000
    );
    executor.audit().unwrap();
}

#[test]
fn a_genesis_validator_can_unstake_and_is_paid_after_the_unbonding_period() {
    // The operator's stake is bonded, not spendable, so it is also
    // allocated some coin to pay fees with.
    let with_fee_money = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(1, 100_000)],
        vec![validator(1, BIG_STAKE)],
    )
    .unwrap();
    let mut executor = Executor::from_genesis(&with_fee_money).unwrap();

    let operator = address(1);
    let shares =
        executor.with_registry(|r| r.shares_of(&ValidatorId(operator), &operator).unwrap());
    let unstake = call(
        1,
        0,
        UNSTAKE,
        vec![
            operator.as_bytes().to_vec(),
            (shares / 2).to_le_bytes().to_vec(),
        ],
    );
    let began = block_at(&executor, GENESIS_TIME + 1_000, vec![unstake]);
    let executed = commit(&mut executor, &began);
    assert_eq!(executed.outcomes[0], TransactionOutcome::Success);
    let after_fee = executor.read_account(operator).unwrap().balance;
    assert_eq!(after_fee, 100_000 - 1_000);

    let matured = block_at(
        &executor,
        GENESIS_TIME + 1_000 + MIN_UNBONDING_PERIOD_MS,
        Vec::new(),
    );
    commit(&mut executor, &matured);
    assert_eq!(
        executor.read_account(operator).unwrap().balance,
        after_fee + BIG_STAKE / 2 - chain_exec::native::UNBONDING_ENTRY_STORAGE_DEPOSIT,
        "half of the self-stake came back"
    );
    executor.audit().unwrap();
}

#[test]
fn the_first_epoch_starts_its_reward_clock_at_the_first_block_not_at_genesis() {
    // Genesis time can be well before launch; nothing is owed for that gap.
    let mut executor = Executor::from_genesis(&config()).unwrap();
    let supply = executor.supply().unwrap();
    let block = block_at(&executor, GENESIS_TIME + 30 * 86_400_000, Vec::new());
    commit(&mut executor, &block);
    assert_eq!(
        executor.supply().unwrap(),
        supply,
        "no reward at the first block"
    );
}

// ---- restoring a chain that has validators, stakes and unbonding -------------

fn restored(executor: &Executor) -> Executor {
    let state = executor
        .state_entries()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Executor::restore(
        ChainId(1),
        state,
        executor.tip_block_hash(),
        executor.state_root(),
    )
    .unwrap()
}

#[test]
fn a_chain_restored_mid_unbonding_pays_out_exactly_as_the_original_does() {
    let with_fee_money = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![allocation(1, 100_000)],
        vec![validator(1, BIG_STAKE), validator(2, MIN)],
    )
    .unwrap();
    let mut original = Executor::from_genesis(&with_fee_money).unwrap();

    // Begin unstaking half of the operator's shares, so the restored copy is
    // taken with an unbonding entry open and a reward clock running.
    let operator = address(1);
    let shares =
        original.with_registry(|r| r.shares_of(&ValidatorId(operator), &operator).unwrap());
    let unstake = call(
        1,
        0,
        UNSTAKE,
        vec![
            operator.as_bytes().to_vec(),
            (shares / 2).to_le_bytes().to_vec(),
        ],
    );
    let began = block_at(&original, GENESIS_TIME + 1_000, vec![unstake]);
    commit(&mut original, &began);

    let mut copy = restored(&original);
    assert_eq!(copy.state_root(), original.state_root());
    assert_eq!(
        copy.validator_set().unwrap(),
        original.validator_set().unwrap()
    );
    assert_eq!(copy.params().unwrap(), original.params().unwrap());
    assert_eq!(copy.supply(), original.supply());
    copy.audit().unwrap();

    // What consensus reads through the view is the same too.
    assert_eq!(
        ChainView::head(&copy).unwrap(),
        ChainView::head(&original).unwrap()
    );
    assert_eq!(
        ChainView::validator_set(&copy).unwrap(),
        ChainView::validator_set(&original).unwrap()
    );
    assert_eq!(
        ChainView::block_limits(&copy).unwrap(),
        ChainView::block_limits(&original).unwrap()
    );

    // The unbonding period elapses in a block both run: the payout, the
    // queue and the rewards must come out the same.
    let matured = block_at(
        &original,
        GENESIS_TIME + 1_000 + MIN_UNBONDING_PERIOD_MS,
        Vec::new(),
    );
    let by_original = original
        .execute_block(original.state_root(), &matured)
        .unwrap();
    let by_copy = copy.execute_block(copy.state_root(), &matured).unwrap();
    assert_eq!(by_original, by_copy);
    original.finalise_block(&matured, &by_original).unwrap();
    copy.finalise_block(&matured, &by_copy).unwrap();

    assert_eq!(copy.state_root(), original.state_root());
    assert_eq!(
        copy.read_account(operator).unwrap().balance,
        original.read_account(operator).unwrap().balance
    );
    assert_eq!(
        copy.read_account(operator).unwrap().balance,
        100_000 - 1_000 + BIG_STAKE / 2 - chain_exec::native::UNBONDING_ENTRY_STORAGE_DEPOSIT,
        "half of the self-stake came back, on the restored chain too"
    );
    copy.audit().unwrap();
    original.audit().unwrap();
}

// ---- the read-only view consensus uses -------------------------------------

use chain_engine_api::{ChainView, MAX_BLOCK_SIZE_BYTES};

#[test]
fn the_head_at_genesis_is_the_genesis_state_and_moves_with_each_block() {
    let c = config();
    let mut executor = Executor::from_genesis(&c).unwrap();
    let head = executor.head().unwrap();
    assert_eq!(head.height, BlockHeight(0));
    assert_eq!(head.timestamp_ms, GENESIS_TIME);
    assert_eq!(head.block_hash, c.hash());
    assert_eq!(head.state_root, executor.state_root());

    let block = block_at(&executor, GENESIS_TIME + 1_000, Vec::new());
    commit(&mut executor, &block);
    let head = executor.head().unwrap();
    assert_eq!(head.height, BlockHeight(1));
    assert_eq!(head.timestamp_ms, GENESIS_TIME + 1_000);
    assert_eq!(head.block_hash, block.hash());
    assert_eq!(head.state_root, executor.state_root());
}

#[test]
fn the_validator_set_is_the_genesis_validators_largest_first_with_their_keys() {
    let executor = Executor::from_genesis(&config()).unwrap();
    let set = ChainView::validator_set(&executor).unwrap();
    assert_eq!(
        set.iter().map(|v| v.voting_power).collect::<Vec<_>>(),
        vec![
            u64::try_from(5 * MIN).unwrap(),
            u64::try_from(2 * MIN).unwrap(),
            u64::try_from(MIN).unwrap()
        ]
    );
    assert_eq!(set[0].address, address(2));
    assert_eq!(set[0].consensus_key, bls(2).0);
    assert_eq!(set[2].address, address(3));
}

#[test]
fn voting_power_is_scaled_to_fit_a_u64_keeping_the_proportions() {
    let huge = u128::from(u64::MAX);
    let c = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        GENESIS_PARAM_VALUES,
        vec![],
        vec![
            validator(1, 4 * huge),
            validator(2, 2 * huge),
            validator(3, huge),
        ],
    )
    .unwrap();
    let executor = Executor::from_genesis(&c).unwrap();
    let powers: Vec<u64> = ChainView::validator_set(&executor)
        .unwrap()
        .iter()
        .map(|v| v.voting_power)
        .collect();

    let total: u128 = powers.iter().map(|p| u128::from(*p)).sum();
    assert!(total <= u128::from(u64::MAX), "the scaled total fits");
    // 4 : 2 : 1, to within the bits shifted out.
    assert!(powers[0] / 2 >= powers[1] - 1 && powers[0] / 2 <= powers[1] + 1);
    assert!(powers[1] / 2 >= powers[2] - 1 && powers[1] / 2 <= powers[2] + 1);
}

#[test]
fn the_block_limits_follow_the_governed_parameters() {
    let executor = Executor::from_genesis(&config()).unwrap();
    let limits = executor.block_limits().unwrap();
    assert_eq!(limits.max_gas, GENESIS_PARAM_VALUES.max_block_gas);
    assert_eq!(limits.max_size_bytes, MAX_BLOCK_SIZE_BYTES);

    let mut params = GENESIS_PARAM_VALUES;
    params.max_block_gas = 30_000_000;
    let c = GenesisConfig::new(
        ChainId(1),
        GENESIS_TIME,
        params,
        vec![],
        vec![validator(1, MIN)],
    )
    .unwrap();
    assert_eq!(
        Executor::from_genesis(&c)
            .unwrap()
            .block_limits()
            .unwrap()
            .max_gas,
        30_000_000
    );
}
