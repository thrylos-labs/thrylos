//! The native module boundary end to end: real signed transactions, in
//! real blocks, calling into staking and governance, with the supply
//! audited after each step.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use blst::min_pk::SecretKey;
use chain_engine_api::{
    AbortReason, Block, BlockLimits, Engine, ExecutedBlock, TransactionOutcome,
};
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_exec::hooks::{reward_for, EPOCH_BLOCKS};
use chain_exec::native::UNBONDING_ENTRY_STORAGE_DEPOSIT;
use chain_exec::native::{
    COIN_MODULE_NAME, COIN_PACKAGE_ADDRESS, GOVERNANCE_MODULE_NAME, GOVERNANCE_PACKAGE_ADDRESS,
    NEW_ACCOUNT_STORAGE_DEPOSIT, NEW_ENTRY_STORAGE_DEPOSIT, REGISTER_VALIDATOR, STAKE,
    STAKING_MODULE_NAME, STAKING_PACKAGE_ADDRESS, SUBMIT_EVIDENCE, SUBMIT_PROPOSAL, TRANSFER,
    UNJAIL, UNSTAKE, VOTE,
};
use chain_exec::Executor;
use chain_modules::governance::{
    ApplyFailure, ProposalId, ProposalKind, ProposalStatus, TIMELOCK_MS, VOTING_PERIOD_MS,
};
use chain_modules::params::{DAY_MS, GENESIS_PARAM_VALUES, MIN_UNBONDING_PERIOD_MS};
use chain_modules::{ParamChange, ValidatorId, DEAD_SHARES};
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION, DST_VOTE};
use chain_types::{
    Address, BlockHeight, BlsPublicKey, ChainId, DuplicateVoteEvidence, Encode, GasAmount,
    GasPrice, Hash, MoveCall, PublicKey, Round, SequenceNumber, Signature, Transaction,
    TransactionBody, Vote, VoteKind,
};
use ed25519_dalek::{Signer, SigningKey};

const GAS_LIMIT: u64 = 1_000;
const MAX_FEE: u64 = 10;
/// What every transaction here pays: its gas limit, at the base fee of 1.
const FEE: u128 = 1_000;
const MIN_STAKE: u128 = GENESIS_PARAM_VALUES.min_self_stake;

// ---- encoding arguments --------------------------------------------------

fn u128_arg(value: u128) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn address_arg(address: Address) -> Vec<u8> {
    address.as_bytes().to_vec()
}

/// A `vector<u8>` argument: ULEB128 length, then the bytes.
fn vector_arg(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut length = bytes.len();
    loop {
        let low = (length & 0x7F) as u8;
        length >>= 7;
        if length == 0 {
            out.push(low);
            break;
        }
        out.push(low | 0x80);
    }
    out.extend_from_slice(bytes);
    out
}

// ---- actors --------------------------------------------------------------

/// Someone who signs transactions, keeping their own sequence number.
struct Actor {
    key: SigningKey,
    sequence: u64,
}

impl Actor {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            sequence: 0,
        }
    }

    fn public(&self) -> PublicKey {
        PublicKey::from_ed25519_bytes(self.key.verifying_key().to_bytes()).unwrap()
    }

    fn address(&self) -> Address {
        // The same derivation the executor uses for the sender.
        self.call_with(0, GAS_LIMIT, [0; 32], "x", "x", Vec::new())
            .sender_address()
    }

    fn call_with(
        &self,
        sequence: u64,
        gas_limit: u64,
        package: [u8; 32],
        module: &str,
        function: &str,
        arguments: Vec<Vec<u8>>,
    ) -> Transaction {
        let body = TransactionBody {
            chain_id: ChainId(1),
            sender: self.public(),
            sequence_number: SequenceNumber(sequence),
            expiry: BlockHeight(5_000),
            gas_limit: GasAmount(gas_limit),
            max_fee_per_gas: GasPrice(MAX_FEE),
            declared_inputs: Vec::new(),
            call: MoveCall {
                module_address: Address::from_bytes(package),
                module_name: module.as_bytes().to_vec(),
                function_name: function.as_bytes().to_vec(),
                type_arguments: Vec::new(),
                arguments,
            },
        };
        let mut bytes = Vec::new();
        body.encode(&mut bytes);
        let signature = Signature::from_ed25519_bytes(self.key.sign(&bytes).to_bytes());
        Transaction { body, signature }
    }

    /// The next transaction from this actor, calling `function` of
    /// `module` in `package`.
    fn call(
        &mut self,
        package: [u8; 32],
        module: &str,
        function: &str,
        arguments: Vec<Vec<u8>>,
    ) -> Transaction {
        let tx = self.call_with(
            self.sequence,
            GAS_LIMIT,
            package,
            module,
            function,
            arguments,
        );
        self.sequence += 1;
        tx
    }

    fn staking(&mut self, function: &str, arguments: Vec<Vec<u8>>) -> Transaction {
        self.call(
            STAKING_PACKAGE_ADDRESS,
            STAKING_MODULE_NAME,
            function,
            arguments,
        )
    }

    fn governance(&mut self, function: &str, arguments: Vec<Vec<u8>>) -> Transaction {
        self.call(
            GOVERNANCE_PACKAGE_ADDRESS,
            GOVERNANCE_MODULE_NAME,
            function,
            arguments,
        )
    }

    fn transfer(&mut self, recipient: Address, amount: u128) -> Transaction {
        self.call(
            COIN_PACKAGE_ADDRESS,
            COIN_MODULE_NAME,
            TRANSFER,
            vec![address_arg(recipient), u128_arg(amount)],
        )
    }

    /// Registers this actor as a validator with the BLS key of `bls_seed`.
    fn register(&mut self, bls_seed: u8, self_stake: u128) -> Transaction {
        let (key, proof) = bls_identity(bls_seed);
        self.staking(
            REGISTER_VALIDATOR,
            vec![
                vector_arg(&key.to_bytes()),
                vector_arg(&proof.to_bytes()),
                u128_arg(self_stake),
            ],
        )
    }
}

fn bls_secret(seed: u8) -> SecretKey {
    SecretKey::key_gen(&[seed; 32], &[]).unwrap()
}

fn bls_identity(seed: u8) -> (BlsPublicKey, BlsSignature) {
    let sk = bls_secret(seed);
    let key = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
    let proof = BlsSignature::from_bytes(
        sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .unwrap();
    (key, proof)
}

/// Real, verifiable equivocation at `height` by the validator whose BLS
/// key is `bls_seed`'s and whose address is `validator`, on this test chain.
fn equivocation(bls_seed: u8, validator: Address, height: u64) -> DuplicateVoteEvidence {
    equivocation_on(ChainId(1), bls_seed, validator, height)
}

/// The same, with the votes signed for `chain`.
fn equivocation_on(
    chain: ChainId,
    bls_seed: u8,
    validator: Address,
    height: u64,
) -> DuplicateVoteEvidence {
    let sk = bls_secret(bls_seed);
    let vote = |value: u8| Vote {
        chain_id: chain,
        height: BlockHeight(height),
        round: Round(0),
        value: Some(Hash::from_bytes([value; 32])),
        kind: VoteKind::Prevote,
        validator,
    };
    let sign = |v: &Vote| {
        BlsSignature::from_bytes(sk.sign(&v.signing_bytes(), DST_VOTE, &[]).to_bytes()).unwrap()
    };
    let (a, b) = (vote(1), vote(2));
    DuplicateVoteEvidence {
        signature_a: sign(&a),
        signature_b: sign(&b),
        vote_a: a,
        vote_b: b,
    }
}

// ---- the chain -----------------------------------------------------------

struct Chain {
    executor: Executor,
    now_ms: u64,
}

const START_MS: u64 = 1_700_000_000_000;

impl Chain {
    fn new() -> Self {
        Self {
            executor: Executor::genesis(ChainId(1)).unwrap(),
            now_ms: START_MS,
        }
    }

    fn fund(&mut self, who: &Actor, amount: u128) {
        self.executor.credit_account(who.address(), amount).unwrap();
    }

    fn balance(&self, who: Address) -> u128 {
        self.executor.read_account(who).unwrap().balance
    }

    /// A block a second after the last one.
    fn block(&mut self, transactions: Vec<Transaction>) -> ExecutedBlock {
        self.block_after(1_000, transactions)
    }

    /// A block `after_ms` after the last one.
    fn block_after(&mut self, after_ms: u64, transactions: Vec<Transaction>) -> ExecutedBlock {
        self.now_ms += after_ms;
        let root = self.executor.state_root();
        let height = BlockHeight(self.executor.head_height().unwrap() + 1);
        let block: Block = self.executor.propose_block(
            self.executor.tip_block_hash(),
            root,
            height,
            self.now_ms,
            transactions,
            BlockLimits {
                max_gas: u64::MAX,
                max_size_bytes: 4 * 1024 * 1024,
            },
        );
        let executed = self.executor.execute_block(root, &block).unwrap();
        self.executor.finalise_block(&block, &executed).unwrap();
        executed
    }

    /// One transaction in its own block; its outcome.
    fn run(&mut self, tx: Transaction) -> TransactionOutcome {
        self.block(vec![tx]).outcomes[0]
    }

    /// The state stays balanced and every module's own records agree.
    fn audit(&self) {
        self.executor.audit().unwrap();
    }
}

const SUCCESS: TransactionOutcome = TransactionOutcome::Success;

fn aborted(reason: AbortReason) -> TransactionOutcome {
    TransactionOutcome::Aborted(reason)
}

/// A chain with one registered validator (operator seed 1, BLS seed 1).
fn chain_with_validator() -> (Chain, Actor) {
    let mut chain = Chain::new();
    let mut operator = Actor::new(1);
    chain.fund(&operator, 10 * MIN_STAKE + 100 * NEW_ENTRY_STORAGE_DEPOSIT);
    let tx = operator.register(1, MIN_STAKE);
    assert_eq!(chain.run(tx), SUCCESS);
    (chain, operator)
}

// ---- coin ----------------------------------------------------------------

#[test]
fn transferring_moves_coin_to_the_recipient_and_burns_only_the_fee() {
    let mut chain = Chain::new();
    let mut sender = Actor::new(1);
    let recipient = Actor::new(2);
    chain.fund(&sender, 100_000);
    // Already exists, so this transfer pays no storage deposit — that is
    // its own, separately covered behaviour.
    chain.fund(&recipient, 1);
    let supply = chain.executor.supply().unwrap();

    let tx = sender.transfer(recipient.address(), 40_000);
    assert_eq!(chain.run(tx), SUCCESS);

    assert_eq!(chain.balance(sender.address()), 100_000 - 40_000 - FEE);
    assert_eq!(chain.balance(recipient.address()), 1 + 40_000);
    assert_eq!(chain.executor.supply().unwrap(), supply - FEE);
    chain.audit();
}

#[test]
fn transferring_to_a_fresh_address_also_burns_the_storage_deposit() {
    let mut chain = Chain::new();
    let mut sender = Actor::new(1);
    let recipient = Actor::new(2); // never funded: has no account yet
    chain.fund(&sender, 100_000_000);
    let supply = chain.executor.supply().unwrap();

    let tx = sender.transfer(recipient.address(), 40_000);
    assert_eq!(chain.run(tx), SUCCESS);

    assert_eq!(
        chain.balance(sender.address()),
        100_000_000 - 40_000 - NEW_ACCOUNT_STORAGE_DEPOSIT - FEE
    );
    assert_eq!(chain.balance(recipient.address()), 40_000);
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - NEW_ACCOUNT_STORAGE_DEPOSIT - FEE
    );
    chain.audit();
}

#[test]
fn a_transfer_that_cannot_afford_the_storage_deposit_aborts_and_only_pays_the_real_fee() {
    let mut chain = Chain::new();
    let mut sender = Actor::new(1);
    let recipient = Actor::new(2); // never funded: has no account yet
                                   // Enough for the amount and the fee, but the deposit this recipient
                                   // needs is not on top of that.
    chain.fund(&sender, 40_000 + FEE);

    let tx = sender.transfer(recipient.address(), 40_000);
    assert_eq!(chain.run(tx), aborted(AbortReason::InsufficientBalance));

    assert_eq!(chain.balance(sender.address()), 40_000);
    assert_eq!(chain.balance(recipient.address()), 0);
    chain.audit();
}

#[test]
fn a_transfer_that_cannot_leave_the_maximum_fee_aborts_and_only_pays_the_real_fee() {
    let mut chain = Chain::new();
    let mut sender = Actor::new(1);
    let recipient = Actor::new(2);
    chain.fund(&sender, 40_000);

    let tx = sender.transfer(recipient.address(), 40_000);
    assert_eq!(chain.run(tx), aborted(AbortReason::InsufficientBalance));

    assert_eq!(chain.balance(sender.address()), 40_000 - FEE);
    assert_eq!(chain.balance(recipient.address()), 0);
    chain.audit();
}

#[test]
fn zero_and_self_transfers_abort_without_moving_coin() {
    let mut chain = Chain::new();
    let mut sender = Actor::new(1);
    let recipient = Actor::new(2);
    chain.fund(&sender, 100_000);

    let zero = sender.transfer(recipient.address(), 0);
    assert_eq!(chain.run(zero), aborted(AbortReason::InvalidArguments));
    let to_self = sender.transfer(sender.address(), 1);
    assert_eq!(chain.run(to_self), aborted(AbortReason::InvalidArguments));

    assert_eq!(chain.balance(sender.address()), 100_000 - 2 * FEE);
    assert_eq!(chain.balance(recipient.address()), 0);
    chain.audit();
}

// ---- registering and staking --------------------------------------------

#[test]
fn registering_moves_the_stake_and_the_dead_shares_into_the_pool_and_charges_the_fee() {
    let mut chain = Chain::new();
    let mut operator = Actor::new(1);
    chain.fund(&operator, 10 * MIN_STAKE);
    let supply = chain.executor.supply().unwrap();

    let tx = operator.register(1, MIN_STAKE);
    assert_eq!(chain.run(tx), SUCCESS);

    let id = ValidatorId(operator.address());
    assert_eq!(
        chain.balance(operator.address()),
        10 * MIN_STAKE - MIN_STAKE - DEAD_SHARES - FEE,
        "the stake, the locked dead shares, and the fee"
    );
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - FEE,
        "only the fee left the supply"
    );
    let set = chain.executor.validator_set().unwrap();
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].id, id);
    assert_eq!(set[0].stake, MIN_STAKE);
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.stake_of(&id, &operator.address()).unwrap()),
        MIN_STAKE
    );
    chain.audit();
}

#[test]
fn invalid_registration_or_registration_after_bootstrap_aborts_and_costs_only_the_fee() {
    let mut chain = Chain::new();
    let mut operator = Actor::new(1);
    chain.fund(&operator, 10 * MIN_STAKE + 100 * NEW_ENTRY_STORAGE_DEPOSIT);
    let start = chain.balance(operator.address());

    let too_little = operator.register(1, MIN_STAKE - 1);
    assert_eq!(chain.run(too_little), aborted(AbortReason::StakingRefused));

    // A proof of possession from somebody else's key.
    let (key, _) = bls_identity(1);
    let (_, someone_elses_proof) = bls_identity(2);
    let bad_proof = operator.staking(
        REGISTER_VALIDATOR,
        vec![
            vector_arg(&key.to_bytes()),
            vector_arg(&someone_elses_proof.to_bytes()),
            u128_arg(MIN_STAKE),
        ],
    );
    assert_eq!(chain.run(bad_proof), aborted(AbortReason::StakingRefused));

    assert_eq!(chain.balance(operator.address()), start - 2 * FEE);
    assert!(chain.executor.validator_set().unwrap().is_empty());

    let ok = operator.register(1, MIN_STAKE);
    assert_eq!(chain.run(ok), SUCCESS);
    let again = operator.register(2, MIN_STAKE);
    assert_eq!(
        chain.run(again),
        aborted(AbortReason::Unauthorised),
        "validator membership is frozen after bootstrap"
    );
    chain.audit();
}

#[test]
fn a_registration_the_balance_cannot_cover_aborts() {
    let mut chain = Chain::new();
    let mut operator = Actor::new(1);
    // Enough for the stake, but not for the dead shares and the fee too.
    chain.fund(&operator, MIN_STAKE + 500);
    let tx = operator.register(1, MIN_STAKE);
    assert_eq!(chain.run(tx), aborted(AbortReason::InsufficientBalance));
    assert!(
        chain.executor.validator_set().unwrap().is_empty(),
        "nothing registered"
    );
    chain.audit();
}

#[test]
fn delegating_mints_shares_and_debits_the_delegator() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(2);
    chain.fund(&delegator, 100_000 + NEW_ENTRY_STORAGE_DEPOSIT);

    let tx = delegator.staking(
        STAKE,
        vec![address_arg(operator.address()), u128_arg(40_000)],
    );
    assert_eq!(chain.run(tx), SUCCESS);

    let id = ValidatorId(operator.address());
    assert_eq!(chain.balance(delegator.address()), 100_000 - 40_000 - FEE);
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.stake_of(&id, &delegator.address()).unwrap()),
        40_000
    );
    assert_eq!(
        chain.executor.validator_set().unwrap()[0].stake,
        MIN_STAKE + 40_000
    );
    chain.audit();
}

#[test]
fn a_stake_that_would_leave_the_fee_unpayable_aborts_and_changes_nothing_else() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(2);
    // 40_000 is affordable; 40_000 plus the most a fee can come to is not.
    chain.fund(&delegator, 40_000);
    let id = ValidatorId(operator.address());

    let tx = delegator.staking(
        STAKE,
        vec![address_arg(operator.address()), u128_arg(40_000)],
    );
    assert_eq!(chain.run(tx), aborted(AbortReason::InsufficientBalance));

    assert_eq!(
        chain.balance(delegator.address()),
        40_000 - FEE,
        "only the fee"
    );
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.shares_of(&id, &delegator.address()).unwrap()),
        0,
        "the stake the registry accepted was rolled back with the call"
    );
    chain.audit();
}

#[test]
fn staking_with_a_validator_that_does_not_exist_aborts() {
    let (mut chain, _) = chain_with_validator();
    let mut delegator = Actor::new(2);
    chain.fund(&delegator, 100_000);
    let nobody = Actor::new(99).address();
    let tx = delegator.staking(STAKE, vec![address_arg(nobody), u128_arg(1_000)]);
    assert_eq!(chain.run(tx), aborted(AbortReason::StakingRefused));
    assert_eq!(chain.balance(delegator.address()), 100_000 - FEE);
}

// ---- unbonding -----------------------------------------------------------

#[test]
fn unstaking_is_paid_out_by_the_block_after_the_unbonding_period_and_not_before() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(2);
    // Big enough that the stake is worth more than the unbonding entry's
    // storage deposit, which is taken out of it.
    let staked: u128 = 100_000_000;
    let funded: u128 = 1_000_000_000;
    let entry_deposit = UNBONDING_ENTRY_STORAGE_DEPOSIT;
    chain.fund(&delegator, funded);
    let id = ValidatorId(operator.address());
    let tx = delegator.staking(
        STAKE,
        vec![address_arg(operator.address()), u128_arg(staked)],
    );
    assert_eq!(chain.run(tx), SUCCESS);
    let shares = chain
        .executor
        .with_registry(|r| r.shares_of(&id, &delegator.address()).unwrap());

    let unstake = delegator.staking(
        UNSTAKE,
        vec![address_arg(operator.address()), u128_arg(shares)],
    );
    let began = chain.block(vec![unstake]);
    assert_eq!(began.outcomes[0], SUCCESS);
    let balance_after_unstaking = chain.balance(delegator.address());
    assert_eq!(
        balance_after_unstaking,
        funded - staked - NEW_ENTRY_STORAGE_DEPOSIT - 2 * FEE,
        "not paid yet"
    );
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.total_unbonding().unwrap()),
        staked - entry_deposit
    );
    chain.audit();

    // A second before it matures: still waiting.
    chain.block_after(MIN_UNBONDING_PERIOD_MS - 1_000, Vec::new());
    assert_eq!(chain.balance(delegator.address()), balance_after_unstaking);

    // The block that lands exactly on it pays it out, in that same block.
    chain.block_after(1_000, Vec::new());
    assert_eq!(
        chain.balance(delegator.address()),
        balance_after_unstaking + staked - entry_deposit
    );
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.total_unbonding().unwrap()),
        0
    );
    chain.audit();
}

#[test]
fn unstaking_more_than_owned_or_from_a_stranger_aborts() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(2);
    chain.fund(&delegator, 100_000);
    let too_many = delegator.staking(UNSTAKE, vec![address_arg(operator.address()), u128_arg(1)]);
    assert_eq!(chain.run(too_many), aborted(AbortReason::StakingRefused));
    let unknown = delegator.staking(
        UNSTAKE,
        vec![address_arg(Actor::new(99).address()), u128_arg(1)],
    );
    assert_eq!(chain.run(unknown), aborted(AbortReason::StakingRefused));
}

#[test]
fn a_validator_that_is_not_jailed_cannot_unjail() {
    let (mut chain, mut operator) = chain_with_validator();
    let tx = operator.staking(UNJAIL, Vec::new());
    assert_eq!(chain.run(tx), aborted(AbortReason::StakingRefused));
    let with_args = operator.staking(UNJAIL, vec![vec![1]]);
    assert_eq!(chain.run(with_args), aborted(AbortReason::InvalidArguments));
}

// ---- malformed calls -----------------------------------------------------

#[test]
fn unknown_functions_and_malformed_arguments_abort_and_cost_the_fee() {
    let (mut chain, mut operator) = chain_with_validator();
    chain.fund(&operator, 1_000_000);
    let start = chain.balance(operator.address());

    for tx in [
        operator.staking("no_such_function", Vec::new()),
        operator.governance("no_such_function", Vec::new()),
    ] {
        assert_eq!(chain.run(tx), aborted(AbortReason::UnknownFunction));
    }
    for tx in [
        operator.staking(STAKE, Vec::new()),
        operator.staking(STAKE, vec![vec![1; 31], u128_arg(1)]),
        operator.staking(STAKE, vec![address_arg(operator.address()), vec![1; 15]]),
        operator.staking(REGISTER_VALIDATOR, vec![vec![1], vec![2], vec![3]]),
        // A vector whose length prefix is not minimal.
        operator.staking(SUBMIT_EVIDENCE, vec![vec![0x80, 0x00]]),
        operator.governance(VOTE, vec![vec![0; 8]]),
        operator.governance(VOTE, vec![vec![0; 8], vec![9]]),
    ] {
        assert_eq!(chain.run(tx), aborted(AbortReason::InvalidArguments));
    }
    assert_eq!(chain.balance(operator.address()), start - 9 * FEE);
    chain.audit();
}

// ---- governance ----------------------------------------------------------

fn inflation_proposal(bps: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    ProposalKind::ParameterChange(ParamChange {
        inflation_bps: Some(bps),
        ..ParamChange::default()
    })
    .encode(&mut bytes);
    vector_arg(&bytes)
}

fn min_self_stake_proposal(value: u128) -> Vec<u8> {
    let mut bytes = Vec::new();
    ProposalKind::ParameterChange(ParamChange {
        min_self_stake: Some(value),
        ..ParamChange::default()
    })
    .encode(&mut bytes);
    vector_arg(&bytes)
}

fn status(chain: &Chain, id: u64) -> ProposalStatus {
    chain
        .executor
        .with_governance(|g| g.proposal(ProposalId(id)).unwrap().unwrap().status())
}

#[test]
fn a_proposal_passes_waits_out_the_timelock_and_changes_the_parameters() {
    let (mut chain, mut operator) = chain_with_validator();
    assert_eq!(chain.executor.params().unwrap().values().inflation_bps, 400);

    let submit = operator.governance(SUBMIT_PROPOSAL, vec![inflation_proposal(700)]);
    assert_eq!(chain.run(submit), SUCCESS);
    let vote = operator.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]); // Yes
    assert_eq!(chain.run(vote), SUCCESS);

    // Voting closes: it passes, but nothing has changed yet.
    chain.block_after(VOTING_PERIOD_MS, Vec::new());
    assert!(matches!(status(&chain, 0), ProposalStatus::Passed { .. }));
    assert_eq!(chain.executor.params().unwrap().values().inflation_bps, 400);

    // The timelock runs out: applied.
    chain.block_after(TIMELOCK_MS, Vec::new());
    assert_eq!(status(&chain, 0), ProposalStatus::Applied);
    assert_eq!(chain.executor.params().unwrap().values().inflation_bps, 700);
    chain.audit();
}

/// Governance could once set the minimum self-stake to anything positive,
/// including above every operator's stake: the active set would empty, and
/// since only a validator in it can propose, nothing could ever undo that.
/// It must now fail when it comes to be applied, on a real chain, whatever
/// the vote said.
#[test]
fn a_passed_proposal_that_would_empty_the_validator_set_fails_and_changes_nothing() {
    let (mut chain, mut operator) = chain_with_validator();
    let before = chain.executor.params().unwrap().values().min_self_stake;
    let members = chain.executor.validator_set().unwrap().len();
    assert!(members > 0);

    // Twice what the only validator holds: it would no longer qualify.
    let submit = operator.governance(SUBMIT_PROPOSAL, vec![min_self_stake_proposal(before * 2)]);
    assert_eq!(chain.run(submit), SUCCESS);
    let vote = operator.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]); // Yes
    assert_eq!(chain.run(vote), SUCCESS);

    chain.block_after(VOTING_PERIOD_MS, Vec::new());
    assert!(matches!(status(&chain, 0), ProposalStatus::Passed { .. }));
    chain.block_after(TIMELOCK_MS, Vec::new());

    assert_eq!(
        status(&chain, 0),
        ProposalStatus::Failed(ApplyFailure::Params(
            chain_modules::params::ParamError::MinSelfStakeWouldEmptyTheSet
        ))
    );
    assert_eq!(
        chain.executor.params().unwrap().values().min_self_stake,
        before
    );
    assert_eq!(chain.executor.validator_set().unwrap().len(), members);
    chain.audit();
}

#[test]
fn lowering_the_minimum_self_stake_still_applies() {
    let (mut chain, mut operator) = chain_with_validator();
    let before = chain.executor.params().unwrap().values().min_self_stake;

    let submit = operator.governance(
        SUBMIT_PROPOSAL,
        vec![min_self_stake_proposal(before.div_euclid(2))],
    );
    assert_eq!(chain.run(submit), SUCCESS);
    let vote = operator.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]);
    assert_eq!(chain.run(vote), SUCCESS);
    chain.block_after(VOTING_PERIOD_MS, Vec::new());
    chain.block_after(TIMELOCK_MS, Vec::new());

    assert_eq!(status(&chain, 0), ProposalStatus::Applied);
    assert_eq!(
        chain.executor.params().unwrap().values().min_self_stake,
        before.div_euclid(2)
    );
    chain.audit();
}

#[test]
fn only_a_validator_in_the_active_set_can_propose_and_only_one_in_the_snapshot_can_vote() {
    let (mut chain, mut operator) = chain_with_validator();
    let mut outsider = Actor::new(2);
    chain.fund(&outsider, 100_000);

    let proposal = outsider.governance(SUBMIT_PROPOSAL, vec![inflation_proposal(700)]);
    assert_eq!(chain.run(proposal), aborted(AbortReason::Unauthorised));

    let submit = operator.governance(SUBMIT_PROPOSAL, vec![inflation_proposal(700)]);
    assert_eq!(chain.run(submit), SUCCESS);
    let vote = outsider.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]);
    assert_eq!(chain.run(vote), aborted(AbortReason::GovernanceRefused));

    // First-testnet membership is fixed at genesis, so an outsider cannot
    // join after the proposal (or after launch at all).
    let mut late = Actor::new(3);
    chain.fund(&late, 10 * MIN_STAKE);
    let register = late.register(3, MIN_STAKE);
    assert_eq!(chain.run(register), aborted(AbortReason::Unauthorised));
    let late_vote = late.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]);
    assert_eq!(
        chain.run(late_vote),
        aborted(AbortReason::GovernanceRefused)
    );
    chain.audit();
}

#[test]
fn a_proposal_that_is_malformed_or_changes_nothing_aborts() {
    let (mut chain, mut operator) = chain_with_validator();
    let garbage = operator.governance(SUBMIT_PROPOSAL, vec![vector_arg(&[9, 9, 9])]);
    assert_eq!(chain.run(garbage), aborted(AbortReason::InvalidArguments));

    let mut empty = Vec::new();
    ProposalKind::ParameterChange(ParamChange::default()).encode(&mut empty);
    let nothing = operator.governance(SUBMIT_PROPOSAL, vec![vector_arg(&empty)]);
    assert_eq!(chain.run(nothing), aborted(AbortReason::GovernanceRefused));
}

#[test]
fn governed_parameters_govern_execution_a_lowered_gas_limit_refuses_a_block_it_allowed() {
    let (mut chain, mut operator) = chain_with_validator();
    let mut lower = Vec::new();
    ProposalKind::ParameterChange(ParamChange {
        max_block_gas: Some(10_000_000),
        ..ParamChange::default()
    })
    .encode(&mut lower);
    let submit = operator.governance(SUBMIT_PROPOSAL, vec![vector_arg(&lower)]);
    assert_eq!(chain.run(submit), SUCCESS);
    let vote = operator.governance(VOTE, vec![0u64.to_le_bytes().to_vec(), vec![0]]);
    assert_eq!(chain.run(vote), SUCCESS);
    chain.block_after(VOTING_PERIOD_MS, Vec::new());
    chain.block_after(TIMELOCK_MS, Vec::new());
    assert_eq!(
        chain.executor.params().unwrap().values().max_block_gas,
        10_000_000
    );

    // A transaction asking for 12M gas would have fit under the old 60M,
    // but now exceeds one quarter of the governed 10M block limit.
    let heavy = operator.call_with(
        operator.sequence,
        12_000_000,
        STAKING_PACKAGE_ADDRESS,
        STAKING_MODULE_NAME,
        UNJAIL,
        Vec::new(),
    );
    chain.fund(&operator, 12_000_000 * u128::from(MAX_FEE));
    let root = chain.executor.state_root();
    let block = chain.executor.propose_block(
        chain.executor.tip_block_hash(),
        root,
        BlockHeight(chain.executor.head_height().unwrap() + 1),
        chain.now_ms + 1_000,
        vec![heavy],
        BlockLimits {
            max_gas: u64::MAX,
            max_size_bytes: 4 * 1024 * 1024,
        },
    );
    let rejected = chain.executor.execute_block(root, &block).unwrap_err();
    assert_eq!(
        rejected.reason,
        chain_engine_api::RejectionReason::TransactionGasLimitExceeded
    );
}

// ---- slashing ------------------------------------------------------------

/// Two validators (operator seeds 1 and 2), the first with `first_stake`.
fn chain_with_two_validators(first_stake: u128) -> (Chain, Actor, Actor) {
    let first = Actor::new(1);
    let second = Actor::new(2);
    let make_validator = |actor: &Actor, seed, self_stake| {
        let (consensus_key, proof_of_possession) = bls_identity(seed);
        GenesisValidator {
            operator: actor.public(),
            consensus_key,
            proof_of_possession,
            self_stake,
        }
    };
    let config = GenesisConfig::new(
        ChainId(1),
        START_MS,
        GENESIS_PARAM_VALUES,
        vec![
            Allocation {
                owner: first.public(),
                amount: 10 * first_stake,
            },
            Allocation {
                owner: second.public(),
                amount: 100 * MIN_STAKE,
            },
        ],
        vec![
            make_validator(&first, 1, first_stake),
            make_validator(&second, 2, 30 * MIN_STAKE),
        ],
    )
    .unwrap();
    let mut chain = Chain {
        executor: Executor::from_genesis(&config).unwrap(),
        now_ms: START_MS,
    };
    // Evidence at height 1 needs the chain-owned time checkpoint created by
    // that height; validator registration itself is already in genesis.
    chain.block(Vec::new());
    (chain, first, second)
}

#[test]
fn evidence_of_equivocation_burns_stake_removes_the_validator_and_lowers_the_supply() {
    let (mut chain, first, mut second) = chain_with_two_validators(5 * MIN_STAKE);
    let reporter_supply = chain.executor.supply().unwrap();
    let id = ValidatorId(first.address());
    let pooled_before = chain
        .executor
        .with_registry(|r| r.total_pooled_stake().unwrap());

    // The equivocation happened at height 1; it is reported a few blocks
    // later.
    let evidence = equivocation(1, first.address(), 1);
    let mut bytes = Vec::new();
    evidence.encode(&mut bytes);
    chain.block(Vec::new());
    let report = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&bytes)]);
    assert_eq!(chain.run(report), SUCCESS);

    let pooled_after = chain
        .executor
        .with_registry(|r| r.total_pooled_stake().unwrap());
    let burned = pooled_before - pooled_after;
    assert!(burned > 0, "something was slashed");
    assert_eq!(
        chain.executor.supply().unwrap(),
        reporter_supply - burned - FEE,
        "the burn left the supply, and so did the reporter's fee"
    );
    assert_eq!(
        chain.executor.with_registry(|r| r.status(&id).unwrap()),
        chain_modules::ValidatorStatus::Tombstoned
    );
    let set = chain.executor.validator_set().unwrap();
    assert_eq!(set.len(), 1, "only the other validator remains");
    assert_ne!(set[0].id, id);
    chain.audit();
}

#[test]
fn equivocation_signed_for_another_chain_is_refused_and_convicts_nobody() {
    let (mut chain, first, mut second) = chain_with_two_validators(5 * MIN_STAKE);
    let id = ValidatorId(first.address());
    let stake = chain
        .executor
        .with_registry(|r| r.total_pooled_stake().unwrap());
    let supply = chain.executor.supply().unwrap();

    // Genuine equivocation by a registered validator, but on chain 2's votes.
    let mut elsewhere = Vec::new();
    equivocation_on(ChainId(2), 1, first.address(), 1).encode(&mut elsewhere);
    let report = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&elsewhere)]);
    assert_eq!(chain.run(report), aborted(AbortReason::EvidenceRefused));
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - FEE,
        "only the reporter's fee left the supply"
    );
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.total_pooled_stake().unwrap()),
        stake,
        "nothing was slashed"
    );
    assert_eq!(
        chain.executor.with_registry(|r| r.status(&id).unwrap()),
        chain_modules::ValidatorStatus::Active
    );

    // The same equivocation signed for this chain does convict.
    let mut here = Vec::new();
    equivocation(1, first.address(), 1).encode(&mut here);
    let report = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&here)]);
    assert_eq!(chain.run(report), SUCCESS);
    assert_eq!(
        chain.executor.with_registry(|r| r.status(&id).unwrap()),
        chain_modules::ValidatorStatus::Tombstoned
    );
    chain.audit();
}

#[test]
fn the_same_equivocation_cannot_be_punished_twice() {
    let (mut chain, first, mut second) = chain_with_two_validators(5 * MIN_STAKE);
    let mut bytes = Vec::new();
    equivocation(1, first.address(), 1).encode(&mut bytes);
    let report = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&bytes)]);
    assert_eq!(chain.run(report), SUCCESS);
    let supply = chain.executor.supply().unwrap();
    let again = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&bytes)]);
    assert_eq!(chain.run(again), aborted(AbortReason::EvidenceRefused));
    assert_eq!(chain.executor.supply().unwrap(), supply - FEE);
    chain.audit();
}

#[test]
fn evidence_that_does_not_verify_or_names_no_validator_or_is_from_before_the_chain_is_refused() {
    let (mut chain, first, mut second) = chain_with_two_validators(5 * MIN_STAKE);
    let submit = |actor: &mut Actor, evidence: &DuplicateVoteEvidence| {
        let mut bytes = Vec::new();
        evidence.encode(&mut bytes);
        actor.staking(SUBMIT_EVIDENCE, vec![vector_arg(&bytes)])
    };

    // Signed by a key that is not the validator's registered one.
    let forged = equivocation(9, first.address(), 1);
    let tx = submit(&mut second, &forged);
    assert_eq!(chain.run(tx), aborted(AbortReason::EvidenceRefused));

    // Against an address that never registered.
    let stranger = equivocation(1, Actor::new(77).address(), 1);
    let tx = submit(&mut second, &stranger);
    assert_eq!(chain.run(tx), aborted(AbortReason::EvidenceRefused));

    // At height 0: genesis, before anyone could have voted.
    let genesis = equivocation(1, first.address(), 0);
    let tx = submit(&mut second, &genesis);
    assert_eq!(chain.run(tx), aborted(AbortReason::EvidenceRefused));

    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.status(&ValidatorId(first.address())).unwrap()),
        chain_modules::ValidatorStatus::Active,
        "none of it convicted anyone"
    );
    chain.audit();
}

#[test]
fn evidence_older_than_the_evidence_window_is_refused() {
    let (mut chain, first, mut second) = chain_with_two_validators(5 * MIN_STAKE);
    let mut bytes = Vec::new();
    equivocation(1, first.address(), 1).encode(&mut bytes);
    // A day past the 14-day window.
    chain.block_after(15 * DAY_MS, Vec::new());
    let report = second.staking(SUBMIT_EVIDENCE, vec![vector_arg(&bytes)]);
    assert_eq!(chain.run(report), aborted(AbortReason::EvidenceRefused));
    chain.audit();
}

// ---- rewards -------------------------------------------------------------

#[test]
fn an_epoch_of_blocks_mints_inflation_into_the_validators_pools() {
    let (mut chain, operator) = {
        let mut chain = Chain::new();
        let mut operator = Actor::new(1);
        // A large supply, so a few minutes of 4% is a visible number.
        chain.fund(&operator, 10_000_000_000_000);
        let tx = operator.register(1, MIN_STAKE * 1_000);
        assert_eq!(chain.run(tx), SUCCESS);
        (chain, operator)
    };
    let id = ValidatorId(operator.address());

    // Run to the block before the first epoch boundary, a minute apart.
    while chain.executor.head_height().unwrap() < EPOCH_BLOCKS - 1 {
        chain.block_after(60_000, Vec::new());
    }
    let supply_before = chain.executor.supply().unwrap();
    let pooled_before = chain
        .executor
        .with_registry(|r| r.total_pooled_stake().unwrap());
    let clock_started_at = START_MS + 1_000; // the first block's timestamp
    assert_eq!(supply_before, chain.executor.supply().unwrap());

    // The boundary block pays.
    chain.block_after(60_000, Vec::new());
    assert_eq!(chain.executor.head_height().unwrap(), EPOCH_BLOCKS);
    let elapsed = chain.now_ms - clock_started_at;
    let expected = reward_for(supply_before, 400, elapsed);
    assert!(
        expected > 0,
        "the test is only meaningful if something is paid"
    );

    assert_eq!(chain.executor.supply().unwrap(), supply_before + expected);
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.total_pooled_stake().unwrap()),
        pooled_before + expected,
        "all of it went into the one validator's pool"
    );
    assert!(
        chain
            .executor
            .with_registry(|r| r.stake_of(&id, &operator.address()).unwrap())
            > MIN_STAKE * 1_000,
        "and raised the share price"
    );
    chain.audit();
}

#[test]
fn an_ordinary_block_pays_no_rewards_and_a_long_halt_is_not_paid_for_in_full() {
    let mut chain = Chain::new();
    let mut operator = Actor::new(1);
    chain.fund(&operator, 10_000_000_000_000);
    let tx = operator.register(1, MIN_STAKE * 1_000);
    assert_eq!(chain.run(tx), SUCCESS);
    let supply = chain.executor.supply().unwrap();

    for _ in 0..5 {
        chain.block(Vec::new());
    }
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply,
        "no rewards off the boundary"
    );

    // Reach the boundary after an absurdly long gap: the payout is for at
    // most a day.
    while chain.executor.head_height().unwrap() < EPOCH_BLOCKS - 1 {
        chain.block(Vec::new());
    }
    let before = chain.executor.supply().unwrap();
    chain.block_after(365 * DAY_MS, Vec::new());
    let minted = chain.executor.supply().unwrap() - before;
    assert_eq!(minted, reward_for(before, 400, DAY_MS));
    chain.audit();
}

// ---- determinism ---------------------------------------------------------

#[test]
fn two_nodes_running_the_same_native_transactions_reach_the_same_state() {
    let run = || {
        let (mut chain, mut operator) = chain_with_validator();
        let mut delegator = Actor::new(2);
        chain.fund(&delegator, 100_000);
        let stake = delegator.staking(
            STAKE,
            vec![address_arg(operator.address()), u128_arg(40_000)],
        );
        let submit = operator.governance(SUBMIT_PROPOSAL, vec![inflation_proposal(700)]);
        chain.block(vec![stake, submit]);
        chain.block_after(VOTING_PERIOD_MS, Vec::new());
        chain.executor.state_root()
    };
    assert_eq!(run(), run());
}

// ---- storage deposit on delegation and proposals --------------------------

#[test]
fn a_first_delegation_pays_the_entry_deposit_and_a_top_up_does_not() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(7);
    chain.fund(&delegator, 100_000_000);
    let validator = operator.address();
    let start = chain.balance(delegator.address());
    let supply = chain.executor.supply().unwrap();

    let first = delegator.staking(STAKE, vec![address_arg(validator), u128_arg(1_000)]);
    assert_eq!(chain.run(first), SUCCESS);
    assert_eq!(
        chain.balance(delegator.address()),
        start - 1_000 - NEW_ENTRY_STORAGE_DEPOSIT - FEE
    );
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - NEW_ENTRY_STORAGE_DEPOSIT - FEE,
        "the deposit is burned, not moved"
    );

    let after_first = chain.balance(delegator.address());
    let top_up = delegator.staking(STAKE, vec![address_arg(validator), u128_arg(1_000)]);
    assert_eq!(chain.run(top_up), SUCCESS);
    assert_eq!(
        chain.balance(delegator.address()),
        after_first - 1_000 - FEE,
        "adding to an existing delegation creates nothing"
    );
    chain.audit();
}

#[test]
fn a_delegation_that_cannot_afford_its_entry_deposit_aborts_and_pays_only_the_fee() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(8);
    // Enough for the stake and the fee, not the deposit.
    chain.fund(
        &delegator,
        1_000 + FEE + NEW_ENTRY_STORAGE_DEPOSIT.div_euclid(2),
    );
    let tx = delegator.staking(
        STAKE,
        vec![address_arg(operator.address()), u128_arg(1_000)],
    );
    assert_eq!(chain.run(tx), aborted(AbortReason::InsufficientBalance));
    assert_eq!(
        chain.balance(delegator.address()),
        1_000 + NEW_ENTRY_STORAGE_DEPOSIT.div_euclid(2),
        "nothing but the fee was taken"
    );
    chain.audit();
}

#[test]
fn opening_a_proposal_pays_for_the_snapshot_it_creates() {
    let (mut chain, mut operator) = chain_with_validator();
    let before = chain.balance(operator.address());
    let supply = chain.executor.supply().unwrap();
    let tx = operator.governance(SUBMIT_PROPOSAL, vec![min_self_stake_proposal(MIN_STAKE)]);
    assert_eq!(chain.run(tx), SUCCESS);
    let paid = before - chain.balance(operator.address());
    assert!(
        paid > FEE && (paid - FEE).is_multiple_of(NEW_ENTRY_STORAGE_DEPOSIT),
        "whole deposits on top of the fee, got {paid}"
    );
    assert_eq!(chain.executor.supply().unwrap(), supply - paid);
    chain.audit();
}

// ---- unbonding entries pay for themselves ----------------------------------

#[test]
fn a_stake_worth_less_than_an_unbonding_entry_buys_no_entry_and_is_forfeited() {
    // Otherwise dust from many accounts fills a validator's unbonding queue
    // and nobody else can unstake from it for three weeks.
    let (mut chain, operator) = chain_with_validator();
    let mut griefer = Actor::new(9);
    chain.fund(&griefer, 1_000_000_000);
    let id = ValidatorId(operator.address());
    let dust = UNBONDING_ENTRY_STORAGE_DEPOSIT.div_euclid(2);
    let stake = griefer.staking(STAKE, vec![address_arg(operator.address()), u128_arg(dust)]);
    assert_eq!(chain.run(stake), SUCCESS);
    let shares = chain
        .executor
        .with_registry(|r| r.shares_of(&id, &griefer.address()).unwrap());
    let entries = chain.executor.with_registry(|r| r.unbonding_entry_count());
    let supply = chain.executor.supply().unwrap();

    let unstake = griefer.staking(
        UNSTAKE,
        vec![address_arg(operator.address()), u128_arg(shares)],
    );
    assert_eq!(chain.run(unstake), SUCCESS);
    assert_eq!(
        chain.executor.with_registry(|r| r.unbonding_entry_count()),
        entries,
        "no entry was opened"
    );
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - dust - FEE,
        "what the shares were worth was burned"
    );
    chain.audit();
}

#[test]
fn a_larger_unstake_pays_the_entry_deposit_out_of_its_own_proceeds() {
    let (mut chain, operator) = chain_with_validator();
    let mut delegator = Actor::new(10);
    chain.fund(&delegator, 1_000_000_000);
    let id = ValidatorId(operator.address());
    let staked: u128 = 500_000_000;
    let stake = delegator.staking(
        STAKE,
        vec![address_arg(operator.address()), u128_arg(staked)],
    );
    assert_eq!(chain.run(stake), SUCCESS);
    let shares = chain
        .executor
        .with_registry(|r| r.shares_of(&id, &delegator.address()).unwrap());
    let supply = chain.executor.supply().unwrap();

    let unstake = delegator.staking(
        UNSTAKE,
        vec![address_arg(operator.address()), u128_arg(shares)],
    );
    assert_eq!(chain.run(unstake), SUCCESS);
    assert_eq!(
        chain
            .executor
            .with_registry(|r| r.total_unbonding().unwrap()),
        staked - UNBONDING_ENTRY_STORAGE_DEPOSIT
    );
    assert_eq!(
        chain.executor.supply().unwrap(),
        supply - UNBONDING_ENTRY_STORAGE_DEPOSIT - FEE
    );
    chain.audit();
}
