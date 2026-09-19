//! Integration tests for the real (narrowly-scoped) `Executor` — the
//! full `propose_block` -> `execute_block` -> `finalise_block` pipeline
//! against real chain-state, not just the MoveVM proof-of-life.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chain_engine_api::{
    AbortReason, BlockLimits, Engine, ExecutedBlock, FinaliseErrorReason, RejectionReason,
    TransactionOutcome,
};
use chain_exec::genesis::{
    COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME, COUNTER_PACKAGE_ADDRESS, INITIAL_COUNTER_ADDRESS,
    SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME, SYSTEM_PACKAGE_ADDRESS,
};
use chain_exec::Executor;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, Hash, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

fn genesis_root_and_hash(executor: &Executor) -> (chain_state::StateRoot, Hash) {
    (executor.state_root(), executor.tip_block_hash())
}

fn calculator_call(a: u64, b: u64) -> MoveCall {
    MoveCall {
        module_address: Address::from_bytes(SYSTEM_PACKAGE_ADDRESS.into_bytes()),
        module_name: SYSTEM_MODULE_NAME.as_bytes().to_vec(),
        function_name: SYSTEM_FUNCTION_NAME.as_bytes().to_vec(),
        type_arguments: Vec::new(),
        arguments: vec![a.to_le_bytes().to_vec(), b.to_le_bytes().to_vec()],
    }
}

fn bump_call(amount: u64) -> MoveCall {
    MoveCall {
        module_address: Address::from_bytes(COUNTER_PACKAGE_ADDRESS.into_bytes()),
        module_name: COUNTER_MODULE_NAME.as_bytes().to_vec(),
        function_name: COUNTER_BUMP_FUNCTION.as_bytes().to_vec(),
        type_arguments: Vec::new(),
        arguments: vec![amount.to_le_bytes().to_vec()],
    }
}

fn counter_address() -> Address {
    Address::from_bytes(INITIAL_COUNTER_ADDRESS.into_bytes())
}

fn signed_transaction(seed: u8, chain_id: u64, call: MoveCall) -> Transaction {
    signed_transaction_with_inputs(seed, chain_id, Vec::new(), call)
}

fn signed_transaction_with_inputs(
    seed: u8,
    chain_id: u64,
    declared_inputs: Vec<Address>,
    call: MoveCall,
) -> Transaction {
    signed_transaction_full(seed, chain_id, 0, declared_inputs, call)
}

fn signed_transaction_full(
    seed: u8,
    chain_id: u64,
    sequence_number: u64,
    declared_inputs: Vec<Address>,
    call: MoveCall,
) -> Transaction {
    signed_transaction_priced(
        seed,
        chain_id,
        sequence_number,
        1_000,
        1,
        declared_inputs,
        call,
    )
}

/// Like [`signed_transaction_full`], with the gas limit and the
/// `max_fee_per_gas` ceiling under the caller's control.
fn signed_transaction_priced(
    seed: u8,
    chain_id: u64,
    sequence_number: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    declared_inputs: Vec<Address>,
    call: MoveCall,
) -> Transaction {
    signed_transaction_expiring(
        seed,
        chain_id,
        sequence_number,
        1_000,
        gas_limit,
        max_fee_per_gas,
        declared_inputs,
        call,
    )
}

/// Like [`signed_transaction_priced`], with the expiry height under the
/// caller's control too.
#[allow(clippy::too_many_arguments)]
fn signed_transaction_expiring(
    seed: u8,
    chain_id: u64,
    sequence_number: u64,
    expiry: u64,
    gas_limit: u64,
    max_fee_per_gas: u64,
    declared_inputs: Vec<Address>,
    call: MoveCall,
) -> Transaction {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
    let body = TransactionBody {
        chain_id: ChainId(chain_id),
        sender,
        sequence_number: SequenceNumber(sequence_number),
        expiry: BlockHeight(expiry),
        gas_limit: GasAmount(gas_limit),
        max_fee_per_gas: GasPrice(max_fee_per_gas),
        declared_inputs,
        call,
    };
    let mut signing_bytes = Vec::new();
    body.encode(&mut signing_bytes);
    let raw_sig = signing_key.sign(&signing_bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(raw_sig.to_bytes()),
    }
}

/// The first block's timestamp in these tests, and the step between blocks.
const FIRST_TIMESTAMP: u64 = 1_700_000_000_000;

/// What the very first block writes that no later one does: the reward
/// clock is started, and the first time checkpoint is kept.
const FIRST_BLOCK_BOOKKEEPING: usize = 2;
const BLOCK_INTERVAL_MS: u64 = 1_000;

/// Height and timestamp for the block after the executor's current head:
/// one higher, and one interval later.
fn next_height_and_timestamp(executor: &Executor) -> (BlockHeight, u64) {
    let height = BlockHeight(executor.head_height().unwrap().saturating_add(1));
    let timestamp = match executor.head_timestamp_millis().unwrap() {
        0 => FIRST_TIMESTAMP,
        previous => previous.saturating_add(BLOCK_INTERVAL_MS),
    };
    (height, timestamp)
}

/// Proposes, executes and finalises `transactions` as the next block on
/// top of the executor's current tip, returning what execution produced.
fn execute_and_finalise(executor: &mut Executor, transactions: Vec<Transaction>) -> ExecutedBlock {
    let parent_root = executor.state_root();
    let (height, timestamp) = next_height_and_timestamp(executor);
    let block = executor.propose_block(
        executor.tip_block_hash(),
        parent_root,
        height,
        timestamp,
        transactions,
        default_limits(),
    );
    let executed = executor.execute_block(parent_root, &block).unwrap();
    executor.finalise_block(&block, &executed).unwrap();
    executed
}

fn fund(executor: &mut Executor, tx: &Transaction) {
    executor
        .credit_account(tx.sender_address(), 1_000_000)
        .unwrap();
}

fn default_limits() -> BlockLimits {
    BlockLimits {
        max_gas: 60_000_000,
        max_size_bytes: 4 * 1024 * 1024,
    }
}

#[test]
fn genesis_state_root_is_deterministic() {
    let a = Executor::genesis(ChainId(1)).unwrap();
    let b = Executor::genesis(ChainId(1)).unwrap();
    assert_eq!(a.state_root(), b.state_root());
}

#[test]
fn full_pipeline_executes_a_real_transaction_and_commits_the_result() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();

    let tx = signed_transaction(1, 1, calculator_call(2, 40));
    let sender = tx.sender_address();
    executor.credit_account(sender, 1_000_000).unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![tx],
        default_limits(),
    );
    assert_eq!(
        block.transactions.len(),
        1,
        "the transaction should be packed in"
    );

    let executed = executor.execute_block(genesis_root, &block).unwrap();
    assert_eq!(executed.gas_used, 1_000);
    // execute_block must not have mutated the executor's committed state.
    assert_eq!(executor.state_root(), genesis_root);

    executor.finalise_block(&block, &executed).unwrap();
    assert_eq!(executor.state_root(), executed.state_root);
    assert_ne!(
        executor.state_root(),
        genesis_root,
        "the write must show up in the root"
    );
    assert_eq!(executor.tip_block_hash(), block.hash());

    // The actual computed sum landed in state under the sender's key.
    assert_eq!(executor.read_result(&sender), Some(42));
}

#[test]
fn execute_rejects_a_transaction_with_a_bad_signature() {
    let executor = Executor::genesis(ChainId(1)).unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let mut tx = signed_transaction(2, 1, calculator_call(1, 1));
    tx.body.sequence_number = SequenceNumber(1); // invalidates the signature

    let block = chain_engine_api::Block {
        parent_block_hash: genesis_hash,
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };

    let result = executor.execute_block(genesis_root, &block);
    assert_eq!(
        result.unwrap_err().reason,
        RejectionReason::InvalidSignature
    );
}

#[test]
fn an_unknown_function_aborts_the_transaction_but_not_the_block() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();

    let mut call = calculator_call(1, 1);
    call.function_name = b"subtract".to_vec();
    let tx = signed_transaction(3, 1, call);
    let sender = tx.sender_address();
    fund(&mut executor, &tx);

    let executed = execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(
        executed.outcomes,
        vec![TransactionOutcome::Aborted(AbortReason::UnknownFunction)]
    );

    // Included, so charged and sequenced — even though it did nothing.
    let account = executor.read_account(sender).unwrap();
    assert_eq!(account.balance, 1_000_000 - 1_000);
    assert_eq!(account.next_sequence_number, SequenceNumber(1));
}

#[test]
fn execute_rejects_a_block_on_the_wrong_parent() {
    let executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(4, 1, calculator_call(1, 1));

    let block = chain_engine_api::Block {
        parent_block_hash: Hash::from_bytes([0xFFu8; 32]), // wrong parent
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };

    let result = executor.execute_block(executor.state_root(), &block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::MalformedBlock);
}

#[test]
fn finalise_rejects_a_block_that_does_not_extend_the_current_tip() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(5, 1, calculator_call(1, 1));

    let block = chain_engine_api::Block {
        parent_block_hash: Hash::from_bytes([0xFFu8; 32]),
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };
    let fabricated = chain_engine_api::ExecutedBlock {
        state_root: executor.state_root(),
        gas_used: 0,
        state_diff: chain_state::StateDiff::empty(),
        outcomes: Vec::new(),
    };

    let result = executor.finalise_block(&block, &fabricated);
    assert_eq!(
        result.unwrap_err().reason,
        FinaliseErrorReason::NotOnCanonicalChain
    );
}

#[test]
fn finalise_rejects_a_tampered_executed_block() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(6, 1, calculator_call(2, 40));
    executor
        .credit_account(tx.sender_address(), 1_000_000)
        .unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![tx],
        default_limits(),
    );
    let mut executed = executor.execute_block(genesis_root, &block).unwrap();
    executed.gas_used += 1; // tamper with the claimed result

    let result = executor.finalise_block(&block, &executed);
    assert_eq!(
        result.unwrap_err().reason,
        FinaliseErrorReason::StateRootMismatch
    );
}

#[test]
fn genesis_counter_starts_at_zero() {
    let executor = Executor::genesis(ChainId(1)).unwrap();
    assert_eq!(executor.read_counter(), Some(0));
}

#[test]
fn bump_mutates_the_counter_object_and_the_write_is_readable_back() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction_with_inputs(10, 1, vec![counter_address()], bump_call(5));
    executor
        .credit_account(tx.sender_address(), 1_000_000)
        .unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![tx],
        default_limits(),
    );
    let executed = executor.execute_block(genesis_root, &block).unwrap();
    // Keys changed: the counter object's bumped value, the sender's
    // account (gas debited, sequence number advanced), the supply (the
    // fee is burned), the chain head (the block's own height and
    // timestamp), and the first block's bookkeeping. The
    // diff is what `chain-db` would persist instead of the whole
    // state, so it has to reflect the real writes, not the genesis
    // state's other untouched keys.
    assert_eq!(executed.state_diff.len(), 4 + FIRST_BLOCK_BOOKKEEPING);
    executor.finalise_block(&block, &executed).unwrap();

    assert_eq!(executor.read_counter(), Some(5));
    assert_eq!(executor.state_root(), executed.state_root);
}

#[test]
fn bump_accumulates_across_multiple_transactions_in_the_same_block() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let first = signed_transaction_with_inputs(11, 1, vec![counter_address()], bump_call(3));
    let second = signed_transaction_with_inputs(12, 1, vec![counter_address()], bump_call(4));
    executor
        .credit_account(first.sender_address(), 1_000_000)
        .unwrap();
    executor
        .credit_account(second.sender_address(), 1_000_000)
        .unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![first, second],
        default_limits(),
    );
    assert_eq!(block.transactions.len(), 2);

    let executed = executor.execute_block(genesis_root, &block).unwrap();
    executor.finalise_block(&block, &executed).unwrap();

    // The second bump must see the first bump's write within the same
    // block, not a stale pre-block value.
    assert_eq!(executor.read_counter(), Some(7));
}

#[test]
fn bump_without_declaring_the_counter_aborts_and_leaves_it_untouched() {
    // `docs/spec.md`, "Execution": "A transaction touching an object it
    // did not declare aborts rather than being resolved dynamically" —
    // an abort, not a block rejection, and not silently resolved anyway.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction_with_inputs(13, 1, Vec::new(), bump_call(5));
    let sender = tx.sender_address();
    fund(&mut executor, &tx);

    let executed = execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(
        executed.outcomes,
        vec![TransactionOutcome::Aborted(
            AbortReason::UndeclaredObjectAccess
        )]
    );
    assert_eq!(executor.read_counter(), Some(0), "an abort must not write");
    assert_eq!(
        executor.read_account(sender).unwrap().next_sequence_number,
        SequenceNumber(1)
    );
}

#[test]
fn bump_declaring_a_different_object_aborts_as_undeclared_access() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let wrong_address = Address::from_bytes([0xAAu8; 32]);
    let tx = signed_transaction_with_inputs(14, 1, vec![wrong_address], bump_call(5));
    fund(&mut executor, &tx);

    let executed = execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(
        executed.outcomes,
        vec![TransactionOutcome::Aborted(
            AbortReason::UndeclaredObjectAccess
        )]
    );
    assert_eq!(executor.read_counter(), Some(0));
}

#[test]
fn bump_may_declare_more_objects_than_it_touches() {
    // "Every object touched is listed" is a superset rule: declaring
    // extra inputs is fine, only omitting one it touches is not.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let extra = Address::from_bytes([0xBBu8; 32]);
    let tx = signed_transaction_with_inputs(24, 1, vec![extra, counter_address()], bump_call(5));
    fund(&mut executor, &tx);

    let executed = execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(executed.outcomes, vec![TransactionOutcome::Success]);
    assert_eq!(executor.read_counter(), Some(5));
}

#[test]
fn a_call_with_the_wrong_arguments_aborts_as_invalid_arguments() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();

    let mut no_amount = bump_call(0);
    no_amount.arguments = Vec::new();
    let bump = signed_transaction_with_inputs(25, 1, vec![counter_address()], no_amount);

    let mut short_arg = calculator_call(1, 1);
    short_arg.arguments = vec![vec![1, 2, 3], 1u64.to_le_bytes().to_vec()]; // 3 bytes, not 8
    let add = signed_transaction(26, 1, short_arg);

    fund(&mut executor, &bump);
    fund(&mut executor, &add);
    let executed = execute_and_finalise(&mut executor, vec![bump, add]);
    assert_eq!(
        executed.outcomes,
        vec![
            TransactionOutcome::Aborted(AbortReason::InvalidArguments),
            TransactionOutcome::Aborted(AbortReason::InvalidArguments),
        ]
    );
}

#[test]
fn a_move_abort_charges_gas_and_rolls_back_but_the_block_carries_on() {
    // u64::MAX + 1 aborts inside Move ("arithmetic aborts rather than
    // wrapping"). The transaction after it in the same block must still
    // run: aborts "never abort the block".
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let overflowing = signed_transaction(30, 1, calculator_call(u64::MAX, 1));
    let fine = signed_transaction(31, 1, calculator_call(2, 40));
    let (overflowing_sender, fine_sender) = (overflowing.sender_address(), fine.sender_address());
    fund(&mut executor, &overflowing);
    fund(&mut executor, &fine);

    let executed = execute_and_finalise(&mut executor, vec![overflowing, fine]);
    assert_eq!(
        executed.outcomes,
        vec![
            TransactionOutcome::Aborted(AbortReason::ExecutionFailed),
            TransactionOutcome::Success,
        ]
    );
    // Both were charged the same stand-in gas.
    assert_eq!(executed.gas_used, 2_000);

    assert_eq!(
        executor.read_result(&overflowing_sender),
        None,
        "the aborted call's write must have been rolled back"
    );
    assert_eq!(executor.read_result(&fine_sender), Some(42));

    let charged = executor.read_account(overflowing_sender).unwrap();
    assert_eq!(charged.balance, 1_000_000 - 1_000);
    assert_eq!(charged.next_sequence_number, SequenceNumber(1));
}

#[test]
fn an_aborted_transaction_cannot_be_replayed() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(32, 1, calculator_call(u64::MAX, 1));
    fund(&mut executor, &tx);
    execute_and_finalise(&mut executor, vec![tx.clone()]);

    // Aborting used up sequence number 0, so this is now a replay — a
    // validity failure, which does reject the block.
    let replay_block = chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(2),
        timestamp_millis: 1_700_000_000_001,
        transactions: vec![tx],
    };
    let result = executor.execute_block(executor.state_root(), &replay_block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::Rejected);
}

#[test]
fn an_invalid_transaction_still_rejects_the_whole_block_even_after_an_abort() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let aborting = signed_transaction(33, 1, calculator_call(u64::MAX, 1));
    let gap = signed_transaction_full(34, 1, 5, Vec::new(), calculator_call(1, 1)); // skips ahead
    fund(&mut executor, &aborting);
    fund(&mut executor, &gap);

    let block = chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![aborting, gap],
    };
    let rejected = executor
        .execute_block(executor.state_root(), &block)
        .unwrap_err();
    assert_eq!(rejected.reason, RejectionReason::Rejected);
    assert_eq!(
        rejected.transaction_index,
        Some(1),
        "the abort at index 0 is fine; the gap at index 1 is what rejects"
    );
}

#[test]
fn an_aborted_transactions_diff_is_only_the_senders_account() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction_with_inputs(35, 1, Vec::new(), bump_call(5)); // undeclared: aborts
    fund(&mut executor, &tx);

    let executed = execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(
        executed.state_diff.len(),
        3 + FIRST_BLOCK_BOOKKEEPING,
        "the sender's gas and sequence number, the supply the fee came out of, and the \
         chain head every block writes: the only effects of an abort"
    );
}

#[test]
fn finalise_rejects_tampered_outcomes() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(36, 1, calculator_call(2, 40));
    fund(&mut executor, &tx);
    let parent_root = executor.state_root();
    let block = executor.propose_block(
        executor.tip_block_hash(),
        parent_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![tx],
        default_limits(),
    );
    let mut executed = executor.execute_block(parent_root, &block).unwrap();
    executed.outcomes = vec![TransactionOutcome::Aborted(AbortReason::ExecutionFailed)];

    let result = executor.finalise_block(&block, &executed);
    assert_eq!(
        result.unwrap_err().reason,
        FinaliseErrorReason::StateRootMismatch
    );
}

#[test]
fn execute_rejects_a_transaction_with_the_wrong_chain_id() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(15, 2, calculator_call(1, 1)); // chain 2, executor is chain 1
    executor
        .credit_account(tx.sender_address(), 1_000_000)
        .unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = chain_engine_api::Block {
        parent_block_hash: genesis_hash,
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };

    let result = executor.execute_block(genesis_root, &block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::WrongChainId);
}

#[test]
fn execute_rejects_a_transaction_the_sender_cannot_afford() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(16, 1, calculator_call(1, 1)); // gas_limit 1_000 * price 1 = 1_000
    executor.credit_account(tx.sender_address(), 999).unwrap(); // one short
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = chain_engine_api::Block {
        parent_block_hash: genesis_hash,
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };

    let result = executor.execute_block(genesis_root, &block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::Rejected);
}

#[test]
fn execute_rejects_a_replayed_sequence_number() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let first = signed_transaction_full(17, 1, 0, Vec::new(), calculator_call(1, 1));
    let sender = first.sender_address();
    executor.credit_account(sender, 1_000_000).unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![first],
        default_limits(),
    );
    let executed = executor.execute_block(genesis_root, &block).unwrap();
    executor.finalise_block(&block, &executed).unwrap();
    assert_eq!(
        executor.read_account(sender).unwrap().next_sequence_number,
        SequenceNumber(1)
    );

    // The exact same (sender, sequence_number) pair again: a replay,
    // now that the sender's next expected sequence number is 1.
    let replay = signed_transaction_full(17, 1, 0, Vec::new(), calculator_call(1, 1));
    let second_block = chain_engine_api::Block {
        parent_block_hash: block.hash(),
        height: BlockHeight(2),
        timestamp_millis: 1_700_000_000_001,
        transactions: vec![replay],
    };
    let result = executor.execute_block(executor.state_root(), &second_block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::Rejected);
}

#[test]
fn execute_rejects_a_sequence_number_that_skips_ahead() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    // A brand-new sender's next expected sequence number is 0; this
    // transaction presents 1, a gap.
    let tx = signed_transaction_full(18, 1, 1, Vec::new(), calculator_call(1, 1));
    executor
        .credit_account(tx.sender_address(), 1_000_000)
        .unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = chain_engine_api::Block {
        parent_block_hash: genesis_hash,
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };

    let result = executor.execute_block(genesis_root, &block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::Rejected);
}

#[test]
fn a_successful_transaction_debits_gas_and_advances_the_sequence_number() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction(19, 1, calculator_call(2, 40)); // gas_limit 1_000 * price 1
    let sender = tx.sender_address();
    executor.credit_account(sender, 1_000_000).unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let block = executor.propose_block(
        genesis_hash,
        genesis_root,
        BlockHeight(1),
        1_700_000_000_000,
        vec![tx],
        default_limits(),
    );
    let executed = executor.execute_block(genesis_root, &block).unwrap();
    executor.finalise_block(&block, &executed).unwrap();

    let account = executor.read_account(sender).unwrap();
    assert_eq!(account.balance, 1_000_000 - 1_000);
    assert_eq!(account.next_sequence_number, SequenceNumber(1));
}

/// A block-filling transaction: `gas_limit` gas, which the executor
/// charges in full as a stand-in for real metering.
fn heavy_transaction(seed: u8, sequence_number: u64, gas_limit: u64, max_fee: u64) -> Transaction {
    signed_transaction_priced(
        seed,
        1,
        sequence_number,
        gas_limit,
        max_fee,
        Vec::new(),
        calculator_call(1, 1),
    )
}

const GENESIS_LIMIT: u64 = chain_engine_api::GENESIS_MAX_BLOCK_GAS;
/// The gas usage at which the base fee holds steady: half the limit.
const TARGET: u64 = 30_000_000;
const _: () = assert!(TARGET * 2 == GENESIS_LIMIT);

#[test]
fn genesis_seeds_the_base_fee_in_state() {
    let executor = Executor::genesis(ChainId(1)).unwrap();
    assert_eq!(executor.base_fee(), Some(1));
}

#[test]
fn a_transaction_is_charged_the_base_fee_not_its_max_fee() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    // A ceiling of 50 against a base fee of 1: 1_000 gas costs 1_000,
    // not 50_000.
    let tx = heavy_transaction(40, 0, 1_000, 50);
    let sender = tx.sender_address();
    executor.credit_account(sender, 1_000_000).unwrap();

    execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(
        executor.read_account(sender).unwrap().balance,
        1_000_000 - 1_000
    );
}

#[test]
fn a_transaction_whose_ceiling_is_below_the_base_fee_rejects_the_block() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    // Free to check against a balance, but it can never pay the base fee.
    let tx = heavy_transaction(41, 0, 1_000, 0);
    fund(&mut executor, &tx);

    let block = chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![tx],
    };
    let rejected = executor
        .execute_block(executor.state_root(), &block)
        .unwrap_err();
    assert_eq!(rejected.reason, RejectionReason::Rejected);
    assert_eq!(rejected.transaction_index, Some(0));
}

#[test]
fn a_block_above_target_raises_the_next_base_fee_and_the_new_price_is_charged() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();

    // 60M gas is a completely full block: 1 + max(1 * 30M / 30M / 8, 1) = 2.
    let filler = heavy_transaction(42, 0, GENESIS_LIMIT, 1);
    executor
        .credit_account(filler.sender_address(), 1_000_000_000)
        .unwrap();
    execute_and_finalise(&mut executor, vec![filler]);
    assert_eq!(executor.base_fee(), Some(2));

    // The next block charges 2, even though this sender's ceiling is 5.
    let next = heavy_transaction(43, 0, 1_000, 5);
    let sender = next.sender_address();
    executor.credit_account(sender, 1_000_000).unwrap();
    execute_and_finalise(&mut executor, vec![next]);
    assert_eq!(
        executor.read_account(sender).unwrap().balance,
        1_000_000 - 2_000
    );
}

#[test]
fn once_the_base_fee_has_risen_a_lower_ceiling_no_longer_clears_it() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let filler = heavy_transaction(44, 0, GENESIS_LIMIT, 1);
    executor
        .credit_account(filler.sender_address(), 1_000_000_000)
        .unwrap();
    execute_and_finalise(&mut executor, vec![filler]);
    assert_eq!(executor.base_fee(), Some(2));

    // Ceiling 1 was enough at genesis and isn't now.
    let stale = heavy_transaction(45, 0, 1_000, 1);
    fund(&mut executor, &stale);
    let block = chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(2),
        timestamp_millis: 1_700_000_000_001,
        transactions: vec![stale],
    };
    let result = executor.execute_block(executor.state_root(), &block);
    assert_eq!(result.unwrap_err().reason, RejectionReason::Rejected);
}

#[test]
fn a_block_exactly_on_target_leaves_the_base_fee_alone() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = heavy_transaction(46, 0, TARGET, 1);
    executor
        .credit_account(tx.sender_address(), 1_000_000_000)
        .unwrap();
    execute_and_finalise(&mut executor, vec![tx]);
    assert_eq!(executor.base_fee(), Some(1));
}

#[test]
fn an_empty_block_does_not_take_the_base_fee_below_its_floor() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let executed = execute_and_finalise(&mut executor, Vec::new());
    assert_eq!(executor.base_fee(), Some(1));
    assert!(executed.outcomes.is_empty());
}

#[test]
fn sustained_load_raises_the_base_fee_and_idling_lowers_it_again() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    executor
        .credit_account(
            heavy_transaction(47, 0, 1, 1).sender_address(),
            u128::from(u64::MAX),
        )
        .unwrap();

    let mut previous = executor.base_fee().unwrap();
    for sequence in 0..40 {
        // Ceiling far above any fee reached, so only the base fee moves.
        let filler = heavy_transaction(47, sequence, GENESIS_LIMIT, 1_000_000);
        execute_and_finalise(&mut executor, vec![filler]);
        let fee = executor.base_fee().unwrap();
        assert!(fee > previous, "block {sequence}: {previous} -> {fee}");
        previous = fee;
    }
    let peak = previous;
    assert!(
        peak > 30,
        "40 full blocks should compound well past +1 each: {peak}"
    );

    for _ in 0..100 {
        execute_and_finalise(&mut executor, Vec::new());
        let fee = executor.base_fee().unwrap();
        // Lowered whenever the proportional step (fee / 8) is non-zero,
        // and never raised.
        if previous >= 8 {
            assert!(
                fee < previous,
                "an idle block must lower it: {previous} -> {fee}"
            );
        } else {
            assert_eq!(fee, previous);
        }
        previous = fee;
    }
    // Where an idle chain settles: the last value whose 1/8 step still
    // rounds to zero. See `chain_modules::fees`'s doc comment — the
    // reference rule's own floor, not `MIN_BASE_FEE`.
    assert_eq!(previous, 7);
    assert!(previous < peak);
}

#[test]
fn the_base_fee_moves_show_up_in_the_state_diff() {
    // A fee change is consensus state like any other: if it weren't in
    // the diff, `chain-db` would never persist it.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let filler = heavy_transaction(48, 0, GENESIS_LIMIT, 1);
    executor
        .credit_account(filler.sender_address(), 1_000_000_000)
        .unwrap();

    let executed = execute_and_finalise(&mut executor, vec![filler]);
    // calculator result + the sender's account + the base fee + the head
    // + the supply the fee was burned from.
    assert_eq!(executed.state_diff.len(), 5 + FIRST_BLOCK_BOOKKEEPING);
}

#[test]
fn a_block_over_the_gas_limit_is_rejected_as_malformed() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let first = heavy_transaction(49, 0, 40_000_000, 1);
    let second = heavy_transaction(50, 0, 40_000_000, 1); // 80M total > 60M
    executor
        .credit_account(first.sender_address(), 1_000_000_000)
        .unwrap();
    executor
        .credit_account(second.sender_address(), 1_000_000_000)
        .unwrap();

    let block = chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(1),
        timestamp_millis: 1_700_000_000_000,
        transactions: vec![first, second],
    };
    let rejected = executor
        .execute_block(executor.state_root(), &block)
        .unwrap_err();
    assert_eq!(rejected.reason, RejectionReason::MalformedBlock);
    assert_eq!(
        rejected.transaction_index, None,
        "the block as a whole is over the limit, not any one transaction"
    );
}

#[test]
fn a_block_exactly_at_the_gas_limit_is_accepted() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = heavy_transaction(51, 0, GENESIS_LIMIT, 1);
    executor
        .credit_account(tx.sender_address(), 1_000_000_000)
        .unwrap();
    execute_and_finalise(&mut executor, vec![tx]);
}

// ---- expiry, height and timestamp ---------------------------------------

/// A block on top of `executor`'s head with the given height, timestamp
/// and transactions, built by hand so a test can make either one wrong.
fn block_at(
    executor: &Executor,
    height: u64,
    timestamp_millis: u64,
    transactions: Vec<Transaction>,
) -> chain_engine_api::Block {
    chain_engine_api::Block {
        parent_block_hash: executor.tip_block_hash(),
        height: BlockHeight(height),
        timestamp_millis,
        transactions,
    }
}

fn expiring_at(seed: u8, sequence_number: u64, expiry: u64) -> Transaction {
    signed_transaction_expiring(
        seed,
        1,
        sequence_number,
        expiry,
        1_000,
        1,
        Vec::new(),
        calculator_call(1, 2),
    )
}

/// Advances `executor` through `count` empty blocks.
fn advance(executor: &mut Executor, count: u64) {
    for _ in 0..count {
        execute_and_finalise(executor, Vec::new());
    }
}

fn rejection_of(
    executor: &Executor,
    block: &chain_engine_api::Block,
) -> (RejectionReason, Option<u32>) {
    let rejected = executor
        .execute_block(executor.state_root(), block)
        .unwrap_err();
    (rejected.reason, rejected.transaction_index)
}

#[test]
fn a_transaction_is_valid_up_to_and_including_its_expiry_height_and_not_after() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    advance(&mut executor, 9); // the next block is height 10
    let at_expiry = expiring_at(60, 0, 10);
    let past_expiry = expiring_at(61, 0, 9);
    fund(&mut executor, &at_expiry);
    fund(&mut executor, &past_expiry);
    let (height, timestamp) = next_height_and_timestamp(&executor);
    assert_eq!(height, BlockHeight(10));

    let ok = block_at(&executor, height.0, timestamp, vec![at_expiry]);
    assert!(executor.execute_block(executor.state_root(), &ok).is_ok());

    let expired = block_at(&executor, height.0, timestamp, vec![past_expiry]);
    assert_eq!(
        rejection_of(&executor, &expired),
        (RejectionReason::InvalidExpiry, Some(0))
    );
}

#[test]
fn an_expired_transaction_rejects_the_whole_block_and_is_attributed_to_its_index() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    advance(&mut executor, 4); // the next block is height 5
    let fine = expiring_at(62, 0, 100);
    let stale = expiring_at(63, 0, 4);
    fund(&mut executor, &fine);
    fund(&mut executor, &stale);
    let (height, timestamp) = next_height_and_timestamp(&executor);

    let block = block_at(&executor, height.0, timestamp, vec![fine, stale]);
    assert_eq!(
        rejection_of(&executor, &block),
        (RejectionReason::InvalidExpiry, Some(1))
    );
}

#[test]
fn an_expiry_set_further_ahead_than_the_horizon_is_rejected_at_execution_too() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let horizon = chain_types::MAX_EXPIRY_HORIZON;
    let at_horizon = expiring_at(64, 0, 1 + horizon); // block height 1
    let beyond = expiring_at(65, 0, 1 + horizon + 1);
    fund(&mut executor, &at_horizon);
    fund(&mut executor, &beyond);
    let (height, timestamp) = next_height_and_timestamp(&executor);

    let ok = block_at(&executor, height.0, timestamp, vec![at_horizon]);
    assert!(executor.execute_block(executor.state_root(), &ok).is_ok());

    let too_far = block_at(&executor, height.0, timestamp, vec![beyond]);
    assert_eq!(
        rejection_of(&executor, &too_far),
        (RejectionReason::InvalidExpiry, Some(0))
    );
}

#[test]
fn a_transaction_that_expired_while_waiting_cannot_be_included_later() {
    // The point of the rule: signed at height 1, valid until 3, not
    // included in time — it must stay out for good, not merely for now.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = expiring_at(66, 0, 3);
    fund(&mut executor, &tx);

    advance(&mut executor, 2); // the next block is height 3: the last valid one
    let (height, timestamp) = next_height_and_timestamp(&executor);
    let still_ok = block_at(&executor, height.0, timestamp, vec![tx.clone()]);
    assert!(executor
        .execute_block(executor.state_root(), &still_ok)
        .is_ok());

    advance(&mut executor, 1); // height 3 passes without it
    let (height, timestamp) = next_height_and_timestamp(&executor);
    let too_late = block_at(&executor, height.0, timestamp, vec![tx]);
    assert_eq!(
        rejection_of(&executor, &too_late),
        (RejectionReason::InvalidExpiry, Some(0))
    );
}

#[test]
fn a_proposer_cannot_dodge_expiry_by_claiming_a_lower_height() {
    // Expiry is measured against the block's height, so the height has
    // to be pinned to the chain's, or the rule is decoration.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = expiring_at(67, 0, 3);
    fund(&mut executor, &tx);
    advance(&mut executor, 4); // the chain is at height 4; the tx expired at 3
    let (_, timestamp) = next_height_and_timestamp(&executor);

    let lying = block_at(&executor, 2, timestamp, vec![tx]);
    assert_eq!(
        rejection_of(&executor, &lying),
        (RejectionReason::InvalidBlockHeight, None)
    );
}

#[test]
fn a_block_must_be_exactly_one_higher_than_its_parent() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    assert_eq!(executor.head_height(), Some(0));

    for wrong in [0, 2, 1_000, u64::MAX] {
        let block = block_at(&executor, wrong, FIRST_TIMESTAMP, Vec::new());
        assert_eq!(
            rejection_of(&executor, &block),
            (RejectionReason::InvalidBlockHeight, None),
            "height {wrong} on a genesis parent"
        );
    }
    let right = block_at(&executor, 1, FIRST_TIMESTAMP, Vec::new());
    assert!(executor
        .execute_block(executor.state_root(), &right)
        .is_ok());

    advance(&mut executor, 1);
    assert_eq!(executor.head_height(), Some(1));
    // Repeating the height just executed is no better than skipping ahead.
    for wrong in [1, 3] {
        let block = block_at(
            &executor,
            wrong,
            FIRST_TIMESTAMP + 10 * BLOCK_INTERVAL_MS,
            Vec::new(),
        );
        assert_eq!(
            rejection_of(&executor, &block),
            (RejectionReason::InvalidBlockHeight, None)
        );
    }
}

#[test]
fn a_block_must_be_strictly_later_than_its_parent() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    advance(&mut executor, 1);
    let parent = executor.head_timestamp_millis().unwrap();
    assert_eq!(parent, FIRST_TIMESTAMP);

    for (label, timestamp) in [
        ("equal", parent),
        ("a millisecond earlier", parent - 1),
        ("zero", 0),
    ] {
        let block = block_at(&executor, 2, timestamp, Vec::new());
        assert_eq!(
            rejection_of(&executor, &block),
            (RejectionReason::InvalidBlockTimestamp, None),
            "{label}"
        );
    }
    let next = block_at(&executor, 2, parent + 1, Vec::new());
    assert!(
        executor.execute_block(executor.state_root(), &next).is_ok(),
        "a millisecond later is enough"
    );
}

#[test]
fn the_first_block_must_be_after_the_genesis_timestamp() {
    let executor = Executor::genesis(ChainId(1)).unwrap();
    assert_eq!(executor.head_timestamp_millis(), Some(0));
    let block = block_at(&executor, 1, 0, Vec::new());
    assert_eq!(
        rejection_of(&executor, &block),
        (RejectionReason::InvalidBlockTimestamp, None)
    );
}

#[test]
fn the_head_is_committed_in_the_state_root_and_the_diff() {
    // Two blocks alike in everything but their timestamp must land on
    // different states, or nodes could disagree about the parent a later
    // block is checked against without the roots ever showing it.
    let executor = Executor::genesis(ChainId(1)).unwrap();
    let executed_at = |timestamp: u64| {
        let block = block_at(&executor, 1, timestamp, Vec::new());
        executor
            .execute_block(executor.state_root(), &block)
            .unwrap()
    };
    let (a, b) = (
        executed_at(FIRST_TIMESTAMP),
        executed_at(FIRST_TIMESTAMP + 1),
    );
    assert_ne!(a.state_root, b.state_root);
    assert_eq!(
        a.state_diff.len(),
        1 + FIRST_BLOCK_BOOKKEEPING,
        "an empty block writes only the head, and the first one the bookkeeping"
    );
}

#[test]
fn finalising_advances_the_head() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    advance(&mut executor, 3);
    assert_eq!(executor.head_height(), Some(3));
    assert_eq!(
        executor.head_timestamp_millis(),
        Some(FIRST_TIMESTAMP + 2 * BLOCK_INTERVAL_MS)
    );
}

#[test]
fn a_rejected_block_leaves_the_head_where_it_was() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    advance(&mut executor, 1);
    let before = (executor.head_height(), executor.head_timestamp_millis());
    let root = executor.state_root();

    let bad = block_at(&executor, 5, FIRST_TIMESTAMP + 1, Vec::new());
    assert!(executor.execute_block(root, &bad).is_err());
    assert_eq!(
        (executor.head_height(), executor.head_timestamp_millis()),
        before
    );
    assert_eq!(executor.state_root(), root);
}

#[test]
fn finalise_refuses_a_block_whose_height_or_timestamp_is_wrong() {
    // `finalise_block` re-runs the checks rather than trusting the
    // caller's `ExecutedBlock`: a block that could not have executed
    // cannot be committed with someone else's result attached.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let good = block_at(&executor, 1, FIRST_TIMESTAMP, Vec::new());
    let executed = executor
        .execute_block(executor.state_root(), &good)
        .unwrap();

    let wrong_height = block_at(&executor, 2, FIRST_TIMESTAMP, Vec::new());
    assert_eq!(
        executor
            .finalise_block(&wrong_height, &executed)
            .unwrap_err()
            .reason,
        FinaliseErrorReason::StateRootMismatch
    );
    let wrong_time = block_at(&executor, 1, 0, Vec::new());
    assert_eq!(
        executor
            .finalise_block(&wrong_time, &executed)
            .unwrap_err()
            .reason,
        FinaliseErrorReason::StateRootMismatch
    );
    assert_eq!(executor.head_height(), Some(0), "nothing was committed");
}
