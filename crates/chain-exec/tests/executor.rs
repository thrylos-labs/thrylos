//! Integration tests for the real (narrowly-scoped) `Executor` — the
//! full `propose_block` -> `execute_block` -> `finalise_block` pipeline
//! against real chain-state, not just the MoveVM proof-of-life.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chain_engine_api::{BlockLimits, Engine, FinaliseErrorReason, RejectionReason};
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
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
    let body = TransactionBody {
        chain_id: ChainId(chain_id),
        sender,
        sequence_number: SequenceNumber(sequence_number),
        expiry: BlockHeight(1_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(1),
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
fn execute_rejects_a_call_to_a_different_function() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();

    let mut call = calculator_call(1, 1);
    call.function_name = b"subtract".to_vec();
    let tx = signed_transaction(3, 1, call);
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
    // Two keys changed: the counter object's bumped value, and the
    // sender's account (gas debited, sequence number advanced). The
    // diff is what `chain-db` would persist instead of the whole
    // state, so it has to reflect the real writes, not the genesis
    // state's other untouched keys.
    assert_eq!(executed.state_diff.len(), 2);
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
fn bump_rejects_without_declaring_the_counter_as_an_input() {
    // `docs/spec.md`, "Execution": "Transactions declare the objects
    // they access before execution" — omitting the declaration must be
    // rejected, not silently resolved anyway.
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let tx = signed_transaction_with_inputs(13, 1, Vec::new(), bump_call(5));
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
    assert_eq!(
        executor.read_counter(),
        Some(0),
        "a rejected block must not mutate anything"
    );
}

#[test]
fn bump_rejects_a_declared_input_that_is_not_the_counter() {
    let mut executor = Executor::genesis(ChainId(1)).unwrap();
    let wrong_address = Address::from_bytes([0xAAu8; 32]);
    let tx = signed_transaction_with_inputs(14, 1, vec![wrong_address], bump_call(5));
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
