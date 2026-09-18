//! Integration tests for the real (narrowly-scoped) `Executor` — the
//! full `propose_block` -> `execute_block` -> `finalise_block` pipeline
//! against real chain-state, not just the MoveVM proof-of-life.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chain_engine_api::{BlockLimits, Engine, FinaliseErrorReason, RejectionReason};
use chain_exec::genesis::{SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME, SYSTEM_PACKAGE_ADDRESS};
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

fn signed_transaction(seed: u8, chain_id: u64, call: MoveCall) -> Transaction {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
    let body = TransactionBody {
        chain_id: ChainId(chain_id),
        sender,
        sequence_number: SequenceNumber(0),
        expiry: BlockHeight(1_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(1),
        declared_inputs: Vec::new(),
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
    let a = Executor::genesis().unwrap();
    let b = Executor::genesis().unwrap();
    assert_eq!(a.state_root(), b.state_root());
}

#[test]
fn full_pipeline_executes_a_real_transaction_and_commits_the_result() {
    let mut executor = Executor::genesis().unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let tx = signed_transaction(1, 1, calculator_call(2, 40));
    let sender = tx.sender_address();

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
    let executor = Executor::genesis().unwrap();
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
    let executor = Executor::genesis().unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);

    let mut call = calculator_call(1, 1);
    call.function_name = b"subtract".to_vec();
    let tx = signed_transaction(3, 1, call);

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
    let executor = Executor::genesis().unwrap();
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
    let mut executor = Executor::genesis().unwrap();
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
    };

    let result = executor.finalise_block(&block, &fabricated);
    assert_eq!(
        result.unwrap_err().reason,
        FinaliseErrorReason::NotOnCanonicalChain
    );
}

#[test]
fn finalise_rejects_a_tampered_executed_block() {
    let mut executor = Executor::genesis().unwrap();
    let (genesis_root, genesis_hash) = genesis_root_and_hash(&executor);
    let tx = signed_transaction(6, 1, calculator_call(2, 40));

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
