#![no_main]

//! Publishing arbitrary bytes as a Move package. A publish must never panic,
//! never reject its block, and only ever succeed or be refused as a publish
//! (or run the sender out of balance); and when it succeeds the package is in
//! the state diff under its derived address. Inputs either split the fuzzer's
//! bytes into modules, or mutate byte positions of real compiled modules
//! (`fuzz/seeds`), so most inputs get past the format check and reach the
//! verifier, the dependency check and the VM's own validation.

use std::cell::RefCell;

use chain_engine_api::{
    AbortReason, BlockLimits, Engine, TransactionOutcome, GENESIS_MAX_BLOCK_GAS,
};
use chain_exec::keys::package_key;
use chain_exec::publish::{package_address, MOVE_MODULE_NAME, MOVE_PACKAGE_ADDRESS, PUBLISH};
use chain_exec::Executor;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;

const SEEDS: [&[u8]; 3] = [
    include_bytes!("../seeds/hello.mv"),
    include_bytes!("../seeds/first.mv"),
    include_bytes!("../seeds/second.mv"),
];
const SENDER_SEED: u8 = 9;
const GAS_LIMIT: u64 = 400_000;

thread_local! {
    static EXECUTOR: RefCell<Executor> = RefCell::new(executor());
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[SENDER_SEED; 32])
}

fn public() -> PublicKey {
    PublicKey::from_ed25519_bytes(key().verifying_key().to_bytes())
        .unwrap_or_else(|error| panic!("fixed Ed25519 key is invalid: {error}"))
}

fn executor() -> Executor {
    let mut executor = Executor::genesis(ChainId(1))
        .unwrap_or_else(|error| panic!("fuzz executor failed to start: {error}"));
    executor
        .credit_account(Address::from_public_key(&public()), 1_000_000_000_000_000)
        .unwrap_or_else(|error| panic!("fuzz funding failed: {error}"));
    executor
}

/// The modules an input describes.
fn modules(input: &[u8]) -> Vec<Vec<u8>> {
    let (mode, rest) = input.split_first().map_or((0, &[][..]), |(m, r)| (*m, r));
    if mode % 4 == 0 {
        // The fuzzer's own bytes, cut into one to four modules.
        let count = usize::from(rest.first().copied().unwrap_or(0) % 4) + 1;
        let body = rest.get(1..).unwrap_or_default();
        let size = body.len().div_ceil(count).max(1);
        return body.chunks(size).map(<[u8]>::to_vec).collect();
    }
    // Real modules with bytes changed: three bytes an edit (position, value).
    let seeds: Vec<Vec<u8>> = match mode % 4 {
        1 => vec![SEEDS[0].to_vec()],
        2 => vec![SEEDS[1].to_vec(), SEEDS[2].to_vec()],
        _ => SEEDS.iter().map(|seed| seed.to_vec()).collect(),
    };
    let mut seeds = seeds;
    for edit in rest.chunks_exact(3) {
        let which = usize::from(edit[0]) % seeds.len();
        if let Some(module) = seeds.get_mut(which) {
            let position = usize::from(edit[1]) % module.len().max(1);
            if let Some(byte) = module.get_mut(position) {
                *byte = edit[2];
            }
        }
    }
    seeds
}

fn transaction(sequence: u64, arguments: Vec<Vec<u8>>) -> Transaction {
    let body = TransactionBody {
        chain_id: ChainId(1),
        sender: public(),
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(7_000),
        gas_limit: GasAmount(GAS_LIMIT),
        max_fee_per_gas: GasPrice(10),
        declared_inputs: Vec::new(),
        call: MoveCall {
            module_address: Address::from_bytes(MOVE_PACKAGE_ADDRESS),
            module_name: MOVE_MODULE_NAME.as_bytes().to_vec(),
            function_name: PUBLISH.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments,
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key().sign(&bytes).to_bytes()),
    }
}

fuzz_target!(|input: &[u8]| {
    EXECUTOR.with(|cell| {
        let executor = cell.borrow();
        let parent_root = executor.state_root();
        let tx = transaction(0, modules(input));
        let sender = tx.sender_address();
        let block = executor.propose_block(
            executor.tip_block_hash(),
            parent_root,
            BlockHeight(1),
            1_700_000_001_000,
            vec![tx],
            BlockLimits {
                max_gas: GENESIS_MAX_BLOCK_GAS,
                max_size_bytes: chain_engine_api::MAX_BLOCK_SIZE_BYTES,
            },
        );
        // Not proposed at all is fine (over a limit); a proposed one must run.
        if block.transactions.len() != 1 {
            return;
        }
        let executed = executor
            .execute_block(parent_root, &block)
            .unwrap_or_else(|error| panic!("a publish rejected its block: {error:?}"));
        match executed.outcomes[0] {
            TransactionOutcome::Success => {
                let id = package_address(&sender, 0);
                let wanted = package_key(id);
                assert!(
                    executed.state_diff.iter().any(|(key, _)| *key == wanted),
                    "a successful publish stored no package"
                );
            }
            TransactionOutcome::Aborted(AbortReason::PublishRefused) => {}
            other => panic!("a publish ended as {other:?}"),
        }
    });
});
