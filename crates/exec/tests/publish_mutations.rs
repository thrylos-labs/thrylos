//! A deterministic stand-in for the `move_publish` fuzz target, so its
//! invariant is checked on every test run and not only when a fuzzer is: no
//! byte-level mutation of a real module may panic, reject the block, or end
//! any way but success or a refused publish.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

// The same independent check and table mutator the fuzz target uses.
#[path = "../../../fuzz/oracle.rs"]
mod oracle;

use common::*;

use chain_engine_api::{AbortReason, BlockLimits, Engine, TransactionOutcome};
use chain_types::BlockHeight;

/// A small deterministic generator (xorshift), so a failure repeats.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn mutated_modules_only_ever_publish_or_are_refused() {
    let seeds: Vec<Vec<u8>> = compile(
        "module 0x0::hello { public fun answer(): u64 { 42 } public fun add(a: u64, b: u64): u64 { let mut i = 0; let mut s = a; while (i < b) { s = s + 1; i = i + 1; }; s } }
         module 0x0::other { public struct S has copy, drop { a: u64, b: vector<u8> } public fun f(x: u64): S { S { a: x, b: vector[] } } }",
    )
    .into_values()
    .collect();
    let (chain, mut publisher) = rich();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let (mut published, mut refused) = (0u32, 0u32);

    for round in 0..3_000u32 {
        let mut modules = seeds.clone();
        // Zero to four edits, some of them a single flipped bit.
        for _ in 0..(rng.next() % 5) {
            let which = (rng.next() as usize) % modules.len();
            let module = &mut modules[which];
            let position = (rng.next() as usize) % module.len();
            if rng.next().is_multiple_of(2) {
                module[position] ^= 1 << (rng.next() % 8);
            } else {
                module[position] = rng.next() as u8;
            }
        }
        // Sometimes truncate or extend.
        match rng.next() % 8 {
            0 => {
                let keep = (rng.next() as usize) % modules[0].len();
                modules[0].truncate(keep);
            }
            1 => modules[0].push(rng.next() as u8),
            2 => modules.truncate(1),
            _ => {}
        }

        // Never finalised: each round is run against the same starting state.
        let mut fresh = publisher.publish(modules);
        fresh.body.sequence_number = chain_types::SequenceNumber(0);
        let tx = publisher.resign(fresh);
        let root = chain.executor.state_root();
        let block = chain.executor.propose_block(
            chain.executor.tip_block_hash(),
            root,
            BlockHeight(chain.executor.head_height().unwrap() + 1),
            chain.now_ms + 1_000,
            vec![tx],
            BlockLimits {
                max_gas: u64::MAX,
                max_size_bytes: 4 * 1024 * 1024,
            },
        );
        assert_eq!(
            block.transactions.len(),
            1,
            "round {round} was not proposed"
        );
        let executed = chain
            .executor
            .execute_block(root, &block)
            .unwrap_or_else(|error| panic!("round {round} rejected its block: {error:?}"));
        match executed.outcomes[0] {
            TransactionOutcome::Success => published += 1,
            TransactionOutcome::Aborted(AbortReason::PublishRefused) => refused += 1,
            other => panic!("round {round} ended as {other:?}"),
        }
    }
    // The mutations must reach both outcomes, or the test proves little.
    assert!(published > 0, "no mutation ever published");
    assert!(refused > 0, "no mutation was ever refused");
    eprintln!("published {published}, refused {refused}");
}

const SEEDS: [&[u8]; 7] = [
    include_bytes!("../../../fuzz/seeds/hello.mv"),
    include_bytes!("../../../fuzz/seeds/first.mv"),
    include_bytes!("../../../fuzz/seeds/second.mv"),
    include_bytes!("../../../fuzz/seeds/own.mv"),
    include_bytes!("../../../fuzz/seeds/victim.mv"),
    include_bytes!("../../../fuzz/seeds/thief.mv"),
    include_bytes!("../../../fuzz/seeds/leak.mv"),
];
const SETS: [&[usize]; 5] = [&[3], &[4, 5], &[6, 3], &[3, 4, 5, 6], &[5, 3]];

/// The storage rule under attack: modules that use `thrylos::store`, with their
/// tables edited (a type handle retargeted, a signature swapped, a call
/// redirected) and then their bytes. Whatever the chain publishes must pass an
/// independent check of the rule, and the edits must actually reach the rule
/// and the oracle, or the test proves nothing.
#[test]
fn edited_modules_that_use_the_store_never_break_the_storage_rule() {
    use chain_exec::publish::{prepare, PublishError};
    use move_binary_format::file_format::CompiledModule;

    let (chain, mut publisher) = rich();
    let mut rng = Rng(0xC0FF_EE00_D15E_A5E5);
    let (mut published, mut refused_by_the_rule, mut stored_with_calls) = (0u32, 0u32, 0u32);

    for round in 0..6_000u32 {
        let set = SETS[(rng.next() as usize) % SETS.len()];
        let mut modules: Vec<Vec<u8>> = set.iter().map(|i| SEEDS[*i].to_vec()).collect();
        for _ in 0..(rng.next() % 4) {
            let which = (rng.next() as usize) % modules.len();
            let Ok(mut module) = CompiledModule::deserialize_with_defaults(&modules[which]) else {
                continue;
            };
            oracle::mutate(&mut module, &mut || rng.next());
            let mut out = Vec::new();
            if module
                .serialize_with_version(module.version, &mut out)
                .is_ok()
            {
                modules[which] = out;
            }
        }
        if rng.next().is_multiple_of(4) {
            let which = (rng.next() as usize) % modules.len();
            let at = (rng.next() as usize) % modules[which].len();
            modules[which][at] = rng.next() as u8;
        }

        // Does the rule itself refuse it? (What the chain decides first, without state.)
        if let Err(PublishError::StoreTypeNotOwned { .. }) = prepare(
            &modules,
            move_core_types::account_address::AccountAddress::new([1; 32]),
            |_| true,
        ) {
            refused_by_the_rule += 1;
        }

        let mut fresh = publisher.publish(modules);
        fresh.body.sequence_number = chain_types::SequenceNumber(0);
        let tx = publisher.resign(fresh);
        let id = chain_exec::publish::package_address(&tx.sender_address(), 0);
        let root = chain.executor.state_root();
        let block = chain.executor.propose_block(
            chain.executor.tip_block_hash(),
            root,
            BlockHeight(chain.executor.head_height().unwrap() + 1),
            chain.now_ms + 1_000,
            vec![tx],
            BlockLimits {
                max_gas: u64::MAX,
                max_size_bytes: 4 * 1024 * 1024,
            },
        );
        assert_eq!(
            block.transactions.len(),
            1,
            "round {round} was not proposed"
        );
        let executed = chain
            .executor
            .execute_block(root, &block)
            .unwrap_or_else(|error| panic!("round {round} rejected its block: {error:?}"));
        match executed.outcomes[0] {
            TransactionOutcome::Success => {
                published += 1;
                let wanted = chain_exec::keys::package_key(id);
                let (_, change) = executed
                    .state_diff
                    .iter()
                    .find(|(key, _)| **key == wanted)
                    .unwrap_or_else(|| panic!("round {round}: no package stored"));
                let chain_state::StateChange::Put(value) = change else {
                    panic!("round {round}: a publish deleted a package")
                };
                let stored: Vec<Vec<u8>> =
                    chain_types::codec::decode_exact(value.as_bytes()).unwrap();
                for bytes in stored {
                    let module = CompiledModule::deserialize_with_defaults(&bytes).unwrap();
                    let broken = oracle::violations(&module);
                    assert!(
                        broken.is_empty(),
                        "round {round}: the chain published a module that breaks the storage rule: {broken:?}"
                    );
                    if oracle::store_calls(&module) > 0 {
                        stored_with_calls += 1;
                    }
                }
            }
            TransactionOutcome::Aborted(AbortReason::PublishRefused) => {}
            other => panic!("round {round} ended as {other:?}"),
        }
    }
    eprintln!("published {published}, refused by the rule {refused_by_the_rule}, stored modules that call the store {stored_with_calls}");
    // The test must reach what it tests: modules the rule refuses, and modules
    // that use the store and are accepted (so the oracle has something to judge).
    assert!(
        refused_by_the_rule > 100,
        "the edits rarely reach the rule: {refused_by_the_rule}"
    );
    assert!(
        stored_with_calls > 100,
        "the oracle rarely sees a store call: {stored_with_calls}"
    );
}
