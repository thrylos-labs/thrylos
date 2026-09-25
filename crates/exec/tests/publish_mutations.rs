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
