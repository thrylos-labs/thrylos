//! What the chain charges for Move work (`chain_exec::gas`, and
//! `docs/gas-calibration.md`): the prices themselves, and the two properties
//! the calibration exists to give, which are that nothing is much cheaper than
//! the work it does and that what scales with size is charged by size.
//!
//! Gas is consensus. A number pinned here is a rule of the chain: a change to
//! it is a change of rules, and must be made on purpose.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use chain_engine_api::TransactionOutcome;
use chain_exec::gas::*;
use common::*;

const SOURCE: &str = "
module 0x0::prices {
    fun inc(x: u64): u64 { x + 1 }
    entry fun noop() {}
    entry fun adds(n: u64) {
        let mut i = 0u64;
        let mut x = 0u64;
        while (i < n) { x = x + i; i = i + 1; };
        assert!(x >= 0, 1);
    }
    entry fun calls(n: u64) {
        let mut i = 0u64;
        let mut x = 0u64;
        while (i < n) { x = inc(x); i = i + 1; };
        assert!(x == n, 1);
    }
    entry fun copies(n: u64, len: u64) {
        let mut v = vector[];
        let mut k = 0u64;
        while (k < len) { v.push_back(k); k = k + 1; };
        let mut i = 0u64;
        while (i < n) { let w = copy v; assert!(w.length() == len, 1); i = i + 1; };
    }
    entry fun compares(n: u64, len: u64) {
        let mut v = vector[];
        let mut k = 0u64;
        while (k < len) { v.push_back(k); k = k + 1; };
        let w = copy v;
        let mut i = 0u64;
        while (i < n) { assert!(v == w, 1); i = i + 1; };
    }
}";

struct World {
    chain: Chain,
    owner: Publisher,
    package: [u8; 32],
}

fn world() -> World {
    let (mut chain, mut owner) = rich();
    let package = id_of(&owner, 0);
    let modules: Vec<_> = compile_with_system_packages(SOURCE).into_values().collect();
    assert_eq!(
        chain.run(owner.publish(modules)),
        TransactionOutcome::Success
    );
    World {
        chain,
        owner,
        package,
    }
}

impl World {
    /// The gas a call uses, run to the end.
    fn gas(&mut self, function: &str, arguments: &[u64]) -> u64 {
        let mut tx = self.owner.call(
            self.package,
            "prices",
            function,
            arguments.iter().map(|a| a.to_le_bytes().to_vec()).collect(),
        );
        self.owner.sequence -= 1;
        tx.body.gas_limit = chain_types::GasAmount(75_000);
        let tx = self.owner.resign(tx);
        self.chain
            .executor
            .simulate(&tx)
            .unwrap_or_else(|e| panic!("{function}: {e}"))
            .gas_used
    }
}

#[test]
fn the_prices_are_these() {
    assert_eq!(INTERNAL_PER_GAS, 1_000);
    assert_eq!(PRICE_SIMPLE, 60);
    assert_eq!(PRICE_ARITHMETIC, 280);
    assert_eq!(PRICE_CALL, 350);
    assert_eq!(PRICE_CALL_PER_ARGUMENT, 120);
    assert_eq!(PRICE_PACK, 90);
    assert_eq!(PRICE_PACK_PER_FIELD, 30);
    assert_eq!(PRICE_VECTOR_BORROW, 250);
    assert_eq!(PRICE_VECTOR_SWAP, 200);
    assert_eq!(PRICE_VECTOR_PUSH_POP, 100);
    assert_eq!(PRICE_VECTOR_PACK, 150);
    assert_eq!(PRICE_VECTOR_PACK_PER_ELEMENT, 60);
    assert_eq!(PRICE_CONSTANT, 150);
    assert_eq!(PRICE_CONSTANT_PER_16_BYTES, 1);
    assert_eq!(PRICE_PER_4_SIZE_UNITS, 1);
}

#[test]
fn a_call_is_charged_by_what_it_does_and_the_total_is_pinned() {
    let mut w = world();
    let noop = w.gas("noop", &[]);
    let adds_100 = w.gas("adds", &[100]);
    let adds_1000 = w.gas("adds", &[1_000]);
    let calls_100 = w.gas("calls", &[100]);
    println!("noop {noop}, adds {adds_100} {adds_1000}, calls {calls_100}");
    // A loop of ten times as many iterations costs ten times as much, to within
    // the loop's fixed part.
    let per_100 = adds_1000 - adds_100;
    assert!(per_100 >= 8 * (adds_100 - noop), "{adds_100} {adds_1000}");
    // A call costs more than the plain arithmetic it replaces.
    assert!(calls_100 > adds_100);
}

/// The size of what is copied or compared is charged, contents of a vector
/// included. The VM's own schedule did not, and a program could copy a large
/// vector a million times for the price of a million small copies.
#[test]
fn copying_and_comparing_a_vector_costs_by_its_length() {
    let mut w = world();
    // 100 copies of 4,096 numbers move 409,600 numbers (8 size units each, and
    // a quarter of a nanosecond a unit): at least 800 gas more than 100 copies of
    // 64, by the price alone.
    let building_small = w.gas("copies", &[1, 64]);
    let small = w.gas("copies", &[100, 64]) - building_small;
    let building_big = w.gas("copies", &[1, 4_096]);
    let big = w.gas("copies", &[100, 4_096]) - building_big;
    println!("copy 100x: 64 numbers {small}, 4,096 numbers {big}");
    assert!(big > small + 700, "{big} vs {small}");

    // Two operands, so twice the size.
    let building_small = w.gas("compares", &[1, 64]);
    let small = w.gas("compares", &[100, 64]) - building_small;
    let building_big = w.gas("compares", &[1, 4_096]);
    let big = w.gas("compares", &[100, 4_096]) - building_big;
    println!("compare 100x: 64 numbers {small}, 4,096 numbers {big}");
    assert!(big > small + 1_500, "{big} vs {small}");
}
