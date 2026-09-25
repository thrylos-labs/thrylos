//! Measures what the gas schedule and the `simulate` cap should be set from:
//! how much wall-clock time a unit of gas costs, for the kinds of work a call
//! does. Run it in a **release** build on the hardware that matters:
//!
//! ```text
//! cargo run --release -p chain-exec --example gas_bench            # full
//! cargo run --release -p chain-exec --example gas_bench -- --quick # a smoke run
//! ```
//!
//! Every scenario runs several times; the table gives the fastest run (the best
//! estimate of the cost itself, with contention from other processes taken out),
//! the median, and the slowest. `ns/gas` uses the fastest.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::float_arithmetic,
    clippy::integer_division,
    clippy::ptr_arg
)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use chain_engine_api::{BlockLimits, Engine, TransactionOutcome};
use chain_exec::publish::publish_gas;
use chain_types::{BlockHeight, Transaction};
use common::*;

const SOURCE: &str = "
module pkg::bench {
    use std::hash;
    use thrylos::signer;
    use thrylos::store;

    public struct Counter has key, store, copy, drop { n: u64 }
    public struct Blob has key, store { data: vector<u8> }

    entry fun noop() {}
    entry fun arith(n: u64) {
        let mut i = 0u64;
        let mut s = 0u64;
        while (i < n) { s = s + i * 3 + 1; i = i + 1; };
        assert!(s > 0 || n == 0, 1);
    }
    entry fun vec_push(n: u64) {
        let mut v = vector[];
        let mut i = 0u64;
        while (i < n) { v.push_back(i); i = i + 1; };
        assert!(v.length() == n, 1);
    }
    entry fun hashing(n: u64) {
        let mut i = 0u64;
        while (i < n) { let _h = hash::sha3_256(b\"abcdefghijklmnopqrstuvwxyz\"); i = i + 1; };
    }
    entry fun store_pairs(s: &signer, n: u64) {
        let o = signer::address_of(s);
        let mut i = 0u64;
        while (i < n) {
            // Slots reused: one call may change at most 16 drawers.
            store::put(o, i % 16, Counter { n: i });
            let _c = store::take<Counter>(o, i % 16);
            i = i + 1;
        };
    }
    fun blob(n: u64): Blob {
        let mut data = vector[];
        let mut i = 0u64;
        while (i < n) { data.push_back(7); i = i + 1; };
        Blob { data }
    }
    entry fun build_only(n: u64) { let Blob { data: _ } = blob(n); }
    entry fun make_blob(s: &signer, n: u64) { store::put(signer::address_of(s), 0, blob(n)); }
    // Read and write what is already there: the cost of moving the bytes, without the loop.
    entry fun churn_blob(s: &signer) {
        let o = signer::address_of(s);
        let b = store::take<Blob>(o, 0);
        store::put(o, 0, b);
    }
    entry fun read_blob(s: &signer) {
        let o = signer::address_of(s);
        let Blob { data } = store::take<Blob>(o, 0);
        assert!(data.length() > 0, 1);
        store::put(o, 0, Blob { data });
    }
}";

struct Row {
    label: String,
    gas: u64,
    times: Vec<Duration>,
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn report(rows: &mut Vec<Row>) {
    println!(
        "{:<44} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "scenario", "gas", "min ms", "median", "max", "ns/gas"
    );
    for row in rows.iter_mut() {
        row.times.sort();
        let min = row.times[0];
        let median = row.times[row.times.len() / 2];
        let max = row.times[row.times.len() - 1];
        let ns_per_gas = if row.gas == 0 {
            f64::NAN
        } else {
            min.as_nanos() as f64 / row.gas as f64
        };
        println!(
            "{:<44} {:>9} {:>9.2} {:>9.2} {:>9.2} {:>9.1}",
            row.label,
            row.gas,
            ms(min),
            ms(median),
            ms(max),
            ns_per_gas
        );
    }
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let runs = if quick { 2 } else { 21 };
    let scale = if quick { 20 } else { 1 };
    let mut rows: Vec<Row> = Vec::new();

    let (mut chain, mut owner) = rich();
    let package = id_of(&owner, 0);
    let modules: Vec<_> = compile_with_system_packages(SOURCE).into_values().collect();
    assert_eq!(
        chain.run(owner.publish(modules)),
        TransactionOutcome::Success
    );
    let sim = |chain: &Chain,
               owner: &mut Publisher,
               f: &str,
               args: Vec<Vec<u8>>|
     -> (u64, Vec<Duration>) {
        let tx = {
            let tx = owner.call(package, "bench", f, args);
            owner.sequence -= 1;
            tx
        };
        // Two warm-ups, then the timed runs.
        let mut gas = 0;
        for _ in 0..2 {
            gas = chain
                .executor
                .simulate(&tx)
                .unwrap_or_else(|e| panic!("{f}: {e}"))
                .gas_used;
        }
        let mut times = Vec::new();
        for _ in 0..runs {
            let started = Instant::now();
            let result = chain.executor.simulate(&tx);
            times.push(started.elapsed());
            gas = result.unwrap_or_else(|e| panic!("{f}: {e}")).gas_used;
        }
        (gas, times)
    };
    let n = |v: u64| (v / scale).max(1).to_le_bytes().to_vec();

    // ---- what a call costs before it does anything, and pure interpreter work ----
    let add = |rows: &mut Vec<Row>, label: &str, (gas, times): (u64, Vec<Duration>)| {
        rows.push(Row {
            label: label.to_owned(),
            gas,
            times,
        });
    };
    add(
        &mut rows,
        "noop (load the package, run nothing)",
        sim(&chain, &mut owner, "noop", vec![]),
    );
    add(
        &mut rows,
        "arith x 2,000",
        sim(&chain, &mut owner, "arith", vec![n(2_000)]),
    );
    add(
        &mut rows,
        "arith x 20,000",
        sim(&chain, &mut owner, "arith", vec![n(20_000)]),
    );
    add(
        &mut rows,
        "vector push x 5,000",
        sim(&chain, &mut owner, "vec_push", vec![n(5_000)]),
    );
    add(
        &mut rows,
        "sha3_256 x 500",
        sim(&chain, &mut owner, "hashing", vec![n(500)]),
    );
    add(
        &mut rows,
        "store put+take x 32 (64 operations)",
        sim(&chain, &mut owner, "store_pairs", vec![n(32)]),
    );
    add(
        &mut rows,
        "build a 3,000-byte vector, drop it",
        sim(&chain, &mut owner, "build_only", vec![n(3_000)]),
    );

    // ---- moving large stored values: the bytes, without the loop that built them ----
    let big = if quick { 500u64 } else { 16_000 };
    let tx = {
        let mut tx = owner.call(
            package,
            "bench",
            "make_blob",
            vec![big.to_le_bytes().to_vec()],
        );
        tx.body.gas_limit = chain_types::GasAmount(2_000_000);
        owner.resign(tx)
    };
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Success,
        "stores a {big}-byte value"
    );
    add(
        &mut rows,
        &format!("take+put a stored {big}-byte value"),
        sim(&chain, &mut owner, "churn_blob", vec![]),
    );
    add(
        &mut rows,
        &format!("take a {big}-byte value, read its length, put"),
        sim(&chain, &mut owner, "read_blob", vec![]),
    );

    // ---- publishing: verification is the work, and the gas for it is by size ----
    println!("\n== calls, simulated ({runs} runs each) ==");
    report(&mut rows);

    let mut publishes: Vec<Row> = Vec::new();
    for (label, functions) in [
        ("small module", 4usize),
        ("medium module", 40),
        ("larger module", 90),
        ("large module", 160),
        ("largest tried", 300),
    ] {
        let mut source = String::from("module pkg::wide {\n");
        // Branches, no loops: the verifier allows a module only a few loops, and
        // this is meant to be the most verification work a package can ask for.
        for i in 0..functions {
            source.push_str(&format!(
                "    public fun f{i}(a: u64, b: u64): u64 {{ let mut x = a;"
            ));
            for k in 0..14 {
                source.push_str(&format!(
                    " if (x > {}) {{ x = x + b * {}; }} else {{ x = x + {}; }};",
                    k + i % 7,
                    k + 1,
                    k
                ));
            }
            source.push_str(" x }\n");
        }
        source.push('}');
        let bytes: Vec<Vec<u8>> = compile(&source).into_values().collect();
        let size: usize = bytes.iter().map(Vec::len).sum();
        if size > chain_exec::move_config::MAX_PACKAGE_BYTES {
            println!("(skipping {label}: {size} bytes is over the package limit)");
            continue;
        }
        // What the chain would say without running it: the limits are part of what is measured.
        if let Err(error) = chain_exec::publish::prepare(
            &bytes,
            move_core_types::account_address::AccountAddress::new([1; 32]),
            |_| true,
        ) {
            println!("({label}: {size} bytes, {functions} functions is refused: {error})");
            continue;
        }
        let mut times = Vec::new();
        for _ in 0..runs.min(7) {
            let (fresh, mut who) = rich();
            let mut tx: Transaction = who.publish(bytes.clone());
            tx.body.gas_limit = chain_types::GasAmount(2_000_000);
            let tx = who.resign(tx);
            let root = fresh.executor.state_root();
            let block = fresh.executor.propose_block(
                fresh.executor.tip_block_hash(),
                root,
                BlockHeight(fresh.executor.head_height().unwrap() + 1),
                fresh.now_ms + 1_000,
                vec![tx],
                BlockLimits {
                    max_gas: u64::MAX,
                    max_size_bytes: 4 * 1024 * 1024,
                },
            );
            assert_eq!(block.transactions.len(), 1);
            let started = Instant::now();
            let executed = fresh.executor.execute_block(root, &block).unwrap();
            times.push(started.elapsed());
            assert_eq!(executed.outcomes[0], TransactionOutcome::Success, "{label}");
        }
        publishes.push(Row {
            label: format!("publish {label}: {size} bytes, {functions} functions"),
            gas: publish_gas(size),
            times,
        });
    }
    println!("\n== publishing (whole block execution; gas is what the publish is charged) ==");
    report(&mut publishes);

    // ---- the same work as a real transaction, run to the end of its gas: what a
    // hostile call costs a validator, at a gas limit a user may choose ----
    let mut hostile: Vec<Row> = Vec::new();
    for (label, function, gas_limit) in [
        ("arithmetic loop to 300,000 gas", "arith", 300_000u64),
        ("arithmetic loop to 3,000,000 gas", "arith", 3_000_000),
        ("sha3 loop to 300,000 gas", "hashing", 300_000),
    ] {
        if quick && gas_limit > 300_000 {
            continue;
        }
        let mut times = Vec::new();
        let mut gas = 0;
        for _ in 0..3 {
            let (fresh, mut who) = {
                let (mut c, mut w) = rich();
                let id = id_of(&w, 0);
                let modules: Vec<_> = compile_with_system_packages(SOURCE).into_values().collect();
                assert_eq!(c.run(w.publish(modules)), TransactionOutcome::Success);
                let _ = id;
                (c, w)
            };
            let mut tx = who.call(
                package_of(&fresh, &who),
                "bench",
                function,
                vec![u64::MAX.to_le_bytes().to_vec()],
            );
            tx.body.gas_limit = chain_types::GasAmount(gas_limit);
            let tx = who.resign(tx);
            let root = fresh.executor.state_root();
            let block = fresh.executor.propose_block(
                fresh.executor.tip_block_hash(),
                root,
                BlockHeight(fresh.executor.head_height().unwrap() + 1),
                fresh.now_ms + 1_000,
                vec![tx],
                BlockLimits {
                    max_gas: u64::MAX,
                    max_size_bytes: 4 * 1024 * 1024,
                },
            );
            assert_eq!(block.transactions.len(), 1);
            let started = Instant::now();
            let executed = fresh.executor.execute_block(root, &block).unwrap();
            times.push(started.elapsed());
            gas = executed.gas_used;
        }
        hostile.push(Row {
            label: label.to_owned(),
            gas,
            times,
        });
    }
    println!("\n== a hostile call run to the end of its gas limit (whole block execution) ==");
    report(&mut hostile);
}

/// The address the package published first by `who` got.
fn package_of(_chain: &Chain, who: &Publisher) -> [u8; 32] {
    id_of(who, 0)
}
