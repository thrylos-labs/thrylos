//! Measures what each kind of Move instruction costs in nanoseconds, so that the
//! chain's price table can be set from measurement (`docs/gas-calibration.md`).
//! Since 1 gas is 1 microsecond and 1 gas is 1,000 of the VM's internal units,
//! **one internal unit is one nanosecond**: the number this prints for an
//! instruction is the price to give it.
//!
//! ```text
//! cargo run --release -p chain-exec --example opcode_bench            # full
//! cargo run --release -p chain-exec --example opcode_bench -- --quick # a smoke run
//! ```
//!
//! Each case is a loop whose body repeats one kind of statement ten times; the
//! same loop with an empty body is timed too, and the difference, divided by the
//! statements run, is the cost of the statement. The fastest of many runs is
//! reported (contention from other processes only ever adds time).

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
    clippy::integer_division
)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::time::Instant;

use chain_engine_api::TransactionOutcome;
use common::*;

const REPEAT: usize = 10;

struct Case {
    name: &'static str,
    /// Statements declared before the loop.
    prelude: String,
    /// The statement repeated in the loop body.
    body: String,
    /// The loops the case has (the verifier limits a module's).
    loops: usize,
    /// Loop iterations.
    n: u64,
    /// What one statement is, for the printout: how many of the statement's
    /// costs are counted per run (usually 1).
    per: f64,
}

fn hex(len: usize) -> String {
    let mut s = String::from("x\"");
    for i in 0..len {
        s.push_str(&format!("{:02x}", (i * 7 + 1) % 256));
    }
    s.push('"');
    s
}

fn ascii(len: usize) -> String {
    let mut s = String::from("x\"");
    for i in 0..len {
        s.push_str(&format!("{:02x}", 0x41 + (i % 26)));
    }
    s.push('"');
    s
}

fn vector_literal(len: usize) -> String {
    let items: Vec<String> = (0..len).map(|i| format!("{i}u64")).collect();
    format!("vector[{}]", items.join(", "))
}

fn build_vec(len: u64) -> String {
    format!(
        "let mut v = vector[]; let mut k = 0u64; while (k < {len}) {{ v.push_back(k); k = k + 1; }};"
    )
}

fn cases(quick: bool) -> Vec<Case> {
    let n = if quick { 500 } else { 20_000 };
    let c = |name: &'static str, prelude: &str, body: &str, loops: usize, n: u64| Case {
        name,
        prelude: prelude.to_owned(),
        body: body.to_owned(),
        loops,
        n,
        per: 1.0,
    };
    let base = "let mut x = 12345u64; let y = 7u64; let mut a = 3u128; let b = 5u128; \
                let mut c = 3u256; let d = 5u256; let mut f = 3u8;";
    let vec64 = format!("{} let mut w = copy v;", build_vec(64));
    let mut all = vec![
        c("empty loop", base, "", 1, n),
        c("x = x + i", base, "x = x + i;", 1, n),
        c("x = y * i", base, "x = y * i;", 1, n),
        c("x = i / y", base, "x = i / y;", 1, n),
        c("x = i % y", base, "x = i % y;", 1, n),
        c("x = x ^ i", base, "x = x ^ i;", 1, n),
        c("x = x << 1", base, "x = x << 1;", 1, n),
        c("f = (y as u8)", base, "f = (y as u8);", 1, n),
        c("a = b + b (u128)", base, "a = b + b;", 1, n),
        c("a = b * b (u128)", base, "a = b * b;", 1, n),
        c("a = b / b (u128)", base, "a = b / b;", 1, n),
        c("c = d + d (u256)", base, "c = d + d;", 1, n),
        c("c = d * d (u256)", base, "c = d * d;", 1, n),
        c("c = d / d (u256)", base, "c = d / d;", 1, n),
        c("c = (x as u256)", base, "c = (x as u256);", 1, n),
        c("x = inc(x)   (a call)", base, "x = inc(x);", 1, n),
        c(
            "x = add3(x, y, i)  (3 arguments)",
            base,
            "x = add3(x, y, i);",
            1,
            n,
        ),
        c(
            "pack + unpack a 3-field struct",
            base,
            "let p = P { a: x, b: y, c: i }; let P { a: q, b: _, c: _ } = p; x = q;",
            1,
            n,
        ),
        c(
            "read a struct field via a reference",
            &format!("{base} let p = P {{ a: 1, b: 2, c: 3 }};"),
            "x = p.a;",
            1,
            n,
        ),
        c(
            "write a struct field via a reference",
            &format!("{base} let mut p = P {{ a: 1, b: 2, c: 3 }};"),
            "p.a = x;",
            1,
            n,
        ),
        c(
            "v.length()  (64 numbers)",
            &format!("{base} let v = {};", vector_literal(64)),
            "x = v.length();",
            1,
            n,
        ),
        c(
            "*v.borrow(j)",
            &format!("{base} let v = {}; let j = 17u64;", vector_literal(64)),
            "x = *v.borrow(j);",
            1,
            n,
        ),
        c(
            "*v.borrow_mut(j) = x",
            &format!("{base} let mut v = {}; let j = 17u64;", vector_literal(64)),
            "*v.borrow_mut(j) = x;",
            1,
            n,
        ),
        c(
            "v.swap(0, j)",
            &format!("{base} let mut v = {}; let j = 17u64;", vector_literal(64)),
            "v.swap(0, j);",
            1,
            n,
        ),
        c(
            "v.push_back(x); v.pop_back()",
            &format!("{base} let mut v = {};", vector_literal(64)),
            "v.push_back(x); let _e = v.pop_back();",
            1,
            n,
        ),
        c(
            "vector[x, y, x, y]  (pack 4)",
            base,
            "let t = vector[x, y, x, y]; x = t.length();",
            1,
            n,
        ),
        c(
            "a 64-byte constant",
            &format!("{base} "),
            &format!("let k = {}; x = k.length();", hex(64)),
            1,
            n / 2,
        ),
        c(
            "a 1,024-byte constant",
            &format!("{base} "),
            &format!("let k = {}; x = k.length();", hex(1024)),
            1,
            n / 8,
        ),
        c(
            "sha3_256 of 32 bytes",
            &format!("{base} let k = {};", hex(32)),
            "let h = hash::sha3_256(copy k); x = h.length();",
            1,
            n / 2,
        ),
        c(
            "sha3_256 of 1,024 bytes",
            &format!("{base} let k = {};", hex(1024)),
            "let h = hash::sha3_256(copy k); x = h.length();",
            1,
            n / 8,
        ),
        c(
            "sha2_256 of 1,024 bytes",
            &format!("{base} let k = {};", hex(1024)),
            "let h = hash::sha2_256(copy k); x = h.length();",
            1,
            n / 8,
        ),
        c(
            "bcs::to_bytes(&u64)",
            base,
            "let e = bcs::to_bytes(&x); x = e.length();",
            1,
            n / 2,
        ),
        c(
            "string::utf8 of 64 bytes",
            &format!("{base} let k = {};", ascii(64)),
            "let s = string::utf8(copy k); x = s.length();",
            1,
            n / 2,
        ),
        c(
            "type_name::get<u64>()",
            base,
            "let t = type_name::get<u64>(); x = t.into_string().length();",
            1,
            n / 4,
        ),
    ];
    // Copying and comparing whole vectors, by length.
    for len in [64u64, 1_024, 8_192] {
        let count = (n * 64 / len.max(64)).max(200);
        all.push(c(
            Box::leak(format!("copy a {len}-number vector").into_boxed_str()),
            &format!("{} {}", base, build_vec(len)),
            "let w = copy v; x = w.length();",
            2,
            count / 4,
        ));
        all.push(c(
            Box::leak(format!("compare two {len}-number vectors").into_boxed_str()),
            &format!("{} {} let w = copy v;", base, build_vec(len)),
            "if (v == w) { x = x + 1; };",
            2,
            count / 4,
        ));
    }
    let _ = vec64;
    all
}

fn main() {
    let quick = std::env::args().any(|a| a == "--quick");
    let runs = if quick { 3 } else { 15 };
    let cases = cases(quick);

    // One module per few loops: the verifier allows a module only a few.
    let mut modules: Vec<String> = Vec::new();
    let mut placement: Vec<(usize, String)> = Vec::new();
    let mut current = String::new();
    let mut loops_here = 0usize;
    let mut module_index = 0usize;
    let header = |i: usize| {
        format!(
            "#[allow(unused_variable, unused_assignment, unused_mut_parameter)]
module pkg::m{i} {{
    use std::hash;
    use std::bcs;
    use std::string;
    use std::type_name;
    public struct P has copy, drop {{ a: u64, b: u64, c: u64 }}
    fun inc(x: u64): u64 {{ x + 1 }}
    fun add3(a: u64, b: u64, c: u64): u64 {{ a + b + c }}
"
        )
    };
    current.push_str(&header(0));
    // The empty loop is needed once per iteration count: emit a base per case.
    let mut function_names: Vec<(String, String)> = Vec::new(); // (case, base)
    for (index, case) in cases.iter().enumerate() {
        for kind in ["run", "base"] {
            let loops = case.loops;
            if loops_here + loops > 8 {
                current.push_str("}\n");
                modules.push(std::mem::take(&mut current));
                module_index += 1;
                current.push_str(&header(module_index));
                loops_here = 0;
            }
            loops_here += loops;
            let body = if kind == "run" {
                case.body.repeat(REPEAT)
            } else {
                String::new()
            };
            let fname = format!("{kind}_{index}");
            current.push_str(&format!(
                "    entry fun {fname}(n: u64) {{ {} let mut i = 0u64; while (i < n) {{ {} i = i + 1; }}; }}\n",
                case.prelude, body
            ));
            placement.push((module_index, fname.clone()));
        }
        function_names.push((format!("run_{index}"), format!("base_{index}")));
    }
    current.push_str("}\n");
    modules.push(current);
    let source = modules.join("\n");

    let (mut chain, mut owner) = rich_with_block_gas(600_000);
    let package = id_of(&owner, 0);
    let bytes: Vec<Vec<u8>> = compile_with_system_packages(&source)
        .into_values()
        .collect();
    let total: usize = bytes.iter().map(Vec::len).sum();
    let mut tx = owner.publish(bytes);
    tx.body.gas_limit = chain_types::GasAmount(150_000);
    let tx = owner.resign(tx);
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Success,
        "publishes ({total} bytes)"
    );

    let time = |chain: &Chain, owner: &mut Publisher, module: usize, f: &str, n: u64| -> f64 {
        let mut tx = owner.call(
            package,
            &format!("m{module}"),
            f,
            vec![n.to_le_bytes().to_vec()],
        );
        owner.sequence -= 1;
        tx.body.gas_limit = chain_types::GasAmount(1_000_000_000_000);
        let tx = owner.resign(tx);
        for _ in 0..2 {
            chain
                .executor
                .simulate_up_to(&tx, u64::MAX / 4)
                .unwrap_or_else(|e| panic!("{f}: {e}"));
        }
        (0..runs)
            .map(|_| {
                let started = Instant::now();
                chain
                    .executor
                    .simulate_up_to(&tx, u64::MAX / 4)
                    .unwrap_or_else(|e| panic!("{f}: {e}"));
                started.elapsed().as_secs_f64() * 1e9
            })
            .fold(f64::MAX, f64::min)
    };

    println!(
        "{:<44} {:>9} {:>12} {:>10}",
        "statement (repeated 10x per iteration)", "iters", "loop ns/iter", "ns each"
    );
    let mut base_cost = f64::NAN;
    for (index, case) in cases.iter().enumerate() {
        let module = placement[index * 2].0;
        let run = time(&chain, &mut owner, module, &format!("run_{index}"), case.n);
        let base = time(
            &chain,
            &mut owner,
            placement[index * 2 + 1].0,
            &format!("base_{index}"),
            case.n,
        );
        let each = (run - base) / (case.n as f64 * REPEAT as f64 * case.per);
        if index == 0 {
            base_cost = base / case.n as f64;
        }
        println!(
            "{:<44} {:>9} {:>12.1} {:>10.1}",
            case.name,
            case.n,
            run / case.n as f64,
            each
        );
    }
    println!("\n(the empty loop, about 9 instructions an iteration, costs {base_cost:.1} ns an iteration)");
}
