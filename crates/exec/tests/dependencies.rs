//! Packages that depend on other published packages.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::*;

use chain_engine_api::{AbortReason, TransactionOutcome};
use chain_exec::publish::MAX_DEPENDENCY_PACKAGES;

const OK: TransactionOutcome = TransactionOutcome::Success;
const REFUSED: TransactionOutcome = TransactionOutcome::Aborted(AbortReason::PublishRefused);

fn hex(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Publish the module named `name` from `source`, which also defines its
/// dependencies at the addresses they were published at (so it can be
/// compiled); only `name` is sent.
fn publish_one(
    chain: &mut Chain,
    p: &mut Publisher,
    source: &str,
    name: &str,
) -> ([u8; 32], TransactionOutcome) {
    let id = id_of(p, p.sequence);
    let module = compile(source).remove(name).unwrap();
    let outcome = chain.run(p.publish(vec![module]));
    (id, outcome)
}

#[test]
fn a_package_can_use_another_published_package_and_a_call_reaches_into_it() {
    let (mut chain, mut p) = rich();
    let (lib, out) = publish_one(
        &mut chain,
        &mut p,
        "module 0x0::lib { public fun double(x: u64): u64 { x * 2 } }",
        "lib",
    );
    assert_eq!(out, OK);
    let source = format!(
        "module 0x{lib}::lib {{ public fun double(x: u64): u64 {{ x * 2 }} }}
         module 0x0::app {{
             entry fun run(x: u64) {{ assert!(0x{lib}::lib::double(x) == 10, 1); }}
         }}",
        lib = hex(lib)
    );
    let (app, out) = publish_one(&mut chain, &mut p, &source, "app");
    assert_eq!(out, OK);
    let good = p.call(app, "app", "run", vec![5u64.to_le_bytes().to_vec()]);
    assert_eq!(chain.run(good), OK);
    let bad = p.call(app, "app", "run", vec![4u64.to_le_bytes().to_vec()]);
    assert_eq!(
        chain.run(bad),
        TransactionOutcome::Aborted(AbortReason::ExecutionFailed)
    );
}

#[test]
fn a_dependency_of_a_dependency_is_linked_too() {
    let (mut chain, mut p) = rich();
    let (a, out) = publish_one(
        &mut chain,
        &mut p,
        "module 0x0::a { public fun one(): u64 { 1 } }",
        "a",
    );
    assert_eq!(out, OK);
    let b_src = format!(
        "module 0x{a}::a {{ public fun one(): u64 {{ 1 }} }}
         module 0x0::b {{ public fun two(): u64 {{ 0x{a}::a::one() + 1 }} }}",
        a = hex(a)
    );
    let (b, out) = publish_one(&mut chain, &mut p, &b_src, "b");
    assert_eq!(out, OK);
    // `c` imports only `b`; running it needs `a` as well.
    let c_src = format!(
        "module 0x{b}::b {{ public fun two(): u64 {{ 2 }} }}
         module 0x0::c {{ entry fun run() {{ assert!(0x{b}::b::two() == 2, 1); }} }}",
        b = hex(b)
    );
    let (c, out) = publish_one(&mut chain, &mut p, &c_src, "c");
    assert_eq!(out, OK);
    let call = p.call(c, "c", "run", vec![]);
    assert_eq!(chain.run(call), OK);
}

#[test]
fn an_import_of_a_package_that_is_not_published_is_refused() {
    let (mut chain, mut p) = rich();
    let ghost = hex([0x77; 32]);
    let source = format!(
        "module 0x{ghost}::g {{ public fun f(): u64 {{ 1 }} }}
         module 0x0::user {{ public fun h(): u64 {{ 0x{ghost}::g::f() }} }}"
    );
    let (_, out) = publish_one(&mut chain, &mut p, &source, "user");
    assert_eq!(out, REFUSED);
}

#[test]
fn a_long_chain_of_dependencies_stops_at_the_limit() {
    let (mut chain, mut p) = rich();
    // p0 stands alone; each next package imports the one before, so package
    // k needs k packages besides itself.
    let (mut previous, out) = publish_one(
        &mut chain,
        &mut p,
        "module 0x0::m0 { public fun f(): u64 { 0 } }",
        "m0",
    );
    assert_eq!(out, OK);
    for k in 1..=MAX_DEPENDENCY_PACKAGES + 1 {
        let source = format!(
            "module 0x{previous}::m{j} {{ public fun f(): u64 {{ 0 }} }}
             module 0x0::m{k} {{ public fun f(): u64 {{ 0x{previous}::m{j}::f() }} }}",
            previous = hex(previous),
            j = k - 1,
        );
        let (id, out) = publish_one(&mut chain, &mut p, &source, &format!("m{k}"));
        if k <= MAX_DEPENDENCY_PACKAGES {
            assert_eq!(out, OK, "package {k} needs {k} others, within the limit");
            previous = id;
        } else {
            assert_eq!(out, REFUSED, "package {k} needs {k} others, over the limit");
        }
    }
}
