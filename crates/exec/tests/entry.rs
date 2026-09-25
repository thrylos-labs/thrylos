//! Calling entry functions of published packages end to end.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::*;

use chain_engine_api::{AbortReason, TransactionOutcome};

const SOURCE: &str = "
module 0x0::demo {
    public struct Thing has drop { v: u64 }

    entry fun sum_is_ten(a: u64, b: u64) { assert!(a + b == 10, 7); }
    entry fun with_sender(_s: &signer, a: u8) { assert!(a > 0, 1); }
    entry fun with_signer_value(_s: signer) {}
    entry fun kinds(a: bool, b: u16, c: u32, d: u128, e: u256, f: address, g: vector<u8>, h: vector<vector<u64>>) {
        assert!(a, 1);
    }
    public entry fun public_entry() {}
    public fun not_entry() {}
    entry fun generic<T>() {}
    entry fun returns(): u64 { 1 }
    entry fun takes_struct(_t: Thing) {}
    entry fun signer_second(_a: u8, _s: &signer) {}
    entry fun too_deep(_v: vector<vector<vector<vector<u8>>>>) {}
    entry fun loops() { let mut i = 0u64; while (true) { i = i + 1; }; }
}";

fn published() -> (Chain, Publisher, [u8; 32]) {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(SOURCE).into_values().collect();
    let id = id_of(&publisher, 0);
    assert_eq!(
        chain.run(publisher.publish(modules)),
        TransactionOutcome::Success
    );
    (chain, publisher, id)
}

fn u64_arg(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn aborted(reason: AbortReason) -> TransactionOutcome {
    TransactionOutcome::Aborted(reason)
}

fn call(
    chain: &mut Chain,
    p: &mut Publisher,
    id: [u8; 32],
    f: &str,
    args: Vec<Vec<u8>>,
) -> TransactionOutcome {
    let tx = p.call(id, "demo", f, args);
    chain.run(tx)
}

#[test]
fn an_entry_function_runs_with_arguments_decoded_from_its_signature() {
    let (mut chain, mut p, id) = published();
    let ok = call(
        &mut chain,
        &mut p,
        id,
        "sum_is_ten",
        vec![u64_arg(4), u64_arg(6)],
    );
    assert_eq!(ok, TransactionOutcome::Success);
}

#[test]
fn a_move_abort_is_an_execution_failure_that_costs_less_than_the_limit() {
    let (mut chain, mut p, id) = published();
    let before = chain.balance(p.address());
    let out = call(
        &mut chain,
        &mut p,
        id,
        "sum_is_ten",
        vec![u64_arg(1), u64_arg(1)],
    );
    assert_eq!(out, aborted(AbortReason::ExecutionFailed));
    let paid = before - chain.balance(p.address());
    assert!(
        paid < 50_000,
        "charged the metered amount, not the whole limit: {paid}"
    );
    assert!(paid >= 1_000);
}

#[test]
fn a_call_that_never_ends_runs_out_of_gas_and_pays_the_limit() {
    let (mut chain, mut p, id) = published();
    let before = chain.balance(p.address());
    let out = call(&mut chain, &mut p, id, "loops", vec![]);
    assert_eq!(out, aborted(AbortReason::ExecutionFailed));
    assert_eq!(before - chain.balance(p.address()), 50_000);
}

#[test]
fn the_sender_is_supplied_for_a_leading_signer_and_takes_no_argument() {
    let (mut chain, mut p, id) = published();
    assert_eq!(
        call(&mut chain, &mut p, id, "with_sender", vec![vec![1]]),
        TransactionOutcome::Success
    );
    assert_eq!(
        call(&mut chain, &mut p, id, "with_signer_value", vec![]),
        TransactionOutcome::Success
    );
    // Supplying one anyway is an argument-count mismatch.
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "with_sender",
            vec![vec![0; 32], vec![1]]
        ),
        aborted(AbortReason::InvalidArguments)
    );
}

#[test]
fn every_primitive_and_vector_kind_decodes() {
    let (mut chain, mut p, id) = published();
    let args = vec![
        vec![1],                               // bool
        vec![1, 0],                            // u16
        vec![1, 0, 0, 0],                      // u32
        vec![1; 16],                           // u128
        vec![1; 32],                           // u256
        vec![9; 32],                           // address
        vec![3, 1, 2, 3],                      // vector<u8>
        vec![2, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0], // vector<vector<u64>>: [[5], []]
    ];
    assert_eq!(
        call(&mut chain, &mut p, id, "kinds", args),
        TransactionOutcome::Success
    );
}

#[test]
fn malformed_arguments_abort_as_invalid() {
    let (mut chain, mut p, id) = published();
    let bad: Vec<Vec<Vec<u8>>> = vec![
        vec![],                                           // too few
        vec![u64_arg(4)],                                 // too few
        vec![u64_arg(4), u64_arg(6), u64_arg(1)],         // too many
        vec![vec![4, 0, 0], u64_arg(6)],                  // short u64
        vec![u64_arg(4), [u64_arg(6), vec![0]].concat()], // trailing byte
    ];
    for args in bad {
        assert_eq!(
            call(&mut chain, &mut p, id, "sum_is_ten", args),
            aborted(AbortReason::InvalidArguments)
        );
    }
    // A bool must be 0 or 1.
    let mut args = vec![vec![2]];
    args.extend([
        vec![1, 0],
        vec![1, 0, 0, 0],
        vec![1; 16],
        vec![1; 32],
        vec![9; 32],
        vec![0],
        vec![0],
    ]);
    assert_eq!(
        call(&mut chain, &mut p, id, "kinds", args),
        aborted(AbortReason::InvalidArguments)
    );
}

#[test]
fn a_type_argument_is_refused() {
    let (mut chain, mut p, id) = published();
    let mut tx = p.call(id, "demo", "sum_is_ten", vec![u64_arg(4), u64_arg(6)]);
    tx.body.call.type_arguments = vec![1];
    // Re-sign by rebuilding through the helper's key.
    let tx = p.resign(tx);
    assert_eq!(chain.run(tx), aborted(AbortReason::InvalidArguments));
}

#[test]
fn only_plain_entry_functions_are_callable() {
    let (mut chain, mut p, id) = published();
    for f in [
        "not_entry",
        "generic",
        "returns",
        "takes_struct",
        "signer_second",
        "too_deep",
        "missing_function",
    ] {
        assert_eq!(
            call(&mut chain, &mut p, id, f, vec![]),
            aborted(AbortReason::UnknownFunction),
            "{f}"
        );
    }
    assert_eq!(
        call(&mut chain, &mut p, id, "public_entry", vec![]),
        TransactionOutcome::Success
    );
}

#[test]
fn a_missing_module_or_package_is_unknown() {
    let (mut chain, mut p, id) = published();
    let tx = p.call(id, "nope", "sum_is_ten", vec![]);
    assert_eq!(chain.run(tx), aborted(AbortReason::UnknownFunction));
    let tx = p.call([0x33; 32], "demo", "sum_is_ten", vec![]);
    assert_eq!(chain.run(tx), aborted(AbortReason::UnknownFunction));
}

#[test]
fn the_older_demo_packages_are_not_reachable_as_generic_calls() {
    let (mut chain, mut p, _) = published();
    let tx = p.call([1; 32], "calculator", "add", vec![u64_arg(1), u64_arg(2)]);
    // Still works, as the fixed call it always was.
    assert_eq!(chain.run(tx), TransactionOutcome::Success);
    let tx = p.call([2; 32], "counter", "nothing", vec![]);
    assert_eq!(chain.run(tx), aborted(AbortReason::UnknownFunction));
}
