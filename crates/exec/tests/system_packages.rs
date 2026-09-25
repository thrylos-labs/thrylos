//! The standard library at `0x1` and the Thrylos framework at `0x2`, used by
//! published packages the way a developer would.

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
module 0x0::uses_std {
    use std::bcs;
    use std::hash;
    use std::string;
    use thrylos::chain;
    use thrylos::signer;

    entry fun vectors() {
        let mut v = vector[1u64, 2, 3];
        v.push_back(4);
        assert!(v.length() == 4, 1);
        assert!(v.pop_back() == 4, 2);
    }
    entry fun options() {
        let o = option::some(5u64);
        assert!(o.is_some() && *o.borrow() == 5, 1);
    }
    entry fun hashing() {
        assert!(hash::sha2_256(b\"abc\").length() == 32, 1);
        assert!(hash::sha3_256(b\"abc\").length() == 32, 2);
    }
    entry fun strings() {
        let s = string::utf8(b\"h\\xc3\\xa9llo\");
        assert!(s.length() == 6, 1);
    }
    entry fun encoding() { assert!(bcs::to_bytes(&7u64).length() == 8, 1); }
    entry fun sender_is(s: &signer, a: address) { assert!(signer::address_of(s) == a, 1); }
    entry fun time_is(t: u64) { assert!(chain::block_time_ms() == t, 1); }
    entry fun height_is(h: u64) { assert!(chain::height() == h, 1); }
    entry fun chain_id_is(c: u64) { assert!(chain::chain_id() == c, 1); }
    entry fun hash_loop(n: u64) {
        let mut i = 0;
        while (i < n) { let _ = hash::sha3_256(b\"abcdefghijklmnopqrstuvwxyz\"); i = i + 1; };
    }
}";

fn published() -> (Chain, Publisher, [u8; 32]) {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile_with_system_packages(SOURCE).into_values().collect();
    let id = id_of(&publisher, 0);
    assert_eq!(
        chain.run(publisher.publish(modules)),
        TransactionOutcome::Success,
        "a package that imports 0x1 and 0x2 publishes"
    );
    (chain, publisher, id)
}

fn call(
    chain: &mut Chain,
    p: &mut Publisher,
    id: [u8; 32],
    f: &str,
    args: Vec<Vec<u8>>,
) -> TransactionOutcome {
    let tx = p.call(id, "uses_std", f, args);
    chain.run(tx)
}

const OK: TransactionOutcome = TransactionOutcome::Success;

#[test]
fn library_functions_run() {
    let (mut chain, mut p, id) = published();
    for f in ["vectors", "options", "hashing", "strings", "encoding"] {
        assert_eq!(call(&mut chain, &mut p, id, f, vec![]), OK, "{f}");
    }
}

#[test]
fn a_function_can_read_its_senders_address_and_only_that() {
    let (mut chain, mut p, id) = published();
    let me = p.address().as_bytes().to_vec();
    assert_eq!(call(&mut chain, &mut p, id, "sender_is", vec![me]), OK);
    assert_eq!(
        call(&mut chain, &mut p, id, "sender_is", vec![vec![9; 32]]),
        TransactionOutcome::Aborted(AbortReason::ExecutionFailed)
    );
}

#[test]
fn a_function_reads_the_block_it_runs_in() {
    let (mut chain, mut p, id) = published();
    let (height, time) = chain.next_block();
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "height_is",
            vec![height.to_le_bytes().to_vec()]
        ),
        OK
    );
    let (_, time2) = chain.next_block();
    assert!(time2 > time);
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "time_is",
            vec![time2.to_le_bytes().to_vec()]
        ),
        OK
    );
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "chain_id_is",
            vec![1u64.to_le_bytes().to_vec()]
        ),
        OK
    );
    // And a wrong guess is a failure, so the reads are real.
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "height_is",
            vec![0u64.to_le_bytes().to_vec()]
        ),
        TransactionOutcome::Aborted(AbortReason::ExecutionFailed)
    );
}

#[test]
fn hashing_is_charged_per_call_and_a_long_loop_of_it_runs_out_of_gas() {
    let (mut chain, mut p, id) = published();
    let few = {
        let before = chain.balance(p.address());
        assert_eq!(
            call(
                &mut chain,
                &mut p,
                id,
                "hash_loop",
                vec![200u64.to_le_bytes().to_vec()]
            ),
            OK
        );
        before - chain.balance(p.address())
    };
    let many = {
        let before = chain.balance(p.address());
        assert_eq!(
            call(
                &mut chain,
                &mut p,
                id,
                "hash_loop",
                vec![1000u64.to_le_bytes().to_vec()]
            ),
            OK
        );
        before - chain.balance(p.address())
    };
    assert!(
        many > few,
        "a thousand hashes cost more than two hundred: {many} vs {few}"
    );
    // The natives' own charge is in it: without it a thousand hashes cost
    // about 2,400 in all.
    assert!(many > 5_000, "{many}");
    assert_eq!(
        call(
            &mut chain,
            &mut p,
            id,
            "hash_loop",
            vec![u64::MAX.to_le_bytes().to_vec()]
        ),
        TransactionOutcome::Aborted(AbortReason::ExecutionFailed)
    );
}

#[test]
fn the_system_packages_themselves_have_no_callable_entry_functions() {
    let (mut chain, mut p, _) = published();
    let mut one = [0u8; 32];
    one[31] = 1;
    let tx = p.call(one, "vector", "empty", vec![]);
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Aborted(AbortReason::UnknownFunction)
    );
}
