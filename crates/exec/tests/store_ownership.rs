//! The rule that makes storage safe (`docs/move-storage-design.md`, D7): only the
//! module that defines a type may keep it in a drawer. Every way of trying to
//! get round it, published through the real chain, and the ways that are allowed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::*;

use chain_engine_api::{AbortReason, TransactionOutcome};
use chain_exec::publish::{prepare, store_violations, PublishError};
use move_binary_format::file_format::CompiledModule;
use move_core_types::account_address::AccountAddress;

const OK: TransactionOutcome = TransactionOutcome::Success;
const REFUSED: TransactionOutcome = TransactionOutcome::Aborted(AbortReason::PublishRefused);

fn hex(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Publish every module `source` defines at `0x0`, except those in `skip`.
fn publish(
    chain: &mut Chain,
    p: &mut Publisher,
    source: &str,
    only: &[&str],
) -> ([u8; 32], TransactionOutcome) {
    let id = id_of(p, p.sequence);
    let mut all = compile_with_system_packages(source);
    let modules: Vec<Vec<u8>> = if only.is_empty() {
        all.into_values().collect()
    } else {
        only.iter().map(|name| all.remove(*name).unwrap()).collect()
    };
    (id, chain.run(p.publish(modules)))
}

fn outcome(source: &str, only: &[&str]) -> TransactionOutcome {
    let (mut chain, mut p) = rich();
    publish(&mut chain, &mut p, source, only).1
}

// ---- what is allowed -------------------------------------------------------

#[test]
fn a_module_may_store_the_types_it_defines_in_every_shape() {
    let source = "
    module pkg::app {
        use thrylos::store;
        public struct Plain has key, store, copy, drop { n: u64 }
        public struct Wrapper<T: store> has key, store, copy, drop { v: T }
        public enum Kind has key, store, copy, drop { A, B(u64) }
        public struct Linear has key, store { n: u64 }

        entry fun all_four(o: address) {
            store::put(o, 0, Plain { n: 1 });
            assert!(store::has<Plain>(o, 0), 1);
            let _c = store::read<Plain>(o, 0);
            let _t = store::take<Plain>(o, 0);
        }
        // Its own generic type, with a type from anywhere else inside it.
        entry fun instantiated(o: address) {
            store::put(o, 0, Wrapper<Option<u64>> { v: option::some(1) });
            store::put(o, 1, Wrapper<vector<u8>> { v: b\"x\" });
        }
        // Its own generic type over a type parameter: still its own type.
        public fun generic<T: store>(o: address, v: T) { store::put(o, 0, Wrapper<T> { v }); }
        public fun generic_back<T: store>(o: address): T {
            let Wrapper { v } = store::take<Wrapper<T>>(o, 0);
            v
        }
        entry fun enums(o: address) { store::put(o, 0, Kind::B(3)); let _k = store::take<Kind>(o, 0); }
        entry fun linear(o: address) { store::put(o, 0, Linear { n: 8 }); let Linear { n: _ } = store::take<Linear>(o, 0); }
    }";
    assert_eq!(outcome(source, &[]), OK);
}

#[test]
fn a_package_that_never_touches_the_store_is_unaffected() {
    assert_eq!(
        outcome("module 0x0::m { public fun f(): u64 { 1 } }", &[]),
        OK
    );
}

#[test]
fn a_module_that_merely_is_called_store_is_not_the_framework_store() {
    // The rule is about `0x2::store` exactly: a package's own module of that name,
    // with its own generic functions, is nothing special.
    let source = "
    module pkg::store { public fun put<T: drop>(_v: T) {} }
    module pkg::app { entry fun f() { pkg::store::put(1u64); pkg::store::put(vector[1u8]); } }";
    assert_eq!(outcome(source, &[]), OK);
}

// ---- what is refused -------------------------------------------------------

#[test]
fn a_function_generic_over_the_stored_type_is_refused_for_every_operation() {
    for function in [
        "public fun leak<T: key>(o: address, v: T) { store::put(o, 0, v); }",
        "public fun leak<T: key>(o: address): T { store::take<T>(o, 0) }",
        "public fun leak<T: key>(o: address): bool { store::has<T>(o, 0) }",
        "public fun leak<T: key + copy>(o: address): T { store::read<T>(o, 0) }",
    ] {
        let source = format!("module pkg::app {{ use thrylos::store; {function} }}");
        assert_eq!(outcome(&source, &[]), REFUSED, "{function}");
    }
}

#[test]
fn another_modules_type_in_the_same_package_is_refused() {
    let source = "
    module pkg::theirs { public struct Token has key, store { n: u64 } public fun mint(): Token { Token { n: 1 } } }
    module pkg::thief {
        use thrylos::store;
        entry fun steal(o: address) { store::put(o, 0, pkg::theirs::mint()); }
    }";
    assert_eq!(outcome(source, &[]), REFUSED);
}

#[test]
fn a_type_from_another_published_package_is_refused() {
    let (mut chain, mut p) = rich();
    let (theirs, out) = publish(
        &mut chain,
        &mut p,
        "module pkg::vault { public struct Coin has key, store { n: u64 } public fun new(): Coin { Coin { n: 1 } } }",
        &[],
    );
    assert_eq!(out, OK);
    let source = format!(
        "module 0x{a}::vault {{ public struct Coin has key, store {{ n: u64 }} public fun new(): Coin {{ Coin {{ n: 1 }} }} }}
         module pkg::thief {{
             use thrylos::store;
             entry fun steal(o: address) {{ store::put(o, 0, 0x{a}::vault::new()); }}
         }}",
        a = hex(theirs)
    );
    let (_, out) = publish(&mut chain, &mut p, &source, &["thief"]);
    assert_eq!(out, REFUSED);
}

#[test]
fn one_bad_module_refuses_the_whole_package() {
    let source = "
    module pkg::good { use thrylos::store; public struct Mine has key, store { n: u64 } entry fun f(o: address) { store::put(o, 0, Mine { n: 1 }); } }
    module pkg::bad { use thrylos::store; public fun leak<T: key>(o: address, v: T) { store::put(o, 0, v); } }";
    assert_eq!(outcome(source, &[]), REFUSED);
    assert_eq!(
        outcome(source, &["good"]),
        OK,
        "the good module alone is fine"
    );
}

#[test]
fn a_module_that_declares_its_own_native_function_is_refused() {
    // Natives are matched by the address and name of the module that declares
    // them, and nothing is registered for a published package's address.
    let source = "module pkg::evil { public native fun put<T: key>(o: address, slot: u64, v: T); }";
    assert_eq!(outcome(source, &[]), REFUSED);
}

// ---- the check itself, on bytecode -----------------------------------------

fn modules(source: &str) -> std::collections::BTreeMap<String, CompiledModule> {
    compile_with_system_packages(source)
        .into_iter()
        .map(|(name, bytes)| {
            (
                name,
                CompiledModule::deserialize_with_defaults(&bytes).unwrap(),
            )
        })
        .collect()
}

const THIEF: &str = "
module pkg::theirs { public struct Token has key, store { n: u64 } public fun mint(): Token { Token { n: 1 } } }
module pkg::thief {
    use thrylos::store;
    entry fun steal(o: address) { store::put(o, 0, pkg::theirs::mint()); }
    public fun leak<T: key>(o: address, v: T) { store::put(o, 1, v); }
    public struct Mine has key, store { n: u64 }
    entry fun mine(o: address) { store::put(o, 2, Mine { n: 1 }); }
}";

#[test]
fn the_scan_names_each_offending_call_and_only_those() {
    let m = modules(THIEF);
    let found = store_violations(&m["thief"]);
    let mut described: Vec<(String, String)> = found
        .iter()
        .map(|v| (v.function.clone(), v.found.clone()))
        .collect();
    described.sort();
    assert_eq!(
        described,
        vec![
            ("put".to_owned(), "a type parameter".to_owned()),
            ("put".to_owned(), "theirs::Token".to_owned()),
        ]
    );
    assert!(store_violations(&m["theirs"]).is_empty());
}

#[test]
fn a_foreign_type_relabelled_as_the_modules_own_is_still_caught() {
    // Hand-made bytecode: the handle for `theirs::Token` is pointed at the
    // module's own handle. The module has no definition for it, so the scan
    // does not take the claim for proof.
    let mut m = modules(THIEF).remove("thief").unwrap();
    let own = m.self_handle_idx();
    let token = m
        .datatype_handles
        .iter()
        .position(|h| m.identifier_at(h.name).as_str() == "Token")
        .expect("the foreign Token handle");
    m.datatype_handles[token].module = own;
    let found = store_violations(&m);
    assert!(
        found
            .iter()
            .any(|v| v.function == "put" && v.found.ends_with("::Token")),
        "{found:?}"
    );
}

#[test]
fn the_error_a_developer_sees_says_which_call_and_why() {
    let m = modules(THIEF);
    let bytes: Vec<Vec<u8>> = compile_with_system_packages(THIEF)
        .into_iter()
        .filter(|(name, _)| name == "thief" || name == "theirs")
        .map(|(_, b)| b)
        .collect();
    let error = prepare(&bytes, AccountAddress::new([1; 32]), |_| true).unwrap_err();
    let text = error.to_string();
    assert!(
        matches!(error, PublishError::StoreTypeNotOwned { .. }),
        "{text}"
    );
    assert!(
        text.contains("thief") && text.contains("put") && text.contains("does not define"),
        "{text}"
    );
    let _ = m;
}
