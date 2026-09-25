//! Publishing Move packages end to end: real signed transactions in real
//! blocks, real compiled Move, and the state checked afterwards.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::*;

use chain_engine_api::{AbortReason, TransactionOutcome};
use chain_exec::move_config::{MAX_MODULES_PER_PACKAGE, MAX_MODULE_BYTES};
use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
use chain_exec::publish::{
    publish_gas, MOVE_PACKAGE_ADDRESS, PUBLISH_BASE_GAS, PUBLISH_DEPOSIT_PER_KIB,
};
use chain_exec::Executor;
use chain_types::ChainId;
use move_binary_format::file_format::CompiledModule;

#[test]
fn a_package_is_stored_at_the_address_its_publisher_and_sequence_give_it() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let expected = id_of(&publisher, 0);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let stored = chain
        .package(expected)
        .expect("stored at the derived address");
    let decoded: Vec<Vec<u8>> = chain_types::codec::decode_exact(&stored).unwrap();
    assert_eq!(decoded.len(), 1);
    let module = CompiledModule::deserialize_with_defaults(&decoded[0]).unwrap();
    assert_eq!(module.self_id().address().into_bytes(), expected);
    assert_eq!(module.self_id().name().as_str(), "hello");
}

#[test]
fn a_package_of_several_modules_that_use_each_other_is_published_whole() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(TWO_MODULES).into_values().collect();
    let expected = id_of(&publisher, 0);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let stored = chain.package(expected).unwrap();
    let decoded: Vec<Vec<u8>> = chain_types::codec::decode_exact(&stored).unwrap();
    let names: Vec<String> = decoded
        .iter()
        .map(|bytes| {
            let m = CompiledModule::deserialize_with_defaults(bytes).unwrap();
            assert_eq!(m.self_id().address().into_bytes(), expected);
            m.self_id().name().to_string()
        })
        .collect();
    assert_eq!(names, ["first", "second"]);
}

#[test]
fn the_order_the_modules_are_listed_in_does_not_change_what_is_stored() {
    let (mut chain_a, mut a) = rich();
    let (mut chain_b, mut b) = rich();
    let mut forward: Vec<_> = compile(TWO_MODULES).into_values().collect();
    let expected = id_of(&a, 0);
    assert_eq!(chain_a.run(a.publish(forward.clone())), SUCCESS);
    forward.reverse();
    assert_eq!(chain_b.run(b.publish(forward)), SUCCESS);
    assert_eq!(chain_a.package(expected), chain_b.package(expected));
    assert_eq!(chain_a.executor.state_root(), chain_b.executor.state_root());
}

#[test]
fn publishing_burns_the_fee_and_the_deposit_and_nothing_else() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let total: usize = modules.iter().map(Vec::len).sum();
    let before = chain.balance(publisher.address());
    let supply = chain.executor.supply().unwrap();
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);

    let fee = u128::from(publish_gas(total)); // base fee is 1
    let deposit = NEW_ENTRY_STORAGE_DEPOSIT
        + u128::try_from(total.div_ceil(1024)).unwrap() * PUBLISH_DEPOSIT_PER_KIB;
    assert_eq!(chain.balance(publisher.address()), before - fee - deposit);
    assert_eq!(chain.executor.supply().unwrap(), supply - fee - deposit);
}

#[test]
fn the_same_package_published_twice_lands_at_two_addresses() {
    let (mut chain, mut publisher) = rich();
    let modules: Vec<_> = compile(ONE_MODULE).into_values().collect();
    let (first, second) = (id_of(&publisher, 0), id_of(&publisher, 1));
    assert_ne!(first, second);
    assert_eq!(chain.run(publisher.publish(modules.clone())), SUCCESS);
    assert_eq!(chain.run(publisher.publish(modules)), SUCCESS);
    assert!(chain.package(first).is_some());
    assert!(chain.package(second).is_some());
}

#[test]
fn two_publishers_never_share_an_address() {
    let (a, b) = (Publisher::new(1), Publisher::new(2));
    assert_ne!(id_of(&a, 0), id_of(&b, 0));
}

#[test]
fn bytes_that_are_not_a_module_are_refused_and_store_nothing() {
    let (mut chain, mut publisher) = rich();
    assert_eq!(
        chain.run(publisher.publish(vec![b"not bytecode".to_vec()])),
        REFUSED
    );
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_module_with_trailing_bytes_is_refused() {
    let (mut chain, mut publisher) = rich();
    let mut module: Vec<u8> = compile(ONE_MODULE).into_values().next().unwrap();
    module.push(0);
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
}

#[test]
fn a_module_that_names_a_real_address_for_itself_is_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile("module 0x99::elsewhere { public fun f(): u64 { 1 } }")
        .into_values()
        .next()
        .unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
}

#[test]
fn two_modules_with_one_name_are_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(
        chain.run(publisher.publish(vec![module.clone(), module])),
        REFUSED
    );
}

#[test]
fn an_import_from_an_address_outside_the_allowed_ones_is_refused() {
    let (mut chain, mut publisher) = rich();
    // Compiled against another package's address: the demo `calculator`.
    let source = "
        module 0x0101010101010101010101010101010101010101010101010101010101010101::calculator {
            public fun add(a: u64, b: u64): u64 { a + b }
        }
        module 0x0::user { public fun f(): u64 {
            0x0101010101010101010101010101010101010101010101010101010101010101::calculator::add(1, 2)
        } }";
    let all = compile(source);
    let user = all.get("user").unwrap().clone();
    assert_eq!(chain.run(publisher.publish(vec![user])), REFUSED);
}

#[test]
fn no_modules_and_too_many_modules_are_refused() {
    let (mut chain, mut publisher) = rich();
    assert_eq!(chain.run(publisher.publish(vec![])), REFUSED);
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    let many = vec![module; MAX_MODULES_PER_PACKAGE + 1];
    assert_eq!(chain.run(publisher.publish(many)), REFUSED);
}

#[test]
fn a_module_over_the_size_limit_is_refused() {
    let (mut chain, mut publisher) = rich();
    let oversize = vec![0u8; MAX_MODULE_BYTES + 1];
    assert_eq!(chain.run(publisher.publish(vec![oversize])), REFUSED);
}

#[test]
fn a_gas_limit_below_the_publish_charge_is_refused() {
    let (mut chain, mut publisher) = rich();
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    let tx = publisher.publish_with_gas(PUBLISH_BASE_GAS - 1, vec![module]);
    assert_eq!(chain.run(tx), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_refused_publish_burns_the_gas_limit_and_still_advances_the_sequence() {
    let (mut chain, mut publisher) = rich();
    let before = chain.balance(publisher.address());
    assert_eq!(
        chain.run(publisher.publish(vec![b"nope".to_vec()])),
        REFUSED
    );
    assert_eq!(
        chain.balance(publisher.address()),
        before - u128::from(PUBLISH_GAS)
    );
    // The next publish uses the next sequence number, and succeeds.
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), SUCCESS);
    assert!(chain.package(id_of(&publisher, 1)).is_some());
}

#[test]
fn a_publisher_who_cannot_pay_the_deposit_is_refused_and_pays_only_the_fee() {
    let mut chain = Chain::new();
    let mut publisher = Publisher::new(3);
    // Enough for the fee reserve, not for the deposit on top of it.
    chain.fund(
        &publisher,
        u128::from(PUBLISH_GAS) * u128::from(MAX_FEE) + 1,
    );
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(
        chain.run(publisher.publish(vec![module])),
        TransactionOutcome::Aborted(AbortReason::InsufficientBalance)
    );
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_call_to_the_publish_package_that_is_not_publish_aborts() {
    let (mut chain, publisher) = rich();
    let tx = publisher.tx_with(0, 1_000, MOVE_PACKAGE_ADDRESS, "upgrade", vec![]);
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Aborted(AbortReason::UnknownFunction)
    );
}

#[test]
fn a_module_that_deserializes_but_fails_bytecode_verification_is_refused() {
    use move_binary_format::file_format::Bytecode;
    let (mut chain, mut publisher) = rich();
    let bytes = compile(ONE_MODULE).into_values().next().unwrap();
    let mut module = CompiledModule::deserialize_with_defaults(&bytes).unwrap();
    // Pops from an empty stack: well-formed bytes, but not a safe program.
    module.function_defs[0].code.as_mut().unwrap().code = vec![Bytecode::Pop, Bytecode::Ret];
    let mut broken = Vec::new();
    module
        .serialize_with_version(module.version, &mut broken)
        .unwrap();
    assert_eq!(chain.run(publisher.publish(vec![broken])), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_chain_with_publishing_switched_off_refuses_every_publish() {
    let params = chain_modules::ParamValues {
        publish_enabled: false,
        ..chain_modules::params::GENESIS_PARAM_VALUES
    };
    let mut chain = Chain {
        executor: Executor::genesis_with_params(ChainId(1), params).unwrap(),
        now_ms: START_MS,
    };
    let mut publisher = Publisher::new(1);
    chain.fund(&publisher, 1_000_000_000_000);
    let module = compile(ONE_MODULE).into_values().next().unwrap();
    assert_eq!(chain.run(publisher.publish(vec![module])), REFUSED);
    assert!(chain.package(id_of(&publisher, 0)).is_none());
}

#[test]
fn a_module_compiled_in_test_mode_cannot_be_published() {
    // The compiler marks test-mode output as not for publishing; the chain
    // refuses to read that mark.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m.move");
    std::fs::write(
        &path,
        "module 0x0::t { #[test_only] fun helper() {} public fun f(): u64 { 1 } }",
    )
    .unwrap();
    // Test mode needs the library and its test-only `unit_test` as dependencies.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../move");
    let mut deps = Vec::new();
    for package in ["stdlib", "test-support"] {
        for entry in std::fs::read_dir(root.join(package).join("sources")).unwrap() {
            deps.push(entry.unwrap().path().to_str().unwrap().to_string());
        }
    }
    let mut one = [0u8; 32];
    one[31] = 1;
    let addresses = std::collections::BTreeMap::from([(
        "std".to_string(),
        move_compiler::shared::NumericalAddress::new(one, move_compiler::shared::NumberFormat::Hex),
    )]);
    let (_, units) = move_compiler::Compiler::from_files(
        None,
        vec![path.to_str().unwrap().to_string()],
        deps,
        addresses,
    )
    .set_flags(move_compiler::shared::Flags::testing())
    .build_and_report()
    .unwrap();
    let mut bytes = Vec::new();
    let module = units.into_iter().next().unwrap().named_module.module;
    module
        .serialize_with_version(module.version, &mut bytes)
        .unwrap();
    let (mut chain, mut publisher) = rich();
    assert_eq!(chain.run(publisher.publish(vec![bytes])), REFUSED);
}
