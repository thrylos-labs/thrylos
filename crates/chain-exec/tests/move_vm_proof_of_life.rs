//! Proof of life for the MoveVM dependency itself: compile real Move
//! source, publish it, execute a function, and check the result — not
//! just that the git dependency builds.
//!
//! This is deliberately not chain-exec's production API. There isn't
//! one yet: this test uses `move_vm_runtime::dev_utils`'s own in-memory
//! test adapter directly, not `chain-state`. The real block executor —
//! bridging `chain-state`'s trie to MoveVM's storage/resolver interface,
//! declared-object enforcement, real gas metering tied to a fee
//! schedule, and the `chain-engine-api::Engine` trait — is future work.
//! What this proves: the pinned dependency, once wired up, produces a
//! working VM that compiles and runs real Move code end to end.
//!
//! `move_vm_runtime::dev_utils::compilation_utils` (which the crate's
//! own tests use for exactly this) is `#[cfg(test)]`-gated inside that
//! crate, so it isn't visible to us as a downstream dependency — the
//! `compile_units` helper below reimplements the same handful of lines,
//! using `move-compiler` directly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use move_binary_format::file_format::CompiledModule;
use move_compiler::Compiler as MoveCompiler;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_vm_runtime::dev_utils::in_memory_test_adapter::InMemoryTestAdapter;
use move_vm_runtime::dev_utils::storage::StoredPackage;
use move_vm_runtime::dev_utils::vm_test_adapter::VMTestAdapter;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::shared::gas::UnmeteredGasMeter;
use std::io::Write;

/// Compile `source` (one `.move` file's worth of text) into its
/// annotated compiled modules. Reimplements
/// `move_vm_runtime::dev_utils::compilation_utils::compile_units`,
/// which isn't reachable from outside that crate.
fn compile_modules(source: &str) -> Vec<CompiledModule> {
    let dir = tempfile::tempdir().expect("create temp dir");
    let file_path = dir.path().join("module.move");
    {
        let mut file = std::fs::File::create(&file_path).expect("create temp file");
        writeln!(file, "{source}").expect("write source");
    }

    let (_, units) = MoveCompiler::from_files(
        None,
        vec![file_path.to_str().expect("utf8 path").to_string()],
        vec![],
        std::collections::BTreeMap::<String, move_compiler::shared::NumericalAddress>::new(),
    )
    .build_and_report()
    .expect("Move source failed to compile");

    dir.close().expect("clean up temp dir");
    units
        .into_iter()
        .map(|unit| unit.named_module.module)
        .collect()
}

const TEST_ADDR: AccountAddress = AccountAddress::new([7; AccountAddress::LENGTH]);

#[test]
fn compiles_publishes_and_executes_a_real_move_function() {
    let source = format!(
        r#"
        module 0x{TEST_ADDR}::calculator {{
            public fun add(a: u64, b: u64): u64 {{
                a + b
            }}
        }}
        "#
    );

    let modules = compile_modules(&source);
    assert_eq!(modules.len(), 1, "expected exactly one compiled module");

    let mut adapter = InMemoryTestAdapter::new();
    let package = StoredPackage::from_modules_for_testing(TEST_ADDR, modules)
        .expect("assemble package from compiled modules");
    adapter.insert_package_into_storage(package);

    let linkage = adapter
        .get_linkage_context(TEST_ADDR)
        .expect("build linkage context for the published package");
    let mut vm = adapter.make_vm(linkage).expect("construct a VM instance");

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("calculator").unwrap());
    let function_name = Identifier::new("add").unwrap();

    let mut returned = vm
        .execute_function_bypass_visibility(
            &module_id,
            &function_name,
            vec![],
            vec![Value::u64(2), Value::u64(40)],
            &mut UnmeteredGasMeter,
            None,
        )
        .expect("executing add(2, 40) should succeed");

    assert_eq!(returned.len(), 1, "add returns exactly one value");
    let sum: u64 = returned
        .remove(0)
        .value_as()
        .expect("returned value is a u64");
    assert_eq!(sum, 42);
}

#[test]
fn an_abort_inside_move_is_reported_as_an_execution_error_not_a_panic() {
    // `docs/spec.md`, "Execution": "Aborts consume gas and roll back the
    // transaction's effects, but never abort the block" — the VM must
    // surface this as a normal error the caller handles, never as a
    // process-level panic, however the real executor eventually chooses
    // to react to it.
    let source = format!(
        r#"
        module 0x{TEST_ADDR}::calculator {{
            public fun always_aborts(): u64 {{
                abort 1
            }}
        }}
        "#
    );

    let modules = compile_modules(&source);
    let mut adapter = InMemoryTestAdapter::new();
    let package = StoredPackage::from_modules_for_testing(TEST_ADDR, modules).unwrap();
    adapter.insert_package_into_storage(package);

    let linkage = adapter.get_linkage_context(TEST_ADDR).unwrap();
    let mut vm = adapter.make_vm(linkage).unwrap();

    let module_id = ModuleId::new(TEST_ADDR, Identifier::new("calculator").unwrap());
    let function_name = Identifier::new("always_aborts").unwrap();

    let result = vm.execute_function_bypass_visibility(
        &module_id,
        &function_name,
        vec![],
        vec![],
        &mut UnmeteredGasMeter,
        None,
    );

    assert!(
        result.is_err(),
        "an abort must surface as an Err, not a panic"
    );
}
