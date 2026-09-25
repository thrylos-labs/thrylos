//! Running a package's `#[test]` functions in the chain's own Move runtime.
//!
//! The package is compiled in test mode, its tests are found from the
//! compiler's own test plan, and each runs in a fresh VM linked to the real
//! system packages (the same bytes the chain's genesis holds) and to any
//! dependency packages given as sources. `#[expected_failure]` is honoured,
//! including its abort code. Tests that take arguments are reported as skipped.

use std::collections::BTreeMap;

use chain_exec::framework::{
    native_table, BlockInfo, FRAMEWORK_ADDRESS, FRAMEWORK_BUNDLE, STD_ADDRESS, STD_BUNDLE,
};
use chain_exec::keys::package_key;
use chain_exec::module_resolver::ChainStateModuleResolver;
use chain_state::{StateKey, StateValue};
use chain_types::codec::Encode;
use move_compiler::compiled_unit::NamedCompiledModule;
use move_compiler::shared::Flags;
use move_compiler::unit_test::{self, ExpectedFailure, MoveErrorType};
use move_compiler::{Compiler, PASS_CFGIR};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_core_types::vm_status::StatusCode;
use move_vm_runtime::dev_utils::gas_schedule::{Gas, GasStatus, INITIAL_COST_SCHEDULE};
use move_vm_runtime::natives::extensions::NativeContextExtensions;
use move_vm_runtime::shared::linkage_context::LinkageContext;
use std::cell::RefCell;
use std::rc::Rc;

use crate::compile::{
    address_table, compile_groups, dependency_groups, render, serialize, source_files, Group,
    Options, SystemSources,
};

/// The gas a test may use unless told otherwise. Generous: a test that hits it
/// is a loop that does not end, not a costly test.
pub const DEFAULT_TEST_GAS: u64 = 100_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed(String),
    Skipped(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    /// `module::test_name`.
    pub name: String,
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestReport {
    pub results: Vec<TestResult>,
}

impl TestReport {
    pub fn passed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Passed))
    }
    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Failed(_)))
    }
    pub fn skipped(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Skipped(_)))
    }
    fn count(&self, keep: impl Fn(&Outcome) -> bool) -> usize {
        self.results.iter().filter(|r| keep(&r.outcome)).count()
    }
    /// Every test that ran passed (skipped ones are not failures).
    pub fn ok(&self) -> bool {
        self.failed() == 0
    }
}

/// A package's modules as the state holds them: `Vec<Vec<u8>>` by module name.
fn install(
    state: &mut BTreeMap<StateKey, StateValue>,
    address: AccountAddress,
    modules: BTreeMap<String, Vec<u8>>,
) {
    let ordered: Vec<Vec<u8>> = modules.into_values().collect();
    let mut bytes = Vec::new();
    ordered.encode(&mut bytes);
    state.insert(package_key(address), StateValue::new(bytes));
}

/// Modules grouped into packages by the address they are at.
fn by_address(
    units: &[NamedCompiledModule],
) -> Result<BTreeMap<AccountAddress, BTreeMap<String, Vec<u8>>>, String> {
    let mut packages: BTreeMap<AccountAddress, BTreeMap<String, Vec<u8>>> = BTreeMap::new();
    for unit in units {
        packages
            .entry(*unit.module.self_id().address())
            .or_default()
            .insert(
                unit.module.self_id().name().to_string(),
                serialize(&unit.module)?,
            );
    }
    Ok(packages)
}

/// Whether a VM error is the failure a test said to expect.
fn matches_expected(
    expected: &ExpectedFailure,
    status: StatusCode,
    sub_status: Option<u64>,
) -> bool {
    let code_matches = |wanted: &MoveErrorType| match wanted {
        MoveErrorType::Code(code) => sub_status == Some(*code),
        // A constant's value is resolved by the compiler into the abort code it
        // holds; if it was left by name, any abort code is accepted.
        MoveErrorType::ConstantName(_) => true,
    };
    match expected {
        ExpectedFailure::Expected => true,
        ExpectedFailure::ExpectedWithCodeDEPRECATED(wanted) => {
            status == StatusCode::ABORTED && code_matches(wanted)
        }
        ExpectedFailure::ExpectedWithError(error) => {
            status == error.0 && error.1.as_ref().is_none_or(code_matches)
        }
    }
}

/// Run the tests of the package in `options.dir`, those whose `module::name`
/// contains `filter` if one is given.
pub fn run_tests(options: &Options, filter: Option<&str>, gas: u64) -> Result<TestReport, String> {
    let plain = SystemSources::write(false)?;
    let system = SystemSources::write(true)?;

    // Dependency packages, as bytecode at the addresses they were published at.
    let mut dependency_packages = BTreeMap::new();
    if !options.deps.is_empty() {
        let mut groups = dependency_groups(options, &plain.files)?;
        // The system group is only what they are compiled against; each
        // dependency is also a target.
        let targets = groups.split_off(1);
        let units = compile_groups(targets, groups, false)?;
        dependency_packages = by_address(&units)?;
    }

    // The package itself, in test mode.
    let target = Group {
        files: source_files(&options.dir)?
            .iter()
            .map(|path| {
                path.to_str()
                    .map(str::to_owned)
                    .ok_or("a path is not valid text")
            })
            .collect::<Result<_, _>>()?,
        addresses: address_table(options)?,
    };
    let dependencies = dependency_groups(options, &system.files)?;
    let mut compiler = Compiler::from_package_paths(
        None,
        vec![move_compiler::shared::PackagePaths {
            name: None,
            paths: target.files,
            named_address_map: target.addresses,
        }],
        dependencies
            .into_iter()
            .map(|group| move_compiler::shared::PackagePaths {
                name: None,
                paths: group.files,
                named_address_map: group.addresses,
            })
            .collect(),
    )
    .map_err(|error| error.to_string())?;
    compiler = compiler.set_flags(Flags::testing());
    let (files, result) = compiler
        .run::<PASS_CFGIR>()
        .map_err(|error| error.to_string())?;
    let compiler = match result {
        Ok(compiler) => compiler,
        Err((_pass, diagnostics)) => return Err(render(&files, diagnostics)),
    };
    let (compiler, cfgir) = compiler.into_ast();
    let plan =
        unit_test::plan_builder::construct_test_plan(compiler.compilation_env(), None, &cfgir)
            .unwrap_or_default();
    let built = compiler.at_cfgir(cfgir).build();
    let units: Vec<NamedCompiledModule> = match built {
        Ok((units, warnings)) => {
            if !warnings.is_empty() {
                eprint!("{}", render(&files, warnings));
            }
            units.into_iter().map(|unit| unit.named_module).collect()
        }
        Err((_pass, diagnostics)) => return Err(render(&files, diagnostics)),
    };

    // The two test-only library modules, compiled here, joined to the chain's
    // standard library in one package at 0x1.
    let support_files: Vec<String> = system
        .files
        .iter()
        .filter(|file| file.contains("test-support"))
        .cloned()
        .collect();
    let support = compile_groups(
        vec![Group::system_of(support_files)],
        vec![Group::system_of(plain.files.clone())],
        true,
    )?;
    let mut std_modules: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let chain_std: Vec<Vec<u8>> =
        chain_types::codec::decode_exact(STD_BUNDLE).map_err(|error| error.to_string())?;
    for bytes in chain_std {
        let module =
            move_binary_format::file_format::CompiledModule::deserialize_with_defaults(&bytes)
                .map_err(|error| error.to_string())?;
        std_modules.insert(module.self_id().name().to_string(), bytes);
    }
    for unit in &support {
        std_modules.insert(
            unit.module.self_id().name().to_string(),
            serialize(&unit.module)?,
        );
    }

    // Everything the tests run against, as chain state.
    let mut state = BTreeMap::new();
    install(&mut state, STD_ADDRESS, std_modules);
    state.insert(
        package_key(FRAMEWORK_ADDRESS),
        StateValue::new(FRAMEWORK_BUNDLE.to_vec()),
    );
    for (address, modules) in dependency_packages {
        install(&mut state, address, modules);
    }
    for (address, modules) in by_address(&units)? {
        install(&mut state, address, modules);
    }

    let runtime = test_runtime()?;
    let mut report = TestReport::default();
    for module_plan in &plan {
        let module_id = &module_plan.module_id;
        for (test_name, case) in &module_plan.tests {
            let label = format!("{}::{test_name}", module_id.name());
            if filter.is_some_and(|wanted| !label.contains(wanted)) {
                continue;
            }
            if !case.arguments.is_empty() {
                report.results.push(TestResult {
                    name: label,
                    outcome: Outcome::Skipped(
                        "tests that take arguments are not supported yet".into(),
                    ),
                });
                continue;
            }
            let outcome = run_one(
                &runtime,
                &state,
                module_id,
                test_name,
                case.expected_failure.as_ref(),
                gas,
            );
            report.results.push(TestResult {
                name: label,
                outcome,
            });
        }
    }
    Ok(report)
}

fn run_one(
    runtime: &move_vm_runtime::runtime::MoveRuntime,
    state: &BTreeMap<StateKey, StateValue>,
    module_id: &ModuleId,
    test_name: &str,
    expected: Option<&ExpectedFailure>,
    gas: u64,
) -> Outcome {
    let resolver = ChainStateModuleResolver::allowing_test_modules(state);
    let package = match resolver.package(*module_id.address()) {
        Ok(Some(package)) => package,
        _ => return Outcome::Failed("the test's package could not be loaded".into()),
    };
    let Ok(linkage) = LinkageContext::new(package.linkage_table.clone()) else {
        return Outcome::Failed("the test's package could not be linked".into());
    };
    let extensions = Rc::new(RefCell::new(NativeContextExtensions::default()));
    extensions.borrow_mut().add(BlockInfo {
        height: 1,
        time_ms: 1_700_000_000_000,
        chain_id: 0,
    });
    let mut vm = match runtime.make_vm_with_native_extensions(
        ChainStateModuleResolver::allowing_test_modules(state),
        linkage,
        extensions,
    ) {
        Ok(vm) => vm,
        Err(error) => {
            return Outcome::Failed(format!("the package could not be loaded: {error:?}"))
        }
    };
    let Ok(function) = Identifier::new(test_name) else {
        return Outcome::Failed("not a function name".into());
    };
    let mut meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(gas));
    let result = vm.execute_function_bypass_visibility(
        module_id,
        &function,
        vec![],
        vec![],
        &mut meter,
        None,
    );
    match (result, expected) {
        (Ok(_), None) => Outcome::Passed,
        (Ok(_), Some(_)) => Outcome::Failed("expected the test to fail, but it passed".into()),
        (Err(error), None) => Outcome::Failed(describe(&error)),
        (Err(error), Some(wanted)) => {
            if matches_expected(wanted, error.major_status(), error.sub_status()) {
                Outcome::Passed
            } else {
                Outcome::Failed(format!(
                    "it failed, but not as expected: {}",
                    describe(&error)
                ))
            }
        }
    }
}

fn describe(error: &move_binary_format::errors::VMError) -> String {
    match (error.major_status(), error.sub_status()) {
        (StatusCode::ABORTED, Some(code)) => format!("aborted with code {code}"),
        (StatusCode::OUT_OF_GAS, _) => "ran out of gas (does it loop forever?)".to_owned(),
        (status, _) => format!("{status:?}"),
    }
}

/// The chain's runtime, plus the natives only tests use: `std::debug` (which
/// prints) and `std::unit_test`.
fn test_runtime() -> Result<move_vm_runtime::runtime::MoveRuntime, String> {
    use move_core_types::gas_algebra::InternalGas;
    use move_vm_runtime::natives::functions::{
        make_table, NativeFunction, NativeFunctions, NativeResult,
    };
    use move_vm_runtime::natives::move_stdlib::{stdlib_native_function_table, GasParameters};
    use smallvec::smallvec;
    use std::sync::Arc;

    let mut table = native_table();
    // The library's `debug` natives, which the chain's table leaves out.
    table.extend(
        stdlib_native_function_table(STD_ADDRESS, GasParameters::zeros(), false)
            .into_iter()
            .filter(|(_, module, _, _)| module.as_str() == "debug"),
    );
    let nothing = || -> NativeFunction {
        Arc::new(|_context, _types, _arguments| {
            Ok(NativeResult::ok(InternalGas::new(0), smallvec![]))
        })
    };
    table.extend(make_table(
        STD_ADDRESS,
        [
            ("unit_test", "poison", nothing()),
            ("unit_test", "destroy", nothing()),
        ],
    ));
    let natives = NativeFunctions::new(table).map_err(|error| format!("natives: {error}"))?;
    let mut config = chain_exec::move_config::vm_config();
    // Test-mode modules carry a mark that they are not for publishing.
    config.binary_config = move_binary_format::binary_config::BinaryConfig::new_unpublishable();
    Ok(move_vm_runtime::runtime::MoveRuntime::new(natives, config))
}
