//! Compiles and publishes this executor's one fixed system package.
//! `docs/spec.md`'s "Native module boundary" describes a frozen list of
//! entry points, published once and changed only by a fork — for this
//! pass, a single fixed test module stands in for that; a real module-
//! publishing transaction type is future work (see `crate`'s doc
//! comment).
//!
//! This compiles Move source at genesis using `move-compiler` directly,
//! which means real file I/O (via `tempfile`) at construction time —
//! acceptable for this pass, but not how a real deployment would work:
//! production genesis should embed pre-compiled bytecode built ahead of
//! time, with the running executor never touching a compiler or a
//! filesystem.

use std::collections::BTreeMap;
use std::io::Write;

use chain_state::{StateKey, StateValue};
use move_binary_format::file_format::CompiledModule;
use move_compiler::Compiler as MoveCompiler;
use move_core_types::account_address::AccountAddress;

use crate::keys::{module_key, object_key};

pub const SYSTEM_PACKAGE_ADDRESS: AccountAddress =
    AccountAddress::new([1u8; AccountAddress::LENGTH]);
pub const SYSTEM_MODULE_NAME: &str = "calculator";
pub const SYSTEM_FUNCTION_NAME: &str = "add";

/// A second, independent single-module package (see `module_resolver`'s
/// doc comment on why each package gets its own address in this pass)
/// holding the one object type this pass supports.
pub const COUNTER_PACKAGE_ADDRESS: AccountAddress =
    AccountAddress::new([2u8; AccountAddress::LENGTH]);
pub const COUNTER_MODULE_NAME: &str = "counter";
pub const COUNTER_STRUCT_NAME: &str = "Counter";
pub const COUNTER_BUMP_FUNCTION: &str = "bump";

/// The one `Counter` object this pass seeds at genesis, for
/// transactions to declare and mutate.
pub const INITIAL_COUNTER_ADDRESS: AccountAddress =
    AccountAddress::new([3u8; AccountAddress::LENGTH]);
pub const INITIAL_COUNTER_VALUE: u64 = 0;

#[derive(Debug)]
pub enum GenesisError {
    Io(std::io::Error),
    Compilation(String),
    NoModuleProduced,
    Serialization(String),
}

impl core::fmt::Display for GenesisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "genesis compilation I/O error: {err}"),
            Self::Compilation(msg) => write!(f, "genesis module failed to compile: {msg}"),
            Self::NoModuleProduced => f.write_str("genesis compilation produced no module"),
            Self::Serialization(msg) => write!(f, "genesis module failed to serialize: {msg}"),
        }
    }
}

impl std::error::Error for GenesisError {}

impl From<std::io::Error> for GenesisError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Compile the fixed system modules and return the initial chain state
/// with them published — plus one seeded `Counter` object for
/// transactions to declare and mutate.
pub fn genesis_state() -> Result<BTreeMap<StateKey, StateValue>, GenesisError> {
    let mut state = BTreeMap::new();

    let calculator_source = format!(
        r#"
        module 0x{SYSTEM_PACKAGE_ADDRESS}::{SYSTEM_MODULE_NAME} {{
            public fun {SYSTEM_FUNCTION_NAME}(a: u64, b: u64): u64 {{
                a + b
            }}
        }}
        "#
    );
    publish_module(&mut state, SYSTEM_PACKAGE_ADDRESS, &calculator_source)?;

    let counter_source = format!(
        r#"
        module 0x{COUNTER_PACKAGE_ADDRESS}::{COUNTER_MODULE_NAME} {{
            public struct {COUNTER_STRUCT_NAME} has store, drop {{
                value: u64,
            }}

            public fun {COUNTER_BUMP_FUNCTION}(counter: &mut {COUNTER_STRUCT_NAME}, amount: u64) {{
                counter.value = counter.value + amount;
            }}
        }}
        "#
    );
    publish_module(&mut state, COUNTER_PACKAGE_ADDRESS, &counter_source)?;

    state.insert(
        object_key(INITIAL_COUNTER_ADDRESS),
        StateValue::new(INITIAL_COUNTER_VALUE.to_le_bytes().to_vec()),
    );

    Ok(state)
}

fn publish_module(
    state: &mut BTreeMap<StateKey, StateValue>,
    address: AccountAddress,
    source: &str,
) -> Result<(), GenesisError> {
    let module = compile_single_module(source)?;
    let mut bytes = Vec::new();
    module
        .serialize_with_version(module.version, &mut bytes)
        .map_err(|err| GenesisError::Serialization(err.to_string()))?;
    state.insert(module_key(address), StateValue::new(bytes));
    Ok(())
}

fn compile_single_module(source: &str) -> Result<CompiledModule, GenesisError> {
    let dir = tempfile::tempdir()?;
    let file_path = dir.path().join("module.move");
    {
        let mut file = std::fs::File::create(&file_path)?;
        writeln!(file, "{source}")?;
    }

    let compiled = MoveCompiler::from_files(
        None,
        vec![file_path
            .to_str()
            .ok_or_else(|| GenesisError::Compilation("non-utf8 temp path".to_string()))?
            .to_string()],
        vec![],
        BTreeMap::<String, move_compiler::shared::NumericalAddress>::new(),
    )
    .build_and_report();

    dir.close()?;

    let (_, mut units) = compiled.map_err(|err| GenesisError::Compilation(err.to_string()))?;
    if units.is_empty() {
        return Err(GenesisError::NoModuleProduced);
    }
    Ok(units.remove(0).named_module.module)
}
