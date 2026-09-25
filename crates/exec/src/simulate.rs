//! Running a call against the latest state without committing it, so a developer
//! can see what it would do and read what a package holds.
//!
//! A simulation runs the same code as a real call (`crate::entry`), with three
//! differences, all of them about looking and not changing:
//!
//! - it may also call a `public` function that is not `entry`, which may return
//!   primitives and vectors of them (a "view");
//! - nothing is signed, sequenced or paid: the sender is whoever the
//!   transaction says, and nothing is written, debited or burned. What the call
//!   *would* write and owe is reported;
//! - it is capped at [`SIMULATE_MAX_GAS`], since it is asked for by anyone who can
//!   reach the RPC and runs on the node's own thread.

use chain_types::Transaction;
use move_binary_format::errors::{Location, VMError};
use move_binary_format::file_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_core_types::runtime_value::MoveTypeLayout;
use move_core_types::vm_status::StatusCode;
use move_vm_runtime::dev_utils::gas_schedule::{Gas, GasStatus, INITIAL_COST_SCHEDULE};
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;

use crate::effects::BlockCtx;
use crate::entry::{decode_arguments, extensions_for, signature, Callable};
use crate::keys::package_key;
use crate::module_resolver::ChainStateModuleResolver;
use crate::native::State;
use crate::store::StoreExtension;
use crate::view::ViewValue;

/// The most gas a simulation may use, whatever the transaction says.
/// Measured on the alpha VPS in a release build (`docs/gas-calibration.md`): a
/// unit of gas spent on plain instructions took 8 to 11 microseconds there, so
/// this is about a tenth of a second of the node's thread at worst.
pub const SIMULATE_MAX_GAS: u64 = 10_000;

/// What a simulated call did.
#[derive(Debug, Clone, PartialEq)]
pub struct Simulation {
    pub gas_used: u64,
    /// What the function returned, decoded.
    pub returns: Vec<ViewValue>,
    /// Drawers the call would have changed.
    pub drawers_changed: usize,
    /// The storage deposit the call would have owed.
    pub deposit: u128,
}

/// Why a simulation gave no result. `Failed` is the call itself failing, as it
/// would on the chain, with what it had used and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationFailure {
    /// The transaction does not call a published package.
    NotAPackageCall,
    /// No such package, module or callable function.
    UnknownFunction,
    /// The arguments do not fit the function's parameters.
    InvalidArguments,
    /// The call failed while running.
    Failed { gas_used: u64, reason: String },
    /// Something the caller did not cause.
    Internal,
}

impl core::fmt::Display for SimulationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAPackageCall => {
                f.write_str("only calls to published packages can be simulated")
            }
            Self::UnknownFunction => {
                f.write_str("there is no such package, module or callable function")
            }
            Self::InvalidArguments => {
                f.write_str("the arguments do not fit the function's parameters")
            }
            Self::Failed { reason, .. } => write!(f, "the call failed: {reason}"),
            Self::Internal => f.write_str("the simulation could not be run"),
        }
    }
}

impl std::error::Error for SimulationFailure {}

/// The way an error from the VM reads to a developer.
fn describe(error: &VMError) -> String {
    let place = match error.location() {
        Location::Module(id) => format!(" in {}", id.short_str_lossless()),
        _ => String::new(),
    };
    match (error.major_status(), error.sub_status()) {
        (StatusCode::ABORTED, Some(code)) => format!("aborted with code {code}{place}"),
        (StatusCode::OUT_OF_GAS, _) => "ran out of gas".to_owned(),
        (status, _) => format!("{status:?}{place}"),
    }
}

pub(crate) fn simulate(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Result<Simulation, SimulationFailure> {
    let call = &tx.body.call;
    let id = AccountAddress::new(*call.module_address.as_bytes());
    if !state.contains_key(&package_key(id)) {
        return Err(SimulationFailure::NotAPackageCall);
    }
    let unknown = || SimulationFailure::UnknownFunction;
    let resolver = ChainStateModuleResolver::new(state);
    let package = resolver
        .package(id)
        .map_err(|_| SimulationFailure::Internal)?
        .ok_or_else(unknown)?;
    let module_name = std::str::from_utf8(&call.module_name).map_err(|_| unknown())?;
    let function_name = std::str::from_utf8(&call.function_name).map_err(|_| unknown())?;
    let module_bytes = Identifier::new(module_name)
        .ok()
        .and_then(|name| package.modules.get(&name))
        .ok_or_else(unknown)?;
    let module =
        CompiledModule::deserialize_with_config(module_bytes, &crate::move_config::binary_config())
            .map_err(|_| SimulationFailure::Internal)?;
    let signature =
        signature(&module, function_name, Callable::EntryOrPublic).ok_or_else(unknown)?;
    if !call.type_arguments.is_empty() {
        return Err(SimulationFailure::InvalidArguments);
    }

    let sender = AccountAddress::new(*tx.sender_address().as_bytes());
    let mut heap = BaseHeap::new();
    let values = decode_arguments(&signature.params, &call.arguments, sender, &mut heap)
        .map_err(|_| SimulationFailure::InvalidArguments)?;

    let linkage = LinkageContext::new(package.linkage_table.clone())
        .map_err(|_| SimulationFailure::Internal)?;
    let extensions = extensions_for(state, tx, ctx);
    let mut vm = runtime
        .make_vm_with_native_extensions(
            ChainStateModuleResolver::new(state),
            linkage,
            extensions.clone(),
        )
        .map_err(|_| SimulationFailure::Internal)?;
    let identifier = Identifier::new(function_name).map_err(|_| unknown())?;
    let module_id = ModuleId::new(id, Identifier::new(module_name).map_err(|_| unknown())?);
    let limit = tx.body.gas_limit.0.min(SIMULATE_MAX_GAS);
    let mut meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(limit));
    // `execute_function_bypass_visibility` so a `public` function that is not
    // `entry` can be called; what may be called was decided by `signature` above.
    let execution = vm.execute_function_bypass_visibility(
        &module_id,
        &identifier,
        vec![],
        values,
        &mut meter,
        None,
    );
    let remaining: u64 = meter.remaining_gas().into();
    let gas_used = limit.saturating_sub(remaining);
    let returned = execution.map_err(|error| SimulationFailure::Failed {
        gas_used,
        reason: describe(&error),
    })?;
    drop(vm);

    let store = extensions
        .borrow_mut()
        .remove::<StoreExtension>()
        .map_err(|_| SimulationFailure::Internal)?;
    let mut returns = Vec::with_capacity(returned.len());
    for (value, layout) in returned.into_iter().zip(signature.returns.iter()) {
        let bytes = value
            .typed_serialize(layout)
            .ok_or(SimulationFailure::Internal)?;
        returns.push(render_return(&bytes, layout).ok_or(SimulationFailure::Internal)?);
    }
    Ok(Simulation {
        gas_used,
        returns,
        drawers_changed: store.overlay.changes().len(),
        deposit: store.overlay.deposit(),
    })
}

fn render_return(bytes: &[u8], layout: &MoveTypeLayout) -> Option<ViewValue> {
    let value =
        move_core_types::runtime_value::MoveValue::simple_deserialize(bytes, layout).ok()?;
    ViewValue::from_runtime(&value)
}
