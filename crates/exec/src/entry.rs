//! Calling an entry function of a published Move package.
//!
//! A call names a package address, a module and a function; each argument is
//! the BCS encoding of one parameter, in order. What the call may do is
//! decided by the function's own signature, read from the published module,
//! never by the transaction:
//!
//! - the function must be `entry`, not generic, and return nothing;
//! - a first parameter of type `signer` or `&signer` is the transaction's
//!   sender, supplied by the chain and not by an argument;
//! - every other parameter must be a primitive (`bool`, `u8` to `u256`,
//!   `address`) or a vector of them, nested at most [`MAX_VECTOR_DEPTH`]
//!   deep, and takes the next argument.
//!
//! Anything else (an object reference, a struct, a type argument) makes the
//! function not callable in this stage and the call aborts. Running it is
//! metered against the transaction's gas limit; a call has no writes yet, so
//! what it costs is all it does, other than aborting or not.

use chain_engine_api::AbortReason;
use chain_types::Transaction;
use move_binary_format::file_format::{CompiledModule, SignatureToken};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_core_types::runtime_value::MoveTypeLayout;
use move_vm_runtime::dev_utils::gas_schedule::{Gas, GasStatus, INITIAL_COST_SCHEDULE};
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;

use crate::effects::{CallEffects, CallError};
use crate::keys::package_key;
use crate::module_resolver::{ChainStateModuleResolver, ResolverError};
use crate::native::State;

/// How deeply vectors may nest in an argument: `vector<vector<u8>>` is 2.
pub const MAX_VECTOR_DEPTH: usize = 3;
/// Arguments in one call. Move functions take at most this many parameters
/// under the verifier limit anyway; this bounds the work before the VM.
pub const MAX_ARGUMENTS: usize = 32;

/// What one parameter needs from the call.
enum Param {
    /// The sender, by value.
    Signer,
    /// The sender, by reference.
    SignerRef,
    /// The next argument, decoded with this layout.
    Argument(MoveTypeLayout),
}

fn layout(token: &SignatureToken, depth: usize) -> Option<MoveTypeLayout> {
    Some(match token {
        SignatureToken::Bool => MoveTypeLayout::Bool,
        SignatureToken::U8 => MoveTypeLayout::U8,
        SignatureToken::U16 => MoveTypeLayout::U16,
        SignatureToken::U32 => MoveTypeLayout::U32,
        SignatureToken::U64 => MoveTypeLayout::U64,
        SignatureToken::U128 => MoveTypeLayout::U128,
        SignatureToken::U256 => MoveTypeLayout::U256,
        SignatureToken::Address => MoveTypeLayout::Address,
        SignatureToken::Vector(inner) => {
            if depth >= MAX_VECTOR_DEPTH {
                return None;
            }
            MoveTypeLayout::Vector(Box::new(layout(inner, depth.saturating_add(1))?))
        }
        _ => return None,
    })
}

fn param(token: &SignatureToken) -> Option<Param> {
    match token {
        SignatureToken::Signer => Some(Param::Signer),
        SignatureToken::Reference(inner) if **inner == SignatureToken::Signer => {
            Some(Param::SignerRef)
        }
        other => layout(other, 1).map(Param::Argument),
    }
}

/// The parameters of `module`'s entry function `name`, if it is one this
/// stage can call.
fn parameters(module: &CompiledModule, name: &str) -> Option<Vec<Param>> {
    let definition = module.function_defs().iter().find(|definition| {
        let handle = module.function_handle_at(definition.function);
        module.identifier_at(handle.name).as_str() == name
    })?;
    let handle = module.function_handle_at(definition.function);
    if !definition.is_entry
        || !handle.type_parameters.is_empty()
        || !module.signature_at(handle.return_).0.is_empty()
    {
        return None;
    }
    let tokens = &module.signature_at(handle.parameters).0;
    if tokens.len() > MAX_ARGUMENTS {
        return None;
    }
    let params: Vec<Param> = tokens.iter().map(param).collect::<Option<_>>()?;
    // The sender may only be the first parameter.
    if params
        .iter()
        .skip(1)
        .any(|p| matches!(p, Param::Signer | Param::SignerRef))
    {
        return None;
    }
    Some(params)
}

/// Run `tx`'s call. `None` if no published package has that address, so the
/// caller can say the function is unknown.
pub(crate) fn call(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
) -> Option<Result<CallEffects, CallError>> {
    let call = &tx.body.call;
    let id = AccountAddress::new(*call.module_address.as_bytes());
    if !state.contains_key(&package_key(id)) {
        return None;
    }
    Some(run(runtime, state, tx, id))
}

fn run(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
    id: AccountAddress,
) -> Result<CallEffects, CallError> {
    let call = &tx.body.call;
    let unknown = || CallError::from(AbortReason::UnknownFunction);
    let invalid = || CallError::from(AbortReason::InvalidArguments);

    let resolver = ChainStateModuleResolver::new(state);
    let package = resolver
        .package(id)
        .map_err(|_: ResolverError| CallError::Internal)?
        .ok_or_else(unknown)?;

    let module_name = std::str::from_utf8(&call.module_name).map_err(|_| unknown())?;
    let function_name = std::str::from_utf8(&call.function_name).map_err(|_| unknown())?;
    let module_bytes = Identifier::new(module_name)
        .ok()
        .and_then(|name| package.modules.get(&name))
        .ok_or_else(unknown)?;
    let module =
        CompiledModule::deserialize_with_config(module_bytes, &crate::move_config::binary_config())
            .map_err(|_| CallError::Internal)?;
    let params = parameters(&module, function_name).ok_or_else(unknown)?;
    if !call.type_arguments.is_empty() {
        return Err(invalid());
    }

    let wanted = params
        .iter()
        .filter(|p| matches!(p, Param::Argument(_)))
        .count();
    if call.arguments.len() != wanted {
        return Err(invalid());
    }

    let sender = AccountAddress::new(*tx.sender_address().as_bytes());
    let mut heap = BaseHeap::new();
    let mut supplied = call.arguments.iter();
    let mut values = Vec::with_capacity(params.len());
    for p in &params {
        values.push(match p {
            Param::Signer => Value::signer(sender),
            Param::SignerRef => {
                heap.allocate_and_borrow_loc(Value::signer(sender))
                    .map_err(|_| CallError::Internal)?
                    .1
            }
            Param::Argument(layout) => {
                let bytes = supplied.next().ok_or_else(invalid)?;
                Value::simple_deserialize(bytes, layout).ok_or_else(invalid)?
            }
        });
    }

    let linkage =
        LinkageContext::new(package.linkage_table.clone()).map_err(|_| CallError::Internal)?;
    let mut vm = runtime
        .make_vm(ChainStateModuleResolver::new(state), linkage)
        .map_err(|_| CallError::Internal)?;
    let identifier = Identifier::new(function_name).map_err(|_| unknown())?;
    let module_id = ModuleId::new(id, Identifier::new(module_name).map_err(|_| unknown())?);
    let mut meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(tx.body.gas_limit.0));
    let execution = vm.execute_entry_function(&module_id, &identifier, vec![], values, &mut meter);
    let remaining: u64 = meter.remaining_gas().into();
    let gas_used = tx.body.gas_limit.0.saturating_sub(remaining);
    execution.map_err(|_| CallError::MeteredAbort {
        reason: AbortReason::ExecutionFailed,
        gas_used,
    })?;
    Ok(CallEffects {
        changes: Vec::new(),
        gas_used,
    })
}
