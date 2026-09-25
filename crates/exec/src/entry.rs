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
//! metered against the transaction's gas limit. What a call writes goes to its
//! drawers (`crate::store`), held back until it succeeds; keeping them costs a
//! deposit (`crate::drawer`).

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
use move_vm_runtime::natives::extensions::NativeContextExtensions;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;
use std::cell::RefCell;
use std::rc::Rc;

use chain_state::StateValue;
use chain_types::codec::Encode;

use crate::accounting::read_supply;
use crate::drawer::{Access, DrawerOverlay};
use crate::effects::{BlockCtx, CallEffects, CallError};
use crate::framework::BlockInfo;
use crate::keys::{package_key, supply_key};
use crate::module_resolver::{ChainStateModuleResolver, ResolverError};
use crate::native::{debit_sender, State};
use crate::store::StoreExtension;

/// How deeply vectors may nest in an argument: `vector<vector<u8>>` is 2.
pub const MAX_VECTOR_DEPTH: usize = 3;
/// Arguments in one call. Move functions take at most this many parameters
/// under the verifier limit anyway; this bounds the work before the VM.
pub const MAX_ARGUMENTS: usize = 32;

/// What one parameter needs from the call.
pub(crate) enum Param {
    /// The sender, by value.
    Signer,
    /// The sender, by reference.
    SignerRef,
    /// The next argument, decoded with this layout.
    Argument(MoveTypeLayout),
}

pub(crate) fn layout(token: &SignatureToken, depth: usize) -> Option<MoveTypeLayout> {
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

/// Which functions of a module a call may name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Callable {
    /// What a transaction may call: an `entry` function that returns nothing.
    Entry,
    /// What a simulation may also call: any `public` function, which may return
    /// primitives and vectors of them (a "view").
    EntryOrPublic,
}

/// What a callable function takes and gives back.
pub(crate) struct Signature {
    pub params: Vec<Param>,
    pub returns: Vec<MoveTypeLayout>,
}

/// The signature of `module`'s function `name`, if it is one this stage can call
/// in the way `callable` says.
pub(crate) fn signature(
    module: &CompiledModule,
    name: &str,
    callable: Callable,
) -> Option<Signature> {
    use move_binary_format::file_format::Visibility;
    let definition = module.function_defs().iter().find(|definition| {
        let handle = module.function_handle_at(definition.function);
        module.identifier_at(handle.name).as_str() == name
    })?;
    let handle = module.function_handle_at(definition.function);
    let reachable = match callable {
        Callable::Entry => definition.is_entry,
        Callable::EntryOrPublic => {
            definition.is_entry || definition.visibility == Visibility::Public
        }
    };
    if !reachable || !handle.type_parameters.is_empty() {
        return None;
    }
    let return_tokens = &module.signature_at(handle.return_).0;
    let returns: Vec<MoveTypeLayout> = return_tokens
        .iter()
        .map(|token| layout(token, 1))
        .collect::<Option<_>>()?;
    if callable == Callable::Entry && !returns.is_empty() {
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
    Some(Signature { params, returns })
}

/// The values a call's parameters take: the sender where a `signer` is asked
/// for, and each argument decoded by its layout otherwise. `heap` must outlive
/// the call, since a `&signer` points into it.
pub(crate) fn decode_arguments(
    params: &[Param],
    arguments: &[Vec<u8>],
    sender: AccountAddress,
    heap: &mut BaseHeap,
) -> Result<Vec<Value>, CallError> {
    let wanted = params
        .iter()
        .filter(|p| matches!(p, Param::Argument(_)))
        .count();
    if arguments.len() != wanted {
        return Err(AbortReason::InvalidArguments.into());
    }
    let mut supplied = arguments.iter();
    let mut values = Vec::with_capacity(params.len());
    for p in params {
        values.push(match p {
            Param::Signer => Value::signer(sender),
            Param::SignerRef => {
                heap.allocate_and_borrow_loc(Value::signer(sender))
                    .map_err(|_| CallError::Internal)?
                    .1
            }
            Param::Argument(layout) => {
                let bytes = supplied
                    .next()
                    .ok_or(CallError::Abort(AbortReason::InvalidArguments))?;
                Value::simple_deserialize(bytes, layout)
                    .ok_or(CallError::Abort(AbortReason::InvalidArguments))?
            }
        });
    }
    Ok(values)
}

/// What a running call can reach besides its arguments: the block it runs in,
/// and its drawers (the sender's, and those it declared, on top of `state`,
/// held back until the call is over).
pub(crate) fn extensions_for<'a>(
    state: &'a State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Rc<RefCell<NativeContextExtensions<'a>>> {
    let extensions = Rc::new(RefCell::new(NativeContextExtensions::default()));
    extensions.borrow_mut().add(BlockInfo {
        height: ctx.height.0,
        time_ms: ctx.timestamp_ms,
        chain_id: ctx.chain_id.0,
    });
    extensions.borrow_mut().add(StoreExtension {
        overlay: DrawerOverlay::new(
            state,
            Access {
                sender: AccountAddress::new(*tx.sender_address().as_bytes()),
                declared: tx
                    .body
                    .declared_inputs
                    .iter()
                    .map(|address| AccountAddress::new(*address.as_bytes()))
                    .collect(),
                unrestricted: false,
            },
        ),
    });
    extensions
}

/// Run `tx`'s call. `None` if no published package has that address, so the
/// caller can say the function is unknown.
pub(crate) fn call(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Option<Result<CallEffects, CallError>> {
    let call = &tx.body.call;
    let id = AccountAddress::new(*call.module_address.as_bytes());
    if !state.contains_key(&package_key(id)) {
        return None;
    }
    Some(run(runtime, state, tx, ctx, id))
}

fn run(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
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
    let signature = signature(&module, function_name, Callable::Entry).ok_or_else(unknown)?;
    if !call.type_arguments.is_empty() {
        return Err(invalid());
    }

    let sender = AccountAddress::new(*tx.sender_address().as_bytes());
    let mut heap = BaseHeap::new();
    let values = decode_arguments(&signature.params, &call.arguments, sender, &mut heap)?;

    let linkage =
        LinkageContext::new(package.linkage_table.clone()).map_err(|_| CallError::Internal)?;
    let extensions = extensions_for(state, tx, ctx);
    let mut vm = runtime
        .make_vm_with_native_extensions(
            ChainStateModuleResolver::new(state),
            linkage,
            extensions.clone(),
        )
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
    // The VM holds the other reference to the extensions until it is dropped.
    drop(vm);
    let store = extensions
        .borrow_mut()
        .remove::<StoreExtension>()
        .map_err(|_| CallError::Internal)?;

    // What the call wrote to its drawers, and what that costs to keep: taken from
    // the sender and burned, in the same effects, so it all lands or none does.
    // A sender who cannot pay ends the call at what it had metered.
    let deposit = store.overlay.deposit();
    let mut changes = store.overlay.changes();
    if deposit > 0 {
        debit_sender(state, tx, deposit, &mut changes).map_err(|error| match error {
            CallError::Abort(reason) => CallError::MeteredAbort { reason, gas_used },
            other => other,
        })?;
        let supply = read_supply(state).ok_or(CallError::Internal)?;
        let after = supply.checked_sub(deposit).ok_or(CallError::Internal)?;
        let mut bytes = Vec::new();
        after.encode(&mut bytes);
        changes.push((supply_key(), Some(StateValue::new(bytes))));
    }
    Ok(CallEffects { changes, gas_used })
}
