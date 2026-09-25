//! The natives behind `thrylos::store` (`move/framework/sources/store.move`):
//! `put`, `take`, `has` and `read`.
//!
//! They translate. What a drawer is, who may touch it, how much may be written
//! and what it costs are decided by `crate::drawer`; here a Move value becomes
//! bytes and back, and each step is paid for in gas first. A native reaches the
//! state through a [`StoreExtension`] the executor puts in the VM's extensions:
//! a call's [`DrawerOverlay`], which borrows the state and holds back the call's
//! writes until it succeeds.
//!
//! Nothing here panics on a value or type a transaction can build. A type too
//! large for the VM to give a layout, a value that will not serialise, or a name
//! or value over the limits, is the store's code 4; a stored value that cannot be
//! read back (damaged state, which no transaction can cause) is code 6. Both are
//! ordinary aborts: the VM's invariant errors are avoided on purpose, since the
//! VM turns them into panics in debug builds.

use std::collections::VecDeque;
use std::sync::Arc;

use better_any::{Tid, TidAble};
use move_binary_format::errors::PartialVMResult;
use move_binary_format::partial_vm_error;
use move_core_types::account_address::AccountAddress;
use move_core_types::gas_algebra::InternalGas;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::execution::Type;
use move_vm_runtime::natives::extensions::NativeExtensionMarker;
use move_vm_runtime::natives::functions::{NativeContext, NativeFunction, NativeResult};
use move_vm_runtime::pop_arg;
use smallvec::smallvec;

use crate::drawer::{DrawerError, DrawerOverlay, DrawerValue, CODE_CORRUPT, CODE_TOO_LARGE};

/// What a store native charges, in the VM's internal units (1000 to one unit of
/// gas). A fixed amount for every operation, then for the bytes it moves; a
/// byte written costs five times a byte read, since writing is what grows the
/// state. Like the rest of the schedule these are a safety bound until measured
/// on reference hardware.
pub const STORE_BASE_GAS: u64 = 4_000;
pub const STORE_READ_PER_BYTE: u64 = 12;
pub const STORE_WRITE_PER_BYTE: u64 = 60;

/// The store's part of a running call.
#[derive(Tid)]
pub struct StoreExtension<'a> {
    pub overlay: DrawerOverlay<'a>,
}

impl<'a> NativeExtensionMarker<'a> for StoreExtension<'a> {}

/// The natives, by name, for the `thrylos::store` module.
pub fn natives() -> Vec<(&'static str, NativeFunction)> {
    vec![
        ("put", Arc::new(put) as NativeFunction),
        ("take", Arc::new(take)),
        ("has", Arc::new(has)),
        ("read", Arc::new(read)),
    ]
}

type Outcome = PartialVMResult<NativeResult>;

/// Pay `amount` more, or end the call out of gas. Out of gas is the VM's own
/// status, not an abort with a code of ours: an abort code of 1 would read as the
/// store's "empty".
fn pay(context: &NativeContext, amount: u64) -> PartialVMResult<Option<NativeResult>> {
    if context.charge_gas(InternalGas::new(amount))? {
        Ok(None)
    } else {
        Err(partial_vm_error!(OUT_OF_GAS))
    }
}

fn per_byte(rate: u64, bytes: usize) -> u64 {
    rate.saturating_mul(u64::try_from(bytes).unwrap_or(u64::MAX))
}

/// A refusal from the drawers, as the abort a caller sees.
fn refused(context: &NativeContext, error: DrawerError) -> Outcome {
    Ok(NativeResult::err(context.gas_used(), error.abort_code()))
}

fn too_large(context: &NativeContext) -> Outcome {
    Ok(NativeResult::err(context.gas_used(), CODE_TOO_LARGE))
}

/// The canonical name of the native's type argument.
fn type_name(context: &NativeContext, ty_args: &[Type]) -> PartialVMResult<String> {
    let ty = ty_args
        .first()
        .ok_or_else(|| partial_vm_error!(UNKNOWN_INVARIANT_VIOLATION_ERROR, "no type argument"))?;
    Ok(context.type_to_type_tag(ty)?.to_canonical_string(true))
}

fn overlay<'c, 'b>(
    context: &'c mut NativeContext<'_, 'b, '_>,
) -> PartialVMResult<&'c mut DrawerOverlay<'b>> {
    Ok(&mut context
        .extensions_mut()
        .get_mut::<StoreExtension<'b>>()?
        .overlay)
}

fn put(context: &mut NativeContext, ty_args: Vec<Type>, mut args: VecDeque<Value>) -> Outcome {
    let value = args
        .pop_back()
        .ok_or_else(|| partial_vm_error!(UNKNOWN_INVARIANT_VIOLATION_ERROR, "no value argument"))?;
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    if let Some(out) = pay(context, STORE_BASE_GAS)? {
        return Ok(out);
    }
    let name = type_name(context, &ty_args)?;
    let ty = ty_args
        .first()
        .ok_or_else(|| partial_vm_error!(UNKNOWN_INVARIANT_VIOLATION_ERROR, "no type argument"))?;
    // A type the VM cannot give a layout (too many nodes, too deep) cannot be stored.
    let Some(layout) = context.type_to_type_layout(ty)? else {
        return too_large(context);
    };
    let Some(bytes) = value.typed_serialize(&layout) else {
        return too_large(context);
    };
    if let Some(out) = pay(context, per_byte(STORE_WRITE_PER_BYTE, bytes.len()))? {
        return Ok(out);
    }
    let Some(drawer) = DrawerValue::new(name, bytes) else {
        return too_large(context);
    };
    match overlay(context)?.put(owner, slot, drawer) {
        Ok(()) => Ok(NativeResult::ok(context.gas_used(), smallvec![])),
        Err(error) => refused(context, error),
    }
}

/// `take` and `read`: find the value, pay for its bytes, turn it back into a Move value.
fn load(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
    remove: bool,
) -> Outcome {
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    if let Some(out) = pay(context, STORE_BASE_GAS)? {
        return Ok(out);
    }
    let name = type_name(context, &ty_args)?;
    let found = if remove {
        overlay(context)?.take(owner, slot, &name)
    } else {
        overlay(context)?.read(owner, slot, &name)
    };
    let drawer = match found {
        Ok(drawer) => drawer,
        Err(error) => return refused(context, error),
    };
    if let Some(out) = pay(context, per_byte(STORE_READ_PER_BYTE, drawer.bytes.len()))? {
        return Ok(out);
    }
    let ty = ty_args
        .first()
        .ok_or_else(|| partial_vm_error!(UNKNOWN_INVARIANT_VIOLATION_ERROR, "no type argument"))?;
    // The value was stored under this type, so it has a layout and reads back.
    let Some(layout) = context.type_to_type_layout(ty)? else {
        return Ok(NativeResult::err(context.gas_used(), CODE_CORRUPT));
    };
    let Some(value) = Value::simple_deserialize(&drawer.bytes, &layout) else {
        return Ok(NativeResult::err(context.gas_used(), CODE_CORRUPT));
    };
    Ok(NativeResult::ok(context.gas_used(), smallvec![value]))
}

fn take(context: &mut NativeContext, ty_args: Vec<Type>, args: VecDeque<Value>) -> Outcome {
    load(context, ty_args, args, true)
}

fn read(context: &mut NativeContext, ty_args: Vec<Type>, args: VecDeque<Value>) -> Outcome {
    load(context, ty_args, args, false)
}

fn has(context: &mut NativeContext, ty_args: Vec<Type>, mut args: VecDeque<Value>) -> Outcome {
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    if let Some(out) = pay(context, STORE_BASE_GAS)? {
        return Ok(out);
    }
    let name = type_name(context, &ty_args)?;
    match overlay(context)?.has(owner, slot, &name) {
        Ok(there) => Ok(NativeResult::ok(
            context.gas_used(),
            smallvec![Value::bool(there)],
        )),
        Err(error) => refused(context, error),
    }
}
