//! The two system packages every chain starts with, and the natives they need.
//!
//! - `0x1`, the Move standard library, unmodified from the pinned upstream
//!   revision except that `debug` and `unit_test` are left out (the first
//!   prints from inside a validator and the second is for test runners).
//! - `0x2`, the Thrylos framework: what a function may know about its block
//!   (`chain`), and reading a signer's address (`signer`).
//!
//! Their sources are in `move/` at the repository root and their compiled
//! bytecode is checked in beside them (`move/bytecode/*.bundle`), so a chain's
//! genesis embeds fixed bytes and never runs a compiler. A test compiles the
//! sources again and requires the result to equal the checked-in bytes.
//!
//! A bundle is the package exactly as it is stored in chain state: the
//! canonical encoding of the modules' bytes, ordered by module name.

use std::sync::Arc;

use better_any::{Tid, TidAble};
use move_core_types::account_address::AccountAddress;
use move_core_types::gas_algebra::{InternalGas, InternalGasPerByte, NumBytes};
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::natives::extensions::NativeExtensionMarker;
use move_vm_runtime::natives::functions::{
    make_table, NativeFunction, NativeFunctionTable, NativeFunctions, NativeResult,
};
use move_vm_runtime::natives::move_stdlib::{
    bcs, hash, signer, stdlib_native_function_table, string, type_name, vector, GasParameters,
};
use move_vm_runtime::runtime::MoveRuntime;
use smallvec::smallvec;

/// Where the standard library is published.
pub const STD_ADDRESS: AccountAddress = AccountAddress::ONE;
/// Where the Thrylos framework is published.
pub const FRAMEWORK_ADDRESS: AccountAddress = AccountAddress::TWO;

/// The standard library, as stored in state.
pub const STD_BUNDLE: &[u8] = include_bytes!("../../../move/bytecode/std.bundle");
/// The Thrylos framework, as stored in state.
pub const FRAMEWORK_BUNDLE: &[u8] = include_bytes!("../../../move/bytecode/thrylos.bundle");

/// What the block-reading natives report: the running block.
#[derive(Tid)]
pub struct BlockInfo {
    pub height: u64,
    pub time_ms: u64,
    pub chain_id: u64,
}

impl<'a> NativeExtensionMarker<'a> for BlockInfo {}

/// Native charges, in the VM's internal units, which are nanoseconds (see
/// `crate::gas`). Measured (`examples/opcode_bench.rs`): a hash costs a fixed
/// few hundred nanoseconds and then a few for each byte; encoding a number
/// about the same fixed cost; a string check or a type name a good deal more,
/// nearly all of it fixed. So every native has a fixed charge that covers the
/// slowest of them, and the ones that read their input add a charge per byte.
const BASE: u64 = 1_000;
/// Checking a string, taking part of one, searching in one.
const STRING_BASE: u64 = 2_500;
/// Naming a type.
const TYPE_NAME_BASE: u64 = 4_500;
const PER_BYTE: u64 = 10;

fn per_byte() -> InternalGasPerByte {
    InternalGasPerByte::new(PER_BYTE)
}

fn base() -> InternalGas {
    InternalGas::new(BASE)
}

fn string_base() -> InternalGas {
    InternalGas::new(STRING_BASE)
}

fn gas_parameters() -> GasParameters {
    GasParameters {
        bcs: bcs::GasParameters {
            to_bytes: bcs::ToBytesGasParameters {
                per_byte_serialized: per_byte(),
                legacy_min_output_size: NumBytes::new(1),
                failure: base(),
            },
        },
        // Never registered: `debug` is not part of the chain's library.
        debug: GasParameters::zeros().debug,
        hash: hash::GasParameters {
            sha2_256: hash::Sha2_256GasParameters {
                base: base(),
                per_byte: per_byte(),
                legacy_min_input_len: NumBytes::new(1),
            },
            sha3_256: hash::Sha3_256GasParameters {
                base: base(),
                per_byte: per_byte(),
                legacy_min_input_len: NumBytes::new(1),
            },
        },
        signer: signer::GasParameters {
            borrow_address: signer::BorrowAddressGasParameters { base: base() },
        },
        string: string::GasParameters {
            check_utf8: string::CheckUtf8GasParameters {
                base: string_base(),
                per_byte: per_byte(),
            },
            is_char_boundary: string::IsCharBoundaryGasParameters {
                base: string_base(),
            },
            sub_string: string::SubStringGasParameters {
                base: string_base(),
                per_byte: per_byte(),
            },
            index_of: string::IndexOfGasParameters {
                base: string_base(),
                per_byte_pattern: per_byte(),
                per_byte_searched: per_byte(),
            },
        },
        type_name: type_name::GasParameters {
            get: type_name::GetGasParameters {
                base: InternalGas::new(TYPE_NAME_BASE),
                per_byte: per_byte(),
            },
            id: type_name::IdGasParameters::new(Some(TYPE_NAME_BASE)),
        },
        vector: vector::GasParameters {
            empty: vector::EmptyGasParameters { base: base() },
            length: vector::LengthGasParameters { base: base() },
            push_back: vector::PushBackGasParameters {
                base: base(),
                legacy_per_abstract_memory_unit: 0.into(),
            },
            borrow: vector::BorrowGasParameters { base: base() },
            pop_back: vector::PopBackGasParameters { base: base() },
            destroy_empty: vector::DestroyEmptyGasParameters { base: base() },
            swap: vector::SwapGasParameters { base: base() },
        },
    }
}

fn block_native(read: fn(&BlockInfo) -> u64) -> NativeFunction {
    Arc::new(move |context, _type_arguments, _arguments| {
        let value = read(context.extensions().get::<BlockInfo>()?);
        Ok(NativeResult::ok(base(), smallvec![Value::u64(value)]))
    })
}

/// Every native function the chain's VM knows: the library's at `0x1`, and the
/// framework's at `0x2`.
pub fn native_table() -> NativeFunctionTable {
    let mut table = stdlib_native_function_table(STD_ADDRESS, gas_parameters(), true);
    // `debug` and `unit_test` are not in the library, so nothing refers to
    // their natives; drop them anyway so they cannot be reached.
    table.retain(|(_, module, _, _)| !matches!(module.as_str(), "debug" | "unit_test"));

    let chain: [(&str, NativeFunction); 3] = [
        ("block_time_ms", block_native(|b| b.time_ms)),
        ("height", block_native(|b| b.height)),
        ("chain_id", block_native(|b| b.chain_id)),
    ];
    table.extend(make_table(
        FRAMEWORK_ADDRESS,
        chain
            .into_iter()
            .map(|(name, native)| ("chain", name, native)),
    ));
    table.extend(make_table(
        FRAMEWORK_ADDRESS,
        crate::store::natives()
            .into_iter()
            .map(|(name, native)| ("store", name, native)),
    ));
    table.extend(make_table(
        FRAMEWORK_ADDRESS,
        signer::make_all(signer::GasParameters {
            borrow_address: signer::BorrowAddressGasParameters { base: base() },
        })
        .map(|(name, native)| ("signer".to_string(), name, native)),
    ));
    table
}

/// The Move runtime every executor, and every local test run, is made with:
/// the same natives and the same fixed configuration, so a package behaves the
/// same in `thrylos move test` as on the chain.
pub fn new_runtime() -> Result<MoveRuntime, String> {
    let natives = NativeFunctions::new(native_table())
        .map_err(|error| format!("failed to build native function table: {error}"))?;
    Ok(MoveRuntime::new(natives, crate::move_config::vm_config()))
}
