//! What a Move instruction costs on this chain, and the meter that charges it.
//!
//! **Consensus.** Two validators that price an instruction differently disagree
//! on which transactions run out of gas, and so on the state.
//!
//! One ruler, from `docs/gas-calibration.md`: **1 gas is about 1 microsecond of
//! a validator's time**. The VM counts in internal units, 1,000 to a unit of
//! gas, so **one internal unit is about one nanosecond**, and every price below
//! is written as the nanoseconds the operation was measured to take on the
//! reference machine (`examples/opcode_bench.rs`), rounded up, with headroom.
//! Overpricing costs a user a little; underpricing lets someone hold every
//! validator up, so the prices lean high wherever the two conflict.
//!
//! The VM's own schedule (`INITIAL_COST_SCHEDULE`), which the chain used at
//! first, could not be tuned to this: it prices by opcode, not by what an
//! operation does. Two things in it were wrong in ways that matter:
//!
//! - it priced a function call, or a vector borrow, at a hundred times a plain
//!   instruction and the plain instruction at a tenth of what it costs; and
//! - it did not count the length of a vector when copying, comparing or reading
//!   it, so a program could copy a large vector a million times for the price
//!   of a million small copies.
//!
//! This meter replaces it. It implements the VM's own `GasMeter` trait, so the
//! VM neither knows nor cares.

use std::ops::Add;

use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::{AbstractMemorySize, InternalGas, NumArgs, NumBytes};
use move_vm_runtime::dev_utils::gas_schedule::Gas;
use move_vm_runtime::shared::gas::{GasMeter, SimpleInstruction};
use move_vm_runtime::shared::views::{SizeConfig, ValueView};

/// Internal units to a unit of gas.
pub const INTERNAL_PER_GAS: u64 = 1_000;

/// A plain instruction: a load, a store, a branch, a comparison, a borrow of a
/// field, a bit operation, a cast, an `abort`.
pub const PRICE_SIMPLE: u64 = 60;
/// Add, subtract, multiply, divide, remainder. One price for every width, so it
/// is set by the widest (`u256`, the slowest).
pub const PRICE_ARITHMETIC: u64 = 280;
/// A call: this, and a price for each argument passed.
pub const PRICE_CALL: u64 = 350;
pub const PRICE_CALL_PER_ARGUMENT: u64 = 120;
/// Making a struct or taking one apart: this, and a price for each field.
pub const PRICE_PACK: u64 = 90;
pub const PRICE_PACK_PER_FIELD: u64 = 30;
/// Borrowing a vector's element, swapping two, pushing, popping.
pub const PRICE_VECTOR_BORROW: u64 = 250;
pub const PRICE_VECTOR_SWAP: u64 = 200;
pub const PRICE_VECTOR_PUSH_POP: u64 = 100;
/// Making a vector from its elements, or taking one apart: this, and a price for
/// each element.
pub const PRICE_VECTOR_PACK: u64 = 150;
pub const PRICE_VECTOR_PACK_PER_ELEMENT: u64 = 60;
/// A constant loaded from the module: this, and a price per 16 bytes of it.
pub const PRICE_CONSTANT: u64 = 150;
pub const PRICE_CONSTANT_PER_16_BYTES: u64 = 1;
/// Copying, comparing or reading a value costs a plain instruction and, for what
/// is big, its size: this many internal units for every 4 units of the value's
/// size (a number is 8 units, so about 2 for each number in a vector), counting a
/// vector's contents.
pub const PRICE_PER_4_SIZE_UNITS: u64 = 1;

/// How big a value is, for what it costs to copy or compare it: contents of
/// vectors included, which the VM's own measure leaves out.
const SIZE: SizeConfig = SizeConfig {
    traverse_references: false,
    include_vector_size: true,
};

/// The meter every Move call on this chain runs under.
pub struct ChainGas {
    left: u64,
}

impl ChainGas {
    /// A meter with `limit` gas to spend.
    pub fn new(limit: Gas) -> Self {
        Self {
            left: u64::from(limit).saturating_mul(INTERNAL_PER_GAS),
        }
    }

    /// What is left, in whole units of gas (rounded down, so that what was used is
    /// rounded up).
    pub fn remaining_gas(&self) -> Gas {
        Gas::new(self.left.checked_div(INTERNAL_PER_GAS).unwrap_or(0))
    }

    fn charge(&mut self, amount: u64) -> PartialVMResult<()> {
        match self.left.checked_sub(amount) {
            Some(left) => {
                self.left = left;
                Ok(())
            }
            None => {
                self.left = 0;
                Err(move_binary_format::partial_vm_error!(OUT_OF_GAS))
            }
        }
    }

    /// A plain instruction, and the size of a value it copies or compares.
    fn charge_sized(&mut self, base: u64, size: AbstractMemorySize) -> PartialVMResult<()> {
        let units: u64 = size.into();
        self.charge(base.saturating_add(units.div_ceil(4).saturating_mul(PRICE_PER_4_SIZE_UNITS)))
    }
}

fn size_of(value: &impl ValueView) -> PartialVMResult<AbstractMemorySize> {
    value.abstract_memory_size(&SIZE)
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

impl GasMeter for ChainGas {
    fn charge_simple_instr(&mut self, instr: SimpleInstruction) -> PartialVMResult<()> {
        use SimpleInstruction::*;
        self.charge(match instr {
            Add | Sub | Mul | Mod | Div => PRICE_ARITHMETIC,
            _ => PRICE_SIMPLE,
        })
    }

    fn charge_pop(&mut self, _popped_val: impl ValueView) -> PartialVMResult<()> {
        self.charge(PRICE_SIMPLE)
    }

    fn charge_call(
        &mut self,
        args: impl ExactSizeIterator<Item = impl ValueView>,
        _num_locals: NumArgs,
    ) -> PartialVMResult<()> {
        self.charge(
            PRICE_CALL.saturating_add(count(args.len()).saturating_mul(PRICE_CALL_PER_ARGUMENT)),
        )
    }

    fn charge_call_generic(
        &mut self,
        args: impl ExactSizeIterator<Item = impl ValueView>,
        num_locals: NumArgs,
    ) -> PartialVMResult<()> {
        self.charge_call(args, num_locals)
    }

    fn charge_ld_const(&mut self, size: NumBytes) -> PartialVMResult<()> {
        let bytes: u64 = size.into();
        self.charge(
            PRICE_CONSTANT.saturating_add(
                bytes
                    .div_ceil(16)
                    .saturating_mul(PRICE_CONSTANT_PER_16_BYTES),
            ),
        )
    }

    fn charge_ld_const_after_deserialization(
        &mut self,
        _val: impl ValueView,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn charge_copy_loc(&mut self, val: impl ValueView) -> PartialVMResult<()> {
        let size = size_of(&val)?;
        self.charge_sized(PRICE_SIMPLE, size)
    }

    fn charge_move_loc(&mut self, _val: impl ValueView) -> PartialVMResult<()> {
        self.charge(PRICE_SIMPLE)
    }

    fn charge_store_loc(&mut self, _val: impl ValueView) -> PartialVMResult<()> {
        self.charge(PRICE_SIMPLE)
    }

    fn charge_pack(
        &mut self,
        _is_generic: bool,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        self.charge(
            PRICE_PACK.saturating_add(count(args.len()).saturating_mul(PRICE_PACK_PER_FIELD)),
        )
    }

    fn charge_unpack(
        &mut self,
        _is_generic: bool,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        self.charge(
            PRICE_PACK.saturating_add(count(args.len()).saturating_mul(PRICE_PACK_PER_FIELD)),
        )
    }

    fn charge_variant_switch(&mut self, _val: impl ValueView) -> PartialVMResult<()> {
        self.charge(PRICE_SIMPLE.saturating_mul(3))
    }

    fn charge_read_ref(&mut self, val: impl ValueView) -> PartialVMResult<()> {
        let size = size_of(&val)?;
        self.charge_sized(PRICE_SIMPLE, size)
    }

    fn charge_write_ref(
        &mut self,
        new_val: impl ValueView,
        _old_val: impl ValueView,
    ) -> PartialVMResult<()> {
        let size = size_of(&new_val)?;
        self.charge_sized(PRICE_SIMPLE, size)
    }

    fn charge_eq(&mut self, lhs: impl ValueView, rhs: impl ValueView) -> PartialVMResult<()> {
        let size = size_of(&lhs)?.add(size_of(&rhs)?);
        self.charge_sized(PRICE_SIMPLE, size)
    }

    fn charge_neq(&mut self, lhs: impl ValueView, rhs: impl ValueView) -> PartialVMResult<()> {
        let size = size_of(&lhs)?.add(size_of(&rhs)?);
        self.charge_sized(PRICE_SIMPLE, size)
    }

    fn charge_vec_pack(
        &mut self,
        args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        self.charge(
            PRICE_VECTOR_PACK
                .saturating_add(count(args.len()).saturating_mul(PRICE_VECTOR_PACK_PER_ELEMENT)),
        )
    }

    fn charge_vec_len(&mut self) -> PartialVMResult<()> {
        self.charge(PRICE_SIMPLE)
    }

    fn charge_vec_borrow(&mut self, _is_mut: bool, _is_success: bool) -> PartialVMResult<()> {
        self.charge(PRICE_VECTOR_BORROW)
    }

    fn charge_vec_push_back(&mut self, _val: impl ValueView) -> PartialVMResult<()> {
        self.charge(PRICE_VECTOR_PUSH_POP)
    }

    fn charge_vec_pop_back(&mut self, _val: Option<impl ValueView>) -> PartialVMResult<()> {
        self.charge(PRICE_VECTOR_PUSH_POP)
    }

    fn charge_vec_unpack(
        &mut self,
        expect_num_elements: NumArgs,
        _elems: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        let elements: u64 = expect_num_elements.into();
        self.charge(
            PRICE_VECTOR_PACK
                .saturating_add(elements.saturating_mul(PRICE_VECTOR_PACK_PER_ELEMENT)),
        )
    }

    fn charge_vec_swap(&mut self) -> PartialVMResult<()> {
        self.charge(PRICE_VECTOR_SWAP)
    }

    fn charge_native_function(
        &mut self,
        amount: InternalGas,
        _ret_vals: Option<impl ExactSizeIterator<Item = impl ValueView>>,
    ) -> PartialVMResult<()> {
        self.charge(amount.into())
    }

    fn charge_native_function_before_execution(
        &mut self,
        _args: impl ExactSizeIterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn charge_drop_frame(
        &mut self,
        _locals: impl Iterator<Item = impl ValueView>,
    ) -> PartialVMResult<()> {
        Ok(())
    }

    fn remaining_gas(&self) -> InternalGas {
        InternalGas::new(self.left)
    }
}
