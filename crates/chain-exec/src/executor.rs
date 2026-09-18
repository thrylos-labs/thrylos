//! The real (if narrowly scoped) block executor, implementing
//! `chain_engine_api::Engine`. See `crate`'s doc comment for exactly
//! what this pass covers and what's deferred.

use std::collections::BTreeMap;

use chain_engine_api::{
    AbortReason, Block, BlockLimits, BlockRejected, Engine, ExecutedBlock, FinaliseError,
    FinaliseErrorReason, RejectionReason, TransactionOutcome, GENESIS_MAX_BLOCK_GAS,
};
use chain_modules::fees::{
    next_base_fee, FeeError, FeeParams, GENESIS_BASE_FEE, GENESIS_BASE_FEE_CHANGE_DENOMINATOR,
};
use chain_state::{compute_root, StateKey, StateRoot, StateValue};
use chain_types::codec::CodecError;
use chain_types::{Address, BlockHeight, ChainId, GasAmount, GasPrice, Hash, Transaction};
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_vm_config::runtime::VMConfig;
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::execution::values::{Struct, Value};
use move_vm_runtime::natives::functions::NativeFunctions;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::gas::UnmeteredGasMeter;
use move_vm_runtime::shared::linkage_context::LinkageContext;

use crate::genesis::{
    genesis_state, GenesisError, COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME,
    COUNTER_PACKAGE_ADDRESS, INITIAL_COUNTER_ADDRESS, SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME,
    SYSTEM_PACKAGE_ADDRESS,
};
use crate::keys::{base_fee_key, calculator_result_key, object_key};
use crate::module_resolver::ChainStateModuleResolver;

#[derive(Debug)]
pub enum ExecutorError {
    Genesis(GenesisError),
    Runtime(String),
    FeeParams(FeeError),
}

impl core::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(err) => write!(f, "genesis failed: {err}"),
            Self::Runtime(msg) => write!(f, "runtime construction failed: {msg}"),
            Self::FeeParams(err) => write!(f, "invalid genesis fee parameters: {err}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

/// What a call would change, held back rather than applied: handlers
/// read state and return one of these, and only the caller decides
/// whether it ever reaches `state`. That is what makes an abort's
/// rollback structural instead of something each handler has to
/// remember to undo.
struct CallEffects {
    writes: Vec<(StateKey, StateValue)>,
    gas_used: u64,
}

/// Why a call produced no [`CallEffects`].
enum CallError {
    /// The transaction's own doing: it was valid to run, and running it
    /// failed. Becomes an aborted [`TransactionOutcome`].
    Abort(AbortReason),
    /// Not the transaction's doing — the executor itself couldn't do
    /// what it should always be able to (build its VM from constants,
    /// read back a state invariant genesis established, unpack a value
    /// its own module just returned). Nothing a transaction can
    /// trigger, so charging its sender for it would be wrong; the block
    /// is rejected instead, the same way a corrupt account read is.
    Internal,
}

impl From<AbortReason> for CallError {
    fn from(reason: AbortReason) -> Self {
        Self::Abort(reason)
    }
}

struct AppliedTransaction {
    gas_used: u64,
    outcome: TransactionOutcome,
}

pub struct Executor {
    chain_id: ChainId,
    /// Fixed at genesis for now. The block gas limit and base fee
    /// denominator are governance-adjustable in `docs/spec.md`, and
    /// consensus-critical, so once governance exists they belong in
    /// state alongside the base fee itself; until then every node
    /// building from the same genesis agrees on them by construction.
    fee_params: FeeParams,
    state: BTreeMap<StateKey, StateValue>,
    tip_block_hash: Hash,
    runtime: MoveRuntime,
}

impl Executor {
    /// A freshly initialised executor with the fixed system packages
    /// published, including one seeded `Counter` object (see
    /// `crate::genesis`), checking every transaction against
    /// `chain_id` (`docs/spec.md`, "Transaction validity": "Chain ID
    /// ... checked against the node's own").
    pub fn genesis(chain_id: ChainId) -> Result<Self, ExecutorError> {
        let mut state = genesis_state().map_err(ExecutorError::Genesis)?;
        let fee_params = FeeParams::new(GENESIS_MAX_BLOCK_GAS, GENESIS_BASE_FEE_CHANGE_DENOMINATOR)
            .map_err(ExecutorError::FeeParams)?;
        state.insert(
            base_fee_key(),
            StateValue::new(GENESIS_BASE_FEE.to_le_bytes().to_vec()),
        );
        let natives = NativeFunctions::new(std::iter::empty()).map_err(|err| {
            ExecutorError::Runtime(format!("failed to build native function table: {err}"))
        })?;
        // `new_for_test` is the only constructor this dependency exposes
        // (see `crate`'s doc comment on the pinned MoveVM dependency);
        // `allow_unpublishable_code_execution: false` is the more
        // restrictive, production-appropriate setting despite the name.
        let vm_config = VMConfig::new_for_test(false, None);
        let runtime = MoveRuntime::new(natives, vm_config);
        Ok(Self {
            chain_id,
            fee_params,
            state,
            tip_block_hash: Hash::from_bytes([0u8; 32]),
            runtime,
        })
    }

    pub fn state_root(&self) -> StateRoot {
        compute_root(&self.state)
    }

    pub const fn tip_block_hash(&self) -> Hash {
        self.tip_block_hash
    }

    /// The last result of a `calculator::add` call by `address`, if any.
    pub fn read_result(&self, address: &Address) -> Option<u64> {
        read_u64(
            &self.state,
            &calculator_result_key(account_address(address)),
        )
    }

    /// The genesis `Counter` object's current value.
    pub fn read_counter(&self) -> Option<u64> {
        read_u64(&self.state, &object_key(INITIAL_COUNTER_ADDRESS))
    }

    /// The base fee per gas the next block will charge — the price every
    /// transaction in it pays, and the floor its `max_fee_per_gas` must
    /// clear. Recomputed from each block's gas usage as it's executed.
    pub fn base_fee(&self) -> Option<u64> {
        read_u64(&self.state, &base_fee_key())
    }

    /// `address`'s account (balance and next sequence number) as of
    /// the currently committed state.
    pub fn read_account(&self, address: Address) -> Result<chain_state::Account, CodecError> {
        chain_state::account::read_account(&self.state, address)
    }

    /// Credits `address`'s account by `amount`. `docs/spec.md` doesn't
    /// specify a genesis allocation table yet (only that fixed system
    /// state exists at genesis — see `crate::genesis`), so this is the
    /// explicit, auditable stand-in tests use to fund a sender rather
    /// than transactions succeeding against an implicit balance.
    pub fn credit_account(&mut self, address: Address, amount: u128) -> Result<(), CodecError> {
        let mut account = chain_state::account::read_account(&self.state, address)?;
        account.balance = account.balance.saturating_add(amount);
        chain_state::account::write_account(&mut self.state, address, account);
        Ok(())
    }

    /// Apply every transaction in `block` to `state` in order. A
    /// structurally invalid transaction rejects the whole block
    /// (`docs/spec.md`, "Execution": "Invalid transaction in a proposed
    /// block rejects the block. There is no skip-and-continue path");
    /// a valid one that fails *while executing* is aborted and the
    /// block carries on ("Aborts consume gas and roll back the
    /// transaction's effects, but never abort the block").
    ///
    /// Every transaction in the block pays the same price, the base fee
    /// stored in `state` when the block starts; the block's total gas
    /// then sets the base fee the *next* block will charge, written back
    /// into `state` so it lands in the state root and diff. Returns the
    /// total gas used and one outcome per transaction.
    fn apply_block(
        &self,
        state: &mut BTreeMap<StateKey, StateValue>,
        block: &Block,
    ) -> Result<(u64, Vec<TransactionOutcome>), BlockRejected> {
        // Missing or malformed, this is a broken state invariant (genesis
        // seeds it and only this function writes it), not anything a
        // block did.
        let base_fee = read_u64(state, &base_fee_key()).ok_or(BlockRejected {
            transaction_index: None,
            reason: RejectionReason::Rejected,
        })?;

        let mut gas_used: u64 = 0;
        let mut outcomes = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            let applied = self.apply_transaction(state, tx, index, base_fee)?;
            gas_used = gas_used.saturating_add(applied.gas_used);
            // Checked as it accumulates rather than after the loop, so an
            // oversized block is refused without executing the rest of it.
            // Not any one transaction's fault: the block as a whole is
            // over the limit `docs/spec.md` gives the base fee its target
            // from ("Max block gas").
            if gas_used > self.fee_params.max_block_gas() {
                return Err(BlockRejected {
                    transaction_index: None,
                    reason: RejectionReason::MalformedBlock,
                });
            }
            outcomes.push(applied.outcome);
        }

        let next_fee = next_base_fee(&self.fee_params, base_fee, gas_used);
        state.insert(
            base_fee_key(),
            StateValue::new(next_fee.to_le_bytes().to_vec()),
        );
        Ok((gas_used, outcomes))
    }

    /// One transaction, in two distinct phases with distinct failure
    /// modes. First, validity (`docs/spec.md`'s "Transaction validity"
    /// table in full): chain ID, signature, then sequence number and
    /// balance against the sender's account. Failing any of those is a
    /// rejection — the transaction should never have been in this block.
    /// Second, execution of the call itself, which can only abort:
    /// the sender is still charged and their sequence number still
    /// advances (they were allowed to run, and a replay must stay
    /// impossible), but the call's own writes are never applied.
    fn apply_transaction(
        &self,
        state: &mut BTreeMap<StateKey, StateValue>,
        tx: &Transaction,
        tx_index: usize,
        base_fee: u64,
    ) -> Result<AppliedTransaction, BlockRejected> {
        let transaction_index = u32::try_from(tx_index).ok();
        let reject = move |reason: RejectionReason| BlockRejected {
            transaction_index,
            reason,
        };

        if tx.body.chain_id != self.chain_id {
            return Err(reject(RejectionReason::WrongChainId));
        }
        tx.verify_signature()
            .map_err(|_| reject(RejectionReason::InvalidSignature))?;

        let sender = tx.sender_address();
        let account = chain_state::account::read_account(state, sender)
            .map_err(|_| reject(RejectionReason::Rejected))?;
        account
            .check(
                tx.body.sequence_number,
                tx.body.gas_limit,
                tx.body.max_fee_per_gas,
            )
            .map_err(|_| reject(RejectionReason::Rejected))?;
        // "Gas budget: covered by sender balance at maximum price" is
        // only meaningful if that maximum price can actually pay: a
        // transaction whose ceiling is below this block's base fee could
        // never be charged what the block owes, so it is invalid here,
        // not merely cheap. A proposer filters these out.
        if tx.body.max_fee_per_gas.0 < base_fee {
            return Err(reject(RejectionReason::Rejected));
        }

        let (outcome, gas_used) = match self.execute_call(state, tx) {
            Ok(effects) => {
                // The only place a call's writes ever reach `state`:
                // an abort returns before this, so rollback is
                // structural — there is nothing to undo.
                for (key, value) in effects.writes {
                    state.insert(key, value);
                }
                (TransactionOutcome::Success, effects.gas_used)
            }
            // Unmetered for this pass — see `crate`'s doc comment.
            // Charging the declared gas limit for an abort, same as for
            // a success, is the conservative stand-in: an abort that
            // cost nothing would be free spam. The account was already
            // checked to afford exactly this much.
            Err(CallError::Abort(reason)) => {
                (TransactionOutcome::Aborted(reason), tx.body.gas_limit.0)
            }
            Err(CallError::Internal) => return Err(reject(RejectionReason::Rejected)),
        };

        // Charged the base fee, not the sender's `max_fee_per_gas`
        // ceiling: that ceiling was only ever checked, above, to be
        // enough. The fee is burned — nothing is credited for it — as in
        // EIP-1559; there is no priority tip to pay a proposer (see
        // `chain_modules::fees`'s doc comment).
        let updated_account = account.apply_transaction(GasAmount(gas_used), GasPrice(base_fee));
        chain_state::account::write_account(state, sender, updated_account);

        Ok(AppliedTransaction { gas_used, outcome })
    }

    /// Dispatch to this pass's one of two supported call shapes: the
    /// fixed `calculator::add` (plain `u64` arguments) or `counter::bump`
    /// (one `Counter` object, declared as one of this transaction's
    /// inputs, mutated by reference). Reads `state` but never writes
    /// it: whatever the call would change comes back as
    /// [`CallEffects`] for the caller to apply or discard.
    fn execute_call(
        &self,
        state: &BTreeMap<StateKey, StateValue>,
        tx: &Transaction,
    ) -> Result<CallEffects, CallError> {
        let call = &tx.body.call;
        if call.module_address == Address::from_bytes(SYSTEM_PACKAGE_ADDRESS.into_bytes())
            && call.module_name == SYSTEM_MODULE_NAME.as_bytes()
            && call.function_name == SYSTEM_FUNCTION_NAME.as_bytes()
        {
            self.call_calculator_add(state, tx)
        } else if call.module_address == Address::from_bytes(COUNTER_PACKAGE_ADDRESS.into_bytes())
            && call.module_name == COUNTER_MODULE_NAME.as_bytes()
            && call.function_name == COUNTER_BUMP_FUNCTION.as_bytes()
        {
            self.call_counter_bump(state, tx)
        } else {
            Err(AbortReason::UnknownFunction.into())
        }
    }

    fn call_calculator_add(
        &self,
        state: &BTreeMap<StateKey, StateValue>,
        tx: &Transaction,
    ) -> Result<CallEffects, CallError> {
        let call = &tx.body.call;
        let [arg_a, arg_b] = call.arguments.as_slice() else {
            return Err(AbortReason::InvalidArguments.into());
        };
        let a = decode_u64_arg(arg_a).ok_or(AbortReason::InvalidArguments)?;
        let b = decode_u64_arg(arg_b).ok_or(AbortReason::InvalidArguments)?;

        let module_id = ModuleId::new(
            SYSTEM_PACKAGE_ADDRESS,
            Identifier::new(SYSTEM_MODULE_NAME).map_err(|_| CallError::Internal)?,
        );
        let function_name =
            Identifier::new(SYSTEM_FUNCTION_NAME).map_err(|_| CallError::Internal)?;

        let mut vm = self
            .make_vm(state, SYSTEM_PACKAGE_ADDRESS)
            .map_err(|_| CallError::Internal)?;
        let mut returned = vm
            .execute_function_bypass_visibility(
                &module_id,
                &function_name,
                vec![],
                vec![Value::u64(a), Value::u64(b)],
                &mut UnmeteredGasMeter,
                None,
            )
            .map_err(|_| AbortReason::ExecutionFailed)?;
        drop(vm);

        if returned.len() != 1 {
            return Err(CallError::Internal);
        }
        let sum: u64 = returned
            .remove(0)
            .value_as()
            .map_err(|_| CallError::Internal)?;

        Ok(CallEffects {
            writes: vec![(
                calculator_result_key(account_address(&tx.sender_address())),
                StateValue::new(sum.to_le_bytes().to_vec()),
            )],
            // Unmetered for this pass — see `crate`'s doc comment.
            // Charging the declared gas limit as a stand-in keeps
            // `gas_used` meaningful without pretending it's a
            // calibrated cost.
            gas_used: tx.body.gas_limit.0,
        })
    }

    /// `docs/spec.md`, "Execution": "Transactions declare the objects
    /// they access before execution ... A transaction touching an
    /// object it did not declare aborts rather than being resolved
    /// dynamically." Enforced twice over: as an explicit abort here
    /// when the counter's address isn't among `declared_inputs`, and
    /// structurally underneath it — Sui's Move has no ambient lookup
    /// by address, so `bump` can only touch the `Counter` this function
    /// itself constructs and passes in, and it only ever does that for
    /// the one declared address.
    fn call_counter_bump(
        &self,
        state: &BTreeMap<StateKey, StateValue>,
        tx: &Transaction,
    ) -> Result<CallEffects, CallError> {
        let counter_address = Address::from_bytes(INITIAL_COUNTER_ADDRESS.into_bytes());
        if !tx.body.declared_inputs.contains(&counter_address) {
            return Err(AbortReason::UndeclaredObjectAccess.into());
        }

        let [amount_bytes] = tx.body.call.arguments.as_slice() else {
            return Err(AbortReason::InvalidArguments.into());
        };
        let amount = decode_u64_arg(amount_bytes).ok_or(AbortReason::InvalidArguments)?;

        // A declared counter that isn't in state, or isn't 8 bytes, is
        // a broken state invariant (genesis seeds it and only this
        // function writes it), not something the transaction did.
        let current =
            read_u64(state, &object_key(INITIAL_COUNTER_ADDRESS)).ok_or(CallError::Internal)?;

        let module_id = ModuleId::new(
            COUNTER_PACKAGE_ADDRESS,
            Identifier::new(COUNTER_MODULE_NAME).map_err(|_| CallError::Internal)?,
        );
        let function_name =
            Identifier::new(COUNTER_BUMP_FUNCTION).map_err(|_| CallError::Internal)?;

        let mut heap = BaseHeap::new();
        let counter_value = Value::struct_(Struct::pack(vec![Value::u64(current)]));
        let (heap_id, counter_ref) = heap
            .allocate_and_borrow_loc(counter_value)
            .map_err(|_| CallError::Internal)?;

        let mut vm = self
            .make_vm(state, COUNTER_PACKAGE_ADDRESS)
            .map_err(|_| CallError::Internal)?;
        let returned = vm
            .execute_function_bypass_visibility(
                &module_id,
                &function_name,
                vec![],
                vec![counter_ref, Value::u64(amount)],
                &mut UnmeteredGasMeter,
                None,
            )
            .map_err(|_| AbortReason::ExecutionFailed)?;
        drop(vm);

        if !returned.is_empty() {
            return Err(CallError::Internal);
        }

        let mutated = heap.take_loc(heap_id).map_err(|_| CallError::Internal)?;
        let mutated_struct: Struct = mutated.value_as().map_err(|_| CallError::Internal)?;
        let new_value: u64 = mutated_struct
            .unpack()
            .next()
            .ok_or(CallError::Internal)?
            .value_as()
            .map_err(|_| CallError::Internal)?;

        Ok(CallEffects {
            writes: vec![(
                object_key(INITIAL_COUNTER_ADDRESS),
                StateValue::new(new_value.to_le_bytes().to_vec()),
            )],
            gas_used: tx.body.gas_limit.0,
        })
    }

    fn make_vm<'extensions>(
        &self,
        state: &BTreeMap<StateKey, StateValue>,
        package_address: move_core_types::account_address::AccountAddress,
    ) -> Result<move_vm_runtime::execution::vm::MoveVM<'extensions>, ()> {
        let resolver = ChainStateModuleResolver::new(state);
        let linkage = LinkageContext::new(BTreeMap::from([(package_address, package_address)]))
            .map_err(|_| ())?;
        self.runtime.make_vm(resolver, linkage).map_err(|_| ())
    }
}

fn account_address(address: &Address) -> move_core_types::account_address::AccountAddress {
    move_core_types::account_address::AccountAddress::new(*address.as_bytes())
}

fn read_u64(state: &BTreeMap<StateKey, StateValue>, key: &StateKey) -> Option<u64> {
    let value = state.get(key)?;
    let bytes: [u8; 8] = value.as_bytes().try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn decode_u64_arg(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

impl Engine for Executor {
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        _parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block {
        let mut transactions = Vec::new();
        let mut gas_so_far: u64 = 0;
        for tx in candidate_transactions {
            let Some(next_total) = gas_so_far.checked_add(tx.body.gas_limit.0) else {
                break;
            };
            if next_total > limits.max_gas {
                break;
            }
            gas_so_far = next_total;
            transactions.push(tx);
        }

        Block {
            parent_block_hash,
            height,
            timestamp_millis,
            transactions,
        }
    }

    fn execute_block(
        &self,
        parent_state_root: StateRoot,
        block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected> {
        if parent_state_root != self.state_root() || block.parent_block_hash != self.tip_block_hash
        {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::MalformedBlock,
            });
        }

        let mut scratch = self.state.clone();
        let (gas_used, outcomes) = self.apply_block(&mut scratch, block)?;
        Ok(ExecutedBlock {
            state_root: compute_root(&scratch),
            gas_used,
            state_diff: chain_state::diff(&self.state, &scratch),
            outcomes,
        })
    }

    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        if block.parent_block_hash != self.tip_block_hash {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::NotOnCanonicalChain,
            });
        }

        let mut scratch = self.state.clone();
        // A rejection here means `executed` doesn't correspond to a real
        // execution of `block` on top of this executor's own state —
        // treated the same as a root mismatch, since both mean the
        // caller handed us something inconsistent.
        let (gas_used, outcomes) =
            self.apply_block(&mut scratch, block)
                .map_err(|_| FinaliseError {
                    reason: FinaliseErrorReason::StateRootMismatch,
                })?;
        let recomputed_root = compute_root(&scratch);
        let recomputed_diff = chain_state::diff(&self.state, &scratch);
        if recomputed_root != executed.state_root
            || gas_used != executed.gas_used
            || recomputed_diff != executed.state_diff
            || outcomes != executed.outcomes
        {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::StateRootMismatch,
            });
        }

        self.state = scratch;
        self.tip_block_hash = block.hash();
        Ok(())
    }
}
