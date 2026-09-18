//! The real (if narrowly scoped) block executor, implementing
//! `chain_engine_api::Engine`. See `crate`'s doc comment for exactly
//! what this pass covers and what's deferred.

use std::collections::BTreeMap;

use chain_engine_api::{
    Block, BlockLimits, BlockRejected, Engine, ExecutedBlock, FinaliseError, FinaliseErrorReason,
    RejectionReason,
};
use chain_state::{compute_root, StateKey, StateRoot, StateValue};
use chain_types::{Address, BlockHeight, Hash, Transaction};
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_vm_config::runtime::VMConfig;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::natives::functions::NativeFunctions;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::gas::UnmeteredGasMeter;
use move_vm_runtime::shared::linkage_context::LinkageContext;

use crate::genesis::{
    genesis_state, GenesisError, SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME, SYSTEM_PACKAGE_ADDRESS,
};
use crate::module_resolver::ChainStateModuleResolver;

#[derive(Debug)]
pub enum ExecutorError {
    Genesis(GenesisError),
    Runtime(String),
}

impl core::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(err) => write!(f, "genesis failed: {err}"),
            Self::Runtime(msg) => write!(f, "runtime construction failed: {msg}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

pub struct Executor {
    state: BTreeMap<StateKey, StateValue>,
    tip_block_hash: Hash,
    runtime: MoveRuntime,
}

impl Executor {
    /// A freshly initialised executor with the fixed system package
    /// published (see `crate::genesis`).
    pub fn genesis() -> Result<Self, ExecutorError> {
        let state = genesis_state().map_err(ExecutorError::Genesis)?;
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

    /// The last computed result for `address`'s calls, if any. The only
    /// read path this narrow slice needs; a real state-read API belongs
    /// to `chain-state`, once there's more than one kind of value to
    /// read.
    pub fn read_result(&self, address: &Address) -> Option<u64> {
        let key = StateKey::new(address.as_bytes().to_vec());
        let value = self.state.get(&key)?;
        let bytes: [u8; 8] = value.as_bytes().try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    /// Apply every transaction in `block` to `state` in order, rejecting
    /// the whole block on the first structurally invalid transaction
    /// (`docs/spec.md`, "Execution": "Invalid transaction in a proposed
    /// block rejects the block. There is no skip-and-continue path").
    /// Returns the total gas used.
    fn apply_block(
        &self,
        state: &mut BTreeMap<StateKey, StateValue>,
        block: &Block,
    ) -> Result<u64, BlockRejected> {
        let mut gas_used: u64 = 0;
        for (index, tx) in block.transactions.iter().enumerate() {
            let used = self.apply_transaction(state, tx, index)?;
            gas_used = gas_used.saturating_add(used);
        }
        Ok(gas_used)
    }

    /// Run this pass's one supported call shape: the fixed system
    /// function, called with exactly two `u64` arguments, no object
    /// arguments. Writes the result into `state` under a key derived
    /// from the sender's address.
    fn apply_transaction(
        &self,
        state: &mut BTreeMap<StateKey, StateValue>,
        tx: &Transaction,
        tx_index: usize,
    ) -> Result<u64, BlockRejected> {
        let transaction_index = u32::try_from(tx_index).ok();
        let reject = |reason: RejectionReason| BlockRejected {
            transaction_index,
            reason,
        };

        tx.verify_signature()
            .map_err(|_| reject(RejectionReason::InvalidSignature))?;

        let call = &tx.body.call;
        let expected_module_address = Address::from_bytes(SYSTEM_PACKAGE_ADDRESS.into_bytes());
        if call.module_address != expected_module_address
            || call.module_name != SYSTEM_MODULE_NAME.as_bytes()
            || call.function_name != SYSTEM_FUNCTION_NAME.as_bytes()
        {
            return Err(reject(RejectionReason::Rejected));
        }

        let [arg_a, arg_b] = call.arguments.as_slice() else {
            return Err(reject(RejectionReason::Rejected));
        };
        let a = decode_u64_arg(arg_a).ok_or_else(|| reject(RejectionReason::Rejected))?;
        let b = decode_u64_arg(arg_b).ok_or_else(|| reject(RejectionReason::Rejected))?;

        let resolver = ChainStateModuleResolver::new(state);
        let linkage = LinkageContext::new(BTreeMap::from([(
            SYSTEM_PACKAGE_ADDRESS,
            SYSTEM_PACKAGE_ADDRESS,
        )]))
        .map_err(|_| reject(RejectionReason::Rejected))?;
        let mut vm = self
            .runtime
            .make_vm(resolver, linkage)
            .map_err(|_| reject(RejectionReason::Rejected))?;

        let module_id = ModuleId::new(
            SYSTEM_PACKAGE_ADDRESS,
            Identifier::new(SYSTEM_MODULE_NAME).map_err(|_| reject(RejectionReason::Rejected))?,
        );
        let function_name =
            Identifier::new(SYSTEM_FUNCTION_NAME).map_err(|_| reject(RejectionReason::Rejected))?;

        let mut returned = vm
            .execute_function_bypass_visibility(
                &module_id,
                &function_name,
                vec![],
                vec![Value::u64(a), Value::u64(b)],
                &mut UnmeteredGasMeter,
                None,
            )
            .map_err(|_| reject(RejectionReason::Rejected))?;

        if returned.len() != 1 {
            return Err(reject(RejectionReason::Rejected));
        }
        let sum: u64 = returned
            .remove(0)
            .value_as()
            .map_err(|_| reject(RejectionReason::Rejected))?;

        let result_key = StateKey::new(tx.sender_address().as_bytes().to_vec());
        state.insert(result_key, StateValue::new(sum.to_le_bytes().to_vec()));

        // Unmetered for this pass — see `crate`'s doc comment. Charging
        // the declared gas limit as a stand-in keeps `gas_used`
        // meaningful without pretending it's a calibrated cost.
        Ok(tx.body.gas_limit.0)
    }
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
        let gas_used = self.apply_block(&mut scratch, block)?;
        Ok(ExecutedBlock {
            state_root: compute_root(&scratch),
            gas_used,
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
        let gas_used = self
            .apply_block(&mut scratch, block)
            .map_err(|_| FinaliseError {
                reason: FinaliseErrorReason::StateRootMismatch,
            })?;
        let recomputed_root = compute_root(&scratch);
        if recomputed_root != executed.state_root || gas_used != executed.gas_used {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::StateRootMismatch,
            });
        }

        self.state = scratch;
        self.tip_block_hash = block.hash();
        Ok(())
    }
}
