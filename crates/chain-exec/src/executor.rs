//! The real (if narrowly scoped) block executor, implementing
//! `chain_engine_api::Engine`. See `crate`'s doc comment for exactly
//! what this pass covers and what's deferred.

use std::collections::BTreeMap;

use chain_engine_api::timestamp::is_after_parent;
use chain_engine_api::{
    AbortReason, Block, BlockLimits, BlockRejected, ChainView, ChainViewError, Engine,
    ExecutedBlock, FinaliseError, FinaliseErrorReason, Head, RejectionReason, TransactionOutcome,
    ValidatorInfo, MAX_BLOCK_SIZE_BYTES,
};
use chain_modules::fees::{next_base_fee, GENESIS_BASE_FEE};
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_modules::{
    ActiveValidator, Governance, GovernedParams, ParamError, ParamValues, StakingRegistry,
    ValidatorId, DEAD_SHARES,
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

use crate::accounting::{
    audit_supply, check_block_conservation, read_supply, write_supply, AccountingError,
};
use crate::effects::{BlockCtx, CallEffects, CallError};
use crate::genesis::{
    genesis_state, GenesisError, COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME,
    COUNTER_PACKAGE_ADDRESS, INITIAL_COUNTER_ADDRESS, SYSTEM_FUNCTION_NAME, SYSTEM_MODULE_NAME,
    SYSTEM_PACKAGE_ADDRESS,
};
use crate::genesis_config::{GenesisConfig, GenesisConfigError};
use crate::hooks::end_of_block;
use crate::keys::{base_fee_key, calculator_result_key, chain_head_key, object_key};
use crate::module_resolver::ChainStateModuleResolver;
use crate::module_store::{StateStore, StateView};
use crate::native;

#[derive(Debug)]
pub enum ExecutorError {
    Genesis(GenesisError),
    Runtime(String),
    /// The genesis parameters are outside their clamps.
    Params(ParamError),
    /// A native module could not read or write its own state.
    Modules(String),
    /// The state failed an audit.
    Audit(String),
    /// A genesis configuration could not be turned into a chain.
    GenesisConfig(GenesisConfigError),
}

impl core::fmt::Display for ExecutorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Genesis(err) => write!(f, "genesis failed: {err}"),
            Self::Runtime(msg) => write!(f, "runtime construction failed: {msg}"),
            Self::Params(err) => write!(f, "invalid genesis parameters: {err}"),
            Self::Modules(msg) => write!(f, "native module state: {msg}"),
            Self::Audit(msg) => write!(f, "audit failed: {msg}"),
            Self::GenesisConfig(err) => write!(f, "genesis configuration: {err}"),
        }
    }
}

impl std::error::Error for ExecutorError {}

struct AppliedTransaction {
    gas_used: u64,
    outcome: TransactionOutcome,
}

/// The height of the state `Executor::genesis` builds: no block yet.
pub const GENESIS_HEIGHT: u64 = 0;

/// The timestamp of the state [`Executor::genesis`] builds: the earliest
/// possible one, leaving the first block's timestamp bounded only by the
/// host's clock check. A real chain sets its own through
/// [`crate::genesis_config::GenesisConfig`].
pub const GENESIS_TIMESTAMP_MILLIS: u64 = 0;

pub struct Executor {
    chain_id: ChainId,
    state: BTreeMap<StateKey, StateValue>,
    tip_block_hash: Hash,
    runtime: MoveRuntime,
    /// Test-only: something to do to the state after the block's hooks,
    /// standing in for a module that misbehaves, so the check that must
    /// catch it can be shown to.
    #[cfg(test)]
    fault: Option<fn(&mut BTreeMap<StateKey, StateValue>)>,
}

impl Executor {
    /// The chain a [`GenesisConfig`] describes: its parameters, its
    /// allocations, and its validators registered and bonded, at its start
    /// time. This is how a real chain starts. The first block's parent is
    /// the configuration's hash ([`GenesisConfig::hash`]), so blocks of a
    /// network with any different genesis are not blocks on this one.
    ///
    /// The configuration is already valid, so what can fail here is the
    /// executor's own construction; a final audit confirms the supply
    /// equals what was created, so a genesis that would start a chain
    /// out of balance is refused rather than started.
    pub fn from_genesis(config: &GenesisConfig) -> Result<Self, ExecutorError> {
        let params = GovernedParams::new(*config.parameters()).map_err(ExecutorError::Params)?;
        let mut executor = Self::build(
            config.chain_id(),
            config.genesis_time_ms(),
            params,
            config.hash(),
        )?;

        for allocation in config.allocations() {
            executor
                .credit_account(
                    Address::from_public_key(&allocation.owner),
                    allocation.amount,
                )
                .map_err(|err| ExecutorError::Modules(err.to_string()))?;
        }
        for validator in config.validators() {
            let operator = Address::from_public_key(&validator.operator);
            StakingRegistry::new(StateStore::new(&mut executor.state))
                .register_validator(
                    &params,
                    ValidatorId(operator),
                    operator,
                    validator.consensus_key,
                    &validator.proof_of_possession,
                    validator.self_stake,
                )
                .map_err(|error| {
                    ExecutorError::GenesisConfig(GenesisConfigError::Registry { operator, error })
                })?;
            // The stake and the pool's dead shares came into being here.
            let created = validator.self_stake.checked_add(DEAD_SHARES).ok_or(
                ExecutorError::GenesisConfig(GenesisConfigError::SupplyOverflow),
            )?;
            let supply = read_supply(&executor.state).unwrap_or(0);
            write_supply(
                &mut executor.state,
                supply
                    .checked_add(created)
                    .ok_or(ExecutorError::GenesisConfig(
                        GenesisConfigError::SupplyOverflow,
                    ))?,
            );
        }

        executor.audit()?;
        if executor.supply() != Some(config.total_supply()) {
            return Err(ExecutorError::Audit(
                "the supply is not what the genesis configuration creates".to_owned(),
            ));
        }
        Ok(executor)
    }

    /// A freshly initialised executor with the fixed system packages
    /// published, including one seeded `Counter` object (see
    /// `crate::genesis`), checking every transaction against
    /// `chain_id` (`docs/spec.md`, "Transaction validity": "Chain ID
    /// ... checked against the node's own").
    ///
    /// For development and tests: default parameters, no allocations and
    /// no validators, starting at [`GENESIS_TIMESTAMP_MILLIS`]. A real
    /// chain starts from [`Self::from_genesis`].
    pub fn genesis(chain_id: ChainId) -> Result<Self, ExecutorError> {
        Self::genesis_with_params(chain_id, GENESIS_PARAM_VALUES)
    }

    /// Like [`Self::genesis`], starting from `params` instead of the
    /// defaults. They must be inside the clamps. The parameters are
    /// stored in state, where governance can change them from then on.
    ///
    /// The supply starts at zero and grows only as coin is allocated with
    /// [`Self::credit_account`]; there are no validators until some
    /// register.
    pub fn genesis_with_params(
        chain_id: ChainId,
        params: ParamValues,
    ) -> Result<Self, ExecutorError> {
        let params = GovernedParams::new(params).map_err(ExecutorError::Params)?;
        Self::build(
            chain_id,
            GENESIS_TIMESTAMP_MILLIS,
            params,
            Hash::from_bytes([0u8; 32]),
        )
    }

    /// The empty chain: fixed system packages, the base fee, the head at
    /// height 0 and `genesis_time_ms`, zero supply, and the governed
    /// parameters in state. `tip` is what the first block names as its
    /// parent.
    fn build(
        chain_id: ChainId,
        genesis_time_ms: u64,
        params: GovernedParams,
        tip: Hash,
    ) -> Result<Self, ExecutorError> {
        let mut state = genesis_state().map_err(ExecutorError::Genesis)?;
        state.insert(
            base_fee_key(),
            StateValue::new(GENESIS_BASE_FEE.to_le_bytes().to_vec()),
        );
        write_head(&mut state, GENESIS_HEIGHT, genesis_time_ms);
        write_supply(&mut state, 0);
        Governance::new(StateStore::new(&mut state))
            .init_genesis(params)
            .map_err(|err| ExecutorError::Modules(err.to_string()))?;
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
            state,
            tip_block_hash: tip,
            runtime,
            #[cfg(test)]
            fault: None,
        })
    }

    pub fn state_root(&self) -> StateRoot {
        compute_root(&self.state)
    }

    pub const fn tip_block_hash(&self) -> Hash {
        self.tip_block_hash
    }

    /// The height of the last executed block (`0` at genesis) — the next
    /// block must be exactly one more.
    pub fn head_height(&self) -> Option<u64> {
        read_head(&self.state).map(|(height, _)| height)
    }

    /// The timestamp of the last executed block — the next block's must
    /// be strictly later. [`GENESIS_TIMESTAMP_MILLIS`] at genesis.
    pub fn head_timestamp_millis(&self) -> Option<u64> {
        read_head(&self.state).map(|(_, timestamp)| timestamp)
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
    ///
    /// Coin allocated this way is new supply, and is recorded as such.
    pub fn credit_account(&mut self, address: Address, amount: u128) -> Result<(), CodecError> {
        let mut account = chain_state::account::read_account(&self.state, address)?;
        account.balance = account.balance.saturating_add(amount);
        chain_state::account::write_account(&mut self.state, address, account);
        let supply = read_supply(&self.state).unwrap_or(0);
        write_supply(&mut self.state, supply.saturating_add(amount));
        Ok(())
    }

    /// The total supply: every unit in an account, a staking pool or the
    /// unbonding queue.
    pub fn supply(&self) -> Option<u128> {
        read_supply(&self.state)
    }

    /// The governed parameters as they stand now.
    pub fn params(&self) -> Result<GovernedParams, ExecutorError> {
        Governance::new(StateView::new(&self.state))
            .params()
            .map_err(|err| ExecutorError::Modules(err.to_string()))
    }

    /// The validators consensus should run on, by stake — `docs/spec.md`'s
    /// `read_validator_set()`, as a Rust call: read-only, from the
    /// committed state.
    pub fn validator_set(&self) -> Result<Vec<ActiveValidator>, ExecutorError> {
        let params = self.params()?;
        StakingRegistry::new(StateView::new(&self.state))
            .active_set(&params)
            .map_err(|err| ExecutorError::Modules(format!("{err:?}")))
    }

    /// Reads the staking registry as of the committed state.
    pub fn with_registry<T>(&self, read: impl FnOnce(&StakingRegistry<StateView<'_>>) -> T) -> T {
        read(&StakingRegistry::new(StateView::new(&self.state)))
    }

    /// Reads governance as of the committed state.
    pub fn with_governance<T>(&self, read: impl FnOnce(&Governance<StateView<'_>>) -> T) -> T {
        read(&Governance::new(StateView::new(&self.state)))
    }

    /// Checks everything that should always hold, by reading all of it:
    /// that the supply equals everything held, and each module's own
    /// invariants (every pool's share ledger, the unbonding queue's
    /// indexes, governance's tallies). O(state) — for tests and periodic
    /// audits. What runs on every block is the cheaper change-only check
    /// (`crate::accounting::check_block_conservation`).
    pub fn audit(&self) -> Result<(), ExecutorError> {
        audit_supply(&self.state)
            .map_err(|err| ExecutorError::Audit(format!("supply: {err:?}")))?;
        self.with_registry(|registry| registry.assert_invariants())
            .map_err(|err| ExecutorError::Audit(format!("registry: {err:?}")))?;
        self.with_governance(|governance| governance.assert_invariants())
            .map_err(|err| ExecutorError::Audit(format!("governance: {err:?}")))
    }

    /// Apply every transaction in `block` to `state` in order. A
    /// structurally invalid transaction rejects the whole block
    /// (`docs/spec.md`, "Execution": "Invalid transaction in a proposed
    /// block rejects the block. There is no skip-and-continue path");
    /// a valid one that fails *while executing* is aborted and the
    /// block carries on ("Aborts consume gas and roll back the
    /// transaction's effects, but never abort the block").
    ///
    /// Before any transaction runs, the block itself is checked against
    /// its parent, both read from state: its height must be exactly the
    /// parent's plus one (a transaction's expiry is measured against it,
    /// so it can't be left to the proposer's say-so), and its timestamp
    /// strictly later (`docs/spec.md`, "Transaction validity"). The
    /// other timestamp rule, "not too far ahead of the clock", needs a
    /// clock and belongs to the consensus host — see
    /// `chain_engine_api::timestamp`. The new height and timestamp are
    /// written back once the block has applied.
    ///
    /// Every transaction in the block pays the same price, the base fee
    /// stored in `state` when the block starts; the block's total gas
    /// then sets the base fee the *next* block will charge, written back
    /// into `state` so it lands in the state root and diff. Returns the
    /// total gas used and one outcome per transaction.
    ///
    /// The governed parameters — the block gas limit and the fee
    /// denominator among them — are read from state when the block
    /// begins, so a change governance applies takes effect from the next
    /// block. After the transactions the modules' hooks run
    /// ([`crate::hooks`]), and last of all the block is checked to have
    /// neither created nor destroyed value
    /// ([`crate::accounting::check_block_conservation`]); a block that did
    /// is rejected as [`RejectionReason::InvariantViolated`], which halts
    /// the chain at it — the spec's "halts block production if violated".
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

        let (parent_height, parent_timestamp) = read_head(state).ok_or(BlockRejected {
            transaction_index: None,
            reason: RejectionReason::Rejected,
        })?;
        if parent_height.checked_add(1) != Some(block.height.0) {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::InvalidBlockHeight,
            });
        }
        if !is_after_parent(parent_timestamp, block.timestamp_millis) {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::InvalidBlockTimestamp,
            });
        }

        let params = Governance::new(StateView::new(state))
            .params()
            .map_err(|_| BlockRejected {
                transaction_index: None,
                reason: RejectionReason::Rejected,
            })?;
        let fee_params = params.fee_params();
        let ctx = BlockCtx {
            height: block.height,
            timestamp_ms: block.timestamp_millis,
            base_fee,
            params,
        };

        let mut gas_used: u64 = 0;
        let mut outcomes = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            let applied = self.apply_transaction(state, tx, index, &ctx)?;
            gas_used = gas_used.saturating_add(applied.gas_used);
            // Checked as it accumulates rather than after the loop, so an
            // oversized block is refused without executing the rest of it.
            // Not any one transaction's fault: the block as a whole is
            // over the limit `docs/spec.md` gives the base fee its target
            // from ("Max block gas").
            if gas_used > fee_params.max_block_gas() {
                return Err(BlockRejected {
                    transaction_index: None,
                    reason: RejectionReason::MalformedBlock,
                });
            }
            outcomes.push(applied.outcome);
        }

        let next_fee = next_base_fee(&fee_params, base_fee, gas_used);
        state.insert(
            base_fee_key(),
            StateValue::new(next_fee.to_le_bytes().to_vec()),
        );
        end_of_block(state, &ctx).map_err(|_| BlockRejected {
            transaction_index: None,
            reason: RejectionReason::Rejected,
        })?;
        write_head(state, block.height.0, block.timestamp_millis);
        #[cfg(test)]
        if let Some(fault) = self.fault {
            fault(state);
        }

        check_block_conservation(&self.state, state).map_err(|err| BlockRejected {
            transaction_index: None,
            reason: rejection_for(err),
        })?;
        Ok((gas_used, outcomes))
    }

    /// One transaction, in two distinct phases with distinct failure
    /// modes. First, validity (`docs/spec.md`'s "Transaction validity"
    /// table in full): chain ID, expiry against `height` (the height of
    /// the block carrying it), signature, then sequence number and
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
        ctx: &BlockCtx,
    ) -> Result<AppliedTransaction, BlockRejected> {
        let (base_fee, height) = (ctx.base_fee, ctx.height);
        let transaction_index = u32::try_from(tx_index).ok();
        let reject = move |reason: RejectionReason| BlockRejected {
            transaction_index,
            reason,
        };

        if tx.body.chain_id != self.chain_id {
            return Err(reject(RejectionReason::WrongChainId));
        }
        // Both halves of the rule, as `is_expiry_valid` defines them:
        // not yet past its expiry, and not set further ahead than the
        // horizon. The second is checked here as well as at admission so
        // it is a rule of the chain, not just of one node's mempool: a
        // transaction signed to live for years is exactly what the
        // horizon exists to prevent.
        if !tx.is_expiry_valid(height) {
            return Err(reject(RejectionReason::InvalidExpiry));
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

        let (outcome, gas_used) = match self.execute_call(state, tx, ctx) {
            Ok(effects) => {
                // The only place a call's changes ever reach `state`:
                // an abort returns before this, so rollback is
                // structural — there is nothing to undo.
                for (key, change) in effects.changes {
                    match change {
                        Some(value) => {
                            state.insert(key, value);
                        }
                        None => {
                            state.remove(&key);
                        }
                    }
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
        //
        // The sender's account is read again here, not taken from before
        // the call: a native call may have debited it (staking moves coin
        // out of the sender's balance), and the fee comes out of what is
        // left.
        let account = chain_state::account::read_account(state, sender)
            .map_err(|_| reject(RejectionReason::Rejected))?;
        let updated_account = account.apply_transaction(GasAmount(gas_used), GasPrice(base_fee));
        chain_state::account::write_account(state, sender, updated_account);

        // A burned fee leaves the supply. What was actually taken, which
        // is less than gas times price only if the balance ran out, which
        // the balance check above rules out.
        let burned = account.balance.saturating_sub(updated_account.balance);
        if burned > 0 {
            let supply = read_supply(state).ok_or_else(|| reject(RejectionReason::Rejected))?;
            let after = supply
                .checked_sub(burned)
                .ok_or_else(|| reject(RejectionReason::Rejected))?;
            write_supply(state, after);
        }

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
        ctx: &BlockCtx,
    ) -> Result<CallEffects, CallError> {
        // The native modules first: a call to one of their reserved
        // packages is theirs, whatever else it looks like.
        if let Some(result) = native::call(state, tx, ctx) {
            return result;
        }
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
            changes: vec![(
                calculator_result_key(account_address(&tx.sender_address())),
                Some(StateValue::new(sum.to_le_bytes().to_vec())),
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
            changes: vec![(
                object_key(INITIAL_COUNTER_ADDRESS),
                Some(StateValue::new(new_value.to_le_bytes().to_vec())),
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

/// How a failed conservation check rejects the block. Value created or
/// lost is the invariant the spec says halts block production; state the
/// check cannot read is damaged state, rejected as such.
fn rejection_for(err: AccountingError) -> RejectionReason {
    match err {
        AccountingError::Unbalanced => RejectionReason::InvariantViolated,
        AccountingError::SupplyUnreadable | AccountingError::Corrupt => RejectionReason::Rejected,
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

/// The head is 16 bytes: height then timestamp, both little-endian.
fn read_head(state: &BTreeMap<StateKey, StateValue>) -> Option<(u64, u64)> {
    let bytes: [u8; 16] = state.get(&chain_head_key())?.as_bytes().try_into().ok()?;
    let (height, timestamp) = bytes.split_at(8);
    Some((
        u64::from_le_bytes(height.try_into().ok()?),
        u64::from_le_bytes(timestamp.try_into().ok()?),
    ))
}

fn write_head(state: &mut BTreeMap<StateKey, StateValue>, height: u64, timestamp_millis: u64) {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&timestamp_millis.to_le_bytes());
    state.insert(chain_head_key(), StateValue::new(bytes));
}

fn decode_u64_arg(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

impl ChainView for Executor {
    fn head(&self) -> Result<Head, ChainViewError> {
        Ok(Head {
            height: BlockHeight(self.head_height().ok_or(ChainViewError)?),
            timestamp_ms: self.head_timestamp_millis().ok_or(ChainViewError)?,
            block_hash: self.tip_block_hash(),
            state_root: self.state_root(),
        })
    }

    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError> {
        Ok(Executor::validator_set(self)
            .map_err(|_| ChainViewError)?
            .into_iter()
            .map(|validator| ValidatorInfo {
                address: validator.id.0,
                consensus_key: validator.consensus_key,
                voting_power: validator.voting_power,
            })
            .collect())
    }

    fn block_limits(&self) -> Result<BlockLimits, ChainViewError> {
        Ok(BlockLimits {
            max_gas: self
                .params()
                .map_err(|_| ChainViewError)?
                .values()
                .max_block_gas,
            max_size_bytes: MAX_BLOCK_SIZE_BYTES,
        })
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn value_created_or_lost_is_the_invariant_rejection_and_damage_is_not() {
        assert_eq!(
            rejection_for(AccountingError::Unbalanced),
            RejectionReason::InvariantViolated
        );
        assert_eq!(
            rejection_for(AccountingError::Corrupt),
            RejectionReason::Rejected
        );
        assert_eq!(
            rejection_for(AccountingError::SupplyUnreadable),
            RejectionReason::Rejected
        );
    }

    #[test]
    fn the_audit_passes_on_a_fresh_executor_and_notices_value_that_appeared_from_nowhere() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(Address::from_bytes([1; 32]), 1_000)
            .unwrap();
        executor.audit().unwrap();

        // Inflate a balance without the supply following.
        let mut account = executor.read_account(Address::from_bytes([1; 32])).unwrap();
        account.balance += 1;
        chain_state::account::write_account(
            &mut executor.state,
            Address::from_bytes([1; 32]),
            account,
        );
        assert!(matches!(executor.audit(), Err(ExecutorError::Audit(_))));
    }

    #[test]
    fn genesis_parameters_outside_their_clamps_are_refused() {
        let mut values = GENESIS_PARAM_VALUES;
        values.inflation_bps = 9_999;
        assert!(matches!(
            Executor::genesis_with_params(ChainId(1), values),
            Err(ExecutorError::Params(_))
        ));
    }

    #[test]
    fn the_genesis_parameters_are_stored_in_state_where_governance_can_change_them() {
        let executor = Executor::genesis(ChainId(1)).unwrap();
        assert_eq!(*executor.params().unwrap().values(), GENESIS_PARAM_VALUES);
        assert_eq!(executor.supply(), Some(0));
        assert!(executor.validator_set().unwrap().is_empty());
    }

    /// An executor with `fault` applied to the state at the end of every
    /// block, and one funded account.
    fn faulty(fault: fn(&mut BTreeMap<StateKey, StateValue>)) -> Executor {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(Address::from_bytes([1; 32]), 1_000)
            .unwrap();
        executor.fault = Some(fault);
        executor
    }

    fn empty_block(executor: &Executor) -> Block {
        Block {
            parent_block_hash: executor.tip_block_hash(),
            height: BlockHeight(1),
            timestamp_millis: 1_000,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn a_block_that_creates_value_is_rejected_and_so_is_one_that_loses_it() {
        let creates: fn(&mut BTreeMap<StateKey, StateValue>) = |state| {
            let who = Address::from_bytes([1; 32]);
            let mut account = chain_state::account::read_account(state, who).unwrap();
            account.balance += 1;
            chain_state::account::write_account(state, who, account);
        };
        let destroys: fn(&mut BTreeMap<StateKey, StateValue>) = |state| {
            let who = Address::from_bytes([1; 32]);
            let mut account = chain_state::account::read_account(state, who).unwrap();
            account.balance -= 1;
            chain_state::account::write_account(state, who, account);
        };
        let inflates_supply: fn(&mut BTreeMap<StateKey, StateValue>) = |state| {
            let supply = read_supply(state).unwrap();
            write_supply(state, supply + 1);
        };

        for (name, fault) in [
            ("creates", creates),
            ("destroys", destroys),
            ("inflates the supply", inflates_supply),
        ] {
            let executor = faulty(fault);
            let block = empty_block(&executor);
            let rejected = executor
                .execute_block(executor.state_root(), &block)
                .unwrap_err();
            assert_eq!(
                rejected.reason,
                RejectionReason::InvariantViolated,
                "{name}"
            );
            assert_eq!(rejected.transaction_index, None);
        }
    }

    #[test]
    fn a_block_that_moves_value_without_making_or_losing_any_is_accepted() {
        let executor = faulty(|state| {
            // A transfer: one account down, another up, supply unchanged.
            let (a, b) = (Address::from_bytes([1; 32]), Address::from_bytes([2; 32]));
            let mut from = chain_state::account::read_account(state, a).unwrap();
            let mut to = chain_state::account::read_account(state, b).unwrap();
            from.balance -= 100;
            to.balance += 100;
            chain_state::account::write_account(state, a, from);
            chain_state::account::write_account(state, b, to);
        });
        let block = empty_block(&executor);
        assert!(executor
            .execute_block(executor.state_root(), &block)
            .is_ok());
    }

    #[test]
    fn finalising_refuses_such_a_block_too_so_it_cannot_be_committed() {
        let mut executor = faulty(|state| {
            let who = Address::from_bytes([1; 32]);
            let mut account = chain_state::account::read_account(state, who).unwrap();
            account.balance += 1;
            chain_state::account::write_account(state, who, account);
        });
        let good = Executor::genesis(ChainId(1)).unwrap();
        let block = empty_block(&executor);
        // A result computed by an honest node, offered for this block.
        let honest = good.execute_block(good.state_root(), &block).unwrap();
        assert_eq!(
            executor.finalise_block(&block, &honest).unwrap_err().reason,
            FinaliseErrorReason::StateRootMismatch
        );
        assert_eq!(executor.head_height(), Some(0), "nothing committed");
    }

    #[test]
    fn credited_coin_is_recorded_as_supply() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(Address::from_bytes([1; 32]), 700)
            .unwrap();
        executor
            .credit_account(Address::from_bytes([2; 32]), 300)
            .unwrap();
        assert_eq!(executor.supply(), Some(1_000));
        executor.audit().unwrap();
    }
}
