//! The real (if narrowly scoped) block executor, implementing
//! `chain_engine_api::Engine`. See `crate`'s doc comment for exactly
//! what this pass covers and what's deferred.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

use chain_engine_api::timestamp::is_after_parent;
use chain_engine_api::{
    max_transaction_gas, AbortReason, Block, BlockLimits, BlockRejected, ChainView, ChainViewError,
    Engine, ExecutedBlock, FinaliseError, FinaliseErrorReason, Head, RejectionReason,
    TransactionOutcome, ValidatorInfo, MAX_BLOCK_SIZE_BYTES,
};
use chain_modules::fees::{next_base_fee, GENESIS_BASE_FEE};
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_modules::{
    ActiveValidator, Governance, GovernedParams, ParamError, ParamValues, StakingRegistry,
    ValidatorId, DEAD_SHARES, MAX_ACTIVE_VALIDATORS,
};
use chain_state::{compute_root, StateChange, StateDiff, StateKey, StateRoot, StateValue};
use chain_types::codec::{CodecError, Encode};
use chain_types::{Address, BlockHeight, ChainId, GasAmount, GasPrice, Hash, Transaction};
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_vm_runtime::dev_utils::gas_schedule::{Gas, GasStatus, INITIAL_COST_SCHEDULE};
use move_vm_runtime::execution::interpreter::locals::BaseHeap;
use move_vm_runtime::execution::values::{Struct, Value};
use move_vm_runtime::runtime::MoveRuntime;
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
    /// Stored state could not be turned back into a chain: it is not the
    /// state that was committed, or is not a state a chain can be in.
    Restore(&'static str),
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
            Self::Restore(reason) => write!(f, "cannot restore the chain: {reason}"),
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

/// Consensus-enforced ceilings for the flat state. Execution currently
/// derives a block from a full in-memory snapshot, so these limits turn that
/// work from a function of unbounded chain history into a bounded protocol
/// cost. Raising either is a network upgrade, not a local tuning knob.
pub const MAX_STATE_ENTRIES: usize = 100_000;
pub const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

/// One compact authentication record per possible first-testnet proposer.
/// Unlike retaining full execution results, this stays small even when every
/// candidate has a block-sized write set.
const MAX_CACHED_EXECUTIONS: usize = MAX_ACTIVE_VALIDATORS;

const fn state_dimensions_within_limits(entries: usize, bytes: usize) -> bool {
    entries <= MAX_STATE_ENTRIES && bytes <= MAX_STATE_BYTES
}

fn state_within_limits(state: &BTreeMap<StateKey, StateValue>) -> bool {
    if !state_dimensions_within_limits(state.len(), 0) {
        return false;
    }
    let bytes = state.iter().try_fold(0usize, |total, (key, value)| {
        total
            .checked_add(key.as_bytes().len())?
            .checked_add(value.as_bytes().len())
    });
    bytes.is_some_and(|bytes| state_dimensions_within_limits(state.len(), bytes))
}

fn credit_account_state(
    state: &mut BTreeMap<StateKey, StateValue>,
    address: Address,
    amount: u128,
) -> Result<(), CodecError> {
    let mut account = chain_state::account::read_account(state, address)?;
    account.balance = account.balance.saturating_add(amount);
    chain_state::account::write_account(state, address, account);
    let supply = read_supply(state).unwrap_or(0);
    write_supply(state, supply.saturating_add(amount));
    Ok(())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

/// A compact commitment to every field finalisation trusts. It is local-only
/// (never a wire or consensus format), with its own BLAKE3 derivation context
/// so it cannot be confused with any protocol hash.
fn execution_fingerprint(executed: &ExecutedBlock) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("thrylos.execution-cache.v1");
    hasher.update(executed.state_root.as_hash().as_bytes());
    hasher.update(&executed.gas_used.to_le_bytes());
    hasher.update(
        &u64::try_from(executed.state_diff.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for (key, change) in executed.state_diff.iter() {
        hash_bytes(&mut hasher, key.as_bytes());
        match change {
            StateChange::Put(value) => {
                hasher.update(&[1]);
                hash_bytes(&mut hasher, value.as_bytes());
            }
            StateChange::Delete => {
                hasher.update(&[0]);
            }
        }
    }
    hasher.update(
        &u64::try_from(executed.outcomes.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for outcome in &executed.outcomes {
        hasher.update(&[outcome.code()]);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Copy)]
struct CachedExecution {
    parent_block_hash: Hash,
    parent_state_root: StateRoot,
    block_hash: Hash,
    fingerprint: [u8; 32],
}

pub struct Executor {
    chain_id: ChainId,
    state: BTreeMap<StateKey, StateValue>,
    state_root: StateRoot,
    tip_block_hash: Hash,
    runtime: MoveRuntime,
    /// Compact commitments to recently checked candidates. Keeping hashes,
    /// rather than block-sized write sets, bounds proposal-churn memory while
    /// allowing an earlier candidate to become certified after a later one
    /// was executed.
    executions: RefCell<VecDeque<CachedExecution>>,
    /// Test-only: something to do to the state after the block's hooks,
    /// standing in for a module that misbehaves, so the check that must
    /// catch it can be shown to.
    #[cfg(test)]
    fault: Option<fn(&mut BTreeMap<StateKey, StateValue>)>,
}

/// A fully checked next state, kept opaque so callers can persist the block
/// before allowing the executor's in-memory canonical head to advance.
///
/// [`Executor::prepare_finalisation`] checks that this exact result came from
/// this executor. [`Executor::apply_prepared_finalisation`] applies its
/// already-verified write set after confirming the executor has not moved.
pub struct PreparedFinalisation {
    parent_block_hash: Hash,
    parent_state_root: StateRoot,
    state_root: StateRoot,
    state_diff: StateDiff,
    block_hash: Hash,
}

impl Executor {
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Validate a previously executed result without advancing canonical
    /// in-memory state. A durable host commits `executed.state_diff` and the
    /// block atomically after this succeeds, then installs this value. The
    /// result must still be in this executor's bounded execution cache;
    /// finalisation never re-executes a block.
    pub fn prepare_finalisation(
        &self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<PreparedFinalisation, FinaliseError> {
        let max_size = usize::try_from(MAX_BLOCK_SIZE_BYTES).unwrap_or(usize::MAX);
        if block.encoded_len().is_none_or(|size| size > max_size) {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::StateRootMismatch,
            });
        }
        if block.parent_block_hash != self.tip_block_hash {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::NotOnCanonicalChain,
            });
        }

        let block_hash = block.hash();
        let fingerprint = execution_fingerprint(executed);
        let cached = self
            .executions
            .borrow()
            .iter()
            .rev()
            .find(|candidate| {
                candidate.parent_block_hash == self.tip_block_hash
                    && candidate.parent_state_root == self.state_root
                    && candidate.block_hash == block_hash
                    && candidate.fingerprint == fingerprint
            })
            .copied();
        if cached.is_none() {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::StateRootMismatch,
            });
        }

        Ok(PreparedFinalisation {
            parent_block_hash: self.tip_block_hash,
            parent_state_root: self.state_root,
            state_root: executed.state_root,
            state_diff: executed.state_diff.clone(),
            block_hash,
        })
    }

    /// Advance to a state returned by [`Self::prepare_finalisation`]. This
    /// remains fallible so a stale prepared value can never overwrite a head
    /// that moved before it was installed.
    pub fn apply_prepared_finalisation(
        &mut self,
        prepared: PreparedFinalisation,
    ) -> Result<(), FinaliseError> {
        if self.tip_block_hash != prepared.parent_block_hash
            || self.state_root != prepared.parent_state_root
        {
            return Err(FinaliseError {
                reason: FinaliseErrorReason::NotOnCanonicalChain,
            });
        }
        chain_state::apply(&mut self.state, &prepared.state_diff);
        self.state_root = prepared.state_root;
        self.tip_block_hash = prepared.block_hash;
        self.executions.get_mut().clear();
        Ok(())
    }

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
            credit_account_state(
                &mut executor.state,
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
        if !state_within_limits(&executor.state) {
            return Err(ExecutorError::GenesisConfig(
                GenesisConfigError::StateLimitExceeded,
            ));
        }
        executor.state_root = compute_root(&executor.state);
        executor.executions.get_mut().clear();
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
        let state_root = compute_root(&state);
        Ok(Self {
            chain_id,
            state,
            state_root,
            tip_block_hash: tip,
            runtime: Self::new_runtime()?,
            executions: RefCell::new(VecDeque::new()),
            #[cfg(test)]
            fault: None,
        })
    }

    /// The Move runtime every executor uses, however it was made: the same
    /// configuration for a chain that is starting and one that is restarting.
    fn new_runtime() -> Result<MoveRuntime, ExecutorError> {
        crate::framework::new_runtime().map_err(ExecutorError::Runtime)
    }

    /// Rebuilds the executor of a chain that was already running, from the
    /// state a node stored: `state` is the whole committed state,
    /// `tip_block_hash` is what the next block names as its parent, and
    /// `expected_root` is the root recorded for that state.
    ///
    /// Nothing is taken on trust. The state must hash to `expected_root`,
    /// must record a chain head, a base fee and governed parameters that can
    /// be read, and must pass the full [`Self::audit`]. Any failure is an
    /// error, so a node never starts from anything but the state it
    /// committed. Like the rest of this crate it does no I/O: every input is
    /// an argument, and the Move packages come from `state` itself, so
    /// nothing is compiled.
    pub fn restore(
        chain_id: ChainId,
        state: BTreeMap<StateKey, StateValue>,
        tip_block_hash: Hash,
        expected_root: StateRoot,
    ) -> Result<Self, ExecutorError> {
        if !state_within_limits(&state) {
            return Err(ExecutorError::Restore(
                "the state exceeds the protocol's entry or byte limit",
            ));
        }
        if compute_root(&state) != expected_root {
            return Err(ExecutorError::Restore(
                "the state does not hash to the recorded root",
            ));
        }
        if read_head(&state).is_none() {
            return Err(ExecutorError::Restore("the state records no chain head"));
        }
        let executor = Self {
            chain_id,
            state,
            state_root: expected_root,
            tip_block_hash,
            runtime: Self::new_runtime()?,
            executions: RefCell::new(VecDeque::new()),
            #[cfg(test)]
            fault: None,
        };
        if executor.base_fee().is_none() {
            return Err(ExecutorError::Restore("the state records no base fee"));
        }
        if executor.params().is_err() {
            return Err(ExecutorError::Restore(
                "the governed parameters cannot be read",
            ));
        }
        executor.audit()?;
        Ok(executor)
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// The canonical flat state in key order. Persistence, replay and audit
    /// harnesses use this to initialise an independently updated copy and
    /// compare its root with the executor's cached canonical root.
    pub fn state_entries(&self) -> impl Iterator<Item = (&StateKey, &StateValue)> {
        self.state.iter()
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

    /// What the package stored at (`owner`, `slot`, `type_name`) holds, as of the
    /// committed state. `type_name` is the type's canonical name
    /// (`0x<64 hex>::module::Name`, with `<...>` for a generic type).
    pub fn read_drawer(
        &self,
        owner: move_core_types::account_address::AccountAddress,
        slot: u64,
        type_name: &str,
    ) -> Result<Option<crate::drawer::DrawerValue>, crate::drawer::DrawerError> {
        let key = crate::keys::drawer_key(owner, slot, type_name);
        match self.state.get(&key) {
            None => Ok(None),
            Some(stored) => {
                let value = crate::drawer::DrawerValue::from_state(stored)?;
                Ok((value.type_name == type_name).then_some(value))
            }
        }
    }

    /// The drawers `owner` has, at most `limit`.
    pub fn drawers_of(
        &self,
        owner: move_core_types::account_address::AccountAddress,
        limit: usize,
    ) -> Vec<crate::view::DrawerSummary> {
        crate::view::drawers_of(&self.state, owner, limit)
    }

    /// A drawer's value read by its type, if the type's layout can be had.
    pub fn render_drawer(
        &self,
        drawer: &crate::drawer::DrawerValue,
    ) -> Option<crate::view::ViewValue> {
        crate::view::render_drawer(&self.runtime, &self.state, drawer)
    }

    /// What `tx`'s call would do, run against the committed state without
    /// committing it (`crate::simulate`). The transaction is not checked: no
    /// signature, sequence number or balance is needed, and none is used.
    pub fn simulate(
        &self,
        tx: &Transaction,
    ) -> Result<crate::simulate::Simulation, crate::simulate::SimulationFailure> {
        use crate::simulate::SimulationFailure;
        let (height, timestamp) = read_head(&self.state).ok_or(SimulationFailure::Internal)?;
        let ctx = self
            .block_ctx(
                &self.state,
                BlockHeight(height.saturating_add(1)),
                timestamp.saturating_add(1),
            )
            .map_err(|_| SimulationFailure::Internal)?;
        crate::simulate::simulate(&self.runtime, &self.state, tx, &ctx)
    }

    /// Credits `address`'s account by `amount`. `docs/spec.md` doesn't
    /// specify a genesis allocation table yet (only that fixed system
    /// state exists at genesis — see `crate::genesis`), so this is the
    /// explicit, auditable stand-in tests use to fund a sender rather
    /// than transactions succeeding against an implicit balance.
    ///
    /// Coin allocated this way is new supply, and is recorded as such.
    pub fn credit_account(&mut self, address: Address, amount: u128) -> Result<(), CodecError> {
        let previous = self.state.clone();
        credit_account_state(&mut self.state, address, amount)?;
        if !state_within_limits(&self.state) {
            self.state = previous;
            return Err(CodecError::LengthTooLarge);
        }
        self.state_root = compute_root(&self.state);
        self.executions.get_mut().clear();
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
        crate::drawer::audit(&self.state)
            .map_err(|err| ExecutorError::Audit(format!("drawers: {err}")))?;
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
    /// The block context a call runs in: the base fee and governed
    /// parameters as `state` currently has them. Shared by `apply_block`
    /// and `propose_block` — proposing now simulates execution too (see
    /// `propose_block`'s doc comment), and the two must agree on exactly
    /// what a call would see, or a proposal's simulation could accept what
    /// execution would later reject on a technicality unrelated to the
    /// state cap it exists to police.
    fn block_ctx(
        &self,
        state: &BTreeMap<StateKey, StateValue>,
        height: BlockHeight,
        timestamp_millis: u64,
    ) -> Result<BlockCtx, BlockRejected> {
        // Missing or malformed, this is a broken state invariant (genesis
        // seeds it and only `apply_block` writes it), not anything a block
        // did.
        let base_fee = read_u64(state, &base_fee_key()).ok_or(BlockRejected {
            transaction_index: None,
            reason: RejectionReason::Rejected,
        })?;
        let params = Governance::new(StateView::new(state))
            .params()
            .map_err(|_| BlockRejected {
                transaction_index: None,
                reason: RejectionReason::Rejected,
            })?;
        Ok(BlockCtx {
            chain_id: self.chain_id,
            height,
            timestamp_ms: timestamp_millis,
            base_fee,
            params,
        })
    }

    fn apply_block(
        &self,
        state: &mut BTreeMap<StateKey, StateValue>,
        block: &Block,
    ) -> Result<(u64, Vec<TransactionOutcome>), BlockRejected> {
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

        let ctx = self.block_ctx(state, block.height, block.timestamp_millis)?;
        let fee_params = ctx.params.fee_params();
        let transaction_gas_ceiling = max_transaction_gas(fee_params.max_block_gas());
        let base_fee = ctx.base_fee;

        let mut gas_used: u64 = 0;
        let mut protocol_calls = 0usize;
        let mut outcomes = Vec::with_capacity(block.transactions.len());
        for (index, tx) in block.transactions.iter().enumerate() {
            if tx.body.gas_limit.0 > transaction_gas_ceiling {
                return Err(BlockRejected {
                    transaction_index: u32::try_from(index).ok(),
                    reason: RejectionReason::TransactionGasLimitExceeded,
                });
            }
            if native::is_limited_protocol_call(tx) {
                protocol_calls = protocol_calls.saturating_add(1);
                if protocol_calls > native::MAX_PROTOCOL_CALLS_PER_BLOCK {
                    return Err(BlockRejected {
                        transaction_index: u32::try_from(index).ok(),
                        reason: RejectionReason::MalformedBlock,
                    });
                }
            }
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
        // A rule of the chain, not just of one node's mempool: a block that
        // carries a transaction under the floor is not a valid block.
        if tx.body.gas_limit.0 < chain_types::MIN_GAS_LIMIT {
            return Err(reject(RejectionReason::TransactionGasLimitExceeded));
        }
        if native::is_protocol_call(tx) && tx.body.gas_limit.0 < native::MIN_PROTOCOL_CALL_GAS {
            return Err(reject(RejectionReason::TransactionGasLimitExceeded));
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
            // Calls outside the Move interpreter do not yet have measured
            // schedules. Charge their declared ceiling on abort so those
            // paths cannot become free spam. Metered Move aborts carry the
            // amount the VM actually consumed in the next arm.
            Err(CallError::Abort(reason)) => {
                (TransactionOutcome::Aborted(reason), tx.body.gas_limit.0)
            }
            Err(CallError::MeteredAbort { reason, gas_used }) => {
                (TransactionOutcome::Aborted(reason), gas_used)
            }
            Err(CallError::Internal) => return Err(reject(RejectionReason::Rejected)),
        };

        // Never less than the floor, whatever the call happened to meter:
        // a call that fails almost at once must not be nearly free to send.
        // The declared limit is at least the floor (checked above), and a
        // call never uses more than it declared, so this stays within it.
        let gas_used = gas_used.max(chain_types::MIN_GAS_LIMIT);

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
        if crate::publish::is_publish_call(tx) {
            return crate::publish::call(&self.runtime, state, tx, ctx);
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
        } else if let Some(result) = crate::entry::call(&self.runtime, state, tx, ctx) {
            result
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
        let mut gas_meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(tx.body.gas_limit.0));
        let execution = vm.execute_function_bypass_visibility(
            &module_id,
            &function_name,
            vec![],
            vec![Value::u64(a), Value::u64(b)],
            &mut gas_meter,
            None,
        );
        let remaining: u64 = gas_meter.remaining_gas().into();
        let gas_used = tx.body.gas_limit.0.saturating_sub(remaining);
        let mut returned = execution.map_err(|_| CallError::MeteredAbort {
            reason: AbortReason::ExecutionFailed,
            gas_used,
        })?;
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
            gas_used,
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
        let mut gas_meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(tx.body.gas_limit.0));
        let execution = vm.execute_function_bypass_visibility(
            &module_id,
            &function_name,
            vec![],
            vec![counter_ref, Value::u64(amount)],
            &mut gas_meter,
            None,
        );
        let remaining: u64 = gas_meter.remaining_gas().into();
        let gas_used = tx.body.gas_limit.0.saturating_sub(remaining);
        let returned = execution.map_err(|_| CallError::MeteredAbort {
            reason: AbortReason::ExecutionFailed,
            gas_used,
        })?;
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
            gas_used,
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
    fn chain_id(&self) -> ChainId {
        self.chain_id()
    }

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
    /// Packs candidates by gas and size, as before, but each survivor is
    /// also speculatively applied to a scratch copy of `state` before it is
    /// accepted, and dropped if that would breach the protocol's state
    /// cap ([`MAX_STATE_ENTRIES`], [`MAX_STATE_BYTES`]).
    ///
    /// This exists because `execute_block` checks that cap only once, over
    /// the whole block, and reports a breach as an unattributed rejection
    /// (`transaction_index: None`) — nothing names which transaction to
    /// drop. A proposer that packed blindly would have every candidate
    /// bulk-rejected the moment state neared the cap, and its retry loop
    /// (`chain_consensus::host`) can only respond to an unattributed
    /// rejection by discarding every candidate and proposing empty — so
    /// once state was near the cap, no transaction that grows it (an
    /// ordinary transfer to a fresh address among them) could ever be
    /// included again, by any proposer, permanently. Simulating here
    /// instead means a block this executor proposes never fails this check
    /// in the first place, at the cost of running each accepted candidate
    /// through real execution during proposal as well as at execution —
    /// bounded by how many candidates are offered, not by state size, but
    /// a real cost this function did not use to pay.
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
        // Gas the Move calls packed so far actually used (`crate::policy`).
        let mut move_gas_used: u64 = 0;
        let transaction_gas_ceiling = max_transaction_gas(limits.max_gas);
        let max_size =
            usize::try_from(limits.max_size_bytes.min(MAX_BLOCK_SIZE_BYTES)).unwrap_or(usize::MAX);
        let empty = Block {
            parent_block_hash,
            height,
            timestamp_millis,
            transactions: Vec::new(),
        };
        let mut encoded_size = empty.encoded_len().unwrap_or(usize::MAX);

        // `None` only if the state invariants `block_ctx` depends on are
        // already broken, in which case `execute_block` will fail on this
        // same state moments later regardless — simulation is skipped
        // rather than proposing nothing, since that failure is not this
        // function's to report.
        let ctx = self.block_ctx(&self.state, height, timestamp_millis).ok();
        let mut scratch = ctx.is_some().then(|| self.state.clone());
        let mut try_on_copy = false;
        let mut protocol_calls = 0usize;

        for tx in candidate_transactions {
            if tx.body.gas_limit.0 > transaction_gas_ceiling
                || tx.body.gas_limit.0 < chain_types::MIN_GAS_LIMIT
            {
                continue;
            }
            let Some(next_total) = gas_so_far.checked_add(tx.body.gas_limit.0) else {
                break;
            };
            if next_total > limits.max_gas {
                break;
            }
            // `apply_block` refuses a block with more than this many
            // protocol calls, so a proposer must stop at the cap rather
            // than propose a block its own peers will reject.
            let limited = native::is_limited_protocol_call(&tx);
            if limited && protocol_calls >= native::MAX_PROTOCOL_CALLS_PER_BLOCK {
                continue;
            }

            let mut encoded_transaction = Vec::new();
            tx.encode(&mut encoded_transaction);
            let Some(next_size) = encoded_size.checked_add(encoded_transaction.len()) else {
                continue;
            };
            if next_size > max_size {
                continue;
            }

            // A node's own limit on Move work per block (`crate::policy`), not a
            // rule of the chain: once the calls already packed have used their
            // share, the rest wait for a later block.
            let user_move_call = crate::policy::is_user_move_call(&tx);
            if user_move_call && move_gas_used >= crate::policy::MOVE_GAS_PER_PROPOSED_BLOCK {
                continue;
            }
            if let (Some(ctx), Some(state)) = (ctx, scratch.as_mut()) {
                let would_be_index = transactions.len();
                // `Err` means nothing was written — every rejecting check
                // in `apply_transaction` runs before its first mutation —
                // so a transaction invalid for reasons unrelated to the
                // state cap is left for `execute_block`'s existing
                // per-transaction retry to name and drop, exactly as
                // before this function simulated anything. Only a breach
                // of the cap itself is this loop's to police.
                //
                // The common case applies straight onto the running
                // scratch: no per-candidate copy of the whole state. Only
                // when a transaction is found to have breached the cap is
                // the scratch rebuilt from the accepted transactions, and
                // from then on candidates are tried on a copy, since a
                // proposer that has hit the cap is the one place a rollback
                // is needed again.
                if try_on_copy {
                    let mut attempt = state.clone();
                    if let Ok(applied) =
                        self.apply_transaction(&mut attempt, &tx, would_be_index, &ctx)
                    {
                        if !state_within_limits(&attempt) {
                            continue;
                        }
                        *state = attempt;
                        if user_move_call {
                            move_gas_used = move_gas_used.saturating_add(applied.gas_used);
                        }
                    }
                } else if let Ok(applied) = self.apply_transaction(state, &tx, would_be_index, &ctx)
                {
                    if !state_within_limits(state) {
                        let mut rebuilt = self.state.clone();
                        for (index, kept) in transactions.iter().enumerate() {
                            // Replaying what was already accepted: it applied
                            // cleanly against exactly this state a moment ago.
                            let _ = self.apply_transaction(&mut rebuilt, kept, index, &ctx);
                        }
                        *state = rebuilt;
                        try_on_copy = true;
                        continue;
                    }
                    if user_move_call {
                        move_gas_used = move_gas_used.saturating_add(applied.gas_used);
                    }
                }
            } else if user_move_call {
                // No scratch state to try it on: count what it may use.
                move_gas_used = move_gas_used.saturating_add(tx.body.gas_limit.0);
            }

            gas_so_far = next_total;
            encoded_size = next_size;
            if limited {
                protocol_calls = protocol_calls.saturating_add(1);
            }
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
        let max_size = usize::try_from(MAX_BLOCK_SIZE_BYTES).unwrap_or(usize::MAX);
        if block.encoded_len().is_none_or(|size| size > max_size) {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::MalformedBlock,
            });
        }
        if parent_state_root != self.state_root || block.parent_block_hash != self.tip_block_hash {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::MalformedBlock,
            });
        }

        let mut scratch = self.state.clone();
        let (gas_used, outcomes) = self.apply_block(&mut scratch, block)?;
        if !state_within_limits(&scratch) {
            return Err(BlockRejected {
                transaction_index: None,
                reason: RejectionReason::MalformedBlock,
            });
        }
        let executed = ExecutedBlock {
            state_root: compute_root(&scratch),
            gas_used,
            state_diff: chain_state::diff(&self.state, &scratch),
            outcomes,
        };
        let block_hash = block.hash();
        let cached = CachedExecution {
            parent_block_hash: self.tip_block_hash,
            parent_state_root: self.state_root,
            block_hash,
            fingerprint: execution_fingerprint(&executed),
        };
        let mut executions = self.executions.borrow_mut();
        executions.retain(|candidate| candidate.block_hash != block_hash);
        if executions.len() == MAX_CACHED_EXECUTIONS {
            executions.pop_front();
        }
        executions.push_back(cached);
        Ok(executed)
    }

    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        let prepared = self.prepare_finalisation(block, executed)?;
        self.apply_prepared_finalisation(prepared)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BLOCK_APPLICATIONS: AtomicUsize = AtomicUsize::new(0);

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
    fn finalisation_applies_the_cached_write_set_without_reexecuting() {
        BLOCK_APPLICATIONS.store(0, Ordering::SeqCst);
        let mut executor = faulty(|_| {
            BLOCK_APPLICATIONS.fetch_add(1, Ordering::SeqCst);
        });
        let block = empty_block(&executor);
        let executed = executor
            .execute_block(executor.state_root(), &block)
            .unwrap();
        assert_eq!(BLOCK_APPLICATIONS.load(Ordering::SeqCst), 1);
        executor.finalise_block(&block, &executed).unwrap();
        assert_eq!(BLOCK_APPLICATIONS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_later_candidate_does_not_displace_an_earlier_one_that_becomes_certified() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        let first = empty_block(&executor);
        let mut later = first.clone();
        later.timestamp_millis = later.timestamp_millis.saturating_add(1);

        let executed_first = executor
            .execute_block(executor.state_root(), &first)
            .unwrap();
        executor
            .execute_block(executor.state_root(), &later)
            .unwrap();
        executor.finalise_block(&first, &executed_first).unwrap();

        assert_eq!(executor.tip_block_hash(), first.hash());
        assert_eq!(
            executor.head_timestamp_millis(),
            Some(first.timestamp_millis)
        );
    }

    #[test]
    fn state_entry_and_payload_limits_include_the_boundary_but_not_one_past_it() {
        assert!(state_dimensions_within_limits(
            MAX_STATE_ENTRIES,
            MAX_STATE_BYTES
        ));
        assert!(!state_dimensions_within_limits(
            MAX_STATE_ENTRIES + 1,
            MAX_STATE_BYTES
        ));
        assert!(!state_dimensions_within_limits(
            MAX_STATE_ENTRIES,
            MAX_STATE_BYTES + 1
        ));
    }

    /// The address a `coin_transfer(seed, ..)` call signs from — so a test
    /// can fund the account that will actually send it, not a coincidental
    /// stand-in address with no relation to the signing key.
    fn address_of(seed: u8) -> Address {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let public =
            chain_types::PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes())
                .unwrap();
        Address::from_public_key(&public)
    }

    /// A native coin transfer to `recipient`, signed by `seed`, funded and
    /// sequenced by the caller ([`address_of`] names the account that must
    /// hold that funding). Building one by hand (rather than through
    /// `client::signed_transfer`, which this crate cannot depend on) keeps
    /// this test inside `chain-exec` alongside the code it is proving.
    fn coin_transfer(
        seed: u8,
        sequence_number: u64,
        recipient: Address,
        amount: u128,
    ) -> Transaction {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let sender =
            chain_types::PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes())
                .unwrap();
        let body = chain_types::TransactionBody {
            chain_id: ChainId(1),
            sender,
            sequence_number: chain_types::SequenceNumber(sequence_number),
            expiry: BlockHeight(1_000),
            gas_limit: GasAmount(native::MIN_PROTOCOL_CALL_GAS),
            max_fee_per_gas: GasPrice(1),
            declared_inputs: Vec::new(),
            call: chain_types::MoveCall {
                module_address: Address::from_bytes(native::COIN_PACKAGE_ADDRESS),
                module_name: native::COIN_MODULE_NAME.as_bytes().to_vec(),
                function_name: native::TRANSFER.as_bytes().to_vec(),
                type_arguments: Vec::new(),
                arguments: vec![recipient.as_bytes().to_vec(), amount.to_le_bytes().to_vec()],
            },
        };
        let mut bytes = Vec::new();
        body.encode(&mut bytes);
        use ed25519_dalek::Signer;
        let signature =
            chain_types::Signature::from_ed25519_bytes(signing_key.sign(&bytes).to_bytes());
        Transaction { body, signature }
    }

    /// Pads `executor`'s state with synthetic entries — content is
    /// irrelevant to the cap, only count is — until exactly `spare` slots
    /// remain under [`MAX_STATE_ENTRIES`].
    fn fill_state_to_within(executor: &mut Executor, spare: usize) {
        let target = MAX_STATE_ENTRIES.saturating_sub(spare);
        let mut next = 0u64;
        while executor.state.len() < target {
            let key = StateKey::new(format!("load-test-padding-{next}").into_bytes());
            executor.state.insert(key, StateValue::new(vec![0u8; 8]));
            next += 1;
        }
    }

    #[test]
    fn proposal_drops_a_transaction_that_would_breach_the_state_entry_cap() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(address_of(2), 1_000_000_000)
            .unwrap();
        let limits = executor.block_limits().unwrap();

        // No room for even one more entry: a transfer to a fresh address
        // must be dropped, not proposed and rejected wholesale later.
        fill_state_to_within(&mut executor, 0);
        let recipient = Address::from_bytes([222; 32]);
        let tx = coin_transfer(2, 0, recipient, 10);
        let block = executor.propose_block(
            executor.tip_block_hash(),
            executor.state_root(),
            BlockHeight(1),
            1_000,
            vec![tx],
            limits,
        );
        assert_eq!(
            block.transactions,
            Vec::new(),
            "a state-cap-breaching transaction must not be proposed"
        );
    }

    #[test]
    fn proposal_still_includes_a_transaction_that_fits_under_the_state_entry_cap() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(address_of(2), 1_000_000_000)
            .unwrap();
        let limits = executor.block_limits().unwrap();

        // Room for exactly one more entry: the same shape of transaction
        // now fits, proving the drop above is about the cap specifically,
        // not a simulation that always refuses.
        fill_state_to_within(&mut executor, 1);
        let recipient = Address::from_bytes([222; 32]);
        let tx = coin_transfer(2, 0, recipient, 10);
        let block = executor.propose_block(
            executor.tip_block_hash(),
            executor.state_root(),
            BlockHeight(1),
            1_000,
            vec![tx.clone()],
            limits,
        );
        assert_eq!(block.transactions, vec![tx]);
    }

    fn unjail_call(seed: u8, sequence_number: u64) -> Transaction {
        let mut tx = coin_transfer(seed, sequence_number, Address::from_bytes([0; 32]), 1);
        tx.body.call.module_address = Address::from_bytes(native::STAKING_PACKAGE_ADDRESS);
        tx.body.call.module_name = native::STAKING_MODULE_NAME.as_bytes().to_vec();
        tx.body.call.function_name = native::UNJAIL.as_bytes().to_vec();
        tx.body.call.arguments = Vec::new();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut bytes = Vec::new();
        tx.body.encode(&mut bytes);
        use ed25519_dalek::Signer;
        tx.signature =
            chain_types::Signature::from_ed25519_bytes(signing_key.sign(&bytes).to_bytes());
        tx
    }

    #[test]
    fn proposal_stops_at_the_protocol_call_cap_instead_of_proposing_a_block_peers_reject() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(address_of(2), 1_000_000_000)
            .unwrap();
        let limits = executor.block_limits().unwrap();
        let cap = native::MAX_PROTOCOL_CALLS_PER_BLOCK;
        let calls: Vec<Transaction> = (0..u64::try_from(cap + 10).unwrap())
            .map(|sequence| unjail_call(2, sequence))
            .collect();
        let block = executor.propose_block(
            executor.tip_block_hash(),
            executor.state_root(),
            BlockHeight(1),
            1_000,
            calls,
            limits,
        );
        assert_eq!(block.transactions.len(), cap);
        assert!(
            executor
                .execute_block(executor.state_root(), &block)
                .is_ok(),
            "the block it proposed must be one it would itself accept"
        );
    }

    #[test]
    fn proposal_keeps_what_fits_after_dropping_a_transaction_that_breached_the_cap() {
        let mut executor = Executor::genesis(ChainId(1)).unwrap();
        executor
            .credit_account(address_of(2), 1_000_000_000)
            .unwrap();
        let limits = executor.block_limits().unwrap();
        fill_state_to_within(&mut executor, 1);
        let first = Address::from_bytes([222; 32]);
        let second = Address::from_bytes([223; 32]);
        let fits = coin_transfer(2, 0, first, 10);
        let breaches = coin_transfer(2, 1, second, 10);
        // Sequence 1 again: the dropped transaction never used its number.
        let later = coin_transfer(2, 1, first, 10);
        let block = executor.propose_block(
            executor.tip_block_hash(),
            executor.state_root(),
            BlockHeight(1),
            1_000,
            vec![fits.clone(), breaches, later.clone()],
            limits,
        );
        assert_eq!(block.transactions, vec![fits, later]);
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
