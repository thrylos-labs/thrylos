//! Staking, rewards, fees, governance, evidence.
//!
//! Tier A. Failure if wrong: Fund loss. This is the crate with the
//! highest invariant-testing budget in the workspace (`docs/spec.md`,
//! "Native modules": "These modules hold the funds").
//!
//! Six slices so far. [`store`] is where the modules keep their state: an
//! ordered key-value trait, one entry per entity, with an in-memory
//! implementation for tests and an [`store::Overlay`] that makes a failed
//! operation leave nothing behind (`chain-exec` adapts the chain's flat
//! state to it). [`staking`] is one validator's share-price arithmetic.
//! [`registry`] gives every validator one, in the store: registration
//! with proof of possession, delegation, the unbonding queue (still
//! slashable while it waits), the active validator set consensus runs on,
//! and the wiring of slashing to real stake. [`fees`] is the base-fee market's
//! arithmetic, EIP-1559 on the single dimension of compute — a pure
//! function, with storing and charging the fee left to `chain-exec`.
//! [`params`] and [`governance`] are minimal governance: the compiled-in
//! clamps on every adjustable parameter, and the proposal lifecycle
//! (vote, timelock, apply) that changes them or schedules a fork.
//! [`slashing`] admits equivocation evidence, prices it by how much stake
//! offended together, and jails for downtime; it returns burn orders,
//! which the registry applies. Governance still keeps its state in memory
//! and is next to move into the store. Nothing routes a transaction to
//! any of this until the native module boundary exists.

#![forbid(unsafe_code)]

pub mod fees;
pub mod governance;
pub mod params;
pub mod registry;
pub mod slashing;
pub mod staking;
pub mod store;

pub use fees::{next_base_fee, FeeError, FeeParams, GENESIS_BASE_FEE, MIN_BASE_FEE};
pub use governance::{
    ForkName, Governance, GovernanceError, ProposalId, ProposalKind, ProposalStatus, VoteChoice,
};
pub use params::{GovernedParams, ParamChange, ParamError, ParamValues};
pub use registry::{
    ActiveValidator, Matured, RegistryError, SlashApplied, StakingRegistry, ValidatorId,
    MAX_ACTIVE_VALIDATORS, MAX_MATURING_PER_CALL, MAX_UNBONDING_ENTRIES_PER_PAIR,
};
pub use slashing::{
    slash_bps, EvidenceRejection, SlashOrder, SlashingTracker, ValidatorStatus, BASE_SLASH_BPS,
};
pub use staking::{StakingError, StakingPool, DEAD_SHARES, PRICE_FRAC_BITS};
pub use store::{MemStore, Overlay, Store};
