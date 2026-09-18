//! Staking, rewards, fees, governance, evidence.
//!
//! Tier A. Failure if wrong: Fund loss. This is the crate with the
//! highest invariant-testing budget in the workspace (`docs/spec.md`,
//! "Native modules": "These modules hold the funds").
//!
//! Five slices so far. [`staking`] is one validator's share-price
//! accounting. [`registry`] gives every validator one: registration with
//! proof of possession, delegation, the unbonding queue (still slashable
//! while it waits), the active validator set consensus runs on, and the
//! wiring of slashing to real stake. [`fees`] is the base-fee market's
//! arithmetic, EIP-1559 on the single dimension of compute — a pure
//! function, with storing and charging the fee left to `chain-exec`.
//! [`params`] and [`governance`] are minimal governance: the compiled-in
//! clamps on every adjustable parameter, and the proposal lifecycle
//! (vote, timelock, apply) that changes them or schedules a fork.
//! [`slashing`] admits equivocation evidence, prices it by how much stake
//! offended together, and jails for downtime; it returns burn orders,
//! which the registry applies. Governance and the registry are logic only
//! — nothing routes a transaction to either until the native module
//! boundary exists.

#![forbid(unsafe_code)]

pub mod fees;
pub mod governance;
pub mod params;
pub mod registry;
pub mod slashing;
pub mod staking;

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
