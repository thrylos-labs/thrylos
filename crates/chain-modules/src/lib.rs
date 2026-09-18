//! Staking, rewards, fees, governance, evidence.
//!
//! Tier A. Failure if wrong: Fund loss. This is the crate with the
//! highest invariant-testing budget in the workspace (`docs/spec.md`,
//! "Native modules": "These modules hold the funds").
//!
//! Four slices so far. [`staking`] is share-price accounting only — see
//! its doc comment for what (the pool registry, `StakeReceipt`,
//! `ValidatorId`, the unbonding-period queue) is deliberately deferred.
//! [`fees`] is the base-fee market's arithmetic, EIP-1559 on the single
//! dimension of compute — a pure function, with storing and charging
//! the fee left to `chain-exec`. [`params`] and [`governance`] are
//! minimal governance: the compiled-in clamps on every adjustable
//! parameter, and the proposal lifecycle (vote, timelock, apply) that
//! changes them or schedules a fork. [`slashing`] admits equivocation
//! evidence, prices it by how much stake offended together, and jails
//! for downtime; it returns burn orders rather than holding any stake.
//! Governance and slashing are logic only — nothing routes a
//! transaction to either until the native module boundary exists.

#![forbid(unsafe_code)]

pub mod fees;
pub mod governance;
pub mod params;
pub mod slashing;
pub mod staking;

pub use fees::{next_base_fee, FeeError, FeeParams, GENESIS_BASE_FEE, MIN_BASE_FEE};
pub use governance::{
    ForkName, Governance, GovernanceError, ProposalId, ProposalKind, ProposalStatus, VoteChoice,
};
pub use params::{GovernedParams, ParamChange, ParamError, ParamValues};
pub use slashing::{
    slash_bps, EvidenceRejection, SlashOrder, SlashingTracker, ValidatorStatus, BASE_SLASH_BPS,
};
pub use staking::{StakingError, StakingPool, DEAD_SHARES, PRICE_FRAC_BITS};
