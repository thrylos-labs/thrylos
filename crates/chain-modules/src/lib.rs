//! Staking, rewards, fees, governance, evidence.
//!
//! Tier A. Failure if wrong: Fund loss. This is the crate with the
//! highest invariant-testing budget in the workspace (`docs/spec.md`,
//! "Native modules": "These modules hold the funds").
//!
//! This first slice covers staking's share-price accounting only —
//! see [`staking`]'s module doc comment for exactly what's included and
//! what (the pool registry, `StakeReceipt`, `ValidatorId`, the
//! unbonding-period queue) is deliberately deferred. Fees, governance,
//! and evidence/slashing aren't started yet.

#![forbid(unsafe_code)]

pub mod staking;

pub use staking::{StakingError, StakingPool, DEAD_SHARES, PRICE_FRAC_BITS};
