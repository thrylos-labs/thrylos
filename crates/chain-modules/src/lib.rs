//! Staking, rewards, fees, governance, evidence.
//!
//! Tier A. Failure if wrong: Fund loss. This is the crate with the
//! highest invariant-testing budget in the workspace (`docs/spec.md`,
//! "Native modules": "These modules hold the funds").
//!
//! Two slices so far. [`staking`] is share-price accounting only — see
//! its doc comment for what (the pool registry, `StakeReceipt`,
//! `ValidatorId`, the unbonding-period queue) is deliberately deferred.
//! [`fees`] is the base-fee market's arithmetic, EIP-1559 on the single
//! dimension of compute — a pure function, with storing and charging
//! the fee left to `chain-exec`. Governance and evidence/slashing
//! aren't started yet.

#![forbid(unsafe_code)]

pub mod fees;
pub mod staking;

pub use fees::{next_base_fee, FeeError, FeeParams, GENESIS_BASE_FEE, MIN_BASE_FEE};
pub use staking::{StakingError, StakingPool, DEAD_SHARES, PRICE_FRAC_BITS};
