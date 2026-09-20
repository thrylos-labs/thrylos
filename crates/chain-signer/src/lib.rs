//! Remote signer, slash protection.
//!
//! Tier A. Failure if wrong: Stake burn.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This crate owns the double-sign-protection logic: the high-water-mark
//! state machine ([`Signer`]), its narrow [`ConsensusSigner`] boundary and the
//! timing invariant that makes slashing enforceable
//! ([`assert_slashing_window_ordering`]). `chain-node` supplies the separate
//! signer process, authenticated local protocol and fsync'd mark store;
//! [`InMemoryStore`] remains test-only. Key generation, rotation and custody
//! integrations are outside this crate — [`Signer::load`] takes an already
//! provisioned key.

#![forbid(unsafe_code)]

pub mod high_water_mark;
pub mod signer;
pub mod store;
pub mod timing;

pub use high_water_mark::{HighWaterMark, Step};
pub use signer::{ConsensusSigner, Signer, SignerError};
pub use store::{HighWaterMarkStore, InMemoryStore};
pub use timing::{assert_slashing_window_ordering, TimingError};
