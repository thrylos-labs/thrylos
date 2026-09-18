//! Remote signer, slash protection.
//!
//! Tier A. Failure if wrong: Stake burn.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This crate is the double-sign-protection *logic* — the high-water-
//! mark state machine ([`Signer`]) and the timing invariant that makes
//! slashing enforceable ([`assert_slashing_window_ordering`]) — not a
//! standalone daemon. `docs/spec.md` calls for the signer to be "a
//! separate process with its own storage": that process/deployment
//! architecture, and a real fsync'd [`HighWaterMarkStore`]
//! implementation, are out of scope here; [`InMemoryStore`] exists only
//! for tests and is explicitly not durable. Key generation and custody
//! are likewise out of scope — [`Signer::load`] takes an already-
//! provisioned key.

#![forbid(unsafe_code)]

pub mod high_water_mark;
pub mod signer;
pub mod store;
pub mod timing;

pub use high_water_mark::{HighWaterMark, Step};
pub use signer::{Signer, SignerError};
pub use store::{HighWaterMarkStore, InMemoryStore};
pub use timing::{assert_slashing_window_ordering, TimingError};
