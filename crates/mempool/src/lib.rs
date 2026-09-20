//! Tx admission, eviction, replacement.
//!
//! Tier B. Failure if wrong: DoS, censorship.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This first slice covers everything the pending-transaction pool
//! itself can decide: admission (chain ID, signature, expiry,
//! sequence-number floor, balance-covers-max-fee), fee-bump
//! replacement, effective-fee eviction under a per-sender cap, and
//! fee-ordered candidate selection for block proposal — see [`pool`]'s
//! doc comment for the exact rules and why "effective fee" is just
//! `max_fee_per_gas` for now.
//!
//! [`AccountView`] is a typed seam, not a hard dependency on how a
//! caller keeps account state: [`StateAccountView`] is the real
//! implementation, backed by `chain-state`'s account model. Gossip/
//! propagation (P2P admission ordering and peer handling) is out of scope
//! here — that's `chain-p2p`'s side of `docs/spec.md`'s "P2P and
//! mempool" section.

#![forbid(unsafe_code)]

pub mod account_view;
pub mod pool;

pub use account_view::{AccountView, StateAccountView};
pub use pool::{AdmissionError, Mempool, MempoolConfig};
