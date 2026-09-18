//! Merkle state trie, account model.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This first slice covers the trie mechanics only — a pure function
//! from a flat, canonical key-value state to a deterministic root hash,
//! per `docs/spec.md`, "State, storage and sync": "State is a binary
//! Merkle trie over a flat key-value store ... with the flat layout as
//! the source of truth and the trie derived." The "account model" half
//! of this crate's stated scope — what a state key actually addresses
//! (an account, a Move resource, an object) — depends on MoveVM
//! integration decisions not yet made, so [`StateKey`] stays a fully
//! opaque byte string rather than guessing a structure.
//!
//! Also out of scope here: the actual persistent, incremental storage
//! backend (`chain-db`'s job — "Storage, pruning, snapshots"), and
//! inclusion/exclusion proofs, which `docs/spec.md` explicitly puts out
//! of scope for v1 ("light-client proofs").

#![forbid(unsafe_code)]

pub mod key_value;
pub mod trie;

pub use key_value::{StateKey, StateValue};
pub use trie::{compute_root, empty_root, StateRoot};
