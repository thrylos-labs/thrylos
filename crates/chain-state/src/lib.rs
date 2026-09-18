//! Merkle state trie, account model.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! The trie mechanics are a pure function from a flat, canonical
//! key-value state to a deterministic root hash, per `docs/spec.md`,
//! "State, storage and sync": "State is a binary Merkle trie over a
//! flat key-value store ... with the flat layout as the source of
//! truth and the trie derived." [`StateKey`] itself stays a fully
//! opaque, tagged byte string — [`account`] is one specific,
//! structured use of that space (tag [`account::KEY_TAG`]), not a
//! claim on the rest of it; a MoveVM integration's own object/module
//! keys share the same flat space under their own tags.
//!
//! [`account`] covers exactly what `docs/spec.md`'s "Transaction
//! validity" table needs from account state: a balance and the next
//! sequence number a sender's transaction must present, plus the
//! checks and effects built on them. It is not a Move resource/object
//! model — an account here is a plain struct, not a Move value.
//!
//! [`StateDiff`] recovers which keys one block's execution actually
//! wrote, so `chain-db` has something incremental to persist without
//! needing `chain-exec` to change how it executes. Still out of scope
//! here: the actual persistent storage backend (`chain-db`'s job —
//! "Storage, pruning, snapshots"), and inclusion/exclusion proofs,
//! which `docs/spec.md` explicitly puts out of scope for v1
//! ("light-client proofs").

#![forbid(unsafe_code)]

pub mod account;
pub mod diff;
pub mod key_value;
pub mod trie;

pub use account::{Account, AccountError};
pub use diff::{apply, diff, StateDiff};
pub use key_value::{StateKey, StateValue};
pub use trie::{compute_root, empty_root, StateRoot};
