//! Storage, pruning, snapshots.
//!
//! Tier B. Failure if wrong: Halt, local corruption.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This first slice covers the flat key-value store: [`Db::commit_block`]
//! persists a block, its state root, and the state diff its execution
//! produced (`chain_state::StateDiff`) in one atomic MDBX transaction —
//! `docs/spec.md`, "State, storage and sync": "Writes are batched per
//! block and committed atomically with the block header. A crash
//! mid-write leaves the node at block N or N+1, never between."
//! `tests/crash_durability.rs` proves that by actually killing a
//! process mid-write (via `src/bin/crash_helper.rs`) and checking the
//! store afterward, not just by reasoning about MDBX's documented
//! guarantees.
//!
//! [`Db::initialise`] records where the chain starts (the genesis hash, the
//! root at height 0 and the whole genesis state), because a block commit
//! writes only what the block changes; [`Db::load_state`] reads the whole
//! committed state back, which is how a node restarts.
//!
//! [`HeightLog`] is a separate, smaller piece: a crash-safe append-only
//! file of entries grouped by height, with the torn-write handling a
//! write-ahead log needs, for the consensus host's log.
//!
//! Deliberately deferred, and not yet attempted: pruning (removing
//! anything outside the unbonding window), the three sync modes
//! (`docs/spec.md` requires full replay, snapshot sync, and warp sync
//! to all produce byte-identical roots — snapshot export/import and
//! warp sync don't exist here at all yet), and multi-process/
//! concurrent-writer coordination beyond what MDBX gives for free.

#![forbid(unsafe_code)]

pub mod error;
pub mod height_log;
pub mod schema;
pub mod store;

pub use error::DbError;
pub use height_log::{HeightLog, LogError};
pub use store::Db;
