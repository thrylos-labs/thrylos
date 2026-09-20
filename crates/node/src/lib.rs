//! Durable node storage and the separate consensus-signer process boundary.
//!
//! Tier B, and not in the spec's crate table: this is where the traits that
//! `chain-consensus` (tier A, no I/O) defines meet the files `chain-db`
//! knows how to write safely, and where a node binary will be assembled.
//!
//! The chain itself is [`DurableEngine`]'s: the executor with its blocks and
//! state kept in an MDBX database (`chain/` inside the node's directory),
//! committed before the chain advances and restored, checked, on restart.
//!
//! The node keeps three things beyond the chain itself, each with its own
//! file under one directory ([`NodeDisk::open`]):
//!
//! | File | Trait | Holds | Kept |
//! |---|---|---|---|
//! | `signed.log` | `SignedLog` | the signatures made at the current height | the current height |
//! | `wal.log` | `Wal` | what changed the host's state at the current height | the current height |
//! | `commits.log` | `CommitLog` | recent decided blocks with their proofs, and the seed each led to | a window of recent heights |
//!
//! Every write that a safety argument rests on is `fsync`ed before the call
//! returns: the remote signer persists its mark before releasing a signature;
//! the node persists the signature's record before releasing it to consensus;
//! and it records a commit before finalising the block. What each log does
//! with a write that a crash cut short is the business of `chain-db`'s
//! `HeightLog`; the signer mark cannot be cut short because it is replaced by
//! rename.
//!
//! [`SignerServer`] is the separate process boundary. It owns the consensus
//! key and [`FileMarkStore`]; [`RemoteSigner`] is the node-side handle and
//! contains neither.

#![forbid(unsafe_code)]

mod atomic;
pub mod commit_log;
pub mod disk;
pub mod durable_engine;
pub mod mark_store;
pub mod remote_signer;
pub mod signed_log;
pub mod wal;

pub use commit_log::FileCommitLog;
pub use disk::{DiskConfig, FileStorage, NodeDisk};
pub use durable_engine::{DurableEngine, OpenError};
pub use mark_store::{FileMarkStore, MarkError};
pub use remote_signer::{RemoteSigner, RemoteSignerError, SignerCredential, SignerServer};
pub use signed_log::FileSignedLog;
pub use wal::FileWal;

use chain_consensus::host::StorageError;

/// A storage failure, named for the host.
fn storage(error: impl core::fmt::Display) -> StorageError {
    StorageError(error.to_string())
}
