//! The node's runtime pieces: for now, the durable storage the consensus
//! host keeps on disk.
//!
//! Tier B, and not in the spec's crate table: this is where the traits that
//! `chain-consensus` (tier A, no I/O) defines meet the files `chain-db`
//! knows how to write safely, and where a node binary will be assembled.
//!
//! The host keeps four things beyond the chain itself, each with its own
//! file under one directory ([`NodeDisk::open`]):
//!
//! | File | Trait | Holds | Kept |
//! |---|---|---|---|
//! | `signer.mark` | `chain_signer::HighWaterMarkStore` | the position the signer will never sign at or below again | one value, replaced atomically |
//! | `signed.log` | `SignedLog` | the signatures made at the current height | the current height |
//! | `wal.log` | `Wal` | what changed the host's state at the current height | the current height |
//! | `commits.log` | `CommitLog` | recent decided blocks with their proofs, and the seed each led to | a window of recent heights |
//!
//! Every write that a safety argument rests on is `fsync`ed before the call
//! returns: the mark before a signature is released, the signature's record
//! before the signature is, the commit's record before the block is
//! finalised, the log before the host lets anything out. What each file does
//! with a write that a crash cut short is the business of `chain-db`'s
//! `HeightLog`; the mark file cannot be cut short, since it is replaced by
//! rename.
//!
//! The spec wants the signer to be a separate process with its own storage,
//! so that a node rollback cannot rewind it. This crate does not make it one;
//! [`FileMarkStore`] is the storage half of that, and refuses to be rewound
//! by the process that owns it.

#![forbid(unsafe_code)]

mod atomic;
pub mod commit_log;
pub mod disk;
pub mod mark_store;
pub mod signed_log;
pub mod wal;

pub use commit_log::FileCommitLog;
pub use disk::{DiskConfig, FileStorage, NodeDisk};
pub use mark_store::{FileMarkStore, MarkError};
pub use signed_log::FileSignedLog;
pub use wal::FileWal;

use chain_consensus::host::StorageError;

/// A storage failure, named for the host.
fn storage(error: impl core::fmt::Display) -> StorageError {
    StorageError(error.to_string())
}
