//! Everything the host keeps on disk, opened from one directory.

use std::fs;
use std::path::Path;

use chain_consensus::host::{
    Clock, CommitLog, CommitRecord, Ports, StorageError, TransactionSource, Wal,
};
use chain_types::{BlockHeight, Hash};

use crate::commit_log::FileCommitLog;
use crate::remote_signer::RemoteSigner;
use crate::signed_log::FileSignedLog;
use crate::storage;
use crate::wal::FileWal;

/// The host's own storage: its commit history and its write-ahead log.
pub struct FileStorage {
    commits: FileCommitLog,
    wal: FileWal,
}

impl CommitLog for FileStorage {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) -> Result<(), StorageError> {
        self.commits.record(record, seed_after)
    }

    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        self.commits.range(from, max)
    }

    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.commits.seed_after(height)
    }
}

impl Wal for FileStorage {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), StorageError> {
        self.wal.append(height, entry)
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.wal.flush()
    }

    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, StorageError> {
        self.wal.start_height(height)
    }
}

/// The node-owned files. The signer mark is deliberately absent: it belongs
/// to the separate signer process and its independently managed storage.
pub struct NodeDisk {
    pub signed: FileSignedLog,
    pub storage: FileStorage,
}

impl NodeDisk {
    /// Opens (creating what is missing) the files in `dir`. Anything damaged
    /// fails here, before the node does anything.
    pub fn open(dir: &Path) -> Result<Self, StorageError> {
        fs::create_dir_all(dir).map_err(storage)?;
        Ok(Self {
            signed: FileSignedLog::open(&dir.join("signed.log"))?,
            storage: FileStorage {
                commits: FileCommitLog::open(&dir.join("commits.log"))?,
                wal: FileWal::open(&dir.join("wal.log"))?,
            },
        })
    }

    /// The host's ports with a signer client supplied by the runtime. The node
    /// disk never receives a consensus secret key or signer mark store.
    pub fn into_ports<T: TransactionSource, C: Clock>(
        self,
        source: T,
        clock: C,
        signer: RemoteSigner,
    ) -> Ports<T, C, RemoteSigner, FileSignedLog, FileStorage> {
        Ports {
            source,
            clock,
            signer,
            log: self.signed,
            storage: self.storage,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn opening_makes_the_directory_and_the_files_and_a_second_open_finds_them() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("node");
        NodeDisk::open(&nested).unwrap();
        for file in ["signed.log", "commits.log", "wal.log"] {
            assert!(nested.join(file).exists(), "{file}");
        }
        assert!(!nested.join("signer.mark").exists());
        NodeDisk::open(&nested).unwrap();
    }

    #[test]
    fn a_damaged_file_stops_the_node_before_it_starts() {
        let dir = tempfile::tempdir().unwrap();
        NodeDisk::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("wal.log"), b"garbage that is not a log").unwrap();
        // The write-ahead log is only read when a height begins, but the
        // others are read at once.
        std::fs::write(dir.path().join("signed.log"), b"garbage that is not a log").unwrap();
        assert!(NodeDisk::open(dir.path()).is_err());
    }
}
