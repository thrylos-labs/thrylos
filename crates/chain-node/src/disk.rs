//! Everything the host keeps on disk, opened from one directory.

use std::fs;
use std::path::Path;

use blst::min_pk::SecretKey;
use chain_consensus::host::{
    Clock, CommitLog, CommitRecord, Ports, StorageError, TransactionSource, Wal,
};
use chain_signer::Signer;
use chain_types::{BlockHeight, Hash};

use crate::commit_log::FileCommitLog;
use crate::mark_store::{FileMarkStore, MarkError};
use crate::signed_log::FileSignedLog;
use crate::storage;
use crate::wal::FileWal;

/// How the files are kept.
#[derive(Debug, Clone, Copy)]
pub struct DiskConfig {
    /// **A choice.** How many recent decided blocks the commit log keeps to
    /// answer a peer that fell behind. Held in memory, so it is a bound on
    /// how much.
    pub commit_history: usize,
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            commit_history: 256,
        }
    }
}

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

/// The four files under a node's directory. See the crate docs.
pub struct NodeDisk {
    pub mark: FileMarkStore,
    pub signed: FileSignedLog,
    pub storage: FileStorage,
}

impl NodeDisk {
    /// Opens (creating what is missing) the files in `dir`. Anything damaged
    /// fails here, before the node does anything.
    pub fn open(dir: &Path, config: DiskConfig) -> Result<Self, StorageError> {
        fs::create_dir_all(dir).map_err(storage)?;
        Ok(Self {
            mark: FileMarkStore::open(&dir.join("signer.mark")),
            signed: FileSignedLog::open(&dir.join("signed.log"))?,
            storage: FileStorage {
                commits: FileCommitLog::open(&dir.join("commits.log"), config.commit_history)?,
                wal: FileWal::open(&dir.join("wal.log"))?,
            },
        })
    }

    /// The host's ports, with the signer loaded from its mark file.
    pub fn into_ports<T: TransactionSource, C: Clock>(
        self,
        source: T,
        clock: C,
        secret_key: SecretKey,
    ) -> Result<Ports<T, C, FileMarkStore, FileSignedLog, FileStorage>, MarkError> {
        Ok(Ports {
            source,
            clock,
            signer: Signer::load(secret_key, self.mark)?,
            log: self.signed,
            storage: self.storage,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use blst::min_pk::SecretKey;
    use chain_signer::{HighWaterMark, HighWaterMarkStore, Step};
    use chain_types::{Round, Transaction};

    use super::*;

    struct NoTransactions;

    impl TransactionSource for NoTransactions {
        fn candidates(&mut self, _max: usize) -> Vec<Transaction> {
            Vec::new()
        }
        fn committed(&mut self, _block: &chain_engine_api::Block) {}
    }

    struct Clock0;

    impl Clock for Clock0 {
        fn now_ms(&self) -> u64 {
            0
        }
    }

    #[test]
    fn opening_makes_the_directory_and_the_files_and_a_second_open_finds_them() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("node");
        NodeDisk::open(&nested, DiskConfig::default()).unwrap();
        for file in ["signer.mark", "signed.log", "commits.log", "wal.log"] {
            // The mark file appears with the first mark; the logs at once.
            if file != "signer.mark" {
                assert!(nested.join(file).exists(), "{file}");
            }
        }
        NodeDisk::open(&nested, DiskConfig::default()).unwrap();
    }

    #[test]
    fn a_signer_made_from_the_disk_leaves_its_mark_where_a_restart_finds_it() {
        let dir = tempfile::tempdir().unwrap();
        let secret = SecretKey::key_gen(&[9; 32], &[]).unwrap();
        let mut ports = NodeDisk::open(dir.path(), DiskConfig::default())
            .unwrap()
            .into_ports(NoTransactions, Clock0, secret)
            .unwrap();
        let at = HighWaterMark::new(chain_types::BlockHeight(3), Round(1), Step::Prevote);
        ports
            .signer
            .sign(at, b"a vote", chain_types::bls::DST_VOTE)
            .unwrap();
        drop(ports);

        let restarted = NodeDisk::open(dir.path(), DiskConfig::default()).unwrap();
        assert_eq!(restarted.mark.load().unwrap(), Some(at));
    }

    #[test]
    fn a_damaged_file_stops_the_node_before_it_starts() {
        let dir = tempfile::tempdir().unwrap();
        NodeDisk::open(dir.path(), DiskConfig::default()).unwrap();
        std::fs::write(dir.path().join("wal.log"), b"garbage that is not a log").unwrap();
        // The write-ahead log is only read when a height begins, but the
        // others are read at once.
        std::fs::write(dir.path().join("signed.log"), b"garbage that is not a log").unwrap();
        assert!(NodeDisk::open(dir.path(), DiskConfig::default()).is_err());
    }
}
