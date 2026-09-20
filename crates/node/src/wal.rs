//! The host's write-ahead log, on disk: a `chain-db` `HeightLog`.

use std::path::Path;

use chain_consensus::host::{StorageError, Wal};
use chain_db::HeightLog;
use chain_types::BlockHeight;

use crate::storage;

/// A [`Wal`] in a file.
pub struct FileWal {
    log: HeightLog,
}

impl FileWal {
    /// Opens the log at `path`, creating it if there is none. Nothing is
    /// read until [`Wal::start_height`].
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Ok(Self {
            log: HeightLog::open(path).map_err(storage)?,
        })
    }
}

impl Wal for FileWal {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), StorageError> {
        self.log.append(height.0, entry).map_err(storage)
    }

    fn flush(&mut self) -> Result<(), StorageError> {
        self.log.flush().map_err(storage)
    }

    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, StorageError> {
        self.log.start_height(height.0).map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn entries_come_back_after_a_reopen_and_earlier_heights_are_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        let mut wal = FileWal::open(&path).unwrap();
        wal.append(BlockHeight(7), b"old").unwrap();
        wal.append(BlockHeight(8), b"one").unwrap();
        wal.append(BlockHeight(8), b"two").unwrap();
        wal.flush().unwrap();
        drop(wal);

        let mut wal = FileWal::open(&path).unwrap();
        assert_eq!(
            wal.start_height(BlockHeight(8)).unwrap(),
            vec![b"one".to_vec(), b"two".to_vec()]
        );
        assert!(wal.start_height(BlockHeight(7)).unwrap().is_empty());
    }

    #[test]
    fn a_log_that_is_not_one_fails_when_the_height_begins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        std::fs::write(&path, b"something else entirely").unwrap();
        let mut wal = FileWal::open(&path).unwrap();
        assert!(wal.start_height(BlockHeight(1)).is_err());
    }
}
