//! The host's history of what the chain decided, on disk.
//!
//! Each record is the seed the block led to, then the block with its proof
//! (`chain_consensus::wire`). Every height is retained for the first testnet,
//! so a peer can catch up from genesis without snapshots or warp sync. Only an
//! index is held in memory — where each record is in the file, and the seed it
//! led to — and a record is read back when a peer asks for it. (Holding every
//! record in memory made a node's memory grow with the chain, and a node's
//! start read the whole log twice over: at about half a million blocks four
//! nodes no longer fitted a 1 GB machine.) Pruning belongs with a future
//! snapshot and sync design, not with this log in isolation.

use std::collections::BTreeMap;
use std::path::Path;

use chain_consensus::host::{CommitLog, CommitRecord, StorageError};
use chain_consensus::wire::{decode_commit_record, encode_commit_record};
use chain_db::HeightLog;
use chain_types::{BlockHeight, Hash};

use crate::storage;

/// The seed ‖ the record.
const SEED: usize = 32;

/// How many of the newest records are decoded when the log is opened. The log
/// checks every record's bytes as it is read, so damage anywhere fails the
/// open; decoding is what would catch a record that is whole but is not a
/// commit record, and every record in the file was written by `record` below,
/// so the newest few are enough to say the format is the one this build
/// reads. (Decoding all of them took minutes of processor time at half a
/// million blocks.)
const DECODED_AT_OPEN: usize = 64;

/// Where a record is, and the seed the block led to.
struct Located {
    offset: u64,
    seed: Hash,
}

/// A [`CommitLog`] in a file.
pub struct FileCommitLog {
    log: HeightLog,
    index: BTreeMap<u64, Located>,
}

fn unreadable() -> StorageError {
    StorageError("a commit record cannot be read".into())
}

/// The record in `bytes` (a seed, then the record), which must be filed at
/// `height`.
fn parse(height: u64, bytes: &[u8]) -> Result<(CommitRecord, Hash), StorageError> {
    let (seed, rest) = bytes.split_at_checked(SEED).ok_or_else(unreadable)?;
    let seed: [u8; SEED] = seed.try_into().map_err(|_| unreadable())?;
    let record = decode_commit_record(rest).map_err(|_| unreadable())?;
    if record.block.height.0 != height {
        return Err(unreadable());
    }
    Ok((record, Hash::from_bytes(seed)))
}

impl FileCommitLog {
    /// Opens the log at `path`, creating it if there is none. A damaged log
    /// fails here, not later.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut log = HeightLog::open(path).map_err(storage)?;
        let mut index = BTreeMap::new();
        log.scan(|height, offset, bytes| {
            let (seed, _) =
                bytes
                    .split_at_checked(SEED)
                    .ok_or_else(|| chain_db::LogError::Corrupt {
                        offset: usize::try_from(offset).unwrap_or(usize::MAX),
                    })?;
            let seed: [u8; SEED] = seed.try_into().map_err(|_| chain_db::LogError::Corrupt {
                offset: usize::try_from(offset).unwrap_or(usize::MAX),
            })?;
            index.insert(
                height,
                Located {
                    offset,
                    seed: Hash::from_bytes(seed),
                },
            );
            Ok(())
        })
        .map_err(storage)?;
        let this = Self { log, index };
        for (height, located) in this.index.iter().rev().take(DECODED_AT_OPEN) {
            let (filed, bytes) = this.log.read_at(located.offset).map_err(storage)?;
            if filed != *height {
                return Err(unreadable());
            }
            parse(*height, &bytes)?;
        }
        Ok(this)
    }

    fn read(&self, height: u64) -> Option<CommitRecord> {
        let located = self.index.get(&height)?;
        let (filed, bytes) = self.log.read_at(located.offset).ok()?;
        if filed != height {
            return None;
        }
        parse(height, &bytes).ok().map(|(record, _)| record)
    }
}

impl CommitLog for FileCommitLog {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) -> Result<(), StorageError> {
        let mut bytes = seed_after.as_bytes().to_vec();
        bytes.extend_from_slice(&encode_commit_record(record));
        let offset = self
            .log
            .append(record.block.height.0, &bytes)
            .map_err(storage)?;
        self.log.flush().map_err(storage)?;
        self.index.insert(
            record.block.height.0,
            Located {
                offset,
                seed: seed_after,
            },
        );
        Ok(())
    }

    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        let mut out = Vec::new();
        let mut next = from.0;
        while out.len() < max {
            let Some(record) = self.read(next) else {
                break;
            };
            out.push(record);
            let Some(after) = next.checked_add(1) else {
                break;
            };
            next = after;
        }
        out
    }

    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.index.get(&height.0).map(|located| located.seed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use blst::min_pk::SecretKey;
    use chain_consensus::types::{ConsensusAddress, ConsensusHeight};
    use chain_engine_api::Block;
    use chain_types::bls::{BlsSignature, DST_VOTE};
    use chain_types::Address;
    use malachite_core_types::{CommitCertificate, CommitSignature, Round};

    use super::*;

    fn signature(n: u8) -> BlsSignature {
        let secret = SecretKey::key_gen(&[n; 32], &[]).unwrap();
        BlsSignature::from_bytes(secret.sign(&[n], DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn record(height: u64) -> CommitRecord {
        let block = Block {
            parent_block_hash: Hash::from_bytes([1; 32]),
            height: BlockHeight(height),
            timestamp_millis: 1_700_000_000_000u64.saturating_add(height),
            transactions: Vec::new(),
        };
        CommitRecord {
            certificate: CommitCertificate {
                height: ConsensusHeight(BlockHeight(height)),
                round: Round::new(0),
                value_id: block.hash(),
                commit_signatures: vec![CommitSignature {
                    address: ConsensusAddress(Address::from_bytes([2; 32])),
                    signature: signature(3),
                }],
            },
            block,
            reveal: signature(4),
        }
    }

    fn seed(height: u64) -> Hash {
        Hash::from_bytes([u8::try_from(height % 251).unwrap(); 32])
    }

    fn heights(log: &FileCommitLog) -> Vec<u64> {
        log.index.keys().copied().collect()
    }

    #[test]
    fn what_was_recorded_is_served_and_its_seed_found_after_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commits.log");
        let mut log = FileCommitLog::open(&path).unwrap();
        for height in 1..=5 {
            log.record(&record(height), seed(height)).unwrap();
        }
        drop(log);

        let log = FileCommitLog::open(&path).unwrap();
        let served = log.range(BlockHeight(2), 10);
        assert_eq!(
            served.iter().map(|r| r.block.height.0).collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        assert_eq!(
            format!("{:?}", served[0]),
            format!("{:?}", record(2)),
            "the block, its proof and its reveal come back whole"
        );
        for height in 1..=5 {
            assert_eq!(log.seed_after(BlockHeight(height)), Some(seed(height)));
        }
        assert_eq!(log.seed_after(BlockHeight(6)), None);
        assert!(log.range(BlockHeight(6), 10).is_empty());
        assert_eq!(log.range(BlockHeight(1), 2).len(), 2, "capped");
    }

    #[test]
    fn every_height_is_retained_on_disk_and_served_after_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commits.log");
        let mut log = FileCommitLog::open(&path).unwrap();
        for height in 1..=300 {
            log.record(&record(height), seed(height)).unwrap();
            assert_eq!(
                log.seed_after(BlockHeight(height)),
                Some(seed(height)),
                "every recorded seed remains available"
            );
        }
        assert_eq!(heights(&log), (1..=300).collect::<Vec<_>>());
        drop(log);

        let log = FileCommitLog::open(&path).unwrap();
        assert_eq!(heights(&log), (1..=300).collect::<Vec<_>>());
        assert_eq!(
            log.range(BlockHeight(1), 300)
                .iter()
                .map(|record| record.block.height.0)
                .collect::<Vec<_>>(),
            (1..=300).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_log_with_a_record_it_cannot_read_will_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commits.log");
        for bad in [
            vec![0u8; 5],
            vec![7u8; 100],
            // A seed and then a record filed under another height.
            {
                let mut bytes = vec![0u8; SEED];
                bytes.extend_from_slice(&encode_commit_record(&record(9)));
                bytes
            },
        ] {
            let mut raw = HeightLog::open(&path).unwrap();
            raw.append(4, &bad).unwrap();
            raw.flush().unwrap();
            drop(raw);
            assert!(FileCommitLog::open(&path).is_err());
            std::fs::remove_file(&path).unwrap();
        }
    }
}
