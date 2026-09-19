//! The host's history of what the chain decided, on disk.
//!
//! Each record is the seed the block led to, then the block with its proof
//! (`chain_consensus::wire`). A window of recent heights is kept — enough to
//! answer a peer that has fallen a little behind, and to give a restarted
//! host the seed for the height after its head, which is the newest record.
//! A peer further behind than the window needs blocks from somewhere else:
//! this log does not serve full history, and `chain-db` does not keep the
//! proofs.
//!
//! The window is held in memory. It is pruned in one rewrite when it reaches
//! twice its size, so the cost of forgetting is amortised over as many
//! commits as the window holds.

use std::collections::BTreeMap;
use std::path::Path;

use chain_consensus::host::{CommitLog, CommitRecord, StorageError};
use chain_consensus::wire::{decode_commit_record, encode_commit_record};
use chain_db::HeightLog;
use chain_types::{BlockHeight, Hash};

use crate::storage;

/// The seed ‖ the record.
const SEED: usize = 32;

/// A [`CommitLog`] in a file.
pub struct FileCommitLog {
    log: HeightLog,
    records: BTreeMap<u64, (CommitRecord, Hash)>,
    retain: usize,
}

impl FileCommitLog {
    /// Opens the log at `path`, creating it if there is none, keeping the
    /// most recent `retain` heights (at least one). A damaged log fails
    /// here, not later.
    pub fn open(path: &Path, retain: usize) -> Result<Self, StorageError> {
        let mut log = HeightLog::open(path).map_err(storage)?;
        let mut records = BTreeMap::new();
        for (height, bytes) in log.retain_from(0).map_err(storage)? {
            let unreadable = || StorageError("a commit record cannot be read".into());
            let (seed, rest) = bytes.split_at_checked(SEED).ok_or_else(unreadable)?;
            let seed: [u8; SEED] = seed.try_into().map_err(|_| unreadable())?;
            let record = decode_commit_record(rest).map_err(|_| unreadable())?;
            if record.block.height.0 != height {
                return Err(unreadable());
            }
            records.insert(height, (record, Hash::from_bytes(seed)));
        }
        Ok(Self {
            log,
            records,
            retain: retain.max(1),
        })
    }

    /// Forgets all but the newest `retain` heights, on disk and in memory.
    fn prune(&mut self) -> Result<(), StorageError> {
        if self.records.len() < self.retain.saturating_mul(2) {
            return Ok(());
        }
        let excess = self.records.len().saturating_sub(self.retain);
        let Some(first_kept) = self.records.keys().nth(excess).copied() else {
            return Ok(());
        };
        self.log.retain_from(first_kept).map_err(storage)?;
        self.records.retain(|height, _| *height >= first_kept);
        Ok(())
    }
}

impl CommitLog for FileCommitLog {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) -> Result<(), StorageError> {
        let mut bytes = seed_after.as_bytes().to_vec();
        bytes.extend_from_slice(&encode_commit_record(record));
        self.log
            .append(record.block.height.0, &bytes)
            .map_err(storage)?;
        self.log.flush().map_err(storage)?;
        self.records
            .insert(record.block.height.0, (record.clone(), seed_after));
        self.prune()
    }

    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        let mut out = Vec::new();
        let mut next = from.0;
        while out.len() < max {
            let Some((record, _)) = self.records.get(&next) else {
                break;
            };
            out.push(record.clone());
            let Some(after) = next.checked_add(1) else {
                break;
            };
            next = after;
        }
        out
    }

    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.records.get(&height.0).map(|(_, seed)| *seed)
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
        log.records.keys().copied().collect()
    }

    #[test]
    fn what_was_recorded_is_served_and_its_seed_found_after_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commits.log");
        let mut log = FileCommitLog::open(&path, 100).unwrap();
        for height in 1..=5 {
            log.record(&record(height), seed(height)).unwrap();
        }
        drop(log);

        let log = FileCommitLog::open(&path, 100).unwrap();
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
    fn a_window_of_recent_heights_is_kept_and_the_newest_never_forgotten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commits.log");
        let mut log = FileCommitLog::open(&path, 3).unwrap();
        for height in 1..=40 {
            log.record(&record(height), seed(height)).unwrap();
            assert!(log.records.len() < 6, "pruned at twice the window");
            assert_eq!(
                log.seed_after(BlockHeight(height)),
                Some(seed(height)),
                "the newest seed is always there"
            );
        }
        let kept = heights(&log);
        assert!(kept.len() >= 3, "{kept:?}");
        assert_eq!(kept.last(), Some(&40));
        drop(log);

        // What was forgotten is gone from the disk too.
        let log = FileCommitLog::open(&path, 3).unwrap();
        assert_eq!(heights(&log), kept);
        assert!(log.range(BlockHeight(1), 10).is_empty());
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
            assert!(FileCommitLog::open(&path, 10).is_err());
            std::fs::remove_file(&path).unwrap();
        }
    }
}
