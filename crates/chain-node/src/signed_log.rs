//! The record of what the host has signed, on disk.
//!
//! Only the current height's signatures are kept: a restart replays the
//! height it crashed in, and no earlier position is ever asked for again
//! (the signer's mark would refuse it). Recording a signature at a later
//! height forgets the earlier ones.

use std::collections::BTreeMap;
use std::path::Path;

use chain_consensus::host::{SignedEntry, SignedLog, StorageError};
use chain_db::HeightLog;
use chain_signer::{HighWaterMark, Step};
use chain_types::bls::{BlsSignature, BLS_SIGNATURE_LEN};
use chain_types::{BlockHeight, Round};

use crate::storage;

/// round ‖ step ‖ signature, then the signed bytes.
const HEAD: usize = 8 + 1 + BLS_SIGNATURE_LEN;

fn encode(position: HighWaterMark, entry: &SignedEntry) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEAD.saturating_add(entry.bytes.len()));
    out.extend_from_slice(&position.round.0.to_le_bytes());
    out.push(position.step as u8);
    out.extend_from_slice(&entry.signature.to_bytes());
    out.extend_from_slice(&entry.bytes);
    out
}

fn decode(height: u64, bytes: &[u8]) -> Option<(HighWaterMark, SignedEntry)> {
    let round = u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?);
    let step = match bytes.get(8)? {
        0 => Step::Propose,
        1 => Step::Prevote,
        2 => Step::Precommit,
        _ => return None,
    };
    let signature: [u8; BLS_SIGNATURE_LEN] = bytes.get(9..HEAD)?.try_into().ok()?;
    Some((
        HighWaterMark::new(BlockHeight(height), Round(round), step),
        SignedEntry {
            bytes: bytes.get(HEAD..)?.to_vec(),
            signature: BlsSignature::from_bytes(signature).ok()?,
        },
    ))
}

/// A [`SignedLog`] in a file.
pub struct FileSignedLog {
    log: HeightLog,
    entries: BTreeMap<HighWaterMark, SignedEntry>,
    newest: u64,
}

impl FileSignedLog {
    /// Opens the log at `path`, creating it if there is none, and reads what
    /// it holds. A damaged log fails here, not later.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let mut log = HeightLog::open(path).map_err(storage)?;
        let mut entries = BTreeMap::new();
        let mut newest = 0;
        for (height, bytes) in log.retain_from(0).map_err(storage)? {
            let (position, entry) = decode(height, &bytes)
                .ok_or_else(|| StorageError("a signed-message record cannot be read".into()))?;
            newest = newest.max(height);
            entries.insert(position, entry);
        }
        Ok(Self {
            log,
            entries,
            newest,
        })
    }
}

impl SignedLog for FileSignedLog {
    fn get(&self, position: HighWaterMark) -> Option<SignedEntry> {
        self.entries.get(&position).cloned()
    }

    fn record(&mut self, position: HighWaterMark, entry: SignedEntry) -> Result<(), StorageError> {
        let height = position.height.0;
        if height > self.newest {
            self.log.retain_from(height).map_err(storage)?;
            self.entries.retain(|at, _| at.height.0 >= height);
            self.newest = height;
        }
        self.log
            .append(height, &encode(position, &entry))
            .map_err(storage)?;
        self.log.flush().map_err(storage)?;
        self.entries.insert(position, entry);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use blst::min_pk::SecretKey;
    use chain_types::bls::DST_VOTE;

    use super::*;

    fn signature(n: u8) -> BlsSignature {
        let secret = SecretKey::key_gen(&[n; 32], &[]).unwrap();
        BlsSignature::from_bytes(secret.sign(&[n], DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn position(height: u64, round: u64, step: Step) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(round), step)
    }

    fn entry(n: u8) -> SignedEntry {
        SignedEntry {
            bytes: vec![n; usize::from(n)],
            signature: signature(n),
        }
    }

    #[test]
    fn what_was_recorded_is_answered_after_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.log");
        let mut log = FileSignedLog::open(&path).unwrap();
        let cases = [
            (position(4, 0, Step::Propose), entry(1)),
            (position(4, 0, Step::Prevote), entry(2)),
            (position(4, 3, Step::Precommit), entry(0)),
        ];
        for (at, e) in &cases {
            assert_eq!(log.get(*at), None);
            log.record(*at, e.clone()).unwrap();
            assert_eq!(log.get(*at), Some(e.clone()));
        }
        drop(log);

        let log = FileSignedLog::open(&path).unwrap();
        for (at, e) in &cases {
            assert_eq!(log.get(*at), Some(e.clone()));
        }
        assert_eq!(log.get(position(4, 1, Step::Prevote)), None);
        assert_eq!(log.get(position(5, 0, Step::Propose)), None);
    }

    #[test]
    fn a_later_height_forgets_the_earlier_one_on_disk_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.log");
        let mut log = FileSignedLog::open(&path).unwrap();
        log.record(position(4, 0, Step::Prevote), entry(1)).unwrap();
        log.record(position(5, 0, Step::Prevote), entry(2)).unwrap();
        assert_eq!(log.get(position(4, 0, Step::Prevote)), None);
        drop(log);

        let log = FileSignedLog::open(&path).unwrap();
        assert_eq!(log.get(position(4, 0, Step::Prevote)), None);
        assert_eq!(log.get(position(5, 0, Step::Prevote)), Some(entry(2)));
    }

    #[test]
    fn a_log_with_a_record_it_cannot_read_will_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.log");
        let mut raw = HeightLog::open(&path).unwrap();
        raw.append(4, b"not a signed-message record").unwrap();
        raw.flush().unwrap();
        drop(raw);
        assert!(FileSignedLog::open(&path).is_err());
    }
}
