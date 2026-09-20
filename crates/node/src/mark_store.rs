//! The signer's high-water mark on disk.
//!
//! `docs/spec.md`, "Keys, signing and slashing safety": the mark is
//! "persisted and fsynced *before* any signature is returned", and it is
//! refused, unconditionally, to move backwards. The file is one fixed-size
//! record, replaced atomically with mode `0600` — so a crash leaves the old
//! mark or the new one, never a mixture — and checked on reading.
//!
//! **A damaged mark file is an error, not "no mark".** Reading it as absent
//! would tell the signer it had never signed, which is the one thing it must
//! never be told.

use std::fs;
use std::path::{Path, PathBuf};

use chain_signer::{HighWaterMark, HighWaterMarkStore, Step};
use chain_types::{BlockHeight, Round};

use crate::atomic::write_atomic;

const MAGIC: &[u8; 8] = b"THRYMARK";
/// magic ‖ height ‖ round ‖ step ‖ check.
const PAYLOAD: usize = 8 + 8 + 8 + 1;
const CHECK: usize = 8;

#[derive(Debug)]
pub enum MarkError {
    Io(std::io::Error),
    /// The file is not a mark this crate wrote.
    Corrupt,
    /// Asked to persist a mark below the one already on disk.
    Regression {
        on_disk: HighWaterMark,
    },
}

impl core::fmt::Display for MarkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "signer mark i/o: {error}"),
            Self::Corrupt => f.write_str("the signer's mark file is damaged"),
            Self::Regression { on_disk } => {
                write!(f, "refusing to move the mark back from {on_disk:?}")
            }
        }
    }
}

impl std::error::Error for MarkError {}

impl From<std::io::Error> for MarkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

fn check(payload: &[u8]) -> [u8; CHECK] {
    let mut out = [0u8; CHECK];
    for (byte, from) in out.iter_mut().zip(blake3::hash(payload).as_bytes()) {
        *byte = *from;
    }
    out
}

fn encode(mark: HighWaterMark) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD.saturating_add(CHECK));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&mark.height.0.to_le_bytes());
    out.extend_from_slice(&mark.round.0.to_le_bytes());
    out.push(mark.step as u8);
    let check = check(&out);
    out.extend_from_slice(&check);
    out
}

fn decode(bytes: &[u8]) -> Result<HighWaterMark, MarkError> {
    if bytes.len() != PAYLOAD.saturating_add(CHECK) {
        return Err(MarkError::Corrupt);
    }
    let (payload, stored) = bytes.split_at(PAYLOAD);
    if check(payload) != stored {
        return Err(MarkError::Corrupt);
    }
    let field = |from: usize| -> Option<u64> {
        let end = from.checked_add(8)?;
        Some(u64::from_le_bytes(payload.get(from..end)?.try_into().ok()?))
    };
    let (Some(magic), Some(height), Some(round), Some(step)) = (
        payload.get(..8),
        field(8),
        field(16),
        payload.get(24).copied(),
    ) else {
        return Err(MarkError::Corrupt);
    };
    if magic != MAGIC {
        return Err(MarkError::Corrupt);
    }
    let step = match step {
        0 => Step::Propose,
        1 => Step::Prevote,
        2 => Step::Precommit,
        _ => return Err(MarkError::Corrupt),
    };
    Ok(HighWaterMark::new(BlockHeight(height), Round(round), step))
}

/// A [`HighWaterMarkStore`] in one file.
#[derive(Debug)]
pub struct FileMarkStore {
    path: PathBuf,
}

impl FileMarkStore {
    /// The store at `path`. Nothing is read or written until it is used.
    pub fn open(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl HighWaterMarkStore for FileMarkStore {
    type Error = MarkError;

    fn load(&self) -> Result<Option<HighWaterMark>, MarkError> {
        match fs::read(&self.path) {
            Ok(bytes) => decode(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn persist(&mut self, mark: HighWaterMark) -> Result<(), MarkError> {
        if let Some(on_disk) = self.load()? {
            if mark < on_disk {
                return Err(MarkError::Regression { on_disk });
            }
        }
        write_atomic(&self.path, &encode(mark))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn mark(height: u64, round: u64, step: Step) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(round), step)
    }

    fn store(dir: &tempfile::TempDir) -> (FileMarkStore, PathBuf) {
        let path = dir.path().join("signer.mark");
        (FileMarkStore::open(&path), path)
    }

    #[test]
    fn a_store_that_has_never_persisted_has_no_mark() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(store(&dir).0.load().unwrap(), None);
    }

    #[test]
    fn a_persisted_mark_is_there_after_a_reopen_whatever_its_step() {
        for step in [Step::Propose, Step::Prevote, Step::Precommit] {
            let dir = tempfile::tempdir().unwrap();
            let (mut s, path) = store(&dir);
            let m = mark(u64::MAX, 7, step);
            s.persist(m).unwrap();
            drop(s);
            assert_eq!(FileMarkStore::open(&path).load().unwrap(), Some(m));
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn the_mark_can_stay_or_advance_but_never_go_back() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = store(&dir);
        s.persist(mark(5, 2, Step::Prevote)).unwrap();
        s.persist(mark(5, 2, Step::Prevote)).unwrap();
        s.persist(mark(5, 2, Step::Precommit)).unwrap();
        s.persist(mark(6, 0, Step::Propose)).unwrap();
        for lower in [mark(5, 9, Step::Precommit), mark(1, 1, Step::Propose)] {
            assert!(matches!(
                s.persist(lower),
                Err(MarkError::Regression { .. })
            ));
        }
        assert_eq!(s.load().unwrap(), Some(mark(6, 0, Step::Propose)));
    }

    #[test]
    fn a_damaged_file_is_an_error_and_never_read_as_no_mark() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        s.persist(mark(9, 1, Step::Prevote)).unwrap();
        let good = fs::read(&path).unwrap();

        // Every flipped bit, every truncation, and an empty and an extended
        // file.
        for at in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[at] ^= 1 << bit;
                fs::write(&path, &bad).unwrap();
                assert!(
                    matches!(s.load(), Err(MarkError::Corrupt)),
                    "byte {at} bit {bit}"
                );
            }
            fs::write(&path, &good[..at]).unwrap();
            assert!(matches!(s.load(), Err(MarkError::Corrupt)), "cut at {at}");
        }
        let mut longer = good;
        longer.push(0);
        fs::write(&path, &longer).unwrap();
        assert!(matches!(s.load(), Err(MarkError::Corrupt)));

        // And a store that cannot read its mark will not overwrite it.
        assert!(s.persist(mark(10, 0, Step::Propose)).is_err());
    }

    #[test]
    fn a_leftover_temporary_from_a_crash_does_not_disturb_the_mark() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        s.persist(mark(3, 0, Step::Propose)).unwrap();
        fs::write(dir.path().join("signer.mark.tmp"), b"half a wri").unwrap();
        assert_eq!(s.load().unwrap(), Some(mark(3, 0, Step::Propose)));
        s.persist(mark(4, 0, Step::Propose)).unwrap();
        assert_eq!(
            FileMarkStore::open(&path).load().unwrap(),
            Some(mark(4, 0, Step::Propose))
        );
    }
}
