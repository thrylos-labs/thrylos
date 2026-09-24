//! The signer's high-water mark on disk.
//!
//! `docs/spec.md`, "Keys, signing and slashing safety": the mark is
//! "persisted and fsynced *before* any signature is returned", and it is
//! refused, unconditionally, to move backwards. The file is one fixed-size
//! record, replaced atomically with mode `0600` — so a crash leaves the old
//! mark or the new one, never a mixture — and checked on reading.
//!
//! The record also holds a digest of the message signed at the mark, written in
//! the same replacement, so the signer can recognise that message if it is
//! asked for it again (see `Signer::sign`). Two formats exist: `THRYMRK2`,
//! which every write produces, and the earlier `THRYMARK`, which has no digest.
//! An earlier file is read as a mark with no digest, which makes the signer
//! refuse everything at that position, exactly as before; it is never read as
//! damaged nor as absent, and the first signature after it writes the new form.
//!
//! **One signer per mark.** Opening the store takes an exclusive advisory lock
//! (`flock`) on a sibling `.lock` file and keeps it until the store is
//! dropped, so a second signer pointed at the same mark — a mistaken restart
//! script, a stray old process — is refused at startup instead of racing the
//! first: each would read the mark, find room, sign, and write, and two
//! different messages could be signed at one position, which is the slashable
//! act this file exists to prevent. The kernel drops the lock when the holder
//! exits, however it exits, so a crash never leaves a stale one behind. (The
//! lock is on its own file because the mark file itself is replaced by
//! rename on every write.)
//!
//! **A damaged mark file is an error, not "no mark".** Reading it as absent
//! would tell the signer it had never signed, which is the one thing it must
//! never be told.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chain_signer::{HighWaterMark, HighWaterMarkStore, MessageDigest, Step};
use chain_types::{BlockHeight, Round};

use crate::atomic::write_atomic;

/// The first format: no digest.
const MAGIC_V1: &[u8; 8] = b"THRYMARK";
/// The current format: a digest of what was signed at the mark.
const MAGIC: &[u8; 8] = b"THRYMRK2";
/// V1: magic ‖ height ‖ round ‖ step, then the check.
const PAYLOAD_V1: usize = 8 + 8 + 8 + 1;
/// Current: magic ‖ height ‖ round ‖ step ‖ has-digest ‖ digest, then the check.
const PAYLOAD: usize = PAYLOAD_V1 + 1 + 32;
const CHECK: usize = 8;

#[derive(Debug)]
pub enum MarkError {
    Io(std::io::Error),
    /// The file is not a mark this crate wrote.
    Corrupt,
    /// Another process holds this mark's lock: another signer is running
    /// against the same mark file.
    Locked,
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
            Self::Locked => f.write_str(
                "another signer is already running against this mark file; refusing to start a second",
            ),
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

fn encode(mark: HighWaterMark, digest: Option<MessageDigest>) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD.saturating_add(CHECK));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&mark.height.0.to_le_bytes());
    out.extend_from_slice(&mark.round.0.to_le_bytes());
    out.push(mark.step as u8);
    out.push(u8::from(digest.is_some()));
    // Zeros when there is none, so the record is one size either way.
    out.extend_from_slice(&digest.unwrap_or([0; 32]));
    let check = check(&out);
    out.extend_from_slice(&check);
    out
}

/// A mark and the digest of what was signed at it, if the file holds one.
type Recorded = (HighWaterMark, Option<MessageDigest>);

fn decode(bytes: &[u8]) -> Result<Recorded, MarkError> {
    // Which format it is decides how long it must be, and so where the check is.
    let payload_len = match bytes.get(..8) {
        Some(magic) if magic == MAGIC => PAYLOAD,
        Some(magic) if magic == MAGIC_V1 => PAYLOAD_V1,
        _ => return Err(MarkError::Corrupt),
    };
    if bytes.len() != payload_len.saturating_add(CHECK) {
        return Err(MarkError::Corrupt);
    }
    let (payload, stored) = bytes.split_at(payload_len);
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
    if magic != MAGIC && magic != MAGIC_V1 {
        return Err(MarkError::Corrupt);
    }
    let step = match step {
        0 => Step::Propose,
        1 => Step::Prevote,
        2 => Step::Precommit,
        _ => return Err(MarkError::Corrupt),
    };
    let digest = if payload_len == PAYLOAD {
        let stored: Option<MessageDigest> = payload
            .get(PAYLOAD_V1.saturating_add(1)..)
            .and_then(|digest| digest.try_into().ok());
        match (payload.get(PAYLOAD_V1).copied(), stored) {
            (Some(1), Some(digest)) => Some(digest),
            // No digest: and then the space for one holds nothing.
            (Some(0), Some(zeros)) if zeros == [0; 32] => None,
            _ => return Err(MarkError::Corrupt),
        }
    } else {
        None
    };
    Ok((
        HighWaterMark::new(BlockHeight(height), Round(round), step),
        digest,
    ))
}

/// A [`HighWaterMarkStore`] in one file.
#[derive(Debug)]
pub struct FileMarkStore {
    path: PathBuf,
    /// Held for as long as the store lives; dropping it releases the lock.
    _lock: File,
}

impl FileMarkStore {
    /// The store at `path`, holding its exclusive lock. Nothing else is read
    /// or written until it is used. [`MarkError::Locked`] if another store
    /// on the same path is open, in this process or any other.
    pub fn open(path: &Path) -> Result<Self, MarkError> {
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(PathBuf::from(lock_path))?;
        match lock.try_lock() {
            Ok(()) => Ok(Self {
                path: path.to_path_buf(),
                _lock: lock,
            }),
            Err(TryLockError::WouldBlock) => Err(MarkError::Locked),
            Err(TryLockError::Error(error)) => Err(error.into()),
        }
    }
}

impl FileMarkStore {
    fn read(&self) -> Result<Option<Recorded>, MarkError> {
        match fs::read(&self.path) {
            Ok(bytes) => decode(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Replaces the record, unless that would move the mark back or attach a
    /// different message to a position that already has one.
    fn write(
        &mut self,
        mark: HighWaterMark,
        digest: Option<MessageDigest>,
    ) -> Result<(), MarkError> {
        if let Some((on_disk, on_disk_digest)) = self.read()? {
            let rebinds =
                mark == on_disk && on_disk_digest.is_some_and(|held| digest != Some(held));
            if mark < on_disk || rebinds {
                return Err(MarkError::Regression { on_disk });
            }
        }
        write_atomic(&self.path, &encode(mark, digest))?;
        Ok(())
    }
}

impl HighWaterMarkStore for FileMarkStore {
    type Error = MarkError;

    fn load(&self) -> Result<Option<HighWaterMark>, MarkError> {
        Ok(self.read()?.map(|(mark, _)| mark))
    }

    fn persist(&mut self, mark: HighWaterMark) -> Result<(), MarkError> {
        self.write(mark, None)
    }

    fn load_digest(&self) -> Result<Option<MessageDigest>, MarkError> {
        Ok(self.read()?.and_then(|(_, digest)| digest))
    }

    fn persist_signed(
        &mut self,
        mark: HighWaterMark,
        digest: MessageDigest,
    ) -> Result<(), MarkError> {
        self.write(mark, Some(digest))
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
        (FileMarkStore::open(&path).unwrap(), path)
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
            assert_eq!(FileMarkStore::open(&path).unwrap().load().unwrap(), Some(m));
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

    /// A file in the earlier format, which had no digest.
    fn write_v1(path: &Path, mark: HighWaterMark) {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC_V1);
        out.extend_from_slice(&mark.height.0.to_le_bytes());
        out.extend_from_slice(&mark.round.0.to_le_bytes());
        out.push(mark.step as u8);
        let check = check(&out);
        out.extend_from_slice(&check);
        fs::write(path, out).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn the_digest_is_there_after_a_reopen_with_the_mark_it_belongs_to() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        assert_eq!(s.load_digest().unwrap(), None);
        s.persist_signed(mark(4, 0, Step::Prevote), [0xab; 32])
            .unwrap();
        drop(s);
        let reopened = FileMarkStore::open(&path).unwrap();
        assert_eq!(reopened.load().unwrap(), Some(mark(4, 0, Step::Prevote)));
        assert_eq!(reopened.load_digest().unwrap(), Some([0xab; 32]));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // A mark that is later persisted alone brings no digest with it.
        drop(reopened);
        let mut s = FileMarkStore::open(&path).unwrap();
        s.persist(mark(5, 0, Step::Propose)).unwrap();
        assert_eq!(s.load_digest().unwrap(), None);
    }

    #[test]
    fn a_second_signer_on_the_same_mark_is_refused_until_the_first_lets_go() {
        let dir = tempfile::tempdir().unwrap();
        let (first, path) = store(&dir);
        assert!(matches!(FileMarkStore::open(&path), Err(MarkError::Locked)));
        drop(first);
        assert!(
            FileMarkStore::open(&path).is_ok(),
            "released with the store"
        );
    }

    #[test]
    fn a_file_in_the_earlier_format_is_a_mark_with_no_digest_and_is_replaced_in_the_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        write_v1(&path, mark(12, 3, Step::Precommit));
        assert_eq!(s.load().unwrap(), Some(mark(12, 3, Step::Precommit)));
        assert_eq!(s.load_digest().unwrap(), None);
        // It still holds the line: nothing below it may be persisted.
        assert!(matches!(
            s.persist(mark(12, 3, Step::Prevote)),
            Err(MarkError::Regression { .. })
        ));

        s.persist_signed(mark(13, 0, Step::Propose), [1; 32])
            .unwrap();
        assert_eq!(&fs::read(&path).unwrap()[..8], MAGIC);
        assert_eq!(s.load_digest().unwrap(), Some([1; 32]));
    }

    #[test]
    fn a_position_that_has_a_message_cannot_be_given_another_but_can_be_moved_past() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, _) = store(&dir);
        let at = mark(6, 0, Step::Prevote);
        s.persist_signed(at, [1; 32]).unwrap();
        s.persist_signed(at, [1; 32]).unwrap();
        for other in [Some([2; 32]), None] {
            let result = match other {
                Some(digest) => s.persist_signed(at, digest),
                None => s.persist(at),
            };
            assert!(
                matches!(result, Err(MarkError::Regression { .. })),
                "{other:?}"
            );
        }
        assert_eq!(s.load_digest().unwrap(), Some([1; 32]), "it was left alone");
        s.persist_signed(mark(6, 0, Step::Precommit), [2; 32])
            .unwrap();
        assert_eq!(s.load_digest().unwrap(), Some([2; 32]));
    }

    #[test]
    fn a_damaged_file_is_an_error_and_never_read_as_no_mark() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        s.persist(mark(9, 1, Step::Prevote)).unwrap();
        every_damage_is_corrupt(&mut s, &path);

        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        s.persist_signed(mark(9, 1, Step::Prevote), [0x5a; 32])
            .unwrap();
        every_damage_is_corrupt(&mut s, &path);

        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        write_v1(&path, mark(9, 1, Step::Prevote));
        every_damage_is_corrupt(&mut s, &path);
    }

    /// A digest flag that says there is none, over space that holds one, is not
    /// a record this store wrote, though its check is right.
    #[test]
    fn a_record_that_contradicts_itself_is_damaged() {
        let dir = tempfile::tempdir().unwrap();
        let (s, path) = store(&dir);
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.push(Step::Propose as u8);
        out.push(0); // no digest ...
        out.extend_from_slice(&[9; 32]); // ... but there is one
        let sum = check(&out);
        out.extend_from_slice(&sum);
        fs::write(&path, &out).unwrap();
        assert!(matches!(s.load(), Err(MarkError::Corrupt)));

        // A flag that is neither 0 nor 1 is damage too.
        out[PAYLOAD_V1] = 2;
        let payload = out[..PAYLOAD].to_vec();
        out.truncate(PAYLOAD);
        out.extend_from_slice(&check(&payload));
        fs::write(&path, &out).unwrap();
        assert!(matches!(s.load(), Err(MarkError::Corrupt)));
    }

    fn every_damage_is_corrupt(s: &mut FileMarkStore, path: &Path) {
        let good = fs::read(path).unwrap();
        assert!(s.load().is_ok());

        // Every flipped bit, every truncation, and an empty and an extended
        // file.
        for at in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[at] ^= 1 << bit;
                fs::write(path, &bad).unwrap();
                assert!(
                    matches!(s.load(), Err(MarkError::Corrupt)),
                    "byte {at} bit {bit}"
                );
            }
            fs::write(path, &good[..at]).unwrap();
            assert!(matches!(s.load(), Err(MarkError::Corrupt)), "cut at {at}");
        }
        let mut longer = good.clone();
        longer.push(0);
        fs::write(path, &longer).unwrap();
        assert!(matches!(s.load(), Err(MarkError::Corrupt)));

        // And a store that cannot read its mark will not overwrite it.
        assert!(s.persist(mark(10, 0, Step::Propose)).is_err());
        fs::write(path, &good).unwrap();
    }

    #[test]
    fn a_leftover_temporary_from_a_crash_does_not_disturb_the_mark() {
        let dir = tempfile::tempdir().unwrap();
        let (mut s, path) = store(&dir);
        s.persist(mark(3, 0, Step::Propose)).unwrap();
        fs::write(dir.path().join("signer.mark.tmp"), b"half a wri").unwrap();
        assert_eq!(s.load().unwrap(), Some(mark(3, 0, Step::Propose)));
        s.persist(mark(4, 0, Step::Propose)).unwrap();
        drop(s);
        assert_eq!(
            FileMarkStore::open(&path).unwrap().load().unwrap(),
            Some(mark(4, 0, Step::Propose))
        );
    }
}
