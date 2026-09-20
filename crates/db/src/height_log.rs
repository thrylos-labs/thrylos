//! A crash-safe append-only log of entries grouped by height, for the small
//! logs that a database transaction does not suit — the consensus host's
//! write-ahead log above all.
//!
//! [`HeightLog::append`] adds an entry, [`HeightLog::flush`] makes everything
//! appended so far survive a crash (`fdatasync`), and
//! [`HeightLog::start_height`] is what a restart calls: it reads the file
//! back, forgets every height before the one begun, and returns what is there
//! for it. Those three are the shape of the host's `Wal` trait; the two are
//! kept apart so that this crate does not depend on consensus.
//!
//! # The file
//!
//! A header, then records, each `length (u32) ‖ height (u64) ‖ head check
//! (4 bytes) ‖ entry check (8 bytes) ‖ entry`, the checks being the first
//! bytes of BLAKE3 over the length and height, and over all three. A crash
//! can leave the *last* record cut short, or extended with contents that
//! never reached the disk; the file then ends inside the record, or the
//! record's entry fails its check and is the last thing in the file, or what
//! is left is nothing but zeros. Each is dropped as if the append had never
//! been made, which is what it was: nothing was released to the outside
//! world before its flush. Anything else that does not check out — a head
//! whose check fails, so that its length cannot be believed, or an entry
//! that fails its check with more file after it — is damage, and reading
//! fails: what follows a hole cannot be trusted to mean what it did, and
//! taking a bad length for a torn tail would silently discard the rest.
//!
//! Forgetting earlier heights, and dropping a torn record, rewrite the file
//! (to a temporary, synced, renamed over, the directory synced), so at every
//! moment the file on disk is a complete log.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const HEADER: &[u8] = b"THRYLOS-HEIGHT-LOG-1\n";
const CHECK_LEN: usize = 8;
const HEAD_CHECK_LEN: usize = 4;
const ENTRY_CHECK_AT: usize = 4 + 8 + HEAD_CHECK_LEN;
/// `length ‖ height ‖ head check ‖ entry check`.
const RECORD_HEAD: usize = 4 + 8 + HEAD_CHECK_LEN + CHECK_LEN;

/// The largest entry [`HeightLog::append`] accepts: far above any block the
/// chain's gas limit allows.
pub const MAX_ENTRY: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum LogError {
    Io(std::io::Error),
    /// Not a log this crate wrote.
    BadHeader,
    /// A record before the end of the file failed its check, or claimed a
    /// length no entry can have.
    Corrupt {
        offset: usize,
    },
    /// An entry larger than [`MAX_ENTRY`].
    TooLarge,
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "log i/o: {error}"),
            Self::BadHeader => f.write_str("not a height log"),
            Self::Corrupt { offset } => write!(f, "log damaged at byte {offset}"),
            Self::TooLarge => f.write_str("entry too large"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<std::io::Error> for LogError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct HeightLog {
    path: PathBuf,
    file: File,
}

struct Record {
    height: u64,
    entry: Vec<u8>,
}

fn head_check(length: [u8; 4], height: [u8; 8]) -> [u8; HEAD_CHECK_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&length);
    hasher.update(&height);
    let mut out = [0u8; HEAD_CHECK_LEN];
    for (byte, from) in out.iter_mut().zip(hasher.finalize().as_bytes()) {
        *byte = *from;
    }
    out
}

fn entry_check(length: [u8; 4], height: [u8; 8], entry: &[u8]) -> [u8; CHECK_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&length);
    hasher.update(&height);
    hasher.update(entry);
    let mut out = [0u8; CHECK_LEN];
    for (byte, from) in out.iter_mut().zip(hasher.finalize().as_bytes()) {
        *byte = *from;
    }
    out
}

fn encode(height: u64, entry: &[u8]) -> Result<Vec<u8>, LogError> {
    let length = u32::try_from(entry.len()).map_err(|_| LogError::TooLarge)?;
    if entry.len() > MAX_ENTRY {
        return Err(LogError::TooLarge);
    }
    let length = length.to_le_bytes();
    let height = height.to_le_bytes();
    let mut out = Vec::with_capacity(RECORD_HEAD.saturating_add(entry.len()));
    out.extend_from_slice(&length);
    out.extend_from_slice(&height);
    out.extend_from_slice(&head_check(length, height));
    out.extend_from_slice(&entry_check(length, height, entry));
    out.extend_from_slice(entry);
    Ok(out)
}

/// The records in `bytes` and how many leading bytes of it are whole: less
/// than all of them if the last record was torn.
fn parse(bytes: &[u8]) -> Result<(Vec<Record>, usize), LogError> {
    if bytes.get(..HEADER.len()) != Some(HEADER) {
        return Err(LogError::BadHeader);
    }
    let mut records = Vec::new();
    let mut at = HEADER.len();
    loop {
        let rest = bytes.get(at..).unwrap_or_default();
        if rest.is_empty() {
            return Ok((records, at));
        }
        let (Some(length), Some(height), Some(head), Some(stored)) = (
            rest.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok()),
            rest.get(4..12).and_then(|b| <[u8; 8]>::try_from(b).ok()),
            rest.get(12..ENTRY_CHECK_AT),
            rest.get(ENTRY_CHECK_AT..RECORD_HEAD),
        ) else {
            // The file ends inside a record's head: torn.
            return Ok((records, at));
        };
        if head_check(length, height) != head {
            // The length cannot be believed, so a record cannot be told to be
            // torn: unless nothing but zeros is left, which is what a file
            // extended and never written looks like.
            if rest.iter().all(|byte| *byte == 0) {
                return Ok((records, at));
            }
            return Err(LogError::Corrupt { offset: at });
        }
        let size = usize::try_from(u32::from_le_bytes(length)).unwrap_or(usize::MAX);
        if size > MAX_ENTRY {
            return Err(LogError::Corrupt { offset: at });
        }
        let end = RECORD_HEAD
            .checked_add(size)
            .and_then(|n| at.checked_add(n));
        let Some(end) = end.filter(|end| *end <= bytes.len()) else {
            // The file ends inside the entry: torn.
            return Ok((records, at));
        };
        let Some(entry) = bytes.get(at.saturating_add(RECORD_HEAD)..end) else {
            return Ok((records, at));
        };
        if entry_check(length, height, entry) != stored {
            if end == bytes.len() {
                // The last record, whose contents never reached the disk.
                return Ok((records, at));
            }
            return Err(LogError::Corrupt { offset: at });
        }
        records.push(Record {
            height: u64::from_le_bytes(height),
            entry: entry.to_vec(),
        });
        at = end;
    }
}

fn sync_directory(path: &Path) -> Result<(), LogError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    File::open(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    })?
    .sync_all()?;
    Ok(())
}

impl HeightLog {
    /// Opens the log at `path`, creating it if there is none. Nothing is
    /// read: that is [`Self::start_height`]'s job.
    pub fn open(path: &Path) -> Result<Self, LogError> {
        let existed = path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(path)?;
        if !existed || file.metadata()?.len() == 0 {
            file.write_all(HEADER)?;
            file.sync_all()?;
            sync_directory(path)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Adds an entry for `height`. It survives a crash only after
    /// [`Self::flush`].
    pub fn append(&mut self, height: u64, entry: &[u8]) -> Result<(), LogError> {
        let record = encode(height, entry)?;
        // One write, so a crash tears at most this record.
        self.file.write_all(&record)?;
        Ok(())
    }

    /// Makes everything appended so far survive a crash.
    pub fn flush(&mut self) -> Result<(), LogError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Begins `height`: forgets every earlier height and returns the entries
    /// this log holds for `height`, oldest first. A torn final record is
    /// dropped; damage anywhere else is an error.
    pub fn start_height(&mut self, height: u64) -> Result<Vec<Vec<u8>>, LogError> {
        Ok(self
            .retain_from(height)?
            .into_iter()
            .filter(|(at, _)| *at == height)
            .map(|(_, entry)| entry)
            .collect())
    }

    /// Forgets every height before `height` and returns everything from it
    /// on, as `(height, entry)`, in the order it was appended. Like
    /// [`Self::start_height`], drops a torn final record and fails on damage
    /// anywhere else.
    pub fn retain_from(&mut self, height: u64) -> Result<Vec<(u64, Vec<u8>)>, LogError> {
        let mut bytes = Vec::new();
        File::open(&self.path)?.read_to_end(&mut bytes)?;
        let (records, whole) = parse(&bytes)?;

        let keeps = |record: &Record| record.height >= height;
        let dropping_heights = records.iter().any(|record| !keeps(record));
        if dropping_heights || whole != bytes.len() {
            self.rewrite(records.iter().filter(|record| keeps(record)))?;
        }
        Ok(records
            .into_iter()
            .filter(|record| keeps(record))
            .map(|record| (record.height, record.entry))
            .collect())
    }

    /// Replaces the file with one holding just `records`, atomically.
    fn rewrite<'a>(&mut self, records: impl Iterator<Item = &'a Record>) -> Result<(), LogError> {
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        {
            let mut file = File::create(&temporary)?;
            file.write_all(HEADER)?;
            for record in records {
                file.write_all(&encode(record.height, &record.entry)?)?;
            }
            file.sync_all()?;
        }
        fs::rename(&temporary, &self.path)?;
        sync_directory(&self.path)?;
        self.file = OpenOptions::new()
            .append(true)
            .read(true)
            .open(&self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    fn log_in(dir: &tempfile::TempDir) -> (HeightLog, PathBuf) {
        let path = dir.path().join("wal.log");
        (HeightLog::open(&path).unwrap(), path)
    }

    fn entries(log: &mut HeightLog, height: u64) -> Vec<Vec<u8>> {
        log.start_height(height).unwrap()
    }

    #[test]
    fn what_was_appended_and_flushed_comes_back_in_order_after_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        for entry in [b"one".as_slice(), b"two", b"", b"three"] {
            log.append(7, entry).unwrap();
        }
        log.flush().unwrap();
        drop(log);

        let mut log = HeightLog::open(&path).unwrap();
        assert_eq!(
            entries(&mut log, 7),
            vec![
                b"one".to_vec(),
                b"two".to_vec(),
                Vec::new(),
                b"three".to_vec()
            ]
        );
    }

    #[test]
    fn beginning_a_height_forgets_the_earlier_ones_for_good() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(1, b"a").unwrap();
        log.append(2, b"b").unwrap();
        log.append(2, b"c").unwrap();
        log.flush().unwrap();

        assert_eq!(entries(&mut log, 2), vec![b"b".to_vec(), b"c".to_vec()]);
        // Appending goes on after the rewrite, and a reopen sees exactly
        // that.
        log.append(2, b"d").unwrap();
        log.flush().unwrap();
        drop(log);
        let mut log = HeightLog::open(&path).unwrap();
        assert_eq!(
            entries(&mut log, 2),
            vec![b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
        );
        assert!(entries(&mut log, 1).is_empty(), "height 1 is gone");
        assert!(!dir.path().join("wal.log.tmp").exists());
    }

    #[test]
    fn retaining_from_a_height_returns_everything_from_it_on_and_forgets_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        for (height, entry) in [(1, "a"), (2, "b"), (3, "c"), (3, "d"), (5, "e")] {
            log.append(height, entry.as_bytes()).unwrap();
        }
        log.flush().unwrap();

        let kept = log.retain_from(3).unwrap();
        assert_eq!(
            kept,
            vec![(3, b"c".to_vec()), (3, b"d".to_vec()), (5, b"e".to_vec())]
        );
        drop(log);
        let mut log = HeightLog::open(&path).unwrap();
        assert_eq!(
            log.retain_from(0).unwrap(),
            kept,
            "and it is gone from disk"
        );
    }

    #[test]
    fn a_height_with_nothing_logged_returns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, _) = log_in(&dir);
        assert!(entries(&mut log, 5).is_empty());
        log.append(5, b"x").unwrap();
        assert!(entries(&mut log, 6).is_empty());
    }

    #[test]
    fn a_torn_last_record_is_dropped_wherever_it_was_cut() {
        // Cut the file at every length inside the last record: each time the
        // earlier records come back, the file is repaired, and appending
        // carries on from there.
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(3, b"first").unwrap();
        log.append(3, b"second").unwrap();
        log.flush().unwrap();
        let whole = fs::read(&path).unwrap();
        let last = encode(3, b"second").unwrap().len();
        drop(log);

        for cut in 1..last {
            fs::write(&path, &whole[..whole.len() - cut]).unwrap();
            let mut log = HeightLog::open(&path).unwrap();
            assert_eq!(entries(&mut log, 3), vec![b"first".to_vec()], "cut {cut}");
            log.append(3, b"again").unwrap();
            log.flush().unwrap();
            drop(log);
            let mut log = HeightLog::open(&path).unwrap();
            assert_eq!(
                entries(&mut log, 3),
                vec![b"first".to_vec(), b"again".to_vec()],
                "cut {cut}"
            );
        }
    }

    #[test]
    fn a_last_record_that_reached_the_disk_as_zeros_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(3, b"first").unwrap();
        log.append(3, b"second").unwrap();
        log.flush().unwrap();
        drop(log);

        // Full length, but the entry's bytes are what a filesystem that
        // extended the file before writing the data would show.
        let mut bytes = fs::read(&path).unwrap();
        let end = bytes.len();
        bytes[end - 6..].fill(0);
        fs::write(&path, &bytes).unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert_eq!(entries(&mut log, 3), vec![b"first".to_vec()]);
    }

    #[test]
    fn a_record_whose_head_does_not_check_is_damage_unless_only_zeros_remain() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(3, b"first").unwrap();
        log.flush().unwrap();
        drop(log);

        // Zeros where the next record would be: a file extended and never
        // written.
        let mut bytes = fs::read(&path).unwrap();
        let whole = bytes.len();
        bytes.extend_from_slice(&[0; 100]);
        fs::write(&path, &bytes).unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert_eq!(entries(&mut log, 3), vec![b"first".to_vec()]);
        assert_eq!(fs::read(&path).unwrap().len(), whole, "and repaired");

        // Anything else is not.
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        bytes.extend_from_slice(&[0; 20]);
        fs::write(&path, &bytes).unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert!(matches!(log.start_height(3), Err(LogError::Corrupt { .. })));
    }

    #[test]
    fn damage_before_the_end_is_an_error_not_a_shorter_log() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(3, b"first").unwrap();
        log.append(3, b"second").unwrap();
        log.flush().unwrap();
        drop(log);

        // A byte of the first record's entry, with a whole record after it.
        let mut bytes = fs::read(&path).unwrap();
        bytes[HEADER.len() + RECORD_HEAD] ^= 0xFF;
        fs::write(&path, &bytes).unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert!(matches!(
            log.start_height(3),
            Err(LogError::Corrupt { offset }) if offset == HEADER.len()
        ));
    }

    #[test]
    fn the_check_covers_the_length_and_the_height_as_well_as_the_entry() {
        // An entry filed under the wrong height would be replayed at the
        // wrong time, so a flipped bit anywhere in a record's head is damage.
        for byte in 0..RECORD_HEAD {
            let dir = tempfile::tempdir().unwrap();
            let (mut log, path) = log_in(&dir);
            log.append(3, b"first").unwrap();
            log.append(3, b"second").unwrap();
            log.flush().unwrap();
            drop(log);
            let mut bytes = fs::read(&path).unwrap();
            bytes[HEADER.len() + byte] ^= 0x01;
            fs::write(&path, &bytes).unwrap();
            let mut log = HeightLog::open(&path).unwrap();
            assert!(log.start_height(3).is_err(), "byte {byte}");
        }
    }

    #[test]
    fn a_damaged_head_is_damage_even_on_the_last_record() {
        // With nothing after it, a record whose entry fails its check is a
        // torn write. One whose *head* fails its check is not: its length
        // and height cannot be believed either way.
        for byte in 0..ENTRY_CHECK_AT {
            let dir = tempfile::tempdir().unwrap();
            let (mut log, path) = log_in(&dir);
            log.append(3, b"only").unwrap();
            log.flush().unwrap();
            drop(log);
            let mut bytes = fs::read(&path).unwrap();
            bytes[HEADER.len() + byte] ^= 0x01;
            fs::write(&path, &bytes).unwrap();
            let mut log = HeightLog::open(&path).unwrap();
            assert!(log.start_height(3).is_err(), "byte {byte}");
        }
    }

    #[test]
    fn a_length_no_entry_can_have_is_damage_even_with_a_head_that_checks() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, path) = log_in(&dir);
        log.append(3, b"first").unwrap();
        log.flush().unwrap();
        drop(log);
        let length = u32::try_from(MAX_ENTRY + 1).unwrap().to_le_bytes();
        let height = 3u64.to_le_bytes();
        let mut bytes = fs::read(&path).unwrap();
        bytes.extend_from_slice(&length);
        bytes.extend_from_slice(&height);
        bytes.extend_from_slice(&head_check(length, height));
        bytes.extend_from_slice(&[0xAA; CHECK_LEN + 5]);
        fs::write(&path, &bytes).unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert!(matches!(log.start_height(3), Err(LogError::Corrupt { .. })));
    }

    #[test]
    fn a_file_that_is_not_a_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wal.log");
        fs::write(&path, b"something else entirely").unwrap();
        let mut log = HeightLog::open(&path).unwrap();
        assert!(matches!(log.start_height(1), Err(LogError::BadHeader)));
    }

    #[test]
    fn an_entry_too_large_to_be_one_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (mut log, _) = log_in(&dir);
        assert!(matches!(
            log.append(1, &vec![0; MAX_ENTRY + 1]),
            Err(LogError::TooLarge)
        ));
        log.append(1, &vec![7; MAX_ENTRY]).unwrap();
        log.flush().unwrap();
        assert_eq!(entries(&mut log, 1).len(), 1);
    }
}
