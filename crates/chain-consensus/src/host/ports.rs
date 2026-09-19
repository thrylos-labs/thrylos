//! What the host needs from the world outside consensus: a clock, a supply
//! of transactions, and a memory of what its signer has already signed.
//! Each is a small trait so the host stays free of I/O — the same
//! discipline as the engine API — and can be driven by a test as easily as
//! by a runtime.

use std::collections::BTreeMap;

use chain_engine_api::Block;
use chain_signer::HighWaterMark;
use chain_types::{BlockHeight, BlsSignature, Hash, Transaction};

use super::messages::CommitRecord;

/// The node's own clock, read by the host for exactly two things: the
/// timestamp of a block it proposes, and the "not more than 5 seconds
/// ahead" check on a block it is asked to vote for
/// (`chain_engine_api::timestamp`). Nothing below the engine API reads a
/// clock; this is the one place on the consensus side that does.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// Where a proposer gets transactions from — in practice `chain-mempool`.
pub trait TransactionSource {
    /// Up to `max` pending transactions, best first. They may include ones
    /// that are no longer valid; the host drops any that execution
    /// rejects.
    fn candidates(&mut self, max: usize) -> Vec<Transaction>;

    /// Called once for each block the chain commits, so the source can
    /// forget what was included and what has since become stale.
    fn committed(&mut self, block: &Block);
}

/// A signature the host's signer has already produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEntry {
    /// The exact bytes that were signed.
    pub bytes: Vec<u8>,
    pub signature: BlsSignature,
}

/// The host's record of every vote and proposal it has signed, by
/// position.
///
/// The signer refuses to sign at or below a position it has signed before,
/// unconditionally — that is what makes double-signing impossible. But
/// consensus can legitimately *ask again*: after a restart it replays, and
/// a vote it signed before the crash is asked for anew. Answering from
/// this log turns that into a lookup: the same bytes at the same position
/// get the signature already made, and *different* bytes at a position
/// already signed are refused outright, which is exactly an equivocation
/// attempt. If the log is lost the signer still refuses to go backwards; the
/// node loses its place, never its safety.
pub trait SignedLog {
    fn get(&self, position: HighWaterMark) -> Option<SignedEntry>;
    fn record(&mut self, position: HighWaterMark, entry: SignedEntry);
}

/// A [`SignedLog`] in memory, for tests. A real one must survive a crash.
#[derive(Debug, Default)]
pub struct MemorySignedLog {
    entries: BTreeMap<HighWaterMark, SignedEntry>,
}

impl MemorySignedLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl SignedLog for MemorySignedLog {
    fn get(&self, position: HighWaterMark) -> Option<SignedEntry> {
        self.entries.get(&position).cloned()
    }

    fn record(&mut self, position: HighWaterMark, entry: SignedEntry) {
        self.entries.insert(position, entry);
    }
}

/// The host's own history of what the chain decided: the block, the proof
/// and the reveal for every height it has committed, and the seed each
/// produced.
///
/// It serves two purposes. Peers that fall behind are answered from it
/// (`Message::SyncRequest`), and a restarted host finds in it the seed for
/// the height after the chain's head, which cannot be recomputed from
/// state. The chain itself does not keep certificates or reveals.
///
/// The host records a commit *before* it finalises the block, so a crash
/// between the two leaves a record for a height the chain does not yet
/// have — harmless, and the height is decided again.
pub trait CommitLog {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash);

    /// Up to `max` consecutive records starting at `from`; empty if there
    /// is none at `from`.
    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord>;

    /// The seed for the height after `height`.
    fn seed_after(&self, height: BlockHeight) -> Option<Hash>;
}

/// A [`CommitLog`] in memory. A real one must survive a crash.
#[derive(Debug, Default)]
pub struct MemoryCommitLog {
    records: BTreeMap<u64, (CommitRecord, Hash)>,
}

impl MemoryCommitLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl CommitLog for MemoryCommitLog {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) {
        self.records
            .insert(record.block.height.0, (record.clone(), seed_after));
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

/// Why the write-ahead log could not do what it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalError(pub String);

/// The host's write-ahead log: what changed its state during the height it
/// is running, kept so that a restart can put it back.
///
/// Malachite's engine is a deterministic function of its inputs. What it has
/// promised — a vote signed, a value locked — is the result of the messages
/// and timeouts it has been fed, so a host that remembers those can feed
/// them again and land in the same place. The signer's memory
/// ([`SignedLog`]) makes the replay *safe*: every vote asked for again is
/// answered with the signature already made. This log makes it *possible*.
///
/// The host appends an entry before it acts on what the entry records, and
/// calls [`Self::flush`] before anything it produced can leave the process;
/// what a peer has seen of this node is therefore always something a
/// restart will reproduce. Entries are opaque bytes: how they are stored is
/// the log's business, what they mean is the host's.
pub trait Wal {
    /// Adds an entry for `height`. It need not survive a crash until the
    /// next [`Self::flush`].
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), WalError>;

    /// Makes everything appended so far survive a crash.
    fn flush(&mut self) -> Result<(), WalError>;

    /// Begins `height`: forgets every earlier height's entries and returns,
    /// oldest first, what was appended for `height` before — empty unless
    /// this is a restart in the middle of it.
    ///
    /// A log that finds its last entry cut short by a crash drops that entry
    /// and returns the rest; one that finds damage anywhere else must fail,
    /// since what follows a hole cannot be trusted to mean what it did.
    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, WalError>;
}

/// A [`Wal`] in memory, for tests. A real one must survive a crash;
/// [`Self::lose_unflushed`] is what a crash does to this one.
#[derive(Debug, Default)]
pub struct MemoryWal {
    entries: Vec<(u64, Vec<u8>)>,
    flushed: usize,
}

impl MemoryWal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops what was appended since the last flush.
    pub fn lose_unflushed(&mut self) {
        self.entries.truncate(self.flushed);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Wal for MemoryWal {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), WalError> {
        self.entries.push((height.0, entry.to_vec()));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), WalError> {
        self.flushed = self.entries.len();
        Ok(())
    }

    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, WalError> {
        self.entries.retain(|(h, _)| *h >= height.0);
        self.flushed = self.flushed.min(self.entries.len());
        Ok(self
            .entries
            .iter()
            .filter(|(h, _)| *h == height.0)
            .map(|(_, entry)| entry.clone())
            .collect())
    }
}

/// Everything the host keeps for itself besides what its signer keeps.
pub trait Storage: CommitLog + Wal {}

impl<T: CommitLog + Wal> Storage for T {}

/// [`Storage`] in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    pub commits: MemoryCommitLog,
    pub wal: MemoryWal,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CommitLog for MemoryStorage {
    fn record(&mut self, record: &CommitRecord, seed_after: Hash) {
        self.commits.record(record, seed_after);
    }

    fn range(&self, from: BlockHeight, max: usize) -> Vec<CommitRecord> {
        self.commits.range(from, max)
    }

    fn seed_after(&self, height: BlockHeight) -> Option<Hash> {
        self.commits.seed_after(height)
    }
}

impl Wal for MemoryStorage {
    fn append(&mut self, height: BlockHeight, entry: &[u8]) -> Result<(), WalError> {
        self.wal.append(height, entry)
    }

    fn flush(&mut self) -> Result<(), WalError> {
        self.wal.flush()
    }

    fn start_height(&mut self, height: BlockHeight) -> Result<Vec<Vec<u8>>, WalError> {
        self.wal.start_height(height)
    }
}
