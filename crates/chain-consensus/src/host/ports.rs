//! What the host needs from the world outside consensus: a clock, a supply
//! of transactions, and a memory of what its signer has already signed.
//! Each is a small trait so the host stays free of I/O — the same
//! discipline as the engine API — and can be driven by a test as easily as
//! by a runtime.

use std::collections::BTreeMap;

use chain_engine_api::Block;
use chain_signer::HighWaterMark;
use chain_types::{BlsSignature, Transaction};

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
