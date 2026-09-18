//! The pluggable durable-storage boundary. `docs/spec.md`, "Keys,
//! signing and slashing safety": "It is a separate process with its own
//! storage, so a node rollback, restore-from-snapshot or container
//! restart cannot rewind it." *Which* process and *which* disk is a
//! deployment concern this crate doesn't decide; what it owns is the
//! contract — persist, and confirm the persist, before any signature is
//! returned — captured here as a trait so [`crate::Signer`]'s
//! high-water-mark logic stays pure and testable regardless of the
//! backing store.

use crate::high_water_mark::HighWaterMark;

pub trait HighWaterMarkStore {
    type Error;

    /// The most recently persisted mark, or `None` if this store has
    /// never persisted one (a brand-new signer).
    fn load(&self) -> Result<Option<HighWaterMark>, Self::Error>;

    /// Durably persist `mark`. Must not return `Ok` until `mark` is
    /// safely recoverable after a crash — `docs/spec.md`: "persisted and
    /// fsynced before any signature is returned".
    fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error>;
}

/// An in-memory store with no actual durability — a real deployment
/// needs a store that genuinely survives a crash (fsynced disk, in its
/// own process). This exists for tests, including this crate's own and
/// any downstream crate's, and is not a substitute for one.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    mark: Option<HighWaterMark>,
}

impl InMemoryStore {
    pub const fn new() -> Self {
        Self { mark: None }
    }
}

impl HighWaterMarkStore for InMemoryStore {
    type Error = core::convert::Infallible;

    fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
        Ok(self.mark)
    }

    fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
        self.mark = Some(mark);
        Ok(())
    }
}
