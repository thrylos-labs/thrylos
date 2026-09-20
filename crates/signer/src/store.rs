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

/// A digest of a message the signer signed, and of the domain it signed it
/// under: enough to recognise that message again, and nothing to recover it
/// from.
pub type MessageDigest = [u8; 32];

pub trait HighWaterMarkStore {
    type Error;

    /// The most recently persisted mark, or `None` if this store has
    /// never persisted one (a brand-new signer).
    fn load(&self) -> Result<Option<HighWaterMark>, Self::Error>;

    /// Durably persist `mark`. Must not return `Ok` until `mark` is
    /// safely recoverable after a crash — `docs/spec.md`: "persisted and
    /// fsynced before any signature is returned".
    fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error>;

    /// The digest of the message signed at the stored mark, if it was recorded
    /// with it. A store that keeps only positions leaves this default, and a
    /// signer over such a store never signs at or below its mark, as it never
    /// did before digests existed.
    fn load_digest(&self) -> Result<Option<MessageDigest>, Self::Error> {
        Ok(None)
    }

    /// Like [`Self::persist`], and records `digest` as that of the message signed
    /// at `mark`, in the same durable step: the two must never be seen apart.
    /// (A [`Self::persist`] afterwards leaves no digest, since it says nothing
    /// about what was signed.)
    fn persist_signed(
        &mut self,
        mark: HighWaterMark,
        _digest: MessageDigest,
    ) -> Result<(), Self::Error> {
        self.persist(mark)
    }
}

/// An in-memory store with no actual durability — a real deployment
/// needs a store that genuinely survives a crash (fsynced disk, in its
/// own process). This exists for tests, including this crate's own and
/// any downstream crate's, and is not a substitute for one.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    mark: Option<HighWaterMark>,
    digest: Option<MessageDigest>,
}

impl InMemoryStore {
    pub const fn new() -> Self {
        Self {
            mark: None,
            digest: None,
        }
    }
}

impl HighWaterMarkStore for InMemoryStore {
    type Error = core::convert::Infallible;

    fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
        Ok(self.mark)
    }

    fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
        self.mark = Some(mark);
        self.digest = None;
        Ok(())
    }

    fn load_digest(&self) -> Result<Option<MessageDigest>, Self::Error> {
        Ok(self.digest)
    }

    fn persist_signed(
        &mut self,
        mark: HighWaterMark,
        digest: MessageDigest,
    ) -> Result<(), Self::Error> {
        self.mark = Some(mark);
        self.digest = Some(digest);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::high_water_mark::Step;
    use chain_types::{BlockHeight, Round};

    fn mark(height: u64) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(0), Step::Prevote)
    }

    #[test]
    fn a_digest_belongs_to_the_mark_it_was_stored_with() {
        let mut store = InMemoryStore::new();
        assert_eq!(store.load_digest(), Ok(None));
        store.persist_signed(mark(1), [7; 32]).unwrap();
        assert_eq!(store.load(), Ok(Some(mark(1))));
        assert_eq!(store.load_digest(), Ok(Some([7; 32])));
        // A mark stored without one says nothing about what was signed there.
        store.persist(mark(2)).unwrap();
        assert_eq!(store.load_digest(), Ok(None));
    }

    #[test]
    fn a_store_that_knows_only_positions_never_has_a_digest() {
        struct Positions(Option<HighWaterMark>);
        impl HighWaterMarkStore for Positions {
            type Error = core::convert::Infallible;
            fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
                Ok(self.0)
            }
            fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
                self.0 = Some(mark);
                Ok(())
            }
        }
        let mut store = Positions(None);
        store.persist_signed(mark(3), [9; 32]).unwrap();
        assert_eq!(store.load(), Ok(Some(mark(3))), "the position was kept");
        assert_eq!(store.load_digest(), Ok(None), "and only that");
    }
}
