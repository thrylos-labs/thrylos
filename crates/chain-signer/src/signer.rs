//! The signer itself. `docs/spec.md`, "Keys, signing and slashing
//! safety": "The failure to design against here is not theft, it is an
//! honest validator getting slashed by their own node. A validator
//! restarting from a truncated write-ahead log signs a second block at
//! the same height, and burns real stake for an honest operator's disk
//! fsync behaviour."

use chain_types::bls::BlsSignature;

use crate::high_water_mark::HighWaterMark;
use crate::store::HighWaterMarkStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
    /// Refused: `requested` is at or below `mark`, the last position
    /// this signer has already signed. Unconditional — `docs/spec.md`:
    /// "It refuses to sign anything at or below that mark,
    /// unconditionally, with no override flag and no reset command."
    Regression {
        requested: HighWaterMark,
        mark: HighWaterMark,
    },
    /// The new high-water mark could not be durably persisted. Refusing
    /// to sign here is the safe choice: a signature must never be
    /// returned unless the mark that gates it is already recoverable
    /// after a crash.
    PersistenceFailed,
    /// The freshly produced signature's own compressed bytes failed to
    /// parse back into a valid `BlsSignature` — meaning `blst` itself
    /// returned something malformed. Should be unreachable; surfaced
    /// rather than assumed impossible.
    MalformedSignature,
}

/// A BLS consensus signer with double-sign protection, generic over
/// where the high-water mark is durably stored (see [`HighWaterMarkStore`]).
pub struct Signer<S: HighWaterMarkStore> {
    secret_key: blst::min_pk::SecretKey,
    store: S,
    mark: Option<HighWaterMark>,
}

impl<S: HighWaterMarkStore> Signer<S> {
    /// Load a signer from `store`'s persisted state. `secret_key` is
    /// assumed already provisioned by whatever secure process holds it —
    /// key generation and custody are outside this crate's scope
    /// (`docs/spec.md`: consensus keys are "held only by the signer;
    /// the node never sees them").
    pub fn load(secret_key: blst::min_pk::SecretKey, store: S) -> Result<Self, S::Error> {
        let mark = store.load()?;
        Ok(Self {
            secret_key,
            store,
            mark,
        })
    }

    pub const fn high_water_mark(&self) -> Option<HighWaterMark> {
        self.mark
    }

    /// Sign `message` under `dst` at `requested`, refusing unless
    /// `requested` is strictly greater than the persisted high-water
    /// mark. Persists the new mark before producing the signature —
    /// never the other way around.
    pub fn sign(
        &mut self,
        requested: HighWaterMark,
        message: &[u8],
        dst: &[u8],
    ) -> Result<BlsSignature, SignerError> {
        if let Some(mark) = self.mark {
            if requested <= mark {
                return Err(SignerError::Regression { requested, mark });
            }
        }

        self.store
            .persist(requested)
            .map_err(|_| SignerError::PersistenceFailed)?;
        self.mark = Some(requested);

        let raw = self.secret_key.sign(message, dst, &[]);
        BlsSignature::from_bytes(raw.to_bytes()).map_err(|_| SignerError::MalformedSignature)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::high_water_mark::Step;
    use crate::store::InMemoryStore;
    use blst::min_pk::SecretKey;
    use chain_types::{BlockHeight, Round};

    const DST: &[u8] = b"THRYLOS-BLS-VOTE-TEST";

    fn test_key() -> SecretKey {
        SecretKey::key_gen(&[9u8; 32], &[]).unwrap()
    }

    fn hwm(height: u64, round: u64, step: Step) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(round), step)
    }

    #[test]
    fn fresh_signer_signs_at_any_position() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let result = signer.sign(hwm(1, 0, Step::Propose), b"msg", DST);
        assert!(result.is_ok());
        assert_eq!(signer.high_water_mark(), Some(hwm(1, 0, Step::Propose)));
    }

    #[test]
    fn refuses_to_sign_at_the_same_position_again() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let position = hwm(1, 0, Step::Propose);
        signer.sign(position, b"msg", DST).unwrap();

        let result = signer.sign(position, b"msg", DST);
        assert_eq!(
            result,
            Err(SignerError::Regression {
                requested: position,
                mark: position
            })
        );
    }

    #[test]
    fn refuses_to_sign_at_an_earlier_position() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        signer
            .sign(hwm(5, 2, Step::Precommit), b"msg", DST)
            .unwrap();

        let result = signer.sign(hwm(5, 1, Step::Propose), b"msg", DST);
        assert!(matches!(result, Err(SignerError::Regression { .. })));
    }

    #[test]
    fn allows_advancing_through_all_three_steps_within_one_round() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        assert!(signer.sign(hwm(1, 0, Step::Propose), b"p", DST).is_ok());
        assert!(signer.sign(hwm(1, 0, Step::Prevote), b"v", DST).is_ok());
        assert!(signer.sign(hwm(1, 0, Step::Precommit), b"c", DST).is_ok());
    }

    #[test]
    fn loading_from_a_store_with_an_existing_mark_refuses_to_regress() {
        struct FixedStore {
            mark: Option<HighWaterMark>,
        }
        impl HighWaterMarkStore for FixedStore {
            type Error = core::convert::Infallible;
            fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
                Ok(self.mark)
            }
            fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
                self.mark = Some(mark);
                Ok(())
            }
        }

        let already_signed = hwm(10, 0, Step::Precommit);
        let store = FixedStore {
            mark: Some(already_signed),
        };
        let mut signer = Signer::load(test_key(), store).unwrap();
        assert_eq!(signer.high_water_mark(), Some(already_signed));

        let result = signer.sign(already_signed, b"msg", DST);
        assert!(matches!(result, Err(SignerError::Regression { .. })));

        // Strictly beyond the reloaded mark is still fine.
        assert!(signer.sign(hwm(11, 0, Step::Propose), b"msg", DST).is_ok());
    }

    #[test]
    fn persistence_failure_prevents_signing() {
        struct FailingStore;
        impl HighWaterMarkStore for FailingStore {
            type Error = &'static str;
            fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
                Ok(None)
            }
            fn persist(&mut self, _mark: HighWaterMark) -> Result<(), Self::Error> {
                Err("disk full")
            }
        }

        let mut signer = Signer::load(test_key(), FailingStore).unwrap();
        let result = signer.sign(hwm(1, 0, Step::Propose), b"msg", DST);
        assert_eq!(result, Err(SignerError::PersistenceFailed));
        // A failed persist must not advance the in-memory mark either —
        // a later retry at the same position must still be possible.
        assert_eq!(signer.high_water_mark(), None);
    }

    #[test]
    fn signature_verifies_against_the_signer_s_own_public_key() {
        let key = test_key();
        let public = chain_types::bls::BlsPublicKey::from_bytes(key.sk_to_pk().to_bytes()).unwrap();
        let mut signer = Signer::load(key, InMemoryStore::new()).unwrap();

        let sig = signer
            .sign(hwm(1, 0, Step::Propose), b"hello", DST)
            .unwrap();
        // No single-key verify is exposed by `chain_types::bls` (only
        // proof-of-possession and aggregate verification) — a one-element
        // aggregate check is exactly equivalent and reuses its existing
        // public API rather than adding a new one just for this test.
        assert!(chain_types::bls::verify_aggregate(&[&public], b"hello", DST, &sig).is_ok());
    }
}
