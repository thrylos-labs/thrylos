//! The signer itself. `docs/spec.md`, "Keys, signing and slashing
//! safety": "The failure to design against here is not theft, it is an
//! honest validator getting slashed by their own node. A validator
//! restarting from a truncated write-ahead log signs a second block at
//! the same height, and burns real stake for an honest operator's disk
//! fsync behaviour."

use chain_types::bls::BlsSignature;

use crate::high_water_mark::HighWaterMark;
use crate::store::{HighWaterMarkStore, MessageDigest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerError {
    /// Refused: `requested` is at or below `mark`, the last position
    /// this signer has already signed, and is not a request for the very
    /// message it signed there (`docs/spec.md`: it refuses "anything at or
    /// below that mark ... with no override flag and no reset command", the
    /// one thing it will do at exactly the mark being to give again the
    /// signature it already gave).
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
    /// The separate signer process or its authenticated local protocol was
    /// unavailable. Consensus must halt rather than sign locally or bypass
    /// the durable mark.
    Unavailable,
}

impl core::fmt::Display for SignerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Regression { requested, mark } => write!(
                f,
                "refusing to sign at {requested}: it is at or below the last signed position, {mark}"
            ),
            Self::PersistenceFailed => f.write_str("could not durably record the new signing position, so nothing was signed"),
            Self::MalformedSignature => f.write_str("the signing library returned a malformed signature"),
            Self::Unavailable => f.write_str("the signer process is unavailable"),
        }
    }
}

impl std::error::Error for SignerError {}

/// The narrow signing boundary used by consensus. Implementations may hold
/// the key locally (tests and the signer process) or call a separate process;
/// the node only needs these two fixed signing operations.
pub trait ConsensusSigner {
    fn high_water_mark(&self) -> Option<HighWaterMark>;

    fn sign(
        &mut self,
        requested: HighWaterMark,
        message: &[u8],
    ) -> Result<BlsSignature, SignerError>;

    fn sign_beacon(
        &self,
        height: chain_types::BlockHeight,
        seed: &chain_types::Hash,
    ) -> Result<BlsSignature, SignerError>;
}

/// A BLS consensus signer with double-sign protection, generic over
/// where the high-water mark is durably stored (see [`HighWaterMarkStore`]).
pub struct Signer<S: HighWaterMarkStore> {
    secret_key: blst::min_pk::SecretKey,
    store: S,
    mark: Option<HighWaterMark>,
    /// The digest of the message signed at `mark`, when the store recorded it.
    last_digest: Option<MessageDigest>,
}

/// What identifies a message to sign: its domain-separation tag as well as its
/// bytes, since the same bytes under another tag are another signature.
fn digest_of(dst: &[u8], message: &[u8]) -> MessageDigest {
    let mut hasher = blake3::Hasher::new_derive_key("thrylos chain-signer signed message v1");
    hasher.update(&u64::try_from(dst.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(dst);
    hasher.update(message);
    *hasher.finalize().as_bytes()
}

impl<S: HighWaterMarkStore> Signer<S> {
    /// Load a signer from `store`'s persisted state. `secret_key` is
    /// assumed already provisioned by whatever secure process holds it —
    /// key generation and custody are outside this crate's scope
    /// (`docs/spec.md`: consensus keys are "held only by the signer;
    /// the node never sees them").
    pub fn load(secret_key: blst::min_pk::SecretKey, store: S) -> Result<Self, S::Error> {
        let mark = store.load()?;
        let last_digest = if mark.is_some() {
            store.load_digest()?
        } else {
            None
        };
        Ok(Self {
            secret_key,
            store,
            mark,
            last_digest,
        })
    }

    pub const fn high_water_mark(&self) -> Option<HighWaterMark> {
        self.mark
    }

    /// Sign `message` under `dst` at `requested`, refusing unless
    /// `requested` is strictly greater than the persisted high-water
    /// mark. Persists the new mark, and a digest of what is signed at it,
    /// before producing the signature — never the other way around.
    ///
    /// The one exception is a request for exactly what was signed last: the
    /// same `message` under the same `dst` at exactly the mark. That gets the
    /// same signature again and moves nothing. It exists because a signature
    /// can be made and then lost on its way to whoever asked (the asker
    /// crashed before it recorded the signature), and the asker must be able
    /// to ask again. It cannot be used to sign twice: BLS signatures are
    /// unique, so the answer is the very bytes already given, and any
    /// different message at that position is refused as before.
    pub fn sign(
        &mut self,
        requested: HighWaterMark,
        message: &[u8],
        dst: &[u8],
    ) -> Result<BlsSignature, SignerError> {
        let digest = digest_of(dst, message);
        if let Some(mark) = self.mark {
            if requested < mark || (requested == mark && self.last_digest != Some(digest)) {
                return Err(SignerError::Regression { requested, mark });
            }
            if requested == mark {
                return self.produce(message, dst);
            }
        }

        self.store
            .persist_signed(requested, digest)
            .map_err(|_| SignerError::PersistenceFailed)?;
        self.mark = Some(requested);
        self.last_digest = Some(digest);
        self.produce(message, dst)
    }

    fn produce(&self, message: &[u8], dst: &[u8]) -> Result<BlsSignature, SignerError> {
        let raw = self.secret_key.sign(message, dst, &[]);
        BlsSignature::from_bytes(raw.to_bytes()).map_err(|_| SignerError::MalformedSignature)
    }

    /// This validator's *reveal* for `height` under `seed`: its share of
    /// the randomness beacon that picks proposers (`chain_types::beacon`).
    ///
    /// Unlike [`Self::sign`] this takes no position and moves no mark, and
    /// that is safe because of what it cannot be made to sign. The message
    /// and the domain-separation tag are fixed here, not chosen by the
    /// caller: it signs only `beacon_message(height, seed)` under
    /// `DST_BEACON`, so the result can never verify as a vote or a
    /// proposal and can never be evidence of anything slashable. BLS
    /// signatures are unique, so asking twice gives the same bytes — there
    /// is nothing here to equivocate with.
    pub fn sign_beacon(
        &self,
        height: chain_types::BlockHeight,
        seed: &chain_types::Hash,
    ) -> Result<BlsSignature, SignerError> {
        let message = chain_types::beacon::beacon_message(height, seed);
        let raw = self
            .secret_key
            .sign(&message, chain_types::bls::DST_BEACON, &[]);
        BlsSignature::from_bytes(raw.to_bytes()).map_err(|_| SignerError::MalformedSignature)
    }
}

impl<S: HighWaterMarkStore> ConsensusSigner for Signer<S> {
    fn high_water_mark(&self) -> Option<HighWaterMark> {
        Signer::high_water_mark(self)
    }

    fn sign(
        &mut self,
        requested: HighWaterMark,
        message: &[u8],
    ) -> Result<BlsSignature, SignerError> {
        Signer::sign(self, requested, message, chain_types::bls::DST_VOTE)
    }

    fn sign_beacon(
        &self,
        height: chain_types::BlockHeight,
        seed: &chain_types::Hash,
    ) -> Result<BlsSignature, SignerError> {
        Signer::sign_beacon(self, height, seed)
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
    fn refuses_a_different_message_at_the_same_position() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let position = hwm(1, 0, Step::Propose);
        signer.sign(position, b"msg", DST).unwrap();

        let result = signer.sign(position, b"another msg", DST);
        assert_eq!(
            result,
            Err(SignerError::Regression {
                requested: position,
                mark: position
            })
        );
    }

    #[test]
    fn the_same_message_at_the_same_position_gets_the_same_signature_and_moves_nothing() {
        use std::cell::Cell;
        use std::rc::Rc;

        /// An in-memory store that counts what is persisted.
        struct Counting(InMemoryStore, Rc<Cell<u32>>);
        impl HighWaterMarkStore for Counting {
            type Error = core::convert::Infallible;
            fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
                self.0.load()
            }
            fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
                self.1.set(self.1.get() + 1);
                self.0.persist(mark)
            }
            fn load_digest(&self) -> Result<Option<MessageDigest>, Self::Error> {
                self.0.load_digest()
            }
            fn persist_signed(
                &mut self,
                mark: HighWaterMark,
                digest: MessageDigest,
            ) -> Result<(), Self::Error> {
                self.1.set(self.1.get() + 1);
                self.0.persist_signed(mark, digest)
            }
        }

        let writes = Rc::new(Cell::new(0));
        let mut signer =
            Signer::load(test_key(), Counting(InMemoryStore::new(), writes.clone())).unwrap();
        let position = hwm(1, 0, Step::Prevote);
        let first = signer.sign(position, b"vote", DST).unwrap();
        assert_eq!(writes.get(), 1);

        for _ in 0..3 {
            assert_eq!(signer.sign(position, b"vote", DST), Ok(first));
        }
        assert_eq!(writes.get(), 1, "asking again wrote nothing");
        assert_eq!(signer.high_water_mark(), Some(position));

        // The refusal of anything else is untouched by having been asked again.
        assert!(matches!(
            signer.sign(position, b"a different vote", DST),
            Err(SignerError::Regression { .. })
        ));
        assert_eq!(signer.sign(position, b"vote", DST), Ok(first));
    }

    #[test]
    fn the_same_bytes_under_another_domain_are_another_message() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let position = hwm(1, 0, Step::Prevote);
        signer.sign(position, b"vote", DST).unwrap();
        // The same length, so only what the tag says can tell them apart.
        let other = b"THRYLOS-BLS-VOTE-TESU";
        assert_eq!(other.len(), DST.len());
        assert!(matches!(
            signer.sign(position, b"vote", other),
            Err(SignerError::Regression { .. })
        ));
    }

    /// A store two signers can be loaded from one after the other, as a disk is.
    #[derive(Clone, Default)]
    struct Disk(std::rc::Rc<std::cell::RefCell<InMemoryStore>>);

    impl HighWaterMarkStore for Disk {
        type Error = core::convert::Infallible;
        fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
            self.0.borrow().load()
        }
        fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
            self.0.borrow_mut().persist(mark)
        }
        fn load_digest(&self) -> Result<Option<MessageDigest>, Self::Error> {
            self.0.borrow().load_digest()
        }
        fn persist_signed(
            &mut self,
            mark: HighWaterMark,
            digest: MessageDigest,
        ) -> Result<(), Self::Error> {
            self.0.borrow_mut().persist_signed(mark, digest)
        }
    }

    #[test]
    fn a_signer_started_again_from_what_the_last_one_persisted_can_answer_for_its_last_message() {
        let disk = Disk::default();
        let (first, second) = (hwm(3, 0, Step::Prevote), hwm(3, 0, Step::Precommit));
        let mut before = Signer::load(test_key(), disk.clone()).unwrap();
        before.sign(first, b"vote", DST).unwrap();
        let commit = before.sign(second, b"commit", DST).unwrap();
        drop(before);

        // The process is gone; a new one reads only the disk.
        let mut after = Signer::load(test_key(), disk.clone()).unwrap();
        assert_eq!(after.high_water_mark(), Some(second));
        assert_eq!(after.sign(second, b"commit", DST), Ok(commit));
        assert!(matches!(
            after.sign(second, b"another commit", DST),
            Err(SignerError::Regression { .. })
        ));
        // Only the last position: the one before it is below the mark.
        assert!(matches!(
            after.sign(first, b"vote", DST),
            Err(SignerError::Regression { .. })
        ));
    }

    #[test]
    fn only_the_last_position_can_be_asked_for_again() {
        let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let (first, second) = (hwm(1, 0, Step::Prevote), hwm(1, 0, Step::Precommit));
        signer.sign(first, b"vote", DST).unwrap();
        let precommit = signer.sign(second, b"commit", DST).unwrap();

        // Below the mark, even for exactly what was signed there: refused.
        assert!(matches!(
            signer.sign(first, b"vote", DST),
            Err(SignerError::Regression { .. })
        ));
        // At the mark it is still the same signature.
        assert_eq!(signer.sign(second, b"commit", DST), Ok(precommit));
        // And a message signed below is not the one signed at the mark.
        assert!(matches!(
            signer.sign(second, b"vote", DST),
            Err(SignerError::Regression { .. })
        ));
    }

    #[test]
    fn a_signer_loaded_from_a_store_that_holds_the_digest_can_answer_again() {
        // What a restart finds when the signer had signed, and its asker never
        // heard: the mark, with the digest of what was signed at it.
        let position = hwm(7, 1, Step::Precommit);
        let mut store = InMemoryStore::new();
        store
            .persist_signed(position, digest_of(DST, b"the vote"))
            .unwrap();
        let mut signer = Signer::load(test_key(), store).unwrap();

        let mut fresh = Signer::load(test_key(), InMemoryStore::new()).unwrap();
        let expected = fresh.sign(position, b"the vote", DST).unwrap();
        assert_eq!(signer.sign(position, b"the vote", DST), Ok(expected));
        assert!(matches!(
            signer.sign(position, b"another vote", DST),
            Err(SignerError::Regression { .. })
        ));
    }

    #[test]
    fn a_mark_with_no_digest_refuses_everything_at_it_as_a_signer_always_did() {
        let position = hwm(7, 1, Step::Precommit);
        let mut store = InMemoryStore::new();
        store.persist(position).unwrap();
        let mut signer = Signer::load(test_key(), store).unwrap();
        assert!(matches!(
            signer.sign(position, b"the vote", DST),
            Err(SignerError::Regression { .. })
        ));
        assert!(signer.sign(hwm(7, 1, Step::Precommit), b"x", DST).is_err());
        assert!(signer.sign(hwm(8, 0, Step::Propose), b"x", DST).is_ok());
    }

    mod never_twice {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// Whatever is asked, in whatever order, the signer never gives
            /// two different messages a signature at one position, never
            /// signs below where it has been, and answers a repeat with the
            /// signature it gave.
            #[test]
            fn no_sequence_of_requests_makes_it_sign_two_things_at_one_position(
                requests in proptest::collection::vec((0u64..3, 0u64..2, 0u8..3, 0u8..3), 1..80),
            ) {
                let mut signer = Signer::load(test_key(), InMemoryStore::new()).unwrap();
                let mut signed: std::collections::BTreeMap<HighWaterMark, (u8, BlsSignature)> =
                    std::collections::BTreeMap::new();
                let mut high: Option<HighWaterMark> = None;
                for (height, round, step, message) in requests {
                    let step = match step {
                        0 => Step::Propose,
                        1 => Step::Prevote,
                        _ => Step::Precommit,
                    };
                    let position = hwm(height, round, step);
                    let bytes = [message];
                    if let Ok(signature) = signer.sign(position, &bytes, DST) {
                        if let Some((earlier, given)) = signed.get(&position) {
                            prop_assert_eq!(*earlier, message, "two messages at {}", position);
                            prop_assert_eq!(*given, signature);
                        }
                        prop_assert!(high.is_none_or(|high| position >= high), "went back");
                        signed.insert(position, (message, signature));
                        high = Some(position);
                    }
                    prop_assert_eq!(signer.high_water_mark(), high);
                }
            }
        }
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

    #[test]
    fn a_beacon_reveal_verifies_as_one_and_moves_no_mark() {
        use chain_types::beacon::verify_reveal;
        use chain_types::{BlockHeight as Height, BlsPublicKey, Hash};
        let key = test_key();
        let public = BlsPublicKey::from_bytes(key.sk_to_pk().to_bytes()).unwrap();
        let mut signer = Signer::load(key, InMemoryStore::new()).unwrap();
        let seed = Hash::from_bytes([4u8; 32]);

        let reveal = signer.sign_beacon(Height(9), &seed).unwrap();
        assert!(verify_reveal(&public, Height(9), &seed, &reveal).is_ok());
        assert_eq!(signer.high_water_mark(), None, "no position was consumed");

        // Same bytes every time, and it does not disturb signing votes.
        assert_eq!(signer.sign_beacon(Height(9), &seed).unwrap(), reveal);
        assert!(signer.sign(hwm(9, 0, Step::Propose), b"msg", DST).is_ok());
        assert_eq!(signer.sign_beacon(Height(9), &seed).unwrap(), reveal);
    }

    #[test]
    fn a_beacon_reveal_cannot_be_used_as_a_vote_signature() {
        use chain_types::bls::{verify_aggregate, DST_VOTE};
        use chain_types::{BlockHeight as Height, BlsPublicKey, Hash};
        let key = test_key();
        let public = BlsPublicKey::from_bytes(key.sk_to_pk().to_bytes()).unwrap();
        let signer = Signer::load(key, InMemoryStore::new()).unwrap();
        let seed = Hash::from_bytes([4u8; 32]);
        let reveal = signer.sign_beacon(Height(9), &seed).unwrap();
        let message = chain_types::beacon::beacon_message(Height(9), &seed);
        assert!(verify_aggregate(&[&public], &message, DST_VOTE, &reveal).is_err());
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    /// Every message reads as a sentence about the problem: not empty, not
    /// the variant's Rust name, no trailing full stop, one line, and no two
    /// variants alike.
    fn readable<T: core::fmt::Display + core::fmt::Debug>(all: &[T]) {
        let mut seen = Vec::new();
        for value in all {
            let message = value.to_string();
            assert!(!message.is_empty(), "{value:?}");
            assert!(
                !message.ends_with('.') && !message.contains('\n'),
                "{message}"
            );
            assert_ne!(message, format!("{value:?}"), "only the variant's name");
            assert!(!seen.contains(&message), "two variants say {message:?}");
            seen.push(message);
        }
    }

    use crate::high_water_mark::Step;
    use chain_types::{BlockHeight, Round};

    #[test]
    fn a_refused_signature_names_both_positions() {
        let requested = HighWaterMark::new(BlockHeight(5), Round(1), Step::Prevote);
        let mark = HighWaterMark::new(BlockHeight(5), Round(2), Step::Precommit);
        let message = SignerError::Regression { requested, mark }.to_string();
        assert!(message.contains("height 5, round 1, prevote"), "{message}");
        assert!(
            message.contains("height 5, round 2, precommit"),
            "{message}"
        );
    }

    #[test]
    fn every_signer_error_reads_as_a_sentence() {
        let position = HighWaterMark::new(BlockHeight(1), Round(0), Step::Propose);
        readable(&[
            SignerError::Regression {
                requested: position,
                mark: position,
            },
            SignerError::PersistenceFailed,
            SignerError::MalformedSignature,
            SignerError::Unavailable,
        ]);
    }
}
