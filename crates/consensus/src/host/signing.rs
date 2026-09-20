//! The signer with its memory: the safety-critical core of the host.
//!
//! [`GuardedSigner`] is `chain-signer` (which refuses to sign at or below a
//! position it has signed, and persists the new position before returning
//! a signature) with a [`SignedLog`] in front. The pairing does two jobs
//! neither does alone:
//!
//! - **Asking again is harmless.** Consensus can legitimately ask for the
//!   same signature twice — a replay after a restart, a vote it lost track
//!   of. The signer alone would refuse the second request as a regression.
//!   With the log, identical bytes at an already-signed position get the
//!   signature already made.
//! - **Different bytes at a signed position are refused, by name.** That
//!   is an equivocation attempt, and the refusal says so instead of
//!   presenting as a generic signer error.
//!
//! The order matters: the log is consulted first, then the signer signs
//! (persisting its mark before it returns), and only then is the entry
//! recorded. A crash between the last two leaves a signer that remembers
//! what the log does not. On restart the node asks again, and because the
//! signer also remembers *what* it signed, it gives the same signature for
//! the same bytes (`Signer::sign`), which is then recorded. Only different
//! bytes at that position are refused, and that refusal halts the node: it
//! would be signing twice.
//!
//! Losing the log entirely is different from a crash in that window: the
//! signer then holds only its last position, and is asked for signatures the
//! log used to answer. It answers for the one at its mark, and refuses the
//! rest, because they are below it.

use chain_signer::{ConsensusSigner, HighWaterMark, SignerError};
use chain_types::bls::BlsSignature;
use chain_types::{BlockHeight, Hash};

use super::ports::{SignedEntry, SignedLog, StorageError};

/// Why a signature was not produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningRefusal {
    /// The signer refused: at or below its mark, or unable to record it.
    Signer(SignerError),
    /// The position was already signed with different bytes.
    Conflicting(HighWaterMark),
    /// The signature could not be recorded, so it is not released: a
    /// signature that a restart could not answer for is one the node must
    /// not have made.
    Log(StorageError),
}

impl core::fmt::Display for SigningRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Signer(error) => write!(f, "the signer refused: {error}"),
            Self::Conflicting(position) => {
                write!(f, "different bytes were already signed at {position}")
            }
            Self::Log(error) => write!(
                f,
                "the signature could not be recorded, so it was not released: {error}"
            ),
        }
    }
}

impl std::error::Error for SigningRefusal {}

/// A [`ConsensusSigner`] that answers repeats from a [`SignedLog`]. See the module
/// docs.
pub struct GuardedSigner<K: ConsensusSigner, L> {
    signer: K,
    log: L,
}

impl<K: ConsensusSigner, L> GuardedSigner<K, L> {
    pub const fn new(signer: K, log: L) -> Self {
        Self { signer, log }
    }

    /// This validator's beacon reveal for `height` under `seed`. Needs no
    /// position and no log: it is the same bytes every time.
    pub fn reveal(&self, height: BlockHeight, seed: &Hash) -> Result<BlsSignature, SignerError> {
        self.signer.sign_beacon(height, seed)
    }

    /// The signer's high-water mark.
    pub fn high_water_mark(&self) -> Option<HighWaterMark> {
        self.signer.high_water_mark()
    }
}

impl<K: ConsensusSigner, L: SignedLog> GuardedSigner<K, L> {
    /// Signs `bytes` (a vote or a proposal, under the vote domain) at
    /// `position`: the signature already made if this exact message was
    /// signed there before, a fresh one if nothing was, a refusal if the
    /// position was signed with anything else.
    pub fn sign(
        &mut self,
        position: HighWaterMark,
        bytes: Vec<u8>,
    ) -> Result<BlsSignature, SigningRefusal> {
        if let Some(entry) = self.log.get(position) {
            return if entry.bytes == bytes {
                Ok(entry.signature)
            } else {
                Err(SigningRefusal::Conflicting(position))
            };
        }
        let signature = self
            .signer
            .sign(position, &bytes)
            .map_err(SigningRefusal::Signer)?;
        self.log
            .record(position, SignedEntry { bytes, signature })
            .map_err(SigningRefusal::Log)?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::host::ports::MemorySignedLog;
    use blst::min_pk::SecretKey;
    use chain_signer::{InMemoryStore, Signer, Step};
    use chain_types::bls::DST_VOTE;
    use chain_types::{BlsPublicKey, Round};

    fn secret() -> SecretKey {
        SecretKey::key_gen(&[5u8; 32], &[]).unwrap()
    }

    fn position(height: u64, round: u64, step: Step) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(round), step)
    }

    fn guarded() -> GuardedSigner<Signer<InMemoryStore>, MemorySignedLog> {
        GuardedSigner::new(
            Signer::load(secret(), InMemoryStore::new()).unwrap(),
            MemorySignedLog::new(),
        )
    }

    /// A log that cannot be written.
    struct FullDisk;

    impl SignedLog for FullDisk {
        fn get(&self, _: HighWaterMark) -> Option<SignedEntry> {
            None
        }
        fn record(&mut self, _: HighWaterMark, _: SignedEntry) -> Result<(), StorageError> {
            Err(StorageError("disk full".into()))
        }
    }

    #[test]
    fn a_signature_that_could_not_be_recorded_is_not_released() {
        let mut g = GuardedSigner::new(
            Signer::load(secret(), InMemoryStore::new()).unwrap(),
            FullDisk,
        );
        let refused = g.sign(position(1, 0, Step::Prevote), b"vote".to_vec());
        assert_eq!(
            refused,
            Err(SigningRefusal::Log(StorageError("disk full".into())))
        );
    }

    #[test]
    fn a_first_request_is_signed_and_remembered() {
        let mut g = guarded();
        let p = position(1, 0, Step::Prevote);
        let signature = g.sign(p, b"vote".to_vec()).unwrap();
        assert_eq!(g.high_water_mark(), Some(p));
        // It is a genuine signature by the key, over those bytes.
        let public = BlsPublicKey::from_bytes(secret().sk_to_pk().to_bytes()).unwrap();
        assert!(
            chain_types::bls::verify_aggregate(&[&public], b"vote", DST_VOTE, &signature).is_ok()
        );
    }

    #[test]
    fn asking_again_for_the_same_message_returns_the_same_signature() {
        let mut g = guarded();
        let p = position(1, 0, Step::Prevote);
        let first = g.sign(p, b"vote".to_vec()).unwrap();
        assert_eq!(g.sign(p, b"vote".to_vec()).unwrap(), first);
        assert_eq!(g.sign(p, b"vote".to_vec()).unwrap(), first, "and again");
        assert_eq!(g.high_water_mark(), Some(p), "the mark did not move");
    }

    #[test]
    fn a_different_message_at_a_signed_position_is_refused_as_a_conflict() {
        let mut g = guarded();
        let p = position(1, 0, Step::Prevote);
        g.sign(p, b"vote for A".to_vec()).unwrap();
        assert_eq!(
            g.sign(p, b"vote for B".to_vec()),
            Err(SigningRefusal::Conflicting(p))
        );
        // The refusal did not spoil the original.
        assert!(g.sign(p, b"vote for A".to_vec()).is_ok());
    }

    #[test]
    fn a_position_below_the_mark_is_refused_by_the_signer() {
        let mut g = guarded();
        g.sign(position(5, 0, Step::Precommit), b"later".to_vec())
            .unwrap();
        let earlier = position(4, 9, Step::Precommit);
        assert!(matches!(
            g.sign(earlier, b"earlier".to_vec()),
            Err(SigningRefusal::Signer(SignerError::Regression { .. }))
        ));
    }

    #[test]
    fn each_step_of_a_round_is_its_own_position() {
        let mut g = guarded();
        for step in [Step::Propose, Step::Prevote, Step::Precommit] {
            g.sign(position(1, 0, step), format!("{step:?}").into_bytes())
                .unwrap();
        }
    }

    /// A store the "crash" and the "restart" both see, as a disk is.
    #[derive(Clone, Default)]
    struct Disk(std::rc::Rc<std::cell::RefCell<InMemoryStore>>);

    impl chain_signer::HighWaterMarkStore for Disk {
        type Error = core::convert::Infallible;

        fn load(&self) -> Result<Option<HighWaterMark>, Self::Error> {
            self.0.borrow().load()
        }

        fn persist(&mut self, mark: HighWaterMark) -> Result<(), Self::Error> {
            self.0.borrow_mut().persist(mark)
        }

        fn load_digest(&self) -> Result<Option<chain_signer::MessageDigest>, Self::Error> {
            self.0.borrow().load_digest()
        }

        fn persist_signed(
            &mut self,
            mark: HighWaterMark,
            digest: chain_signer::MessageDigest,
        ) -> Result<(), Self::Error> {
            self.0.borrow_mut().persist_signed(mark, digest)
        }
    }

    /// The signer records a signature and the node dies before it records the
    /// same signature: the log write fails, as a crash there would have.
    fn signed_but_never_logged(disk: &Disk, at: HighWaterMark, bytes: &[u8]) {
        use chain_signer::HighWaterMarkStore;

        let mut before_the_crash =
            GuardedSigner::new(Signer::load(secret(), disk.clone()).unwrap(), FullDisk);
        assert!(matches!(
            before_the_crash.sign(at, bytes.to_vec()),
            Err(SigningRefusal::Log(_))
        ));
        assert_eq!(disk.load().unwrap(), Some(at), "the signer did record it");
    }

    #[test]
    fn a_crash_between_the_signer_and_the_log_is_recovered_by_asking_again() {
        let disk = Disk::default();
        let at = position(4, 0, Step::Prevote);
        signed_but_never_logged(&disk, at, b"vote");

        // The restarted node has an empty log and the same signer state.
        let mut restarted = GuardedSigner::new(
            Signer::load(secret(), disk.clone()).unwrap(),
            MemorySignedLog::new(),
        );
        let signature = restarted.sign(at, b"vote".to_vec()).unwrap();
        let public = BlsPublicKey::from_bytes(secret().sk_to_pk().to_bytes()).unwrap();
        assert!(
            chain_types::bls::verify_aggregate(&[&public], b"vote", DST_VOTE, &signature).is_ok()
        );
        // It is remembered now, and answered from the log without the signer.
        assert_eq!(restarted.sign(at, b"vote".to_vec()).unwrap(), signature);
        assert_eq!(
            restarted.sign(at, b"another vote".to_vec()),
            Err(SigningRefusal::Conflicting(at))
        );
        // And the chain goes on from there.
        assert!(restarted
            .sign(position(4, 0, Step::Precommit), b"commit".to_vec())
            .is_ok());
    }

    #[test]
    fn a_crash_in_that_window_does_not_let_the_restarted_node_sign_something_else() {
        use chain_signer::HighWaterMarkStore;

        let disk = Disk::default();
        let at = position(4, 0, Step::Prevote);
        signed_but_never_logged(&disk, at, b"vote for A");
        let mut restarted = GuardedSigner::new(
            Signer::load(secret(), disk.clone()).unwrap(),
            MemorySignedLog::new(),
        );
        assert!(matches!(
            restarted.sign(at, b"vote for B".to_vec()),
            Err(SigningRefusal::Signer(SignerError::Regression { .. }))
        ));
        assert_eq!(disk.load().unwrap(), Some(at), "and the mark stayed");
    }

    #[test]
    fn a_signer_that_kept_only_the_position_still_refuses_at_it() {
        // A signer state from before digests were kept: the position, and no
        // record of what was signed there. Asking again gets a refusal, as
        // it always did: the node loses its place, never its safety.
        let mut store = InMemoryStore::new();
        {
            let mut g = GuardedSigner::new(
                Signer::load(secret(), InMemoryStore::new()).unwrap(),
                MemorySignedLog::new(),
            );
            g.sign(position(1, 0, Step::Prevote), b"vote".to_vec())
                .unwrap();
            // Carry the signer's persisted mark over to the "restart".
            chain_signer::HighWaterMarkStore::persist(&mut store, g.high_water_mark().unwrap())
                .unwrap();
        }
        let mut restarted = GuardedSigner::new(
            Signer::load(secret(), store).unwrap(),
            MemorySignedLog::new(),
        );
        assert!(matches!(
            restarted.sign(position(1, 0, Step::Prevote), b"vote".to_vec()),
            Err(SigningRefusal::Signer(SignerError::Regression { .. }))
        ));
    }

    #[test]
    fn a_reveal_needs_no_position_and_is_stable() {
        let mut g = guarded();
        let seed = Hash::from_bytes([2u8; 32]);
        let reveal = g.reveal(BlockHeight(3), &seed).unwrap();
        assert_eq!(g.reveal(BlockHeight(3), &seed).unwrap(), reveal);
        g.sign(position(3, 0, Step::Propose), b"proposal".to_vec())
            .unwrap();
        assert_eq!(g.reveal(BlockHeight(3), &seed).unwrap(), reveal);
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

    use chain_signer::Step;
    use chain_types::Round;

    #[test]
    fn every_signing_refusal_reads_as_a_sentence() {
        let position = HighWaterMark::new(BlockHeight(3), Round(0), Step::Prevote);
        readable(&[
            SigningRefusal::Signer(SignerError::Unavailable),
            SigningRefusal::Conflicting(position),
            SigningRefusal::Log(StorageError("disk full".into())),
        ]);
        let message = SigningRefusal::Conflicting(position).to_string();
        assert!(message.contains("height 3, round 0, prevote"), "{message}");
        let message = SigningRefusal::Log(StorageError("disk full".into())).to_string();
        assert!(message.contains("disk full"), "{message}");
    }
}
