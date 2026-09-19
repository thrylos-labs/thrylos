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
//! what the log does not — so on restart it *refuses*, and the node is
//! stuck at that height until it moves on. Safe, and the only cost is
//! liveness. Losing the log entirely has the same result.

use chain_signer::{HighWaterMark, HighWaterMarkStore, Signer, SignerError};
use chain_types::bls::{BlsSignature, DST_VOTE};
use chain_types::{BlockHeight, Hash};

use super::ports::{SignedEntry, SignedLog};

/// Why a signature was not produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRefusal {
    /// The signer refused: at or below its mark, or unable to record it.
    Signer(SignerError),
    /// The position was already signed with different bytes.
    Conflicting(HighWaterMark),
}

/// A [`Signer`] that answers repeats from a [`SignedLog`]. See the module
/// docs.
pub struct GuardedSigner<S: HighWaterMarkStore, L> {
    signer: Signer<S>,
    log: L,
}

impl<S: HighWaterMarkStore, L> GuardedSigner<S, L> {
    pub const fn new(signer: Signer<S>, log: L) -> Self {
        Self { signer, log }
    }

    /// This validator's beacon reveal for `height` under `seed`. Needs no
    /// position and no log: it is the same bytes every time.
    pub fn reveal(&self, height: BlockHeight, seed: &Hash) -> Result<BlsSignature, SignerError> {
        self.signer.sign_beacon(height, seed)
    }

    /// The signer's high-water mark.
    pub const fn high_water_mark(&self) -> Option<HighWaterMark> {
        self.signer.high_water_mark()
    }
}

impl<S: HighWaterMarkStore, L: SignedLog> GuardedSigner<S, L> {
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
            .sign(position, &bytes, DST_VOTE)
            .map_err(SigningRefusal::Signer)?;
        self.log.record(position, SignedEntry { bytes, signature });
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::host::ports::MemorySignedLog;
    use blst::min_pk::SecretKey;
    use chain_signer::{InMemoryStore, Step};
    use chain_types::{BlsPublicKey, Round};

    fn secret() -> SecretKey {
        SecretKey::key_gen(&[5u8; 32], &[]).unwrap()
    }

    fn position(height: u64, round: u64, step: Step) -> HighWaterMark {
        HighWaterMark::new(BlockHeight(height), Round(round), step)
    }

    fn guarded() -> GuardedSigner<InMemoryStore, MemorySignedLog> {
        GuardedSigner::new(
            Signer::load(secret(), InMemoryStore::new()).unwrap(),
            MemorySignedLog::new(),
        )
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

    #[test]
    fn a_lost_log_does_not_let_the_signer_sign_again() {
        // The signer has moved to (1,0,Prevote); a fresh log has forgotten
        // it. Asking for the same message finds no entry, and the signer
        // itself refuses: the node loses its place, never its safety.
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
