//! A consensus vote, and evidence that a validator signed two
//! conflicting ones.
//!
//! [`Vote::signing_bytes`] is the *only* definition of what a validator's
//! BLS signature on a vote covers — the same rule `Transaction::
//! signing_bytes` follows, "the bytes that get signed have exactly one
//! definition". `chain-consensus` signs and verifies through it, and
//! [`DuplicateVoteEvidence::verify`] checks against it, so there is no way
//! for what a validator was punished for signing to differ from what the
//! consensus engine believed it signed. It lives here rather than in
//! `chain-consensus` so that evidence can be verified without depending on
//! the consensus engine at all.

use crate::address::Address;
use crate::bls::{verify_aggregate, BlsPublicKey, BlsSignature, DST_VOTE};
use crate::codec::{decode_field, CodecError, Decode, Encode};
use crate::hash::Hash;
use crate::ids::{BlockHeight, Round};

/// Leading byte of every vote's signing bytes: domain separation from
/// every other BLS-signed message, so no other structure's encoding can
/// ever be mistaken for a vote's. `chain-consensus` gives its proposals a
/// different tag for the same reason — the two must never be equal.
pub const VOTE_SIGNING_TAG: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteKind {
    Prevote,
    Precommit,
}

/// One validator's vote in one round of one height: for a block
/// (`Some(hash)`) or for nothing (`None`, a nil vote).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vote {
    pub height: BlockHeight,
    pub round: Round,
    pub value: Option<Hash>,
    pub kind: VoteKind,
    pub validator: Address,
}

impl Vote {
    /// The exact bytes the validator's signature covers.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }
}

impl Encode for Vote {
    fn encode(&self, out: &mut Vec<u8>) {
        VOTE_SIGNING_TAG.encode(out);
        self.height.encode(out);
        self.round.encode(out);
        match self.value {
            None => false.encode(out),
            Some(hash) => {
                true.encode(out);
                hash.encode(out);
            }
        }
        matches!(self.kind, VoteKind::Precommit).encode(out);
        self.validator.encode(out);
    }
}

impl Decode for Vote {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (tag, offset) = u8::decode(input)?;
        if tag != VOTE_SIGNING_TAG {
            return Err(CodecError::InvalidValue);
        }
        let (height, offset) = decode_field::<BlockHeight>(input, offset)?;
        let (round, offset) = decode_field::<Round>(input, offset)?;
        let (has_value, offset) = decode_field::<bool>(input, offset)?;
        let (value, offset) = if has_value {
            let (hash, offset) = decode_field::<Hash>(input, offset)?;
            (Some(hash), offset)
        } else {
            (None, offset)
        };
        let (is_precommit, offset) = decode_field::<bool>(input, offset)?;
        let (validator, offset) = decode_field::<Address>(input, offset)?;
        Ok((
            Self {
                height,
                round,
                value,
                kind: if is_precommit {
                    VoteKind::Precommit
                } else {
                    VoteKind::Prevote
                },
                validator,
            },
            offset,
        ))
    }
}

/// Why a piece of [`DuplicateVoteEvidence`] is not evidence of anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceError {
    /// The two votes are from different validators.
    DifferentValidators,
    /// The two votes are for different heights, rounds, or vote kinds —
    /// voting for different things at different times is not
    /// equivocation.
    DifferentSlot,
    /// The two votes are identical: nothing conflicts.
    NotConflicting,
    /// A signature does not verify under the validator's key.
    InvalidSignature,
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::DifferentValidators => "the two votes are from different validators",
            Self::DifferentSlot => "the two votes are for different heights, rounds or kinds",
            Self::NotConflicting => "the two votes do not conflict",
            Self::InvalidSignature => "a vote's signature does not verify",
        })
    }
}

impl std::error::Error for EvidenceError {}

/// Two votes, from one validator, for the same height, round and kind but
/// different values — each carrying that validator's signature. The
/// standard proof of equivocation: it convicts on its own, needing
/// nothing from the chain but the validator's registered public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplicateVoteEvidence {
    pub vote_a: Vote,
    pub signature_a: BlsSignature,
    pub vote_b: Vote,
    pub signature_b: BlsSignature,
}

impl DuplicateVoteEvidence {
    pub const fn validator(&self) -> Address {
        self.vote_a.validator
    }

    /// The height the equivocation happened at.
    pub const fn height(&self) -> BlockHeight {
        self.vote_a.height
    }

    /// Whether this is evidence of the same offence as `other`: the same
    /// validator equivocating in the same slot. Which two of a validator's
    /// several conflicting votes are presented, and in which order, does
    /// not change what they did wrong.
    pub fn same_offence_as(&self, other: &Self) -> bool {
        self.validator() == other.validator()
            && self.vote_a.height == other.vote_a.height
            && self.vote_a.round == other.vote_a.round
            && self.vote_a.kind == other.vote_a.kind
    }

    /// Checks that this really is equivocation by the holder of
    /// `public_key`. Cheap structural checks first, signatures last, so
    /// garbage is refused before any pairing is computed.
    pub fn verify(&self, public_key: &BlsPublicKey) -> Result<(), EvidenceError> {
        let (a, b) = (&self.vote_a, &self.vote_b);
        if a.validator != b.validator {
            return Err(EvidenceError::DifferentValidators);
        }
        if a.height != b.height || a.round != b.round || a.kind != b.kind {
            return Err(EvidenceError::DifferentSlot);
        }
        if a.value == b.value {
            return Err(EvidenceError::NotConflicting);
        }
        for (vote, signature) in [(a, &self.signature_a), (b, &self.signature_b)] {
            verify_aggregate(&[public_key], &vote.signing_bytes(), DST_VOTE, signature)
                .map_err(|_| EvidenceError::InvalidSignature)?;
        }
        Ok(())
    }
}

impl Encode for DuplicateVoteEvidence {
    fn encode(&self, out: &mut Vec<u8>) {
        self.vote_a.encode(out);
        self.signature_a.encode(out);
        self.vote_b.encode(out);
        self.signature_b.encode(out);
    }
}

impl Decode for DuplicateVoteEvidence {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (vote_a, offset) = Vote::decode(input)?;
        let (signature_a, offset) = decode_field::<BlsSignature>(input, offset)?;
        let (vote_b, offset) = decode_field::<Vote>(input, offset)?;
        let (signature_b, offset) = decode_field::<BlsSignature>(input, offset)?;
        Ok((
            Self {
                vote_a,
                signature_a,
                vote_b,
                signature_b,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use crate::codec::decode_exact;
    use blst::min_pk::SecretKey;

    fn keypair(seed: u8) -> (SecretKey, BlsPublicKey) {
        let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let pk = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        (sk, pk)
    }

    fn sign(sk: &SecretKey, vote: &Vote) -> BlsSignature {
        BlsSignature::from_bytes(sk.sign(&vote.signing_bytes(), DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn validator() -> Address {
        Address::from_bytes([7u8; 32])
    }

    fn vote(value: Option<u8>) -> Vote {
        Vote {
            height: BlockHeight(10),
            round: Round(2),
            value: value.map(|b| Hash::from_bytes([b; 32])),
            kind: VoteKind::Prevote,
            validator: validator(),
        }
    }

    fn evidence(sk: &SecretKey, a: Vote, b: Vote) -> DuplicateVoteEvidence {
        DuplicateVoteEvidence {
            signature_a: sign(sk, &a),
            signature_b: sign(sk, &b),
            vote_a: a,
            vote_b: b,
        }
    }

    #[test]
    fn a_vote_round_trips_including_nil() {
        for value in [None, Some(9)] {
            for kind in [VoteKind::Prevote, VoteKind::Precommit] {
                let v = Vote {
                    kind,
                    ..vote(value)
                };
                let mut buf = Vec::new();
                v.encode(&mut buf);
                assert_eq!(decode_exact::<Vote>(&buf).unwrap(), v);
            }
        }
    }

    #[test]
    fn signing_bytes_have_the_layout_chain_consensus_signed_before_this_type_existed() {
        // Guards against the refactor that moved this here changing what
        // gets signed: tag, height, round, has-value, hash, is-precommit,
        // validator — each in canonical little-endian form.
        let v = Vote {
            kind: VoteKind::Precommit,
            ..vote(Some(3))
        };
        let mut expected = vec![0u8]; // VOTE_SIGNING_TAG
        expected.extend_from_slice(&10u64.to_le_bytes());
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&[3u8; 32]);
        expected.push(1);
        expected.extend_from_slice(&[7u8; 32]);
        assert_eq!(v.signing_bytes(), expected);
    }

    #[test]
    fn a_nil_vote_and_a_value_vote_sign_different_bytes() {
        assert_ne!(vote(None).signing_bytes(), vote(Some(0)).signing_bytes());
    }

    #[test]
    fn decoding_rejects_a_wrong_leading_tag() {
        let mut buf = vote(Some(1)).signing_bytes();
        buf[0] = 1;
        assert_eq!(
            decode_exact::<Vote>(&buf),
            Err(CodecError::InvalidValue),
            "a proposal-tagged payload is not a vote"
        );
    }

    #[test]
    fn genuine_equivocation_verifies() {
        let (sk, pk) = keypair(1);
        let ev = evidence(&sk, vote(Some(1)), vote(Some(2)));
        assert_eq!(ev.verify(&pk), Ok(()));
    }

    #[test]
    fn a_nil_vote_against_a_value_vote_is_equivocation_too() {
        let (sk, pk) = keypair(1);
        assert_eq!(evidence(&sk, vote(None), vote(Some(2))).verify(&pk), Ok(()));
    }

    #[test]
    fn the_same_vote_twice_is_not_equivocation() {
        let (sk, pk) = keypair(1);
        assert_eq!(
            evidence(&sk, vote(Some(1)), vote(Some(1))).verify(&pk),
            Err(EvidenceError::NotConflicting)
        );
    }

    #[test]
    fn votes_from_different_validators_are_not_equivocation() {
        let (sk, pk) = keypair(1);
        let other = Vote {
            validator: Address::from_bytes([8u8; 32]),
            ..vote(Some(2))
        };
        assert_eq!(
            evidence(&sk, vote(Some(1)), other).verify(&pk),
            Err(EvidenceError::DifferentValidators)
        );
    }

    #[test]
    fn votes_in_different_slots_are_not_equivocation() {
        let (sk, pk) = keypair(1);
        let variants = [
            Vote {
                height: BlockHeight(11),
                ..vote(Some(2))
            },
            Vote {
                round: Round(3),
                ..vote(Some(2))
            },
            Vote {
                kind: VoteKind::Precommit,
                ..vote(Some(2))
            },
        ];
        for other in variants {
            assert_eq!(
                evidence(&sk, vote(Some(1)), other).verify(&pk),
                Err(EvidenceError::DifferentSlot),
                "{other:?}"
            );
        }
    }

    #[test]
    fn a_signature_from_the_wrong_key_is_rejected() {
        let (sk, _) = keypair(1);
        let (_, other_pk) = keypair(2);
        assert_eq!(
            evidence(&sk, vote(Some(1)), vote(Some(2))).verify(&other_pk),
            Err(EvidenceError::InvalidSignature)
        );
    }

    #[test]
    fn a_swapped_signature_is_rejected() {
        // Each signature only covers its own vote.
        let (sk, pk) = keypair(1);
        let mut ev = evidence(&sk, vote(Some(1)), vote(Some(2)));
        core::mem::swap(&mut ev.signature_a, &mut ev.signature_b);
        assert_eq!(ev.verify(&pk), Err(EvidenceError::InvalidSignature));
    }

    #[test]
    fn a_tampered_vote_no_longer_matches_its_signature() {
        let (sk, pk) = keypair(1);
        let mut ev = evidence(&sk, vote(Some(1)), vote(Some(2)));
        ev.vote_b.value = Some(Hash::from_bytes([9u8; 32]));
        assert_eq!(ev.verify(&pk), Err(EvidenceError::InvalidSignature));
    }

    #[test]
    fn evidence_round_trips() {
        let (sk, _) = keypair(1);
        let ev = evidence(&sk, vote(Some(1)), vote(Some(2)));
        let mut buf = Vec::new();
        ev.encode(&mut buf);
        assert_eq!(decode_exact::<DuplicateVoteEvidence>(&buf).unwrap(), ev);
    }

    #[test]
    fn evidence_truncated_anywhere_is_rejected_not_misparsed() {
        let (sk, _) = keypair(1);
        let mut buf = Vec::new();
        evidence(&sk, vote(Some(1)), vote(Some(2))).encode(&mut buf);
        for len in 0..buf.len() {
            assert!(
                decode_exact::<DuplicateVoteEvidence>(&buf[..len]).is_err(),
                "a {len}-byte prefix must not decode"
            );
        }
    }

    #[test]
    fn the_same_offence_ignores_which_conflicting_votes_and_in_what_order() {
        let (sk, _) = keypair(1);
        let ab = evidence(&sk, vote(Some(1)), vote(Some(2)));
        let ba = evidence(&sk, vote(Some(2)), vote(Some(1)));
        let ac = evidence(&sk, vote(Some(1)), vote(Some(3)));
        assert!(ab.same_offence_as(&ba));
        assert!(ab.same_offence_as(&ac));

        let elsewhere = evidence(
            &sk,
            Vote {
                round: Round(5),
                ..vote(Some(1))
            },
            Vote {
                round: Round(5),
                ..vote(Some(2))
            },
        );
        assert!(
            !ab.same_offence_as(&elsewhere),
            "a different round is a different offence"
        );
    }
}
