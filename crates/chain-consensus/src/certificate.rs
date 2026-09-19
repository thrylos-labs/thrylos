//! Verifying the certificates consensus messages carry.
//!
//! Malachite's core asks its host to verify every certificate it is handed
//! (`Effect::VerifyCommitCertificate`, `VerifyPolkaCertificate`,
//! `VerifyRoundCertificate`) and trusts the answer, so this is where a
//! forged certificate is stopped. Each is a list of validators' signed
//! votes, and each check is the same in four parts:
//!
//! - every signer is in the validator set *the caller supplies* — the
//!   canonical set for the height, never anything the certificate claims
//!   (`docs/spec.md`: "verified against the canonical participation
//!   bitfield, never against a set the message itself supplies");
//! - no signer is counted twice;
//! - every signature verifies, as that validator's vote for exactly the
//!   height, round and value the certificate is for;
//! - and the signers' voting power clears the threshold.
//!
//! A vote's signed bytes include its validator's address
//! ([`ConsensusVote`]), so a signature cannot be attributed to a different
//! validator than the one who made it, and a signature for one round,
//! height or value never verifies as another.
//!
//! The signatures are verified one at a time. They cannot be aggregated
//! into a single check because each covers different bytes (its own
//! address is in them); at a few hundred microseconds each that is a
//! known cost — 128 validators is on the order of tens of milliseconds
//! against the spec's 20 ms aggregate target — and the remedy, signing an
//! address-free message so one aggregate verifies a whole round, is a
//! change to what validators sign, not something to fold in here.

// `CertificateError` is Malachite's type and is large because it carries whole
// signed messages. The verifiers return it as it is, matching what Malachite's
// own callers expect; they run once per certificate, not per message.
#![allow(clippy::result_large_err)]

use chain_types::bls::{verify_aggregate, BlsSignature, DST_VOTE};
use chain_types::codec::Encode;
use chain_types::collections::BTreeSet;
use chain_types::Hash;
use malachite_core_consensus::ThresholdParams;
use malachite_core_types::{
    CertificateError, CommitCertificate, NilOrVal, PolkaCertificate, Round, RoundCertificate,
    RoundCertificateType, ThresholdParam, Validator as _, ValidatorSet as _, VoteType, VotingPower,
};

use crate::context::ThrylosContext;
use crate::types::{ConsensusAddress, ConsensusHeight, ConsensusValidatorSet, ConsensusVote};

type Error = CertificateError<ThrylosContext>;

/// One signature to check: whose it claims to be, and what it claims to be
/// a signature on.
struct Entry<'a> {
    address: &'a ConsensusAddress,
    vote_type: VoteType,
    value_id: NilOrVal<Hash>,
    signature: &'a BlsSignature,
}

/// What the shared check found wrong, by entry.
enum Fault {
    Unknown(ConsensusAddress),
    Duplicate(ConsensusAddress),
    BadSignature(usize),
    Overflow {
        signed: VotingPower,
        added: VotingPower,
    },
    NotEnough {
        signed: VotingPower,
        total: VotingPower,
        expected: VotingPower,
    },
}

/// The least voting power out of `total` that `threshold` counts as met:
/// strictly more than `numerator / denominator` of it.
fn power_needed(threshold: ThresholdParam, total: VotingPower) -> VotingPower {
    let scaled = u128::from(total).saturating_mul(u128::from(threshold.numerator));
    let floor = scaled
        .checked_div(u128::from(threshold.denominator))
        .unwrap_or(u128::MAX);
    u64::try_from(floor.saturating_add(1)).unwrap_or(u64::MAX)
}

fn check(
    height: ConsensusHeight,
    round: Round,
    set: &ConsensusValidatorSet,
    threshold: ThresholdParam,
    entries: &[Entry<'_>],
) -> Result<(), Fault> {
    let mut seen = BTreeSet::new();
    let mut signed: VotingPower = 0;
    for (index, entry) in entries.iter().enumerate() {
        let Some(validator) = set.get_by_address(entry.address) else {
            return Err(Fault::Unknown(*entry.address));
        };
        if !seen.insert(*entry.address) {
            return Err(Fault::Duplicate(*entry.address));
        }
        let vote = ConsensusVote {
            height,
            round,
            value_id: entry.value_id,
            vote_type: entry.vote_type,
            validator_address: *entry.address,
            extension: None,
        };
        let mut bytes = Vec::new();
        vote.encode(&mut bytes);
        if verify_aggregate(&[validator.public_key()], &bytes, DST_VOTE, entry.signature).is_err() {
            return Err(Fault::BadSignature(index));
        }
        let added = validator.voting_power();
        signed = signed
            .checked_add(added)
            .ok_or(Fault::Overflow { signed, added })?;
    }

    let total = set.total_voting_power();
    if !threshold.is_met(signed, total) {
        return Err(Fault::NotEnough {
            signed,
            total,
            expected: power_needed(threshold, total),
        });
    }
    Ok(())
}

fn common(fault: Fault) -> Error {
    match fault {
        Fault::Unknown(address) => CertificateError::UnknownValidator(address),
        Fault::Duplicate(address) => CertificateError::DuplicateVote(address),
        Fault::Overflow { signed, added } => {
            CertificateError::VotingPowerOverflow { signed, added }
        }
        Fault::NotEnough {
            signed,
            total,
            expected,
        } => CertificateError::NotEnoughVotingPower {
            signed,
            total,
            expected,
        },
        // Callers map this themselves, to the variant that names the
        // offending signature.
        Fault::BadSignature(_) => CertificateError::VerificationError(None),
    }
}

/// Verifies that `certificate` is a quorum's precommits for its value at
/// its height and round.
pub fn verify_commit_certificate(
    certificate: &CommitCertificate<ThrylosContext>,
    set: &ConsensusValidatorSet,
    params: ThresholdParams,
) -> Result<(), Error> {
    let entries: Vec<Entry<'_>> = certificate
        .commit_signatures
        .iter()
        .map(|s| Entry {
            address: &s.address,
            vote_type: VoteType::Precommit,
            value_id: NilOrVal::Val(certificate.value_id),
            signature: &s.signature,
        })
        .collect();
    check(
        certificate.height,
        certificate.round,
        set,
        params.quorum,
        &entries,
    )
    .map_err(|fault| match fault {
        Fault::BadSignature(index) => match certificate.commit_signatures.get(index) {
            Some(signature) => CertificateError::InvalidCommitSignature(signature.clone()),
            None => CertificateError::VerificationError(None),
        },
        other => common(other),
    })
}

/// Verifies that `certificate` is a quorum's prevotes for its value at its
/// height and round.
pub fn verify_polka_certificate(
    certificate: &PolkaCertificate<ThrylosContext>,
    set: &ConsensusValidatorSet,
    params: ThresholdParams,
) -> Result<(), Error> {
    let entries: Vec<Entry<'_>> = certificate
        .polka_signatures
        .iter()
        .map(|s| Entry {
            address: &s.address,
            vote_type: VoteType::Prevote,
            value_id: NilOrVal::Val(certificate.value_id),
            signature: &s.signature,
        })
        .collect();
    check(
        certificate.height,
        certificate.round,
        set,
        params.quorum,
        &entries,
    )
    .map_err(|fault| match fault {
        Fault::BadSignature(index) => match certificate.polka_signatures.get(index) {
            Some(signature) => CertificateError::InvalidPolkaSignature(signature.clone()),
            None => CertificateError::VerificationError(None),
        },
        other => common(other),
    })
}

/// Verifies a round certificate: for a skip, more than a third of the
/// power voting at the round; for a precommit certificate, a quorum's
/// precommits (of any value or nil) and only precommits.
pub fn verify_round_certificate(
    certificate: &RoundCertificate<ThrylosContext>,
    set: &ConsensusValidatorSet,
    params: ThresholdParams,
) -> Result<(), Error> {
    let threshold = match certificate.cert_type {
        RoundCertificateType::Skip => params.honest,
        RoundCertificateType::Precommit => {
            if let Some(wrong) = certificate
                .round_signatures
                .iter()
                .find(|s| s.vote_type != VoteType::Precommit)
            {
                return Err(CertificateError::InvalidVoteType(wrong.address));
            }
            params.quorum
        }
    };
    let entries: Vec<Entry<'_>> = certificate
        .round_signatures
        .iter()
        .map(|s| Entry {
            address: &s.address,
            vote_type: s.vote_type,
            value_id: s.value_id,
            signature: &s.signature,
        })
        .collect();
    check(
        certificate.height,
        certificate.round,
        set,
        threshold,
        &entries,
    )
    .map_err(|fault| match fault {
        Fault::BadSignature(index) => match certificate.round_signatures.get(index) {
            Some(signature) => CertificateError::InvalidRoundSignature(signature.clone()),
            None => CertificateError::VerificationError(None),
        },
        other => common(other),
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use crate::types::ConsensusValidator;
    use blst::min_pk::SecretKey;
    use chain_types::{Address, BlockHeight, BlsPublicKey};
    use malachite_core_types::{CommitSignature, PolkaSignature, RoundSignature};

    struct Keyed {
        address: ConsensusAddress,
        secret: SecretKey,
        power: u64,
    }

    fn keyed(powers: &[u64]) -> Vec<Keyed> {
        powers
            .iter()
            .enumerate()
            .map(|(i, power)| {
                let byte = u8::try_from(i).unwrap() + 1;
                Keyed {
                    address: ConsensusAddress(Address::from_bytes([byte; 32])),
                    secret: SecretKey::key_gen(&[byte; 32], &[]).unwrap(),
                    power: *power,
                }
            })
            .collect()
    }

    fn set_of(keyed: &[Keyed]) -> ConsensusValidatorSet {
        ConsensusValidatorSet::new(
            keyed
                .iter()
                .map(|k| ConsensusValidator {
                    address: k.address,
                    public_key: BlsPublicKey::from_bytes(k.secret.sk_to_pk().to_bytes()).unwrap(),
                    voting_power: k.power,
                })
                .collect(),
        )
    }

    const HEIGHT: ConsensusHeight = ConsensusHeight(BlockHeight(9));
    fn round() -> Round {
        Round::new(2)
    }
    fn value() -> Hash {
        Hash::from_bytes([7u8; 32])
    }

    /// `signer`'s signature on a vote `as_validator` would cast.
    fn sign(
        signer: &Keyed,
        as_validator: &ConsensusAddress,
        height: ConsensusHeight,
        round: Round,
        value_id: NilOrVal<Hash>,
        vote_type: VoteType,
    ) -> BlsSignature {
        let vote = ConsensusVote {
            height,
            round,
            value_id,
            vote_type,
            validator_address: *as_validator,
            extension: None,
        };
        let mut bytes = Vec::new();
        vote.encode(&mut bytes);
        BlsSignature::from_bytes(signer.secret.sign(&bytes, DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn honest(k: &Keyed, vote_type: VoteType) -> BlsSignature {
        sign(
            k,
            &k.address,
            HEIGHT,
            round(),
            NilOrVal::Val(value()),
            vote_type,
        )
    }

    fn commit(signers: &[&Keyed]) -> CommitCertificate<ThrylosContext> {
        CommitCertificate {
            height: HEIGHT,
            round: round(),
            value_id: value(),
            commit_signatures: signers
                .iter()
                .map(|k| CommitSignature::new(k.address, honest(k, VoteType::Precommit)))
                .collect(),
        }
    }

    fn polka(signers: &[&Keyed]) -> PolkaCertificate<ThrylosContext> {
        PolkaCertificate {
            height: HEIGHT,
            round: round(),
            value_id: value(),
            polka_signatures: signers
                .iter()
                .map(|k| PolkaSignature::new(k.address, honest(k, VoteType::Prevote)))
                .collect(),
        }
    }

    fn params() -> ThresholdParams {
        ThresholdParams::default()
    }

    // ---- commit ----------------------------------------------------------

    #[test]
    fn a_quorum_of_precommits_is_a_valid_commit_certificate() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        assert!(verify_commit_certificate(&commit(&[&k[0], &k[1], &k[2]]), &set, params()).is_ok());
        assert!(
            verify_commit_certificate(&commit(&[&k[0], &k[1], &k[2], &k[3]]), &set, params())
                .is_ok()
        );
    }

    #[test]
    fn less_than_a_quorum_is_refused_and_exactly_two_thirds_is_not_enough() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        assert!(matches!(
            verify_commit_certificate(&commit(&[&k[0], &k[1]]), &set, params()),
            Err(CertificateError::NotEnoughVotingPower {
                signed: 2,
                total: 4,
                expected: 3
            })
        ));
        // Three equal validators: two is exactly two thirds, which is not
        // *more than* two thirds.
        let k3 = keyed(&[1, 1, 1]);
        let set3 = set_of(&k3);
        assert!(matches!(
            verify_commit_certificate(&commit(&[&k3[0], &k3[1]]), &set3, params()),
            Err(CertificateError::NotEnoughVotingPower {
                signed: 2,
                total: 3,
                expected: 3
            })
        ));
        assert!(
            verify_commit_certificate(&commit(&[&k3[0], &k3[1], &k3[2]]), &set3, params()).is_ok()
        );
    }

    #[test]
    fn a_quorum_is_of_voting_power_not_of_headcount() {
        let k = keyed(&[50, 30, 20]);
        let set = set_of(&k);
        // 50 + 30 of 100: a quorum by power with two of three validators.
        assert!(verify_commit_certificate(&commit(&[&k[0], &k[1]]), &set, params()).is_ok());
        // The two smaller ones together are two of three and only 50 of 100.
        assert!(verify_commit_certificate(&commit(&[&k[1], &k[2]]), &set, params()).is_err());
        assert!(verify_commit_certificate(&commit(&[&k[0]]), &set, params()).is_err());
    }

    #[test]
    fn a_signature_by_the_wrong_key_is_refused_and_named() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let mut cert = commit(&[&k[0], &k[1], &k[2]]);
        // Validator 2's slot signed by validator 3's key.
        cert.commit_signatures[2].signature = sign(
            &k[3],
            &k[2].address,
            HEIGHT,
            round(),
            NilOrVal::Val(value()),
            VoteType::Precommit,
        );
        let result = verify_commit_certificate(&cert, &set, params());
        assert!(
            matches!(
                &result,
                Err(CertificateError::InvalidCommitSignature(bad)) if bad.address == k[2].address
            ),
            "{result:?}"
        );
    }

    #[test]
    fn a_signature_cannot_be_moved_to_another_validators_slot() {
        // The signed bytes include the validator's address, so validator 0's
        // genuine precommit does not count for validator 1.
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let mut cert = commit(&[&k[0], &k[1], &k[2]]);
        cert.commit_signatures[1].signature = cert.commit_signatures[0].signature;
        assert!(matches!(
            verify_commit_certificate(&cert, &set, params()),
            Err(CertificateError::InvalidCommitSignature(_))
        ));
    }

    #[test]
    fn signatures_for_another_height_round_value_or_kind_do_not_verify() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let other_height = ConsensusHeight(BlockHeight(10));
        let signatures = [
            sign(
                &k[2],
                &k[2].address,
                other_height,
                round(),
                NilOrVal::Val(value()),
                VoteType::Precommit,
            ),
            sign(
                &k[2],
                &k[2].address,
                HEIGHT,
                Round::new(3),
                NilOrVal::Val(value()),
                VoteType::Precommit,
            ),
            sign(
                &k[2],
                &k[2].address,
                HEIGHT,
                round(),
                NilOrVal::Val(Hash::from_bytes([8; 32])),
                VoteType::Precommit,
            ),
            sign(
                &k[2],
                &k[2].address,
                HEIGHT,
                round(),
                NilOrVal::Nil,
                VoteType::Precommit,
            ),
            sign(
                &k[2],
                &k[2].address,
                HEIGHT,
                round(),
                NilOrVal::Val(value()),
                VoteType::Prevote,
            ),
        ];
        for signature in signatures {
            let mut cert = commit(&[&k[0], &k[1], &k[2]]);
            cert.commit_signatures[2].signature = signature;
            assert!(
                matches!(
                    verify_commit_certificate(&cert, &set, params()),
                    Err(CertificateError::InvalidCommitSignature(_))
                ),
                "a signature for some other vote was accepted"
            );
        }
    }

    #[test]
    fn a_certificate_naming_a_different_value_than_was_signed_is_refused() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let mut cert = commit(&[&k[0], &k[1], &k[2]]);
        cert.value_id = Hash::from_bytes([99; 32]);
        assert!(verify_commit_certificate(&cert, &set, params()).is_err());
        let mut cert = commit(&[&k[0], &k[1], &k[2]]);
        cert.height = ConsensusHeight(BlockHeight(10));
        assert!(verify_commit_certificate(&cert, &set, params()).is_err());
        let mut cert = commit(&[&k[0], &k[1], &k[2]]);
        cert.round = Round::new(3);
        assert!(verify_commit_certificate(&cert, &set, params()).is_err());
    }

    #[test]
    fn a_validator_counted_twice_is_refused() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        // Two genuine copies of one precommit, and a third from another
        // validator, would reach 3 of 4 if the repeat were counted.
        let cert = commit(&[&k[0], &k[0], &k[1]]);
        assert!(matches!(
            verify_commit_certificate(&cert, &set, params()),
            Err(CertificateError::DuplicateVote(a)) if a == k[0].address
        ));
    }

    #[test]
    fn a_signer_outside_the_supplied_set_is_refused() {
        let k = keyed(&[1, 1, 1, 1, 1]);
        let set = set_of(&k[..4]); // the fifth is not a validator
        let cert = commit(&[&k[0], &k[1], &k[4]]);
        assert!(matches!(
            verify_commit_certificate(&cert, &set, params()),
            Err(CertificateError::UnknownValidator(a)) if a == k[4].address
        ));
    }

    #[test]
    fn a_certificate_is_only_as_good_as_the_set_it_is_checked_against() {
        // Signed by a real quorum of one set, presented against another
        // whose members hold different keys: nothing verifies.
        let signers = keyed(&[1, 1, 1, 1]);
        let cert = commit(&[&signers[0], &signers[1], &signers[2]]);
        let mut other = keyed(&[1, 1, 1, 1]);
        for (i, k) in other.iter_mut().enumerate() {
            k.secret = SecretKey::key_gen(&[u8::try_from(i).unwrap() + 100; 32], &[]).unwrap();
        }
        assert!(verify_commit_certificate(&cert, &set_of(&other), params()).is_err());
    }

    #[test]
    fn signed_power_that_would_overflow_is_an_error_not_a_wrap() {
        let k = keyed(&[u64::MAX, u64::MAX, 1]);
        let set = set_of(&k);
        let cert = commit(&[&k[0], &k[1]]);
        assert!(matches!(
            verify_commit_certificate(&cert, &set, params()),
            Err(CertificateError::VotingPowerOverflow { .. })
        ));
    }

    #[test]
    fn an_empty_certificate_is_not_a_quorum() {
        let k = keyed(&[1, 1, 1]);
        assert!(matches!(
            verify_commit_certificate(&commit(&[]), &set_of(&k), params()),
            Err(CertificateError::NotEnoughVotingPower { signed: 0, .. })
        ));
    }

    // ---- polka -----------------------------------------------------------

    #[test]
    fn a_quorum_of_prevotes_is_a_valid_polka_and_a_precommit_is_not_a_prevote() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        assert!(verify_polka_certificate(&polka(&[&k[0], &k[1], &k[2]]), &set, params()).is_ok());
        assert!(matches!(
            verify_polka_certificate(&polka(&[&k[0], &k[1]]), &set, params()),
            Err(CertificateError::NotEnoughVotingPower { .. })
        ));

        // Precommits presented as prevotes do not verify.
        let mut cert = polka(&[&k[0], &k[1], &k[2]]);
        cert.polka_signatures[0].signature = honest(&k[0], VoteType::Precommit);
        assert!(matches!(
            verify_polka_certificate(&cert, &set, params()),
            Err(CertificateError::InvalidPolkaSignature(_))
        ));
    }

    // ---- round -----------------------------------------------------------

    fn round_cert(
        cert_type: RoundCertificateType,
        signers: &[(&Keyed, VoteType, NilOrVal<Hash>)],
    ) -> RoundCertificate<ThrylosContext> {
        RoundCertificate {
            height: HEIGHT,
            round: round(),
            cert_type,
            round_signatures: signers
                .iter()
                .map(|(k, vote_type, value_id)| {
                    RoundSignature::new(
                        *vote_type,
                        *value_id,
                        k.address,
                        sign(k, &k.address, HEIGHT, round(), *value_id, *vote_type),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn a_skip_certificate_needs_more_than_a_third_and_accepts_any_votes() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let nil = NilOrVal::Nil;
        let val = NilOrVal::Val(value());
        let two = round_cert(
            RoundCertificateType::Skip,
            &[
                (&k[0], VoteType::Prevote, nil),
                (&k[1], VoteType::Precommit, val),
            ],
        );
        assert!(
            verify_round_certificate(&two, &set, params()).is_ok(),
            "2 of 4 is over a third"
        );

        let one = round_cert(
            RoundCertificateType::Skip,
            &[(&k[0], VoteType::Prevote, nil)],
        );
        assert!(matches!(
            verify_round_certificate(&one, &set, params()),
            Err(CertificateError::NotEnoughVotingPower {
                signed: 1,
                total: 4,
                expected: 2
            })
        ));
    }

    #[test]
    fn a_precommit_round_certificate_needs_a_quorum_of_precommits_and_only_precommits() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let nil = NilOrVal::Nil;
        let ok = round_cert(
            RoundCertificateType::Precommit,
            &[
                (&k[0], VoteType::Precommit, nil),
                (&k[1], VoteType::Precommit, NilOrVal::Val(value())),
                (&k[2], VoteType::Precommit, nil),
            ],
        );
        assert!(verify_round_certificate(&ok, &set, params()).is_ok());

        let with_prevote = round_cert(
            RoundCertificateType::Precommit,
            &[
                (&k[0], VoteType::Precommit, nil),
                (&k[1], VoteType::Prevote, nil),
                (&k[2], VoteType::Precommit, nil),
            ],
        );
        assert!(matches!(
            verify_round_certificate(&with_prevote, &set, params()),
            Err(CertificateError::InvalidVoteType(a)) if a == k[1].address
        ));

        let too_few = round_cert(
            RoundCertificateType::Precommit,
            &[
                (&k[0], VoteType::Precommit, nil),
                (&k[1], VoteType::Precommit, nil),
            ],
        );
        assert!(matches!(
            verify_round_certificate(&too_few, &set, params()),
            Err(CertificateError::NotEnoughVotingPower { .. })
        ));
    }

    #[test]
    fn a_round_signature_claiming_a_different_vote_than_was_signed_is_refused() {
        let k = keyed(&[1, 1, 1, 1]);
        let set = set_of(&k);
        let mut cert = round_cert(
            RoundCertificateType::Skip,
            &[
                (&k[0], VoteType::Prevote, NilOrVal::Nil),
                (&k[1], VoteType::Prevote, NilOrVal::Nil),
            ],
        );
        // Claims the vote was for a value; the signature covers nil.
        cert.round_signatures[1].value_id = NilOrVal::Val(value());
        assert!(matches!(
            verify_round_certificate(&cert, &set, params()),
            Err(CertificateError::InvalidRoundSignature(_))
        ));
    }

    #[test]
    fn the_power_needed_is_the_least_that_strictly_exceeds_the_threshold() {
        assert_eq!(power_needed(ThresholdParam::TWO_F_PLUS_ONE, 3), 3);
        assert_eq!(power_needed(ThresholdParam::TWO_F_PLUS_ONE, 4), 3);
        assert_eq!(power_needed(ThresholdParam::TWO_F_PLUS_ONE, 100), 67);
        assert_eq!(power_needed(ThresholdParam::F_PLUS_ONE, 4), 2);
        assert_eq!(power_needed(ThresholdParam::F_PLUS_ONE, 3), 2);
        // floor(2 * u64::MAX / 3) + 1, computed without overflow.
        assert_eq!(
            power_needed(ThresholdParam::TWO_F_PLUS_ONE, u64::MAX),
            12_297_829_382_473_034_411
        );
    }
}
