//! Proves this chain's real `Context` (`chain_consensus::context::
//! ThrylosContext`, over `chain_consensus::types`' wrappers around
//! `chain-types`' own types) drives a round to commit — the same shape
//! of proof as `malachite_proof_of_life.rs`, but through the real
//! types instead of Malachite's `TestContext`, and with genuine
//! BLS12-381 signing and verification instead of `Signature::test()`
//! stubs: `handle_effect` below signs with each validator's real
//! private key and `Effect::VerifySignature` is answered by actually
//! calling `chain_types::bls::verify_aggregate`, so a tampered
//! signature would be caught here rather than rubber-stamped.
//!
//! Proposer selection is plain round-robin
//! (`ThrylosContext::select_proposer`) — explicitly insecure, see
//! `crate`'s doc comment. This test drives whichever round-0 proposer
//! that selects, rather than hard-coding one, so it stays correct if
//! the round-robin formula ever changes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use blst::min_pk::SecretKey;
use chain_consensus::context::ThrylosContext;
use chain_consensus::types::{
    ConsensusAddress, ConsensusHeight, ConsensusProposal, ConsensusValidator,
    ConsensusValidatorSet, ConsensusValue, ConsensusVote,
};
use chain_types::bls::{BlsPublicKey, BlsSignature, DST_VOTE};
use chain_types::codec::Encode;
use chain_types::{Address, BlockHeight, Hash};
use malachite_core_consensus::{
    process, ConsensusMsg, Effect, Error, Input, Params, Resumable, State,
};
use malachite_core_types::{
    Context as _, NilOrVal, Round, SignedProposal, SignedVote, Validity, ValueOrigin,
};
use malachite_metrics::Metrics;

fn drop_result(result: Result<(), Error<ThrylosContext>>) {
    result.expect("consensus step failed");
}

/// A validator plus the private key backing it — kept together only in
/// this test's harness, never inside `Context` itself (real signing is
/// `chain-signer`'s job, kept isolated, see `crate::types`'
/// `ConsensusSigningScheme` doc comment).
struct Keyed {
    validator: ConsensusValidator,
    secret_key: SecretKey,
}

fn make_validator(seed_byte: u8) -> Keyed {
    let secret_key = SecretKey::key_gen(&[seed_byte; 32], &[]).unwrap();
    let public_key = BlsPublicKey::from_bytes(secret_key.sk_to_pk().to_bytes()).unwrap();
    let validator = ConsensusValidator {
        address: ConsensusAddress(Address::from_bytes([seed_byte; 32])),
        public_key,
        voting_power: 1,
    };
    Keyed {
        validator,
        secret_key,
    }
}

fn sign(secret_key: &SecretKey, bytes: &[u8]) -> BlsSignature {
    BlsSignature::from_bytes(secret_key.sign(bytes, DST_VOTE, &[]).to_bytes()).unwrap()
}

fn make_state(
    validator_set: ConsensusValidatorSet,
    height: ConsensusHeight,
    my_address: ConsensusAddress,
) -> State<ThrylosContext> {
    State::new(
        ThrylosContext::new(),
        height,
        validator_set,
        Params {
            address: my_address,
            threshold_params: Default::default(),
            value_payload: malachite_core_types::ValuePayload::ProposalOnly,
            enabled: true,
        },
        1_000,
        1_000,
    )
}

/// Answers every effect the engine can yield during a plain,
/// non-Byzantine round, signing and verifying for real: `keyed` holds
/// every validator's private key, keyed by address, so `SignVote`/
/// `SignProposal` can find the right key from the message's own
/// `validator_address`, and `VerifySignature` genuinely checks the
/// signature against the canonical encoding of the signed message.
fn handle_effect(
    effect: Effect<ThrylosContext>,
    keyed: &[Keyed],
) -> Result<malachite_core_consensus::Resume<ThrylosContext>, ()> {
    use malachite_core_consensus::Resume;
    use Effect::*;

    let key_for = |address: &ConsensusAddress| -> &SecretKey {
        &keyed
            .iter()
            .find(|k| &k.validator.address == address)
            .expect("unknown validator address")
            .secret_key
    };

    Ok(match effect {
        SignVote(vote, r) => {
            let mut bytes = Vec::new();
            vote.encode(&mut bytes);
            let signature = sign(key_for(&vote.validator_address), &bytes);
            r.resume_with(SignedVote::new(vote, signature))
        }
        SignProposal(proposal, r) => {
            let mut bytes = Vec::new();
            proposal.encode(&mut bytes);
            let signature = sign(key_for(&proposal.validator_address), &bytes);
            r.resume_with(SignedProposal::new(proposal, signature))
        }
        VerifySignature(signed, public_key, r) => {
            let mut bytes = Vec::new();
            match &signed.message {
                ConsensusMsg::Vote(vote) => vote.encode(&mut bytes),
                ConsensusMsg::Proposal(proposal) => proposal.encode(&mut bytes),
            }
            let valid = chain_types::bls::verify_aggregate(
                &[&public_key],
                &bytes,
                DST_VOTE,
                &signed.signature,
            )
            .is_ok();
            r.resume_with(valid)
        }
        VerifyCommitCertificate(_, _, _, r) => r.resume_with(Ok(())),
        _ => Resume::Continue,
    })
}

#[test]
fn drives_a_single_round_to_commit_with_real_context_and_bls() {
    let keyed: Vec<Keyed> = (1u8..=4).map(make_validator).collect();
    let validators: Vec<ConsensusValidator> = keyed.iter().map(|k| k.validator.clone()).collect();
    let validator_set = ConsensusValidatorSet::new(validators.clone());

    let height = ConsensusHeight(BlockHeight(1));
    let ctx = ThrylosContext::new();
    let proposer = ctx
        .select_proposer(&validator_set, height, Round::new(0))
        .clone();

    let value = ConsensusValue(Hash::from_bytes([42u8; 32]));

    let mut state = make_state(
        ConsensusValidatorSet::new(validators.clone()),
        height,
        proposer.address,
    );
    let metrics = Metrics::new();

    drop_result(process!(
        input: Input::StartHeight(
            height,
            ConsensusValidatorSet::new(validators.clone()),
            false,
            None,
            Default::default(),
        ),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect, &keyed)
    ));

    let proposal = ConsensusProposal {
        height,
        round: Round::new(0),
        value,
        pol_round: Round::Nil,
        validator_address: proposer.address,
    };
    let mut proposal_bytes = Vec::new();
    proposal.encode(&mut proposal_bytes);
    let proposer_key = &keyed
        .iter()
        .find(|k| k.validator.address == proposer.address)
        .unwrap()
        .secret_key;
    let signed_proposal =
        SignedProposal::new(proposal.clone(), sign(proposer_key, &proposal_bytes));

    drop_result(process!(
        input: Input::Proposal(signed_proposal),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect, &keyed)
    ));

    drop_result(process!(
        input: Input::ProposedValue(
            malachite_core_consensus::ProposedValue {
                height,
                round: Round::new(0),
                valid_round: Round::Nil,
                proposer: proposer.address,
                value,
                validity: Validity::Valid,
            },
            ValueOrigin::Consensus,
        ),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect, &keyed)
    ));

    for keyed_validator in &keyed {
        let vote = ConsensusVote {
            height,
            round: Round::new(0),
            value_id: NilOrVal::Val(value.0),
            vote_type: malachite_core_types::VoteType::Prevote,
            validator_address: keyed_validator.validator.address,
            extension: None,
        };
        let mut bytes = Vec::new();
        vote.encode(&mut bytes);
        let signed_vote = SignedVote::new(vote, sign(&keyed_validator.secret_key, &bytes));
        drop_result(process!(
            input: Input::Vote(signed_vote),
            state: &mut state,
            metrics: &metrics,
            with: effect => handle_effect(effect, &keyed)
        ));
    }

    for keyed_validator in &keyed {
        let vote = ConsensusVote {
            height,
            round: Round::new(0),
            value_id: NilOrVal::Val(value.0),
            vote_type: malachite_core_types::VoteType::Precommit,
            validator_address: keyed_validator.validator.address,
            extension: None,
        };
        let mut bytes = Vec::new();
        vote.encode(&mut bytes);
        let signed_vote = SignedVote::new(vote, sign(&keyed_validator.secret_key, &bytes));
        drop_result(process!(
            input: Input::Vote(signed_vote),
            state: &mut state,
            metrics: &metrics,
            with: effect => handle_effect(effect, &keyed)
        ));
    }

    assert!(
        state.driver.step_is_commit(),
        "four honest validators voting for the same value in round 0 must reach commit"
    );
}
