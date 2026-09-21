//! A real double vote, driven through the real consensus engine
//! (`ThrylosContext`, real BLS signatures verified by the effect
//! handler), must come out as `DuplicateVoteEvidence` that convicts the
//! offender — and an honest round must produce none.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use blst::min_pk::SecretKey;
use chain_consensus::context::ThrylosContext;
use chain_consensus::evidence::duplicate_vote_evidence;
use chain_consensus::types::{
    ConsensusAddress, ConsensusHeight, ConsensusValidator, ConsensusValidatorSet, ConsensusVote,
};
use chain_types::bls::{BlsPublicKey, BlsSignature, DST_VOTE};
use chain_types::codec::{decode_exact, Encode};
use chain_types::{Address, BlockHeight, ChainId, DuplicateVoteEvidence, Hash};

/// The chain the tests' votes are signed for, and their context runs on.
const CHAIN: ChainId = ChainId(1);

use malachite_core_consensus::{
    process, ConsensusMsg, Effect, Error, Input, MisbehaviorEvidence, Params, Resumable, State,
};
use malachite_core_types::{NilOrVal, Round, SignedProposal, SignedVote};
use malachite_metrics::Metrics;

fn ok(result: Result<(), Error<ThrylosContext>>) {
    result.expect("consensus step failed");
}

struct Keyed {
    validator: ConsensusValidator,
    secret_key: SecretKey,
}

fn make_validator(seed: u8) -> Keyed {
    let secret_key = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    Keyed {
        validator: ConsensusValidator {
            address: ConsensusAddress(Address::from_bytes([seed; 32])),
            public_key: BlsPublicKey::from_bytes(secret_key.sk_to_pk().to_bytes()).unwrap(),
            voting_power: 1,
        },
        secret_key,
    }
}

fn sign(key: &SecretKey, bytes: &[u8]) -> BlsSignature {
    BlsSignature::from_bytes(key.sign(bytes, DST_VOTE, &[]).to_bytes()).unwrap()
}

fn handle_effect(
    effect: Effect<ThrylosContext>,
    keyed: &[Keyed],
) -> Result<malachite_core_consensus::Resume<ThrylosContext>, ()> {
    use malachite_core_consensus::Resume;
    use Effect::*;

    let key_for = |address: &ConsensusAddress| {
        &keyed
            .iter()
            .find(|k| &k.validator.address == address)
            .expect("unknown validator")
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
        // Real verification: the evidence only means anything if the
        // engine genuinely checked both signatures before accepting them.
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

fn prevote(offender: &Keyed, value: u8) -> SignedVote<ThrylosContext> {
    let vote = ConsensusVote {
        chain_id: CHAIN,
        height: ConsensusHeight(BlockHeight(1)),
        round: Round::new(0),
        value_id: NilOrVal::Val(Hash::from_bytes([value; 32])),
        vote_type: malachite_core_types::VoteType::Prevote,
        validator_address: offender.validator.address,
        extension: None,
    };
    let mut bytes = Vec::new();
    vote.encode(&mut bytes);
    SignedVote::new(vote, sign(&offender.secret_key, &bytes))
}

/// A started height with four validators, plus the harness.
fn started() -> (Vec<Keyed>, State<ThrylosContext>, Metrics) {
    let keyed: Vec<Keyed> = (1u8..=4).map(make_validator).collect();
    let validators: Vec<ConsensusValidator> = keyed.iter().map(|k| k.validator.clone()).collect();
    let height = ConsensusHeight(BlockHeight(1));
    let mut state = State::new(
        ThrylosContext::new(CHAIN),
        height,
        ConsensusValidatorSet::new(validators.clone()),
        Params {
            address: validators.first().unwrap().address,
            threshold_params: Default::default(),
            value_payload: malachite_core_types::ValuePayload::ProposalOnly,
            enabled: true,
        },
        1_000,
        1_000,
    );
    let metrics = Metrics::new();
    ok(process!(
        input: Input::StartHeight(
            height,
            ConsensusValidatorSet::new(validators),
            false,
            None,
            Default::default(),
        ),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect, &keyed)
    ));
    (keyed, state, metrics)
}

fn feed(
    state: &mut State<ThrylosContext>,
    metrics: &Metrics,
    keyed: &[Keyed],
    vote: SignedVote<ThrylosContext>,
) {
    ok(process!(
        input: Input::Vote(vote),
        state: state,
        metrics: metrics,
        with: effect => handle_effect(effect, keyed)
    ));
}

fn take_evidence(state: &mut State<ThrylosContext>) -> MisbehaviorEvidence<ThrylosContext> {
    MisbehaviorEvidence {
        proposals: state.driver.take_proposal_evidence(),
        votes: state.driver.take_vote_evidence(),
    }
}

#[test]
fn a_double_vote_becomes_evidence_that_convicts_the_offender() {
    let (keyed, mut state, metrics) = started();
    let offender = keyed.get(1).unwrap();

    feed(&mut state, &metrics, &keyed, prevote(offender, 0xAA));
    feed(&mut state, &metrics, &keyed, prevote(offender, 0xBB));

    let evidence = duplicate_vote_evidence(&take_evidence(&mut state));
    assert_eq!(evidence.len(), 1, "one equivocation, one piece of evidence");
    let found = evidence.first().unwrap();

    assert_eq!(found.validator(), offender.validator.address.0);
    assert_eq!(found.height(), BlockHeight(1));
    assert_eq!(
        found.verify(&offender.validator.public_key, CHAIN),
        Ok(()),
        "the evidence must stand up on its own, without the consensus engine"
    );
}

#[test]
fn the_evidence_does_not_convict_anyone_else() {
    let (keyed, mut state, metrics) = started();
    let offender = keyed.get(1).unwrap();
    let bystander = keyed.get(2).unwrap();

    feed(&mut state, &metrics, &keyed, prevote(offender, 0xAA));
    feed(&mut state, &metrics, &keyed, prevote(offender, 0xBB));

    let evidence = duplicate_vote_evidence(&take_evidence(&mut state));
    assert!(evidence
        .first()
        .unwrap()
        .verify(&bystander.validator.public_key, CHAIN)
        .is_err());
}

#[test]
fn the_evidence_survives_the_wire() {
    let (keyed, mut state, metrics) = started();
    let offender = keyed.get(1).unwrap();
    feed(&mut state, &metrics, &keyed, prevote(offender, 0xAA));
    feed(&mut state, &metrics, &keyed, prevote(offender, 0xBB));

    let found = *duplicate_vote_evidence(&take_evidence(&mut state))
        .first()
        .unwrap();
    let mut bytes = Vec::new();
    found.encode(&mut bytes);
    let decoded: DuplicateVoteEvidence = decode_exact(&bytes).unwrap();
    assert_eq!(decoded, found);
    assert_eq!(
        decoded.verify(&offender.validator.public_key, CHAIN),
        Ok(())
    );
}

#[test]
fn honest_voting_produces_no_evidence() {
    let (keyed, mut state, metrics) = started();
    // Every validator votes once, for the same value.
    for validator in &keyed {
        feed(&mut state, &metrics, &keyed, prevote(validator, 0xAA));
    }
    assert!(duplicate_vote_evidence(&take_evidence(&mut state)).is_empty());
}

#[test]
fn repeating_the_same_vote_is_not_equivocation() {
    let (keyed, mut state, metrics) = started();
    let voter = keyed.get(1).unwrap();
    feed(&mut state, &metrics, &keyed, prevote(voter, 0xAA));
    feed(&mut state, &metrics, &keyed, prevote(voter, 0xAA));
    assert!(duplicate_vote_evidence(&take_evidence(&mut state)).is_empty());
}
