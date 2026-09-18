//! Proof of life for the Malachite consensus engine dependency itself:
//! drive a single round to decision using the low-level `process!`
//! input/effect loop, using Malachite's own `arc-malachitebft-test`
//! harness (`TestContext`) — not this chain's own `Context`/`Host`.
//!
//! This is deliberately not chain-consensus's production integration.
//! There isn't one yet — see `crate`'s doc comment for what that needs
//! (a real `Context` over `chain-types`, a `Host` answering effects via
//! `chain-signer`/`chain-exec`, and a proposer-selection scheme —
//! plain round-robin until a VRF library is chosen). What this proves:
//! the pinned dependency, once wired up, actually reaches a commit
//! decision for a full BFT round (proposal, prevotes, precommits from
//! every validator), not just that it compiles.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use malachite_core_consensus::{process, Effect, Error, Input, Params, Resumable, State};
use malachite_core_types::{NilOrVal, Round, SignedProposal, SignedVote, Validity, ValueOrigin};
use malachite_metrics::Metrics;
use malachite_test::utils::validators::make_validators;
use malachite_test::{
    Address, Height, Proposal, Signature, TestContext, Validator, ValidatorSet, Value, Vote,
};

fn drop_result(result: Result<(), Error<TestContext>>) {
    // `process!` surfaces coroutine-driver errors as `Result`, never a
    // panic — checking `Ok(())` on every step, rather than discarding
    // it, is what actually proves the round didn't silently misfire.
    result.expect("consensus step failed");
}

fn make_state(validators: &[Validator], my_address: Address) -> State<TestContext> {
    let validator_set = ValidatorSet::new(validators.to_vec());
    State::new(
        TestContext::new(),
        Height::new(1),
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
/// non-Byzantine round: signatures always verify, and signing just
/// attaches a fixed test signature (`arc-malachitebft-test`'s own
/// stand-in — this proof-of-life isn't exercising `chain-signer`).
/// Every other effect (timeouts, `StartRound`, `Publish`, ...) is
/// answered with `Resume::Continue`, which is a no-op resumption, not a
/// silently-ignored effect: the engine only asks for a specific
/// `Resume` payload when it actually needs one back.
fn handle_effect(
    effect: Effect<TestContext>,
) -> Result<malachite_core_consensus::Resume<TestContext>, ()> {
    use malachite_core_consensus::Resume;
    use Effect::*;
    Ok(match effect {
        VerifySignature(_, _, r) => r.resume_with(true),
        VerifyCommitCertificate(_, _, _, r) => r.resume_with(Ok(())),
        SignVote(vote, r) => r.resume_with(SignedVote::new(vote, Signature::test())),
        SignProposal(proposal, r) => {
            r.resume_with(SignedProposal::new(proposal, Signature::test()))
        }
        _ => Resume::Continue,
    })
}

#[test]
fn drives_a_single_round_to_commit() {
    let [(v0, _), (v1, _), (v2, _), (v3, _)] = make_validators([1, 1, 1, 1]);
    let validators = [v0.clone(), v1.clone(), v2.clone(), v3.clone()];
    let proposer = v0.address;
    let value = Value::new(42);

    let mut state = make_state(&validators, proposer);
    let validator_set = ValidatorSet::new(validators.to_vec());
    let metrics = Metrics::new();

    drop_result(process!(
        input: Input::StartHeight(
            Height::new(1),
            validator_set,
            false,
            None,
            Default::default(),
        ),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect)
    ));

    let proposal = SignedProposal::new(
        Proposal::new(
            Height::new(1),
            Round::new(0),
            value.clone(),
            Round::Nil,
            proposer,
        ),
        Signature::test(),
    );
    drop_result(process!(
        input: Input::Proposal(proposal),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect)
    ));

    drop_result(process!(
        input: Input::ProposedValue(
            malachite_core_consensus::ProposedValue {
                height: Height::new(1),
                round: Round::new(0),
                valid_round: Round::Nil,
                proposer,
                value: value.clone(),
                validity: Validity::Valid,
            },
            ValueOrigin::Consensus,
        ),
        state: &mut state,
        metrics: &metrics,
        with: effect => handle_effect(effect)
    ));

    for v in &validators {
        let prevote = SignedVote::new(
            Vote::new_prevote(
                Height::new(1),
                Round::new(0),
                NilOrVal::Val(value.id()),
                v.address,
            ),
            Signature::test(),
        );
        drop_result(process!(
            input: Input::Vote(prevote),
            state: &mut state,
            metrics: &metrics,
            with: effect => handle_effect(effect)
        ));
    }

    for v in &validators {
        let precommit = SignedVote::new(
            Vote::new_precommit(
                Height::new(1),
                Round::new(0),
                NilOrVal::Val(value.id()),
                v.address,
            ),
            Signature::test(),
        );
        drop_result(process!(
            input: Input::Vote(precommit),
            state: &mut state,
            metrics: &metrics,
            with: effect => handle_effect(effect)
        ));
    }

    assert!(
        state.driver.step_is_commit(),
        "four honest validators voting for the same value in round 0 must reach commit"
    );
}
