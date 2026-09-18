//! This chain's `malachite_core_types::Context` implementation: ties
//! together the wrapper types in `crate::types` and picks a proposer
//! for each round.
//!
//! Proposer selection here is plain round-robin over the validator
//! set's deterministic order, **not** the spec's VRF-based scheme —
//! see `crate`'s doc comment. It is a placeholder: predictable well
//! ahead of time, so it must never be treated as sybil- or
//! grinding-resistant. Swapping it for VRF-based selection later only
//! touches `select_proposer`; nothing else in this file depends on how
//! the proposer is chosen.

use malachite_core_types::{LinearTimeouts, NilOrVal, Round};

use crate::types::{
    round_as_u64, ConsensusAddress, ConsensusProposal, ConsensusProposalPart,
    ConsensusSigningScheme, ConsensusValidator, ConsensusValidatorSet, ConsensusValue,
    ConsensusVote,
};

#[derive(Debug, Clone)]
pub struct ThrylosContext;

impl ThrylosContext {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ThrylosContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Round-robin index into a deterministically-sorted validator set.
/// Falls back to index `0` only when `validator_count` is `0`, which
/// never happens for a validator set consensus is actually running
/// against.
fn round_robin_index(height: u64, round: Round, validator_count: usize) -> usize {
    let count = u64::try_from(validator_count).unwrap_or(1);
    let offset = height
        .checked_add(round_as_u64(round))
        .unwrap_or(0)
        .checked_rem(count)
        .unwrap_or(0);
    usize::try_from(offset).unwrap_or(0)
}

impl malachite_core_types::Context for ThrylosContext {
    type Address = ConsensusAddress;
    type Height = crate::types::ConsensusHeight;
    type ProposalPart = ConsensusProposalPart;
    type Proposal = ConsensusProposal;
    type Validator = ConsensusValidator;
    type ValidatorSet = ConsensusValidatorSet;
    type Timeouts = LinearTimeouts;
    type Value = ConsensusValue;
    type Vote = ConsensusVote;
    type Extension = ();
    type SigningScheme = ConsensusSigningScheme;

    fn select_proposer<'a>(
        &self,
        validator_set: &'a Self::ValidatorSet,
        height: Self::Height,
        round: Round,
    ) -> &'a Self::Validator {
        use malachite_core_types::ValidatorSet as _;

        // Consensus cannot run against an empty validator set at all, so
        // this signature (`-> &Validator`, not `Option`) has no valid
        // total implementation for that case — Malachite's own reference
        // `Context` (`core-types/src/context.rs`) resolves the same
        // signature the same way, with the same assertion.
        assert!(
            validator_set.count() > 0,
            "select_proposer called with an empty validator set"
        );
        let index = round_robin_index(height.0 .0, round, validator_set.count());
        // `index` is `checked_rem`-derived and strictly less than
        // `validator_set.count()`, which the assertion above just
        // established is nonzero, so this index is always in range.
        match validator_set.get_by_index(index) {
            Some(validator) => validator,
            None => match validator_set.iter().next() {
                Some(validator) => validator,
                None => unreachable!("validator_set.count() > 0 was just asserted"),
            },
        }
    }

    fn new_proposal(
        &self,
        height: Self::Height,
        round: Round,
        value: Self::Value,
        pol_round: Round,
        address: Self::Address,
    ) -> Self::Proposal {
        ConsensusProposal {
            height,
            round,
            value,
            pol_round,
            validator_address: address,
        }
    }

    fn new_prevote(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<chain_types::Hash>,
        address: Self::Address,
    ) -> Self::Vote {
        ConsensusVote {
            height,
            round,
            value_id,
            vote_type: malachite_core_types::VoteType::Prevote,
            validator_address: address,
            extension: None,
        }
    }

    fn new_precommit(
        &self,
        height: Self::Height,
        round: Round,
        value_id: NilOrVal<chain_types::Hash>,
        address: Self::Address,
    ) -> Self::Vote {
        ConsensusVote {
            height,
            round,
            value_id,
            vote_type: malachite_core_types::VoteType::Precommit,
            validator_address: address,
            extension: None,
        }
    }
}
