//! This chain's `malachite_core_types::Context` implementation: ties
//! together the wrapper types in `crate::types` and picks a proposer
//! for each round.
//!
//! Proposer selection is the stake-weighted beacon draw of
//! [`crate::proposer`], seeded by randomness the previous block fixed
//! (`chain_types::beacon`) and carried on the validator set for the height.

use chain_types::ChainId;
use malachite_core_types::{LinearTimeouts, NilOrVal, Round};

use crate::proposer::proposer_index;
use crate::types::{
    round_as_u64, ConsensusAddress, ConsensusProposal, ConsensusProposalPart,
    ConsensusSigningScheme, ConsensusValidator, ConsensusValidatorSet, ConsensusValue,
    ConsensusVote,
};

#[derive(Debug, Clone)]
pub struct ThrylosContext {
    chain_id: ChainId,
}

impl ThrylosContext {
    pub const fn new(chain_id: ChainId) -> Self {
        Self { chain_id }
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
}

impl Default for ThrylosContext {
    fn default() -> Self {
        Self::new(ChainId(0))
    }
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
        // `None` only if every validator has no power, which a set consensus
        // runs against never does; the first validator is then as good a
        // choice as any and, being a function of the set alone, the same on
        // every node.
        let index = proposer_index(
            validator_set.proposer_seed(),
            height.0,
            round_as_u64(round),
            &validator_set.powers(),
        )
        .unwrap_or(0);
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
            chain_id: self.chain_id,
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
            chain_id: self.chain_id,
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
            chain_id: self.chain_id,
            height,
            round,
            value_id,
            vote_type: malachite_core_types::VoteType::Precommit,
            validator_address: address,
            extension: None,
        }
    }
}
