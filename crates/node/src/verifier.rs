//! What the transport checks about a consensus message before the node sees it.
//!
//! The transport already authenticates the *peer* (every frame is signed by
//! its key) and decodes the message strictly. What it cannot know is whether
//! the message is what that peer is entitled to send. [`SenderBoundVerifier`]
//! checks the cheapest such thing: a message that names its author must name
//! the validator the peer it arrived from is configured as. A peer cannot
//! inject a vote or a proposal in another validator's name, nor ask for
//! catch-up as someone else, so the host never spends time on them.
//!
//! It is a filter, not a proof: the host still verifies every signature and
//! every certificate, against the validator set at the right height, before it
//! acts on anything.
//!
//! Only messages a validator sends *about itself* are bound. A vote or
//! certificate in a liveness message, a block, and a catch-up answer can
//! legitimately carry other validators' signed data (a node helps a peer
//! reach a round by relaying votes it holds), so they pass here and are judged
//! by their signatures.

use std::collections::BTreeMap;

use chain_consensus::host::Message;
use chain_p2p::{ConsensusVerifier, PeerId};
use chain_types::Address;
use malachite_core_consensus::SignedConsensusMsg;

/// Checks that a message names, as its author, the validator its peer is.
pub struct SenderBoundVerifier {
    validators: BTreeMap<PeerId, Address>,
}

impl SenderBoundVerifier {
    /// A verifier for peers that are the given validators. A peer that is not
    /// listed is not a validator, and may send nothing that names an author.
    pub fn new(validators: impl IntoIterator<Item = (PeerId, Address)>) -> Self {
        Self {
            validators: validators.into_iter().collect(),
        }
    }
}

/// The validator a message says it is from, if it says.
fn claimed_author(message: &Message) -> Option<Address> {
    match message {
        Message::Consensus(SignedConsensusMsg::Vote(vote)) => {
            Some(vote.message.validator_address.0)
        }
        Message::Consensus(SignedConsensusMsg::Proposal(proposal)) => {
            Some(proposal.message.validator_address.0)
        }
        Message::SyncRequest(request) => Some(request.requester),
        Message::Liveness(_) | Message::Block(_) | Message::SyncResponse(_) => None,
    }
}

impl ConsensusVerifier for SenderBoundVerifier {
    fn verify(&self, peer: PeerId, message: &Message) -> bool {
        match claimed_author(message) {
            None => true,
            Some(claimed) => self.validators.get(&peer) == Some(&claimed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use chain_consensus::host::{SyncRequest, SyncResponse};
    use chain_consensus::types::{
        ConsensusAddress, ConsensusHeight, ConsensusProposal, ConsensusValue, ConsensusVote,
    };
    use chain_types::bls::BlsSignature;
    use chain_types::{BlockHeight, ChainId, Hash};
    use malachite_core_types::{NilOrVal, Round, SignedProposal, SignedVote, VoteType};

    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    fn validator(n: u8) -> Address {
        Address::from_bytes([n; 32])
    }

    fn verifier() -> SenderBoundVerifier {
        SenderBoundVerifier::new([(peer(1), validator(1)), (peer(2), validator(2))])
    }

    fn signature() -> BlsSignature {
        BlsSignature::from_bytes(
            blst::min_pk::SecretKey::key_gen(&[7; 32], &[])
                .unwrap()
                .sign(b"x", chain_types::bls::DST_VOTE, &[])
                .to_bytes(),
        )
        .unwrap()
    }

    fn proposal_by(author: u8) -> Message {
        let proposal = ConsensusProposal {
            chain_id: ChainId(1),
            height: ConsensusHeight(BlockHeight(1)),
            round: Round::new(0),
            value: ConsensusValue(Hash::from_bytes([1; 32])),
            pol_round: Round::Nil,
            validator_address: ConsensusAddress(validator(author)),
        };
        Message::Consensus(SignedConsensusMsg::Proposal(SignedProposal::new(
            proposal,
            signature(),
        )))
    }

    fn prevote_by(author: u8) -> Message {
        let vote = ConsensusVote {
            chain_id: ChainId(1),
            height: ConsensusHeight(BlockHeight(1)),
            round: Round::new(0),
            value_id: NilOrVal::Nil,
            vote_type: VoteType::Prevote,
            validator_address: ConsensusAddress(validator(author)),
            extension: None,
        };
        Message::Consensus(SignedConsensusMsg::Vote(SignedVote::new(vote, signature())))
    }

    #[test]
    fn a_vote_is_accepted_from_the_validator_it_names_and_from_nobody_else() {
        let verifier = verifier();
        assert!(verifier.verify(peer(1), &prevote_by(1)));
        assert!(
            !verifier.verify(peer(2), &prevote_by(1)),
            "in another's name"
        );
        assert!(!verifier.verify(peer(9), &prevote_by(9)), "not a validator");
    }

    #[test]
    fn a_proposal_is_accepted_from_the_validator_it_names_and_from_nobody_else() {
        let verifier = verifier();
        assert!(verifier.verify(peer(2), &proposal_by(2)));
        assert!(
            !verifier.verify(peer(1), &proposal_by(2)),
            "in another's name"
        );
        assert!(
            !verifier.verify(peer(9), &proposal_by(9)),
            "not a validator"
        );
    }

    #[test]
    fn a_catch_up_request_must_come_from_the_requester() {
        let verifier = verifier();
        let request = |who: u8| {
            Message::SyncRequest(SyncRequest {
                requester: validator(who),
                from: BlockHeight(1),
            })
        };
        assert!(verifier.verify(peer(2), &request(2)));
        assert!(!verifier.verify(peer(2), &request(1)));
    }

    #[test]
    fn what_may_carry_other_validators_data_is_left_to_its_signatures() {
        let verifier = verifier();
        let answer = Message::SyncResponse(SyncResponse {
            requester: validator(1),
            commits: Vec::new(),
        });
        // From any peer, listed or not: the host verifies what it holds.
        assert!(verifier.verify(peer(2), &answer));
        assert!(verifier.verify(peer(9), &answer));
    }
}
