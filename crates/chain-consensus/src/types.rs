//! This chain's own types, wrapped to satisfy Malachite's `Context`
//! associated-type traits. Every wrapper exists only because of Rust's
//! orphan rule: neither `chain-types`' types nor Malachite's traits are
//! local to this crate, so implementing one for the other needs a local
//! newtype in between — the same pattern `chain-exec` used for MoveVM's
//! resolver trait, just with more pieces here.

use chain_types::codec::{CodecError, Encode};
use chain_types::{Address as ChainAddress, BlockHeight, BlsPublicKey, BlsSignature, Hash};
use malachite_core_types::{NilOrVal, Round, VotingPower};

use crate::context::ThrylosContext;

/// Wraps `chain_types::Address` to satisfy `malachite_core_types::Address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusAddress(pub ChainAddress);

impl core::fmt::Display for ConsensusAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl malachite_core_types::Address for ConsensusAddress {}

/// Wraps `chain_types::BlockHeight` to satisfy `malachite_core_types::Height`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusHeight(pub BlockHeight);

impl core::fmt::Display for ConsensusHeight {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl malachite_core_types::Height for ConsensusHeight {
    const ZERO: Self = Self(BlockHeight(0));
    const INITIAL: Self = Self(BlockHeight(1));

    fn increment_by(&self, n: u64) -> Self {
        Self(BlockHeight(self.0 .0.saturating_add(n)))
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0 .0.checked_sub(n).map(BlockHeight).map(Self)
    }

    fn as_u64(&self) -> u64 {
        self.0 .0
    }
}

/// The value consensus decides on for a height: a block's hash. The
/// full block body is a separate concern (fetched from wherever the
/// host tracks proposed values by hash) — not part of this pass, see
/// `crate`'s doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConsensusValue(pub Hash);

impl malachite_core_types::Value for ConsensusValue {
    type Id = Hash;

    fn id(&self) -> Self::Id {
        self.0
    }
}

/// A validator: an address plus the BLS public key it signs consensus
/// messages with (`docs/spec.md`, "Consensus": "Signatures are
/// BLS12-381 with proof-of-possession, aggregated per round") and its
/// stake-derived voting power.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusValidator {
    pub address: ConsensusAddress,
    pub public_key: BlsPublicKey,
    pub voting_power: VotingPower,
}

impl malachite_core_types::Validator<ThrylosContext> for ConsensusValidator {
    fn address(&self) -> &ConsensusAddress {
        &self.address
    }

    fn public_key(&self) -> &BlsPublicKey {
        &self.public_key
    }

    fn voting_power(&self) -> VotingPower {
        self.voting_power
    }
}

/// A validator set. `docs/spec.md`'s consensus table: "Active validator
/// set: 128, by stake". Malachite requires validators sorted
/// deterministically (by descending power, then ascending address) —
/// `new` sorts on construction so that invariant can't be forgotten at
/// a call site.
///
/// The set also carries the randomness that decides who proposes at its
/// height (`chain_types::beacon`), because that is the one thing
/// `select_proposer` is handed besides the height and round: Malachite
/// gives each height its own set, so the seed for the height travels
/// with it instead of living in some state the engine's own copy of the
/// context could not see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusValidatorSet {
    validators: Vec<ConsensusValidator>,
    proposer_seed: Hash,
}

impl ConsensusValidatorSet {
    /// A set with the all-zero seed — for tests and anything that does not
    /// care who proposes. A running chain uses [`Self::from_infos`].
    pub fn new(validators: Vec<ConsensusValidator>) -> Self {
        Self::with_seed(validators, Hash::from_bytes([0u8; 32]))
    }

    pub fn with_seed(mut validators: Vec<ConsensusValidator>, proposer_seed: Hash) -> Self {
        validators.sort_by(|a, b| {
            b.voting_power
                .cmp(&a.voting_power)
                .then_with(|| a.address.cmp(&b.address))
        });
        Self {
            validators,
            proposer_seed,
        }
    }

    /// The set the chain reports (`chain_engine_api::ChainView::
    /// validator_set`) with the seed in force for the height it is for.
    pub fn from_infos(infos: &[chain_engine_api::ValidatorInfo], proposer_seed: Hash) -> Self {
        Self::with_seed(
            infos
                .iter()
                .map(|info| ConsensusValidator {
                    address: ConsensusAddress(info.address),
                    public_key: info.consensus_key,
                    voting_power: info.voting_power,
                })
                .collect(),
            proposer_seed,
        )
    }

    /// The randomness that picks this height's proposers.
    pub const fn proposer_seed(&self) -> &Hash {
        &self.proposer_seed
    }

    /// Voting powers in the set's own order.
    pub fn powers(&self) -> Vec<u64> {
        self.validators.iter().map(|v| v.voting_power).collect()
    }

    /// The validators, in the set's own order.
    pub fn validators(&self) -> &[ConsensusValidator] {
        &self.validators
    }
}

impl malachite_core_types::ValidatorSet<ThrylosContext> for ConsensusValidatorSet {
    fn count(&self) -> usize {
        self.validators.len()
    }

    fn total_voting_power(&self) -> VotingPower {
        self.validators
            .iter()
            .map(|validator| validator.voting_power)
            .fold(0u64, u64::saturating_add)
    }

    fn get_by_address(&self, address: &ConsensusAddress) -> Option<&ConsensusValidator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    fn get_by_index(&self, index: usize) -> Option<&ConsensusValidator> {
        self.validators.get(index)
    }
}

/// A vote — prevote or precommit — for a value (or nil) at a given
/// height and round. Encodes canonically via `chain_types::codec` so
/// this crate's own `SignVote`/`VerifySignature` effect handling always
/// signs and checks the exact same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusVote {
    pub height: ConsensusHeight,
    pub round: Round,
    pub value_id: NilOrVal<Hash>,
    pub vote_type: malachite_core_types::VoteType,
    pub validator_address: ConsensusAddress,
    pub extension: Option<malachite_core_types::SignedExtension<ThrylosContext>>,
}

/// Leading discriminant byte of a proposal's signing bytes, so a
/// proposal's canonical encoding can never collide with a vote's — the
/// same "domain separation" reasoning as `chain_types::hash::DomainTag`,
/// applied to what gets BLS-signed. The vote's own tag is
/// `chain_types::vote::VOTE_SIGNING_TAG`; the two must differ.
const SIGNING_TAG_PROPOSAL: u8 = 1;
const _: () = assert!(SIGNING_TAG_PROPOSAL != chain_types::vote::VOTE_SIGNING_TAG);

impl ConsensusVote {
    /// This vote as `chain-types`' [`chain_types::Vote`], whose
    /// [`signing_bytes`](chain_types::Vote::signing_bytes) is the single
    /// definition of what a validator's signature on a vote covers —
    /// shared with equivocation evidence, so what a validator is
    /// punished for signing is exactly what this engine had it sign.
    /// (`extension` is not part of the signed vote: it carries its own
    /// signature.)
    pub fn to_vote(&self) -> chain_types::Vote {
        chain_types::Vote {
            height: self.height.0,
            round: chain_types::Round(round_as_u64(self.round)),
            value: match self.value_id {
                NilOrVal::Nil => None,
                NilOrVal::Val(hash) => Some(hash),
            },
            kind: match self.vote_type {
                malachite_core_types::VoteType::Prevote => chain_types::VoteKind::Prevote,
                malachite_core_types::VoteType::Precommit => chain_types::VoteKind::Precommit,
            },
            validator: self.validator_address.0,
        }
    }
}

impl Encode for ConsensusVote {
    fn encode(&self, out: &mut Vec<u8>) {
        self.to_vote().encode(out);
    }
}

/// `Round` has no public constructor from an arbitrary `i64`/`u64` other
/// than `Round::new(u32)` — this maps `Round::as_i64()` (`-1` for `Nil`,
/// otherwise the non-negative round number) onto `u64`, with `Nil`
/// represented as `u64::MAX`, a value `Round::new`'s `u32` argument can
/// never produce.
pub(crate) fn round_as_u64(round: Round) -> u64 {
    u64::try_from(round.as_i64()).unwrap_or(u64::MAX)
}

impl malachite_core_types::Vote<ThrylosContext> for ConsensusVote {
    fn height(&self) -> ConsensusHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &NilOrVal<Hash> {
        &self.value_id
    }

    fn take_value(self) -> NilOrVal<Hash> {
        self.value_id
    }

    fn vote_type(&self) -> malachite_core_types::VoteType {
        self.vote_type
    }

    fn validator_address(&self) -> &ConsensusAddress {
        &self.validator_address
    }

    fn extension(&self) -> Option<&malachite_core_types::SignedExtension<ThrylosContext>> {
        self.extension.as_ref()
    }

    fn take_extension(&mut self) -> Option<malachite_core_types::SignedExtension<ThrylosContext>> {
        self.extension.take()
    }

    fn extend(mut self, extension: malachite_core_types::SignedExtension<ThrylosContext>) -> Self {
        self.extension = Some(extension);
        self
    }
}

/// A proposal for a value at a given height, round, and proof-of-lock
/// round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusProposal {
    pub height: ConsensusHeight,
    pub round: Round,
    pub value: ConsensusValue,
    pub pol_round: Round,
    pub validator_address: ConsensusAddress,
}

impl Encode for ConsensusProposal {
    fn encode(&self, out: &mut Vec<u8>) {
        SIGNING_TAG_PROPOSAL.encode(out);
        self.height.0.encode(out);
        round_as_u64(self.round).encode(out);
        self.value.0.encode(out);
        round_as_u64(self.pol_round).encode(out);
        self.validator_address.0.encode(out);
    }
}

impl malachite_core_types::Proposal<ThrylosContext> for ConsensusProposal {
    fn height(&self) -> ConsensusHeight {
        self.height
    }

    fn round(&self) -> Round {
        self.round
    }

    fn value(&self) -> &ConsensusValue {
        &self.value
    }

    fn take_value(self) -> ConsensusValue {
        self.value
    }

    fn pol_round(&self) -> Round {
        self.pol_round
    }

    fn validator_address(&self) -> &ConsensusAddress {
        &self.validator_address
    }
}

/// The host runs `ValuePayload::ProposalAndParts`, but carries the block
/// as its own message (`host::ProposedBlock`) rather than through
/// Malachite's part-streaming, so this type is never constructed: it
/// exists only to satisfy `Context`'s associated type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusProposalPart;

impl malachite_core_types::ProposalPart<ThrylosContext> for ConsensusProposalPart {
    fn is_first(&self) -> bool {
        true
    }

    fn is_last(&self) -> bool {
        true
    }
}

/// BLS12-381, matching `docs/spec.md`'s consensus signature scheme.
/// Encoding/decoding delegates to `chain_types::bls`'s own validated
/// constructors — an invalid key or signature is a decode error here,
/// same as everywhere else in this codebase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusSigningScheme;

impl malachite_core_types::SigningScheme for ConsensusSigningScheme {
    type DecodingError = CodecError;
    type Signature = BlsSignature;
    type PublicKey = BlsPublicKey;
    /// Real signing happens in `chain-signer`, isolated from everything
    /// else (`docs/spec.md`, "Keys, signing and slashing safety") — this
    /// `Context` never holds or constructs a private key.
    type PrivateKey = ();

    fn decode_signature(bytes: &[u8]) -> Result<Self::Signature, Self::DecodingError> {
        let array: [u8; chain_types::bls::BLS_SIGNATURE_LEN] =
            bytes.try_into().map_err(|_| CodecError::InvalidValue)?;
        BlsSignature::from_bytes(array)
    }

    fn encode_signature(signature: &Self::Signature) -> Vec<u8> {
        signature.to_bytes().to_vec()
    }

    fn decode_public_key(bytes: &[u8]) -> Result<Self::PublicKey, Self::DecodingError> {
        let array: [u8; chain_types::bls::BLS_PUBLIC_KEY_LEN] =
            bytes.try_into().map_err(|_| CodecError::InvalidValue)?;
        BlsPublicKey::from_bytes(array)
    }

    fn encode_public_key(public_key: &Self::PublicKey) -> Vec<u8> {
        public_key.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout this file wrote by hand before `chain_types::Vote`
    /// existed. Signatures made under it must stay valid, so it must
    /// stay byte-for-byte what `ConsensusVote` encodes to.
    fn legacy_encoding(vote: &ConsensusVote) -> Vec<u8> {
        let mut out = Vec::new();
        0u8.encode(&mut out);
        vote.height.0.encode(&mut out);
        round_as_u64(vote.round).encode(&mut out);
        match vote.value_id {
            NilOrVal::Nil => false.encode(&mut out),
            NilOrVal::Val(id) => {
                true.encode(&mut out);
                id.encode(&mut out);
            }
        }
        matches!(vote.vote_type, malachite_core_types::VoteType::Precommit).encode(&mut out);
        vote.validator_address.0.encode(&mut out);
        out
    }

    #[test]
    fn a_consensus_vote_encodes_exactly_as_it_did_before_the_shared_type() {
        for value_id in [NilOrVal::Nil, NilOrVal::Val(Hash::from_bytes([5u8; 32]))] {
            for vote_type in [
                malachite_core_types::VoteType::Prevote,
                malachite_core_types::VoteType::Precommit,
            ] {
                for round in [Round::new(0), Round::new(7)] {
                    let vote = ConsensusVote {
                        height: ConsensusHeight(BlockHeight(42)),
                        round,
                        value_id,
                        vote_type,
                        validator_address: ConsensusAddress(ChainAddress::from_bytes([9u8; 32])),
                        extension: None,
                    };
                    let mut encoded = Vec::new();
                    vote.encode(&mut encoded);
                    assert_eq!(encoded, legacy_encoding(&vote));
                    assert_eq!(encoded, vote.to_vote().signing_bytes());
                }
            }
        }
    }
}
