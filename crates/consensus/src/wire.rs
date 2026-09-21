//! The byte encoding of what hosts send each other, and of what a host keeps
//! in its write-ahead log.
//!
//! Built on `chain_types::codec`: one valid encoding per value, decoding
//! never panics and rejects anything malformed — an unknown tag, a length
//! that does not fit, a round no encoder would write, bytes left over.
//! Decoding does not *trust* what it reads; a decoded vote is still an
//! unchecked claim until the host verifies its signature.
//!
//! Sizes are bounded here only enough that a length cannot be used to make
//! the decoder allocate more than the input holds: [`MAX_SIGNATURES`] per
//! certificate and [`MAX_COMMITS`] per answer. How large a whole message
//! may be is the transport's limit to enforce, before it gets here.
//!
//! Vote extensions are not used by this chain, so a vote or a commit
//! signature carries none, and decoding always produces `None`.

use std::time::Duration;

use chain_engine_api::Block;
use chain_types::codec::{decode_field, CodecError, Decode, Encode};
use chain_types::{Address, BlockHeight, BlsSignature, ChainId, Hash};
use malachite_core_consensus::{LivenessMsg, SignedConsensusMsg};
use malachite_core_types::{
    CommitCertificate, CommitSignature, NilOrVal, PolkaCertificate, PolkaSignature, Round,
    RoundCertificate, RoundCertificateType, RoundSignature, SignedProposal, SignedVote, Timeout,
    TimeoutKind, VoteType,
};

use crate::context::ThrylosContext;
use crate::host::{CommitRecord, Message, ProposedBlock, SyncRequest, SyncResponse};
use crate::types::{
    round_as_u64, ConsensusAddress, ConsensusHeight, ConsensusProposal, ConsensusValue,
    ConsensusVote,
};

/// The most signatures a certificate may carry: comfortably past the largest
/// validator set the spec allows (128).
pub const MAX_SIGNATURES: u32 = 1024;

/// The most decided blocks one answer may carry.
pub const MAX_COMMITS: u32 = 256;

// Message tags.
const VOTE: u8 = 0;
const PROPOSAL: u8 = 1;
const LIVENESS_VOTE: u8 = 2;
const POLKA_CERTIFICATE: u8 = 3;
const SKIP_ROUND_CERTIFICATE: u8 = 4;
const BLOCK: u8 = 5;
const SYNC_REQUEST: u8 = 6;
const SYNC_RESPONSE: u8 = 7;

// Timeout kinds.
const PROPOSE: u8 = 0;
const PREVOTE: u8 = 1;
const PRECOMMIT: u8 = 2;
const REBROADCAST: u8 = 3;
const FINALIZE_HEIGHT: u8 = 4;

// ---- reading ------------------------------------------------------------------

/// A cursor over the input, so a composite decode reads as a flat sequence
/// of fields.
struct Reader<'a> {
    input: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, at: 0 }
    }

    fn take<T: Decode>(&mut self) -> Result<T, CodecError> {
        let (value, at) = decode_field(self.input, self.at)?;
        self.at = at;
        Ok(value)
    }

    /// A collection's length, checked against `max` before anything is read
    /// for it.
    fn count(&mut self, max: u32) -> Result<usize, CodecError> {
        let count: u32 = self.take()?;
        if count > max {
            return Err(CodecError::LengthTooLarge);
        }
        usize::try_from(count).map_err(|_| CodecError::LengthTooLarge)
    }

    fn round(&mut self) -> Result<Round, CodecError> {
        let value: u64 = self.take()?;
        if value == u64::MAX {
            return Ok(Round::Nil);
        }
        let round = u32::try_from(value).map_err(|_| CodecError::InvalidValue)?;
        Ok(Round::new(round))
    }

    fn height(&mut self) -> Result<ConsensusHeight, CodecError> {
        Ok(ConsensusHeight(BlockHeight(self.take()?)))
    }

    fn address(&mut self) -> Result<ConsensusAddress, CodecError> {
        Ok(ConsensusAddress(self.take()?))
    }

    fn vote_type(&mut self) -> Result<VoteType, CodecError> {
        match self.take::<u8>()? {
            0 => Ok(VoteType::Prevote),
            1 => Ok(VoteType::Precommit),
            _ => Err(CodecError::InvalidValue),
        }
    }

    fn nil_or_value(&mut self) -> Result<NilOrVal<Hash>, CodecError> {
        match self.take::<u8>()? {
            0 => Ok(NilOrVal::Nil),
            1 => Ok(NilOrVal::Val(self.take()?)),
            _ => Err(CodecError::InvalidValue),
        }
    }

    fn signed_vote(&mut self) -> Result<SignedVote<ThrylosContext>, CodecError> {
        let vote = ConsensusVote {
            chain_id: self.take::<ChainId>()?,
            height: self.height()?,
            round: self.round()?,
            value_id: self.nil_or_value()?,
            vote_type: self.vote_type()?,
            validator_address: self.address()?,
            extension: None,
        };
        Ok(SignedVote::new(vote, self.take()?))
    }

    fn signed_proposal(&mut self) -> Result<SignedProposal<ThrylosContext>, CodecError> {
        let proposal = ConsensusProposal {
            chain_id: self.take::<ChainId>()?,
            height: self.height()?,
            round: self.round()?,
            value: ConsensusValue(self.take()?),
            pol_round: self.round()?,
            validator_address: self.address()?,
        };
        Ok(SignedProposal::new(proposal, self.take()?))
    }

    fn commit_certificate(&mut self) -> Result<CommitCertificate<ThrylosContext>, CodecError> {
        let height = self.height()?;
        let round = self.round()?;
        let value_id = self.take()?;
        let mut commit_signatures = Vec::new();
        for _ in 0..self.count(MAX_SIGNATURES)? {
            commit_signatures.push(CommitSignature {
                address: self.address()?,
                signature: self.take()?,
            });
        }
        Ok(CommitCertificate {
            height,
            round,
            value_id,
            commit_signatures,
        })
    }

    fn polka_certificate(&mut self) -> Result<PolkaCertificate<ThrylosContext>, CodecError> {
        let height = self.height()?;
        let round = self.round()?;
        let value_id = self.take()?;
        let mut polka_signatures = Vec::new();
        for _ in 0..self.count(MAX_SIGNATURES)? {
            polka_signatures.push(PolkaSignature {
                address: self.address()?,
                signature: self.take()?,
            });
        }
        Ok(PolkaCertificate {
            height,
            round,
            value_id,
            polka_signatures,
        })
    }

    fn round_certificate(&mut self) -> Result<RoundCertificate<ThrylosContext>, CodecError> {
        let height = self.height()?;
        let round = self.round()?;
        let cert_type = match self.take::<u8>()? {
            0 => RoundCertificateType::Skip,
            1 => RoundCertificateType::Precommit,
            _ => return Err(CodecError::InvalidValue),
        };
        let mut round_signatures = Vec::new();
        for _ in 0..self.count(MAX_SIGNATURES)? {
            round_signatures.push(RoundSignature {
                vote_type: self.vote_type()?,
                value_id: self.nil_or_value()?,
                address: self.address()?,
                signature: self.take()?,
            });
        }
        Ok(RoundCertificate {
            height,
            round,
            cert_type,
            round_signatures,
        })
    }

    fn commit_record(&mut self) -> Result<CommitRecord, CodecError> {
        Ok(CommitRecord {
            block: self.take::<Block>()?,
            certificate: self.commit_certificate()?,
            reveal: self.take()?,
        })
    }

    fn finish(&self) -> Result<(), CodecError> {
        if self.at == self.input.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

// ---- writing ------------------------------------------------------------------

fn put_round(out: &mut Vec<u8>, round: Round) {
    round_as_u64(round).encode(out);
}

fn put_height(out: &mut Vec<u8>, height: ConsensusHeight) {
    height.0 .0.encode(out);
}

fn put_vote_type(out: &mut Vec<u8>, vote_type: VoteType) {
    match vote_type {
        VoteType::Prevote => 0u8,
        VoteType::Precommit => 1u8,
    }
    .encode(out);
}

fn put_nil_or_value(out: &mut Vec<u8>, value: &NilOrVal<Hash>) {
    match value {
        NilOrVal::Nil => 0u8.encode(out),
        NilOrVal::Val(hash) => {
            1u8.encode(out);
            hash.encode(out);
        }
    }
}

fn put_count(out: &mut Vec<u8>, count: usize) {
    // A collection this large cannot be built from anything decoded (the
    // decoder's own bound is far smaller), so saturating is only ever
    // reached by a caller that constructed something absurd — and the
    // result then fails to decode rather than being mistaken for a small
    // one.
    u32::try_from(count).unwrap_or(u32::MAX).encode(out);
}

fn put_signed_vote(out: &mut Vec<u8>, vote: &SignedVote<ThrylosContext>) {
    let message = &vote.message;
    message.chain_id.encode(out);
    put_height(out, message.height);
    put_round(out, message.round);
    put_nil_or_value(out, &message.value_id);
    put_vote_type(out, message.vote_type);
    message.validator_address.0.encode(out);
    vote.signature.encode(out);
}

fn put_signed_proposal(out: &mut Vec<u8>, proposal: &SignedProposal<ThrylosContext>) {
    let message = &proposal.message;
    message.chain_id.encode(out);
    put_height(out, message.height);
    put_round(out, message.round);
    message.value.0.encode(out);
    put_round(out, message.pol_round);
    message.validator_address.0.encode(out);
    proposal.signature.encode(out);
}

fn put_commit_certificate(out: &mut Vec<u8>, certificate: &CommitCertificate<ThrylosContext>) {
    put_height(out, certificate.height);
    put_round(out, certificate.round);
    certificate.value_id.encode(out);
    put_count(out, certificate.commit_signatures.len());
    for entry in &certificate.commit_signatures {
        entry.address.0.encode(out);
        entry.signature.encode(out);
    }
}

fn put_polka_certificate(out: &mut Vec<u8>, certificate: &PolkaCertificate<ThrylosContext>) {
    put_height(out, certificate.height);
    put_round(out, certificate.round);
    certificate.value_id.encode(out);
    put_count(out, certificate.polka_signatures.len());
    for entry in &certificate.polka_signatures {
        entry.address.0.encode(out);
        entry.signature.encode(out);
    }
}

fn put_round_certificate(out: &mut Vec<u8>, certificate: &RoundCertificate<ThrylosContext>) {
    put_height(out, certificate.height);
    put_round(out, certificate.round);
    match certificate.cert_type {
        RoundCertificateType::Skip => 0u8,
        RoundCertificateType::Precommit => 1u8,
    }
    .encode(out);
    put_count(out, certificate.round_signatures.len());
    for entry in &certificate.round_signatures {
        put_vote_type(out, entry.vote_type);
        put_nil_or_value(out, &entry.value_id);
        entry.address.0.encode(out);
        entry.signature.encode(out);
    }
}

fn put_commit_record(out: &mut Vec<u8>, record: &CommitRecord) {
    record.block.encode(out);
    put_commit_certificate(out, &record.certificate);
    record.reveal.encode(out);
}

// ---- messages -----------------------------------------------------------------

/// A message as bytes.
pub fn encode_message(message: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    match message {
        Message::Consensus(SignedConsensusMsg::Vote(vote)) => {
            VOTE.encode(&mut out);
            put_signed_vote(&mut out, vote);
        }
        Message::Consensus(SignedConsensusMsg::Proposal(proposal)) => {
            PROPOSAL.encode(&mut out);
            put_signed_proposal(&mut out, proposal);
        }
        Message::Liveness(LivenessMsg::Vote(vote)) => {
            LIVENESS_VOTE.encode(&mut out);
            put_signed_vote(&mut out, vote);
        }
        Message::Liveness(LivenessMsg::PolkaCertificate(certificate)) => {
            POLKA_CERTIFICATE.encode(&mut out);
            put_polka_certificate(&mut out, certificate);
        }
        Message::Liveness(LivenessMsg::SkipRoundCertificate(certificate)) => {
            SKIP_ROUND_CERTIFICATE.encode(&mut out);
            put_round_certificate(&mut out, certificate);
        }
        Message::Block(block) => {
            BLOCK.encode(&mut out);
            block.proposer.encode(&mut out);
            block.block.encode(&mut out);
            block.reveal.encode(&mut out);
        }
        Message::SyncRequest(request) => {
            SYNC_REQUEST.encode(&mut out);
            request.requester.encode(&mut out);
            request.from.0.encode(&mut out);
        }
        Message::SyncResponse(response) => {
            SYNC_RESPONSE.encode(&mut out);
            response.requester.encode(&mut out);
            put_count(&mut out, response.commits.len());
            for record in &response.commits {
                put_commit_record(&mut out, record);
            }
        }
    }
    out
}

/// A message from bytes, which must be exactly one message.
pub fn decode_message(input: &[u8]) -> Result<Message, CodecError> {
    let mut reader = Reader::new(input);
    let message = match reader.take::<u8>()? {
        VOTE => Message::Consensus(SignedConsensusMsg::Vote(reader.signed_vote()?)),
        PROPOSAL => Message::Consensus(SignedConsensusMsg::Proposal(reader.signed_proposal()?)),
        LIVENESS_VOTE => Message::Liveness(LivenessMsg::Vote(reader.signed_vote()?)),
        POLKA_CERTIFICATE => {
            Message::Liveness(LivenessMsg::PolkaCertificate(reader.polka_certificate()?))
        }
        SKIP_ROUND_CERTIFICATE => Message::Liveness(LivenessMsg::SkipRoundCertificate(
            reader.round_certificate()?,
        )),
        BLOCK => Message::Block(ProposedBlock {
            proposer: reader.take::<Address>()?,
            block: reader.take::<Block>()?,
            reveal: reader.take::<BlsSignature>()?,
        }),
        SYNC_REQUEST => Message::SyncRequest(SyncRequest {
            requester: reader.take::<Address>()?,
            from: BlockHeight(reader.take()?),
        }),
        SYNC_RESPONSE => {
            let requester = reader.take::<Address>()?;
            let mut commits = Vec::new();
            for _ in 0..reader.count(MAX_COMMITS)? {
                commits.push(reader.commit_record()?);
            }
            Message::SyncResponse(SyncResponse { requester, commits })
        }
        _ => return Err(CodecError::InvalidValue),
    };
    reader.finish()?;
    Ok(message)
}

// ---- timeouts -----------------------------------------------------------------

/// A timeout as bytes.
pub fn encode_timeout(timeout: Timeout) -> Vec<u8> {
    let mut out = Vec::new();
    match timeout.kind {
        TimeoutKind::Propose => PROPOSE.encode(&mut out),
        TimeoutKind::Prevote => PREVOTE.encode(&mut out),
        TimeoutKind::Precommit => PRECOMMIT.encode(&mut out),
        TimeoutKind::Rebroadcast => REBROADCAST.encode(&mut out),
        TimeoutKind::FinalizeHeight(duration) => {
            FINALIZE_HEIGHT.encode(&mut out);
            duration.as_secs().encode(&mut out);
            duration.subsec_nanos().encode(&mut out);
        }
    }
    put_round(&mut out, timeout.round);
    out
}

/// A timeout from bytes, which must be exactly one.
pub fn decode_timeout(input: &[u8]) -> Result<Timeout, CodecError> {
    let mut reader = Reader::new(input);
    let kind = match reader.take::<u8>()? {
        PROPOSE => TimeoutKind::Propose,
        PREVOTE => TimeoutKind::Prevote,
        PRECOMMIT => TimeoutKind::Precommit,
        REBROADCAST => TimeoutKind::Rebroadcast,
        FINALIZE_HEIGHT => {
            let secs: u64 = reader.take()?;
            let nanos: u32 = reader.take()?;
            // `Duration::new` would fold an out-of-range count of nanoseconds
            // into the seconds, giving two encodings for one duration.
            if nanos >= 1_000_000_000 {
                return Err(CodecError::InvalidValue);
            }
            TimeoutKind::FinalizeHeight(Duration::new(secs, nanos))
        }
        _ => return Err(CodecError::InvalidValue),
    };
    let round = reader.round()?;
    reader.finish()?;
    Ok(Timeout { kind, round })
}

/// A decided block and its proof as bytes.
pub fn encode_commit_record(record: &CommitRecord) -> Vec<u8> {
    let mut out = Vec::new();
    put_commit_record(&mut out, record);
    out
}

/// A decided block and its proof from bytes, which must be exactly one.
pub fn decode_commit_record(input: &[u8]) -> Result<CommitRecord, CodecError> {
    let mut reader = Reader::new(input);
    let record = reader.commit_record()?;
    reader.finish()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use blst::min_pk::SecretKey;
    use chain_types::bls::DST_VOTE;

    use super::*;

    fn signature(n: u8) -> BlsSignature {
        let secret = SecretKey::key_gen(&[n; 32], &[]).unwrap();
        BlsSignature::from_bytes(secret.sign(&[n], DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn address(n: u8) -> ConsensusAddress {
        ConsensusAddress(Address::from_bytes([n; 32]))
    }

    fn hash(n: u8) -> Hash {
        Hash::from_bytes([n; 32])
    }

    fn block(height: u64) -> Block {
        Block {
            parent_block_hash: hash(1),
            height: BlockHeight(height),
            timestamp_millis: 1_700_000_000_000 + height,
            transactions: Vec::new(),
        }
    }

    fn vote(vote_type: VoteType, value: NilOrVal<Hash>) -> SignedVote<ThrylosContext> {
        SignedVote::new(
            ConsensusVote {
                chain_id: ChainId(7),
                height: ConsensusHeight(BlockHeight(7)),
                round: Round::new(3),
                value_id: value,
                vote_type,
                validator_address: address(2),
                extension: None,
            },
            signature(1),
        )
    }

    fn commit_certificate(height: u64) -> CommitCertificate<ThrylosContext> {
        CommitCertificate {
            height: ConsensusHeight(BlockHeight(height)),
            round: Round::new(1),
            value_id: hash(4),
            commit_signatures: (1..=3)
                .map(|n| CommitSignature {
                    address: address(n),
                    signature: signature(n),
                })
                .collect(),
        }
    }

    fn record(height: u64) -> CommitRecord {
        CommitRecord {
            block: block(height),
            certificate: commit_certificate(height),
            reveal: signature(9),
        }
    }

    /// One of every kind of message, with the awkward values in: a nil
    /// vote, a nil proof-of-lock round, an empty and a full certificate.
    fn messages() -> Vec<Message> {
        vec![
            Message::Consensus(SignedConsensusMsg::Vote(vote(
                VoteType::Prevote,
                NilOrVal::Val(hash(5)),
            ))),
            Message::Consensus(SignedConsensusMsg::Vote(vote(
                VoteType::Precommit,
                NilOrVal::Nil,
            ))),
            Message::Consensus(SignedConsensusMsg::Proposal(SignedProposal::new(
                ConsensusProposal {
                    chain_id: ChainId(7),
                    height: ConsensusHeight(BlockHeight(7)),
                    round: Round::new(2),
                    value: ConsensusValue(hash(6)),
                    pol_round: Round::Nil,
                    validator_address: address(3),
                },
                signature(2),
            ))),
            Message::Consensus(SignedConsensusMsg::Proposal(SignedProposal::new(
                ConsensusProposal {
                    chain_id: ChainId(7),
                    height: ConsensusHeight(BlockHeight(7)),
                    round: Round::new(2),
                    value: ConsensusValue(hash(6)),
                    pol_round: Round::new(1),
                    validator_address: address(3),
                },
                signature(2),
            ))),
            Message::Liveness(LivenessMsg::Vote(vote(VoteType::Prevote, NilOrVal::Nil))),
            Message::Liveness(LivenessMsg::PolkaCertificate(PolkaCertificate {
                height: ConsensusHeight(BlockHeight(7)),
                round: Round::new(1),
                value_id: hash(8),
                polka_signatures: (1..=3)
                    .map(|n| PolkaSignature {
                        address: address(n),
                        signature: signature(n),
                    })
                    .collect(),
            })),
            Message::Liveness(LivenessMsg::SkipRoundCertificate(RoundCertificate {
                height: ConsensusHeight(BlockHeight(7)),
                round: Round::new(1),
                cert_type: RoundCertificateType::Skip,
                round_signatures: vec![
                    RoundSignature {
                        vote_type: VoteType::Prevote,
                        value_id: NilOrVal::Nil,
                        address: address(1),
                        signature: signature(1),
                    },
                    RoundSignature {
                        vote_type: VoteType::Precommit,
                        value_id: NilOrVal::Val(hash(3)),
                        address: address(2),
                        signature: signature(2),
                    },
                ],
            })),
            Message::Liveness(LivenessMsg::SkipRoundCertificate(RoundCertificate {
                height: ConsensusHeight(BlockHeight(7)),
                round: Round::new(0),
                cert_type: RoundCertificateType::Precommit,
                round_signatures: Vec::new(),
            })),
            Message::Block(ProposedBlock {
                proposer: Address::from_bytes([4; 32]),
                block: block(7),
                reveal: signature(4),
            }),
            Message::SyncRequest(SyncRequest {
                requester: Address::from_bytes([5; 32]),
                from: BlockHeight(12),
            }),
            Message::SyncResponse(SyncResponse {
                requester: Address::from_bytes([5; 32]),
                commits: vec![record(12), record(13)],
            }),
            Message::SyncResponse(SyncResponse {
                requester: Address::from_bytes([5; 32]),
                commits: Vec::new(),
            }),
        ]
    }

    #[test]
    fn every_kind_of_message_survives_the_round_trip() {
        for message in messages() {
            let bytes = encode_message(&message);
            let decoded = decode_message(&bytes).unwrap();
            assert_eq!(format!("{decoded:?}"), format!("{message:?}"));
            assert_eq!(encode_message(&decoded), bytes);
        }
    }

    #[test]
    fn no_shorter_input_decodes_as_a_message() {
        for message in messages() {
            let bytes = encode_message(&message);
            for length in 0..bytes.len() {
                assert!(
                    decode_message(&bytes[..length]).is_err(),
                    "{length} of {} bytes of {message:?} decoded",
                    bytes.len()
                );
            }
        }
    }

    #[test]
    fn bytes_left_over_are_refused() {
        for message in messages() {
            let mut bytes = encode_message(&message);
            bytes.push(0);
            assert_eq!(
                decode_message(&bytes).unwrap_err(),
                CodecError::TrailingBytes
            );
        }
    }

    #[test]
    fn whatever_decodes_is_the_one_encoding_of_what_it_decodes_to() {
        // Change any one byte of any message: the decoder either refuses it
        // or produces something that encodes back to exactly those bytes.
        // There is no second way to write a value, and no input panics.
        for message in messages() {
            let bytes = encode_message(&message);
            for at in 0..bytes.len() {
                for change in [0x01u8, 0x80, 0xFF] {
                    let mut altered = bytes.clone();
                    altered[at] ^= change;
                    if let Ok(decoded) = decode_message(&altered) {
                        assert_eq!(
                            encode_message(&decoded),
                            altered,
                            "byte {at} of {message:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_unknown_tag_is_refused() {
        for tag in [8u8, 9, 100, 255] {
            assert_eq!(
                decode_message(&[tag]).unwrap_err(),
                CodecError::InvalidValue
            );
        }
        assert_eq!(decode_message(&[]).unwrap_err(), CodecError::UnexpectedEof);
    }

    #[test]
    fn a_round_no_encoder_would_write_is_refused() {
        // A proposal's round sits after the tag, the 8-byte chain ID and the
        // 8-byte height.
        let bytes = encode_message(&messages()[2]);
        for bad in [1u64 << 32, u64::MAX - 1] {
            let mut altered = bytes.clone();
            altered[17..25].copy_from_slice(&bad.to_le_bytes());
            assert_eq!(
                decode_message(&altered).unwrap_err(),
                CodecError::InvalidValue
            );
        }
        // The largest real round and nil are fine.
        for good in [u64::from(u32::MAX), u64::MAX] {
            let mut altered = bytes.clone();
            altered[17..25].copy_from_slice(&good.to_le_bytes());
            assert!(decode_message(&altered).is_ok());
        }
    }

    #[test]
    fn a_length_larger_than_allowed_is_refused_before_anything_is_read_for_it() {
        // A sync response: tag, requester (32 bytes), then the count.
        let mut bytes = vec![SYNC_RESPONSE];
        bytes.extend_from_slice(&[5; 32]);
        (MAX_COMMITS + 1).encode(&mut bytes);
        assert_eq!(
            decode_message(&bytes).unwrap_err(),
            CodecError::LengthTooLarge
        );

        // At the limit with nothing behind it: short, not an allocation.
        let mut bytes = vec![SYNC_RESPONSE];
        bytes.extend_from_slice(&[5; 32]);
        MAX_COMMITS.encode(&mut bytes);
        assert_eq!(
            decode_message(&bytes).unwrap_err(),
            CodecError::UnexpectedEof
        );

        // Signatures in a certificate: after the tag, height, round, value.
        let mut bytes = vec![POLKA_CERTIFICATE];
        7u64.encode(&mut bytes);
        1u64.encode(&mut bytes);
        hash(8).encode(&mut bytes);
        (MAX_SIGNATURES + 1).encode(&mut bytes);
        assert_eq!(
            decode_message(&bytes).unwrap_err(),
            CodecError::LengthTooLarge
        );
    }

    #[test]
    fn a_vote_or_certificate_signature_that_is_not_a_signature_is_refused() {
        let bytes = encode_message(&messages()[0]);
        let mut altered = bytes.clone();
        let end = altered.len();
        altered[end - 96..].fill(0xAB);
        assert!(decode_message(&altered).is_err());
    }

    #[test]
    fn every_kind_of_timeout_survives_the_round_trip() {
        for timeout in [
            Timeout::propose(Round::new(0)),
            Timeout::prevote(Round::new(9)),
            Timeout::precommit(Round::new(u32::MAX)),
            Timeout {
                kind: TimeoutKind::Rebroadcast,
                round: Round::new(2),
            },
            Timeout {
                kind: TimeoutKind::FinalizeHeight(Duration::new(3, 999_999_999)),
                round: Round::Nil,
            },
        ] {
            let bytes = encode_timeout(timeout);
            assert_eq!(decode_timeout(&bytes).unwrap(), timeout);
            for length in 0..bytes.len() {
                assert!(decode_timeout(&bytes[..length]).is_err());
            }
            let mut longer = bytes;
            longer.push(0);
            assert_eq!(
                decode_timeout(&longer).unwrap_err(),
                CodecError::TrailingBytes
            );
        }
    }

    #[test]
    fn a_duration_written_two_ways_is_refused_the_second() {
        let mut bytes = vec![FINALIZE_HEIGHT];
        3u64.encode(&mut bytes);
        1_000_000_000u32.encode(&mut bytes);
        u64::MAX.encode(&mut bytes);
        assert_eq!(
            decode_timeout(&bytes).unwrap_err(),
            CodecError::InvalidValue
        );
        assert_eq!(decode_timeout(&[5]).unwrap_err(), CodecError::InvalidValue);
    }

    #[test]
    fn a_commit_record_survives_the_round_trip_and_nothing_shorter_decodes() {
        let original = record(21);
        let bytes = encode_commit_record(&original);
        let decoded = decode_commit_record(&bytes).unwrap();
        assert_eq!(format!("{decoded:?}"), format!("{original:?}"));
        for length in 0..bytes.len() {
            assert!(decode_commit_record(&bytes[..length]).is_err());
        }
    }
}
