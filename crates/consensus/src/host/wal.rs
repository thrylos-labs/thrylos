//! What the host writes to its write-ahead log ([`super::ports::Wal`]).
//!
//! Each entry records one thing that changed what the host will do, in the
//! form it will be replayed in:
//!
//! - a **message** that passed verification — a vote, a proposal, a
//!   certificate — or a block a peer sent with a genuine reveal, all as the
//!   wire format ([`crate::wire`]) has them;
//! - a **timeout** that fired;
//! - a block this validator **built** for a round, so that after a restart
//!   it proposes that block again and not a different one;
//! - a verdict of **invalid** on a block, so that a block voted against
//!   because its timestamp was too far ahead is not, on restart, judged by
//!   a later clock and voted for.
//!
//! Messages that failed verification are never written: what a peer can
//! make this log hold is limited to what only a validator could have signed.

use chain_types::codec::{CodecError, Decode, Encode};
use chain_types::Hash;
use malachite_core_types::Round;

use super::messages::{Message, ProposedBlock};
use crate::types::round_as_u64;
use crate::wire::{decode_message, decode_timeout, encode_message, encode_timeout};

const MESSAGE: u8 = 0;
const TIMEOUT: u8 = 1;
const OWN_BLOCK: u8 = 2;
const INVALID: u8 = 3;

#[derive(Debug, Clone)]
pub(super) enum Entry {
    Message(Message),
    Timeout(malachite_core_types::Timeout),
    OwnBlock {
        round: Round,
        proposed: ProposedBlock,
    },
    Invalid(Hash),
}

impl Entry {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Message(message) => {
                MESSAGE.encode(&mut out);
                out.extend_from_slice(&encode_message(message));
            }
            Self::Timeout(timeout) => {
                TIMEOUT.encode(&mut out);
                out.extend_from_slice(&encode_timeout(*timeout));
            }
            Self::OwnBlock { round, proposed } => {
                OWN_BLOCK.encode(&mut out);
                round_as_u64(*round).encode(&mut out);
                out.extend_from_slice(&encode_message(&Message::Block(proposed.clone())));
            }
            Self::Invalid(id) => {
                INVALID.encode(&mut out);
                id.encode(&mut out);
            }
        }
        out
    }

    pub(super) fn decode(input: &[u8]) -> Result<Self, CodecError> {
        let (tag, rest) = input.split_first().ok_or(CodecError::UnexpectedEof)?;
        match *tag {
            MESSAGE => Ok(Self::Message(decode_message(rest)?)),
            TIMEOUT => Ok(Self::Timeout(decode_timeout(rest)?)),
            OWN_BLOCK => {
                let (round, used) = u64::decode(rest)?;
                let round = if round == u64::MAX {
                    Round::Nil
                } else {
                    Round::new(u32::try_from(round).map_err(|_| CodecError::InvalidValue)?)
                };
                let after = rest.get(used..).ok_or(CodecError::UnexpectedEof)?;
                match decode_message(after)? {
                    Message::Block(proposed) => Ok(Self::OwnBlock { round, proposed }),
                    _ => Err(CodecError::InvalidValue),
                }
            }
            INVALID => Ok(Self::Invalid(chain_types::codec::decode_exact(rest)?)),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use blst::min_pk::SecretKey;
    use chain_engine_api::Block;
    use chain_types::bls::{BlsSignature, DST_VOTE};
    use chain_types::{Address, BlockHeight};
    use malachite_core_consensus::SignedConsensusMsg;
    use malachite_core_types::{NilOrVal, SignedVote, Timeout, TimeoutKind, VoteType};
    use std::time::Duration;

    use super::*;
    use crate::types::{ConsensusAddress, ConsensusHeight, ConsensusVote};

    fn signature() -> BlsSignature {
        let secret = SecretKey::key_gen(&[3; 32], &[]).unwrap();
        BlsSignature::from_bytes(secret.sign(b"x", DST_VOTE, &[]).to_bytes()).unwrap()
    }

    fn proposed() -> ProposedBlock {
        ProposedBlock {
            proposer: Address::from_bytes([1; 32]),
            block: Block {
                parent_block_hash: Hash::from_bytes([2; 32]),
                height: BlockHeight(4),
                timestamp_millis: 1_700_000_000_004,
                transactions: Vec::new(),
            },
            reveal: signature(),
        }
    }

    fn entries() -> Vec<Entry> {
        vec![
            Entry::Message(Message::Consensus(SignedConsensusMsg::Vote(
                SignedVote::new(
                    ConsensusVote {
                        height: ConsensusHeight(BlockHeight(4)),
                        round: Round::new(1),
                        value_id: NilOrVal::Nil,
                        vote_type: VoteType::Prevote,
                        validator_address: ConsensusAddress(Address::from_bytes([7; 32])),
                        extension: None,
                    },
                    signature(),
                ),
            ))),
            Entry::Message(Message::Block(proposed())),
            Entry::Timeout(Timeout::propose(Round::new(0))),
            Entry::Timeout(Timeout {
                kind: TimeoutKind::FinalizeHeight(Duration::new(1, 5)),
                round: Round::Nil,
            }),
            Entry::OwnBlock {
                round: Round::new(2),
                proposed: proposed(),
            },
            Entry::OwnBlock {
                round: Round::Nil,
                proposed: proposed(),
            },
            Entry::Invalid(Hash::from_bytes([9; 32])),
        ]
    }

    #[test]
    fn every_kind_of_entry_survives_the_round_trip() {
        for entry in entries() {
            let bytes = entry.encode();
            let decoded = Entry::decode(&bytes).unwrap();
            assert_eq!(format!("{decoded:?}"), format!("{entry:?}"));
            assert_eq!(decoded.encode(), bytes);
        }
    }

    #[test]
    fn nothing_shorter_or_longer_decodes_as_an_entry() {
        for entry in entries() {
            let bytes = entry.encode();
            for length in 0..bytes.len() {
                assert!(
                    Entry::decode(&bytes[..length]).is_err(),
                    "{entry:?} at {length}"
                );
            }
            let mut longer = bytes;
            longer.push(0);
            assert!(
                Entry::decode(&longer).is_err(),
                "{entry:?} with a byte more"
            );
        }
    }

    #[test]
    fn an_unknown_tag_and_a_block_entry_holding_another_kind_of_message_are_refused() {
        assert!(Entry::decode(&[]).is_err());
        assert!(Entry::decode(&[4]).is_err());
        assert!(Entry::decode(&[0xFF]).is_err());

        // An own-block entry must carry a block message.
        let mut bytes = vec![OWN_BLOCK];
        1u64.encode(&mut bytes);
        bytes.extend_from_slice(&encode_message(&Message::SyncRequest(
            super::super::messages::SyncRequest {
                requester: Address::from_bytes([1; 32]),
                from: BlockHeight(1),
            },
        )));
        assert!(Entry::decode(&bytes).is_err());
    }
}
