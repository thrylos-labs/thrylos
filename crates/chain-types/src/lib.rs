//! Consensus-critical types, canonical SSZ-style codec.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".

#![forbid(unsafe_code)]

pub mod address;
pub mod bls;
pub mod codec;
pub mod collections;
pub mod hash;
pub mod ids;
pub mod keys;
pub mod transaction;
pub mod vote;

pub use address::Address;
pub use bls::{BlsPublicKey, BlsSignature, BlsSignatureError};
pub use codec::{decode_exact, CodecError, Decode, Encode};
pub use hash::{hash_with_domain, DomainTag, Hash};
pub use ids::{BlockHeight, ChainId, GasAmount, GasPrice, Round, SequenceNumber};
pub use keys::{PublicKey, Scheme, Signature, SignatureError};
pub use transaction::{MoveCall, Transaction, TransactionBody, MAX_EXPIRY_HORIZON};
pub use vote::{DuplicateVoteEvidence, EvidenceError, Vote, VoteKind, VOTE_SIGNING_TAG};
