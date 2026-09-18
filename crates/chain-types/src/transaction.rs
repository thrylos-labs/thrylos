//! Transactions. See `docs/spec.md`, "Transaction validity": "Rules
//! every transaction is checked against before it enters a block. Each
//! exists because its absence is an exploit, not a bug."
//!
//! Every field in [`TransactionBody`] maps onto a row of that table:
//! `chain_id`, `sequence_number`, `expiry`, and `declared_inputs` are
//! named directly; the "Scheme byte" row is covered structurally by
//! `sender: PublicKey` and the outer `signature: Signature`, since both
//! already carry their own leading scheme byte (`docs/spec.md`'s new
//! "Scheme byte" row, `crate::keys`). "Gas budget: covered by sender
//! balance at maximum price" is realised as `gas_limit` (a unit count,
//! for metering during execution) and `max_fee_per_gas` (a price cap,
//! for the balance check) — the two fields the spec's own "Fees" section
//! implies are needed once a base fee can vary, rather than one number
//! that can't express both a metering stop-point and a balance cap.
//!
//! This module only defines the shape and the signature-integrity check.
//! Sequence-number ordering, balance sufficiency, and object resolution
//! all need chain state and belong in `chain-state`/`chain-mempool`.

use crate::address::Address;
use crate::codec::{checked_add, slice_from, CodecError, Decode, Encode};
use crate::ids::{BlockHeight, ChainId, GasAmount, GasPrice, SequenceNumber};
use crate::keys::{PublicKey, Signature, SignatureError};

/// How far past the current height an `expiry` may be set, checked at
/// submission time. See `docs/spec.md`, "Transaction validity": "Valid
/// until a stated block height, max 7,200 ahead".
pub const MAX_EXPIRY_HORIZON: u64 = 7_200;

/// Everything a transaction commits to except its own signature. Kept
/// separate from [`Transaction`] so "the bytes that get signed" has
/// exactly one definition, instead of the signing code and the codec
/// having to agree on a field subset by convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionBody {
    pub chain_id: ChainId,
    pub sender: PublicKey,
    pub sequence_number: SequenceNumber,
    pub expiry: BlockHeight,
    pub gas_limit: GasAmount,
    pub max_fee_per_gas: GasPrice,
    /// Every object this transaction will touch. See `docs/spec.md`,
    /// "Transaction validity": absent it, "dynamic resolution, and the
    /// parallelism path closes".
    pub declared_inputs: Vec<Address>,
}

impl Encode for TransactionBody {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.sender.encode(out);
        self.sequence_number.encode(out);
        self.expiry.encode(out);
        self.gas_limit.encode(out);
        self.max_fee_per_gas.encode(out);
        self.declared_inputs.encode(out);
    }
}

impl Decode for TransactionBody {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (chain_id, offset) = ChainId::decode(input)?;
        let (sender, offset) = chain_after(input, offset, PublicKey::decode)?;
        let (sequence_number, offset) = chain_after(input, offset, SequenceNumber::decode)?;
        let (expiry, offset) = chain_after(input, offset, BlockHeight::decode)?;
        let (gas_limit, offset) = chain_after(input, offset, GasAmount::decode)?;
        let (max_fee_per_gas, offset) = chain_after(input, offset, GasPrice::decode)?;
        let (declared_inputs, offset) = chain_after(input, offset, Vec::<Address>::decode)?;
        Ok((
            Self {
                chain_id,
                sender,
                sequence_number,
                expiry,
                gas_limit,
                max_fee_per_gas,
                declared_inputs,
            },
            offset,
        ))
    }
}

/// Decode `T` starting at `offset` into `input`, returning the new total
/// offset. Small helper so [`TransactionBody::decode`] reads as a flat
/// sequence of fields instead of manually threading `slice_from`/
/// `checked_add` through each one.
fn chain_after<T>(
    input: &[u8],
    offset: usize,
    decode: impl FnOnce(&[u8]) -> Result<(T, usize), CodecError>,
) -> Result<(T, usize), CodecError> {
    let (value, used) = decode(slice_from(input, offset)?)?;
    Ok((value, checked_add(offset, used)?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub body: TransactionBody,
    pub signature: Signature,
}

impl Transaction {
    /// The exact bytes [`Self::signature`] must cover: the canonical
    /// encoding of `body`, nothing else.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.body.encode(&mut buf);
        buf
    }

    /// Check the signature against `body`'s sender key and canonical
    /// encoding. Does not check chain ID, expiry, sequence number, or
    /// gas — those need chain state, not just the transaction itself.
    pub fn verify_signature(&self) -> Result<(), SignatureError> {
        self.body
            .sender
            .verify(&self.signing_bytes(), &self.signature)
    }

    pub fn sender_address(&self) -> Address {
        Address::from_public_key(&self.body.sender)
    }

    /// Not yet past `expiry`, and — when called at submission time with
    /// the height the transaction was submitted at — not set further
    /// ahead than [`MAX_EXPIRY_HORIZON`]. As `current_height` advances
    /// toward a fixed `expiry`, the horizon half of this check only gets
    /// easier to satisfy, so a single method correctly serves both the
    /// submission-time cap and every later not-yet-expired check.
    pub fn is_expiry_valid(&self, current_height: BlockHeight) -> bool {
        current_height.0 <= self.body.expiry.0
            && self.body.expiry.0.saturating_sub(current_height.0) <= MAX_EXPIRY_HORIZON
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        self.body.encode(out);
        self.signature.encode(out);
    }
}

impl Decode for Transaction {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (body, offset) = TransactionBody::decode(input)?;
        let (signature, offset) = chain_after(input, offset, Signature::decode)?;
        Ok((Self { body, signature }, offset))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::codec::decode_exact;
    use crate::keys::Signature;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_transaction(seed: u8, declared_inputs: Vec<Address>) -> Transaction {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
        let body = TransactionBody {
            chain_id: ChainId(1),
            sender,
            sequence_number: SequenceNumber(0),
            expiry: BlockHeight(1_000),
            gas_limit: GasAmount(100_000),
            max_fee_per_gas: GasPrice(5),
            declared_inputs,
        };
        let mut signing_bytes = Vec::new();
        body.encode(&mut signing_bytes);
        let raw_sig = signing_key.sign(&signing_bytes);
        Transaction {
            body,
            signature: Signature::from_ed25519_bytes(raw_sig.to_bytes()),
        }
    }

    #[test]
    fn transaction_round_trips() {
        let tx = signed_transaction(1, vec![Address::from_bytes([7u8; 32])]);
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded: Transaction = decode_exact(&buf).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn empty_declared_inputs_round_trips() {
        let tx = signed_transaction(2, Vec::new());
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        let decoded: Transaction = decode_exact(&buf).unwrap();
        assert_eq!(decoded, tx);
    }

    #[test]
    fn signature_verifies_on_an_untampered_transaction() {
        let tx = signed_transaction(3, vec![]);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn tampering_any_field_after_signing_breaks_verification() {
        let mut tx = signed_transaction(4, vec![]);
        tx.body.sequence_number = SequenceNumber(1);
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn tampering_declared_inputs_after_signing_breaks_verification() {
        let mut tx = signed_transaction(5, vec![Address::from_bytes([1u8; 32])]);
        tx.body.declared_inputs.push(Address::from_bytes([2u8; 32]));
        assert!(tx.verify_signature().is_err());
    }

    #[test]
    fn sender_address_matches_the_signing_key() {
        let tx = signed_transaction(6, vec![]);
        assert_eq!(
            tx.sender_address(),
            Address::from_public_key(&tx.body.sender)
        );
    }

    #[test]
    fn expiry_valid_before_and_at_the_expiry_height() {
        let tx = signed_transaction(7, vec![]); // expiry = BlockHeight(1_000)
        assert!(tx.is_expiry_valid(BlockHeight(999)));
        assert!(tx.is_expiry_valid(BlockHeight(1_000)));
    }

    #[test]
    fn expiry_invalid_once_past_the_expiry_height() {
        let tx = signed_transaction(8, vec![]);
        assert!(!tx.is_expiry_valid(BlockHeight(1_001)));
    }

    #[test]
    fn expiry_invalid_when_set_further_ahead_than_the_horizon() {
        let tx = signed_transaction(9, vec![]); // expiry = BlockHeight(1_000)
                                                // 1_000 - 0 = 1_000 <= 7_200: within horizon from height 0.
        assert!(tx.is_expiry_valid(BlockHeight(0)));

        let mut far = signed_transaction(10, vec![]);
        far.body.expiry = BlockHeight(MAX_EXPIRY_HORIZON + 1);
        assert!(!far.is_expiry_valid(BlockHeight(0)));
    }
}
