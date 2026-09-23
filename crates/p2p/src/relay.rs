//! Compact block relay: what travels when a block is announced without its
//! transactions.
//!
//! A proposer that broadcast every block in full would send each of its peers
//! the whole of it, up to the four MiB cap, and at a hundred peers that is
//! hundreds of megabytes from one machine inside a two-second round. But the
//! validators already hold nearly every transaction in the block: they were each
//! handed it when it was submitted. So the proposer sends a [`CompactBlock`]: the
//! block's header fields, its hash, and one eight-byte short identifier for each
//! transaction. A receiver looks each identifier up among the transactions it
//! holds, assembles the block, and checks it against the hash. What it cannot
//! find it asks for, by position, with a [`TransactionRequest`], and is answered
//! with a [`BlockTransactions`].
//!
//! The identifiers are keyed by a nonce the proposer picks for each block (mixed
//! with the block's own header), so no one can make two transactions collide
//! ahead of time to spoil a reconstruction. A collision, or anything else that
//! makes the assembled block not match its hash, is not an error: the receiver
//! asks for all of it. Nothing in this module is trusted for anything the host
//! does not check again: what comes out is an ordinary full block, and goes to
//! the host exactly as one received whole would.

use chain_consensus::host::ProposedBlock;
use chain_engine_api::Block;
use chain_types::bls::BlsSignature;
use chain_types::codec::{decode_field, CodecError};
use chain_types::{Address, BlockHeight, Decode, Encode, Hash, Transaction};

/// Bytes in a short transaction identifier.
pub const SHORT_ID_BYTES: usize = 8;

/// The most transactions one compact block or request may name. A four MiB block
/// cannot hold more than this whatever the transactions, so a frame naming more
/// is not a block.
pub const MAX_COMPACT_TRANSACTIONS: usize = 65_536;

/// The largest compact block or request frame: sixty-five thousand identifiers of
/// eight bytes is half a MiB, and the rest is a fixed header.
pub const MAX_RELAY_CONTROL_FRAME_BYTES: usize = 1024 * 1024;

/// The largest frame of transactions sent in answer: a whole block, and a little
/// over for the framing.
pub const MAX_BLOCK_TRANSACTIONS_FRAME_BYTES: usize = 5 * 1024 * 1024;

/// The identifier of one transaction under a block's key.
pub type ShortId = [u8; SHORT_ID_BYTES];

/// A block announced without its transactions. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactBlock {
    pub proposer: Address,
    pub reveal: BlsSignature,
    /// The hash of the whole block, which whatever is assembled must match.
    pub block_hash: Hash,
    pub parent_block_hash: Hash,
    pub height: BlockHeight,
    pub timestamp_millis: u64,
    /// Picked by the proposer for this block; keys the identifiers.
    pub nonce: [u8; 8],
    /// One for each transaction, in the block's order.
    pub short_ids: Vec<ShortId>,
}

/// "Send me the transactions at these positions of the block with this hash."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequest {
    pub block_hash: Hash,
    pub indexes: Vec<u32>,
}

/// The transactions asked for, in the order they were asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockTransactions {
    pub block_hash: Hash,
    pub transactions: Vec<Transaction>,
}

/// The key the identifiers of the block with these header fields are made
/// under.
pub fn short_id_key(
    nonce: &[u8; 8],
    parent_block_hash: &Hash,
    height: BlockHeight,
    timestamp_millis: u64,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("thrylos compact block short id key v1");
    hasher.update(nonce);
    hasher.update(parent_block_hash.as_bytes());
    hasher.update(&height.0.to_le_bytes());
    hasher.update(&timestamp_millis.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// The identifier of `transaction` under `key`: the front of a keyed hash of its
/// canonical encoding.
pub fn short_id(key: &[u8; 32], transaction: &Transaction) -> ShortId {
    let mut bytes = Vec::new();
    transaction.encode(&mut bytes);
    let hash = blake3::keyed_hash(key, &bytes);
    let mut id = [0u8; SHORT_ID_BYTES];
    for (out, byte) in id.iter_mut().zip(hash.as_bytes()) {
        *out = *byte;
    }
    id
}

impl CompactBlock {
    /// The announcement of `proposed`, with identifiers keyed by `nonce`.
    pub fn announce(proposed: &ProposedBlock, nonce: [u8; 8]) -> Self {
        let block = &proposed.block;
        let key = short_id_key(
            &nonce,
            &block.parent_block_hash,
            block.height,
            block.timestamp_millis,
        );
        Self {
            proposer: proposed.proposer,
            reveal: proposed.reveal,
            block_hash: block.hash(),
            parent_block_hash: block.parent_block_hash,
            height: block.height,
            timestamp_millis: block.timestamp_millis,
            nonce,
            short_ids: block
                .transactions
                .iter()
                .map(|transaction| short_id(&key, transaction))
                .collect(),
        }
    }

    /// The key this announcement's identifiers are made under.
    pub fn key(&self) -> [u8; 32] {
        short_id_key(
            &self.nonce,
            &self.parent_block_hash,
            self.height,
            self.timestamp_millis,
        )
    }

    /// The block with `transactions` in it, if that is the block announced: the
    /// right number of them, and a block whose hash is the one named.
    pub fn assemble(&self, transactions: Vec<Transaction>) -> Option<ProposedBlock> {
        if transactions.len() != self.short_ids.len() {
            return None;
        }
        let block = Block {
            parent_block_hash: self.parent_block_hash,
            height: self.height,
            timestamp_millis: self.timestamp_millis,
            transactions,
        };
        (block.hash() == self.block_hash).then_some(ProposedBlock {
            proposer: self.proposer,
            block,
            reveal: self.reveal,
        })
    }
}

impl Encode for CompactBlock {
    fn encode(&self, out: &mut Vec<u8>) {
        self.proposer.encode(out);
        self.reveal.encode(out);
        self.block_hash.encode(out);
        self.parent_block_hash.encode(out);
        self.height.encode(out);
        self.timestamp_millis.encode(out);
        out.extend_from_slice(&self.nonce);
        u32::try_from(self.short_ids.len())
            .unwrap_or(u32::MAX)
            .encode(out);
        for id in &self.short_ids {
            out.extend_from_slice(id);
        }
    }
}

impl Decode for CompactBlock {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (proposer, offset) = decode_field::<Address>(input, 0)?;
        let (reveal, offset) = decode_field::<BlsSignature>(input, offset)?;
        let (block_hash, offset) = decode_field::<Hash>(input, offset)?;
        let (parent_block_hash, offset) = decode_field::<Hash>(input, offset)?;
        let (height, offset) = decode_field::<BlockHeight>(input, offset)?;
        let (timestamp_millis, offset) = decode_field::<u64>(input, offset)?;
        let nonce_end = offset.checked_add(8).ok_or(CodecError::LengthTooLarge)?;
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(
            input
                .get(offset..nonce_end)
                .ok_or(CodecError::UnexpectedEof)?,
        );
        let (count, offset) = decode_field::<u32>(input, nonce_end)?;
        let count = usize::try_from(count).map_err(|_| CodecError::LengthTooLarge)?;
        if count > MAX_COMPACT_TRANSACTIONS {
            return Err(CodecError::LengthTooLarge);
        }
        let end = count
            .checked_mul(SHORT_ID_BYTES)
            .and_then(|bytes| offset.checked_add(bytes))
            .ok_or(CodecError::LengthTooLarge)?;
        let body = input.get(offset..end).ok_or(CodecError::UnexpectedEof)?;
        let short_ids = body
            .chunks_exact(SHORT_ID_BYTES)
            .map(|chunk| {
                let mut id = [0u8; SHORT_ID_BYTES];
                id.copy_from_slice(chunk);
                id
            })
            .collect();
        Ok((
            Self {
                proposer,
                reveal,
                block_hash,
                parent_block_hash,
                height,
                timestamp_millis,
                nonce,
                short_ids,
            },
            end,
        ))
    }
}

impl Encode for TransactionRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        self.block_hash.encode(out);
        self.indexes.encode(out);
    }
}

impl Decode for TransactionRequest {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (block_hash, offset) = decode_field::<Hash>(input, 0)?;
        let (indexes, offset) = decode_field::<Vec<u32>>(input, offset)?;
        if indexes.len() > MAX_COMPACT_TRANSACTIONS {
            return Err(CodecError::LengthTooLarge);
        }
        Ok((
            Self {
                block_hash,
                indexes,
            },
            offset,
        ))
    }
}

impl Encode for BlockTransactions {
    fn encode(&self, out: &mut Vec<u8>) {
        self.block_hash.encode(out);
        self.transactions.encode(out);
    }
}

impl Decode for BlockTransactions {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (block_hash, offset) = decode_field::<Hash>(input, 0)?;
        let (transactions, offset) = decode_field::<Vec<Transaction>>(input, offset)?;
        if transactions.len() > MAX_COMPACT_TRANSACTIONS {
            return Err(CodecError::LengthTooLarge);
        }
        Ok((
            Self {
                block_hash,
                transactions,
            },
            offset,
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use chain_types::{
        ChainId, GasAmount, GasPrice, MoveCall, PublicKey, SequenceNumber, Signature,
        TransactionBody,
    };
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// A distinct, validly signed transaction for each `n`.
    pub(crate) fn transaction(n: u64) -> Transaction {
        let key = SigningKey::from_bytes(&[(n % 200) as u8 + 1; 32]);
        let body = TransactionBody {
            chain_id: ChainId(1),
            sender: PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
            sequence_number: SequenceNumber(n),
            expiry: BlockHeight(100),
            gas_limit: GasAmount(1_000),
            max_fee_per_gas: GasPrice(1),
            declared_inputs: Vec::new(),
            call: MoveCall {
                module_address: Address::from_bytes([2; 32]),
                module_name: b"m".to_vec(),
                function_name: b"f".to_vec(),
                type_arguments: Vec::new(),
                arguments: vec![n.to_le_bytes().to_vec()],
            },
        };
        let mut bytes = Vec::new();
        body.encode(&mut bytes);
        Transaction {
            body,
            signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
        }
    }

    pub(crate) fn proposed(count: u64) -> ProposedBlock {
        ProposedBlock {
            proposer: Address::from_bytes([7; 32]),
            block: Block {
                parent_block_hash: Hash::from_bytes([3; 32]),
                height: BlockHeight(12),
                timestamp_millis: 1_700_000_000_123,
                transactions: (0..count).map(transaction).collect(),
            },
            reveal: BlsSignature::from_bytes(reveal_bytes()).unwrap(),
        }
    }

    /// The bytes of a genuine BLS signature (any will do).
    fn reveal_bytes() -> [u8; chain_types::bls::BLS_SIGNATURE_LEN] {
        let secret = blst::min_pk::SecretKey::key_gen(&[5; 32], &[]).unwrap();
        secret
            .sign(b"reveal", chain_types::bls::DST_VOTE, &[])
            .to_bytes()
    }

    #[test]
    fn a_compact_block_round_trips_and_says_what_the_block_is() {
        let block = proposed(50);
        let compact = CompactBlock::announce(&block, [9; 8]);
        assert_eq!(compact.short_ids.len(), 50);
        assert_eq!(compact.block_hash, block.block.hash());

        let mut bytes = Vec::new();
        compact.encode(&mut bytes);
        // Header fields and eight bytes a transaction, not the transactions.
        assert!(
            bytes.len() < 32 + 96 + 32 + 32 + 8 + 8 + 8 + 4 + 50 * 8 + 16,
            "{}",
            bytes.len()
        );
        assert_eq!(
            chain_types::decode_exact::<CompactBlock>(&bytes).unwrap(),
            compact
        );

        // Given the transactions, it assembles the very block it announced.
        let assembled = compact.assemble(block.block.transactions.clone()).unwrap();
        assert_eq!(assembled, block);
    }

    #[test]
    fn an_assembly_that_is_not_the_announced_block_is_refused() {
        let block = proposed(6);
        let compact = CompactBlock::announce(&block, [1; 8]);
        let mut wrong_order = block.block.transactions.clone();
        wrong_order.swap(0, 1);
        assert!(
            compact.assemble(wrong_order).is_none(),
            "the hash pins the order"
        );
        let mut substituted = block.block.transactions.clone();
        substituted[3] = transaction(999);
        assert!(compact.assemble(substituted).is_none());
        assert!(compact
            .assemble(block.block.transactions[..5].to_vec())
            .is_none());
        let mut extra = block.block.transactions.clone();
        extra.push(transaction(7));
        assert!(compact.assemble(extra).is_none());
    }

    #[test]
    fn identifiers_depend_on_the_nonce_and_the_header_so_a_collision_cannot_be_prepared() {
        let block = proposed(20);
        let one = CompactBlock::announce(&block, [1; 8]);
        let other = CompactBlock::announce(&block, [2; 8]);
        assert_ne!(one.short_ids, other.short_ids);
        assert_ne!(one.key(), other.key());

        let mut later = block.clone();
        later.block.timestamp_millis += 1;
        assert_ne!(CompactBlock::announce(&later, [1; 8]).key(), one.key());
        let mut higher = block.clone();
        higher.block.height = BlockHeight(13);
        assert_ne!(CompactBlock::announce(&higher, [1; 8]).key(), one.key());

        // And within one block they tell its transactions apart.
        let mut ids = one.short_ids.clone();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 20);
        // An identifier is a function of the transaction and the key alone.
        assert_eq!(
            short_id(&one.key(), &block.block.transactions[4]),
            one.short_ids[4]
        );
    }

    #[test]
    fn what_is_cut_short_or_over_bound_or_followed_by_more_is_not_a_compact_block() {
        let compact = CompactBlock::announce(&proposed(4), [1; 8]);
        let mut bytes = Vec::new();
        compact.encode(&mut bytes);
        for cut in [0, 1, 40, bytes.len() - 1] {
            assert!(
                chain_types::decode_exact::<CompactBlock>(&bytes[..cut]).is_err(),
                "cut at {cut}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(chain_types::decode_exact::<CompactBlock>(&longer).is_err());

        // A count that promises more identifiers than there are bytes for, and
        // one past the bound however many bytes follow.
        let count_at = bytes.len() - 4 * SHORT_ID_BYTES - 4;
        let mut promises = bytes.clone();
        promises[count_at..count_at + 4].copy_from_slice(&5u32.to_le_bytes());
        assert!(chain_types::decode_exact::<CompactBlock>(&promises).is_err());
        let mut over = bytes[..count_at].to_vec();
        over.extend_from_slice(
            &u32::try_from(MAX_COMPACT_TRANSACTIONS + 1)
                .unwrap()
                .to_le_bytes(),
        );
        over.extend(vec![0u8; (MAX_COMPACT_TRANSACTIONS + 1) * SHORT_ID_BYTES]);
        assert!(chain_types::decode_exact::<CompactBlock>(&over).is_err());
        // The most is fine, and fits its frame with room to spare.
        let mut most = bytes[..count_at].to_vec();
        most.extend_from_slice(
            &u32::try_from(MAX_COMPACT_TRANSACTIONS)
                .unwrap()
                .to_le_bytes(),
        );
        most.extend(vec![0u8; MAX_COMPACT_TRANSACTIONS * SHORT_ID_BYTES]);
        assert!(most.len() < MAX_RELAY_CONTROL_FRAME_BYTES);
        assert_eq!(
            chain_types::decode_exact::<CompactBlock>(&most)
                .unwrap()
                .short_ids
                .len(),
            MAX_COMPACT_TRANSACTIONS
        );
    }

    #[test]
    fn requests_and_answers_round_trip_and_are_bounded() {
        let request = TransactionRequest {
            block_hash: Hash::from_bytes([4; 32]),
            indexes: vec![0, 5, 9, 4_000],
        };
        let mut bytes = Vec::new();
        request.encode(&mut bytes);
        assert_eq!(
            chain_types::decode_exact::<TransactionRequest>(&bytes).unwrap(),
            request
        );
        assert!(
            chain_types::decode_exact::<TransactionRequest>(&bytes[..bytes.len() - 1]).is_err()
        );

        let mut too_many = TransactionRequest {
            block_hash: Hash::from_bytes([4; 32]),
            indexes: vec![0; MAX_COMPACT_TRANSACTIONS + 1],
        };
        let mut bytes = Vec::new();
        too_many.encode(&mut bytes);
        assert!(chain_types::decode_exact::<TransactionRequest>(&bytes).is_err());
        too_many.indexes.truncate(MAX_COMPACT_TRANSACTIONS);
        let mut bytes = Vec::new();
        too_many.encode(&mut bytes);
        assert!(bytes.len() < MAX_RELAY_CONTROL_FRAME_BYTES);
        assert!(chain_types::decode_exact::<TransactionRequest>(&bytes).is_ok());

        let answer = BlockTransactions {
            block_hash: Hash::from_bytes([4; 32]),
            transactions: (0..5).map(transaction).collect(),
        };
        let mut bytes = Vec::new();
        answer.encode(&mut bytes);
        assert_eq!(
            chain_types::decode_exact::<BlockTransactions>(&bytes).unwrap(),
            answer
        );
        assert!(chain_types::decode_exact::<BlockTransactions>(&bytes[..bytes.len() - 3]).is_err());
    }
}
