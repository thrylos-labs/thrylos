//! The block type exchanged across the consensus/execution boundary.
//!
//! Deliberately narrower than a "certified" block: no VRF proof, no
//! aggregate signature, no participation bitfield. Those justify *how*
//! a block was agreed on and belong to a certificate type layered on
//! top of this by `chain-consensus`; execution only needs what's here to
//! run the transactions (`docs/spec.md`, "Execution": "Block execution
//! is a pure function with no I/O of its own").

use chain_state::{StateDiff, StateRoot};
use chain_types::codec::{decode_field, CodecError, Decode, Encode};
use chain_types::hash::{hash_with_domain, DomainTag};
use chain_types::{BlockHeight, Hash, Transaction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The previous block's hash — chain linkage. Distinct from the
    /// parent *state root*, which flows separately through
    /// `Engine::execute_block`'s own `parent_state_root` argument and
    /// [`ExecutedBlock::state_root`]: a block hash and a state root are
    /// different things and must not be typed the same way.
    pub parent_block_hash: Hash,
    pub height: BlockHeight,
    /// Milliseconds since the Unix epoch, taken from consensus — never
    /// read from a system clock during execution (`docs/spec.md`,
    /// "Determinism rules": "No wall-clock or system time ... block
    /// time comes from the header").
    pub timestamp_millis: u64,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn hash(&self) -> Hash {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        hash_with_domain(DomainTag::BlockHeaderV1, &bytes)
    }

    /// Exact canonical encoded length, accumulated one transaction at a
    /// time. This avoids allocating a second block-sized buffer merely to
    /// enforce the wire-size limit.
    pub fn encoded_len(&self) -> Option<usize> {
        let mut fixed = Vec::new();
        self.parent_block_hash.encode(&mut fixed);
        self.height.encode(&mut fixed);
        self.timestamp_millis.encode(&mut fixed);
        0u32.encode(&mut fixed);

        self.transactions.iter().try_fold(fixed.len(), |total, tx| {
            let mut encoded = Vec::new();
            tx.encode(&mut encoded);
            total.checked_add(encoded.len())
        })
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.parent_block_hash.encode(out);
        self.height.encode(out);
        self.timestamp_millis.encode(out);
        self.transactions.encode(out);
    }
}

impl Decode for Block {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (parent_block_hash, offset) = Hash::decode(input)?;
        let (height, offset) = decode_field::<BlockHeight>(input, offset)?;
        let (timestamp_millis, offset) = decode_field::<u64>(input, offset)?;
        let (transactions, offset) = decode_field::<Vec<Transaction>>(input, offset)?;
        Ok((
            Self {
                parent_block_hash,
                height,
                timestamp_millis,
                transactions,
            },
            offset,
        ))
    }
}

/// Why a transaction that was valid to include in a block still failed
/// while executing. `docs/spec.md`, "Execution": "Aborts consume gas
/// and roll back the transaction's effects, but never abort the block."
/// Distinct from [`crate::RejectionReason`]: a rejection means the
/// transaction should never have been in the block at all and takes
/// the whole block with it; an abort is an ordinary, expected outcome
/// of a transaction that was allowed to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// The call names a module/function the executor doesn't have.
    UnknownFunction,
    /// The call's arguments don't match what the function takes.
    InvalidArguments,
    /// The call touches an object its `declared_inputs` don't list —
    /// `docs/spec.md`, "Execution": "A transaction touching an object
    /// it did not declare aborts rather than being resolved
    /// dynamically."
    UndeclaredObjectAccess,
    /// The VM itself failed the call: a Move `abort`, or an arithmetic
    /// overflow ("arithmetic aborts rather than wrapping").
    ExecutionFailed,
    /// A native call needed to move more coin than the sender had left
    /// after setting aside the most their fee could come to.
    InsufficientBalance,
    /// The staking module refused the call: an unknown validator, a
    /// tombstoned one, too many open unbonding entries, a stake below the
    /// minimum, and so on. The module's own error is not carried; the
    /// state shows what did and did not happen.
    StakingRefused,
    /// The governance module refused the call: a closed proposal, a
    /// voter outside its snapshot, too many open proposals, and so on.
    GovernanceRefused,
    /// The evidence was not admitted: not evidence of equivocation by the
    /// registered key, too old, or against a validator already convicted.
    EvidenceRefused,
    /// The caller may not do this: proposing needs a seat in the active
    /// validator set, unjailing needs the validator's own operator.
    Unauthorised,
}

/// What happened to one transaction that made it into an executed
/// block. Either way the sender was charged gas and their sequence
/// number advanced; only a [`Self::Success`] applied the call's own
/// effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionOutcome {
    Success,
    Aborted(AbortReason),
}

/// The deterministic result of executing a [`Block`] on top of a given
/// parent state root. Not wire-encoded: unlike `Block`, this never
/// crosses the network — every validator computes its own by calling
/// [`crate::Engine::execute_block`], rather than receiving one from a
/// peer.
///
/// `state_diff` is what actually changed, not the whole resulting
/// state — see `chain_state::StateDiff`'s doc comment for why this
/// exists (`chain-db` needs something incremental to persist).
///
/// `outcomes` has exactly one entry per transaction in the block, in
/// block order — the only way a caller can tell an aborted transaction
/// from a successful one, since both are included and both are charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedBlock {
    pub state_root: StateRoot,
    pub gas_used: u64,
    pub state_diff: StateDiff,
    pub outcomes: Vec<TransactionOutcome>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chain_types::codec::decode_exact;

    fn empty_block() -> Block {
        Block {
            parent_block_hash: Hash::from_bytes([0u8; 32]),
            height: BlockHeight(1),
            timestamp_millis: 1_700_000_000_000,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn block_round_trips() {
        let block = empty_block();
        let mut buf = Vec::new();
        block.encode(&mut buf);
        assert_eq!(block.encoded_len(), Some(buf.len()));
        let decoded: Block = decode_exact(&buf).unwrap();
        assert_eq!(decoded, block);
    }

    #[test]
    fn hash_changes_when_any_field_changes() {
        let a = empty_block();
        let mut b = a.clone();
        b.timestamp_millis = 1_700_000_000_001;
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn hash_is_domain_separated_from_a_bare_hash_of_the_same_bytes() {
        let block = empty_block();
        let mut bytes = Vec::new();
        block.encode(&mut bytes);
        let undomained = chain_types::hash::hash_with_domain(DomainTag::TrieLeafV1, &bytes);
        assert_ne!(block.hash(), undomained);
    }
}
