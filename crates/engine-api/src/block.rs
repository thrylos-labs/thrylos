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
    /// A Move package was refused publication: malformed, over a limit,
    /// failed verification, or publishing is switched off.
    PublishRefused,
}

impl AbortReason {
    /// Every reason, for whoever must go through them all.
    pub const ALL: [Self; 10] = [
        Self::UnknownFunction,
        Self::InvalidArguments,
        Self::UndeclaredObjectAccess,
        Self::ExecutionFailed,
        Self::InsufficientBalance,
        Self::StakingRefused,
        Self::GovernanceRefused,
        Self::EvidenceRefused,
        Self::Unauthorised,
        Self::PublishRefused,
    ];

    /// The number this reason is stored as, from 1. Written out rather than
    /// taken from the variant's position, so that reordering the enum cannot
    /// silently change what an old record means. Never reuse a number.
    pub const fn code(self) -> u8 {
        match self {
            Self::UnknownFunction => 1,
            Self::InvalidArguments => 2,
            Self::UndeclaredObjectAccess => 3,
            Self::ExecutionFailed => 4,
            Self::InsufficientBalance => 5,
            Self::StakingRefused => 6,
            Self::GovernanceRefused => 7,
            Self::EvidenceRefused => 8,
            Self::Unauthorised => 9,
            Self::PublishRefused => 10,
        }
    }

    /// The reason stored as `code`, if it is one this version knows.
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::UnknownFunction,
            2 => Self::InvalidArguments,
            3 => Self::UndeclaredObjectAccess,
            4 => Self::ExecutionFailed,
            5 => Self::InsufficientBalance,
            6 => Self::StakingRefused,
            7 => Self::GovernanceRefused,
            8 => Self::EvidenceRefused,
            9 => Self::Unauthorised,
            10 => Self::PublishRefused,
            _ => return None,
        })
    }

    /// The name a client is shown: the variant's own.
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnknownFunction => "UnknownFunction",
            Self::InvalidArguments => "InvalidArguments",
            Self::UndeclaredObjectAccess => "UndeclaredObjectAccess",
            Self::ExecutionFailed => "ExecutionFailed",
            Self::InsufficientBalance => "InsufficientBalance",
            Self::StakingRefused => "StakingRefused",
            Self::GovernanceRefused => "GovernanceRefused",
            Self::EvidenceRefused => "EvidenceRefused",
            Self::Unauthorised => "Unauthorised",
            Self::PublishRefused => "PublishRefused",
        }
    }
}

impl core::fmt::Display for AbortReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownFunction => f.write_str("the call names a module or function that does not exist"),
            Self::InvalidArguments => f.write_str("the call's arguments do not match what the function takes"),
            Self::UndeclaredObjectAccess => f.write_str("the call touched an object it did not declare among its inputs"),
            Self::ExecutionFailed => f.write_str("the Move VM aborted the call: an explicit abort or an arithmetic overflow"),
            Self::InsufficientBalance => f.write_str("the call needed more coin than the sender had left after reserving the maximum fee"),
            Self::StakingRefused => f.write_str("the staking module refused the call"),
            Self::GovernanceRefused => f.write_str("the governance module refused the call"),
            Self::EvidenceRefused => f.write_str("the evidence was not admitted"),
            Self::Unauthorised => f.write_str("the caller is not allowed to make this call"),
            Self::PublishRefused => f.write_str("the Move package was refused publication"),
        }
    }
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

impl TransactionOutcome {
    /// One byte, for storing: 0 for success, else the abort reason's code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Aborted(reason) => reason.code(),
        }
    }

    /// The outcome stored as `code`, if this version knows it.
    pub const fn from_code(code: u8) -> Option<Self> {
        if code == 0 {
            return Some(Self::Success);
        }
        match AbortReason::from_code(code) {
            Some(reason) => Some(Self::Aborted(reason)),
            None => None,
        }
    }
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

#[cfg(test)]
mod display_tests {
    use super::*;

    /// Every message reads as a sentence about the problem: not empty, not
    /// the variant's Rust name, no trailing full stop, one line, and no two
    /// variants alike.
    fn readable<T: core::fmt::Display + core::fmt::Debug>(all: &[T]) {
        let mut seen = Vec::new();
        for value in all {
            let message = value.to_string();
            assert!(!message.is_empty(), "{value:?}");
            assert!(
                !message.ends_with('.') && !message.contains('\n'),
                "{message}"
            );
            assert_ne!(message, format!("{value:?}"), "only the variant's name");
            assert!(!seen.contains(&message), "two variants say {message:?}");
            seen.push(message);
        }
    }

    #[test]
    fn every_outcome_has_its_own_stable_code_that_reads_back() {
        let mut outcomes = vec![TransactionOutcome::Success];
        outcomes.extend(AbortReason::ALL.map(TransactionOutcome::Aborted));
        let mut codes: Vec<u8> = outcomes.iter().map(|o| o.code()).collect();
        for outcome in &outcomes {
            assert_eq!(
                TransactionOutcome::from_code(outcome.code()),
                Some(*outcome)
            );
        }
        codes.sort_unstable();
        assert_eq!(
            codes,
            (0..=10).collect::<Vec<u8>>(),
            "distinct, and 0 is success"
        );
        // Numbers that were never given out read as nothing, not as something.
        for code in 11..=255u8 {
            assert_eq!(TransactionOutcome::from_code(code), None, "{code}");
        }
        // Pinned, so that a renumbering is a deliberate act: these are on disk.
        assert_eq!(AbortReason::UnknownFunction.code(), 1);
        assert_eq!(AbortReason::ExecutionFailed.code(), 4);
        assert_eq!(AbortReason::Unauthorised.code(), 9);
        assert_eq!(AbortReason::PublishRefused.code(), 10);
    }

    #[test]
    fn every_abort_reason_has_a_name_that_is_its_variant() {
        for reason in AbortReason::ALL {
            assert_eq!(reason.name(), format!("{reason:?}"));
        }
    }

    #[test]
    fn every_abort_reason_reads_as_a_sentence() {
        readable(&[
            AbortReason::UnknownFunction,
            AbortReason::InvalidArguments,
            AbortReason::UndeclaredObjectAccess,
            AbortReason::ExecutionFailed,
            AbortReason::InsufficientBalance,
            AbortReason::StakingRefused,
            AbortReason::GovernanceRefused,
            AbortReason::PublishRefused,
            AbortReason::EvidenceRefused,
            AbortReason::Unauthorised,
        ]);
    }
}
