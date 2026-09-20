//! The `Engine` trait: the entire boundary between consensus and
//! execution, three mutating calls wide. `docs/spec.md`, "Scope and
//! non-goals" keeps this v1 boundary in-process and adds [`crate::ChainView`]
//! for deterministic reads. Every input is explicit and the interface can be
//! differentially fuzzed against a reference in isolation.
//!
//! This crate defines the contract only: no selection algorithm, no
//! MoveVM, no storage. An implementation belongs to `chain-exec`
//! (execution) and is driven by `chain-consensus`.

use chain_state::StateRoot;
use chain_types::{BlockHeight, Hash, Transaction};

use crate::block::{Block, ExecutedBlock};

/// A block's gas and size ceiling. `max_gas` is governance-adjustable
/// within clamps; `max_size_bytes` is a hard cap that no governance
/// vote can raise (`docs/spec.md`, "Consensus": "Max block gas: 60M,
/// governance-adjustable within clamps" / "Max block size: 4 MiB hard
/// cap"). Callers pass the currently-active values in; this crate does
/// not read governance state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLimits {
    pub max_gas: u64,
    pub max_size_bytes: u32,
}

/// The block size ceiling — fixed, never governance-adjustable.
pub const MAX_BLOCK_SIZE_BYTES: u32 = 4 * 1024 * 1024;

/// A transaction may reserve at most one quarter of the active block gas
/// limit. This keeps one transaction from monopolising block execution and
/// leaves the proposer no discretion over the limit.
pub const MAX_TRANSACTION_GAS_DIVISOR: u64 = 4;

pub const fn max_transaction_gas(block_gas_limit: u64) -> u64 {
    match block_gas_limit.checked_div(MAX_TRANSACTION_GAS_DIVISOR) {
        Some(limit) => limit,
        None => 0,
    }
}

/// The genesis default for [`BlockLimits::max_gas`]. Governance may move
/// this within its clamp (10M–120M); this constant is only the starting
/// value, not an enforced ceiling.
pub const GENESIS_MAX_BLOCK_GAS: u64 = 60_000_000;

/// Why a transaction caused its whole block to be rejected outright,
/// rather than merely aborting during execution. `docs/spec.md`,
/// "Execution": "Invalid transaction in a proposed block rejects the
/// block. There is no skip-and-continue path, which would be a fork
/// condition." This is distinct from a Move-level abort, which "consumes
/// gas and rolls back the transaction's effects, but never aborts the
/// block" — an abort is never a [`RejectionReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// `docs/spec.md`, "Transaction validity": chain ID missing or not
    /// the node's own.
    WrongChainId,
    /// Signature does not verify against the declared sender.
    InvalidSignature,
    /// Expired at the height of the block carrying it, or scheduled
    /// further ahead than `chain_types::transaction::MAX_EXPIRY_HORIZON`
    /// from that height.
    InvalidExpiry,
    /// A check that needs chain state failed: sequence-number ordering
    /// or balance. The specific reason is owned by whichever crate
    /// performs the check, not enumerated here. A failure *while
    /// executing* a transaction that passed these checks — including a
    /// declared-access violation — is not a rejection: it's an
    /// [`crate::AbortReason`], and the block stands.
    Rejected,
    /// The block's height is not exactly one more than its parent's.
    /// Checked because a transaction's expiry is measured against the
    /// height of the block that carries it: a proposer free to claim any
    /// height could keep an expired transaction alive forever.
    InvalidBlockHeight,
    /// The block's timestamp is not strictly after its parent's
    /// (`docs/spec.md`, "Transaction validity"). Only the half of the
    /// rule that needs chain state alone: the "not too far ahead of the
    /// clock" half needs a clock, and is the consensus host's to check —
    /// see [`crate::timestamp`].
    InvalidBlockTimestamp,
    /// The transaction asks for more than one quarter of the active block
    /// gas limit. This is a transaction-level validity failure even when the
    /// block total remains below its limit.
    TransactionGasLimitExceeded,
    /// After applying the block, the total of every balance, every staked
    /// unit and every unbonding entry no longer equals the supply the
    /// chain has recorded: value was created or lost somewhere. Not
    /// anything a transaction chooses; a bug in a module or the
    /// executor, and the reason this check exists is that the block
    /// must not be accepted (`docs/spec.md`: an invariant "that halts
    /// block production if violated").
    InvariantViolated,
    /// The block itself is malformed independent of any one
    /// transaction — over a [`BlockLimits`] ceiling, for instance.
    MalformedBlock,
}

impl core::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongChainId => f.write_str("the transaction's chain ID is missing or is not this chain's"),
            Self::InvalidSignature => f.write_str("the transaction's signature does not verify against its sender"),
            Self::InvalidExpiry => f.write_str("the transaction has expired at this height, or expires too far ahead"),
            Self::Rejected => f.write_str("the transaction failed a check against chain state: its sequence number or the sender's balance"),
            Self::InvalidBlockHeight => f.write_str("the block's height is not exactly one more than its parent's"),
            Self::InvalidBlockTimestamp => f.write_str("the block's timestamp is not after its parent's"),
            Self::TransactionGasLimitExceeded => f.write_str("the transaction asks for more than a quarter of the block gas limit"),
            Self::InvariantViolated => f.write_str("the block would break the supply invariant: value was created or lost"),
            Self::MalformedBlock => f.write_str("the block is malformed or over a size limit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRejected {
    /// Index into the block's transaction list, when the rejection is
    /// attributable to one transaction. `None` for a whole-block reason
    /// such as [`RejectionReason::MalformedBlock`].
    pub transaction_index: Option<u32>,
    pub reason: RejectionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinaliseErrorReason {
    /// `executed` doesn't match what a fresh `execute_block` of the same
    /// `block` and parent would produce. Should be unreachable in a
    /// correct caller; surfaced rather than trusted blindly because a
    /// reachable panic here would be a chain halt (`docs/spec.md`,
    /// "Determinism rules").
    StateRootMismatch,
    /// `block`'s parent is not the current chain tip.
    NotOnCanonicalChain,
    /// The durable store did not commit the block. The in-memory canonical
    /// state must remain at its previous head when this is returned.
    StorageUnavailable,
}

impl core::fmt::Display for FinaliseErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StateRootMismatch => f.write_str(
                "the executed block's state root differs from a fresh execution of the same block",
            ),
            Self::NotOnCanonicalChain => {
                f.write_str("the block's parent is not the current chain head")
            }
            Self::StorageUnavailable => f.write_str("the durable store did not commit the block"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinaliseError {
    pub reason: FinaliseErrorReason,
}

/// The entire mutating boundary between consensus and execution. It exposes
/// no untyped shared state: blocks, roots, limits and results cross through
/// explicit values.
pub trait Engine {
    /// Assemble a candidate block extending `parent_block_hash` /
    /// `parent_state_root` from `candidate_transactions` (already
    /// ordered and selected — e.g. by the mempool — for this round),
    /// greedily packing transactions in the given order until `limits`
    /// would be exceeded. Pure assembly: does not execute the
    /// transactions or compute a state root. Called only by this
    /// round's proposer.
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block;

    /// Deterministically execute `block` on top of `parent_state_root`.
    /// Called by every validator — proposer and non-proposer alike — on
    /// every block, whether self-proposed or received over gossip, to
    /// compute (and so implicitly verify) the resulting state before
    /// voting. `docs/spec.md`, "Execution": "Block execution is a pure
    /// function with no I/O of its own." Does not itself check that
    /// `block.parent_block_hash` is the caller's actual chain tip —
    /// that's the caller's responsibility, not this crate's.
    fn execute_block(
        &self,
        parent_state_root: StateRoot,
        block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected>;

    /// Durably commit a block once it has a quorum certificate,
    /// advancing the canonical chain tip. Never re-executes: `executed`
    /// must be exactly what `execute_block` already produced for
    /// `block`.
    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chain_types::hash::{hash_with_domain, DomainTag};
    use chain_types::{
        ChainId, Encode, GasAmount, GasPrice, PublicKey, SequenceNumber, Signature, TransactionBody,
    };
    use ed25519_dalek::{Signer, SigningKey};

    /// A toy `Engine`: rejects transactions from another chain or with a
    /// bad signature, otherwise hashes parent + block together as a
    /// stand-in state root and sums declared gas limits as gas used.
    /// Enough to prove the trait's signatures actually compose with real
    /// `chain-types`/`chain-state` values — not a model of real
    /// execution.
    struct MockEngine {
        chain_id: ChainId,
        tip_block_hash: Hash,
        tip_state_root: StateRoot,
    }

    impl MockEngine {
        fn genesis(chain_id: ChainId) -> Self {
            Self {
                chain_id,
                tip_block_hash: Hash::from_bytes([0u8; 32]),
                tip_state_root: chain_state::empty_root(),
            }
        }
    }

    impl Engine for MockEngine {
        fn propose_block(
            &self,
            parent_block_hash: Hash,
            _parent_state_root: StateRoot,
            height: BlockHeight,
            timestamp_millis: u64,
            candidate_transactions: Vec<Transaction>,
            _limits: BlockLimits,
        ) -> Block {
            Block {
                parent_block_hash,
                height,
                timestamp_millis,
                transactions: candidate_transactions,
            }
        }

        fn execute_block(
            &self,
            parent_state_root: StateRoot,
            block: &Block,
        ) -> Result<ExecutedBlock, BlockRejected> {
            for (index, tx) in block.transactions.iter().enumerate() {
                let transaction_index = u32::try_from(index).ok();
                if tx.body.chain_id != self.chain_id {
                    return Err(BlockRejected {
                        transaction_index,
                        reason: RejectionReason::WrongChainId,
                    });
                }
                if tx.verify_signature().is_err() {
                    return Err(BlockRejected {
                        transaction_index,
                        reason: RejectionReason::InvalidSignature,
                    });
                }
            }
            let mut bytes = Vec::new();
            parent_state_root.as_hash().encode(&mut bytes);
            block.encode(&mut bytes);
            let state_root = StateRoot::from_hash(hash_with_domain(DomainTag::TrieLeafV1, &bytes));
            let gas_used = block
                .transactions
                .iter()
                .map(|tx| tx.body.gas_limit.0)
                .sum();
            Ok(ExecutedBlock {
                state_root,
                gas_used,
                // `MockEngine` hashes parent+block as a stand-in root
                // and never models a real flat state, so there is
                // nothing for a diff to report.
                state_diff: chain_state::StateDiff::empty(),
                // Nothing here can abort: every transaction that passes
                // the chain-ID/signature checks above "succeeds".
                outcomes: vec![crate::TransactionOutcome::Success; block.transactions.len()],
            })
        }

        fn finalise_block(
            &mut self,
            block: &Block,
            executed: &ExecutedBlock,
        ) -> Result<(), FinaliseError> {
            self.tip_block_hash = block.hash();
            self.tip_state_root = executed.state_root;
            Ok(())
        }
    }

    fn test_transaction(seed: u8, chain_id: ChainId, gas_limit: u64) -> Transaction {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
        let body = TransactionBody {
            chain_id,
            sender,
            sequence_number: SequenceNumber(0),
            expiry: BlockHeight(1_000),
            gas_limit: GasAmount(gas_limit),
            max_fee_per_gas: GasPrice(1),
            declared_inputs: Vec::new(),
            call: chain_types::MoveCall {
                module_address: chain_types::Address::from_bytes([0u8; 32]),
                module_name: Vec::new(),
                function_name: Vec::new(),
                type_arguments: Vec::new(),
                arguments: Vec::new(),
            },
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
    fn propose_execute_finalise_round_trip() {
        let chain_id = ChainId(7);
        let mut engine = MockEngine::genesis(chain_id);
        let genesis_block_hash = engine.tip_block_hash;
        let genesis_root = engine.tip_state_root;
        let limits = BlockLimits {
            max_gas: GENESIS_MAX_BLOCK_GAS,
            max_size_bytes: MAX_BLOCK_SIZE_BYTES,
        };

        let tx = test_transaction(1, chain_id, 21_000);
        let block = engine.propose_block(
            genesis_block_hash,
            genesis_root,
            BlockHeight(1),
            1_700_000_000_000,
            vec![tx],
            limits,
        );
        assert_eq!(block.transactions.len(), 1);
        // Block linkage and the state it executes on top of are
        // different things, carried separately — not the same value.
        assert_eq!(block.parent_block_hash, genesis_block_hash);

        let executed = engine.execute_block(genesis_root, &block).unwrap();
        assert_eq!(executed.gas_used, 21_000);

        assert!(engine.finalise_block(&block, &executed).is_ok());
        assert_eq!(engine.tip_state_root, executed.state_root);
        assert_eq!(engine.tip_block_hash, block.hash());
    }

    #[test]
    fn execute_rejects_a_transaction_from_a_different_chain() {
        let chain_id = ChainId(7);
        let engine = MockEngine::genesis(chain_id);
        let genesis_root = engine.tip_state_root;

        let wrong_chain_tx = test_transaction(2, ChainId(999), 21_000);
        let block = Block {
            parent_block_hash: engine.tip_block_hash,
            height: BlockHeight(1),
            timestamp_millis: 1_700_000_000_000,
            transactions: vec![wrong_chain_tx],
        };

        let result = engine.execute_block(genesis_root, &block);
        assert_eq!(
            result,
            Err(BlockRejected {
                transaction_index: Some(0),
                reason: RejectionReason::WrongChainId,
            })
        );
    }

    #[test]
    fn execute_rejects_a_transaction_with_a_bad_signature() {
        let chain_id = ChainId(7);
        let engine = MockEngine::genesis(chain_id);
        let genesis_root = engine.tip_state_root;

        let mut tampered = test_transaction(3, chain_id, 21_000);
        tampered.body.sequence_number = SequenceNumber(1); // signed over seq 0
        let block = Block {
            parent_block_hash: engine.tip_block_hash,
            height: BlockHeight(1),
            timestamp_millis: 1_700_000_000_000,
            transactions: vec![tampered],
        };

        let result = engine.execute_block(genesis_root, &block);
        assert_eq!(
            result,
            Err(BlockRejected {
                transaction_index: Some(0),
                reason: RejectionReason::InvalidSignature,
            })
        );
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
    fn every_finalise_and_rejection_reason_reads_as_a_sentence() {
        readable(&[
            FinaliseErrorReason::StateRootMismatch,
            FinaliseErrorReason::NotOnCanonicalChain,
            FinaliseErrorReason::StorageUnavailable,
        ]);
        readable(&[
            RejectionReason::WrongChainId,
            RejectionReason::InvalidSignature,
            RejectionReason::InvalidExpiry,
            RejectionReason::Rejected,
            RejectionReason::InvalidBlockHeight,
            RejectionReason::InvalidBlockTimestamp,
            RejectionReason::TransactionGasLimitExceeded,
            RejectionReason::InvariantViolated,
            RejectionReason::MalformedBlock,
        ]);
    }
}
