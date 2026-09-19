//! Typed boundary between consensus and execution.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! [`timestamp`] holds the block-timestamp rules that don't need chain
//! state: the clock tolerance a host checks before voting, and the
//! timestamp a proposer should pick.

#![forbid(unsafe_code)]

pub mod block;
pub mod engine;
pub mod timestamp;

pub use block::{AbortReason, Block, ExecutedBlock, TransactionOutcome};
pub use engine::{
    BlockLimits, BlockRejected, Engine, FinaliseError, FinaliseErrorReason, RejectionReason,
    GENESIS_MAX_BLOCK_GAS, MAX_BLOCK_SIZE_BYTES,
};
