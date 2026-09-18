//! Typed boundary between consensus and execution.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".

#![forbid(unsafe_code)]

pub mod block;
pub mod engine;

pub use block::{AbortReason, Block, ExecutedBlock, TransactionOutcome};
pub use engine::{
    BlockLimits, BlockRejected, Engine, FinaliseError, FinaliseErrorReason, RejectionReason,
    GENESIS_MAX_BLOCK_GAS, MAX_BLOCK_SIZE_BYTES,
};
