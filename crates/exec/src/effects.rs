//! What a call does and what it is told about the block it runs in.
//!
//! Shared by the two things that can execute a transaction's call: the
//! fixed Move functions in [`crate::executor`] and the native modules in
//! [`crate::native`].

use chain_engine_api::AbortReason;
use chain_modules::GovernedParams;
use chain_state::{StateKey, StateValue};
use chain_types::{BlockHeight, ChainId};

/// What a call would change, held back rather than applied: handlers
/// read state and return one of these, and only the caller decides
/// whether it ever reaches `state`. That is what makes an abort's
/// rollback structural instead of something each handler has to
/// remember to undo. `None` is a deletion.
pub(crate) struct CallEffects {
    pub changes: Vec<(StateKey, Option<StateValue>)>,
    pub gas_used: u64,
}

/// Why a call produced no [`CallEffects`].
pub(crate) enum CallError {
    /// The transaction's own doing: it was valid to run, and running it
    /// failed. Becomes an aborted [`chain_engine_api::TransactionOutcome`].
    Abort(AbortReason),
    /// A Move call failed after the VM meter charged part or all of its
    /// budget.
    MeteredAbort { reason: AbortReason, gas_used: u64 },
    /// Not the transaction's doing — the executor itself couldn't do
    /// what it should always be able to (build its VM from constants,
    /// read back a state invariant genesis established, unpack a value
    /// its own module just returned, decode a record a module wrote).
    /// Nothing a transaction can trigger, so charging its sender for it
    /// would be wrong; the block is rejected instead, the same way a
    /// corrupt account read is.
    Internal,
}

impl From<AbortReason> for CallError {
    fn from(reason: AbortReason) -> Self {
        Self::Abort(reason)
    }
}

/// The block a call runs in, as far as a call may know it: its own height
/// and timestamp from the header, the price its gas is charged at, and the
/// governed parameters as they stood when the block began.
#[derive(Clone, Copy)]
pub(crate) struct BlockCtx {
    /// The chain this executor runs: what evidence must have been signed for.
    pub chain_id: ChainId,
    pub height: BlockHeight,
    pub timestamp_ms: u64,
    pub base_fee: u64,
    pub params: GovernedParams,
}
