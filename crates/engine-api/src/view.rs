//! What consensus may read of the chain it drives, beyond the three
//! calls of [`crate::Engine`].
//!
//! `docs/spec.md` keeps the boundary to `propose_block`, `execute_block`
//! and `finalise_block`, and that stays true of *execution*: nothing here
//! changes state. But consensus has to know who the validators are and what
//! the chain's head is, and those are facts about committed state, not
//! operations. [`ChainView`] is that read-only window, and it is
//! deterministic: two nodes at the same head see the same answers.

use chain_state::StateRoot;
use chain_types::{Address, BlockHeight, BlsPublicKey, ChainId, Hash};

use crate::engine::BlockLimits;

/// One validator of the active set, as consensus needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorInfo {
    /// The validator's identity: its operator's address.
    pub address: Address,
    /// The key its consensus messages verify under.
    pub consensus_key: BlsPublicKey,
    /// Its weight in votes. Stake, scaled down uniformly if the total would
    /// not fit a `u64`: proportions are what consensus cares about.
    pub voting_power: u64,
}

/// The last block the chain has committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub height: BlockHeight,
    pub timestamp_ms: u64,
    /// The hash a next block names as its parent: the last block's hash, or
    /// at genesis the genesis configuration's.
    pub block_hash: Hash,
    pub state_root: StateRoot,
}

/// The committed state could not be read: it is damaged, not merely empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainViewError;

impl core::fmt::Display for ChainViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the committed state could not be read")
    }
}

impl std::error::Error for ChainViewError {}

/// A read-only view of the committed chain. See the module docs.
pub trait ChainView {
    /// The network domain every consensus signature must commit to.
    fn chain_id(&self) -> ChainId;

    /// The last committed block.
    fn head(&self) -> Result<Head, ChainViewError>;

    /// The validators consensus runs on for the height after [`Self::head`],
    /// largest voting power first. Never empty for a chain that can make
    /// progress; a caller must not assume it.
    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError>;

    /// The gas and size a block proposed on top of [`Self::head`] may use.
    fn block_limits(&self) -> Result<BlockLimits, ChainViewError>;
}
