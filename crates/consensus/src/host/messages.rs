//! What crosses the host's edges: the messages it exchanges with peers, the
//! commands it gives its runtime, and what it reports having decided.

use std::time::Duration;

use chain_engine_api::{Block, ExecutedBlock};
use chain_signer::{HighWaterMark, SignerError};
use chain_types::{Address, BlockHeight, BlsSignature, DuplicateVoteEvidence, Hash};
use malachite_core_consensus::{LivenessMsg, SignedConsensusMsg};
use malachite_core_types::{CommitCertificate, Timeout};

use crate::context::ThrylosContext;

/// A block, with what its proposer contributes to the randomness beacon.
///
/// Consensus decides on a block's *hash*; the block itself travels on its
/// own, and this is how. `reveal` is `proposer`'s signature over the
/// height and seed (`chain_types::beacon`): the host checks it on arrival
/// and drops the message if it is not the proposer's, so a forged reveal
/// can never displace a real one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedBlock {
    pub proposer: Address,
    pub block: Block,
    pub reveal: BlsSignature,
}

impl ProposedBlock {
    /// What consensus votes on.
    pub fn id(&self) -> Hash {
        self.block.hash()
    }
}

/// A decided block with the proof that it was decided: everything a node
/// that missed the height needs to adopt it without having watched
/// consensus. Nothing in it is taken on trust — the receiver checks the
/// certificate against the validator set it already knows, the reveal
/// against the proposer the draw picked, and executes the block itself.
#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub block: Block,
    /// The quorum of precommits that decided `block`.
    pub certificate: CommitCertificate<ThrylosContext>,
    /// The proposer's reveal, which the next height's seed is built from.
    pub reveal: BlsSignature,
}

/// "I am at `from`; send me what was decided from there on."
///
/// Unauthenticated, and it need not be: the reply is bounded by
/// `HostConfig::sync_batch` and is only ever addressed to a validator, and
/// what a reply contains is checked by whoever receives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRequest {
    pub requester: Address,
    pub from: BlockHeight,
}

/// Consecutive decided blocks, oldest first, for `requester`.
#[derive(Debug, Clone)]
pub struct SyncResponse {
    pub requester: Address,
    pub commits: Vec<CommitRecord>,
}

/// A message between hosts.
#[derive(Debug, Clone)]
pub enum Message {
    /// A vote or a proposal.
    Consensus(SignedConsensusMsg<ThrylosContext>),
    /// A vote or certificate sent to help a peer catch up to a round.
    Liveness(LivenessMsg<ThrylosContext>),
    /// A proposed block's contents.
    Block(ProposedBlock),
    /// A node that has fallen behind asking a peer for what it missed. Sent
    /// to one peer (see [`Outbox::directed`]).
    SyncRequest(SyncRequest),
    /// The answer, sent to the requester alone.
    SyncResponse(SyncResponse),
}

/// A timer the runtime should keep for the host. When one fires it calls
/// `Host::handle_timeout` with the same [`Timeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerCommand {
    Schedule { timeout: Timeout, after: Duration },
    Cancel(Timeout),
    CancelAll,
}

/// A block the chain has committed, with everything needed to persist and
/// serve it.
#[derive(Debug, Clone)]
pub struct Committed {
    pub height: BlockHeight,
    pub block: Block,
    /// What executing the block produced, including its state diff.
    pub executed: ExecutedBlock,
    /// The quorum of precommits that decided it.
    pub certificate: CommitCertificate<ThrylosContext>,
    /// The proposer's reveal, which the next height's seed is built from.
    pub reveal: BlsSignature,
    /// The seed for the *next* height. The host also keeps it in its
    /// [`crate::host::CommitLog`], which is where a restart finds it.
    pub seed_after: Hash,
}

impl Committed {
    /// The part of this that a peer can be sent and can check.
    pub fn record(&self) -> CommitRecord {
        CommitRecord {
            block: self.block.clone(),
            certificate: self.certificate.clone(),
            reveal: self.reveal,
        }
    }
}

/// Everything the host wants done, collected as it runs. The runtime
/// drains it with `Host::take_outbox` after each call.
#[derive(Debug, Default)]
pub struct Outbox {
    /// To send to every peer.
    pub messages: Vec<Message>,
    /// To send to one validator only, named by its address.
    pub directed: Vec<(Address, Message)>,
    pub timers: Vec<TimerCommand>,
    /// Blocks committed, in order.
    pub committed: Vec<Committed>,
    /// Equivocation this node witnessed, ready to be submitted for slashing
    /// as a `staking::submit_evidence` transaction.
    pub evidence: Vec<DuplicateVoteEvidence>,
}

/// Why the host stopped. Once it has, it does nothing further: a validator
/// that cannot be sure of its own state must not keep voting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaltReason {
    /// The signer refused what it was asked to sign — it had already signed
    /// at or past that position, or could not record the new one. Voting
    /// on would risk signing twice.
    SignerRefused(SignerError),
    /// Asked to sign something different from what was already signed at
    /// the same position: an attempt to equivocate, refused.
    ConflictingSignature(HighWaterMark),
    /// The committed state could not be read.
    ChainUnreadable,
    /// There is no validator to run consensus with.
    NoValidators,
    /// Consensus decided a block this node then could not commit — the
    /// block is missing from its books or fails its own execution — so it
    /// has fallen out of step with the chain and must sync rather than
    /// guess.
    CannotCommit { height: BlockHeight },
    /// The chain refused a block this node itself had executed.
    FinaliseFailed { height: BlockHeight },
    /// Something the host keeps on disk — its write-ahead log, its record of
    /// what it signed, its commit history — could not be written, flushed or
    /// read. A host that cannot remember what it is about to do must not do
    /// it.
    StorageFailed(String),
    /// The chain is past genesis but the host has no record of the seed for
    /// the height after its head, so it cannot tell who proposes.
    SeedUnknown,
    /// The consensus engine reported an error it cannot continue past.
    Engine(String),
}
