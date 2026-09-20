//! The consensus host: the piece that owns the consensus engine's I/O loop
//! and wires it to everything real — the chain it drives, the signer that
//! holds the key, the clock, the mempool.
//!
//! Malachite's core is pure: it is handed an input (a vote, a timeout, a
//! decided value) and *yields effects* — sign this, verify that, schedule a
//! timer, publish a message, build a block, commit a decision — expecting
//! the host to carry each out and resume it with the answer. This is that
//! host. It is a **sans-IO state machine**: a runtime feeds it
//! [`Host::handle_message`] and [`Host::handle_timeout`], drains
//! [`Host::take_outbox`] for what to send, which timers to keep and what
//! was committed, and supplies the clock, the transactions and the
//! signature log through the small traits in [`ports`]. Nothing here
//! touches a socket, a thread or a disk, so a network of hosts can be run
//! in a test process and every failure staged deterministically.
//!
//! # What the host does for each effect
//!
//! - **Signing.** Every vote and proposal goes through `chain-signer`,
//!   which refuses to sign at or below a position it has already signed.
//!   The host puts a log in front of it ([`ports::SignedLog`]): the same
//!   bytes at the same position get the signature already made (so a
//!   replay after a restart is harmless), different bytes are refused.
//!   Any refusal halts the host rather than risk equivocating.
//! - **Verifying.** Signatures against the key in the canonical validator
//!   set; commit, polka and round certificates against that set with the
//!   right quorum ([`crate::certificate`]).
//! - **Building a block** when this validator is the proposer: pack
//!   candidate transactions, drop any that execution rejects, timestamp it
//!   from the clock (never earlier than its parent's successor), and
//!   attach the proposer's beacon *reveal*.
//! - **Judging a proposed block** before voting for it: its parent, its
//!   height, its timestamp against the parent and against this node's clock
//!   (`chain_engine_api::timestamp`), and by *executing it*. A block that
//!   fails any of that is voted against.
//! - **Committing** a decided block to the chain and moving to the next
//!   height with the validator set the chain now reports and the seed the
//!   decided block's reveal produced.
//!
//! # Why `ProposalAndParts`
//!
//! Malachite offers `ProposalOnly` (the proposal carries the whole value)
//! and `ProposalAndParts` (it carries the value's id and the value follows
//! separately). With `ProposalOnly` the engine constructs the proposed value
//! itself and marks it `Valid` — its own source carries a `TODO` about
//! asking the host — so a host has no way to vote against a proposal, and a
//! validator would prevote for a block it had never executed. This host
//! therefore runs `ProposalAndParts` and sends the block as a
//! [`messages::ProposedBlock`], holds every proposal until the block has
//! arrived and been judged, and only then tells the engine the verdict
//! (`Input::ProposedValue`). `tests/network.rs` has a proposer whose blocks
//! are invalid and shows the network voting against them.
//!
//! # Proposer selection
//!
//! `select_proposer` is the stake-weighted draw of [`crate::proposer`]. Its
//! seed comes from the previous height's decided block
//! (`chain_types::beacon`), which is why a block travels with a
//! [`messages::ProposedBlock`]: consensus votes on a hash, and the reveal
//! that fixes the *next* seed has to reach everyone alongside the block.
//!
//! # Restarting: the write-ahead log
//!
//! The engine is a deterministic function of what it has been fed, so a
//! host that remembers those inputs can feed them again and arrive where it
//! was: with the value it had locked, the blocks it had built, the votes it
//! had seen. [`ports::Wal`] is that memory. Before acting on a verified
//! vote, proposal or certificate, a block from a peer, a timeout, a block of
//! its own, or a decision to vote against a block, the host appends it, and
//! it flushes before the runtime can collect anything the call produced —
//! so nothing has left the node that a restart would not reproduce. On
//! [`Host::start`] the entries for the height are replayed through the same
//! code that first handled them. The signer's log makes every re-signed
//! message the one already signed; a block built for a round is proposed
//! again as it was; a block voted against stays voted against even if the
//! clock has since moved on. If a log cannot be written, the host halts:
//! one that cannot remember what it is about to do must not do it.
//!
//! The engine's own `Effect::WalAppend` is not used, because what has to be
//! remembered includes what it does not know about — the blocks.
//!
//! # Catching up: sync
//!
//! A node that missed a height — it never received the block, or it lacks a
//! proposer's reveal — is not stuck. It notices that validators are working
//! at a later height (a verified vote or proposal past its own), and if that
//! is still so after [`HostConfig::sync_grace_ms`] it asks one of them for
//! what was decided from its height on ([`messages::SyncRequest`]); the
//! answer is a run of [`messages::CommitRecord`]s. Nothing in an answer is
//! trusted. For each block the node checks the commit certificate against
//! the validator set it already holds, the reveal against the proposer the
//! draw picked, and then *executes the block itself*; only then does it
//! commit and move on. Peers are tried in turn if one does not answer. A
//! block certified by a quorum that this node's own chain cannot accept
//! means the node is on another chain, and it halts
//! ([`HaltReason::CannotCommit`]) rather than guess.
//!
//! The runtime calls [`Host::tick`] when [`Host::next_wake_ms`] comes due;
//! everything else is driven by messages.
//!
//! # Pace
//!
//! A committed block does not start the next height at once: the host waits
//! [`HostConfig::min_block_interval_ms`] (the spec's 1 s target) and starts it
//! from [`Host::tick`]. Without that, a height would begin the moment the last
//! ended, and a validator with no one to wait for would commit blocks without
//! end inside a single call.
//!
//! # What is not built
//!
//! - **Durable storage is not in this crate.** [`ports::Wal`],
//!   [`ports::CommitLog`], [`ports::SignedLog`] and the signer's mark store are
//!   traits, here with in-memory implementations for tests; tier A does no
//!   I/O. The file-backed ones are in `chain-node`, and the restart tests run
//!   against them. Every write a safety argument rests on must be durable
//!   before the trait method returns, and every one can fail — a failure halts
//!   the host, and a signature whose record could not be written is never
//!   released.
//! - **A source of blocks other than validators.** A node whose peers all
//!   fail to answer stays where it is.
//! - **Observer nodes.** The host assumes it is one of the validators.
//! - **Vote extensions**, which the spec does not use.

pub mod messages;
pub mod ports;
pub mod signing;
mod wal;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use chain_engine_api::timestamp::{is_after_parent, is_within_clock_tolerance, proposal_timestamp};
use chain_engine_api::{Block, ChainView, Engine, ExecutedBlock};
use chain_signer::{ConsensusSigner, HighWaterMark, Step};
use chain_types::beacon::{next_seed, verify_reveal};
use chain_types::bls::{verify_aggregate, BlsSignature, DST_VOTE};
use chain_types::codec::Encode;
use chain_types::{Address, BlockHeight, Hash, Transaction};
use malachite_core_consensus::{
    process, ConsensusMsg, Effect, Input, LivenessMsg, LocallyProposedValue, MisbehaviorEvidence,
    Params, ProposedValue, Resumable, Resume, SignedConsensusMsg, State, ThresholdParams,
};
use malachite_core_types::{
    CommitCertificate, Context as _, LinearTimeouts, Round, SignedMessage, SignedProposal,
    SignedVote, Timeout, TimeoutKind, Validator as _, ValidatorSet as _, Validity, ValueOrigin,
    ValuePayload, VoteExtensionPolicy,
};
use malachite_metrics::Metrics;

use crate::certificate::{
    verify_commit_certificate, verify_polka_certificate, verify_round_certificate,
};
use crate::context::ThrylosContext;
use crate::evidence::duplicate_vote_evidence;
use crate::types::{
    round_as_u64, ConsensusAddress, ConsensusHeight, ConsensusProposal, ConsensusValidatorSet,
    ConsensusValue,
};
use wal::Entry;

pub use messages::{
    CommitRecord, Committed, HaltReason, Message, Outbox, ProposedBlock, SyncRequest, SyncResponse,
    TimerCommand,
};
pub use ports::{
    Clock, CommitLog, MemoryCommitLog, MemorySignedLog, MemoryStorage, MemoryWal, SignedEntry,
    SignedLog, Storage, StorageError, TransactionSource, Wal,
};
pub use signing::{GuardedSigner, SigningRefusal};

/// The host's tunables.
#[derive(Debug, Clone, Copy)]
pub struct HostConfig {
    /// How long each step waits. `docs/spec.md`, "Consensus": "1s target,
    /// 2s timeout" — the propose step's timeout is the 2 seconds; the
    /// vote steps' and every round's growth are choices.
    pub timeouts: LinearTimeouts,
    /// Quorum and honest thresholds: more than two thirds and more than
    /// one third by default.
    pub threshold: ThresholdParams,
    /// **A choice.** The most transactions asked of the source for one
    /// block; the block's gas limit is what actually bounds it.
    pub max_transactions: usize,
    /// **A choice.** How many heights ahead a block message is held for,
    /// so a peer that is slightly ahead is not made to resend.
    pub max_future_heights: u64,
    /// **A choice.** The most block messages held per future height, and
    /// (with the same cap) the most distinct blocks and proposals kept for
    /// the height being run: everything a peer can make this node hold is
    /// bounded.
    pub max_pending_per_height: usize,
    /// **A choice.** How long a validator has to be seen working past this
    /// node's height before it asks for what it missed. Peers a moment ahead
    /// are the normal case at every height boundary; a node that is still
    /// behind a second later has missed something.
    pub sync_grace_ms: u64,
    /// **A choice.** How long to wait for an answer before asking again,
    /// of a different peer.
    pub sync_retry_ms: u64,
    /// **A choice.** The most decided blocks sent in one answer.
    pub sync_batch: usize,
    /// The spec's "1s target" for block time (`docs/spec.md`, "Consensus":
    /// "1s target, 2s timeout"), as a pace: after committing a block the host
    /// waits this long, by its own clock, before it starts the next height.
    ///
    /// The wait comes *before* the height starts, in every node, so that the
    /// propose timeout counts from the moment the height starts and keeps all
    /// of its two seconds for the proposal to arrive; a wait inside the
    /// proposer would take the pace out of that time. It is measured from the
    /// node's own commit, not from the block's timestamp, so validators whose
    /// clocks differ by seconds (which the timestamp rule tolerates) do not
    /// drift apart in it.
    ///
    /// It is a pace and not a rule for validity: a block a validator proposes
    /// sooner is still accepted, and a node that adopts blocks from a peer to
    /// catch up starts its height at once, without waiting. `0` means no pace:
    /// each height starts as soon as the last is committed, which is as fast as
    /// the network lets consensus go, and without end for a validator that has
    /// no one to wait for.
    pub min_block_interval_ms: u64,
    /// **A choice.** The most received messages and blocks written to the
    /// write-ahead log for one height. Past it they are simply not
    /// remembered — after a restart the node may have to be told them again
    /// — so that a validator sending endless distinct signed votes cannot
    /// fill the disk. This node's own blocks, its verdicts and its timeouts
    /// are always written.
    pub max_wal_entries: usize,
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            timeouts: LinearTimeouts {
                propose: Duration::from_secs(2),
                ..LinearTimeouts::default()
            },
            threshold: ThresholdParams::default(),
            max_transactions: 10_000,
            max_future_heights: 2,
            max_pending_per_height: 64,
            sync_grace_ms: 1_000,
            sync_retry_ms: 3_000,
            sync_batch: 16,
            min_block_interval_ms: 1_000,
            max_wal_entries: 4096,
        }
    }
}

/// What judging a block concluded, kept so it is only executed once.
#[derive(Debug, Clone)]
struct Verdict {
    validity: Validity,
    /// The result of executing it, if it was valid: kept for the commit.
    executed: Option<ExecutedBlock>,
}

/// A proposal seen for the height, waiting for its block.
#[derive(Debug, Clone, Copy)]
struct Prop {
    round: Round,
    pol_round: Round,
    /// Whether the engine has been told about the block for it.
    fed: bool,
}

/// What the host knows about being behind.
#[derive(Debug, Default)]
struct Lag {
    /// Validators seen, with a checked signature, working at a height past
    /// this node's, and the highest each was seen at. Such a validator has
    /// committed everything below that height, so it can answer a request.
    ahead: BTreeMap<Address, u64>,
    /// When the first of them was seen.
    since_ms: Option<u64>,
    last_request_ms: Option<u64>,
    /// How many requests since the node last made progress, used to rotate
    /// through the peers.
    attempts: usize,
}

/// What became of one block from a peer's answer.
enum Adopted {
    Committed,
    /// Already have it.
    Old,
    /// Not usable: out of order, or not proven. The rest of the answer is
    /// dropped with it.
    Rejected,
}

/// An effect could not be carried out; the reason is in `Env::halted`.
#[derive(Debug)]
struct HostError;

/// Everything but the engine's own state, so that carrying out an effect
/// (which needs `&mut Env`) can happen while the engine (`&mut State`) is
/// mid-step.
struct Env<X, T, C, K: ConsensusSigner, L, D> {
    config: HostConfig,
    ctx: ThrylosContext,
    me: ConsensusAddress,
    exec: X,
    source: T,
    clock: C,
    guard: GuardedSigner<K, L>,
    storage: D,

    /// The height being run, its validators (with its seed) and that seed.
    height: BlockHeight,
    validators: ConsensusValidatorSet,
    seed: Hash,
    /// The seed the decided block's reveal produced, adopted at `Finalize`.
    seed_after: Option<Hash>,

    // Per height.
    blocks: BTreeMap<Hash, Block>,
    reveals: BTreeMap<Address, BlsSignature>,
    verdicts: BTreeMap<Hash, Verdict>,
    props: BTreeMap<(Hash, Address), Prop>,
    announced: BTreeSet<Hash>,

    /// The write-ahead log's entries for this height, as written, so that
    /// replaying one does not write it a second time.
    logged: BTreeSet<Vec<u8>>,
    /// How many entries this height has in the log.
    logged_count: usize,
    wal_dirty: bool,
    /// Blocks this validator built, by round, so it never builds a second
    /// for a round it already has one for.
    own_blocks: BTreeMap<u64, ProposedBlock>,
    /// Blocks the log says this node judged invalid.
    judged_invalid: BTreeSet<Hash>,

    /// Set when the engine decided a block this node could not commit
    /// itself; the height then stays open until a peer's answer closes it.
    awaiting_sync: bool,
    /// When the next height starts, if the pace has it waiting to.
    next_height_at_ms: Option<u64>,
    lag: Lag,
    future_blocks: BTreeMap<u64, Vec<ProposedBlock>>,
    queue: VecDeque<Input<ThrylosContext>>,
    outbox: Outbox,
    halted: Option<HaltReason>,
}

/// What a host talks to besides the chain: where transactions come from,
/// what time it is, and the validator's key with its record of what it has
/// signed.
pub struct Ports<T, C, K: ConsensusSigner, L, D> {
    pub source: T,
    pub clock: C,
    pub signer: K,
    pub log: L,
    /// The host's own history of what was decided; see [`CommitLog`].
    pub storage: D,
}

/// The host. See the module docs.
pub struct Host<X, T, C, K: ConsensusSigner, L, D> {
    consensus: State<ThrylosContext>,
    metrics: Metrics,
    env: Env<X, T, C, K, L, D>,
}

impl<X, T, C, K, L, D> Host<X, T, C, K, L, D>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    K: ConsensusSigner,
    L: SignedLog,
    D: Storage,
{
    /// A host for the validator `me` on the chain `exec`, at the chain's
    /// current head. `genesis_seed` is `chain_types::beacon::genesis_seed` of
    /// the genesis hash; past genesis the seed for the next height is the
    /// one the [`CommitLog`] recorded when it committed the head, so a
    /// restart finds its place there.
    pub fn new(
        config: HostConfig,
        me: Address,
        exec: X,
        ports: Ports<T, C, K, L, D>,
        genesis_seed: Hash,
    ) -> Result<Self, HaltReason> {
        let Ports {
            source,
            clock,
            signer,
            log,
            storage,
        } = ports;
        let head = exec.head().map_err(|_| HaltReason::ChainUnreadable)?;
        let infos = exec
            .validator_set()
            .map_err(|_| HaltReason::ChainUnreadable)?;
        if infos.is_empty() {
            return Err(HaltReason::NoValidators);
        }
        let height = BlockHeight(head.height.0.saturating_add(1));
        let seed = if head.height.0 == 0 {
            genesis_seed
        } else {
            storage
                .seed_after(head.height)
                .ok_or(HaltReason::SeedUnknown)?
        };
        let validators = ConsensusValidatorSet::from_infos(&infos, seed);
        let me = ConsensusAddress(me);

        let consensus = State::new(
            ThrylosContext::new(),
            ConsensusHeight(height),
            validators.clone(),
            Params {
                address: me,
                threshold_params: config.threshold,
                // Not `ProposalOnly`: in that mode the engine builds the
                // value itself and marks it valid, never asking the host —
                // so a host could not vote against a bad block. With
                // `ProposalAndParts` the proposal carries the block's hash,
                // the block travels as its own message, and the engine
                // waits for this host's verdict.
                value_payload: ValuePayload::ProposalAndParts,
                enabled: true,
            },
            1_000,
            1_000,
        );
        Ok(Self {
            consensus,
            metrics: Metrics::new(),
            env: Env {
                config,
                ctx: ThrylosContext::new(),
                me,
                exec,
                source,
                clock,
                guard: GuardedSigner::new(signer, log),
                storage,
                height,
                validators,
                seed,
                seed_after: None,
                blocks: BTreeMap::new(),
                reveals: BTreeMap::new(),
                verdicts: BTreeMap::new(),
                props: BTreeMap::new(),
                announced: BTreeSet::new(),
                logged: BTreeSet::new(),
                logged_count: 0,
                wal_dirty: false,
                own_blocks: BTreeMap::new(),
                judged_invalid: BTreeSet::new(),
                awaiting_sync: false,
                next_height_at_ms: None,
                lag: Lag::default(),
                future_blocks: BTreeMap::new(),
                queue: VecDeque::new(),
                outbox: Outbox::default(),
                halted: None,
            },
        })
    }

    /// Begins consensus at the height after the chain's head.
    ///
    /// If the write-ahead log holds entries for that height, this is a
    /// restart in the middle of it: they are replayed, in order, through the
    /// same code that handled them the first time, so the engine arrives
    /// where it was — with the value it had locked, the blocks it had
    /// built, the votes it had seen — and anything it signs on the way is
    /// what it signed before.
    pub fn start(&mut self) {
        if self.env.halted.is_some() {
            return;
        }
        let entries = match self.env.storage.start_height(self.env.height) {
            Ok(entries) => entries,
            Err(error) => {
                self.env.halt(HaltReason::StorageFailed(error.0));
                return;
            }
        };
        let mut replay = Vec::with_capacity(entries.len());
        for bytes in entries {
            match Entry::decode(&bytes) {
                Ok(entry) => {
                    self.env.remember(&entry, bytes);
                    replay.push(entry);
                }
                Err(_) => {
                    self.env
                        .halt(HaltReason::StorageFailed("an entry cannot be read".into()));
                    return;
                }
            }
        }

        let height = self.env.height;
        let set = self.env.validators.clone();
        self.env.queue.push_back(Input::StartHeight(
            ConsensusHeight(height),
            set,
            false,
            None,
            VoteExtensionPolicy::default(),
        ));
        self.pump();
        for entry in replay {
            match entry {
                Entry::Message(message) => self.route(message),
                Entry::Timeout(timeout) => {
                    self.env.queue.push_back(Input::TimeoutElapsed(timeout));
                }
                Entry::OwnBlock { .. } | Entry::Invalid(_) => {}
            }
            self.pump();
        }
        self.env.flush_wal();
    }

    /// A message from a peer.
    pub fn handle_message(&mut self, message: Message) {
        if self.env.halted.is_some() {
            return;
        }
        self.route(message);
        self.pump();
        self.env.maybe_request_sync();
        self.env.flush_wal();
    }

    fn route(&mut self, message: Message) {
        match message {
            Message::Consensus(SignedConsensusMsg::Vote(vote)) => {
                self.env.note_ahead_vote(&vote);
                self.input_for_height(vote.message.height, Input::Vote(vote));
            }
            Message::Consensus(SignedConsensusMsg::Proposal(proposal)) => {
                self.env.note_ahead_proposal(&proposal);
                self.input_for_height(proposal.message.height, Input::Proposal(proposal));
            }
            Message::Liveness(LivenessMsg::Vote(vote)) => {
                self.env.note_ahead_vote(&vote);
                self.input_for_height(vote.message.height, Input::Vote(vote));
            }
            Message::Liveness(LivenessMsg::PolkaCertificate(certificate)) => {
                self.input_for_height(certificate.height, Input::PolkaCertificate(certificate));
            }
            Message::Liveness(LivenessMsg::SkipRoundCertificate(certificate)) => {
                self.input_for_height(certificate.height, Input::RoundCertificate(certificate));
            }
            Message::Block(block) => self.env.receive_block(block),
            Message::SyncRequest(request) => self.env.serve(&request),
            Message::SyncResponse(response) => {
                if self.env.adopt(response) && self.env.halted.is_none() {
                    // The height the engine was stuck at is over; it
                    // restarts at the new one, cancelling its timers.
                    self.env.start_next_height();
                }
            }
        }
    }

    /// Gives the host a chance to act on the passage of time: starting the
    /// next height once the pace allows ([`HostConfig::min_block_interval_ms`]),
    /// and asking a peer for what it missed, once it has been behind long
    /// enough. The runtime should call it whenever [`Self::next_wake_ms`]
    /// comes due, and it is harmless to call at any other time.
    pub fn tick(&mut self) {
        if self.env.halted.is_some() {
            return;
        }
        if self
            .env
            .next_height_at_ms
            .is_some_and(|due| self.env.clock.now_ms() >= due)
        {
            self.env.start_next_height();
            self.pump();
            self.env.flush_wal();
        }
        self.env.maybe_request_sync();
    }

    /// The time, on the host's clock, at which [`Self::tick`] next has
    /// something to do: the next height's start, or asking for what was
    /// missed. `None` when neither is pending.
    pub fn next_wake_ms(&self) -> Option<u64> {
        if self.env.halted.is_some() {
            return None;
        }
        match (self.env.next_height_at_ms, self.env.next_sync_action_ms()) {
            (Some(start), Some(sync)) => Some(start.min(sync)),
            (start, sync) => start.or(sync),
        }
    }

    /// A timer the host asked for has fired.
    pub fn handle_timeout(&mut self, timeout: Timeout) {
        if self.env.halted.is_some() {
            return;
        }
        // Written even if identical to an earlier one: a timer can fire
        // again, and it is the sequence that is replayed.
        if self.env.log_timeout(timeout).is_err() {
            return;
        }
        self.env.queue.push_back(Input::TimeoutElapsed(timeout));
        self.pump();
        self.env.maybe_request_sync();
        self.env.flush_wal();
    }

    /// What the host wants done, collected since the last call.
    pub fn take_outbox(&mut self) -> Outbox {
        core::mem::take(&mut self.env.outbox)
    }

    /// The chain the host is driving.
    pub const fn chain(&self) -> &X {
        &self.env.exec
    }

    /// Gives the chain back, for a runtime that is tearing this host down —
    /// after a crash it is the chain that is durable, and the next host is
    /// built on it.
    pub fn into_chain(self) -> X {
        self.env.exec
    }

    /// Why the host stopped, if it has.
    pub const fn halted(&self) -> Option<&HaltReason> {
        self.env.halted.as_ref()
    }

    /// The height being run.
    pub const fn height(&self) -> BlockHeight {
        self.env.height
    }

    /// The beacon seed in force for [`Self::height`].
    pub const fn seed(&self) -> &Hash {
        &self.env.seed
    }

    /// Queues `input` if it is for the current or a later height; an earlier
    /// one is history and is dropped. (The engine itself holds inputs for
    /// heights it has not reached.)
    fn input_for_height(&mut self, height: ConsensusHeight, input: Input<ThrylosContext>) {
        if height.0 >= self.env.height {
            self.env.queue.push_back(input);
        }
    }

    /// Runs queued inputs through the engine until none are left, carrying
    /// out every effect each yields.
    fn pump(&mut self) {
        while let Some(input) = self.env.queue.pop_front() {
            if self.env.halted.is_some() {
                self.env.queue.clear();
                return;
            }
            let result: Result<(), malachite_core_consensus::Error<ThrylosContext>> = process!(
                input: input,
                state: &mut self.consensus,
                metrics: &self.metrics,
                with: effect => self.env.handle_effect(effect)
            );
            if let Err(error) = result {
                if self.env.halted.is_none() {
                    self.env.halted = Some(HaltReason::Engine(format!("{error:?}")));
                }
            }
        }
    }
}

impl<X, T, C, K, L, D> Env<X, T, C, K, L, D>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    K: ConsensusSigner,
    L: SignedLog,
    D: Storage,
{
    fn halt(&mut self, reason: HaltReason) -> HostError {
        if self.halted.is_none() {
            self.halted = Some(reason);
        }
        HostError
    }

    // ---- the write-ahead log -----------------------------------------------------

    /// Notes that `entry`, in the form `bytes`, is already in the log.
    fn remember(&mut self, entry: &Entry, bytes: Vec<u8>) {
        self.logged_count = self.logged_count.saturating_add(1);
        match entry {
            Entry::OwnBlock { round, proposed } => {
                self.own_blocks
                    .insert(round_as_u64(*round), proposed.clone());
            }
            Entry::Invalid(id) => {
                self.judged_invalid.insert(*id);
            }
            Entry::Message(_) | Entry::Timeout(_) => {}
        }
        if !matches!(entry, Entry::Timeout(_)) {
            self.logged.insert(bytes);
        }
    }

    /// Writes `entry`, unless it is already there. A `bounded` entry — one a
    /// peer can cause — is not written once the height has the configured
    /// number.
    fn log(&mut self, entry: &Entry, bounded: bool) -> Result<(), HostError> {
        let bytes = entry.encode();
        if self.logged.contains(&bytes) {
            return Ok(());
        }
        if bounded && self.logged_count >= self.config.max_wal_entries {
            return Ok(());
        }
        if let Err(error) = self.storage.append(self.height, &bytes) {
            return Err(self.halt(HaltReason::StorageFailed(error.0)));
        }
        self.wal_dirty = true;
        self.remember(entry, bytes);
        Ok(())
    }

    fn log_timeout(&mut self, timeout: Timeout) -> Result<(), HostError> {
        let bytes = Entry::Timeout(timeout).encode();
        if let Err(error) = self.storage.append(self.height, &bytes) {
            return Err(self.halt(HaltReason::StorageFailed(error.0)));
        }
        self.logged_count = self.logged_count.saturating_add(1);
        self.wal_dirty = true;
        Ok(())
    }

    /// Makes what was logged survive a crash before the runtime can take
    /// anything this call produced; if that fails, nothing is released.
    fn flush_wal(&mut self) {
        if !self.wal_dirty {
            return;
        }
        self.wal_dirty = false;
        if let Err(error) = self.storage.flush() {
            self.halt(HaltReason::StorageFailed(error.0));
        }
        if self.halted.is_some() {
            self.outbox.messages.clear();
            self.outbox.directed.clear();
        }
    }

    fn handle_effect(
        &mut self,
        effect: Effect<ThrylosContext>,
    ) -> Result<Resume<ThrylosContext>, HostError> {
        Ok(match effect {
            Effect::CancelAllTimeouts(r) => {
                self.outbox.timers.push(TimerCommand::CancelAll);
                r.resume_with(())
            }
            Effect::CancelTimeout(timeout, r) => {
                self.outbox.timers.push(TimerCommand::Cancel(timeout));
                r.resume_with(())
            }
            Effect::ScheduleTimeout(timeout, r) => {
                if let Some(after) = self.duration(timeout) {
                    self.outbox
                        .timers
                        .push(TimerCommand::Schedule { timeout, after });
                }
                r.resume_with(())
            }
            Effect::StartRound(_, _, _, _, r) => r.resume_with(()),
            Effect::PublishConsensusMsg(message, r) => {
                if let SignedConsensusMsg::Proposal(proposal) = &message {
                    // Our own proposal, possibly a re-proposal of a value
                    // first proposed by someone else in an earlier round:
                    // whichever it is, our reveal has to reach everyone
                    // with the block, since the next seed is built from the
                    // decided round's proposer's.
                    if proposal.message.validator_address == self.me {
                        self.announce_own(proposal.message.value.0)?;
                    }
                }
                self.outbox.messages.push(Message::Consensus(message));
                r.resume_with(())
            }
            Effect::PublishLivenessMsg(message, r) => {
                self.outbox.messages.push(Message::Liveness(message));
                r.resume_with(())
            }
            Effect::RepublishVote(vote, r) => {
                self.outbox
                    .messages
                    .push(Message::Liveness(LivenessMsg::Vote(vote)));
                r.resume_with(())
            }
            Effect::RepublishRoundCertificate(certificate, r) => {
                self.outbox
                    .messages
                    .push(Message::Liveness(LivenessMsg::SkipRoundCertificate(
                        certificate,
                    )));
                r.resume_with(())
            }
            Effect::GetValue(height, round, _timeout, r) => {
                self.build_value(height, round)?;
                r.resume_with(())
            }
            Effect::RestreamProposal(_, _, _, _, id, r) => {
                self.resend_block(id)?;
                r.resume_with(())
            }
            Effect::CertVerifiedSyncValue(_, _, r) => r.resume_with(()),
            Effect::CertRejectedSyncValue(_, _, _, r) => r.resume_with(()),
            Effect::Decide(certificate, _extensions, r) => {
                self.decide(&certificate)?;
                r.resume_with(())
            }
            Effect::SignVote(vote, r) => {
                let step = match vote.vote_type {
                    malachite_core_types::VoteType::Prevote => Step::Prevote,
                    malachite_core_types::VoteType::Precommit => Step::Precommit,
                };
                let signature =
                    self.sign_at(position(vote.height, vote.round, step), encoded(&vote))?;
                r.resume_with(SignedVote::new(vote, signature))
            }
            Effect::SignProposal(proposal, r) => {
                let signature = self.sign_at(
                    position(proposal.height, proposal.round, Step::Propose),
                    encoded(&proposal),
                )?;
                r.resume_with(SignedProposal::new(proposal, signature))
            }
            Effect::VerifySignature(signed, public_key, r) => {
                let valid = self.verify_signature(&signed, &public_key)?;
                r.resume_with(valid)
            }
            Effect::VerifyCommitCertificate(certificate, set, params, r) => {
                r.resume_with(verify_commit_certificate(&certificate, &set, params))
            }
            Effect::VerifyExtendedCommitCertificate(certificate, set, params, _policy, r) => r
                .resume_with(verify_commit_certificate(
                    &certificate.trim_vote_extensions(),
                    &set,
                    params,
                )),
            Effect::VerifyPolkaCertificate(certificate, set, params, r) => {
                let result = verify_polka_certificate(&certificate, &set, params);
                if result.is_ok() && certificate.height.0 == self.height {
                    let message = Message::Liveness(LivenessMsg::PolkaCertificate(certificate));
                    self.log(&Entry::Message(message), true)?;
                }
                r.resume_with(result)
            }
            Effect::VerifyRoundCertificate(certificate, set, params, r) => {
                let result = verify_round_certificate(&certificate, &set, params);
                if result.is_ok() && certificate.height.0 == self.height {
                    let message = Message::Liveness(LivenessMsg::SkipRoundCertificate(certificate));
                    self.log(&Entry::Message(message), true)?;
                }
                r.resume_with(result)
            }
            // The engine's own write-ahead entries are not used: the host
            // keeps its own (see the module docs), which also holds what the
            // engine does not know about — the blocks.
            Effect::WalAppend(_, _, r) => r.resume_with(()),
            Effect::ExtendVote(_, _, _, r) => r.resume_with(None),
            Effect::VerifyVoteExtension(_, _, _, _, _, _, r) => r.resume_with(Ok(())),
            Effect::Finalize(certificate, _extensions, evidence, r) => {
                self.finalize(&certificate, &evidence)?;
                r.resume_with(())
            }
        })
    }

    /// How long a timeout runs; `None` for one on no round at all.
    fn duration(&self, timeout: Timeout) -> Option<Duration> {
        if let TimeoutKind::FinalizeHeight(duration) = timeout.kind {
            return Some(duration);
        }
        timeout.round.as_u32()?;
        Some(self.config.timeouts.duration_for(timeout))
    }

    // ---- signing and verifying ---------------------------------------------

    /// Signs `bytes` at `position`, once. See [`signing::GuardedSigner`].
    fn sign_at(
        &mut self,
        position: HighWaterMark,
        bytes: Vec<u8>,
    ) -> Result<BlsSignature, HostError> {
        self.guard.sign(position, bytes).map_err(|refusal| {
            self.halt(match refusal {
                SigningRefusal::Signer(error) => HaltReason::SignerRefused(error),
                SigningRefusal::Conflicting(position) => HaltReason::ConflictingSignature(position),
                SigningRefusal::Log(error) => HaltReason::StorageFailed(error.0),
            })
        })
    }

    fn verify_signature(
        &mut self,
        signed: &SignedMessage<ThrylosContext, ConsensusMsg<ThrylosContext>>,
        public_key: &chain_types::BlsPublicKey,
    ) -> Result<bool, HostError> {
        let bytes = match &signed.message {
            ConsensusMsg::Vote(vote) => encoded(vote),
            ConsensusMsg::Proposal(proposal) => encoded(proposal),
        };
        let valid = verify_aggregate(&[public_key], &bytes, DST_VOTE, &signed.signature).is_ok();

        if !valid {
            return Ok(false);
        }
        // Written before anything is done about it.
        let message = match &signed.message {
            ConsensusMsg::Vote(vote) if vote.height.0 == self.height => Some(
                SignedConsensusMsg::Vote(SignedVote::new(vote.clone(), signed.signature)),
            ),
            ConsensusMsg::Proposal(proposal) if proposal.height.0 == self.height => {
                Some(SignedConsensusMsg::Proposal(SignedProposal::new(
                    proposal.clone(),
                    signed.signature,
                )))
            }
            _ => None,
        };
        if let Some(message) = message {
            self.log(&Entry::Message(Message::Consensus(message)), true)?;
        }

        // A proposal that verifies, from the validator the draw picked for
        // its round, is one whose block is worth executing. Anything else
        // is left for the engine to reject without this node spending work
        // on it.
        if let ConsensusMsg::Proposal(proposal) = &signed.message {
            self.note_proposal(proposal);
        }
        Ok(true)
    }

    fn note_proposal(&mut self, proposal: &ConsensusProposal) {
        if proposal.height.0 != self.height {
            return;
        }
        let chosen = self
            .ctx
            .select_proposer(&self.validators, proposal.height, proposal.round);
        if chosen.address() != &proposal.validator_address {
            return;
        }
        let key = (proposal.value.0, proposal.validator_address.0);
        if !self.props.contains_key(&key) && self.props.len() >= self.config.max_pending_per_height
        {
            return;
        }
        self.props.entry(key).or_insert(Prop {
            round: proposal.round,
            pol_round: proposal.pol_round,
            fed: false,
        });
        self.feed_ready();
    }

    // ---- blocks that arrive ------------------------------------------------

    /// A block message from a peer: for this height it is checked and kept,
    /// for a slightly later one it is held, and otherwise dropped.
    fn receive_block(&mut self, pb: ProposedBlock) {
        let height = pb.block.height.0;
        if height == self.height.0 {
            self.accept_block(pb);
        } else if height > self.height.0
            && height <= self.height.0.saturating_add(self.config.max_future_heights)
        {
            let held = self.future_blocks.entry(height).or_default();
            if held.len() < self.config.max_pending_per_height {
                held.push(pb);
            }
        }
    }

    /// Keeps a block for the height being run — but only with a genuine
    /// reveal from a validator, so a forged one can never displace the real
    /// thing.
    fn accept_block(&mut self, pb: ProposedBlock) {
        let Some(validator) = self
            .validators
            .get_by_address(&ConsensusAddress(pb.proposer))
        else {
            return;
        };
        if verify_reveal(validator.public_key(), self.height, &self.seed, &pb.reveal).is_err() {
            return;
        }
        let id = pb.id();
        if !self.blocks.contains_key(&id) && self.blocks.len() >= self.config.max_pending_per_height
        {
            return;
        }
        // Written before it is used.
        if self
            .log(&Entry::Message(Message::Block(pb.clone())), true)
            .is_err()
        {
            return;
        }
        self.reveals.entry(pb.proposer).or_insert(pb.reveal);
        self.blocks.entry(id).or_insert(pb.block);
        self.feed_ready();
    }

    /// Tells the engine about every proposal whose block and proposer's
    /// reveal have both arrived.
    fn feed_ready(&mut self) {
        let ready: Vec<(Hash, Address)> = self
            .props
            .iter()
            .filter(|((id, proposer), prop)| {
                !prop.fed && self.blocks.contains_key(id) && self.reveals.contains_key(proposer)
            })
            .map(|(key, _)| *key)
            .collect();
        for (id, proposer) in ready {
            let verdict = match self.verdict(id) {
                Ok(verdict) => verdict,
                Err(_) => return,
            };
            let Some(prop) = self.props.get_mut(&(id, proposer)) else {
                continue;
            };
            prop.fed = true;
            let (round, valid_round) = (prop.round, prop.pol_round);
            self.queue.push_back(Input::ProposedValue(
                ProposedValue {
                    height: ConsensusHeight(self.height),
                    round,
                    valid_round,
                    proposer: ConsensusAddress(proposer),
                    value: ConsensusValue(id),
                    validity: verdict.validity,
                },
                ValueOrigin::Consensus,
            ));
        }
    }

    /// The verdict on block `id`, judged once and remembered.
    fn verdict(&mut self, id: Hash) -> Result<Verdict, HostError> {
        if let Some(verdict) = self.verdicts.get(&id) {
            return Ok(verdict.clone());
        }
        // A block this node voted against stays voted against: after a
        // restart a later clock must not be allowed to change its mind.
        let verdict = if self.judged_invalid.contains(&id) {
            Verdict {
                validity: Validity::Invalid,
                executed: None,
            }
        } else {
            match self.judge(id) {
                Ok(verdict) => verdict,
                Err(reason) => return Err(self.halt(reason)),
            }
        };
        if verdict.validity == Validity::Invalid {
            self.log(&Entry::Invalid(id), false)?;
        }
        self.verdicts.insert(id, verdict.clone());
        Ok(verdict)
    }

    /// Whether this node would vote for block `id`: cheap checks first,
    /// execution last.
    fn judge(&self, id: Hash) -> Result<Verdict, HaltReason> {
        let invalid = Verdict {
            validity: Validity::Invalid,
            executed: None,
        };
        let Some(block) = self.blocks.get(&id) else {
            return Ok(invalid);
        };
        let head = self.exec.head().map_err(|_| HaltReason::ChainUnreadable)?;
        if block.height != self.height
            || block.parent_block_hash != head.block_hash
            || !is_after_parent(head.timestamp_ms, block.timestamp_millis)
            || !is_within_clock_tolerance(block.timestamp_millis, self.clock.now_ms())
        {
            return Ok(invalid);
        }
        match self.exec.execute_block(head.state_root, block) {
            Ok(executed) => Ok(Verdict {
                validity: Validity::Valid,
                executed: Some(executed),
            }),
            Err(_) => Ok(invalid),
        }
    }

    // ---- blocks that go out --------------------------------------------------

    /// Builds this validator's block for `height` and hands it to the
    /// engine to propose.
    fn build_value(&mut self, height: ConsensusHeight, round: Round) -> Result<(), HostError> {
        // A block already built for this round — before a restart, which is
        // replaying it — is proposed again as it was: proposing a different
        // one would be signing two proposals for the round.
        if let Some(proposed) = self.own_blocks.get(&round_as_u64(round)).cloned() {
            let id = proposed.id();
            self.blocks.entry(id).or_insert(proposed.block);
            self.reveals.entry(self.me.0).or_insert(proposed.reveal);
            self.verdict(id)?;
            self.announce_own(id)?;
            self.queue
                .push_back(Input::Propose(LocallyProposedValue::new(
                    height,
                    round,
                    ConsensusValue(id),
                )));
            return Ok(());
        }
        let head = self
            .exec
            .head()
            .map_err(|_| self.halt(HaltReason::ChainUnreadable))?;
        let limits = self
            .exec
            .block_limits()
            .map_err(|_| self.halt(HaltReason::ChainUnreadable))?;
        let timestamp = proposal_timestamp(head.timestamp_ms, self.clock.now_ms());
        let mut transactions = self.source.candidates(self.config.max_transactions);

        // Execution rejects a block with any invalid transaction, so the
        // proposer must not offer one: try, drop what execution names, and
        // try again, falling back to an empty block, which always executes.
        let (block, executed) = 'build: {
            for _ in 0..8 {
                let block = self.exec.propose_block(
                    head.block_hash,
                    head.state_root,
                    height.0,
                    timestamp,
                    transactions.clone(),
                    limits,
                );
                match self.exec.execute_block(head.state_root, &block) {
                    Ok(executed) => break 'build (block, executed),
                    Err(rejected) => match rejected.transaction_index {
                        Some(index) => {
                            let index = usize::try_from(index).unwrap_or(usize::MAX);
                            if index < transactions.len() {
                                transactions.remove(index);
                            } else {
                                transactions.clear();
                            }
                        }
                        None => transactions.clear(),
                    },
                }
            }
            let block = self.exec.propose_block(
                head.block_hash,
                head.state_root,
                height.0,
                timestamp,
                Vec::<Transaction>::new(),
                limits,
            );
            match self.exec.execute_block(head.state_root, &block) {
                Ok(executed) => (block, executed),
                Err(_) => return Err(self.halt(HaltReason::ChainUnreadable)),
            }
        };

        let id = block.hash();
        let reveal = self.my_reveal()?;
        // Written before the engine hears of it, so before any proposal of
        // it is signed.
        self.log(
            &Entry::OwnBlock {
                round,
                proposed: ProposedBlock {
                    proposer: self.me.0,
                    block: block.clone(),
                    reveal,
                },
            },
            false,
        )?;
        self.blocks.insert(id, block);
        self.verdicts.insert(
            id,
            Verdict {
                validity: Validity::Valid,
                executed: Some(executed),
            },
        );
        self.announce_own(id)?;
        self.queue
            .push_back(Input::Propose(LocallyProposedValue::new(
                height,
                round,
                ConsensusValue(id),
            )));
        Ok(())
    }

    /// This validator's reveal for the height being run.
    fn my_reveal(&mut self) -> Result<BlsSignature, HostError> {
        if let Some(reveal) = self.reveals.get(&self.me.0) {
            return Ok(*reveal);
        }
        match self.guard.reveal(self.height, &self.seed) {
            Ok(reveal) => {
                self.reveals.insert(self.me.0, reveal);
                Ok(reveal)
            }
            Err(error) => Err(self.halt(HaltReason::SignerRefused(error))),
        }
    }

    /// Sends block `id` to everyone under this validator's name and reveal,
    /// once.
    fn announce_own(&mut self, id: Hash) -> Result<(), HostError> {
        if self.announced.contains(&id) {
            return Ok(());
        }
        self.resend_block(id)?;
        self.announced.insert(id);
        Ok(())
    }

    fn resend_block(&mut self, id: Hash) -> Result<(), HostError> {
        let Some(block) = self.blocks.get(&id).cloned() else {
            return Ok(());
        };
        let reveal = self.my_reveal()?;
        self.outbox.messages.push(Message::Block(ProposedBlock {
            proposer: self.me.0,
            block,
            reveal,
        }));
        Ok(())
    }

    // ---- deciding ----------------------------------------------------------

    /// Consensus has decided a block: commit it to the chain.
    fn decide(&mut self, certificate: &CommitCertificate<ThrylosContext>) -> Result<(), HostError> {
        let id = certificate.value_id;
        let proposer = self
            .ctx
            .select_proposer(&self.validators, certificate.height, certificate.round)
            .address()
            .0;

        // The engine decided this, but this node may not hold everything it
        // needs to commit it: a re-proposed block whose new proposer's reveal
        // never reached it, say. That is not a reason to stop. The decision
        // is certified and any peer that signed it can supply the block with
        // its proof, which this node then checks and executes for itself; if
        // that is where it disagrees, it halts there.
        let (Some(block), Some(reveal), Some(verdict)) = (
            self.blocks.get(&id).cloned(),
            self.reveals.get(&proposer).copied(),
            self.verdicts.get(&id).cloned(),
        ) else {
            self.defer_to_sync(certificate);
            return Ok(());
        };
        let Some(executed) = verdict.executed else {
            self.defer_to_sync(certificate);
            return Ok(());
        };

        self.commit(block, executed, certificate.clone(), reveal)
    }

    /// The engine decided a block this node cannot commit from what it holds:
    /// stays at the height and asks the validators that signed the decision,
    /// at once, for the block and its proof.
    fn defer_to_sync(&mut self, certificate: &CommitCertificate<ThrylosContext>) {
        self.awaiting_sync = true;
        let seen = certificate.height.0 .0.saturating_add(1);
        for entry in &certificate.commit_signatures {
            if entry.address != self.me {
                self.lag.ahead.insert(entry.address.0, seen);
            }
        }
        let now = self
            .clock
            .now_ms()
            .saturating_sub(self.config.sync_grace_ms);
        self.lag.since_ms = Some(self.lag.since_ms.map_or(now, |since| since.min(now)));
    }

    /// Makes a block the chain's next: records it (with its proof, for
    /// peers and for a restart), finalises it, and remembers the seed it
    /// leads to. The host must not have committed anything else since
    /// `executed` was produced.
    fn commit(
        &mut self,
        block: Block,
        executed: ExecutedBlock,
        certificate: CommitCertificate<ThrylosContext>,
        reveal: BlsSignature,
    ) -> Result<(), HostError> {
        let height = block.height;
        let seed_after = next_seed(&self.seed, &reveal);
        // Before finalising: a record without a block is harmless, a block
        // without its record would leave a restarted node without a seed.
        if let Err(error) = self.storage.record(
            &CommitRecord {
                block: block.clone(),
                certificate: certificate.clone(),
                reveal,
            },
            seed_after,
        ) {
            return Err(self.halt(HaltReason::StorageFailed(error.0)));
        }
        if self.exec.finalise_block(&block, &executed).is_err() {
            return Err(self.halt(HaltReason::FinaliseFailed { height }));
        }
        self.source.committed(&block);
        self.seed_after = Some(seed_after);
        self.outbox.committed.push(Committed {
            height,
            block,
            executed,
            certificate,
            reveal,
            seed_after,
        });
        Ok(())
    }

    /// The height is final: report what was witnessed and start the next.
    fn finalize(
        &mut self,
        _certificate: &CommitCertificate<ThrylosContext>,
        evidence: &MisbehaviorEvidence<ThrylosContext>,
    ) -> Result<(), HostError> {
        self.outbox
            .evidence
            .extend(duplicate_vote_evidence(evidence));

        if self.awaiting_sync {
            // The block was not committed, so there is no next height yet.
            return Ok(());
        }
        self.advance_state()?;
        self.begin_next_height();
        Ok(())
    }

    /// Starts the next height, or, if there is a pace, arranges for
    /// [`Host::tick`] to start it once the pace has passed.
    fn begin_next_height(&mut self) {
        let pace = self.config.min_block_interval_ms;
        if pace == 0 {
            self.start_next_height();
        } else {
            self.next_height_at_ms = Some(self.clock.now_ms().saturating_add(pace));
        }
    }

    /// Moves to the height after the chain's head, with the validators it
    /// reports and the seed the last commit led to. Does not start the
    /// engine on it: a run of heights adopted from a peer only starts the
    /// last one.
    fn advance_state(&mut self) -> Result<(), HostError> {
        let head = self
            .exec
            .head()
            .map_err(|_| self.halt(HaltReason::ChainUnreadable))?;
        let infos = self
            .exec
            .validator_set()
            .map_err(|_| self.halt(HaltReason::ChainUnreadable))?;
        if infos.is_empty() {
            return Err(self.halt(HaltReason::NoValidators));
        }
        let seed = self.seed_after.take().unwrap_or(self.seed);
        let next = BlockHeight(head.height.0.saturating_add(1));

        self.height = next;
        self.seed = seed;
        self.validators = ConsensusValidatorSet::from_infos(&infos, seed);
        self.blocks.clear();
        self.reveals.clear();
        self.verdicts.clear();
        self.props.clear();
        self.announced.clear();
        self.future_blocks.retain(|height, _| *height >= next.0);
        self.awaiting_sync = false;
        self.logged.clear();
        self.logged_count = 0;
        self.own_blocks.clear();
        self.judged_invalid.clear();
        // Progress: whatever was asked for is answered, and any further
        // request can go at once.
        self.lag.last_request_ms = None;
        self.lag.attempts = 0;
        Ok(())
    }

    /// Starts the engine on the height `advance_state` moved to.
    fn start_next_height(&mut self) {
        self.next_height_at_ms = None;
        // The log forgets the heights before this one.
        if let Err(error) = self.storage.start_height(self.height) {
            self.halt(HaltReason::StorageFailed(error.0));
            return;
        }
        self.queue.push_back(Input::StartHeight(
            ConsensusHeight(self.height),
            self.validators.clone(),
            false,
            None,
            VoteExtensionPolicy::default(),
        ));
        // Blocks that peers sent while this node was still on the last
        // height, now checked against this height's seed.
        for pb in self
            .future_blocks
            .remove(&self.height.0)
            .unwrap_or_default()
        {
            self.accept_block(pb);
        }
    }

    // ---- catching up -----------------------------------------------------------

    fn note_ahead_vote(&mut self, vote: &SignedVote<ThrylosContext>) {
        self.note_ahead(
            vote.message.height,
            vote.message.validator_address,
            &vote.message,
            &vote.signature,
        );
    }

    fn note_ahead_proposal(&mut self, proposal: &SignedProposal<ThrylosContext>) {
        self.note_ahead(
            proposal.message.height,
            proposal.message.validator_address,
            &proposal.message,
            &proposal.signature,
        );
    }

    /// Records that `signer` was seen at `height` — if that is past this
    /// node's and the signature is genuine. An honest validator only works
    /// at a height once it has committed the one before, so this is what
    /// tells a node that the network has moved on without it. The check
    /// costs one signature verification, and only for a message that raises
    /// what that validator has been seen at.
    fn note_ahead<M: Encode>(
        &mut self,
        height: ConsensusHeight,
        signer: ConsensusAddress,
        message: &M,
        signature: &BlsSignature,
    ) {
        if height.0 <= self.height {
            return;
        }
        if self
            .lag
            .ahead
            .get(&signer.0)
            .is_some_and(|seen| *seen >= height.0 .0)
        {
            return;
        }
        let Some(validator) = self.validators.get_by_address(&signer) else {
            return;
        };
        let genuine = verify_aggregate(
            &[validator.public_key()],
            &encoded(message),
            DST_VOTE,
            signature,
        )
        .is_ok();
        if !genuine {
            return;
        }
        self.lag.ahead.insert(signer.0, height.0 .0);
        if self.lag.since_ms.is_none() {
            self.lag.since_ms = Some(self.clock.now_ms());
        }
    }

    /// Forgets peers that this node has caught up with.
    fn prune_ahead(&mut self) {
        let height = self.height.0;
        self.lag.ahead.retain(|_, seen| *seen > height);
        if self.lag.ahead.is_empty() {
            self.lag.since_ms = None;
        }
    }

    /// When [`Self::maybe_request_sync`] will next act, if it will.
    fn next_sync_action_ms(&self) -> Option<u64> {
        if !self.lag.ahead.values().any(|seen| *seen > self.height.0) {
            return None;
        }
        let due = self.lag.since_ms?.saturating_add(self.config.sync_grace_ms);
        Some(match self.lag.last_request_ms {
            Some(last) => due.max(last.saturating_add(self.config.sync_retry_ms)),
            None => due,
        })
    }

    /// Asks a peer that is ahead for what this node missed, if it has been
    /// behind long enough and has not just asked. Successive requests go to
    /// successive peers, so one that will not answer cannot hold it up.
    fn maybe_request_sync(&mut self) {
        self.prune_ahead();
        let Some(due) = self.next_sync_action_ms() else {
            return;
        };
        if self.clock.now_ms() < due {
            return;
        }
        let peers: Vec<Address> = self.lag.ahead.keys().copied().collect();
        let Some(index) = self.lag.attempts.checked_rem(peers.len()) else {
            return;
        };
        let Some(peer) = peers.get(index).copied() else {
            return;
        };
        self.outbox.directed.push((
            peer,
            Message::SyncRequest(SyncRequest {
                requester: self.me.0,
                from: self.height,
            }),
        ));
        self.lag.last_request_ms = Some(self.clock.now_ms());
        self.lag.attempts = self.lag.attempts.saturating_add(1);
    }

    /// Answers a request from a validator with what was decided from the
    /// height it is at.
    fn serve(&mut self, request: &SyncRequest) {
        if self
            .validators
            .get_by_address(&ConsensusAddress(request.requester))
            .is_none()
        {
            return;
        }
        let commits = self.storage.range(request.from, self.config.sync_batch);
        if commits.is_empty() {
            return;
        }
        self.outbox.directed.push((
            request.requester,
            Message::SyncResponse(SyncResponse {
                requester: request.requester,
                commits,
            }),
        ));
    }

    /// Adopts, one after another, the blocks in a peer's answer — each only
    /// after checking for itself that the network decided it. Returns whether
    /// the chain moved.
    fn adopt(&mut self, response: SyncResponse) -> bool {
        if response.requester != self.me.0 {
            return false;
        }
        let mut moved = false;
        for record in response.commits {
            match self.adopt_one(record) {
                Adopted::Committed => moved = true,
                Adopted::Old => {}
                Adopted::Rejected => break,
            }
            if self.halted.is_some() {
                break;
            }
        }
        moved
    }

    fn adopt_one(&mut self, record: CommitRecord) -> Adopted {
        let CommitRecord {
            block,
            certificate,
            reveal,
        } = record;
        if block.height < self.height {
            return Adopted::Old;
        }
        let id = block.hash();
        if block.height > self.height
            || certificate.height.0 != block.height
            || certificate.value_id != id
        {
            return Adopted::Rejected;
        }
        // A quorum of this height's validators precommitted exactly this
        // block...
        if verify_commit_certificate(&certificate, &self.validators, self.config.threshold).is_err()
        {
            return Adopted::Rejected;
        }
        // ...and the reveal is the one the proposer the draw picked for the
        // deciding round made, which fixes the next seed.
        let proposer = self
            .ctx
            .select_proposer(&self.validators, certificate.height, certificate.round)
            .address();
        let Some(proposer) = self.validators.get_by_address(proposer) else {
            return Adopted::Rejected;
        };
        if verify_reveal(proposer.public_key(), self.height, &self.seed, &reveal).is_err() {
            return Adopted::Rejected;
        }

        // The network decided it. What follows is this node's own chain
        // agreeing or not, and if not it cannot go on.
        let cannot_commit = HaltReason::CannotCommit {
            height: block.height,
        };
        let Ok(head) = self.exec.head() else {
            self.halt(HaltReason::ChainUnreadable);
            return Adopted::Rejected;
        };
        if block.parent_block_hash != head.block_hash {
            self.halt(cannot_commit);
            return Adopted::Rejected;
        }
        let Ok(executed) = self.exec.execute_block(head.state_root, &block) else {
            self.halt(cannot_commit);
            return Adopted::Rejected;
        };
        if self
            .commit(block, executed, certificate, reveal)
            .and_then(|()| self.advance_state())
            .is_err()
        {
            return Adopted::Rejected;
        }
        Adopted::Committed
    }
}

/// The signer position a message sits at.
fn position(height: ConsensusHeight, round: Round, step: Step) -> HighWaterMark {
    HighWaterMark::new(height.0, chain_types::Round(round_as_u64(round)), step)
}

fn encoded<T: Encode>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    bytes
}
