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
//! # What is not built
//!
//! - **A write-ahead log.** The engine asks for one (`Effect::WalAppend`)
//!   so it can restore a locked value after a crash. Without it a restarted
//!   node must not vote at the height it crashed in, and the runtime should
//!   simply start it at the next one. Double-signing is prevented
//!   independently, by the signer; what a missing WAL costs is *liveness
//!   and lock memory*, not slashing.
//! - **Sync and stall detection.** A node that never receives a block, or
//!   whose own execution judges a block invalid, does not vote for it and
//!   Malachite will not decide a value the host has not called valid: the
//!   node *stalls* at that height, safely — it commits nothing it cannot
//!   vouch for — but silently. Noticing "the network is deciding and I am
//!   not" and fetching the missing blocks belongs with the (separate) sync
//!   path. [`HaltReason::CannotCommit`] is the backstop for a decision that
//!   reaches the host and then cannot be committed.
//! - **Wire encoding.** [`Message`] is a Rust value; putting it on a
//!   network needs a codec and the size limits `chain-p2p` enforces.
//! - **Observer nodes.** The host assumes it is one of the validators.
//! - **Vote extensions**, which the spec does not use.

pub mod messages;
pub mod ports;
pub mod signing;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use chain_engine_api::timestamp::{is_after_parent, is_within_clock_tolerance, proposal_timestamp};
use chain_engine_api::{Block, ChainView, Engine, ExecutedBlock};
use chain_signer::{HighWaterMark, HighWaterMarkStore, Signer, Step};
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

pub use messages::{Committed, HaltReason, Message, Outbox, ProposedBlock, TimerCommand};
pub use ports::{Clock, MemorySignedLog, SignedEntry, SignedLog, TransactionSource};
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

/// An effect could not be carried out; the reason is in `Env::halted`.
#[derive(Debug)]
struct HostError;

/// Everything but the engine's own state, so that carrying out an effect
/// (which needs `&mut Env`) can happen while the engine (`&mut State`) is
/// mid-step.
struct Env<X, T, C, S: HighWaterMarkStore, L> {
    config: HostConfig,
    ctx: ThrylosContext,
    me: ConsensusAddress,
    exec: X,
    source: T,
    clock: C,
    guard: GuardedSigner<S, L>,

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

    future_blocks: BTreeMap<u64, Vec<ProposedBlock>>,
    queue: VecDeque<Input<ThrylosContext>>,
    outbox: Outbox,
    halted: Option<HaltReason>,
}

/// What a host talks to besides the chain: where transactions come from,
/// what time it is, and the validator's key with its record of what it has
/// signed.
pub struct Ports<T, C, S: HighWaterMarkStore, L> {
    pub source: T,
    pub clock: C,
    pub signer: Signer<S>,
    pub log: L,
}

/// The host. See the module docs.
pub struct Host<X, T, C, S: HighWaterMarkStore, L> {
    consensus: State<ThrylosContext>,
    metrics: Metrics,
    env: Env<X, T, C, S, L>,
}

impl<X, T, C, S, L> Host<X, T, C, S, L>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    S: HighWaterMarkStore,
    L: SignedLog,
{
    /// A host for the validator `me` on the chain `exec`, at the chain's
    /// current head. `seed` is the beacon seed for the next height — for a
    /// new chain `chain_types::beacon::genesis_seed(genesis_hash)`, and for
    /// a restarted node the `Committed::seed_after` it saved.
    pub fn new(
        config: HostConfig,
        me: Address,
        exec: X,
        ports: Ports<T, C, S, L>,
        seed: Hash,
    ) -> Result<Self, HaltReason> {
        let Ports {
            source,
            clock,
            signer,
            log,
        } = ports;
        let head = exec.head().map_err(|_| HaltReason::ChainUnreadable)?;
        let infos = exec
            .validator_set()
            .map_err(|_| HaltReason::ChainUnreadable)?;
        if infos.is_empty() {
            return Err(HaltReason::NoValidators);
        }
        let height = BlockHeight(head.height.0.saturating_add(1));
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
                height,
                validators,
                seed,
                seed_after: None,
                blocks: BTreeMap::new(),
                reveals: BTreeMap::new(),
                verdicts: BTreeMap::new(),
                props: BTreeMap::new(),
                announced: BTreeSet::new(),
                future_blocks: BTreeMap::new(),
                queue: VecDeque::new(),
                outbox: Outbox::default(),
                halted: None,
            },
        })
    }

    /// Begins consensus at the height after the chain's head.
    pub fn start(&mut self) {
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
    }

    /// A message from a peer.
    pub fn handle_message(&mut self, message: Message) {
        if self.env.halted.is_some() {
            return;
        }
        match message {
            Message::Consensus(SignedConsensusMsg::Vote(vote)) => {
                self.input_for_height(vote.message.height, Input::Vote(vote));
            }
            Message::Consensus(SignedConsensusMsg::Proposal(proposal)) => {
                self.input_for_height(proposal.message.height, Input::Proposal(proposal));
            }
            Message::Liveness(LivenessMsg::Vote(vote)) => {
                self.input_for_height(vote.message.height, Input::Vote(vote));
            }
            Message::Liveness(LivenessMsg::PolkaCertificate(certificate)) => {
                self.input_for_height(certificate.height, Input::PolkaCertificate(certificate));
            }
            Message::Liveness(LivenessMsg::SkipRoundCertificate(certificate)) => {
                self.input_for_height(certificate.height, Input::RoundCertificate(certificate));
            }
            Message::Block(block) => self.env.receive_block(block),
        }
        self.pump();
    }

    /// A timer the host asked for has fired.
    pub fn handle_timeout(&mut self, timeout: Timeout) {
        if self.env.halted.is_some() {
            return;
        }
        self.env.queue.push_back(Input::TimeoutElapsed(timeout));
        self.pump();
    }

    /// What the host wants done, collected since the last call.
    pub fn take_outbox(&mut self) -> Outbox {
        core::mem::take(&mut self.env.outbox)
    }

    /// The chain the host is driving.
    pub const fn chain(&self) -> &X {
        &self.env.exec
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

impl<X, T, C, S, L> Env<X, T, C, S, L>
where
    X: Engine + ChainView,
    T: TransactionSource,
    C: Clock,
    S: HighWaterMarkStore,
    L: SignedLog,
{
    fn halt(&mut self, reason: HaltReason) -> HostError {
        if self.halted.is_none() {
            self.halted = Some(reason);
        }
        HostError
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
                r.resume_with(self.verify_signature(&signed, &public_key))
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
                r.resume_with(verify_polka_certificate(&certificate, &set, params))
            }
            Effect::VerifyRoundCertificate(certificate, set, params, r) => {
                r.resume_with(verify_round_certificate(&certificate, &set, params))
            }
            // See the module docs: no write-ahead log yet.
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
            })
        })
    }

    fn verify_signature(
        &mut self,
        signed: &SignedMessage<ThrylosContext, ConsensusMsg<ThrylosContext>>,
        public_key: &chain_types::BlsPublicKey,
    ) -> bool {
        let bytes = match &signed.message {
            ConsensusMsg::Vote(vote) => encoded(vote),
            ConsensusMsg::Proposal(proposal) => encoded(proposal),
        };
        let valid = verify_aggregate(&[public_key], &bytes, DST_VOTE, &signed.signature).is_ok();

        // A proposal that verifies, from the validator the draw picked for
        // its round, is one whose block is worth executing. Anything else
        // is left for the engine to reject without this node spending work
        // on it.
        if valid {
            if let ConsensusMsg::Proposal(proposal) = &signed.message {
                self.note_proposal(proposal);
            }
        }
        valid
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
        let verdict = match self.judge(id) {
            Ok(verdict) => verdict,
            Err(reason) => return Err(self.halt(reason)),
        };
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
        let height = certificate.height.0;
        let id = certificate.value_id;
        let proposer = self
            .ctx
            .select_proposer(&self.validators, certificate.height, certificate.round)
            .address()
            .0;

        let cannot_commit = HaltReason::CannotCommit { height };
        let (Some(block), Some(reveal), Some(verdict)) = (
            self.blocks.get(&id).cloned(),
            self.reveals.get(&proposer).copied(),
            self.verdicts.get(&id).cloned(),
        ) else {
            return Err(self.halt(cannot_commit));
        };
        let Some(executed) = verdict.executed else {
            return Err(self.halt(cannot_commit));
        };

        if self.exec.finalise_block(&block, &executed).is_err() {
            return Err(self.halt(HaltReason::FinaliseFailed { height }));
        }
        self.source.committed(&block);
        let seed_after = next_seed(&self.seed, &reveal);
        self.seed_after = Some(seed_after);
        self.outbox.committed.push(Committed {
            height,
            block,
            executed,
            certificate: certificate.clone(),
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

        self.queue.push_back(Input::StartHeight(
            ConsensusHeight(next),
            self.validators.clone(),
            false,
            None,
            VoteExtensionPolicy::default(),
        ));
        // Blocks that peers sent while this node was still on the last
        // height, now checked against this height's seed.
        for pb in self.future_blocks.remove(&next.0).unwrap_or_default() {
            self.accept_block(pb);
        }
        Ok(())
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
