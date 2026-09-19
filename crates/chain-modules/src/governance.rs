//! Minimal governance. `docs/spec.md`, "Native modules: staking, fees and
//! governance": "Parameter changes only. No arbitrary code execution, no
//! treasury, no upgradable modules." It exists for two reasons: "a
//! permissionless, pseudonymous validator set has no other way to
//! coordinate a fork activation, and a mispriced gas-schedule entry would
//! otherwise be a permanent denial of service."
//!
//! Two kinds of proposal, and nothing else: a [`ParamChange`] and a
//! named fork's activation height. Every proposal moves through the same
//! fixed lifecycle:
//!
//! ```text
//! submit -> Voting -> Rejected            (quorum, veto, or majority failed)
//!                  -> Passed -> Applied    (after the timelock)
//!                            -> Failed     (clamp or fork rule violated at application)
//! ```
//!
//! Time is whatever the caller passes in — a block's own timestamp,
//! never a wall clock — and the only thing that advances the lifecycle
//! is [`Governance::process`], meant to run once per block as a module
//! hook. Nothing here signs or touches a network; voting power is
//! supplied by the caller as a snapshot taken when the proposal was
//! submitted, so stake moving mid-vote cannot swing the result.
//!
//! # Storage
//!
//! State lives in a [`Store`], one entry per entity, so a vote touches
//! two keys however many proposals or voters exist:
//!
//! | key | value |
//! |---|---|
//! | `GOV_PARAMS` | the live parameters (re-validated against their clamps on every read) |
//! | `GOV_META` | the next proposal id |
//! | `GOV_PROPOSAL ‖ id` | the proposal: kind, deadline, total power, running tally, status |
//! | `GOV_VOTE ‖ id ‖ voter` | one voter's choice and power |
//! | `GOV_OPEN ‖ id` | index of the unresolved proposals |
//! | `GOV_FORK ‖ name` | a scheduled fork's activation height |
//!
//! The tally is kept as running totals on the proposal, adjusted as each
//! vote arrives, so casting a vote does not read the other votes and
//! closing a proposal does not read any. The open index is what keeps
//! [`Governance::process`] to the handful of unresolved proposals rather
//! than every proposal ever made.
//!
//! Every mutating method runs on an [`Overlay`] and reaches the store only
//! if it returns `Ok`.
//!
//! Resolved proposals and their votes are kept, as the record of how the
//! chain was governed; state grows by one entry per vote cast, each of
//! which cost a transaction fee and is capped per proposal
//! ([`MAX_VOTERS_PER_PROPOSAL`]). Pruning them is a later decision.
//!
//! What this is not, yet: nothing routes a transaction to it.
//! `docs/spec.md`'s frozen `vote(GovCap, ProposalId, Vote)` entry point
//! is a Move-callable native, and wiring one up is the native-module-
//! boundary work — this module is the logic that native will call.
//!
//! Numbers the spec gives are used as-is (48-hour timelock, two weeks'
//! notice for a fork). Numbers it doesn't — the voting period, how many
//! proposals may be open at once — are choices, marked as such below.

use ruint::aliases::U256;

use chain_types::codec::{decode_exact, decode_field, CodecError, Decode, Encode};
use chain_types::{Address, BlockHeight};

use crate::params::{GovernedParams, ParamChange, ParamError, DAY_MS, SECOND_MS};
use crate::store::{atomically, be64, load, read_be64, save, tag, Corrupt, Overlay, Store};

/// `docs/spec.md`: "A 48-hour minimum timelock sits between passage and
/// application, so a hostile or mistaken proposal can be observed before
/// it takes effect."
pub const TIMELOCK_MS: u64 = 48 * 60 * 60 * SECOND_MS;

/// **A choice.** The spec names no voting period. Long enough that
/// validators in every timezone see a proposal, short enough that a
/// mispriced parameter isn't a week-long emergency.
pub const VOTING_PERIOD_MS: u64 = 7 * DAY_MS;

/// `docs/spec.md`, "Upgrades and migrations": "Fork activation heights
/// sit far enough ahead that operators have at least two weeks to
/// upgrade." Measured in blocks because "every consensus change is gated
/// behind a named fork activated at a height ..., never at a timestamp",
/// so this assumes the 1-second block-time target: at any other block
/// time, retune it.
pub const MIN_FORK_LEAD_BLOCKS: u64 = 14 * 24 * 60 * 60;

/// **A choice.** Bounds how many proposals are unresolved at once
/// ("Every queue, loop and allocation ... is explicitly bounded").
/// There is no proposal deposit in the spec, so this cap is also the only
/// thing standing between one actor and an unbounded pile of them — at
/// the price that a determined one can hold every slot for a voting
/// period at a time.
pub const MAX_OPEN_PROPOSALS: usize = 32;

/// **A choice.** Bounds the per-proposal vote map. Comfortably above the
/// 128-validator active set, in case voting extends to delegators.
pub const MAX_VOTERS_PER_PROPOSAL: usize = 4_096;

pub const MAX_FORK_NAME_LEN: usize = 32;

const BPS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProposalId(pub u64);

/// A fork's name: 1 to [`MAX_FORK_NAME_LEN`] characters of `a-z`, `0-9`,
/// `_` and `-`. Kept this narrow so a name can never be ambiguous or
/// unprintable in a log.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForkName(String);

impl ForkName {
    pub fn new(name: &str) -> Result<Self, GovernanceError> {
        let well_formed = name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if name.is_empty() || name.len() > MAX_FORK_NAME_LEN || !well_formed {
            return Err(GovernanceError::InvalidForkName);
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalKind {
    ParameterChange(ParamChange),
    /// Sets (or reschedules) a named fork's activation height.
    ForkActivation {
        fork: ForkName,
        height: BlockHeight,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
    /// A no that also counts toward the veto threshold.
    NoWithVeto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Total voting power that took part was below the quorum.
    QuorumNotMet,
    /// Veto votes exceeded the veto threshold's share of those cast.
    Vetoed,
    /// `yes` was not a strict majority of `yes + no + veto`. Abstentions
    /// count toward quorum but not toward this. A tie fails.
    NotEnoughYes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyFailure {
    /// The change, merged onto the parameters as they stand at
    /// application time, violates a clamp.
    Params(ParamError),
    /// The activation height is under [`MIN_FORK_LEAD_BLOCKS`] past the
    /// height it is being applied at.
    ForkTooSoon,
    /// That fork already activated; its height can no longer move.
    ForkAlreadyActivated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    Voting,
    Rejected(Rejection),
    /// Passed the vote; takes effect at `apply_at_ms`, not before.
    Passed {
        apply_at_ms: u64,
    },
    Applied,
    /// Passed the vote but could not be applied. Not an error to the
    /// chain — the whole point of checking clamps at application time is
    /// that this is a normal, harmless outcome.
    Failed(ApplyFailure),
}

impl Encode for ProposalId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ProposalId {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (id, used) = u64::decode(input)?;
        Ok((Self(id), used))
    }
}

/// A fork name is stored as its bytes and re-validated on decode, so a
/// stored name that isn't a well-formed one is an invalid encoding.
impl Encode for ForkName {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.as_bytes().to_vec().encode(out);
    }
}

impl Decode for ForkName {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = Vec::<u8>::decode(input)?;
        let name = core::str::from_utf8(&bytes).map_err(|_| CodecError::InvalidValue)?;
        let fork = Self::new(name).map_err(|_| CodecError::InvalidValue)?;
        Ok((fork, used))
    }
}

impl Encode for ProposalKind {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ParameterChange(change) => {
                0u8.encode(out);
                change.encode(out);
            }
            Self::ForkActivation { fork, height } => {
                1u8.encode(out);
                fork.encode(out);
                height.encode(out);
            }
        }
    }
}

impl Decode for ProposalKind {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => {
                let (change, offset) = decode_field::<ParamChange>(input, offset)?;
                Ok((Self::ParameterChange(change), offset))
            }
            1 => {
                let (fork, offset) = decode_field::<ForkName>(input, offset)?;
                let (height, offset) = decode_field::<BlockHeight>(input, offset)?;
                Ok((Self::ForkActivation { fork, height }, offset))
            }
            _ => Err(CodecError::InvalidValue),
        }
    }
}

impl Encode for VoteChoice {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Yes => 0u8,
            Self::No => 1u8,
            Self::Abstain => 2u8,
            Self::NoWithVeto => 3u8,
        }
        .encode(out);
    }
}

impl Decode for VoteChoice {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        let choice = match kind {
            0 => Self::Yes,
            1 => Self::No,
            2 => Self::Abstain,
            3 => Self::NoWithVeto,
            _ => return Err(CodecError::InvalidValue),
        };
        Ok((choice, offset))
    }
}

impl Encode for Rejection {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::QuorumNotMet => 0u8,
            Self::Vetoed => 1u8,
            Self::NotEnoughYes => 2u8,
        }
        .encode(out);
    }
}

impl Decode for Rejection {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        let rejection = match kind {
            0 => Self::QuorumNotMet,
            1 => Self::Vetoed,
            2 => Self::NotEnoughYes,
            _ => return Err(CodecError::InvalidValue),
        };
        Ok((rejection, offset))
    }
}

impl Encode for ApplyFailure {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Params(err) => {
                0u8.encode(out);
                err.encode(out);
            }
            Self::ForkTooSoon => 1u8.encode(out),
            Self::ForkAlreadyActivated => 2u8.encode(out),
        }
    }
}

impl Decode for ApplyFailure {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => {
                let (err, offset) = decode_field::<ParamError>(input, offset)?;
                Ok((Self::Params(err), offset))
            }
            1 => Ok((Self::ForkTooSoon, offset)),
            2 => Ok((Self::ForkAlreadyActivated, offset)),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

impl Encode for ProposalStatus {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Voting => 0u8.encode(out),
            Self::Rejected(reason) => {
                1u8.encode(out);
                reason.encode(out);
            }
            Self::Passed { apply_at_ms } => {
                2u8.encode(out);
                apply_at_ms.encode(out);
            }
            Self::Applied => 3u8.encode(out),
            Self::Failed(failure) => {
                4u8.encode(out);
                failure.encode(out);
            }
        }
    }
}

impl Decode for ProposalStatus {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => Ok((Self::Voting, offset)),
            1 => {
                let (reason, offset) = decode_field::<Rejection>(input, offset)?;
                Ok((Self::Rejected(reason), offset))
            }
            2 => {
                let (apply_at_ms, offset) = decode_field::<u64>(input, offset)?;
                Ok((Self::Passed { apply_at_ms }, offset))
            }
            3 => Ok((Self::Applied, offset)),
            4 => {
                let (failure, offset) = decode_field::<ApplyFailure>(input, offset)?;
                Ok((Self::Failed(failure), offset))
            }
            _ => Err(CodecError::InvalidValue),
        }
    }
}

/// Votes cast so far, by choice, kept as running totals so casting a vote
/// and closing the tally never have to read the votes themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Tally {
    yes: u128,
    no: u128,
    abstain: u128,
    veto: u128,
    /// How many distinct voters have a vote on record.
    voters: u64,
}

impl Tally {
    const fn bucket(&mut self, choice: VoteChoice) -> &mut u128 {
        match choice {
            VoteChoice::Yes => &mut self.yes,
            VoteChoice::No => &mut self.no,
            VoteChoice::Abstain => &mut self.abstain,
            VoteChoice::NoWithVeto => &mut self.veto,
        }
    }

    /// Everything cast, of every kind.
    const fn cast(&self) -> u128 {
        self.yes
            .saturating_add(self.no)
            .saturating_add(self.abstain)
            .saturating_add(self.veto)
    }
}

impl Encode for Tally {
    fn encode(&self, out: &mut Vec<u8>) {
        self.yes.encode(out);
        self.no.encode(out);
        self.abstain.encode(out);
        self.veto.encode(out);
        self.voters.encode(out);
    }
}

impl Decode for Tally {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (yes, offset) = u128::decode(input)?;
        let (no, offset) = decode_field::<u128>(input, offset)?;
        let (abstain, offset) = decode_field::<u128>(input, offset)?;
        let (veto, offset) = decode_field::<u128>(input, offset)?;
        let (voters, offset) = decode_field::<u64>(input, offset)?;
        Ok((
            Self {
                yes,
                no,
                abstain,
                veto,
                voters,
            },
            offset,
        ))
    }
}

/// One proposal, as stored: what it is, when voting ends, the total
/// voting power it was submitted against, the running tally, and where it
/// stands. The individual votes are separate entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    kind: ProposalKind,
    voting_ends_at_ms: u64,
    total_power: u128,
    tally: Tally,
    status: ProposalStatus,
}

impl Proposal {
    pub const fn kind(&self) -> &ProposalKind {
        &self.kind
    }

    pub const fn status(&self) -> ProposalStatus {
        self.status
    }

    pub const fn voting_ends_at_ms(&self) -> u64 {
        self.voting_ends_at_ms
    }

    /// The total voting power this proposal was submitted against.
    pub const fn total_power(&self) -> u128 {
        self.total_power
    }

    /// How many distinct voters have voted.
    pub const fn voter_count(&self) -> u64 {
        self.tally.voters
    }

    const fn is_open(&self) -> bool {
        matches!(
            self.status,
            ProposalStatus::Voting | ProposalStatus::Passed { .. }
        )
    }
}

impl Encode for Proposal {
    fn encode(&self, out: &mut Vec<u8>) {
        self.kind.encode(out);
        self.voting_ends_at_ms.encode(out);
        self.total_power.encode(out);
        self.tally.encode(out);
        self.status.encode(out);
    }
}

impl Decode for Proposal {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = ProposalKind::decode(input)?;
        let (voting_ends_at_ms, offset) = decode_field::<u64>(input, offset)?;
        let (total_power, offset) = decode_field::<u128>(input, offset)?;
        let (tally, offset) = decode_field::<Tally>(input, offset)?;
        let (status, offset) = decode_field::<ProposalStatus>(input, offset)?;
        Ok((
            Self {
                kind,
                voting_ends_at_ms,
                total_power,
                tally,
                status,
            },
            offset,
        ))
    }
}

/// One voter's vote on one proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ballot {
    choice: VoteChoice,
    power: u128,
}

impl Encode for Ballot {
    fn encode(&self, out: &mut Vec<u8>) {
        self.choice.encode(out);
        self.power.encode(out);
    }
}

impl Decode for Ballot {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (choice, offset) = VoteChoice::decode(input)?;
        let (power, offset) = decode_field::<u128>(input, offset)?;
        Ok((Self { choice, power }, offset))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceError {
    UnknownProposal,
    /// Not in [`ProposalStatus::Voting`], or its deadline has passed.
    VotingClosed,
    ZeroVotingPower,
    /// A proposal needs a nonzero total voting power to have a quorum.
    ZeroTotalPower,
    /// Would take the votes cast past the total voting power the
    /// proposal was submitted against.
    VotingPowerExceedsTotal,
    TooManyOpenProposals,
    TooManyVoters,
    /// A [`ParamChange`] that changes nothing.
    EmptyParamChange,
    InvalidForkName,
    ProposalIdsExhausted,
    /// No parameters are stored: [`Governance::init_genesis`] has not
    /// been called on this store.
    NotInitialised,
    /// Parameters are already stored; genesis happens once.
    AlreadyInitialised,
    /// A stored record no longer decodes, or the store's records
    /// disagree with each other. Nothing about a transaction can cause
    /// this; it means the state itself is damaged.
    CorruptState,
}

impl From<Corrupt> for GovernanceError {
    fn from(_: Corrupt) -> Self {
        Self::CorruptState
    }
}

impl core::fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnknownProposal => "no such proposal",
            Self::VotingClosed => "voting on this proposal is closed",
            Self::ZeroVotingPower => "voting power must be positive",
            Self::ZeroTotalPower => "total voting power must be positive",
            Self::VotingPowerExceedsTotal => "votes cast would exceed the total voting power",
            Self::TooManyOpenProposals => "too many open proposals",
            Self::TooManyVoters => "too many voters on this proposal",
            Self::EmptyParamChange => "the parameter change changes nothing",
            Self::InvalidForkName => "fork names are 1-32 characters of a-z, 0-9, _ and -",
            Self::ProposalIdsExhausted => "no proposal ids left",
            Self::NotInitialised => "governance has no genesis parameters",
            Self::AlreadyInitialised => "governance already has genesis parameters",
            Self::CorruptState => "stored governance state is damaged",
        })
    }
}

impl std::error::Error for GovernanceError {}

// ---- keys ------------------------------------------------------------

fn params_key() -> Vec<u8> {
    vec![tag::GOV_PARAMS]
}

fn next_id_key() -> Vec<u8> {
    vec![tag::GOV_META, 0]
}

fn proposal_key(id: ProposalId) -> Vec<u8> {
    let mut key = vec![tag::GOV_PROPOSAL];
    key.extend_from_slice(&be64(id.0));
    key
}

fn open_key(id: ProposalId) -> Vec<u8> {
    let mut key = vec![tag::GOV_OPEN];
    key.extend_from_slice(&be64(id.0));
    key
}

fn vote_prefix(id: ProposalId) -> Vec<u8> {
    let mut key = vec![tag::GOV_VOTE];
    key.extend_from_slice(&be64(id.0));
    key
}

fn vote_key(id: ProposalId, voter: &Address) -> Vec<u8> {
    let mut key = vote_prefix(id);
    key.extend_from_slice(voter.as_bytes());
    key
}

fn fork_key(fork: &ForkName) -> Vec<u8> {
    let mut key = vec![tag::GOV_FORK];
    key.extend_from_slice(fork.as_str().as_bytes());
    key
}

/// Governance, over a [`Store`]. See the module docs for what it keeps
/// there and how operations are made atomic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Governance<S> {
    store: S,
}

impl<S: Store> Governance<S> {
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    pub const fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    fn atomic<T>(
        &mut self,
        op: impl FnOnce(&mut Governance<&mut Overlay<'_, S>>) -> Result<T, GovernanceError>,
    ) -> Result<T, GovernanceError> {
        atomically(&mut self.store, |overlay| op(&mut Governance::new(overlay)))
    }

    /// Stores the genesis parameters. Done once, when the chain is
    /// created; a store that already has parameters refuses.
    pub fn init_genesis(&mut self, params: GovernedParams) -> Result<(), GovernanceError> {
        self.atomic(|gov| {
            if gov.store.get(&params_key()).is_some() {
                return Err(GovernanceError::AlreadyInitialised);
            }
            save(&mut gov.store, params_key(), &params);
            Ok(())
        })
    }

    // ---- reads ---------------------------------------------------------

    /// The parameters as they stand now.
    pub fn params(&self) -> Result<GovernedParams, GovernanceError> {
        load(&self.store, &params_key())?.ok_or(GovernanceError::NotInitialised)
    }

    pub fn proposal(&self, id: ProposalId) -> Result<Option<Proposal>, GovernanceError> {
        Ok(load(&self.store, &proposal_key(id))?)
    }

    /// `voter`'s vote on `id` and the power it carries, if they have one.
    pub fn vote_of(
        &self,
        id: ProposalId,
        voter: &Address,
    ) -> Result<Option<(VoteChoice, u128)>, GovernanceError> {
        let ballot: Option<Ballot> = load(&self.store, &vote_key(id, voter))?;
        Ok(ballot.map(|ballot| (ballot.choice, ballot.power)))
    }

    /// The unresolved proposals — still being voted on, or passed and
    /// waiting out the timelock — in id order. At most
    /// [`MAX_OPEN_PROPOSALS`], which is what keeps [`Self::process`]
    /// bounded however many proposals have ever been made.
    fn open_ids(&self) -> Result<Vec<ProposalId>, Corrupt> {
        self.store
            .scan_prefix(&[tag::GOV_OPEN], usize::MAX)
            .into_iter()
            .map(|(key, _)| {
                key.get(1..)
                    .and_then(read_be64)
                    .map(ProposalId)
                    .ok_or(Corrupt)
            })
            .collect()
    }

    /// How many proposals are unresolved: still being voted on, or
    /// passed and waiting out the timelock.
    pub fn open_proposal_count(&self) -> Result<usize, GovernanceError> {
        Ok(self.open_ids()?.len())
    }

    pub fn fork_activation(&self, fork: &ForkName) -> Result<Option<BlockHeight>, GovernanceError> {
        Ok(load(&self.store, &fork_key(fork))?)
    }

    /// Whether `fork` is scheduled at or before `height`.
    pub fn is_fork_active(
        &self,
        fork: &ForkName,
        height: BlockHeight,
    ) -> Result<bool, GovernanceError> {
        Ok(self
            .fork_activation(fork)?
            .is_some_and(|activation| activation <= height))
    }

    /// Checks that governance's records agree with each other, by reading
    /// all of them: every proposal's running tally equals the sum of its
    /// votes, exactly the unresolved proposals are in the open index, the
    /// next id is past every id in use, and the parameters are stored and
    /// within their clamps. O(state): for tests and periodic audits.
    pub fn assert_invariants(&self) -> Result<(), GovernanceError> {
        self.params()?;
        let next_id = load::<u64>(&self.store, &next_id_key())?.unwrap_or(0);
        let open: Vec<ProposalId> = self.open_ids()?;

        let mut open_seen = 0usize;
        for (key, bytes) in self.store.scan_prefix(&[tag::GOV_PROPOSAL], usize::MAX) {
            let id = key
                .get(1..)
                .and_then(read_be64)
                .map(ProposalId)
                .ok_or(Corrupt)?;
            let proposal: Proposal = decode_exact(&bytes).map_err(|_| Corrupt)?;
            if id.0 >= next_id || proposal.is_open() != open.contains(&id) {
                return Err(GovernanceError::CorruptState);
            }
            if proposal.is_open() {
                open_seen = open_seen.saturating_add(1);
            }

            let mut recount = Tally::default();
            for (_, ballot_bytes) in self.store.scan_prefix(&vote_prefix(id), usize::MAX) {
                let ballot: Ballot = decode_exact(&ballot_bytes).map_err(|_| Corrupt)?;
                let bucket = recount.bucket(ballot.choice);
                *bucket = bucket.saturating_add(ballot.power);
                recount.voters = recount.voters.saturating_add(1);
            }
            if recount != proposal.tally || recount.cast() > proposal.total_power {
                return Err(GovernanceError::CorruptState);
            }
        }
        if open_seen != open.len() {
            return Err(GovernanceError::CorruptState);
        }
        Ok(())
    }

    // ---- proposals -----------------------------------------------------

    /// Opens a proposal for voting. `total_power` is the total voting
    /// power at this moment, fixed for this proposal's whole life.
    pub fn submit(
        &mut self,
        kind: ProposalKind,
        now_ms: u64,
        total_power: u128,
    ) -> Result<ProposalId, GovernanceError> {
        self.atomic(|gov| gov.do_submit(kind, now_ms, total_power))
    }

    fn do_submit(
        &mut self,
        kind: ProposalKind,
        now_ms: u64,
        total_power: u128,
    ) -> Result<ProposalId, GovernanceError> {
        if total_power == 0 {
            return Err(GovernanceError::ZeroTotalPower);
        }
        if let ProposalKind::ParameterChange(change) = &kind {
            if change.is_empty() {
                return Err(GovernanceError::EmptyParamChange);
            }
        }
        if self.open_proposal_count()? >= MAX_OPEN_PROPOSALS {
            return Err(GovernanceError::TooManyOpenProposals);
        }
        let next_id = load::<u64>(&self.store, &next_id_key())?.unwrap_or(0);
        let id = ProposalId(next_id);
        let after = next_id
            .checked_add(1)
            .ok_or(GovernanceError::ProposalIdsExhausted)?;
        save(&mut self.store, next_id_key(), &after);

        save(
            &mut self.store,
            proposal_key(id),
            &Proposal {
                kind,
                voting_ends_at_ms: now_ms.saturating_add(VOTING_PERIOD_MS),
                total_power,
                tally: Tally::default(),
                status: ProposalStatus::Voting,
            },
        );
        self.store.put(open_key(id), Vec::new());
        Ok(id)
    }

    /// Records `voter`'s vote, replacing any earlier one of theirs on
    /// this proposal. `power` is their voting power in the snapshot the
    /// proposal was submitted against.
    pub fn vote(
        &mut self,
        id: ProposalId,
        voter: Address,
        power: u128,
        choice: VoteChoice,
        now_ms: u64,
    ) -> Result<(), GovernanceError> {
        self.atomic(|gov| gov.do_vote(id, voter, power, choice, now_ms))
    }

    fn do_vote(
        &mut self,
        id: ProposalId,
        voter: Address,
        power: u128,
        choice: VoteChoice,
        now_ms: u64,
    ) -> Result<(), GovernanceError> {
        let mut proposal = self.proposal(id)?.ok_or(GovernanceError::UnknownProposal)?;
        if proposal.status != ProposalStatus::Voting || now_ms >= proposal.voting_ends_at_ms {
            return Err(GovernanceError::VotingClosed);
        }
        if power == 0 {
            return Err(GovernanceError::ZeroVotingPower);
        }
        let earlier: Option<Ballot> = load(&self.store, &vote_key(id, &voter))?;
        let voters_full = usize::try_from(proposal.tally.voters)
            .map_or(true, |voters| voters >= MAX_VOTERS_PER_PROPOSAL);
        if earlier.is_none() && voters_full {
            return Err(GovernanceError::TooManyVoters);
        }
        let cast_by_others = proposal
            .tally
            .cast()
            .saturating_sub(earlier.map_or(0, |ballot| ballot.power));
        if cast_by_others.saturating_add(power) > proposal.total_power {
            return Err(GovernanceError::VotingPowerExceedsTotal);
        }

        // Take the earlier vote back out of the tally, put this one in.
        if let Some(earlier) = earlier {
            let bucket = proposal.tally.bucket(earlier.choice);
            *bucket = bucket.saturating_sub(earlier.power);
        } else {
            proposal.tally.voters = proposal.tally.voters.saturating_add(1);
        }
        let bucket = proposal.tally.bucket(choice);
        *bucket = bucket.saturating_add(power);

        save(
            &mut self.store,
            vote_key(id, &voter),
            &Ballot { choice, power },
        );
        save(&mut self.store, proposal_key(id), &proposal);
        Ok(())
    }

    /// Advances every proposal that is due, in id order, and returns the
    /// ones whose status changed, with the new status. Meant to run once
    /// per block, after that block's transactions ("Module hooks run in a
    /// fixed, compiled-in order and cannot re-enter execution").
    ///
    /// A proposal whose voting period has ended is tallied against the
    /// quorum and veto threshold as they stand *now*; one that passed
    /// more than [`TIMELOCK_MS`] ago is applied against the parameters as
    /// they stand now, which an earlier proposal in this same call may
    /// just have changed — id order makes that deterministic. The
    /// timelock is measured from when passage is recorded (`now_ms`), not
    /// from the voting deadline, so a late call can never shorten the
    /// window in which a passed proposal can be observed.
    ///
    /// Reads only the unresolved proposals, at most
    /// [`MAX_OPEN_PROPOSALS`], and never their votes.
    pub fn process(
        &mut self,
        now_ms: u64,
        now_height: BlockHeight,
    ) -> Result<Vec<(ProposalId, ProposalStatus)>, GovernanceError> {
        self.atomic(|gov| gov.do_process(now_ms, now_height))
    }

    fn do_process(
        &mut self,
        now_ms: u64,
        now_height: BlockHeight,
    ) -> Result<Vec<(ProposalId, ProposalStatus)>, GovernanceError> {
        let mut params = self.params()?;
        let mut changed = Vec::new();
        for id in self.open_ids()? {
            let mut proposal = self.proposal(id)?.ok_or(GovernanceError::CorruptState)?;
            let next = match proposal.status {
                ProposalStatus::Voting if now_ms >= proposal.voting_ends_at_ms => Some(
                    match evaluate(&proposal.tally, proposal.total_power, &params) {
                        Ok(()) => ProposalStatus::Passed {
                            apply_at_ms: now_ms.saturating_add(TIMELOCK_MS),
                        },
                        Err(rejection) => ProposalStatus::Rejected(rejection),
                    },
                ),
                ProposalStatus::Passed { apply_at_ms } if now_ms >= apply_at_ms => {
                    Some(self.apply(&proposal.kind, &mut params, now_height)?)
                }
                _ => None,
            };
            if let Some(status) = next {
                proposal.status = status;
                save(&mut self.store, proposal_key(id), &proposal);
                if !proposal.is_open() {
                    self.store.delete(&open_key(id));
                }
                changed.push((id, status));
            }
        }
        Ok(changed)
    }

    /// Applies a passed proposal, returning how that went. A failure
    /// leaves the stored parameters and fork activations exactly as they
    /// were; a success writes them, and updates `params` so a later
    /// proposal in the same call sees the change.
    fn apply(
        &mut self,
        kind: &ProposalKind,
        params: &mut GovernedParams,
        now_height: BlockHeight,
    ) -> Result<ProposalStatus, GovernanceError> {
        Ok(match kind {
            ProposalKind::ParameterChange(change) => match params.with_change(change) {
                Ok(updated) => {
                    *params = updated;
                    save(&mut self.store, params_key(), &updated);
                    ProposalStatus::Applied
                }
                Err(err) => ProposalStatus::Failed(ApplyFailure::Params(err)),
            },
            ProposalKind::ForkActivation { fork, height } => {
                if self
                    .fork_activation(fork)?
                    .is_some_and(|existing| existing <= now_height)
                {
                    return Ok(ProposalStatus::Failed(ApplyFailure::ForkAlreadyActivated));
                }
                if height.0 < now_height.0.saturating_add(MIN_FORK_LEAD_BLOCKS) {
                    return Ok(ProposalStatus::Failed(ApplyFailure::ForkTooSoon));
                }
                save(&mut self.store, fork_key(fork), height);
                ProposalStatus::Applied
            }
        })
    }
}

/// Whether a proposal whose voting period has ended passed, and if not,
/// why. Checked in a fixed order — quorum, then veto, then majority — so
/// a proposal that fails several always reports the same one.
fn evaluate(tally: &Tally, total_power: u128, params: &GovernedParams) -> Result<(), Rejection> {
    let (yes, no, veto) = (tally.yes, tally.no, tally.veto);
    let voted = tally.cast();

    // Cross-multiplied in `U256` so a `u128` voting power times a basis-
    // point figure cannot overflow, and no division rounds a threshold
    // the wrong way.
    let scaled = |power: u128, bps: u64| U256::from(power).saturating_mul(U256::from(bps));
    let values = params.values();

    let quorum_bps = u64::from(values.quorum_bps);
    if scaled(voted, BPS_DENOMINATOR) < scaled(total_power, quorum_bps) {
        return Err(Rejection::QuorumNotMet);
    }

    let veto_bps = u64::from(values.veto_threshold_bps);
    if scaled(veto, BPS_DENOMINATOR) > scaled(voted, veto_bps) {
        return Err(Rejection::Vetoed);
    }

    let contested = yes.saturating_add(no).saturating_add(veto);
    if contested == 0 || scaled(yes, 2) <= scaled(contested, 1) {
        return Err(Rejection::NotEnoughYes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::indexing_slicing
    )]

    use super::*;
    use crate::params::{ParamValues, MIN_UNBONDING_PERIOD_MS};
    use crate::store::MemStore;

    type Gov = Governance<MemStore>;

    /// A governance over an empty store, with the genesis parameters in.
    fn new_gov() -> Gov {
        let mut gov = Governance::new(MemStore::new());
        gov.init_genesis(params()).unwrap();
        gov
    }

    const T0: u64 = 1_000_000;

    fn params() -> GovernedParams {
        GovernedParams::new(ParamValues {
            max_block_gas: 60_000_000,
            base_fee_change_denominator: 8,
            min_self_stake: 1_000,
            inflation_bps: 400,
            unbonding_period_ms: MIN_UNBONDING_PERIOD_MS,
            quorum_bps: 3_340,
            veto_threshold_bps: 3_340,
        })
        .unwrap()
    }

    fn voter(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    fn inflation_change(bps: u16) -> ProposalKind {
        ProposalKind::ParameterChange(ParamChange {
            inflation_bps: Some(bps),
            ..ParamChange::default()
        })
    }

    /// Submits `kind` against a total power of 1000 at `T0`.
    fn submit(gov: &mut Gov, kind: ProposalKind) -> ProposalId {
        gov.submit(kind, T0, 1_000).unwrap()
    }

    fn cast(gov: &mut Gov, id: ProposalId, who: u8, power: u128, choice: VoteChoice) {
        gov.vote(id, voter(who), power, choice, T0 + 1).unwrap();
    }

    /// Runs voting to its deadline and returns the resulting status.
    fn close_voting(gov: &mut Gov, id: ProposalId) -> ProposalStatus {
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        gov.proposal(id).unwrap().unwrap().status()
    }

    #[test]
    fn a_passing_proposal_waits_out_the_timelock_before_it_takes_effect() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);

        assert!(gov
            .process(T0 + VOTING_PERIOD_MS - 1, BlockHeight(1))
            .unwrap()
            .is_empty());
        assert_eq!(
            gov.proposal(id).unwrap().unwrap().status(),
            ProposalStatus::Voting
        );

        let passed_at = T0 + VOTING_PERIOD_MS;
        assert_eq!(
            gov.process(passed_at, BlockHeight(1)).unwrap(),
            vec![(
                id,
                ProposalStatus::Passed {
                    apply_at_ms: passed_at + TIMELOCK_MS
                }
            )]
        );
        assert_eq!(gov.params().unwrap().values().inflation_bps, 400, "not yet");

        assert!(gov
            .process(passed_at + TIMELOCK_MS - 1, BlockHeight(2))
            .unwrap()
            .is_empty());
        assert_eq!(
            gov.params().unwrap().values().inflation_bps,
            400,
            "still timelocked"
        );

        assert_eq!(
            gov.process(passed_at + TIMELOCK_MS, BlockHeight(3))
                .unwrap(),
            vec![(id, ProposalStatus::Applied)]
        );
        assert_eq!(gov.params().unwrap().values().inflation_bps, 500);
    }

    #[test]
    fn the_timelock_runs_from_when_passage_is_recorded_not_from_the_deadline() {
        // A process call that comes late must not shorten the window in
        // which a passed proposal can be seen before it takes effect.
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);

        let late = T0 + VOTING_PERIOD_MS + 10 * DAY_MS;
        gov.process(late, BlockHeight(1)).unwrap();
        assert_eq!(
            gov.proposal(id).unwrap().unwrap().status(),
            ProposalStatus::Passed {
                apply_at_ms: late + TIMELOCK_MS
            }
        );
        assert!(gov.process(late + 1, BlockHeight(2)).unwrap().is_empty());
    }

    #[test]
    fn too_little_turnout_fails_the_quorum() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 333, VoteChoice::Yes); // 33.3% < 33.4%

        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::QuorumNotMet)
        );
    }

    #[test]
    fn turnout_exactly_at_the_quorum_counts() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 334, VoteChoice::Yes); // exactly 33.4%

        assert!(matches!(
            close_voting(&mut gov, id),
            ProposalStatus::Passed { .. }
        ));
    }

    #[test]
    fn a_veto_beats_a_yes_majority() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 500, VoteChoice::Yes);
        cast(&mut gov, id, 2, 340, VoteChoice::NoWithVeto); // 340/840 > 33.4%

        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::Vetoed)
        );
    }

    #[test]
    fn a_veto_exactly_at_the_threshold_does_not_veto() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 666, VoteChoice::Yes);
        cast(&mut gov, id, 2, 334, VoteChoice::NoWithVeto); // 334/1000 = 33.4% exactly

        assert!(matches!(
            close_voting(&mut gov, id),
            ProposalStatus::Passed { .. }
        ));
    }

    #[test]
    fn abstentions_count_for_quorum_but_not_for_the_majority() {
        let mut gov = new_gov();
        let only_abstentions = submit(&mut gov, inflation_change(500));
        cast(&mut gov, only_abstentions, 1, 600, VoteChoice::Abstain);
        assert_eq!(
            close_voting(&mut gov, only_abstentions),
            ProposalStatus::Rejected(Rejection::NotEnoughYes),
            "quorum was met, but nobody voted for it"
        );

        let mut gov = new_gov();
        let one_yes = submit(&mut gov, inflation_change(500));
        cast(&mut gov, one_yes, 1, 600, VoteChoice::Abstain);
        cast(&mut gov, one_yes, 2, 1, VoteChoice::Yes);
        assert!(
            matches!(
                close_voting(&mut gov, one_yes),
                ProposalStatus::Passed { .. }
            ),
            "the abstentions neither help nor hurt the 1-to-0 majority"
        );
    }

    #[test]
    fn a_tie_fails() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 200, VoteChoice::Yes);
        cast(&mut gov, id, 2, 200, VoteChoice::No);

        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::NotEnoughYes)
        );
    }

    #[test]
    fn a_proposal_outside_a_clamp_can_pass_the_vote_and_then_fails_at_application() {
        // The spec's exact requirement: "a proposal outside the clamp
        // fails rather than passing and bricking the chain."
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(5_000)); // 50%, clamp is 10%
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);

        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        let events = gov
            .process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();
        assert_eq!(
            events,
            vec![(
                id,
                ProposalStatus::Failed(ApplyFailure::Params(ParamError::InflationOutOfRange))
            )]
        );
        assert_eq!(
            gov.params().unwrap().values().inflation_bps,
            400,
            "chain untouched"
        );
    }

    #[test]
    fn two_proposals_applied_together_both_take_effect() {
        // Each change is merged onto the parameters as they stand when it
        // is applied, not onto a snapshot from when it was submitted — so
        // the second must not quietly undo the first.
        let mut gov = new_gov();
        let first = submit(&mut gov, inflation_change(1_000));
        let second = submit(
            &mut gov,
            ProposalKind::ParameterChange(ParamChange {
                unbonding_period_ms: Some(MIN_UNBONDING_PERIOD_MS + DAY_MS),
                ..ParamChange::default()
            }),
        );
        for id in [first, second] {
            cast(&mut gov, id, 1, 900, VoteChoice::Yes);
        }
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        let events = gov
            .process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();

        assert_eq!(
            events,
            vec![
                (first, ProposalStatus::Applied),
                (second, ProposalStatus::Applied)
            ]
        );
        assert_eq!(gov.params().unwrap().values().inflation_bps, 1_000);
        assert_eq!(
            gov.params().unwrap().values().unbonding_period_ms,
            MIN_UNBONDING_PERIOD_MS + DAY_MS
        );
    }

    #[test]
    fn voting_closes_at_the_deadline() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        assert_eq!(
            gov.vote(id, voter(1), 10, VoteChoice::Yes, T0 + VOTING_PERIOD_MS),
            Err(GovernanceError::VotingClosed)
        );
        assert!(gov
            .vote(id, voter(1), 10, VoteChoice::Yes, T0 + VOTING_PERIOD_MS - 1)
            .is_ok());
    }

    #[test]
    fn a_finished_proposal_cannot_be_voted_on() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);
        close_voting(&mut gov, id);
        assert_eq!(
            gov.vote(id, voter(2), 10, VoteChoice::No, T0 + 1),
            Err(GovernanceError::VotingClosed),
            "even with a timestamp inside the old window"
        );
    }

    #[test]
    fn a_voter_can_change_their_vote_and_only_the_last_one_counts() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);
        cast(&mut gov, id, 1, 600, VoteChoice::No);

        assert_eq!(
            gov.vote_of(id, &voter(1)).unwrap(),
            Some((VoteChoice::No, 600))
        );
        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::NotEnoughYes)
        );
    }

    #[test]
    fn votes_cannot_add_up_to_more_than_the_total_power() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);
        assert_eq!(
            gov.vote(id, voter(2), 401, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::VotingPowerExceedsTotal)
        );
        assert!(gov.vote(id, voter(2), 400, VoteChoice::Yes, T0 + 1).is_ok());
        // Re-voting replaces, so voter 1 may grow to fill what voter 2 leaves.
        assert_eq!(
            gov.vote(id, voter(1), 601, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::VotingPowerExceedsTotal)
        );
        assert!(gov.vote(id, voter(1), 600, VoteChoice::No, T0 + 1).is_ok());
    }

    #[test]
    fn zero_power_and_unknown_proposals_are_refused() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        assert_eq!(
            gov.vote(id, voter(1), 0, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::ZeroVotingPower)
        );
        assert_eq!(
            gov.vote(ProposalId(99), voter(1), 1, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::UnknownProposal)
        );
    }

    #[test]
    fn a_proposal_needs_a_nonzero_total_power_and_a_real_change() {
        let mut gov = new_gov();
        assert_eq!(
            gov.submit(inflation_change(500), T0, 0),
            Err(GovernanceError::ZeroTotalPower)
        );
        assert_eq!(
            gov.submit(
                ProposalKind::ParameterChange(ParamChange::default()),
                T0,
                1_000
            ),
            Err(GovernanceError::EmptyParamChange)
        );
    }

    #[test]
    fn open_proposals_are_bounded_and_resolving_one_frees_its_slot() {
        let mut gov = new_gov();
        for _ in 0..MAX_OPEN_PROPOSALS {
            submit(&mut gov, inflation_change(500));
        }
        assert_eq!(
            gov.submit(inflation_change(500), T0, 1_000),
            Err(GovernanceError::TooManyOpenProposals)
        );

        // Nobody voted, so all of them are rejected for want of quorum.
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        assert_eq!(gov.open_proposal_count().unwrap(), 0);
        assert!(gov
            .submit(inflation_change(500), T0 + VOTING_PERIOD_MS, 1_000)
            .is_ok());
    }

    #[test]
    fn a_passed_proposal_holds_its_slot_until_it_is_applied() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);
        close_voting(&mut gov, id);
        assert_eq!(gov.open_proposal_count().unwrap(), 1);
        gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();
        assert_eq!(gov.open_proposal_count().unwrap(), 0);
    }

    #[test]
    fn the_number_of_voters_on_one_proposal_is_bounded() {
        let mut gov = new_gov();
        let id = gov.submit(inflation_change(500), T0, u128::MAX).unwrap();
        for i in 0..MAX_VOTERS_PER_PROPOSAL {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            gov.vote(id, Address::from_bytes(bytes), 1, VoteChoice::Yes, T0 + 1)
                .unwrap();
        }
        assert_eq!(
            gov.vote(id, voter(0xFF), 1, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::TooManyVoters)
        );
        // Changing an existing vote is not a new voter.
        assert!(gov
            .vote(
                id,
                Address::from_bytes([0u8; 32]),
                2,
                VoteChoice::No,
                T0 + 1
            )
            .is_ok());
    }

    #[test]
    fn voting_power_near_the_top_of_u128_does_not_overflow_the_tally() {
        let mut gov = new_gov();
        let id = gov.submit(inflation_change(500), T0, u128::MAX).unwrap();
        gov.vote(id, voter(1), u128::MAX, VoteChoice::Yes, T0 + 1)
            .unwrap();
        assert!(matches!(
            close_voting(&mut gov, id),
            ProposalStatus::Passed { .. }
        ));
    }

    #[test]
    fn fork_names_are_narrowly_validated() {
        assert!(ForkName::new("cancun-2").is_ok());
        assert!(ForkName::new("v2_final").is_ok());
        for bad in [
            "",
            "Upper",
            "has space",
            "dot.name",
            &"x".repeat(MAX_FORK_NAME_LEN + 1),
        ] {
            assert_eq!(
                ForkName::new(bad),
                Err(GovernanceError::InvalidForkName),
                "{bad:?}"
            );
        }
        assert!(ForkName::new(&"x".repeat(MAX_FORK_NAME_LEN)).is_ok());
    }

    /// Passes and applies a fork activation at `apply_height`.
    fn schedule_fork(
        gov: &mut Gov,
        fork: &str,
        activation: u64,
        apply_height: u64,
        submitted_at: u64,
    ) -> ProposalStatus {
        let id = gov
            .submit(
                ProposalKind::ForkActivation {
                    fork: ForkName::new(fork).unwrap(),
                    height: BlockHeight(activation),
                },
                submitted_at,
                1_000,
            )
            .unwrap();
        gov.vote(id, voter(1), 900, VoteChoice::Yes, submitted_at + 1)
            .unwrap();
        let passed_at = submitted_at + VOTING_PERIOD_MS;
        gov.process(passed_at, BlockHeight(apply_height)).unwrap();
        gov.process(passed_at + TIMELOCK_MS, BlockHeight(apply_height))
            .unwrap();
        gov.proposal(id).unwrap().unwrap().status()
    }

    #[test]
    fn a_fork_with_two_weeks_notice_is_scheduled_and_activates_at_its_height() {
        let mut gov = new_gov();
        let apply_height = 1_000;
        let activation = apply_height + MIN_FORK_LEAD_BLOCKS;
        assert_eq!(
            schedule_fork(&mut gov, "v2", activation, apply_height, T0),
            ProposalStatus::Applied
        );

        let fork = ForkName::new("v2").unwrap();
        assert_eq!(
            gov.fork_activation(&fork).unwrap(),
            Some(BlockHeight(activation))
        );
        assert!(!gov
            .is_fork_active(&fork, BlockHeight(activation - 1))
            .unwrap());
        assert!(gov.is_fork_active(&fork, BlockHeight(activation)).unwrap());
        assert!(gov
            .is_fork_active(&fork, BlockHeight(activation + 1))
            .unwrap());
        assert!(!gov
            .is_fork_active(&ForkName::new("other").unwrap(), BlockHeight(u64::MAX))
            .unwrap());
    }

    #[test]
    fn a_fork_with_less_than_two_weeks_notice_fails_at_application() {
        let mut gov = new_gov();
        let apply_height = 1_000;
        let too_soon = apply_height + MIN_FORK_LEAD_BLOCKS - 1;
        assert_eq!(
            schedule_fork(&mut gov, "v2", too_soon, apply_height, T0),
            ProposalStatus::Failed(ApplyFailure::ForkTooSoon)
        );
        assert_eq!(
            gov.fork_activation(&ForkName::new("v2").unwrap()).unwrap(),
            None
        );
    }

    #[test]
    fn a_pending_fork_can_be_rescheduled() {
        let mut gov = new_gov();
        let first = 1_000 + MIN_FORK_LEAD_BLOCKS;
        schedule_fork(&mut gov, "v2", first, 1_000, T0);

        let later = 2_000 + MIN_FORK_LEAD_BLOCKS + 500;
        assert_eq!(
            schedule_fork(&mut gov, "v2", later, 2_000, T0 + 30 * DAY_MS),
            ProposalStatus::Applied
        );
        assert_eq!(
            gov.fork_activation(&ForkName::new("v2").unwrap()).unwrap(),
            Some(BlockHeight(later))
        );
    }

    #[test]
    fn a_fork_that_has_already_activated_cannot_be_moved() {
        let mut gov = new_gov();
        let activation = 1_000 + MIN_FORK_LEAD_BLOCKS;
        schedule_fork(&mut gov, "v2", activation, 1_000, T0);

        // Applied well after the activation height has passed.
        let status = schedule_fork(
            &mut gov,
            "v2",
            activation + 10 * MIN_FORK_LEAD_BLOCKS,
            activation + 5,
            T0 + 30 * DAY_MS,
        );
        assert_eq!(
            status,
            ProposalStatus::Failed(ApplyFailure::ForkAlreadyActivated)
        );
        assert_eq!(
            gov.fork_activation(&ForkName::new("v2").unwrap()).unwrap(),
            Some(BlockHeight(activation)),
            "the original activation stands"
        );
    }

    #[test]
    fn a_fork_counts_as_activated_from_its_own_height_and_not_the_block_before() {
        let activation = 1_000 + MIN_FORK_LEAD_BLOCKS;

        // Applied at the very height it activates at: too late to move.
        let mut gov = new_gov();
        schedule_fork(&mut gov, "v2", activation, 1_000, T0);
        assert_eq!(
            schedule_fork(
                &mut gov,
                "v2",
                activation + 10 * MIN_FORK_LEAD_BLOCKS,
                activation,
                T0 + 30 * DAY_MS
            ),
            ProposalStatus::Failed(ApplyFailure::ForkAlreadyActivated)
        );

        // One block earlier it has not activated, so it can still move.
        let mut gov = new_gov();
        schedule_fork(&mut gov, "v2", activation, 1_000, T0);
        assert_eq!(
            schedule_fork(
                &mut gov,
                "v2",
                activation + 10 * MIN_FORK_LEAD_BLOCKS,
                activation - 1,
                T0 + 30 * DAY_MS
            ),
            ProposalStatus::Applied
        );
    }

    #[test]
    fn identical_inputs_give_identical_governance_state() {
        let run = || {
            let mut gov = new_gov();
            let id = submit(&mut gov, inflation_change(500));
            cast(&mut gov, id, 2, 300, VoteChoice::Yes);
            cast(&mut gov, id, 1, 200, VoteChoice::No);
            gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
            gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
                .unwrap();
            gov
        };
        assert_eq!(run(), run());
    }

    // ---- storage -------------------------------------------------------

    use chain_types::codec::decode_exact;
    use proptest::prelude::*;

    fn count(store: &MemStore, tag: u8) -> usize {
        store.scan_prefix(&[tag], usize::MAX).len()
    }

    /// How many keys differ between two stores.
    fn keys_changed(before: &MemStore, after: &MemStore) -> usize {
        let keys: std::collections::BTreeSet<&Vec<u8>> =
            before.iter().chain(after.iter()).map(|(k, _)| k).collect();
        keys.into_iter()
            .filter(|key| before.get(key) != after.get(key))
            .count()
    }

    fn tampered(gov: Gov, edit: impl FnOnce(&mut MemStore)) -> Gov {
        let mut store = gov.into_store();
        edit(&mut store);
        Governance::new(store)
    }

    #[test]
    fn nothing_works_before_genesis_and_genesis_happens_once() {
        let mut gov = Governance::new(MemStore::new());
        assert_eq!(gov.params(), Err(GovernanceError::NotInitialised));
        assert_eq!(
            gov.process(T0, BlockHeight(1)),
            Err(GovernanceError::NotInitialised)
        );
        assert!(gov.store().is_empty(), "and the refusal left nothing");

        gov.init_genesis(params()).unwrap();
        assert_eq!(gov.params().unwrap(), params());
        let before = gov.store().clone();
        assert_eq!(
            gov.init_genesis(params()),
            Err(GovernanceError::AlreadyInitialised)
        );
        assert_eq!(gov.store(), &before);
    }

    #[test]
    fn an_operation_touches_a_handful_of_keys_however_many_proposals_and_voters_exist() {
        let mut gov = new_gov();
        let id = gov.submit(inflation_change(500), T0, u128::MAX).unwrap();
        for i in 0..300u64 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            gov.vote(id, Address::from_bytes(bytes), 1, VoteChoice::Yes, T0 + 1)
                .unwrap();
        }
        for _ in 0..10 {
            gov.submit(inflation_change(600), T0, 1_000).unwrap();
        }

        let before = gov.store().clone();
        gov.vote(id, voter(0xEE), 5, VoteChoice::No, T0 + 2)
            .unwrap();
        assert_eq!(
            keys_changed(&before, gov.store()),
            2,
            "the voter's ballot and the proposal's tally"
        );

        let before = gov.store().clone();
        gov.vote(id, voter(0xEE), 7, VoteChoice::Yes, T0 + 3)
            .unwrap();
        assert_eq!(keys_changed(&before, gov.store()), 2, "a re-vote likewise");

        let before = gov.store().clone();
        gov.submit(inflation_change(700), T0, 1_000).unwrap();
        assert_eq!(
            keys_changed(&before, gov.store()),
            3,
            "the proposal, its open-index entry and the id counter"
        );
    }

    #[test]
    fn processing_reads_only_unresolved_proposals_never_the_history() {
        // Resolved proposals — records and votes alike — are history:
        // damage to them must not touch what `process` does, because
        // `process` must not read them.
        let mut gov = new_gov();
        let done = submit(&mut gov, inflation_change(500));
        cast(&mut gov, done, 1, 900, VoteChoice::Yes);
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();
        assert_eq!(
            gov.proposal(done).unwrap().unwrap().status(),
            ProposalStatus::Applied
        );

        let later = T0 + 30 * DAY_MS;
        let live = gov.submit(inflation_change(600), later, 1_000).unwrap();
        gov.vote(live, voter(1), 900, VoteChoice::Yes, later + 1)
            .unwrap();

        let mut gov = tampered(gov, |store| {
            store.put(proposal_key(done), vec![0xFF, 0xFF]);
            store.put(vote_key(done, &voter(1)), vec![0xFF]);
        });
        let events = gov
            .process(later + VOTING_PERIOD_MS, BlockHeight(3))
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, live);
    }

    #[test]
    fn resolved_proposals_and_their_votes_are_kept() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();

        assert_eq!(
            gov.vote_of(id, &voter(1)).unwrap(),
            Some((VoteChoice::Yes, 900))
        );
        assert_eq!(count(gov.store(), tag::GOV_PROPOSAL), 1);
        assert_eq!(count(gov.store(), tag::GOV_OPEN), 0, "but not open");
        gov.assert_invariants().unwrap();
    }

    #[test]
    fn a_new_governance_over_a_copy_of_the_store_is_the_same_governance() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();

        let mut restarted = Governance::new(gov.store().clone());
        assert_eq!(restarted, gov);
        // And it carries on: the timelock it was in the middle of ends.
        let events = restarted
            .process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();
        assert_eq!(events, vec![(id, ProposalStatus::Applied)]);
        assert_eq!(restarted.params().unwrap().values().inflation_bps, 500);
    }

    #[test]
    fn forks_are_stored_one_entry_per_name() {
        let mut gov = new_gov();
        schedule_fork(&mut gov, "v2", 1_000 + MIN_FORK_LEAD_BLOCKS, 1_000, T0);
        schedule_fork(
            &mut gov,
            "v3",
            5_000 + MIN_FORK_LEAD_BLOCKS,
            5_000,
            T0 + 30 * DAY_MS,
        );
        assert_eq!(count(gov.store(), tag::GOV_FORK), 2);
        assert_eq!(
            gov.fork_activation(&ForkName::new("v2").unwrap()).unwrap(),
            Some(BlockHeight(1_000 + MIN_FORK_LEAD_BLOCKS))
        );
        assert_eq!(
            gov.fork_activation(&ForkName::new("v3").unwrap()).unwrap(),
            Some(BlockHeight(5_000 + MIN_FORK_LEAD_BLOCKS))
        );
    }

    // ---- the running tally ---------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// However votes are cast and changed, the proposal's running tally
        /// is exactly what recounting each voter's *last* vote gives, and
        /// the stored records stay consistent with each other.
        #[test]
        fn the_running_tally_always_equals_a_recount_of_each_voters_last_vote(
            votes in proptest::collection::vec((0u8..6, 1u128..200, 0u8..4), 1..40)
        ) {
            let mut gov = new_gov();
            let id = gov.submit(inflation_change(500), T0, 1_000).unwrap();
            let mut last: std::collections::BTreeMap<u8, (VoteChoice, u128)> =
                std::collections::BTreeMap::new();
            for (who, power, kind) in votes {
                let choice = match kind {
                    0 => VoteChoice::Yes,
                    1 => VoteChoice::No,
                    2 => VoteChoice::Abstain,
                    _ => VoteChoice::NoWithVeto,
                };
                if gov.vote(id, voter(who), power, choice, T0 + 1).is_ok() {
                    last.insert(who, (choice, power));
                }
                gov.assert_invariants().unwrap();
            }

            let mut expected = Tally::default();
            for (choice, power) in last.values() {
                let bucket = expected.bucket(*choice);
                *bucket += power;
                expected.voters += 1;
            }
            let stored = gov.proposal(id).unwrap().unwrap();
            prop_assert_eq!(stored.tally, expected);
            prop_assert!(expected.cast() <= 1_000, "never past the total power");
        }
    }

    // ---- corruption and atomicity --------------------------------------

    #[test]
    fn a_stored_record_that_does_not_decode_is_corruption_not_absence() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));

        let bad_proposal = tampered(gov.clone(), |s| s.put(proposal_key(id), vec![7, 7]));
        assert_eq!(
            bad_proposal.proposal(id),
            Err(GovernanceError::CorruptState)
        );
        let mut bad_proposal = bad_proposal;
        assert_eq!(
            bad_proposal.vote(id, voter(1), 10, VoteChoice::Yes, T0 + 1),
            Err(GovernanceError::CorruptState),
            "not UnknownProposal: the record is there, and bad"
        );

        let bad_params = tampered(gov.clone(), |s| s.put(params_key(), vec![1]));
        assert_eq!(bad_params.params(), Err(GovernanceError::CorruptState));

        let bad_ballot = tampered(gov, |s| s.put(vote_key(id, &voter(1)), vec![9]));
        assert_eq!(
            bad_ballot.vote_of(id, &voter(1)),
            Err(GovernanceError::CorruptState)
        );
    }

    #[test]
    fn stored_parameters_outside_their_clamps_are_refused_on_read() {
        // The clamps are checked when a set is built, and again every time
        // one is read back, so damaged state cannot smuggle a bad value in.
        let mut values = *params().values();
        values.inflation_bps = 9_999; // clamp is 1_000
        let mut bytes = Vec::new();
        values.encode(&mut bytes);

        let gov = tampered(new_gov(), |s| s.put(params_key(), bytes));
        assert_eq!(gov.params(), Err(GovernanceError::CorruptState));
    }

    #[test]
    fn a_corrupt_record_found_halfway_through_processing_leaves_nothing_changed() {
        // Two proposals are due. The first would pass; the second is
        // damaged. Nothing may be recorded for the first either.
        let mut gov = new_gov();
        let first = submit(&mut gov, inflation_change(500));
        cast(&mut gov, first, 1, 900, VoteChoice::Yes);
        let second = submit(&mut gov, inflation_change(600));
        let mut gov = tampered(gov, |s| s.put(proposal_key(second), vec![0xFF]));
        let before = gov.store().clone();

        assert_eq!(
            gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)),
            Err(GovernanceError::CorruptState)
        );
        assert_eq!(gov.store(), &before);
    }

    #[test]
    fn a_refused_vote_or_submission_changes_nothing() {
        let mut gov = new_gov();
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);
        let before = gov.store().clone();

        assert!(gov
            .vote(id, voter(2), 401, VoteChoice::Yes, T0 + 1)
            .is_err());
        assert!(gov.vote(id, voter(2), 0, VoteChoice::Yes, T0 + 1).is_err());
        assert!(gov
            .vote(ProposalId(9), voter(2), 1, VoteChoice::Yes, T0 + 1)
            .is_err());
        assert!(gov.submit(inflation_change(1), T0, 0).is_err());
        assert_eq!(gov.store(), &before);
    }

    #[test]
    fn the_invariant_check_notices_records_that_no_longer_agree() {
        let build = || {
            let mut gov = new_gov();
            let id = submit(&mut gov, inflation_change(500));
            cast(&mut gov, id, 1, 400, VoteChoice::Yes);
            cast(&mut gov, id, 2, 100, VoteChoice::No);
            gov.assert_invariants().unwrap();
            (gov, id)
        };

        // A ballot altered without the tally following.
        let (gov, id) = build();
        let gov = tampered(gov, |s| {
            let mut bytes = Vec::new();
            Ballot {
                choice: VoteChoice::Yes,
                power: 401,
            }
            .encode(&mut bytes);
            s.put(vote_key(id, &voter(1)), bytes);
        });
        assert_eq!(gov.assert_invariants(), Err(GovernanceError::CorruptState));

        // An unresolved proposal missing from the open index.
        let (gov, id) = build();
        let gov = tampered(gov, |s| s.delete(&open_key(id)));
        assert_eq!(gov.assert_invariants(), Err(GovernanceError::CorruptState));

        // A resolved proposal still in the open index.
        let (mut gov, id) = build();
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();
        gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
            .unwrap();
        gov.assert_invariants().unwrap();
        let gov = tampered(gov, |s| s.put(open_key(id), Vec::new()));
        assert_eq!(gov.assert_invariants(), Err(GovernanceError::CorruptState));

        // A proposal id at or past the counter.
        let (gov, _) = build();
        let gov = tampered(gov, |s| {
            let mut bytes = Vec::new();
            0u64.encode(&mut bytes);
            s.put(next_id_key(), bytes);
        });
        assert_eq!(gov.assert_invariants(), Err(GovernanceError::CorruptState));
    }

    // ---- codecs --------------------------------------------------------

    fn round_trips<T: Encode + Decode + PartialEq + core::fmt::Debug>(value: T) {
        let mut bytes = Vec::new();
        value.encode(&mut bytes);
        assert_eq!(decode_exact::<T>(&bytes).unwrap(), value);
        // Strict: a byte too many, and every strict prefix, are refused.
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(decode_exact::<T>(&longer).is_err(), "trailing byte");
        for cut in 0..bytes.len() {
            assert!(
                decode_exact::<T>(&bytes[..cut]).is_err(),
                "truncated to {cut} of {}",
                bytes.len()
            );
        }
    }

    #[test]
    fn every_persisted_enum_variant_round_trips_strictly() {
        for choice in [
            VoteChoice::Yes,
            VoteChoice::No,
            VoteChoice::Abstain,
            VoteChoice::NoWithVeto,
        ] {
            round_trips(choice);
        }
        for rejection in [
            Rejection::QuorumNotMet,
            Rejection::Vetoed,
            Rejection::NotEnoughYes,
        ] {
            round_trips(rejection);
        }
        for failure in [
            ApplyFailure::ForkTooSoon,
            ApplyFailure::ForkAlreadyActivated,
            ApplyFailure::Params(ParamError::MinSelfStakeZero),
            ApplyFailure::Params(ParamError::InflationOutOfRange),
            ApplyFailure::Params(ParamError::UnbondingPeriodOutOfRange),
            ApplyFailure::Params(ParamError::QuorumOutOfRange),
            ApplyFailure::Params(ParamError::VetoThresholdOutOfRange),
            ApplyFailure::Params(ParamError::Fee(
                crate::fees::FeeError::BlockGasLimitOutOfRange,
            )),
            ApplyFailure::Params(ParamError::Fee(
                crate::fees::FeeError::DenominatorOutOfRange,
            )),
        ] {
            round_trips(failure);
            round_trips(ProposalStatus::Failed(failure));
        }
        for status in [
            ProposalStatus::Voting,
            ProposalStatus::Applied,
            ProposalStatus::Passed { apply_at_ms: 99 },
            ProposalStatus::Rejected(Rejection::Vetoed),
        ] {
            round_trips(status);
        }
    }

    #[test]
    fn proposals_and_their_kinds_round_trip() {
        round_trips(ProposalKind::ParameterChange(ParamChange {
            max_block_gas: Some(1),
            base_fee_change_denominator: None,
            min_self_stake: Some(u128::MAX),
            inflation_bps: Some(7),
            unbonding_period_ms: None,
            quorum_bps: Some(2),
            veto_threshold_bps: None,
        }));
        round_trips(ProposalKind::ForkActivation {
            fork: ForkName::new("v2-final_1").unwrap(),
            height: BlockHeight(123_456),
        });
        round_trips(Proposal {
            kind: inflation_change(500),
            voting_ends_at_ms: 7,
            total_power: u128::MAX,
            tally: Tally {
                yes: 1,
                no: 2,
                abstain: 3,
                veto: 4,
                voters: 5,
            },
            status: ProposalStatus::Passed { apply_at_ms: 8 },
        });
        round_trips(Ballot {
            choice: VoteChoice::NoWithVeto,
            power: 42,
        });
    }

    #[test]
    fn unknown_variants_and_malformed_fork_names_are_invalid_encodings() {
        for bad in [[9u8].as_slice(), &[4, 9], &[1, 9]] {
            assert!(decode_exact::<ProposalStatus>(bad).is_err(), "{bad:?}");
        }
        assert!(decode_exact::<VoteChoice>(&[4]).is_err());
        assert!(decode_exact::<Rejection>(&[3]).is_err());
        assert!(decode_exact::<ProposalKind>(&[2]).is_err());

        // A fork activation whose name is not a well-formed one.
        let mut bytes = vec![1u8];
        b"Upper".to_vec().encode(&mut bytes);
        BlockHeight(1).encode(&mut bytes);
        assert!(decode_exact::<ProposalKind>(&bytes).is_err());
        let mut bytes = vec![1u8];
        vec![0xFFu8, 0xFE].encode(&mut bytes);
        BlockHeight(1).encode(&mut bytes);
        assert!(decode_exact::<ProposalKind>(&bytes).is_err(), "not UTF-8");
    }
}
