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
//! hook. Nothing here reads state, signs, or touches a network; voting
//! power is supplied by the caller as a snapshot taken when the proposal
//! was submitted, so stake moving mid-vote cannot swing the result.
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

use chain_types::collections::BTreeMap;
use chain_types::{Address, BlockHeight};

use crate::params::{GovernedParams, ParamChange, ParamError, DAY_MS, SECOND_MS};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    kind: ProposalKind,
    voting_ends_at_ms: u64,
    total_power: u128,
    votes: BTreeMap<Address, (VoteChoice, u128)>,
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

    pub fn vote_of(&self, voter: &Address) -> Option<(VoteChoice, u128)> {
        self.votes.get(voter).copied()
    }

    const fn is_open(&self) -> bool {
        matches!(
            self.status,
            ProposalStatus::Voting | ProposalStatus::Passed { .. }
        )
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
        })
    }
}

impl std::error::Error for GovernanceError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Governance {
    params: GovernedParams,
    next_id: u64,
    proposals: BTreeMap<ProposalId, Proposal>,
    fork_activations: BTreeMap<ForkName, BlockHeight>,
}

impl Governance {
    pub fn new(params: GovernedParams) -> Self {
        Self {
            params,
            next_id: 0,
            proposals: BTreeMap::new(),
            fork_activations: BTreeMap::new(),
        }
    }

    pub const fn params(&self) -> &GovernedParams {
        &self.params
    }

    pub fn proposal(&self, id: ProposalId) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// How many proposals are unresolved: still being voted on, or
    /// passed and waiting out the timelock.
    pub fn open_proposal_count(&self) -> usize {
        self.proposals.values().filter(|p| p.is_open()).count()
    }

    /// Whether `fork` is scheduled at or before `height`.
    pub fn is_fork_active(&self, fork: &ForkName, height: BlockHeight) -> bool {
        self.fork_activations
            .get(fork)
            .is_some_and(|activation| *activation <= height)
    }

    pub fn fork_activation(&self, fork: &ForkName) -> Option<BlockHeight> {
        self.fork_activations.get(fork).copied()
    }

    /// Opens a proposal for voting. `total_power` is the total voting
    /// power at this moment, fixed for this proposal's whole life.
    pub fn submit(
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
        if self.open_proposal_count() >= MAX_OPEN_PROPOSALS {
            return Err(GovernanceError::TooManyOpenProposals);
        }
        let id = ProposalId(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(GovernanceError::ProposalIdsExhausted)?;

        self.proposals.insert(
            id,
            Proposal {
                kind,
                voting_ends_at_ms: now_ms.saturating_add(VOTING_PERIOD_MS),
                total_power,
                votes: BTreeMap::new(),
                status: ProposalStatus::Voting,
            },
        );
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
        let proposal = self
            .proposals
            .get_mut(&id)
            .ok_or(GovernanceError::UnknownProposal)?;
        if proposal.status != ProposalStatus::Voting || now_ms >= proposal.voting_ends_at_ms {
            return Err(GovernanceError::VotingClosed);
        }
        if power == 0 {
            return Err(GovernanceError::ZeroVotingPower);
        }
        if !proposal.votes.contains_key(&voter) && proposal.votes.len() >= MAX_VOTERS_PER_PROPOSAL {
            return Err(GovernanceError::TooManyVoters);
        }
        let cast_by_others = proposal
            .votes
            .iter()
            .filter(|(address, _)| **address != voter)
            .map(|(_, (_, other_power))| *other_power)
            .fold(0u128, u128::saturating_add);
        if cast_by_others.saturating_add(power) > proposal.total_power {
            return Err(GovernanceError::VotingPowerExceedsTotal);
        }
        proposal.votes.insert(voter, (choice, power));
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
    pub fn process(
        &mut self,
        now_ms: u64,
        now_height: BlockHeight,
    ) -> Vec<(ProposalId, ProposalStatus)> {
        let mut changed = Vec::new();
        for (id, proposal) in &mut self.proposals {
            let next = match proposal.status {
                ProposalStatus::Voting if now_ms >= proposal.voting_ends_at_ms => {
                    Some(match evaluate(proposal, &self.params) {
                        Ok(()) => ProposalStatus::Passed {
                            apply_at_ms: now_ms.saturating_add(TIMELOCK_MS),
                        },
                        Err(rejection) => ProposalStatus::Rejected(rejection),
                    })
                }
                ProposalStatus::Passed { apply_at_ms } if now_ms >= apply_at_ms => Some(apply(
                    &proposal.kind,
                    &mut self.params,
                    &mut self.fork_activations,
                    now_height,
                )),
                _ => None,
            };
            if let Some(status) = next {
                proposal.status = status;
                changed.push((*id, status));
            }
        }
        changed
    }
}

/// Whether a proposal whose voting period has ended passed, and if not,
/// why. Checked in a fixed order — quorum, then veto, then majority — so
/// a proposal that fails several always reports the same one.
fn evaluate(proposal: &Proposal, params: &GovernedParams) -> Result<(), Rejection> {
    let (mut yes, mut no, mut abstain, mut veto) = (0u128, 0u128, 0u128, 0u128);
    for &(choice, power) in proposal.votes.values() {
        let bucket = match choice {
            VoteChoice::Yes => &mut yes,
            VoteChoice::No => &mut no,
            VoteChoice::Abstain => &mut abstain,
            VoteChoice::NoWithVeto => &mut veto,
        };
        *bucket = bucket.saturating_add(power);
    }
    let voted = yes
        .saturating_add(no)
        .saturating_add(abstain)
        .saturating_add(veto);

    // Cross-multiplied in `U256` so a `u128` voting power times a basis-
    // point figure cannot overflow, and no division rounds a threshold
    // the wrong way.
    let scaled = |power: u128, bps: u64| U256::from(power).saturating_mul(U256::from(bps));
    let values = params.values();

    let quorum_bps = u64::from(values.quorum_bps);
    if scaled(voted, BPS_DENOMINATOR) < scaled(proposal.total_power, quorum_bps) {
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

/// Applies a passed proposal, returning how that went. A failure here
/// leaves `params` and `fork_activations` exactly as they were.
fn apply(
    kind: &ProposalKind,
    params: &mut GovernedParams,
    fork_activations: &mut BTreeMap<ForkName, BlockHeight>,
    now_height: BlockHeight,
) -> ProposalStatus {
    match kind {
        ProposalKind::ParameterChange(change) => match params.with_change(change) {
            Ok(updated) => {
                *params = updated;
                ProposalStatus::Applied
            }
            Err(err) => ProposalStatus::Failed(ApplyFailure::Params(err)),
        },
        ProposalKind::ForkActivation { fork, height } => {
            if fork_activations
                .get(fork)
                .is_some_and(|existing| *existing <= now_height)
            {
                return ProposalStatus::Failed(ApplyFailure::ForkAlreadyActivated);
            }
            if height.0 < now_height.0.saturating_add(MIN_FORK_LEAD_BLOCKS) {
                return ProposalStatus::Failed(ApplyFailure::ForkTooSoon);
            }
            fork_activations.insert(fork.clone(), *height);
            ProposalStatus::Applied
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::integer_division
    )]

    use super::*;
    use crate::params::{ParamValues, MIN_UNBONDING_PERIOD_MS};

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
    fn submit(gov: &mut Governance, kind: ProposalKind) -> ProposalId {
        gov.submit(kind, T0, 1_000).unwrap()
    }

    fn cast(gov: &mut Governance, id: ProposalId, who: u8, power: u128, choice: VoteChoice) {
        gov.vote(id, voter(who), power, choice, T0 + 1).unwrap();
    }

    /// Runs voting to its deadline and returns the resulting status.
    fn close_voting(gov: &mut Governance, id: ProposalId) -> ProposalStatus {
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1));
        gov.proposal(id).unwrap().status()
    }

    #[test]
    fn a_passing_proposal_waits_out_the_timelock_before_it_takes_effect() {
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);

        assert!(gov
            .process(T0 + VOTING_PERIOD_MS - 1, BlockHeight(1))
            .is_empty());
        assert_eq!(gov.proposal(id).unwrap().status(), ProposalStatus::Voting);

        let passed_at = T0 + VOTING_PERIOD_MS;
        assert_eq!(
            gov.process(passed_at, BlockHeight(1)),
            vec![(
                id,
                ProposalStatus::Passed {
                    apply_at_ms: passed_at + TIMELOCK_MS
                }
            )]
        );
        assert_eq!(gov.params().values().inflation_bps, 400, "not yet");

        assert!(gov
            .process(passed_at + TIMELOCK_MS - 1, BlockHeight(2))
            .is_empty());
        assert_eq!(gov.params().values().inflation_bps, 400, "still timelocked");

        assert_eq!(
            gov.process(passed_at + TIMELOCK_MS, BlockHeight(3)),
            vec![(id, ProposalStatus::Applied)]
        );
        assert_eq!(gov.params().values().inflation_bps, 500);
    }

    #[test]
    fn the_timelock_runs_from_when_passage_is_recorded_not_from_the_deadline() {
        // A process call that comes late must not shorten the window in
        // which a passed proposal can be seen before it takes effect.
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);

        let late = T0 + VOTING_PERIOD_MS + 10 * DAY_MS;
        gov.process(late, BlockHeight(1));
        assert_eq!(
            gov.proposal(id).unwrap().status(),
            ProposalStatus::Passed {
                apply_at_ms: late + TIMELOCK_MS
            }
        );
        assert!(gov.process(late + 1, BlockHeight(2)).is_empty());
    }

    #[test]
    fn too_little_turnout_fails_the_quorum() {
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 333, VoteChoice::Yes); // 33.3% < 33.4%

        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::QuorumNotMet)
        );
    }

    #[test]
    fn turnout_exactly_at_the_quorum_counts() {
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 334, VoteChoice::Yes); // exactly 33.4%

        assert!(matches!(
            close_voting(&mut gov, id),
            ProposalStatus::Passed { .. }
        ));
    }

    #[test]
    fn a_veto_beats_a_yes_majority() {
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
        let only_abstentions = submit(&mut gov, inflation_change(500));
        cast(&mut gov, only_abstentions, 1, 600, VoteChoice::Abstain);
        assert_eq!(
            close_voting(&mut gov, only_abstentions),
            ProposalStatus::Rejected(Rejection::NotEnoughYes),
            "quorum was met, but nobody voted for it"
        );

        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(5_000)); // 50%, clamp is 10%
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);

        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1));
        let events = gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2));
        assert_eq!(
            events,
            vec![(
                id,
                ProposalStatus::Failed(ApplyFailure::Params(ParamError::InflationOutOfRange))
            )]
        );
        assert_eq!(gov.params().values().inflation_bps, 400, "chain untouched");
    }

    #[test]
    fn two_proposals_applied_together_both_take_effect() {
        // Each change is merged onto the parameters as they stand when it
        // is applied, not onto a snapshot from when it was submitted — so
        // the second must not quietly undo the first.
        let mut gov = Governance::new(params());
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
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1));
        let events = gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2));

        assert_eq!(
            events,
            vec![
                (first, ProposalStatus::Applied),
                (second, ProposalStatus::Applied)
            ]
        );
        assert_eq!(gov.params().values().inflation_bps, 1_000);
        assert_eq!(
            gov.params().values().unbonding_period_ms,
            MIN_UNBONDING_PERIOD_MS + DAY_MS
        );
    }

    #[test]
    fn voting_closes_at_the_deadline() {
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 600, VoteChoice::Yes);
        cast(&mut gov, id, 1, 600, VoteChoice::No);

        assert_eq!(
            gov.proposal(id).unwrap().vote_of(&voter(1)),
            Some((VoteChoice::No, 600))
        );
        assert_eq!(
            close_voting(&mut gov, id),
            ProposalStatus::Rejected(Rejection::NotEnoughYes)
        );
    }

    #[test]
    fn votes_cannot_add_up_to_more_than_the_total_power() {
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
        for _ in 0..MAX_OPEN_PROPOSALS {
            submit(&mut gov, inflation_change(500));
        }
        assert_eq!(
            gov.submit(inflation_change(500), T0, 1_000),
            Err(GovernanceError::TooManyOpenProposals)
        );

        // Nobody voted, so all of them are rejected for want of quorum.
        gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1));
        assert_eq!(gov.open_proposal_count(), 0);
        assert!(gov
            .submit(inflation_change(500), T0 + VOTING_PERIOD_MS, 1_000)
            .is_ok());
    }

    #[test]
    fn a_passed_proposal_holds_its_slot_until_it_is_applied() {
        let mut gov = Governance::new(params());
        let id = submit(&mut gov, inflation_change(500));
        cast(&mut gov, id, 1, 900, VoteChoice::Yes);
        close_voting(&mut gov, id);
        assert_eq!(gov.open_proposal_count(), 1);
        gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2));
        assert_eq!(gov.open_proposal_count(), 0);
    }

    #[test]
    fn the_number_of_voters_on_one_proposal_is_bounded() {
        let mut gov = Governance::new(params());
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
        let mut gov = Governance::new(params());
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
        gov: &mut Governance,
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
        gov.process(passed_at, BlockHeight(apply_height));
        gov.process(passed_at + TIMELOCK_MS, BlockHeight(apply_height));
        gov.proposal(id).unwrap().status()
    }

    #[test]
    fn a_fork_with_two_weeks_notice_is_scheduled_and_activates_at_its_height() {
        let mut gov = Governance::new(params());
        let apply_height = 1_000;
        let activation = apply_height + MIN_FORK_LEAD_BLOCKS;
        assert_eq!(
            schedule_fork(&mut gov, "v2", activation, apply_height, T0),
            ProposalStatus::Applied
        );

        let fork = ForkName::new("v2").unwrap();
        assert_eq!(gov.fork_activation(&fork), Some(BlockHeight(activation)));
        assert!(!gov.is_fork_active(&fork, BlockHeight(activation - 1)));
        assert!(gov.is_fork_active(&fork, BlockHeight(activation)));
        assert!(gov.is_fork_active(&fork, BlockHeight(activation + 1)));
        assert!(!gov.is_fork_active(&ForkName::new("other").unwrap(), BlockHeight(u64::MAX)));
    }

    #[test]
    fn a_fork_with_less_than_two_weeks_notice_fails_at_application() {
        let mut gov = Governance::new(params());
        let apply_height = 1_000;
        let too_soon = apply_height + MIN_FORK_LEAD_BLOCKS - 1;
        assert_eq!(
            schedule_fork(&mut gov, "v2", too_soon, apply_height, T0),
            ProposalStatus::Failed(ApplyFailure::ForkTooSoon)
        );
        assert_eq!(gov.fork_activation(&ForkName::new("v2").unwrap()), None);
    }

    #[test]
    fn a_pending_fork_can_be_rescheduled() {
        let mut gov = Governance::new(params());
        let first = 1_000 + MIN_FORK_LEAD_BLOCKS;
        schedule_fork(&mut gov, "v2", first, 1_000, T0);

        let later = 2_000 + MIN_FORK_LEAD_BLOCKS + 500;
        assert_eq!(
            schedule_fork(&mut gov, "v2", later, 2_000, T0 + 30 * DAY_MS),
            ProposalStatus::Applied
        );
        assert_eq!(
            gov.fork_activation(&ForkName::new("v2").unwrap()),
            Some(BlockHeight(later))
        );
    }

    #[test]
    fn a_fork_that_has_already_activated_cannot_be_moved() {
        let mut gov = Governance::new(params());
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
            gov.fork_activation(&ForkName::new("v2").unwrap()),
            Some(BlockHeight(activation)),
            "the original activation stands"
        );
    }

    #[test]
    fn identical_inputs_give_identical_governance_state() {
        let run = || {
            let mut gov = Governance::new(params());
            let id = submit(&mut gov, inflation_change(500));
            cast(&mut gov, id, 2, 300, VoteChoice::Yes);
            cast(&mut gov, id, 1, 200, VoteChoice::No);
            gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1));
            gov.process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2));
            gov
        };
        assert_eq!(run(), run());
    }
}
