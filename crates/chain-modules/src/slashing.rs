//! Evidence admission, graduated slashing, and jailing. `docs/spec.md`,
//! "Keys, signing and slashing safety": "Slashing itself is graduated
//! and correlation-aware: a small penalty for an isolated double-sign,
//! scaled up by the fraction of stake that equivocated in the same
//! window, so a shared-infrastructure failure by one operator is not
//! priced as a coordinated attack. Downtime is jailing, not burning."
//! And, in "Economic security": double-sign "5% of stake, scaling to 100%
//! with correlated stake"; downtime "0%, jailing only".
//!
//! This is bookkeeping and policy only. [`SlashingTracker`] decides
//! *whether* evidence convicts and *how much* to burn from whom; it does
//! not hold any stake. It returns [`SlashOrder`]s, and the caller applies
//! each to the offender's `StakingPool` with `StakingPool::slash`. What
//! stake a validator had, when, and how much is bonded in total are all
//! passed in from chain state.
//!
//! # The rate
//!
//! [`slash_bps`]: a floor of 5%, rising by [`CORRELATION_MULTIPLIER`]
//! times the fraction of all bonded stake that equivocated in the same
//! window, capped at 100%. At a multiplier of 3 the penalty reaches 100%
//! exactly when a third of the stake has equivocated — the point at which
//! two conflicting blocks could both have been finalised, and the point
//! the spec's "cost to acquire 1/3 of stake" security target is
//! measured at. The multiplier is a choice (Ethereum's own) rather than
//! something the spec states.
//!
//! The offender's own stake counts toward that fraction, as the spec's
//! wording ("the fraction of stake that equivocated") implies. One
//! consequence worth knowing: the 5% floor is for validators holding
//! under 1/60 of bonded stake (about 1.7%). A validator with 10% of the
//! stake, offending entirely alone, already pays 3 x 10% = 30%. With 128
//! validators the average holds under 1%, so the typical isolated
//! offender pays the floor, but a large one does not.
//!
//! # Correlation is retroactive, on purpose
//!
//! Slashing each offender at the rate implied by whoever had been
//! reported *so far* would be order-dependent, and exploitable: a
//! coordinated attack could get its evidence submitted one validator at a
//! time and have the first several pay only the 5% floor. Instead every
//! new offender re-prices everyone else within the window: earlier
//! offenders are *topped up* to the higher rate, never refunded. So what
//! each pays depends only on the set of offenders in the window, not on
//! the order their evidence arrived in (see the `order` property test).
//!
//! # Deliberate simplifications
//!
//! - A validator is convicted **once**. The first admitted evidence
//!   tombstones them permanently — removed for good, further evidence
//!   against them is [`EvidenceRejection::AlreadySlashed`]. (Cosmos does
//!   the same; the spec says nothing either way.) The set of tombstoned
//!   validators only grows, bounded by the cost of being a slashable
//!   validator in the first place.
//! - Only double *votes* are handled. Malachite also detects double
//!   proposals; slashing for them is separate work.
//! - Downtime *detection* — deciding a validator missed enough blocks —
//!   needs participation data from consensus and is not built. Only the
//!   consequence, [`SlashingTracker::jail_for_downtime`], is. Slashing
//!   during a chain-wide halt is suspended per the spec's halt-recovery
//!   runbook; that is a caller's decision not to call it, not something
//!   this module can know.

use ruint::aliases::U256;

use chain_types::collections::BTreeMap;
use chain_types::{Address, BlsPublicKey, DuplicateVoteEvidence, EvidenceError};

use crate::params::{DAY_MS, MAX_EVIDENCE_AGE_MS};

/// `docs/spec.md`, "Economic security": "Slashing, double-sign: 5% of
/// stake" — the rate for an isolated offender.
pub const BASE_SLASH_BPS: u16 = 500;

/// "... scaling to 100% with correlated stake."
pub const MAX_SLASH_BPS: u16 = 10_000;

/// **A choice.** How steeply the penalty rises with correlated stake;
/// 3 makes it reach [`MAX_SLASH_BPS`] at one third of bonded stake.
pub const CORRELATION_MULTIPLIER: u64 = 3;

/// **A choice.** Two equivocations count as "the same window" if their
/// infractions were within this of each other. Set to the maximum
/// evidence age, so any two offences that could both still be reported
/// at the same moment are treated as correlated.
pub const CORRELATION_WINDOW_MS: u64 = MAX_EVIDENCE_AGE_MS;

/// **A choice.** The spec says downtime is jailing without a duration.
pub const DOWNTIME_JAIL_MS: u64 = DAY_MS;

const BPS_DENOMINATOR: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashingError {
    /// There is no bonded stake at all, so no fraction of it is defined.
    NoBondedStake,
}

fn ceil_div(numerator: U256, denominator: U256) -> Option<U256> {
    numerator
        .checked_add(denominator.checked_sub(U256::from(1u8))?)?
        .checked_div(denominator)
}

/// The slash rate, in basis points, for an offender given how much stake
/// equivocated in the same window (`correlated_stake`, including the
/// offender's own) out of `total_bonded`. Rounded *up* at every step —
/// against the offender, the same direction the staking module rounds
/// withdrawals against the user.
pub fn slash_bps(correlated_stake: u128, total_bonded: u128) -> Result<u16, SlashingError> {
    if total_bonded == 0 {
        return Err(SlashingError::NoBondedStake);
    }
    let correlated = correlated_stake.min(total_bonded);
    let correlated_bps = ceil_div(
        U256::from(correlated).saturating_mul(U256::from(BPS_DENOMINATOR)),
        U256::from(total_bonded),
    )
    .ok_or(SlashingError::NoBondedStake)?;

    let scaled = correlated_bps.saturating_mul(U256::from(CORRELATION_MULTIPLIER));
    let rate = scaled
        .max(U256::from(BASE_SLASH_BPS))
        .min(U256::from(MAX_SLASH_BPS));
    // At most 10_000, so the conversion cannot fail; the fallback is the
    // cap, never a smaller penalty.
    Ok(u16::try_from(&rate).unwrap_or(MAX_SLASH_BPS))
}

/// `ceil(stake * bps / 10_000)`: how much of `stake` a `bps` penalty
/// takes, rounded against the offender. Never more than `stake` for a
/// `bps` of at most [`MAX_SLASH_BPS`].
pub fn penalty(stake: u128, bps: u16) -> u128 {
    let product = U256::from(stake).saturating_mul(U256::from(bps));
    ceil_div(product, U256::from(BPS_DENOMINATOR))
        .and_then(|amount| u128::try_from(&amount).ok())
        .unwrap_or(stake)
        .min(stake)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRejection {
    /// Not evidence of equivocation by the key it was checked against.
    Invalid(EvidenceError),
    /// The infraction is dated after `now`.
    FromTheFuture,
    /// Older than [`MAX_EVIDENCE_AGE_MS`]. `docs/spec.md`: unbonding
    /// (21 days) must exceed max evidence age (14), so within this
    /// window the offender's stake is still there to slash.
    TooOld,
    /// This validator has already been convicted.
    AlreadySlashed,
    NoBondedStake,
    /// The validator had no stake at the infraction, so there is nothing
    /// to slash and the evidence is not acted on.
    NoStakeToSlash,
    /// The validator's stake exceeds the total — inconsistent input.
    StakeExceedsBonded,
}

/// How much of one validator's stake to burn. A validator can appear
/// more than once over time: once when first convicted, and again if
/// later offenders raise the correlated rate and they are topped up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashOrder {
    pub validator: Address,
    pub burn: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    /// Removed from the active set until they unjail (downtime), no
    /// earlier than `until_ms`.
    Jailed {
        until_ms: u64,
    },
    /// Convicted of equivocation: gone for good.
    Tombstoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JailError {
    Tombstoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnjailError {
    NotJailed,
    StillJailed { until_ms: u64 },
    Tombstoned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlashRecord {
    infraction_ms: u64,
    /// The validator's stake when they offended: what every rate is a
    /// fraction of, fixed at conviction so later top-ups are computed
    /// from the same base, not from a stake already reduced by the
    /// earlier burn.
    stake: u128,
    /// Total ordered burned against this record so far. Only ever grows.
    slashed: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlashingTracker {
    statuses: BTreeMap<Address, ValidatorStatus>,
    /// Recent convictions, kept only while they can still correlate with
    /// a new one. The permanent memory of who was convicted is
    /// `statuses`.
    records: BTreeMap<Address, SlashRecord>,
}

impl SlashingTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn status(&self, validator: &Address) -> ValidatorStatus {
        self.statuses
            .get(validator)
            .copied()
            .unwrap_or(ValidatorStatus::Active)
    }

    /// Everything ordered burned against `validator`'s equivocation so
    /// far, while their record is still within the correlation horizon.
    pub fn total_slashed(&self, validator: &Address) -> Option<u128> {
        self.records.get(validator).map(|record| record.slashed)
    }

    /// Admits `evidence` and returns what to burn, or says why not.
    ///
    /// `public_key` is the validator's registered BLS key. The
    /// remaining arguments must come from chain state, never from the
    /// evidence or its submitter: `infraction_time_ms` is the timestamp of
    /// the block at `evidence.height()`, `validator_stake` the validator's
    /// stake at that height, and `total_bonded_stake` the total bonded
    /// stake now. Nothing is changed unless the evidence is admitted.
    ///
    /// The returned orders are in validator-address order.
    pub fn submit_evidence(
        &mut self,
        evidence: &DuplicateVoteEvidence,
        public_key: &BlsPublicKey,
        infraction_time_ms: u64,
        validator_stake: u128,
        total_bonded_stake: u128,
        now_ms: u64,
    ) -> Result<Vec<SlashOrder>, EvidenceRejection> {
        let validator = evidence.validator();

        // Cheapest checks first; the signature check is last.
        if self.status(&validator) == ValidatorStatus::Tombstoned {
            return Err(EvidenceRejection::AlreadySlashed);
        }
        if infraction_time_ms > now_ms {
            return Err(EvidenceRejection::FromTheFuture);
        }
        if now_ms.saturating_sub(infraction_time_ms) > MAX_EVIDENCE_AGE_MS {
            return Err(EvidenceRejection::TooOld);
        }
        if total_bonded_stake == 0 {
            return Err(EvidenceRejection::NoBondedStake);
        }
        if validator_stake == 0 {
            return Err(EvidenceRejection::NoStakeToSlash);
        }
        if validator_stake > total_bonded_stake {
            return Err(EvidenceRejection::StakeExceedsBonded);
        }
        evidence
            .verify(public_key)
            .map_err(EvidenceRejection::Invalid)?;

        // Admitted. From here on the state changes.
        let horizon = CORRELATION_WINDOW_MS.saturating_mul(2);
        self.records
            .retain(|_, record| now_ms.saturating_sub(record.infraction_ms) <= horizon);
        self.records.insert(
            validator,
            SlashRecord {
                infraction_ms: infraction_time_ms,
                stake: validator_stake,
                slashed: 0,
            },
        );
        self.statuses.insert(validator, ValidatorStatus::Tombstoned);

        self.reprice_around(infraction_time_ms, total_bonded_stake)
    }

    /// Re-prices every record within the correlation window of
    /// `around_ms` — the new record and everyone it now correlates with
    /// — and returns what each is now owed beyond what was already
    /// ordered.
    fn reprice_around(
        &mut self,
        around_ms: u64,
        total_bonded_stake: u128,
    ) -> Result<Vec<SlashOrder>, EvidenceRejection> {
        let affected: Vec<Address> = self
            .records
            .iter()
            .filter(|(_, record)| record.infraction_ms.abs_diff(around_ms) <= CORRELATION_WINDOW_MS)
            .map(|(validator, _)| *validator)
            .collect();

        let mut orders = Vec::new();
        for validator in affected {
            let Some(record) = self.records.get(&validator).copied() else {
                continue;
            };
            let correlated = self
                .records
                .values()
                .filter(|other| {
                    other.infraction_ms.abs_diff(record.infraction_ms) <= CORRELATION_WINDOW_MS
                })
                .fold(0u128, |total, other| total.saturating_add(other.stake));
            let bps = slash_bps(correlated, total_bonded_stake)
                .map_err(|_| EvidenceRejection::NoBondedStake)?;

            let owed = penalty(record.stake, bps);
            let burn = owed.saturating_sub(record.slashed);
            if burn > 0 {
                if let Some(entry) = self.records.get_mut(&validator) {
                    entry.slashed = owed;
                }
                orders.push(SlashOrder { validator, burn });
            }
        }
        Ok(orders)
    }

    /// Jails `validator` for downtime — no burn, just removal from the
    /// active set for at least [`DOWNTIME_JAIL_MS`]. Never shortens an
    /// existing jail.
    pub fn jail_for_downtime(&mut self, validator: Address, now_ms: u64) -> Result<(), JailError> {
        let until_ms = now_ms.saturating_add(DOWNTIME_JAIL_MS);
        match self.status(&validator) {
            ValidatorStatus::Tombstoned => Err(JailError::Tombstoned),
            ValidatorStatus::Jailed { until_ms: existing } => {
                self.statuses.insert(
                    validator,
                    ValidatorStatus::Jailed {
                        until_ms: existing.max(until_ms),
                    },
                );
                Ok(())
            }
            ValidatorStatus::Active => {
                self.statuses
                    .insert(validator, ValidatorStatus::Jailed { until_ms });
                Ok(())
            }
        }
    }

    /// Returns a jailed validator to the active set, once their jail has
    /// run its course. A tombstoned validator can never return.
    pub fn unjail(&mut self, validator: &Address, now_ms: u64) -> Result<(), UnjailError> {
        match self.status(validator) {
            ValidatorStatus::Tombstoned => Err(UnjailError::Tombstoned),
            ValidatorStatus::Active => Err(UnjailError::NotJailed),
            ValidatorStatus::Jailed { until_ms } if now_ms < until_ms => {
                Err(UnjailError::StillJailed { until_ms })
            }
            ValidatorStatus::Jailed { .. } => {
                self.statuses.remove(validator);
                Ok(())
            }
        }
    }
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
    use crate::staking::StakingPool;
    use blst::min_pk::SecretKey;
    use chain_types::bls::{BlsSignature, DST_VOTE};
    use chain_types::{BlockHeight, Hash, Round, Vote, VoteKind};
    use proptest::prelude::*;

    const NOW: u64 = 100 * DAY_MS;

    fn addr_of(seed: u8) -> Address {
        Address::from_bytes([seed; 32])
    }

    /// Real, verifiable equivocation by the validator `seed`, plus its key.
    fn offence(seed: u8) -> (DuplicateVoteEvidence, BlsPublicKey) {
        let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let pk = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        let vote = |value: u8| Vote {
            height: BlockHeight(10),
            round: Round(0),
            value: Some(Hash::from_bytes([value; 32])),
            kind: VoteKind::Prevote,
            validator: addr_of(seed),
        };
        let sign = |v: &Vote| {
            BlsSignature::from_bytes(sk.sign(&v.signing_bytes(), DST_VOTE, &[]).to_bytes()).unwrap()
        };
        let (a, b) = (vote(1), vote(2));
        (
            DuplicateVoteEvidence {
                signature_a: sign(&a),
                signature_b: sign(&b),
                vote_a: a,
                vote_b: b,
            },
            pk,
        )
    }

    /// Submits `seed`'s offence, dated `NOW - age_ms`, staked `stake` of
    /// `total` bonded.
    fn submit(
        tracker: &mut SlashingTracker,
        seed: u8,
        age_ms: u64,
        stake: u128,
        total: u128,
    ) -> Result<Vec<SlashOrder>, EvidenceRejection> {
        let (evidence, pk) = offence(seed);
        tracker.submit_evidence(&evidence, &pk, NOW - age_ms, stake, total, NOW)
    }

    fn burned(orders: &[SlashOrder], seed: u8) -> u128 {
        orders
            .iter()
            .filter(|o| o.validator == addr_of(seed))
            .map(|o| o.burn)
            .sum()
    }

    // ---- the rate ------------------------------------------------------

    #[test]
    fn an_isolated_offender_pays_the_five_percent_floor() {
        // 1% of stake correlated (just themselves): 3% scaled, floored to 5%.
        assert_eq!(slash_bps(10, 1_000), Ok(500));
        assert_eq!(slash_bps(1, 1_000_000), Ok(500));
    }

    #[test]
    fn the_rate_rises_with_correlated_stake() {
        assert_eq!(slash_bps(100, 1_000), Ok(3_000), "10% correlated -> 30%");
        assert_eq!(slash_bps(200, 1_000), Ok(6_000), "20% correlated -> 60%");
        assert_eq!(slash_bps(50, 1_000), Ok(1_500), "5% correlated -> 15%");
    }

    #[test]
    fn a_third_of_the_stake_equivocating_costs_all_of_it() {
        assert_eq!(slash_bps(1_000, 3_000), Ok(10_000), "exactly one third");
        assert_eq!(slash_bps(2_000, 3_000), Ok(10_000));
        assert_eq!(slash_bps(3_000, 3_000), Ok(10_000));
    }

    #[test]
    fn just_under_a_third_is_still_just_under_everything() {
        let rate = slash_bps(999, 3_000).unwrap(); // 33.3% -> ceil 3330 bps * 3 = 9990
        assert!(rate < 10_000 && rate > 9_900, "{rate}");
    }

    #[test]
    fn more_correlated_stake_than_exists_is_capped_not_an_error() {
        assert_eq!(slash_bps(5_000, 1_000), Ok(10_000));
    }

    #[test]
    fn with_nothing_bonded_no_rate_is_defined() {
        assert_eq!(slash_bps(0, 0), Err(SlashingError::NoBondedStake));
        assert_eq!(slash_bps(10, 0), Err(SlashingError::NoBondedStake));
    }

    #[test]
    fn rates_do_not_overflow_at_the_top_of_u128() {
        assert_eq!(slash_bps(u128::MAX, u128::MAX), Ok(10_000));
        assert_eq!(slash_bps(u128::MAX / 2, u128::MAX), Ok(10_000));
    }

    #[test]
    fn the_penalty_rounds_against_the_offender() {
        assert_eq!(penalty(1_000, 500), 50);
        assert_eq!(penalty(1_001, 500), 51, "50.05 rounds up");
        assert_eq!(penalty(1, 500), 1, "even a sliver of a unit costs a unit");
        assert_eq!(penalty(0, 500), 0);
    }

    #[test]
    fn a_full_slash_takes_exactly_the_stake_and_never_more() {
        assert_eq!(penalty(1_234_567, 10_000), 1_234_567);
        assert_eq!(penalty(u128::MAX, 10_000), u128::MAX);
    }

    proptest! {
        #[test]
        fn the_rate_stays_within_its_bounds_and_never_falls_as_correlation_grows(
            total in 1u128..=u128::MAX,
            a in 0u128..=u128::MAX,
            b in 0u128..=u128::MAX,
        ) {
            let (low, high) = (a.min(b), a.max(b));
            let (r_low, r_high) = (slash_bps(low, total).unwrap(), slash_bps(high, total).unwrap());
            prop_assert!((BASE_SLASH_BPS..=MAX_SLASH_BPS).contains(&r_low));
            prop_assert!((BASE_SLASH_BPS..=MAX_SLASH_BPS).contains(&r_high));
            prop_assert!(r_low <= r_high);
        }

        #[test]
        fn a_penalty_never_exceeds_the_stake_and_never_falls_as_the_rate_rises(
            stake in 0u128..=u128::MAX,
            r1 in 0u16..=10_000,
            r2 in 0u16..=10_000,
        ) {
            let (lo, hi) = (r1.min(r2), r1.max(r2));
            prop_assert!(penalty(stake, hi) <= stake);
            prop_assert!(penalty(stake, lo) <= penalty(stake, hi));
        }
    }

    // ---- admitting evidence -------------------------------------------

    #[test]
    fn an_isolated_offender_is_burned_five_percent_and_tombstoned() {
        let mut tracker = SlashingTracker::new();
        let orders = submit(&mut tracker, 1, DAY_MS, 100, 10_000).unwrap();

        assert_eq!(
            orders,
            vec![SlashOrder {
                validator: addr_of(1),
                burn: 5
            }]
        );
        assert_eq!(tracker.status(&addr_of(1)), ValidatorStatus::Tombstoned);
        assert_eq!(tracker.total_slashed(&addr_of(1)), Some(5));
    }

    #[test]
    fn evidence_checked_against_the_wrong_key_changes_nothing() {
        let mut tracker = SlashingTracker::new();
        let (evidence, _) = offence(1);
        let (_, someone_elses_key) = offence(2);

        let result = tracker.submit_evidence(&evidence, &someone_elses_key, NOW, 100, 1_000, NOW);
        assert_eq!(
            result,
            Err(EvidenceRejection::Invalid(EvidenceError::InvalidSignature))
        );
        assert_eq!(
            tracker,
            SlashingTracker::new(),
            "a rejection must leave no trace"
        );
    }

    #[test]
    fn evidence_from_the_future_is_refused() {
        let mut tracker = SlashingTracker::new();
        let (evidence, pk) = offence(1);
        assert_eq!(
            tracker.submit_evidence(&evidence, &pk, NOW + 1, 100, 1_000, NOW),
            Err(EvidenceRejection::FromTheFuture)
        );
        assert_eq!(tracker, SlashingTracker::new());
    }

    #[test]
    fn evidence_is_admissible_up_to_exactly_the_max_age_and_not_a_moment_past() {
        let mut tracker = SlashingTracker::new();
        assert!(submit(&mut tracker, 1, MAX_EVIDENCE_AGE_MS, 100, 1_000).is_ok());

        let mut tracker = SlashingTracker::new();
        assert_eq!(
            submit(&mut tracker, 1, MAX_EVIDENCE_AGE_MS + 1, 100, 1_000),
            Err(EvidenceRejection::TooOld)
        );
        assert_eq!(tracker, SlashingTracker::new());
    }

    #[test]
    fn inconsistent_stake_figures_are_refused_without_effect() {
        let mut tracker = SlashingTracker::new();
        assert_eq!(
            submit(&mut tracker, 1, 0, 100, 0),
            Err(EvidenceRejection::NoBondedStake)
        );
        assert_eq!(
            submit(&mut tracker, 1, 0, 0, 1_000),
            Err(EvidenceRejection::NoStakeToSlash)
        );
        assert_eq!(
            submit(&mut tracker, 1, 0, 2_000, 1_000),
            Err(EvidenceRejection::StakeExceedsBonded)
        );
        assert_eq!(tracker, SlashingTracker::new());
    }

    #[test]
    fn a_validator_is_convicted_only_once() {
        let mut tracker = SlashingTracker::new();
        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();
        let after_first = tracker.clone();

        assert_eq!(
            submit(&mut tracker, 1, 0, 100, 10_000),
            Err(EvidenceRejection::AlreadySlashed)
        );
        assert_eq!(tracker, after_first);
    }

    // ---- correlation ---------------------------------------------------

    #[test]
    fn correlated_offenders_top_each_other_up_as_evidence_arrives() {
        // Three validators each holding 5% of 100_000 bonded stake, all
        // offending together.
        let mut tracker = SlashingTracker::new();

        // Alone, 5% of the stake equivocating: 3 x 5% = 15% of 5_000.
        let first = submit(&mut tracker, 1, 0, 5_000, 100_000).unwrap();
        assert_eq!(
            first,
            vec![SlashOrder {
                validator: addr_of(1),
                burn: 750
            }]
        );

        // Now 10% correlated -> 30% each = 1_500.
        let second = submit(&mut tracker, 2, 0, 5_000, 100_000).unwrap();
        assert_eq!(burned(&second, 2), 1_500);
        assert_eq!(burned(&second, 1), 750, "topped up from 750 to 1_500");

        // 15% correlated -> 45% each = 2_250.
        let third = submit(&mut tracker, 3, 0, 5_000, 100_000).unwrap();
        assert_eq!(burned(&third, 3), 2_250);
        assert_eq!(burned(&third, 1), 750);
        assert_eq!(burned(&third, 2), 750);

        for seed in [1, 2, 3] {
            assert_eq!(tracker.total_slashed(&addr_of(seed)), Some(2_250));
        }
    }

    #[test]
    fn a_large_validator_offending_alone_already_pays_more_than_the_floor() {
        // 10% of the bonded stake, entirely on their own: 3 x 10% = 30%.
        let mut tracker = SlashingTracker::new();
        let orders = submit(&mut tracker, 1, 0, 100, 1_000).unwrap();
        assert_eq!(
            orders,
            vec![SlashOrder {
                validator: addr_of(1),
                burn: 30
            }]
        );
    }

    #[test]
    fn a_coordinated_attack_cannot_hide_behind_arriving_one_at_a_time() {
        // A third of the stake equivocating, evidence trickling in one
        // validator at a time: everyone must still end up paying 100%.
        let mut tracker = SlashingTracker::new();
        for seed in 1..=4u8 {
            submit(&mut tracker, seed, 0, 250, 3_000).unwrap();
        }
        // 4 * 250 = 1000 of 3000 = exactly a third.
        for seed in 1..=4u8 {
            assert_eq!(
                tracker.total_slashed(&addr_of(seed)),
                Some(250),
                "validator {seed} pays in full"
            );
        }
    }

    #[test]
    fn offences_exactly_one_window_apart_still_correlate() {
        let mut tracker = SlashingTracker::new();
        // Infraction at NOW: 5% of the stake, alone, is 15% of 500 = 75.
        submit(&mut tracker, 1, 0, 500, 10_000).unwrap();

        // The window equals the max evidence age, so exactly one window
        // earlier is the oldest infraction still admissible.
        let orders = submit(&mut tracker, 2, CORRELATION_WINDOW_MS, 500, 10_000).unwrap();
        assert_eq!(burned(&orders, 2), 150, "10% correlated -> 30% of 500");
        assert_eq!(burned(&orders, 1), 75, "topped up from 75 to 150");
    }

    #[test]
    fn an_offence_more_than_a_window_from_another_is_priced_alone() {
        // Two infractions can only be more than a window apart if the
        // earlier one was reported while it was still admissible. Submit
        // the old one, then a fresh one a window and a millisecond later.
        let mut tracker = SlashingTracker::new();
        let (evidence, pk) = offence(1);
        let old = 10 * DAY_MS;
        tracker
            .submit_evidence(&evidence, &pk, old, 100, 10_000, old + DAY_MS)
            .unwrap();

        let later = old + CORRELATION_WINDOW_MS + 1;
        let (evidence, pk) = offence(2);
        let orders = tracker
            .submit_evidence(&evidence, &pk, later, 100, 10_000, later)
            .unwrap();
        // 1% of the stake, alone: 3% scaled, so the 5% floor: 5 of 100.
        assert_eq!(
            orders,
            vec![SlashOrder {
                validator: addr_of(2),
                burn: 5
            }]
        );
        assert_eq!(
            tracker.total_slashed(&addr_of(1)),
            Some(5),
            "the earlier one is not touched"
        );
    }

    #[test]
    fn old_records_are_forgotten_but_their_tombstones_are_not() {
        let mut tracker = SlashingTracker::new();
        let (evidence, pk) = offence(1);
        tracker
            .submit_evidence(&evidence, &pk, 0, 100, 1_000, DAY_MS)
            .unwrap();
        assert!(tracker.total_slashed(&addr_of(1)).is_some());

        // A much later conviction prunes the old record...
        let much_later = 3 * CORRELATION_WINDOW_MS;
        let (evidence, pk) = offence(2);
        tracker
            .submit_evidence(&evidence, &pk, much_later, 100, 1_000, much_later)
            .unwrap();
        assert_eq!(tracker.total_slashed(&addr_of(1)), None);
        // ...but the first validator is still tombstoned.
        assert_eq!(tracker.status(&addr_of(1)), ValidatorStatus::Tombstoned);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn what_each_offender_pays_does_not_depend_on_the_order_evidence_arrives_in(
            offenders in proptest::collection::vec((1u128..=400, 0u64..=(10 * DAY_MS)), 1..=5),
            rotation in 0usize..5,
        ) {
            let total = 2_000u128;
            let run = |order: &[usize]| {
                let mut tracker = SlashingTracker::new();
                for &i in order {
                    let (stake, offset) = offenders[i];
                    let seed = u8::try_from(i + 1).unwrap();
                    let (evidence, pk) = offence(seed);
                    tracker
                        .submit_evidence(&evidence, &pk, NOW - offset, stake, total, NOW)
                        .unwrap();
                }
                (0..offenders.len())
                    .map(|i| tracker.total_slashed(&addr_of(u8::try_from(i + 1).unwrap())).unwrap())
                    .collect::<Vec<_>>()
            };

            let n = offenders.len();
            let forward: Vec<usize> = (0..n).collect();
            let reversed: Vec<usize> = (0..n).rev().collect();
            let mut rotated = forward.clone();
            rotated.rotate_left(rotation % n);

            let expected = run(&forward);
            prop_assert_eq!(&run(&reversed), &expected);
            prop_assert_eq!(&run(&rotated), &expected);

            // And no offender ever loses more than they had.
            for (i, paid) in expected.iter().enumerate() {
                prop_assert!(*paid <= offenders[i].0);
            }
        }
    }

    // ---- the pool ------------------------------------------------------

    #[test]
    fn slashing_orders_apply_to_a_staking_pool() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr_of(200), 9_000).unwrap();
        let stake = pool.total_stake();
        assert_eq!(stake, 10_000);

        let mut tracker = SlashingTracker::new();
        let orders = submit(&mut tracker, 1, 0, stake, 1_000_000).unwrap();
        assert_eq!(orders.len(), 1);
        let order = orders[0];
        assert_eq!(order.burn, 500, "5% of 10_000");

        assert_eq!(pool.slash(order.burn), 500);
        pool.assert_invariant().unwrap();
        // The delegator bears the loss pro rata: 9_000 of 10_000 shares,
        // against 9_500 of stake.
        assert_eq!(pool.withdraw(addr_of(200), 9_000).unwrap(), 8_550);
    }

    #[test]
    fn a_topped_up_slash_burns_only_the_difference() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr_of(200), 9_000).unwrap();
        let mut tracker = SlashingTracker::new();

        let first = submit(&mut tracker, 1, 0, 10_000, 100_000).unwrap();
        let mut total_burned = pool.slash(burned(&first, 1));

        // A second offender doubles the correlated stake, lifting the
        // first's rate; the pool is slashed by just the extra.
        let second = submit(&mut tracker, 2, 0, 10_000, 100_000).unwrap();
        total_burned += pool.slash(burned(&second, 1));

        assert_eq!(total_burned, tracker.total_slashed(&addr_of(1)).unwrap());
        assert_eq!(
            total_burned,
            penalty(10_000, slash_bps(20_000, 100_000).unwrap())
        );
    }

    // ---- jailing -------------------------------------------------------

    #[test]
    fn downtime_jails_without_burning_and_can_be_undone_after_the_term() {
        let mut tracker = SlashingTracker::new();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap();
        assert_eq!(
            tracker.status(&addr_of(1)),
            ValidatorStatus::Jailed {
                until_ms: NOW + DOWNTIME_JAIL_MS
            }
        );
        assert_eq!(
            tracker.total_slashed(&addr_of(1)),
            None,
            "downtime burns nothing"
        );

        assert_eq!(
            tracker.unjail(&addr_of(1), NOW + DOWNTIME_JAIL_MS - 1),
            Err(UnjailError::StillJailed {
                until_ms: NOW + DOWNTIME_JAIL_MS
            })
        );
        assert_eq!(tracker.unjail(&addr_of(1), NOW + DOWNTIME_JAIL_MS), Ok(()));
        assert_eq!(tracker.status(&addr_of(1)), ValidatorStatus::Active);
    }

    #[test]
    fn unjailing_someone_who_is_not_jailed_is_an_error() {
        let mut tracker = SlashingTracker::new();
        assert_eq!(
            tracker.unjail(&addr_of(1), NOW),
            Err(UnjailError::NotJailed)
        );
    }

    #[test]
    fn a_second_downtime_never_shortens_the_jail() {
        let mut tracker = SlashingTracker::new();
        tracker.jail_for_downtime(addr_of(1), NOW + DAY_MS).unwrap();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap(); // an earlier "now"
        assert_eq!(
            tracker.status(&addr_of(1)),
            ValidatorStatus::Jailed {
                until_ms: NOW + 2 * DAY_MS
            }
        );
    }

    #[test]
    fn a_jailed_validator_can_still_be_convicted_and_then_never_returns() {
        let mut tracker = SlashingTracker::new();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap();

        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();
        assert_eq!(tracker.status(&addr_of(1)), ValidatorStatus::Tombstoned);
        assert_eq!(
            tracker.unjail(&addr_of(1), NOW + 365 * DAY_MS),
            Err(UnjailError::Tombstoned)
        );
        assert_eq!(
            tracker.jail_for_downtime(addr_of(1), NOW),
            Err(JailError::Tombstoned)
        );
    }
}
