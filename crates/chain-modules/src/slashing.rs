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
//! Its own state — who is jailed or tombstoned, and the recent convictions
//! that later ones correlate with — lives in a [`Store`], one entry per
//! validator, with the convictions also indexed by infraction time so the
//! correlation window is a range read rather than a scan of everything:
//!
//! | key | value |
//! |---|---|
//! | `SLASH_STATUS ‖ validator` | jailed-until or tombstoned; absent means active |
//! | `SLASH_RECORD ‖ validator` | infraction time, stake at the time, total ordered burned |
//! | `SLASH_BY_TIME ‖ infraction_ms (BE) ‖ validator` | the validator, ordered by infraction time |
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

use chain_types::codec::{decode_field, CodecError, Decode, Encode};
use chain_types::collections::BTreeMap;
use chain_types::{Address, BlsPublicKey, DuplicateVoteEvidence, EvidenceError};

use crate::params::{DAY_MS, MAX_EVIDENCE_AGE_MS};
use crate::store::{be64, load, prefix_end, save, tag, Corrupt, Store};

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
    /// A record this module stored no longer decodes.
    CorruptState,
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
    /// A record this module stored no longer decodes.
    CorruptState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnjailError {
    NotJailed,
    StillJailed {
        until_ms: u64,
    },
    Tombstoned,
    /// A record this module stored no longer decodes.
    CorruptState,
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

impl Encode for SlashRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        self.infraction_ms.encode(out);
        self.stake.encode(out);
        self.slashed.encode(out);
    }
}

impl Decode for SlashRecord {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (infraction_ms, offset) = u64::decode(input)?;
        let (stake, offset) = decode_field::<u128>(input, offset)?;
        let (slashed, offset) = decode_field::<u128>(input, offset)?;
        Ok((
            Self {
                infraction_ms,
                stake,
                slashed,
            },
            offset,
        ))
    }
}

/// [`ValidatorStatus::Active`] is never stored — absence means active —
/// but encodes anyway so the encoding is total.
impl Encode for ValidatorStatus {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Active => 0u8.encode(out),
            Self::Jailed { until_ms } => {
                1u8.encode(out);
                until_ms.encode(out);
            }
            Self::Tombstoned => 2u8.encode(out),
        }
    }
}

impl Decode for ValidatorStatus {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => Ok((Self::Active, offset)),
            1 => {
                let (until_ms, offset) = decode_field::<u64>(input, offset)?;
                Ok((Self::Jailed { until_ms }, offset))
            }
            2 => Ok((Self::Tombstoned, offset)),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

fn keyed(tag: u8, validator: &Address) -> Vec<u8> {
    let mut key = vec![tag];
    key.extend_from_slice(validator.as_bytes());
    key
}

fn status_key(validator: &Address) -> Vec<u8> {
    keyed(tag::SLASH_STATUS, validator)
}

fn record_key(validator: &Address) -> Vec<u8> {
    keyed(tag::SLASH_RECORD, validator)
}

/// `SLASH_BY_TIME ‖ infraction_ms ‖ validator`; big-endian time, so byte
/// order is time order.
fn by_time_key(infraction_ms: u64, validator: &Address) -> Vec<u8> {
    let mut key = vec![tag::SLASH_BY_TIME];
    key.extend_from_slice(&be64(infraction_ms));
    key.extend_from_slice(validator.as_bytes());
    key
}

/// The start of the time index at `infraction_ms`: every key for a
/// validator whose infraction was at exactly that time starts with this.
fn time_prefix(infraction_ms: u64) -> Vec<u8> {
    let mut key = vec![tag::SLASH_BY_TIME];
    key.extend_from_slice(&be64(infraction_ms));
    key
}

/// `validator`'s status as `store` records it, without needing a tracker
/// (and so without needing the store mutably). Absent means active.
pub fn status_in(
    store: &(impl Store + ?Sized),
    validator: &Address,
) -> Result<ValidatorStatus, Corrupt> {
    Ok(load(store, &status_key(validator))?.unwrap_or(ValidatorStatus::Active))
}

/// Evidence admission and jailing, over a [`Store`]. See the module docs
/// for what it keeps there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlashingTracker<S> {
    store: S,
}

impl<S: Store> SlashingTracker<S> {
    pub const fn new(store: S) -> Self {
        Self { store }
    }

    pub const fn store(&self) -> &S {
        &self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn status(&self, validator: &Address) -> Result<ValidatorStatus, Corrupt> {
        status_in(&self.store, validator)
    }

    fn record(&self, validator: &Address) -> Result<Option<SlashRecord>, Corrupt> {
        load(&self.store, &record_key(validator))
    }

    /// When `validator`'s equivocation happened, while their record is
    /// still within the correlation horizon. What a caller needs to work
    /// out which of the validator's stake was at risk at the time.
    pub fn infraction_time_ms(&self, validator: &Address) -> Result<Option<u64>, Corrupt> {
        Ok(self.record(validator)?.map(|record| record.infraction_ms))
    }

    /// Everything ordered burned against `validator`'s equivocation so
    /// far, while their record is still within the correlation horizon.
    pub fn total_slashed(&self, validator: &Address) -> Result<Option<u128>, Corrupt> {
        Ok(self.record(validator)?.map(|record| record.slashed))
    }

    /// Admits `evidence` and returns what to burn, or says why not.
    ///
    /// `public_key` is the validator's registered BLS key. The
    /// remaining arguments must come from chain state, never from the
    /// evidence or its submitter: `infraction_time_ms` is the timestamp of
    /// the block at `evidence.height()`, `validator_stake` the validator's
    /// stake at that height, and `total_bonded_stake` the total bonded
    /// stake now. Nothing is changed unless the evidence is admitted, and
    /// everything is read before anything is written.
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
        let corrupt = |_: Corrupt| EvidenceRejection::CorruptState;

        // Cheapest checks first; the signature check is last.
        if self.status(&validator).map_err(corrupt)? == ValidatorStatus::Tombstoned {
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

        // Admitted. Read what the new conviction correlates with, and
        // what has aged out, before changing anything.
        let horizon = CORRELATION_WINDOW_MS.saturating_mul(2);
        let keep_from = now_ms.saturating_sub(horizon);
        let stale = self
            .indexed_between(0, keep_from.checked_sub(1))
            .map_err(corrupt)?;

        // Everything within twice the window of the new infraction is
        // enough: an earlier record is only re-priced if within one
        // window of it, and what it correlates with is within one more.
        let lo = infraction_time_ms.saturating_sub(horizon);
        let hi = infraction_time_ms.saturating_add(horizon);
        let mut records: BTreeMap<Address, SlashRecord> = BTreeMap::new();
        for (other, _) in self.indexed_between(lo, Some(hi)).map_err(corrupt)? {
            if let Some(record) = self.record(&other).map_err(corrupt)? {
                if record.infraction_ms >= keep_from {
                    records.insert(other, record);
                }
            }
        }
        let before: BTreeMap<Address, u128> = records
            .iter()
            .map(|(validator, record)| (*validator, record.slashed))
            .collect();
        records.insert(
            validator,
            SlashRecord {
                infraction_ms: infraction_time_ms,
                stake: validator_stake,
                slashed: 0,
            },
        );

        let orders = reprice_around(&mut records, infraction_time_ms, total_bonded_stake)?;

        // Nothing can fail from here: write it all.
        for (old, infraction_ms) in &stale {
            self.store.delete(&by_time_key(*infraction_ms, old));
            self.store.delete(&record_key(old));
        }
        for (other, record) in &records {
            let is_new = *other == validator;
            if is_new || before.get(other) != Some(&record.slashed) {
                save(&mut self.store, record_key(other), record);
            }
            if is_new {
                save(
                    &mut self.store,
                    by_time_key(record.infraction_ms, other),
                    other,
                );
            }
        }
        save(
            &mut self.store,
            status_key(&validator),
            &ValidatorStatus::Tombstoned,
        );
        Ok(orders)
    }

    /// The validators with a record whose infraction time is in
    /// `from_ms..=to_ms` (`to_ms` of `None` is an empty range), in time
    /// order, each with its time.
    fn indexed_between(
        &self,
        from_ms: u64,
        to_ms: Option<u64>,
    ) -> Result<Vec<(Address, u64)>, Corrupt> {
        let Some(to_ms) = to_ms else {
            return Ok(Vec::new());
        };
        let start = time_prefix(from_ms);
        let Some(end) = prefix_end(&time_prefix(to_ms)) else {
            return Ok(Vec::new());
        };
        self.store
            .range(&start, Some(&end), usize::MAX)
            .into_iter()
            .map(|(key, value)| {
                let validator =
                    chain_types::codec::decode_exact::<Address>(&value).map_err(|_| Corrupt)?;
                let time = key
                    .get(1..)
                    .and_then(crate::store::read_be64)
                    .ok_or(Corrupt)?;
                Ok((validator, time))
            })
            .collect()
    }

    /// Jails `validator` for downtime — no burn, just removal from the
    /// active set for at least [`DOWNTIME_JAIL_MS`]. Never shortens an
    /// existing jail.
    pub fn jail_for_downtime(&mut self, validator: Address, now_ms: u64) -> Result<(), JailError> {
        let until_ms = now_ms.saturating_add(DOWNTIME_JAIL_MS);
        let status = self
            .status(&validator)
            .map_err(|_| JailError::CorruptState)?;
        let jailed_until = match status {
            ValidatorStatus::Tombstoned => return Err(JailError::Tombstoned),
            ValidatorStatus::Jailed { until_ms: existing } => existing.max(until_ms),
            ValidatorStatus::Active => until_ms,
        };
        save(
            &mut self.store,
            status_key(&validator),
            &ValidatorStatus::Jailed {
                until_ms: jailed_until,
            },
        );
        Ok(())
    }

    /// Returns a jailed validator to the active set, once their jail has
    /// run its course. A tombstoned validator can never return.
    pub fn unjail(&mut self, validator: &Address, now_ms: u64) -> Result<(), UnjailError> {
        match self
            .status(validator)
            .map_err(|_| UnjailError::CorruptState)?
        {
            ValidatorStatus::Tombstoned => Err(UnjailError::Tombstoned),
            ValidatorStatus::Active => Err(UnjailError::NotJailed),
            ValidatorStatus::Jailed { until_ms } if now_ms < until_ms => {
                Err(UnjailError::StillJailed { until_ms })
            }
            ValidatorStatus::Jailed { .. } => {
                self.store.delete(&status_key(validator));
                Ok(())
            }
        }
    }
}

/// Re-prices every record within the correlation window of `around_ms` —
/// the new record and everyone it now correlates with — and returns what
/// each is now owed beyond what was already ordered, updating each
/// record's `slashed` to match. Pure: `records` is the whole neighbourhood
/// (everything within twice the window of `around_ms`), so what a record
/// correlates with is all in it.
fn reprice_around(
    records: &mut BTreeMap<Address, SlashRecord>,
    around_ms: u64,
    total_bonded_stake: u128,
) -> Result<Vec<SlashOrder>, EvidenceRejection> {
    let affected: Vec<Address> = records
        .iter()
        .filter(|(_, record)| record.infraction_ms.abs_diff(around_ms) <= CORRELATION_WINDOW_MS)
        .map(|(validator, _)| *validator)
        .collect();

    let mut orders = Vec::new();
    for validator in affected {
        let Some(record) = records.get(&validator).copied() else {
            continue;
        };
        let correlated = records
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
            if let Some(entry) = records.get_mut(&validator) {
                entry.slashed = owed;
            }
            orders.push(SlashOrder { validator, burn });
        }
    }
    Ok(orders)
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
    use crate::store::MemStore;
    use blst::min_pk::SecretKey;
    use chain_types::bls::{BlsSignature, DST_VOTE};
    use chain_types::{BlockHeight, Hash, Round, Vote, VoteKind};
    use proptest::prelude::*;

    type Tracker = SlashingTracker<MemStore>;

    fn new_tracker() -> Tracker {
        SlashingTracker::new(MemStore::new())
    }

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
        tracker: &mut Tracker,
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
        let mut tracker = new_tracker();
        let orders = submit(&mut tracker, 1, DAY_MS, 100, 10_000).unwrap();

        assert_eq!(
            orders,
            vec![SlashOrder {
                validator: addr_of(1),
                burn: 5
            }]
        );
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
        assert_eq!(tracker.total_slashed(&addr_of(1)).unwrap(), Some(5));
    }

    #[test]
    fn evidence_checked_against_the_wrong_key_changes_nothing() {
        let mut tracker = new_tracker();
        let (evidence, _) = offence(1);
        let (_, someone_elses_key) = offence(2);

        let result = tracker.submit_evidence(&evidence, &someone_elses_key, NOW, 100, 1_000, NOW);
        assert_eq!(
            result,
            Err(EvidenceRejection::Invalid(EvidenceError::InvalidSignature))
        );
        assert_eq!(tracker, new_tracker(), "a rejection must leave no trace");
    }

    #[test]
    fn evidence_from_the_future_is_refused() {
        let mut tracker = new_tracker();
        let (evidence, pk) = offence(1);
        assert_eq!(
            tracker.submit_evidence(&evidence, &pk, NOW + 1, 100, 1_000, NOW),
            Err(EvidenceRejection::FromTheFuture)
        );
        assert_eq!(tracker, new_tracker());
    }

    #[test]
    fn evidence_is_admissible_up_to_exactly_the_max_age_and_not_a_moment_past() {
        let mut tracker = new_tracker();
        assert!(submit(&mut tracker, 1, MAX_EVIDENCE_AGE_MS, 100, 1_000).is_ok());

        let mut tracker = new_tracker();
        assert_eq!(
            submit(&mut tracker, 1, MAX_EVIDENCE_AGE_MS + 1, 100, 1_000),
            Err(EvidenceRejection::TooOld)
        );
        assert_eq!(tracker, new_tracker());
    }

    #[test]
    fn inconsistent_stake_figures_are_refused_without_effect() {
        let mut tracker = new_tracker();
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
        assert_eq!(tracker, new_tracker());
    }

    #[test]
    fn a_validator_is_convicted_only_once() {
        let mut tracker = new_tracker();
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
        let mut tracker = new_tracker();

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
            assert_eq!(tracker.total_slashed(&addr_of(seed)).unwrap(), Some(2_250));
        }
    }

    #[test]
    fn a_large_validator_offending_alone_already_pays_more_than_the_floor() {
        // 10% of the bonded stake, entirely on their own: 3 x 10% = 30%.
        let mut tracker = new_tracker();
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
        let mut tracker = new_tracker();
        for seed in 1..=4u8 {
            submit(&mut tracker, seed, 0, 250, 3_000).unwrap();
        }
        // 4 * 250 = 1000 of 3000 = exactly a third.
        for seed in 1..=4u8 {
            assert_eq!(
                tracker.total_slashed(&addr_of(seed)).unwrap(),
                Some(250),
                "validator {seed} pays in full"
            );
        }
    }

    #[test]
    fn offences_exactly_one_window_apart_still_correlate() {
        let mut tracker = new_tracker();
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
        let mut tracker = new_tracker();
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
            tracker.total_slashed(&addr_of(1)).unwrap(),
            Some(5),
            "the earlier one is not touched"
        );
    }

    #[test]
    fn old_records_are_forgotten_but_their_tombstones_are_not() {
        let mut tracker = new_tracker();
        let (evidence, pk) = offence(1);
        tracker
            .submit_evidence(&evidence, &pk, 0, 100, 1_000, DAY_MS)
            .unwrap();
        assert!(tracker.total_slashed(&addr_of(1)).unwrap().is_some());

        // A much later conviction prunes the old record...
        let much_later = 3 * CORRELATION_WINDOW_MS;
        let (evidence, pk) = offence(2);
        tracker
            .submit_evidence(&evidence, &pk, much_later, 100, 1_000, much_later)
            .unwrap();
        assert_eq!(tracker.total_slashed(&addr_of(1)).unwrap(), None);
        // ...but the first validator is still tombstoned.
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
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
                let mut tracker = new_tracker();
                for &i in order {
                    let (stake, offset) = offenders[i];
                    let seed = u8::try_from(i + 1).unwrap();
                    let (evidence, pk) = offence(seed);
                    tracker
                        .submit_evidence(&evidence, &pk, NOW - offset, stake, total, NOW)
                        .unwrap();
                }
                (0..offenders.len())
                    .map(|i| tracker.total_slashed(&addr_of(u8::try_from(i + 1).unwrap())).unwrap().unwrap())
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
        let delegator_shares = pool.deposit(9_000).unwrap();
        let stake = pool.total_stake();
        assert_eq!(stake, 10_000);

        let mut tracker = new_tracker();
        let orders = submit(&mut tracker, 1, 0, stake, 1_000_000).unwrap();
        assert_eq!(orders.len(), 1);
        let order = orders[0];
        assert_eq!(order.burn, 500, "5% of 10_000");

        assert_eq!(pool.slash(order.burn), 500);
        pool.assert_invariant(delegator_shares).unwrap();
        // The delegator bears the loss pro rata: 9_000 of 10_000 shares,
        // against 9_500 of stake.
        assert_eq!(pool.withdraw(delegator_shares).unwrap(), 8_550);
    }

    #[test]
    fn a_topped_up_slash_burns_only_the_difference() {
        let mut pool = StakingPool::genesis();
        pool.deposit(9_000).unwrap();
        let mut tracker = new_tracker();

        let first = submit(&mut tracker, 1, 0, 10_000, 100_000).unwrap();
        let mut total_burned = pool.slash(burned(&first, 1));

        // A second offender doubles the correlated stake, lifting the
        // first's rate; the pool is slashed by just the extra.
        let second = submit(&mut tracker, 2, 0, 10_000, 100_000).unwrap();
        total_burned += pool.slash(burned(&second, 1));

        assert_eq!(
            total_burned,
            tracker.total_slashed(&addr_of(1)).unwrap().unwrap()
        );
        assert_eq!(
            total_burned,
            penalty(10_000, slash_bps(20_000, 100_000).unwrap())
        );
    }

    // ---- jailing -------------------------------------------------------

    #[test]
    fn downtime_jails_without_burning_and_can_be_undone_after_the_term() {
        let mut tracker = new_tracker();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap();
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Jailed {
                until_ms: NOW + DOWNTIME_JAIL_MS
            }
        );
        assert_eq!(
            tracker.total_slashed(&addr_of(1)).unwrap(),
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
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Active
        );
    }

    #[test]
    fn unjailing_someone_who_is_not_jailed_is_an_error() {
        let mut tracker = new_tracker();
        assert_eq!(
            tracker.unjail(&addr_of(1), NOW),
            Err(UnjailError::NotJailed)
        );
    }

    #[test]
    fn a_second_downtime_never_shortens_the_jail() {
        let mut tracker = new_tracker();
        tracker.jail_for_downtime(addr_of(1), NOW + DAY_MS).unwrap();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap(); // an earlier "now"
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Jailed {
                until_ms: NOW + 2 * DAY_MS
            }
        );
    }

    #[test]
    fn a_jailed_validator_can_still_be_convicted_and_then_never_returns() {
        let mut tracker = new_tracker();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap();

        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
        assert_eq!(
            tracker.unjail(&addr_of(1), NOW + 365 * DAY_MS),
            Err(UnjailError::Tombstoned)
        );
        assert_eq!(
            tracker.jail_for_downtime(addr_of(1), NOW),
            Err(JailError::Tombstoned)
        );
    }

    // ---- storage -------------------------------------------------------

    fn count(store: &MemStore, tag: u8) -> usize {
        store.scan_prefix(&[tag], usize::MAX).len()
    }

    #[test]
    fn a_conviction_writes_a_status_a_record_and_a_time_index_entry() {
        let mut tracker = new_tracker();
        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();
        let store = tracker.store();
        assert_eq!(count(store, tag::SLASH_STATUS), 1);
        assert_eq!(count(store, tag::SLASH_RECORD), 1);
        assert_eq!(count(store, tag::SLASH_BY_TIME), 1);
        assert_eq!(store.len(), 3, "and nothing else");
    }

    #[test]
    fn jailing_writes_one_entry_and_unjailing_removes_it() {
        let mut tracker = new_tracker();
        tracker.jail_for_downtime(addr_of(1), NOW).unwrap();
        assert_eq!(tracker.store().len(), 1);
        tracker.unjail(&addr_of(1), NOW + DOWNTIME_JAIL_MS).unwrap();
        assert!(
            tracker.store().is_empty(),
            "an active validator has no entry"
        );
    }

    #[test]
    fn an_aged_out_record_and_its_index_entry_leave_the_store_but_the_tombstone_stays() {
        let mut tracker = new_tracker();
        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();

        // Long after the horizon, another conviction sweeps the old record.
        let much_later = NOW + 3 * CORRELATION_WINDOW_MS;
        let (evidence, pk) = offence(2);
        tracker
            .submit_evidence(&evidence, &pk, much_later, 100, 10_000, much_later)
            .unwrap();

        let store = tracker.store();
        assert_eq!(count(store, tag::SLASH_RECORD), 1, "only the new one");
        assert_eq!(count(store, tag::SLASH_BY_TIME), 1);
        assert_eq!(count(store, tag::SLASH_STATUS), 2, "both stay convicted");
        assert_eq!(tracker.total_slashed(&addr_of(1)).unwrap(), None);
        assert_eq!(
            tracker.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
    }

    #[test]
    fn a_new_tracker_over_a_copy_of_the_store_remembers_everything() {
        let mut tracker = new_tracker();
        submit(&mut tracker, 1, 0, 5_000, 100_000).unwrap();
        tracker.jail_for_downtime(addr_of(9), NOW).unwrap();

        let mut restarted = SlashingTracker::new(tracker.store().clone());
        assert_eq!(restarted, tracker);
        assert_eq!(
            restarted.status(&addr_of(1)).unwrap(),
            ValidatorStatus::Tombstoned
        );
        // A correlated offender arriving after the restart still tops up
        // the one convicted before it.
        let orders = submit(&mut restarted, 2, 0, 5_000, 100_000).unwrap();
        assert!(orders.iter().any(|o| o.validator == addr_of(1)));
    }

    #[test]
    fn a_status_that_does_not_decode_is_corruption_never_active() {
        let mut store = MemStore::new();
        store.put(status_key(&addr_of(1)), vec![9, 9, 9]);
        let mut tracker = SlashingTracker::new(store);

        assert!(tracker.status(&addr_of(1)).is_err());
        assert_eq!(
            tracker.jail_for_downtime(addr_of(1), NOW),
            Err(JailError::CorruptState)
        );
        assert_eq!(
            tracker.unjail(&addr_of(1), NOW),
            Err(UnjailError::CorruptState)
        );
        assert_eq!(
            submit(&mut tracker, 1, 0, 100, 1_000),
            Err(EvidenceRejection::CorruptState)
        );
    }

    #[test]
    fn a_corrupt_record_in_the_window_refuses_the_evidence_and_changes_nothing() {
        let mut tracker = new_tracker();
        submit(&mut tracker, 1, 0, 100, 10_000).unwrap();
        let mut store = tracker.into_store();
        store.put(record_key(&addr_of(1)), vec![1]);
        let before = store.clone();
        let mut tracker = SlashingTracker::new(store);

        assert_eq!(
            submit(&mut tracker, 2, 0, 100, 10_000),
            Err(EvidenceRejection::CorruptState)
        );
        assert_eq!(tracker.store(), &before);
    }

    #[test]
    fn statuses_round_trip_and_an_unknown_kind_is_invalid() {
        use chain_types::codec::decode_exact;
        for status in [
            ValidatorStatus::Active,
            ValidatorStatus::Jailed { until_ms: 123_456 },
            ValidatorStatus::Tombstoned,
        ] {
            let mut bytes = Vec::new();
            status.encode(&mut bytes);
            assert_eq!(decode_exact::<ValidatorStatus>(&bytes).unwrap(), status);
        }
        assert!(decode_exact::<ValidatorStatus>(&[7]).is_err());
        assert!(
            decode_exact::<ValidatorStatus>(&[1, 0, 0]).is_err(),
            "truncated"
        );
        assert!(
            decode_exact::<ValidatorStatus>(&[2, 0]).is_err(),
            "trailing"
        );
    }

    #[test]
    fn records_round_trip() {
        use chain_types::codec::decode_exact;
        let record = SlashRecord {
            infraction_ms: 42,
            stake: 1_000_000,
            slashed: 50_000,
        };
        let mut bytes = Vec::new();
        record.encode(&mut bytes);
        assert_eq!(decode_exact::<SlashRecord>(&bytes).unwrap(), record);
    }

    #[test]
    fn the_time_index_orders_by_infraction_time() {
        // Big-endian time in the key is what makes a range read a window.
        let mut tracker = new_tracker();
        for (seed, age) in [(1u8, 3 * DAY_MS), (2, DAY_MS), (3, 2 * DAY_MS)] {
            submit(&mut tracker, seed, age, 10, 100_000).unwrap();
        }
        let times: Vec<u64> = tracker
            .indexed_between(0, Some(u64::MAX))
            .unwrap()
            .into_iter()
            .map(|(_, time)| time)
            .collect();
        assert_eq!(
            times,
            vec![NOW - 3 * DAY_MS, NOW - 2 * DAY_MS, NOW - DAY_MS]
        );
    }

    /// Convicts `seed` for an infraction at `infraction_ms`, reported at
    /// `now_ms`, with `stake` of `total` bonded.
    fn convict(
        tracker: &mut Tracker,
        seed: u8,
        infraction_ms: u64,
        now_ms: u64,
        stake: u128,
        total: u128,
    ) -> Vec<SlashOrder> {
        let (evidence, pk) = offence(seed);
        tracker
            .submit_evidence(&evidence, &pk, infraction_ms, stake, total, now_ms)
            .unwrap()
    }

    #[test]
    fn a_record_is_kept_for_exactly_twice_the_window_and_swept_a_moment_after() {
        let horizon = 2 * CORRELATION_WINDOW_MS;
        let (stake, total) = (5_000, 100_000);
        for (extra, kept) in [(0, true), (1, false)] {
            let mut tracker = new_tracker();
            let first = NOW - horizon - extra;
            convict(&mut tracker, 1, first, first, stake, total);
            // Another conviction, exactly `horizon + extra` later.
            convict(&mut tracker, 2, NOW, NOW, stake, total);

            assert_eq!(
                tracker.total_slashed(&addr_of(1)).unwrap().is_some(),
                kept,
                "{extra} ms past the horizon"
            );
            assert_eq!(
                tracker.status(&addr_of(1)).unwrap(),
                ValidatorStatus::Tombstoned,
                "the conviction itself is permanent"
            );
        }
    }

    #[test]
    fn correlation_chains_through_a_record_more_than_one_window_from_the_newest() {
        // A and B are a window apart, B and C are a window apart, A and C
        // are two windows apart. C's arrival re-prices B — and B's rate
        // counts A, which is beyond C's own window but not B's.
        let w = CORRELATION_WINDOW_MS;
        let t0 = NOW - 2 * w;
        let (stake, total) = (5_000u128, 100_000u128);
        let mut tracker = new_tracker();

        convict(&mut tracker, 1, t0, t0, stake, total); // A
        convict(&mut tracker, 2, t0 + w, t0 + w, stake, total); // B
        let owed_a = penalty(stake, slash_bps(2 * stake, total).unwrap());
        assert_eq!(tracker.total_slashed(&addr_of(1)).unwrap(), Some(owed_a));

        let orders = convict(&mut tracker, 3, t0 + 2 * w, t0 + 2 * w, stake, total); // C

        let owed_b = penalty(stake, slash_bps(3 * stake, total).unwrap());
        assert_eq!(
            tracker.total_slashed(&addr_of(2)).unwrap(),
            Some(owed_b),
            "B is priced against A, B and C together"
        );
        assert_eq!(
            tracker.total_slashed(&addr_of(1)).unwrap(),
            Some(owed_a),
            "A is more than a window from C, so C does not re-price it"
        );
        assert!(
            orders.iter().any(|o| o.validator == addr_of(2)),
            "B topped up"
        );
        assert!(orders.iter().all(|o| o.validator != addr_of(1)));
        // A, at exactly twice the window, is still on record.
        assert!(tracker.total_slashed(&addr_of(1)).unwrap().is_some());
    }

    #[test]
    fn a_record_that_has_aged_out_no_longer_counts_toward_anyones_rate() {
        // D and A are one millisecond apart, so they were correlated when
        // D was convicted. By the time C arrives A is a millisecond past
        // the horizon and is swept, so D is priced against D and C alone
        // — which is what it already owed — and nothing more is taken.
        let w = CORRELATION_WINDOW_MS;
        let (stake, total) = (5_000u128, 100_000u128);
        let a = NOW - 2 * w - 1;
        let d = NOW - 2 * w;
        let c = NOW - w;
        let mut tracker = new_tracker();

        convict(&mut tracker, 1, a, a, stake, total);
        convict(&mut tracker, 2, d, d, stake, total);
        let owed_d = penalty(stake, slash_bps(2 * stake, total).unwrap());
        assert_eq!(tracker.total_slashed(&addr_of(2)).unwrap(), Some(owed_d));

        let orders = convict(&mut tracker, 3, c, NOW, stake, total);

        assert_eq!(
            tracker.total_slashed(&addr_of(1)).unwrap(),
            None,
            "A was swept"
        );
        assert_eq!(
            orders.iter().map(|o| o.validator).collect::<Vec<_>>(),
            vec![addr_of(3)],
            "D was not topped up on account of a record that no longer counts"
        );
    }
}
