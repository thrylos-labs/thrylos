//! The governance-adjustable parameters and their compiled-in clamps.
//! `docs/spec.md`, "Native modules: staking, fees and governance":
//! "Every parameter carries a compiled-in clamp, checked at application
//! time, and a proposal outside the clamp fails rather than passing and
//! bricking the chain."
//!
//! [`GovernedParams`] can only be built through [`GovernedParams::new`],
//! which checks every clamp, and a proposed [`ParamChange`] is applied
//! by merging it onto the current values and building a *new*
//! `GovernedParams` the same way — there is no path that skips a check.
//!
//! The spec lists the clamps it wants and gives numbers for some:
//!
//! | Parameter | Spec | Here |
//! |---|---|---|
//! | Block gas limit | 10M–120M, never zero | `chain_modules::fees` |
//! | Gas schedule entries | within 4x of genesis, per entry | **not built** — there is no gas schedule until real metering exists |
//! | Min self-stake | strictly positive | `>= 1` |
//! | Inflation | 0–10% annualised | 0..=1000 basis points |
//! | Unbonding period | never below max evidence age + 7 days | see [`MIN_UNBONDING_PERIOD_MS`] |
//! | Base fee denominator, quorum, veto threshold | "bounded ranges, all non-degenerate" | see the constants below |
//!
//! Where the spec says "bounded" without a number, the range below is a
//! choice, not a fact from the spec, and each is marked as one.

use chain_types::codec::{decode_field, CodecError, Decode, Encode};

use crate::fees::{FeeError, FeeParams};
use crate::store::{decode_option, encode_option};

pub const SECOND_MS: u64 = 1_000;
pub const DAY_MS: u64 = 24 * 60 * 60 * SECOND_MS;

/// `docs/spec.md`, "Consensus": "Max evidence age: 14 days". Not
/// governance-adjustable: it is the fixed point the unbonding clamp is
/// measured from.
pub const MAX_EVIDENCE_AGE_MS: u64 = 14 * DAY_MS;

/// `docs/spec.md`: unbonding period "never below max evidence age + 7
/// days".
pub const MIN_UNBONDING_MARGIN_MS: u64 = 7 * DAY_MS;

/// 21 days, which is also the spec's genesis unbonding period — the
/// genesis value sits exactly on the clamp's lower edge.
pub const MIN_UNBONDING_PERIOD_MS: u64 = MAX_EVIDENCE_AGE_MS + MIN_UNBONDING_MARGIN_MS;

/// **A choice.** The spec gives only a lower bound, but "every
/// parameter carries a compiled-in clamp" and an unbonding period of
/// `u64::MAX` would lock all stake forever, which is exactly "bricking
/// the chain".
pub const MAX_UNBONDING_PERIOD_MS: u64 = 365 * DAY_MS;

/// `docs/spec.md`: "Inflation: 0–10% annualised." In basis points.
pub const MAX_INFLATION_BPS: u16 = 1_000;

/// **A choice.** A quorum of zero would let a proposal pass on no
/// turnout at all; above two thirds it could be blocked by a minority
/// simply staying home.
pub const MIN_QUORUM_BPS: u16 = 1_000;
pub const MAX_QUORUM_BPS: u16 = 6_700;

/// **A choice.** Too low and any small faction can kill every
/// proposal; at or above half the veto would be a second, hidden
/// majority rule.
pub const MIN_VETO_THRESHOLD_BPS: u16 = 1_000;
pub const MAX_VETO_THRESHOLD_BPS: u16 = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamError {
    /// The block gas limit or base fee denominator, per
    /// [`FeeParams::new`].
    Fee(FeeError),
    MinSelfStakeZero,
    InflationOutOfRange,
    UnbondingPeriodOutOfRange,
    QuorumOutOfRange,
    VetoThresholdOutOfRange,
}

impl Encode for ParamError {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Fee(err) => {
                0u8.encode(out);
                err.encode(out);
            }
            Self::MinSelfStakeZero => 1u8.encode(out),
            Self::InflationOutOfRange => 2u8.encode(out),
            Self::UnbondingPeriodOutOfRange => 3u8.encode(out),
            Self::QuorumOutOfRange => 4u8.encode(out),
            Self::VetoThresholdOutOfRange => 5u8.encode(out),
        }
    }
}

impl Decode for ParamError {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => {
                let (err, offset) = decode_field::<FeeError>(input, offset)?;
                Ok((Self::Fee(err), offset))
            }
            1 => Ok((Self::MinSelfStakeZero, offset)),
            2 => Ok((Self::InflationOutOfRange, offset)),
            3 => Ok((Self::UnbondingPeriodOutOfRange, offset)),
            4 => Ok((Self::QuorumOutOfRange, offset)),
            5 => Ok((Self::VetoThresholdOutOfRange, offset)),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

impl core::fmt::Display for ParamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Fee(err) => write!(f, "fee parameter outside its clamp: {err}"),
            Self::MinSelfStakeZero => f.write_str("minimum self-stake must be positive"),
            Self::InflationOutOfRange => f.write_str("inflation outside its clamp"),
            Self::UnbondingPeriodOutOfRange => f.write_str("unbonding period outside its clamp"),
            Self::QuorumOutOfRange => f.write_str("quorum outside its clamp"),
            Self::VetoThresholdOutOfRange => f.write_str("veto threshold outside its clamp"),
        }
    }
}

impl std::error::Error for ParamError {}

impl From<FeeError> for ParamError {
    fn from(err: FeeError) -> Self {
        Self::Fee(err)
    }
}

/// Every governance-adjustable value, unchecked. Only ever a proposal
/// under construction or the raw material for [`GovernedParams::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamValues {
    pub max_block_gas: u64,
    pub base_fee_change_denominator: u64,
    pub min_self_stake: u128,
    pub inflation_bps: u16,
    pub unbonding_period_ms: u64,
    pub quorum_bps: u16,
    pub veto_threshold_bps: u16,
}

impl Encode for ParamValues {
    fn encode(&self, out: &mut Vec<u8>) {
        self.max_block_gas.encode(out);
        self.base_fee_change_denominator.encode(out);
        self.min_self_stake.encode(out);
        self.inflation_bps.encode(out);
        self.unbonding_period_ms.encode(out);
        self.quorum_bps.encode(out);
        self.veto_threshold_bps.encode(out);
    }
}

impl Decode for ParamValues {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (max_block_gas, offset) = u64::decode(input)?;
        let (base_fee_change_denominator, offset) = decode_field::<u64>(input, offset)?;
        let (min_self_stake, offset) = decode_field::<u128>(input, offset)?;
        let (inflation_bps, offset) = decode_field::<u16>(input, offset)?;
        let (unbonding_period_ms, offset) = decode_field::<u64>(input, offset)?;
        let (quorum_bps, offset) = decode_field::<u16>(input, offset)?;
        let (veto_threshold_bps, offset) = decode_field::<u16>(input, offset)?;
        Ok((
            Self {
                max_block_gas,
                base_fee_change_denominator,
                min_self_stake,
                inflation_bps,
                unbonding_period_ms,
                quorum_bps,
                veto_threshold_bps,
            },
            offset,
        ))
    }
}

/// A proposed change to some of the parameters; `None` leaves that
/// parameter as it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ParamChange {
    pub max_block_gas: Option<u64>,
    pub base_fee_change_denominator: Option<u64>,
    pub min_self_stake: Option<u128>,
    pub inflation_bps: Option<u16>,
    pub unbonding_period_ms: Option<u64>,
    pub quorum_bps: Option<u16>,
    pub veto_threshold_bps: Option<u16>,
}

impl Encode for ParamChange {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_option(&self.max_block_gas, out);
        encode_option(&self.base_fee_change_denominator, out);
        encode_option(&self.min_self_stake, out);
        encode_option(&self.inflation_bps, out);
        encode_option(&self.unbonding_period_ms, out);
        encode_option(&self.quorum_bps, out);
        encode_option(&self.veto_threshold_bps, out);
    }
}

impl Decode for ParamChange {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (max_block_gas, offset) = decode_option::<u64>(input, 0)?;
        let (base_fee_change_denominator, offset) = decode_option::<u64>(input, offset)?;
        let (min_self_stake, offset) = decode_option::<u128>(input, offset)?;
        let (inflation_bps, offset) = decode_option::<u16>(input, offset)?;
        let (unbonding_period_ms, offset) = decode_option::<u64>(input, offset)?;
        let (quorum_bps, offset) = decode_option::<u16>(input, offset)?;
        let (veto_threshold_bps, offset) = decode_option::<u16>(input, offset)?;
        Ok((
            Self {
                max_block_gas,
                base_fee_change_denominator,
                min_self_stake,
                inflation_bps,
                unbonding_period_ms,
                quorum_bps,
                veto_threshold_bps,
            },
            offset,
        ))
    }
}

impl ParamChange {
    pub const fn is_empty(&self) -> bool {
        self.max_block_gas.is_none()
            && self.base_fee_change_denominator.is_none()
            && self.min_self_stake.is_none()
            && self.inflation_bps.is_none()
            && self.unbonding_period_ms.is_none()
            && self.quorum_bps.is_none()
            && self.veto_threshold_bps.is_none()
    }

    fn merged_onto(&self, base: &ParamValues) -> ParamValues {
        ParamValues {
            max_block_gas: self.max_block_gas.unwrap_or(base.max_block_gas),
            base_fee_change_denominator: self
                .base_fee_change_denominator
                .unwrap_or(base.base_fee_change_denominator),
            min_self_stake: self.min_self_stake.unwrap_or(base.min_self_stake),
            inflation_bps: self.inflation_bps.unwrap_or(base.inflation_bps),
            unbonding_period_ms: self.unbonding_period_ms.unwrap_or(base.unbonding_period_ms),
            quorum_bps: self.quorum_bps.unwrap_or(base.quorum_bps),
            veto_threshold_bps: self.veto_threshold_bps.unwrap_or(base.veto_threshold_bps),
        }
    }
}

/// A full parameter set that has passed every clamp. The fields are
/// private, so one that hasn't cannot exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernedParams {
    values: ParamValues,
    fees: FeeParams,
}

/// A parameter set is stored as its raw values. Decoding re-checks every
/// clamp, so a stored set that somehow fell outside them cannot become a
/// [`GovernedParams`] — it is an invalid encoding.
impl Encode for GovernedParams {
    fn encode(&self, out: &mut Vec<u8>) {
        self.values.encode(out);
    }
}

impl Decode for GovernedParams {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (values, offset) = ParamValues::decode(input)?;
        let params = Self::new(values).map_err(|_| CodecError::InvalidValue)?;
        Ok((params, offset))
    }
}

impl GovernedParams {
    pub fn new(values: ParamValues) -> Result<Self, ParamError> {
        let fees = FeeParams::new(values.max_block_gas, values.base_fee_change_denominator)?;
        if values.min_self_stake == 0 {
            return Err(ParamError::MinSelfStakeZero);
        }
        if values.inflation_bps > MAX_INFLATION_BPS {
            return Err(ParamError::InflationOutOfRange);
        }
        if !(MIN_UNBONDING_PERIOD_MS..=MAX_UNBONDING_PERIOD_MS)
            .contains(&values.unbonding_period_ms)
        {
            return Err(ParamError::UnbondingPeriodOutOfRange);
        }
        if !(MIN_QUORUM_BPS..=MAX_QUORUM_BPS).contains(&values.quorum_bps) {
            return Err(ParamError::QuorumOutOfRange);
        }
        if !(MIN_VETO_THRESHOLD_BPS..=MAX_VETO_THRESHOLD_BPS).contains(&values.veto_threshold_bps) {
            return Err(ParamError::VetoThresholdOutOfRange);
        }
        Ok(Self { values, fees })
    }

    pub const fn values(&self) -> &ParamValues {
        &self.values
    }

    /// The fee parameters, already validated as part of building
    /// `self`.
    pub const fn fee_params(&self) -> FeeParams {
        self.fees
    }

    /// `self` with `change` applied — checked against every clamp, the
    /// same way a fresh set is. Fails, leaving `self` untouched, if the
    /// result would violate any of them.
    pub fn with_change(&self, change: &ParamChange) -> Result<Self, ParamError> {
        Self::new(change.merged_onto(&self.values))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use proptest::prelude::*;

    fn valid() -> ParamValues {
        ParamValues {
            max_block_gas: 60_000_000,
            base_fee_change_denominator: 8,
            min_self_stake: 1_000,
            inflation_bps: 400,
            unbonding_period_ms: MIN_UNBONDING_PERIOD_MS,
            quorum_bps: 3_340,
            veto_threshold_bps: 3_340,
        }
    }

    #[test]
    fn the_specs_genesis_values_are_accepted() {
        assert!(GovernedParams::new(valid()).is_ok());
    }

    #[test]
    fn the_minimum_unbonding_period_is_the_specs_21_days() {
        assert_eq!(MIN_UNBONDING_PERIOD_MS, 21 * DAY_MS);
    }

    #[test]
    fn fee_parameters_are_clamped_through_the_fee_module() {
        let mut values = valid();
        values.max_block_gas = 9_999_999;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::Fee(FeeError::BlockGasLimitOutOfRange))
        );
        let mut values = valid();
        values.base_fee_change_denominator = 1;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::Fee(FeeError::DenominatorOutOfRange))
        );
    }

    #[test]
    fn a_zero_minimum_self_stake_is_rejected() {
        let mut values = valid();
        values.min_self_stake = 0;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::MinSelfStakeZero)
        );
    }

    #[test]
    fn inflation_is_clamped_to_ten_percent() {
        let mut values = valid();
        values.inflation_bps = MAX_INFLATION_BPS;
        assert!(GovernedParams::new(values).is_ok());
        values.inflation_bps = MAX_INFLATION_BPS + 1;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::InflationOutOfRange)
        );
        values.inflation_bps = 0;
        assert!(
            GovernedParams::new(values).is_ok(),
            "zero inflation is allowed"
        );
    }

    #[test]
    fn unbonding_below_evidence_age_plus_seven_days_is_rejected() {
        let mut values = valid();
        values.unbonding_period_ms = MIN_UNBONDING_PERIOD_MS - 1;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::UnbondingPeriodOutOfRange)
        );
        values.unbonding_period_ms = 0;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::UnbondingPeriodOutOfRange)
        );
    }

    #[test]
    fn unbonding_has_an_upper_clamp_too() {
        let mut values = valid();
        values.unbonding_period_ms = MAX_UNBONDING_PERIOD_MS;
        assert!(GovernedParams::new(values).is_ok());
        values.unbonding_period_ms = MAX_UNBONDING_PERIOD_MS + 1;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::UnbondingPeriodOutOfRange)
        );
        values.unbonding_period_ms = u64::MAX;
        assert_eq!(
            GovernedParams::new(values),
            Err(ParamError::UnbondingPeriodOutOfRange)
        );
    }

    #[test]
    fn quorum_and_veto_are_clamped_at_both_ends() {
        for (bps, ok) in [
            (MIN_QUORUM_BPS - 1, false),
            (MIN_QUORUM_BPS, true),
            (MAX_QUORUM_BPS, true),
            (MAX_QUORUM_BPS + 1, false),
            (0, false),
        ] {
            let mut values = valid();
            values.quorum_bps = bps;
            assert_eq!(GovernedParams::new(values).is_ok(), ok, "quorum {bps}");
        }
        for (bps, ok) in [
            (MIN_VETO_THRESHOLD_BPS - 1, false),
            (MIN_VETO_THRESHOLD_BPS, true),
            (MAX_VETO_THRESHOLD_BPS, true),
            (MAX_VETO_THRESHOLD_BPS + 1, false),
            (10_000, false),
        ] {
            let mut values = valid();
            values.veto_threshold_bps = bps;
            assert_eq!(GovernedParams::new(values).is_ok(), ok, "veto {bps}");
        }
    }

    #[test]
    fn a_change_touches_only_what_it_names() {
        let params = GovernedParams::new(valid()).unwrap();
        let changed = params
            .with_change(&ParamChange {
                inflation_bps: Some(500),
                ..ParamChange::default()
            })
            .unwrap();
        assert_eq!(changed.values().inflation_bps, 500);
        assert_eq!(changed.values().quorum_bps, valid().quorum_bps);
        assert_eq!(changed.values().max_block_gas, valid().max_block_gas);
    }

    #[test]
    fn a_change_outside_a_clamp_fails_and_leaves_the_original_alone() {
        let params = GovernedParams::new(valid()).unwrap();
        let result = params.with_change(&ParamChange {
            inflation_bps: Some(5_000),
            ..ParamChange::default()
        });
        assert_eq!(result, Err(ParamError::InflationOutOfRange));
        assert_eq!(params.values().inflation_bps, 400);
    }

    #[test]
    fn a_change_re_checks_parameters_it_did_not_touch_only_via_the_merged_set() {
        // Changing the gas limit alone still re-validates the whole set,
        // so a change can never smuggle in a state that no fresh
        // `GovernedParams::new` would accept.
        let params = GovernedParams::new(valid()).unwrap();
        let changed = params
            .with_change(&ParamChange {
                max_block_gas: Some(120_000_000),
                ..ParamChange::default()
            })
            .unwrap();
        assert_eq!(GovernedParams::new(*changed.values()), Ok(changed));
    }

    #[test]
    fn an_empty_change_is_recognised() {
        assert!(ParamChange::default().is_empty());
        assert!(!ParamChange {
            quorum_bps: Some(4_000),
            ..ParamChange::default()
        }
        .is_empty());
    }

    #[test]
    fn every_accepted_set_also_satisfies_the_signers_slashing_window_ordering() {
        // `chain-signer` asserts `unbonding > max evidence age > fork-choice
        // horizon` "at genesis, on every parameter change". The clamp here
        // is stricter (a 7-day margin), so anything it accepts must pass
        // that check too. There is no fork choice under single-slot
        // finality, so the horizon is 0.
        for unbonding in [
            MIN_UNBONDING_PERIOD_MS,
            30 * DAY_MS,
            MAX_UNBONDING_PERIOD_MS,
        ] {
            let mut values = valid();
            values.unbonding_period_ms = unbonding;
            assert!(GovernedParams::new(values).is_ok());
            assert!(chain_signer::assert_slashing_window_ordering(
                unbonding,
                MAX_EVIDENCE_AGE_MS,
                0
            )
            .is_ok());
        }
    }

    proptest! {
        #[test]
        fn a_set_is_accepted_exactly_when_every_value_is_inside_its_clamp(
            max_block_gas in 0u64..=200_000_000,
            denominator in 0u64..=100,
            min_self_stake in 0u128..=10,
            inflation_bps in 0u16..=2_000,
            unbonding in 0u64..=(400 * DAY_MS),
            quorum_bps in 0u16..=10_000,
            veto_bps in 0u16..=10_000,
        ) {
            let values = ParamValues {
                max_block_gas,
                base_fee_change_denominator: denominator,
                min_self_stake,
                inflation_bps,
                unbonding_period_ms: unbonding,
                quorum_bps,
                veto_threshold_bps: veto_bps,
            };
            let expected = (10_000_000..=120_000_000).contains(&max_block_gas)
                && (2..=64).contains(&denominator)
                && min_self_stake >= 1
                && inflation_bps <= 1_000
                && (MIN_UNBONDING_PERIOD_MS..=MAX_UNBONDING_PERIOD_MS).contains(&unbonding)
                && (MIN_QUORUM_BPS..=MAX_QUORUM_BPS).contains(&quorum_bps)
                && (MIN_VETO_THRESHOLD_BPS..=MAX_VETO_THRESHOLD_BPS).contains(&veto_bps);
            prop_assert_eq!(GovernedParams::new(values).is_ok(), expected);
        }
    }

    // ---- encoding ------------------------------------------------------

    use chain_types::codec::decode_exact;

    fn encoded<T: Encode>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        value.encode(&mut bytes);
        bytes
    }

    #[test]
    fn parameter_values_round_trip_and_are_strict() {
        let bytes = encoded(&valid());
        assert_eq!(decode_exact::<ParamValues>(&bytes).unwrap(), valid());
        assert_eq!(bytes.len(), 8 + 8 + 16 + 2 + 8 + 2 + 2, "fixed width");
        assert!(decode_exact::<ParamValues>(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes;
        longer.push(0);
        assert!(decode_exact::<ParamValues>(&longer).is_err());
    }

    #[test]
    fn a_governed_set_is_re_validated_on_decode() {
        let params = GovernedParams::new(valid()).unwrap();
        let bytes = encoded(&params);
        assert_eq!(decode_exact::<GovernedParams>(&bytes).unwrap(), params);

        // The same bytes with a value outside its clamp are not a
        // `GovernedParams`, however they got that way.
        let mut values = valid();
        values.quorum_bps = MAX_QUORUM_BPS + 1;
        let bad = encoded(&values);
        assert!(
            decode_exact::<ParamValues>(&bad).is_ok(),
            "raw values decode"
        );
        assert!(
            decode_exact::<GovernedParams>(&bad).is_err(),
            "but a validated set does not"
        );
    }

    #[test]
    fn a_parameter_change_round_trips_with_any_mix_of_fields() {
        for change in [
            ParamChange::default(),
            ParamChange {
                inflation_bps: Some(5),
                ..ParamChange::default()
            },
            ParamChange {
                max_block_gas: Some(u64::MAX),
                base_fee_change_denominator: Some(2),
                min_self_stake: Some(u128::MAX),
                inflation_bps: Some(u16::MAX),
                unbonding_period_ms: Some(0),
                quorum_bps: Some(1),
                veto_threshold_bps: Some(3),
            },
        ] {
            let bytes = encoded(&change);
            assert_eq!(decode_exact::<ParamChange>(&bytes).unwrap(), change);
            for cut in 0..bytes.len() {
                assert!(decode_exact::<ParamChange>(&bytes[..cut]).is_err());
            }
        }
        // A presence byte that is neither 0 nor 1.
        assert!(decode_exact::<ParamChange>(&[2; 7]).is_err());
    }

    #[test]
    fn parameter_errors_round_trip() {
        for err in [
            ParamError::MinSelfStakeZero,
            ParamError::InflationOutOfRange,
            ParamError::UnbondingPeriodOutOfRange,
            ParamError::QuorumOutOfRange,
            ParamError::VetoThresholdOutOfRange,
            ParamError::Fee(FeeError::BlockGasLimitOutOfRange),
            ParamError::Fee(FeeError::DenominatorOutOfRange),
        ] {
            assert_eq!(decode_exact::<ParamError>(&encoded(&err)).unwrap(), err);
        }
        assert!(decode_exact::<ParamError>(&[6]).is_err());
        assert!(
            decode_exact::<ParamError>(&[0, 2]).is_err(),
            "unknown fee error"
        );
    }
}
