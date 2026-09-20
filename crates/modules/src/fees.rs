//! The base-fee market. `docs/spec.md`, "Native modules: staking, fees
//! and governance": "EIP-1559 on one dimension: compute. A fixed gas
//! price plus permissionless submission is a spam economy — an attacker
//! fills every block at constant cost and the only remedy is a fork. A
//! base fee that rises under load prices that attack out without a
//! governance vote. State growth and bandwidth stay unpriced at launch."
//!
//! This module is the pure arithmetic only: given the last block's base
//! fee and how full it was, what is the next block's base fee. Storing
//! the base fee in chain state, charging it, and rejecting transactions
//! that can't pay it belong to whoever executes blocks (`chain-exec`);
//! nothing here reads or writes state.
//!
//! The update rule is EIP-1559's, with integer arithmetic throughout:
//! the target is half the block gas limit, a block above target raises
//! the base fee by up to `1 / denominator` (at least 1 unit, so it can
//! always rise), and a block below target lowers it by up to the same
//! fraction, never below [`MIN_BASE_FEE`].
//!
//! Two rounding consequences are inherited from the reference rule
//! rather than papered over. A decrease is floored, so once the fee is
//! below the denominator the proportional step is zero and the fee
//! stops falling: with the default denominator of 8 an idle chain
//! settles at 7, not at [`MIN_BASE_FEE`] (this is why Ethereum's base
//! fee bottoms out at 7 wei). [`MIN_BASE_FEE`] is therefore a hard
//! guard on the output, not a value decay normally reaches. And the
//! target is `max_block_gas / 2` floored, so for an odd limit a
//! completely full block sits one unit further above target than a
//! below-target block can sit below it.
//!
//! Two things are deliberately not here. There is no priority tip:
//! `chain_types::TransactionBody` carries only `max_fee_per_gas`, and
//! adding a second price field would change the signed transaction
//! format for every crate, so a transaction simply pays the base fee.
//! And there is no governance: [`FeeParams::new`] enforces the
//! compiled-in clamps `docs/spec.md` requires ("Every parameter carries
//! a compiled-in clamp, checked at application time"), but nothing yet
//! proposes or timelocks a change to them.
//!
//! Every numeric bound below is a choice, not something the spec pins
//! down: it says the block gas limit is clamped to 10M–120M (used
//! as-is) and that the base fee denominator is "bounded ... non-
//! degenerate" without giving a range.

use chain_types::codec::{CodecError, Decode, Encode};

/// The floor the base fee can never fall below. Zero would make blocks
/// free to fill, which is exactly the spam economy this module exists to
/// prevent — and a base fee of zero could never rise proportionally
/// either.
pub const MIN_BASE_FEE: u64 = 1;

/// The base fee the chain starts with.
pub const GENESIS_BASE_FEE: u64 = 1;

/// A block is "on target" at `max_block_gas / ELASTICITY_MULTIPLIER`.
/// EIP-1559's value; not governance-adjustable (the spec's list of
/// adjustable fee parameters is the block gas limit and the base fee
/// denominator).
pub const ELASTICITY_MULTIPLIER: u64 = 2;

/// `docs/spec.md`, "Governance, minimal": "Block gas limit: 10M–120M,
/// never zero."
pub const MIN_BLOCK_GAS_LIMIT: u64 = 10_000_000;
pub const MAX_BLOCK_GAS_LIMIT: u64 = 120_000_000;

/// EIP-1559's own value: a block that is completely full raises the
/// base fee by 12.5%. That was chosen for 12-second blocks; at this
/// chain's 1-second target it is a roughly 12x faster wall-clock swing,
/// so this default should be revisited with real load data rather than
/// trusted.
pub const GENESIS_BASE_FEE_CHANGE_DENOMINATOR: u64 = 8;

/// A denominator of 1 would let the base fee double in a single block
/// and 0 would divide by zero; neither is a market.
pub const MIN_BASE_FEE_CHANGE_DENOMINATOR: u64 = 2;
/// Past this, the base fee reacts too slowly to load to price out a
/// sustained spam attack in any useful time.
pub const MAX_BASE_FEE_CHANGE_DENOMINATOR: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeError {
    /// Outside [`MIN_BLOCK_GAS_LIMIT`]..=[`MAX_BLOCK_GAS_LIMIT`].
    BlockGasLimitOutOfRange,
    /// Outside [`MIN_BASE_FEE_CHANGE_DENOMINATOR`]..=
    /// [`MAX_BASE_FEE_CHANGE_DENOMINATOR`].
    DenominatorOutOfRange,
}

impl Encode for FeeError {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::BlockGasLimitOutOfRange => 0u8.encode(out),
            Self::DenominatorOutOfRange => 1u8.encode(out),
        }
    }
}

impl Decode for FeeError {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (kind, offset) = u8::decode(input)?;
        match kind {
            0 => Ok((Self::BlockGasLimitOutOfRange, offset)),
            1 => Ok((Self::DenominatorOutOfRange, offset)),
            _ => Err(CodecError::InvalidValue),
        }
    }
}

impl core::fmt::Display for FeeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BlockGasLimitOutOfRange => f.write_str("block gas limit outside its clamp"),
            Self::DenominatorOutOfRange => f.write_str("base fee denominator outside its clamp"),
        }
    }
}

impl std::error::Error for FeeError {}

/// The governance-adjustable fee parameters. Fields are private so an
/// out-of-clamp value cannot exist: a proposal outside the clamp "fails
/// rather than passing and bricking the chain" (`docs/spec.md`), which
/// here means [`FeeParams::new`] returns an error and there is no other
/// way to build one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeParams {
    max_block_gas: u64,
    base_fee_change_denominator: u64,
}

impl FeeParams {
    pub fn new(max_block_gas: u64, base_fee_change_denominator: u64) -> Result<Self, FeeError> {
        if !(MIN_BLOCK_GAS_LIMIT..=MAX_BLOCK_GAS_LIMIT).contains(&max_block_gas) {
            return Err(FeeError::BlockGasLimitOutOfRange);
        }
        if !(MIN_BASE_FEE_CHANGE_DENOMINATOR..=MAX_BASE_FEE_CHANGE_DENOMINATOR)
            .contains(&base_fee_change_denominator)
        {
            return Err(FeeError::DenominatorOutOfRange);
        }
        Ok(Self {
            max_block_gas,
            base_fee_change_denominator,
        })
    }

    pub const fn max_block_gas(&self) -> u64 {
        self.max_block_gas
    }

    pub const fn base_fee_change_denominator(&self) -> u64 {
        self.base_fee_change_denominator
    }

    /// The gas usage at which the base fee holds steady. Never zero for
    /// a `FeeParams` built through [`Self::new`], since the smallest
    /// allowed limit is millions.
    pub fn target_gas(&self) -> u64 {
        self.max_block_gas
            .checked_div(ELASTICITY_MULTIPLIER)
            .unwrap_or(0)
    }
}

/// `base_fee * amount / target / denominator`, floored, in `u128` so the
/// multiply cannot overflow. Saturates to `u64::MAX` if the result
/// doesn't fit (only reachable with a `gas_used` far beyond the block
/// limit), and is `0` if a divisor is zero (not reachable through a
/// validated [`FeeParams`]).
fn scaled_delta(base_fee: u64, amount: u64, target: u64, denominator: u64) -> u64 {
    let product = u128::from(base_fee).saturating_mul(u128::from(amount));
    product
        .checked_div(u128::from(target))
        .and_then(|per_target| per_target.checked_div(u128::from(denominator)))
        .map_or(0, |delta| u64::try_from(delta).unwrap_or(u64::MAX))
}

/// The base fee for the block after one that used `parent_gas_used`
/// gas at `parent_base_fee`. EIP-1559's rule: unchanged exactly on
/// target, raised by at least 1 and at most `1 / denominator` above it,
/// lowered by at most `1 / denominator` below it, and never below
/// [`MIN_BASE_FEE`].
pub fn next_base_fee(params: &FeeParams, parent_base_fee: u64, parent_gas_used: u64) -> u64 {
    let target = params.target_gas();
    let denominator = params.base_fee_change_denominator();

    let next = match parent_gas_used.cmp(&target) {
        core::cmp::Ordering::Equal => parent_base_fee,
        core::cmp::Ordering::Greater => {
            let excess = parent_gas_used.saturating_sub(target);
            let delta = scaled_delta(parent_base_fee, excess, target, denominator).max(1);
            parent_base_fee.saturating_add(delta)
        }
        core::cmp::Ordering::Less => {
            let shortfall = target.saturating_sub(parent_gas_used);
            let delta = scaled_delta(parent_base_fee, shortfall, target, denominator);
            parent_base_fee.saturating_sub(delta)
        }
    };
    next.max(MIN_BASE_FEE)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::integer_division
    )]

    use super::*;
    use proptest::prelude::*;

    fn params() -> FeeParams {
        // Target = 30M.
        FeeParams::new(60_000_000, 8).unwrap()
    }

    #[test]
    fn params_reject_a_block_gas_limit_outside_the_clamp() {
        assert_eq!(
            FeeParams::new(MIN_BLOCK_GAS_LIMIT - 1, 8),
            Err(FeeError::BlockGasLimitOutOfRange)
        );
        assert_eq!(
            FeeParams::new(MAX_BLOCK_GAS_LIMIT + 1, 8),
            Err(FeeError::BlockGasLimitOutOfRange)
        );
        assert_eq!(
            FeeParams::new(0, 8),
            Err(FeeError::BlockGasLimitOutOfRange),
            "a zero limit must never be constructible"
        );
    }

    #[test]
    fn params_accept_both_ends_of_the_block_gas_clamp() {
        assert!(FeeParams::new(MIN_BLOCK_GAS_LIMIT, 8).is_ok());
        assert!(FeeParams::new(MAX_BLOCK_GAS_LIMIT, 8).is_ok());
    }

    #[test]
    fn params_reject_a_denominator_outside_the_clamp() {
        for bad in [0, 1, MAX_BASE_FEE_CHANGE_DENOMINATOR + 1, u64::MAX] {
            assert_eq!(
                FeeParams::new(60_000_000, bad),
                Err(FeeError::DenominatorOutOfRange),
                "denominator {bad}"
            );
        }
        assert!(FeeParams::new(60_000_000, MIN_BASE_FEE_CHANGE_DENOMINATOR).is_ok());
        assert!(FeeParams::new(60_000_000, MAX_BASE_FEE_CHANGE_DENOMINATOR).is_ok());
    }

    #[test]
    fn target_is_half_the_block_gas_limit() {
        assert_eq!(params().target_gas(), 30_000_000);
    }

    #[test]
    fn base_fee_holds_exactly_on_target() {
        assert_eq!(next_base_fee(&params(), 1_000, 30_000_000), 1_000);
    }

    #[test]
    fn a_completely_full_block_raises_the_base_fee_by_one_denominator() {
        // 1000 + 1000 * (60M - 30M) / 30M / 8 = 1000 + 125.
        assert_eq!(next_base_fee(&params(), 1_000, 60_000_000), 1_125);
    }

    #[test]
    fn an_empty_block_lowers_the_base_fee_by_one_denominator() {
        // 1000 - 1000 * 30M / 30M / 8 = 1000 - 125.
        assert_eq!(next_base_fee(&params(), 1_000, 0), 875);
    }

    #[test]
    fn the_change_is_proportional_to_how_far_from_target_the_block_was() {
        // Halfway between target and full: 1000 * 15M / 30M / 8 = 62.5,
        // floored to 62.
        assert_eq!(next_base_fee(&params(), 1_000, 45_000_000), 1_062);
    }

    #[test]
    fn the_base_fee_can_always_rise_even_when_the_proportional_step_rounds_to_zero() {
        // 1 * 30M / 30M / 8 = 0.125, floored to 0 — but a full block
        // must still move it, or it could never leave a tiny value.
        assert_eq!(next_base_fee(&params(), 1, 60_000_000), 2);
    }

    #[test]
    fn the_base_fee_never_falls_below_the_floor() {
        assert_eq!(next_base_fee(&params(), MIN_BASE_FEE, 0), MIN_BASE_FEE);
        assert_eq!(next_base_fee(&params(), 3, 0), 3, "floors to 3 - 0");
    }

    #[test]
    fn a_sustained_run_of_full_blocks_keeps_raising_it() {
        let mut fee = GENESIS_BASE_FEE;
        for _ in 0..200 {
            let next = next_base_fee(&params(), fee, 60_000_000);
            assert!(next > fee);
            fee = next;
        }
        assert!(fee > 1_000, "compounding must outrun the +1 floor: {fee}");
    }

    #[test]
    fn a_sustained_run_of_empty_blocks_decays_it_until_the_step_rounds_to_zero() {
        let mut fee = 1_000_000;
        for _ in 0..1_000 {
            fee = next_base_fee(&params(), fee, 0);
        }
        // Once fee * 30M / 30M / 8 floors to 0 (fee < 8) it stops
        // falling — the reference rule's own floor, see the module docs.
        assert_eq!(fee, 7);
        assert_eq!(next_base_fee(&params(), fee, 0), fee);
    }

    #[test]
    fn saturates_instead_of_overflowing_at_the_top_of_the_range() {
        assert_eq!(next_base_fee(&params(), u64::MAX, 60_000_000), u64::MAX);
    }

    #[test]
    fn a_gas_figure_far_past_the_limit_saturates_rather_than_panicking() {
        // Unreachable through a block that respects the limit, but a
        // caller bug must not become a panic in a tier-A crate.
        let fee = next_base_fee(&params(), u64::MAX / 2, u64::MAX);
        assert_eq!(fee, u64::MAX);
    }

    proptest! {
        #[test]
        fn the_base_fee_never_drops_below_the_floor(
            base_fee in 1u64..=u64::MAX,
            gas_used in 0u64..=MAX_BLOCK_GAS_LIMIT,
            limit in MIN_BLOCK_GAS_LIMIT..=MAX_BLOCK_GAS_LIMIT,
            denominator in MIN_BASE_FEE_CHANGE_DENOMINATOR..=MAX_BASE_FEE_CHANGE_DENOMINATOR,
        ) {
            let p = FeeParams::new(limit, denominator).unwrap();
            prop_assert!(next_base_fee(&p, base_fee, gas_used.min(limit)) >= MIN_BASE_FEE);
        }

        #[test]
        fn more_gas_used_never_yields_a_lower_next_base_fee(
            base_fee in 1u64..=u64::MAX,
            a in 0u64..=MAX_BLOCK_GAS_LIMIT,
            b in 0u64..=MAX_BLOCK_GAS_LIMIT,
            limit in MIN_BLOCK_GAS_LIMIT..=MAX_BLOCK_GAS_LIMIT,
            denominator in MIN_BASE_FEE_CHANGE_DENOMINATOR..=MAX_BASE_FEE_CHANGE_DENOMINATOR,
        ) {
            let p = FeeParams::new(limit, denominator).unwrap();
            let (lo, hi) = (a.min(b).min(limit), a.max(b).min(limit));
            prop_assert!(next_base_fee(&p, base_fee, lo) <= next_base_fee(&p, base_fee, hi));
        }

        #[test]
        fn the_direction_of_change_always_follows_the_load(
            base_fee in 1u64..=(u64::MAX - 1),
            gas_used in 0u64..=MAX_BLOCK_GAS_LIMIT,
            limit in MIN_BLOCK_GAS_LIMIT..=MAX_BLOCK_GAS_LIMIT,
            denominator in MIN_BASE_FEE_CHANGE_DENOMINATOR..=MAX_BASE_FEE_CHANGE_DENOMINATOR,
        ) {
            let p = FeeParams::new(limit, denominator).unwrap();
            let used = gas_used.min(limit);
            let next = next_base_fee(&p, base_fee, used);
            match used.cmp(&p.target_gas()) {
                core::cmp::Ordering::Greater => prop_assert!(next > base_fee),
                core::cmp::Ordering::Equal => prop_assert_eq!(next, base_fee),
                core::cmp::Ordering::Less => prop_assert!(next <= base_fee),
            }
        }

        #[test]
        fn a_single_block_never_moves_the_base_fee_by_more_than_its_cap(
            base_fee in 1u64..=(u64::MAX / 2),
            gas_used in 0u64..=MAX_BLOCK_GAS_LIMIT,
            limit in MIN_BLOCK_GAS_LIMIT..=MAX_BLOCK_GAS_LIMIT,
            denominator in MIN_BASE_FEE_CHANGE_DENOMINATOR..=MAX_BASE_FEE_CHANGE_DENOMINATOR,
        ) {
            let p = FeeParams::new(limit, denominator).unwrap();
            let target = p.target_gas();
            let next = next_base_fee(&p, base_fee, gas_used.min(limit));

            // The largest a block can be above target is `limit - target`,
            // which is `target + 1` for an odd limit (target is floored);
            // the largest it can be below is `target`.
            let cap_up = (u128::from(base_fee) * u128::from(limit - target)
                / u128::from(target)
                / u128::from(denominator))
            .max(1);
            let cap_down = u128::from(base_fee / denominator);

            if next >= base_fee {
                prop_assert!(u128::from(next - base_fee) <= cap_up, "{base_fee} -> {next}, cap {cap_up}");
            } else {
                prop_assert!(u128::from(base_fee - next) <= cap_down, "{base_fee} -> {next}, cap {cap_down}");
            }
        }
    }
}
