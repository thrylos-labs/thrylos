//! What runs at the end of every block, after its transactions: the
//! modules' hooks. `docs/spec.md`, "Execution": "Module hooks run in a
//! fixed, compiled-in order and cannot re-enter execution."
//!
//! In that order:
//!
//! 1. **Unbonding payouts.** Entries whose time has come are removed from
//!    the queue and their coin credited to the staker's account. At most
//!    `chain_modules::MAX_MATURING_PER_CALL` a block, so a pile-up is paid
//!    out over several blocks rather than one slow one.
//! 2. **Rewards**, on the first block of each epoch: coin is minted at the
//!    governed inflation rate and added to the validators' pools in
//!    proportion to their stake, which raises every share's price.
//! 3. **Governance**: votes are tallied, timelocks run out, and passed
//!    proposals are applied.
//! 4. **Time checkpoints**: the block's timestamp is recorded on the
//!    epoch's first height, and records too old to matter are dropped.
//!
//! # Rewards
//!
//! The spec says "Inflation: 3–5% annualised, paid to stakers" and fixes
//! no more, so these are choices, each easy to change:
//!
//! - It is inflation of the *supply*: over a year the supply grows by the
//!   governed rate, however much of it is staked.
//! - It is paid out once per epoch ([`EPOCH_BLOCKS`] blocks, about 17
//!   minutes at the 1-second target) rather than every block, so the work
//!   of touching every validator's pool is done rarely.
//! - The amount is the time since the last payout, from the blocks' own
//!   timestamps — never a clock — capped at [`MAX_REWARD_ELAPSED_MS`] so
//!   a long halt does not pay out for the time nobody was producing.
//! - It goes to the active validator set only, pro rata by stake, with no
//!   commission and no extra for the proposer.
//! - Only what is actually paid into pools is minted: the rounding
//!   remainder is never created, so the supply stays exactly what is held.
//!
//! # Time checkpoints
//!
//! Slashing needs *when* an equivocation happened, which is the timestamp
//! of the block at the evidence's height. Keeping every block's timestamp
//! for the whole evidence window (14 days, over a million blocks) is a
//! lot of state for something read rarely, so one is kept per epoch, and
//! an equivocation is dated to the checkpoint at or before its height. That
//! is never later than the truth, so a delay only ever makes evidence look
//! a little older and stake look a little more at risk — never in the
//! offender's favour, the same direction every other approximation in
//! slashing errs — by at most one epoch, against a margin of a week
//! between the evidence window and unbonding.

use chain_modules::params::{DAY_MS, MAX_EVIDENCE_AGE_MS};
use chain_modules::{Governance, StakingRegistry};
use chain_state::{StateKey, StateValue};
use chain_types::codec::{decode_exact, Encode};
use chain_types::collections::BTreeMap;
use ruint::aliases::U256;

use crate::accounting::{read_supply, write_supply};
use crate::effects::BlockCtx;
use crate::keys::{reward_clock_key, time_checkpoint_key, time_checkpoint_tag};
use crate::module_store::StateStore;

type State = BTreeMap<StateKey, StateValue>;

/// **A choice.** Blocks per epoch: how often rewards are paid and how
/// often a time checkpoint is kept.
pub const EPOCH_BLOCKS: u64 = 1_024;

/// **A choice.** The longest span one reward payout covers.
pub const MAX_REWARD_ELAPSED_MS: u64 = DAY_MS;

/// A year, for turning an annual rate into a per-span one.
pub const YEAR_MS: u64 = 365 * DAY_MS;

/// **A choice.** How many aged-out checkpoints one block deletes. One a
/// block is what steady state needs; the slack is for catching up.
const MAX_CHECKPOINTS_PRUNED_PER_BLOCK: usize = 8;

/// A hook could not run because the state it reads is damaged. Nothing a
/// transaction can cause; the block is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookFailure;

/// What a year's inflation at `inflation_bps` comes to over `elapsed_ms`,
/// on `supply`: `floor(supply * bps * elapsed / (10_000 * YEAR_MS))`.
pub fn reward_for(supply: u128, inflation_bps: u16, elapsed_ms: u64) -> u128 {
    let numerator = U256::from(supply)
        .saturating_mul(U256::from(inflation_bps))
        .saturating_mul(U256::from(elapsed_ms));
    let denominator = U256::from(10_000u64).saturating_mul(U256::from(YEAR_MS));
    numerator
        .checked_div(denominator)
        .and_then(|reward| u128::try_from(&reward).ok())
        .unwrap_or(0)
}

/// Splits `total` across `weights` in proportion, each share rounded down,
/// so the shares add up to at most `total` and never more. All zeros if the
/// weights add up to nothing.
pub fn split_pro_rata(total: u128, weights: &[u128]) -> Vec<u128> {
    let sum = weights.iter().fold(U256::ZERO, |sum, weight| {
        sum.saturating_add(U256::from(*weight))
    });
    weights
        .iter()
        .map(|weight| {
            U256::from(total)
                .saturating_mul(U256::from(*weight))
                .checked_div(sum)
                .and_then(|share| u128::try_from(&share).ok())
                .unwrap_or(0)
        })
        .collect()
}

/// The height whose time checkpoint dates `height`: the last checkpoint
/// height at or before it. Checkpoints are kept at the first height of each
/// epoch — 1, one epoch on, and so on — so every height from 1 has one.
/// Height 0 is genesis, where nobody votes, and has none.
pub const fn checkpoint_height_for(height: u64) -> Option<u64> {
    if height == 0 {
        return None;
    }
    // Heights 1..=EPOCH_BLOCKS are the first epoch, whose checkpoint is 1.
    let Some(epoch) = height.saturating_sub(1).checked_div(EPOCH_BLOCKS) else {
        return None;
    };
    Some(epoch.saturating_mul(EPOCH_BLOCKS).saturating_add(1))
}

/// When the block at `height` happened, as far as the chain remembers: the
/// timestamp of its epoch's checkpoint. `None` if it is too old to be
/// remembered (or is genesis), which for evidence means too old to act on.
pub fn infraction_time(state: &State, height: u64) -> Option<u64> {
    let checkpoint = checkpoint_height_for(height)?;
    decode_exact(state.get(&time_checkpoint_key(checkpoint))?.as_bytes()).ok()
}

/// Runs every hook, in order, for the block described by `ctx`.
pub(crate) fn end_of_block(state: &mut State, ctx: &BlockCtx) -> Result<(), HookFailure> {
    pay_matured_unbonding(state, ctx)?;
    pay_rewards(state, ctx)?;
    Governance::new(StateStore::new(state))
        .process(ctx.timestamp_ms, ctx.height)
        .map_err(|_| HookFailure)?;
    keep_time_checkpoints(state, ctx);
    Ok(())
}

fn pay_matured_unbonding(state: &mut State, ctx: &BlockCtx) -> Result<(), HookFailure> {
    let matured = StakingRegistry::new(StateStore::new(state))
        .process(ctx.timestamp_ms)
        .map_err(|_| HookFailure)?;
    for payout in matured {
        let mut account =
            chain_state::account::read_account(state, payout.staker).map_err(|_| HookFailure)?;
        account.balance = account
            .balance
            .checked_add(payout.amount)
            .ok_or(HookFailure)?;
        chain_state::account::write_account(state, payout.staker, account);
    }
    Ok(())
}

fn read_clock(state: &State) -> Option<u64> {
    decode_exact(state.get(&reward_clock_key())?.as_bytes()).ok()
}

fn write_clock(state: &mut State, timestamp_ms: u64) {
    let mut bytes = Vec::new();
    timestamp_ms.encode(&mut bytes);
    state.insert(reward_clock_key(), StateValue::new(bytes));
}

fn pay_rewards(state: &mut State, ctx: &BlockCtx) -> Result<(), HookFailure> {
    let Some(last_paid) = read_clock(state) else {
        // The first block: start the clock. Nothing is owed for the time
        // before there was a chain.
        write_clock(state, ctx.timestamp_ms);
        return Ok(());
    };
    if ctx.height.0.checked_rem(EPOCH_BLOCKS) != Some(0) {
        return Ok(());
    }

    let elapsed = ctx
        .timestamp_ms
        .saturating_sub(last_paid)
        .min(MAX_REWARD_ELAPSED_MS);
    write_clock(state, ctx.timestamp_ms);

    let supply = read_supply(state).ok_or(HookFailure)?;
    let total = reward_for(supply, ctx.params.values().inflation_bps, elapsed);
    let active = StakingRegistry::new(StateStore::new(state))
        .active_set(&ctx.params)
        .map_err(|_| HookFailure)?;
    let stakes: Vec<u128> = active.iter().map(|validator| validator.stake).collect();

    let mut minted = 0u128;
    for (validator, share) in active.iter().zip(split_pro_rata(total, &stakes)) {
        if share == 0 {
            continue;
        }
        StakingRegistry::new(StateStore::new(state))
            .credit_rewards(&validator.id, share)
            .map_err(|_| HookFailure)?;
        minted = minted.checked_add(share).ok_or(HookFailure)?;
    }
    if minted > 0 {
        write_supply(state, supply.checked_add(minted).ok_or(HookFailure)?);
    }
    Ok(())
}

fn keep_time_checkpoints(state: &mut State, ctx: &BlockCtx) {
    if checkpoint_height_for(ctx.height.0) == Some(ctx.height.0) {
        let mut bytes = Vec::new();
        ctx.timestamp_ms.encode(&mut bytes);
        state.insert(time_checkpoint_key(ctx.height.0), StateValue::new(bytes));
    }

    // Drop the oldest checkpoints once they are too old to date any
    // evidence that could still be admitted.
    let oldest_useful = ctx.timestamp_ms.saturating_sub(MAX_EVIDENCE_AGE_MS);
    let stale: Vec<StateKey> = state
        .range(StateKey::new(vec![time_checkpoint_tag()])..)
        .take_while(|(key, _)| key.as_bytes().first() == Some(&time_checkpoint_tag()))
        .take(MAX_CHECKPOINTS_PRUNED_PER_BLOCK)
        .filter(|(_, value)| {
            decode_exact::<u64>(value.as_bytes()).is_ok_and(|ts| ts < oldest_useful)
        })
        .map(|(key, _)| key.clone())
        .collect();
    for key in stale {
        state.remove(&key);
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

    #[test]
    fn a_year_at_four_percent_is_four_percent_of_the_supply() {
        assert_eq!(reward_for(1_000_000, 400, YEAR_MS), 40_000);
        assert_eq!(reward_for(1_000_000, 1_000, YEAR_MS), 100_000);
    }

    #[test]
    fn rewards_scale_with_time_and_round_down() {
        assert_eq!(reward_for(1_000_000, 400, YEAR_MS / 2), 20_000);
        assert_eq!(reward_for(1_000_000, 400, 0), 0);
        assert_eq!(reward_for(0, 400, YEAR_MS), 0);
        assert_eq!(reward_for(1_000_000, 0, YEAR_MS), 0);
        // One second's worth of 4% on a million is far under a unit.
        assert_eq!(reward_for(1_000_000, 400, 1_000), 0);
        // And what does not round to a whole unit is dropped, not rounded up.
        assert_eq!(reward_for(10_000_000_000, 400, 1_000), 12);
    }

    #[test]
    fn rewards_do_not_overflow_at_the_top_of_the_supply() {
        let reward = reward_for(u128::MAX, 1_000, MAX_REWARD_ELAPSED_MS);
        assert!(reward < u128::MAX / 100, "{reward}");
    }

    #[test]
    fn a_split_never_hands_out_more_than_the_total() {
        for (total, weights) in [
            (100u128, vec![1u128, 1, 1]),
            (7, vec![5, 3]),
            (1, vec![1, 1, 1, 1]),
            (u128::MAX, vec![u128::MAX, u128::MAX]),
            (1_000, vec![0, 0]),
            (1_000, vec![]),
            (0, vec![4, 5]),
        ] {
            let shares = split_pro_rata(total, &weights);
            assert_eq!(shares.len(), weights.len());
            let paid = shares.iter().fold(0u128, |sum, s| sum.saturating_add(*s));
            assert!(paid <= total, "{total} over {weights:?}: {shares:?}");
        }
    }

    #[test]
    fn a_split_is_proportional_and_rounds_each_share_down() {
        assert_eq!(split_pro_rata(100, &[1, 3]), vec![25, 75]);
        assert_eq!(split_pro_rata(100, &[1, 1, 1]), vec![33, 33, 33]);
        assert_eq!(split_pro_rata(10, &[6, 4]), vec![6, 4]);
        assert_eq!(split_pro_rata(1_000, &[0, 0]), vec![0, 0]);
    }

    #[test]
    fn every_height_from_one_is_dated_by_the_first_height_of_its_epoch() {
        assert_eq!(checkpoint_height_for(0), None, "genesis has none");
        assert_eq!(checkpoint_height_for(1), Some(1));
        assert_eq!(checkpoint_height_for(EPOCH_BLOCKS), Some(1));
        assert_eq!(
            checkpoint_height_for(EPOCH_BLOCKS + 1),
            Some(EPOCH_BLOCKS + 1)
        );
        assert_eq!(
            checkpoint_height_for(2 * EPOCH_BLOCKS),
            Some(EPOCH_BLOCKS + 1)
        );
        assert_eq!(
            checkpoint_height_for(2 * EPOCH_BLOCKS + 1),
            Some(2 * EPOCH_BLOCKS + 1)
        );
        assert_eq!(
            checkpoint_height_for(u64::MAX).map(|h| h % EPOCH_BLOCKS),
            Some(1)
        );
    }

    #[test]
    fn a_checkpoint_is_never_after_the_height_it_dates() {
        for height in [
            1u64,
            2,
            500,
            EPOCH_BLOCKS,
            EPOCH_BLOCKS + 1,
            50_000,
            u64::MAX,
        ] {
            let checkpoint = checkpoint_height_for(height).unwrap();
            assert!(checkpoint <= height, "{height} -> {checkpoint}");
            assert!(height - checkpoint < EPOCH_BLOCKS, "within one epoch");
        }
    }

    // ---- time checkpoints ------------------------------------------------

    use chain_modules::GovernedParams;
    use chain_types::{BlockHeight, ChainId};

    fn ctx(height: u64, timestamp_ms: u64) -> BlockCtx {
        BlockCtx {
            chain_id: ChainId(1),
            height: BlockHeight(height),
            timestamp_ms,
            base_fee: 1,
            params: GovernedParams::new(chain_modules::params::GENESIS_PARAM_VALUES).unwrap(),
        }
    }

    fn checkpoint_heights(state: &State) -> Vec<u64> {
        state
            .keys()
            .filter(|key| key.as_bytes().first() == Some(&time_checkpoint_tag()))
            .filter_map(|key| {
                let bytes: [u8; 8] = key.as_bytes().get(1..)?.try_into().ok()?;
                Some(u64::from_be_bytes(bytes))
            })
            .collect()
    }

    #[test]
    fn a_checkpoint_is_kept_on_the_first_height_of_each_epoch_and_only_then() {
        let mut state = State::new();
        for height in [1, 2, EPOCH_BLOCKS, EPOCH_BLOCKS + 1, EPOCH_BLOCKS + 2] {
            keep_time_checkpoints(&mut state, &ctx(height, 1_000_000 + height));
        }
        assert_eq!(checkpoint_heights(&state), vec![1, EPOCH_BLOCKS + 1]);
        assert_eq!(infraction_time(&state, 1), Some(1_000_001));
        assert_eq!(infraction_time(&state, EPOCH_BLOCKS), Some(1_000_001));
        assert_eq!(
            infraction_time(&state, EPOCH_BLOCKS + 500),
            Some(1_000_000 + EPOCH_BLOCKS + 1)
        );
        assert_eq!(infraction_time(&state, 0), None, "genesis has no time");
        assert_eq!(
            infraction_time(&state, 3 * EPOCH_BLOCKS),
            None,
            "an epoch with no checkpoint yet"
        );
    }

    #[test]
    fn checkpoints_older_than_the_evidence_window_are_dropped_and_newer_ones_kept() {
        let now = 100 * DAY_MS;
        let mut state = State::new();
        for (height, ts) in [
            (1, now - MAX_EVIDENCE_AGE_MS - 2),
            (EPOCH_BLOCKS + 1, now - MAX_EVIDENCE_AGE_MS - 1),
            (2 * EPOCH_BLOCKS + 1, now - MAX_EVIDENCE_AGE_MS),
            (3 * EPOCH_BLOCKS + 1, now - DAY_MS),
        ] {
            let mut bytes = Vec::new();
            ts.encode(&mut bytes);
            state.insert(time_checkpoint_key(height), StateValue::new(bytes));
        }

        keep_time_checkpoints(&mut state, &ctx(7, now));

        // Two are past the window; one is exactly at its edge (still able to
        // date evidence that is exactly as old as allowed) and stays.
        assert_eq!(
            checkpoint_heights(&state),
            vec![2 * EPOCH_BLOCKS + 1, 3 * EPOCH_BLOCKS + 1]
        );
    }

    #[test]
    fn pruning_is_bounded_per_block_so_a_backlog_clears_over_several() {
        let now = 100 * DAY_MS;
        let mut state = State::new();
        let mut bytes = Vec::new();
        1u64.encode(&mut bytes); // far too old
        for i in 0..20u64 {
            state.insert(
                time_checkpoint_key(i * EPOCH_BLOCKS + 1),
                StateValue::new(bytes.clone()),
            );
        }
        keep_time_checkpoints(&mut state, &ctx(7, now));
        assert_eq!(
            checkpoint_heights(&state).len(),
            20 - MAX_CHECKPOINTS_PRUNED_PER_BLOCK
        );
        keep_time_checkpoints(&mut state, &ctx(8, now));
        keep_time_checkpoints(&mut state, &ctx(9, now));
        assert!(checkpoint_heights(&state).is_empty());
    }

    #[test]
    fn pruning_touches_only_time_checkpoints() {
        let now = 100 * DAY_MS;
        let mut state = State::new();
        let mut old = Vec::new();
        1u64.encode(&mut old);
        state.insert(time_checkpoint_key(1), StateValue::new(old.clone()));
        state.insert(crate::keys::base_fee_key(), StateValue::new(old.clone()));
        state.insert(crate::keys::reward_clock_key(), StateValue::new(old));
        keep_time_checkpoints(&mut state, &ctx(7, now));
        assert_eq!(state.len(), 2, "the base fee and the reward clock stay");
    }

    #[test]
    fn the_reward_clock_starts_on_the_first_block_and_pays_nothing_then() {
        let mut state = State::new();
        write_supply(&mut state, 1_000_000);
        pay_rewards(&mut state, &ctx(1, 5_000)).unwrap();
        assert_eq!(read_clock(&state), Some(5_000));
        assert_eq!(read_supply(&state), Some(1_000_000));

        // Not an epoch boundary: nothing, and the clock is not reset.
        pay_rewards(&mut state, &ctx(2, 9_000)).unwrap();
        assert_eq!(read_clock(&state), Some(5_000));
    }

    #[test]
    fn each_epoch_boundary_moves_the_reward_clock_on_even_when_nobody_is_paid() {
        // No validators, so nothing is minted; the clock must still advance,
        // or the next epoch would be paid for this one's time as well.
        let mut state = State::new();
        write_supply(&mut state, 1_000_000);
        write_clock(&mut state, 5_000);

        pay_rewards(&mut state, &ctx(EPOCH_BLOCKS, 8_000)).unwrap();
        assert_eq!(read_clock(&state), Some(8_000));
        pay_rewards(&mut state, &ctx(2 * EPOCH_BLOCKS, 12_000)).unwrap();
        assert_eq!(read_clock(&state), Some(12_000));
        assert_eq!(read_supply(&state), Some(1_000_000), "nobody to pay");
    }
}
