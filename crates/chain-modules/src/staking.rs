//! Staking share-price accounting. `docs/spec.md`, "Native modules:
//! staking, fees and governance": "Reward distribution is a share-price
//! system and inherits every share-price bug from DeFi: first-depositor
//! inflation, division-before-multiplication dust, and rounding that
//! favours the caller."
//!
//! Mitigations, matching the spec line for line:
//! - "mint a dead share at genesis so the pool is never empty" —
//!   [`StakingPool::genesis`] mints [`DEAD_SHARES`] shares against an
//!   equal, permanently unredeemable amount of stake, diluting any
//!   first-depositor price-manipulation attempt (see the
//!   `first_depositor_inflation_attack_is_mitigated` test).
//! - "fixed-point arithmetic throughout with a single U256 fixed-point
//!   type and no ad-hoc scaling" — every price computation goes through
//!   [`price`] alone, at [`PRICE_FRAC_BITS`] fractional bits, using
//!   [`ruint`]'s `U256` as the widening intermediate so a `u128 * u128`
//!   multiply can never silently overflow.
//! - "round against the user on every withdrawal path" —
//!   [`shares_for_deposit`] and [`stake_for_withdrawal`] both floor
//!   (truncating integer division always rounds toward zero for
//!   non-negative operands), so any rounding remainder stays with the
//!   pool, never the individual depositor.
//! - "assert sum(shares) * price == total_stake ± 1 wei as a
//!   block-level invariant that halts block production if violated" —
//!   [`StakingPool::assert_invariant`].
//!
//! Deliberately out of scope for this slice: the per-validator pool
//! registry, `StakeReceipt`, `ValidatorId`, and the unbonding-period
//! queue that gates real withdrawals (`docs/spec.md`'s
//! `unstake(StakeReceipt) -> Coin` is "subject to the unbonding
//! period" — a scheduling concern layered on top of this arithmetic
//! core, not part of it). [`StakingPool`] models one pool's accounting
//! in isolation; wiring many pools together, keyed by validator, is a
//! follow-up.

use ruint::aliases::U256;

use chain_types::collections::BTreeMap;
use chain_types::Address;

/// Fractional bits used by every fixed-point price in this module. See
/// the module doc comment: "a single U256 fixed-point type and no
/// ad-hoc scaling".
pub const PRICE_FRAC_BITS: usize = 64;

/// Shares minted at genesis to no one, permanently locked, so the pool
/// is never empty and a first depositor can never own 100% of it.
/// Matches the value Uniswap V2 uses for its own dead-share mitigation
/// (`MINIMUM_LIQUIDITY`) — reusing a widely reviewed constant rather
/// than picking a new one.
pub const DEAD_SHARES: u128 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakingError {
    /// A deposit or withdrawal of zero was requested.
    ZeroAmount,
    /// A deposit rounded down to zero shares at the current price —
    /// rejected rather than silently accepting stake that buys the
    /// depositor nothing.
    DepositTooSmall,
    /// A withdrawal requested more shares than the staker holds.
    InsufficientShares,
    /// An arithmetic operation would have overflowed its type. Treated
    /// as a hard error, never a silent wrap — `docs/spec.md`,
    /// "Determinism rules": "No overflow".
    Overflow,
    /// [`StakingPool::assert_invariant`] found the ledger or the price
    /// identity broken. Should be unreachable in a correct caller,
    /// which is exactly why it halts block production rather than
    /// being ignored.
    InvariantViolated,
}

/// A single pool's share-price accounting: one validator's stake plus
/// its delegators' proportional claims on it, as shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingPool {
    total_shares: u128,
    total_stake: u128,
    balances: BTreeMap<Address, u128>,
}

impl StakingPool {
    /// A freshly initialised pool: [`DEAD_SHARES`] shares against an
    /// equal amount of stake, both permanently locked (owned by no
    /// address, never withdrawable).
    pub fn genesis() -> Self {
        Self {
            total_shares: DEAD_SHARES,
            total_stake: DEAD_SHARES,
            balances: BTreeMap::new(),
        }
    }

    pub const fn total_shares(&self) -> u128 {
        self.total_shares
    }

    pub const fn total_stake(&self) -> u128 {
        self.total_stake
    }

    pub fn balance_of(&self, staker: &Address) -> u128 {
        self.balances.get(staker).copied().unwrap_or(0)
    }

    /// Current price, in `PRICE_FRAC_BITS`-fixed-point units of stake
    /// per share. `Err(StakingError::Overflow)` only if `total_stake`
    /// has somehow grown large enough that shifting it left by
    /// `PRICE_FRAC_BITS` bits no longer fits in `U256` — not reachable
    /// for any realistic token supply.
    pub fn price(&self) -> Result<U256, StakingError> {
        let stake = to_u256(self.total_stake)?;
        let shares = to_u256(self.total_shares)?;
        let scaled = stake
            .checked_shl(PRICE_FRAC_BITS)
            .ok_or(StakingError::Overflow)?;
        scaled.checked_div(shares).ok_or(StakingError::Overflow)
    }

    /// Burns up to `amount` of the pool's stake as a slashing penalty and
    /// returns how much was actually burned. Every share is worth
    /// proportionally less afterwards and nobody's share count changes —
    /// the validator and every delegator bear the loss pro rata, which
    /// is what makes delegating to a validator that later equivocates
    /// a risk.
    ///
    /// Never burns the pool's last unit of stake: a pool with none would
    /// have a price of zero, and no deposit could be priced against it.
    /// Deposits into a pool slashed nearly to nothing still work — they
    /// are priced at the post-slash share price, so the depositor gets
    /// many shares for little stake and, on withdrawing, gets back what
    /// they put in (less rounding). That is fair to everyone already in
    /// the pool, whose loss was booked by the slash, just pointless: a
    /// tombstoned validator's pool has nothing to offer a new staker.
    ///
    /// Shares and stake stay consistent by construction (the price is
    /// derived from them), so [`Self::assert_invariant`] still holds.
    pub fn slash(&mut self, amount: u128) -> u128 {
        let burned = amount.min(self.total_stake.saturating_sub(1));
        self.total_stake = self.total_stake.saturating_sub(burned);
        burned
    }

    /// Deposit `stake_amount` on behalf of `staker`, minting shares at
    /// the current price (rounded down). Returns the shares minted.
    pub fn deposit(&mut self, staker: Address, stake_amount: u128) -> Result<u128, StakingError> {
        if stake_amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        let minted = shares_for_deposit(stake_amount, self.total_shares, self.total_stake)?;
        if minted == 0 {
            return Err(StakingError::DepositTooSmall);
        }

        self.total_shares = self
            .total_shares
            .checked_add(minted)
            .ok_or(StakingError::Overflow)?;
        self.total_stake = self
            .total_stake
            .checked_add(stake_amount)
            .ok_or(StakingError::Overflow)?;

        let existing = self.balance_of(&staker);
        let updated = existing.checked_add(minted).ok_or(StakingError::Overflow)?;
        self.balances.insert(staker, updated);

        Ok(minted)
    }

    /// Redeem `shares_amount` of `staker`'s shares, returning stake at
    /// the current price (rounded down).
    pub fn withdraw(&mut self, staker: Address, shares_amount: u128) -> Result<u128, StakingError> {
        if shares_amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        let balance = self.balance_of(&staker);
        if shares_amount > balance {
            return Err(StakingError::InsufficientShares);
        }

        let returned = stake_for_withdrawal(shares_amount, self.total_shares, self.total_stake)?;

        self.total_shares = self
            .total_shares
            .checked_sub(shares_amount)
            .ok_or(StakingError::Overflow)?;
        self.total_stake = self
            .total_stake
            .checked_sub(returned)
            .ok_or(StakingError::Overflow)?;

        let remaining = balance
            .checked_sub(shares_amount)
            .ok_or(StakingError::Overflow)?;
        if remaining == 0 {
            self.balances.remove(&staker);
        } else {
            self.balances.insert(staker, remaining);
        }

        Ok(returned)
    }

    /// Add `reward_amount` to the pool's stake without minting new
    /// shares — the mechanism by which price-per-share rises for
    /// existing holders as rewards accrue.
    pub fn accrue_rewards(&mut self, reward_amount: u128) -> Result<(), StakingError> {
        self.total_stake = self
            .total_stake
            .checked_add(reward_amount)
            .ok_or(StakingError::Overflow)?;
        Ok(())
    }

    /// `docs/spec.md`, "Native modules": "assert sum(shares) * price ==
    /// total_stake ± 1 wei as a block-level invariant that halts block
    /// production if violated." Checks two things: every individual
    /// balance plus the dead shares sums to `total_shares` (catches a
    /// mint/burn accounting bug), and `total_shares * price` matches
    /// `total_stake` within one part in `2^PRICE_FRAC_BITS` (catches
    /// drift between the two if a future change ever lets them be
    /// updated independently).
    pub fn assert_invariant(&self) -> Result<(), StakingError> {
        let mut ledger_sum: u128 = 0;
        for balance in self.balances.values() {
            ledger_sum = ledger_sum
                .checked_add(*balance)
                .ok_or(StakingError::Overflow)?;
        }
        ledger_sum = ledger_sum
            .checked_add(DEAD_SHARES)
            .ok_or(StakingError::Overflow)?;
        if ledger_sum != self.total_shares {
            return Err(StakingError::InvariantViolated);
        }

        let price = self.price()?;
        let shares = to_u256(self.total_shares)?;
        let product = shares.checked_mul(price).ok_or(StakingError::Overflow)?;
        // A plain truncating shift, not `checked_shr`: ruint's
        // `checked_shr` returns `None` whenever the shift is *inexact*
        // (any bit shifted out is nonzero) — the wrong tool here, since
        // an inexact shift is the expected, common case for a
        // floor-rounded price, not an error. `wrapping_shr` can't
        // actually wrap for a right shift (nothing is lost off the top),
        // it's simply the ordinary truncating shift as a method call
        // rather than the `>>` operator, which the arithmetic-side-
        // effects lint (rightly, in general) still flags for a
        // non-primitive type like `U256`.
        let implied_stake = product.wrapping_shr(PRICE_FRAC_BITS);
        let actual_stake = to_u256(self.total_stake)?;

        let diff = if implied_stake >= actual_stake {
            implied_stake
                .checked_sub(actual_stake)
                .ok_or(StakingError::Overflow)?
        } else {
            actual_stake
                .checked_sub(implied_stake)
                .ok_or(StakingError::Overflow)?
        };

        if diff > to_u256(1)? {
            return Err(StakingError::InvariantViolated);
        }

        Ok(())
    }
}

fn to_u256(value: u128) -> Result<U256, StakingError> {
    U256::try_from(value).map_err(|_| StakingError::Overflow)
}

fn from_u256(value: U256) -> Result<u128, StakingError> {
    u128::try_from(&value).map_err(|_| StakingError::Overflow)
}

/// `floor(stake_amount * total_shares / total_stake)` — rounds down, so
/// any remainder stays with the pool rather than the depositor.
fn shares_for_deposit(
    stake_amount: u128,
    total_shares: u128,
    total_stake: u128,
) -> Result<u128, StakingError> {
    let numerator = to_u256(stake_amount)?
        .checked_mul(to_u256(total_shares)?)
        .ok_or(StakingError::Overflow)?;
    let result = numerator
        .checked_div(to_u256(total_stake)?)
        .ok_or(StakingError::Overflow)?;
    from_u256(result)
}

/// `floor(shares_amount * total_stake / total_shares)` — rounds down, so
/// any remainder stays with the pool rather than the withdrawer.
fn stake_for_withdrawal(
    shares_amount: u128,
    total_shares: u128,
    total_stake: u128,
) -> Result<u128, StakingError> {
    let numerator = to_u256(shares_amount)?
        .checked_mul(to_u256(total_stake)?)
        .ok_or(StakingError::Overflow)?;
    let result = numerator
        .checked_div(to_u256(total_shares)?)
        .ok_or(StakingError::Overflow)?;
    from_u256(result)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    #[test]
    fn genesis_pool_satisfies_the_invariant() {
        let pool = StakingPool::genesis();
        assert!(pool.assert_invariant().is_ok());
        assert_eq!(pool.total_shares(), DEAD_SHARES);
        assert_eq!(pool.total_stake(), DEAD_SHARES);
    }

    #[test]
    fn deposit_then_withdraw_round_trips_at_constant_price() {
        let mut pool = StakingPool::genesis();
        let staker = addr(1);

        let minted = pool.deposit(staker, 5_000).unwrap();
        assert!(pool.assert_invariant().is_ok());

        let returned = pool.withdraw(staker, minted).unwrap();
        assert!(pool.assert_invariant().is_ok());

        // Price never moved (no rewards accrued), so this staker gets
        // back what they put in, modulo at most 1 wei of floor rounding
        // on each leg.
        assert!(returned <= 5_000);
        assert!(5_000u128.checked_sub(returned).unwrap() <= 1);
    }

    #[test]
    fn rewards_increase_price_for_existing_holders() {
        let mut pool = StakingPool::genesis();
        let staker = addr(1);
        let minted = pool.deposit(staker, 10_000).unwrap();

        let price_before = pool.price().unwrap();
        pool.accrue_rewards(1_000).unwrap();
        let price_after = pool.price().unwrap();
        assert!(price_after > price_before);
        assert!(pool.assert_invariant().is_ok());

        // The staker's existing shares now redeem for more stake than
        // they deposited, without minting them any new shares.
        let returned = pool.withdraw(staker, minted).unwrap();
        assert!(returned > 10_000);
    }

    #[test]
    fn withdrawal_rejects_more_shares_than_the_balance() {
        let mut pool = StakingPool::genesis();
        let staker = addr(1);
        pool.deposit(staker, 1_000).unwrap();
        let over_balance = pool.balance_of(&staker).checked_add(1).unwrap();
        assert_eq!(
            pool.withdraw(staker, over_balance),
            Err(StakingError::InsufficientShares)
        );
    }

    #[test]
    fn zero_amount_deposit_and_withdrawal_are_rejected() {
        let mut pool = StakingPool::genesis();
        let staker = addr(1);
        assert_eq!(pool.deposit(staker, 0), Err(StakingError::ZeroAmount));
        assert_eq!(pool.withdraw(staker, 0), Err(StakingError::ZeroAmount));
    }

    /// The classic DeFi first-depositor attack: deposit a token amount
    /// that mints a small number of shares, then donate a large amount
    /// directly to the pool (simulated here via `accrue_rewards`, which
    /// has the same effect on price as an out-of-band donation would)
    /// to inflate price-per-share before a victim deposits, hoping the
    /// victim's shares round down to zero and their whole deposit is
    /// lost to the attacker. The dead-share floor from genesis should
    /// keep the victim's loss bounded to at most one share's worth,
    /// not their entire deposit.
    #[test]
    fn first_depositor_inflation_attack_is_mitigated() {
        let mut pool = StakingPool::genesis();
        let attacker = addr(1);
        let victim = addr(2);

        let attacker_shares = pool.deposit(attacker, 1).unwrap();
        assert!(attacker_shares > 0);

        // Attacker inflates the pool's stake without minting more
        // shares — same effect on price as directly donating tokens.
        pool.accrue_rewards(10_000).unwrap();

        let victim_deposit = 10_000u128;
        let victim_shares = pool.deposit(victim, victim_deposit).unwrap();
        assert!(
            victim_shares > 0,
            "victim must receive nonzero shares even after the attacker's price manipulation"
        );

        let victim_redeemable =
            stake_for_withdrawal(victim_shares, pool.total_shares(), pool.total_stake()).unwrap();
        // The victim's deposit must come back close to whole — bounded
        // rounding loss only, not the attacker draining the deposit.
        let loss = victim_deposit.checked_sub(victim_redeemable).unwrap();
        let one_percent = victim_deposit.checked_div(100).unwrap();
        assert!(
            loss < one_percent,
            "victim lost more than 1% of their deposit to the price-manipulation attempt: \
             deposited {victim_deposit}, redeemable {victim_redeemable}"
        );
        assert!(pool.assert_invariant().is_ok());
    }

    proptest! {
        #[test]
        fn invariant_holds_after_arbitrary_deposit_withdraw_sequences(
            ops in proptest::collection::vec((any::<bool>(), 1u128..1_000_000, 0usize..4), 1..30)
        ) {
            let mut pool = StakingPool::genesis();
            let stakers: Vec<Address> = (1u8..5).map(addr).collect();

            for (is_deposit, amount, staker_index) in ops {
                let Some(&staker) = stakers.get(staker_index) else {
                    continue;
                };
                if is_deposit {
                    let _ = pool.deposit(staker, amount);
                } else {
                    let balance = pool.balance_of(&staker);
                    if balance > 0 {
                        let shares = amount.min(balance);
                        let _ = pool.withdraw(staker, shares);
                    }
                }
                prop_assert!(pool.assert_invariant().is_ok());
            }
        }

        #[test]
        fn a_deposit_never_mints_more_value_than_it_puts_in(
            stake_amount in 1u128..1_000_000_000,
        ) {
            let mut pool = StakingPool::genesis();
            let staker = addr(9);
            let minted = pool.deposit(staker, stake_amount);
            if let Ok(minted) = minted {
                let redeemable = stake_for_withdrawal(minted, pool.total_shares(), pool.total_stake()).unwrap();
                prop_assert!(redeemable <= stake_amount);
            }
        }
    }
    #[test]
    fn slashing_lowers_every_stakers_redeemable_amount_pro_rata() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr(1), 9_000).unwrap();
        assert_eq!(pool.total_stake(), 10_000);

        // A 10% slash of the pool.
        assert_eq!(pool.slash(1_000), 1_000);
        assert_eq!(pool.total_stake(), 9_000);
        assert_eq!(pool.total_shares(), 10_000, "share counts don't change");

        // 9_000 shares of 10_000, against 9_000 of stake: 8_100 — the
        // depositor lost 10% of what they put in, as did the dead stake.
        assert_eq!(pool.withdraw(addr(1), 9_000).unwrap(), 8_100);
    }

    #[test]
    fn slashing_keeps_the_pool_invariant() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr(1), 5_000).unwrap();
        pool.deposit(addr(2), 3_333).unwrap();
        pool.slash(777);
        pool.assert_invariant().unwrap();
        pool.accrue_rewards(50).unwrap();
        pool.assert_invariant().unwrap();
    }

    #[test]
    fn slashing_zero_burns_nothing() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr(1), 1_000).unwrap();
        let before = pool.clone();
        assert_eq!(pool.slash(0), 0);
        assert_eq!(pool, before);
    }

    #[test]
    fn slashing_never_burns_the_last_unit_of_stake() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr(1), 4_000).unwrap();
        let burned = pool.slash(u128::MAX);
        assert_eq!(burned, 4_999, "everything but one unit");
        assert_eq!(pool.total_stake(), 1);
        assert!(pool.price().is_ok());
        pool.assert_invariant().unwrap();
    }

    #[test]
    fn a_deposit_into_a_slashed_out_pool_is_priced_fairly_and_takes_nothing_from_others() {
        let mut pool = StakingPool::genesis();
        pool.deposit(addr(1), 4_000).unwrap();
        pool.slash(u128::MAX); // leaves 1 unit of stake against 5_000 shares

        let minted = pool.deposit(addr(2), 1_000).unwrap();
        assert!(
            minted > 1_000_000,
            "the post-slash price is tiny: {minted} shares"
        );
        pool.assert_invariant().unwrap();

        // The new depositor gets back what they put in, not more.
        let back = pool.withdraw(addr(2), minted).unwrap();
        assert!((999..=1_000).contains(&back), "got back {back}");
        // And the original staker gained nothing from it.
        assert!(pool.withdraw(addr(1), 4_000).unwrap() <= 1);
    }
}
