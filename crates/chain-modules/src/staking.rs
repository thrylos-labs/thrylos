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
//! [`StakingPool`] is one pool's *totals* and the share-price arithmetic
//! on them — pure, with no per-staker ledger. Who holds how many shares
//! is state that grows with the number of stakers, so it lives in the
//! store, one entry per staker (`crate::registry`), and the registry
//! moves a staker's balance and the pool's totals together. That split is
//! why the ledger half of the spec's invariant — every balance plus the
//! dead shares sums to `total_shares` — is checked by
//! [`StakingPool::assert_invariant`] against a sum the caller supplies.
//! Keying pools by validator, the unbonding queue and the wiring to
//! slashing are `crate::registry`'s; `StakeReceipt` as a transferable
//! object is not built.

use ruint::aliases::U256;

use chain_types::codec::{decode_field, CodecError, Decode, Encode};

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

/// A single pool's totals: how many shares exist and how much stake backs
/// them. Every holder's claim is `shares / total_shares` of the stake;
/// the per-holder balances are kept outside, see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakingPool {
    total_shares: u128,
    total_stake: u128,
}

impl StakingPool {
    /// A freshly initialised pool: [`DEAD_SHARES`] shares against an
    /// equal amount of stake, both permanently locked (owned by no
    /// address, never withdrawable).
    pub const fn genesis() -> Self {
        Self {
            total_shares: DEAD_SHARES,
            total_stake: DEAD_SHARES,
        }
    }

    /// A pool with the given totals — for reading one back out of
    /// storage. Nothing is checked here; [`Self::assert_invariant`] is
    /// how a pool's consistency is established.
    pub const fn from_totals(total_shares: u128, total_stake: u128) -> Self {
        Self {
            total_shares,
            total_stake,
        }
    }

    pub const fn total_shares(&self) -> u128 {
        self.total_shares
    }

    pub const fn total_stake(&self) -> u128 {
        self.total_stake
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

    /// What `shares` are worth right now, rounded down (the same
    /// direction a withdrawal rounds).
    pub fn redeemable_for(&self, shares: u128) -> u128 {
        stake_for_withdrawal(shares, self.total_shares, self.total_stake).unwrap_or(0)
    }

    /// The pool's stake net of what its dead shares are worth: the stake
    /// that actually belongs to stakers, and so what counts as this
    /// validator's bonded weight. The dead shares' own stake backs no one
    /// and votes for no one.
    pub fn attributable_stake(&self) -> u128 {
        let dead = self.redeemable_for(DEAD_SHARES);
        self.total_stake.saturating_sub(dead)
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

    /// Takes in `stake_amount`, minting shares at the current price
    /// (rounded down). Returns the shares minted, for the caller to
    /// credit to the depositor's balance.
    pub fn deposit(&mut self, stake_amount: u128) -> Result<u128, StakingError> {
        if stake_amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        let minted = shares_for_deposit(stake_amount, self.total_shares, self.total_stake)?;
        if minted == 0 {
            return Err(StakingError::DepositTooSmall);
        }

        let total_shares = self
            .total_shares
            .checked_add(minted)
            .ok_or(StakingError::Overflow)?;
        let total_stake = self
            .total_stake
            .checked_add(stake_amount)
            .ok_or(StakingError::Overflow)?;
        self.total_shares = total_shares;
        self.total_stake = total_stake;
        Ok(minted)
    }

    /// Redeems `shares_amount` at the current price (rounded down),
    /// returning the stake. The caller must already have checked the
    /// shares are the withdrawer's to redeem and debit their balance; as
    /// a backstop the pool itself refuses to redeem into the dead shares.
    pub fn withdraw(&mut self, shares_amount: u128) -> Result<u128, StakingError> {
        if shares_amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        if shares_amount > self.total_shares.saturating_sub(DEAD_SHARES) {
            return Err(StakingError::InsufficientShares);
        }

        let returned = stake_for_withdrawal(shares_amount, self.total_shares, self.total_stake)?;
        let total_shares = self
            .total_shares
            .checked_sub(shares_amount)
            .ok_or(StakingError::Overflow)?;
        let total_stake = self
            .total_stake
            .checked_sub(returned)
            .ok_or(StakingError::Overflow)?;
        self.total_shares = total_shares;
        self.total_stake = total_stake;
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
    /// production if violated." `holders_shares` is the sum of every
    /// holder's balance, which the caller reads from the ledger. Checks
    /// two things: that sum plus the dead shares equals `total_shares`
    /// (catches a mint/burn accounting bug), and `total_shares * price`
    /// matches `total_stake` within one part in `2^PRICE_FRAC_BITS`
    /// (catches drift between the two if a future change ever lets them
    /// be updated independently).
    pub fn assert_invariant(&self, holders_shares: u128) -> Result<(), StakingError> {
        let ledger_sum = holders_shares
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

impl Encode for StakingPool {
    fn encode(&self, out: &mut Vec<u8>) {
        self.total_shares.encode(out);
        self.total_stake.encode(out);
    }
}

impl Decode for StakingPool {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (total_shares, offset) = u128::decode(input)?;
        let (total_stake, offset) = decode_field::<u128>(input, offset)?;
        Ok((
            Self {
                total_shares,
                total_stake,
            },
            offset,
        ))
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use chain_types::codec::decode_exact;
    use chain_types::collections::BTreeMap;
    use chain_types::Address;
    use proptest::prelude::*;

    /// A pool together with the per-staker ledger the registry keeps in
    /// storage: the ledger-side checks (a withdrawal is of the withdrawer's
    /// own shares) and bookkeeping (balances move with the totals) that
    /// the pool itself no longer holds, so its arithmetic can be tested
    /// through the same scenarios as ever.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Ledgered {
        pool: StakingPool,
        balances: BTreeMap<Address, u128>,
    }

    impl Ledgered {
        fn genesis() -> Self {
            Self {
                pool: StakingPool::genesis(),
                balances: BTreeMap::new(),
            }
        }

        fn balance_of(&self, staker: &Address) -> u128 {
            self.balances.get(staker).copied().unwrap_or(0)
        }

        fn deposit(&mut self, staker: Address, amount: u128) -> Result<u128, StakingError> {
            let minted = self.pool.deposit(amount)?;
            let updated = self.balance_of(&staker).checked_add(minted).unwrap();
            self.balances.insert(staker, updated);
            Ok(minted)
        }

        fn withdraw(&mut self, staker: Address, shares: u128) -> Result<u128, StakingError> {
            if shares > self.balance_of(&staker) {
                return Err(StakingError::InsufficientShares);
            }
            let returned = self.pool.withdraw(shares)?;
            let remaining = self.balance_of(&staker).checked_sub(shares).unwrap();
            if remaining == 0 {
                self.balances.remove(&staker);
            } else {
                self.balances.insert(staker, remaining);
            }
            Ok(returned)
        }

        fn redeemable(&self, staker: &Address) -> u128 {
            self.pool.redeemable_for(self.balance_of(staker))
        }

        fn slash(&mut self, amount: u128) -> u128 {
            self.pool.slash(amount)
        }

        fn accrue_rewards(&mut self, amount: u128) -> Result<(), StakingError> {
            self.pool.accrue_rewards(amount)
        }

        fn price(&self) -> Result<U256, StakingError> {
            self.pool.price()
        }

        fn total_shares(&self) -> u128 {
            self.pool.total_shares()
        }

        fn total_stake(&self) -> u128 {
            self.pool.total_stake()
        }

        fn attributable_stake(&self) -> u128 {
            self.pool.attributable_stake()
        }

        fn assert_invariant(&self) -> Result<(), StakingError> {
            self.pool
                .assert_invariant(self.balances.values().copied().sum())
        }
    }

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    #[test]
    fn genesis_pool_satisfies_the_invariant() {
        let pool = Ledgered::genesis();
        assert!(pool.assert_invariant().is_ok());
        assert_eq!(pool.total_shares(), DEAD_SHARES);
        assert_eq!(pool.total_stake(), DEAD_SHARES);
    }

    #[test]
    fn deposit_then_withdraw_round_trips_at_constant_price() {
        let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
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
            let mut pool = Ledgered::genesis();
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
            let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
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
        let mut pool = Ledgered::genesis();
        pool.deposit(addr(1), 5_000).unwrap();
        pool.deposit(addr(2), 3_333).unwrap();
        pool.slash(777);
        pool.assert_invariant().unwrap();
        pool.accrue_rewards(50).unwrap();
        pool.assert_invariant().unwrap();
    }

    #[test]
    fn slashing_zero_burns_nothing() {
        let mut pool = Ledgered::genesis();
        pool.deposit(addr(1), 1_000).unwrap();
        let before = pool.clone();
        assert_eq!(pool.slash(0), 0);
        assert_eq!(pool, before);
    }

    #[test]
    fn slashing_never_burns_the_last_unit_of_stake() {
        let mut pool = Ledgered::genesis();
        pool.deposit(addr(1), 4_000).unwrap();
        let burned = pool.slash(u128::MAX);
        assert_eq!(burned, 4_999, "everything but one unit");
        assert_eq!(pool.total_stake(), 1);
        assert!(pool.price().is_ok());
        pool.assert_invariant().unwrap();
    }

    #[test]
    fn a_deposit_into_a_slashed_out_pool_is_priced_fairly_and_takes_nothing_from_others() {
        let mut pool = Ledgered::genesis();
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
    #[test]
    fn redeemable_is_what_a_full_withdrawal_would_pay() {
        let mut pool = Ledgered::genesis();
        pool.deposit(addr(1), 4_000).unwrap();
        pool.slash(500);
        let expected = pool.redeemable(&addr(1));
        assert_eq!(pool.withdraw(addr(1), 4_000).unwrap(), expected);
        assert_eq!(pool.redeemable(&addr(9)), 0, "a stranger holds nothing");
    }

    #[test]
    fn attributable_stake_excludes_only_the_dead_shares_worth() {
        let mut pool = Ledgered::genesis();
        assert_eq!(
            pool.attributable_stake(),
            0,
            "an empty pool has no one's stake"
        );
        pool.deposit(addr(1), 9_000).unwrap();
        assert_eq!(pool.attributable_stake(), 9_000);
        // Slashing shrinks the dead shares' stake along with everyone's.
        pool.slash(1_000);
        assert_eq!(pool.total_stake(), 9_000);
        assert_eq!(pool.attributable_stake(), 8_100);
        assert_eq!(pool.attributable_stake(), pool.redeemable(&addr(1)));
    }

    #[test]
    fn a_pool_round_trips_through_its_encoding() {
        let mut pool = StakingPool::genesis();
        pool.deposit(7_777).unwrap();
        pool.slash(123);
        let mut bytes = Vec::new();
        pool.encode(&mut bytes);
        assert_eq!(bytes.len(), 32, "two u128s, nothing else");
        assert_eq!(decode_exact::<StakingPool>(&bytes).unwrap(), pool);
        assert!(decode_exact::<StakingPool>(&bytes[..31]).is_err());
    }

    #[test]
    fn from_totals_rebuilds_what_the_totals_describe() {
        let mut pool = StakingPool::genesis();
        pool.deposit(9_000).unwrap();
        let rebuilt = StakingPool::from_totals(pool.total_shares(), pool.total_stake());
        assert_eq!(rebuilt, pool);
    }

    #[test]
    fn the_pool_itself_refuses_to_redeem_into_the_dead_shares() {
        // The ledger stops this first; the pool backs it up.
        let mut pool = StakingPool::genesis();
        pool.deposit(5_000).unwrap();
        assert_eq!(pool.total_shares(), 6_000);
        assert_eq!(
            pool.withdraw(5_001),
            Err(StakingError::InsufficientShares),
            "5_001 would eat a dead share"
        );
        assert!(pool.withdraw(5_000).is_ok());
        assert_eq!(pool.total_shares(), DEAD_SHARES);
    }

    #[test]
    fn a_failed_deposit_or_withdrawal_leaves_the_pool_untouched() {
        let mut pool = StakingPool::genesis();
        pool.deposit(5_000).unwrap();
        let before = pool;
        assert!(pool.deposit(0).is_err());
        assert!(pool.withdraw(0).is_err());
        assert!(pool.withdraw(u128::MAX).is_err());
        assert_eq!(pool, before);
    }

    #[test]
    fn the_invariant_notices_a_ledger_that_does_not_add_up() {
        let mut pool = StakingPool::genesis();
        let minted = pool.deposit(5_000).unwrap();
        assert!(pool.assert_invariant(minted).is_ok());
        assert_eq!(
            pool.assert_invariant(minted - 1),
            Err(StakingError::InvariantViolated),
            "a share missing from the ledger"
        );
        assert_eq!(
            pool.assert_invariant(minted + 1),
            Err(StakingError::InvariantViolated),
            "a share too many"
        );
    }
}
