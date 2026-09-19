//! Supply accounting, and the check that a block did not create or destroy
//! value.
//!
//! The chain records its total supply in state, and every unit it counts is
//! held in exactly one of three places: an account's balance, a validator's
//! staking pool, or an unbonding entry that still owes it. Coin enters the
//! supply only through a genesis allocation or a reward mint, and leaves
//! only when a fee or a slash burns it; moving between the three places is
//! not a change of supply. So at every block boundary
//!
//! ```text
//! supply == sum(account balances) + sum(pool stakes) + sum(unbonding entries)
//! ```
//!
//! `docs/spec.md`, "Native modules": "assert ... as a block-level
//! invariant that halts block production if violated." Summing every
//! account on every block would make a block's cost grow with the chain,
//! so [`check_block_conservation`] checks the *change* instead: over just
//! the keys the block wrote or removed, what the supply moved by must
//! equal what those keys' holdings moved by. It is exact — a block that
//! creates or loses a single unit anywhere it touched fails — and costs
//! what the block's diff costs. What it cannot see is a key the block
//! changed *wrongly without changing it*, so [`total_held`] is the full
//! sum, for the periodic audit and for tests.
//!
//! What counts as held is decided here, by key: an account key by its
//! balance, a module key by `chain_modules::coin_held_by_entry`, and
//! nothing else holds anything. A state entry that holds coin under a key
//! this does not recognise would be invisible to the check, which is why
//! the recognised set is short and every new coin-holding kind must be
//! added to it.

use chain_state::{StateChange, StateKey, StateValue};
use chain_types::codec::{decode_exact, Encode};
use chain_types::collections::BTreeMap;

use crate::keys::{module_state_tag, supply_key};

type State = BTreeMap<StateKey, StateValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingError {
    /// The supply entry is missing or does not decode.
    SupplyUnreadable,
    /// An entry this check must read does not decode.
    Corrupt,
    /// The supply and the holdings disagree: value was created or lost.
    Unbalanced,
}

/// The total supply recorded in `state`.
pub fn read_supply(state: &State) -> Option<u128> {
    decode_exact(state.get(&supply_key())?.as_bytes()).ok()
}

pub fn write_supply(state: &mut State, supply: u128) {
    let mut bytes = Vec::new();
    supply.encode(&mut bytes);
    state.insert(supply_key(), StateValue::new(bytes));
}

/// The coin held by the entry at `key` with `value`, or `0` for an entry
/// that holds none. The supply entry itself is not a holding.
fn held_by(key: &StateKey, value: &StateValue) -> Result<u128, AccountingError> {
    let bytes = key.as_bytes();
    match bytes.first() {
        Some(&kind) if kind == chain_state::account::KEY_TAG => {
            let account: chain_state::Account =
                decode_exact(value.as_bytes()).map_err(|_| AccountingError::Corrupt)?;
            Ok(account.balance)
        }
        Some(&kind) if kind == module_state_tag() => {
            let module_key = bytes.get(1..).ok_or(AccountingError::Corrupt)?;
            chain_modules::coin_held_by_entry(module_key, value.as_bytes())
                .map_err(|_| AccountingError::Corrupt)
        }
        _ => Ok(0),
    }
}

/// Checks that going from `old` to `new` moved the supply by exactly what
/// the changed entries' holdings moved by. Reads only the entries that
/// differ. `old` must itself have been balanced.
pub fn check_block_conservation(old: &State, new: &State) -> Result<(), AccountingError> {
    let supply_old = read_supply(old).ok_or(AccountingError::SupplyUnreadable)?;
    let supply_new = read_supply(new).ok_or(AccountingError::SupplyUnreadable)?;

    // supply_new - supply_old == held_new - held_old, over the changed
    // entries, rearranged so nothing can go below zero.
    let mut held_old = 0u128;
    let mut held_new = 0u128;
    for (key, change) in chain_state::diff(old, new).iter() {
        if let Some(before) = old.get(key) {
            held_old = held_old
                .checked_add(held_by(key, before)?)
                .ok_or(AccountingError::Unbalanced)?;
        }
        if let StateChange::Put(after) = change {
            held_new = held_new
                .checked_add(held_by(key, after)?)
                .ok_or(AccountingError::Unbalanced)?;
        }
    }
    let left = supply_new
        .checked_add(held_old)
        .ok_or(AccountingError::Unbalanced)?;
    let right = supply_old
        .checked_add(held_new)
        .ok_or(AccountingError::Unbalanced)?;
    if left == right {
        Ok(())
    } else {
        Err(AccountingError::Unbalanced)
    }
}

/// Everything held anywhere in `state`, by reading all of it. O(state):
/// what an audit or a test compares the supply against.
pub fn total_held(state: &State) -> Result<u128, AccountingError> {
    let mut total = 0u128;
    for (key, value) in state {
        total = total
            .checked_add(held_by(key, value)?)
            .ok_or(AccountingError::Unbalanced)?;
    }
    Ok(total)
}

/// Whether `state` is balanced: the recorded supply equals everything held.
pub fn audit_supply(state: &State) -> Result<(), AccountingError> {
    let supply = read_supply(state).ok_or(AccountingError::SupplyUnreadable)?;
    if supply == total_held(state)? {
        Ok(())
    } else {
        Err(AccountingError::Unbalanced)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use blst::min_pk::SecretKey;
    use chain_modules::params::GENESIS_PARAM_VALUES;
    use chain_modules::store::MemStore;
    use chain_modules::{StakingRegistry, ValidatorId};
    use chain_state::account::{read_account, write_account};
    use chain_types::Address;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    fn state_with(balances: &[(u8, u128)], supply: u128) -> State {
        let mut state = State::new();
        for (who, balance) in balances {
            write_account(
                &mut state,
                addr(*who),
                chain_state::Account {
                    balance: *balance,
                    ..Default::default()
                },
            );
        }
        write_supply(&mut state, supply);
        state
    }

    fn credit(state: &mut State, who: u8, delta: i128) {
        let mut account = read_account(state, addr(who)).unwrap();
        account.balance = account.balance.checked_add_signed(delta).unwrap();
        write_account(state, addr(who), account);
    }

    #[test]
    fn a_balanced_state_audits_and_an_unbalanced_one_does_not() {
        let state = state_with(&[(1, 600), (2, 400)], 1_000);
        assert_eq!(audit_supply(&state), Ok(()));
        assert_eq!(total_held(&state), Ok(1_000));

        let short = state_with(&[(1, 600), (2, 400)], 999);
        assert_eq!(audit_supply(&short), Err(AccountingError::Unbalanced));
    }

    #[test]
    fn a_transfer_between_accounts_conserves() {
        let old = state_with(&[(1, 600), (2, 400)], 1_000);
        let mut new = old.clone();
        credit(&mut new, 1, -100);
        credit(&mut new, 2, 100);
        assert_eq!(check_block_conservation(&old, &new), Ok(()));
    }

    #[test]
    fn a_burn_must_lower_the_supply_by_exactly_what_it_took() {
        let old = state_with(&[(1, 600), (2, 400)], 1_000);
        let mut burned = old.clone();
        credit(&mut burned, 1, -25);
        write_supply(&mut burned, 975);
        assert_eq!(check_block_conservation(&old, &burned), Ok(()));

        // The balance fell but the supply did not: 25 units vanished.
        let mut lost = old.clone();
        credit(&mut lost, 1, -25);
        assert_eq!(
            check_block_conservation(&old, &lost),
            Err(AccountingError::Unbalanced)
        );

        // The supply fell by more than was taken.
        let mut over = burned.clone();
        write_supply(&mut over, 974);
        assert_eq!(
            check_block_conservation(&old, &over),
            Err(AccountingError::Unbalanced)
        );
    }

    #[test]
    fn coin_appearing_from_nowhere_is_caught_even_by_one_unit() {
        let old = state_with(&[(1, 600), (2, 400)], 1_000);
        let mut minted = old.clone();
        credit(&mut minted, 1, 1);
        assert_eq!(
            check_block_conservation(&old, &minted),
            Err(AccountingError::Unbalanced)
        );
        write_supply(&mut minted, 1_001);
        assert_eq!(check_block_conservation(&old, &minted), Ok(()));
    }

    #[test]
    fn a_new_account_and_an_account_read_as_zero_both_count() {
        let old = state_with(&[(1, 1_000)], 1_000);
        let mut new = old.clone();
        credit(&mut new, 1, -300);
        credit(&mut new, 9, 300); // never existed before
        assert_eq!(check_block_conservation(&old, &new), Ok(()));
    }

    #[test]
    fn coin_moving_into_a_pool_and_back_out_conserves() {
        let validator = ValidatorId(addr(7));
        let sk = SecretKey::key_gen(&[3u8; 32], &[]).unwrap();
        let key = chain_types::BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
        let pop = chain_types::bls::BlsSignature::from_bytes(
            sk.sign(
                &key.to_bytes(),
                chain_types::bls::DST_PROOF_OF_POSSESSION,
                &[],
            )
            .to_bytes(),
        )
        .unwrap();
        let params = chain_modules::GovernedParams::new(GENESIS_PARAM_VALUES).unwrap();
        let self_stake = GENESIS_PARAM_VALUES.min_self_stake;

        let mut registry = StakingRegistry::new(MemStore::new());
        registry
            .register_validator(&params, validator, addr(7), key, &pop, self_stake)
            .unwrap();
        let module_entries: Vec<(Vec<u8>, Vec<u8>)> = registry
            .store()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // Before: the registrant holds the cost of the pool. After: it is
        // in the pool (the validator record and its share entry).
        let cost = self_stake + chain_modules::DEAD_SHARES;
        let old = state_with(&[(7, cost)], cost);
        let mut new = state_with(&[(7, 0)], cost);
        for (key, value) in &module_entries {
            let mut state_key = vec![module_state_tag()];
            state_key.extend_from_slice(key);
            new.insert(StateKey::new(state_key), StateValue::new(value.clone()));
        }
        assert_eq!(check_block_conservation(&old, &new), Ok(()));
        assert_eq!(audit_supply(&new), Ok(()));

        // The same move with the pool one unit short is caught.
        let mut short = new.clone();
        credit(&mut short, 7, 1);
        assert_eq!(
            check_block_conservation(&old, &short),
            Err(AccountingError::Unbalanced)
        );
    }

    #[test]
    fn unreadable_supply_or_a_corrupt_entry_is_an_error_not_a_pass() {
        let old = state_with(&[(1, 10)], 10);

        let mut no_supply = old.clone();
        no_supply.remove(&supply_key());
        assert_eq!(
            check_block_conservation(&old, &no_supply),
            Err(AccountingError::SupplyUnreadable)
        );

        let mut corrupt = old.clone();
        corrupt.insert(
            chain_state::account::account_key(addr(1)),
            StateValue::new(vec![1, 2, 3]),
        );
        assert_eq!(
            check_block_conservation(&old, &corrupt),
            Err(AccountingError::Corrupt)
        );
    }

    #[test]
    fn entries_that_hold_no_coin_are_ignored() {
        let old = state_with(&[(1, 10)], 10);
        let mut new = old.clone();
        new.insert(crate::keys::base_fee_key(), StateValue::new(vec![9; 8]));
        new.insert(
            crate::keys::time_checkpoint_key(5),
            StateValue::new(vec![1; 8]),
        );
        assert_eq!(check_block_conservation(&old, &new), Ok(()));
    }
}
