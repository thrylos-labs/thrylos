//! The account model: what `docs/spec.md`'s "Transaction validity"
//! table needs from chain state to check a transaction (sequence
//! number, balance) and what applying one does to that state
//! afterward. Previously deferred — see `crate`'s doc comment's
//! history — because it depended on MoveVM integration decisions that
//! are now made: an account's balance and sequence number are
//! plain fields, addressed by `chain_types::Address`, sharing the flat
//! `StateKey`/`StateValue` space with (but structurally unrelated to)
//! whatever a MoveVM integration stores under its own object/module
//! keys.

use chain_types::codec::{decode_exact, CodecError, Decode, Encode};
use chain_types::{Address, GasAmount, GasPrice, SequenceNumber};

use crate::key_value::{StateKey, StateValue};
use chain_types::collections::BTreeMap;

/// The key tag this module reserves in the shared flat `StateKey`
/// space (see `key_value`'s doc comment: a `StateKey` is just an
/// opaque, tagged byte string). Every other crate sharing this
/// keyspace must use a different first byte, or an account's
/// `StateKey` could collide with something else's — `chain-exec`'s own
/// `KeyTag` enum numbers its tags starting from `KEY_TAG + 1` for
/// exactly this reason, rather than choosing independently.
pub const KEY_TAG: u8 = 0;

fn account_key(address: Address) -> StateKey {
    let mut bytes = vec![KEY_TAG];
    bytes.extend_from_slice(address.as_bytes());
    StateKey::new(bytes)
}

/// Why a transaction fails the account-state checks from
/// `docs/spec.md`'s "Transaction validity" table. Distinct from that
/// table's other rows (chain ID, scheme byte, expiry, declared inputs)
/// which need no account state at all to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountError {
    /// Below `next_sequence_number`: already executed, or a replay.
    SequenceNumberTooLow,
    /// Above `next_sequence_number`: a gap. "Strictly increments per
    /// sender, no gaps accepted" rules this out just as firmly as a
    /// replay — a gap would mean applying transactions out of order,
    /// which isn't a well-defined state transition.
    SequenceNumberTooHigh,
    /// `gas_limit * max_fee_per_gas` — the worst case, since the real
    /// cost isn't known until execution finishes — exceeds `balance`.
    InsufficientBalance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    pub balance: u128,
    pub next_sequence_number: SequenceNumber,
}

impl Account {
    /// Checks the two "Transaction validity" rows that need account
    /// state, against this account as it stands right now. Does not
    /// mutate anything — see [`Self::apply_transaction`] for the
    /// effect a transaction actually has once it's allowed to run.
    pub fn check(
        &self,
        sequence_number: SequenceNumber,
        gas_limit: GasAmount,
        max_fee_per_gas: GasPrice,
    ) -> Result<(), AccountError> {
        if sequence_number < self.next_sequence_number {
            return Err(AccountError::SequenceNumberTooLow);
        }
        if sequence_number > self.next_sequence_number {
            return Err(AccountError::SequenceNumberTooHigh);
        }
        let max_cost = u128::from(gas_limit.0).saturating_mul(u128::from(max_fee_per_gas.0));
        if max_cost > self.balance {
            return Err(AccountError::InsufficientBalance);
        }
        Ok(())
    }

    /// The effect a transaction that was allowed to run has on its
    /// sender, regardless of whether it later aborts: the sequence
    /// number advances by exactly one, and the real cost (`gas_used`,
    /// not the declared `gas_limit` this account was checked against)
    /// is debited. `docs/spec.md`, "Execution": "Aborts consume gas
    /// and roll back the transaction's effects, but never abort the
    /// block" — this is that consumption, independent of the rollback.
    ///
    /// `gas_used` is trusted to be at most the `gas_limit` this
    /// account was already checked to afford — `saturating_sub` is
    /// defensive, not a substitute for that check, and never panics
    /// even if a caller violates it.
    pub fn apply_transaction(&self, gas_used: GasAmount, max_fee_per_gas: GasPrice) -> Self {
        let fee = u128::from(gas_used.0).saturating_mul(u128::from(max_fee_per_gas.0));
        Self {
            balance: self.balance.saturating_sub(fee),
            next_sequence_number: SequenceNumber(self.next_sequence_number.0.saturating_add(1)),
        }
    }
}

impl Encode for Account {
    fn encode(&self, out: &mut Vec<u8>) {
        self.balance.encode(out);
        self.next_sequence_number.encode(out);
    }
}

impl Decode for Account {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (balance, offset) = u128::decode(input)?;
        let (next_sequence_number, offset) =
            chain_types::codec::decode_field::<SequenceNumber>(input, offset)?;
        Ok((
            Self {
                balance,
                next_sequence_number,
            },
            offset,
        ))
    }
}

/// `address`'s account, or the default (zero balance, sequence number
/// zero) for an address that has never transacted. A key that exists
/// but fails to decode is a real error (corruption, or a schema
/// mismatch), surfaced rather than silently treated as either case.
pub fn read_account(
    state: &BTreeMap<StateKey, StateValue>,
    address: Address,
) -> Result<Account, CodecError> {
    match state.get(&account_key(address)) {
        Some(value) => decode_exact(value.as_bytes()),
        None => Ok(Account::default()),
    }
}

pub fn write_account(
    state: &mut BTreeMap<StateKey, StateValue>,
    address: Address,
    account: Account,
) {
    let mut bytes = Vec::new();
    account.encode(&mut bytes);
    state.insert(account_key(address), StateValue::new(bytes));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chain_types::{GasAmount, GasPrice};

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    #[test]
    fn a_never_seen_address_reads_as_the_default_account() {
        let state = BTreeMap::new();
        assert_eq!(read_account(&state, addr(1)).unwrap(), Account::default());
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut state = BTreeMap::new();
        let account = Account {
            balance: 1_000,
            next_sequence_number: SequenceNumber(3),
        };
        write_account(&mut state, addr(2), account);
        assert_eq!(read_account(&state, addr(2)).unwrap(), account);
    }

    #[test]
    fn different_addresses_never_collide() {
        let mut state = BTreeMap::new();
        write_account(
            &mut state,
            addr(1),
            Account {
                balance: 1,
                next_sequence_number: SequenceNumber(0),
            },
        );
        write_account(
            &mut state,
            addr(2),
            Account {
                balance: 2,
                next_sequence_number: SequenceNumber(0),
            },
        );
        assert_eq!(read_account(&state, addr(1)).unwrap().balance, 1);
        assert_eq!(read_account(&state, addr(2)).unwrap().balance, 2);
    }

    #[test]
    fn check_rejects_a_sequence_number_below_the_next_expected() {
        let account = Account {
            balance: 1_000_000,
            next_sequence_number: SequenceNumber(5),
        };
        assert_eq!(
            account.check(SequenceNumber(4), GasAmount(1), GasPrice(1)),
            Err(AccountError::SequenceNumberTooLow)
        );
    }

    #[test]
    fn check_rejects_a_sequence_number_above_the_next_expected() {
        let account = Account {
            balance: 1_000_000,
            next_sequence_number: SequenceNumber(5),
        };
        assert_eq!(
            account.check(SequenceNumber(6), GasAmount(1), GasPrice(1)),
            Err(AccountError::SequenceNumberTooHigh)
        );
    }

    #[test]
    fn check_accepts_exactly_the_next_expected_sequence_number() {
        let account = Account {
            balance: 1_000_000,
            next_sequence_number: SequenceNumber(5),
        };
        assert_eq!(
            account.check(SequenceNumber(5), GasAmount(1), GasPrice(1)),
            Ok(())
        );
    }

    #[test]
    fn check_rejects_a_balance_that_cannot_cover_gas_limit_at_max_price() {
        let account = Account {
            balance: 99,
            next_sequence_number: SequenceNumber(0),
        };
        assert_eq!(
            account.check(SequenceNumber(0), GasAmount(10), GasPrice(10)),
            Err(AccountError::InsufficientBalance)
        );
    }

    #[test]
    fn check_accepts_a_balance_exactly_covering_gas_limit_at_max_price() {
        let account = Account {
            balance: 100,
            next_sequence_number: SequenceNumber(0),
        };
        assert_eq!(
            account.check(SequenceNumber(0), GasAmount(10), GasPrice(10)),
            Ok(())
        );
    }

    #[test]
    fn apply_transaction_debits_gas_used_not_gas_limit_and_advances_sequence() {
        let account = Account {
            balance: 1_000,
            next_sequence_number: SequenceNumber(0),
        };
        // Checked against a gas_limit of 100, but only 40 was used.
        let after = account.apply_transaction(GasAmount(40), GasPrice(2));
        assert_eq!(after.balance, 1_000 - 80);
        assert_eq!(after.next_sequence_number, SequenceNumber(1));
    }

    #[test]
    fn apply_transaction_never_underflows_balance() {
        let account = Account {
            balance: 5,
            next_sequence_number: SequenceNumber(0),
        };
        let after = account.apply_transaction(GasAmount(100), GasPrice(100));
        assert_eq!(after.balance, 0);
    }
}
