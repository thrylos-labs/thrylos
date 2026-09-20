//! The account state this crate needs, and nothing else. [`AccountView`]
//! is the same kind of typed seam `chain-engine-api::Engine` is for
//! consensus/execution: this crate depends on the contract, not on how
//! a caller keeps account state up to date. [`StateAccountView`] is the
//! real implementation, backed by `chain-state`'s account model
//! (`chain_state::account`) — a mempool in practice reads this against
//! a snapshot of canonical chain-tip state, most likely one `chain-exec`
//! exposes, though this crate depends only on `chain-state`, not on
//! `chain-exec` itself.

use chain_types::collections::BTreeMap;
use chain_types::Address;

/// Read-only view onto one account's admission-relevant state, as of
/// the current canonical chain tip.
pub trait AccountView {
    /// The sequence number this account's next transaction must carry:
    /// one past the highest sequence number ever executed on-chain for
    /// `address`, or `0` for an address that has never transacted. See
    /// `docs/spec.md`, "Transaction validity": "strictly increasing,
    /// no gaps".
    fn next_sequence_number(&self, address: &Address) -> chain_types::SequenceNumber;

    /// Spendable balance, in the smallest denomination. Used only for
    /// the "balance covers max fee" admission check (`docs/spec.md`,
    /// "P2P and mempool": "signature, nonce, balance-covers-max-fee") —
    /// a conservative check against the transaction's own declared
    /// ceiling, not a debit against anything this transaction actually
    /// spends.
    fn balance(&self, address: &Address) -> u128;
}

/// [`AccountView`] over a real flat chain-state snapshot
/// (`chain_state::StateKey`/`StateValue`, the same shape `chain-exec`
/// executes against and `chain-db` persists). A key that fails to
/// decode as an [`chain_state::Account`] — corruption, or a schema
/// mismatch — is treated as the default account rather than
/// propagating an error: unlike `chain-state`'s own `read_account`,
/// this trait's methods have no `Result` to return it through, and a
/// mempool erring toward "this sender can't afford anything" on
/// corrupt input is the safe direction to fail in.
pub struct StateAccountView<'a> {
    state: &'a BTreeMap<chain_state::StateKey, chain_state::StateValue>,
}

impl<'a> StateAccountView<'a> {
    pub const fn new(state: &'a BTreeMap<chain_state::StateKey, chain_state::StateValue>) -> Self {
        Self { state }
    }
}

impl AccountView for StateAccountView<'_> {
    fn next_sequence_number(&self, address: &Address) -> chain_types::SequenceNumber {
        chain_state::account::read_account(self.state, *address)
            .map(|account| account.next_sequence_number)
            .unwrap_or_default()
    }

    fn balance(&self, address: &Address) -> u128 {
        chain_state::account::read_account(self.state, *address)
            .map(|account| account.balance)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_state::account::write_account;
    use chain_state::Account;
    use chain_types::SequenceNumber;

    #[test]
    fn reads_a_real_account_written_into_chain_state() {
        let mut state = BTreeMap::new();
        let address = Address::from_bytes([1u8; 32]);
        write_account(
            &mut state,
            address,
            Account {
                balance: 500,
                next_sequence_number: SequenceNumber(3),
            },
        );

        let view = StateAccountView::new(&state);
        assert_eq!(view.balance(&address), 500);
        assert_eq!(view.next_sequence_number(&address), SequenceNumber(3));
    }

    #[test]
    fn a_never_seen_address_reads_as_the_default_account() {
        let state = BTreeMap::new();
        let address = Address::from_bytes([2u8; 32]);

        let view = StateAccountView::new(&state);
        assert_eq!(view.balance(&address), 0);
        assert_eq!(view.next_sequence_number(&address), SequenceNumber(0));
    }
}
