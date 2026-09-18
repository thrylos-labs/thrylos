//! The account state this crate needs, and nothing else. `chain-state`
//! does not yet have an account model (see its own crate doc comment:
//! that half of its scope is deliberately deferred), so this trait is
//! the same kind of typed seam `chain-engine-api::Engine` is for
//! consensus/execution — a contract with no implementation here,
//! satisfied later by whatever crate ends up owning account state, and
//! by a test double (see `pool`'s tests) until then.

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
