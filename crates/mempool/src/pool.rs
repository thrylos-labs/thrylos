//! The pending-transaction pool: admission, fee-bump replacement,
//! effective-fee eviction, and fee-ordered candidate selection for
//! block proposal. See `docs/spec.md`, "P2P and mempool": "Mempool
//! admission charges full validation cost before accepting: signature,
//! nonce, balance-covers-max-fee. Replacement requires a strict fee
//! bump above a floor... Eviction is by effective fee with a per-sender
//! cap on pending transactions."
//!
//! "Effective fee" here is just `max_fee_per_gas`. The chain does have a
//! base fee now (`chain_modules::fees`), but every transaction in a
//! block pays exactly that, with no priority tip on top —
//! `chain_types::TransactionBody` has only the one price field — so
//! there is no priority fee to rank by, and `max_fee_per_gas` remains
//! the only signal of how much a sender is willing to pay. Its one
//! consequence for this file is [`Mempool::candidate_transactions`]:
//! a transaction whose ceiling is below the current base fee cannot be
//! included, and offering one would make the proposed block invalid.

use std::collections::BinaryHeap;

use chain_types::collections::BTreeMap;
use chain_types::{Address, BlockHeight, ChainId, SequenceNumber, Transaction};

use crate::account_view::AccountView;

/// Why a transaction was refused admission. Distinct from
/// `chain_engine_api::RejectionReason`, which is about a transaction
/// already inside a *block*; this is about a transaction the mempool
/// itself declines to hold at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    WrongChainId,
    InvalidSignature,
    InvalidExpiry,
    /// Below the sender's on-chain next sequence number: already
    /// executed, or otherwise unreachable.
    SequenceNumberTooLow,
    /// `gas_limit * max_fee_per_gas` exceeds the sender's balance.
    InsufficientBalance,
    /// A transaction is already pending at this `(sender,
    /// sequence_number)` and the new one's fee does not clear
    /// `MempoolConfig::min_replacement_fee_bump_percent` above it.
    ReplacementFeeTooLow,
    /// The sender already has `MempoolConfig::max_pending_per_sender`
    /// distinct sequence numbers pending, and this isn't a replacement
    /// of one of them.
    PerSenderPendingLimitReached,
}

impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongChainId => f.write_str("the chain ID is missing or is not this chain's"),
            Self::InvalidSignature => f.write_str("the signature does not verify against the sender"),
            Self::InvalidExpiry => f.write_str("the transaction has expired, or expires too far ahead"),
            Self::SequenceNumberTooLow => f.write_str("the sequence number is below the sender's next one: already executed"),
            Self::InsufficientBalance => f.write_str("the sender's balance is below the worst-case fee, gas limit times max fee per gas"),
            Self::ReplacementFeeTooLow => f.write_str("a transaction is already pending at this sequence number and the fee is not raised enough to replace it"),
            Self::PerSenderPendingLimitReached => f.write_str("the sender already has the maximum number of pending transactions"),
        }
    }
}

impl std::error::Error for AdmissionError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolConfig {
    pub chain_id: ChainId,
    /// Hard cap on total pending transactions across every sender.
    /// Admission past this cap succeeds only by evicting the
    /// globally-lowest-fee pending transaction first.
    pub max_pool_size: usize,
    /// Hard cap on distinct pending sequence numbers for one sender —
    /// bounds one sender's share of the pool independent of fee, so a
    /// single well-funded sender can't crowd out everyone else.
    pub max_pending_per_sender: usize,
    /// Minimum percentage a replacement's `max_fee_per_gas` must clear
    /// the transaction it replaces by, e.g. `10` means at least 10%
    /// higher, not merely higher.
    pub min_replacement_fee_bump_percent: u64,
}

/// Whether `new_fee` clears `old_fee` by at least `bump_percent`
/// percent, computed as `new_fee * 100 >= old_fee * (100 +
/// bump_percent)` — cross-multiplied so no division is needed
/// (`docs/spec.md`'s determinism rules deny integer division outright,
/// and this crate's checks should hold to the same discipline even
/// though the mempool itself isn't tier A).
fn clears_replacement_bump(old_fee: u64, new_fee: u64, bump_percent: u64) -> bool {
    let Some(multiplier) = bump_percent.checked_add(100) else {
        return false;
    };
    let Some(lhs) = u128::from(new_fee).checked_mul(100) else {
        return false;
    };
    let Some(rhs) = u128::from(old_fee).checked_mul(u128::from(multiplier)) else {
        return false;
    };
    lhs >= rhs
}

/// A pending transaction ranked by fee for eviction/selection, without
/// cloning the whole `Transaction` just to compare it. Ties break on
/// `(sender, sequence_number)` purely so ordering is total and
/// reproducible in tests, not because cross-node determinism matters
/// here (candidate selection is each node's own local choice, not part
/// of the state transition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RankedSlot {
    fee: u64,
    sender: Address,
    sequence_number: SequenceNumber,
}

pub struct Mempool<A> {
    config: MempoolConfig,
    accounts: A,
    pending: BTreeMap<Address, BTreeMap<SequenceNumber, Transaction>>,
    size: usize,
}

impl<A: AccountView> Mempool<A> {
    pub fn new(config: MempoolConfig, accounts: A) -> Self {
        Self {
            config,
            accounts,
            pending: BTreeMap::new(),
            size: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Every pending transaction, in no particular order. For a caller that
    /// wants to find one it was told of by something other than its hash (a
    /// block announced in compact form).
    pub fn pending(&self) -> impl Iterator<Item = &Transaction> {
        self.pending.values().flat_map(BTreeMap::values)
    }

    pub fn contains(&self, sender: &Address, sequence_number: SequenceNumber) -> bool {
        self.pending
            .get(sender)
            .is_some_and(|by_sequence| by_sequence.contains_key(&sequence_number))
    }

    /// Validate and admit `tx`, evicting the globally-lowest-fee
    /// pending transaction if admitting it pushes the pool past
    /// `MempoolConfig::max_pool_size`.
    pub fn admit(
        &mut self,
        tx: Transaction,
        current_height: BlockHeight,
    ) -> Result<(), AdmissionError> {
        if tx.body.chain_id != self.config.chain_id {
            return Err(AdmissionError::WrongChainId);
        }
        if tx.verify_signature().is_err() {
            return Err(AdmissionError::InvalidSignature);
        }
        if !tx.is_expiry_valid(current_height) {
            return Err(AdmissionError::InvalidExpiry);
        }

        let sender = tx.sender_address();
        if tx.body.sequence_number < self.accounts.next_sequence_number(&sender) {
            return Err(AdmissionError::SequenceNumberTooLow);
        }

        let cost =
            u128::from(tx.body.gas_limit.0).checked_mul(u128::from(tx.body.max_fee_per_gas.0));
        match cost {
            Some(cost) if cost <= self.accounts.balance(&sender) => {}
            _ => return Err(AdmissionError::InsufficientBalance),
        }

        // `.entry().or_default()` inserts an empty inner map for a
        // brand-new sender even on a path that ends up rejecting `tx`
        // (reachable when `max_pending_per_sender` is misconfigured to
        // `0`) — `prune_if_empty` below undoes that so a rejected
        // sender never leaves a stray empty entry behind.
        let existing_for_sender = self.pending.entry(sender).or_default();
        let is_replacement = existing_for_sender.contains_key(&tx.body.sequence_number);

        if is_replacement {
            let existing_fee = existing_for_sender
                .get(&tx.body.sequence_number)
                .map(|existing| existing.body.max_fee_per_gas.0);
            let Some(existing_fee) = existing_fee else {
                return Err(AdmissionError::ReplacementFeeTooLow);
            };
            if !clears_replacement_bump(
                existing_fee,
                tx.body.max_fee_per_gas.0,
                self.config.min_replacement_fee_bump_percent,
            ) {
                return Err(AdmissionError::ReplacementFeeTooLow);
            }
            existing_for_sender.insert(tx.body.sequence_number, tx);
        } else if existing_for_sender.len() >= self.config.max_pending_per_sender {
            self.prune_if_empty(sender);
            return Err(AdmissionError::PerSenderPendingLimitReached);
        } else {
            existing_for_sender.insert(tx.body.sequence_number, tx);
            self.size = self.size.saturating_add(1);
        }

        if self.size > self.config.max_pool_size {
            self.evict_lowest_fee();
        }
        Ok(())
    }

    /// Remove `sender`'s entry if admission left it with no pending
    /// transactions. See the comment in `admit` on why this can happen.
    fn prune_if_empty(&mut self, sender: Address) {
        if self.pending.get(&sender).is_some_and(BTreeMap::is_empty) {
            self.pending.remove(&sender);
        }
    }

    /// Remove and return the pending transaction with the lowest fee,
    /// if any. Used both by `admit` when the pool is over capacity and
    /// directly by callers implementing their own back-pressure.
    pub fn evict_lowest_fee(&mut self) -> Option<Transaction> {
        let lowest = self
            .pending
            .iter()
            .flat_map(|(sender, by_sequence)| {
                by_sequence
                    .iter()
                    .map(move |(sequence_number, tx)| RankedSlot {
                        fee: tx.body.max_fee_per_gas.0,
                        sender: *sender,
                        sequence_number: *sequence_number,
                    })
            })
            .min()?;

        let by_sequence = self.pending.get_mut(&lowest.sender)?;
        let removed = by_sequence.remove(&lowest.sequence_number);
        if by_sequence.is_empty() {
            self.pending.remove(&lowest.sender);
        }
        if removed.is_some() {
            self.size = self.size.saturating_sub(1);
        }
        removed
    }

    /// Forgets what a committed block made stale, and says how many
    /// transactions that was.
    ///
    /// `touched` are the senders whose accounts the block changed (the ones
    /// with a transaction in it): for each, a pending transaction below the
    /// account's next sequence number has been executed (or superseded) and is
    /// dropped, and so is one whose worst-case fee the balance no longer
    /// covers. Every sender's transactions past their `expiry` at
    /// `current_height` are dropped too, since time passes for all of them.
    /// Anything else is left: a transaction is only removed for a reason the
    /// chain now shows.
    ///
    /// Reads the accounts as they are *now*, so it is called after the block
    /// has been finalised.
    pub fn prune_after_commit(
        &mut self,
        touched: &[Address],
        current_height: BlockHeight,
    ) -> usize {
        let before = self.size;
        for sender in touched {
            let next = self.accounts.next_sequence_number(sender);
            let balance = self.accounts.balance(sender);
            if let Some(by_sequence) = self.pending.get_mut(sender) {
                by_sequence.retain(|sequence_number, tx| {
                    let cost = u128::from(tx.body.gas_limit.0)
                        .checked_mul(u128::from(tx.body.max_fee_per_gas.0));
                    *sequence_number >= next && cost.is_some_and(|cost| cost <= balance)
                });
            }
        }
        for by_sequence in self.pending.values_mut() {
            by_sequence.retain(|_, tx| current_height.0 <= tx.body.expiry.0);
        }
        self.pending
            .retain(|_, by_sequence| !by_sequence.is_empty());
        self.size = self.pending.values().map(BTreeMap::len).sum();
        before.saturating_sub(self.size)
    }

    /// Up to `limit` pending transactions, highest fee first, honouring
    /// per-sender sequence order: a sender's transaction at sequence
    /// `n + 1` is only ever offered once its `n` has been. This is the
    /// "already ordered and selected" input `chain_engine_api::Engine::
    /// propose_block` expects.
    ///
    /// `base_fee` is the price the block being built will charge. A
    /// transaction whose `max_fee_per_gas` is below it is never
    /// offered — the executor rejects the whole block for including
    /// one — and, because a sender's transactions must run in order,
    /// neither is anything of that sender's queued behind it.
    pub fn candidate_transactions(&self, limit: usize, base_fee: u64) -> Vec<Transaction> {
        let mut ready: BinaryHeap<RankedSlot> = self
            .pending
            .iter()
            .filter_map(|(sender, by_sequence)| {
                let (sequence_number, tx) = by_sequence.iter().next()?;
                if tx.body.max_fee_per_gas.0 < base_fee {
                    return None;
                }
                Some(RankedSlot {
                    fee: tx.body.max_fee_per_gas.0,
                    sender: *sender,
                    sequence_number: *sequence_number,
                })
            })
            .collect();

        let mut selected = Vec::new();
        while selected.len() < limit {
            let Some(slot) = ready.pop() else { break };
            let Some(by_sequence) = self.pending.get(&slot.sender) else {
                continue;
            };
            let Some(tx) = by_sequence.get(&slot.sequence_number) else {
                continue;
            };
            selected.push(tx.clone());

            if let Some(next_sequence) = by_sequence.keys().find(|s| **s > slot.sequence_number) {
                if let Some(next_tx) = by_sequence.get(next_sequence) {
                    if next_tx.body.max_fee_per_gas.0 >= base_fee {
                        ready.push(RankedSlot {
                            fee: next_tx.body.max_fee_per_gas.0,
                            sender: slot.sender,
                            sequence_number: *next_sequence,
                        });
                    }
                }
            }
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use chain_types::{GasAmount, GasPrice, MoveCall, PublicKey, Signature};
    use ed25519_dalek::{Signer as _, SigningKey};

    struct MockAccounts {
        next_sequence: BTreeMap<Address, SequenceNumber>,
        balances: BTreeMap<Address, u128>,
    }

    impl MockAccounts {
        fn new() -> Self {
            Self {
                next_sequence: BTreeMap::new(),
                balances: BTreeMap::new(),
            }
        }

        fn with_balance(mut self, address: Address, balance: u128) -> Self {
            self.balances.insert(address, balance);
            self
        }
    }

    impl AccountView for MockAccounts {
        fn next_sequence_number(&self, address: &Address) -> SequenceNumber {
            self.next_sequence
                .get(address)
                .copied()
                .unwrap_or(SequenceNumber(0))
        }

        fn balance(&self, address: &Address) -> u128 {
            self.balances.get(address).copied().unwrap_or(0)
        }
    }

    fn signed_tx(
        seed: u8,
        chain_id: ChainId,
        sequence_number: u64,
        max_fee_per_gas: u64,
    ) -> Transaction {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let sender = PublicKey::from_ed25519_bytes(signing_key.verifying_key().to_bytes()).unwrap();
        let body = chain_types::TransactionBody {
            chain_id,
            sender,
            sequence_number: SequenceNumber(sequence_number),
            expiry: BlockHeight(1_000),
            gas_limit: GasAmount(1_000),
            max_fee_per_gas: GasPrice(max_fee_per_gas),
            declared_inputs: Vec::new(),
            call: MoveCall {
                module_address: Address::from_bytes([0u8; 32]),
                module_name: Vec::new(),
                function_name: Vec::new(),
                type_arguments: Vec::new(),
                arguments: Vec::new(),
            },
        };
        let mut signing_bytes = Vec::new();
        chain_types::Encode::encode(&body, &mut signing_bytes);
        let raw_sig = signing_key.sign(&signing_bytes);
        Transaction {
            body,
            signature: Signature::from_ed25519_bytes(raw_sig.to_bytes()),
        }
    }

    fn pool_with(sender_seeds: &[u8], txs: Vec<Transaction>) -> Mempool<MockAccounts> {
        let chain_id = ChainId(1);
        let mut accounts = MockAccounts::new();
        for seed in sender_seeds {
            accounts =
                accounts.with_balance(signed_tx(*seed, chain_id, 0, 1).sender_address(), 1_000_000);
        }
        let mut pool = Mempool::new(config(chain_id), accounts);
        for tx in txs {
            pool.admit(tx, BlockHeight(0)).unwrap();
        }
        pool
    }

    #[test]
    fn pending_lists_every_held_transaction_once_and_follows_the_pool() {
        let chain_id = ChainId(1);
        let mut pool = pool_with(
            &[1, 2],
            vec![
                signed_tx(1, chain_id, 0, 5),
                signed_tx(1, chain_id, 1, 5),
                signed_tx(2, chain_id, 0, 5),
            ],
        );
        assert_eq!(pool.pending().count(), 3);
        let one = signed_tx(1, chain_id, 0, 5).sender_address();
        pool.accounts.next_sequence.insert(one, SequenceNumber(1));
        pool.prune_after_commit(&[one], BlockHeight(1));
        let held: Vec<_> = pool
            .pending()
            .map(|tx| (tx.sender_address(), tx.body.sequence_number.0))
            .collect();
        assert_eq!(held.len(), 2);
        assert!(!held.contains(&(one, 0)));
        assert!(pool
            .pending()
            .all(|tx| pool.contains(&tx.sender_address(), tx.body.sequence_number)));
    }

    #[test]
    fn a_commit_drops_what_it_executed_and_only_that() {
        let chain_id = ChainId(1);
        let mut pool = pool_with(
            &[1, 2],
            vec![
                signed_tx(1, chain_id, 0, 5),
                signed_tx(1, chain_id, 1, 5),
                signed_tx(2, chain_id, 0, 5),
            ],
        );
        let one = signed_tx(1, chain_id, 0, 5).sender_address();
        let two = signed_tx(2, chain_id, 0, 5).sender_address();

        // Sender one's first transaction was executed: its next sequence is 1.
        pool.accounts.next_sequence.insert(one, SequenceNumber(1));
        assert_eq!(pool.prune_after_commit(&[one], BlockHeight(1)), 1);
        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&one, SequenceNumber(0)));
        assert!(
            pool.contains(&one, SequenceNumber(1)),
            "the one behind it stays"
        );
        assert!(
            pool.contains(&two, SequenceNumber(0)),
            "another sender's stays"
        );
    }

    #[test]
    fn a_commit_that_left_a_sender_unable_to_pay_drops_what_it_can_no_longer_cover() {
        let chain_id = ChainId(1);
        let mut pool = pool_with(
            &[1],
            vec![signed_tx(1, chain_id, 0, 5), signed_tx(1, chain_id, 1, 900)],
        );
        let one = signed_tx(1, chain_id, 0, 5).sender_address();
        // Worst-case fees: 1_000 gas at 5 is 5_000, and at 900 is 900_000. A
        // balance of 10_000 covers the first and not the second.
        pool.accounts.balances.insert(one, 10_000);
        assert_eq!(pool.prune_after_commit(&[one], BlockHeight(1)), 1);
        assert!(pool.contains(&one, SequenceNumber(0)));
        assert!(!pool.contains(&one, SequenceNumber(1)));
    }

    #[test]
    fn a_sender_the_block_did_not_touch_is_not_re_examined_for_its_account_but_expiry_is_for_everyone(
    ) {
        let chain_id = ChainId(1);
        let mut pool = pool_with(
            &[1, 2],
            vec![signed_tx(1, chain_id, 0, 5), signed_tx(2, chain_id, 0, 5)],
        );
        let one = signed_tx(1, chain_id, 0, 5).sender_address();
        let two = signed_tx(2, chain_id, 0, 5).sender_address();
        // Sender two is poorer now, but no block of theirs has committed, so
        // nothing is checked for them.
        pool.accounts.balances.insert(two, 0);
        assert_eq!(pool.prune_after_commit(&[one], BlockHeight(1)), 0);
        assert_eq!(pool.len(), 2);

        // Expiry is 1_000: at height 1_000 they are still good, past it gone,
        // whoever the block was from.
        assert_eq!(pool.prune_after_commit(&[], BlockHeight(1_000)), 0);
        assert_eq!(pool.prune_after_commit(&[], BlockHeight(1_001)), 2);
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn pruning_keeps_the_pool_consistent_with_what_it_holds() {
        let chain_id = ChainId(1);
        let mut pool = pool_with(
            &[1],
            vec![signed_tx(1, chain_id, 0, 5), signed_tx(1, chain_id, 1, 5)],
        );
        let one = signed_tx(1, chain_id, 0, 5).sender_address();
        pool.accounts.next_sequence.insert(one, SequenceNumber(2));
        assert_eq!(pool.prune_after_commit(&[one], BlockHeight(1)), 2);
        assert!(pool.is_empty());
        // Room again: a sender's slot is not left counted.
        assert!(pool.candidate_transactions(10, 0).is_empty());
        let fresh = signed_tx(1, chain_id, 2, 5);
        pool.accounts.balances.insert(one, 1_000_000);
        assert!(pool.admit(fresh, BlockHeight(1)).is_ok());
        assert_eq!(pool.len(), 1);
    }

    fn config(chain_id: ChainId) -> MempoolConfig {
        MempoolConfig {
            chain_id,
            max_pool_size: 10,
            max_pending_per_sender: 2,
            min_replacement_fee_bump_percent: 10,
        }
    }

    #[test]
    fn admits_a_well_formed_transaction() {
        let chain_id = ChainId(1);
        let tx = signed_tx(1, chain_id, 0, 5);
        let sender = tx.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert!(pool.admit(tx, BlockHeight(0)).is_ok());
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&sender, SequenceNumber(0)));
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let chain_id = ChainId(1);
        let tx = signed_tx(2, ChainId(2), 0, 5);
        let sender = tx.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert_eq!(
            pool.admit(tx, BlockHeight(0)),
            Err(AdmissionError::WrongChainId)
        );
    }

    #[test]
    fn rejects_a_tampered_signature() {
        let chain_id = ChainId(1);
        let mut tx = signed_tx(3, chain_id, 0, 5);
        tx.body.sequence_number = SequenceNumber(1);
        let sender = tx.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert_eq!(
            pool.admit(tx, BlockHeight(0)),
            Err(AdmissionError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_an_expired_transaction() {
        let chain_id = ChainId(1);
        let tx = signed_tx(4, chain_id, 0, 5); // expiry = BlockHeight(1_000)
        let sender = tx.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert_eq!(
            pool.admit(tx, BlockHeight(1_001)),
            Err(AdmissionError::InvalidExpiry)
        );
    }

    #[test]
    fn rejects_a_sequence_number_already_executed() {
        let chain_id = ChainId(1);
        let tx = signed_tx(5, chain_id, 0, 5);
        let sender = tx.sender_address();
        let mut accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        accounts.next_sequence.insert(sender, SequenceNumber(1));
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert_eq!(
            pool.admit(tx, BlockHeight(0)),
            Err(AdmissionError::SequenceNumberTooLow)
        );
    }

    #[test]
    fn rejects_insufficient_balance() {
        let chain_id = ChainId(1);
        let tx = signed_tx(6, chain_id, 0, 5); // gas_limit 1_000 * fee 5 = 5_000
        let sender = tx.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 4_999);
        let mut pool = Mempool::new(config(chain_id), accounts);

        assert_eq!(
            pool.admit(tx, BlockHeight(0)),
            Err(AdmissionError::InsufficientBalance)
        );
    }

    #[test]
    fn replacement_below_the_fee_bump_floor_is_rejected() {
        let chain_id = ChainId(1);
        let first = signed_tx(7, chain_id, 0, 100);
        let sender = first.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);
        pool.admit(first, BlockHeight(0)).unwrap();

        let replacement = signed_tx(7, chain_id, 0, 105); // +5%, floor is 10%
        assert_eq!(
            pool.admit(replacement, BlockHeight(0)),
            Err(AdmissionError::ReplacementFeeTooLow)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn replacement_clearing_the_fee_bump_floor_replaces_the_pending_transaction() {
        let chain_id = ChainId(1);
        let first = signed_tx(8, chain_id, 0, 100);
        let sender = first.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts);
        pool.admit(first, BlockHeight(0)).unwrap();

        let replacement = signed_tx(8, chain_id, 0, 111); // +11%, clears 10% floor
        assert!(pool.admit(replacement, BlockHeight(0)).is_ok());
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn per_sender_pending_limit_is_enforced() {
        let chain_id = ChainId(1);
        let tx0 = signed_tx(9, chain_id, 0, 5);
        let sender = tx0.sender_address();
        let accounts = MockAccounts::new().with_balance(sender, 1_000_000);
        let mut pool = Mempool::new(config(chain_id), accounts); // cap: 2 per sender
        pool.admit(tx0, BlockHeight(0)).unwrap();
        pool.admit(signed_tx(9, chain_id, 1, 5), BlockHeight(0))
            .unwrap();

        assert_eq!(
            pool.admit(signed_tx(9, chain_id, 2, 5), BlockHeight(0)),
            Err(AdmissionError::PerSenderPendingLimitReached)
        );
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn admitting_past_capacity_evicts_the_lowest_fee_transaction() {
        let chain_id = ChainId(1);
        let mut cfg = config(chain_id);
        cfg.max_pool_size = 2;
        cfg.max_pending_per_sender = 5;

        let low = signed_tx(10, chain_id, 0, 1);
        let mid = signed_tx(11, chain_id, 0, 5);
        let high = signed_tx(12, chain_id, 0, 9);
        let low_sender = low.sender_address();
        let mid_sender = mid.sender_address();
        let high_sender = high.sender_address();

        let accounts = MockAccounts::new()
            .with_balance(low_sender, u128::MAX)
            .with_balance(mid_sender, u128::MAX)
            .with_balance(high_sender, u128::MAX);
        let mut pool = Mempool::new(cfg, accounts);

        pool.admit(low, BlockHeight(0)).unwrap();
        pool.admit(mid, BlockHeight(0)).unwrap();
        assert_eq!(pool.len(), 2);

        pool.admit(high, BlockHeight(0)).unwrap();
        assert_eq!(pool.len(), 2, "pool must stay within max_pool_size");
        assert!(
            !pool.contains(&low_sender, SequenceNumber(0)),
            "lowest fee must be evicted"
        );
        assert!(pool.contains(&mid_sender, SequenceNumber(0)));
        assert!(pool.contains(&high_sender, SequenceNumber(0)));
    }

    #[test]
    fn candidate_transactions_are_ordered_by_fee_and_respect_sender_sequence_order() {
        let chain_id = ChainId(1);
        let cfg = config(chain_id);
        let sender_a_tx0 = signed_tx(13, chain_id, 0, 1); // low fee, but first in queue
        let sender_a_tx1 = signed_tx(13, chain_id, 1, 100); // high fee, but blocked behind tx0
        let sender_b_tx0 = signed_tx(14, chain_id, 0, 50);

        let sender_a = sender_a_tx0.sender_address();
        let sender_b = sender_b_tx0.sender_address();
        let accounts = MockAccounts::new()
            .with_balance(sender_a, u128::MAX)
            .with_balance(sender_b, u128::MAX);
        let mut pool = Mempool::new(cfg, accounts);
        pool.admit(sender_a_tx0, BlockHeight(0)).unwrap();
        pool.admit(sender_a_tx1, BlockHeight(0)).unwrap();
        pool.admit(sender_b_tx0, BlockHeight(0)).unwrap();

        let candidates = pool.candidate_transactions(10, 1);
        assert_eq!(candidates.len(), 3);
        // sender_b's single tx (fee 50) beats sender_a's *ready* tx
        // (sequence 0, fee 1) even though sender_a has a higher-fee tx
        // queued behind it — that one isn't ready yet.
        assert_eq!(candidates[0].sender_address(), sender_b);
        assert_eq!(candidates[1].sender_address(), sender_a);
        assert_eq!(candidates[1].body.sequence_number, SequenceNumber(0));
        assert_eq!(candidates[2].sender_address(), sender_a);
        assert_eq!(candidates[2].body.sequence_number, SequenceNumber(1));
    }

    #[test]
    fn candidate_transactions_respects_the_limit() {
        let chain_id = ChainId(1);
        let cfg = config(chain_id);
        let tx_a = signed_tx(15, chain_id, 0, 10);
        let tx_b = signed_tx(16, chain_id, 0, 20);
        let sender_a = tx_a.sender_address();
        let sender_b = tx_b.sender_address();
        let accounts = MockAccounts::new()
            .with_balance(sender_a, u128::MAX)
            .with_balance(sender_b, u128::MAX);
        let mut pool = Mempool::new(cfg, accounts);
        pool.admit(tx_a, BlockHeight(0)).unwrap();
        pool.admit(tx_b, BlockHeight(0)).unwrap();

        let candidates = pool.candidate_transactions(1, 1);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sender_address(), sender_b);
    }
    #[test]
    fn a_transaction_below_the_base_fee_is_never_offered() {
        let chain_id = ChainId(1);
        let cheap = signed_tx(60, chain_id, 0, 3);
        let fine = signed_tx(61, chain_id, 0, 10);
        let (cheap_sender, fine_sender) = (cheap.sender_address(), fine.sender_address());
        let accounts = MockAccounts::new()
            .with_balance(cheap_sender, u128::MAX)
            .with_balance(fine_sender, u128::MAX);
        let mut pool = Mempool::new(config(chain_id), accounts);
        pool.admit(cheap, BlockHeight(0)).unwrap();
        pool.admit(fine, BlockHeight(0)).unwrap();

        let candidates = pool.candidate_transactions(10, 5);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].sender_address(), fine_sender);
    }

    #[test]
    fn a_transaction_exactly_at_the_base_fee_is_offered() {
        let chain_id = ChainId(1);
        let tx = signed_tx(62, chain_id, 0, 5);
        let sender = tx.sender_address();
        let mut pool = Mempool::new(
            config(chain_id),
            MockAccounts::new().with_balance(sender, u128::MAX),
        );
        pool.admit(tx, BlockHeight(0)).unwrap();

        assert_eq!(pool.candidate_transactions(10, 5).len(), 1);
        assert!(pool.candidate_transactions(10, 6).is_empty());
    }

    #[test]
    fn an_unaffordable_first_transaction_also_holds_back_the_ones_queued_behind_it() {
        let chain_id = ChainId(1);
        // Sequence 0 can't pay the base fee, so sequence 1 — which could —
        // must wait: the executor runs a sender's transactions in order.
        let blocked = signed_tx(63, chain_id, 0, 2);
        let behind = signed_tx(63, chain_id, 1, 100);
        let sender = blocked.sender_address();
        let mut pool = Mempool::new(
            config(chain_id),
            MockAccounts::new().with_balance(sender, u128::MAX),
        );
        pool.admit(blocked, BlockHeight(0)).unwrap();
        pool.admit(behind, BlockHeight(0)).unwrap();

        assert!(pool.candidate_transactions(10, 5).is_empty());
    }

    #[test]
    fn a_later_transaction_below_the_base_fee_is_left_out_but_earlier_ones_are_offered() {
        let chain_id = ChainId(1);
        let first = signed_tx(64, chain_id, 0, 100);
        let second = signed_tx(64, chain_id, 1, 2); // below the base fee of 5
        let sender = first.sender_address();
        let mut pool = Mempool::new(
            config(chain_id),
            MockAccounts::new().with_balance(sender, u128::MAX),
        );
        pool.admit(first, BlockHeight(0)).unwrap();
        pool.admit(second, BlockHeight(0)).unwrap();

        let candidates = pool.candidate_transactions(10, 5);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].body.sequence_number, SequenceNumber(0));
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    /// Every message reads as a sentence about the problem: not empty, not
    /// the variant's Rust name, no trailing full stop, one line, and no two
    /// variants alike.
    fn readable<T: core::fmt::Display + core::fmt::Debug>(all: &[T]) {
        let mut seen = Vec::new();
        for value in all {
            let message = value.to_string();
            assert!(!message.is_empty(), "{value:?}");
            assert!(
                !message.ends_with('.') && !message.contains('\n'),
                "{message}"
            );
            assert_ne!(message, format!("{value:?}"), "only the variant's name");
            assert!(!seen.contains(&message), "two variants say {message:?}");
            seen.push(message);
        }
    }

    #[test]
    fn every_admission_error_reads_as_a_sentence() {
        readable(&[
            AdmissionError::WrongChainId,
            AdmissionError::InvalidSignature,
            AdmissionError::InvalidExpiry,
            AdmissionError::SequenceNumberTooLow,
            AdmissionError::InsufficientBalance,
            AdmissionError::ReplacementFeeTooLow,
            AdmissionError::PerSenderPendingLimitReached,
        ]);
    }
}
