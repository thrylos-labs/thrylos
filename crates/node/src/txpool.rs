//! The node's transaction pool, joined to the chain, the host and the network.
//!
//! `chain-mempool` decides what a pool holds; this is what it is fed from and
//! what it feeds. One [`NodeMempool`] is both halves of the join, and clones of
//! it share one pool:
//!
//! - as the host's [`TransactionSource`], it offers the best pending
//!   transactions when this node proposes a block, and forgets what a committed
//!   block made stale;
//! - as the event loop's [`TransactionIntake`], it admits the transactions
//!   that arrive from peers and says which of them to pass on.
//!
//! The pool has to read the chain's accounts (the next sequence number and the
//! balance of a sender) and its base fee, and the host owns the chain. So the
//! chain is shared: [`SharedEngine`] is the engine the host is given, and the
//! pool holds another handle to the same one. Both live on the event loop's
//! thread and take turns: the host borrows the engine for one call at a time,
//! and the pool reads it between calls, never across one.
//!
//! **Relaying.** A transaction that is new to this pool is passed on to every
//! peer but the one it came from, so a transaction handed to any node reaches
//! whichever validator proposes next. One that is already held, or that the
//! chain has already executed, is refused by the pool and so not passed on: that
//! is what ends the relaying, and it is why no message needs a hop count.

use std::cell::RefCell;
use std::rc::Rc;

use chain_consensus::host::TransactionSource;
use chain_engine_api::{
    Block, BlockLimits, BlockRejected, ChainView, ChainViewError, Engine, ExecutedBlock,
    FinaliseError, Head, ValidatorInfo,
};
use chain_mempool::{AccountView, AdmissionError, Mempool, MempoolConfig};
use chain_state::StateRoot;
use chain_types::{Address, BlockHeight, ChainId, Hash, SequenceNumber, Transaction};

use crate::durable_engine::DurableEngine;
use crate::event_loop::TransactionIntake;

/// The most transactions a node holds pending.
pub const MAX_POOL_SIZE: usize = 10_000;
/// The most pending sequence numbers one sender may have.
pub const MAX_PENDING_PER_SENDER: usize = 16;
/// How much a replacement must raise the fee by, in percent.
pub const MIN_REPLACEMENT_BUMP_PERCENT: u64 = 10;

/// The chain, shared between the host and the pool. See the module docs.
#[derive(Clone)]
pub struct SharedEngine(Rc<RefCell<DurableEngine>>);

impl SharedEngine {
    pub fn new(engine: DurableEngine) -> Self {
        Self(Rc::new(RefCell::new(engine)))
    }

    /// Runs `read` on the chain. It must not call back into the host.
    pub fn with<R>(&self, read: impl FnOnce(&DurableEngine) -> R) -> R {
        read(&self.0.borrow())
    }
}

impl Engine for SharedEngine {
    fn propose_block(
        &self,
        parent_block_hash: Hash,
        parent_state_root: StateRoot,
        height: BlockHeight,
        timestamp_millis: u64,
        candidate_transactions: Vec<Transaction>,
        limits: BlockLimits,
    ) -> Block {
        self.0.borrow().propose_block(
            parent_block_hash,
            parent_state_root,
            height,
            timestamp_millis,
            candidate_transactions,
            limits,
        )
    }

    fn execute_block(
        &self,
        parent_state_root: StateRoot,
        block: &Block,
    ) -> Result<ExecutedBlock, BlockRejected> {
        self.0.borrow().execute_block(parent_state_root, block)
    }

    fn finalise_block(
        &mut self,
        block: &Block,
        executed: &ExecutedBlock,
    ) -> Result<(), FinaliseError> {
        self.0.borrow_mut().finalise_block(block, executed)
    }
}

impl ChainView for SharedEngine {
    fn head(&self) -> Result<Head, ChainViewError> {
        ChainView::head(&*self.0.borrow())
    }

    fn validator_set(&self) -> Result<Vec<ValidatorInfo>, ChainViewError> {
        ChainView::validator_set(&*self.0.borrow())
    }

    fn block_limits(&self) -> Result<BlockLimits, ChainViewError> {
        ChainView::block_limits(&*self.0.borrow())
    }
}

/// The accounts of the chain as committed, for the pool's admission checks.
/// An account the chain cannot read is treated as empty, which errs toward
/// refusing its transactions.
pub struct ChainAccounts(SharedEngine);

impl AccountView for ChainAccounts {
    fn next_sequence_number(&self, address: &Address) -> SequenceNumber {
        self.0
            .with(|engine| engine.executor().read_account(*address))
            .map(|account| account.next_sequence_number)
            .unwrap_or_default()
    }

    fn balance(&self, address: &Address) -> u128 {
        self.0
            .with(|engine| engine.executor().read_account(*address))
            .map(|account| account.balance)
            .unwrap_or_default()
    }
}

/// The node's pool: both the host's source of transactions and the event
/// loop's intake. Clones share one pool.
#[derive(Clone)]
pub struct NodeMempool {
    engine: SharedEngine,
    pool: Rc<RefCell<Mempool<ChainAccounts>>>,
}

impl NodeMempool {
    /// An empty pool for the chain `engine` holds, whose chain ID is `chain_id`.
    pub fn new(engine: SharedEngine, chain_id: ChainId) -> Self {
        let pool = Mempool::new(
            MempoolConfig {
                chain_id,
                max_pool_size: MAX_POOL_SIZE,
                max_pending_per_sender: MAX_PENDING_PER_SENDER,
                min_replacement_fee_bump_percent: MIN_REPLACEMENT_BUMP_PERCENT,
            },
            ChainAccounts(engine.clone()),
        );
        Self {
            engine,
            pool: Rc::new(RefCell::new(pool)),
        }
    }

    /// How many transactions are pending.
    pub fn len(&self) -> usize {
        self.pool.borrow().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn height(&self) -> BlockHeight {
        self.engine
            .with(ChainView::head)
            .map(|head| head.height)
            .unwrap_or_default()
    }

    /// Admits `transaction` as if it had arrived from a peer.
    pub fn admit(&self, transaction: Transaction) -> Result<(), AdmissionError> {
        let height = self.height();
        self.pool.borrow_mut().admit(transaction, height)
    }
}

impl TransactionSource for NodeMempool {
    fn candidates(&mut self, max: usize) -> Vec<Transaction> {
        // The price the block being built will charge: a transaction whose
        // ceiling is below it could only make the block invalid.
        let base_fee = self
            .engine
            .with(|engine| engine.executor().base_fee())
            .unwrap_or_default();
        self.pool.borrow().candidate_transactions(max, base_fee)
    }

    fn committed(&mut self, block: &Block) {
        let senders: Vec<Address> = block
            .transactions
            .iter()
            .map(Transaction::sender_address)
            .collect();
        // The block is finalised by now, so the accounts read are the new ones.
        self.pool
            .borrow_mut()
            .prune_after_commit(&senders, block.height);
    }
}

impl TransactionIntake for NodeMempool {
    fn submit(&mut self, transaction: Transaction, _now_ms: u64) -> Option<Transaction> {
        let for_relay = transaction.clone();
        self.admit(transaction).ok().map(|()| for_relay)
    }
}

/// Fixtures for tests here and in the RPC's: a real chain on the devnet genesis,
/// and signed calls to its counter.
#[cfg(test)]
pub(crate) mod testing {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use chain_exec::genesis::{
        COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME, COUNTER_PACKAGE_ADDRESS,
        INITIAL_COUNTER_ADDRESS,
    };
    use chain_genesis::devnet;
    use chain_types::{
        Encode, GasAmount, GasPrice, MoveCall, PublicKey, Signature, TransactionBody,
    };
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    pub(crate) const DEVNET_CHAIN: u64 = devnet::DEVNET_CHAIN_ID;

    pub(crate) fn chain() -> (tempfile::TempDir, SharedEngine, NodeMempool) {
        let dir = tempfile::tempdir().unwrap();
        let genesis = devnet::config().unwrap();
        let engine = SharedEngine::new(DurableEngine::open(dir.path(), &genesis).unwrap());
        let pool = NodeMempool::new(engine.clone(), genesis.chain_id());
        (dir, engine, pool)
    }

    /// A signed call to the genesis counter's `bump`, from the devnet account
    /// with this seed (101 to 104 are funded).
    pub(crate) fn bump(seed: u8, chain_id: u64, sequence: u64, max_fee: u64) -> Transaction {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let sender = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap();
        let body = TransactionBody {
            chain_id: chain_types::ChainId(chain_id),
            sender,
            sequence_number: chain_types::SequenceNumber(sequence),
            expiry: BlockHeight(1_000),
            gas_limit: GasAmount(1_000),
            max_fee_per_gas: GasPrice(max_fee),
            declared_inputs: vec![Address::from_bytes(INITIAL_COUNTER_ADDRESS.into_bytes())],
            call: MoveCall {
                module_address: Address::from_bytes(COUNTER_PACKAGE_ADDRESS.into_bytes()),
                module_name: COUNTER_MODULE_NAME.as_bytes().to_vec(),
                function_name: COUNTER_BUMP_FUNCTION.as_bytes().to_vec(),
                type_arguments: Vec::new(),
                arguments: vec![1u64.to_le_bytes().to_vec()],
            },
        };
        let mut bytes = Vec::new();
        body.encode(&mut bytes);
        Transaction {
            body,
            signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
        }
    }

    /// The next block on the chain, holding `transactions`, committed.
    pub(crate) fn commit(engine: &SharedEngine, transactions: Vec<Transaction>) -> Block {
        let head = ChainView::head(engine).unwrap();
        let limits = ChainView::block_limits(engine).unwrap();
        let block = engine.propose_block(
            head.block_hash,
            head.state_root,
            BlockHeight(head.height.0.saturating_add(1)),
            head.timestamp_ms.saturating_add(1),
            transactions,
            limits,
        );
        let executed = engine.execute_block(head.state_root, &block).unwrap();
        engine.clone().finalise_block(&block, &executed).unwrap();
        block
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::testing::*;
    use super::*;

    #[test]
    fn a_funded_senders_transaction_is_admitted_offered_and_passed_on_once() {
        let (_dir, _engine, mut pool) = chain();
        let tx = bump(101, DEVNET_CHAIN, 0, 1);

        assert_eq!(
            pool.submit(tx.clone(), 0),
            Some(tx.clone()),
            "new: pass it on"
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.candidates(10), vec![tx.clone()]);

        // Seen again (from another peer, say): held already, so not passed on.
        assert_eq!(pool.submit(tx, 0), None);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn what_the_chain_would_refuse_is_neither_held_nor_passed_on() {
        let (_dir, _engine, mut pool) = chain();
        for (what, tx) in [
            ("another chain", bump(101, DEVNET_CHAIN + 1, 0, 1)),
            ("a sender with no funds", bump(9, DEVNET_CHAIN, 0, 1)),
        ] {
            assert_eq!(pool.submit(tx, 0), None, "{what}");
        }
        let mut forged = bump(101, DEVNET_CHAIN, 0, 1);
        forged.body.sequence_number = chain_types::SequenceNumber(5);
        assert_eq!(
            pool.submit(forged, 0),
            None,
            "a signature that does not match"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_committed_block_takes_its_transactions_out_and_they_cannot_come_back() {
        let (_dir, engine, mut pool) = chain();
        let first = bump(101, DEVNET_CHAIN, 0, 1);
        let second = bump(101, DEVNET_CHAIN, 1, 1);
        pool.submit(first.clone(), 0).unwrap();
        pool.submit(second.clone(), 0).unwrap();

        let block = commit(&engine, vec![first.clone()]);
        assert_eq!(block.transactions.len(), 1);
        pool.committed(&block);

        // It ran, once; the one behind it is still pending and is now next.
        assert_eq!(engine.with(|e| e.executor().read_counter()), Some(1));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.candidates(10), vec![second]);
        // Sent again, it is refused: already executed.
        assert_eq!(pool.submit(first, 0), None);
    }

    #[test]
    fn a_transaction_that_cannot_pay_the_current_base_fee_is_kept_but_never_offered() {
        let (_dir, engine, mut pool) = chain();
        let base_fee = engine.with(|e| e.executor().base_fee()).unwrap();
        assert!(base_fee > 0, "the test needs a fee to fall short of");
        let cheap = bump(101, DEVNET_CHAIN, 0, base_fee - 1);
        assert!(
            pool.submit(cheap, 0).is_some(),
            "admission does not look at the base fee"
        );
        assert_eq!(pool.len(), 1);
        assert!(
            pool.candidates(10).is_empty(),
            "a block with it would be invalid"
        );
    }

    #[test]
    fn clones_share_one_pool() {
        let (_dir, _engine, mut pool) = chain();
        let mut as_source = pool.clone();
        pool.submit(bump(101, DEVNET_CHAIN, 0, 1), 0).unwrap();
        assert_eq!(as_source.candidates(10).len(), 1);
        assert_eq!(as_source.len(), 1);
    }
}
