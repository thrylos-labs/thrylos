//! The node's answers to its RPC: what each of the nine methods says, from the
//! chain, the pool and the loop.
//!
//! [`NodeApi`] runs on the event loop's thread (the loop hands it the chance
//! between the other things it does, through [`RpcPort`]), so it reads the chain
//! exactly as the host sees it, with nothing shared across threads. It answers a
//! bounded number of calls each time, so a burst of requests cannot hold up
//! consensus.

use chain_consensus::host::CommitRecord;
use chain_engine_api::{ChainView, Head, TransactionOutcome};
use chain_exec::simulate::{SimulationFailure, SIMULATE_MAX_GAS};
use chain_exec::view::ViewValue;
use chain_mempool::AdmissionError;
use chain_rpc::call::transaction_hash;
use chain_rpc::hex;
use chain_rpc::{Call, Inbox, Reply, RpcError};
use chain_text::format_address;
use chain_types::{Address, BlockHeight, ChainId, Encode, Hash, Transaction};
use move_core_types::account_address::AccountAddress;
use serde_json::{json, Value};

use crate::event_loop::{NodeFacts, RpcPort};
use crate::txpool::{NodeMempool, SharedEngine};

/// The most calls answered in one pass of the event loop.
pub const MAX_CALLS_PER_PASS: usize = 16;

/// Answers a node's RPC. See the module docs.
pub struct NodeApi {
    engine: SharedEngine,
    pool: NodeMempool,
    inbox: Inbox,
    chain_id: ChainId,
    genesis_hash: Hash,
    validator: Address,
    /// Whether `simulate` is served (`rpc.simulate`).
    simulate: bool,
    /// When the last simulation started. Wall-clock time, used only to space
    /// simulations out; nothing consensus reads it.
    last_simulation: std::cell::Cell<Option<std::time::Instant>>,
}

/// The least time between two simulations. One runs a Move call on the thread
/// that also runs consensus, so they are rationed: at [`SIMULATE_MAX_GAS`] each
/// takes a fraction of a second at most, and this keeps them to a fraction of the
/// thread's time however hard the RPC is pushed.
pub const SIMULATION_SPACING: std::time::Duration = std::time::Duration::from_millis(1_000);

/// The most drawers `move_resources` lists.
pub const MAX_LISTED_DRAWERS: usize = 100;

impl NodeApi {
    pub const fn new(
        engine: SharedEngine,
        pool: NodeMempool,
        inbox: Inbox,
        chain_id: ChainId,
        genesis_hash: Hash,
        validator: Address,
        simulate: bool,
    ) -> Self {
        Self {
            engine,
            pool,
            inbox,
            chain_id,
            genesis_hash,
            validator,
            simulate,
            last_simulation: std::cell::Cell::new(None),
        }
    }

    /// Answers `call`. Public so it can be tested without a socket.
    pub fn answer(&self, call: &Call, facts: &dyn NodeFacts) -> Reply {
        match call {
            Call::Status => self.status(facts),
            Call::Block { height, full } => self.block(*height, *full),
            Call::Commit { height } => self.commit(*height, facts),
            Call::Account { address } => self.account(address),
            Call::SendTransaction { transaction } => self.send(transaction, facts),
            Call::Transaction { hash } => self.transaction(hash),
            Call::MoveResource {
                owner,
                type_name,
                slot,
            } => self.move_resource(owner, type_name, *slot),
            Call::MoveResources { owner } => self.move_resources(owner),
            Call::Simulate { transaction } => self.simulate(transaction),
        }
    }

    fn head(&self) -> Result<Head, RpcError> {
        self.engine
            .with(ChainView::head)
            .map_err(|_| RpcError::unavailable("the chain cannot be read"))
    }

    fn status(&self, facts: &dyn NodeFacts) -> Reply {
        let head = self.head()?;
        let base_fee = self.engine.with(|engine| engine.executor().base_fee());
        Ok(json!({
            "chainId": self.chain_id.0,
            "genesisHash": self.genesis_hash.to_string(),
            "validator": format_address(&self.validator),
            "latest": {
                "height": head.height.0,
                "hash": head.block_hash.to_string(),
                "stateRoot": head.state_root.as_hash().to_string(),
                "timestampMs": head.timestamp_ms,
            },
            "baseFee": base_fee,
            "peers": facts.connected_peers(),
            "mempool": self.pool.len(),
            "halted": facts.halted(),
            "blockRelay": relay_json(facts.relay_stats()),
        }))
    }

    /// The stored block and state root at `height`.
    fn stored(
        &self,
        height: BlockHeight,
    ) -> Result<Option<(chain_engine_api::Block, Hash)>, RpcError> {
        self.engine.with(|engine| {
            let db = engine.database();
            let unreadable = |_| RpcError::unavailable("the chain database cannot be read");
            let block = db.get_block(height).map_err(unreadable)?;
            let root = db.get_root(height).map_err(unreadable)?;
            Ok(block.zip(root))
        })
    }

    /// `height`, or the newest if none was given, and an error if it is not there.
    fn existing(&self, height: Option<u64>) -> Result<(BlockHeight, Head), RpcError> {
        let head = self.head()?;
        let height = BlockHeight(height.unwrap_or(head.height.0));
        if height.0 > head.height.0 {
            return Err(RpcError::not_found(format!(
                "no block at height {} yet: the chain is at {}",
                height.0, head.height.0
            )));
        }
        Ok((height, head))
    }

    fn block(&self, height: Option<u64>, full: bool) -> Reply {
        let (height, head) = self.existing(height)?;
        let Some((block, state_root)) = self.stored(height)? else {
            return if height.0 == 0 {
                Err(RpcError::not_found(format!(
                    "there is no block at height 0: the chain starts from its genesis, {}, whose state root is {}",
                    head.block_hash, head.state_root.as_hash()
                )))
            } else {
                Err(RpcError::not_found(format!(
                    "no block at height {}",
                    height.0
                )))
            };
        };
        let outcomes = self.outcomes(height, block.transactions.len())?;
        let transactions: Vec<Value> = block
            .transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| {
                if full {
                    let mut bytes = Vec::new();
                    transaction.encode(&mut bytes);
                    json!({
                        "hash": transaction_hash(transaction).to_string(),
                        "sender": format_address(&transaction.sender_address()),
                        "sequenceNumber": transaction.body.sequence_number.0,
                        "encoded": hex::encode(&bytes),
                        "outcome": outcomes.as_ref().and_then(|all| all.get(index)).map(|o| outcome_json(*o)),
                    })
                } else {
                    json!(transaction_hash(transaction).to_string())
                }
            })
            .collect();
        Ok(json!({
            "height": block.height.0,
            "hash": block.hash().to_string(),
            "parentHash": block.parent_block_hash.to_string(),
            "timestampMs": block.timestamp_millis,
            "stateRoot": state_root.to_string(),
            "transactionCount": block.transactions.len(),
            // How many of them aborted: null for a block whose outcomes were
            // not kept (one committed before they were).
            "abortedCount": outcomes.as_ref().map(|all| {
                all.iter().filter(|o| matches!(o, TransactionOutcome::Aborted(_))).count()
            }),
            "transactions": transactions,
        }))
    }

    /// What became of each of the block's transactions, if that was recorded.
    fn outcomes(
        &self,
        height: BlockHeight,
        transactions: usize,
    ) -> Result<Option<Vec<TransactionOutcome>>, RpcError> {
        let outcomes = self
            .engine
            .with(|engine| engine.database().get_outcomes(height))
            .map_err(|_| RpcError::unavailable("the chain database cannot be read"))?;
        match outcomes {
            Some(all) if all.len() != transactions => Err(RpcError::unavailable(
                "the recorded outcomes of this block do not match its transactions",
            )),
            other => Ok(other),
        }
    }

    /// What became of one transaction: in a block, and how it went, or waiting
    /// in the pool.
    fn transaction(&self, hash: &Hash) -> Reply {
        let unreadable = |_| RpcError::unavailable("the chain database cannot be read");
        let found = self
            .engine
            .with(|engine| engine.database().find_transaction(hash))
            .map_err(unreadable)?;
        if let Some((height, index)) = found {
            let (block, _) = self.stored(height)?.ok_or_else(|| {
                RpcError::unavailable("the index names a block that is not stored")
            })?;
            let at = locate(&block, index, hash)?;
            let outcomes = self.outcomes(height, block.transactions.len())?;
            return Ok(json!({
                "hash": hash.to_string(),
                "status": "included",
                "height": height.0,
                "index": index,
                "blockHash": block.hash().to_string(),
                "outcome": outcomes.as_ref().and_then(|all| all.get(at)).map(|o| outcome_json(*o)),
            }));
        }
        if self.pool.holds(hash) {
            return Ok(json!({ "hash": hash.to_string(), "status": "pending" }));
        }
        Err(RpcError::not_found(
            "no such transaction is waiting here or in a block: it may never have arrived, \
             or it expired or was dropped from the pool, which leaves no trace",
        ))
    }

    fn commit(&self, height: Option<u64>, facts: &dyn NodeFacts) -> Reply {
        let (height, _) = self.existing(height)?;
        let Some(record) = facts.commit_record(height) else {
            return Err(RpcError::not_found(format!(
                "this node no longer holds the certificate for height {}",
                height.0
            )));
        };
        let state_root = self.stored(height)?.map(|(_, root)| root.to_string());
        Ok(commit_json(&record, state_root))
    }

    fn account(&self, address: &Address) -> Reply {
        let head = self.head()?;
        let account = self
            .engine
            .with(|engine| engine.executor().read_account(*address))
            .map_err(|_| RpcError::unavailable("the account state cannot be read"))?;
        Ok(json!({
            "address": format_address(address),
            "balance": account.balance.to_string(),
            "nextSequenceNumber": account.next_sequence_number.0,
            "height": head.height.0,
        }))
    }

    fn move_resource(&self, owner: &Address, type_name: &str, slot: u64) -> Reply {
        let head = self.head()?;
        let account = AccountAddress::new(*owner.as_bytes());
        let found = self
            .engine
            .with(|engine| {
                let executor = engine.executor();
                executor
                    .read_drawer(account, slot, type_name)
                    .map(|drawer| {
                        drawer.map(|drawer| {
                            let value = executor.render_drawer(&drawer);
                            (drawer, value)
                        })
                    })
            })
            .map_err(|_| RpcError::unavailable("a stored value is damaged"))?;
        let Some((drawer, value)) = found else {
            return Err(RpcError::not_found(format!(
                "no {type_name} is stored in slot {slot} of {}",
                format_address(owner)
            )));
        };
        Ok(json!({
            "owner": format_address(owner),
            "slot": slot,
            "type": drawer.type_name,
            "bytes": hex::encode(&drawer.bytes),
            "value": value.as_ref().map(view_json),
            "height": head.height.0,
        }))
    }

    fn move_resources(&self, owner: &Address) -> Reply {
        let head = self.head()?;
        let account = AccountAddress::new(*owner.as_bytes());
        let drawers = self
            .engine
            .with(|engine| engine.executor().drawers_of(account, MAX_LISTED_DRAWERS));
        Ok(json!({
            "owner": format_address(owner),
            "height": head.height.0,
            "resources": drawers
                .iter()
                .map(|d| json!({ "slot": d.slot, "type": d.type_name, "bytes": d.bytes }))
                .collect::<Vec<_>>(),
        }))
    }

    #[allow(clippy::disallowed_methods)] // the spacing is wall-clock, and no consensus rule reads it
    fn simulate(&self, transaction: &Transaction) -> Reply {
        if !self.simulate {
            return Err(RpcError::unavailable(
                "this node does not serve simulate (its `rpc.simulate` is off)",
            ));
        }
        let now = std::time::Instant::now();
        if let Some(last) = self.last_simulation.get() {
            if now.duration_since(last) < SIMULATION_SPACING {
                return Err(RpcError::unavailable(
                    "a simulation was run a moment ago; try again in a second",
                ));
            }
        }
        self.last_simulation.set(Some(now));
        let head = self.head()?;
        let outcome = self
            .engine
            .with(|engine| engine.executor().simulate(transaction));
        match outcome {
            Ok(simulation) => Ok(json!({
                "status": "success",
                "gasUsed": simulation.gas_used,
                "gasCap": SIMULATE_MAX_GAS,
                "returns": simulation.returns.iter().map(view_json).collect::<Vec<_>>(),
                "drawersChanged": simulation.drawers_changed,
                "deposit": simulation.deposit.to_string(),
                "height": head.height.0,
            })),
            // The call failing is an answer, the same as it would have been on the chain.
            Err(SimulationFailure::Failed { gas_used, reason }) => Ok(json!({
                "status": "failed",
                "reason": reason,
                "gasUsed": gas_used,
                "gasCap": SIMULATE_MAX_GAS,
                "height": head.height.0,
            })),
            Err(SimulationFailure::Internal) => {
                Err(RpcError::unavailable("the simulation could not be run"))
            }
            Err(other) => Err(RpcError::invalid_params(other.to_string())),
        }
    }

    fn send(&self, transaction: &Transaction, facts: &dyn NodeFacts) -> Reply {
        let hash = transaction_hash(transaction);
        match self.pool.admit(transaction.clone()) {
            Ok(()) => {
                // New to this node: the other nodes need it too, since any of
                // them may be the next to propose.
                facts.relay(transaction);
                Ok(json!({ "hash": hash.to_string(), "status": "pending" }))
            }
            Err(error) => Err(RpcError::new(RpcError::REFUSED, error.to_string())
                .with_data(json!({ "reason": reason(error), "hash": hash.to_string() }))),
        }
    }
}

impl RpcPort for NodeApi {
    fn serve(&mut self, facts: &dyn NodeFacts) {
        for _ in 0..MAX_CALLS_PER_PASS {
            let Some(pending) = self.inbox.next() else {
                return;
            };
            let reply = self.answer(&pending.call, facts);
            pending.answer(reply);
        }
    }
}

/// A decoded Move value as JSON: numbers as decimal text (JSON numbers cannot hold
/// a `u128`), addresses as `thry1…`, structs as objects with a `_type` member.
fn view_json(value: &ViewValue) -> Value {
    match value {
        ViewValue::Bool(b) => json!(b),
        ViewValue::Number(n) => json!(n),
        ViewValue::Address(a) => json!(format_address(&Address::from_bytes(a.into_bytes()))),
        ViewValue::Vector(items) => Value::Array(items.iter().map(view_json).collect()),
        ViewValue::Struct { type_name, fields } => {
            let mut object = serde_json::Map::new();
            object.insert("_type".into(), json!(type_name));
            for (name, field) in fields {
                object.insert(name.clone(), view_json(field));
            }
            Value::Object(object)
        }
        ViewValue::Variant {
            type_name,
            variant,
            fields,
        } => {
            let mut object = serde_json::Map::new();
            object.insert("_type".into(), json!(type_name));
            object.insert("_variant".into(), json!(variant));
            for (name, field) in fields {
                object.insert(name.clone(), view_json(field));
            }
            Value::Object(object)
        }
    }
}

/// The position in `block` that the index gave for the transaction with this
/// hash, checked: the block must hold that transaction there. An index that
/// disagrees with its block is damage, and is said to be, not answered from.
fn locate(block: &chain_engine_api::Block, index: u32, hash: &Hash) -> Result<usize, RpcError> {
    let at = usize::try_from(index).unwrap_or(usize::MAX);
    match block.transactions.get(at) {
        Some(transaction) if transaction.hash() == *hash => Ok(at),
        _ => Err(RpcError::unavailable(
            "the index and the block it names disagree",
        )),
    }
}

/// What became of a transaction that ran: it succeeded, or it aborted, which
/// still charged its sender and advanced their sequence number but applied none of
/// its effects.
fn outcome_json(outcome: TransactionOutcome) -> Value {
    match outcome {
        TransactionOutcome::Success => json!({ "status": "success" }),
        TransactionOutcome::Aborted(reason) => json!({
            "status": "aborted",
            "reason": reason.name(),
            "message": reason.to_string(),
        }),
    }
}

/// How well block relay is working: a node that is mostly asking for what it is
/// missing is one whose pool is not keeping up.
fn relay_json(stats: crate::block_relay::RelayStats) -> Value {
    json!({
        "announcedCompact": stats.announced_compact,
        "announcedWhole": stats.announced_whole,
        "rebuiltFromPool": stats.rebuilt_from_pool,
        "requestsMade": stats.requests_made,
        "transactionsRequested": stats.transactions_requested,
        "rebuiltAfterRequest": stats.rebuilt_after_request,
        "requestsAnswered": stats.requests_answered,
        "setAside": stats.set_aside,
    })
}

/// The name of the rule a transaction broke, stable for a client to switch on.
const fn reason(error: AdmissionError) -> &'static str {
    match error {
        AdmissionError::WrongChainId => "WrongChainId",
        AdmissionError::InvalidSignature => "InvalidSignature",
        AdmissionError::InvalidExpiry => "InvalidExpiry",
        AdmissionError::GasLimitTooLow => "GasLimitTooLow",
        AdmissionError::SequenceNumberTooFarAhead => "SequenceNumberTooFarAhead",
        AdmissionError::SequenceNumberTooLow => "SequenceNumberTooLow",
        AdmissionError::InsufficientBalance => "InsufficientBalance",
        AdmissionError::ReplacementFeeTooLow => "ReplacementFeeTooLow",
        AdmissionError::PerSenderPendingLimitReached => "PerSenderPendingLimitReached",
        AdmissionError::MoveCallGasTooHigh => "MoveCallGasTooHigh",
    }
}

/// A commit certificate as JSON: enough to compare across nodes (the block, the
/// state it led to, who signed) and to check (every signature).
fn commit_json(record: &CommitRecord, state_root: Option<String>) -> Value {
    let certificate = &record.certificate;
    let signatures: Vec<Value> = certificate
        .commit_signatures
        .iter()
        .map(|entry| {
            json!({
                "validator": format_address(&entry.address.0),
                "signature": hex::encode(&entry.signature.to_bytes()),
            })
        })
        .collect();
    json!({
        "height": record.block.height.0,
        "round": certificate.round.as_u32(),
        "blockHash": record.block.hash().to_string(),
        "stateRoot": state_root,
        "signatureCount": signatures.len(),
        "signatures": signatures,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic
    )]

    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use chain_genesis::devnet;
    use chain_rpc::{RpcError, Server, ServerConfig};
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::client::signed_transfer;
    use crate::txpool::testing::{bump, bump_by, chain, commit, DEVNET_CHAIN};

    /// What the loop would tell the API, with the relaying recorded.
    struct Facts {
        peers: usize,
        halted: Option<String>,
        relayed: RefCell<Vec<Transaction>>,
    }

    impl Facts {
        fn new() -> Self {
            Self {
                peers: 3,
                halted: None,
                relayed: RefCell::new(Vec::new()),
            }
        }
    }

    impl NodeFacts for Facts {
        fn connected_peers(&self) -> usize {
            self.peers
        }

        fn halted(&self) -> Option<String> {
            self.halted.clone()
        }

        fn commit_record(&self, _height: BlockHeight) -> Option<CommitRecord> {
            None
        }

        fn relay(&self, transaction: &Transaction) {
            self.relayed.borrow_mut().push(transaction.clone());
        }

        fn relay_stats(&self) -> crate::block_relay::RelayStats {
            crate::block_relay::RelayStats::default()
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        engine: SharedEngine,
        api: NodeApi,
        _server: Server,
    }

    fn fixture() -> Fixture {
        fixture_with(true)
    }

    fn fixture_with(simulate: bool) -> Fixture {
        let (dir, engine, pool) = chain();
        let (server, inbox) =
            Server::start(ServerConfig::at("127.0.0.1:0".parse().unwrap())).unwrap();
        let genesis = devnet::config().unwrap();
        let api = NodeApi::new(
            engine.clone(),
            pool,
            inbox,
            genesis.chain_id(),
            genesis.hash(),
            Address::from_bytes([9; 32]),
            simulate,
        );
        Fixture {
            _dir: dir,
            engine,
            api,
            _server: server,
        }
    }

    fn ok(reply: Reply) -> Value {
        reply.unwrap_or_else(|error| panic!("{error}"))
    }

    fn account_of(seed: u8) -> Address {
        Address::from_public_key(&devnet::ed25519(seed).unwrap())
    }

    #[test]
    fn status_says_what_a_monitor_needs_to_know() {
        let f = fixture();
        let status = ok(f.api.answer(&Call::Status, &Facts::new()));
        assert_eq!(status["chainId"], devnet::DEVNET_CHAIN_ID);
        assert_eq!(status["latest"]["height"], 0);
        assert_eq!(status["peers"], 3);
        assert_eq!(status["mempool"], 0);
        assert_eq!(status["halted"], Value::Null);
        assert_eq!(
            status["validator"],
            format_address(&Address::from_bytes([9; 32]))
        );
        assert_eq!(status["genesisHash"].as_str().unwrap().len(), 64);
        assert_eq!(status["latest"]["stateRoot"].as_str().unwrap().len(), 64);
        assert!(status["baseFee"].is_number());

        // A node whose host has stopped says why.
        let mut facts = Facts::new();
        facts.halted = Some("the signer refused".into());
        let status = ok(f.api.answer(&Call::Status, &facts));
        assert_eq!(status["halted"], "the signer refused");
    }

    #[test]
    fn an_account_reads_its_balance_and_the_sequence_number_its_next_transaction_needs() {
        let f = fixture();
        let funded = ok(f.api.answer(
            &Call::Account {
                address: account_of(101),
            },
            &Facts::new(),
        ));
        assert_eq!(funded["balance"], "1000000000000");
        assert_eq!(funded["nextSequenceNumber"], 0);
        assert_eq!(funded["height"], 0);
        assert_eq!(funded["address"], format_address(&account_of(101)));

        let stranger = ok(f.api.answer(
            &Call::Account {
                address: Address::from_bytes([77; 32]),
            },
            &Facts::new(),
        ));
        assert_eq!(stranger["balance"], "0");
        assert_eq!(stranger["nextSequenceNumber"], 0);
    }

    #[test]
    fn a_sent_transaction_is_held_and_passed_on_once_and_a_repeat_is_refused_with_its_reason() {
        let f = fixture();
        let facts = Facts::new();
        let tx = bump(101, DEVNET_CHAIN, 0, 1);
        let send = |tx: &Transaction| {
            f.api.answer(
                &Call::SendTransaction {
                    transaction: Box::new(tx.clone()),
                },
                &facts,
            )
        };

        let sent = ok(send(&tx));
        assert_eq!(sent["hash"], transaction_hash(&tx).to_string());
        assert_eq!(sent["status"], "pending");
        assert_eq!(facts.relayed.borrow().as_slice(), std::slice::from_ref(&tx));
        assert_eq!(ok(f.api.answer(&Call::Status, &facts))["mempool"], 1);

        // The same again: refused, with the rule named, and not passed on again.
        let error = send(&tx).unwrap_err();
        assert_eq!(error.code, RpcError::REFUSED);
        assert_eq!(
            error.data.as_ref().unwrap()["reason"],
            "ReplacementFeeTooLow"
        );
        assert_eq!(
            error.data.as_ref().unwrap()["hash"],
            transaction_hash(&tx).to_string()
        );
        assert_eq!(facts.relayed.borrow().len(), 1);
    }

    #[test]
    fn a_transfer_sent_through_rpc_reaches_the_recipient_account() {
        let f = fixture();
        let facts = Facts::new();
        let recipient = Address::from_bytes([77; 32]);
        let transaction = signed_transfer(
            &SigningKey::from_bytes(&[101; 32]),
            DEVNET_CHAIN,
            0,
            1_000,
            recipient,
            2_500_000_000,
            1,
        )
        .unwrap();

        let sent = ok(f.api.answer(
            &Call::SendTransaction {
                transaction: Box::new(transaction.clone()),
            },
            &facts,
        ));
        assert_eq!(sent["status"], "pending");
        commit(&f.engine, vec![transaction]);

        let account = ok(f.api.answer(&Call::Account { address: recipient }, &facts));
        assert_eq!(account["balance"], "2500000000");
        assert_eq!(account["nextSequenceNumber"], 0);
    }

    #[test]
    fn each_way_a_transaction_can_be_refused_says_which() {
        let f = fixture();
        let facts = Facts::new();
        let mut forged = bump(101, DEVNET_CHAIN, 0, 1);
        forged.body.sequence_number = chain_types::SequenceNumber(4);
        for (tx, reason) in [
            (bump(101, DEVNET_CHAIN + 1, 0, 1), "WrongChainId"),
            (bump(9, DEVNET_CHAIN, 0, 1), "InsufficientBalance"),
            (forged, "InvalidSignature"),
        ] {
            let error = f
                .api
                .answer(
                    &Call::SendTransaction {
                        transaction: Box::new(tx),
                    },
                    &facts,
                )
                .unwrap_err();
            assert_eq!(error.code, RpcError::REFUSED);
            assert_eq!(error.data.as_ref().unwrap()["reason"], reason, "{error}");
            assert!(!error.message.is_empty());
        }
        assert!(
            facts.relayed.borrow().is_empty(),
            "nothing refused is passed on"
        );
    }

    #[test]
    fn a_block_is_read_back_by_height_with_its_state_root_and_its_transactions() {
        let f = fixture();
        let facts = Facts::new();
        let tx = bump(101, DEVNET_CHAIN, 0, 1);
        f.api
            .answer(
                &Call::SendTransaction {
                    transaction: Box::new(tx.clone()),
                },
                &facts,
            )
            .unwrap();
        let block = commit(&f.engine, vec![tx.clone()]);

        let latest = ok(f.api.answer(
            &Call::Block {
                height: None,
                full: false,
            },
            &facts,
        ));
        assert_eq!(latest["height"], 1);
        assert_eq!(latest["hash"], block.hash().to_string());
        assert_eq!(latest["parentHash"], block.parent_block_hash.to_string());
        assert_eq!(latest["transactionCount"], 1);
        assert_eq!(
            latest["transactions"],
            json!([transaction_hash(&tx).to_string()])
        );
        let root = f
            .engine
            .with(|engine| engine.database().get_root(BlockHeight(1)).unwrap().unwrap());
        assert_eq!(latest["stateRoot"], root.to_string());
        assert_eq!(
            ok(f.api.answer(
                &Call::Block {
                    height: Some(1),
                    full: false
                },
                &facts
            )),
            latest
        );

        // With the transactions in full: who sent it, which, and its bytes.
        let full = ok(f.api.answer(
            &Call::Block {
                height: Some(1),
                full: true,
            },
            &facts,
        ));
        let one = &full["transactions"][0];
        assert_eq!(one["hash"], transaction_hash(&tx).to_string());
        assert_eq!(one["sender"], format_address(&tx.sender_address()));
        assert_eq!(one["sequenceNumber"], 0);
        let mut bytes = Vec::new();
        tx.encode(&mut bytes);
        assert_eq!(one["encoded"], hex::encode(&bytes));

        // And the status and the account moved on with it.
        assert_eq!(
            ok(f.api.answer(&Call::Status, &facts))["latest"]["height"],
            1
        );
        let account = ok(f.api.answer(
            &Call::Account {
                address: tx.sender_address(),
            },
            &facts,
        ));
        assert_eq!(account["nextSequenceNumber"], 1);
    }

    /// The first call overflows the counter's start of 0 only if it is the second
    /// of two: MAX, then 1. So the first succeeds and the second aborts.
    fn a_block_of_one_success_and_one_abort(f: &Fixture) -> (Transaction, Transaction) {
        let succeeds = bump_by(101, DEVNET_CHAIN, 0, 1, u64::MAX);
        let aborts = bump_by(102, DEVNET_CHAIN, 0, 1, 1);
        commit(&f.engine, vec![succeeds.clone(), aborts.clone()]);
        (succeeds, aborts)
    }

    #[test]
    fn a_transaction_is_pending_then_included_and_says_whether_it_succeeded_or_aborted() {
        let f = fixture();
        let facts = Facts::new();
        let ask = |tx: &Transaction| f.api.answer(&Call::Transaction { hash: tx.hash() }, &facts);
        let succeeds = bump_by(101, DEVNET_CHAIN, 0, 1, u64::MAX);
        let aborts = bump_by(102, DEVNET_CHAIN, 0, 1, 1);

        // Not heard of.
        let unknown = ask(&succeeds).unwrap_err();
        assert_eq!(unknown.code, RpcError::NOT_FOUND);

        // Sent, and waiting: and one that the pool holds does not make another
        // that it does not hold appear.
        let send = |tx: &Transaction| {
            f.api
                .answer(
                    &Call::SendTransaction {
                        transaction: Box::new(tx.clone()),
                    },
                    &facts,
                )
                .unwrap();
        };
        send(&succeeds);
        assert_eq!(ask(&aborts).unwrap_err().code, RpcError::NOT_FOUND);
        send(&aborts);
        let pending = ok(ask(&succeeds));
        assert_eq!(pending["status"], "pending");
        assert_eq!(pending["hash"], succeeds.hash().to_string());
        assert!(pending.get("height").is_none());

        // Committed, in one block, in the order sent.
        let block = commit(&f.engine, vec![succeeds.clone(), aborts.clone()]);
        let done = ok(ask(&succeeds));
        assert_eq!(done["status"], "included");
        assert_eq!(
            (done["height"].clone(), done["index"].clone()),
            (json!(1), json!(0))
        );
        assert_eq!(done["blockHash"], block.hash().to_string());
        assert_eq!(done["outcome"], json!({ "status": "success" }));

        let failed = ok(ask(&aborts));
        assert_eq!(
            failed["status"], "included",
            "an abort is still included, and charged"
        );
        assert_eq!(failed["index"], 1);
        assert_eq!(failed["outcome"]["status"], "aborted");
        assert_eq!(failed["outcome"]["reason"], "ExecutionFailed");
        assert!(!failed["outcome"]["message"].as_str().unwrap().is_empty());

        // Both spent their sequence numbers, the aborted one too.
        for tx in [&succeeds, &aborts] {
            let account = ok(f.api.answer(
                &Call::Account {
                    address: tx.sender_address(),
                },
                &facts,
            ));
            assert_eq!(account["nextSequenceNumber"], 1);
        }
    }

    #[test]
    fn a_block_says_how_many_of_its_transactions_aborted_and_which() {
        let f = fixture();
        let facts = Facts::new();
        let (succeeds, aborts) = a_block_of_one_success_and_one_abort(&f);

        let listed = ok(f.api.answer(
            &Call::Block {
                height: Some(1),
                full: false,
            },
            &facts,
        ));
        assert_eq!(listed["abortedCount"], 1);
        assert_eq!(
            listed["transactions"],
            json!([succeeds.hash().to_string(), aborts.hash().to_string()])
        );

        let full = ok(f.api.answer(
            &Call::Block {
                height: Some(1),
                full: true,
            },
            &facts,
        ));
        assert_eq!(full["transactions"][0]["outcome"]["status"], "success");
        assert_eq!(full["transactions"][1]["outcome"]["status"], "aborted");
        assert_eq!(
            full["transactions"][1]["outcome"]["reason"],
            "ExecutionFailed"
        );
    }

    #[test]
    fn a_block_with_no_aborts_counts_none_and_an_empty_block_none_either() {
        let f = fixture();
        let facts = Facts::new();
        commit(&f.engine, vec![bump(101, DEVNET_CHAIN, 0, 1)]);
        commit(&f.engine, Vec::new());
        for height in [1, 2] {
            let block = ok(f.api.answer(
                &Call::Block {
                    height: Some(height),
                    full: true,
                },
                &facts,
            ));
            assert_eq!(block["abortedCount"], 0, "height {height}");
        }
    }

    #[test]
    fn an_index_entry_that_does_not_match_its_block_is_refused_not_answered_from() {
        let block = chain_engine_api::Block {
            parent_block_hash: Hash::from_bytes([0; 32]),
            height: BlockHeight(1),
            timestamp_millis: 1,
            transactions: vec![bump(101, DEVNET_CHAIN, 0, 1), bump(102, DEVNET_CHAIN, 0, 1)],
        };
        let (first, second) = (block.transactions[0].hash(), block.transactions[1].hash());
        assert_eq!(locate(&block, 0, &first).unwrap(), 0);
        assert_eq!(locate(&block, 1, &second).unwrap(), 1);
        for (index, hash) in [
            (1, first),                     // another transaction is there
            (0, second),                    // and the other way
            (2, first),                     // past the end
            (u32::MAX, first),              // far past it
            (0, Hash::from_bytes([9; 32])), // not in the block at all
        ] {
            let error = locate(&block, index, &hash).unwrap_err();
            assert_eq!(error.code, RpcError::UNAVAILABLE, "{index}");
            assert!(error.message.contains("disagree"), "{error}");
        }
    }

    #[test]
    fn a_transaction_that_was_never_here_is_not_found_and_says_what_that_can_mean() {
        let f = fixture();
        let facts = Facts::new();
        let error = f
            .api
            .answer(
                &Call::Transaction {
                    hash: Hash::from_bytes([5; 32]),
                },
                &facts,
            )
            .unwrap_err();
        assert_eq!(error.code, RpcError::NOT_FOUND);
        assert!(error.message.contains("expired"), "{error}");
    }

    #[test]
    fn a_block_that_is_not_there_says_so_and_says_where_the_chain_is() {
        let f = fixture();
        let facts = Facts::new();
        let ahead = f
            .api
            .answer(
                &Call::Block {
                    height: Some(9),
                    full: false,
                },
                &facts,
            )
            .unwrap_err();
        assert_eq!(ahead.code, RpcError::NOT_FOUND);
        assert!(ahead.message.contains("the chain is at 0"), "{ahead}");

        // There is no stored block 0: the genesis is what the chain starts from.
        let genesis = f
            .api
            .answer(
                &Call::Block {
                    height: Some(0),
                    full: false,
                },
                &facts,
            )
            .unwrap_err();
        assert_eq!(genesis.code, RpcError::NOT_FOUND);
        assert!(genesis.message.contains("genesis"), "{genesis}");
    }

    #[test]
    fn an_address_with_nothing_stored_lists_no_drawers_and_an_empty_one_is_not_found() {
        let f = fixture();
        let facts = Facts::new();
        let owner = account_of(1);
        let listed = ok(f.api.answer(&Call::MoveResources { owner }, &facts));
        assert_eq!(listed["resources"], json!([]));
        assert_eq!(listed["owner"], format_address(&owner));
        let reply = f.api.answer(
            &Call::MoveResource {
                owner,
                type_name: "0x1::m::T".into(),
                slot: 3,
            },
            &facts,
        );
        let error = reply.unwrap_err();
        assert_eq!(error.code, RpcError::NOT_FOUND);
        assert!(
            error.message.contains("slot 3") && error.message.contains("0x1::m::T"),
            "{}",
            error.message
        );
    }

    fn a_transfer(seed: u8) -> Transaction {
        signed_transfer(
            &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            1,
            0,
            100,
            account_of(9),
            1,
            2,
        )
        .unwrap()
    }

    #[test]
    fn simulate_is_off_unless_the_node_says_so() {
        let f = fixture_with(false);
        let error = f
            .api
            .answer(
                &Call::Simulate {
                    transaction: Box::new(a_transfer(1)),
                },
                &Facts::new(),
            )
            .unwrap_err();
        assert_eq!(error.code, RpcError::UNAVAILABLE);
        assert!(error.message.contains("rpc.simulate"), "{}", error.message);
    }

    #[test]
    fn a_simulation_of_something_that_is_not_a_package_call_says_so_and_they_are_spaced_out() {
        let f = fixture();
        let facts = Facts::new();
        let call = Call::Simulate {
            transaction: Box::new(a_transfer(1)),
        };
        let error = f.api.answer(&call, &facts).unwrap_err();
        assert_eq!(error.code, RpcError::INVALID_PARAMS);
        assert!(
            error.message.contains("published packages"),
            "{}",
            error.message
        );
        // Straight after, another is refused as busy, whatever it is.
        let again = f.api.answer(&call, &facts).unwrap_err();
        assert_eq!(again.code, RpcError::UNAVAILABLE);
        assert!(again.message.contains("a moment ago"), "{}", again.message);
        // And after the spacing, it is served again.
        std::thread::sleep(SIMULATION_SPACING + std::time::Duration::from_millis(50));
        assert_eq!(
            f.api.answer(&call, &facts).unwrap_err().code,
            RpcError::INVALID_PARAMS
        );
    }

    #[test]
    fn decoded_values_become_json_with_numbers_as_text() {
        let value = ViewValue::Struct {
            type_name: "0x1::m::T".into(),
            fields: vec![
                ("n".into(), ViewValue::Number(u128::MAX.to_string())),
                ("ok".into(), ViewValue::Bool(true)),
                (
                    "who".into(),
                    ViewValue::Address(AccountAddress::new([7; 32])),
                ),
                (
                    "xs".into(),
                    ViewValue::Vector(vec![ViewValue::Number("1".into())]),
                ),
                (
                    "k".into(),
                    ViewValue::Variant {
                        type_name: "0x1::m::K".into(),
                        variant: "B".into(),
                        fields: vec![],
                    },
                ),
            ],
        };
        let json = view_json(&value);
        assert_eq!(json["_type"], "0x1::m::T");
        assert_eq!(json["n"], u128::MAX.to_string());
        assert_eq!(json["ok"], true);
        assert_eq!(json["who"], format_address(&Address::from_bytes([7; 32])));
        assert_eq!(json["xs"], json!(["1"]));
        assert_eq!(json["k"]["_variant"], "B");
    }

    #[test]
    fn a_commit_the_node_does_not_hold_is_not_found_and_one_past_the_head_says_so() {
        let f = fixture();
        let facts = Facts::new();
        let not_held = f
            .api
            .answer(&Call::Commit { height: None }, &facts)
            .unwrap_err();
        assert_eq!(not_held.code, RpcError::NOT_FOUND);
        let ahead = f
            .api
            .answer(&Call::Commit { height: Some(5) }, &facts)
            .unwrap_err();
        assert!(ahead.message.contains("yet"), "{ahead}");
    }

    /// A client's request, on its own thread, waiting for the answer.
    fn client(address: std::net::SocketAddr, answered: Arc<AtomicUsize>) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let body = r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#;
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            write!(
                stream,
                "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            let mut text = String::new();
            let _ = stream.read_to_string(&mut text);
            if text.contains("\"result\"") {
                answered.fetch_add(1, Ordering::SeqCst);
            }
        })
    }

    #[test]
    fn only_so_many_calls_are_answered_in_one_pass_so_a_burst_cannot_hold_up_consensus() {
        let (dir, engine, pool) = chain();
        let _keep = dir;
        let mut config = ServerConfig::at("127.0.0.1:0".parse().unwrap());
        config.workers = 40;
        config.backlog = 64;
        config.pending_calls = 64;
        let (server, inbox) = Server::start(config).unwrap();
        let genesis = devnet::config().unwrap();
        let mut api = NodeApi::new(
            engine,
            pool,
            inbox,
            genesis.chain_id(),
            genesis.hash(),
            Address::from_bytes([9; 32]),
            false,
        );

        let answered = Arc::new(AtomicUsize::new(0));
        let clients: Vec<_> = (0..MAX_CALLS_PER_PASS + 5)
            .map(|_| client(server.local_addr(), Arc::clone(&answered)))
            .collect();
        // Let every request arrive: they are all waiting on the node.
        thread::sleep(Duration::from_millis(700));
        assert_eq!(answered.load(Ordering::SeqCst), 0);

        let facts = Facts::new();
        api.serve(&facts);
        thread::sleep(Duration::from_millis(300));
        assert_eq!(
            answered.load(Ordering::SeqCst),
            MAX_CALLS_PER_PASS,
            "one pass answers its share"
        );
        api.serve(&facts);
        for client in clients {
            client.join().unwrap();
        }
        assert_eq!(answered.load(Ordering::SeqCst), MAX_CALLS_PER_PASS + 5);
    }
}
