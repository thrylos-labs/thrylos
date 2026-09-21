//! A small RPC client, and what `chain-node devnet bump` does with it.
//!
//! The client is plain HTTP over a socket and nothing more: one JSON-RPC call
//! per connection, as `chain-rpc` serves it. [`bump`] is the whole developer
//! loop on a generated network in one command: read an account's next sequence
//! number, sign a call to the genesis counter with a funded devnet account (whose
//! keys are public, like everything else in the development genesis), send it,
//! and watch for the block that includes it.

// Indexing a `serde_json::Value` by a name never panics: what is missing reads as
// `null`. The lint cannot know that, and every use here is followed by a check.
#![allow(clippy::indexing_slicing)]
// Waiting for a block is real time, which nothing consensus reads.
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use chain_exec::genesis::{
    COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME, COUNTER_PACKAGE_ADDRESS, INITIAL_COUNTER_ADDRESS,
};
use chain_rpc::call::transaction_hash;
use chain_rpc::hex;
use chain_rpc::RpcError;
use chain_text::format_address;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::config::NodeConfig;
use crate::devnet::{nodes_in, DevnetError};

/// How long to wait for a transaction to be included.
pub const INCLUSION_PATIENCE: Duration = Duration::from_secs(60);

/// Why a call, or the command built on it, did not work.
#[derive(Debug)]
pub enum ClientError {
    /// The network, or the server's HTTP, misbehaved.
    Transport(String),
    /// The node answered with a JSON-RPC error.
    Rpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    /// The directory is not a network, or the choice of node or account is wrong.
    Setup(String),
    /// The transaction was sent and not seen included in time.
    NotIncluded { hash: String },
    /// The transaction was included, and aborted when it ran.
    Aborted {
        hash: String,
        height: u64,
        reason: String,
        message: String,
    },
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(message) => write!(f, "{message}"),
            Self::Rpc {
                code,
                message,
                data,
            } => {
                write!(f, "the node refused: {message} (code {code})")?;
                if let Some(reason) = data.as_ref().and_then(|d| d.get("reason")) {
                    write!(f, " [{}]", reason.as_str().unwrap_or("?"))?;
                }
                Ok(())
            }
            Self::Setup(message) => write!(f, "{message}"),
            Self::Aborted {
                hash,
                height,
                reason,
                message,
            } => write!(
                f,
                "transaction {hash} was included in block {height} and aborted: {message} \
                 ({reason}); it was still charged its fee and used its sequence number"
            ),
            Self::NotIncluded { hash } => write!(
                f,
                "transaction {hash} was sent, and was not seen in a block within {} seconds: \
                 it may still be pending",
                INCLUSION_PATIENCE.as_secs()
            ),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<DevnetError> for ClientError {
    fn from(error: DevnetError) -> Self {
        Self::Setup(error.to_string())
    }
}

fn transport(error: impl core::fmt::Display) -> ClientError {
    ClientError::Transport(error.to_string())
}

/// A client of one node's RPC.
#[derive(Debug, Clone, Copy)]
pub struct RpcClient {
    pub address: SocketAddr,
}

impl RpcClient {
    /// One call. A JSON-RPC error becomes [`ClientError::Rpc`].
    pub fn call(&self, method: &str, params: &Value) -> Result<Value, ClientError> {
        let body =
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        let mut stream = TcpStream::connect_timeout(&self.address, Duration::from_secs(5))
            .map_err(|error| {
                ClientError::Transport(format!(
                    "cannot reach the RPC at {}: {error} (is the network running?)",
                    self.address
                ))
            })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(transport)?;
        write!(
            stream,
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.address,
            body.len()
        )
        .map_err(transport)?;
        let mut text = String::new();
        stream.read_to_string(&mut text).map_err(transport)?;
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| ClientError::Transport("no HTTP response".into()))?;
        if !head.starts_with("HTTP/1.1 200") {
            return Err(ClientError::Transport(format!(
                "the RPC answered `{}`",
                head.lines().next().unwrap_or_default()
            )));
        }
        let mut response: Value = serde_json::from_str(body).map_err(transport)?;
        if let Some(error) = response.get_mut("error").map(Value::take) {
            return Err(ClientError::Rpc {
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"].as_str().unwrap_or_default().to_owned(),
                data: error.get("data").cloned(),
            });
        }
        Ok(response["result"].take())
    }
}

/// How many blocks a transaction this client signs stays valid for: well inside
/// the horizon a transaction may expire in.
pub const EXPIRES_AFTER: u64 = 1_000;

/// A signed call to the genesis counter's `bump`, from the devnet account with
/// this seed (101 to 104 are funded), for `chain_id` at `sequence`, valid until
/// height `expiry`.
pub fn signed_counter_bump(
    seed: u8,
    chain_id: u64,
    sequence: u64,
    expiry: u64,
    amount: u64,
) -> Result<Transaction, ClientError> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let sender = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
        .map_err(|_| ClientError::Setup("the signing key is not a valid public key".into()))?;
    let body = TransactionBody {
        chain_id: ChainId(chain_id),
        sender,
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(expiry),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(1),
        declared_inputs: vec![Address::from_bytes(INITIAL_COUNTER_ADDRESS.into_bytes())],
        call: MoveCall {
            module_address: Address::from_bytes(COUNTER_PACKAGE_ADDRESS.into_bytes()),
            module_name: COUNTER_MODULE_NAME.as_bytes().to_vec(),
            function_name: COUNTER_BUMP_FUNCTION.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![amount.to_le_bytes().to_vec()],
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    let signature = Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes());
    Ok(Transaction { body, signature })
}

/// What `devnet bump` reports as it goes.
pub type Say<'a> = &'a mut dyn FnMut(String);

/// Sends a bump of the counter, by `amount`, from devnet account `account`
/// (1 to 4), through node `node`'s RPC, and waits to see the block that has it.
pub fn bump(
    network: &Path,
    node: usize,
    account: u8,
    amount: u64,
    say: Say<'_>,
) -> Result<(), ClientError> {
    if !(1..=4).contains(&account) {
        return Err(ClientError::Setup(format!(
            "account {account}: the development genesis funds accounts 1 to 4"
        )));
    }
    let nodes = nodes_in(network)?;
    let chosen = nodes
        .iter()
        .find(|candidate| candidate.number == node)
        .ok_or_else(|| ClientError::Setup(format!("the network has no node {node}")))?;
    let config = NodeConfig::load(&chosen.config())
        .map_err(|error| ClientError::Setup(error.to_string()))?;
    let address = config.rpc_listen.ok_or_else(|| {
        ClientError::Setup(format!("node {node}'s configuration has no `rpc` section"))
    })?;
    let client = RpcClient { address };

    let seed = 100u8.saturating_add(account);
    let sender = chain_genesis::devnet::ed25519(seed)
        .map(|key| Address::from_public_key(&key))
        .map_err(|error| ClientError::Setup(error.to_string()))?;
    let status = client.call("status", &json!({}))?;
    let chain_id = status["chainId"]
        .as_u64()
        .ok_or_else(|| ClientError::Transport("status has no chain ID".into()))?;
    let account_now = client.call("account", &json!({ "address": format_address(&sender) }))?;
    let sequence = account_now["nextSequenceNumber"]
        .as_u64()
        .ok_or_else(|| ClientError::Transport("the account has no sequence number".into()))?;
    say(format!(
        "account {account} ({}) has balance {} and is at sequence {sequence}",
        format_address(&sender),
        account_now["balance"].as_str().unwrap_or("?")
    ));

    let head = status["latest"]["height"].as_u64().unwrap_or(0);
    let transaction = signed_counter_bump(
        seed,
        chain_id,
        sequence,
        head.saturating_add(EXPIRES_AFTER),
        amount,
    )?;
    let mut bytes = Vec::new();
    transaction.encode(&mut bytes);
    let sent = client.call(
        "send_transaction",
        &json!({ "transaction": hex::encode(&bytes) }),
    )?;
    let hash = transaction_hash(&transaction).to_string();
    say(format!(
        "sent {hash} to node {node}: {}",
        sent["status"].as_str().unwrap_or("?")
    ));

    // Ask what became of it until it is in a block. Not finding it at first is
    // not an error: it is on its way.
    let started = Instant::now();
    while started.elapsed() < INCLUSION_PATIENCE {
        match client.call("transaction", &json!({ "hash": hash })) {
            Ok(found) if found["status"] == "included" => {
                say(format!(
                    "included in block {} ({}), position {}",
                    found["height"],
                    found["blockHash"].as_str().unwrap_or("?"),
                    found["index"]
                ));
                let after =
                    client.call("account", &json!({ "address": format_address(&sender) }))?;
                say(format!(
                    "account {account} is now at sequence {}",
                    after["nextSequenceNumber"]
                ));
                let outcome = &found["outcome"];
                return match outcome["status"].as_str() {
                    Some("success") => {
                        say("it succeeded".to_owned());
                        Ok(())
                    }
                    Some("aborted") => Err(ClientError::Aborted {
                        hash,
                        height: found["height"].as_u64().unwrap_or(0),
                        reason: outcome["reason"].as_str().unwrap_or("?").to_owned(),
                        message: outcome["message"].as_str().unwrap_or("").to_owned(),
                    }),
                    _ => {
                        say("its outcome was not recorded by this node".to_owned());
                        Ok(())
                    }
                };
            }
            Ok(_) => {}
            Err(ClientError::Rpc { code, .. }) if code == RpcError::NOT_FOUND => {}
            Err(other) => return Err(other),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(ClientError::NotIncluded { hash })
}
