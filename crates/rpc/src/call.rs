//! The JSON-RPC 2.0 messages: what is asked, and how the answer is written.
//!
//! Nine methods, and only these (`docs/spec.md` does not name any; these are what
//! its gates need of an interface):
//!
//! | Method | Params | Why it exists |
//! |---|---|---|
//! | `status` | none | "Monitoring alerts operators automatically": the condition is machine-detectable |
//! | `block` | `height` (default: the latest), `full` (default `false`) | A checkpoint is "block height and state root"; a client finds its transaction here |
//! | `commit` | `height` (default: the latest) | "Every node publishes its last commit certificate": the recovery point |
//! | `account` | `address` | The next sequence number and the balance a client needs to build a valid transaction |
//! | `send_transaction` | `transaction`: the canonical encoding, in hex | Submitting one |
//! | `transaction` | `hash`: 64 hex digits | What became of one: still pending, or in which block, and whether it succeeded or aborted and why |
//! | `move_resource` | `owner`, `type`, `slot` (default 0) | What a Move package has stored: one drawer, its bytes and its value read by its type |
//! | `move_resources` | `owner` | The drawers an address has |
//! | `simulate` | `transaction`: the canonical encoding, in hex | What a call to a published package would do, without committing it. Off unless the node's `rpc.simulate` is set |
//!
//! Parameters are a JSON object, or absent. Addresses are `thry1…`, hashes and
//! byte strings are hex, and a token amount is a decimal string in base units
//! (JSON numbers cannot hold one). A request is read strictly: an unknown
//! member is an error, so a misspelt parameter cannot quietly take its default.

use chain_types::{decode_exact, Address, Hash, Transaction};
use serde_json::{json, Map, Value};

use crate::hex;

/// The largest transaction accepted, in bytes of canonical encoding.
pub const MAX_TRANSACTION_BYTES: usize = 256 * 1024;

/// A transaction's identifier: the domain-separated hash of its canonical
/// encoding, signature included. It is what `send_transaction` returns and what
/// `block` lists.
pub fn transaction_hash(transaction: &Transaction) -> Hash {
    transaction.hash()
}

/// What a client asks the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Status,
    Block {
        height: Option<u64>,
        full: bool,
    },
    Commit {
        height: Option<u64>,
    },
    Account {
        address: Address,
    },
    SendTransaction {
        transaction: Box<Transaction>,
    },
    Transaction {
        hash: Hash,
    },
    MoveResource {
        owner: Address,
        type_name: String,
        slot: u64,
    },
    MoveResources {
        owner: Address,
    },
    Simulate {
        transaction: Box<Transaction>,
    },
}

/// An error in JSON-RPC's shape. The codes from -32768 to -32000 are the
/// specification's; the ones below -32000 in this range are this node's.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub const PARSE: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    /// The node cannot answer now: busy, shutting down, or halted.
    pub const UNAVAILABLE: i64 = -32000;
    /// What was asked for does not exist (here).
    pub const NOT_FOUND: i64 = -32001;
    /// A transaction the pool refused; `data.reason` says which rule.
    pub const REFUSED: i64 = -32010;

    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(Self::INVALID_PARAMS, message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(Self::UNAVAILABLE, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Self::NOT_FOUND, message)
    }

    fn to_json(&self) -> Value {
        let mut error = Map::new();
        error.insert("code".into(), json!(self.code));
        error.insert("message".into(), json!(self.message));
        if let Some(data) = &self.data {
            error.insert("data".into(), data.clone());
        }
        Value::Object(error)
    }
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// The answer to a [`Call`]: a JSON value, or an error.
pub type Reply = Result<Value, RpcError>;

/// A request read from a client: what it asks, and the `id` to answer it under.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: Value,
    pub call: Call,
}

/// A request that could not be read. It carries the `id` if one could be found,
/// since an answer is owed under it.
#[derive(Debug, Clone, PartialEq)]
pub struct Malformed {
    pub id: Value,
    pub error: RpcError,
}

fn malformed(id: &Value, error: RpcError) -> Malformed {
    Malformed {
        id: id.clone(),
        error,
    }
}

/// Reads one request from the bytes of an HTTP body.
pub fn parse(body: &[u8]) -> Result<Request, Malformed> {
    let value: Value = serde_json::from_slice(body).map_err(|error| {
        malformed(
            &Value::Null,
            RpcError::new(RpcError::PARSE, format!("not JSON: {error}")),
        )
    })?;
    let Value::Object(mut members) = value else {
        let message = if value.is_array() {
            "batches are not supported: send one request at a time"
        } else {
            "a request is a JSON object"
        };
        return Err(malformed(
            &Value::Null,
            RpcError::new(RpcError::INVALID_REQUEST, message),
        ));
    };
    let id = members.remove("id");
    // Answered under the id when it is one; a notification (no id) is not a
    // thing this interface answers, since every method here is a question.
    let id = match id {
        Some(id @ (Value::Null | Value::Number(_) | Value::String(_))) => id,
        Some(_) => {
            return Err(malformed(
                &Value::Null,
                RpcError::new(
                    RpcError::INVALID_REQUEST,
                    "`id` is a number, a string or null",
                ),
            ))
        }
        None => {
            return Err(malformed(
                &Value::Null,
                RpcError::new(RpcError::INVALID_REQUEST, "`id` is required"),
            ))
        }
    };
    if members.remove("jsonrpc") != Some(Value::String("2.0".into())) {
        return Err(malformed(
            &id,
            RpcError::new(RpcError::INVALID_REQUEST, "`jsonrpc` must be \"2.0\""),
        ));
    }
    let Some(Value::String(method)) = members.remove("method") else {
        return Err(malformed(
            &id,
            RpcError::new(RpcError::INVALID_REQUEST, "`method` is a string"),
        ));
    };
    let params = match members.remove("params") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(params)) => params,
        Some(_) => {
            return Err(malformed(
                &id,
                RpcError::invalid_params("`params` is an object with named members"),
            ))
        }
    };
    if let Some(extra) = members.keys().next() {
        return Err(malformed(
            &id,
            RpcError::new(
                RpcError::INVALID_REQUEST,
                format!("unknown member `{extra}`"),
            ),
        ));
    }
    let call = call_from(&method, params).map_err(|error| malformed(&id, error))?;
    Ok(Request { id, call })
}

/// Takes `name` out of `params` as a height: a non-negative integer.
fn height_param(params: &mut Map<String, Value>, name: &str) -> Result<Option<u64>, RpcError> {
    match params.remove(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            RpcError::invalid_params(format!("`{name}` is a whole number, zero or more"))
        }),
        Some(_) => Err(RpcError::invalid_params(format!(
            "`{name}` is a whole number, zero or more"
        ))),
    }
}

fn string_param(params: &mut Map<String, Value>, name: &str) -> Result<String, RpcError> {
    match params.remove(name) {
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(RpcError::invalid_params(format!("`{name}` is a string"))),
        None => Err(RpcError::invalid_params(format!("`{name}` is required"))),
    }
}

/// Takes `name` out of `params` as an address in its `thry1…` text form.
fn address_param(params: &mut Map<String, Value>, name: &str) -> Result<Address, RpcError> {
    let text = string_param(params, name)?;
    chain_text::parse_address(&text)
        .map_err(|error| RpcError::invalid_params(format!("`{name}`: {error}")))
}

/// Takes `transaction` out of `params`: the canonical encoding, in hex.
fn transaction_param(params: &mut Map<String, Value>) -> Result<Box<Transaction>, RpcError> {
    let text = string_param(params, "transaction")?;
    // The size is checked on the text, before it is turned into bytes.
    if text.len() > MAX_TRANSACTION_BYTES.saturating_mul(2).saturating_add(2) {
        return Err(RpcError::invalid_params(format!(
            "`transaction` is over the {MAX_TRANSACTION_BYTES}-byte limit"
        )));
    }
    let bytes = hex::decode(&text)
        .map_err(|error| RpcError::invalid_params(format!("`transaction` {error}")))?;
    let transaction: Transaction = decode_exact(&bytes).map_err(|error| {
        RpcError::invalid_params(format!(
            "`transaction` is not a transaction in the canonical encoding: {error}"
        ))
    })?;
    Ok(Box::new(transaction))
}

fn nothing_else(params: Map<String, Value>) -> Result<(), RpcError> {
    match params.keys().next() {
        Some(name) => Err(RpcError::invalid_params(format!(
            "unknown parameter `{name}`"
        ))),
        None => Ok(()),
    }
}

fn call_from(method: &str, mut params: Map<String, Value>) -> Result<Call, RpcError> {
    match method {
        "status" => {
            nothing_else(params)?;
            Ok(Call::Status)
        }
        "block" => {
            let height = height_param(&mut params, "height")?;
            let full = match params.remove("full") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(full)) => full,
                Some(_) => return Err(RpcError::invalid_params("`full` is true or false")),
            };
            nothing_else(params)?;
            Ok(Call::Block { height, full })
        }
        "commit" => {
            let height = height_param(&mut params, "height")?;
            nothing_else(params)?;
            Ok(Call::Commit { height })
        }
        "account" => {
            let text = string_param(&mut params, "address")?;
            nothing_else(params)?;
            let address = chain_text::parse_address(&text)
                .map_err(|error| RpcError::invalid_params(format!("`address`: {error}")))?;
            Ok(Call::Account { address })
        }
        "send_transaction" => {
            let transaction = transaction_param(&mut params)?;
            nothing_else(params)?;
            Ok(Call::SendTransaction { transaction })
        }
        "transaction" => {
            let text = string_param(&mut params, "hash")?;
            nothing_else(params)?;
            let bytes = hex::decode(&text)
                .map_err(|error| RpcError::invalid_params(format!("`hash` {error}")))?;
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                RpcError::invalid_params("`hash` is 32 bytes: 64 hexadecimal digits")
            })?;
            Ok(Call::Transaction {
                hash: Hash::from_bytes(bytes),
            })
        }
        "move_resource" => {
            let owner = address_param(&mut params, "owner")?;
            let type_name = string_param(&mut params, "type")?;
            if type_name.len() > 256 {
                return Err(RpcError::invalid_params("`type` is over 256 bytes"));
            }
            let slot = height_param(&mut params, "slot")?.unwrap_or(0);
            nothing_else(params)?;
            Ok(Call::MoveResource { owner, type_name, slot })
        }
        "move_resources" => {
            let owner = address_param(&mut params, "owner")?;
            nothing_else(params)?;
            Ok(Call::MoveResources { owner })
        }
        "simulate" => {
            let transaction = transaction_param(&mut params)?;
            nothing_else(params)?;
            Ok(Call::Simulate { transaction })
        }
        other => Err(RpcError::new(
            RpcError::METHOD_NOT_FOUND,
            format!("no method `{other}`; there are status, block, commit, account, send_transaction, transaction, move_resource, move_resources and simulate"),
        )),
    }
}

/// The body of a successful response.
pub fn success(id: &Value, result: Value) -> Vec<u8> {
    to_bytes(&json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// The body of an error response.
pub fn failure(id: &Value, error: &RpcError) -> Vec<u8> {
    to_bytes(&json!({ "jsonrpc": "2.0", "id": id, "error": error.to_json() }))
}

/// The body answering `reply` under `id`.
pub fn respond(id: &Value, reply: Reply) -> Vec<u8> {
    match reply {
        Ok(result) => success(id, result),
        Err(error) => failure(id, &error),
    }
}

fn to_bytes(value: &Value) -> Vec<u8> {
    // A `Value` always serialises.
    serde_json::to_vec(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use chain_types::Encode;

    use super::*;

    fn request(text: &str) -> Result<Request, Malformed> {
        parse(text.as_bytes())
    }

    fn refused(text: &str) -> RpcError {
        request(text).unwrap_err().error
    }

    #[test]
    fn each_method_reads_its_parameters() {
        let call = |text: &str| request(text).unwrap().call;
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#),
            Call::Status
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{}}"#),
            Call::Status
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"block"}"#),
            Call::Block {
                height: None,
                full: false
            }
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"height":7,"full":true}}"#),
            Call::Block {
                height: Some(7),
                full: true
            }
        );
        assert_eq!(
            call(r#"{"jsonrpc":"2.0","id":1,"method":"commit","params":{"height":0}}"#),
            Call::Commit { height: Some(0) }
        );
        let address = Address::from_bytes([7; 32]);
        let text = chain_text::format_address(&address);
        assert_eq!(
            call(&format!(
                r#"{{"jsonrpc":"2.0","id":"a","method":"account","params":{{"address":"{text}"}}}}"#
            )),
            Call::Account { address }
        );
        let hash = Hash::from_bytes([0xab; 32]);
        assert_eq!(
            call(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"transaction","params":{{"hash":"{hash}"}}}}"#
            )),
            Call::Transaction { hash }
        );
        // Capital letters are the same digits.
        assert_eq!(
            call(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"transaction","params":{{"hash":"{}"}}}}"#,
                hash.to_string().to_uppercase()
            )),
            Call::Transaction { hash }
        );
    }

    #[test]
    fn the_id_is_answered_as_it_came() {
        for id in ["1", "\"abc\"", "null", "18446744073709551615"] {
            let text = format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"status"}}"#);
            let read = request(&text).unwrap();
            let body = respond(&read.id, Ok(json!("ok")));
            let answer: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(answer["id"], serde_json::from_str::<Value>(id).unwrap());
            assert_eq!(answer["jsonrpc"], "2.0");
            assert_eq!(answer["result"], "ok");
        }
    }

    #[test]
    fn what_is_not_a_request_is_refused_with_the_right_code() {
        for (text, code) in [
            ("", RpcError::PARSE),
            ("not json", RpcError::PARSE),
            ("[]", RpcError::INVALID_REQUEST),
            (
                r#"[{"jsonrpc":"2.0","id":1,"method":"status"}]"#,
                RpcError::INVALID_REQUEST,
            ),
            ("3", RpcError::INVALID_REQUEST),
            (
                r#"{"jsonrpc":"2.0","method":"status"}"#,
                RpcError::INVALID_REQUEST,
            ),
            (
                r#"{"jsonrpc":"2.0","id":[1],"method":"status"}"#,
                RpcError::INVALID_REQUEST,
            ),
            (
                r#"{"jsonrpc":"1.0","id":1,"method":"status"}"#,
                RpcError::INVALID_REQUEST,
            ),
            (r#"{"id":1,"method":"status"}"#, RpcError::INVALID_REQUEST),
            (r#"{"jsonrpc":"2.0","id":1}"#, RpcError::INVALID_REQUEST),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":5}"#,
                RpcError::INVALID_REQUEST,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"status","extra":1}"#,
                RpcError::INVALID_REQUEST,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"nothing"}"#,
                RpcError::METHOD_NOT_FOUND,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"status","params":[]}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"status","params":{"x":1}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"height":-1}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"height":1.5}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"height":"7"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"full":"yes"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"block","params":{"hieght":3}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"transaction"}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"transaction","params":{"hash":"abcd"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"transaction","params":{"hash":"zz"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"transaction","params":{"hash":7}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"transaction","params":{"hash":"00","txid":1}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"account"}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"account","params":{"address":"nope"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"send_transaction","params":{"transaction":"zz"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"send_transaction","params":{"transaction":"abc"}}"#,
                RpcError::INVALID_PARAMS,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"send_transaction","params":{"transaction":"00"}}"#,
                RpcError::INVALID_PARAMS,
            ),
        ] {
            let error = refused(text);
            assert_eq!(error.code, code, "{text}: {error}");
        }
    }

    #[test]
    fn a_refused_request_still_says_which_id_it_was_answered_under_when_it_had_one() {
        let error = request(r#"{"jsonrpc":"2.0","id":42,"method":"nothing"}"#).unwrap_err();
        assert_eq!(error.id, json!(42));
        let error = request("garbage").unwrap_err();
        assert_eq!(error.id, Value::Null);
    }

    #[test]
    fn a_misspelt_address_says_what_is_wrong_with_it() {
        let address = chain_text::format_address(&Address::from_bytes([1; 32]));
        let mut typo = address.clone();
        typo.replace_range(12..13, if &address[12..13] == "q" { "p" } else { "q" });
        let text = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"account","params":{{"address":"{typo}"}}}}"#
        );
        let error = refused(&text);
        assert!(error.message.contains("`address`"), "{error}");
    }

    #[test]
    fn a_transaction_is_read_only_from_exactly_its_canonical_bytes() {
        let key = [3u8; 32];
        let _ = key;
        // A transaction encoded, then the same with a byte on the end and with
        // one taken off: only the first is a transaction.
        let transaction = sample_transaction();
        let mut bytes = Vec::new();
        transaction.encode(&mut bytes);
        let ask = |bytes: &[u8]| {
            request(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"send_transaction","params":{{"transaction":"{}"}}}}"#,
                hex::encode(bytes)
            ))
        };
        assert_eq!(
            ask(&bytes).unwrap().call,
            Call::SendTransaction {
                transaction: Box::new(transaction)
            }
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            ask(&longer).unwrap_err().error.code,
            RpcError::INVALID_PARAMS
        );
        assert_eq!(
            ask(&bytes[..bytes.len() - 1]).unwrap_err().error.code,
            RpcError::INVALID_PARAMS
        );
    }

    #[test]
    fn an_oversized_transaction_is_refused_before_it_is_decoded() {
        let text = "0".repeat(MAX_TRANSACTION_BYTES * 2 + 10);
        let error = refused(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"send_transaction","params":{{"transaction":"{text}"}}}}"#
        ));
        assert!(error.message.contains("limit"), "{error}");
    }

    #[test]
    fn an_error_carries_its_data_when_it_has_some() {
        let with = RpcError::new(RpcError::REFUSED, "no").with_data(json!({"reason": "X"}));
        let body: Value = serde_json::from_slice(&failure(&json!(1), &with)).unwrap();
        assert_eq!(body["error"]["code"], RpcError::REFUSED);
        assert_eq!(body["error"]["data"]["reason"], "X");
        let without: Value =
            serde_json::from_slice(&failure(&json!(1), &RpcError::not_found("x"))).unwrap();
        assert!(without["error"].get("data").is_none());
    }

    /// Any well-formed transaction will do.
    fn sample_transaction() -> Transaction {
        use chain_types::{
            ChainId, GasAmount, GasPrice, MoveCall, PublicKey, SequenceNumber, Signature,
            TransactionBody,
        };
        Transaction {
            body: TransactionBody {
                chain_id: ChainId(1),
                sender: PublicKey::from_ed25519_bytes(ed25519_public_key_for_tests()).unwrap(),
                sequence_number: SequenceNumber(0),
                expiry: chain_types::BlockHeight(10),
                gas_limit: GasAmount(1_000),
                max_fee_per_gas: GasPrice(1),
                declared_inputs: Vec::new(),
                call: MoveCall {
                    module_address: Address::from_bytes([2; 32]),
                    module_name: b"m".to_vec(),
                    function_name: b"f".to_vec(),
                    type_arguments: Vec::new(),
                    arguments: Vec::new(),
                },
            },
            signature: Signature::from_ed25519_bytes([9; 64]),
        }
    }

    /// A valid Ed25519 point (the base point), without a signing library.
    fn ed25519_public_key_for_tests() -> [u8; 32] {
        let mut point = [0u8; 32];
        point[0] = 0x58;
        point[1..].fill(0x66);
        point
    }

    #[test]
    fn the_storage_methods_read_their_parameters_strictly() {
        let owner = chain_text::format_address(&Address::from_bytes([3; 32]));
        let ok = |body: String| request(&body).unwrap().call;
        assert_eq!(
            ok(format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}","type":"0x1::m::T"}}}}"#
            )),
            Call::MoveResource {
                owner: Address::from_bytes([3; 32]),
                type_name: "0x1::m::T".into(),
                slot: 0
            },
            "the slot defaults to 0"
        );
        assert_eq!(
            ok(format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}","type":"T","slot":9}}}}"#
            )),
            Call::MoveResource {
                owner: Address::from_bytes([3; 32]),
                type_name: "T".into(),
                slot: 9
            }
        );
        assert_eq!(
            ok(format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"move_resources","params":{{"owner":"{owner}"}}}}"#
            )),
            Call::MoveResources {
                owner: Address::from_bytes([3; 32])
            }
        );
        let bad = |body: String| request(&body).unwrap_err();
        for body in [
            // No owner, no type, a bad owner, a negative or fractional slot, an unknown member.
            r#"{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{"type":"T"}}"#.to_owned(),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}"}}}}"#),
            r#"{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{"owner":"nope","type":"T"}}"#.to_owned(),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}","type":"T","slot":-1}}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}","type":"T","slot":1.5}}}}"#),
            format!(r#"{{"jsonrpc":"2.0","id":1,"method":"move_resources","params":{{"owner":"{owner}","limit":5}}}}"#),
            format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"move_resource","params":{{"owner":"{owner}","type":"{}"}}}}"#,
                "x".repeat(257)
            ),
            r#"{"jsonrpc":"2.0","id":1,"method":"simulate","params":{}}"#.to_owned(),
            r#"{"jsonrpc":"2.0","id":1,"method":"simulate","params":{"transaction":"zz"}}"#.to_owned(),
        ] {
            let error = bad(body.clone());
            assert_eq!(error.error.code, RpcError::INVALID_PARAMS, "{body}");
        }
    }
}
