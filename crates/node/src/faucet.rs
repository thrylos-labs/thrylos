//! Durable policy and transaction queue for the testnet faucet.
//!
//! Discord is only one way to submit a [`FaucetRequest`]. This module owns the
//! rules: one fixed payout, per-user and per-address daily claim caps, a global
//! daily cap, idempotent request IDs and a single prepared transaction at a
//! time. State is atomically replaced and fsynced after every transition, so a
//! restart sees either the old complete queue or the new complete queue.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use chain_exec::native::MIN_PROTOCOL_CALL_GAS;
use chain_rpc::call::transaction_hash;
use chain_rpc::hex;
use chain_text::{format_address, parse_address, parse_amount};
use chain_types::codec::decode_exact;
use chain_types::{Address, Encode, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::atomic::write_atomic;
use crate::client::{
    signed_transfer, submit_transaction, wait_for_inclusion, ClientError, RpcClient, EXPIRES_AFTER,
};
use crate::wallet::Wallet;

const CONFIG_FILE: &str = "faucet.json";
const STATE_FILE: &str = "state.json";
const WALLET_FILE: &str = "faucet.key";
const STATE_VERSION: u32 = 1;
const SECONDS_PER_DAY: u64 = 86_400;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug)]
pub enum FaucetError {
    Setup(String),
    Io { path: PathBuf, problem: String },
    InvalidConfig(String),
    InvalidState(String),
    Client(ClientError),
}

impl core::fmt::Display for FaucetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Setup(message) | Self::InvalidConfig(message) | Self::InvalidState(message) => {
                f.write_str(message)
            }
            Self::Io { path, problem } => write!(f, "{}: {problem}", path.display()),
            Self::Client(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for FaucetError {}

impl From<ClientError> for FaucetError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

fn io(path: &Path, error: impl core::fmt::Display) -> FaucetError {
    FaucetError::Io {
        path: path.to_owned(),
        problem: error.to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaucetConfig {
    /// Local validator or gateway RPC address.
    pub rpc: String,
    /// Amount sent for each accepted request, in human THRY notation.
    pub payout: String,
    pub per_user_daily_claims: u32,
    pub per_address_daily_claims: u32,
    pub global_daily_claims: u32,
    pub max_pending: usize,
    /// How old, in whole days, a Discord account must be to claim. Discord
    /// user IDs are snowflakes that carry their creation time, so this needs
    /// no lookup and cannot be faked by the requester. It is the cheap
    /// defence against one person farming many fresh accounts past the
    /// per-user cap; `0` turns it off.
    #[serde(default = "default_min_account_age_days")]
    pub min_account_age_days: u32,
    /// Discord application public key, as 64 hex digits. `null` until set.
    pub discord_public_key: Option<String>,
}

const fn default_min_account_age_days() -> u32 {
    7
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            rpc: "127.0.0.1:26660".into(),
            payout: "10 THRY".into(),
            per_user_daily_claims: 1,
            per_address_daily_claims: 1,
            global_daily_claims: 100,
            max_pending: 1_000,
            min_account_age_days: default_min_account_age_days(),
            discord_public_key: None,
        }
    }
}

impl FaucetConfig {
    fn validate(&self) -> Result<(), FaucetError> {
        self.rpc.parse::<std::net::SocketAddr>().map_err(|_| {
            FaucetError::InvalidConfig(format!(
                "faucet configuration `rpc` must be an address such as 127.0.0.1:26660, not {:?}",
                self.rpc
            ))
        })?;
        let payout = parse_amount(&self.payout).map_err(|error| {
            FaucetError::InvalidConfig(format!("faucet configuration `payout`: {error}"))
        })?;
        if payout == 0 {
            return Err(FaucetError::InvalidConfig(
                "faucet configuration `payout` must be more than zero".into(),
            ));
        }
        for (value, field) in [
            (self.per_user_daily_claims, "per_user_daily_claims"),
            (self.per_address_daily_claims, "per_address_daily_claims"),
            (self.global_daily_claims, "global_daily_claims"),
        ] {
            if value == 0 {
                return Err(FaucetError::InvalidConfig(format!(
                    "faucet configuration `{field}` must be more than zero"
                )));
            }
        }
        if self.max_pending == 0 || self.max_pending > MAX_RECORDS {
            return Err(FaucetError::InvalidConfig(format!(
                "faucet configuration `max_pending` must be from 1 to {MAX_RECORDS}"
            )));
        }
        if let Some(key) = &self.discord_public_key {
            let bytes = hex::decode(key).map_err(|error| {
                FaucetError::InvalidConfig(format!(
                    "faucet configuration `discord_public_key` {error}"
                ))
            })?;
            if bytes.len() != 32 {
                return Err(FaucetError::InvalidConfig(
                    "faucet configuration `discord_public_key` must be 32 bytes: 64 hexadecimal digits"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    pub fn rpc_client(&self) -> Result<RpcClient, FaucetError> {
        let address = self
            .rpc
            .parse()
            .map_err(|_| FaucetError::InvalidConfig("the faucet RPC address is invalid".into()))?;
        Ok(RpcClient { address })
    }

    pub fn payout_base_units(&self) -> Result<u128, FaucetError> {
        parse_amount(&self.payout).map_err(|error| FaucetError::InvalidConfig(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestStatus {
    Queued,
    Prepared { transaction: String, hash: String },
    Included { hash: String, height: u64 },
    Failed { message: String },
}

impl RequestStatus {
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Prepared { .. } => "processing",
            Self::Included { .. } => "included",
            Self::Failed { .. } => "failed",
        }
    }

    const fn is_pending(&self) -> bool {
        matches!(self, Self::Queued | Self::Prepared { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    pub id: String,
    pub user_id: String,
    pub address: String,
    /// UTC day since the Unix epoch on which the claim was accepted.
    pub day: u64,
    pub status: RequestStatus,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FaucetState {
    version: u32,
    requests: Vec<RequestRecord>,
}

impl Default for FaucetState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            requests: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FaucetRequest<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueResult {
    Queued,
    Existing(RequestStatus),
    UserDailyLimit,
    AddressDailyLimit,
    GlobalDailyLimit,
    QueueFull,
}

#[derive(Debug, Clone)]
pub struct PreparedRequest {
    pub id: String,
    pub hash: String,
    pub transaction: Transaction,
}

#[derive(Debug, Clone)]
pub enum NextWork {
    Prepared(Box<PreparedRequest>),
    Queued { id: String, address: Address },
}

#[derive(Debug, Clone, Copy)]
pub struct TransferContext {
    pub chain_id: u64,
    pub height: u64,
    pub base_fee: u64,
    pub sequence: u64,
    pub balance: u128,
}

#[derive(Debug, Clone)]
pub enum WorkResult {
    Included { hash: String, height: u64 },
    Failed(String),
}

pub struct Faucet {
    directory: PathBuf,
    config: FaucetConfig,
    wallet: Wallet,
    state: FaucetState,
}

impl Faucet {
    /// Create a new faucet directory and its dedicated account key.
    pub fn init(directory: &Path) -> Result<Address, FaucetError> {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(FaucetError::Setup(format!(
                    "{} already exists; choose a new directory so no faucet state is overwritten",
                    directory.display()
                )))
            }
            Err(error) => return Err(io(directory, error)),
        }
        let wallet_path = directory.join(WALLET_FILE);
        let wallet = Wallet::create(&wallet_path).map_err(|error| {
            FaucetError::Setup(format!("could not create the faucet wallet: {error}"))
        })?;
        let config = serde_json::to_vec_pretty(&FaucetConfig::default())
            .map_err(|error| FaucetError::Setup(error.to_string()))?;
        write_atomic(&directory.join(CONFIG_FILE), &config)
            .map_err(|error| io(&directory.join(CONFIG_FILE), error))?;
        let state = serde_json::to_vec_pretty(&FaucetState::default())
            .map_err(|error| FaucetError::Setup(error.to_string()))?;
        write_atomic(&directory.join(STATE_FILE), &state)
            .map_err(|error| io(&directory.join(STATE_FILE), error))?;
        Ok(wallet.address())
    }

    pub fn load(directory: &Path) -> Result<Self, FaucetError> {
        let config_path = directory.join(CONFIG_FILE);
        let state_path = directory.join(STATE_FILE);
        let config: FaucetConfig = read_json(&config_path)?;
        config.validate()?;
        let state: FaucetState = read_json(&state_path)?;
        validate_state(&state)?;
        let wallet = Wallet::load(&directory.join(WALLET_FILE))
            .map_err(|error| FaucetError::Setup(error.to_string()))?;
        Ok(Self {
            directory: directory.to_owned(),
            config,
            wallet,
            state,
        })
    }

    pub const fn config(&self) -> &FaucetConfig {
        &self.config
    }

    pub fn address(&self) -> Address {
        self.wallet.address()
    }

    pub fn enqueue(
        &mut self,
        request: FaucetRequest<'_>,
        day: u64,
    ) -> Result<EnqueueResult, FaucetError> {
        if request.id.is_empty() || request.id.len() > 128 {
            return Err(FaucetError::InvalidState(
                "a faucet request ID must contain 1 to 128 characters".into(),
            ));
        }
        if request.user_id.is_empty() || request.user_id.len() > 128 {
            return Err(FaucetError::InvalidState(
                "a faucet user ID must contain 1 to 128 characters".into(),
            ));
        }
        let address = format_address(&request.address);
        if let Some(existing) = self
            .state
            .requests
            .iter()
            .find(|entry| entry.id == request.id)
        {
            if existing.user_id != request.user_id || existing.address != address {
                return Err(FaucetError::InvalidState(format!(
                    "request ID {:?} was already used for a different claim",
                    request.id
                )));
            }
            return Ok(EnqueueResult::Existing(existing.status.clone()));
        }
        let pending = self
            .state
            .requests
            .iter()
            .filter(|entry| entry.status.is_pending())
            .count();
        if pending >= self.config.max_pending {
            return Ok(EnqueueResult::QueueFull);
        }
        let claims = self.state.requests.iter().filter(|entry| entry.day == day);
        let mut global = 0u32;
        let mut by_user = 0u32;
        let mut by_address = 0u32;
        for entry in claims {
            global = global.saturating_add(1);
            if entry.user_id == request.user_id {
                by_user = by_user.saturating_add(1);
            }
            if entry.address == address {
                by_address = by_address.saturating_add(1);
            }
        }
        if by_user >= self.config.per_user_daily_claims {
            return Ok(EnqueueResult::UserDailyLimit);
        }
        if by_address >= self.config.per_address_daily_claims {
            return Ok(EnqueueResult::AddressDailyLimit);
        }
        if global >= self.config.global_daily_claims {
            return Ok(EnqueueResult::GlobalDailyLimit);
        }
        if self.state.requests.len() >= MAX_RECORDS {
            self.prune(day);
        }
        if self.state.requests.len() >= MAX_RECORDS {
            return Ok(EnqueueResult::QueueFull);
        }
        self.state.requests.push(RequestRecord {
            id: request.id.to_owned(),
            user_id: request.user_id.to_owned(),
            address,
            day,
            status: RequestStatus::Queued,
        });
        self.save()?;
        Ok(EnqueueResult::Queued)
    }

    /// The work at the head of the queue. A prepared transaction always goes
    /// first so only one sequence number can be in flight.
    pub fn next_work(&self) -> Result<Option<NextWork>, FaucetError> {
        if let Some(entry) = self
            .state
            .requests
            .iter()
            .find(|entry| matches!(entry.status, RequestStatus::Prepared { .. }))
        {
            let RequestStatus::Prepared { transaction, hash } = &entry.status else {
                return Ok(None);
            };
            let bytes = hex::decode(transaction).map_err(|error| {
                FaucetError::InvalidState(format!(
                    "prepared request {:?} has an invalid transaction: {error}",
                    entry.id
                ))
            })?;
            let transaction: Transaction = decode_exact(&bytes).map_err(|error| {
                FaucetError::InvalidState(format!(
                    "prepared request {:?} is not a transaction: {error}",
                    entry.id
                ))
            })?;
            if transaction_hash(&transaction).to_string() != *hash {
                return Err(FaucetError::InvalidState(format!(
                    "prepared request {:?}'s transaction hash does not match",
                    entry.id
                )));
            }
            return Ok(Some(NextWork::Prepared(Box::new(PreparedRequest {
                id: entry.id.clone(),
                hash: hash.clone(),
                transaction,
            }))));
        }

        let Some(entry) = self
            .state
            .requests
            .iter()
            .find(|entry| matches!(entry.status, RequestStatus::Queued))
        else {
            return Ok(None);
        };
        let address = parse_address(&entry.address)
            .map_err(|error| FaucetError::InvalidState(error.to_string()))?;
        Ok(Some(NextWork::Queued {
            id: entry.id.clone(),
            address,
        }))
    }

    /// Sign and durably record the next queued request using RPC facts fetched
    /// without holding the service's state lock.
    pub fn prepare(
        &mut self,
        id: &str,
        context: TransferContext,
    ) -> Result<PreparedRequest, FaucetError> {
        if self
            .state
            .requests
            .iter()
            .any(|entry| matches!(entry.status, RequestStatus::Prepared { .. }))
        {
            return Err(FaucetError::InvalidState(
                "another faucet transaction is already prepared".into(),
            ));
        }
        let position = self
            .state
            .requests
            .iter()
            .position(|entry| entry.id == id)
            .ok_or_else(|| FaucetError::InvalidState(format!("no faucet request {id:?}")))?;
        if !matches!(self.state.requests[position].status, RequestStatus::Queued) {
            return Err(FaucetError::InvalidState(format!(
                "faucet request {id:?} is not queued"
            )));
        }
        let recipient = parse_address(&self.state.requests[position].address)
            .map_err(|error| FaucetError::InvalidState(error.to_string()))?;
        let max_fee_per_gas = context.base_fee.saturating_mul(2).max(1);
        let maximum_fee = u128::from(MIN_PROTOCOL_CALL_GAS)
            .checked_mul(u128::from(max_fee_per_gas))
            .ok_or_else(|| FaucetError::Setup("the network fee is too large".into()))?;
        let payout = self.config.payout_base_units()?;
        let needed = payout
            .checked_add(maximum_fee)
            .ok_or_else(|| FaucetError::Setup("the faucet payout and fee are too large".into()))?;
        if needed > context.balance {
            return Err(FaucetError::Setup(format!(
                "the faucet wallet is not funded: {} base units are available and {needed} are needed; fund {}",
                context.balance,
                format_address(&self.wallet.address())
            )));
        }
        let transaction = signed_transfer(
            self.wallet.signing_key(),
            context.chain_id,
            context.sequence,
            context.height.saturating_add(EXPIRES_AFTER),
            recipient,
            payout,
            max_fee_per_gas,
        )?;
        let mut bytes = Vec::new();
        transaction.encode(&mut bytes);
        let hash = transaction_hash(&transaction).to_string();
        self.state.requests[position].status = RequestStatus::Prepared {
            transaction: hex::encode(&bytes),
            hash: hash.clone(),
        };
        self.save()?;
        Ok(PreparedRequest {
            id: id.to_owned(),
            hash,
            transaction,
        })
    }

    /// Convenience for the one-shot operator command. Long-running services
    /// should use [`Self::next_work`], fetch the context without their mutex,
    /// then call [`Self::prepare`].
    pub fn prepare_next(&mut self) -> Result<Option<PreparedRequest>, FaucetError> {
        match self.next_work()? {
            None => Ok(None),
            Some(NextWork::Prepared(prepared)) => Ok(Some(*prepared)),
            Some(NextWork::Queued { id, .. }) => {
                let client = self.config.rpc_client()?;
                let context = transfer_context(&client, self.wallet.address())?;
                self.prepare(&id, context).map(Some)
            }
        }
    }

    pub fn finish(&mut self, id: &str, result: WorkResult) -> Result<(), FaucetError> {
        let entry = self
            .state
            .requests
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| FaucetError::InvalidState(format!("no faucet request {id:?}")))?;
        if !matches!(entry.status, RequestStatus::Prepared { .. }) {
            return Err(FaucetError::InvalidState(format!(
                "faucet request {id:?} is not prepared"
            )));
        }
        entry.status = match result {
            WorkResult::Included { hash, height } => RequestStatus::Included { hash, height },
            WorkResult::Failed(message) => RequestStatus::Failed { message },
        };
        self.save()
    }

    pub fn request(&self, id: &str) -> Option<&RequestRecord> {
        self.state.requests.iter().find(|entry| entry.id == id)
    }

    pub fn latest_for_user(&self, user_id: &str) -> Option<&RequestRecord> {
        self.state
            .requests
            .iter()
            .rev()
            .find(|entry| entry.user_id == user_id)
    }

    pub fn pending_count(&self) -> usize {
        self.state
            .requests
            .iter()
            .filter(|entry| entry.status.is_pending())
            .count()
    }

    fn prune(&mut self, today: u64) {
        self.state
            .requests
            .retain(|entry| entry.day == today || entry.status.is_pending());
    }

    fn save(&self) -> Result<(), FaucetError> {
        let path = self.directory.join(STATE_FILE);
        let bytes = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| FaucetError::InvalidState(error.to_string()))?;
        write_atomic(&path, &bytes).map_err(|error| io(&path, error))
    }
}

/// Submit and wait for one prepared request without holding the faucet state
/// lock. Asking the RPC first makes retry after a crash idempotent.
pub fn execute_prepared(
    client: &RpcClient,
    prepared: &PreparedRequest,
) -> Result<WorkResult, FaucetError> {
    match client.call("transaction", &json!({ "hash": prepared.hash })) {
        Ok(_) => {}
        Err(ClientError::Rpc { code, .. }) if code == chain_rpc::RpcError::NOT_FOUND => {
            if let Err(error) = submit_transaction(client, &prepared.transaction) {
                if permanent_submission_error(&error) {
                    return Ok(WorkResult::Failed(error.to_string()));
                }
                return Err(error.into());
            }
        }
        Err(error) => return Err(error.into()),
    }
    let found = wait_for_inclusion(client, &prepared.hash)?;
    let height = found["height"].as_u64().unwrap_or(0);
    match found["outcome"]["status"].as_str() {
        Some("success") => Ok(WorkResult::Included {
            hash: prepared.hash.clone(),
            height,
        }),
        Some("aborted") => Ok(WorkResult::Failed(format!(
            "transaction {} aborted at height {height}: {}",
            prepared.hash,
            found["outcome"]["message"]
                .as_str()
                .unwrap_or("unknown reason")
        ))),
        _ => Ok(WorkResult::Failed(format!(
            "transaction {} was included without a recorded outcome",
            prepared.hash
        ))),
    }
}

fn permanent_submission_error(error: &ClientError) -> bool {
    let ClientError::Rpc { data, .. } = error else {
        return false;
    };
    matches!(
        data.as_ref()
            .and_then(|value| value.get("reason"))
            .and_then(Value::as_str),
        Some(
            "WrongChainId"
                | "InvalidSignature"
                | "InvalidExpiry"
                | "SequenceNumberTooLow"
                | "InsufficientBalance"
        )
    )
}

pub fn transfer_context(
    client: &RpcClient,
    faucet_address: Address,
) -> Result<TransferContext, FaucetError> {
    let network = client.call("status", &json!({}))?;
    let account = client.call(
        "account",
        &json!({ "address": format_address(&faucet_address) }),
    )?;
    Ok(TransferContext {
        chain_id: required_u64(&network, "chainId", "status")?,
        height: required_u64(&network["latest"], "height", "status")?,
        base_fee: required_u64(&network, "baseFee", "status")?,
        sequence: required_u64(&account, "nextSequenceNumber", "account")?,
        balance: account["balance"]
            .as_str()
            .ok_or_else(|| {
                FaucetError::Client(ClientError::Transport(
                    "the RPC's account response has no balance".into(),
                ))
            })?
            .parse()
            .map_err(|_| {
                FaucetError::Client(ClientError::Transport(
                    "the RPC returned an invalid faucet balance".into(),
                ))
            })?,
    })
}

pub fn current_utc_day() -> Result<u64, FaucetError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FaucetError::Setup("the system clock is before 1970".into()))?
        .as_secs();
    Ok(seconds.checked_div(SECONDS_PER_DAY).unwrap_or(0))
}

fn required_u64(value: &Value, field: &str, context: &str) -> Result<u64, FaucetError> {
    value[field].as_u64().ok_or_else(|| {
        FaucetError::Client(ClientError::Transport(format!(
            "the RPC's {context} response has no {field}"
        )))
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, FaucetError> {
    let metadata = fs::metadata(path).map_err(|error| io(path, error))?;
    if metadata.len() > MAX_FILE_BYTES {
        return Err(FaucetError::InvalidState(format!(
            "{} is over the {}-byte faucet file limit",
            path.display(),
            MAX_FILE_BYTES
        )));
    }
    let bytes = fs::read(path).map_err(|error| io(path, error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        FaucetError::InvalidState(format!("{} is not valid: {error}", path.display()))
    })
}

fn validate_state(state: &FaucetState) -> Result<(), FaucetError> {
    if state.version != STATE_VERSION {
        return Err(FaucetError::InvalidState(format!(
            "faucet state version {} is not supported by this binary",
            state.version
        )));
    }
    if state.requests.len() > MAX_RECORDS {
        return Err(FaucetError::InvalidState(format!(
            "faucet state has more than {MAX_RECORDS} requests"
        )));
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut prepared = 0usize;
    for request in &state.requests {
        if !ids.insert(&request.id) {
            return Err(FaucetError::InvalidState(format!(
                "faucet request ID {:?} appears more than once",
                request.id
            )));
        }
        parse_address(&request.address).map_err(|error| {
            FaucetError::InvalidState(format!(
                "faucet request {:?} has an invalid address: {error}",
                request.id
            ))
        })?;
        if matches!(request.status, RequestStatus::Prepared { .. }) {
            prepared = prepared.saturating_add(1);
        }
    }
    if prepared > 1 {
        return Err(FaucetError::InvalidState(
            "faucet state has more than one prepared transaction; sequence numbers must be serialized"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn faucet() -> (tempfile::TempDir, Faucet) {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("faucet");
        Faucet::init(&directory).unwrap();
        let faucet = Faucet::load(&directory).unwrap();
        (parent, faucet)
    }

    fn request<'a>(id: &'a str, user_id: &'a str, byte: u8) -> FaucetRequest<'a> {
        FaucetRequest {
            id,
            user_id,
            address: Address::from_bytes([byte; 32]),
        }
    }

    #[test]
    fn init_creates_a_separate_private_wallet_and_never_overwrites() {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("faucet");
        let address = Faucet::init(&directory).unwrap();
        assert_eq!(Faucet::load(&directory).unwrap().address(), address);
        assert!(Faucet::init(&directory).is_err());
    }

    #[test]
    fn a_request_is_durable_and_its_id_is_idempotent() {
        let (parent, mut faucet) = faucet();
        let directory = parent.path().join("faucet");
        assert_eq!(
            faucet.enqueue(request("one", "user-1", 1), 20).unwrap(),
            EnqueueResult::Queued
        );
        drop(faucet);
        let mut loaded = Faucet::load(&directory).unwrap();
        assert_eq!(loaded.request("one").unwrap().status, RequestStatus::Queued);
        assert_eq!(
            loaded.enqueue(request("one", "user-1", 1), 20).unwrap(),
            EnqueueResult::Existing(RequestStatus::Queued)
        );
        assert!(loaded.enqueue(request("one", "another", 2), 20).is_err());
    }

    #[test]
    fn daily_limits_apply_independently_to_user_address_and_everyone() {
        let (_parent, mut faucet) = faucet();
        faucet.config.per_user_daily_claims = 1;
        faucet.config.per_address_daily_claims = 1;
        faucet.config.global_daily_claims = 2;
        assert_eq!(
            faucet.enqueue(request("a", "u1", 1), 5).unwrap(),
            EnqueueResult::Queued
        );
        assert_eq!(
            faucet.enqueue(request("b", "u1", 2), 5).unwrap(),
            EnqueueResult::UserDailyLimit
        );
        assert_eq!(
            faucet.enqueue(request("c", "u2", 1), 5).unwrap(),
            EnqueueResult::AddressDailyLimit
        );
        assert_eq!(
            faucet.enqueue(request("d", "u2", 2), 5).unwrap(),
            EnqueueResult::Queued
        );
        assert_eq!(
            faucet.enqueue(request("e", "u3", 3), 5).unwrap(),
            EnqueueResult::GlobalDailyLimit
        );
        assert_eq!(
            faucet.enqueue(request("f", "u1", 2), 6).unwrap(),
            EnqueueResult::Queued,
            "a new UTC day has fresh limits"
        );
    }

    #[test]
    fn only_one_transaction_can_be_prepared_at_a_time() {
        let (_parent, mut faucet) = faucet();
        faucet.enqueue(request("one", "u1", 1), 5).unwrap();
        faucet.enqueue(request("two", "u2", 2), 5).unwrap();
        // Preparation needs a live RPC, so write an already prepared record
        // and prove loading rejects a second one.
        faucet.state.requests[0].status = RequestStatus::Prepared {
            transaction: "00".into(),
            hash: "00".into(),
        };
        faucet.state.requests[1].status = RequestStatus::Prepared {
            transaction: "00".into(),
            hash: "00".into(),
        };
        faucet.save().unwrap();
        assert!(Faucet::load(&faucet.directory).is_err());
    }

    #[test]
    fn a_prepared_transaction_survives_restart_byte_for_byte_and_finishes_once() {
        let (parent, mut faucet) = faucet();
        let directory = parent.path().join("faucet");
        faucet.enqueue(request("one", "u1", 1), 5).unwrap();
        let prepared = faucet
            .prepare(
                "one",
                TransferContext {
                    chain_id: 7,
                    height: 10,
                    base_fee: 1,
                    sequence: 3,
                    balance: 100_000_000_000,
                },
            )
            .unwrap();
        drop(faucet);

        let mut loaded = Faucet::load(&directory).unwrap();
        let work = loaded.next_work().unwrap().unwrap();
        assert!(matches!(work, NextWork::Prepared(_)));
        let NextWork::Prepared(after) = work else {
            return;
        };
        assert_eq!(after.hash, prepared.hash);
        assert_eq!(after.transaction, prepared.transaction);
        loaded
            .finish(
                "one",
                WorkResult::Included {
                    hash: after.hash.clone(),
                    height: 11,
                },
            )
            .unwrap();
        assert!(matches!(
            loaded.request("one").unwrap().status,
            RequestStatus::Included { height: 11, .. }
        ));
        assert!(loaded
            .finish("one", WorkResult::Failed("again".into()))
            .is_err());
    }
}
