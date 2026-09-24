//! The `.thry` name registry: rules, the signed reservation, and the durable
//! state behind the `chain-names` service. See `docs/thry-names.md`.
//!
//! Names are an off-chain convenience for the testnet. A wallet *reserves* a
//! name by signing a claim with its own key; the reservation is *pending* for
//! [`PENDING_TTL_MS`], and becomes a *confirmed*, permanent name when the
//! faucet reports that a Discord user asked for it. Nothing here knows about
//! sockets or clocks: callers pass the time in, so every rule is testable.

#![allow(clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use chain_text::{format_address, parse_address};
use chain_types::{Address, PublicKey};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;

/// What the wallet signs, first. The version is part of the tag so a change to
/// the layout below is a different message and cannot be confused with this one.
pub const CLAIM_TAG: &[u8] = b"thrylos-name-claim-v1";

/// A reservation holds its name for this long before it lapses.
pub const PENDING_TTL_MS: u64 = 72 * 60 * 60 * 1000;

/// How far a claim's timestamp may be from the registry's clock.
pub const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

pub const MAX_CONFIRMED: usize = 100_000;
pub const MAX_PENDING: usize = 20_000;

pub const MIN_NAME_LEN: usize = 3;
pub const MAX_NAME_LEN: usize = 20;

/// Refused whatever their shape: they would be read as the project, or as a
/// service, rather than as a person.
const RESERVED: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "bridge",
    "discord",
    "explorer",
    "faucet",
    "foundation",
    "genesis",
    "help",
    "mail",
    "mainnet",
    "mod",
    "moderator",
    "network",
    "node",
    "null",
    "official",
    "root",
    "rpc",
    "staff",
    "support",
    "system",
    "team",
    "testnet",
    "thry",
    "thrylos",
    "treasury",
    "undefined",
    "validator",
    "wallet",
    "www",
];

const STATE_FILE: &str = "names.json";
const STATE_VERSION: u32 = 1;

/// Why a request was refused. Each has a stable [`NameError::code`] for clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// The name breaks the rules; the text says which.
    InvalidName(&'static str),
    Reserved,
    /// Someone else holds it: confirmed, or pending and not yet lapsed.
    Taken,
    /// The address already has a confirmed name.
    AddressHasName,
    /// The timestamp is too far from the registry's clock.
    StaleClaim,
    /// The public key is not a valid Ed25519 point, or the signature is wrong.
    BadSignature,
    /// No unexpired reservation exists for the address.
    NoReservation,
    /// This Discord user already has a confirmed name.
    DiscordUserHasName,
    /// A capacity limit was reached.
    Full,
    /// A field was missing, the wrong length, or not the right kind of text.
    Malformed(&'static str),
}

impl NameError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidName(_) => "InvalidName",
            Self::Reserved => "Reserved",
            Self::Taken => "Taken",
            Self::AddressHasName => "AddressHasName",
            Self::StaleClaim => "StaleClaim",
            Self::BadSignature => "BadSignature",
            Self::NoReservation => "NoReservation",
            Self::DiscordUserHasName => "DiscordUserHasName",
            Self::Full => "Full",
            Self::Malformed(_) => "Malformed",
        }
    }
}

impl core::fmt::Display for NameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidName(why) => write!(f, "that name is not allowed: {why}"),
            Self::Reserved => f.write_str("that name is reserved"),
            Self::Taken => f.write_str("that name is taken"),
            Self::AddressHasName => f.write_str("this address already has a name"),
            Self::StaleClaim => {
                f.write_str("the claim's timestamp is too far from the registry's clock")
            }
            Self::BadSignature => f.write_str("the claim's signature does not verify for this key"),
            Self::NoReservation => {
                f.write_str("there is no unexpired reservation for that address")
            }
            Self::DiscordUserHasName => f.write_str("this Discord account already has a name"),
            Self::Full => f.write_str("the registry is full"),
            Self::Malformed(what) => write!(f, "malformed request: {what}"),
        }
    }
}

impl std::error::Error for NameError {}

/// The stored form of a name, checked against the rules. Accepts an optional
/// `.thry` suffix and any ASCII case; returns the bare, lowercase name.
///
/// 3 to 20 characters of `a-z`, `0-9` and `-`, starting and ending with a
/// letter or digit, with no `--`. Nothing outside ASCII is accepted, so there
/// are no look-alike characters to police.
pub fn validate_name(raw: &str) -> Result<String, NameError> {
    let lowered = raw.to_ascii_lowercase();
    let bare = lowered.strip_suffix(".thry").unwrap_or(&lowered);
    if !bare.is_ascii() {
        return Err(NameError::InvalidName("use only a-z, 0-9 and -"));
    }
    if bare.len() < MIN_NAME_LEN || bare.len() > MAX_NAME_LEN {
        return Err(NameError::InvalidName("use 3 to 20 characters"));
    }
    if !bare
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(NameError::InvalidName("use only a-z, 0-9 and -"));
    }
    if bare.starts_with('-') || bare.ends_with('-') {
        return Err(NameError::InvalidName("do not start or end with -"));
    }
    if bare.contains("--") {
        return Err(NameError::InvalidName("do not use -- "));
    }
    if RESERVED.contains(&bare) {
        return Err(NameError::Reserved);
    }
    Ok(bare.to_owned())
}

/// The bytes a wallet signs to reserve `name` for `address`.
///
/// `CLAIM_TAG`, then little-endian `chain_id` (u64), the name's length (u8),
/// the name, the 32 address bytes and little-endian `timestamp_ms` (u64). The
/// chain id keeps a claim for one network from being replayed on another.
pub fn claim_message(chain_id: u64, name: &str, address: &Address, timestamp_ms: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CLAIM_TAG.len() + 8 + 1 + name.len() + 32 + 8);
    bytes.extend_from_slice(CLAIM_TAG);
    bytes.extend_from_slice(&chain_id.to_le_bytes());
    // `validate_name` bounds the length well under 256.
    bytes.push(u8::try_from(name.len()).unwrap_or(u8::MAX));
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(address.as_bytes());
    bytes.extend_from_slice(&timestamp_ms.to_le_bytes());
    bytes
}

/// A reservation as the wallet sends it, before any check.
#[derive(Debug, Clone)]
pub struct Reservation {
    pub name: String,
    pub public_key: [u8; 32],
    pub timestamp_ms: u64,
    pub signature: [u8; 64],
}

/// Checks a reservation without touching any state: the name, the clock, the
/// key, and the signature (`verify_strict`). Returns the bare name and the
/// address the key signs for.
pub fn verify_reservation(
    chain_id: u64,
    reservation: &Reservation,
    now_ms: u64,
) -> Result<(String, Address), NameError> {
    let name = validate_name(&reservation.name)?;
    let distance = now_ms.abs_diff(reservation.timestamp_ms);
    if distance > CLOCK_SKEW_MS {
        return Err(NameError::StaleClaim);
    }
    // `PublicKey` refuses points that are not on the curve or are weak.
    let key = PublicKey::from_ed25519_bytes(reservation.public_key)
        .map_err(|_| NameError::BadSignature)?;
    let address = Address::from_public_key(&key);
    let verifying =
        VerifyingKey::from_bytes(&reservation.public_key).map_err(|_| NameError::BadSignature)?;
    let signature = Signature::from_bytes(&reservation.signature);
    let message = claim_message(chain_id, &name, &address, reservation.timestamp_ms);
    verifying
        .verify_strict(&message, &signature)
        .map_err(|_| NameError::BadSignature)?;
    Ok((name, address))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConfirmedRecord {
    name: String,
    address: String,
    discord_user_id: String,
    confirmed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingRecord {
    name: String,
    address: String,
    expires_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u32,
    confirmed: Vec<ConfirmedRecord>,
    pending: Vec<PendingRecord>,
}

/// What the registry says about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressStatus {
    None,
    /// Reserved and not yet confirmed; the name is deliberately not returned.
    Pending {
        expires_ms: u64,
    },
    Confirmed {
        name: String,
    },
}

#[derive(Debug)]
pub enum RegistryError {
    Io(String),
    Corrupt(String),
}

impl core::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(problem) => write!(f, "name registry: {problem}"),
            Self::Corrupt(problem) => write!(f, "the name registry file is damaged: {problem}"),
        }
    }
}

impl std::error::Error for RegistryError {}

/// The registry: every confirmed name and every live reservation, kept in one
/// file replaced atomically after each change.
#[derive(Debug)]
pub struct Registry {
    path: PathBuf,
    confirmed: BTreeMap<String, ConfirmedRecord>,
    by_address: BTreeMap<String, String>,
    by_discord_user: BTreeMap<String, String>,
    pending: BTreeMap<String, PendingRecord>,
    pending_by_address: BTreeMap<String, String>,
}

impl Registry {
    /// Opens the registry in `directory`, creating it if there is none. A file
    /// that exists but cannot be read is an error, never an empty registry.
    pub fn open(directory: &Path) -> Result<Self, RegistryError> {
        fs::create_dir_all(directory).map_err(|error| RegistryError::Io(error.to_string()))?;
        let path = directory.join(STATE_FILE);
        let mut registry = Self {
            path: path.clone(),
            confirmed: BTreeMap::new(),
            by_address: BTreeMap::new(),
            by_discord_user: BTreeMap::new(),
            pending: BTreeMap::new(),
            pending_by_address: BTreeMap::new(),
        };
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(registry),
            Err(error) => return Err(RegistryError::Io(error.to_string())),
        };
        let file: StateFile = serde_json::from_slice(&bytes)
            .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
        if file.version != STATE_VERSION {
            return Err(RegistryError::Corrupt(format!(
                "unknown version {}",
                file.version
            )));
        }
        for record in file.confirmed {
            let name = record.name.clone();
            if registry.by_address.contains_key(&record.address)
                || registry
                    .by_discord_user
                    .contains_key(&record.discord_user_id)
                || registry.confirmed.contains_key(&name)
            {
                return Err(RegistryError::Corrupt(
                    "a name, address or Discord user is listed twice".into(),
                ));
            }
            registry
                .by_address
                .insert(record.address.clone(), name.clone());
            registry
                .by_discord_user
                .insert(record.discord_user_id.clone(), name.clone());
            registry.confirmed.insert(name, record);
        }
        for record in file.pending {
            let name = record.name.clone();
            registry
                .pending_by_address
                .insert(record.address.clone(), name.clone());
            registry.pending.insert(name, record);
        }
        Ok(registry)
    }

    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn save(&self) -> Result<(), RegistryError> {
        let file = StateFile {
            version: STATE_VERSION,
            confirmed: self.confirmed.values().cloned().collect(),
            pending: self.pending.values().cloned().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|error| RegistryError::Io(error.to_string()))?;
        write_atomic(&self.path, &bytes).map_err(|error| RegistryError::Io(error.to_string()))
    }

    /// Drops reservations whose time has passed. Not saved by itself: a lapsed
    /// reservation is ignored everywhere it matters, so this only frees memory,
    /// and the next change writes the file without it.
    fn prune(&mut self, now_ms: u64) {
        let lapsed: Vec<String> = self
            .pending
            .values()
            .filter(|record| record.expires_ms <= now_ms)
            .map(|record| record.name.clone())
            .collect();
        for name in lapsed {
            if let Some(record) = self.pending.remove(&name) {
                self.pending_by_address.remove(&record.address);
            }
        }
    }

    /// Reserves `name` for `address`, replacing any reservation that address
    /// already has. Returns when it lapses.
    pub fn reserve(
        &mut self,
        now_ms: u64,
        name: &str,
        address: &Address,
    ) -> Result<u64, NameErrorOrIo> {
        self.prune(now_ms);
        let address_text = format_address(address);
        if self.by_address.contains_key(&address_text) {
            return Err(NameError::AddressHasName.into());
        }
        if self.confirmed.contains_key(name) {
            return Err(NameError::Taken.into());
        }
        if let Some(holder) = self.pending.get(name) {
            if holder.address != address_text {
                return Err(NameError::Taken.into());
            }
        }
        // Replacing the address's own earlier reservation frees its old name.
        if let Some(old) = self.pending_by_address.get(&address_text).cloned() {
            self.pending.remove(&old);
            self.pending_by_address.remove(&address_text);
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(NameError::Full.into());
        }
        let expires_ms = now_ms.saturating_add(PENDING_TTL_MS);
        self.pending.insert(
            name.to_owned(),
            PendingRecord {
                name: name.to_owned(),
                address: address_text.clone(),
                expires_ms,
            },
        );
        self.pending_by_address
            .insert(address_text, name.to_owned());
        self.save()?;
        Ok(expires_ms)
    }

    /// Turns `address`'s unexpired reservation into a permanent name held by
    /// `discord_user_id`, and returns the name.
    pub fn confirm(
        &mut self,
        now_ms: u64,
        address: &Address,
        discord_user_id: &str,
    ) -> Result<String, NameErrorOrIo> {
        if discord_user_id.is_empty()
            || discord_user_id.len() > 32
            || !discord_user_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(NameError::Malformed("discord user id").into());
        }
        self.prune(now_ms);
        let address_text = format_address(address);
        if self.by_address.contains_key(&address_text) {
            return Err(NameError::AddressHasName.into());
        }
        let Some(name) = self.pending_by_address.get(&address_text).cloned() else {
            return Err(NameError::NoReservation.into());
        };
        if self.by_discord_user.contains_key(discord_user_id) {
            return Err(NameError::DiscordUserHasName.into());
        }
        if self.confirmed.len() >= MAX_CONFIRMED {
            return Err(NameError::Full.into());
        }
        self.pending.remove(&name);
        self.pending_by_address.remove(&address_text);
        self.confirmed.insert(
            name.clone(),
            ConfirmedRecord {
                name: name.clone(),
                address: address_text.clone(),
                discord_user_id: discord_user_id.to_owned(),
                confirmed_ms: now_ms,
            },
        );
        self.by_address.insert(address_text, name.clone());
        self.by_discord_user
            .insert(discord_user_id.to_owned(), name.clone());
        self.save()?;
        Ok(name)
    }

    /// The address a confirmed name points at. A pending name resolves to
    /// nothing.
    pub fn resolve(&self, name: &str) -> Option<Address> {
        parse_address(&self.confirmed.get(name)?.address).ok()
    }

    pub fn status(&self, now_ms: u64, address: &Address) -> AddressStatus {
        let text = format_address(address);
        if let Some(name) = self.by_address.get(&text) {
            return AddressStatus::Confirmed { name: name.clone() };
        }
        match self
            .pending_by_address
            .get(&text)
            .and_then(|name| self.pending.get(name))
        {
            Some(record) if record.expires_ms > now_ms => AddressStatus::Pending {
                expires_ms: record.expires_ms,
            },
            _ => AddressStatus::None,
        }
    }

    /// Whether `name` is free to reserve right now (for the wallet's live
    /// check). Says nothing about who holds a taken one.
    pub fn is_available(&self, now_ms: u64, name: &str) -> bool {
        if self.confirmed.contains_key(name) {
            return false;
        }
        self.pending
            .get(name)
            .is_none_or(|record| record.expires_ms <= now_ms)
    }
}

/// A refusal, or a failure to save. Kept apart so a caller can answer a refusal
/// as the client's doing and a save failure as the server's.
#[derive(Debug)]
pub enum NameErrorOrIo {
    Name(NameError),
    Registry(RegistryError),
}

impl From<NameError> for NameErrorOrIo {
    fn from(error: NameError) -> Self {
        Self::Name(error)
    }
}

impl From<RegistryError> for NameErrorOrIo {
    fn from(error: RegistryError) -> Self {
        Self::Registry(error)
    }
}

/// A sliding-window counter: at most `limit` events per `window_ms` for each
/// key. Held in memory only; a restart forgets it, which is fine for a limit.
#[derive(Debug, Default)]
pub struct RateLimiter {
    events: BTreeMap<String, VecDeque<u64>>,
}

impl RateLimiter {
    /// Counts an event for `key` and returns whether it is within the limit.
    /// A refused event is not counted, so a client that keeps trying does not
    /// extend its own wait.
    pub fn allow(&mut self, key: &str, now_ms: u64, limit: usize, window_ms: u64) -> bool {
        let recent = self.events.entry(key.to_owned()).or_default();
        while recent
            .front()
            .is_some_and(|at| now_ms.saturating_sub(*at) >= window_ms)
        {
            recent.pop_front();
        }
        if recent.len() >= limit {
            return false;
        }
        recent.push_back(now_ms);
        true
    }

    /// Forgets keys with nothing in their window, so the map cannot grow with
    /// every source ever seen.
    pub fn sweep(&mut self, now_ms: u64, window_ms: u64) {
        self.events.retain(|_, recent| {
            recent
                .back()
                .is_some_and(|at| now_ms.saturating_sub(*at) < window_ms)
        });
    }

    pub fn tracked(&self) -> usize {
        self.events.len()
    }
}

/// Whether two secrets are equal, taking the same time however they differ.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = u8::from(left.len() != right.len());
    let longest = left.len().max(right.len());
    for index in 0..longest {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    const CHAIN: u64 = 20_260_923;
    const NOW: u64 = 1_790_000_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn address_of(key: &SigningKey) -> Address {
        let public = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap();
        Address::from_public_key(&public)
    }

    fn reservation(key: &SigningKey, name: &str, timestamp_ms: u64) -> Reservation {
        let address = address_of(key);
        let message = claim_message(CHAIN, name, &address, timestamp_ms);
        Reservation {
            name: name.to_owned(),
            public_key: key.verifying_key().to_bytes(),
            timestamp_ms,
            signature: key.sign(&message).to_bytes(),
        }
    }

    fn registry() -> (tempfile::TempDir, Registry) {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::open(dir.path()).unwrap();
        (dir, registry)
    }

    fn refused(result: Result<impl core::fmt::Debug, NameErrorOrIo>) -> NameError {
        match result {
            Err(NameErrorOrIo::Name(error)) => error,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ---- the rules ------------------------------------------------------

    #[test]
    fn names_are_lowercased_and_may_carry_the_display_suffix() {
        assert_eq!(validate_name("Alice").unwrap(), "alice");
        assert_eq!(validate_name("alice.thry").unwrap(), "alice");
        assert_eq!(validate_name("ALICE.THRY").unwrap(), "alice");
        assert_eq!(validate_name("a-b-c").unwrap(), "a-b-c");
        assert_eq!(validate_name("abc").unwrap(), "abc");
        assert_eq!(validate_name(&"a".repeat(20)).unwrap().len(), 20);
    }

    #[test]
    fn names_outside_the_rules_are_refused() {
        for bad in [
            "ab",            // too short
            &"a".repeat(21), // too long
            "-abc",          // leading hyphen
            "abc-",          // trailing hyphen
            "a--b",          // double hyphen
            "al ice",        // space
            "al_ice",        // underscore
            "al.ice",        // a dot inside
            "alicé",         // non-ASCII
            "аlice",         // a Cyrillic "а": a look-alike
            "🙂🙂🙂",        // emoji
            "",              // nothing
            ".thry",         // only the suffix
        ] {
            assert!(
                matches!(validate_name(bad), Err(NameError::InvalidName(_))),
                "{bad:?} should be refused"
            );
        }
    }

    #[test]
    fn reserved_names_are_refused_in_any_case_and_with_the_suffix() {
        for reserved in [
            "admin",
            "Faucet",
            "THRYLOS",
            "wallet.thry",
            "validator",
            "thry",
        ] {
            assert_eq!(
                validate_name(reserved),
                Err(NameError::Reserved),
                "{reserved}"
            );
        }
    }

    // ---- the signed claim -----------------------------------------------

    #[test]
    fn the_signed_bytes_have_exactly_the_documented_layout() {
        let address = Address::from_bytes([7; 32]);
        let bytes = claim_message(
            0x0102_0304_0506_0708,
            "alice",
            &address,
            0x1112_1314_1516_1718,
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"thrylos-name-claim-v1");
        expected.extend_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        expected.push(5);
        expected.extend_from_slice(b"alice");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&[0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11]);
        assert_eq!(bytes, expected);
        assert_eq!(CLAIM_TAG.len(), 21);
    }

    #[test]
    fn a_genuine_reservation_verifies_and_names_the_address_of_its_key() {
        let key = key(1);
        let (name, address) =
            verify_reservation(CHAIN, &reservation(&key, "alice", NOW), NOW).unwrap();
        assert_eq!(name, "alice");
        assert_eq!(address, address_of(&key));
    }

    #[test]
    fn a_reservation_that_is_wrong_in_any_way_is_refused() {
        let key = key(1);
        let good = reservation(&key, "alice", NOW);
        let check = |r: &Reservation, now: u64| verify_reservation(CHAIN, r, now);

        // A different key's signature.
        let mut wrong_key = good.clone();
        wrong_key.public_key = self::key(2).verifying_key().to_bytes();
        assert_eq!(check(&wrong_key, NOW), Err(NameError::BadSignature));

        // A different name from the one signed.
        let mut other_name = good.clone();
        other_name.name = "bobby".into();
        assert_eq!(check(&other_name, NOW), Err(NameError::BadSignature));

        // Signed for another chain.
        assert_eq!(
            verify_reservation(CHAIN + 1, &good, NOW),
            Err(NameError::BadSignature)
        );

        // A tampered signature byte.
        let mut tampered = good.clone();
        tampered.signature[10] ^= 1;
        assert_eq!(check(&tampered, NOW), Err(NameError::BadSignature));

        // A timestamp the signature does not cover.
        let mut retimed = good.clone();
        retimed.timestamp_ms += 1;
        assert_eq!(check(&retimed, NOW), Err(NameError::BadSignature));

        // Not a curve point at all.
        let mut nonsense = good.clone();
        nonsense.public_key = [0xff; 32];
        assert_eq!(check(&nonsense, NOW), Err(NameError::BadSignature));

        // An invalid name is refused before anything is verified.
        let bad_name = reservation(&key, "a", NOW);
        assert!(matches!(
            check(&bad_name, NOW),
            Err(NameError::InvalidName(_))
        ));
    }

    #[test]
    fn a_claim_is_stale_outside_the_clock_skew_on_either_side() {
        let key = key(1);
        let claim = reservation(&key, "alice", NOW);
        assert!(verify_reservation(CHAIN, &claim, NOW + CLOCK_SKEW_MS).is_ok());
        assert!(verify_reservation(CHAIN, &claim, NOW - CLOCK_SKEW_MS).is_ok());
        assert_eq!(
            verify_reservation(CHAIN, &claim, NOW + CLOCK_SKEW_MS + 1),
            Err(NameError::StaleClaim)
        );
        assert_eq!(
            verify_reservation(CHAIN, &claim, NOW - CLOCK_SKEW_MS - 1),
            Err(NameError::StaleClaim)
        );
    }

    #[test]
    fn a_signature_that_is_not_canonical_is_refused() {
        // Adding the group order to `s` gives a second byte string for the same
        // signature; `verify_strict` must not accept it.
        let key = key(1);
        let mut claim = reservation(&key, "alice", NOW);
        let order: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut carry = 0u16;
        for (index, byte) in order.iter().enumerate() {
            let sum = u16::from(claim.signature[32 + index]) + u16::from(*byte) + carry;
            claim.signature[32 + index] = u8::try_from(sum & 0xff).unwrap();
            carry = sum >> 8;
        }
        assert_eq!(
            verify_reservation(CHAIN, &claim, NOW),
            Err(NameError::BadSignature)
        );
    }

    // ---- the registry ---------------------------------------------------

    #[test]
    fn a_reserved_name_is_pending_hidden_and_then_confirmed_for_good() {
        let (_dir, mut registry) = registry();
        let alice = address_of(&key(1));
        let expires = registry.reserve(NOW, "alice", &alice).unwrap();
        assert_eq!(expires, NOW + PENDING_TTL_MS);

        // Pending: no name in the status, and the name resolves to nothing.
        assert_eq!(
            registry.status(NOW, &alice),
            AddressStatus::Pending {
                expires_ms: expires
            }
        );
        assert_eq!(registry.resolve("alice"), None);
        assert!(!registry.is_available(NOW, "alice"), "held while pending");

        let name = registry
            .confirm(NOW + 1, &alice, "80351110224678912")
            .unwrap();
        assert_eq!(name, "alice");
        assert_eq!(
            registry.status(NOW + 2, &alice),
            AddressStatus::Confirmed {
                name: "alice".into()
            }
        );
        assert_eq!(registry.resolve("alice"), Some(alice));
        assert_eq!(registry.pending_count(), 0);
        assert_eq!(registry.confirmed_count(), 1);
    }

    #[test]
    fn a_reservation_lapses_after_the_window_and_frees_its_name() {
        let (_dir, mut registry) = registry();
        let alice = address_of(&key(1));
        let bob = address_of(&key(2));
        registry.reserve(NOW, "alice", &alice).unwrap();
        // Still held a moment before it lapses.
        assert_eq!(
            refused(registry.reserve(NOW + PENDING_TTL_MS - 1, "alice", &bob)),
            NameError::Taken
        );
        // Gone at the deadline: nobody can confirm it, and another can take it.
        assert_eq!(
            refused(registry.confirm(NOW + PENDING_TTL_MS, &alice, "1")),
            NameError::NoReservation
        );
        assert_eq!(
            registry.status(NOW + PENDING_TTL_MS, &alice),
            AddressStatus::None
        );
        assert!(registry.is_available(NOW + PENDING_TTL_MS, "alice"));
        registry
            .reserve(NOW + PENDING_TTL_MS, "alice", &bob)
            .unwrap();
    }

    #[test]
    fn a_confirmed_name_is_taken_for_good_and_an_address_keeps_one() {
        let (_dir, mut registry) = registry();
        let (alice, bob) = (address_of(&key(1)), address_of(&key(2)));
        registry.reserve(NOW, "alice", &alice).unwrap();
        registry.confirm(NOW, &alice, "11").unwrap();
        let much_later = NOW + 1_000 * PENDING_TTL_MS;

        assert_eq!(
            refused(registry.reserve(much_later, "alice", &bob)),
            NameError::Taken
        );
        assert_eq!(
            refused(registry.reserve(much_later, "alice2", &alice)),
            NameError::AddressHasName,
            "one name per address, permanently"
        );
    }

    #[test]
    fn one_address_holds_one_reservation_and_a_new_one_replaces_it() {
        let (_dir, mut registry) = registry();
        let (alice, bob) = (address_of(&key(1)), address_of(&key(2)));
        registry.reserve(NOW, "first", &alice).unwrap();
        registry.reserve(NOW + 5, "second", &alice).unwrap();
        assert_eq!(registry.pending_count(), 1);
        assert!(
            registry.is_available(NOW + 6, "first"),
            "the old name is free again"
        );
        registry.reserve(NOW + 6, "first", &bob).unwrap();
        // The same address re-reserving the same name is allowed and just renews it.
        registry.reserve(NOW + 7, "second", &alice).unwrap();
    }

    #[test]
    fn a_discord_user_can_confirm_only_one_name() {
        let (_dir, mut registry) = registry();
        let (alice, bob) = (address_of(&key(1)), address_of(&key(2)));
        registry.reserve(NOW, "alice", &alice).unwrap();
        registry.reserve(NOW, "bobby", &bob).unwrap();
        registry.confirm(NOW, &alice, "42").unwrap();
        assert_eq!(
            refused(registry.confirm(NOW, &bob, "42")),
            NameError::DiscordUserHasName
        );
        // Still pending, and another Discord user can confirm it.
        assert!(matches!(
            registry.status(NOW, &bob),
            AddressStatus::Pending { .. }
        ));
        registry.confirm(NOW, &bob, "43").unwrap();
    }

    #[test]
    fn confirming_needs_a_reservation_for_that_address_and_a_sane_discord_id() {
        let (_dir, mut registry) = registry();
        let alice = address_of(&key(1));
        assert_eq!(
            refused(registry.confirm(NOW, &alice, "42")),
            NameError::NoReservation
        );
        registry.reserve(NOW, "alice", &alice).unwrap();
        for bad in ["", "abc", "12 3", &"9".repeat(33)] {
            assert!(
                matches!(
                    refused(registry.confirm(NOW, &alice, bad)),
                    NameError::Malformed(_)
                ),
                "{bad:?}"
            );
        }
        assert_eq!(registry.confirmed_count(), 0);
    }

    #[test]
    fn the_registry_survives_a_restart_and_a_damaged_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (alice, bob) = (address_of(&key(1)), address_of(&key(2)));
        {
            let mut registry = Registry::open(dir.path()).unwrap();
            registry.reserve(NOW, "alice", &alice).unwrap();
            registry.confirm(NOW, &alice, "42").unwrap();
            registry.reserve(NOW, "bobby", &bob).unwrap();
        }
        let mut registry = Registry::open(dir.path()).unwrap();
        assert_eq!(registry.resolve("alice"), Some(alice));
        assert!(matches!(
            registry.status(NOW, &bob),
            AddressStatus::Pending { .. }
        ));
        assert_eq!(
            refused(registry.confirm(NOW, &bob, "42")),
            NameError::DiscordUserHasName,
            "the Discord user's name was remembered too"
        );
        drop(registry);

        fs::write(dir.path().join(STATE_FILE), b"{ not json").unwrap();
        assert!(matches!(
            Registry::open(dir.path()),
            Err(RegistryError::Corrupt(_))
        ));
    }

    #[test]
    fn a_file_that_lists_a_name_or_a_user_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let record = |name: &str, address: &str, user: &str| {
            format!(
                r#"{{"name":"{name}","address":"{address}","discord_user_id":"{user}","confirmed_ms":1}}"#
            )
        };
        let body = format!(
            r#"{{"version":1,"confirmed":[{},{}],"pending":[]}}"#,
            record("alice", "thry1a", "1"),
            record("bobby", "thry1b", "1")
        );
        fs::write(dir.path().join(STATE_FILE), body).unwrap();
        assert!(matches!(
            Registry::open(dir.path()),
            Err(RegistryError::Corrupt(_))
        ));
    }

    #[test]
    fn the_pending_queue_is_capped() {
        let (_dir, mut registry) = registry();
        for index in 0..MAX_PENDING {
            let name = format!("n{index}x");
            let address = Address::from_bytes([
                u8::try_from(index & 0xff).unwrap(),
                u8::try_from((index >> 8) & 0xff).unwrap(),
                u8::try_from((index >> 16) & 0xff).unwrap(),
                1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]);
            // Insert directly: saving 20,000 times would only test the disk.
            let text = format_address(&address);
            registry.pending.insert(
                name.clone(),
                PendingRecord {
                    name: name.clone(),
                    address: text.clone(),
                    expires_ms: NOW + 1,
                },
            );
            registry.pending_by_address.insert(text, name);
        }
        let extra = address_of(&key(9));
        assert_eq!(
            refused(registry.reserve(NOW, "onemore", &extra)),
            NameError::Full
        );
    }

    // ---- limits ---------------------------------------------------------

    #[test]
    fn the_limiter_allows_the_limit_per_window_and_a_refusal_is_not_counted() {
        let mut limiter = RateLimiter::default();
        for at in 0..3 {
            assert!(limiter.allow("a", NOW + at, 3, 1_000));
        }
        assert!(!limiter.allow("a", NOW + 500, 3, 1_000), "over the limit");
        assert!(
            limiter.allow("b", NOW + 500, 3, 1_000),
            "another key is separate"
        );
        // The refusal above did not push the window out: room returns when the
        // first three age past it.
        assert!(limiter.allow("a", NOW + 1_002, 3, 1_000));
        limiter.sweep(NOW + 10_000, 1_000);
        assert_eq!(limiter.tracked(), 0);
    }

    #[test]
    fn secrets_are_compared_whole() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secre"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
