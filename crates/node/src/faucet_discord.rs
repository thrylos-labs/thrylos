//! Thin Discord Interactions adapter for [`crate::faucet`].
//!
//! It verifies Discord's Ed25519 signature over `timestamp || raw body`, then
//! turns `/faucet` into one durable enqueue operation. It never signs a chain
//! transaction and never holds the faucet key itself.

#![allow(clippy::indexing_slicing)]

use chain_rpc::hex;
use chain_text::{format_address, parse_address};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};

use crate::faucet::{
    EnqueueResult, Faucet, FaucetError, FaucetRequest, RequestRecord, RequestStatus,
};
use crate::names_client::{self, Confirmation};

const DISCORD_SIGNATURE_BYTES: usize = 64;
const DISCORD_PUBLIC_KEY_BYTES: usize = 32;
const EPHEMERAL: u64 = 64;

pub struct DiscordResponse {
    pub status: u16,
    pub reason: &'static str,
    pub body: Vec<u8>,
}

impl DiscordResponse {
    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            reason: "OK",
            body: serde_json::to_vec(value).unwrap_or_else(|_| b"{\"type\":1}".to_vec()),
        }
    }

    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            body: Vec::new(),
        }
    }
}

pub fn public_key(faucet: &Faucet) -> Result<VerifyingKey, FaucetError> {
    let text = faucet
        .config()
        .discord_public_key
        .as_deref()
        .ok_or_else(|| {
            FaucetError::InvalidConfig(
                "set `discord_public_key` in faucet.json before starting Discord".into(),
            )
        })?;
    let bytes = hex::decode(text)
        .map_err(|error| FaucetError::InvalidConfig(format!("`discord_public_key` {error}")))?;
    let bytes: [u8; DISCORD_PUBLIC_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| FaucetError::InvalidConfig("`discord_public_key` must be 32 bytes".into()))?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
        FaucetError::InvalidConfig("`discord_public_key` is not an Ed25519 public key".into())
    })?;
    if key.is_weak() {
        return Err(FaucetError::InvalidConfig(
            "`discord_public_key` is a weak Ed25519 key".into(),
        ));
    }
    Ok(key)
}

pub fn verifies(key: &VerifyingKey, signature_hex: &str, timestamp: &str, body: &[u8]) -> bool {
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(signature) = <[u8; DISCORD_SIGNATURE_BYTES]>::try_from(signature) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature);
    let mut message = Vec::with_capacity(timestamp.len().saturating_add(body.len()));
    message.extend_from_slice(timestamp.as_bytes());
    message.extend_from_slice(body);
    key.verify_strict(&message, &signature).is_ok()
}

/// Verify and answer one Discord webhook. Limit refusals are successful,
/// ephemeral command responses; only unauthenticated or malformed HTTP is an
/// HTTP error.
pub fn handle_interaction(
    faucet: &mut Faucet,
    key: &VerifyingKey,
    signature: Option<&str>,
    timestamp: Option<&str>,
    body: &[u8],
    day: u64,
) -> DiscordResponse {
    let (Some(signature), Some(timestamp)) = (signature, timestamp) else {
        return DiscordResponse::empty(401, "Unauthorized");
    };
    if !verifies(key, signature, timestamp, body) {
        return DiscordResponse::empty(401, "Unauthorized");
    }
    let Ok(interaction) = serde_json::from_slice::<Value>(body) else {
        return DiscordResponse::empty(400, "Bad Request");
    };
    match interaction["type"].as_u64() {
        Some(1) => DiscordResponse::json(&json!({ "type": 1 })),
        Some(2) => command(faucet, &interaction, day),
        _ => message("This interaction type is not supported."),
    }
}

fn command(faucet: &mut Faucet, interaction: &Value, day: u64) -> DiscordResponse {
    let Some(user_id) = interaction["member"]["user"]["id"]
        .as_str()
        .or_else(|| interaction["user"]["id"].as_str())
    else {
        return message("Discord did not identify the requesting user.");
    };
    match interaction["data"]["name"].as_str() {
        Some("faucet") => faucet_command(faucet, interaction, user_id, day),
        Some("name") => name_command(faucet, interaction, user_id, day),
        Some("faucet-status") => match faucet.latest_for_user(user_id) {
            Some(record) => message(&record_message(record)),
            None => message("You have no faucet request yet. Use `/faucet` with your address."),
        },
        _ => message("Unknown command. Use `/faucet`, `/name` or `/faucet-status`."),
    }
}

/// Milliseconds from the Unix epoch to Discord's own, 2015-01-01.
const DISCORD_EPOCH_MS: u64 = 1_420_070_400_000;

/// The UTC day (days since the Unix epoch) a Discord account was created,
/// read out of its snowflake ID: the top bits are milliseconds since
/// [`DISCORD_EPOCH_MS`]. `None` if `user_id` is not a snowflake.
fn account_creation_day(user_id: &str) -> Option<u64> {
    let id: u64 = user_id.parse().ok()?;
    let created_ms = (id >> 22).checked_add(DISCORD_EPOCH_MS)?;
    created_ms.checked_div(86_400_000)
}

/// Whether the account is at least `min_days` old on `day`. An ID that is
/// not a snowflake is never old enough: Discord does not send those.
fn old_enough(user_id: &str, day: u64, min_days: u32) -> bool {
    if min_days == 0 {
        return true;
    }
    account_creation_day(user_id)
        .is_some_and(|created| created.saturating_add(u64::from(min_days)) <= day)
}

/// The UTC day (days since the Unix epoch) of an RFC 3339 timestamp such as
/// `2024-03-09T17:04:05.123000+00:00`, from its date part. `None` if it is not
/// one. (Days from the civil date, as in Howard Hinnant's `days_from_civil`.)
#[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
fn utc_day_of(timestamp: &str) -> Option<u64> {
    let date = timestamp.get(..10)?;
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(1970..=9999).contains(&year)
    {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).ok()
}

/// Whether the member has been in the server for at least `min_days` on `day`.
/// With no join date (a DM, or a field Discord did not send) they never have.
fn member_long_enough(interaction: &Value, day: u64, min_days: u32) -> bool {
    if min_days == 0 {
        return true;
    }
    interaction["member"]["joined_at"]
        .as_str()
        .and_then(utc_day_of)
        .is_some_and(|joined| joined.saturating_add(u64::from(min_days)) <= day)
}

fn faucet_command(
    faucet: &mut Faucet,
    interaction: &Value,
    user_id: &str,
    day: u64,
) -> DiscordResponse {
    let Some(request_id) = interaction["id"].as_str() else {
        return message("Discord did not provide a request ID; nothing was queued.");
    };
    let address_text = interaction["data"]["options"]
        .as_array()
        .and_then(|options| options.iter().find(|option| option["name"] == "address"))
        .and_then(|option| option["value"].as_str());
    let Some(address_text) = address_text else {
        return message("Give `/faucet` a Thrylos address beginning `thry1`. Nothing was queued.");
    };
    let address = match parse_address(address_text) {
        Ok(address) => address,
        Err(error) => return message(&format!("That address is not valid: {error}")),
    };
    let min_days = faucet.config().min_account_age_days;
    if !old_enough(user_id, day, min_days) {
        return message(&format!(
            "The faucet is only open to Discord accounts at least {min_days} days old, to stop one person farming many new ones. Nothing was queued."
        ));
    }
    let membership_days = faucet.config().min_server_membership_days;
    if !member_long_enough(interaction, day, membership_days) {
        return message(&format!(
            "The faucet is only open to people who have been in this Discord server at least {membership_days} days, and it must be used in the server, not in a DM. Nothing was queued."
        ));
    }
    let request = FaucetRequest {
        id: request_id,
        user_id,
        address,
    };
    match faucet.enqueue(request, day) {
        Ok(EnqueueResult::Queued) => {
            // A reserved name is confirmed by the same request, so the person
            // does one thing, not two. It never decides whether they are paid.
            let name_note = confirm_name(faucet, &address, user_id, false);
            message(&format!(
                "Queued {} for {}. Request `{request_id}`. Use `/faucet-status` to check it.{name_note}",
                faucet.config().payout,
                format_address(&address)
            ))
        }
        Ok(EnqueueResult::Existing(status)) => message(&format!(
            "Request `{request_id}` was already received and is {}.",
            status.label()
        )),
        Ok(EnqueueResult::UserDailyLimit) => {
            message("You have reached your faucet limit for today. Try again after 00:00 UTC.")
        }
        Ok(EnqueueResult::AddressDailyLimit) => message(
            "That address has reached its faucet limit for today. Try again after 00:00 UTC.",
        ),
        Ok(EnqueueResult::GlobalDailyLimit) => {
            message("The testnet faucet has reached its daily cap. Try again after 00:00 UTC.")
        }
        Ok(EnqueueResult::QueueFull) => {
            message("The faucet is busy. Nothing was queued; please try again shortly.")
        }
        Err(error) => message(&format!("The faucet could not save the request: {error}")),
    }
}

/// Asks the name registry to confirm the reservation for `address`, and words
/// the answer for the user, with a leading line break so it can follow another
/// message. Empty when names are off. `explicit` is a person who asked for a
/// name (`/name`): they hear about every outcome, where a `/faucet` claim stays
/// quiet if there was simply no reservation (a wallet with no name reserved).
fn confirm_name(
    faucet: &Faucet,
    address: &chain_types::Address,
    user_id: &str,
    explicit: bool,
) -> String {
    let Some((registry, secret)) = faucet.names_settings() else {
        return if explicit {
            "\nNames are not switched on for this faucet.".into()
        } else {
            String::new()
        };
    };
    match names_client::confirm(registry, &secret, &format_address(address), user_id) {
        Confirmation::Confirmed { name } => {
            format!("\nYour name `{name}.thry` is confirmed.")
        }
        Confirmation::Refused { code, .. } if code == "NoReservation" && !explicit => String::new(),
        Confirmation::Refused { code, .. } if code == "NoReservation" => {
            "\nThere is no reservation for that address, or it has lapsed. Reserve a name in the wallet first.".into()
        }
        Confirmation::Refused { message, .. } => format!("\nYour name was not confirmed: {message}."),
        Confirmation::Unavailable => {
            "\nYour name could not be confirmed right now. Use `/name` with the same address in a few minutes.".into()
        }
    }
}

/// `/name address:<thry1…>`: confirm a reserved name without asking for coin.
/// It has to pass the same gates as the faucet, or a fresh Discord account
/// could take a name the faucet would have refused it.
fn name_command(
    faucet: &mut Faucet,
    interaction: &Value,
    user_id: &str,
    day: u64,
) -> DiscordResponse {
    let address_text = interaction["data"]["options"]
        .as_array()
        .and_then(|options| options.iter().find(|option| option["name"] == "address"))
        .and_then(|option| option["value"].as_str());
    let Some(address_text) = address_text else {
        return message("Give `/name` the Thrylos address (`thry1…`) you reserved your name for.");
    };
    let address = match parse_address(address_text) {
        Ok(address) => address,
        Err(error) => return message(&format!("That address is not valid: {error}")),
    };
    let min_days = faucet.config().min_account_age_days;
    if !old_enough(user_id, day, min_days) {
        return message(&format!(
            "Names are only open to Discord accounts at least {min_days} days old. Nothing was confirmed."
        ));
    }
    let membership_days = faucet.config().min_server_membership_days;
    if !member_long_enough(interaction, day, membership_days) {
        return message(&format!(
            "Names are only open to people who have been in this Discord server at least {membership_days} days, used in the server rather than a DM. Nothing was confirmed."
        ));
    }
    let outcome = confirm_name(faucet, &address, user_id, true);
    message(outcome.trim_start())
}

fn record_message(record: &RequestRecord) -> String {
    match &record.status {
        RequestStatus::Queued => {
            format!("Request `{}` is queued for {}.", record.id, record.address)
        }
        RequestStatus::Prepared { hash, .. } => format!(
            "Request `{}` for {} is processing. Transaction: `{hash}`.",
            record.id, record.address
        ),
        RequestStatus::Included { hash, height } => format!(
            "Request `{}` for {} succeeded in block {height}. Transaction: `{hash}`.",
            record.id, record.address
        ),
        RequestStatus::Failed { message } => {
            format!(
                "Request `{}` for {} failed: {message}",
                record.id, record.address
            )
        }
    }
}

fn message(content: &str) -> DiscordResponse {
    DiscordResponse::json(&json!({
        "type": 4,
        "data": {
            "content": content,
            "flags": EPHEMERAL,
            "allowed_mentions": { "parse": [] },
        }
    }))
}

/// Command definitions to register with Discord's application-command API.
pub fn command_definitions() -> Value {
    json!([
        {
            "name": "faucet",
            "type": 1,
            "description": "Receive test THRY for the Thrylos alpha network",
            "options": [{
                "name": "address",
                "description": "Your thry1… testnet address",
                "type": 3,
                "required": true,
                "min_length": 63,
                "max_length": 63
            }],
            "contexts": [0, 1],
            "integration_types": [0]
        },
        {
            "name": "name",
            "type": 1,
            "description": "Confirm the .thry name you reserved in the wallet",
            "options": [{
                "name": "address",
                "description": "The thry1… address you reserved the name for",
                "type": 3,
                "required": true,
                "min_length": 63,
                "max_length": 63
            }],
            "contexts": [0, 1],
            "integration_types": [0]
        },
        {
            "name": "faucet-status",
            "type": 1,
            "description": "Check your latest Thrylos faucet request",
            "contexts": [0, 1],
            "integration_types": [0]
        }
    ])
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use chain_types::Address;
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    /// A Discord user ID from 2015: an old account. And a day well after it.
    const OLD_ACCOUNT: &str = "80351110224678912";
    const TODAY: u64 = 20_000;

    fn signed(key: &SigningKey, timestamp: &str, body: &[u8]) -> String {
        let mut message = timestamp.as_bytes().to_vec();
        message.extend_from_slice(body);
        hex::encode(&key.sign(&message).to_bytes())
    }

    fn faucet() -> (tempfile::TempDir, Faucet) {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("faucet");
        Faucet::init(&directory).unwrap();
        (parent, Faucet::load(&directory).unwrap())
    }

    #[test]
    fn only_the_timestamp_and_exact_raw_body_signature_is_accepted() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let body = br#"{"type":1}"#;
        let signature = signed(&key, "123", body);
        assert!(verifies(&key.verifying_key(), &signature, "123", body));
        assert!(!verifies(&key.verifying_key(), &signature, "124", body));
        assert!(!verifies(
            &key.verifying_key(),
            &signature,
            "123",
            br#"{"type": 1}"#
        ));
    }

    #[test]
    fn ping_is_answered_and_an_invalid_signature_is_unauthorised() {
        let (_parent, mut faucet) = faucet();
        let key = SigningKey::from_bytes(&[8; 32]);
        let body = br#"{"type":1}"#;
        let signature = signed(&key, "123", body);
        let answer = handle_interaction(
            &mut faucet,
            &key.verifying_key(),
            Some(&signature),
            Some("123"),
            body,
            1,
        );
        assert_eq!(answer.status, 200);
        assert_eq!(
            serde_json::from_slice::<Value>(&answer.body).unwrap(),
            json!({ "type": 1 })
        );

        let refused = handle_interaction(
            &mut faucet,
            &key.verifying_key(),
            Some("00"),
            Some("123"),
            body,
            1,
        );
        assert_eq!(refused.status, 401);
    }

    #[test]
    fn faucet_command_queues_once_and_returns_an_ephemeral_answer() {
        let (_parent, mut faucet) = faucet();
        let key = SigningKey::from_bytes(&[8; 32]);
        let address = format_address(&Address::from_bytes([7; 32]));
        let body = serde_json::to_vec(&json!({
            "id": "interaction-1",
            "type": 2,
            "member": { "user": { "id": OLD_ACCOUNT } },
            "data": {
                "name": "faucet",
                "options": [{ "name": "address", "type": 3, "value": address }]
            }
        }))
        .unwrap();
        let signature = signed(&key, "123", &body);
        let answer = handle_interaction(
            &mut faucet,
            &key.verifying_key(),
            Some(&signature),
            Some("123"),
            &body,
            TODAY,
        );
        assert_eq!(answer.status, 200);
        let value: Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(value["type"], 4);
        assert_eq!(value["data"]["flags"], EPHEMERAL);
        assert_eq!(
            faucet.request("interaction-1").unwrap().status,
            RequestStatus::Queued
        );

        let again = handle_interaction(
            &mut faucet,
            &key.verifying_key(),
            Some(&signature),
            Some("123"),
            &body,
            TODAY,
        );
        assert_eq!(again.status, 200);
        assert_eq!(
            faucet.request("interaction-1").unwrap().status,
            RequestStatus::Queued
        );
    }

    /// The snowflake for an account created at `days` days after the Unix epoch.
    fn snowflake_created_on(day: u64) -> String {
        let ms = day
            .saturating_mul(86_400_000)
            .saturating_sub(DISCORD_EPOCH_MS);
        (ms << 22).to_string()
    }

    #[test]
    fn an_account_is_old_enough_only_after_the_minimum_age_and_a_bad_id_never_is() {
        let created = 20_000;
        let id = snowflake_created_on(created);
        assert_eq!(account_creation_day(&id), Some(created));
        assert!(!old_enough(&id, created + 6, 7), "six days is too young");
        assert!(old_enough(&id, created + 7, 7), "seven days is enough");
        assert!(!old_enough(&id, created - 1, 7), "not born yet");
        assert!(old_enough("not-a-snowflake", 0, 0), "the gate can be off");
        assert!(!old_enough("not-a-snowflake", TODAY, 7));
    }

    #[test]
    fn a_brand_new_account_is_turned_away_and_nothing_is_queued() {
        let (_parent, mut faucet) = faucet();
        let key = SigningKey::from_bytes(&[8; 32]);
        let address = format_address(&Address::from_bytes([7; 32]));
        let body = serde_json::to_vec(&json!({
            "id": "interaction-new",
            "type": 2,
            "member": { "user": { "id": snowflake_created_on(TODAY - 1) } },
            "data": {
                "name": "faucet",
                "options": [{ "name": "address", "type": 3, "value": address }]
            }
        }))
        .unwrap();
        let signature = signed(&key, "123", &body);
        let answer = handle_interaction(
            &mut faucet,
            &key.verifying_key(),
            Some(&signature),
            Some("123"),
            &body,
            TODAY,
        );
        let value: Value = serde_json::from_slice(&answer.body).unwrap();
        assert!(value["data"]["content"]
            .as_str()
            .unwrap()
            .contains("days old"));
        assert!(faucet.request("interaction-new").is_none());
    }

    #[test]
    fn a_timestamp_is_read_to_its_utc_day_and_nonsense_is_not() {
        assert_eq!(utc_day_of("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(utc_day_of("2000-03-01T12:00:00.5+00:00"), Some(11_017));
        assert_eq!(utc_day_of("2026-09-24T08:15:43.000000+00:00"), Some(20_720));
        assert_eq!(utc_day_of("not a date"), None);
        assert_eq!(utc_day_of("2026-13-01T00:00:00Z"), None);
        assert_eq!(utc_day_of("2026-09"), None);
    }

    #[test]
    fn membership_needs_a_join_date_old_enough_and_a_dm_has_none() {
        let joined = |at: &str| json!({ "member": { "joined_at": at } });
        assert!(member_long_enough(&json!({}), TODAY, 0), "off");
        assert!(
            !member_long_enough(&json!({}), TODAY, 1),
            "a DM has no join date"
        );
        assert!(!member_long_enough(&joined("garbage"), TODAY, 1));
        // 20_720 is 2026-09-24.
        assert!(
            !member_long_enough(&joined("2026-09-24T00:00:00+00:00"), 20_720, 1),
            "today"
        );
        assert!(member_long_enough(
            &joined("2026-09-23T23:59:59+00:00"),
            20_720,
            1
        ));
        assert!(!member_long_enough(
            &joined("2026-09-22T00:00:00+00:00"),
            20_720,
            3
        ));
        assert!(member_long_enough(
            &joined("2026-09-21T00:00:00+00:00"),
            20_720,
            3
        ));
    }

    // ---- names ----------------------------------------------------------

    /// A stand-in registry: answers each connection with the next of `replies`
    /// and remembers what it was sent.
    fn fake_registry(
        replies: Vec<&'static str>,
    ) -> (
        std::net::SocketAddr,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = std::sync::Arc::clone(&seen);
        std::thread::spawn(move || {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let mut buffer = vec![0u8; 4096];
                let count = stream.read(&mut buffer).unwrap_or(0);
                record
                    .lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&buffer[..count]).into_owned());
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (address, seen)
    }

    const CONFIRMED: &str =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n{\"name\":\"alice\",\"status\":\"confirmed\"}";
    const NO_RESERVATION: &str = "HTTP/1.1 404 Not Found\r\n\r\n{\"error\":{\"code\":\"NoReservation\",\"message\":\"none\"}}";
    const HAS_NAME: &str = "HTTP/1.1 409 Conflict\r\n\r\n{\"error\":{\"code\":\"DiscordUserHasName\",\"message\":\"this Discord account already has a name\"}}";

    fn faucet_with_names(registry: std::net::SocketAddr) -> (tempfile::TempDir, Faucet) {
        let parent = tempfile::tempdir().unwrap();
        let directory = parent.path().join("faucet");
        Faucet::init(&directory).unwrap();
        let path = directory.join("faucet.json");
        let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        config["names_registry"] = json!(registry.to_string());
        config["names_secret_file"] = json!("names.secret");
        std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        std::fs::write(directory.join("names.secret"), "the-shared-secret\n").unwrap();
        (parent, Faucet::load(&directory).unwrap())
    }

    fn say(faucet: &mut Faucet, command: &str, user: &str, id: &str, address: &str) -> String {
        let interaction = json!({
            "id": id,
            "type": 2,
            "member": { "user": { "id": user } },
            "data": { "name": command, "options": [{ "name": "address", "value": address }] }
        });
        let body = serde_json::to_vec(&interaction).unwrap();
        let key = SigningKey::from_bytes(&[8; 32]);
        let signature = signed(&key, "123", &body);
        let answer = handle_interaction(
            faucet,
            &key.verifying_key(),
            Some(&signature),
            Some("123"),
            &body,
            TODAY,
        );
        let value: Value = serde_json::from_slice(&answer.body).unwrap();
        value["data"]["content"].as_str().unwrap().to_owned()
    }

    #[test]
    fn an_accepted_faucet_claim_also_confirms_the_reserved_name() {
        let (registry, seen) = fake_registry(vec![CONFIRMED]);
        let (_parent, mut faucet) = faucet_with_names(registry);
        let address = format_address(&Address::from_bytes([7; 32]));
        let reply = say(&mut faucet, "faucet", OLD_ACCOUNT, "i1", &address);
        assert!(reply.starts_with("Queued"), "{reply}");
        assert!(reply.contains("`alice.thry` is confirmed"), "{reply}");
        let sent = seen.lock().unwrap().join("\n");
        assert!(sent.contains("X-Names-Secret: the-shared-secret"), "{sent}");
        assert!(
            sent.contains(&address) && sent.contains(OLD_ACCOUNT),
            "{sent}"
        );
    }

    #[test]
    fn a_refused_faucet_claim_never_reaches_the_registry() {
        // The daily limit stops the second request, so nothing may be confirmed by it.
        let (registry, seen) = fake_registry(vec![NO_RESERVATION]);
        let (_parent, mut faucet) = faucet_with_names(registry);
        let first = format_address(&Address::from_bytes([7; 32]));
        let second = format_address(&Address::from_bytes([9; 32]));
        assert!(say(&mut faucet, "faucet", OLD_ACCOUNT, "i1", &first).starts_with("Queued"));
        let reply = say(&mut faucet, "faucet", OLD_ACCOUNT, "i2", &second);
        assert!(reply.contains("limit"), "{reply}");
        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "only the accepted claim asked"
        );
    }

    #[test]
    fn a_faucet_claim_with_no_reservation_stays_quiet_and_a_registry_outage_never_stops_the_payout()
    {
        let (registry, _) = fake_registry(vec![NO_RESERVATION]);
        let (_parent, mut faucet) = faucet_with_names(registry);
        let address = format_address(&Address::from_bytes([7; 32]));
        let reply = say(&mut faucet, "faucet", OLD_ACCOUNT, "i1", &address);
        assert!(
            reply.starts_with("Queued") && !reply.contains("name"),
            "{reply}"
        );

        // Nothing listening: still paid, with a line saying to use /name.
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (_parent2, mut faucet) = faucet_with_names(closed);
        let other = format_address(&Address::from_bytes([8; 32]));
        let reply = say(&mut faucet, "faucet", OLD_ACCOUNT, "i2", &other);
        assert!(reply.starts_with("Queued"), "{reply}");
        assert!(reply.contains("`/name`"), "{reply}");
        assert_eq!(faucet.request("i2").unwrap().status, RequestStatus::Queued);
    }

    #[test]
    fn the_name_command_confirms_without_a_payout_and_reports_refusals() {
        let (registry, _) = fake_registry(vec![CONFIRMED, HAS_NAME, NO_RESERVATION]);
        let (_parent, mut faucet) = faucet_with_names(registry);
        let address = format_address(&Address::from_bytes([7; 32]));
        let done = say(&mut faucet, "name", OLD_ACCOUNT, "n1", &address);
        assert!(done.contains("`alice.thry` is confirmed"), "{done}");
        assert!(faucet.request("n1").is_none(), "no faucet request was made");
        let twice = say(&mut faucet, "name", OLD_ACCOUNT, "n2", &address);
        assert!(twice.contains("already has a name"), "{twice}");
        let none = say(&mut faucet, "name", OLD_ACCOUNT, "n3", &address);
        assert!(none.contains("no reservation"), "{none}");
    }

    #[test]
    fn the_name_command_applies_the_same_gates_as_the_faucet() {
        let (registry, seen) = fake_registry(vec![CONFIRMED]);
        let (_parent, mut faucet) = faucet_with_names(registry);
        let address = format_address(&Address::from_bytes([7; 32]));
        let young = snowflake_created_on(TODAY - 1);
        let reply = say(&mut faucet, "name", &young, "n1", &address);
        assert!(reply.contains("days old"), "{reply}");
        assert!(
            seen.lock().unwrap().is_empty(),
            "a refused account never asks the registry"
        );
    }

    #[test]
    fn with_names_off_the_name_command_says_so_and_the_faucet_is_unchanged() {
        let (_parent, mut faucet) = faucet();
        let address = format_address(&Address::from_bytes([7; 32]));
        let reply = say(&mut faucet, "name", OLD_ACCOUNT, "n1", &address);
        assert!(reply.contains("not switched on"), "{reply}");
        let paid = say(&mut faucet, "faucet", OLD_ACCOUNT, "i1", &address);
        assert!(
            paid.starts_with("Queued") && !paid.contains("name"),
            "{paid}"
        );
    }

    #[test]
    fn the_command_list_includes_name_with_a_required_address() {
        let commands = command_definitions();
        let name = commands
            .as_array()
            .unwrap()
            .iter()
            .find(|command| command["name"] == "name")
            .unwrap();
        assert_eq!(name["options"][0]["name"], "address");
        assert_eq!(name["options"][0]["required"], true);
    }
}
