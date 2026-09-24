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
        Some("faucet-status") => match faucet.latest_for_user(user_id) {
            Some(record) => message(&record_message(record)),
            None => message("You have no faucet request yet. Use `/faucet` with your address."),
        },
        _ => message("Unknown command. Use `/faucet` or `/faucet-status`."),
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
        Ok(EnqueueResult::Queued) => message(&format!(
            "Queued {} for {}. Request `{request_id}`. Use `/faucet-status` to check it.",
            faucet.config().payout,
            format_address(&address)
        )),
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
}
