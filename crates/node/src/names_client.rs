//! How the faucet asks the name registry to confirm a name: one short HTTP call
//! to a loopback address, carrying the shared secret. Discord gives an
//! interaction about three seconds to be answered, so every step here is tightly
//! timed, and a registry that is down or slow never stops the faucet paying out.

// `serde_json::Value` indexing by key returns `Null` for a missing key and
// never panics; the lint cannot tell it from slice indexing.
#![allow(clippy::indexing_slicing)]

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::{json, Value};

use crate::client::read_capped;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(800);
const IO_TIMEOUT: Duration = Duration::from_millis(1200);

/// What the registry said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// The reservation is now a permanent name.
    Confirmed { name: String },
    /// A refusal the user should hear about (`code` is the registry's).
    Refused { code: String, message: String },
    /// It could not be reached, or answered something unusable.
    Unavailable,
}

/// Asks the registry at `registry` to confirm the reservation for `address`
/// (`thry1…`) on behalf of Discord user `discord_user_id`.
pub fn confirm(
    registry: SocketAddr,
    secret: &str,
    address: &str,
    discord_user_id: &str,
) -> Confirmation {
    let body = json!({ "address": address, "discordUserId": discord_user_id }).to_string();
    let Ok(mut stream) = TcpStream::connect_timeout(&registry, CONNECT_TIMEOUT) else {
        return Confirmation::Unavailable;
    };
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return Confirmation::Unavailable;
    }
    let request = format!(
        "POST /internal/confirm HTTP/1.1\r\nHost: {registry}\r\nContent-Type: application/json\r\n\
         X-Names-Secret: {secret}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return Confirmation::Unavailable;
    }
    let mut text = String::new();
    match read_capped(&mut stream, &mut text) {
        Ok(Ok(_)) => {}
        _ => return Confirmation::Unavailable,
    }
    let Some((head, payload)) = text.split_once("\r\n\r\n") else {
        return Confirmation::Unavailable;
    };
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Confirmation::Unavailable;
    };
    if head.starts_with("HTTP/1.1 200") {
        return match value["name"].as_str() {
            Some(name) => Confirmation::Confirmed {
                name: name.to_owned(),
            },
            None => Confirmation::Unavailable,
        };
    }
    // The secret being wrong is a setup problem, not something to tell the user.
    if head.starts_with("HTTP/1.1 401") || head.starts_with("HTTP/1.1 5") {
        return Confirmation::Unavailable;
    }
    match (
        value["error"]["code"].as_str(),
        value["error"]["message"].as_str(),
    ) {
        (Some(code), Some(message)) => Confirmation::Refused {
            code: code.to_owned(),
            message: message.to_owned(),
        },
        _ => Confirmation::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use std::io::Read;
    use std::net::TcpListener;

    use super::*;

    /// A stand-in registry that answers once with `reply`.
    fn registry_saying(reply: &'static str) -> (SocketAddr, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut seen = vec![0u8; 4096];
            let count = stream.read(&mut seen).unwrap();
            stream.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&seen[..count]).into_owned()
        });
        (address, handle)
    }

    #[test]
    fn a_confirmation_carries_the_secret_and_reads_back_the_name() {
        let (address, seen) = registry_saying(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n{\"name\":\"alice\",\"status\":\"confirmed\"}",
        );
        let outcome = confirm(address, "s3cret", "thry1abc", "42");
        assert_eq!(
            outcome,
            Confirmation::Confirmed {
                name: "alice".into()
            }
        );
        let request = seen.join().unwrap();
        assert!(request.starts_with("POST /internal/confirm HTTP/1.1"));
        assert!(request.contains("X-Names-Secret: s3cret"));
        assert!(request.contains("\"discordUserId\":\"42\""));
    }

    #[test]
    fn a_refusal_is_passed_on_and_a_setup_problem_or_outage_is_not() {
        let (address, _) = registry_saying(
            "HTTP/1.1 409 Conflict\r\n\r\n{\"error\":{\"code\":\"DiscordUserHasName\",\"message\":\"this Discord account already has a name\"}}",
        );
        assert_eq!(
            confirm(address, "s", "thry1abc", "42"),
            Confirmation::Refused {
                code: "DiscordUserHasName".into(),
                message: "this Discord account already has a name".into()
            }
        );
        let (address, _) = registry_saying("HTTP/1.1 401 Unauthorized\r\n\r\n{\"error\":{\"code\":\"Unauthorized\",\"message\":\"no\"}}");
        assert_eq!(
            confirm(address, "s", "thry1abc", "42"),
            Confirmation::Unavailable
        );
        let (address, _) = registry_saying("garbage");
        assert_eq!(
            confirm(address, "s", "thry1abc", "42"),
            Confirmation::Unavailable
        );
        // Nothing listening at all.
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert_eq!(
            confirm(closed, "s", "thry1abc", "42"),
            Confirmation::Unavailable
        );
    }
}
