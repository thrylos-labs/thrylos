//! Drives `chain-faucet run`'s real HTTP listener with a real Discord-style
//! signed interaction, over the wire — not by calling
//! `faucet_discord::handle_interaction` in process, which every other test
//! of this adapter does. This is the one test that exercises the actual
//! bytes a public gateway would forward: real TCP, real HTTP/1.1 framing,
//! real Ed25519 signature verification against `discord_public_key`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use chain_rpc::hex;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

struct Faucet {
    child: Child,
    address: String,
}

impl Drop for Faucet {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts `chain-faucet run` against `dir` on an OS-chosen loopback port and
/// waits for it to say it is listening.
fn start(dir: &std::path::Path) -> Faucet {
    let mut child = Command::new(env!("CARGO_BIN_EXE_chain-faucet"))
        .args(["run"])
        .arg(dir)
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let first = lines
        .next()
        .expect("the faucet exited before printing its listen address")
        .unwrap();
    let address = first
        .strip_prefix("Discord faucet listening on http://")
        .unwrap_or_else(|| panic!("unexpected startup line: {first:?}"))
        .to_owned();
    // The child's stdout must keep being read, or a full pipe buffer could
    // stall it; drain the rest on a thread for the test's lifetime.
    std::thread::spawn(move || for _line in lines.by_ref() {});
    Faucet { child, address }
}

fn sign(key: &SigningKey, timestamp: &str, body: &[u8]) -> String {
    let mut message = Vec::with_capacity(timestamp.len() + body.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.extend_from_slice(body);
    hex::encode(&key.sign(&message).to_bytes())
}

/// One real HTTP/1.1 request over a fresh TCP connection, exactly as a TLS
/// gateway forwarding Discord's own request would send it. Returns the
/// status line and the parsed JSON body.
fn post_interaction(
    address: &str,
    key: &SigningKey,
    timestamp: &str,
    body: &Value,
    valid_signature: bool,
) -> (String, Value) {
    let body = serde_json::to_vec(body).unwrap();
    let signature = if valid_signature {
        sign(key, timestamp, &body)
    } else {
        "00".repeat(64)
    };
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\n\
         X-Signature-Ed25519: {signature}\r\nX-Signature-Timestamp: {timestamp}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    stream.write_all(&body).unwrap();

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, response_body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    let parsed = if response_body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(response_body).unwrap()
    };
    (status, parsed)
}

fn init_faucet(dir: &std::path::Path, discord_key: &SigningKey) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_chain-faucet"))
        .args(["init"])
        .arg(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config_path = dir.join("faucet.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["discord_public_key"] = json!(hex::encode(discord_key.verifying_key().as_bytes()));
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("Address to fund: "))
        .unwrap()
        .to_owned()
}

#[test]
fn a_real_signed_ping_over_the_wire_is_answered_with_the_discord_handshake() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("faucet");
    let discord_key = SigningKey::from_bytes(&[7; 32]);
    init_faucet(&dir, &discord_key);
    let faucet = start(&dir);

    let (status, body) = post_interaction(
        &faucet.address,
        &discord_key,
        "1700000000",
        &json!({ "type": 1 }),
        true,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(body["type"], 1);
}

#[test]
fn a_real_faucet_command_over_the_wire_is_queued_and_a_bad_signature_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("faucet");
    let discord_key = SigningKey::from_bytes(&[9; 32]);
    init_faucet(&dir, &discord_key);
    let faucet = start(&dir);

    let recipient = chain_text::format_address(&chain_types::Address::from_bytes([66; 32]));
    let interaction = json!({
        "id": "wire-test-1",
        "type": 2,
        "member": { "user": { "id": "80351110224678912" } },
        "data": {
            "name": "faucet",
            "options": [{ "name": "address", "value": recipient }]
        }
    });

    let (status, body) = post_interaction(
        &faucet.address,
        &discord_key,
        "1700000000",
        &interaction,
        true,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    let content = body["data"]["content"].as_str().unwrap();
    assert!(content.starts_with("Queued"), "{content}");
    assert!(content.contains("wire-test-1"), "{content}");

    // The same interaction again is the same request, already received.
    let (_status, body) = post_interaction(
        &faucet.address,
        &discord_key,
        "1700000001",
        &interaction,
        true,
    );
    let content = body["data"]["content"].as_str().unwrap();
    assert!(content.contains("already received"), "{content}");

    // A signature that does not match the body is refused before anything
    // is parsed or enqueued, exactly as Discord's own gateway requires.
    let (status, body) = post_interaction(
        &faucet.address,
        &discord_key,
        "1700000002",
        &interaction,
        false,
    );
    assert!(status.starts_with("HTTP/1.1 401"), "{status}");
    assert_eq!(body, Value::Null);
}
