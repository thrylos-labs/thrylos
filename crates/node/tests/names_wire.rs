//! Drives the real `chain-names` process over real TCP: a wallet-style
//! reservation, the faucet-style confirmation, CORS, and slow clients.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chain_node::names::claim_message;
use chain_rpc::hex;
use chain_text::format_address;
use chain_types::{Address, PublicKey};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

const CHAIN: u64 = 20_260_923;

struct Names {
    child: Child,
    address: String,
    secret: String,
}

impl Drop for Names {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start(dir: &std::path::Path) -> Names {
    let init = Command::new(env!("CARGO_BIN_EXE_chain-names"))
        .args(["init"])
        .arg(dir)
        .args(["--chain-id", &CHAIN.to_string()])
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let secret = std::fs::read_to_string(dir.join("names.secret")).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_chain-names"))
        .args(["run"])
        .arg(dir)
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let address = loop {
        let line = lines.next().expect("chain-names exited early").unwrap();
        if let Some(rest) = line.strip_prefix("Name registry listening on http://") {
            break rest.to_owned();
        }
    };
    std::thread::spawn(move || for _line in lines.by_ref() {});
    Names {
        child,
        address,
        secret,
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// One request; returns (status line, lowercase header block, JSON body).
fn http(
    address: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (String, String, Value) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, payload) = response.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    let parsed = if payload.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(payload).unwrap()
    };
    (status, head.to_ascii_lowercase(), parsed)
}

fn reservation(key: &SigningKey, name: &str, timestamp_ms: u64) -> (String, String) {
    let public = PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap();
    let address = Address::from_public_key(&public);
    let message = claim_message(CHAIN, name, &address, timestamp_ms);
    let body = json!({
        "name": name,
        "publicKey": hex::encode(&key.verifying_key().to_bytes()),
        "timestampMs": timestamp_ms,
        "signature": hex::encode(&key.sign(&message).to_bytes()),
    })
    .to_string();
    (body, format_address(&address))
}

#[test]
fn a_reservation_is_confirmed_by_the_faucet_and_then_resolves_over_the_wire() {
    let parent = tempfile::tempdir().unwrap();
    let names = start(&parent.path().join("names"));
    let key = SigningKey::from_bytes(&[5; 32]);
    let (body, address) = reservation(&key, "alice", now_ms());

    // The wallet's live check, then its reservation.
    let (status, _, free) = http(&names.address, "GET", "/names/available/alice", &[], "");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(free["available"], true);
    let (status, headers, reserved) = http(
        &names.address,
        "POST",
        "/names",
        &[("Content-Type", "application/json")],
        &body,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status} {reserved}");
    assert_eq!(reserved["status"], "pending");
    assert!(
        headers.contains("access-control-allow-origin: *"),
        "{headers}"
    );

    // Pending: the name does not resolve.
    let (status, _, _) = http(&names.address, "GET", "/names/alice", &[], "");
    assert!(status.starts_with("HTTP/1.1 404"), "{status}");

    // The faucet confirms, with the secret; a wrong one is refused.
    let confirm = json!({ "address": address, "discordUserId": "80351110224678912" }).to_string();
    let (status, _, _) = http(
        &names.address,
        "POST",
        "/internal/confirm",
        &[("X-Names-Secret", "wrong")],
        &confirm,
    );
    assert!(status.starts_with("HTTP/1.1 401"), "{status}");
    let (status, headers, confirmed) = http(
        &names.address,
        "POST",
        "/internal/confirm",
        &[("X-Names-Secret", names.secret.trim())],
        &confirm,
    );
    assert!(status.starts_with("HTTP/1.1 200"), "{status} {confirmed}");
    assert!(
        !headers.contains("access-control-allow-origin"),
        "the faucet-only route is not open to browsers"
    );

    // And through the tunnel's headers the same request is refused.
    let (status, _, _) = http(
        &names.address,
        "POST",
        "/internal/confirm",
        &[
            ("X-Names-Secret", names.secret.trim()),
            ("CF-Connecting-IP", "8.8.8.8"),
        ],
        &confirm,
    );
    assert!(status.starts_with("HTTP/1.1 401"), "{status}");

    let (status, _, resolved) = http(&names.address, "GET", "/names/alice.thry", &[], "");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(resolved["address"], address);

    // A browser's preflight is answered.
    let (status, headers, _) = http(
        &names.address,
        "OPTIONS",
        "/names",
        &[
            ("Origin", "https://wallet.thrylos.org"),
            ("Access-Control-Request-Method", "POST"),
        ],
        "",
    );
    assert!(status.starts_with("HTTP/1.1 204"), "{status}");
    assert!(
        headers.contains("access-control-allow-methods"),
        "{headers}"
    );
}

#[test]
fn the_registry_is_still_there_after_a_restart() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("names");
    let key = SigningKey::from_bytes(&[6; 32]);
    let (body, address) = reservation(&key, "carol", now_ms());
    {
        let names = start(&dir);
        let (status, _, _) = http(&names.address, "POST", "/names", &[], &body);
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    }
    // Start again over the same directory (init is skipped: it would refuse).
    let mut child = Command::new(env!("CARGO_BIN_EXE_chain-names"))
        .args(["run"])
        .arg(&dir)
        .args(["--listen", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let address_line = loop {
        let line = lines.next().unwrap().unwrap();
        if let Some(rest) = line.strip_prefix("Name registry listening on http://") {
            break rest.to_owned();
        }
    };
    let (status, _, pending) = http(
        &address_line,
        "GET",
        &format!("/names/by-address/{address}"),
        &[],
        "",
    );
    let _ = child.kill();
    let _ = child.wait();
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert_eq!(pending["status"], "pending");
}

#[test]
fn silent_and_dripping_clients_do_not_stop_a_lookup() {
    let parent = tempfile::tempdir().unwrap();
    let names = start(&parent.path().join("names"));
    let _silent: Vec<TcpStream> = (0..4)
        .map(|_| TcpStream::connect(&names.address).unwrap())
        .collect();
    let mut dripper = TcpStream::connect(&names.address).unwrap();
    dripper.write_all(b"GET /names/x HTTP/1.1\r\nHo").unwrap();

    let started = Instant::now();
    let (status, _, _) = http(&names.address, "GET", "/names/available/someone", &[], "");
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "answered after {:?}",
        started.elapsed()
    );
}

#[test]
fn it_refuses_to_run_on_a_public_address_and_init_will_not_overwrite() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("names");
    let _names = start(&dir);
    let again = Command::new(env!("CARGO_BIN_EXE_chain-names"))
        .args(["init"])
        .arg(&dir)
        .args(["--chain-id", "1"])
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("refusing to overwrite"));

    let public = Command::new(env!("CARGO_BIN_EXE_chain-names"))
        .args(["run"])
        .arg(&dir)
        .args(["--listen", "0.0.0.0:0"])
        .output()
        .unwrap();
    assert!(!public.status.success());
    assert!(String::from_utf8_lossy(&public.stderr).contains("loopback"));
}
