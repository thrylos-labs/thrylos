//! Process-level evidence for the signer boundary. Each test runs the real
//! `chain-signer` binary and kills either it or a separate node-side helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods
)]

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use blst::min_pk::SecretKey;
use chain_node::{RemoteSigner, SignerCredential};
use chain_signer::{ConsensusSigner, HighWaterMark, SignerError, Step};
use chain_types::beacon::verify_reveal;
use chain_types::bls::{verify_aggregate, BlsPublicKey, DST_VOTE};
use chain_types::{BlockHeight, Hash, Round};

struct ChildGuard(Child);

impl ChildGuard {
    fn kill_and_wait(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    key: PathBuf,
    credential_file: PathBuf,
    mark: PathBuf,
    credential: SignerCredential,
    public_key: BlsPublicKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("signer.sock");
        let key = dir.path().join("consensus.key");
        let credential_file = dir.path().join("signer.auth");
        let mark = dir.path().join("signer.mark");
        let secret = SecretKey::key_gen(&[42; 32], &[]).unwrap();
        let public_key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes()).unwrap();
        write_private(&key, &secret.to_bytes());
        write_private(&credential_file, &[7; 32]);
        Self {
            _dir: dir,
            socket,
            key,
            credential_file,
            mark,
            credential: SignerCredential::from_bytes([7; 32]),
            public_key,
        }
    }

    fn start_signer(&self) -> ChildGuard {
        let child = Command::new(env!("CARGO_BIN_EXE_chain-signer"))
            .arg(&self.socket)
            .arg(&self.key)
            .arg(&self.credential_file)
            .arg(&self.mark)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn signer process");
        let mut child = ChildGuard(child);
        for _ in 0..200 {
            if self.socket.exists()
                && RemoteSigner::connect(
                    &self.socket,
                    self.credential.clone(),
                    Duration::from_millis(100),
                )
                .is_ok()
            {
                return child;
            }
            if let Some(status) = child.0.try_wait().unwrap() {
                let stderr = child
                    .0
                    .stderr
                    .take()
                    .map(|stderr| std::io::read_to_string(stderr).unwrap())
                    .unwrap_or_default();
                panic!("signer exited during startup ({status}): {stderr}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("signer socket did not appear");
    }

    fn connect(&self) -> RemoteSigner {
        RemoteSigner::connect(
            &self.socket,
            self.credential.clone(),
            Duration::from_secs(2),
        )
        .unwrap()
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn position(height: u64, step: Step) -> HighWaterMark {
    HighWaterMark::new(BlockHeight(height), Round(0), step)
}

#[test]
fn signer_crash_and_restart_preserves_the_mark_and_key_boundary() {
    let fixture = Fixture::new();
    let mut process = fixture.start_signer();
    let first = position(1, Step::Propose);
    let mut client = fixture.connect();
    let signature = client.sign(first, b"first vote").unwrap();
    assert!(verify_aggregate(&[&fixture.public_key], b"first vote", DST_VOTE, &signature).is_ok());
    let seed = Hash::from_bytes([3; 32]);
    let reveal = client.sign_beacon(BlockHeight(2), &seed).unwrap();
    assert!(verify_reveal(&fixture.public_key, BlockHeight(2), &seed, &reveal).is_ok());
    assert_eq!(client.high_water_mark(), Some(first));

    process.kill_and_wait();
    assert!(matches!(
        client.sign(position(2, Step::Propose), b"while dead"),
        Err(SignerError::Unavailable)
    ));

    let _restarted_process = fixture.start_signer();
    let mut restarted_client = fixture.connect();
    assert_eq!(restarted_client.high_water_mark(), Some(first));
    assert!(matches!(
        restarted_client.sign(first, b"conflicting vote"),
        Err(SignerError::Regression { .. })
    ));
    assert!(restarted_client
        .sign(position(2, Step::Propose), b"second vote")
        .is_ok());
}

#[test]
fn node_crash_does_not_stop_or_rewind_the_signer() {
    let fixture = Fixture::new();
    let _signer_process = fixture.start_signer();
    let mut node = Command::new(env!("CARGO_BIN_EXE_signer_node_crash_helper"))
        .arg(&fixture.socket)
        .arg(&fixture.credential_file)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn node-side signer client");
    let stdout = node.stdout.take().expect("node stdout was piped");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "SIGNED");
    node.kill().unwrap();
    node.wait().unwrap();

    let first = position(1, Step::Propose);
    let mut restarted_node = fixture.connect();
    assert_eq!(restarted_node.high_water_mark(), Some(first));
    assert!(matches!(
        restarted_node.sign(first, b"anything"),
        Err(SignerError::Regression { .. })
    ));
    assert!(restarted_node
        .sign(position(1, Step::Prevote), b"next step")
        .is_ok());
}

#[test]
fn a_wrong_local_credential_cannot_reach_the_signer() {
    let fixture = Fixture::new();
    let _signer_process = fixture.start_signer();
    assert!(RemoteSigner::connect(
        &fixture.socket,
        SignerCredential::from_bytes([8; 32]),
        Duration::from_secs(2),
    )
    .is_err());
    assert_eq!(fixture.connect().high_water_mark(), None);
}

#[test]
fn signer_refuses_a_consensus_key_readable_by_other_users() {
    let fixture = Fixture::new();
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o644)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chain-signer"))
        .arg(&fixture.socket)
        .arg(&fixture.key)
        .arg(&fixture.credential_file)
        .arg(&fixture.mark)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("must not be accessible"));
    assert!(
        stderr.contains(&format!("chmod 600 {}", fixture.key.display())),
        "the message says how to fix it: {stderr}"
    );
    assert!(!fixture.socket.exists());
}

#[test]
fn signer_answers_help_and_version_without_touching_anything() {
    for (flag, expected) in [
        ("--help", "usage: chain-signer"),
        ("-h", "usage: chain-signer"),
        ("--version", "chain-signer "),
        ("-V", "chain-signer "),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chain-signer"))
            .arg(flag)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert!(
            String::from_utf8_lossy(&output.stdout).starts_with(expected),
            "{flag}"
        );
        assert!(output.stderr.is_empty(), "{flag}");
    }
}
