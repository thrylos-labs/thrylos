//! The account CLI's offline first-run path: it is useful before any node is
//! reachable and must never overwrite or expose its key.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn setup_makes_a_private_wallet_and_address_reads_the_same_public_address() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("wallet.key");
    let binary = env!("CARGO_BIN_EXE_thrylos");

    let made = Command::new(binary)
        .args(["setup", "--wallet"])
        .arg(&wallet)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let text = String::from_utf8(made.stdout).unwrap();
    let address = text
        .lines()
        .find_map(|line| line.strip_prefix("Address: "))
        .unwrap();
    assert!(address.starts_with("thry1"));
    assert_eq!(
        std::fs::metadata(&wallet).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let shown = Command::new(binary)
        .args(["address", "--wallet"])
        .arg(&wallet)
        .output()
        .unwrap();
    assert!(shown.status.success());
    assert_eq!(String::from_utf8(shown.stdout).unwrap().trim(), address);

    let again = Command::new(binary)
        .args(["setup", "--wallet"])
        .arg(&wallet)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("left unchanged"));
}

#[test]
fn an_address_before_setup_says_exactly_how_to_fix_it() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = dir.path().join("missing.key");
    let output = Command::new(env!("CARGO_BIN_EXE_thrylos"))
        .args(["address", "--wallet"])
        .arg(wallet)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("make one with `thrylos setup`"));
}
