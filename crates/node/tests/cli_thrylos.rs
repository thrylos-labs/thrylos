//! `thrylos network`: saved RPC profiles, so a public testnet's gateway URL
//! does not need to be typed on every command.

#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

fn thrylos(networks: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_thrylos"))
        .env("THRYLOS_NETWORKS", networks)
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_network_can_be_added_used_listed_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let networks = dir.path().join("networks.json");

    let listed = thrylos(&networks, &["network", "list"]);
    assert!(listed.status.success(), "{}", stderr(&listed));
    assert!(stdout(&listed).contains("No saved networks"));

    let added = thrylos(
        &networks,
        &[
            "network",
            "add",
            "testnet-alpha",
            "https://rpc.testnet.example",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(stdout(&added).contains("testnet-alpha"));

    let listed = thrylos(&networks, &["network", "list"]);
    let text = stdout(&listed);
    assert!(text.contains("testnet-alpha"));
    assert!(text.contains("https://rpc.testnet.example"));
    // Not yet active: no line starts with the "current" marker.
    assert!(!text.lines().any(|line| line.starts_with("* ")));

    let used = thrylos(&networks, &["network", "use", "testnet-alpha"]);
    assert!(used.status.success(), "{}", stderr(&used));

    let listed = thrylos(&networks, &["network", "list"]);
    assert!(stdout(&listed)
        .lines()
        .any(|line| line.starts_with("* ") && line.contains("testnet-alpha")));

    let removed = thrylos(&networks, &["network", "remove", "testnet-alpha"]);
    assert!(removed.status.success(), "{}", stderr(&removed));
    let listed = thrylos(&networks, &["network", "list"]);
    assert!(stdout(&listed).contains("No saved networks"));
}

#[test]
fn an_invalid_rpc_is_refused_before_it_is_saved() {
    let dir = tempfile::tempdir().unwrap();
    let networks = dir.path().join("networks.json");

    let added = thrylos(&networks, &["network", "add", "bad", "not-a-url"]);
    assert!(!added.status.success());
    assert!(
        stderr(&added).contains("needs a port"),
        "{}",
        stderr(&added)
    );
    assert!(!networks.exists());
}

#[test]
fn using_an_unknown_network_says_how_to_add_it() {
    let dir = tempfile::tempdir().unwrap();
    let networks = dir.path().join("networks.json");

    let used = thrylos(&networks, &["network", "use", "ghost"]);
    assert!(!used.status.success());
    assert!(
        stderr(&used).contains("thrylos network add ghost"),
        "{}",
        stderr(&used)
    );
}

#[test]
fn an_active_network_is_used_when_no_rpc_flag_is_given() {
    let dir = tempfile::tempdir().unwrap();
    let networks = dir.path().join("networks.json");
    thrylos(
        &networks,
        &["network", "add", "nowhere", "https://127.0.0.1:0"],
    );
    thrylos(&networks, &["network", "use", "nowhere"]);

    // `status` has no --rpc and no THRYLOS_RPC, so it must fall back to the
    // saved "nowhere" network and fail trying to reach it, not silently use
    // the local-node default.
    let status = thrylos(&networks, &["status"]);
    assert!(!status.status.success());
    assert!(
        !stderr(&status).contains("127.0.0.1:26660"),
        "{}",
        stderr(&status)
    );
}

#[test]
fn an_explicit_rpc_flag_overrides_the_active_network() {
    let dir = tempfile::tempdir().unwrap();
    let networks = dir.path().join("networks.json");
    thrylos(
        &networks,
        &["network", "add", "nowhere", "https://rpc.example:443"],
    );
    thrylos(&networks, &["network", "use", "nowhere"]);

    let status = thrylos(&networks, &["status", "--rpc", "127.0.0.1:0"]);
    assert!(!status.status.success());
    // It tried the loopback address from --rpc, not the saved gateway.
    assert!(
        stderr(&status).contains("127.0.0.1:0"),
        "{}",
        stderr(&status)
    );
}
