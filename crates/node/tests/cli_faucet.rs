//! The faucet operator CLI's offline setup and command-definition paths.

#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chain-faucet"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn init_creates_a_private_separate_key_and_refuses_to_overwrite() {
    let parent = tempfile::tempdir().unwrap();
    let directory = parent.path().join("faucet");
    let path = directory.to_str().unwrap();
    let made = run(&["init", path]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let output = String::from_utf8(made.stdout).unwrap();
    assert!(output.contains("Address to fund: thry1"));
    assert!(output.contains("set `discord_public_key`"));
    assert_eq!(
        std::fs::metadata(directory.join("faucet.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(directory.join("faucet.json").is_file());
    assert!(directory.join("state.json").is_file());

    let again = run(&["init", path]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("no faucet state is overwritten"));
}

#[test]
fn discord_commands_are_the_three_expected_slash_commands() {
    let output = run(&["discord-commands"]);
    assert!(output.status.success());
    let commands: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let commands = commands.as_array().unwrap();
    assert_eq!(commands.len(), 3);
    let faucet = commands.first().unwrap();
    assert_eq!(faucet.get("name").unwrap(), "faucet");
    assert_eq!(commands.get(1).unwrap().get("name").unwrap(), "name");
    assert_eq!(
        commands.get(2).unwrap().get("name").unwrap(),
        "faucet-status"
    );
    assert_eq!(
        faucet
            .get("options")
            .unwrap()
            .as_array()
            .unwrap()
            .first()
            .unwrap()
            .get("name")
            .unwrap(),
        "address"
    );
}

#[test]
fn help_is_an_answer_and_public_listening_is_refused() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("TLS reverse proxy"));

    let refused = run(&["run", "/does/not/matter", "--listen", "0.0.0.0:8081"]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("must listen on loopback"));
}
