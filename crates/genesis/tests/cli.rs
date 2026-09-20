//! The `chain-genesis` binary, run as a process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::process::{Command, Output};

const DEVNET: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/devnet.json");

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chain-genesis"))
        .args(args)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}

#[test]
fn check_reports_a_valid_file_and_exits_zero() {
    let output = run(&["check", DEVNET]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let text = stdout(&output);
    for expected in [
        "genesis file:       valid",
        "chain id:           1337",
        "genesis hash:       ",
        "state root:         ",
        "validators:         4",
        "25.00%",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
    assert!(
        !text.contains("warnings:"),
        "a fine set draws none:\n{text}"
    );
}

#[test]
fn hash_prints_exactly_the_genesis_hash_the_check_reports() {
    let hash = stdout(&run(&["hash", DEVNET]));
    let hash = hash.trim();
    assert_eq!(hash.len(), 64);
    assert!(hash.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(stdout(&run(&["check", DEVNET])).contains(hash));
}

#[test]
fn check_on_an_invalid_file_says_why_and_exits_non_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "{ \"chain_id\": 1 }").unwrap();
    let output = run(&["check", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).starts_with("error: "),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());

    let missing = run(&["check", dir.path().join("nope.json").to_str().unwrap()]);
    assert_eq!(missing.status.code(), Some(1));
}

#[test]
fn a_single_validator_genesis_is_valid_but_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("one.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(DEVNET).unwrap()).unwrap();
    value["validators"].as_array_mut().unwrap().truncate(1);
    std::fs::write(&path, value.to_string()).unwrap();

    let output = run(&["check", path.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "warnings are not errors");
    let text = stdout(&output);
    assert!(text.contains("warnings:"), "{text}");
    assert!(text.contains("can halt the chain"), "{text}");
    assert!(text.contains("alone decides finality"), "{text}");
}

#[test]
fn address_derives_the_address_of_a_public_key_and_refuses_junk() {
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(DEVNET).unwrap()).unwrap();
    let key = value["validators"][0]["operator_public_key"]
        .as_str()
        .unwrap();
    let output = run(&["address", key]);
    assert_eq!(output.status.code(), Some(0));
    let address = stdout(&output);
    assert_eq!(address.trim().len(), 64);
    assert_ne!(address.trim(), key, "an address is not the key");
    // It is one of the lines `check` lists for the validators.
    assert!(stdout(&run(&["check", DEVNET])).contains(address.trim()));

    for junk in ["", "zz", "abcd", &"0".repeat(63)] {
        assert_eq!(run(&["address", junk]).status.code(), Some(1), "{junk:?}");
    }
}

#[test]
fn devnet_prints_the_checked_in_example() {
    let printed = stdout(&run(&["devnet"]));
    assert_eq!(printed, std::fs::read_to_string(DEVNET).unwrap());
}

#[test]
fn unknown_commands_and_missing_arguments_print_usage_and_exit_two() {
    for args in [
        &[][..],
        &["check"],
        &["bogus"],
        &["check", "a", "b"],
        &["devnet", "x"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }
}

#[test]
fn check_shows_the_parameters_in_units_a_person_can_read() {
    let text = stdout(&run(&["check", DEVNET]));
    for expected in [
        "parameters:",
        "max block gas:                 60000000",
        "minimum self-stake:            1000000",
        "inflation:                     4.00% (400 bps)",
        "unbonding period:              21 d (1814400000 ms)",
        "governance quorum:             33.40% (3340 bps)",
        "governance veto threshold:     33.40% (3340 bps)",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in:\n{text}");
    }
}

#[test]
fn help_and_version_are_answers_not_errors() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert!(stdout(&output).contains("usage:"), "{flag}");
        assert!(stderr(&output).is_empty(), "{flag}");
    }
    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert_eq!(
            stdout(&output),
            format!("chain-genesis {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
    // Only as the sole argument: a flag among others is still a usage error.
    assert_eq!(run(&["check", "--help"]).status.code(), Some(1));
}
