//! The `chain-node` binary, run as a process.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chain-node"))
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
fn help_and_version_are_answers_not_errors() {
    for flag in ["--help", "-h"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert!(
            stdout(&output).contains("chain-node run <config.json>"),
            "{flag}"
        );
        assert!(stderr(&output).is_empty(), "{flag}");
    }
    for flag in ["--version", "-V"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert_eq!(
            stdout(&output),
            format!("chain-node {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
}

#[test]
fn unknown_commands_and_missing_arguments_print_usage_and_exit_two() {
    for args in [
        &[][..],
        &["bogus"],
        &["run"],
        &["run", "a.json", "b.json"],
        &["run", "a.json", "--until-height"],
        &["run", "a.json", "--until", "3"],
        &["network-key"],
        &["network-key", "a", "b"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }
}

#[test]
fn network_key_makes_a_private_key_prints_its_public_half_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("network.key");
    let path = path.to_str().unwrap();

    let output = run(&["network-key", path]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let public = stdout(&output);
    let public = public.trim();
    assert_eq!(public.len(), 64);
    assert!(public.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let secret = std::fs::read_to_string(path).unwrap();
    assert_eq!(secret.trim().len(), 64);
    assert_ne!(
        secret.trim(),
        public,
        "the file holds the secret, not the public key"
    );

    // The public key it printed is the one the file gives.
    let identity = chain_node::config::read_network_key(std::path::Path::new(path)).unwrap();
    assert_eq!(chain_genesis::hex::encode(&identity.public_key()), public);

    // A second run refuses, says so, and leaves the key alone.
    let again = run(&["network-key", path]);
    assert_eq!(again.status.code(), Some(1));
    assert!(
        stderr(&again).contains("cannot create it"),
        "{}",
        stderr(&again)
    );
    assert_eq!(std::fs::read_to_string(path).unwrap(), secret);
}

#[test]
fn run_says_what_is_wrong_with_a_configuration_before_doing_anything() {
    let dir = tempfile::tempdir().unwrap();

    let missing = dir.path().join("missing.json");
    let output = run(&["run", missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("cannot read"),
        "{}",
        stderr(&output)
    );

    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, "{ not json").unwrap();
    let output = run(&["run", broken.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not valid"), "{}", stderr(&output));

    let output = run(&["run", broken.to_str().unwrap(), "--until-height", "soon"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("block height"),
        "{}",
        stderr(&output)
    );
    assert!(stdout(&output).is_empty());
}
