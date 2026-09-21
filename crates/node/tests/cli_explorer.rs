//! The `chain-explorer` binary's command-line boundary.

#![allow(clippy::unwrap_used)]

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_chain-explorer"))
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
fn help_and_version_are_answers() {
    let help = run(&["--help"]);
    assert!(help.status.success(), "{}", stderr(&help));
    assert!(stdout(&help).contains("chain-explorer <devnet-dir>"));
    assert!(stdout(&help).contains("read-only"));
    assert!(stdout(&help).contains("127.0.0.1:8080"));

    let version = run(&["--version"]);
    assert!(version.status.success(), "{}", stderr(&version));
    assert_eq!(
        stdout(&version),
        format!("chain-explorer {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn bad_arguments_are_usage_errors() {
    for args in [&[][..], &["/tmp/network", "--port", "nope"], &["a", "b"]] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }
}

#[test]
fn a_missing_network_is_explained_before_listening() {
    let output = run(&["/definitely/not/a/thrylos/network"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("holds no generated network"),
        "{}",
        stderr(&output)
    );
}
