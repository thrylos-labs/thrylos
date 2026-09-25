//! `thrylos move new`, `build` and `test`: the parts that need no network.

#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Output};

fn thrylos(args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_thrylos"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_new_package_tests_and_builds_and_publish_says_when_it_is_not_built() {
    let root = tempfile::tempdir().unwrap();
    let made = thrylos(&["move", "new", "hello"], root.path());
    assert!(made.status.success(), "{}", err(&made));
    assert!(root.path().join("hello/sources/hello.move").is_file());

    let tested = thrylos(&["move", "test", "hello"], root.path());
    assert!(tested.status.success(), "{}{}", out(&tested), err(&tested));
    assert!(
        out(&tested).contains("[ PASS ] hello::adds"),
        "{}",
        out(&tested)
    );
    assert!(
        out(&tested).contains("2 passed, 0 failed"),
        "{}",
        out(&tested)
    );

    // Not built yet.
    let early = thrylos(
        &["move", "publish", "hello", "--yes", "--rpc", "127.0.0.1:1"],
        root.path(),
    );
    assert!(!early.status.success());
    assert!(
        err(&early).contains("has not been built"),
        "{}",
        err(&early)
    );

    let built = thrylos(&["move", "build", "hello"], root.path());
    assert!(built.status.success(), "{}{}", out(&built), err(&built));
    assert!(out(&built).contains("hello.mv"));
    assert!(root.path().join("hello/build/hello.mv").is_file());

    // Built, so publish now gets as far as needing a network.
    let late = thrylos(
        &["move", "publish", "hello", "--yes", "--rpc", "127.0.0.1:1"],
        root.path(),
    );
    assert!(!late.status.success());
    assert!(!err(&late).contains("has not been built"), "{}", err(&late));
}

#[test]
fn a_failing_test_fails_the_command_and_says_which() {
    let root = tempfile::tempdir().unwrap();
    assert!(thrylos(&["move", "new", "p"], root.path()).status.success());
    std::fs::write(
        root.path().join("p/sources/extra.move"),
        "module pkg::extra;\n#[test]\nfun broken() { assert!(1u64 == 2u64, 5); }\n",
    )
    .unwrap();
    let tested = thrylos(&["move", "test", "p"], root.path());
    assert!(!tested.status.success());
    assert!(
        out(&tested).contains("[ FAIL ] extra::broken"),
        "{}",
        out(&tested)
    );
    assert!(out(&tested).contains("code 5"), "{}", out(&tested));
    // The filter leaves it out.
    let filtered = thrylos(&["move", "test", "p", "--filter", "adds"], root.path());
    assert!(
        filtered.status.success(),
        "{}{}",
        out(&filtered),
        err(&filtered)
    );
}

#[test]
fn a_compile_error_is_shown_and_fails_the_build() {
    let root = tempfile::tempdir().unwrap();
    assert!(thrylos(&["move", "new", "p"], root.path()).status.success());
    std::fs::write(
        root.path().join("p/sources/bad.move"),
        "module pkg::bad; fun f(): u64 { true }",
    )
    .unwrap();
    let built = thrylos(&["move", "build", "p"], root.path());
    assert!(!built.status.success());
    assert!(err(&built).contains("error"), "{}", err(&built));
    assert!(!root.path().join("p/build").exists());
}

#[test]
fn new_refuses_to_overwrite_and_bad_arguments_are_explained() {
    let root = tempfile::tempdir().unwrap();
    assert!(thrylos(&["move", "new", "p"], root.path()).status.success());
    let again = thrylos(&["move", "new", "p"], root.path());
    assert!(!again.status.success());
    assert!(err(&again).contains("already exists"));
    let bad = thrylos(&["move", "test", "p", "--dep", "nope"], root.path());
    assert!(!bad.status.success());
    assert!(err(&bad).contains("--dep wants"), "{}", err(&bad));
}
