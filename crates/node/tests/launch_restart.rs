//! A network run as a service starts a node that dies again. Runs the real
//! `launch` and the real `chain-signer` against stand-in "nodes": small scripts
//! that fail a set number of times and then behave.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use chain_node::launch::{launch, LaunchOptions, RestartPolicy};

fn devnet(dir: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_chain-node"))
        .args(["devnet", "init"])
        .arg(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A node that exits with failure the first `failures` times it is run, then
/// runs for a moment and finishes cleanly. It counts its runs in a file beside
/// its config.
fn stand_in(dir: &Path, failures: u32) -> std::path::PathBuf {
    let path = dir.join("stand-in-node.sh");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nd=\"$(dirname \"$2\")\"\nn=$(cat \"$d/runs\" 2>/dev/null || echo 0)\nn=$((n+1))\necho $n > \"$d/runs\"\nif [ \"$n\" -le {failures} ]; then echo \"failing on run $n\"; exit 1; fi\nsleep 1\nexit 0\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn quick() -> RestartPolicy {
    RestartPolicy {
        initial_wait: Duration::from_millis(300),
        max_wait: Duration::from_millis(1200),
        stable_after: Duration::from_secs(30),
        give_up_after: 5,
    }
}

fn runs(dir: &Path, node: usize) -> u32 {
    fs::read_to_string(dir.join(format!("node{node}/runs")))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

#[test]
fn a_node_that_dies_is_started_again_until_it_stays_up() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("net");
    devnet(&dir);
    let node = stand_in(parent.path(), 2);
    let signer = Path::new(env!("CARGO_BIN_EXE_chain-signer"));

    let mut said = Vec::new();
    let started = Instant::now();
    let result = launch(
        &dir,
        LaunchOptions {
            node_exe: &node,
            signer_exe: signer,
            until_height: None,
            restart: Some(quick()),
        },
        &mut |line| said.push(line),
    );
    assert!(result.is_ok(), "{result:?}\n{}", said.join("\n"));
    // Each of the four nodes failed twice and was started a third time.
    for number in 1..=4 {
        assert_eq!(runs(&dir, number), 3, "node {number}\n{}", said.join("\n"));
    }
    let text = said.join("\n");
    assert!(text.contains("will be started again in"), "{text}");
    assert!(text.contains("started again (pid"), "{text}");
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn without_a_restart_policy_a_dead_node_stays_dead_as_before() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("net");
    devnet(&dir);
    let node = stand_in(parent.path(), 99);
    let signer = Path::new(env!("CARGO_BIN_EXE_chain-signer"));
    let mut said = Vec::new();
    let result = launch(
        &dir,
        LaunchOptions {
            node_exe: &node,
            signer_exe: signer,
            until_height: None,
            restart: None,
        },
        &mut |line| said.push(line),
    );
    assert!(result.is_err(), "every node failed, so the run fails");
    for number in 1..=4 {
        assert_eq!(runs(&dir, number), 1, "run once and left");
    }
}

#[test]
fn a_node_that_fails_straight_away_every_time_is_given_up_on_and_says_so() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("net");
    devnet(&dir);
    let node = stand_in(parent.path(), 99);
    let signer = Path::new(env!("CARGO_BIN_EXE_chain-signer"));
    let mut said = Vec::new();
    let policy = RestartPolicy {
        initial_wait: Duration::from_millis(100),
        max_wait: Duration::from_millis(300),
        stable_after: Duration::from_secs(30),
        give_up_after: 4,
    };
    let result = launch(
        &dir,
        LaunchOptions {
            node_exe: &node,
            signer_exe: signer,
            until_height: None,
            restart: Some(policy),
        },
        &mut |line| said.push(line),
    );
    assert!(result.is_err());
    for number in 1..=4 {
        assert_eq!(
            runs(&dir, number),
            4,
            "tried four times, then stopped trying"
        );
    }
    let text = said.join("\n");
    assert!(
        text.contains("keeps failing straight after it starts"),
        "{text}"
    );
}

#[test]
fn the_wait_doubles_up_to_a_ceiling() {
    let service = RestartPolicy::service();
    let waits: Vec<u64> = (1..=7).map(|n| service.wait_after(n).as_secs()).collect();
    assert_eq!(waits, vec![5, 10, 20, 40, 60, 60, 60]);
    // A count of zero, or a very large one, cannot overflow or wait less than the first.
    assert_eq!(service.wait_after(0), service.initial_wait);
    assert_eq!(service.wait_after(u32::MAX), service.max_wait);
}

/// A node that stays up until a `stop` file appears beside its config.
fn steady_node(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("steady-node.sh");
    fs::write(
        &path,
        "#!/bin/sh\nd=\"$(dirname \"$2\")\"\nwhile [ ! -e \"$d/stop\" ]; do sleep 0.1; done\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// The signer serving `dir`'s node, found by the full path of its socket so that
/// another test's network, running at the same time, is never mistaken for it.
fn signer_pid(dir: &Path, node: usize) -> Option<u32> {
    let output = Command::new("pgrep")
        .args(["-f", &format!("{}/node{node}/signer.sock", dir.display())])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

#[test]
fn a_signer_that_dies_is_started_again_and_waited_for() {
    let parent = tempfile::tempdir().unwrap();
    let dir = parent.path().join("net");
    devnet(&dir);
    let node = steady_node(parent.path());
    let signer = std::path::PathBuf::from(env!("CARGO_BIN_EXE_chain-signer"));

    let runner = {
        let (dir, node, signer) = (dir.clone(), node.clone(), signer.clone());
        std::thread::spawn(move || {
            let mut said = Vec::new();
            let result = launch(
                &dir,
                LaunchOptions {
                    node_exe: &node,
                    signer_exe: &signer,
                    until_height: None,
                    restart: Some(quick()),
                },
                &mut |line| said.push(line),
            );
            (result.is_ok(), said)
        })
    };

    let socket = dir.join("node1/signer.sock");
    let listening = |socket: &Path| std::os::unix::net::UnixStream::connect(socket).is_ok();
    let started = Instant::now();
    while !listening(&socket) {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the signer never came up"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let before = signer_pid(&dir, 1).expect("a signer for node 1 is running");
    assert!(Command::new("kill")
        .args(["-9", &before.to_string()])
        .status()
        .unwrap()
        .success());

    // A different process is accepting connections on the same socket soon after.
    let killed = Instant::now();
    let after = loop {
        if let Some(pid) = signer_pid(&dir, 1) {
            if pid != before && listening(&socket) {
                break pid;
            }
        }
        assert!(
            killed.elapsed() < Duration::from_secs(20),
            "the signer was not started again"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_ne!(after, before);

    for number in 1..=4 {
        fs::write(dir.join(format!("node{number}/stop")), b"").unwrap();
    }
    let (ok, said) = runner.join().unwrap();
    assert!(ok, "{}", said.join("\n"));
    let text = said.join("\n");
    assert!(text.contains("the signer of node 1 exited with"), "{text}");
    assert!(
        text.contains("the signer of node 1 started again"),
        "{text}"
    );
}
