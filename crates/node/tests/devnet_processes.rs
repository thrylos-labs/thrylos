//! A generated local network, run as real processes: `chain-node devnet init`
//! writes it, and `chain-signer` and `chain-node` binaries run it, one process
//! each per validator, over real sockets and real databases. Nothing here runs
//! in the test's own process except the checking, so a process can be killed
//! with `SIGKILL`, which gives it no chance to clean up, and started again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::fs::{File, OpenOptions};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use chain_engine_api::Block;
use chain_node::devnet::{nodes_in, NodeDir, GENESIS};
use chain_node::event_loop::committed_height;
use chain_node::{DurableEngine, NodeConfig};
use chain_types::{BlockHeight, Hash};

const NODE: &str = env!("CARGO_BIN_EXE_chain-node");
const SIGNER: &str = env!("CARGO_BIN_EXE_chain-signer");

/// `count` consecutive free ports, and the first of them. Ports are handed out
/// from a range that depends on the process, one block after another, so two
/// networks running at once are never given the same ones.
fn free_base_port(count: u16) -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 20_000 + u16::try_from(std::process::id() % 20_000).unwrap();
    loop {
        let start = base + NEXT.fetch_add(count, Ordering::Relaxed);
        if (start..start + count).all(|port| TcpListener::bind(("127.0.0.1", port)).is_ok()) {
            return start;
        }
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(NODE).args(args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn tail(path: &Path) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(12)..].join("\n")
}

/// The heights a node's log says it committed, in the order it said so.
fn committed_heights(log: &Path) -> Vec<u64> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .filter_map(committed_height)
        .collect()
}

/// The highest block a node's log says it committed.
fn committed(log: &Path) -> u64 {
    committed_heights(log).into_iter().max().unwrap_or(0)
}

fn signal(pid: u32, name: &str) {
    let status = Command::new("kill")
        .args([format!("-{name}"), pid.to_string()])
        .status()
        .unwrap();
    assert!(status.success(), "kill -{name} {pid}");
}

fn append(path: &Path) -> File {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap()
}

/// A generated network and the processes running it, all killed when it goes
/// out of scope, so a failed test leaves nothing running.
struct Network {
    _root: tempfile::TempDir,
    dir: PathBuf,
    nodes: Vec<NodeDir>,
    signers: Vec<Option<Child>>,
    processes: Vec<Option<Child>>,
}

impl Network {
    /// Generates a network with the `devnet init` command, as a person would.
    fn generate(validators: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        let base = free_base_port(u16::try_from(validators).unwrap());
        let output = run(&[
            "devnet",
            "init",
            dir.to_str().unwrap(),
            "--validators",
            &validators.to_string(),
            "--base-port",
            &base.to_string(),
        ]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let nodes = nodes_in(&dir).unwrap();
        assert_eq!(nodes.len(), validators);
        Self {
            _root: root,
            dir,
            signers: nodes.iter().map(|_| None).collect(),
            processes: nodes.iter().map(|_| None).collect(),
            nodes,
        }
    }

    fn start_signer(&mut self, index: usize) {
        let node = &self.nodes[index];
        let config = NodeConfig::load(&node.config()).unwrap();
        let log = append(&node.signer_log());
        let child = Command::new(SIGNER)
            .arg(&config.signer_socket)
            .arg(node.signer_key())
            .arg(&config.signer_credential)
            .arg(node.signer_mark())
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.signers[index] = Some(child);
        let end = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&config.signer_socket).is_err() {
            assert!(
                Instant::now() < end,
                "signer {} never came up:\n{}",
                node.number,
                tail(&node.signer_log())
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    fn start_node(&mut self, index: usize, until: u64) {
        let node = &self.nodes[index];
        let log = append(&node.node_log());
        let child = Command::new(NODE)
            .arg("run")
            .arg(node.config())
            .args(["--until-height", &until.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        self.processes[index] = Some(child);
    }

    fn start_all(&mut self, until: u64) {
        for index in 0..self.nodes.len() {
            self.start_signer(index);
        }
        for index in 0..self.nodes.len() {
            self.start_node(index, until);
        }
    }

    /// Kills a process with `SIGKILL` and checks that is what ended it: it was
    /// still running, and had no chance to say goodbye.
    fn kill(child: &mut Option<Child>, what: &str) {
        let mut child = child
            .take()
            .unwrap_or_else(|| panic!("{what} is not running"));
        child.kill().unwrap();
        let status = child.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(9),
            "{what} had already stopped: {status}"
        );
    }

    /// Runs `action` while every other node is frozen with `SIGSTOP`, after
    /// giving the node at `index` time to finish what it was doing. It is then
    /// idle: waiting on peers that are not answering, with no timer due for
    /// longer than the pause. A node killed at a moment like that has nothing
    /// half done.
    fn while_others_are_frozen(&mut self, index: usize, action: impl FnOnce(&mut Self)) {
        let frozen: Vec<u32> = self
            .processes
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .filter_map(|(_, process)| process.as_ref().map(Child::id))
            .collect();
        for pid in &frozen {
            signal(*pid, "STOP");
        }
        thread::sleep(Duration::from_millis(300));
        action(self);
        for pid in &frozen {
            signal(*pid, "CONT");
        }
    }

    fn kill_node(&mut self, index: usize) {
        Self::kill(&mut self.processes[index], "the node");
    }

    fn kill_signer(&mut self, index: usize) {
        Self::kill(&mut self.signers[index], "the signer");
    }

    fn height(&self, index: usize) -> u64 {
        committed(&self.nodes[index].node_log())
    }

    fn await_height(&self, index: usize, target: u64) {
        let end = Instant::now() + Duration::from_secs(90);
        while self.height(index) < target {
            assert!(
                Instant::now() < end,
                "node {} was still at {} waiting for {target}:\n{}",
                self.nodes[index].number,
                self.height(index),
                tail(&self.nodes[index].node_log())
            );
            thread::sleep(Duration::from_millis(25));
        }
    }

    /// Waits for a node to exit by itself and says it did so successfully.
    fn finish(&mut self, index: usize) {
        let end = Instant::now() + Duration::from_secs(90);
        loop {
            let child = self.processes[index].as_mut().expect("node is running");
            if let Some(status) = child.try_wait().unwrap() {
                let node = &self.nodes[index];
                assert!(
                    status.success(),
                    "node {} exited with {status}:\n{}",
                    node.number,
                    tail(&node.node_log())
                );
                return;
            }
            assert!(
                Instant::now() < end,
                "node {} never finished, at {}:\n{}",
                self.nodes[index].number,
                self.height(index),
                tail(&self.nodes[index].node_log())
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for child in self.processes.iter_mut().chain(&mut self.signers).flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The chain a node left in its data directory: its blocks up to `height`, and
/// the state root after each. The node must have exited.
fn chain_on_disk(node: &NodeDir, height: u64) -> Vec<(Block, Hash)> {
    let genesis = chain_genesis::load(&node.dir.join(GENESIS)).unwrap();
    let engine = DurableEngine::open(&node.dir.join("data"), &genesis).unwrap();
    engine.executor().audit().unwrap();
    assert!(
        engine.database().tip_height().unwrap().unwrap().0 >= height,
        "node {} holds too little",
        node.number
    );
    (1..=height)
        .map(|h| {
            let db = engine.database();
            (
                db.get_block(BlockHeight(h)).unwrap().expect("a block"),
                db.get_root(BlockHeight(h)).unwrap().expect("a root"),
            )
        })
        .collect()
}

fn assert_one_chain(nodes: &[NodeDir], height: u64) {
    let chains: Vec<_> = nodes.iter().map(|n| chain_on_disk(n, height)).collect();
    for (index, chain) in chains.iter().enumerate().skip(1) {
        for (h, (a, b)) in chains[0].iter().zip(chain).enumerate() {
            assert_eq!(
                a.0,
                b.0,
                "node {} differs at block {}",
                nodes[index].number,
                h + 1
            );
            assert_eq!(
                a.1,
                b.1,
                "node {} state root differs at block {}",
                nodes[index].number,
                h + 1
            );
        }
    }
}

// ---- the tests ----------------------------------------------------------------------

#[test]
fn devnet_start_runs_a_generated_network_to_a_height_and_leaves_no_process_behind() {
    const HEIGHT: u64 = 6;
    let network = Network::generate(4);
    let output = run(&[
        "devnet",
        "start",
        network.dir.to_str().unwrap(),
        "--until-height",
        &HEIGHT.to_string(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let said = stdout(&output);
    assert_eq!(
        said.matches(&format!("reached height {HEIGHT}")).count(),
        4,
        "{said}"
    );
    // Each node was stopped by having its input closed, not killed: it left
    // through its own exit, with success.
    assert_eq!(
        said.matches(" stopped: exit status: 0").count(),
        4,
        "{said}"
    );

    assert_one_chain(&network.nodes, HEIGHT);
    for node in &network.nodes {
        assert!(
            committed(&node.node_log()) >= HEIGHT,
            "node {}",
            node.number
        );
    }

    // The signers it started were killed when it finished.
    let pids: Vec<&str> = said
        .lines()
        .filter_map(|line| line.split("(signer pid ").nth(1)?.split(')').next())
        .collect();
    assert_eq!(pids.len(), 4, "{said}");
    for pid in pids {
        let alive = Command::new("kill").args(["-0", pid]).output().unwrap();
        assert!(!alive.status.success(), "signer {pid} is still running");
    }
}

#[test]
fn a_network_started_again_from_its_disks_waits_for_fresh_blocks_not_the_old_log() {
    const HEIGHT: u64 = 4;
    let network = Network::generate(4);
    let start = || {
        run(&[
            "devnet",
            "start",
            network.dir.to_str().unwrap(),
            "--until-height",
            &HEIGHT.to_string(),
        ])
    };
    let first = start();
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    let before: Vec<usize> = network
        .nodes
        .iter()
        .map(|node| committed_heights(&node.node_log()).len())
        .collect();
    assert!(before.iter().all(|&count| count >= 4), "{before:?}");

    // Every node's log already says it committed the height asked for. The
    // launcher must not take that for this run: it stops the network only once
    // the nodes have committed something new, after resuming from their disks.
    let second = start();
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    for (node, before) in network.nodes.iter().zip(before) {
        let heights = committed_heights(&node.node_log());
        assert!(
            heights.len() > before,
            "node {} committed nothing new",
            node.number
        );
        assert!(
            heights.windows(2).all(|pair| pair[0] < pair[1]),
            "node {} went back: {heights:?}",
            node.number
        );
    }
    assert_one_chain(&network.nodes, HEIGHT);
}

// What this does not cover, and is known not to work: a kill that lands after a
// signer has recorded a signature and before its node has recorded the same
// signature. The signer's rule, in the spec, is to refuse anything at or below
// its mark unconditionally, so the restarted node is refused the position it
// needs to sign again and halts. A kill at a random moment finds that window
// often enough to make a test of it unreliable, so this one kills while the
// victim is idle (see `while_others_are_frozen`).
#[test]
fn processes_killed_without_warning_while_idle_and_started_again_rejoin_and_the_chain_stays_one() {
    const HEIGHT: u64 = 30;
    let mut network = Network::generate(4);
    network.start_all(HEIGHT);
    let victim = 3;

    // First a crash of the node alone: its signer, a separate process, lives on.
    network.await_height(victim, 3);
    network.while_others_are_frozen(victim, |network| network.kill_node(victim));
    let first_crash = network.height(victim);
    // Three of four validators are more than two thirds: the rest go on.
    network.await_height(0, first_crash + 2);
    network.start_node(victim, HEIGHT);
    network.await_height(victim, first_crash + 3);

    // Then the whole machine at once: the node and its signer, both without
    // warning. The signer has only its mark file to remember what it signed.
    network.while_others_are_frozen(victim, |network| {
        network.kill_node(victim);
        network.kill_signer(victim);
    });
    assert!(
        network.nodes[victim].signer_mark().is_file(),
        "the signer had recorded what it signed"
    );
    let second_crash = network.height(victim);
    network.await_height(0, second_crash + 2);
    network.start_signer(victim);
    network.start_node(victim, HEIGHT);

    for index in 0..4 {
        network.finish(index);
    }
    assert!(
        network.height(victim) >= HEIGHT,
        "it rejoined and reached the end"
    );
    // Across two crashes it never went back: each restart took up from what
    // its disk held, not from the beginning and not from where it had been.
    let heights = committed_heights(&network.nodes[victim].node_log());
    assert!(
        heights.windows(2).all(|pair| pair[0] < pair[1]),
        "a height was repeated: {heights:?}"
    );
    assert_one_chain(&network.nodes, HEIGHT);
}

#[test]
fn a_node_told_to_stop_by_closing_its_input_stops_cleanly_and_not_before() {
    let mut network = Network::generate(4);
    network.start_signer(0);
    let node = &network.nodes[0];
    let log = append(&node.node_log());
    let child = Command::new(NODE)
        .arg("run")
        .arg(node.config())
        .arg("--stop-when-stdin-closes")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .unwrap();
    network.processes[0] = Some(child);
    let node = &network.nodes[0];

    // It starts, and goes on running while its input stays open.
    let end = Instant::now() + Duration::from_secs(30);
    while !std::fs::read_to_string(node.node_log())
        .unwrap_or_default()
        .contains("starting validator")
    {
        assert!(Instant::now() < end, "it never started");
        thread::sleep(Duration::from_millis(25));
    }
    thread::sleep(Duration::from_millis(300));
    let process = network.processes[0].as_mut().unwrap();
    assert!(
        process.try_wait().unwrap().is_none(),
        "it stopped by itself"
    );

    // Closing the input is the request, and it is answered with a clean exit.
    drop(process.stdin.take());
    let end = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = process.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < end,
            "it did not stop when its input closed"
        );
        thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(status.code(), Some(0), "{status}");
}

#[test]
fn a_signer_that_cannot_start_stops_the_launch_before_any_node_runs() {
    let network = Network::generate(2);
    // A key file others can read: the signer refuses it, and says how to fix it.
    let key = network.nodes[0].signer_key();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = run(&[
        "devnet",
        "start",
        network.dir.to_str().unwrap(),
        "--until-height",
        "3",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("the signer of node 1"),
        "{}",
        stderr(&output)
    );
    assert!(
        tail(&network.nodes[0].signer_log()).contains("chmod 600"),
        "the reason is in its log:\n{}",
        tail(&network.nodes[0].signer_log())
    );
    for node in &network.nodes {
        assert!(!node.dir.join("data").exists(), "node {} ran", node.number);
    }
    // Node 2's signer had started fine; it was stopped with the rest.
    let socket = network.nodes[1].dir.join("signer.sock");
    assert!(
        UnixStream::connect(&socket).is_err(),
        "a signer was left running"
    );
}

#[test]
fn a_node_that_cannot_start_is_reported_while_the_others_finish() {
    let network = Network::generate(4);
    // Node 2's transport key is readable by others: that node refuses to start.
    let key = network.nodes[1].dir.join("network.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = run(&[
        "devnet",
        "start",
        network.dir.to_str().unwrap(),
        "--until-height",
        "3",
    ]);
    // Three of four validators are more than two thirds, so the rest finish;
    // the command still says it did not all go well, and which node.
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(
        stderr(&output).contains("node 2 exited with"),
        "{}",
        stderr(&output)
    );
    assert!(
        tail(&network.nodes[1].node_log()).contains("chmod 600"),
        "{}",
        tail(&network.nodes[1].node_log())
    );
    let said = stdout(&output);
    assert_eq!(said.matches("reached height 3").count(), 3, "{said}");
    for index in [0, 2, 3] {
        assert!(network.height(index) >= 3, "node {}", index + 1);
    }
}

#[test]
fn the_devnet_commands_say_what_is_wrong_and_exit_accordingly() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("net");
    let dir = dir.to_str().unwrap();

    // Not the arguments the command takes: usage, exit 2. (The directory is in
    // the temporary one, so a mistake here could not write into the source tree.)
    for args in [
        vec!["devnet"],
        vec!["devnet", "init"],
        vec!["devnet", "start"],
        vec!["devnet", "bogus", dir],
        vec!["devnet", "init", dir, "--validators"],
        vec!["devnet", "init", dir, "--nodes", "4"],
        vec![
            "devnet",
            "init",
            dir,
            "--validators",
            "4",
            "--validators",
            "5",
        ],
        vec!["devnet", "init", dir, "--until-height", "4"],
        vec!["devnet", "start", dir, "--validators", "4"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }

    // The right arguments with values that will not do: an error, exit 1.
    for (args, expected) in [
        (
            vec!["devnet", "init", dir, "--validators", "many"],
            "wants a number",
        ),
        (
            vec!["devnet", "init", dir, "--validators", "0"],
            "not supported",
        ),
        (
            vec!["devnet", "init", dir, "--validators", "1"],
            "one validator",
        ),
        (
            vec!["devnet", "init", dir, "--validators", "500"],
            "not supported",
        ),
        (
            vec!["devnet", "init", dir, "--base-port", "0"],
            "do not fit",
        ),
        (
            vec!["devnet", "init", dir, "--base-port", "99999"],
            "wants a number",
        ),
        (
            vec!["devnet", "start", dir, "--until-height", "soon"],
            "wants a number",
        ),
        (vec!["devnet", "start", dir], "no generated network"),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&output).contains(expected),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    assert!(!Path::new(dir).exists(), "none of that wrote anything");

    // A network is never written over existing files, however it is asked for.
    std::fs::create_dir(dir).unwrap();
    std::fs::write(Path::new(dir).join("keep"), b"me").unwrap();
    let output = run(&["devnet", "init", dir]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not empty"), "{}", stderr(&output));
    assert_eq!(std::fs::read(Path::new(dir).join("keep")).unwrap(), b"me");
}
