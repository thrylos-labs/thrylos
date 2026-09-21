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
use std::io::Read;
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
    /// A network with a fast pace, so tests do not wait a second a block.
    fn generate(validators: usize) -> Self {
        Self::generate_paced(validators, 100)
    }

    fn generate_paced(validators: usize, block_interval_ms: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        // Two ports for each node: one for peers and one for its RPC.
        let base = free_base_port(u16::try_from(validators * 2).unwrap());
        let output = run(&[
            "devnet",
            "init",
            dir.to_str().unwrap(),
            "--validators",
            &validators.to_string(),
            "--base-port",
            &base.to_string(),
            "--block-interval-ms",
            &block_interval_ms.to_string(),
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

    /// `devnet start --until-height` on this network. If it has not finished
    /// within two minutes (a network that cannot make progress never will) it
    /// is killed with everything it started, and the test fails with what the
    /// nodes had said.
    fn start_until(&self, height: u64) -> Output {
        let mut child = Command::new(NODE)
            .args(["devnet", "start", self.dir.to_str().unwrap()])
            .args(["--until-height", &height.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let out = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = out.read_to_end(&mut bytes);
            bytes
        });
        let err = thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = err.read_to_end(&mut bytes);
            bytes
        });
        let end = Instant::now() + Duration::from_secs(120);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= end {
                // Its children first, or they outlive it; then it.
                let _ = Command::new("pkill")
                    .args(["-9", "-P", &child.id().to_string()])
                    .status();
                child.kill().unwrap();
                child.wait().unwrap();
                let tails: Vec<String> = self
                    .nodes
                    .iter()
                    .map(|node| format!("node {}:\n{}", node.number, tail(&node.node_log())))
                    .collect();
                panic!(
                    "devnet start had not finished after two minutes:\n{}\n{}",
                    String::from_utf8_lossy(&out.join().unwrap()),
                    tails.join("\n")
                );
            }
            thread::sleep(Duration::from_millis(50));
        };
        Output {
            status,
            stdout: out.join().unwrap(),
            stderr: err.join().unwrap(),
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

    fn kill_node(&mut self, index: usize) {
        Self::kill(&mut self.processes[index], "the node");
    }

    fn kill_signer(&mut self, index: usize) {
        Self::kill(&mut self.signers[index], "the signer");
    }

    fn height(&self, index: usize) -> u64 {
        committed(&self.nodes[index].node_log())
    }

    fn await_height(&mut self, index: usize, target: u64) {
        let end = Instant::now() + Duration::from_secs(90);
        while self.height(index) < target {
            // A node that has stopped will not get there: say why at once.
            if let Some(Some(status)) = self.processes[index]
                .as_mut()
                .map(|p| p.try_wait().unwrap())
            {
                panic!(
                    "node {} stopped ({status}) at {} before reaching {target}:\n{}",
                    self.nodes[index].number,
                    self.height(index),
                    tail(&self.nodes[index].node_log())
                );
            }
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
    let output = network.start_until(HEIGHT);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let said = stdout(&output);
    assert_eq!(
        said.matches(&format!("reached height {HEIGHT}")).count(),
        4,
        "{said}"
    );
    // It said where the RPCs are and what to try, in commands that can be
    // pasted: the real program and the real directory.
    for node in 1..=4 {
        assert!(
            said.contains(&format!("node {node}  http://127.0.0.1:")),
            "{said}"
        );
    }
    let program = env!("CARGO_BIN_EXE_chain-node");
    let dir = network.dir.display();
    assert!(
        said.contains(&format!("{program} devnet bump {dir}")),
        "{said}"
    );
    assert!(
        said.contains(&format!("{program} devnet check {dir}")),
        "{said}"
    );
    assert!(
        said.contains(&format!("until every node has block {HEIGHT}")),
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
    let start = || network.start_until(HEIGHT);
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

// A kill at a random moment, of the node alone and then of the node and its
// signer together, while the other three carry on. (The signer of a node killed
// between recording a signature and the node recording it gives the same
// signature again when asked for the same message, so no moment is unsafe: see
// `every_process_killed_at_a_random_moment...` for the whole network at once.)
#[test]
fn processes_killed_without_warning_and_started_again_rejoin_and_the_chain_stays_one() {
    const HEIGHT: u64 = 30;
    let mut network = Network::generate(4);
    network.start_all(HEIGHT);
    let victim = 3;

    // First a crash of the node alone: its signer, a separate process, lives on.
    network.await_height(victim, 3);
    network.kill_node(victim);
    let first_crash = network.height(victim);
    // Three of four validators are more than two thirds: the rest go on.
    network.await_height(0, first_crash + 2);
    network.start_node(victim, HEIGHT);
    network.await_height(victim, first_crash + 3);

    // Then the whole machine at once: the node and its signer, both without
    // warning. The signer has only its mark file to remember what it signed.
    network.kill_node(victim);
    network.kill_signer(victim);
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

/// Whatever moment every process of a running network is killed at, it starts
/// again. Each cycle kills all four signers and all four nodes with `SIGKILL`,
/// at a point in the block cycle that changes from one cycle to the next, and
/// then requires every node to come back and commit more. (The moment matters:
/// a signer that has recorded a signature its node died before recording used
/// to refuse the position when asked again, and the node halted. Killing right
/// after a commit is logged does not find that; killing at all phases does.)
#[test]
fn every_process_killed_at_a_random_moment_over_and_over_starts_again_and_the_chain_stays_one() {
    const CYCLES: u64 = 8;
    let mut network = Network::generate(4);
    // A different sequence each run, so that over many runs every phase is
    // tried; a failure prints it.
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos()
        | 1;
    let mut next = move || {
        // xorshift: not random enough to matter, varied enough to matter.
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };

    for cycle in 1..=CYCLES {
        network.start_all(u64::MAX);
        // Every node has to resume and get on, or this cycle proved nothing.
        let reached = (0..4).map(|node| network.height(node)).max().unwrap();
        for node in 0..4 {
            network.await_height(node, reached + 2);
        }
        // Let it run a little further, for a time that is not a whole number of
        // blocks, and then kill everything at once.
        thread::sleep(Duration::from_millis(u64::from(next() % 180)));
        for index in 0..4 {
            network.kill_node(index);
        }
        for index in 0..4 {
            network.kill_signer(index);
        }
        eprintln!(
            "cycle {cycle}: killed at heights {:?}",
            (0..4).map(|n| network.height(n)).collect::<Vec<_>>()
        );
    }

    // After the last kill: one launch that has to bring all four to a height
    // past anything before it.
    let target = (0..4).map(|node| network.height(node)).max().unwrap() + 3;
    let output = network.start_until(target);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    for node in &network.nodes {
        let heights = committed_heights(&node.node_log());
        assert!(
            heights.windows(2).all(|pair| pair[0] < pair[1]),
            "node {} repeated a height across {CYCLES} crashes: {heights:?}",
            node.number
        );
    }
    assert_one_chain(&network.nodes, target);
}

/// The block time the spec names, with nothing to wait for: one validator, and
/// the default pace. Before the pace existed a node in this position committed
/// blocks in a loop that never gave control back, reported nothing and could
/// not be stopped at a height.
#[test]
fn a_network_of_one_validator_makes_a_block_a_second_and_stops_at_a_height() {
    const HEIGHT: u64 = 4;
    let network = Network::generate_paced(1, 1_000);
    let started = Instant::now();
    let output = network.start_until(HEIGHT);
    let took = started.elapsed();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("reached height 4"),
        "{}",
        stdout(&output)
    );

    // The first block is at once and each after it a second on: three seconds
    // to height four, not the fraction of one a chain with no pace would take.
    assert!(
        took >= Duration::from_millis(2_900),
        "height {HEIGHT} in {took:?}: no pace"
    );
    // And the chain was stopped near the height, not left far ahead of it.
    let tip = chain_on_disk(&network.nodes[0], HEIGHT).len();
    assert_eq!(tip, usize::try_from(HEIGHT).unwrap());
    let genesis = chain_genesis::load(&network.nodes[0].dir.join(GENESIS)).unwrap();
    let engine = DurableEngine::open(&network.nodes[0].dir.join("data"), &genesis).unwrap();
    let reached = engine.database().tip_height().unwrap().unwrap().0;
    assert!(
        reached <= HEIGHT + 2,
        "it stopped at height {reached}, having been asked for {HEIGHT}"
    );
}

/// The setting reaches the host: with a pace that is not the default, the blocks
/// on the chain are that far apart, by their own timestamps.
#[test]
fn the_configured_block_interval_is_the_gap_between_the_blocks_on_the_chain() {
    const HEIGHT: u64 = 9;
    let network = Network::generate_paced(1, 300);
    let output = network.start_until(HEIGHT);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let blocks = chain_on_disk(&network.nodes[0], HEIGHT);
    let mut gaps: Vec<u64> = blocks
        .windows(2)
        .map(|pair| pair[1].0.timestamp_millis - pair[0].0.timestamp_millis)
        .collect();
    gaps.sort_unstable();
    // Never closer than the pace; and the usual gap is the pace plus the time a
    // height takes to decide, not the default second (and not nothing). The
    // first height is slower than the rest, which is why this is the median.
    assert!(gaps[0] >= 300, "a gap of {} ms: {gaps:?}", gaps[0]);
    let median = gaps[gaps.len() >> 1];
    assert!(
        (300..800).contains(&median),
        "the median gap is {median} ms: {gaps:?}"
    );
}

/// A transaction, signed and sent by the real `chain-node devnet bump` command
/// over the real RPC of a running network, seen included, and seen from another node.
#[test]
fn a_transaction_sent_with_devnet_bump_is_included_and_seen_from_another_node() {
    let mut network = Network::generate(4);
    network.start_all(u64::MAX);
    network.await_height(0, 2);
    let dir = network.dir.to_str().unwrap().to_owned();

    // Account 2 sends through node 2, twice: the second finds the sequence
    // number the first left, which is what a client is for.
    let first = run(&[
        "devnet",
        "bump",
        &dir,
        "--node",
        "2",
        "--account",
        "2",
        "--amount",
        "5",
    ]);
    assert_eq!(
        first.status.code(),
        Some(0),
        "{}{}",
        stdout(&first),
        stderr(&first)
    );
    let said = stdout(&first);
    assert!(said.contains("is at sequence 0"), "{said}");
    // The balance is in tokens, not the base units the RPC counts in.
    assert!(said.contains("holds 1,000 THRY"), "{said}");
    assert!(!said.contains("1000000000000"), "{said}");
    assert!(said.contains("included in block"), "{said}");
    assert!(said.contains("is now at sequence 1"), "{said}");

    let second = run(&[
        "devnet",
        "bump",
        &dir,
        "--node",
        "2",
        "--account",
        "2",
        "--amount",
        "3",
    ]);
    assert_eq!(
        second.status.code(),
        Some(0),
        "{}{}",
        stdout(&second),
        stderr(&second)
    );
    assert!(
        stdout(&second).contains("is at sequence 1"),
        "{}",
        stdout(&second)
    );
    assert!(
        stdout(&second).contains("is now at sequence 2"),
        "{}",
        stdout(&second)
    );

    // A third adds the most a counter can hold, which overflows it: it is
    // included and charged, and the command says that it aborted and exits 1.
    let third = run(&[
        "devnet",
        "bump",
        &dir,
        "--node",
        "2",
        "--account",
        "2",
        "--amount",
        "18446744073709551615",
    ]);
    assert_eq!(
        third.status.code(),
        Some(1),
        "{}{}",
        stdout(&third),
        stderr(&third)
    );
    assert!(
        stdout(&third).contains("included in block"),
        "{}",
        stdout(&third)
    );
    assert!(
        stdout(&third).contains("is now at sequence 3"),
        "{}",
        stdout(&third)
    );
    let complaint = stderr(&third);
    assert!(
        complaint.contains("aborted") && complaint.contains("ExecutionFailed"),
        "{complaint}"
    );
    assert!(complaint.contains("still charged"), "{complaint}");
    assert!(
        !stdout(&third).contains("it succeeded"),
        "{}",
        stdout(&third)
    );
    assert!(
        stdout(&first).contains("it succeeded"),
        "{}",
        stdout(&first)
    );

    // And node 4, which was not the one it was sent to, agrees over its own RPC.
    let sender =
        chain_types::Address::from_public_key(&chain_genesis::devnet::ed25519(102).unwrap());
    let rpc = NodeConfig::load(&network.nodes[3].config())
        .unwrap()
        .rpc_listen
        .unwrap();
    let client = chain_node::client::RpcClient { address: rpc };
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        let account = client
            .call(
                "account",
                &serde_json::json!({ "address": chain_text::format_address(&sender) }),
            )
            .unwrap();
        if account["nextSequenceNumber"] == 3 {
            break;
        }
        assert!(
            Instant::now() < end,
            "node 4 never saw all three: {account}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// The spec's halt runbook, run: a network loses too many validators to commit,
/// `devnet check` notices, the validators come back, and `devnet check` says the
/// network is well again. (The runbook's later steps, patching and a signed
/// release, are not something a test can do.)
#[test]
fn a_halted_network_is_detected_and_a_recovered_one_is_healthy() {
    const RESTART: u64 = 100_000;
    let mut network = Network::generate(4);
    network.start_all(RESTART);
    network.await_height(0, 3);
    let dir = network.dir.to_str().unwrap().to_owned();

    // Committing, and every node agrees where.
    let well = run(&["devnet", "check", &dir]);
    assert_eq!(
        well.status.code(),
        Some(0),
        "{}{}",
        stdout(&well),
        stderr(&well)
    );
    assert_eq!(
        stdout(&well).lines().last(),
        Some("healthy"),
        "{}",
        stdout(&well)
    );
    assert!(
        stdout(&well).contains("agreed by 4 of 4 nodes"),
        "{}",
        stdout(&well)
    );
    for node in &network.nodes {
        let rpc = NodeConfig::load(&node.config())
            .unwrap()
            .rpc_listen
            .unwrap();
        assert!(
            stdout(&well).contains(&format!("node {} (RPC {rpc})", node.number)),
            "{}",
            stdout(&well)
        );
    }

    // Two of four validators are under the two thirds it takes to commit. The
    // other two go on running, and cannot commit anything more.
    network.kill_node(2);
    network.kill_node(3);
    let stopped_at = network.height(0);
    thread::sleep(chain_node::health::HALT_AFTER + Duration::from_secs(3));
    let halted = run(&["devnet", "check", &dir]);
    assert_eq!(
        halted.status.code(),
        Some(1),
        "{}{}",
        stdout(&halted),
        stderr(&halted)
    );
    let complaint = stderr(&halted);
    assert!(
        complaint.contains("node 1 has committed nothing for"),
        "{complaint}"
    );
    assert!(
        complaint.contains("node 2 has committed nothing for"),
        "{complaint}"
    );
    assert!(complaint.contains("node 3 is unreachable"), "{complaint}");
    assert!(complaint.contains("node 4 is unreachable"), "{complaint}");
    assert!(!stdout(&halted).contains("healthy"), "{}", stdout(&halted));
    // Two nodes are still answering, so the network is up and it does not tell
    // anyone to start it; the last line is the whole finding.
    assert!(!complaint.contains("Start it with"), "{complaint}");
    assert_eq!(
        complaint.lines().last(),
        Some("unhealthy: 4 problems"),
        "{complaint}"
    );
    // The two that ran on still agree with each other where the chain stopped.
    assert!(
        stdout(&halted).contains("agreed by 2 of 4 nodes"),
        "{}",
        stdout(&halted)
    );
    assert!(
        network.height(0) <= stopped_at + 1,
        "it committed while halted"
    );

    // The validators come back, and the chain goes on, and the check agrees.
    network.start_node(2, RESTART);
    network.start_node(3, RESTART);
    network.await_height(0, stopped_at + 3);
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        let now = run(&["devnet", "check", &dir]);
        if now.status.code() == Some(0) {
            assert!(
                stdout(&now).contains("agreed by 4 of 4 nodes"),
                "{}",
                stdout(&now)
            );
            break;
        }
        assert!(
            Instant::now() < end,
            "still not healthy: {}{}",
            stdout(&now),
            stderr(&now)
        );
        thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn devnet_check_says_what_is_wrong_and_exits_accordingly() {
    // A network nobody has started: every node is unreachable, and it says so.
    let network = Network::generate(2);
    let dir = network.dir.to_str().unwrap().to_owned();
    let output = run(&["devnet", "check", &dir]);
    assert_eq!(output.status.code(), Some(1));
    let complaint = stderr(&output);
    assert!(complaint.contains("node 1 is unreachable"), "{complaint}");
    assert!(complaint.contains("node 2 is unreachable"), "{complaint}");
    for node in &network.nodes {
        let rpc = NodeConfig::load(&node.config())
            .unwrap()
            .rpc_listen
            .unwrap();
        assert!(
            complaint.contains(&format!("node {} is unreachable (RPC {rpc})", node.number)),
            "{complaint}"
        );
    }
    // Nothing answered at all, so it says how to start the network...
    let program = env!("CARGO_BIN_EXE_chain-node");
    assert!(
        complaint.contains(&format!("Start it with: {program} devnet start {dir}")),
        "{complaint}"
    );
    // ...and the last thing it says is the whole finding.
    assert_eq!(
        complaint.lines().last(),
        Some("unhealthy: 2 problems"),
        "{complaint}"
    );

    let empty = tempfile::tempdir().unwrap();
    let output = run(&["devnet", "check", empty.path().to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no generated network"),
        "{}",
        stderr(&output)
    );

    for args in [
        vec!["devnet", "check"],
        vec!["devnet", "check", &dir, "--fast"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }
}

#[test]
fn devnet_bump_says_what_is_wrong_and_exits_accordingly() {
    let network = Network::generate(2);
    let dir = network.dir.to_str().unwrap().to_owned();

    // Nothing is running: it says so, and where it looked.
    let output = run(&["devnet", "bump", &dir]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("cannot reach the RPC"),
        "{}",
        stderr(&output)
    );
    // And how to put it right, in a command that can be pasted as it is.
    let program = env!("CARGO_BIN_EXE_chain-node");
    let hint = format!("is the network running? Start it with: {program} devnet start {dir}");
    assert!(stderr(&output).contains(&hint), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("a few seconds"),
        "{}",
        stderr(&output)
    );

    for (args, expected) in [
        (vec!["--account", "5"], "accounts 1 to 4"),
        (vec!["--account", "0"], "accounts 1 to 4"),
        (vec!["--node", "9"], "no node 9"),
        (vec!["--amount", "lots"], "wants a number"),
    ] {
        let mut full = vec!["devnet", "bump", dir.as_str()];
        full.extend(args.iter().copied());
        let output = run(&full);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&output).contains(expected),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    for args in [
        vec!["devnet", "bump"],
        vec!["devnet", "bump", &dir, "--nodes", "2"],
        vec!["devnet", "bump", &dir, "--node"],
        vec!["devnet", "bump", &dir, "--node", "1", "--node", "2"],
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(stderr(&output).contains("usage:"), "{args:?}");
    }
    // A directory that is not a network.
    let empty = tempfile::tempdir().unwrap();
    let output = run(&["devnet", "bump", empty.path().to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("no generated network"),
        "{}",
        stderr(&output)
    );
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

    let output = network.start_until(3);
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

    let output = network.start_until(3);
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
            vec!["devnet", "init", dir, "--block-interval-ms", "0"],
            "must not be zero",
        ),
        (
            vec!["devnet", "init", dir, "--block-interval-ms", "soon"],
            "wants a number",
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
