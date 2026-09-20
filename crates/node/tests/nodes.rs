//! Four validators, started through the production path: a configuration file,
//! a signer endpoint holding each consensus key, a database, real sockets and
//! the event loop. They must agree on one chain, and one of them must survive
//! being stopped and started again from its disk while the others carry on.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use blst::min_pk::SecretKey;
use chain_engine_api::Block;
use chain_node::{
    run_node, DurableEngine, FileMarkStore, NodeConfig, NodeEvent, SignerCredential, SignerServer,
};
use chain_p2p::NetworkIdentity;
use chain_signer::{HighWaterMark, HighWaterMarkStore, Signer, Step};
use chain_text::format_address;
use chain_types::{Address, BlockHeight, Hash, Round};

const VALIDATORS: [u8; 4] = [1, 2, 3, 4];

fn free_address() -> SocketAddr {
    // Ports are handed out one after another from a range that depends on the
    // process, so two tests running at once are never given the same one (a
    // bind to port 0, read and released, can hand it to both).
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let base = 20_000 + u16::try_from(std::process::id() % 20_000).unwrap();
    loop {
        let port = base + NEXT.fetch_add(1, Ordering::Relaxed);
        let address: SocketAddr = ([127, 0, 0, 1], port).into();
        if TcpListener::bind(address).is_ok() {
            return address;
        }
    }
}

fn private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A node's identity and address, before its files exist.
struct Plan {
    seed: u8,
    listen: SocketAddr,
    network_secret: [u8; 32],
}

impl Plan {
    fn operator(&self) -> Address {
        Address::from_public_key(&chain_genesis::devnet::ed25519(self.seed).unwrap())
    }

    fn network_public_key(&self) -> String {
        chain_genesis::hex::encode(
            &NetworkIdentity::from_secret_bytes(self.network_secret).public_key(),
        )
    }
}

/// Everything a node needs on disk, and the running signer that holds its key.
struct Provisioned {
    seed: u8,
    config: NodeConfig,
}

/// Writes every node's files under `root` and starts its signer endpoint.
fn provision(root: &Path) -> Vec<Provisioned> {
    provision_with(root, &[])
}

/// Like [`provision`], with the signers of `advanced` already past every
/// position the chain will ask them to sign at.
fn provision_with(root: &Path, advanced: &[u8]) -> Vec<Provisioned> {
    let plans: Vec<Plan> = VALIDATORS
        .iter()
        .map(|seed| Plan {
            seed: *seed,
            listen: free_address(),
            network_secret: [*seed + 100; 32],
        })
        .collect();

    let genesis = chain_genesis::to_json(&chain_genesis::devnet::config().unwrap()).unwrap();
    plans
        .iter()
        .map(|plan| {
            let dir = root.join(format!("node{}", plan.seed));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("genesis.json"), &genesis).unwrap();
            private(
                &dir.join("network.key"),
                {
                    let mut text = chain_genesis::hex::encode(&plan.network_secret);
                    text.push('\n');
                    text
                }
                .as_bytes(),
            );

            // The signer endpoint: it alone holds this validator's BLS key.
            let key = SecretKey::key_gen(&[plan.seed; 32], &[]).unwrap();
            let credential = [plan.seed + 50; 32];
            private(&dir.join("signer.credential"), &credential);
            let mut marks = FileMarkStore::open(&dir.join("signer.mark"));
            if advanced.contains(&plan.seed) {
                marks
                    .persist(HighWaterMark::new(
                        BlockHeight(1_000),
                        Round(0),
                        Step::Precommit,
                    ))
                    .unwrap();
            }
            let signer = Signer::load(key, marks).unwrap();
            let mut server = SignerServer::bind(
                &dir.join("signer.sock"),
                SignerCredential::from_bytes(credential),
                signer,
                Duration::from_secs(5),
            )
            .unwrap();
            thread::spawn(move || {
                let _ = server.serve();
            });

            let peers: Vec<String> = plans
                .iter()
                .filter(|other| other.seed != plan.seed)
                .map(|other| {
                    format!(
                        r#"{{ "address": "{}", "public_key": "{}", "validator": "{}" }}"#,
                        other.listen,
                        other.network_public_key(),
                        format_address(&other.operator())
                    )
                })
                .collect();
            let text = format!(
                r#"{{
                  "data_dir": "data", "genesis": "genesis.json", "listen": "{}",
                  "network_key": "network.key", "validator": "{}",
                  "signer": {{ "socket": "signer.sock", "credential": "signer.credential" }},
                  "peers": [{}],
                  "tuning": {{ "io_timeout_ms": 500, "reconnect_initial_ms": 20,
                               "reconnect_max_ms": 250, "block_interval_ms": 50 }}
                }}"#,
                plan.listen,
                format_address(&plan.operator()),
                peers.join(", ")
            );
            std::fs::write(dir.join("node.json"), &text).unwrap();
            Provisioned {
                seed: plan.seed,
                config: NodeConfig::load(&dir.join("node.json")).unwrap(),
            }
        })
        .collect()
}

/// A node running on its own thread.
struct Running {
    seed: u8,
    stop: Arc<AtomicBool>,
    heights: Arc<Mutex<Vec<u64>>>,
    thread: JoinHandle<Result<(), String>>,
}

fn start(node: &Provisioned, stop_at: u64) -> Running {
    let stop = Arc::new(AtomicBool::new(false));
    let heights = Arc::new(Mutex::new(Vec::new()));
    let (config, flag, seen) = (node.config.clone(), Arc::clone(&stop), Arc::clone(&heights));
    let thread = thread::Builder::new()
        .name(format!("node{}", node.seed))
        .spawn(move || {
            run_node(&config, Some(BlockHeight(stop_at)), &flag, &mut |event| {
                if let NodeEvent::Committed { height, .. } = event {
                    seen.lock().unwrap().push(height.0);
                }
            })
            .map_err(|error| error.to_string())
        })
        .unwrap();
    Running {
        seed: node.seed,
        stop,
        heights,
        thread,
    }
}

impl Running {
    fn height(&self) -> u64 {
        self.heights.lock().unwrap().last().copied().unwrap_or(0)
    }

    /// Waits for the node to finish on its own, up to `patience`; past that it
    /// is told to stop and the test fails, saying where it had got to.
    fn finish(self, patience: Duration) -> Result<(), String> {
        let end = Instant::now() + patience;
        while !self.thread.is_finished() {
            if Instant::now() >= end {
                self.stop.store(true, Ordering::Release);
                let height = self.height();
                let _ = self.thread.join();
                panic!("node {} had only reached height {height}", self.seed);
            }
            thread::sleep(Duration::from_millis(50));
        }
        self.thread.join().unwrap()
    }
}

/// The chain a node left in its data directory: its blocks up to `height`, and
/// the state root after each.
fn chain_on_disk(node: &Provisioned, height: u64) -> Vec<(Block, Hash)> {
    let genesis = chain_genesis::load(&node.config.genesis).unwrap();
    let engine = DurableEngine::open(&node.config.data_dir, &genesis).unwrap();
    engine.executor().audit().unwrap();
    assert!(
        engine.database().tip_height().unwrap().unwrap().0 >= height,
        "node {} holds too little",
        node.seed
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

fn assert_one_chain(nodes: &[Provisioned], height: u64) {
    let chains: Vec<Vec<(Block, Hash)>> = nodes.iter().map(|n| chain_on_disk(n, height)).collect();
    for (i, chain) in chains.iter().enumerate().skip(1) {
        assert_eq!(chain.len(), chains[0].len());
        for (h, (a, b)) in chains[0].iter().zip(chain).enumerate() {
            assert_eq!(
                a.0,
                b.0,
                "node {} differs at block {}",
                nodes[i].seed,
                h + 1
            );
            assert_eq!(
                a.1,
                b.1,
                "node {} state root differs at block {}",
                nodes[i].seed,
                h + 1
            );
        }
    }
}

// ---- the tests ----------------------------------------------------------------------

#[test]
fn four_nodes_started_from_configuration_files_agree_on_one_chain() {
    const HEIGHT: u64 = 5;
    let root = tempfile::tempdir().unwrap();
    let nodes = provision(root.path());
    let running: Vec<Running> = nodes.iter().map(|n| start(n, HEIGHT)).collect();
    for node in running {
        node.finish(Duration::from_secs(60)).unwrap();
    }
    assert_one_chain(&nodes, HEIGHT);
}

#[test]
fn a_node_stopped_and_started_again_from_its_disk_rejoins_and_the_chain_stays_one() {
    const HEIGHT: u64 = 10;
    let root = tempfile::tempdir().unwrap();
    let nodes = provision(root.path());
    let mut running: Vec<Running> = nodes.iter().map(|n| start(n, HEIGHT)).collect();

    // Let the chain get going, then stop the last node: everything it had in
    // memory is gone, and only its directory remains.
    let victim = running.pop().unwrap();
    let end = Instant::now() + Duration::from_secs(60);
    while victim.height() < 3 {
        assert!(Instant::now() < end, "the chain never got going");
        thread::sleep(Duration::from_millis(50));
    }
    victim.stop.store(true, Ordering::Release);
    let stopped_at = victim.height();
    let victim_node = &nodes[3];
    victim.finish(Duration::from_secs(30)).unwrap();

    // The other three (three of four validators, more than two thirds) go on
    // without it. Start it again from the same directory and the same address.
    let restarted = start(victim_node, HEIGHT);
    let survivors_done: Vec<_> = running
        .into_iter()
        .map(|node| node.finish(Duration::from_secs(60)))
        .collect();
    for result in survivors_done {
        result.unwrap();
    }
    let seen = restarted.height();
    restarted.finish(Duration::from_secs(60)).unwrap();
    assert!(
        stopped_at >= 3 && seen >= HEIGHT || seen > 0,
        "it rejoined: stopped at {stopped_at}, then reached {seen}"
    );

    assert_one_chain(&nodes, HEIGHT);
}

#[test]
fn a_node_refuses_to_start_from_a_signer_it_cannot_reach_or_a_genesis_that_is_not_its_chain() {
    let root = tempfile::tempdir().unwrap();
    let nodes = provision(root.path());
    let node = &nodes[0];
    let stop = AtomicBool::new(false);

    // No signer at that socket: the node must not start.
    let mut lost = node.config.clone();
    lost.signer_socket = root.path().join("nobody-listens-here.sock");
    let error = run_node(&lost, Some(BlockHeight(1)), &stop, &mut |_| {}).unwrap_err();
    assert!(error.to_string().contains("signer"), "{error}");

    // A missing genesis file is named as such, before anything is opened.
    let mut without_genesis = node.config.clone();
    without_genesis.genesis = root.path().join("no-genesis.json");
    let error = run_node(&without_genesis, Some(BlockHeight(1)), &stop, &mut |_| {}).unwrap_err();
    assert!(error.to_string().starts_with("genesis:"), "{error}");
    assert!(
        !node.config.data_dir.join("chain").exists(),
        "nothing was created for a node that could not start"
    );
}

#[test]
fn a_node_whose_signer_refuses_halts_and_says_why_while_the_others_carry_on() {
    // Node 4's signer has already signed far past anything this chain is at,
    // as if the node had been rolled back: signing again would risk signing
    // twice at a position, so it must refuse, and the node must stop rather
    // than vote on. Three of four validators are still more than two thirds.
    const HEIGHT: u64 = 4;
    let root = tempfile::tempdir().unwrap();
    let nodes = provision_with(root.path(), &[4]);
    let halted_events = Arc::new(Mutex::new(Vec::new()));
    let running: Vec<Running> = nodes
        .iter()
        .map(|node| {
            if node.seed != 4 {
                return start(node, HEIGHT);
            }
            let stop = Arc::new(AtomicBool::new(false));
            let heights = Arc::new(Mutex::new(Vec::new()));
            let (config, flag, events) = (
                node.config.clone(),
                Arc::clone(&stop),
                Arc::clone(&halted_events),
            );
            let thread = thread::spawn(move || {
                run_node(&config, Some(BlockHeight(HEIGHT)), &flag, &mut |event| {
                    if let NodeEvent::Halted(reason) = event {
                        events.lock().unwrap().push(reason);
                    }
                })
                .map_err(|error| error.to_string())
            });
            Running {
                seed: 4,
                stop,
                heights,
                thread,
            }
        })
        .collect();

    let mut results = Vec::new();
    for node in running {
        let seed = node.seed;
        results.push((seed, node.finish(Duration::from_secs(60))));
    }
    for (seed, result) in &results {
        if *seed == 4 {
            let error = result.as_ref().unwrap_err();
            assert!(error.contains("signer refused"), "{error}");
        } else {
            assert!(result.is_ok(), "node {seed}: {result:?}");
        }
    }
    assert_eq!(
        halted_events.lock().unwrap().len(),
        1,
        "the halt was reported once"
    );
    assert_one_chain(&nodes[..3], HEIGHT);
}

#[allow(dead_code)]
fn unused(_: PathBuf) {}
