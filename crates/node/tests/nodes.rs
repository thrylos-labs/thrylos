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
use chain_consensus::host::Message;
use chain_engine_api::Block;
use chain_exec::genesis::{
    COUNTER_BUMP_FUNCTION, COUNTER_MODULE_NAME, COUNTER_PACKAGE_ADDRESS, INITIAL_COUNTER_ADDRESS,
};
use chain_node::{
    run_node, DurableEngine, FileMarkStore, NodeConfig, NodeEvent, SignerCredential, SignerServer,
};
use chain_node::{PeerLink, PeerNetwork, PeerNetworkConfig, Recipient};
use chain_p2p::{NetworkIdentity, NetworkMessage, TcpNetwork, TransportConfig, TrustedPeer};
use chain_signer::{HighWaterMark, HighWaterMarkStore, Signer, Step};
use chain_text::format_address;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, Hash, MoveCall, PublicKey, Round,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer as _, SigningKey};

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
    provision_full(root, advanced, &[])
}

/// A peer of one node that is not a validator: a client, with a transport key
/// of its own that the node lists, and the address it listens on.
#[derive(Clone, Copy)]
struct ClientPlan {
    /// The seed of the node that lists it.
    node: u8,
    seed: u8,
    listen: SocketAddr,
}

impl ClientPlan {
    fn identity(&self) -> NetworkIdentity {
        NetworkIdentity::from_secret_bytes([self.seed; 32])
    }
}

/// Like [`provision_with`], and each node also lists the clients planned for it.
fn provision_full(root: &Path, advanced: &[u8], clients: &[ClientPlan]) -> Vec<Provisioned> {
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
            let mut peers = peers;
            for client in clients.iter().filter(|c| c.node == plan.seed) {
                peers.push(format!(
                    r#"{{ "address": "{}", "public_key": "{}" }}"#,
                    client.listen,
                    chain_genesis::hex::encode(&client.identity().public_key())
                ));
            }
            let text = format!(
                r#"{{
                  "data_dir": "data", "genesis": "genesis.json", "listen": "{}",
                  "network_key": "network.key", "validator": "{}",
                  "signer": {{ "socket": "signer.sock", "credential": "signer.credential" }},
                  "peers": [{}],
                  "rpc": {{ "listen": "{}" }},
                  "tuning": {{ "io_timeout_ms": 500, "reconnect_initial_ms": 20,
                               "reconnect_max_ms": 250, "block_interval_ms": 50 }}
                }}"#,
                plan.listen,
                format_address(&plan.operator()),
                peers.join(", "),
                free_address()
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

// ---- the RPC -----------------------------------------------------------------------

/// One JSON-RPC call over HTTP, and the whole response.
fn rpc(address: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use std::io::{Read, Write};
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    write!(
        stream,
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").expect("an HTTP response");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    serde_json::from_str(body).unwrap()
}

/// The result of a call that must have succeeded.
fn rpc_ok(address: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    let response = rpc(address, method, params);
    assert!(response.get("error").is_none(), "{method}: {response}");
    response["result"].clone()
}

/// The error a call must have been answered with.
fn rpc_error(address: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    let response = rpc(address, method, params);
    assert!(
        response.get("result").is_none(),
        "{method} succeeded: {response}"
    );
    response["error"].clone()
}

/// Waits until `check` holds, up to `patience`, polling.
fn wait_until(what: &str, patience: Duration, mut check: impl FnMut() -> bool) {
    let end = Instant::now() + patience;
    while !check() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_transaction_sent_over_rpc_to_one_node_is_seen_included_and_agreed_on_over_rpc_at_others() {
    // Long enough that everything below is done before the nodes stop.
    const HEIGHT: u64 = 150;
    let root = tempfile::tempdir().unwrap();
    let nodes = provision(root.path());
    let addresses: Vec<SocketAddr> = nodes.iter().map(|n| n.config.rpc_listen.unwrap()).collect();
    let running: Vec<Running> = nodes.iter().map(|n| start(n, HEIGHT)).collect();

    // Every node answers, and node 1 has met the other three.
    for address in &addresses {
        wait_until("an RPC to answer", Duration::from_secs(30), || {
            std::net::TcpStream::connect(address).is_ok()
        });
    }
    wait_until("node 1 to meet its peers", Duration::from_secs(30), || {
        rpc_ok(addresses[0], "status", serde_json::json!({}))["peers"] == 3
    });
    let status = rpc_ok(addresses[3], "status", serde_json::json!({}));
    assert_eq!(status["chainId"], chain_genesis::devnet::DEVNET_CHAIN_ID);
    assert_eq!(status["halted"], serde_json::Value::Null);
    assert_eq!(
        status["validator"],
        format_address(&nodes[3].config.validator)
    );

    // What a client does: read the account, build the next transaction, send it.
    let sender = Address::from_public_key(&chain_genesis::devnet::ed25519(101).unwrap());
    let account = rpc_ok(
        addresses[3],
        "account",
        serde_json::json!({ "address": format_address(&sender) }),
    );
    assert_eq!(account["nextSequenceNumber"], 0);
    assert_eq!(account["balance"], "1000000000000");
    let tx = bump(101, account["nextSequenceNumber"].as_u64().unwrap(), 7);
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    let hash = chain_rpc::call::transaction_hash(&tx).to_string();
    let sent = rpc_ok(
        addresses[0],
        "send_transaction",
        serde_json::json!({ "transaction": chain_rpc::hex::encode(&bytes) }),
    );
    assert_eq!(sent["hash"], hash);
    assert_eq!(sent["status"], "pending");

    // Node 4 was never sent it. It sees the account move, and the block.
    wait_until(
        "the transaction to run on node 4",
        Duration::from_secs(60),
        || {
            rpc_ok(
                addresses[3],
                "account",
                serde_json::json!({ "address": format_address(&sender) }),
            )["nextSequenceNumber"]
                == 1
        },
    );
    let latest = rpc_ok(addresses[3], "status", serde_json::json!({}))["latest"]["height"]
        .as_u64()
        .unwrap();
    let found = (1..=latest)
        .find(|height| {
            rpc_ok(
                addresses[3],
                "block",
                serde_json::json!({ "height": height }),
            )["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|listed| listed == &serde_json::json!(hash))
        })
        .expect("a block on node 4 that carries it");

    // Every node has that block, the same, with the same state after it.
    let reference = rpc_ok(
        addresses[3],
        "block",
        serde_json::json!({ "height": found }),
    );
    for address in &addresses[..3] {
        wait_until(
            "the block to reach every node",
            Duration::from_secs(30),
            || {
                rpc(*address, "block", serde_json::json!({ "height": found }))
                    .get("result")
                    .is_some()
            },
        );
        let theirs = rpc_ok(*address, "block", serde_json::json!({ "height": found }));
        assert_eq!(theirs["hash"], reference["hash"]);
        assert_eq!(theirs["stateRoot"], reference["stateRoot"]);
    }
    let full = rpc_ok(
        addresses[1],
        "block",
        serde_json::json!({ "height": found, "full": true }),
    );
    assert_eq!(full["transactions"][0]["sender"], format_address(&sender));
    assert_eq!(
        full["transactions"][0]["encoded"],
        chain_rpc::hex::encode(&bytes)
    );

    // The certificate that decided it: the same block, signed by a quorum of
    // this network's validators.
    let commit = rpc_ok(addresses[2], "commit", serde_json::json!({}));
    let commit_height = commit["height"].as_u64().unwrap();
    let block_at_commit = rpc_ok(
        addresses[2],
        "block",
        serde_json::json!({ "height": commit_height }),
    );
    assert_eq!(commit["blockHash"], block_at_commit["hash"]);
    assert_eq!(commit["stateRoot"], block_at_commit["stateRoot"]);
    assert!(commit["signatureCount"].as_u64().unwrap() >= 3, "{commit}");
    let validators: Vec<String> = nodes
        .iter()
        .map(|n| format_address(&n.config.validator))
        .collect();
    for signature in commit["signatures"].as_array().unwrap() {
        assert!(validators.contains(&signature["validator"].as_str().unwrap().to_owned()));
        assert_eq!(signature["signature"].as_str().unwrap().len(), 96 * 2);
    }

    // Refusals come back as errors that say why, over the wire.
    let again = rpc_error(
        addresses[1],
        "send_transaction",
        serde_json::json!({ "transaction": chain_rpc::hex::encode(&bytes) }),
    );
    assert_eq!(again["code"], -32010);
    assert_eq!(again["data"]["reason"], "SequenceNumberTooLow", "{again}");
    let mut wrong_chain = Vec::new();
    bump_on_chain(101, 1, 1, chain_genesis::devnet::DEVNET_CHAIN_ID + 1).encode(&mut wrong_chain);
    let refused = rpc_error(
        addresses[1],
        "send_transaction",
        serde_json::json!({ "transaction": chain_rpc::hex::encode(&wrong_chain) }),
    );
    assert_eq!(refused["data"]["reason"], "WrongChainId");
    assert_eq!(
        rpc_error(
            addresses[1],
            "block",
            serde_json::json!({ "height": 999_999 })
        )["code"],
        -32001
    );
    assert_eq!(
        rpc_error(addresses[1], "nothing", serde_json::json!({}))["code"],
        -32601
    );
    assert_eq!(
        rpc_error(
            addresses[1],
            "account",
            serde_json::json!({ "address": "thry1nope" })
        )["code"],
        -32602
    );

    // The block that carried it went out compact, and the others put it back
    // together (from what they held, or after asking for what they did not).
    let relay: Vec<serde_json::Value> = addresses
        .iter()
        .map(|address| rpc_ok(*address, "status", serde_json::json!({}))["blockRelay"].clone())
        .collect();
    let total = |field: &str| {
        relay
            .iter()
            .map(|r| r[field].as_u64().unwrap())
            .sum::<u64>()
    };
    assert!(total("announcedCompact") >= 1, "{relay:?}");
    assert!(
        total("rebuiltFromPool") + total("rebuiltAfterRequest") >= 3,
        "the other three each rebuilt the block: {relay:?}"
    );

    // The first transaction succeeded, and every node says so, in the same place.
    let found_block = found;
    let mut places = std::collections::BTreeSet::new();
    for address in &addresses {
        let found = rpc_ok(*address, "transaction", serde_json::json!({ "hash": hash }));
        assert_eq!(found["status"], "included", "{found}");
        assert_eq!(found["outcome"], serde_json::json!({ "status": "success" }));
        assert_eq!(found["height"], serde_json::json!(found_block));
        assert_eq!(found["blockHash"], reference["hash"]);
        places.insert((
            found["height"].to_string(),
            found["index"].to_string(),
            found["blockHash"].to_string(),
        ));
    }
    assert_eq!(
        places.len(),
        1,
        "every node puts it in the same place: {places:?}"
    );

    // One that aborts (the counter is at 7, and this adds the most a counter
    // holds) is still included and still charged, and every node says that it
    // aborted, and why, and in which block.
    let aborting = bump(101, 1, u64::MAX);
    let mut aborting_bytes = Vec::new();
    aborting.encode(&mut aborting_bytes);
    let aborting_hash = chain_rpc::call::transaction_hash(&aborting).to_string();
    let sent = rpc_ok(
        addresses[1],
        "send_transaction",
        serde_json::json!({ "transaction": chain_rpc::hex::encode(&aborting_bytes) }),
    );
    assert_eq!(sent["hash"], aborting_hash);
    let mut places = std::collections::BTreeSet::new();
    for address in &addresses {
        wait_until(
            "the aborting transaction to be included",
            Duration::from_secs(60),
            || {
                rpc(
                    *address,
                    "transaction",
                    serde_json::json!({ "hash": aborting_hash }),
                )
                .get("result")
                .is_some_and(|found| found["status"] == "included")
            },
        );
        let found = rpc_ok(
            *address,
            "transaction",
            serde_json::json!({ "hash": aborting_hash }),
        );
        assert_eq!(found["outcome"]["status"], "aborted", "{found}");
        assert_eq!(found["outcome"]["reason"], "ExecutionFailed");
        assert!(!found["outcome"]["message"].as_str().unwrap().is_empty());
        places.insert((
            found["height"].to_string(),
            found["index"].to_string(),
            found["blockHash"].to_string(),
        ));
    }
    assert_eq!(
        places.len(),
        1,
        "every node puts it in the same place: {places:?}"
    );
    // The block says how many aborted, and the account says it was charged for it.
    let aborted_at = rpc_ok(
        addresses[3],
        "transaction",
        serde_json::json!({ "hash": aborting_hash }),
    )["height"]
        .as_u64()
        .unwrap();
    let block = rpc_ok(
        addresses[3],
        "block",
        serde_json::json!({ "height": aborted_at, "full": true }),
    );
    assert_eq!(block["abortedCount"], 1, "{block}");
    let listed = block["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["hash"] == aborting_hash)
        .unwrap();
    assert_eq!(listed["outcome"]["status"], "aborted");
    let account = rpc_ok(
        addresses[3],
        "account",
        serde_json::json!({ "address": format_address(&sender) }),
    );
    assert_eq!(
        account["nextSequenceNumber"], 2,
        "an abort spends the sequence number too"
    );

    // What was never sent is not found, and a bad hash is a bad parameter.
    assert_eq!(
        rpc_error(
            addresses[0],
            "transaction",
            serde_json::json!({ "hash": "ab".repeat(32) })
        )["code"],
        -32001
    );
    assert_eq!(
        rpc_error(
            addresses[0],
            "transaction",
            serde_json::json!({ "hash": "abcd" })
        )["code"],
        -32602
    );

    // The pool emptied as the block committed.
    wait_until("the pool to empty", Duration::from_secs(30), || {
        rpc_ok(addresses[0], "status", serde_json::json!({}))["mempool"] == 0
    });

    for node in running {
        node.finish(Duration::from_secs(120)).unwrap();
    }
    assert_one_chain(&nodes, 100);
    for node in &nodes {
        assert_eq!(counter_on_disk(node), Some(7), "node {}", node.seed);
    }
}

// ---- transactions ------------------------------------------------------------------

/// A client of `node`: a peer with a transport key the node lists, connected to
/// nothing else, that can hand the node transactions and hears what it passes on.
fn connect_client(client: &ClientPlan, node: &Provisioned) -> PeerNetwork {
    let node_key = chain_node::config::read_network_key(&node.config.network_key)
        .unwrap()
        .public_key();
    let peer = TrustedPeer::new(node.config.listen, node_key).unwrap();
    let network = TcpNetwork::bind(
        client.listen,
        client.identity(),
        vec![peer],
        TransportConfig {
            io_timeout: Duration::from_millis(500),
            ..TransportConfig::default()
        },
        Arc::new(|_, _: &Message| true),
    )
    .unwrap();
    let peers = PeerNetwork::start(
        network,
        vec![PeerLink {
            peer,
            validator: None,
        }],
        PeerNetworkConfig {
            reconnect_initial: Duration::from_millis(20),
            reconnect_max: Duration::from_millis(250),
            ..PeerNetworkConfig::default()
        },
    )
    .unwrap();
    assert!(
        peers.wait_for_peers(1, Duration::from_secs(30)),
        "the client never reached node {}",
        node.seed
    );
    peers
}

/// A signed call to the genesis counter's `bump`, from a funded devnet account
/// (seeds 101 to 104).
fn bump(seed: u8, sequence: u64, amount: u64) -> Transaction {
    bump_on_chain(
        seed,
        sequence,
        amount,
        chain_genesis::devnet::DEVNET_CHAIN_ID,
    )
}

fn bump_on_chain(seed: u8, sequence: u64, amount: u64, chain: u64) -> Transaction {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let body = TransactionBody {
        chain_id: ChainId(chain),
        sender: PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
        sequence_number: SequenceNumber(sequence),
        expiry: BlockHeight(1_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(1),
        declared_inputs: vec![Address::from_bytes(INITIAL_COUNTER_ADDRESS.into_bytes())],
        call: MoveCall {
            module_address: Address::from_bytes(COUNTER_PACKAGE_ADDRESS.into_bytes()),
            module_name: COUNTER_MODULE_NAME.as_bytes().to_vec(),
            function_name: COUNTER_BUMP_FUNCTION.as_bytes().to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![amount.to_le_bytes().to_vec()],
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
    }
}

/// The next transaction `peers` is handed, up to `patience`.
fn next_transaction(peers: &PeerNetwork, patience: Duration) -> Option<Transaction> {
    let end = Instant::now() + patience;
    while Instant::now() < end {
        if let Some(inbound) = peers.recv_timeout(Duration::from_millis(100)) {
            if let NetworkMessage::Transaction(transaction) = inbound.message {
                return Some(transaction);
            }
        }
    }
    None
}

/// What a node's disk says the genesis counter is.
fn counter_on_disk(node: &Provisioned) -> Option<u64> {
    let genesis = chain_genesis::load(&node.config.genesis).unwrap();
    let engine = DurableEngine::open(&node.config.data_dir, &genesis).unwrap();
    engine.executor().read_counter()
}

#[test]
fn a_transaction_handed_to_one_node_reaches_all_of_them_and_runs_once_on_each() {
    // Enough blocks that the transaction, which is handed over a moment after
    // the nodes start, is certain to arrive before they stop.
    const HEIGHT: u64 = 60;
    let root = tempfile::tempdir().unwrap();
    let submitter = ClientPlan {
        node: 1,
        seed: 200,
        listen: free_address(),
    };
    let watcher = ClientPlan {
        node: 3,
        seed: 201,
        listen: free_address(),
    };
    let nodes = provision_full(root.path(), &[], &[submitter, watcher]);
    let running: Vec<Running> = nodes.iter().map(|n| start(n, HEIGHT)).collect();

    let submitting = connect_client(&submitter, &nodes[0]);
    let watching = connect_client(&watcher, &nodes[2]);
    let tx = bump(101, 0, 7);
    submitting.send(&Recipient::All, &NetworkMessage::Transaction(tx.clone()));

    // Node 3 was never handed it. It has it because node 1 passed it on, and
    // it passes it on to its own peers, this one, in turn.
    let relayed = next_transaction(&watching, Duration::from_secs(30));
    assert_eq!(relayed, Some(tx.clone()), "the watcher was never sent it");
    // And nobody sends it back round: it is not offered a second time.
    assert_eq!(next_transaction(&watching, Duration::from_secs(1)), None);

    for node in running {
        node.finish(Duration::from_secs(90)).unwrap();
    }

    // It ran, on every node, once: the counter went up by exactly its amount.
    for node in &nodes {
        assert_eq!(counter_on_disk(node), Some(7), "node {}", node.seed);
    }
    // In exactly one block, the same on all four, with the same state after.
    assert_one_chain(&nodes, HEIGHT);
    let carrying: Vec<u64> = chain_on_disk(&nodes[0], HEIGHT)
        .iter()
        .filter(|(block, _)| block.transactions.contains(&tx))
        .map(|(block, _)| block.height.0)
        .collect();
    assert_eq!(carrying.len(), 1, "in blocks {carrying:?}");
}

#[test]
fn transactions_in_order_from_one_sender_are_all_included_in_that_order() {
    const HEIGHT: u64 = 60;
    let root = tempfile::tempdir().unwrap();
    let submitter = ClientPlan {
        node: 2,
        seed: 200,
        listen: free_address(),
    };
    let nodes = provision_full(root.path(), &[], &[submitter]);
    let running: Vec<Running> = nodes.iter().map(|n| start(n, HEIGHT)).collect();
    let submitting = connect_client(&submitter, &nodes[1]);

    // Three from one account, and one each from two others, handed over at once.
    let sent = [
        bump(101, 0, 1),
        bump(101, 1, 10),
        bump(101, 2, 100),
        bump(102, 0, 1_000),
        bump(103, 0, 10_000),
    ];
    for tx in &sent {
        submitting.send(&Recipient::All, &NetworkMessage::Transaction(tx.clone()));
    }
    for node in running {
        node.finish(Duration::from_secs(90)).unwrap();
    }

    for node in &nodes {
        assert_eq!(counter_on_disk(node), Some(11_111), "node {}", node.seed);
    }
    assert_one_chain(&nodes, HEIGHT);

    // Every one is on the chain, and a sender's are in the order of their
    // sequence numbers, which is the only order execution would accept.
    let included: Vec<Transaction> = chain_on_disk(&nodes[0], HEIGHT)
        .into_iter()
        .flat_map(|(block, _)| block.transactions)
        .collect();
    assert_eq!(included.len(), sent.len());
    for tx in &sent {
        assert!(included.contains(tx));
    }
    let sequences: Vec<u64> = included
        .iter()
        .filter(|tx| tx.body.sender == sent[0].body.sender)
        .map(|tx| tx.body.sequence_number.0)
        .collect();
    assert_eq!(sequences, vec![0, 1, 2]);
}

#[allow(dead_code)]
fn unused(_: PathBuf) {}
