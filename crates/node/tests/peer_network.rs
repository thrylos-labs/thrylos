//! `PeerNetwork` over real loopback sockets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chain_consensus::host::{Message, SyncRequest};
use chain_node::{Inbound, PeerLink, PeerNetwork, PeerNetworkConfig, Recipient};
use chain_p2p::{
    NetworkError, NetworkIdentity, NetworkMessage, PeerId, TcpNetwork, TransportConfig, TrustedPeer,
};
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

const PLACEHOLDER: &str = "127.0.0.1:1";

fn identity(seed: u8) -> NetworkIdentity {
    NetworkIdentity::from_secret_bytes([seed; 32])
}

fn validator(seed: u8) -> Address {
    Address::from_bytes([seed; 32])
}

fn transport(io_timeout: Duration) -> TransportConfig {
    TransportConfig {
        io_timeout,
        ..TransportConfig::default()
    }
}

fn quick() -> PeerNetworkConfig {
    PeerNetworkConfig {
        inbound_queue: 64,
        outbound_queue: 32,
        reconnect_initial: Duration::from_millis(20),
        reconnect_max: Duration::from_millis(200),
    }
}

fn request(from: u64) -> NetworkMessage {
    NetworkMessage::Consensus(Message::SyncRequest(SyncRequest {
        requester: Address::from_bytes([9; 32]),
        from: BlockHeight(from),
    }))
}

fn requested(inbound: &Inbound) -> u64 {
    match &inbound.message {
        NetworkMessage::Consensus(Message::SyncRequest(request)) => request.from.0,
        other => panic!("expected a catch-up request, got {other:?}"),
    }
}

fn transaction(seed: u8) -> Transaction {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let body = TransactionBody {
        chain_id: ChainId(1),
        sender: PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
        sequence_number: SequenceNumber(0),
        expiry: BlockHeight(10),
        gas_limit: GasAmount(10),
        max_fee_per_gas: GasPrice(1),
        declared_inputs: Vec::new(),
        call: MoveCall {
            module_address: Address::from_bytes([1; 32]),
            module_name: b"m".to_vec(),
            function_name: b"f".to_vec(),
            type_arguments: Vec::new(),
            arguments: Vec::new(),
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
    }
}

/// A node in a test cluster, with what it takes to start it again.
struct Node {
    seed: u8,
    peer: PeerId,
    address: SocketAddr,
    network: Option<PeerNetwork>,
}

impl Node {
    fn network(&self) -> &PeerNetwork {
        self.network.as_ref().expect("the node is running")
    }
}

/// Peers, keyed by seed, with the addresses known so far.
struct Cluster {
    nodes: BTreeMap<u8, Node>,
    io_timeout: Duration,
    config: PeerNetworkConfig,
}

/// Starts node `seed`, listening on `bind` (or anywhere), knowing the other
/// `seeds` at `addresses`. An address not yet known is a placeholder: a node
/// only dials peers with a higher id, so it never needs a lower one's.
fn start_node(
    seed: u8,
    seeds: &[u8],
    addresses: &BTreeMap<u8, SocketAddr>,
    bind: SocketAddr,
    io_timeout: Duration,
    config: PeerNetworkConfig,
) -> Node {
    let mut trusted = Vec::new();
    let mut links = Vec::new();
    for other in seeds.iter().copied().filter(|other| *other != seed) {
        let address = addresses
            .get(&other)
            .copied()
            .unwrap_or_else(|| PLACEHOLDER.parse().unwrap());
        let peer = TrustedPeer::new(address, identity(other).public_key()).unwrap();
        trusted.push(peer);
        links.push(PeerLink {
            peer,
            validator: Some(validator(other)),
        });
    }
    let network = TcpNetwork::bind(
        bind,
        identity(seed),
        trusted,
        transport(io_timeout),
        Arc::new(|_, _: &Message| true),
    )
    .unwrap();
    let address = network.local_addr().unwrap();
    Node {
        seed,
        peer: identity(seed).peer_id(),
        address,
        network: Some(PeerNetwork::start(network, links, config).unwrap()),
    }
}

impl Cluster {
    /// Starts every node, highest peer id first, so each already knows the
    /// address of every peer it will dial.
    fn start(seeds: &[u8], io_timeout: Duration, config: PeerNetworkConfig) -> Self {
        let mut order = seeds.to_vec();
        order.sort_by_key(|seed| std::cmp::Reverse(identity(*seed).peer_id()));
        let mut addresses = BTreeMap::new();
        let mut nodes = BTreeMap::new();
        for seed in order {
            let node = start_node(
                seed,
                seeds,
                &addresses,
                "127.0.0.1:0".parse().unwrap(),
                io_timeout,
                config,
            );
            addresses.insert(seed, node.address);
            nodes.insert(seed, node);
        }
        Self {
            nodes,
            io_timeout,
            config,
        }
    }

    fn seeds(&self) -> Vec<u8> {
        self.nodes.keys().copied().collect()
    }

    fn addresses(&self) -> BTreeMap<u8, SocketAddr> {
        self.nodes
            .iter()
            .map(|(seed, node)| (*seed, node.address))
            .collect()
    }

    fn node(&self, seed: u8) -> &PeerNetwork {
        self.nodes[&seed].network()
    }

    /// The node with the highest peer id: the one every other node dials.
    fn highest(&self) -> u8 {
        *self
            .nodes
            .values()
            .max_by_key(|node| node.peer)
            .map(|node| &node.seed)
            .unwrap()
    }

    fn wait_until_meshed(&self) {
        let others = self.nodes.len() - 1;
        for (seed, node) in &self.nodes {
            assert!(
                node.network()
                    .wait_for_peers(others, Duration::from_secs(10)),
                "node {seed} did not reach {others} peers: {:?}",
                node.network().stats()
            );
        }
    }
}

/// What `node` receives in the next `wait`, up to `most` messages.
fn drain(node: &PeerNetwork, most: usize, wait: Duration) -> Vec<Inbound> {
    let end = Instant::now() + wait;
    let mut got = Vec::new();
    while got.len() < most {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match node.recv_timeout(left) {
            Some(inbound) => got.push(inbound),
            None => break,
        }
    }
    got
}

// ---- who gets what -----------------------------------------------------------------

#[test]
fn a_cluster_connects_and_a_message_reaches_exactly_who_it_is_for() {
    let cluster = Cluster::start(&[1, 2, 3, 4], Duration::from_millis(500), quick());
    cluster.wait_until_meshed();

    // To everyone: every other node hears it once, from the sender.
    let report = cluster.node(1).send(&Recipient::All, &request(7));
    assert_eq!(report.queued, 3);
    assert_eq!(report.dropped + report.unreachable, 0);
    for seed in [2, 3, 4] {
        let got = drain(cluster.node(seed), 2, Duration::from_secs(3));
        assert_eq!(got.len(), 1, "node {seed}");
        assert_eq!(got[0].from, identity(1).peer_id());
        assert_eq!(requested(&got[0]), 7);
    }
    assert!(drain(cluster.node(1), 1, Duration::from_millis(200)).is_empty());

    // To one validator, by address: only it hears.
    let report = cluster
        .node(2)
        .send(&Recipient::Validator(validator(4)), &request(8));
    assert_eq!(report.queued, 1);
    let got = drain(cluster.node(4), 2, Duration::from_secs(3));
    assert_eq!(got.len(), 1);
    assert_eq!(requested(&got[0]), 8);
    assert_eq!(got[0].from, identity(2).peer_id());
    for seed in [1, 3] {
        assert!(drain(cluster.node(seed), 1, Duration::from_millis(200)).is_empty());
    }

    // Peers are known by validator, both ways.
    assert_eq!(
        cluster.node(1).validator_of(identity(3).peer_id()),
        Some(validator(3))
    );
}

#[test]
fn a_message_for_a_validator_that_is_not_a_peer_goes_nowhere_and_says_so() {
    let cluster = Cluster::start(&[1, 2], Duration::from_millis(500), quick());
    cluster.wait_until_meshed();
    let report = cluster
        .node(1)
        .send(&Recipient::Validator(validator(77)), &request(1));
    assert_eq!(
        report,
        chain_node::SendReport {
            queued: 0,
            dropped: 0,
            unreachable: 1
        }
    );
    assert!(drain(cluster.node(2), 1, Duration::from_millis(200)).is_empty());
}

#[test]
fn transactions_travel_between_peers_intact() {
    let cluster = Cluster::start(&[1, 2, 3], Duration::from_millis(500), quick());
    cluster.wait_until_meshed();
    let sent = transaction(42);
    cluster
        .node(3)
        .send(&Recipient::All, &NetworkMessage::Transaction(sent.clone()));
    for seed in [1, 2] {
        let got = drain(cluster.node(seed), 1, Duration::from_secs(3));
        match &got.first().expect("the transaction arrived").message {
            NetworkMessage::Transaction(received) => assert_eq!(received, &sent),
            other => panic!("expected a transaction, got {other:?}"),
        }
    }
}

// ---- links coming and going -----------------------------------------------------------

#[test]
fn a_node_that_goes_away_is_noticed_and_found_again_when_it_returns() {
    let mut cluster = Cluster::start(&[1, 2, 3], Duration::from_millis(500), quick());
    cluster.wait_until_meshed();
    let away = cluster.highest();
    let others: Vec<u8> = cluster.seeds().into_iter().filter(|s| *s != away).collect();
    let address = cluster.nodes[&away].address;
    let peer = cluster.nodes[&away].peer;

    // It stops. The others notice, without being told.
    let stopped = cluster
        .nodes
        .get_mut(&away)
        .unwrap()
        .network
        .take()
        .unwrap();
    stopped.shutdown();
    drop(stopped);
    let noticed = Instant::now();
    for seed in &others {
        while cluster.node(*seed).connected_peers().contains(&peer) {
            assert!(noticed.elapsed() < Duration::from_secs(5), "node {seed}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    // It comes back on the same address, with the same key. The others, who
    // dial it, find it again on their own.
    let seeds = cluster.seeds();
    let addresses = cluster.addresses();
    let returned = start_node(
        away,
        &seeds,
        &addresses,
        address,
        cluster.io_timeout,
        cluster.config,
    );
    for seed in &others {
        assert!(
            cluster
                .node(*seed)
                .wait_for_peers(2, Duration::from_secs(10)),
            "node {seed} did not find it again: {:?}",
            cluster.node(*seed).stats()
        );
    }
    cluster.nodes.get_mut(&away).unwrap().network = returned.network;

    // And traffic flows again, both ways.
    let report = cluster.node(others[0]).send(&Recipient::All, &request(5));
    assert_eq!(report.queued, 2);
    let got = drain(cluster.node(away), 1, Duration::from_secs(3));
    assert_eq!(requested(&got[0]), 5);
    cluster.node(away).send(&Recipient::All, &request(6));
    for seed in &others {
        let got = drain(cluster.node(*seed), 3, Duration::from_secs(3));
        assert!(got.iter().any(|i| requested(i) == 6), "node {seed}");
    }
}

#[test]
fn a_quiet_network_keeps_its_connections_instead_of_cycling_them() {
    // A timeout much shorter than the quiet: a link that treated an idle
    // timeout as an error would be torn down and redialled over and over.
    let cluster = Cluster::start(&[1, 2], Duration::from_millis(150), quick());
    cluster.wait_until_meshed();
    std::thread::sleep(Duration::from_millis(1_500));

    for seed in [1, 2] {
        let stats = cluster.node(seed).stats();
        assert_eq!(stats.connected, 1, "node {seed}");
        assert_eq!(stats.connections_made, 1, "node {seed} was not redialled");
        // Only the lower id dials, so nobody dialled a peer that was already
        // dialling back: no handshake was wasted on a duplicate.
        assert_eq!(stats.failed_handshakes, 0, "node {seed}");
    }
    cluster.node(1).send(&Recipient::All, &request(3));
    let got = drain(cluster.node(2), 1, Duration::from_secs(2));
    assert_eq!(requested(&got[0]), 3);
}

/// An address nobody is listening on yet, chosen ahead of time so that two
/// nodes can each be told the other's.
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

#[test]
fn a_link_is_dialled_from_one_side_only_even_when_both_know_each_others_address() {
    // Unlike the clusters above, where a node knows only the addresses of
    // the peers it dials, here each is told the other's: if both dialled,
    // they would race to connect and one attempt would be refused as a
    // duplicate.
    let addresses: BTreeMap<u8, SocketAddr> = [(1, free_address()), (2, free_address())]
        .into_iter()
        .collect();
    let seeds = [1, 2];
    let nodes: Vec<Node> = seeds
        .iter()
        .map(|seed| {
            start_node(
                *seed,
                &seeds,
                &addresses,
                addresses[seed],
                Duration::from_millis(500),
                quick(),
            )
        })
        .collect();
    for node in &nodes {
        assert!(node.network().wait_for_peers(1, Duration::from_secs(10)));
    }
    std::thread::sleep(Duration::from_millis(1_000));
    for node in &nodes {
        let stats = node.network().stats();
        assert_eq!(stats.connected, 1, "node {}", node.seed);
        assert_eq!(stats.connections_made, 1, "node {}", node.seed);
        assert_eq!(stats.failed_handshakes, 0, "node {}", node.seed);
    }
}

// ---- who is kept out ---------------------------------------------------------------------

#[test]
fn an_unlisted_peer_is_not_admitted_and_a_silent_stranger_does_not_hold_up_a_real_one() {
    // A long timeout, so that a silent connection could hold up an acceptor
    // that authenticated in its own thread for the whole of it.
    let cluster = Cluster::start(&[1, 2], Duration::from_secs(10), quick());
    let target = cluster.nodes[&cluster.highest()].address;
    let target_network = cluster.node(cluster.highest());

    // A stranger that connects and says nothing.
    let _silent = TcpStream::connect(target).unwrap();

    // An outsider with a key nobody listed tries to authenticate.
    let outsider = TcpNetwork::bind(
        "127.0.0.1:0".parse().unwrap(),
        identity(99),
        vec![TrustedPeer::new(target, identity(cluster.highest()).public_key()).unwrap()],
        transport(Duration::from_millis(500)),
        Arc::new(|_, _: &Message| true),
    )
    .unwrap();
    assert!(outsider
        .connect(identity(cluster.highest()).peer_id())
        .is_err());

    // The real peer is not held up by either.
    let started = Instant::now();
    cluster.wait_until_meshed();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!target_network
        .connected_peers()
        .contains(&identity(99).peer_id()));
    // The refused handshake was counted.
    let end = Instant::now() + Duration::from_secs(3);
    while target_network.stats().failed_handshakes == 0 {
        assert!(Instant::now() < end, "the outsider's handshake was counted");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn silent_connections_beyond_one_sources_share_of_the_handshake_pool_are_refused_on_arrival() {
    let cluster = Cluster::start(&[1, 2], Duration::from_secs(10), quick());
    let target = cluster.nodes[&cluster.highest()].address;
    let network = cluster.node(cluster.highest());

    // Far more silent connections than may be mid-handshake at once, all from
    // this one address: only its share of the pool is let in, and the rest are
    // refused. (The pool as a whole is capped too, which one address cannot
    // reach: that cap is tested, with many addresses, in the unit tests.)
    let many = 3 * chain_node::peer_network::MAX_PENDING_HANDSHAKES;
    let held: Vec<TcpStream> = (0..many)
        .map(|_| TcpStream::connect(target).unwrap())
        .collect();
    let excess = many - chain_node::peer_network::MAX_PENDING_HANDSHAKES_PER_IP;
    let end = Instant::now() + Duration::from_secs(5);
    while network.stats().refused_handshakes < excess as u64 {
        assert!(
            Instant::now() < end,
            "only {} of {excess} were refused",
            network.stats().refused_handshakes
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Everything past the share was refused. (A peer's own reconnect from the
    // same address during the burst may be refused as well, so not exactly.)
    let refused = network.stats().refused_handshakes;
    assert!(
        refused >= excess as u64 && refused <= many as u64,
        "{refused}"
    );
    drop(held);
}

// ---- bounds ---------------------------------------------------------------------------------

#[test]
fn sending_never_blocks_and_a_peer_that_does_not_keep_up_costs_dropped_messages() {
    let config = PeerNetworkConfig {
        inbound_queue: 4,
        outbound_queue: 8,
        ..quick()
    };
    let cluster = Cluster::start(&[1, 2], Duration::from_millis(500), config);
    cluster.wait_until_meshed();

    // Node 2 reads nothing. Node 1 sends far more than anything can hold.
    let started = Instant::now();
    let mut dropped = 0;
    for i in 0..5_000 {
        dropped += cluster.node(1).send(&Recipient::All, &request(i)).dropped;
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "5,000 sends took {:?}: the sender was made to wait",
        started.elapsed()
    );
    assert!(dropped > 0, "with nothing reading, some were dropped");
    assert_eq!(cluster.node(1).stats().dropped_outgoing, dropped as u64);

    // What node 2 finally reads is a bounded amount, in order, and node 1 is
    // still able to talk to it afterwards.
    let got = drain(cluster.node(2), 5_000, Duration::from_secs(2));
    assert!(!got.is_empty());
    assert!(got.len() < 5_000, "not everything was delivered");
    let heights: Vec<u64> = got.iter().map(requested).collect();
    assert!(heights.windows(2).all(|w| w[0] < w[1]), "in order");

    assert!(cluster.node(1).wait_for_peers(1, Duration::from_secs(10)));
    let report = cluster.node(1).send(&Recipient::All, &request(1_000_000));
    assert_eq!(report.queued, 1);
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let got = drain(cluster.node(2), 10, Duration::from_millis(300));
        if got.iter().any(|i| requested(i) == 1_000_000) {
            break;
        }
        assert!(Instant::now() < end, "the link recovered");
    }
}

// ---- lifecycle -------------------------------------------------------------------------------

#[test]
fn shutdown_is_prompt_and_frees_the_port() {
    let mut cluster = Cluster::start(&[1, 2, 3], Duration::from_secs(5), quick());
    cluster.wait_until_meshed();
    let address = cluster.nodes[&1].address;
    let network = cluster.nodes.get_mut(&1).unwrap().network.take().unwrap();

    let started = Instant::now();
    network.shutdown();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown took {:?}",
        started.elapsed()
    );
    drop(network);
    TcpListener::bind(address).expect("the port is free again");
    // And the others see it go.
    let end = Instant::now() + Duration::from_secs(5);
    while cluster.node(2).connected_peers().len() > 1 {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_network_is_refused_a_link_to_itself_a_repeat_or_a_zero_bound() {
    fn start(
        links: impl FnOnce(&TrustedPeer, &TrustedPeer) -> Vec<PeerLink>,
        config: PeerNetworkConfig,
    ) -> Result<PeerNetwork, NetworkError> {
        let a = TrustedPeer::new(PLACEHOLDER.parse().unwrap(), identity(2).public_key()).unwrap();
        let me = TrustedPeer::new(PLACEHOLDER.parse().unwrap(), identity(1).public_key()).unwrap();
        let network = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            identity(1),
            vec![a],
            transport(Duration::from_millis(200)),
            Arc::new(|_, _: &Message| true),
        )
        .unwrap();
        PeerNetwork::start(network, links(&a, &me), config)
    }
    let link = |peer: TrustedPeer, seed: u8| PeerLink {
        peer,
        validator: Some(validator(seed)),
    };

    assert!(start(|a, _| vec![link(*a, 2)], quick()).is_ok());
    // A link to this node itself.
    assert!(start(|_, me| vec![link(*me, 1)], quick()).is_err());
    // The same peer twice.
    assert!(start(|a, _| vec![link(*a, 2), link(*a, 3)], quick()).is_err());
    // Two peers claiming one validator.
    let other = TrustedPeer::new(PLACEHOLDER.parse().unwrap(), identity(3).public_key()).unwrap();
    assert!(start(|a, _| vec![link(*a, 2), link(other, 2)], quick()).is_err());
    // A queue or a delay of nothing.
    for bad in [
        PeerNetworkConfig {
            inbound_queue: 0,
            ..quick()
        },
        PeerNetworkConfig {
            outbound_queue: 0,
            ..quick()
        },
        PeerNetworkConfig {
            reconnect_initial: Duration::ZERO,
            ..quick()
        },
        PeerNetworkConfig {
            reconnect_max: Duration::from_millis(1),
            ..quick()
        },
    ] {
        assert!(start(|a, _| vec![link(*a, 2)], bad).is_err(), "{bad:?}");
    }
}
