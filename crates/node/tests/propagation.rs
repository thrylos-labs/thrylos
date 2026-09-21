//! Block propagation at the size cap, over real authenticated sockets.
//!
//! `docs/spec.md`: "block *propagation* must complete well inside the round
//! timeout at the size cap. A chain that executes fast but gossips slowly halts in
//! exactly the same way." So this fills a block to the four MiB cap with real
//! signed transactions, has one proposer send it to thirty-two validators, and
//! measures what the proposer must upload and what a receiver must do, three ways:
//! the whole block to everyone (what a node did before compact blocks), a compact
//! block to validators that hold every transaction, and a compact block to
//! validators each missing a tenth of them, who ask for them.
//!
//! Every scenario checks that every receiver ends with exactly the block that was
//! proposed. The numbers that do not depend on the machine (bytes) are asserted;
//! times are printed, and bounded only loosely, because a test machine's loopback
//! says little about a validator's uplink. Bytes are what set the uplink a
//! proposer needs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::integer_division,
    clippy::cast_precision_loss,
    // Only for reporting megabytes and seconds; nothing here is consensus.
    clippy::float_arithmetic
)]

use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use chain_consensus::host::{Message, ProposedBlock};
use chain_consensus::wire::encode_message;
use chain_engine_api::{Block, MAX_BLOCK_SIZE_BYTES};
use chain_node::block_relay::{BlockRelay, PendingTransactions, Received};
use chain_node::{PeerLink, PeerNetwork, PeerNetworkConfig, Recipient};
use chain_p2p::{NetworkIdentity, NetworkMessage, TcpNetwork, TransportConfig, TrustedPeer};
use chain_types::bls::BlsSignature;
use chain_types::{
    Address, BlockHeight, ChainId, Encode, GasAmount, GasPrice, Hash, MoveCall, PublicKey,
    SequenceNumber, Signature, Transaction, TransactionBody,
};
use ed25519_dalek::{Signer, SigningKey};

/// The most validators a proposer is measured feeding: half the peers the
/// transport allows.
const MEASURED_RECEIVERS: usize = 32;
/// What every frame costs on top of its body: the header and the signature.
const FRAME_OVERHEAD: usize = 5 + 64;

fn validator(seed: u8) -> Address {
    Address::from_bytes([seed; 32])
}

fn identity(seed: u8) -> NetworkIdentity {
    NetworkIdentity::from_secret_bytes([seed; 32])
}

/// A distinct, signed call to a counter, from one of a few senders.
fn transaction(n: u64) -> Transaction {
    let key = SigningKey::from_bytes(&[101 + (n % 4) as u8; 32]);
    let body = TransactionBody {
        chain_id: ChainId(1337),
        sender: PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
        sequence_number: SequenceNumber(n / 4),
        expiry: BlockHeight(1_000),
        gas_limit: GasAmount(1_000),
        max_fee_per_gas: GasPrice(1),
        declared_inputs: vec![Address::from_bytes([3; 32])],
        call: MoveCall {
            module_address: Address::from_bytes([2; 32]),
            module_name: b"counter".to_vec(),
            function_name: b"bump".to_vec(),
            type_arguments: Vec::new(),
            arguments: vec![n.to_le_bytes().to_vec()],
        },
    };
    let mut bytes = Vec::new();
    body.encode(&mut bytes);
    Transaction {
        body,
        signature: Signature::from_ed25519_bytes(key.sign(&bytes).to_bytes()),
    }
}

/// A block filled to the cap, and the proposal that carries it. Built once for
/// every test in this file: signing seventeen thousand transactions is not free.
fn full_block() -> ProposedBlock {
    static BLOCK: std::sync::OnceLock<ProposedBlock> = std::sync::OnceLock::new();
    BLOCK.get_or_init(build_full_block).clone()
}

fn build_full_block() -> ProposedBlock {
    let mut block = Block {
        parent_block_hash: Hash::from_bytes([9; 32]),
        height: BlockHeight(42),
        timestamp_millis: 1_700_000_000_000,
        transactions: Vec::new(),
    };
    // What a block costs before it has a transaction, and then each one in turn:
    // measured once each, not by encoding the whole block again every time.
    let mut size = block.encoded_len().unwrap();
    let mut n = 0;
    loop {
        let next = transaction(n);
        let mut bytes = Vec::new();
        next.encode(&mut bytes);
        if size + bytes.len() > MAX_BLOCK_SIZE_BYTES as usize {
            break;
        }
        size += bytes.len();
        block.transactions.push(next);
        n += 1;
    }
    assert_eq!(
        block.encoded_len(),
        Some(size),
        "the running sum is the block's size"
    );
    let secret = blst::min_pk::SecretKey::key_gen(&[5; 32], &[]).unwrap();
    ProposedBlock {
        proposer: validator(1),
        block,
        reveal: BlsSignature::from_bytes(
            secret
                .sign(b"r", chain_types::bls::DST_VOTE, &[])
                .to_bytes(),
        )
        .unwrap(),
    }
}

struct Pool(Vec<Transaction>);

impl PendingTransactions for Pool {
    fn for_each_pending(&self, visit: &mut dyn FnMut(&Transaction)) {
        self.0.iter().for_each(visit);
    }
}

fn free_addresses(count: usize) -> Vec<SocketAddr> {
    let listeners: Vec<TcpListener> = (0..count)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    listeners.iter().map(|l| l.local_addr().unwrap()).collect()
}

fn start_network(seed: u8, listen: SocketAddr, peers: &[(u8, SocketAddr)]) -> PeerNetwork {
    let mut trusted = Vec::new();
    let mut links = Vec::new();
    for (other, address) in peers {
        let peer = TrustedPeer::new(*address, identity(*other).public_key()).unwrap();
        trusted.push(peer);
        links.push(PeerLink {
            peer,
            validator: Some(validator(*other)),
        });
    }
    let network = TcpNetwork::bind(
        listen,
        identity(seed),
        trusted,
        TransportConfig {
            io_timeout: Duration::from_secs(20),
            ..TransportConfig::default()
        },
        std::sync::Arc::new(|_, _: &Message| true),
    )
    .unwrap();
    PeerNetwork::start(
        network,
        links,
        PeerNetworkConfig {
            inbound_queue: 256,
            outbound_queue: 256,
            reconnect_initial: Duration::from_millis(20),
            reconnect_max: Duration::from_millis(200),
        },
    )
    .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The whole block to everyone.
    Whole,
    /// Compact, to validators that hold everything.
    CompactHeldByAll,
    /// Compact, to validators each missing every tenth transaction.
    CompactMissingATenth,
}

struct Outcome {
    /// What the proposer sent, in bytes on the wire.
    proposer_bytes: usize,
    /// What the receivers sent back, in all.
    receiver_bytes: usize,
    /// The last receiver to have the block, from when it was sent.
    slowest: Duration,
    /// The time the busiest receiver spent putting the block together.
    reconstruction: Duration,
    /// Receivers that had to ask for anything.
    asked: usize,
}

fn disseminate(proposed: &ProposedBlock, mode: Mode, receivers_count: usize) -> Outcome {
    let addresses = free_addresses(receivers_count + 1);
    let receiver_seeds: Vec<u8> = (2..).take(receivers_count).collect();
    let proposer = start_network(
        1,
        addresses[0],
        &receiver_seeds
            .iter()
            .zip(&addresses[1..])
            .map(|(seed, address)| (*seed, *address))
            .collect::<Vec<_>>(),
    );

    let (done, results) = mpsc::channel::<(u8, Block, Instant, Duration, usize, bool)>();
    let mut receivers = Vec::new();
    for (index, seed) in receiver_seeds.iter().copied().enumerate() {
        let network = start_network(seed, addresses[index + 1], &[(1, addresses[0])]);
        let done = done.clone();
        // What this receiver holds: everything, or all but every tenth.
        let held: Vec<Transaction> = proposed
            .block
            .transactions
            .iter()
            .enumerate()
            .filter(|(i, _)| mode != Mode::CompactMissingATenth || (i + index) % 10 != 0)
            .map(|(_, t)| t.clone())
            .collect();
        receivers.push(thread::spawn(move || {
            let pool = Pool(held);
            let mut relay = BlockRelay::new();
            let mut reconstruction = Duration::ZERO;
            let mut bytes_back = 0;
            let mut asked = false;
            let deadline = Instant::now() + Duration::from_secs(120);
            while Instant::now() < deadline {
                let Some(inbound) = network.recv_timeout(Duration::from_millis(50)) else {
                    continue;
                };
                let started = Instant::now();
                let received = match inbound.message {
                    NetworkMessage::Consensus(Message::Block(block)) => {
                        Received::Block(Box::new(block))
                    }
                    NetworkMessage::CompactBlock(compact) => {
                        let got = relay.receive_compact(
                            compact,
                            inbound.from,
                            Some(validator(1)),
                            &pool,
                            42,
                        );
                        reconstruction += started.elapsed();
                        got
                    }
                    NetworkMessage::BlockTransactions(answer) => {
                        let got = relay.receive_answer(answer, inbound.from);
                        reconstruction += started.elapsed();
                        got
                    }
                    _ => continue,
                };
                match received {
                    Received::Block(block) => {
                        done.send((
                            seed,
                            block.block,
                            Instant::now(),
                            reconstruction,
                            bytes_back,
                            asked,
                        ))
                        .unwrap();
                        return;
                    }
                    Received::Ask { peer, request } => {
                        asked = true;
                        let mut encoded = Vec::new();
                        request.encode(&mut encoded);
                        bytes_back += encoded.len() + FRAME_OVERHEAD;
                        let _ = network.send_to(peer, &NetworkMessage::TransactionRequest(request));
                    }
                    Received::Nothing => {}
                }
            }
            panic!("receiver {seed} never got the block");
        }));
    }
    drop(done);

    // Connected to everyone, then the block goes out.
    assert!(
        proposer.wait_for_peers(receivers_count, Duration::from_secs(60)),
        "the proposer never met every validator"
    );
    thread::sleep(Duration::from_millis(300));
    let mut relay = BlockRelay::new();
    let message = match mode {
        Mode::Whole => NetworkMessage::Consensus(Message::Block(proposed.clone())),
        _ => relay.announce(proposed),
    };
    let mut proposer_bytes = match &message {
        NetworkMessage::Consensus(Message::Block(block)) => {
            encode_message(&Message::Block(block.clone())).len()
        }
        NetworkMessage::CompactBlock(compact) => {
            let mut bytes = Vec::new();
            compact.encode(&mut bytes);
            bytes.len()
        }
        _ => unreachable!(),
    } + FRAME_OVERHEAD;
    proposer_bytes *= receivers_count;
    let sent_at = Instant::now();
    let _ = proposer.send(&Recipient::All, &message);

    // The proposer answers what it is asked, until everyone has the block.
    let mut finished = Vec::new();
    let end = Instant::now() + Duration::from_secs(120);
    while finished.len() < receivers_count && Instant::now() < end {
        while let Some(inbound) = proposer.recv_timeout(Duration::from_millis(5)) {
            if let NetworkMessage::TransactionRequest(request) = inbound.message {
                let answer = relay
                    .serve(
                        &request,
                        inbound.from,
                        proposer_validator(&proposer, inbound.from),
                    )
                    .expect("a request for the block just announced");
                let mut encoded = Vec::new();
                answer.encode(&mut encoded);
                proposer_bytes += encoded.len() + FRAME_OVERHEAD;
                let _ = proposer.send_to(inbound.from, &NetworkMessage::BlockTransactions(answer));
            }
        }
        while let Ok(result) = results_try(&results) {
            finished.push(result);
        }
    }
    assert_eq!(
        finished.len(),
        receivers_count,
        "not every validator got the block"
    );
    for handle in receivers {
        handle.join().unwrap();
    }

    let expected = proposed.block.hash();
    for (seed, block, ..) in &finished {
        assert_eq!(
            block.hash(),
            expected,
            "validator {seed} has a different block"
        );
        assert_eq!(block, &proposed.block);
    }
    Outcome {
        proposer_bytes,
        receiver_bytes: finished.iter().map(|f| f.4).sum(),
        slowest: finished
            .iter()
            .map(|f| f.2)
            .max()
            .unwrap()
            .saturating_duration_since(sent_at),
        reconstruction: finished.iter().map(|f| f.3).max().unwrap(),
        asked: finished.iter().filter(|f| f.5).count(),
    }
}

fn results_try<T>(results: &mpsc::Receiver<T>) -> Result<T, ()> {
    results.try_recv().map_err(|_| ())
}

fn proposer_validator(network: &PeerNetwork, peer: chain_p2p::PeerId) -> Option<Address> {
    network.validator_of(peer)
}

fn megabytes(bytes: usize) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Seconds to push `bytes` up a link of `megabits` per second.
fn seconds_at(bytes: usize, megabits: f64) -> f64 {
    bytes as f64 * 8.0 / (megabits * 1_000_000.0)
}

fn measure(receivers: usize) {
    let proposed = full_block();
    let block_bytes = proposed.block.encoded_len().unwrap();
    let count = proposed.block.transactions.len();
    assert!(
        block_bytes as f64 > 0.99 * f64::from(MAX_BLOCK_SIZE_BYTES),
        "{block_bytes}"
    );
    assert!(
        count <= 65_536,
        "the identifiers of a block at the cap must fit their frame"
    );

    let whole = disseminate(&proposed, Mode::Whole, receivers);
    let held = disseminate(&proposed, Mode::CompactHeldByAll, receivers);
    let missing = disseminate(&proposed, Mode::CompactMissingATenth, receivers);

    eprintln!(
        "\nblock at the cap: {count} transactions, {:.2} MiB; {receivers} validators over real sockets",
        megabytes(block_bytes)
    );
    eprintln!(
        "{:<34} {:>13} {:>12} {:>10} {:>12}",
        "", "proposer sent", "asked back", "slowest", "rebuild (max)"
    );
    for (name, outcome) in [
        ("whole block to everyone", &whole),
        ("compact, every validator holds all", &held),
        ("compact, each missing a tenth", &missing),
    ] {
        eprintln!(
            "{name:<34} {:>10.2} MiB {:>9.2} MiB {:>8.0} ms {:>10.0} ms   ({} asked)",
            megabytes(outcome.proposer_bytes),
            megabytes(outcome.receiver_bytes),
            outcome.slowest.as_secs_f64() * 1000.0,
            outcome.reconstruction.as_secs_f64() * 1000.0,
            outcome.asked
        );
    }
    // What a proposer to 127 peers (the most a 128-validator set has) would
    // upload, scaled from these, and how long that takes on a link.
    let per_peer = |o: &Outcome| o.proposer_bytes / receivers;
    eprintln!("\nfor 127 peers (a 128-validator set), by proposer upload:");
    for (name, outcome) in [
        ("whole", &whole),
        ("compact, all held", &held),
        ("compact, a tenth missing", &missing),
    ] {
        let bytes = per_peer(outcome) * 127;
        eprintln!(
            "  {name:<26} {:>9.1} MiB   {:>6.2} s at 1 Gbps   {:>6.2} s at 100 Mbps",
            megabytes(bytes),
            seconds_at(bytes, 1_000.0),
            seconds_at(bytes, 100.0)
        );
    }

    // What does not depend on the machine.
    assert!(
        held.proposer_bytes * 20 < whole.proposer_bytes,
        "compact announces at most a twentieth of the whole block: {} against {}",
        held.proposer_bytes,
        whole.proposer_bytes
    );
    assert_eq!(
        held.asked, 0,
        "nobody had to ask when everyone held everything"
    );
    assert_eq!(missing.asked, receivers, "everyone was missing something");
    assert!(
        missing.proposer_bytes * 4 < whole.proposer_bytes,
        "even with a tenth missing everywhere, a quarter of the whole block is not exceeded: {} against {}",
        missing.proposer_bytes,
        whole.proposer_bytes
    );

    // The budget: at 128 validators the proposer must be able to get the block
    // announced within a tenth of the two-second round timeout on a gigabit
    // link, which is 25 MB. The whole block cannot; the compact one can.
    let budget = 25_000_000;
    assert!(
        per_peer(&whole) * 127 > budget * 10,
        "the whole block is nowhere near it"
    );
    assert!(
        per_peer(&held) * 127 < budget,
        "compact fits {} against {budget}",
        per_peer(&held) * 127
    );
    assert!(
        per_peer(&missing) * 127 < budget * 4,
        "and with a tenth missing it is a fraction of a second"
    );

    // Loose bounds on time, so that a broken relay cannot hide in the printout.
    for outcome in [&whole, &held, &missing] {
        assert!(
            outcome.slowest < Duration::from_secs(30),
            "{:?}",
            outcome.slowest
        );
    }
    assert!(
        held.reconstruction < Duration::from_secs(2),
        "putting a block at the cap together took {:?}",
        held.reconstruction
    );
}

/// What the spec's budget needs, at a few validators: every path delivers the
/// exact block over real sockets, and what does not depend on how many there are
/// (bytes per peer) meets the budget for a full 128-validator set.
#[test]
fn a_block_at_the_size_cap_reaches_every_validator_by_every_path_and_fits_the_budget() {
    measure(4);
}

/// The same at thirty-two validators, printed as a table. Slow (minutes, in a
/// build with no optimisation), so run on demand:
/// `cargo test -p chain-node --test propagation -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement: run it with --ignored --nocapture"]
fn measured_at_thirty_two_validators() {
    measure(MEASURED_RECEIVERS);
}

#[test]
fn putting_a_block_at_the_cap_together_from_the_pool_costs_little_of_the_round() {
    let proposed = full_block();
    let mut sender = BlockRelay::new();
    let compact = match sender.announce(&proposed) {
        NetworkMessage::CompactBlock(compact) => compact,
        other => panic!("{other:?}"),
    };
    // The pool holds this block's transactions among many others.
    let mut held = proposed.block.transactions.clone();
    held.extend((1_000_000..1_000_000 + 5_000).map(transaction));
    let pool = Pool(held);

    let mut times = Vec::new();
    for _ in 0..7 {
        let mut relay = BlockRelay::new();
        let started = Instant::now();
        let got = relay.receive_compact(
            compact.clone(),
            chain_p2p::PeerId::from_bytes([1; 32]),
            Some(validator(1)),
            &pool,
            42,
        );
        times.push(started.elapsed());
        assert!(matches!(got, Received::Block(block) if *block == proposed));
    }
    times.sort();
    eprintln!(
        "\nrebuilding a {}-transaction block from a pool of {}: median {:.0} ms, slowest {:.0} ms (a debug build)",
        proposed.block.transactions.len(),
        pool.0.len(),
        times[times.len() / 2].as_secs_f64() * 1000.0,
        times[times.len() - 1].as_secs_f64() * 1000.0
    );
    // A tenth of the two-second round, on a build with no optimisation at all.
    assert!(times[times.len() / 2] < Duration::from_secs(1));
}
