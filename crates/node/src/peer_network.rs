//! The node's connections to its peers: threads and bounded queues around
//! `chain-p2p`'s authenticated transport.
//!
//! [`PeerNetwork`] keeps a node connected to a static set of trusted peers and
//! moves messages between them and the node's event loop, and nothing else.
//! What the messages mean is the host's business; who is trusted is the
//! transport's; when to send and what to do with what arrives is the caller's.
//!
//! **Who dials whom.** For each pair of peers, the one with the lower
//! [`PeerId`] dials and the other accepts. Both sides then agree, without
//! talking, on which of them is responsible for a link, so there are no
//! simultaneous duplicate connections to sort out. A dialer that fails, or
//! whose connection ends, tries again after a delay that doubles up to a
//! ceiling and resets when a connection is made.
//!
//! **Threads.** One acceptor, which takes TCP connections and does nothing
//! else; a bounded set of short-lived handshake threads, so a stranger that
//! connects and stays silent occupies one of them for its timeout and no
//! more; one dialer per peer this node dials; and a reader and a writer per
//! live connection. Every thread checks the shutdown flag at least every few
//! tens of milliseconds, and [`PeerNetwork::shutdown`] joins them.
//!
//! **Bounds.** Everything that can grow is bounded, and each bound has a
//! stated policy.
//!
//! - *Outgoing:* a queue per peer. [`PeerNetwork::send`] never blocks: a
//!   message that does not fit is dropped and counted. Consensus tolerates a
//!   lost message (a node that missed a height asks for it), and a peer that
//!   cannot keep up is disconnected by the write timeout.
//! - *Incoming:* one queue for the whole node. A reader whose message does not
//!   fit waits, and stops reading from its socket while it waits, so a slow
//!   consumer pushes back on the sender through TCP instead of buffering.
//! - *Handshakes:* at most [`MAX_PENDING_HANDSHAKES`] at once; further
//!   connections are closed on arrival and counted.
//!
//! The transport has already checked every message that arrives: its size
//! against the budgets, its signature, its strict decoding, and (for consensus
//! messages) the verifier the node gave it.

// The wall clock is what a socket's timeouts, a redial's backoff and a wait for
// peers are measured in. None of it feeds the deterministic state transition
// that `clippy.toml`'s rule on `Instant::now` protects; see the note there.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chain_p2p::{
    ConnectionCloser, NetworkError, NetworkMessage, PeerConnection, PeerId, PendingConnection,
    TcpNetwork, TrustedPeer,
};
use chain_types::Address;

use crate::runtime::Recipient;

/// The most connections that may be mid-handshake at once.
pub const MAX_PENDING_HANDSHAKES: usize = 16;

/// How often a waiting thread looks at the shutdown flag.
const POLL: Duration = Duration::from_millis(25);
/// How long a writer waits for something to send before it checks its flag.
const WRITER_POLL: Duration = Duration::from_millis(50);
/// How long [`PeerNetwork::shutdown`] waits for connection threads to finish.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(10);

/// The moment `after` from now (the moment itself if that cannot be counted).
fn deadline(after: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(after).unwrap_or(now)
}

/// A peer this node keeps a connection to.
#[derive(Debug, Clone, Copy)]
pub struct PeerLink {
    /// Its transport key and address.
    pub peer: TrustedPeer,
    /// The validator it is, if it is one, so a message for that validator can
    /// be sent by address.
    pub validator: Option<Address>,
}

/// The sizes and delays. **Choices**, not protocol.
#[derive(Debug, Clone, Copy)]
pub struct PeerNetworkConfig {
    /// Messages waiting for the node's event loop, across all peers.
    pub inbound_queue: usize,
    /// Messages waiting to be written, per peer.
    pub outbound_queue: usize,
    /// The first delay before redialling a peer.
    pub reconnect_initial: Duration,
    /// The longest delay before redialling a peer.
    pub reconnect_max: Duration,
}

impl Default for PeerNetworkConfig {
    fn default() -> Self {
        Self {
            inbound_queue: 1_024,
            outbound_queue: 256,
            reconnect_initial: Duration::from_millis(100),
            reconnect_max: Duration::from_secs(5),
        }
    }
}

/// A message from a peer.
#[derive(Debug, Clone)]
pub struct Inbound {
    pub from: PeerId,
    pub message: NetworkMessage,
}

/// What became of a message handed to [`PeerNetwork::send`], counted per peer
/// it was meant for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SendReport {
    /// Queued to be written.
    pub queued: usize,
    /// Dropped because that peer's queue was full.
    pub dropped: usize,
    /// Not sent because that peer is not connected, or is not a peer.
    pub unreachable: usize,
}

/// Counters since the network started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetworkStats {
    /// Peers connected now.
    pub connected: usize,
    /// Connections made, in either direction.
    pub connections_made: u64,
    /// Messages dropped because a peer's outgoing queue was full.
    pub dropped_outgoing: u64,
    /// Connections closed on arrival because too many handshakes were under way.
    pub refused_handshakes: u64,
    /// Handshakes that ended in failure: an unknown key, a bad signature, a
    /// timeout, a peer already connected.
    pub failed_handshakes: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A thread that panicked holding a lock left data that is still valid for
    // everything kept behind these: counters, maps of handles.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A connection that is up.
struct Live {
    id: u64,
    outgoing: SyncSender<NetworkMessage>,
    closer: Arc<ConnectionCloser>,
}

/// One connection's own state, shared by its threads.
struct ConnectionState {
    id: u64,
    alive: AtomicBool,
}

struct Shared {
    network: TcpNetwork,
    links: BTreeMap<PeerId, PeerLink>,
    by_validator: BTreeMap<Address, PeerId>,
    config: PeerNetworkConfig,
    live: Mutex<BTreeMap<PeerId, Live>>,
    inbound: SyncSender<Inbound>,
    shutdown: AtomicBool,
    next_connection: AtomicU64,
    /// Threads still running, so shutdown can wait for them.
    running: (Mutex<usize>, Condvar),
    pending_handshakes: AtomicUsize,
    connections_made: AtomicU64,
    dropped_outgoing: AtomicU64,
    refused_handshakes: AtomicU64,
    failed_handshakes: AtomicU64,
}

impl Shared {
    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Sleeps `duration`, or until shutdown, checking every [`POLL`].
    fn sleep_unless_stopping(&self, duration: Duration) {
        let end = deadline(duration);
        while !self.stopping() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            thread::sleep(left.min(POLL));
        }
    }
}

/// Counts a thread as running for as long as it lives.
struct Running(Arc<Shared>);

impl Running {
    fn new(shared: &Arc<Shared>) -> Self {
        let mut count = lock(&shared.running.0);
        *count = count.saturating_add(1);
        drop(count);
        Self(Arc::clone(shared))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let mut count = lock(&self.0.running.0);
        *count = count.saturating_sub(1);
        self.0.running.1.notify_all();
    }
}

fn spawn(
    shared: &Arc<Shared>,
    name: &str,
    body: impl FnOnce() + Send + 'static,
) -> std::io::Result<JoinHandle<()>> {
    let running = Running::new(shared);
    thread::Builder::new().name(name.to_owned()).spawn(move || {
        let _running = running;
        body();
    })
}

/// A node's connections to its peers. See the module docs.
pub struct PeerNetwork {
    shared: Arc<Shared>,
    inbound: Mutex<Receiver<Inbound>>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl PeerNetwork {
    /// Starts keeping this node connected to `links`, over `network` (already
    /// bound, with the verifier and the trusted set it needs). The node's own
    /// address and key are the network's.
    ///
    /// Fails if a link is to this node itself, or repeats a peer or a
    /// validator, or a queue or a delay is zero.
    pub fn start(
        network: TcpNetwork,
        links: Vec<PeerLink>,
        config: PeerNetworkConfig,
    ) -> Result<Self, NetworkError> {
        if config.inbound_queue == 0
            || config.outbound_queue == 0
            || config.reconnect_initial.is_zero()
            || config.reconnect_max < config.reconnect_initial
        {
            return Err(NetworkError::InvalidConfiguration);
        }
        let me = network.peer_id();
        let mut by_peer = BTreeMap::new();
        let mut by_validator = BTreeMap::new();
        for link in links {
            let peer = link.peer.peer_id();
            if peer == me || by_peer.insert(peer, link).is_some() {
                return Err(NetworkError::InvalidConfiguration);
            }
            if let Some(validator) = link.validator {
                if by_validator.insert(validator, peer).is_some() {
                    return Err(NetworkError::InvalidConfiguration);
                }
            }
        }
        let (inbound_sender, inbound_receiver) = sync_channel(config.inbound_queue);
        let shared = Arc::new(Shared {
            network,
            links: by_peer,
            by_validator,
            config,
            live: Mutex::new(BTreeMap::new()),
            inbound: inbound_sender,
            shutdown: AtomicBool::new(false),
            next_connection: AtomicU64::new(0),
            running: (Mutex::new(0), Condvar::new()),
            pending_handshakes: AtomicUsize::new(0),
            connections_made: AtomicU64::new(0),
            dropped_outgoing: AtomicU64::new(0),
            refused_handshakes: AtomicU64::new(0),
            failed_handshakes: AtomicU64::new(0),
        });

        let mut threads = Vec::new();
        let acceptor = Arc::clone(&shared);
        threads.push(
            spawn(&shared, "peer-accept", move || accept_loop(&acceptor))
                .map_err(NetworkError::Io)?,
        );
        // Dial the peers with a higher id; they dial us if lower.
        for peer in shared.links.keys().copied().filter(|peer| *peer > me) {
            let dialer = Arc::clone(&shared);
            threads.push(
                spawn(&shared, "peer-dial", move || dial_loop(&dialer, peer))
                    .map_err(NetworkError::Io)?,
            );
        }
        Ok(Self {
            shared,
            inbound: Mutex::new(inbound_receiver),
            threads: Mutex::new(threads),
        })
    }

    /// The address this node is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        self.shared.network.local_addr()
    }

    /// This node's transport identity.
    pub fn peer_id(&self) -> PeerId {
        self.shared.network.peer_id()
    }

    /// Queues `message` for the peer or peers `to` names, without waiting. See
    /// the module docs for what happens when a queue is full.
    pub fn send(&self, to: &Recipient, message: &NetworkMessage) -> SendReport {
        let live = lock(&self.shared.live);
        let mut report = SendReport::default();
        let peers: Vec<PeerId> = match to {
            Recipient::All => live.keys().copied().collect(),
            Recipient::Validator(address) => match self.shared.by_validator.get(address) {
                Some(peer) => vec![*peer],
                None => {
                    report.unreachable = 1;
                    return report;
                }
            },
        };
        for peer in peers {
            let Some(connection) = live.get(&peer) else {
                report.unreachable = report.unreachable.saturating_add(1);
                continue;
            };
            match connection.outgoing.try_send(message.clone()) {
                Ok(()) => report.queued = report.queued.saturating_add(1),
                Err(_) => {
                    report.dropped = report.dropped.saturating_add(1);
                    self.shared.dropped_outgoing.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        report
    }

    /// The next message from any peer, waiting up to `timeout`.
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Inbound> {
        lock(&self.inbound).recv_timeout(timeout).ok()
    }

    /// The peers connected now.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        lock(&self.shared.live).keys().copied().collect()
    }

    /// Waits until at least `count` peers are connected, up to `timeout`.
    pub fn wait_for_peers(&self, count: usize, timeout: Duration) -> bool {
        let end = deadline(timeout);
        loop {
            if lock(&self.shared.live).len() >= count {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            thread::sleep(POLL);
        }
    }

    /// The validator a peer is, if it was configured as one.
    pub fn validator_of(&self, peer: PeerId) -> Option<Address> {
        self.shared.links.get(&peer).and_then(|link| link.validator)
    }

    /// Counters since the network started.
    pub fn stats(&self) -> NetworkStats {
        NetworkStats {
            connected: lock(&self.shared.live).len(),
            connections_made: self.shared.connections_made.load(Ordering::Relaxed),
            dropped_outgoing: self.shared.dropped_outgoing.load(Ordering::Relaxed),
            refused_handshakes: self.shared.refused_handshakes.load(Ordering::Relaxed),
            failed_handshakes: self.shared.failed_handshakes.load(Ordering::Relaxed),
        }
    }

    /// Closes every connection, stops every thread and waits for them, so the
    /// listening port is free when this returns. Also done on drop.
    pub fn shutdown(&self) {
        if !self.shared.shutdown.swap(true, Ordering::AcqRel) {
            wake_acceptor(&self.shared);
        }
        for connection in lock(&self.shared.live).values() {
            connection.closer.close();
        }
        let handles: Vec<JoinHandle<()>> = lock(&self.threads).drain(..).collect();
        for handle in handles {
            let _ = handle.join();
        }
        // Handshake, reader and writer threads are not joined one by one;
        // each is counted, and they finish within a poll or a timeout.
        let end = deadline(SHUTDOWN_WAIT);
        let mut count = lock(&self.shared.running.0);
        while *count > 0 {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            count = self
                .shared
                .running
                .1
                .wait_timeout(count, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

impl Drop for PeerNetwork {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Connects to the listener so a blocked `accept` returns and sees the flag.
fn wake_acceptor(shared: &Shared) {
    if let Ok(address) = shared.network.local_addr() {
        let target = if address.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), address.port())
        } else {
            address
        };
        let _ = TcpStream::connect_timeout(&target, Duration::from_millis(200));
    }
}

fn accept_loop(shared: &Arc<Shared>) {
    while !shared.stopping() {
        match shared.network.accept_pending() {
            Ok(pending) => {
                if shared.stopping() {
                    return;
                }
                begin_handshake(shared, pending);
            }
            // Something went wrong with the listener or one connection; do
            // not spin on it.
            Err(_) => shared.sleep_unless_stopping(POLL),
        }
    }
}

/// Authenticates `pending` on its own short-lived thread, if there is room.
fn begin_handshake(shared: &Arc<Shared>, pending: PendingConnection) {
    if shared.pending_handshakes.fetch_add(1, Ordering::AcqRel) >= MAX_PENDING_HANDSHAKES {
        shared.pending_handshakes.fetch_sub(1, Ordering::AcqRel);
        shared.refused_handshakes.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let handshaker = Arc::clone(shared);
    let spawned = spawn(shared, "peer-handshake", move || {
        match pending.authenticate() {
            Ok(connection) => {
                attach(&handshaker, connection);
            }
            Err(_) => {
                handshaker.failed_handshakes.fetch_add(1, Ordering::Relaxed);
            }
        }
        handshaker.pending_handshakes.fetch_sub(1, Ordering::AcqRel);
    });
    if spawned.is_err() {
        shared.pending_handshakes.fetch_sub(1, Ordering::AcqRel);
    }
}

fn dial_loop(shared: &Arc<Shared>, peer: PeerId) {
    let mut delay = shared.config.reconnect_initial;
    while !shared.stopping() {
        match shared.network.connect(peer) {
            Ok(connection) => {
                if let Some(state) = attach(shared, connection) {
                    delay = shared.config.reconnect_initial;
                    while state.alive.load(Ordering::Acquire) && !shared.stopping() {
                        thread::sleep(POLL);
                    }
                }
                shared.sleep_unless_stopping(shared.config.reconnect_initial);
            }
            Err(_) => {
                shared.sleep_unless_stopping(delay);
                delay = delay.saturating_mul(2).min(shared.config.reconnect_max);
            }
        }
    }
}

/// Starts the threads of an authenticated connection and records it as live,
/// replacing any earlier one for the same peer. `None` if it could not start.
fn attach(shared: &Arc<Shared>, connection: PeerConnection) -> Option<Arc<ConnectionState>> {
    let peer = connection.peer_id();
    let (mut reader, mut writer, closer) = connection.split().ok()?;
    let closer = Arc::new(closer);
    let (outgoing, queue) = sync_channel::<NetworkMessage>(shared.config.outbound_queue);
    let state = Arc::new(ConnectionState {
        id: shared.next_connection.fetch_add(1, Ordering::AcqRel),
        alive: AtomicBool::new(true),
    });

    let writer_shared = Arc::clone(shared);
    let writer_state = Arc::clone(&state);
    let writer_closer = Arc::clone(&closer);
    let writing = spawn(shared, "peer-write", move || {
        while writer_state.alive.load(Ordering::Acquire) && !writer_shared.stopping() {
            match queue.recv_timeout(WRITER_POLL) {
                Ok(message) => {
                    if writer.send(&message).is_err() {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        end_connection(&writer_shared, peer, &writer_state, &writer_closer);
    });
    if writing.is_err() {
        closer.close();
        return None;
    }

    let reader_shared = Arc::clone(shared);
    let reader_state = Arc::clone(&state);
    let reader_closer = Arc::clone(&closer);
    let reading = spawn(shared, "peer-read", move || {
        while reader_state.alive.load(Ordering::Acquire) && !reader_shared.stopping() {
            match reader.receive_or_idle() {
                Ok(Some(message)) => {
                    let inbound = Inbound {
                        from: peer,
                        message,
                    };
                    if !deliver(&reader_shared, &reader_state, inbound) {
                        break;
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
        end_connection(&reader_shared, peer, &reader_state, &reader_closer);
    });
    if reading.is_err() {
        end_connection(shared, peer, &state, &closer);
        return None;
    }

    if let Some(replaced) = lock(&shared.live).insert(
        peer,
        Live {
            id: state.id,
            outgoing,
            closer,
        },
    ) {
        replaced.closer.close();
    }
    shared.connections_made.fetch_add(1, Ordering::Relaxed);
    Some(state)
}

/// Puts `inbound` in the node's queue, waiting for room while the connection
/// lives. `false` if the connection or the network ended first.
fn deliver(shared: &Shared, state: &ConnectionState, mut inbound: Inbound) -> bool {
    loop {
        match shared.inbound.try_send(inbound) {
            Ok(()) => return true,
            Err(TrySendError::Full(back)) => {
                if shared.stopping() || !state.alive.load(Ordering::Acquire) {
                    return false;
                }
                inbound = back;
                thread::sleep(Duration::from_millis(2));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// Marks a connection over, closes its socket so the peer sees it, and
/// forgets it (unless a newer connection for the peer has replaced it).
fn end_connection(
    shared: &Shared,
    peer: PeerId,
    state: &ConnectionState,
    closer: &ConnectionCloser,
) {
    state.alive.store(false, Ordering::Release);
    closer.close();
    let mut live = lock(&shared.live);
    if live
        .get(&peer)
        .is_some_and(|connection| connection.id == state.id)
    {
        live.remove(&peer);
    }
}
