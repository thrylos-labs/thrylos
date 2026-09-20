//! Assembling a node from its configuration.
//!
//! [`run_node`] is everything the `chain-node` binary does once it has a
//! configuration: it opens the chain (from genesis, or restored from disk and
//! checked), opens the node's other files, connects to the signer process,
//! builds the consensus host, binds the peer network and runs the event loop
//! until it is told to stop or the host halts. It is a library function so a
//! test can start a real node, over real sockets and real databases, exactly
//! as the binary does.
//!
//! The order matters, and is the order that fails earliest and cheapest, before
//! anything is written: the configuration, the genesis and the transport key (a
//! typo costs nothing), then the signer (a node that cannot sign must not
//! start), then the chain and the node's files (which check themselves and
//! refuse damage), and only then the network, so a node never accepts a
//! connection before it can act on one.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use chain_consensus::host::{HaltReason, Host, HostConfig, StorageError, TransactionSource};
use chain_engine_api::Block;
use chain_p2p::{NetworkError, TcpNetwork, TransportConfig, TrustedPeer};
use chain_types::beacon::genesis_seed;
use chain_types::{BlockHeight, Transaction};

use crate::clock::{now_ms, SystemClock};
use crate::config::{read_network_key, ConfigError, NodeConfig};
use crate::disk::{DiskConfig, NodeDisk};
use crate::durable_engine::{DurableEngine, OpenError};
use crate::event_loop::{DiscardTransactions, EventLoop, NodeEvent};
use crate::peer_network::{PeerLink, PeerNetwork};
use crate::remote_signer::{RemoteSigner, RemoteSignerError, SignerCredential};
use crate::runtime::NodeRuntime;
use crate::verifier::SenderBoundVerifier;

/// Why a node did not start, or why it stopped.
#[derive(Debug)]
pub enum RunError {
    Config(ConfigError),
    /// The genesis file could not be read or is not valid.
    Genesis(String),
    /// The chain could not be started or restored.
    Chain(OpenError),
    /// The node's own files could not be opened.
    Storage(StorageError),
    /// The signer process could not be reached.
    Signer(RemoteSignerError),
    /// The network could not be started.
    Network(NetworkError),
    /// The consensus host stopped.
    Halted(HaltReason),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Genesis(error) => write!(f, "genesis: {error}"),
            Self::Chain(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "the node's files: {error}"),
            Self::Signer(error) => write!(f, "the signer: {error}"),
            Self::Network(error) => write!(f, "the network: {error}"),
            Self::Halted(reason) => write!(f, "the node stopped: {reason}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<ConfigError> for RunError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<OpenError> for RunError {
    fn from(error: OpenError) -> Self {
        Self::Chain(error)
    }
}

impl From<RemoteSignerError> for RunError {
    fn from(error: RemoteSignerError) -> Self {
        Self::Signer(error)
    }
}

impl From<NetworkError> for RunError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

/// A node with no mempool yet: it proposes empty blocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTransactions;

impl TransactionSource for NoTransactions {
    fn candidates(&mut self, _max: usize) -> Vec<Transaction> {
        Vec::new()
    }

    fn committed(&mut self, _block: &Block) {}
}

/// Runs the node `config` describes until `stop` is set, the host halts, or (if
/// given) the chain reaches `stop_at`. `report` hears of blocks committed,
/// equivocation witnessed and a halt as they happen.
pub fn run_node(
    config: &NodeConfig,
    stop_at: Option<BlockHeight>,
    stop: &AtomicBool,
    report: &mut dyn FnMut(NodeEvent),
) -> Result<(), RunError> {
    let genesis = chain_genesis::load(&config.genesis)
        .map_err(|error| RunError::Genesis(error.to_string()))?;
    let identity = read_network_key(&config.network_key)?;

    // The signer first: a node that cannot sign must not start, and finding
    // that out creates nothing on disk.
    let signer = RemoteSigner::connect(
        &config.signer_socket,
        SignerCredential::read(&config.signer_credential)?,
        config.signer_timeout,
    )?;
    let engine = DurableEngine::open(&config.data_dir, &genesis)?;
    let disk =
        NodeDisk::open(&config.data_dir, DiskConfig::default()).map_err(RunError::Storage)?;
    let ports = disk.into_ports(NoTransactions, SystemClock, signer);
    let host = Host::new(
        HostConfig {
            min_block_interval_ms: u64::try_from(config.block_interval.as_millis())
                .unwrap_or(u64::MAX),
            ..HostConfig::default()
        },
        config.validator,
        engine,
        ports,
        genesis_seed(&genesis.hash()),
    )
    .map_err(RunError::Halted)?;

    let mut trusted = Vec::with_capacity(config.peers.len());
    let mut links = Vec::with_capacity(config.peers.len());
    for peer in &config.peers {
        let trusted_peer = TrustedPeer::new(peer.address, peer.public_key)?;
        trusted.push(trusted_peer);
        links.push(PeerLink {
            peer: trusted_peer,
            validator: peer.validator,
        });
    }
    let verifier = SenderBoundVerifier::new(
        links
            .iter()
            .filter_map(|link| link.validator.map(|v| (link.peer.peer_id(), v))),
    );
    let network = TcpNetwork::bind(
        config.listen,
        identity,
        trusted,
        TransportConfig {
            io_timeout: config.io_timeout,
            ..TransportConfig::default()
        },
        Arc::new(verifier),
    )?;
    let peers = PeerNetwork::start(network, links, config.network)?;

    let mut event_loop = EventLoop::new(NodeRuntime::new(host), peers, DiscardTransactions, now_ms);
    if let Some(height) = stop_at {
        event_loop = event_loop.stopping_at(height);
    }
    event_loop.run(stop, report).map_err(RunError::Halted)
}
