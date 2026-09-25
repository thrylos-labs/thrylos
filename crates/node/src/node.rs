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
use chain_rpc::{Server, ServerConfig, ServerError};
use chain_types::beacon::genesis_seed;
use chain_types::{Address, BlockHeight, Transaction};

use crate::clock::{now_ms, SystemClock};
use crate::config::{read_network_key, ConfigError, NodeConfig};
use crate::disk::NodeDisk;
use crate::durable_engine::{DurableEngine, OpenError};
use crate::event_loop::{EventLoop, NodeEvent};
use crate::peer_network::{PeerLink, PeerNetwork};
use crate::remote_signer::{RemoteSigner, RemoteSignerError, SignerCredential};
use crate::rpc_api::NodeApi;
use crate::runtime::NodeRuntime;
use crate::txpool::{NodeMempool, SharedEngine};
use crate::verifier::SenderBoundVerifier;

/// Why a node did not start, or why it stopped.
#[derive(Debug)]
pub enum RunError {
    Config(ConfigError),
    /// The genesis file could not be read or is not valid.
    Genesis(String),
    /// The local validator and its authenticated validator peers do not
    /// exactly cover the validator membership fixed in genesis.
    Topology(String),
    /// The chain could not be started or restored.
    Chain(OpenError),
    /// The node's own files could not be opened.
    Storage(StorageError),
    /// The signer process could not be reached.
    Signer(RemoteSignerError),
    /// The network could not be started.
    Network(NetworkError),
    /// The RPC could not be started.
    Rpc(ServerError),
    /// The consensus host stopped.
    Halted(HaltReason),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Genesis(error) => write!(f, "genesis: {error}"),
            Self::Topology(error) => write!(f, "validator topology: {error}"),
            Self::Chain(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "the node's files: {error}"),
            Self::Signer(error) => write!(f, "the signer: {error}"),
            Self::Network(error) => write!(f, "the network: {error}"),
            Self::Rpc(error) => write!(f, "{error}"),
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

fn check_validator_topology(
    local: Address,
    peers: &[crate::config::PeerSpec],
    validators: &[Address],
) -> Result<(), RunError> {
    if !validators.contains(&local) {
        return Err(RunError::Topology(format!(
            "this node's validator {} is not in genesis",
            chain_text::format_address(&local)
        )));
    }
    for peer in peers {
        if let Some(validator) = peer.validator {
            if !validators.contains(&validator) {
                return Err(RunError::Topology(format!(
                    "configured peer {} is not a genesis validator",
                    chain_text::format_address(&validator)
                )));
            }
        }
    }
    for validator in validators {
        if *validator != local && !peers.iter().any(|peer| peer.validator == Some(*validator)) {
            return Err(RunError::Topology(format!(
                "genesis validator {} has no authenticated peer",
                chain_text::format_address(validator)
            )));
        }
    }
    Ok(())
}

/// A node with no transactions to offer: it proposes empty blocks. The node
/// itself has a pool ([`NodeMempool`]); this is for a caller that wants a host
/// without one.
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
    let validators: Vec<Address> = genesis
        .validators()
        .iter()
        .map(|validator| Address::from_public_key(&validator.operator))
        .collect();
    check_validator_topology(config.validator, &config.peers, &validators)?;
    let identity = read_network_key(&config.network_key)?;

    // The signer first: a node that cannot sign must not start, and finding
    // that out creates nothing on disk.
    let signer = RemoteSigner::connect(
        &config.signer_socket,
        SignerCredential::read(&config.signer_credential)?,
        config.signer_timeout,
    )?;
    // The chain is shared with the transaction pool, which reads the accounts
    // and the base fee that transactions are checked and chosen against.
    let engine = SharedEngine::new(DurableEngine::open(&config.data_dir, &genesis)?);
    let pool = NodeMempool::new(engine.clone(), genesis.chain_id());
    let disk = NodeDisk::open(&config.data_dir).map_err(RunError::Storage)?;
    let ports = disk.into_ports(pool.clone(), SystemClock, signer);
    let host = Host::new(
        HostConfig {
            min_block_interval_ms: u64::try_from(config.block_interval.as_millis())
                .unwrap_or(u64::MAX),
            ..HostConfig::default()
        },
        config.validator,
        engine.clone(),
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

    // The RPC comes last, so that the node never accepts a call before it can
    // answer one.
    let rpc = match config.rpc_listen {
        Some(listen) => Some(Server::start(ServerConfig::at(listen)).map_err(RunError::Rpc)?),
        None => None,
    };

    let mut event_loop = EventLoop::new(NodeRuntime::new(host), peers, pool.clone(), now_ms);
    // The server stops, and gives up its port, when this goes out of scope.
    let _rpc_server = match rpc {
        Some((server, inbox)) => {
            event_loop = event_loop.with_rpc(Box::new(NodeApi::new(
                engine,
                pool,
                inbox,
                genesis.chain_id(),
                genesis.hash(),
                config.validator,
                config.rpc_simulate,
            )));
            Some(server)
        }
        None => None,
    };
    if let Some(height) = stop_at {
        event_loop = event_loop.stopping_at(height);
    }
    event_loop.run(stop, report).map_err(RunError::Halted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerSpec;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn address(byte: u8) -> Address {
        Address::from_bytes([byte; 32])
    }

    fn peer(byte: u8, validator: Option<Address>) -> PeerSpec {
        PeerSpec {
            address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                10_000u16.saturating_add(u16::from(byte)),
            ),
            public_key: [byte; 32],
            validator,
        }
    }

    #[test]
    fn validator_peers_must_exactly_cover_the_other_genesis_validators() {
        let validators = [address(1), address(2), address(3)];
        let complete = [
            peer(2, Some(address(2))),
            peer(3, Some(address(3))),
            peer(9, None),
        ];
        assert!(check_validator_topology(address(1), &complete, &validators).is_ok());

        let missing = [peer(2, Some(address(2)))];
        assert!(matches!(
            check_validator_topology(address(1), &missing, &validators),
            Err(RunError::Topology(problem)) if problem.contains("has no authenticated peer")
        ));

        let outsider = [
            peer(2, Some(address(2))),
            peer(3, Some(address(3))),
            peer(4, Some(address(4))),
        ];
        assert!(matches!(
            check_validator_topology(address(1), &outsider, &validators),
            Err(RunError::Topology(problem)) if problem.contains("is not a genesis validator")
        ));
    }

    #[test]
    fn the_local_validator_must_be_in_genesis() {
        assert!(matches!(
            check_validator_topology(address(9), &[], &[address(1)]),
            Err(RunError::Topology(problem)) if problem.contains("is not in genesis")
        ));
    }
}
