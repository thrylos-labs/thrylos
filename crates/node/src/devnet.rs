//! A local development network, as files.
//!
//! **INSECURE. FOR DEVELOPMENT ONLY.** [`generate`] writes everything a network
//! of validators needs to run on one machine, for the development genesis of
//! `chain-genesis`: its consensus keys are derived from public seeds, so anyone
//! can compute every secret. What is fresh on each run are the things that are
//! not in the genesis: each node's transport key and its signer's credential,
//! so two generated networks never accept each other's connections.
//!
//! ```text
//! <dir>/
//!   node1/
//!     node.json           the configuration `chain-node run` takes
//!     genesis.json        the same in every node's directory
//!     network.key         the transport key                       (private)
//!     signer.key          the consensus key `chain-signer` holds  (private)
//!     signer.credential   what the node shows the signer          (private)
//!   node2/ ...
//! ```
//!
//! Running a node adds `signer.sock`, `signer.mark` and `data/` beside them.
//! Each directory is complete on its own, so it can be moved to another machine
//! as a unit (after changing the addresses in `node.json`).
//!
//! Generation is all or nothing: the files are written into a scratch directory
//! beside the target and moved into place at the end, so a failure leaves
//! nothing behind, and a directory that already holds anything is refused
//! before a byte is written, so no key is ever overwritten.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use blst::min_pk::SecretKey;
use chain_genesis::devnet;
use chain_genesis::hex;
use chain_p2p::{NetworkIdentity, MAX_CONNECTED_PEERS};
use chain_text::format_address;
use chain_types::Address;

/// The most validators a network may have: each node lists every other as a
/// peer, and a node keeps at most [`MAX_CONNECTED_PEERS`].
pub const MAX_VALIDATORS: usize = MAX_CONNECTED_PEERS + 1;

/// The fewest. One validator has no one to wait for, so its blocks come at the
/// pace and no faster (`HostConfig::min_block_interval_ms`); that is why the
/// pace may not be zero.
pub const MIN_VALIDATORS: usize = 1;

/// The first node's port unless told otherwise; the rest follow it.
pub const DEFAULT_BASE_PORT: u16 = 26_656;

/// The longest path `signer.sock` may have. A Unix socket's address holds 104
/// bytes on macOS and 108 on Linux, and a longer path fails when the signer
/// binds, long after generation would have seemed to work.
pub const MAX_SOCKET_PATH: usize = 100;

pub const NODE_CONFIG: &str = "node.json";
pub const GENESIS: &str = "genesis.json";
pub const NETWORK_KEY: &str = "network.key";
pub const SIGNER_KEY: &str = "signer.key";
pub const SIGNER_CREDENTIAL: &str = "signer.credential";
pub const SIGNER_MARK: &str = "signer.mark";
pub const SIGNER_SOCKET: &str = "signer.sock";
pub const SIGNER_LOG: &str = "signer.log";
pub const NODE_LOG: &str = "node.log";
pub(crate) const DIRECTORY_PREFIX: &str = "node";

/// Why a network could not be generated or found.
#[derive(Debug)]
pub enum DevnetError {
    /// The number of validators is not one the network supports.
    Validators(usize),
    /// The ports (two for each validator: one for peers, one for the RPC) do not
    /// fit between `base` and 65535.
    Ports { base: u16, validators: usize },
    /// The block interval is zero.
    BlockInterval,
    /// The target directory exists and holds something.
    NotEmpty(PathBuf),
    /// The signer's socket would have a path too long to bind.
    SocketPathTooLong { path: PathBuf, length: usize },
    /// A file or directory could not be made or read.
    Io { path: PathBuf, error: String },
    /// The genesis could not be made.
    Genesis(String),
    /// The operating system gave no randomness for a key.
    Randomness,
    /// The directory holds no generated network.
    NoNetwork(PathBuf),
}

impl core::fmt::Display for DevnetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Validators(count) => write!(
                f,
                "a network of {count} validators is not supported; use {MIN_VALIDATORS} to \
                 {MAX_VALIDATORS}"
            ),
            Self::Ports { base, validators } => write!(
                f,
                "two ports for each of {validators} validators, from {base}, do not fit below 65536"
            ),
            Self::BlockInterval => write!(
                f,
                "the block interval must not be zero: a validator with no one to wait for \
                 would commit blocks without end"
            ),
            Self::NotEmpty(path) => write!(
                f,
                "{} already exists and is not empty; nothing was written (a network is \
                 never generated over existing files)",
                path.display()
            ),
            Self::SocketPathTooLong { path, length } => write!(
                f,
                "the signer socket {} would be {length} bytes long, and a Unix socket \
                 path may be at most {MAX_SOCKET_PATH}: {} bytes too many. Choose a \
                 shorter directory, for example /tmp/thrylos-devnet",
                path.display(),
                length.saturating_sub(MAX_SOCKET_PATH)
            ),
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Genesis(error) => write!(f, "genesis: {error}"),
            Self::Randomness => write!(f, "the operating system has no randomness for a key"),
            Self::NoNetwork(path) => write!(
                f,
                "{} holds no generated network (no node1/node.json); make one with \
                 `chain-node devnet init`",
                path.display()
            ),
        }
    }
}

impl std::error::Error for DevnetError {}

pub(crate) fn io(path: &Path, error: impl core::fmt::Display) -> DevnetError {
    DevnetError::Io {
        path: path.to_path_buf(),
        error: error.to_string(),
    }
}

/// A node that was generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevnetNode {
    /// From 1.
    pub number: usize,
    pub dir: PathBuf,
    pub listen: SocketAddr,
    /// Where its RPC listens.
    pub rpc: SocketAddr,
    pub validator: Address,
    /// The key its peers list to trust it.
    pub network_public_key: [u8; 32],
}

/// One node's directory inside a generated network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDir {
    pub number: usize,
    pub dir: PathBuf,
}

impl NodeDir {
    pub fn config(&self) -> PathBuf {
        self.dir.join(NODE_CONFIG)
    }

    pub fn signer_key(&self) -> PathBuf {
        self.dir.join(SIGNER_KEY)
    }

    pub fn signer_mark(&self) -> PathBuf {
        self.dir.join(SIGNER_MARK)
    }

    pub fn signer_log(&self) -> PathBuf {
        self.dir.join(SIGNER_LOG)
    }

    pub fn node_log(&self) -> PathBuf {
        self.dir.join(NODE_LOG)
    }
}

/// The node directories of the network in `dir`, in order of their numbers.
pub fn nodes_in(dir: &Path) -> Result<Vec<NodeDir>, DevnetError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(DevnetError::NoNetwork(dir.to_path_buf()));
        }
        Err(error) => return Err(io(dir, error)),
    };
    let mut nodes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io(dir, error))?;
        let name = entry.file_name();
        let Some(number) = name
            .to_str()
            .and_then(|name| name.strip_prefix(DIRECTORY_PREFIX))
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<usize>().ok())
        else {
            continue;
        };
        if entry.path().join(NODE_CONFIG).is_file() {
            nodes.push(NodeDir {
                number,
                dir: entry.path(),
            });
        }
    }
    if nodes.is_empty() {
        return Err(DevnetError::NoNetwork(dir.to_path_buf()));
    }
    nodes.sort_by_key(|node| node.number);
    Ok(nodes)
}

/// Everything decided about a node before any file is written.
struct Plan {
    number: usize,
    seed: u8,
    listen: SocketAddr,
    rpc: SocketAddr,
    validator: Address,
    network_secret: [u8; 32],
    network_public_key: [u8; 32],
    credential: [u8; 32],
}

/// 32 bytes from the operating system's randomness. Shared with
/// `crate::alpha`, which needs the same real key material this module's own
/// (insecure, seed-derived) genesis keys deliberately do not use.
pub(crate) fn random() -> Result<[u8; 32], DevnetError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| DevnetError::Randomness)?;
    Ok(bytes)
}

/// Creates a new file that only its owner can read or write, refusing to
/// replace one.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), DevnetError> {
    write_new(path, bytes, 0o600)
}

pub(crate) fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), DevnetError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| io(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io(path, error))
}

fn node_config_text(plan: &Plan, plans: &[Plan], block_interval_ms: u64) -> String {
    let peers: Vec<String> = plans
        .iter()
        .filter(|other| other.number != plan.number)
        .map(|other| {
            format!(
                r#"    {{
      "address": "{}",
      "public_key": "{}",
      "validator": "{}"
    }}"#,
                other.listen,
                hex::encode(&other.network_public_key),
                format_address(&other.validator)
            )
        })
        .collect();
    let peers = if peers.is_empty() {
        String::new()
    } else {
        format!("\n{}\n  ", peers.join(",\n"))
    };
    format!(
        r#"{{
  "data_dir": "data",
  "genesis": "{GENESIS}",
  "listen": "{}",
  "network_key": "{NETWORK_KEY}",
  "validator": "{}",
  "signer": {{ "socket": "{SIGNER_SOCKET}", "credential": "{SIGNER_CREDENTIAL}" }},
  "peers": [{peers}],
  "rpc": {{ "listen": "{}", "simulate": true }},
  "tuning": {{ "block_interval_ms": {block_interval_ms} }}
}}
"#,
        plan.listen,
        format_address(&plan.validator),
        plan.rpc
    )
}

/// Writes a network of `validators` nodes into `dir`, the first listening on
/// `base_port` on the loopback address and the rest on the ports after it, each
/// pacing its blocks `block_interval_ms` apart.
///
/// `dir` must not exist or must be empty. Either the whole network is written
/// or nothing is.
pub fn generate(
    dir: &Path,
    validators: usize,
    base_port: u16,
    block_interval_ms: u64,
) -> Result<Vec<DevnetNode>, DevnetError> {
    if block_interval_ms == 0 {
        return Err(DevnetError::BlockInterval);
    }
    if !(MIN_VALIDATORS..=MAX_VALIDATORS).contains(&validators) {
        return Err(DevnetError::Validators(validators));
    }
    let count = u8::try_from(validators).map_err(|_| DevnetError::Validators(validators))?;
    let ports_fit = base_port != 0
        && usize::from(base_port)
            .checked_add(validators.saturating_mul(2).saturating_sub(1))
            .is_some_and(|last| u16::try_from(last).is_ok());
    if !ports_fit {
        return Err(DevnetError::Ports {
            base: base_port,
            validators,
        });
    }

    let target = std::path::absolute(dir).map_err(|error| io(dir, error))?;
    match fs::read_dir(&target) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                return Err(DevnetError::NotEmpty(target));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        // Not a directory, or not readable: either way, not ours to replace.
        Err(_) => return Err(DevnetError::NotEmpty(target)),
    }
    let longest_socket = target
        .join(format!("{DIRECTORY_PREFIX}{validators}"))
        .join(SIGNER_SOCKET);
    let length = longest_socket.as_os_str().len();
    if length > MAX_SOCKET_PATH {
        return Err(DevnetError::SocketPathTooLong {
            path: longest_socket,
            length,
        });
    }

    let mut plans = Vec::with_capacity(validators);
    for seed in 1..=count {
        let network_secret = random()?;
        let operator =
            devnet::ed25519(seed).map_err(|error| DevnetError::Genesis(error.to_string()))?;
        let offset = u16::from(seed.saturating_sub(1));
        let ports_error = || DevnetError::Ports {
            base: base_port,
            validators,
        };
        let port = base_port.checked_add(offset).ok_or_else(ports_error)?;
        // The RPC ports follow the peer ports, one block after the other.
        let rpc_port = u16::try_from(validators)
            .ok()
            .and_then(|count| port.checked_add(count))
            .ok_or_else(ports_error)?;
        plans.push(Plan {
            number: usize::from(seed),
            seed,
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            rpc: SocketAddr::from((Ipv4Addr::LOCALHOST, rpc_port)),
            validator: Address::from_public_key(&operator),
            network_secret,
            network_public_key: NetworkIdentity::from_secret_bytes(network_secret).public_key(),
            credential: random()?,
        });
    }
    let genesis = chain_genesis::to_json(
        &devnet::config_with_validators(count)
            .map_err(|error| DevnetError::Genesis(error.to_string()))?,
    )
    .map_err(|error| DevnetError::Genesis(error.to_string()))?
        + "\n";

    let name = target
        .file_name()
        .ok_or_else(|| DevnetError::NotEmpty(target.clone()))?;
    let parent = target
        .parent()
        .ok_or_else(|| DevnetError::NotEmpty(target.clone()))?;
    fs::create_dir_all(parent).map_err(|error| io(parent, error))?;
    let mut scratch_name = std::ffi::OsString::from(".");
    scratch_name.push(name);
    scratch_name.push(".partial");
    let scratch = parent.join(scratch_name);
    fs::create_dir(&scratch).map_err(|error| {
        io(
            &scratch,
            format!("{error} (an earlier attempt may have left it; remove it and retry)"),
        )
    })?;

    let written = write_network(&scratch, &plans, &genesis, block_interval_ms).and_then(|()| {
        // Onto an empty directory, if there is one; onto nothing otherwise.
        fs::rename(&scratch, &target).map_err(|error| io(&target, error))
    });
    if let Err(error) = written {
        // The scratch directory is ours: made just above, holding only what
        // this call wrote.
        let _ = fs::remove_dir_all(&scratch);
        return Err(error);
    }

    Ok(plans
        .iter()
        .map(|plan| DevnetNode {
            number: plan.number,
            dir: target.join(format!("{DIRECTORY_PREFIX}{}", plan.number)),
            listen: plan.listen,
            rpc: plan.rpc,
            validator: plan.validator,
            network_public_key: plan.network_public_key,
        })
        .collect())
}

fn write_network(
    root: &Path,
    plans: &[Plan],
    genesis: &str,
    block_interval_ms: u64,
) -> Result<(), DevnetError> {
    for plan in plans {
        let dir = root.join(format!("{DIRECTORY_PREFIX}{}", plan.number));
        fs::create_dir(&dir).map_err(|error| io(&dir, error))?;
        write_new(&dir.join(GENESIS), genesis.as_bytes(), 0o644)?;

        let consensus_secret = SecretKey::key_gen(&[plan.seed; 32], &[])
            .map_err(|_| DevnetError::Genesis("could not derive a consensus key".to_owned()))?;
        write_private(&dir.join(SIGNER_KEY), &consensus_secret.to_bytes())?;
        write_private(&dir.join(SIGNER_CREDENTIAL), &plan.credential)?;
        let mut network_key = hex::encode(&plan.network_secret);
        network_key.push('\n');
        write_private(&dir.join(NETWORK_KEY), network_key.as_bytes())?;

        write_new(
            &dir.join(NODE_CONFIG),
            node_config_text(plan, plans, block_interval_ms).as_bytes(),
            0o644,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::config::{read_network_key, NodeConfig, DEFAULT_BLOCK_INTERVAL_MS};

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn generated(validators: usize) -> (tempfile::TempDir, PathBuf, Vec<DevnetNode>) {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        let nodes = generate(&dir, validators, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap();
        (root, dir, nodes)
    }

    #[test]
    fn a_network_is_written_whole_and_every_configuration_loads() {
        let (_root, dir, nodes) = generated(4);
        assert_eq!(nodes.len(), 4);
        for (index, node) in nodes.iter().enumerate() {
            assert_eq!(node.number, index + 1);
            assert_eq!(node.dir, dir.join(format!("node{}", index + 1)));
            let config = NodeConfig::load(&node.dir.join(NODE_CONFIG)).unwrap();
            assert_eq!(config.validator, node.validator);
            assert_eq!(config.listen, node.listen);
            // The RPC has an address of its own, on the loopback, in the ports
            // after every node's peer port.
            assert_eq!(config.rpc_listen, Some(node.rpc));
            assert!(node.rpc.ip().is_loopback());
            assert_eq!(node.rpc.port(), 30_000 + 4 + u16::try_from(index).unwrap());
            assert_eq!(config.listen.port(), 30_000 + u16::try_from(index).unwrap());
            assert!(config.listen.ip().is_loopback());
            assert_eq!(config.genesis, node.dir.join(GENESIS));
            assert_eq!(config.peers.len(), 3);
            // The key file the node reads is the one its peers were told.
            assert_eq!(
                read_network_key(&config.network_key).unwrap().public_key(),
                node.network_public_key
            );
        }
    }

    #[test]
    fn each_node_lists_every_other_by_the_key_and_address_that_node_really_has() {
        let (_root, _dir, nodes) = generated(4);
        for node in &nodes {
            let config = NodeConfig::load(&node.dir.join(NODE_CONFIG)).unwrap();
            let expected: Vec<_> = nodes
                .iter()
                .filter(|other| other.number != node.number)
                .collect();
            assert_eq!(config.peers.len(), expected.len());
            for other in expected {
                let peer = config
                    .peers
                    .iter()
                    .find(|peer| peer.public_key == other.network_public_key)
                    .unwrap();
                assert_eq!(peer.address, other.listen);
                assert_eq!(peer.validator, Some(other.validator));
            }
        }
    }

    #[test]
    fn the_genesis_is_the_development_genesis_and_holds_exactly_these_validators_and_keys() {
        let (_root, dir, nodes) = generated(4);
        // Four validators is the checked-in development genesis, byte for byte.
        let golden = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../genesis/examples/devnet.json"
        );
        for node in &nodes {
            assert_eq!(
                fs::read_to_string(node.dir.join(GENESIS)).unwrap(),
                fs::read_to_string(golden).unwrap()
            );
        }

        // Each signer key is the consensus key its validator has in the genesis.
        let genesis = chain_genesis::load(&dir.join("node1").join(GENESIS)).unwrap();
        for node in &nodes {
            let entry = genesis
                .validators()
                .iter()
                .find(|v| Address::from_public_key(&v.operator) == node.validator)
                .unwrap();
            let secret =
                SecretKey::from_bytes(&fs::read(node.dir.join(SIGNER_KEY)).unwrap()).unwrap();
            assert_eq!(secret.sk_to_pk().to_bytes(), entry.consensus_key.to_bytes());
        }
        assert_eq!(genesis.validators().len(), nodes.len());
    }

    #[test]
    fn secrets_are_private_and_nothing_else_needs_to_be() {
        let (_root, _dir, nodes) = generated(2);
        for node in &nodes {
            for secret in [NETWORK_KEY, SIGNER_KEY, SIGNER_CREDENTIAL] {
                assert_eq!(mode(&node.dir.join(secret)), 0o600, "{secret}");
            }
            assert_eq!(
                fs::read(node.dir.join(SIGNER_CREDENTIAL)).unwrap().len(),
                32
            );
        }
    }

    #[test]
    fn transport_keys_and_credentials_are_fresh_each_time_but_the_genesis_is_not() {
        let (_a, dir_a, _) = generated(2);
        let (_b, dir_b, _) = generated(2);
        for file in [NETWORK_KEY, SIGNER_CREDENTIAL] {
            assert_ne!(
                fs::read(dir_a.join("node1").join(file)).unwrap(),
                fs::read(dir_b.join("node1").join(file)).unwrap(),
                "{file}"
            );
        }
        assert_ne!(
            fs::read(dir_a.join("node1").join(NETWORK_KEY)).unwrap(),
            fs::read(dir_a.join("node2").join(NETWORK_KEY)).unwrap(),
            "nodes do not share a key"
        );
        assert_eq!(
            fs::read(dir_a.join("node1").join(GENESIS)).unwrap(),
            fs::read(dir_b.join("node1").join(GENESIS)).unwrap()
        );
    }

    #[test]
    fn a_network_of_one_has_no_peers_and_the_largest_lists_all_the_others() {
        let (_root, _dir, nodes) = generated(MIN_VALIDATORS);
        assert_eq!(nodes.len(), 1);
        let config = NodeConfig::load(&nodes[0].dir.join(NODE_CONFIG)).unwrap();
        assert!(config.peers.is_empty());

        let root = tempfile::tempdir().unwrap();
        let nodes = generate(
            &root.path().join("n"),
            MAX_VALIDATORS,
            20_000,
            DEFAULT_BLOCK_INTERVAL_MS,
        )
        .unwrap();
        assert_eq!(nodes.len(), MAX_VALIDATORS);
        let config = NodeConfig::load(&nodes[MAX_VALIDATORS - 1].dir.join(NODE_CONFIG)).unwrap();
        assert_eq!(config.peers.len(), MAX_VALIDATORS - 1);
    }

    #[test]
    fn an_unsupported_size_or_port_range_is_refused_before_anything_is_written() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        for validators in [0, MAX_VALIDATORS + 1] {
            let error = generate(&dir, validators, 30_000, DEFAULT_BLOCK_INTERVAL_MS)
                .unwrap_err()
                .to_string();
            assert!(error.contains("not supported"), "{error}");
        }
        for (base, validators) in [(0, 4), (65_529, 4), (65_534, 2), (65_535, 1)] {
            let error = generate(&dir, validators, base, DEFAULT_BLOCK_INTERVAL_MS)
                .unwrap_err()
                .to_string();
            assert!(error.contains("do not fit"), "{base}+{validators}: {error}");
        }
        assert!(
            generate(&dir, 4, 65_528, DEFAULT_BLOCK_INTERVAL_MS).is_ok(),
            "the last four ports fit"
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn no_two_addresses_in_a_network_are_the_same() {
        let (_root, _dir, nodes) = generated(MAX_VALIDATORS);
        let mut all: Vec<SocketAddr> = nodes.iter().flat_map(|n| [n.listen, n.rpc]).collect();
        let count = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), count);
    }

    #[test]
    fn the_block_interval_is_written_into_every_configuration_and_may_not_be_zero() {
        let (_root, _dir, nodes) = generated(2);
        for node in &nodes {
            let config = NodeConfig::load(&node.dir.join(NODE_CONFIG)).unwrap();
            assert_eq!(
                config.block_interval,
                std::time::Duration::from_millis(DEFAULT_BLOCK_INTERVAL_MS)
            );
        }

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        let nodes = generate(&dir, 2, 30_000, 250).unwrap();
        for node in &nodes {
            let config = NodeConfig::load(&node.dir.join(NODE_CONFIG)).unwrap();
            assert_eq!(config.block_interval, std::time::Duration::from_millis(250));
        }

        let other = root.path().join("other");
        let error = generate(&other, 2, 31_000, 0).unwrap_err().to_string();
        assert!(error.contains("must not be zero"), "{error}");
        assert!(!other.exists(), "nothing was written");
    }

    #[test]
    fn a_directory_that_holds_anything_is_refused_and_left_exactly_as_it_was() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("precious.key"), b"do not touch").unwrap();
        let error = generate(&dir, 4, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap_err();
        assert!(matches!(error, DevnetError::NotEmpty(_)), "{error}");
        assert_eq!(fs::read(dir.join("precious.key")).unwrap(), b"do not touch");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            1,
            "no scratch left"
        );

        // A file where the directory should be is refused too.
        let file = root.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            generate(&file, 4, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap_err(),
            DevnetError::NotEmpty(_)
        ));
        assert_eq!(fs::read(&file).unwrap(), b"x");
    }

    #[test]
    fn an_empty_existing_directory_is_used_and_a_second_run_is_then_refused() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        fs::create_dir(&dir).unwrap();
        generate(&dir, 2, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap();
        assert!(dir.join("node2").join(NODE_CONFIG).is_file());
        let key = fs::read(dir.join("node1").join(NETWORK_KEY)).unwrap();
        assert!(generate(&dir, 2, 30_000, DEFAULT_BLOCK_INTERVAL_MS).is_err());
        assert_eq!(fs::read(dir.join("node1").join(NETWORK_KEY)).unwrap(), key);
    }

    #[test]
    fn a_path_too_long_for_the_signer_socket_is_refused_with_nothing_left_behind() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("d".repeat(MAX_SOCKET_PATH));
        let error = generate(&dir, 2, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap_err();
        assert!(
            matches!(error, DevnetError::SocketPathTooLong { .. }),
            "{error}"
        );
        let message = error.to_string();
        assert!(message.contains("shorter directory"), "{message}");
        assert!(
            message.contains("for example /tmp/thrylos-devnet"),
            "{message}"
        );
        // It says how far over the limit it is, and the example is under it.
        let DevnetError::SocketPathTooLong { length, .. } = error else {
            unreachable!()
        };
        assert!(
            message.contains(&format!("{} bytes too many", length - MAX_SOCKET_PATH)),
            "{message}"
        );
        let example = Path::new("/tmp/thrylos-devnet")
            .join(format!("{DIRECTORY_PREFIX}{MAX_VALIDATORS}"))
            .join(SIGNER_SOCKET);
        assert!(
            example.as_os_str().len() <= MAX_SOCKET_PATH,
            "the suggestion must work"
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_failure_part_way_leaves_no_partial_network() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("net");
        // An earlier attempt's scratch directory is in the way: refused, and
        // it is not ours to delete.
        let stale = root.path().join(".net.partial");
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("x"), b"x").unwrap();
        let error = generate(&dir, 2, 30_000, DEFAULT_BLOCK_INTERVAL_MS)
            .unwrap_err()
            .to_string();
        assert!(error.contains("earlier attempt"), "{error}");
        assert!(stale.join("x").exists());
        assert!(!dir.exists());
    }

    #[test]
    fn a_failure_after_every_file_is_written_still_leaves_no_network_behind() {
        // The last step moves the finished network into place, and cannot move a
        // directory onto a symbolic link: everything has been written by then.
        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = root.path().join("net");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let error = generate(&link, 4, 30_000, DEFAULT_BLOCK_INTERVAL_MS).unwrap_err();
        assert!(matches!(error, DevnetError::Io { .. }), "{error}");
        assert!(
            !root.path().join(".net.partial").exists(),
            "scratch removed"
        );
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0, "nothing moved in");
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            2,
            "real and net only"
        );
    }

    #[test]
    fn nodes_in_finds_the_nodes_in_numeric_order_and_ignores_everything_else() {
        let (_root, dir, _) = generated(12);
        fs::create_dir(dir.join("node-extra")).unwrap();
        fs::create_dir(dir.join("nodeX")).unwrap();
        fs::create_dir(dir.join("node99")).unwrap(); // no node.json
        fs::write(dir.join("node13"), b"a file").unwrap();
        let numbers: Vec<usize> = nodes_in(&dir).unwrap().iter().map(|n| n.number).collect();
        assert_eq!(numbers, (1..=12).collect::<Vec<_>>());

        let empty = tempfile::tempdir().unwrap();
        assert!(matches!(
            nodes_in(empty.path()).unwrap_err(),
            DevnetError::NoNetwork(_)
        ));
        assert!(matches!(
            nodes_in(&empty.path().join("missing")).unwrap_err(),
            DevnetError::NoNetwork(_)
        ));
    }
}
