//! The node's configuration file.
//!
//! One JSON file says where the node keeps its data, which genesis it runs,
//! where it listens, who its peers are and how it reaches its signer:
//!
//! ```json
//! {
//!   "data_dir": "data",
//!   "genesis": "genesis.json",
//!   "listen": "0.0.0.0:26656",
//!   "network_key": "network.key",
//!   "validator": "thry1…",
//!   "signer": { "socket": "signer.sock", "credential": "signer.credential" },
//!   "peers": [
//!     { "address": "10.0.0.2:26656", "public_key": "<64 hex digits>", "validator": "thry1…" }
//!   ]
//! }
//! ```
//!
//! The file names secrets and never holds one: the transport key and the
//! signer's credential are files of their own, refused unless only their owner
//! can read them. Validators are written as `thry1…` addresses, which catch a
//! mistyped character; the transport keys of peers are hex, like every key in
//! the genesis file.
//!
//! Every field is required except `tuning`, and an unknown field is an error, so
//! a misspelt setting cannot quietly leave a default in place. Relative paths
//! are relative to the directory of the file, so a node's directory can be
//! moved as a unit. Every error names the field it is about.

use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use chain_genesis::hex;
use chain_p2p::{NetworkIdentity, MAX_CONNECTED_PEERS};
use chain_text::parse_address;
use chain_types::Address;
use serde::Deserialize;

use crate::peer_network::PeerNetworkConfig;

/// A configuration file larger than this is refused unread.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Why a configuration could not be used.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Read { path: PathBuf, error: String },
    /// The file is not the JSON the node expects.
    Json(String),
    /// A field has a value that cannot be used.
    Invalid { field: String, problem: String },
    /// A key file could not be used.
    KeyFile { path: PathBuf, problem: String },
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Read { path, error } => {
                write!(
                    f,
                    "cannot read the configuration {}: {error}",
                    path.display()
                )
            }
            Self::Json(error) => write!(f, "the configuration is not valid: {error}"),
            Self::Invalid { field, problem } => write!(f, "configuration `{field}`: {problem}"),
            Self::KeyFile { path, problem } => write!(f, "{}: {problem}", path.display()),
        }
    }
}

impl std::error::Error for ConfigError {}

fn invalid(field: impl Into<String>, problem: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field: field.into(),
        problem: problem.into(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    data_dir: PathBuf,
    genesis: PathBuf,
    listen: SocketAddr,
    network_key: PathBuf,
    validator: String,
    signer: RawSigner,
    peers: Vec<RawPeer>,
    #[serde(default)]
    tuning: RawTuning,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSigner {
    socket: PathBuf,
    credential: PathBuf,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    address: SocketAddr,
    public_key: String,
    validator: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTuning {
    inbound_queue: Option<usize>,
    outbound_queue: Option<usize>,
    io_timeout_ms: Option<u64>,
    reconnect_initial_ms: Option<u64>,
    reconnect_max_ms: Option<u64>,
}

/// A peer the node keeps a connection to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerSpec {
    pub address: SocketAddr,
    pub public_key: [u8; 32],
    pub validator: Option<Address>,
}

/// A checked configuration, with paths resolved.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub genesis: PathBuf,
    pub listen: SocketAddr,
    pub network_key: PathBuf,
    /// The validator this node is.
    pub validator: Address,
    pub signer_socket: PathBuf,
    pub signer_credential: PathBuf,
    pub signer_timeout: Duration,
    pub peers: Vec<PeerSpec>,
    pub network: PeerNetworkConfig,
    /// How long a peer may take over a handshake or a stalled frame.
    pub io_timeout: Duration,
}

fn resolve(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn address_field(field: &str, text: &str) -> Result<Address, ConfigError> {
    parse_address(text).map_err(|error| invalid(field, error.to_string()))
}

impl NodeConfig {
    /// Reads and checks the configuration at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_error = |error: std::io::Error| ConfigError::Read {
            path: path.to_path_buf(),
            error: error.to_string(),
        };
        let size = std::fs::metadata(path).map_err(read_error)?.len();
        if size > MAX_CONFIG_BYTES {
            return Err(invalid(
                "file",
                format!("{size} bytes is larger than the {MAX_CONFIG_BYTES}-byte limit"),
            ));
        }
        let text = std::fs::read_to_string(path).map_err(read_error)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::parse(&text, base)
    }

    /// Checks `text` as a configuration whose relative paths are relative to
    /// `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self, ConfigError> {
        let raw: RawConfig =
            serde_json::from_str(text).map_err(|error| ConfigError::Json(error.to_string()))?;

        let validator = address_field("validator", &raw.validator)?;
        if raw.peers.len() > MAX_CONNECTED_PEERS {
            return Err(invalid(
                "peers",
                format!("at most {MAX_CONNECTED_PEERS} peers are supported"),
            ));
        }
        let mut peers: Vec<PeerSpec> = Vec::with_capacity(raw.peers.len());
        for (index, peer) in raw.peers.iter().enumerate() {
            let public_key = hex::decode::<32>(&peer.public_key).map_err(|error| {
                invalid(format!("peers[{index}].public_key"), error.to_string())
            })?;
            let peer_validator = peer
                .validator
                .as_deref()
                .map(|text| address_field(&format!("peers[{index}].validator"), text))
                .transpose()?;
            if peer_validator == Some(validator) {
                return Err(invalid(
                    format!("peers[{index}].validator"),
                    "that is this node's own validator address",
                ));
            }
            if let Some(earlier) = peers.iter().position(|p| p.public_key == public_key) {
                return Err(invalid(
                    format!("peers[{index}].public_key"),
                    format!("the same key as peers[{earlier}]"),
                ));
            }
            if let Some(earlier) =
                peer_validator.and_then(|v| peers.iter().position(|p| p.validator == Some(v)))
            {
                return Err(invalid(
                    format!("peers[{index}].validator"),
                    format!("the same validator as peers[{earlier}]"),
                ));
            }
            peers.push(PeerSpec {
                address: peer.address,
                public_key,
                validator: peer_validator,
            });
        }

        let millis = |field: &str, value: Option<u64>, default: Duration| match value {
            None => Ok(default),
            Some(0) => Err(invalid(field, "must not be zero")),
            Some(ms) => Ok(Duration::from_millis(ms)),
        };
        let defaults = PeerNetworkConfig::default();
        let network = PeerNetworkConfig {
            inbound_queue: raw.tuning.inbound_queue.unwrap_or(defaults.inbound_queue),
            outbound_queue: raw.tuning.outbound_queue.unwrap_or(defaults.outbound_queue),
            reconnect_initial: millis(
                "tuning.reconnect_initial_ms",
                raw.tuning.reconnect_initial_ms,
                defaults.reconnect_initial,
            )?,
            reconnect_max: millis(
                "tuning.reconnect_max_ms",
                raw.tuning.reconnect_max_ms,
                defaults.reconnect_max,
            )?,
        };
        if network.inbound_queue == 0 {
            return Err(invalid("tuning.inbound_queue", "must not be zero"));
        }
        if network.outbound_queue == 0 {
            return Err(invalid("tuning.outbound_queue", "must not be zero"));
        }
        if network.reconnect_max < network.reconnect_initial {
            return Err(invalid(
                "tuning.reconnect_max_ms",
                "must not be less than reconnect_initial_ms",
            ));
        }

        Ok(Self {
            data_dir: resolve(base, raw.data_dir),
            genesis: resolve(base, raw.genesis),
            listen: raw.listen,
            network_key: resolve(base, raw.network_key),
            validator,
            signer_socket: resolve(base, raw.signer.socket),
            signer_credential: resolve(base, raw.signer.credential),
            signer_timeout: millis(
                "signer.timeout_ms",
                raw.signer.timeout_ms,
                Duration::from_secs(5),
            )?,
            peers,
            network,
            io_timeout: millis(
                "tuning.io_timeout_ms",
                raw.tuning.io_timeout_ms,
                Duration::from_secs(5),
            )?,
        })
    }
}

fn key_file_error(path: &Path, problem: impl Into<String>) -> ConfigError {
    ConfigError::KeyFile {
        path: path.to_path_buf(),
        problem: problem.into(),
    }
}

/// The transport identity in the key file at `path`: 64 hex digits, in a file
/// that only its owner can read.
pub fn read_network_key(path: &Path) -> Result<NetworkIdentity, ConfigError> {
    let metadata =
        std::fs::metadata(path).map_err(|error| key_file_error(path, error.to_string()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(key_file_error(
            path,
            format!(
                "must not be accessible by group or other users; run: chmod 600 {}",
                path.display()
            ),
        ));
    }
    let text =
        std::fs::read_to_string(path).map_err(|error| key_file_error(path, error.to_string()))?;
    let secret = hex::decode::<32>(text.trim())
        .map_err(|error| key_file_error(path, format!("expected 64 hex digits: {error}")))?;
    Ok(NetworkIdentity::from_secret_bytes(secret))
}

/// Makes a new transport key at `path` (refusing to overwrite anything) and
/// returns its public key, which peers list to trust this node.
pub fn create_network_key(path: &Path) -> Result<[u8; 32], ConfigError> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|_| key_file_error(path, "the operating system has no randomness for a key"))?;
    let text = format!("{}\n", hex::encode(&secret));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| key_file_error(path, format!("cannot create it: {error}")))?;
    std::io::Write::write_all(&mut file, text.as_bytes())
        .map_err(|error| key_file_error(path, error.to_string()))?;
    Ok(NetworkIdentity::from_secret_bytes(secret).public_key())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use chain_text::format_address;

    use super::*;

    fn validator(n: u8) -> String {
        format_address(&Address::from_bytes([n; 32]))
    }

    fn key(n: u8) -> String {
        hex::encode(&[n; 32])
    }

    fn config_with(peers: &str, extra: &str) -> String {
        format!(
            r#"{{
              "data_dir": "data", "genesis": "genesis.json", "listen": "127.0.0.1:9000",
              "network_key": "network.key", "validator": "{}",
              "signer": {{ "socket": "signer.sock", "credential": "signer.credential" }},
              "peers": [{peers}]{extra}
            }}"#,
            validator(1)
        )
    }

    fn peer(n: u8, port: u16) -> String {
        format!(
            r#"{{ "address": "127.0.0.1:{port}", "public_key": "{}", "validator": "{}" }}"#,
            key(n),
            validator(n)
        )
    }

    fn parse(text: &str) -> Result<NodeConfig, ConfigError> {
        NodeConfig::parse(text, Path::new("/nodes/a"))
    }

    fn refused(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn a_complete_configuration_is_read_with_its_paths_resolved_against_the_file() {
        let config = parse(&config_with(
            &format!("{}, {}", peer(2, 9001), peer(3, 9002)),
            "",
        ))
        .unwrap();
        assert_eq!(config.data_dir, Path::new("/nodes/a/data"));
        assert_eq!(config.signer_socket, Path::new("/nodes/a/signer.sock"));
        assert_eq!(config.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config.validator, Address::from_bytes([1; 32]));
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers[0].public_key, [2; 32]);
        assert_eq!(
            config.peers[1].validator,
            Some(Address::from_bytes([3; 32]))
        );
        assert_eq!(config.io_timeout, Duration::from_secs(5));
        assert_eq!(
            config.network.inbound_queue,
            PeerNetworkConfig::default().inbound_queue
        );
    }

    #[test]
    fn an_absolute_path_is_left_alone_and_peers_may_be_none() {
        let text = config_with("", "").replace("\"data\"", "\"/var/lib/thrylos\"");
        let config = parse(&text).unwrap();
        assert_eq!(config.data_dir, Path::new("/var/lib/thrylos"));
        assert!(config.peers.is_empty());
    }

    #[test]
    fn tuning_overrides_defaults_and_is_checked() {
        let tuned = config_with(
            "",
            r#", "tuning": { "inbound_queue": 8, "outbound_queue": 4, "io_timeout_ms": 250,
                             "reconnect_initial_ms": 10, "reconnect_max_ms": 100 }"#,
        );
        let config = parse(&tuned).unwrap();
        assert_eq!(config.network.inbound_queue, 8);
        assert_eq!(config.network.outbound_queue, 4);
        assert_eq!(config.io_timeout, Duration::from_millis(250));
        assert_eq!(config.network.reconnect_max, Duration::from_millis(100));

        for (extra, field) in [
            (
                r#", "tuning": { "inbound_queue": 0 }"#,
                "tuning.inbound_queue",
            ),
            (
                r#", "tuning": { "outbound_queue": 0 }"#,
                "tuning.outbound_queue",
            ),
            (
                r#", "tuning": { "io_timeout_ms": 0 }"#,
                "tuning.io_timeout_ms",
            ),
            (
                r#", "tuning": { "reconnect_initial_ms": 500, "reconnect_max_ms": 100 }"#,
                "tuning.reconnect_max_ms",
            ),
        ] {
            let message = refused(&config_with("", extra));
            assert!(message.contains(field), "{extra}: {message}");
        }
    }

    #[test]
    fn a_misspelt_or_missing_field_is_an_error_naming_it() {
        let message = refused(&config_with("", r#", "listn": "0.0.0.0:1""#));
        assert!(message.contains("listn"), "{message}");
        let message = refused(&config_with("", "").replace("\"genesis\": \"genesis.json\",", ""));
        assert!(message.contains("genesis"), "{message}");
        assert!(refused("not json at all").contains("not valid"));
    }

    #[test]
    fn a_bad_validator_address_says_what_is_wrong_and_where() {
        let mut typo = validator(1);
        typo.replace_range(20..21, if &typo[20..21] == "q" { "p" } else { "q" });
        let text = config_with("", "").replace(&validator(1), &typo);
        let message = refused(&text);
        assert!(
            message.contains("`validator`") && message.contains("typo"),
            "{message}"
        );

        let text = config_with(&peer(2, 9001), "").replace(&validator(2), &"ab".repeat(32));
        let message = refused(&text);
        assert!(
            message.contains("peers[0].validator") && message.contains("raw hex"),
            "{message}"
        );
    }

    #[test]
    fn a_bad_peer_key_or_address_names_the_peer() {
        let text = config_with(&peer(2, 9001), "").replace(&key(2), "zz");
        assert!(refused(&text).contains("peers[0].public_key"));
        let text = config_with(&peer(2, 9001), "").replace("127.0.0.1:9001", "not-an-address");
        assert!(refused(&text).contains("not-an-address") || refused(&text).contains("invalid"));
    }

    #[test]
    fn peers_may_not_repeat_a_key_or_a_validator_or_be_this_node() {
        let same_key = config_with(&format!("{}, {}", peer(2, 9001), peer(2, 9002)), "");
        assert!(refused(&same_key).contains("peers[1].public_key"));

        let other_key_same_validator = format!(
            r#"{{ "address": "127.0.0.1:9002", "public_key": "{}", "validator": "{}" }}"#,
            key(9),
            validator(2)
        );
        let text = config_with(
            &format!("{}, {other_key_same_validator}", peer(2, 9001)),
            "",
        );
        assert!(refused(&text).contains("peers[1].validator"));

        let myself = config_with(&peer(1, 9001), "");
        assert!(refused(&myself).contains("own validator"));
    }

    #[test]
    fn a_configuration_over_the_size_limit_is_refused_unread() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        std::fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1],
        )
        .unwrap();
        assert!(NodeConfig::load(&path)
            .unwrap_err()
            .to_string()
            .contains("limit"));
        assert!(NodeConfig::load(&dir.path().join("missing.json"))
            .unwrap_err()
            .to_string()
            .contains("cannot read"));
    }

    #[test]
    fn load_reads_a_file_and_resolves_paths_against_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        std::fs::write(&path, config_with("", "")).unwrap();
        let config = NodeConfig::load(&path).unwrap();
        assert_eq!(config.data_dir, dir.path().join("data"));
    }

    #[test]
    fn a_network_key_is_created_private_read_back_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.key");
        let public = create_network_key(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read_network_key(&path).unwrap().public_key(), public);
        assert!(create_network_key(&path).is_err(), "no overwriting");
        assert_eq!(
            read_network_key(&path).unwrap().public_key(),
            public,
            "and it survived"
        );
    }

    #[test]
    fn a_key_file_others_can_read_or_that_is_not_a_key_is_refused_with_advice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.key");
        create_network_key(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let message = read_network_key(&path).map(|_| ()).unwrap_err().to_string();
        assert!(message.contains("chmod 600"), "{message}");

        std::fs::write(&path, "not a key\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let message = read_network_key(&path).map(|_| ()).unwrap_err().to_string();
        assert!(message.contains("64 hex digits"), "{message}");
    }
}
