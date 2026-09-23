//! A real testnet-alpha network's genesis and node directories
//! (`docs/core-network-alpha.md`, "Create the alpha genesis and release
//! configuration"): a chosen chain ID, a genesis that allocates funds only
//! to the accounts its caller explicitly names, and validator consensus
//! keys from the operating system's randomness — never [`crate::devnet`]'s
//! seed-derived ones, which anyone can recompute.
//!
//! A validator's *operator* identity is deliberately not generated here: it
//! is an ordinary account, made the same way as any other with `thrylos
//! setup`, and only its owner ever holds its secret key. [`init`] takes each
//! validator's already-made operator public key (`thrylos address --hex`)
//! and generates only what nothing else does: a real per-node network
//! transport key (as [`crate::devnet`] already does, just not from a public
//! seed) and a real per-node consensus key, wired into the same node
//! directory layout [`crate::devnet`] uses — `chain-node run` and
//! `chain-signer` do not need to know which generator made their files.
//!
//! `dir` must not exist or must be empty, exactly as
//! [`crate::devnet::generate`] requires, and the two are otherwise
//! unrelated: a directory this wrote should never be initialized again with
//! `chain-node devnet init`, or vice versa.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_genesis::devnet::bls_from_ikm;
use chain_genesis::hex;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_p2p::NetworkIdentity;
use chain_text::format_address;
use chain_types::{Address, ChainId, PublicKey};

use crate::devnet::{
    io, random, write_new, write_private, DevnetError, DevnetNode, DIRECTORY_PREFIX, GENESIS,
    MAX_SOCKET_PATH, MAX_VALIDATORS, MIN_VALIDATORS, NETWORK_KEY, NODE_CONFIG, SIGNER_CREDENTIAL,
    SIGNER_KEY, SIGNER_SOCKET,
};

struct Plan {
    number: usize,
    listen: SocketAddr,
    rpc: SocketAddr,
    validator: Address,
    network_secret: [u8; 32],
    network_public_key: [u8; 32],
    credential: [u8; 32],
    consensus_secret: [u8; 32],
}

/// Writes one node directory per entry in `operators`: a validator whose
/// consensus key is freshly and randomly generated, sharing one genesis
/// with chain ID `chain_id` that allocates funds only to `allocations`.
/// Validators are never implicitly funded here; their stake is credited
/// directly, from `GENESIS_PARAM_VALUES.min_self_stake` times ten, the same
/// policy [`crate::devnet`] uses.
#[allow(clippy::too_many_arguments)]
pub fn init(
    dir: &Path,
    operators: &[PublicKey],
    allocations: Vec<Allocation>,
    chain_id: u64,
    genesis_time_ms: u64,
    base_port: u16,
    block_interval_ms: u64,
) -> Result<Vec<DevnetNode>, DevnetError> {
    let validators = operators.len();
    if block_interval_ms == 0 {
        return Err(DevnetError::BlockInterval);
    }
    if !(MIN_VALIDATORS..=MAX_VALIDATORS).contains(&validators) {
        return Err(DevnetError::Validators(validators));
    }
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
    let mut genesis_validators = Vec::with_capacity(validators);
    let self_stake = GENESIS_PARAM_VALUES.min_self_stake.saturating_mul(10);
    for (index, operator) in operators.iter().enumerate() {
        let ports_error = || DevnetError::Ports {
            base: base_port,
            validators,
        };
        let offset = u16::try_from(index).map_err(|_| ports_error())?;
        let port = base_port.checked_add(offset).ok_or_else(ports_error)?;
        // The RPC ports follow the peer ports, one block after the other.
        let rpc_port = u16::try_from(validators)
            .ok()
            .and_then(|count| port.checked_add(count))
            .ok_or_else(ports_error)?;
        let network_secret = random()?;
        let consensus_secret_ikm = random()?;
        let (consensus_secret, consensus_key, proof_of_possession) =
            bls_from_ikm(&consensus_secret_ikm)
                .map_err(|error| DevnetError::Genesis(error.to_string()))?;
        genesis_validators.push(GenesisValidator {
            operator: *operator,
            consensus_key,
            proof_of_possession,
            self_stake,
        });
        plans.push(Plan {
            number: index.saturating_add(1),
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            rpc: SocketAddr::from((Ipv4Addr::LOCALHOST, rpc_port)),
            validator: Address::from_public_key(operator),
            network_secret,
            network_public_key: NetworkIdentity::from_secret_bytes(network_secret).public_key(),
            credential: random()?,
            consensus_secret: consensus_secret.to_bytes(),
        });
    }

    let genesis_config = GenesisConfig::new(
        ChainId(chain_id),
        genesis_time_ms,
        GENESIS_PARAM_VALUES,
        allocations,
        genesis_validators,
    )
    .map_err(|error| DevnetError::Genesis(error.to_string()))?;
    let genesis = chain_genesis::to_json(&genesis_config)
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

        write_private(&dir.join(SIGNER_KEY), &plan.consensus_secret)?;
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
  "rpc": {{ "listen": "{}" }},
  "tuning": {{ "block_interval_ms": {block_interval_ms} }}
}}
"#,
        plan.listen,
        format_address(&plan.validator),
        plan.rpc
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::os::unix::fs::PermissionsExt;

    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::config::{read_network_key, NodeConfig};
    use crate::devnet::DEFAULT_BASE_PORT;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn a_real_operator(seed: u8) -> PublicKey {
        // Real keys in these tests still come from a small seed only so the
        // test itself is deterministic; `init` never derives one this way.
        let key = SigningKey::from_bytes(&[seed; 32]);
        PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap()
    }

    fn allocation(seed: u8, amount: u128) -> Allocation {
        Allocation {
            owner: a_real_operator(seed),
            amount,
        }
    }

    #[test]
    fn it_writes_one_directory_per_operator_funds_only_named_accounts_and_uses_a_chosen_chain_id() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("alpha");
        let operators = [a_real_operator(1), a_real_operator(2)];
        let faucet = allocation(200, 5_000_000_000);

        let nodes = init(
            &dir,
            &operators,
            vec![faucet],
            9_999,
            1_800_000_000_000,
            DEFAULT_BASE_PORT,
            250,
        )
        .unwrap();

        assert_eq!(nodes.len(), 2);
        for (node, operator) in nodes.iter().zip(operators.iter()) {
            assert_eq!(node.validator, Address::from_public_key(operator));
            let node_dir = dir.join(format!("node{}", node.number));
            assert_eq!(mode(&node_dir.join(SIGNER_KEY)), 0o600);
            assert_eq!(mode(&node_dir.join(SIGNER_CREDENTIAL)), 0o600);
            assert_eq!(mode(&node_dir.join(NETWORK_KEY)), 0o600);
            // A signer key different validators never share: not derivable
            // from anything public about the node.
            let key = fs::read(node_dir.join(SIGNER_KEY)).unwrap();
            assert_eq!(key.len(), 32);

            let config = NodeConfig::load(&node_dir.join(NODE_CONFIG)).unwrap();
            assert_eq!(config.validator, node.validator);
            let network_public_key = read_network_key(&node_dir.join(NETWORK_KEY)).unwrap();
            assert_eq!(network_public_key.public_key(), node.network_public_key);
        }
        // Every node in the network was written with the identical genesis,
        // and it is exactly the caller's allocation: nothing implicit.
        let genesis_bytes = fs::read(dir.join("node1").join(GENESIS)).unwrap();
        assert_eq!(
            genesis_bytes,
            fs::read(dir.join("node2").join(GENESIS)).unwrap()
        );
        let genesis = chain_genesis::load(&dir.join("node1").join(GENESIS)).unwrap();
        assert_eq!(genesis.chain_id(), ChainId(9_999));
        assert_eq!(genesis.allocations(), &[faucet]);
        assert_eq!(genesis.validators().len(), 2);
    }

    #[test]
    fn two_networks_never_share_a_consensus_key_even_from_the_same_operators() {
        let root = tempfile::tempdir().unwrap();
        let operators = [a_real_operator(1)];
        let first = root.path().join("first");
        let second = root.path().join("second");
        init(&first, &operators, Vec::new(), 1, 0, DEFAULT_BASE_PORT, 250).unwrap();
        init(
            &second,
            &operators,
            Vec::new(),
            1,
            0,
            DEFAULT_BASE_PORT,
            250,
        )
        .unwrap();
        assert_ne!(
            fs::read(first.join("node1").join(SIGNER_KEY)).unwrap(),
            fs::read(second.join("node1").join(SIGNER_KEY)).unwrap()
        );
    }

    #[test]
    fn no_operators_or_a_zero_block_interval_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let error = init(
            &root.path().join("net"),
            &[],
            Vec::new(),
            1,
            0,
            DEFAULT_BASE_PORT,
            250,
        )
        .unwrap_err();
        assert!(matches!(error, DevnetError::Validators(0)));

        let error = init(
            &root.path().join("net2"),
            &[a_real_operator(1)],
            Vec::new(),
            1,
            0,
            DEFAULT_BASE_PORT,
            0,
        )
        .unwrap_err();
        assert!(matches!(error, DevnetError::BlockInterval));
    }

    #[test]
    fn a_repeated_operator_is_two_validators_sharing_one_key_and_genesis_refuses_it() {
        let root = tempfile::tempdir().unwrap();
        let operator = a_real_operator(1);
        let error = init(
            &root.path().join("net"),
            &[operator, operator],
            Vec::new(),
            1,
            0,
            DEFAULT_BASE_PORT,
            250,
        )
        .unwrap_err();
        assert!(matches!(error, DevnetError::Genesis(_)), "{error}");
    }
}
