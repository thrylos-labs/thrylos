//! A deterministic development genesis.
//!
//! **INSECURE. FOR DEVELOPMENT ONLY.** Every key here is derived from a
//! small public seed, so anyone can compute every secret. Nothing built on
//! this holds value. It exists so that tests, examples and local networks
//! have a genesis that is valid, reproducible byte for byte, and checked
//! into the repository as a golden file.

use blst::min_pk::SecretKey;
use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisValidator};
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{BlsPublicKey, ChainId, PublicKey};

use crate::file::ParseError;

pub const DEVNET_CHAIN_ID: u64 = 1_337;
pub const DEVNET_GENESIS_TIME_MS: u64 = 1_700_000_000_000;
pub const DEVNET_VALIDATORS: u8 = 4;
pub const DEVNET_ACCOUNTS: u8 = 4;

fn invalid(what: &str) -> ParseError {
    ParseError::Invalid {
        at: format!("devnet {what}"),
        reason: "could not be derived",
    }
}

/// The Ed25519 public key of the development identity with this seed.
pub fn ed25519(seed: u8) -> Result<PublicKey, ParseError> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes())
        .map_err(|_| invalid("ed25519 key"))
}

/// The consensus key and proof of possession of the development validator
/// with this seed.
pub fn bls(seed: u8) -> Result<(BlsPublicKey, BlsSignature), ParseError> {
    let secret = SecretKey::key_gen(&[seed; 32], &[]).map_err(|_| invalid("bls secret"))?;
    let key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes())
        .map_err(|_| invalid("bls public key"))?;
    let proof = BlsSignature::from_bytes(
        secret
            .sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .map_err(|_| invalid("proof of possession"))?;
    Ok((key, proof))
}

/// Four validators (seeds 1 to 4) with ten times the minimum self-stake
/// each, and four funded accounts (seeds 101 to 104).
pub fn config() -> Result<GenesisConfig, ParseError> {
    let stake = GENESIS_PARAM_VALUES.min_self_stake.saturating_mul(10);
    let mut validators = Vec::new();
    for seed in 1..=DEVNET_VALIDATORS {
        let (consensus_key, proof_of_possession) = bls(seed)?;
        validators.push(GenesisValidator {
            operator: ed25519(seed)?,
            consensus_key,
            proof_of_possession,
            self_stake: stake,
        });
    }
    let mut allocations = Vec::new();
    for offset in 1..=DEVNET_ACCOUNTS {
        allocations.push(Allocation {
            owner: ed25519(100u8.saturating_add(offset))?,
            amount: 1_000_000_000_000,
        });
    }
    Ok(GenesisConfig::new(
        ChainId(DEVNET_CHAIN_ID),
        DEVNET_GENESIS_TIME_MS,
        GENESIS_PARAM_VALUES,
        allocations,
        validators,
    )?)
}
