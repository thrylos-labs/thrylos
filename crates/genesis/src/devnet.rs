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
/// The most validators [`config_with_validators`] makes: validator seeds run
/// from 1, and the funded accounts start at seed 101.
pub const DEVNET_MAX_VALIDATORS: u8 = 65;

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

/// The consensus key, its proof of possession, and the secret they were
/// derived from, from 32 bytes of key material. [`bls`] is this with the
/// insecure, seed-derived devnet material; a real validator's material must
/// be secret and unpredictable (`crates/node/src/alpha.rs` uses this
/// directly, with material from the operating system's randomness).
pub fn bls_from_ikm(ikm: &[u8; 32]) -> Result<(SecretKey, BlsPublicKey, BlsSignature), ParseError> {
    let secret = SecretKey::key_gen(ikm, &[]).map_err(|_| invalid("bls secret"))?;
    let key = BlsPublicKey::from_bytes(secret.sk_to_pk().to_bytes())
        .map_err(|_| invalid("bls public key"))?;
    let proof = BlsSignature::from_bytes(
        secret
            .sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .map_err(|_| invalid("proof of possession"))?;
    Ok((secret, key, proof))
}

/// The consensus key and proof of possession of the development validator
/// with this seed.
pub fn bls(seed: u8) -> Result<(BlsPublicKey, BlsSignature), ParseError> {
    let (_secret, key, proof) = bls_from_ikm(&[seed; 32])?;
    Ok((key, proof))
}

/// Four validators (seeds 1 to 4) with ten times the minimum self-stake
/// each, and four funded accounts (seeds 101 to 104).
pub fn config() -> Result<GenesisConfig, ParseError> {
    config_with_validators(DEVNET_VALIDATORS)
}

/// Like [`config`], with `count` validators (seeds 1 to `count`), from one to
/// [`DEVNET_MAX_VALIDATORS`]. The funded accounts are the same whatever the
/// count, so a network of any size can be used with the same test keys.
pub fn config_with_validators(count: u8) -> Result<GenesisConfig, ParseError> {
    if count == 0 || count > DEVNET_MAX_VALIDATORS {
        return Err(ParseError::Invalid {
            at: "devnet validators".to_owned(),
            reason: "must be between 1 and 100",
        });
    }
    let stake = GENESIS_PARAM_VALUES.min_self_stake.saturating_mul(10);
    let mut validators = Vec::new();
    for seed in 1..=count {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn the_default_is_four_validators() {
        assert_eq!(
            config().unwrap().hash(),
            config_with_validators(4).unwrap().hash()
        );
    }

    #[test]
    fn the_default_devnet_matches_the_golden_vectors() {
        let config = config().unwrap();
        let report = crate::check::report(&config).unwrap();
        assert_eq!(
            report.genesis_hash.to_string(),
            "1e441e8b66d3f61a3a08c762e38614a28038b0bb68b6dd1c06730fdbf50d844d"
        );
        assert_eq!(
            report.state_root.to_string(),
            "880924bb68774bf30cf720e9b550ff386eb70e55f65071f12ce96ff588cdf81d"
        );
    }

    #[test]
    fn any_count_from_one_to_the_limit_is_a_valid_genesis_with_the_same_accounts() {
        let four = config().unwrap();
        for count in [1, 2, 7, DEVNET_MAX_VALIDATORS] {
            let config = config_with_validators(count).unwrap();
            assert_eq!(config.validators().len(), usize::from(count));
            assert_eq!(config.allocations(), four.allocations());
        }
        // Validators are held in canonical order, not seed order, but the four
        // of the default network are all there in a larger one.
        let seven = config_with_validators(7).unwrap();
        for validator in four.validators() {
            assert!(seven.validators().contains(validator));
        }
    }

    #[test]
    fn no_validators_or_too_many_is_refused() {
        for count in [0, DEVNET_MAX_VALIDATORS + 1] {
            let error = config_with_validators(count).unwrap_err().to_string();
            assert!(error.contains("between 1 and 100"), "{error}");
        }
    }
}
