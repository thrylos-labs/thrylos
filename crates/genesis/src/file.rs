//! The genesis file's JSON shape, and its conversion to and from a
//! [`GenesisConfig`].
//!
//! The shape is strict on purpose. Unknown fields are refused, so a
//! misspelt `min_self_stake` cannot quietly leave a parameter at some
//! default; every field is required, so nothing depends on a default that
//! a later release might change; a repeated key is refused; and numbers
//! that do not fit a JSON number exactly are strings.
//!
//! Amounts are strings of **base units**, never tokens: `"1000000000"` is
//! one token (see `chain_text::amount`). The file stays in whole base units
//! so that nothing in it can be misread as a decimal; `chain-genesis check`
//! shows the same amounts in tokens.
//!
//! ```json
//! {
//!   "chain_id": 1,
//!   "genesis_time_ms": 1700000000000,
//!   "parameters": {
//!     "max_block_gas": 300000,
//!     "base_fee_change_denominator": 8,
//!     "min_self_stake": "1000000",
//!     "inflation_bps": 400,
//!     "unbonding_period_ms": 1814400000,
//!     "quorum_bps": 3340,
//!     "veto_threshold_bps": 3340,
//!     "publish_enabled": true
//!   },
//!   "allocations": [
//!     { "public_key": "<64 hex digits>", "amount": "1000000000" }
//!   ],
//!   "validators": [
//!     {
//!       "operator_public_key": "<64 hex digits>",
//!       "consensus_key": "<96 hex digits>",
//!       "proof_of_possession": "<192 hex digits>",
//!       "self_stake": "5000000"
//!     }
//!   ]
//! }
//! ```
//!
//! Accounts are named by Ed25519 public key (see `GenesisConfig`).
//! Amounts are base-10 integers in strings, without a sign, separators or
//! leading zeros. Keys and proofs are hexadecimal, with an optional `0x`.

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

use chain_exec::genesis_config::{Allocation, GenesisConfig, GenesisConfigError, GenesisValidator};
use chain_modules::ParamValues;
use chain_types::bls::BlsSignature;
use chain_types::{BlsPublicKey, ChainId, PublicKey};

use crate::hex;

/// Why a genesis file could not be turned into a configuration.
#[derive(Debug)]
pub enum ParseError {
    /// The file could not be read.
    Io(String),
    /// The file is larger than [`crate::MAX_FILE_BYTES`].
    TooLarge,
    /// The text is not JSON of the expected shape (with a line and column).
    Json(String),
    /// A value is well-formed but not acceptable: a key that is not a
    /// point on the curve, say. `at` says where.
    Invalid { at: String, reason: &'static str },
    /// The file parsed, but describes an invalid genesis.
    Genesis(GenesisConfigError),
    /// Something a check needed to build failed.
    Build(String),
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "could not read the file: {err}"),
            Self::TooLarge => write!(f, "the file is larger than {} bytes", crate::MAX_FILE_BYTES),
            Self::Json(err) => write!(f, "not a valid genesis file: {err}"),
            Self::Invalid { at, reason } => write!(f, "{at}: {reason}"),
            Self::Genesis(err) => write!(f, "invalid genesis: {}", crate::describe(err)),
            Self::Build(err) => write!(f, "could not start a chain from it: {err}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<GenesisConfigError> for ParseError {
    fn from(err: GenesisConfigError) -> Self {
        Self::Genesis(err)
    }
}

/// An amount of coin: a base-10 integer in a JSON string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Amount(pub u128);

/// Why an amount string is not an amount.
fn parse_amount(text: &str) -> Result<u128, &'static str> {
    if text.is_empty() {
        return Err("an amount is empty");
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("an amount is base-10 digits only, with no sign or separators");
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err("an amount has no leading zeros");
    }
    text.parse::<u128>()
        .map_err(|_| "an amount does not fit in 128 bits")
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AmountVisitor;
        impl Visitor<'_> for AmountVisitor {
            type Value = Amount;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("a base-10 integer in a string")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Amount, E> {
                parse_amount(text).map(Amount).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(AmountVisitor)
    }
}

/// `N` bytes as a hexadecimal string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hex<const N: usize>(pub [u8; N]);

impl<const N: usize> Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor<const N: usize>;
        impl<const N: usize> Visitor<'_> for HexVisitor<N> {
            type Value = Hex<N>;
            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{N} bytes as a hexadecimal string")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Hex<N>, E> {
                hex::decode::<N>(text).map(Hex).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(HexVisitor::<N>)
    }
}

const PUBLIC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParametersFile {
    pub max_block_gas: u64,
    pub base_fee_change_denominator: u64,
    pub min_self_stake: Amount,
    pub inflation_bps: u16,
    pub unbonding_period_ms: u64,
    pub quorum_bps: u16,
    pub veto_threshold_bps: u16,
    pub publish_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationFile {
    pub public_key: Hex<PUBLIC_KEY_LEN>,
    pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatorFile {
    pub operator_public_key: Hex<PUBLIC_KEY_LEN>,
    pub consensus_key: Hex<{ chain_types::bls::BLS_PUBLIC_KEY_LEN }>,
    pub proof_of_possession: Hex<{ chain_types::bls::BLS_SIGNATURE_LEN }>,
    pub self_stake: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisFile {
    pub chain_id: u64,
    pub genesis_time_ms: u64,
    pub parameters: ParametersFile,
    pub allocations: Vec<AllocationFile>,
    pub validators: Vec<ValidatorFile>,
}

fn public_key(bytes: [u8; PUBLIC_KEY_LEN], at: String) -> Result<PublicKey, ParseError> {
    PublicKey::from_ed25519_bytes(bytes).map_err(|_| ParseError::Invalid {
        at,
        reason: "not a valid Ed25519 public key",
    })
}

impl GenesisFile {
    /// The configuration this file describes, checked in full.
    pub fn into_config(self) -> Result<GenesisConfig, ParseError> {
        let parameters = ParamValues {
            max_block_gas: self.parameters.max_block_gas,
            base_fee_change_denominator: self.parameters.base_fee_change_denominator,
            min_self_stake: self.parameters.min_self_stake.0,
            inflation_bps: self.parameters.inflation_bps,
            unbonding_period_ms: self.parameters.unbonding_period_ms,
            quorum_bps: self.parameters.quorum_bps,
            veto_threshold_bps: self.parameters.veto_threshold_bps,
            publish_enabled: self.parameters.publish_enabled,
        };

        let mut allocations = Vec::with_capacity(self.allocations.len());
        for (index, allocation) in self.allocations.iter().enumerate() {
            allocations.push(Allocation {
                owner: public_key(
                    allocation.public_key.0,
                    format!("allocations[{index}].public_key"),
                )?,
                amount: allocation.amount.0,
            });
        }

        let mut validators = Vec::with_capacity(self.validators.len());
        for (index, validator) in self.validators.iter().enumerate() {
            let consensus_key =
                BlsPublicKey::from_bytes(validator.consensus_key.0).map_err(|_| {
                    ParseError::Invalid {
                        at: format!("validators[{index}].consensus_key"),
                        reason: "not a valid BLS12-381 public key",
                    }
                })?;
            let proof_of_possession = BlsSignature::from_bytes(validator.proof_of_possession.0)
                .map_err(|_| ParseError::Invalid {
                    at: format!("validators[{index}].proof_of_possession"),
                    reason: "not a valid BLS12-381 signature",
                })?;
            validators.push(GenesisValidator {
                operator: public_key(
                    validator.operator_public_key.0,
                    format!("validators[{index}].operator_public_key"),
                )?,
                consensus_key,
                proof_of_possession,
                self_stake: validator.self_stake.0,
            });
        }

        Ok(GenesisConfig::new(
            ChainId(self.chain_id),
            self.genesis_time_ms,
            parameters,
            allocations,
            validators,
        )?)
    }

    /// The file for `config`, in its canonical (sorted) order.
    pub fn from_config(config: &GenesisConfig) -> Self {
        let parameters = config.parameters();
        Self {
            chain_id: config.chain_id().0,
            genesis_time_ms: config.genesis_time_ms(),
            parameters: ParametersFile {
                max_block_gas: parameters.max_block_gas,
                base_fee_change_denominator: parameters.base_fee_change_denominator,
                min_self_stake: Amount(parameters.min_self_stake),
                inflation_bps: parameters.inflation_bps,
                unbonding_period_ms: parameters.unbonding_period_ms,
                quorum_bps: parameters.quorum_bps,
                veto_threshold_bps: parameters.veto_threshold_bps,
                publish_enabled: parameters.publish_enabled,
            },
            allocations: config
                .allocations()
                .iter()
                .map(|allocation| AllocationFile {
                    public_key: Hex(allocation.owner.ed25519_bytes()),
                    amount: Amount(allocation.amount),
                })
                .collect(),
            validators: config
                .validators()
                .iter()
                .map(|validator| ValidatorFile {
                    operator_public_key: Hex(validator.operator.ed25519_bytes()),
                    consensus_key: Hex(validator.consensus_key.to_bytes()),
                    proof_of_possession: Hex(validator.proof_of_possession.to_bytes()),
                    self_stake: Amount(validator.self_stake),
                })
                .collect(),
        }
    }
}
