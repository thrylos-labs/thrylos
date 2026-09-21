//! Genesis configuration files: parsing them, checking them, and the
//! `chain-genesis` tool.
//!
//! Not in `docs/spec.md`'s crate table, and deliberately outside the tier-A
//! set. `chain-exec` defines what a genesis *is* — `GenesisConfig`,
//! validated, canonically ordered, hashed — and takes it as an argument,
//! as tier-A code must; reading a file and parsing JSON is I/O and a
//! parser's worth of dependencies, so it lives here. Nothing in this crate
//! is consensus-critical *as code*: whatever it parses is checked in full
//! by `GenesisConfig::new`, and two nodes that read the same file into
//! different configurations would simply disagree about the genesis hash,
//! which is published and compared before anything starts.
//!
//! - [`parse`] and [`load`] turn a file's text into a `GenesisConfig`, or
//!   say precisely why not ([`file`] documents the format).
//! - [`to_json`] writes one back out, in canonical order.
//! - [`check::report`] builds the chain a configuration describes and
//!   reports its hash, state root and supply, with advisory warnings about
//!   the validator set.
//! - [`devnet`] generates a deterministic development genesis.
//!
//! Generating a *real* validator's consensus key and proof of possession is
//! the signer's job (`chain-signer` holds that key); this crate only reads
//! the results.

#![forbid(unsafe_code)]

pub mod check;
pub mod devnet;
pub mod file;
pub mod hex;
pub mod human;

use std::io::Read;
use std::path::Path;

use chain_exec::genesis_config::{GenesisConfig, GenesisConfigError};
use chain_types::Address;

pub use file::{GenesisFile, ParseError};

/// The largest genesis file [`load`] will read. A file this size holds
/// tens of thousands of entries; anything larger is not a genesis file.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The configuration a genesis file's text describes, checked in full.
pub fn parse(text: &str) -> Result<GenesisConfig, ParseError> {
    serde_json::from_str::<GenesisFile>(text)
        .map_err(|err| ParseError::Json(err.to_string()))?
        .into_config()
}

/// Reads and parses the genesis file at `path`, refusing one larger than
/// [`MAX_FILE_BYTES`] without reading the rest of it.
pub fn load(path: &Path) -> Result<GenesisConfig, ParseError> {
    let file = std::fs::File::open(path).map_err(|err| ParseError::Io(err.to_string()))?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|err| ParseError::Io(err.to_string()))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > MAX_FILE_BYTES) {
        return Err(ParseError::TooLarge);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| ParseError::Json("the file is not valid UTF-8".to_owned()))?;
    parse(&text)
}

/// `config` as a genesis file, entries in canonical order. Parsing what
/// this returns gives back `config`.
pub fn to_json(config: &GenesisConfig) -> Result<String, ParseError> {
    serde_json::to_string_pretty(&GenesisFile::from_config(config))
        .map_err(|err| ParseError::Json(err.to_string()))
}

fn account(address: &Address) -> String {
    chain_text::format_address(address)
}

/// An error in words, naming the account it is about where there is one.
pub fn describe(err: &GenesisConfigError) -> String {
    let address = match err {
        GenesisConfigError::ZeroAllocation { owner }
        | GenesisConfigError::DuplicateAllocation { owner } => Some(owner),
        GenesisConfigError::DuplicateValidator { operator }
        | GenesisConfigError::DuplicateConsensusKey { operator }
        | GenesisConfigError::SelfStakeBelowMinimum { operator }
        | GenesisConfigError::InvalidProofOfPossession { operator }
        | GenesisConfigError::Registry { operator, .. } => Some(operator),
        GenesisConfigError::Parameters(_)
        | GenesisConfigError::NoValidators
        | GenesisConfigError::TooManyValidators
        | GenesisConfigError::StateLimitExceeded
        | GenesisConfigError::SupplyOverflow => None,
    };
    match address {
        Some(address) => format!("{err} (account {})", account(address)),
        None => err.to_string(),
    }
}
