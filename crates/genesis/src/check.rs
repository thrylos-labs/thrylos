//! What a genesis configuration amounts to, and whether it is a good one.
//!
//! [`report`] builds the chain a configuration describes — the same
//! `Executor::from_genesis` a node runs — so what it prints is what a node
//! will compute: operators compare the genesis hash and state root here
//! against the published ones before starting.
//!
//! The warnings are advice, not errors. A single-validator devnet is a
//! legitimate genesis, so nothing here refuses; it says what a real launch
//! would want to know.

use chain_exec::genesis_config::GenesisConfig;
use chain_exec::Executor;
use chain_modules::params::ParamValues;
use chain_types::{Address, Hash};

use crate::file::ParseError;

/// One validator's line in a [`Report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatorLine {
    pub operator: Address,
    pub self_stake: u128,
}

/// Advice about a validator set. See [`warnings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// Fewer than four validators: with fewer, no fault at all is
    /// tolerated (BFT tolerates one fault per three validators).
    FewerThanFourValidators { count: usize },
    /// One validator holds a third or more of the bonded stake, so it can
    /// halt the chain by going offline.
    CanHaltTheChain { operator: Address },
    /// One validator holds two thirds or more, so it alone decides what is
    /// final.
    ControlsFinality { operator: Address },
}

impl core::fmt::Display for Warning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FewerThanFourValidators { count } => write!(
                f,
                "only {count} validator(s): with fewer than 4 the chain tolerates no faulty validator"
            ),
            Self::CanHaltTheChain { operator } => write!(
                f,
                "validator {} holds a third or more of the bonded stake and can halt the chain",
                chain_text::format_address(operator)
            ),
            Self::ControlsFinality { operator } => write!(
                f,
                "validator {} holds two thirds or more of the bonded stake and alone decides finality",
                chain_text::format_address(operator)
            ),
        }
    }
}

/// Advice on the configuration's validator set: how many, and whether any
/// one holds enough stake to halt the chain or decide it alone.
pub fn warnings(config: &GenesisConfig) -> Vec<Warning> {
    let validators = config.validators();
    let mut out = Vec::new();
    if validators.len() < 4 {
        out.push(Warning::FewerThanFourValidators {
            count: validators.len(),
        });
    }
    let bonded = validators
        .iter()
        .fold(0u128, |sum, v| sum.saturating_add(v.self_stake));
    for validator in validators {
        let operator = Address::from_public_key(&validator.operator);
        // `stake >= bonded / 3` as `3 * stake >= bonded`; saturating is
        // right here, since a stake over a third of the largest number is
        // over a third of any bonded total.
        if validator.self_stake.saturating_mul(3) >= bonded {
            out.push(Warning::CanHaltTheChain { operator });
        }
        if validator.self_stake.saturating_mul(3) >= bonded.saturating_mul(2) {
            out.push(Warning::ControlsFinality { operator });
        }
    }
    out
}

/// Everything `chain-genesis check` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub chain_id: u64,
    pub genesis_time_ms: u64,
    /// What the first block names as its parent.
    pub genesis_hash: Hash,
    /// The state root of the chain before its first block.
    pub state_root: Hash,
    pub total_supply: u128,
    pub allocation_count: usize,
    pub allocated: u128,
    /// Bonded self-stake, not counting each pool's dead shares.
    pub bonded: u128,
    /// The parameters the chain starts with.
    pub parameters: ParamValues,
    /// Largest stake first.
    pub validators: Vec<ValidatorLine>,
    pub warnings: Vec<Warning>,
}

/// Builds the chain `config` describes and reports on it.
pub fn report(config: &GenesisConfig) -> Result<Report, ParseError> {
    let executor =
        Executor::from_genesis(config).map_err(|err| ParseError::Build(err.to_string()))?;
    let mut validators: Vec<ValidatorLine> = config
        .validators()
        .iter()
        .map(|v| ValidatorLine {
            operator: Address::from_public_key(&v.operator),
            self_stake: v.self_stake,
        })
        .collect();
    validators.sort_by(|a, b| {
        b.self_stake
            .cmp(&a.self_stake)
            .then_with(|| a.operator.cmp(&b.operator))
    });
    Ok(Report {
        chain_id: config.chain_id().0,
        genesis_time_ms: config.genesis_time_ms(),
        genesis_hash: config.hash(),
        state_root: executor.state_root().as_hash(),
        total_supply: config.total_supply(),
        allocation_count: config.allocations().len(),
        allocated: config
            .allocations()
            .iter()
            .fold(0u128, |sum, a| sum.saturating_add(a.amount)),
        bonded: config
            .validators()
            .iter()
            .fold(0u128, |sum, v| sum.saturating_add(v.self_stake)),
        parameters: *config.parameters(),
        validators,
        warnings: warnings(config),
    })
}
