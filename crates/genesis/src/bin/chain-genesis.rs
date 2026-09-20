//! `chain-genesis`: check a genesis file, print its hash, derive an
//! address, or generate the development genesis.
//!
//! ```text
//! chain-genesis check <file>        validate it and report what it creates
//! chain-genesis hash <file>         print just the genesis hash
//! chain-genesis address <pubkey>    the address of an Ed25519 public key
//! chain-genesis devnet              the INSECURE development genesis, as JSON
//! chain-genesis --help | --version
//! ```
//!
//! Exits non-zero if the file is not a valid genesis. Warnings about the
//! validator set do not change the exit code.

use std::path::Path;
use std::process::ExitCode;

use chain_genesis::check::{report, ValidatorLine};
use chain_genesis::human::{duration, percent_bps};
use chain_genesis::{devnet, hex, load, to_json};
use chain_types::{Address, PublicKey};

const USAGE: &str = "usage:
  chain-genesis check <file>
  chain-genesis hash <file>
  chain-genesis address <ed25519-public-key-hex>
  chain-genesis devnet
  chain-genesis --help | --version";

fn fail(message: impl core::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn percent(part: u128, whole: u128) -> String {
    percent_bps(part.saturating_mul(10_000).checked_div(whole).unwrap_or(0))
}

fn check(path: &Path) -> ExitCode {
    let config = match load(path) {
        Ok(config) => config,
        Err(err) => return fail(err),
    };
    let report = match report(&config) {
        Ok(report) => report,
        Err(err) => return fail(err),
    };
    println!("genesis file:       valid");
    println!("chain id:           {}", report.chain_id);
    println!("genesis time (ms):  {}", report.genesis_time_ms);
    println!(
        "genesis hash:       {}",
        hex::encode(report.genesis_hash.as_bytes())
    );
    println!(
        "state root:         {}",
        hex::encode(report.state_root.as_bytes())
    );
    println!("total supply:       {}", report.total_supply);
    println!(
        "allocations:        {} accounts, {} in total",
        report.allocation_count, report.allocated
    );
    println!(
        "validators:         {}, {} bonded",
        report.validators.len(),
        report.bonded
    );
    for ValidatorLine {
        operator,
        self_stake,
    } in &report.validators
    {
        println!(
            "  {}  {}  {}",
            hex::encode(operator.as_bytes()),
            self_stake,
            percent(*self_stake, report.bonded)
        );
    }
    let p = &report.parameters;
    println!("parameters:");
    println!("  max block gas:                 {}", p.max_block_gas);
    println!(
        "  base fee change denominator:   {}",
        p.base_fee_change_denominator
    );
    println!("  minimum self-stake:            {}", p.min_self_stake);
    println!(
        "  inflation:                     {} ({} bps)",
        percent_bps(u128::from(p.inflation_bps)),
        p.inflation_bps
    );
    println!(
        "  unbonding period:              {} ({} ms)",
        duration(p.unbonding_period_ms),
        p.unbonding_period_ms
    );
    println!(
        "  governance quorum:             {} ({} bps)",
        percent_bps(u128::from(p.quorum_bps)),
        p.quorum_bps
    );
    println!(
        "  governance veto threshold:     {} ({} bps)",
        percent_bps(u128::from(p.veto_threshold_bps)),
        p.veto_threshold_bps
    );
    if !report.warnings.is_empty() {
        println!("warnings:");
        for warning in &report.warnings {
            println!("  - {warning}");
        }
    }
    ExitCode::SUCCESS
}

fn hash(path: &Path) -> ExitCode {
    match load(path) {
        Ok(config) => {
            println!("{}", hex::encode(config.hash().as_bytes()));
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
}

fn address(text: &str) -> ExitCode {
    let bytes = match hex::decode::<32>(text) {
        Ok(bytes) => bytes,
        Err(err) => return fail(format!("public key: {err}")),
    };
    match PublicKey::from_ed25519_bytes(bytes) {
        Ok(key) => {
            println!("{}", hex::encode(Address::from_public_key(&key).as_bytes()));
            ExitCode::SUCCESS
        }
        Err(_) => fail("public key: not a valid Ed25519 public key"),
    }
}

fn devnet_json() -> ExitCode {
    match devnet::config().and_then(|config| to_json(&config)) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(err) => fail(err),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["-h" | "--help"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        ["-V" | "--version"] => {
            println!("chain-genesis {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["check", path] => check(Path::new(path)),
        ["hash", path] => hash(Path::new(path)),
        ["address", key] => address(key),
        ["devnet"] => devnet_json(),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
