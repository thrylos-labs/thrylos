//! `chain-node`: run a validator.
//!
//! ```text
//! chain-node run <config.json> [--until-height <n>]   run the node
//! chain-node network-key <file>                       make a transport key
//! chain-node --help | --version
//! ```
//!
//! `run` starts the node the configuration describes and keeps running until
//! it is killed, its host halts (it says why and exits 1), or, with
//! `--until-height`, its chain reaches that height (it exits 0). There is no
//! orderly shutdown to wait for: the node is crash-safe by construction, so
//! killing it at any moment is safe and is how it is stopped.
//!
//! `network-key` creates the file a node's `network_key` names and prints the
//! public key its peers list to trust it. It refuses to overwrite a file.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use chain_genesis::hex;
use chain_node::config::create_network_key;
use chain_node::{run_node, NodeConfig, NodeEvent};
use chain_types::BlockHeight;

const USAGE: &str = "usage:
  chain-node run <config.json> [--until-height <n>]
  chain-node network-key <file>
  chain-node --help | --version";

fn fail(message: impl core::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn describe(event: &NodeEvent) {
    match event {
        NodeEvent::Committed {
            height,
            transactions,
        } => eprintln!("committed block {height} ({transactions} transactions)"),
        NodeEvent::Equivocation { validator } => eprintln!(
            "witnessed equivocation by {}",
            chain_text::format_address(validator)
        ),
        NodeEvent::Halted(reason) => eprintln!("halted: {reason}"),
    }
}

fn run(path: &str, until: Option<BlockHeight>) -> ExitCode {
    let config = match NodeConfig::load(&PathBuf::from(path)) {
        Ok(config) => config,
        Err(error) => return fail(error),
    };
    eprintln!(
        "starting validator {} on {} with {} peers",
        chain_text::format_address(&config.validator),
        config.listen,
        config.peers.len()
    );
    let stop = AtomicBool::new(false);
    match run_node(&config, until, &stop, &mut |event| describe(&event)) {
        Ok(()) => ExitCode::SUCCESS,
        // A halt was already described as it happened.
        Err(chain_node::node::RunError::Halted(_)) => ExitCode::FAILURE,
        Err(error) => fail(error),
    }
}

fn network_key(path: &str) -> ExitCode {
    match create_network_key(&PathBuf::from(path)) {
        Ok(public_key) => {
            println!("{}", hex::encode(&public_key));
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
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
            println!("chain-node {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["run", path] => run(path, None),
        ["run", path, "--until-height", height] => match height.parse::<u64>() {
            Ok(height) => run(path, Some(BlockHeight(height))),
            Err(_) => fail(format!(
                "--until-height wants a block height, not {height:?}"
            )),
        },
        ["network-key", path] => network_key(path),
        _ => usage_error(),
    }
}
