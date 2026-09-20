//! `chain-node`: run a validator.
//!
//! ```text
//! chain-node run <config.json> [--until-height <n>] [--stop-when-stdin-closes]
//!                                                     run the node
//! chain-node network-key <file>                       make a transport key
//! chain-node devnet init <dir> [--validators <n>] [--base-port <port>]
//!                                                     write a local network
//! chain-node devnet start <dir> [--until-height <n>]  run a local network
//! chain-node --help | --version
//! ```
//!
//! `run` starts the node the configuration describes and keeps running until
//! it is killed, its host halts (it says why and exits 1), or, with
//! `--until-height`, its chain reaches that height (it exits 0).
//!
//! With `--stop-when-stdin-closes` it also stops, and exits 0, when its standard
//! input reaches end of file. That is the orderly way out, and the launcher's:
//! it stops between one thing the node does and the next, never in the middle
//! of signing. Killing a node is *not* always safe to resume from: if it dies
//! after its signer has recorded a signature and before it has recorded that
//! signature itself, the signer will refuse that position on restart (the spec
//! makes that refusal unconditional) and the node halts. Do not use the flag
//! from a shell or a service manager that gives the node an empty standard
//! input, which is closed at once.
//!
//! `network-key` creates the file a node's `network_key` names and prints the
//! public key its peers list to trust it. It refuses to overwrite a file.
//!
//! `devnet init` writes the files of a network of validators on this machine
//! (see `chain_node::devnet`; **insecure**, for development only) and refuses a
//! directory that holds anything. `devnet start` runs one: a `chain-signer` and
//! a `chain-node` per validator, logging to files in their directories, until
//! every node has ended. With `--until-height` it runs until every node has
//! committed that height and then stops them all: a node that joined late is
//! waited for, and the chain goes on meanwhile. (`run --until-height` is
//! different: each node stops as it gets there, so a node that has fallen
//! behind by then cannot catch up once the others have stopped.)

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chain_genesis::hex;
use chain_node::config::create_network_key;
use chain_node::devnet::{generate, DEFAULT_BASE_PORT};
use chain_node::event_loop::committed_line;
use chain_node::launch::{launch, LaunchOptions};
use chain_node::{run_node, NodeConfig, NodeEvent};
use chain_types::BlockHeight;

const USAGE: &str = "usage:
  chain-node run <config.json> [--until-height <n>] [--stop-when-stdin-closes]
  chain-node network-key <file>
  chain-node devnet init <dir> [--validators <n>] [--base-port <port>]
  chain-node devnet start <dir> [--until-height <n>]
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
        } => eprintln!("{}", committed_line(*height, *transactions)),
        NodeEvent::Equivocation { validator } => eprintln!(
            "witnessed equivocation by {}",
            chain_text::format_address(validator)
        ),
        NodeEvent::Halted(reason) => eprintln!("halted: {reason}"),
    }
}

fn run(path: &str, until: Option<BlockHeight>, stop_when_stdin_closes: bool) -> ExitCode {
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
    let stop = Arc::new(AtomicBool::new(false));
    if stop_when_stdin_closes {
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 256];
            let mut stdin = std::io::stdin();
            // Whatever arrives is ignored: only the end of the input matters, and
            // a read that fails means whoever held the other end is gone too.
            while matches!(stdin.read(&mut buffer), Ok(count) if count > 0) {}
            flag.store(true, Ordering::Release);
        });
    }
    match run_node(&config, until, &stop, &mut |event| describe(&event)) {
        Ok(()) => ExitCode::SUCCESS,
        // A halt was already described as it happened.
        Err(chain_node::node::RunError::Halted(_)) => ExitCode::FAILURE,
        Err(error) => fail(error),
    }
}

/// `run`'s flags, in any order, each at most once.
fn run_command(path: &str, flags: &[&str]) -> ExitCode {
    let mut until = None;
    let mut stop_when_stdin_closes = false;
    let mut rest = flags;
    while let Some((flag, tail)) = rest.split_first() {
        match *flag {
            "--stop-when-stdin-closes" if !stop_when_stdin_closes => {
                stop_when_stdin_closes = true;
                rest = tail;
            }
            "--until-height" if until.is_none() => {
                let Some((height, tail)) = tail.split_first() else {
                    return usage_error();
                };
                match height.parse::<u64>() {
                    Ok(height) => until = Some(BlockHeight(height)),
                    Err(_) => {
                        return fail(format!(
                            "--until-height wants a block height, not {height:?}"
                        ))
                    }
                }
                rest = tail;
            }
            _ => return usage_error(),
        }
    }
    run(path, until, stop_when_stdin_closes)
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

/// `--name value` pairs, each of a name in `allowed` and none repeated; `None`
/// if the arguments are anything else.
fn flag_pairs<'a>(args: &[&'a str], allowed: &[&str]) -> Option<Vec<(&'a str, &'a str)>> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    for pair in args.chunks(2) {
        let [name, value] = pair else { return None };
        if !allowed.contains(name) || pairs.iter().any(|(seen, _)| seen == name) {
            return None;
        }
        pairs.push((name, value));
    }
    Some(pairs)
}

/// The value given for `name`, parsed, or `default` if it was not given.
fn flag_value<T: FromStr>(
    pairs: &[(&str, &str)],
    name: &str,
    default: Option<T>,
) -> Result<Option<T>, String> {
    match pairs.iter().find(|(given, _)| *given == name) {
        None => Ok(default),
        Some((_, value)) => value
            .parse()
            .map(Some)
            .map_err(|_| format!("{name} wants a number, not {value:?}")),
    }
}

fn devnet_init(dir: &str, flags: &[&str]) -> ExitCode {
    let Some(pairs) = flag_pairs(flags, &["--validators", "--base-port"]) else {
        return usage_error();
    };
    let (validators, base_port) = match (
        flag_value::<usize>(&pairs, "--validators", Some(4)),
        flag_value::<u16>(&pairs, "--base-port", Some(DEFAULT_BASE_PORT)),
    ) {
        (Ok(Some(validators)), Ok(Some(base_port))) => (validators, base_port),
        (Err(error), _) | (_, Err(error)) => return fail(error),
        _ => return usage_error(),
    };
    match generate(Path::new(dir), validators, base_port) {
        Ok(nodes) => {
            println!(
                "INSECURE development network: every consensus key is derived from a public seed."
            );
            println!("wrote {} validators to {dir}:", nodes.len());
            for node in &nodes {
                println!(
                    "  node{}  {}  {}",
                    node.number,
                    chain_text::format_address(&node.validator),
                    node.listen
                );
            }
            println!("run it with: chain-node devnet start {dir}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn devnet_start(dir: &str, flags: &[&str]) -> ExitCode {
    let Some(pairs) = flag_pairs(flags, &["--until-height"]) else {
        return usage_error();
    };
    let until_height = match flag_value::<u64>(&pairs, "--until-height", None) {
        Ok(height) => height,
        Err(error) => return fail(error),
    };
    let node_exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return fail(format!("cannot find this program: {error}")),
    };
    let signer_exe =
        node_exe.with_file_name(format!("chain-signer{}", std::env::consts::EXE_SUFFIX));
    if !signer_exe.is_file() {
        return fail(format!(
            "{} not found; build it with: cargo build -p chain-node",
            signer_exe.display()
        ));
    }
    let options = LaunchOptions {
        node_exe: &node_exe,
        signer_exe: &signer_exe,
        until_height,
    };
    match launch(Path::new(dir), options, &mut |line| println!("{line}")) {
        Ok(()) => ExitCode::SUCCESS,
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
        ["run", path, flags @ ..] => run_command(path, flags),
        ["network-key", path] => network_key(path),
        ["devnet", "init", dir, flags @ ..] => devnet_init(dir, flags),
        ["devnet", "start", dir, flags @ ..] => devnet_start(dir, flags),
        _ => usage_error(),
    }
}
