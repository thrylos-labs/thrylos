//! `chain-node`: run a validator.
//!
//! ```text
//! chain-node run <config.json> [--until-height <n>] [--stop-when-stdin-closes]
//!                                                     run the node
//! chain-node network-key <file>                       make a transport key
//! chain-node devnet init <dir> [--validators <n>] [--base-port <port>]
//!                          [--block-interval-ms <ms>] write a local network
//! chain-node testnet init <dir> --chain-id <n> --operator <pubkey-hex>...
//!             [--allocate <pubkey-hex>:<amount>]... write a real network
//! chain-node devnet start <dir> [--until-height <n>]  run a generated network
//! chain-node devnet bump <dir> [--node <n>] [--account <1-4>] [--amount <n>]
//!                                                     send a transaction to a running one
//! chain-node devnet fund <dir> <address> [--node <n>] [--account <1-4>]
//!                                      [--amount <THRY>] fund a local wallet or faucet
//! chain-node devnet check <dir>                       is it committing, and do the nodes agree?
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
//! of signing. Killing a node at any moment is also safe to resume from: if it
//! dies after its signer has recorded a signature and before it has recorded
//! that signature itself, the signer gives the same signature again when the
//! restarted node asks for the same message. Do not use the flag from a shell
//! or a service manager that gives the node an empty standard input, which is
//! closed at once.
//!
//! `network-key` creates the file a node's `network_key` names and prints the
//! public key its peers list to trust it. It refuses to overwrite a file.
//!
//! `devnet init` writes the files of a network of validators on this machine
//! (see `chain_node::devnet`; **insecure**, for development only) and refuses a
//! directory that holds anything. `testnet init` writes the same kind of
//! directory with a real, chosen chain ID, real random consensus keys, and a
//! genesis that funds only the addresses it is told to (see
//! `chain_node::alpha`); a validator's own operator key is an ordinary
//! `thrylos` wallet, made and held the same way any account's is. `devnet
//! start` runs either kind: a `chain-signer` and a `chain-node` per
//! validator, logging to files in their directories, until every node has
//! ended. With `--until-height` it runs until every node has committed that
//! height and then stops them all: a node that joined late is waited for,
//! and the chain goes on meanwhile. (`run --until-height` is different: each
//! node stops as it gets there, so a node that has fallen behind by then
//! cannot catch up once the others have stopped.)

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chain_genesis::hex;
use chain_node::client::{self, ClientError};
use chain_node::config::create_network_key;
use chain_node::config::DEFAULT_BLOCK_INTERVAL_MS;
use chain_node::devnet::{generate, DEFAULT_BASE_PORT};
use chain_node::event_loop::committed_line;
use chain_node::health;
use chain_node::launch::{launch, LaunchOptions, RestartPolicy};
use chain_node::{run_node, NodeConfig, NodeEvent};
use chain_types::BlockHeight;

const USAGE: &str = "usage:
  chain-node run <config.json> [--until-height <n>] [--stop-when-stdin-closes]
  chain-node network-key <file>
  chain-node devnet init <dir> [--validators <n>] [--base-port <port>]
                          [--block-interval-ms <ms>]
  chain-node testnet init <dir> --chain-id <n> --operator <pubkey-hex>...
                          [--allocate <pubkey-hex>:<amount>]...
                          [--genesis-time <unix-ms>] [--base-port <port>]
                          [--block-interval-ms <ms>]
  chain-node devnet start <dir> [--until-height <n>]
  chain-node devnet bump <dir> [--node <n>] [--account <1-4>] [--amount <n>]
  chain-node devnet fund <dir> <address> [--node <n>] [--account <1-4>]
                          [--amount <THRY>]
  chain-node devnet check <dir>
  chain-node --help | --version

`chain-node --help` says what each command does.";

const HELP: &str = "chain-node runs a Thrylos validator, and can start a small local network of
them to try. The local network's keys are public test keys: never use it for
anything real.

To try it (four validators on this machine; keep the path short):

  chain-node devnet init /tmp/thrylos-devnet
  chain-node devnet start /tmp/thrylos-devnet      Ctrl-C stops it

and then, in another terminal:

  chain-node devnet bump /tmp/thrylos-devnet       send a transaction
  chain-node devnet check /tmp/thrylos-devnet      is it committing?

The commands:

  chain-node run <config.json> [--until-height <n>] [--stop-when-stdin-closes]
      Run one node from its configuration file. It keeps running until it is
      stopped, or until its chain reaches the height given.

  chain-node network-key <file>
      Make a node's network key, and print the public key its peers must list.

  chain-node devnet init <dir> [--validators <n>] [--base-port <port>]
                          [--block-interval-ms <ms>]
      Write the files of a local network. <dir> must be new or empty. By
      default that is 4 validators (up to 65) making a block every 1000 ms.
      INSECURE: every consensus key is derived from a small public seed.

  chain-node testnet init <dir> --chain-id <n> --operator <pubkey-hex>...
                          [--allocate <pubkey-hex>:<amount>]...
                          [--genesis-time <unix-ms>] [--base-port <port>]
                          [--block-interval-ms <ms>]
      Write the files of a real network: one validator per --operator, each
      with a freshly and randomly generated consensus key. An operator is a
      public key, not an address (`thrylos setup` then `thrylos address
      --hex`); genesis allocates funds only to --allocate, never implicitly.
      --chain-id must be unique to this network. <dir> must be new or empty.

  chain-node devnet start <dir> [--until-height <n>]
      Run a network: one node and one signer for each validator. Despite the
      name this runs any generated network, `devnet init`'s or `testnet
      init`'s. It says where each node's log and RPC are, and what to try
      next.

  chain-node devnet bump <dir> [--node <n>] [--account <1-4>] [--amount <n>]
      Send one transaction to a running network from a funded test account, and
      say whether it succeeded. It adds <amount> (1 by default) to a test
      counter; <node> (1 by default) is the node it is sent to.

  chain-node devnet fund <dir> <address> [--node <n>] [--account <1-4>]
                          [--amount <THRY>]
      Send test THRY to a wallet or faucet from a public development account.
      The default is 100 THRY from account 1 through node 1. This command only
      exists under devnet; it has no production privilege or minting power.

  chain-node devnet check <dir>
      Ask every node whether it is committing, and whether they agree on the
      last block. It exits 1 if anything is wrong, and says what.

  chain-node --help | --version";

fn fail(message: impl core::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

/// What to add when nothing answered: how to start the network, in a command
/// that can be pasted as it is.
fn not_running_hint(dir: &str) -> String {
    let program = std::env::current_exe().map_or_else(
        |_| "chain-node".to_owned(),
        |path| path.display().to_string(),
    );
    format!(
        "is the network running? Start it with: {program} devnet start {dir} \
         (a network takes a few seconds to come up)"
    )
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
    let Some(pairs) = flag_pairs(
        flags,
        &["--validators", "--base-port", "--block-interval-ms"],
    ) else {
        return usage_error();
    };
    let (validators, base_port, interval) = match (
        flag_value::<usize>(&pairs, "--validators", Some(4)),
        flag_value::<u16>(&pairs, "--base-port", Some(DEFAULT_BASE_PORT)),
        flag_value::<u64>(
            &pairs,
            "--block-interval-ms",
            Some(DEFAULT_BLOCK_INTERVAL_MS),
        ),
    ) {
        (Ok(Some(validators)), Ok(Some(base_port)), Ok(Some(interval))) => {
            (validators, base_port, interval)
        }
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => return fail(error),
        _ => return usage_error(),
    };
    match generate(Path::new(dir), validators, base_port, interval) {
        Ok(nodes) => {
            println!(
                "INSECURE development network: every consensus key is derived from a public seed."
            );
            println!("wrote {} validators to {dir}:", nodes.len());
            for node in &nodes {
                println!(
                    "  node{}  {}  peers {}  rpc {}",
                    node.number,
                    chain_text::format_address(&node.validator),
                    node.listen,
                    node.rpc
                );
            }
            println!("run it with: chain-node devnet start {dir}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn devnet_bump(dir: &str, flags: &[&str]) -> ExitCode {
    let Some(pairs) = flag_pairs(flags, &["--node", "--account", "--amount"]) else {
        return usage_error();
    };
    let (node, account, amount) = match (
        flag_value::<usize>(&pairs, "--node", Some(1)),
        flag_value::<u8>(&pairs, "--account", Some(1)),
        flag_value::<u64>(&pairs, "--amount", Some(1)),
    ) {
        (Ok(Some(node)), Ok(Some(account)), Ok(Some(amount))) => (node, account, amount),
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => return fail(error),
        _ => return usage_error(),
    };
    match client::bump(Path::new(dir), node, account, amount, &mut |line| {
        println!("{line}");
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let nothing_answered = matches!(error, ClientError::Unreachable { .. });
            let failed = fail(error);
            if nothing_answered {
                eprintln!("{}", not_running_hint(dir));
            }
            failed
        }
    }
}

fn devnet_fund(dir: &str, address: &str, flags: &[&str]) -> ExitCode {
    let Some(pairs) = flag_pairs(flags, &["--node", "--account", "--amount"]) else {
        return usage_error();
    };
    let (node, account) = match (
        flag_value::<usize>(&pairs, "--node", Some(1)),
        flag_value::<u8>(&pairs, "--account", Some(1)),
    ) {
        (Ok(Some(node)), Ok(Some(account))) => (node, account),
        (Err(error), _) | (_, Err(error)) => return fail(error),
        _ => return usage_error(),
    };
    let recipient = match chain_text::parse_address(address) {
        Ok(address) => address,
        Err(error) => return fail(format!("address: {error}")),
    };
    let amount_text = pairs
        .iter()
        .find(|(name, _)| *name == "--amount")
        .map_or("100", |(_, value)| *value);
    let amount = match chain_text::parse_amount(amount_text) {
        Ok(0) => return fail("--amount must be more than zero"),
        Ok(amount) => amount,
        Err(error) => return fail(format!("--amount: {error}")),
    };
    match client::devnet_transfer(
        Path::new(dir),
        node,
        account,
        recipient,
        amount,
        &mut |line| println!("{line}"),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let nothing_answered = matches!(error, ClientError::Unreachable { .. });
            let failed = fail(error);
            if nothing_answered {
                eprintln!("{}", not_running_hint(dir));
            }
            failed
        }
    }
}

/// Every `--flag value` pair in `flags`, in order, without `flag_pairs`'s
/// restriction to one of each: `testnet init` takes `--operator` and
/// `--allocate` any number of times.
fn flag_occurrences<'a>(flags: &[&'a str]) -> Option<Vec<(&'a str, &'a str)>> {
    let mut pairs = Vec::new();
    for pair in flags.chunks(2) {
        let [name, value] = pair else { return None };
        pairs.push((*name, *value));
    }
    Some(pairs)
}

fn parse_public_key(text: &str) -> Result<chain_types::PublicKey, String> {
    let bytes = hex::decode::<32>(text).map_err(|error| format!("{text:?}: {error}"))?;
    chain_types::PublicKey::from_ed25519_bytes(bytes)
        .map_err(|_| format!("{text:?} is not a valid Ed25519 public key"))
}

fn parse_allocation(text: &str) -> Result<chain_exec::genesis_config::Allocation, String> {
    let (key_text, amount_text) = text
        .split_once(':')
        .ok_or_else(|| format!("--allocate wants <public-key-hex>:<amount>, not {text:?}"))?;
    let owner = parse_public_key(key_text)?;
    let amount = chain_text::parse_amount(amount_text).map_err(|error| error.to_string())?;
    Ok(chain_exec::genesis_config::Allocation { owner, amount })
}

fn testnet_init(dir: &str, flags: &[&str]) -> ExitCode {
    let Some(pairs) = flag_occurrences(flags) else {
        return usage_error();
    };
    let allowed = [
        "--operator",
        "--allocate",
        "--chain-id",
        "--genesis-time",
        "--base-port",
        "--block-interval-ms",
    ];
    if pairs.iter().any(|(name, _)| !allowed.contains(name)) {
        return usage_error();
    }

    let mut operators = Vec::new();
    let mut allocations = Vec::new();
    for (name, value) in &pairs {
        match *name {
            "--operator" => match parse_public_key(value) {
                Ok(key) => operators.push(key),
                Err(error) => return fail(format!("--operator {error}")),
            },
            "--allocate" => match parse_allocation(value) {
                Ok(allocation) => allocations.push(allocation),
                Err(error) => return fail(error),
            },
            _ => {}
        }
    }
    if operators.is_empty() {
        return fail(
            "at least one --operator <public-key-hex> is required (make one with \
             `thrylos setup` then `thrylos address --hex`)",
        );
    }
    let chain_id = match flag_value::<u64>(&pairs, "--chain-id", None) {
        Ok(Some(chain_id)) => chain_id,
        Ok(None) => {
            return fail(
                "--chain-id is required: choose a value unique to this network, never reused \
                 from devnet's 1337 or another testnet's",
            );
        }
        Err(error) => return fail(error),
    };
    let genesis_time_ms =
        match flag_value::<u64>(&pairs, "--genesis-time", Some(chain_node::clock::now_ms())) {
            Ok(Some(value)) => value,
            Ok(None) => return usage_error(),
            Err(error) => return fail(error),
        };
    let base_port = match flag_value::<u16>(&pairs, "--base-port", Some(DEFAULT_BASE_PORT)) {
        Ok(Some(value)) => value,
        Ok(None) => return usage_error(),
        Err(error) => return fail(error),
    };
    let block_interval_ms = match flag_value::<u64>(
        &pairs,
        "--block-interval-ms",
        Some(DEFAULT_BLOCK_INTERVAL_MS),
    ) {
        Ok(Some(value)) => value,
        Ok(None) => return usage_error(),
        Err(error) => return fail(error),
    };

    match chain_node::alpha::init(
        Path::new(dir),
        &operators,
        allocations,
        chain_id,
        genesis_time_ms,
        base_port,
        block_interval_ms,
    ) {
        Ok(nodes) => {
            println!(
                "wrote {} validators to {dir}, chain ID {chain_id}:",
                nodes.len()
            );
            for node in &nodes {
                println!(
                    "  node{}  {}  peers {}  rpc {}",
                    node.number,
                    chain_text::format_address(&node.validator),
                    node.listen,
                    node.rpc
                );
            }
            println!(
                "run it with: chain-node devnet start {dir}  (that command's name is generic; \
                 it runs any generated network, not only an insecure devnet one)"
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

/// Exits 0 if the network is committing and its nodes agree, 1 if not.
fn devnet_check(dir: &str) -> ExitCode {
    match health::check(Path::new(dir)) {
        Err(error) => fail(error),
        Ok(found) => {
            for note in &found.notes {
                println!("{note}");
            }
            if found.problems.is_empty() {
                println!("{}", found.verdict());
                return ExitCode::SUCCESS;
            }
            for problem in &found.problems {
                eprintln!("problem: {problem}");
            }
            if found.nobody_answered {
                eprintln!("{}", not_running_hint(dir));
            }
            // The last line: the whole finding in one.
            eprintln!("{}", found.verdict());
            ExitCode::FAILURE
        }
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
        // Run to a height, a node that stops is left stopped (the run is a test);
        // run as a service, one that stops is started again.
        restart: until_height.is_none().then(RestartPolicy::service),
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
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        ["-V" | "--version"] => {
            println!("chain-node {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["run", path, flags @ ..] => run_command(path, flags),
        ["network-key", path] => network_key(path),
        ["devnet", "init", dir, flags @ ..] => devnet_init(dir, flags),
        ["testnet", "init", dir, flags @ ..] => testnet_init(dir, flags),
        ["devnet", "start", dir, flags @ ..] => devnet_start(dir, flags),
        ["devnet", "bump", dir, flags @ ..] => devnet_bump(dir, flags),
        ["devnet", "fund", dir, address, flags @ ..] => devnet_fund(dir, address, flags),
        ["devnet", "check", dir] => devnet_check(dir),
        _ => usage_error(),
    }
}
