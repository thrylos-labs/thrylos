//! `thrylos`: the small, user-facing account CLI for the core-network alpha.

// JSON objects have fixed, checked field names throughout this presentation
// layer. Missing fields become `null` and are turned into readable errors.
#![allow(clippy::indexing_slicing)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chain_exec::native::MIN_PROTOCOL_CALL_GAS;
use chain_node::client::{
    balance_text, signed_transfer, submit_transaction, wait_for_inclusion, ClientError,
    EXPIRES_AFTER,
};
use chain_node::network_profile;
use chain_node::remote_rpc::Endpoint;
use chain_node::wallet::Wallet;
use chain_rpc::hex;
use chain_text::{format_address, format_amount, parse_address, parse_amount};
use serde_json::{json, Value};

const DEFAULT_RPC: &str = "127.0.0.1:26660";

const USAGE: &str = "Thrylos core-network alpha

Usage:
  thrylos setup
  thrylos address [--hex]
  thrylos balance [address]
  thrylos send <amount> <address> [--yes]
  thrylos tx <hash>
  thrylos status
  thrylos network add <name> <rpc>
  thrylos network use <name>
  thrylos network list
  thrylos network remove <name>

Options:
  --rpc <rpc>         node or gateway RPC: host:port for a local node, or an
                       http(s):// URL for a public gateway (default
                       127.0.0.1:26660, then THRYLOS_RPC, then the active
                       saved network)
  --wallet <file>     wallet key (default ~/.thrylos/wallet.key or THRYLOS_WALLET)
  --yes               send without the confirmation prompt
  --hex               with `address`, print the raw public key instead
                       (what a genesis allocation or validator entry needs;
                       an address cannot be turned back into one)
  --help              show this help
  --version           show the version

Examples:
  thrylos setup
  thrylos address
  thrylos balance
  thrylos send 2.5 thry1...
  thrylos network add testnet-alpha https://rpc.testnet.example
  thrylos network use testnet-alpha
  thrylos balance";

struct Options {
    rpc: Endpoint,
    wallet: PathBuf,
    yes: bool,
    hex: bool,
    positional: Vec<String>,
}

fn option_value(flag: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

/// `--rpc`, then `THRYLOS_RPC`, then the active saved network
/// (`thrylos network use`), then the local-node default.
fn resolve_rpc(flag: Option<String>) -> Result<String, String> {
    if let Some(text) = flag {
        return Ok(text);
    }
    if let Ok(text) = std::env::var("THRYLOS_RPC") {
        return Ok(text);
    }
    let Ok(networks_path) = network_profile::default_path() else {
        return Ok(DEFAULT_RPC.to_owned());
    };
    match network_profile::active_rpc(&networks_path) {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Ok(DEFAULT_RPC.to_owned()),
        Err(error) => Err(error.to_string()),
    }
}

fn parse_options() -> Result<Options, String> {
    let mut args = std::env::args();
    let _program = args.next();
    let mut rpc_flag = None;
    let mut wallet = chain_node::wallet::default_path().map_err(|error| error.to_string())?;
    let mut yes = false;
    let mut hex_flag = false;
    let mut positional = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rpc" => rpc_flag = Some(option_value("--rpc", &mut args)?),
            "--wallet" => wallet = PathBuf::from(option_value("--wallet", &mut args)?),
            "--yes" => yes = true,
            "--hex" => hex_flag = true,
            flag if flag.starts_with("--") && flag != "--help" && flag != "--version" => {
                return Err(format!("unknown option {flag:?}"));
            }
            _ => positional.push(arg),
        }
    }
    let rpc_text = resolve_rpc(rpc_flag)?;
    let rpc = Endpoint::parse(&rpc_text)?;
    Ok(Options {
        rpc,
        wallet,
        hex: hex_flag,
        yes,
        positional,
    })
}

fn load_wallet(path: &Path) -> Result<Wallet, String> {
    if !path.exists() {
        return Err(format!(
            "no wallet exists at {}; make one with `thrylos setup`",
            path.display()
        ));
    }
    Wallet::load(path).map_err(|error| error.to_string())
}

fn field_u64(value: &Value, field: &str, context: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("the RPC's {context} response has no {field}"))
}

fn setup(path: &Path) -> Result<(), String> {
    let wallet = Wallet::create(path).map_err(|error| error.to_string())?;
    println!("Wallet ready.");
    println!("Address: {}", format_address(&wallet.address()));
    println!("Saved securely to: {}", path.display());
    println!("Next: get test THRY from the faucet, then run `thrylos balance`.");
    Ok(())
}

fn address(path: &Path, hex: bool) -> Result<(), String> {
    let wallet = load_wallet(path)?;
    if hex {
        // The raw public key, not the address: a genesis allocation or
        // validator entry (docs/core-network-alpha.md) is written by public
        // key, and an address cannot be turned back into one.
        println!("{}", encode_public_key(&wallet));
    } else {
        println!("{}", format_address(&wallet.address()));
    }
    Ok(())
}

fn encode_public_key(wallet: &Wallet) -> String {
    hex::encode(&wallet.public_key().ed25519_bytes())
}

fn account(client: &Endpoint, address: chain_types::Address) -> Result<Value, String> {
    client
        .call("account", &json!({ "address": format_address(&address) }))
        .map_err(|error| error.to_string())
}

fn balance(options: &Options, requested: Option<&str>) -> Result<(), String> {
    let address = match requested {
        Some(text) => parse_address(text).map_err(|error| error.to_string())?,
        None => load_wallet(&options.wallet)?.address(),
    };
    let result = account(&options.rpc, address)?;
    println!("Address: {}", format_address(&address));
    println!("Balance: {}", balance_text(result["balance"].as_str()));
    println!("At height: {}", result["height"]);
    Ok(())
}

fn status(client: &Endpoint) -> Result<(), String> {
    let status = client
        .call("status", &json!({}))
        .map_err(|error| error.to_string())?;
    if let Some(reason) = status["halted"].as_str() {
        return Err(format!("the node is halted: {reason}"));
    }
    println!("Connected to Thrylos chain {}.", status["chainId"]);
    println!(
        "Height: {} · peers: {} · pending transactions: {}",
        status["latest"]["height"], status["peers"], status["mempool"]
    );
    let latest_hash = status["latest"]["hash"]
        .as_str()
        .ok_or_else(|| "the RPC's status response has no latest block hash".to_owned())?;
    println!("Latest block: {latest_hash}");
    Ok(())
}

fn confirm(amount: u128, recipient: chain_types::Address, maximum_fee: u128) -> Result<(), String> {
    println!("Send {}", format_amount(amount));
    println!("To: {}", format_address(&recipient));
    println!("Maximum network fee: {}", format_amount(maximum_fee));
    print!("Type yes to send: ");
    io::stdout().flush().map_err(|error| error.to_string())?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|error| error.to_string())?;
    if answer.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err("cancelled; nothing was sent".into())
    }
}

fn describe_inclusion(hash: &str, found: &Value) -> Result<(), String> {
    println!(
        "Included in block {} (position {}).",
        found["height"], found["index"]
    );
    match found["outcome"]["status"].as_str() {
        Some("success") => {
            println!("Success: {hash}");
            Ok(())
        }
        Some("aborted") => Err(ClientError::Aborted {
            hash: hash.to_owned(),
            height: found["height"].as_u64().unwrap_or(0),
            reason: found["outcome"]["reason"]
                .as_str()
                .unwrap_or("?")
                .to_owned(),
            message: found["outcome"]["message"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
        }
        .to_string()),
        _ => Err(format!(
            "transaction {hash} was included, but this node has no recorded outcome"
        )),
    }
}

fn send(options: &Options, amount_text: &str, recipient_text: &str) -> Result<(), String> {
    let amount = parse_amount(amount_text).map_err(|error| error.to_string())?;
    if amount == 0 {
        return Err("the amount must be more than zero".into());
    }
    let recipient = parse_address(recipient_text).map_err(|error| error.to_string())?;
    let wallet = load_wallet(&options.wallet)?;
    if recipient == wallet.address() {
        return Err("the recipient is your own address; nothing needs to be sent".into());
    }
    let client = &options.rpc;
    let network = client
        .call("status", &json!({}))
        .map_err(|error| error.to_string())?;
    let chain_id = field_u64(&network, "chainId", "status")?;
    let height = field_u64(&network["latest"], "height", "status")?;
    let base_fee = field_u64(&network, "baseFee", "status")?;
    let max_fee_per_gas = base_fee.saturating_mul(2).max(1);
    let maximum_fee = u128::from(MIN_PROTOCOL_CALL_GAS)
        .checked_mul(u128::from(max_fee_per_gas))
        .ok_or_else(|| "the node reported a fee too large to use".to_owned())?;

    let current = account(client, wallet.address())?;
    let sequence = field_u64(&current, "nextSequenceNumber", "account")?;
    let balance: u128 = current["balance"]
        .as_str()
        .ok_or_else(|| "the RPC's account response has no balance".to_owned())?
        .parse()
        .map_err(|_| "the RPC returned an invalid account balance".to_owned())?;
    let needed = amount
        .checked_add(maximum_fee)
        .ok_or_else(|| "the amount and fee are too large".to_owned())?;
    if needed > balance {
        return Err(format!(
            "not enough THRY: the wallet has {}, but {} plus a maximum fee of {} is needed",
            format_amount(balance),
            format_amount(amount),
            format_amount(maximum_fee)
        ));
    }

    if !options.yes {
        confirm(amount, recipient, maximum_fee)?;
    }
    let transaction = signed_transfer(
        wallet.signing_key(),
        chain_id,
        sequence,
        height.saturating_add(EXPIRES_AFTER),
        recipient,
        amount,
        max_fee_per_gas,
    )
    .map_err(|error| error.to_string())?;
    let hash = submit_transaction(client, &transaction).map_err(|error| error.to_string())?;
    println!("Sent: {hash}");
    println!("Waiting for inclusion…");
    let found = wait_for_inclusion(client, &hash).map_err(|error| error.to_string())?;
    describe_inclusion(&hash, &found)
}

fn transaction(client: &Endpoint, hash: &str) -> Result<(), String> {
    let found = client
        .call("transaction", &json!({ "hash": hash }))
        .map_err(|error| error.to_string())?;
    match found["status"].as_str() {
        Some("pending") => println!("Pending: {hash}"),
        Some("included") => {
            println!("Transaction: {hash}");
            println!(
                "Included in block {} (position {}).",
                found["height"], found["index"]
            );
            println!(
                "Outcome: {}",
                found["outcome"]["status"].as_str().unwrap_or("unknown")
            );
            if let Some(message) = found["outcome"]["message"].as_str() {
                println!("Reason: {message}");
            }
        }
        _ => return Err("the RPC returned an unknown transaction status".into()),
    }
    Ok(())
}

fn network(rest: &[String]) -> Result<(), String> {
    let path = network_profile::default_path().map_err(|error| error.to_string())?;
    let Some((subcommand, rest)) = rest.split_first() else {
        return Err(
            "usage: thrylos network <add <name> <rpc> | use <name> | list | remove <name>>".into(),
        );
    };
    match subcommand.as_str() {
        "add" => {
            let values = exactly(rest, 2, "thrylos network add <name> <rpc>")?;
            let name = &values[0];
            let rpc = &values[1];
            network_profile::add(&path, name, rpc).map_err(|error| error.to_string())?;
            println!("Saved {name:?} as {rpc}. Use it with `thrylos network use {name}`.");
            Ok(())
        }
        "use" => {
            let values = exactly(rest, 1, "thrylos network use <name>")?;
            let name = &values[0];
            network_profile::use_network(&path, name).map_err(|error| error.to_string())?;
            println!("Now using {name:?}.");
            Ok(())
        }
        "remove" => {
            let values = exactly(rest, 1, "thrylos network remove <name>")?;
            let name = &values[0];
            network_profile::remove(&path, name).map_err(|error| error.to_string())?;
            println!("Removed {name:?}.");
            Ok(())
        }
        "list" => {
            exactly(rest, 0, "thrylos network list")?;
            let (current, networks) = network_profile::list(&path).map_err(|error| error.to_string())?;
            if networks.is_empty() {
                println!("No saved networks. Add one with `thrylos network add <name> <rpc>`.");
                return Ok(());
            }
            for (name, rpc) in &networks {
                let marker = if current.as_deref() == Some(name.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!("{marker} {name}  {rpc}");
            }
            Ok(())
        }
        other => Err(format!(
            "unknown `thrylos network {other}`\n\nusage: thrylos network <add <name> <rpc> | use <name> | list | remove <name>>"
        )),
    }
}

fn exactly<'a>(args: &'a [String], count: usize, form: &str) -> Result<&'a [String], String> {
    if args.len() == count {
        Ok(args)
    } else {
        Err(format!("usage: {form}"))
    }
}

fn run(options: &Options) -> Result<(), String> {
    let Some((command, rest)) = options.positional.split_first() else {
        return Err(USAGE.into());
    };
    match command.as_str() {
        "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        "--version" => {
            println!("thrylos {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "setup" => {
            exactly(rest, 0, "thrylos setup")?;
            setup(&options.wallet)
        }
        "address" => {
            exactly(rest, 0, "thrylos address [--hex]")?;
            address(&options.wallet, options.hex)
        }
        "balance" => {
            if rest.len() > 1 {
                return Err("usage: thrylos balance [address]".into());
            }
            balance(options, rest.first().map(String::as_str))
        }
        "status" => {
            exactly(rest, 0, "thrylos status")?;
            status(&options.rpc)
        }
        "network" => network(rest),
        "send" => {
            let values = exactly(rest, 2, "thrylos send <amount> <address> [--yes]")?;
            let Some((amount, tail)) = values.split_first() else {
                return Err("usage: thrylos send <amount> <address> [--yes]".into());
            };
            let Some(recipient) = tail.first() else {
                return Err("usage: thrylos send <amount> <address> [--yes]".into());
            };
            send(options, amount, recipient)
        }
        "tx" => {
            let values = exactly(rest, 1, "thrylos tx <hash>")?;
            let Some(hash) = values.first() else {
                return Err("usage: thrylos tx <hash>".into());
            };
            transaction(&options.rpc, hash)
        }
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    }
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
