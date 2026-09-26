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
  thrylos move new <dir> [--name <module>]
  thrylos move build [dir] [--dep <name>=<dir>@<thry1...>]...
  thrylos move test [dir] [--dep <name>=<dir>@<thry1...>]... [--filter <text>] [--gas <n>]
  thrylos move publish <package dir | module.mv...> [--yes]
  thrylos move call <package> <module> <function> [type:value ...] [--input <address>]... [--gas <n>] [--yes]
  thrylos move view <package> <module> <function> [type:value ...] [--input <address>]...
  thrylos move resources <owner>
  thrylos move resource <owner> <type> [--slot <n>]
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
  --gas <n>           with `move call`, the most gas the call may use
                       (default 20000, also the most nodes accept; only what is used is charged); with
                       `move test`, the most a test may use
  --dep <n>=<dir>@<a> with `move build`/`test`, a package already published at
                       address <a>, whose sources are in <dir>; this package
                       refers to it as <n>::module (repeatable)
  --input <address>   with `move call`, another address whose stored values the
                       call touches (repeatable). A call may touch only its
                       sender's, and those it declares.
  --filter <text>     with `move test`, only tests whose name contains this
  --name <module>     with `move new`, the first module's name
  --slot <n>          with `move resource`, which slot of the owner's drawers (default 0)
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
  thrylos balance
  thrylos move new hello
  thrylos move test hello
  thrylos move build hello
  thrylos move publish hello
  thrylos move call thry1... hello answer
  thrylos move call thry1... counter add u64:2 u64:3

Arguments to `move call` are written type:value: bool:true, u8:7 to u256:9,
address:thry1..., bytes:0x0a0b, string:text, vec:u64:1,2,3, or raw:0x... for
bytes you have already encoded.";

struct Options {
    rpc: Endpoint,
    wallet: PathBuf,
    yes: bool,
    gas: Option<u64>,
    deps: Vec<String>,
    filter: Option<String>,
    inputs: Vec<String>,
    slot: Option<u64>,
    name: Option<String>,
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
    let mut gas = None;
    let mut deps = Vec::new();
    let mut filter = None;
    let mut inputs = Vec::new();
    let mut slot = None;
    let mut name = None;
    let mut hex_flag = false;
    let mut positional = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--rpc" => rpc_flag = Some(option_value("--rpc", &mut args)?),
            "--wallet" => wallet = PathBuf::from(option_value("--wallet", &mut args)?),
            "--yes" => yes = true,
            "--gas" => {
                let text = option_value("--gas", &mut args)?;
                gas = Some(
                    text.parse::<u64>()
                        .map_err(|_| format!("--gas needs a whole number, not {text:?}"))?,
                );
            }
            "--dep" => deps.push(option_value("--dep", &mut args)?),
            "--filter" => filter = Some(option_value("--filter", &mut args)?),
            "--input" => inputs.push(option_value("--input", &mut args)?),
            "--slot" => {
                let text = option_value("--slot", &mut args)?;
                slot = Some(
                    text.parse::<u64>()
                        .map_err(|_| format!("--slot needs a whole number, not {text:?}"))?,
                );
            }
            "--name" => name = Some(option_value("--name", &mut args)?),
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
        gas,
        deps,
        filter,
        inputs,
        slot,
        name,
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

/// What a transaction needs to know about the network and the sender's account.
struct Position {
    chain_id: u64,
    height: u64,
    max_fee_per_gas: u64,
    sequence: u64,
    balance: u128,
}

fn position(client: &Endpoint, sender: chain_types::Address) -> Result<Position, String> {
    let network = client
        .call("status", &json!({}))
        .map_err(|error| error.to_string())?;
    let base_fee = field_u64(&network, "baseFee", "status")?;
    let current = account(client, sender)?;
    Ok(Position {
        chain_id: field_u64(&network, "chainId", "status")?,
        height: field_u64(&network["latest"], "height", "status")?,
        max_fee_per_gas: base_fee.saturating_mul(2).max(1),
        sequence: field_u64(&current, "nextSequenceNumber", "account")?,
        balance: current["balance"]
            .as_str()
            .ok_or_else(|| "the RPC's account response has no balance".to_owned())?
            .parse()
            .map_err(|_| "the RPC returned an invalid account balance".to_owned())?,
    })
}

fn ask(question: &str) -> Result<(), String> {
    print!("{question}");
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

fn submit_and_wait(
    client: &Endpoint,
    transaction: &chain_types::Transaction,
) -> Result<(), String> {
    let hash = submit_transaction(client, transaction).map_err(|error| error.to_string())?;
    println!("Sent: {hash}");
    println!("Waiting for inclusion…");
    let found = wait_for_inclusion(client, &hash).map_err(|error| error.to_string())?;
    describe_inclusion(&hash, &found)
}

fn move_publish(options: &Options, files: &[String]) -> Result<(), String> {
    use chain_exec::move_config::{MAX_MODULES_PER_PACKAGE, MAX_MODULE_BYTES, MAX_PACKAGE_BYTES};
    use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
    use chain_exec::publish::{package_address, publish_gas, PUBLISH_DEPOSIT_PER_KIB};

    if files.is_empty() {
        return Err("usage: thrylos move publish <package dir | module.mv...> [--yes]".into());
    }
    // A package directory means its last build.
    let from_build: Vec<String>;
    let files = match files {
        [dir] if Path::new(dir).is_dir() => {
            if chain_movetools::build_is_stale(Path::new(dir)) {
                println!("{dir} has not been built since its sources changed; building it first.");
                move_build(options, std::slice::from_ref(dir))?;
                println!();
            }
            from_build = chain_movetools::built_files(Path::new(dir))?
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            &from_build[..]
        }
        _ => files,
    };
    if files.len() > MAX_MODULES_PER_PACKAGE {
        return Err(format!(
            "a package has at most {MAX_MODULES_PER_PACKAGE} modules; {} were given",
            files.len()
        ));
    }
    let mut modules = Vec::with_capacity(files.len());
    let mut total = 0usize;
    for file in files {
        let bytes = std::fs::read(file).map_err(|error| format!("cannot read {file}: {error}"))?;
        if bytes.len() > MAX_MODULE_BYTES {
            return Err(format!(
                "{file} is {} bytes; a module can be at most {MAX_MODULE_BYTES}",
                bytes.len()
            ));
        }
        total = total.saturating_add(bytes.len());
        modules.push(bytes);
    }
    if total > MAX_PACKAGE_BYTES {
        return Err(format!(
            "the package is {total} bytes; the most allowed is {MAX_PACKAGE_BYTES}"
        ));
    }

    // What the network would say, before a fee is at stake.
    chain_movetools::check_bytes(&modules)
        .map_err(|reason| format!("the network would refuse this package: {reason}"))?;

    let wallet = load_wallet(&options.wallet)?;
    let at = position(&options.rpc, wallet.address())?;
    let id = chain_types::Address::from_bytes(
        package_address(&wallet.address(), at.sequence).into_bytes(),
    );
    let maximum_fee = u128::from(publish_gas(total)).saturating_mul(u128::from(at.max_fee_per_gas));
    let deposit = u128::try_from(total.div_ceil(1024))
        .unwrap_or(u128::MAX)
        .saturating_mul(PUBLISH_DEPOSIT_PER_KIB)
        .saturating_add(NEW_ENTRY_STORAGE_DEPOSIT);
    let needed = maximum_fee.saturating_add(deposit);
    if needed > at.balance {
        return Err(format!(
            "not enough THRY: the wallet has {}, but a deposit of {} plus a maximum fee of {} is needed",
            format_amount(at.balance),
            format_amount(deposit),
            format_amount(maximum_fee)
        ));
    }
    println!(
        "Publish {} module(s), {total} bytes. A package cannot be changed or removed once published.",
        modules.len()
    );
    println!("It will live at: {}", format_address(&id));
    println!(
        "Storage deposit (kept by the network): {}",
        format_amount(deposit)
    );
    println!("Maximum network fee: {}", format_amount(maximum_fee));
    if !options.yes {
        ask("Type yes to publish: ")?;
    }
    let transaction = chain_node::move_client::signed_publish(
        wallet.signing_key(),
        at.chain_id,
        at.sequence,
        at.height.saturating_add(EXPIRES_AFTER),
        modules,
        at.max_fee_per_gas,
    )?;
    submit_and_wait(&options.rpc, &transaction)?;
    println!("Package address: {}", format_address(&id));
    Ok(())
}

/// The package directory a `move` subcommand works on: the one argument, or
/// the current directory.
fn package_dir(rest: &[String], form: &str) -> Result<std::path::PathBuf, String> {
    match rest {
        [] => Ok(std::path::PathBuf::from(".")),
        [dir] => Ok(std::path::PathBuf::from(dir)),
        _ => Err(format!("usage: {form}")),
    }
}

fn movetools_options(
    options: &Options,
    dir: std::path::PathBuf,
) -> Result<chain_movetools::Options, String> {
    let mut deps = Vec::new();
    for text in &options.deps {
        let form = "--dep wants <name>=<dir>@<thry1...>";
        let (name, rest) = text
            .split_once('=')
            .ok_or_else(|| format!("{form}, not {text:?}"))?;
        let (dep_dir, address) = rest
            .rsplit_once('@')
            .ok_or_else(|| format!("{form}, not {text:?}"))?;
        let address = parse_address(address).map_err(|error| format!("--dep {name}: {error}"))?;
        deps.push(chain_movetools::Dependency {
            name: name.to_owned(),
            dir: std::path::PathBuf::from(dep_dir),
            address: chain_movetools::AccountAddress::new(*address.as_bytes()),
        });
    }
    Ok(chain_movetools::Options { dir, deps })
}

fn move_new(options: &Options, rest: &[String]) -> Result<(), String> {
    let [dir] = rest else {
        return Err("usage: thrylos move new <dir> [--name <module>]".into());
    };
    let path = std::path::Path::new(dir);
    let name = match &options.name {
        Some(name) => name.clone(),
        None => path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("hello")
            .replace('-', "_")
            .to_lowercase(),
    };
    chain_movetools::new_package(path, &name)?;
    println!("Made {dir} with one module, {name}, and two tests.");
    println!("Next: thrylos move test {dir}");
    Ok(())
}

fn move_build(options: &Options, rest: &[String]) -> Result<(), String> {
    let dir = package_dir(rest, "thrylos move build [dir]")?;
    let built = chain_movetools::build(&movetools_options(options, dir.clone())?)?;
    chain_movetools::check(&built)
        .map_err(|reason| format!("built, but the network would refuse this package: {reason}"))?;
    let out = chain_movetools::write_build(&dir, &built)?;
    println!(
        "Built {} module(s), {} bytes, into {}:",
        built.modules.len(),
        built.total_bytes(),
        out.display()
    );
    for (name, bytes) in &built.modules {
        println!("  {name}.mv  {} bytes", bytes.len());
    }
    println!(
        "The network's checks pass. Publish it with: thrylos move publish {}",
        dir.display()
    );
    Ok(())
}

fn move_test(options: &Options, rest: &[String]) -> Result<(), String> {
    let dir = package_dir(rest, "thrylos move test [dir]")?;
    let gas = options.gas.unwrap_or(chain_movetools::DEFAULT_TEST_GAS);
    let report = chain_movetools::run_tests(
        &movetools_options(options, dir)?,
        options.filter.as_deref(),
        gas,
    )?;
    for result in &report.results {
        match &result.outcome {
            chain_movetools::Outcome::Passed => println!("[ PASS ] {}", result.name),
            chain_movetools::Outcome::Failed(why) => println!("[ FAIL ] {}: {why}", result.name),
            chain_movetools::Outcome::Skipped(why) => println!("[ SKIP ] {}: {why}", result.name),
        }
    }
    println!(
        "{} passed, {} failed, {} skipped",
        report.passed(),
        report.failed(),
        report.skipped()
    );
    if report.results.is_empty() {
        println!("No tests found. A test is a function marked #[test].");
    }
    if report.ok() {
        Ok(())
    } else {
        Err(format!("{} test(s) failed", report.failed()))
    }
}

/// A type as the network names it: `0x<64 hex>::module::Name`. A package
/// address written as `thry1…` is turned into that; anything else is left as given.
fn canonical_type(text: &str) -> String {
    match text.split_once("::") {
        Some((first, rest)) => match parse_address(first) {
            Ok(address) => format!("0x{}::{rest}", hex::encode(address.as_bytes())),
            Err(_) => text.to_owned(),
        },
        None => text.to_owned(),
    }
}

fn move_resources(options: &Options, rest: &[String]) -> Result<(), String> {
    let [owner] = rest else {
        return Err("usage: thrylos move resources <owner>".into());
    };
    let address = parse_address(owner).map_err(|error| format!("the owner: {error}"))?;
    let found = options
        .rpc
        .call(
            "move_resources",
            &json!({ "owner": format_address(&address) }),
        )
        .map_err(|error| error.to_string())?;
    let list = found["resources"].as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        println!("{} has nothing stored.", format_address(&address));
        return Ok(());
    }
    println!(
        "{} has {} stored value(s):",
        format_address(&address),
        list.len()
    );
    for drawer in &list {
        println!(
            "  slot {}  {}  ({} bytes)",
            drawer["slot"],
            drawer["type"].as_str().unwrap_or("?"),
            drawer["bytes"]
        );
    }
    Ok(())
}

/// For a read of an empty drawer: the slots the owner does hold that type in, or how
/// much else they hold, so the answer is not just "nothing".
fn other_slots(options: &Options, owner: &chain_types::Address, type_name: &str) -> String {
    let Ok(found) = options
        .rpc
        .call("move_resources", &json!({ "owner": format_address(owner) }))
    else {
        return String::new();
    };
    let list = found["resources"].as_array().cloned().unwrap_or_default();
    let wanted = canonical_type(type_name);
    let slots: Vec<String> = list
        .iter()
        .filter(|drawer| drawer["type"].as_str() == Some(wanted.as_str()))
        .map(|drawer| drawer["slot"].to_string())
        .collect();
    if !slots.is_empty() {
        format!(
            "
It does hold this type in slot {}: use --slot.",
            slots.join(", ")
        )
    } else if list.is_empty() {
        String::new()
    } else {
        format!(
            "
It holds {} other stored value(s); `thrylos move resources` lists them.",
            list.len()
        )
    }
}

fn move_resource(options: &Options, rest: &[String]) -> Result<(), String> {
    let [owner, type_name] = rest else {
        return Err("usage: thrylos move resource <owner> <type> [--slot <n>]".into());
    };
    let address = parse_address(owner).map_err(|error| format!("the owner: {error}"))?;
    let found = options
        .rpc
        .call(
            "move_resource",
            &json!({
                "owner": format_address(&address),
                "type": canonical_type(type_name),
                "slot": options.slot.unwrap_or(0),
            }),
        )
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("is stored in slot") {
                format!("{message}{}", other_slots(options, &address, type_name))
            } else {
                message
            }
        })?;
    println!("Type: {}", found["type"].as_str().unwrap_or("?"));
    println!("Slot: {}", found["slot"]);
    println!("At height: {}", found["height"]);
    match found.get("value").filter(|value| !value.is_null()) {
        Some(value) => println!(
            "Value: {}",
            serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
        ),
        None => println!("Value: (its type could not be read; the raw bytes are below)"),
    }
    println!("Bytes: 0x{}", found["bytes"].as_str().unwrap_or(""));
    Ok(())
}

/// Ask the node what a call would do, without sending it: a `public` function
/// can be called and can return values, and a call's changes are reported and
/// not made.
fn move_view(options: &Options, rest: &[String]) -> Result<(), String> {
    let [package, module, function, arguments @ ..] = rest else {
        return Err(
            "usage: thrylos move view <package> <module> <function> [type:value ...] [--input <address>]..."
                .into(),
        );
    };
    let package =
        parse_address(package).map_err(|error| format!("the package address: {error}"))?;
    let encoded = arguments
        .iter()
        .map(|argument| chain_node::move_client::encode_argument(argument))
        .collect::<Result<Vec<_>, _>>()?;
    let wallet = load_wallet(&options.wallet)?;
    let declared = declared_inputs(options, arguments, &wallet.address())?;
    let at = position(&options.rpc, wallet.address())?;
    let transaction = chain_node::move_client::signed_call(
        wallet.signing_key(),
        at.chain_id,
        at.sequence,
        at.height.saturating_add(EXPIRES_AFTER),
        chain_node::move_client::DEFAULT_CALL_GAS,
        at.max_fee_per_gas,
        declared,
        package,
        module,
        function,
        encoded,
    )?;
    let mut bytes = Vec::new();
    chain_types::Encode::encode(&transaction, &mut bytes);
    let answer = options
        .rpc
        .call("simulate", &json!({ "transaction": hex::encode(&bytes) }))
        .map_err(|error| error.to_string())?;
    let gas = &answer["gasUsed"];
    if answer["status"] == "failed" {
        return Err(format!(
            "the call would fail: {} (used {gas} gas of at most {})",
            answer["reason"].as_str().unwrap_or("?"),
            answer["gasCap"]
        ));
    }
    println!("The call would succeed, using {gas} gas.");
    let returns = answer["returns"].as_array().cloned().unwrap_or_default();
    for (index, value) in returns.iter().enumerate() {
        println!(
            "Returns[{index}]: {}",
            serde_json::to_string(value).map_err(|error| error.to_string())?
        );
    }
    let changed = answer["drawersChanged"].as_u64().unwrap_or(0);
    if changed > 0 {
        let deposit: u128 = answer["deposit"]
            .as_str()
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        println!(
            "It would change {changed} stored value(s), with a storage deposit of {}.",
            format_amount(deposit)
        );
    }
    println!("Nothing was sent or changed.");
    Ok(())
}

/// The addresses a call declares: every `--input`, and every `address:` argument
/// (a call that names an address as an argument nearly always touches its drawers,
/// and forgetting to declare it aborts the call). The sender needs no declaring.
fn declared_inputs(
    options: &Options,
    arguments: &[String],
    sender: &chain_types::Address,
) -> Result<Vec<chain_types::Address>, String> {
    let mut declared: Vec<chain_types::Address> = Vec::new();
    for text in &options.inputs {
        declared.push(parse_address(text).map_err(|error| format!("--input {text}: {error}"))?);
    }
    for argument in arguments {
        if let Some(text) = argument.strip_prefix("address:") {
            if let Ok(address) = parse_address(text) {
                if &address != sender && !declared.contains(&address) {
                    declared.push(address);
                }
            }
        }
    }
    Ok(declared)
}

fn move_call(options: &Options, rest: &[String]) -> Result<(), String> {
    let [package, module, function, arguments @ ..] = rest else {
        return Err(
            "usage: thrylos move call <package> <module> <function> [type:value ...] [--gas <n>] [--yes]"
                .into(),
        );
    };
    let package =
        parse_address(package).map_err(|error| format!("the package address: {error}"))?;
    let encoded = arguments
        .iter()
        .map(|argument| chain_node::move_client::encode_argument(argument))
        .collect::<Result<Vec<_>, _>>()?;
    let gas = options
        .gas
        .unwrap_or(chain_node::move_client::DEFAULT_CALL_GAS);
    if gas < chain_types::MIN_GAS_LIMIT {
        return Err(format!(
            "--gas must be at least {}",
            chain_types::MIN_GAS_LIMIT
        ));
    }

    let wallet = load_wallet(&options.wallet)?;
    let at = position(&options.rpc, wallet.address())?;
    let maximum_fee = u128::from(gas).saturating_mul(u128::from(at.max_fee_per_gas));
    if maximum_fee > at.balance {
        return Err(format!(
            "not enough THRY: the wallet has {}, but a maximum fee of {} is needed",
            format_amount(at.balance),
            format_amount(maximum_fee)
        ));
    }
    println!("Call {module}::{function} in {}", format_address(&package));
    println!(
        "Arguments: {}",
        if arguments.is_empty() {
            "none".to_owned()
        } else {
            arguments.join(" ")
        }
    );
    let declared = declared_inputs(options, arguments, &wallet.address())?;
    for address in &declared {
        println!("Also touches: {}", format_address(address));
    }
    println!("Maximum network fee: {}", format_amount(maximum_fee));
    if !options.yes {
        ask("Type yes to send: ")?;
    }
    let transaction = chain_node::move_client::signed_call(
        wallet.signing_key(),
        at.chain_id,
        at.sequence,
        at.height.saturating_add(EXPIRES_AFTER),
        gas,
        at.max_fee_per_gas,
        declared,
        package,
        module,
        function,
        encoded,
    )?;
    submit_and_wait(&options.rpc, &transaction)
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
        "move" => match rest.split_first() {
            Some((sub, tail)) if sub == "new" => move_new(options, tail),
            Some((sub, tail)) if sub == "build" => move_build(options, tail),
            Some((sub, tail)) if sub == "test" => move_test(options, tail),
            Some((sub, tail)) if sub == "publish" => move_publish(options, tail),
            Some((sub, tail)) if sub == "call" => move_call(options, tail),
            Some((sub, tail)) if sub == "view" => move_view(options, tail),
            Some((sub, tail)) if sub == "resources" => move_resources(options, tail),
            Some((sub, tail)) if sub == "resource" => move_resource(options, tail),
            _ => Err("usage: thrylos move <new | build | test | publish | call | view | resource | resources> ...  (thrylos --help lists each)".into()),
        },
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
