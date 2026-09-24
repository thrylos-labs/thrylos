//! Operator process for the durable testnet faucet and its Discord adapter.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::indexing_slicing
)]
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use chain_node::connection_guard::{self, Slots, MAX_CONCURRENT};
use chain_node::faucet::{
    current_utc_day, execute_prepared, transfer_context, EnqueueResult, Faucet, FaucetError,
    FaucetRequest, NextWork, WorkResult,
};
use chain_node::faucet_discord::{
    command_definitions, handle_interaction, public_key, DiscordResponse,
};
use chain_text::{format_address, parse_address};

const DEFAULT_LISTEN: &str = "127.0.0.1:8081";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(1);

const USAGE: &str = "usage:
  chain-faucet init <dir>
  chain-faucet request <dir> <user-id> <thry1-address>
  chain-faucet work <dir>
  chain-faucet run <dir> [--listen <loopback:port>]
  chain-faucet discord-commands
  chain-faucet --help | --version";

const HELP: &str = "chain-faucet runs the rate-limited Thrylos testnet faucet.

Start locally:

  chain-faucet init /var/lib/thrylos-faucet
  # Fund the address it prints, then edit faucet.json.
  chain-faucet run /var/lib/thrylos-faucet

`run` listens on 127.0.0.1:8081 by default. Put a TLS reverse proxy in front
of it and use that HTTPS URL as the Discord Interactions Endpoint URL. The
faucet itself must stay on loopback. It verifies every Discord request using
the application public key in faucet.json.

`request` is an offline operator/test adapter for the same limits. `work`
processes the durable queue until it is empty. `discord-commands` prints the
two command definitions to register through Discord's application API.

Run only one process for a faucet directory. Do not use `request` or `work`
against that directory while `run` owns it.";

fn fail(message: impl core::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn init(directory: &str) -> Result<(), FaucetError> {
    let path = Path::new(directory);
    let address = Faucet::init(path)?;
    println!("Faucet ready.");
    println!("Address to fund: {}", format_address(&address));
    println!("Configuration: {}", path.join("faucet.json").display());
    println!(
        "Next: fund that address with test THRY, set `discord_public_key`, then run `chain-faucet run {directory}`."
    );
    Ok(())
}

fn request(directory: &str, user_id: &str, address_text: &str) -> Result<(), FaucetError> {
    let address = parse_address(address_text)
        .map_err(|error| FaucetError::Setup(format!("address: {error}")))?;
    let day = current_utc_day()?;
    let id = format!("cli:{day}:{user_id}:{}", format_address(&address));
    let mut faucet = Faucet::load(Path::new(directory))?;
    let result = faucet.enqueue(
        FaucetRequest {
            id: &id,
            user_id,
            address,
        },
        day,
    )?;
    match result {
        EnqueueResult::Queued => println!(
            "queued {} for {}; request {id}",
            faucet.config().payout,
            format_address(&address)
        ),
        EnqueueResult::Existing(status) => {
            println!("request {id} already exists and is {}", status.label())
        }
        EnqueueResult::UserDailyLimit => println!("not queued: that user reached today's limit"),
        EnqueueResult::AddressDailyLimit => {
            println!("not queued: that address reached today's limit")
        }
        EnqueueResult::GlobalDailyLimit => println!("not queued: the global daily cap was reached"),
        EnqueueResult::QueueFull => println!("not queued: the faucet queue is full"),
    }
    Ok(())
}

fn work(directory: &Path) -> Result<(), FaucetError> {
    let mut faucet = Faucet::load(directory)?;
    let client = faucet.config().rpc_client()?;
    loop {
        let Some(prepared) = faucet.prepare_next()? else {
            println!("queue empty");
            return Ok(());
        };
        println!("processing {} as {}", prepared.id, prepared.hash);
        let result = execute_prepared(&client, &prepared)?;
        describe_result(&prepared.id, &result);
        faucet.finish(&prepared.id, result)?;
    }
}

fn describe_result(id: &str, result: &WorkResult) {
    match result {
        WorkResult::Included { hash, height } => {
            println!("request {id}: included {hash} in block {height}")
        }
        WorkResult::Failed(message) => println!("request {id}: failed: {message}"),
    }
}

fn worker(faucet: Arc<Mutex<Faucet>>) {
    loop {
        let work = match faucet.lock() {
            Ok(guard) => guard.next_work(),
            Err(_) => return,
        };
        let work = match work {
            Ok(Some(work)) => work,
            Ok(None) => {
                thread::sleep(RETRY_DELAY);
                continue;
            }
            Err(error) => {
                eprintln!("faucet queue error: {error}");
                thread::sleep(RETRY_DELAY);
                continue;
            }
        };

        let prepared = match work {
            NextWork::Prepared(prepared) => *prepared,
            NextWork::Queued { id, .. } => {
                let (client, faucet_address) = match faucet.lock() {
                    Ok(guard) => match guard.config().rpc_client() {
                        Ok(client) => (client, guard.address()),
                        Err(error) => {
                            eprintln!("faucet configuration error: {error}");
                            thread::sleep(RETRY_DELAY);
                            continue;
                        }
                    },
                    Err(_) => return,
                };
                let context = match transfer_context(&client, faucet_address) {
                    Ok(context) => context,
                    Err(error) => {
                        eprintln!("faucet cannot read the network: {error}");
                        thread::sleep(RETRY_DELAY);
                        continue;
                    }
                };
                match faucet.lock() {
                    Ok(mut guard) => match guard.prepare(&id, context) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            eprintln!("faucet could not prepare request {id}: {error}");
                            thread::sleep(RETRY_DELAY);
                            continue;
                        }
                    },
                    Err(_) => return,
                }
            }
        };

        let client = match faucet.lock() {
            Ok(guard) => match guard.config().rpc_client() {
                Ok(client) => client,
                Err(error) => {
                    eprintln!("faucet configuration error: {error}");
                    thread::sleep(RETRY_DELAY);
                    continue;
                }
            },
            Err(_) => return,
        };
        let result = match execute_prepared(&client, &prepared) {
            Ok(result) => result,
            Err(error) => {
                eprintln!(
                    "request {} remains queued after a network error: {error}",
                    prepared.id
                );
                thread::sleep(RETRY_DELAY);
                continue;
            }
        };
        describe_result(&prepared.id, &result);
        match faucet.lock() {
            Ok(mut guard) => {
                if let Err(error) = guard.finish(&prepared.id, result) {
                    eprintln!("could not record request {}: {error}", prepared.id);
                }
            }
            Err(_) => return,
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(
    stream: &mut TcpStream,
    deadline: Option<Instant>,
) -> Result<HttpRequest, &'static str> {
    let mut bytes = Vec::with_capacity(2_048);
    let mut chunk = [0u8; 2_048];
    let header_end = loop {
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err("Request Header Fields Too Large");
        }
        connection_guard::budget(stream, deadline, IO_TIMEOUT).map_err(|_| "Request Timeout")?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err("Bad Request"),
            Ok(count) => bytes.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    };
    let head = std::str::from_utf8(bytes.get(..header_end).unwrap_or_default())
        .map_err(|_| "Bad Request")?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    if request_line.next().is_none() || request_line.next().is_some() {
        return Err("Bad Request");
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("Bad Request")?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    let content_length = headers
        .get("content-length")
        .ok_or("Length Required")?
        .parse::<usize>()
        .map_err(|_| "Bad Request")?;
    if content_length > MAX_BODY_BYTES {
        return Err("Payload Too Large");
    }
    let body_start = header_end.saturating_add(4);
    while bytes.len().saturating_sub(body_start) < content_length {
        connection_guard::budget(stream, deadline, IO_TIMEOUT).map_err(|_| "Request Timeout")?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err("Bad Request"),
            Ok(count) => bytes.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    }
    let end = body_start.saturating_add(content_length);
    let body = bytes.get(body_start..end).ok_or("Bad Request")?.to_vec();
    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: &DiscordResponse) {
    let content_type = if response.body.is_empty() {
        "text/plain"
    } else {
        "application/json"
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn serve_one(mut stream: TcpStream, faucet: &Mutex<Faucet>, key: &ed25519_dalek::VerifyingKey) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let request = match read_request(&mut stream, connection_guard::deadline()) {
        Ok(request) => request,
        Err(reason) => {
            write_response(
                &mut stream,
                &DiscordResponse {
                    status: 400,
                    reason,
                    body: Vec::new(),
                },
            );
            return;
        }
    };
    if request.method != "POST" || request.path != "/" {
        write_response(
            &mut stream,
            &DiscordResponse {
                status: 404,
                reason: "Not Found",
                body: Vec::new(),
            },
        );
        return;
    }
    let day = match current_utc_day() {
        Ok(day) => day,
        Err(error) => {
            eprintln!("faucet clock error: {error}");
            return;
        }
    };
    let response = match faucet.lock() {
        Ok(mut faucet) => handle_interaction(
            &mut faucet,
            key,
            request
                .headers
                .get("x-signature-ed25519")
                .map(String::as_str),
            request
                .headers
                .get("x-signature-timestamp")
                .map(String::as_str),
            &request.body,
            day,
        ),
        Err(_) => DiscordResponse {
            status: 503,
            reason: "Service Unavailable",
            body: Vec::new(),
        },
    };
    write_response(&mut stream, &response);
}

fn run_server(directory: &str, listen: SocketAddr) -> Result<(), FaucetError> {
    if !listen.ip().is_loopback() {
        return Err(FaucetError::Setup(format!(
            "the faucet must listen on loopback, not {listen}; put a TLS reverse proxy in front"
        )));
    }
    let faucet = Faucet::load(Path::new(directory))?;
    let key = public_key(&faucet)?;
    let faucet = Arc::new(Mutex::new(faucet));
    let worker_faucet = Arc::clone(&faucet);
    thread::Builder::new()
        .name("faucet-worker".into())
        .spawn(move || worker(worker_faucet))
        .map_err(|error| FaucetError::Setup(format!("could not start faucet worker: {error}")))?;

    let listener = TcpListener::bind(listen)
        .map_err(|error| FaucetError::Setup(format!("cannot listen on {listen}: {error}")))?;
    let address = listener
        .local_addr()
        .map_err(|error| FaucetError::Setup(error.to_string()))?;
    println!("Discord faucet listening on http://{address}");
    println!("Keep this address private; expose it only through an HTTPS reverse proxy.");
    let slots = Slots::default();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => match stream.peer_addr() {
                Ok(peer) if is_local(peer.ip()) => {
                    // Concurrent, and bounded: past the limit the connection
                    // is simply closed, so a slow client cannot hold up the
                    // rest and a flood cannot start unlimited threads.
                    let Some(slot) = slots.take(MAX_CONCURRENT) else {
                        continue;
                    };
                    let faucet = Arc::clone(&faucet);
                    let _ = thread::Builder::new()
                        .name("faucet-conn".into())
                        .spawn(move || {
                            let _slot = slot;
                            serve_one(stream, &faucet, &key);
                        });
                }
                _ => {}
            },
            Err(error) => eprintln!("faucet connection failed: {error}"),
        }
    }
    Ok(())
}

fn is_local(ip: IpAddr) -> bool {
    ip.is_loopback()
}

fn parse_run_flags(flags: &[String]) -> Result<SocketAddr, String> {
    match flags {
        [] => DEFAULT_LISTEN
            .parse()
            .map_err(|_| "the built-in faucet listen address is invalid".into()),
        [flag, address] if flag == "--listen" => address.parse().map_err(|_| {
            format!("--listen wants a loopback address such as {DEFAULT_LISTEN}, not {address:?}")
        }),
        _ => Err("usage: chain-faucet run <dir> [--listen <loopback:port>]".into()),
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        return usage_error();
    };
    let result = match (command.as_str(), rest) {
        ("--help" | "help", []) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        ("--version", []) => {
            println!("chain-faucet {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ("init", [directory]) => init(directory),
        ("request", [directory, user_id, address]) => request(directory, user_id, address),
        ("work", [directory]) => work(&PathBuf::from(directory)),
        ("run", [directory, flags @ ..]) => match parse_run_flags(flags) {
            Ok(listen) => run_server(directory, listen),
            Err(error) => return fail(error),
        },
        ("discord-commands", []) => {
            match serde_json::to_string_pretty(&command_definitions()) {
                Ok(commands) => println!("{commands}"),
                Err(error) => return fail(error),
            }
            return ExitCode::SUCCESS;
        }
        _ => return usage_error(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}
