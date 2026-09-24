//! `chain-names`: the `.thry` name registry for the testnet. A small HTTP
//! service on a loopback port, published through the same tunnel as the RPC.
//! The rules, the signed reservation and the limits live in
//! `chain_node::names` and `chain_node::names_service`; this file only reads
//! and writes connections. See `docs/thry-names.md`.

#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chain_node::connection_guard::{self, Slots, MAX_CONCURRENT};
use chain_node::names::Registry;
use chain_node::names_service::{NamesService, Request, Response, MAX_BODY_BYTES};
use serde::{Deserialize, Serialize};

const CONFIG_FILE: &str = "names-config.json";
const SECRET_FILE: &str = "names.secret";
const DEFAULT_LISTEN: &str = "127.0.0.1:8083";
const MAX_HEADER_BYTES: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const USAGE: &str = "usage:
  chain-names init <dir> --chain-id <number>
  chain-names run <dir> [--listen <loopback:port>]
  chain-names --help | --version";

const HELP: &str = "chain-names runs the Thrylos testnet's .thry name registry.

  chain-names init /var/lib/thrylos-names --chain-id 20260923
  chain-names run /var/lib/thrylos-names

`init` writes names-config.json and a random shared secret (names.secret, mode
0600) that the faucet presents to confirm a name. The service listens on a
loopback address only; expose it through an HTTPS reverse proxy or the tunnel,
and do not route /internal/ through it.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    chain_id: u64,
    listen: String,
}

fn fail(message: impl core::fmt::Display) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn init(directory: &Path, chain_id: u64) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let config_path = directory.join(CONFIG_FILE);
    let secret_path = directory.join(SECRET_FILE);
    if config_path.exists() || secret_path.exists() {
        return Err(format!(
            "{} already holds a registry; refusing to overwrite its configuration or secret",
            directory.display()
        ));
    }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|_| "could not get random bytes".to_owned())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret_path)
        .map_err(|error| format!("{}: {error}", secret_path.display()))?;
    file.write_all(chain_rpc::hex::encode(&secret).as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", secret_path.display()))?;
    let config = Config {
        chain_id,
        listen: DEFAULT_LISTEN.into(),
    };
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("{}: {error}", config_path.display()))?;
    println!("Initialised {}", directory.display());
    println!("Chain id {chain_id}; listening on {DEFAULT_LISTEN} once `run`.");
    println!(
        "Give the faucet the secret in {} (`names_secret_file`).",
        secret_path.display()
    );
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

fn run(directory: &Path, listen_override: Option<SocketAddr>) -> Result<(), String> {
    let config: Config = serde_json::from_slice(
        &fs::read(directory.join(CONFIG_FILE))
            .map_err(|error| format!("{}: {error} (run `chain-names init` first)", CONFIG_FILE))?,
    )
    .map_err(|error| format!("{CONFIG_FILE}: {error}"))?;
    let listen: SocketAddr = match listen_override {
        Some(address) => address,
        None => config.listen.parse().map_err(|_| {
            format!("`listen` in {CONFIG_FILE} must be an address such as {DEFAULT_LISTEN}")
        })?,
    };
    if !listen.ip().is_loopback() {
        return Err("chain-names listens on a loopback address only".into());
    }
    let secret_text = fs::read_to_string(directory.join(SECRET_FILE))
        .map_err(|error| format!("{SECRET_FILE}: {error}"))?;
    let secret = secret_text.trim().as_bytes().to_vec();
    if secret.len() < 32 {
        return Err(format!("{SECRET_FILE} is too short to be a secret"));
    }
    let registry = Registry::open(directory).map_err(|error| error.to_string())?;
    println!(
        "{} confirmed names, {} pending",
        registry.confirmed_count(),
        registry.pending_count()
    );
    let service = Arc::new(Mutex::new(NamesService::new(
        registry,
        config.chain_id,
        secret,
    )));

    let listener =
        TcpListener::bind(listen).map_err(|error| format!("cannot listen on {listen}: {error}"))?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    println!("Name registry listening on http://{address}");
    let slots = Slots::default();
    for connection in listener.incoming() {
        let Ok(stream) = connection else { continue };
        let Ok(peer) = stream.peer_addr() else {
            continue;
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Some(slot) = slots.take(MAX_CONCURRENT) else {
            continue;
        };
        let service = Arc::clone(&service);
        let _ = thread::Builder::new()
            .name("names-conn".into())
            .spawn(move || {
                let _slot = slot;
                serve_one(stream, &peer.ip().to_string(), &service);
            });
    }
    Ok(())
}

struct Failure {
    status: u16,
    reason: &'static str,
}

fn serve_one(mut stream: TcpStream, peer: &str, service: &Mutex<NamesService>) {
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(IO_TIMEOUT)).is_err()
    {
        return;
    }
    let response = match read_request(&mut stream, peer, connection_guard::deadline()) {
        Ok(request) => match service.lock() {
            Ok(mut service) => service.handle(now_ms(), &request),
            Err(_) => return,
        },
        Err(Some(failure)) => {
            write_plain(&mut stream, failure.status, failure.reason);
            return;
        }
        Err(None) => return,
    };
    write_response(&mut stream, &response);
}

/// Reads one request. `Err(None)` is a connection that gave out.
fn read_request(
    stream: &mut TcpStream,
    peer: &str,
    deadline: Option<Instant>,
) -> Result<Request, Option<Failure>> {
    let bad = |status, reason| Some(Failure { status, reason });
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(bad(431, "Request Header Fields Too Large"));
        }
        connection_guard::budget(stream, deadline, IO_TIMEOUT).map_err(|_| None)?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(None),
            Ok(count) => buffer.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    };
    let head = buffer
        .get(..header_end)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(|| bad(400, "Bad Request"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default().to_owned();
    let target = request_line.next().unwrap_or_default().to_owned();
    let version = request_line.next().unwrap_or_default();
    if request_line.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(bad(400, "Bad Request"));
    }
    let mut headers = BTreeMap::new();
    let mut content_length: Option<usize> = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| bad(400, "Bad Request"))?;
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_owned());
        if name == "transfer-encoding" {
            return Err(bad(501, "Not Implemented"));
        }
        if name == "content-length" {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(bad(400, "Bad Request"));
            }
            content_length = Some(value.parse().map_err(|_| bad(413, "Payload Too Large"))?);
        }
        headers.insert(name, value);
    }
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(bad(413, "Payload Too Large"));
    }
    let body_start = header_end.saturating_add(4);
    let mut body = buffer.get(body_start..).unwrap_or_default().to_vec();
    if body.len() > length {
        return Err(bad(400, "Bad Request"));
    }
    while body.len() < length {
        let wanted = length.saturating_sub(body.len()).min(chunk.len());
        connection_guard::budget(stream, deadline, IO_TIMEOUT).map_err(|_| None)?;
        match stream.read(chunk.get_mut(..wanted).unwrap_or_default()) {
            Ok(0) | Err(_) => return Err(None),
            Ok(count) => body.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    }
    let path = target.split('?').next().unwrap_or(&target).to_owned();
    Ok(Request {
        method,
        path,
        headers,
        body,
        peer: peer.to_owned(),
    })
}

fn write_plain(stream: &mut TcpStream, status: u16, reason: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n"
    );
    let _ = stream.flush();
}

fn write_response(stream: &mut TcpStream, response: &Response) {
    let body = if response.body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(&response.body).unwrap_or_default()
    };
    let cors = if response.cors {
        "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: content-type\r\nAccess-Control-Max-Age: 600\r\n"
    } else {
        ""
    };
    let content_type = if body.is_empty() {
        ""
    } else {
        "Content-Type: application/json; charset=utf-8\r\n"
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\n{content_type}Content-Length: {}\r\nCache-Control: no-store\r\n\
         Connection: close\r\nX-Content-Type-Options: nosniff\r\n{cors}\r\n",
        response.status,
        response.reason,
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&body);
    let _ = stream.flush();
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = arguments.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match (command.as_str(), rest) {
        ("--help" | "help", []) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        ("--version", []) => {
            println!("chain-names {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ("init", [directory, flag, id]) if flag == "--chain-id" => match id.parse::<u64>() {
            Ok(chain_id) => init(&PathBuf::from(directory), chain_id),
            Err(_) => return fail("--chain-id wants a number"),
        },
        ("run", [directory]) => run(&PathBuf::from(directory), None),
        ("run", [directory, flag, address]) if flag == "--listen" => match address.parse() {
            Ok(address) => run(&PathBuf::from(directory), Some(address)),
            Err(_) => return fail("--listen wants an address such as 127.0.0.1:8083"),
        },
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}
