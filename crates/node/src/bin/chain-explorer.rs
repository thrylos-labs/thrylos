//! A small, read-only web explorer for a local Thrylos development network.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use chain_node::client::{ClientError, RpcClient};
use chain_node::config::NodeConfig;
use chain_node::connection_guard::{self, Slots, MAX_CONCURRENT};
use chain_node::devnet::nodes_in;
use chain_node::health;
use serde_json::{json, Value};

const INDEX: &[u8] = include_bytes!("../../explorer/index.html");
const STYLES: &[u8] = include_bytes!("../../explorer/styles.css");
const APP: &[u8] = include_bytes!("../../explorer/app.js");
const LOGO: &[u8] = include_bytes!("../../explorer/thrylos-logo.png");

const DEFAULT_PORT: u16 = 8_080;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

const USAGE: &str = "usage:
  chain-explorer <devnet-dir> [--port <port>]
  chain-explorer --help | --version";

const HELP: &str = "chain-explorer <devnet-dir> [--port <port>]

chain-explorer serves a read-only web explorer for a local Thrylos network.
Validator RPCs stay bound to loopback; the explorer talks to them on the same
machine and exposes only read methods.

Start the network first, then run:

  chain-explorer /tmp/thrylos-devnet

Open http://127.0.0.1:8080 in a browser. Use --port to choose another local
port. Ctrl-C stops the explorer.";

#[derive(Debug)]
enum ExplorerError {
    Setup(String),
    Io(std::io::Error),
}

impl fmt::Display for ExplorerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(message) => f.write_str(message),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl From<std::io::Error> for ExplorerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

struct Explorer {
    network: PathBuf,
    nodes: Vec<(usize, RpcClient)>,
}

impl Explorer {
    fn load(network: &Path) -> Result<Self, ExplorerError> {
        let directories =
            nodes_in(network).map_err(|error| ExplorerError::Setup(error.to_string()))?;
        let mut nodes = Vec::with_capacity(directories.len());
        for node in directories {
            let config = NodeConfig::load(&node.config())
                .map_err(|error| ExplorerError::Setup(error.to_string()))?;
            let address = config.rpc_listen.ok_or_else(|| {
                ExplorerError::Setup(format!(
                    "node {} has no RPC address in its configuration",
                    node.number
                ))
            })?;
            nodes.push((node.number, RpcClient { address }));
        }
        Ok(Self {
            network: network.to_path_buf(),
            nodes,
        })
    }

    fn primary(&self) -> Result<RpcClient, ExplorerError> {
        self.nodes
            .first()
            .map(|(_, client)| *client)
            .ok_or_else(|| ExplorerError::Setup("the network has no nodes".into()))
    }

    fn start_hint(&self) -> String {
        format!(
            "Start the network with `chain-node devnet start {}` and refresh this page.",
            self.network.display()
        )
    }

    fn info(&self) -> Value {
        let nodes: Vec<Value> = self
            .nodes
            .iter()
            .map(|(number, client)| {
                json!({
                    "number": number,
                    "rpc": client.address.to_string(),
                })
            })
            .collect();
        json!({
            "networkDirectory": self.network.display().to_string(),
            "nodes": nodes,
        })
    }

    fn health(&self) -> Result<Value, ClientError> {
        let assessment = health::check(&self.network)?;
        Ok(json!({
            "healthy": assessment.problems.is_empty(),
            "verdict": assessment.verdict(),
            "problems": assessment.problems,
            "notes": assessment.notes,
            "nobodyAnswered": assessment.nobody_answered,
            "nodeCount": self.nodes.len(),
        }))
    }

    fn rpc(&self, body: &[u8]) -> Result<Value, ApiFailure> {
        let request: Value = serde_json::from_slice(body)
            .map_err(|_| ApiFailure::bad_request("the request body is not valid JSON"))?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| ApiFailure::bad_request("`method` must be a string"))?;
        if !read_method(method) {
            return Err(ApiFailure::forbidden(
                "the explorer exposes read-only RPC methods only",
            ));
        }
        let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
        self.primary()?
            .call(method, &params)
            .map_err(|error| ApiFailure::upstream(error.to_string(), self.start_hint()))
    }
}

impl From<ExplorerError> for ApiFailure {
    fn from(error: ExplorerError) -> Self {
        Self {
            status: 500,
            reason: "Internal Server Error",
            message: error.to_string(),
            hint: None,
        }
    }
}

fn read_method(method: &str) -> bool {
    matches!(
        method,
        "status" | "block" | "commit" | "account" | "transaction"
    )
}

#[derive(Debug)]
struct ApiFailure {
    status: u16,
    reason: &'static str,
    message: String,
    hint: Option<String>,
}

impl ApiFailure {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            message: message.into(),
            hint: None,
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: 403,
            reason: "Forbidden",
            message: message.into(),
            hint: None,
        }
    }

    fn upstream(message: impl Into<String>, hint: String) -> Self {
        Self {
            status: 502,
            reason: "Bad Gateway",
            message: message.into(),
            hint: Some(hint),
        }
    }

    fn body(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "ok": false,
            "error": self.message,
            "hint": self.hint,
        }))
        .unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"request failed\"}".to_vec())
    }
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

#[derive(Debug)]
struct HttpFailure {
    status: u16,
    reason: &'static str,
}

fn http_failure(status: u16, reason: &'static str) -> HttpFailure {
    HttpFailure { status, reason }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_request(stream: &mut TcpStream, deadline: Option<Instant>) -> Result<Request, HttpFailure> {
    let mut buffer = Vec::with_capacity(2_048);
    let mut chunk = [0u8; 2_048];
    let header_end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(http_failure(431, "Request Header Fields Too Large"));
        }
        connection_guard::budget(stream, deadline, IO_TIMEOUT)
            .map_err(|_| http_failure(408, "Request Timeout"))?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(http_failure(400, "Bad Request")),
            Ok(count) => buffer.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(http_failure(431, "Request Header Fields Too Large"));
    }

    let head = buffer
        .get(..header_end)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .ok_or_else(|| http_failure(400, "Bad Request"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or_default();
    let version = request_line.next().unwrap_or_default();
    if request_line.next().is_some() || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(http_failure(400, "Bad Request"));
    }
    if !matches!(method, "GET" | "POST") {
        return Err(http_failure(405, "Method Not Allowed"));
    }

    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| http_failure(400, "Bad Request"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(http_failure(501, "Not Implemented"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(http_failure(400, "Bad Request"));
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| http_failure(413, "Payload Too Large"))?,
            );
        }
    }

    let length = if method == "POST" {
        content_length.ok_or_else(|| http_failure(411, "Length Required"))?
    } else {
        content_length.unwrap_or(0)
    };
    if length > MAX_BODY_BYTES {
        return Err(http_failure(413, "Payload Too Large"));
    }

    let body_start = header_end.saturating_add(4);
    let mut body = buffer.get(body_start..).unwrap_or_default().to_vec();
    if body.len() > length {
        return Err(http_failure(400, "Bad Request"));
    }
    while body.len() < length {
        let wanted = length.saturating_sub(body.len()).min(chunk.len());
        connection_guard::budget(stream, deadline, IO_TIMEOUT)
            .map_err(|_| http_failure(408, "Request Timeout"))?;
        let read = stream
            .read(chunk.get_mut(..wanted).unwrap_or_default())
            .map_err(|_| http_failure(400, "Bad Request"))?;
        if read == 0 {
            return Err(http_failure(400, "Bad Request"));
        }
        body.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }

    Ok(Request {
        method: method.to_owned(),
        path: path.split('?').next().unwrap_or(path).to_owned(),
        body,
    })
}

struct Response {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    cache: &'static str,
}

impl Response {
    fn asset(content_type: &'static str, body: &'static [u8], cache: &'static str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body: body.to_vec(),
            cache,
        }
    }

    fn json(value: Value) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type: "application/json; charset=utf-8",
            body: serde_json::to_vec(&json!({ "ok": true, "result": value })).unwrap_or_default(),
            cache: "no-store",
        }
    }

    fn api_failure(failure: ApiFailure) -> Self {
        Self {
            status: failure.status,
            reason: failure.reason,
            content_type: "application/json; charset=utf-8",
            body: failure.body(),
            cache: "no-store",
        }
    }

    fn http_failure(failure: HttpFailure) -> Self {
        Self {
            status: failure.status,
            reason: failure.reason,
            content_type: "text/plain; charset=utf-8",
            body: format!("{}\n", failure.reason).into_bytes(),
            cache: "no-store",
        }
    }
}

fn route(explorer: &Explorer, request: Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/" | "/index.html") => {
            Response::asset("text/html; charset=utf-8", INDEX, "no-cache")
        }
        ("GET", "/assets/styles.css") => {
            Response::asset("text/css; charset=utf-8", STYLES, "no-store")
        }
        ("GET", "/assets/app.js") => {
            Response::asset("text/javascript; charset=utf-8", APP, "no-store")
        }
        ("GET", "/assets/thrylos-logo.png" | "/favicon.ico") => {
            Response::asset("image/png", LOGO, "no-store")
        }
        ("GET", "/api/info") => Response::json(explorer.info()),
        ("GET", "/api/health") => match explorer.health() {
            Ok(value) => Response::json(value),
            Err(error) => Response::api_failure(ApiFailure::upstream(
                error.to_string(),
                explorer.start_hint(),
            )),
        },
        ("POST", "/api/rpc") => match explorer.rpc(&request.body) {
            Ok(value) => Response::json(value),
            Err(error) => Response::api_failure(error),
        },
        _ => Response::http_failure(http_failure(404, "Not Found")),
    }
}

fn write_response(stream: &mut TcpStream, response: Response) {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
         Cache-Control: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; \
         script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len(),
        response.cache
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

fn serve(network: &Path, port: u16) -> Result<(), ExplorerError> {
    let explorer = Explorer::load(network)?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let listener = TcpListener::bind(address).map_err(|error| {
        ExplorerError::Setup(format!(
            "cannot listen on http://{address}: {error}; choose another port with --port"
        ))
    })?;
    println!("Thrylos Explorer: http://{address}");
    println!(
        "reading {} local validator RPCs; Ctrl-C stops the explorer",
        explorer.nodes.len()
    );
    let explorer = Arc::new(explorer);
    let slots = Slots::default();
    for connection in listener.incoming() {
        let stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("explorer connection failed: {error}");
                continue;
            }
        };
        // Concurrent, and bounded: past the limit the connection is closed,
        // so one slow client cannot hold up the rest.
        let Some(slot) = slots.take(MAX_CONCURRENT) else {
            continue;
        };
        let explorer = Arc::clone(&explorer);
        let _ = thread::Builder::new()
            .name("explorer-conn".into())
            .spawn(move || {
                let _slot = slot;
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                let response = match read_request(&mut stream, connection_guard::deadline()) {
                    Ok(request) => route(&explorer, request),
                    Err(error) => Response::http_failure(error),
                };
                write_response(&mut stream, response);
            });
    }
    Ok(())
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn fail(error: impl fmt::Display) -> ExitCode {
    eprintln!("error: {error}");
    ExitCode::FAILURE
}

fn parse_port(flags: &[&str]) -> Result<u16, ()> {
    match flags {
        [] => Ok(DEFAULT_PORT),
        ["--port", value] => value
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or(()),
        _ => Err(()),
    }
}

fn main() -> ExitCode {
    let owned: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = owned.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["-h" | "--help"] => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        ["-V" | "--version"] => {
            println!("chain-explorer {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [network, flags @ ..] => match parse_port(flags) {
            Ok(port) => serve(Path::new(network), port).map_or_else(fail, |()| ExitCode::SUCCESS),
            Err(()) => usage_error(),
        },
        _ => usage_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_read_methods_are_available() {
        for method in ["status", "block", "commit", "account", "transaction"] {
            assert!(read_method(method), "{method}");
        }
        for method in ["send_transaction", "broadcast", ""] {
            assert!(!read_method(method), "{method}");
        }
    }

    #[test]
    fn the_supplied_logo_is_embedded() {
        assert!(LOGO.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(LOGO.len() > 1_000);
    }

    #[test]
    fn the_frontend_assets_are_present() {
        assert!(INDEX
            .windows("Thrylos Explorer".len())
            .any(|w| w == b"Thrylos Explorer"));
        assert!(STYLES.len() > 1_000);
        assert!(APP.len() > 1_000);
    }

    #[test]
    fn port_flags_are_deliberately_small() {
        assert_eq!(parse_port(&[]), Ok(DEFAULT_PORT));
        assert_eq!(parse_port(&["--port", "9000"]), Ok(9_000));
        assert!(parse_port(&["--port", "0"]).is_err());
        assert!(parse_port(&["--port", "nope"]).is_err());
        assert!(parse_port(&["--host", "0.0.0.0"]).is_err());
    }

    #[test]
    fn static_routes_have_the_right_types_and_unknown_paths_are_not_found() {
        let explorer = Explorer {
            network: PathBuf::from("/tmp/network"),
            nodes: vec![],
        };
        let page = route(
            &explorer,
            Request {
                method: "GET".into(),
                path: "/".into(),
                body: vec![],
            },
        );
        assert_eq!(page.status, 200);
        assert_eq!(page.content_type, "text/html; charset=utf-8");
        assert!(page
            .body
            .windows(16)
            .any(|window| window == b"Thrylos Explorer"));

        let logo = route(
            &explorer,
            Request {
                method: "GET".into(),
                path: "/favicon.ico".into(),
                body: vec![],
            },
        );
        assert_eq!(logo.content_type, "image/png");
        assert_eq!(logo.body, LOGO);

        let missing = route(
            &explorer,
            Request {
                method: "GET".into(),
                path: "/nothing-here".into(),
                body: vec![],
            },
        );
        assert_eq!(missing.status, 404);
    }

    #[test]
    fn write_rpc_methods_are_refused_before_any_node_is_contacted() {
        let explorer = Explorer {
            network: PathBuf::from("/tmp/network"),
            nodes: vec![],
        };
        let response = route(
            &explorer,
            Request {
                method: "POST".into(),
                path: "/api/rpc".into(),
                body: br#"{"method":"send_transaction","params":{}}"#.to_vec(),
            },
        );
        assert_eq!(response.status, 403);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["ok"], false);
        assert!(body["error"].as_str().unwrap().contains("read-only"));
    }
}
