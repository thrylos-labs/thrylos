//! The RPC server over real sockets, with a raw HTTP client.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chain_rpc::{Call, Inbox, RpcError, Server, ServerConfig, ServerError};
use serde_json::{json, Value};

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A node that answers what it is asked, and counts the calls.
struct FakeNode {
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeNode {
    fn answering(inbox: Inbox) -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counted, stopping) = (Arc::clone(&calls), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Acquire) {
                match inbox.next() {
                    Some(pending) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let reply = match &pending.call {
                            Call::Status => Ok(json!({ "answered": "status" })),
                            Call::Block { height, full } => {
                                Ok(json!({ "height": height, "full": full }))
                            }
                            Call::Commit { .. } => Err(RpcError::not_found("no such commit")),
                            _ => Ok(json!("other")),
                        };
                        pending.answer(reply);
                    }
                    None => thread::sleep(Duration::from_millis(2)),
                }
            }
        });
        Self {
            calls,
            stop,
            thread: Some(thread),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start(config: impl FnOnce(&mut ServerConfig)) -> (Server, FakeNode) {
    let mut settings = ServerConfig::at(loopback());
    config(&mut settings);
    let (server, inbox) = Server::start(settings).unwrap();
    (server, FakeNode::answering(inbox))
}

/// Sends `raw` and reads the whole response: its status and body.
fn exchange(address: SocketAddr, raw: &[u8]) -> (u16, String) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw).unwrap();
    read_response(&mut stream)
}

fn read_response(stream: &mut TcpStream) -> (u16, String) {
    let mut text = Vec::new();
    let _ = stream.read_to_end(&mut text);
    let text = String::from_utf8_lossy(&text).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn post_raw(body: &str) -> Vec<u8> {
    format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn call(address: SocketAddr, body: &str) -> Value {
    let (status, body) = exchange(address, &post_raw(body));
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[test]
fn a_request_is_read_handed_to_the_node_and_answered() {
    let (server, node) = start(|_| {});
    let answer = call(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":7,"method":"status"}"#,
    );
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["answered"], "status");
    assert_eq!(node.calls(), 1);

    let answer = call(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":"x","method":"block","params":{"height":3,"full":true}}"#,
    );
    assert_eq!(answer["id"], "x");
    assert_eq!(answer["result"], json!({ "height": 3, "full": true }));

    // An error from the node comes back as a JSON-RPC error, in a 200.
    let answer = call(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"commit"}"#,
    );
    assert_eq!(answer["error"]["code"], RpcError::NOT_FOUND);
}

#[test]
fn what_is_not_json_rpc_is_answered_in_json_rpc_and_never_reaches_the_node() {
    let (server, node) = start(|_| {});
    for (body, code) in [
        ("not json", RpcError::PARSE),
        ("[]", RpcError::INVALID_REQUEST),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#,
            RpcError::METHOD_NOT_FOUND,
        ),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"account"}"#,
            RpcError::INVALID_PARAMS,
        ),
    ] {
        let answer = call(server.local_addr(), body);
        assert_eq!(answer["error"]["code"], code, "{body}");
    }
    assert_eq!(node.calls(), 0);
}

#[test]
fn what_is_not_a_well_formed_http_request_is_refused_with_the_right_status_and_never_reaches_the_node(
) {
    let (server, node) = start(|config| config.max_body = 1_000);
    let address = server.local_addr();
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#;
    let long_header = format!("X-Pad: {}\r\n", "a".repeat(9_000));

    let cases: Vec<(&str, Vec<u8>, u16)> = vec![
        ("a GET", b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), 405),
        (
            "another path",
            format!(
                "POST /rpc HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
            404,
        ),
        (
            "no length",
            format!("POST / HTTP/1.1\r\nHost: x\r\n\r\n{body}").into_bytes(),
            411,
        ),
        (
            "two lengths",
            b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            400,
        ),
        (
            "a length that is not a number",
            b"POST / HTTP/1.1\r\nContent-Length: 12abc\r\n\r\n".to_vec(),
            400,
        ),
        (
            "a length of a signed number",
            b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n".to_vec(),
            400,
        ),
        (
            "a body over the limit, declared",
            b"POST / HTTP/1.1\r\nContent-Length: 1001\r\n\r\n".to_vec(),
            413,
        ),
        (
            "a length too large to be a number",
            b"POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999999\r\n\r\n".to_vec(),
            413,
        ),
        (
            "chunked",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".to_vec(),
            501,
        ),
        (
            "headers that go on and on",
            format!("POST / HTTP/1.1\r\n{long_header}Content-Length: 2\r\n\r\n{{}}").into_bytes(),
            431,
        ),
        (
            "a version that is not HTTP/1",
            b"POST / HTTP/2.0\r\n\r\n".to_vec(),
            400,
        ),
        (
            "a request line with more parts",
            b"POST / HTTP/1.1 extra\r\n\r\n".to_vec(),
            400,
        ),
        (
            "a header with no colon",
            b"POST / HTTP/1.1\r\nnonsense\r\n\r\n".to_vec(),
            400,
        ),
        (
            "more body than it said",
            b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}{}{}".to_vec(),
            400,
        ),
    ];
    for (what, raw, status) in cases {
        let (got, _) = exchange(address, &raw);
        assert_eq!(got, status, "{what}");
    }
    // The 405 says what would have been allowed.
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).unwrap();
    assert!(text.contains("Allow: POST"), "{text}");

    assert_eq!(node.calls(), 0, "none of that was for the node");
    // And it is still serving.
    let answer = call(address, body);
    assert_eq!(answer["result"]["answered"], "status");
}

#[test]
fn a_request_sent_in_pieces_and_one_that_asks_to_continue_are_both_read() {
    let (server, _node) = start(|_| {});
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#;
    let raw = post_raw(body);

    // Split in the middle of the headers and again in the middle of the body.
    let mut stream = TcpStream::connect(server.local_addr()).unwrap();
    let (first, rest) = raw.split_at(20);
    let (second, third) = rest.split_at(rest.len() - 10);
    for piece in [first, second, third] {
        stream.write_all(piece).unwrap();
        stream.flush().unwrap();
        thread::sleep(Duration::from_millis(30));
    }
    let (status, text) = read_response(&mut stream);
    assert_eq!(status, 200);
    assert!(text.contains("\"answered\":\"status\""), "{text}");

    // `Expect: 100-continue`, as some clients send with a larger body.
    let mut stream = TcpStream::connect(server.local_addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).unwrap();
    let mut interim = [0u8; 25];
    stream.read_exact(&mut interim).unwrap();
    assert!(String::from_utf8_lossy(&interim).starts_with("HTTP/1.1 100 Continue"));
    stream.write_all(body.as_bytes()).unwrap();
    let (status, _) = read_response(&mut stream);
    assert_eq!(status, 200);
}

#[test]
fn a_client_that_says_nothing_holds_a_worker_only_as_long_as_the_time_limit() {
    let (server, _node) = start(|config| {
        config.workers = 1;
        config.io_timeout = Duration::from_millis(300);
    });
    // Connects and sends nothing, holding the only worker.
    let _silent = TcpStream::connect(server.local_addr()).unwrap();
    let started = Instant::now();
    let answer = call(
        server.local_addr(),
        r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#,
    );
    assert_eq!(answer["result"]["answered"], "status");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "served after {:?}",
        started.elapsed()
    );
}

#[test]
fn past_the_backlog_a_connection_is_told_so_at_once() {
    let (server, _node) = start(|config| {
        config.workers = 1;
        config.backlog = 1;
        config.io_timeout = Duration::from_secs(3);
    });
    let address = server.local_addr();
    // One that holds the worker, and one that fills the backlog.
    let _holding = TcpStream::connect(address).unwrap();
    thread::sleep(Duration::from_millis(150));
    let _waiting = TcpStream::connect(address).unwrap();
    thread::sleep(Duration::from_millis(150));

    let started = Instant::now();
    let (status, _) = exchange(
        address,
        &post_raw(r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#),
    );
    assert_eq!(status, 503);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "not at once: {:?}",
        started.elapsed()
    );
}

#[test]
fn a_node_that_is_busy_or_slow_or_gone_is_reported_as_unavailable() {
    let mut settings = ServerConfig::at(loopback());
    settings.workers = 2;
    settings.pending_calls = 1;
    settings.reply_timeout = Duration::from_millis(600);
    let (server, inbox) = Server::start(settings).unwrap();
    let address = server.local_addr();
    let ask = r#"{"jsonrpc":"2.0","id":1,"method":"status"}"#;

    // Nobody is reading the inbox. The first call waits in it; a second finds
    // it full and is turned away at once ...
    let first = thread::spawn(move || call(address, ask));
    thread::sleep(Duration::from_millis(150));
    let started = Instant::now();
    let second = call(address, ask);
    assert_eq!(second["error"]["code"], RpcError::UNAVAILABLE);
    assert!(second["error"]["message"]
        .as_str()
        .unwrap()
        .contains("busy"));
    assert!(started.elapsed() < Duration::from_millis(500));

    // ... and the first, never answered, gives up at the time limit.
    let first = first.join().unwrap();
    assert_eq!(first["error"]["code"], RpcError::UNAVAILABLE);
    assert!(first["error"]["message"]
        .as_str()
        .unwrap()
        .contains("in time"));

    // A node that has gone away: told so, not left waiting.
    drop(inbox);
    let third = call(address, ask);
    assert_eq!(third["error"]["code"], RpcError::UNAVAILABLE);
    assert!(third["error"]["message"]
        .as_str()
        .unwrap()
        .contains("shutting down"));
}

#[test]
fn only_a_loopback_address_may_be_listened_on_and_no_bound_may_be_zero() {
    for address in ["0.0.0.0:0", "192.168.1.5:0", "[::]:0", "10.0.0.1:0"] {
        let error = Server::start(ServerConfig::at(address.parse().unwrap()))
            .err()
            .unwrap_or_else(|| panic!("{address} was accepted"));
        assert!(
            matches!(error, ServerError::NotLocal(_)),
            "{address}: {error}"
        );
        assert!(error.to_string().contains("local only"), "{error}");
    }

    for change in [
        (|c: &mut ServerConfig| c.workers = 0) as fn(&mut ServerConfig),
        |c| c.backlog = 0,
        |c| c.pending_calls = 0,
        |c| c.max_body = 0,
        |c| c.io_timeout = Duration::ZERO,
        |c| c.reply_timeout = Duration::ZERO,
    ] {
        let mut config = ServerConfig::at(loopback());
        change(&mut config);
        assert!(matches!(
            Server::start(config).err(),
            Some(ServerError::InvalidConfig(_))
        ));
    }
}

#[test]
fn a_stopped_server_gives_up_its_port_and_its_threads() {
    let (server, node) = start(|_| {});
    let address = server.local_addr();
    assert!(TcpStream::connect(address).is_ok());
    drop(server);
    drop(node);
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err(),
        "still listening"
    );
}

#[test]
fn many_clients_at_once_are_all_answered() {
    let (server, node) = start(|_| {});
    let address = server.local_addr();
    let clients: Vec<_> = (0..24)
        .map(|n| {
            thread::spawn(move || {
                let answer = call(
                    address,
                    &format!(r#"{{"jsonrpc":"2.0","id":{n},"method":"status"}}"#),
                );
                assert_eq!(answer["id"], n);
                assert_eq!(answer["result"]["answered"], "status");
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    assert_eq!(node.calls(), 24);
}
