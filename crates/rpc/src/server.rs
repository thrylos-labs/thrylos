//! The HTTP side: a small, bounded, local-only server for JSON-RPC.
//!
//! **Local only.** `docs/spec.md` lists `chain-rpc` as Tier C with "local only" as
//! its failure class, and this holds it to that: [`Server::start`] refuses a
//! listen address that is not a loopback one, and each connection is checked
//! again. Nothing here authenticates or encrypts, because nothing that is not on
//! this machine can reach it; anything wider belongs to a proxy the operator
//! puts in front, not to this crate.
//!
//! **Bounded.** Every remotely driven thing has a capacity and a stated policy
//! for what happens past it, as the spec asks of the network:
//!
//! - a fixed number of worker threads, each serving one connection at a time;
//! - a queue of accepted connections waiting for a worker, and when it is full
//!   the connection is answered `503` and closed on the spot;
//! - a header block of at most [`MAX_HEADER_BYTES`] and a body of at most
//!   `max_body`, checked against the declared length before anything is read;
//! - a time limit on every read and write, so a client that says nothing holds a
//!   worker for that long and no longer, and a limit on the whole request, so
//!   one that sends a byte just inside each of those limits (a slowloris)
//!   cannot hold a worker for hours either;
//! - a queue of calls waiting for the node (the node answers on its own thread,
//!   between the things it does), and when it is full the caller is told the node
//!   is busy; and a time limit on the node's answer.
//!
//! **Simple.** HTTP/1.1 with one request per connection (`Connection: close`),
//! `POST /` with a `Content-Length` and no chunked encoding, nothing else. A
//! client that wants to send more opens another connection.

// A request deadline is wall-clock I/O timing on a local socket. It never feeds
// the state transition the `Instant::now` ban protects (see `clippy.toml`).
#![allow(clippy::disallowed_methods)]

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::call::{failure, parse, respond, Call, Reply, RpcError};

/// The most bytes of request line and headers read before giving up.
pub const MAX_HEADER_BYTES: usize = 8 * 1024;

/// How the server is bounded.
#[derive(Debug, Clone, Copy)]
pub struct ServerConfig {
    /// Where to listen. Must be a loopback address.
    pub listen: SocketAddr,
    /// Threads serving connections.
    pub workers: usize,
    /// Accepted connections that may wait for a worker.
    pub backlog: usize,
    /// Calls that may wait for the node to answer them.
    pub pending_calls: usize,
    /// The largest request body, in bytes.
    pub max_body: usize,
    /// How long a client may take over any one read or write.
    pub io_timeout: Duration,
    /// How long a client may take to send the whole request, headers and
    /// body together, however steadily it trickles them.
    pub request_timeout: Duration,
    /// How long the node has to answer a call.
    pub reply_timeout: Duration,
}

impl ServerConfig {
    /// The defaults, listening at `listen`.
    pub const fn at(listen: SocketAddr) -> Self {
        Self {
            listen,
            workers: 8,
            backlog: 32,
            pending_calls: 64,
            // A transaction is at most 256 KiB of bytes, so 512 KiB of hex, and
            // some JSON around it.
            max_body: 600 * 1024,
            io_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            reply_timeout: Duration::from_secs(10),
        }
    }
}

/// Why the server could not start.
#[derive(Debug)]
pub enum ServerError {
    /// The listen address is not a loopback address.
    NotLocal(SocketAddr),
    /// A bound of zero.
    InvalidConfig(&'static str),
    /// The socket could not be opened.
    Io(std::io::Error),
}

impl core::fmt::Display for ServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLocal(address) => write!(
                f,
                "the RPC is local only and {address} is not a loopback address; put a proxy in \
                 front of it for anything wider"
            ),
            Self::InvalidConfig(what) => write!(f, "the RPC server's {what} must not be zero"),
            Self::Io(error) => write!(f, "the RPC socket: {error}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<std::io::Error> for ServerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// A call waiting for the node, and where to send the answer.
pub struct Pending {
    pub call: Call,
    reply: SyncSender<Reply>,
}

impl Pending {
    /// Answers the call. If the client has given up, the answer goes nowhere.
    pub fn answer(self, reply: Reply) {
        let _ = self.reply.try_send(reply);
    }
}

/// The node's end: the calls clients have made that it has not answered yet.
pub struct Inbox(Receiver<Pending>);

impl Inbox {
    /// The next waiting call, if there is one. Never blocks.
    pub fn next(&self) -> Option<Pending> {
        self.0.try_recv().ok()
    }
}

/// A running server. Dropping it stops it and waits for its threads.
pub struct Server {
    stop: Arc<AtomicBool>,
    address: SocketAddr,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    /// Starts serving. Calls arrive at the returned [`Inbox`], and each must be
    /// answered, on whatever thread the node chooses, by [`Pending::answer`].
    pub fn start(config: ServerConfig) -> Result<(Self, Inbox), ServerError> {
        if !config.listen.ip().is_loopback() {
            return Err(ServerError::NotLocal(config.listen));
        }
        for (value, name) in [
            (config.workers, "worker count"),
            (config.backlog, "backlog"),
            (config.pending_calls, "call queue"),
            (config.max_body, "body limit"),
        ] {
            if value == 0 {
                return Err(ServerError::InvalidConfig(name));
            }
        }
        if config.io_timeout.is_zero()
            || config.request_timeout.is_zero()
            || config.reply_timeout.is_zero()
        {
            return Err(ServerError::InvalidConfig("timeouts"));
        }
        let listener = TcpListener::bind(config.listen)?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;

        let stop = Arc::new(AtomicBool::new(false));
        let (calls, inbox) = mpsc::sync_channel::<Pending>(config.pending_calls);
        let (connections, waiting) = mpsc::sync_channel::<TcpStream>(config.backlog);
        let waiting = Arc::new(Mutex::new(waiting));

        let mut threads = Vec::with_capacity(config.workers.saturating_add(1));
        {
            let stop = Arc::clone(&stop);
            threads.push(
                thread::Builder::new()
                    .name("rpc-accept".into())
                    .spawn(move || {
                        accept_loop(&listener, &connections, &stop, config.io_timeout)
                    })?,
            );
        }
        for number in 0..config.workers {
            let (stop, waiting, calls) = (Arc::clone(&stop), Arc::clone(&waiting), calls.clone());
            threads.push(
                thread::Builder::new()
                    .name(format!("rpc-worker-{number}"))
                    .spawn(move || worker_loop(&waiting, &calls, &stop, config))?,
            );
        }
        Ok((
            Self {
                stop,
                address,
                threads,
            },
            Inbox(inbox),
        ))
    }

    /// The address it is listening on (the port, if it was asked to pick one).
    pub const fn local_addr(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

const POLL: Duration = Duration::from_millis(10);

fn accept_loop(
    listener: &TcpListener,
    connections: &SyncSender<TcpStream>,
    stop: &AtomicBool,
    io_timeout: Duration,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !is_local(peer.ip()) {
                    continue;
                }
                // The listener is non-blocking so that this loop can notice it
                // is to stop, and on some systems what it accepts is too; the
                // workers rely on their reads waiting, up to the time limit.
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                if let Err(
                    TrySendError::Full(mut stream) | TrySendError::Disconnected(mut stream),
                ) = connections.try_send(stream)
                {
                    // Past the backlog: told so, at once, and let go.
                    let _ =
                        stream.set_write_timeout(Some(io_timeout.min(Duration::from_millis(200))));
                    write_response(&mut stream, 503, "Service Unavailable", &[]);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(_) => thread::sleep(POLL),
        }
    }
}

fn is_local(ip: IpAddr) -> bool {
    ip.is_loopback()
}

fn worker_loop(
    waiting: &Mutex<Receiver<TcpStream>>,
    calls: &SyncSender<Pending>,
    stop: &AtomicBool,
    config: ServerConfig,
) {
    while !stop.load(Ordering::Acquire) {
        let next = {
            let Ok(receiver) = waiting.lock() else { return };
            receiver.recv_timeout(POLL)
        };
        match next {
            Ok(stream) => serve(stream, calls, config),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// What was wrong with an HTTP request, as the status to answer it with.
struct HttpError {
    status: u16,
    reason: &'static str,
}

const fn http(status: u16, reason: &'static str) -> HttpError {
    HttpError { status, reason }
}

fn serve(mut stream: TcpStream, calls: &SyncSender<Pending>, config: ServerConfig) {
    if stream.set_read_timeout(Some(config.io_timeout)).is_err()
        || stream.set_write_timeout(Some(config.io_timeout)).is_err()
    {
        return;
    }
    let body = match read_request(
        &mut stream,
        config.max_body,
        config.io_timeout,
        Instant::now().checked_add(config.request_timeout),
    ) {
        Ok(body) => body,
        // The client stopped talking or the connection broke: nothing to say.
        Err(None) => return,
        Err(Some(error)) => {
            write_response(&mut stream, error.status, error.reason, &[]);
            return;
        }
    };
    let answer = match parse(&body) {
        Err(malformed) => failure(&malformed.id, &malformed.error),
        Ok(request) => respond(&request.id, ask_the_node(request.call, calls, config)),
    };
    write_response(&mut stream, 200, "OK", &answer);
}

fn ask_the_node(call: Call, calls: &SyncSender<Pending>, config: ServerConfig) -> Reply {
    let (reply, answer) = mpsc::sync_channel::<Reply>(1);
    match calls.try_send(Pending { call, reply }) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => return Err(RpcError::unavailable("the node is busy")),
        Err(TrySendError::Disconnected(_)) => {
            return Err(RpcError::unavailable("the node is shutting down"))
        }
    }
    match answer.recv_timeout(config.reply_timeout) {
        Ok(reply) => reply,
        Err(RecvTimeoutError::Timeout) => {
            Err(RpcError::unavailable("the node did not answer in time"))
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err(RpcError::unavailable("the node is shutting down"))
        }
    }
}

/// Reads one request and returns its body. `Err(None)` is a connection that
/// gave out; `Err(Some(_))` is a request to refuse.
///
/// `deadline` is when the whole request must have arrived (`None` if that
/// is too far off to represent, which no configuration reaches). Before
/// every read the socket's timeout is cut to what is left of it, so the
/// per-read limit alone cannot be stretched by a client that always sends
/// one more byte in time.
fn read_request(
    stream: &mut TcpStream,
    max_body: usize,
    io_timeout: Duration,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, Option<HttpError>> {
    let budget = |stream: &TcpStream| -> Result<(), Option<HttpError>> {
        let Some(deadline) = deadline else {
            return Ok(());
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(None);
        }
        stream
            .set_read_timeout(Some(left.min(io_timeout)))
            .map_err(|_| None)
    };
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(end) = find_header_end(&buffer) {
            break end;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(Some(http(431, "Request Header Fields Too Large")));
        }
        budget(stream)?;
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(None),
            Ok(count) => buffer.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(Some(http(431, "Request Header Fields Too Large")));
    }
    let head = buffer.get(..header_end).unwrap_or_default();
    let head = std::str::from_utf8(head).map_err(|_| Some(http(400, "Bad Request")))?;
    let mut lines = head.split("\r\n");

    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (method, path, version) = (parts.next(), parts.next(), parts.next());
    if parts.next().is_some() || !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(Some(http(400, "Bad Request")));
    }
    if method == Some("OPTIONS") {
        // A browser's CORS preflight for the POST below; this RPC is
        // already fully public and unauthenticated, so any origin may ask.
        return Err(Some(http(204, "No Content")));
    }
    if method != Some("POST") {
        return Err(Some(http(405, "Method Not Allowed")));
    }
    if path != Some("/") {
        return Err(Some(http(404, "Not Found")));
    }

    let mut length: Option<usize> = None;
    let mut expects_continue = false;
    for line in lines.filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            return Err(Some(http(400, "Bad Request")));
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        match name.as_str() {
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(Some(http(400, "Bad Request")));
                }
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| Some(http(413, "Payload Too Large")))?,
                );
            }
            "transfer-encoding" => return Err(Some(http(501, "Not Implemented"))),
            "expect" if value.eq_ignore_ascii_case("100-continue") => expects_continue = true,
            _ => {}
        }
    }
    let Some(length) = length else {
        return Err(Some(http(411, "Length Required")));
    };
    if length > max_body {
        return Err(Some(http(413, "Payload Too Large")));
    }

    let body_start = header_end.saturating_add(4);
    let mut body: Vec<u8> = buffer.get(body_start..).unwrap_or_default().to_vec();
    if body.len() > length {
        // More than it said it would send.
        return Err(Some(http(400, "Bad Request")));
    }
    if body.len() < length && expects_continue {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| None)?;
    }
    while body.len() < length {
        let want = length.saturating_sub(body.len()).min(chunk.len());
        budget(stream)?;
        match stream.read(chunk.get_mut(..want).unwrap_or_default()) {
            Ok(0) | Err(_) => return Err(None),
            Ok(count) => body.extend_from_slice(chunk.get(..count).unwrap_or_default()),
        }
    }
    Ok(body)
}

/// The offset of the blank line that ends the headers, if it has arrived.
fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_response(stream: &mut TcpStream, status: u16, reason: &str, body: &[u8]) {
    // This RPC is already fully public and unauthenticated (anyone can
    // already call it directly), so allowing every browser origin adds no
    // capability — it only lets browser JS call it without a backend proxy.
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\nAccess-Control-Allow-Origin: *\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type\r\n{}\r\n",
        body.len(),
        if status == 405 { "Allow: POST\r\n" } else { "" }
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}
