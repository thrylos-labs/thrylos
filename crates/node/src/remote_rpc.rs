//! An RPC connection for `thrylos` that can reach a local node over plain
//! HTTP or a public gateway over TLS, addressed by hostname.
//!
//! Every other RPC caller in this crate (`chain-node devnet`, the faucet, the
//! explorer, `health`) stays on loopback and keeps using
//! [`crate::client::RpcClient`]; this type exists only for the one client
//! that a real person points at a real host on the public internet
//! (`docs/core-network-alpha.md`, "Secure public RPC access"). TLS is
//! rustls, verified against Mozilla's compiled-in root list
//! (`webpki-roots`): no OS trust store to misconfigure, identical behavior
//! on every platform this CLI runs on.

// Indexing a `serde_json::Value` by name never panics: a missing field reads
// as `null`, which every caller here already checks for.
#![allow(clippy::indexing_slicing)]

use std::io::Write;
use std::net::TcpStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::{ServerName, TrustAnchor};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};

use crate::client::{read_capped, ClientError, RpcCall};

const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A parsed `--rpc` / `THRYLOS_RPC` / saved-profile value: `host:port` (plain
/// HTTP, for a local node), or `http://host[:port]` / `https://host[:port]`
/// (for a gateway).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Endpoint {
    /// Parses one of the forms above. A bare `host:port` is always plain
    /// HTTP: that is how a local node is reached, and nothing here should
    /// silently start expecting a TLS handshake from one.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (rest, tls, default_port) = if let Some(rest) = text.strip_prefix("https://") {
            (rest, true, 443)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (rest, false, 80)
        } else {
            (text, false, 0)
        };
        let rest = rest.trim_end_matches('/');
        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port_text)) if !host.is_empty() => {
                let port: u16 = port_text
                    .parse()
                    .map_err(|_| format!("{text:?} has an invalid port"))?;
                (host, port)
            }
            _ if default_port != 0 => (rest, default_port),
            _ => {
                return Err(format!(
                    "{text:?} needs a port, such as {text}:26660, or an http:// / https:// URL"
                ));
            }
        };
        if host.is_empty() {
            return Err(format!("{text:?} has no host"));
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            tls,
        })
    }

    pub fn display(&self) -> String {
        if self.tls {
            format!("https://{}:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// One JSON-RPC call. A JSON-RPC error becomes [`ClientError::Rpc`].
    pub fn call(&self, method: &str, params: &Value) -> Result<Value, ClientError> {
        let body =
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        // `Connection: close` so a keep-alive-by-default gateway still closes
        // the socket after one response; otherwise `read_to_string` would
        // block waiting for an EOF the server never sends.
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.host,
            body.len()
        );
        let text = if self.tls {
            self.exchange_tls(&request)?
        } else {
            self.exchange_plain(&request)?
        };
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or_else(|| ClientError::Transport("no HTTP response".into()))?;
        if !head.starts_with("HTTP/1.1 200") {
            return Err(ClientError::Transport(format!(
                "the RPC answered `{}`",
                head.lines().next().unwrap_or_default()
            )));
        }
        let mut response: Value = serde_json::from_str(body).map_err(transport)?;
        if let Some(error) = response.get_mut("error").map(Value::take) {
            return Err(ClientError::Rpc {
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"].as_str().unwrap_or_default().to_owned(),
                data: error.get("data").cloned(),
            });
        }
        Ok(response["result"].take())
    }

    fn connect(&self) -> Result<TcpStream, ClientError> {
        let stream = TcpStream::connect((self.host.as_str(), self.port)).map_err(|error| {
            ClientError::Transport(format!("could not reach {}: {error}", self.display()))
        })?;
        stream
            .set_read_timeout(Some(READ_TIMEOUT))
            .map_err(transport)?;
        Ok(stream)
    }

    fn exchange_plain(&self, request: &str) -> Result<String, ClientError> {
        let mut stream = self.connect()?;
        stream.write_all(request.as_bytes()).map_err(transport)?;
        let mut text = String::new();
        read_capped(&mut stream, &mut text)?.map_err(transport)?;
        Ok(text)
    }

    fn exchange_tls(&self, request: &str) -> Result<String, ClientError> {
        let config = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(default_roots())
                .with_no_client_auth(),
        );
        let name = ServerName::try_from(self.host.clone()).map_err(|_| {
            ClientError::Setup(format!("{:?} is not a valid TLS server name", self.host))
        })?;
        let connection = ClientConnection::new(config, name).map_err(|error| {
            ClientError::Transport(format!(
                "could not start TLS to {}: {error}",
                self.display()
            ))
        })?;
        let stream = self.connect()?;
        let mut tls = StreamOwned::new(connection, stream);
        tls.write_all(request.as_bytes()).map_err(transport)?;
        let mut text = String::new();
        match read_capped(&mut tls, &mut text)? {
            Ok(_) => {}
            // A server that answers `Connection: close` may end the TLS
            // session without a `close_notify`; the response bytes already
            // read are still whole and authenticated.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof && !text.is_empty() => {
            }
            Err(error) => return Err(transport(error)),
        }
        Ok(text)
    }
}

impl RpcCall for Endpoint {
    fn call(&self, method: &str, params: &Value) -> Result<Value, ClientError> {
        Self::call(self, method, params)
    }
}

fn default_roots() -> RootCertStore {
    static ROOTS: OnceLock<Vec<TrustAnchor<'static>>> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| webpki_roots::TLS_SERVER_ROOTS.to_vec());
    RootCertStore {
        roots: roots.clone(),
    }
}

fn transport(error: impl core::fmt::Display) -> ClientError {
    ClientError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn a_bare_host_port_is_plain_http() {
        let endpoint = Endpoint::parse("127.0.0.1:26660").unwrap();
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 26660);
        assert!(!endpoint.tls);
        assert_eq!(endpoint.display(), "127.0.0.1:26660");
    }

    #[test]
    fn https_defaults_to_port_443_and_http_to_80() {
        let https = Endpoint::parse("https://rpc.testnet.example").unwrap();
        assert_eq!(https.host, "rpc.testnet.example");
        assert_eq!(https.port, 443);
        assert!(https.tls);
        assert_eq!(https.display(), "https://rpc.testnet.example:443");

        let http = Endpoint::parse("http://rpc.testnet.example/").unwrap();
        assert_eq!(http.port, 80);
        assert!(!http.tls);
    }

    #[test]
    fn an_explicit_port_overrides_the_scheme_default() {
        let endpoint = Endpoint::parse("https://rpc.testnet.example:8443").unwrap();
        assert_eq!(endpoint.port, 8443);
        assert!(endpoint.tls);
    }

    #[test]
    fn a_bare_host_with_no_port_is_refused() {
        let error = Endpoint::parse("rpc.testnet.example").unwrap_err();
        assert!(error.contains("needs a port"), "{error}");
    }

    #[test]
    fn an_unreachable_host_fails_cleanly() {
        // Port 0 never accepts a connection.
        let endpoint = Endpoint::parse("127.0.0.1:0").unwrap();
        let error = endpoint.call("status", &json!({})).unwrap_err();
        assert!(matches!(error, ClientError::Transport(_)), "{error}");
    }

    /// A TLS host that does not exist fails through the TLS path (name
    /// resolution, then connection) rather than silently falling back to
    /// plain HTTP.
    #[test]
    fn an_unreachable_tls_host_fails_cleanly() {
        let endpoint = Endpoint::parse("https://127.0.0.1:0").unwrap();
        let error = endpoint.call("status", &json!({})).unwrap_err();
        assert!(matches!(error, ClientError::Transport(_)), "{error}");
    }
}
