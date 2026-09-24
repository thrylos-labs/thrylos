//! What `chain-names` does with a request, with no sockets in it: a parsed HTTP
//! request goes in, a response comes out. The binary reads and writes the
//! connections; everything that decides anything is here, so it is tested
//! directly. See `docs/thry-names.md`.

// `serde_json::Value` indexing by key returns `Null` for a missing key and
// never panics; the lint cannot tell it from slice indexing.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use chain_rpc::hex;
use chain_text::{format_address, parse_address};
use serde_json::{json, Value};

use crate::names::{
    constant_time_eq, validate_name, verify_reservation, AddressStatus, NameError, NameErrorOrIo,
    RateLimiter, Registry, Reservation,
};

/// Reservations one source may make in [`HOUR_MS`].
pub const RESERVATIONS_PER_SOURCE_PER_HOUR: usize = 5;
/// Reservations everyone together may make in [`HOUR_MS`].
pub const RESERVATIONS_PER_HOUR: usize = 500;
/// Lookups one source may make in a minute.
pub const LOOKUPS_PER_SOURCE_PER_MINUTE: usize = 60;
/// The most a request body may be.
pub const MAX_BODY_BYTES: usize = 1024;

const HOUR_MS: u64 = 60 * 60 * 1000;
const MINUTE_MS: u64 = 60 * 1000;
/// Sources tracked by the limiters before the map is swept.
const SWEEP_AT: usize = 4096;

/// A request, already parsed. Header names are lowercase.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    /// The connection's own address, as text (for sources not behind the tunnel).
    pub peer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub body: Value,
    /// Whether browsers may read this from another origin. Off for the route
    /// only the faucet calls.
    pub cors: bool,
}

impl Response {
    fn ok(body: Value) -> Self {
        Self {
            status: 200,
            reason: "OK",
            body,
            cors: true,
        }
    }

    fn failure(status: u16, reason: &'static str, code: &str, message: &str) -> Self {
        Self {
            status,
            reason,
            body: json!({ "error": { "code": code, "message": message } }),
            cors: true,
        }
    }

    fn name_error(error: &NameError) -> Self {
        let (status, reason) = match error {
            NameError::InvalidName(_)
            | NameError::Reserved
            | NameError::Malformed(_)
            | NameError::StaleClaim
            | NameError::BadSignature => (400, "Bad Request"),
            NameError::Taken | NameError::AddressHasName | NameError::DiscordUserHasName => {
                (409, "Conflict")
            }
            NameError::NoReservation => (404, "Not Found"),
            NameError::Full => (503, "Service Unavailable"),
        };
        Self::failure(status, reason, error.code(), &error.to_string())
    }

    fn not_found() -> Self {
        Self::failure(404, "Not Found", "NotFound", "no such name or route")
    }

    /// The preflight answer for a browser's cross-origin check.
    pub fn preflight() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            body: Value::Null,
            cors: true,
        }
    }
}

/// The registry and the limits around it.
pub struct NamesService {
    registry: Registry,
    chain_id: u64,
    /// The secret the faucet presents to confirm a name.
    secret: Vec<u8>,
    per_source: RateLimiter,
    overall: RateLimiter,
    lookups: RateLimiter,
}

impl NamesService {
    pub fn new(registry: Registry, chain_id: u64, secret: Vec<u8>) -> Self {
        Self {
            registry,
            chain_id,
            secret,
            per_source: RateLimiter::default(),
            overall: RateLimiter::default(),
            lookups: RateLimiter::default(),
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn handle(&mut self, now_ms: u64, request: &Request) -> Response {
        if self.lookups.tracked() > SWEEP_AT {
            self.lookups.sweep(now_ms, MINUTE_MS);
        }
        if self.per_source.tracked() > SWEEP_AT {
            self.per_source.sweep(now_ms, HOUR_MS);
        }
        let path = request.path.trim_end_matches('/');
        match (request.method.as_str(), path) {
            ("OPTIONS", _) => Response::preflight(),
            ("POST", "/names") => self.reserve(now_ms, request),
            ("POST", "/internal/confirm") => self.confirm(now_ms, request),
            ("GET", _) => self.lookup(now_ms, request, path),
            _ => Response::failure(
                405,
                "Method Not Allowed",
                "MethodNotAllowed",
                "use GET or POST",
            ),
        }
    }

    /// Who a request is from. Behind the tunnel every connection is from
    /// loopback, so the client's own address is the tunnel's
    /// `CF-Connecting-IP`, which is only believable because this service
    /// listens on loopback and nothing else can reach it.
    fn source(request: &Request) -> String {
        request
            .headers
            .get("cf-connecting-ip")
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && value.len() <= 64)
            .unwrap_or_else(|| request.peer.clone())
    }

    fn lookup(&mut self, now_ms: u64, request: &Request, path: &str) -> Response {
        let source = Self::source(request);
        if !self
            .lookups
            .allow(&source, now_ms, LOOKUPS_PER_SOURCE_PER_MINUTE, MINUTE_MS)
        {
            return Response::failure(
                429,
                "Too Many Requests",
                "RateLimited",
                "too many lookups; wait a minute",
            );
        }
        if let Some(text) = path.strip_prefix("/names/available/") {
            return match validate_name(text) {
                Err(error) => Response::ok(json!({
                    "name": text.to_ascii_lowercase(),
                    "valid": false,
                    "available": false,
                    "reason": error.to_string(),
                })),
                Ok(name) => Response::ok(json!({
                    "name": name,
                    "valid": true,
                    "available": self.registry.is_available(now_ms, &name),
                })),
            };
        }
        if let Some(text) = path.strip_prefix("/names/by-address/") {
            let Ok(address) = parse_address(text) else {
                return Response::name_error(&NameError::Malformed("address"));
            };
            return match self.registry.status(now_ms, &address) {
                AddressStatus::None => Response::not_found(),
                AddressStatus::Pending { expires_ms } => {
                    Response::ok(json!({ "status": "pending", "expiresAtMs": expires_ms }))
                }
                AddressStatus::Confirmed { name } => {
                    Response::ok(json!({ "status": "confirmed", "name": name }))
                }
            };
        }
        if let Some(text) = path.strip_prefix("/names/") {
            let Ok(name) = validate_name(text) else {
                return Response::not_found();
            };
            return match self.registry.resolve(&name) {
                Some(address) => Response::ok(json!({
                    "name": name,
                    "address": format_address(&address),
                })),
                None => Response::not_found(),
            };
        }
        Response::not_found()
    }

    fn reserve(&mut self, now_ms: u64, request: &Request) -> Response {
        let source = Self::source(request);
        if !self
            .per_source
            .allow(&source, now_ms, RESERVATIONS_PER_SOURCE_PER_HOUR, HOUR_MS)
        {
            return Response::failure(
                429,
                "Too Many Requests",
                "RateLimited",
                "too many reservations from here; try again in an hour",
            );
        }
        if !self
            .overall
            .allow("all", now_ms, RESERVATIONS_PER_HOUR, HOUR_MS)
        {
            return Response::failure(
                429,
                "Too Many Requests",
                "RateLimited",
                "the registry is busy; try again later",
            );
        }
        let reservation = match parse_reservation(&request.body) {
            Ok(reservation) => reservation,
            Err(error) => return Response::name_error(&error),
        };
        let (name, address) = match verify_reservation(self.chain_id, &reservation, now_ms) {
            Ok(verified) => verified,
            Err(error) => return Response::name_error(&error),
        };
        match self.registry.reserve(now_ms, &name, &address) {
            Ok(expires_ms) => Response::ok(json!({
                "status": "pending",
                "name": name,
                "address": format_address(&address),
                "expiresAtMs": expires_ms,
            })),
            Err(error) => self.failure_of(error),
        }
    }

    fn confirm(&mut self, now_ms: u64, request: &Request) -> Response {
        // Only ever the faucet, on this machine. A request that came through
        // the tunnel carries Cloudflare's headers and is refused whatever it
        // knows, so a mistake in the tunnel's routes cannot expose this.
        let through_tunnel = request
            .headers
            .keys()
            .any(|name| name == "cf-connecting-ip" || name == "cf-ray");
        let presented = request
            .headers
            .get("x-names-secret")
            .map(String::as_bytes)
            .unwrap_or_default();
        if through_tunnel || !constant_time_eq(presented, &self.secret) {
            return Response {
                status: 401,
                reason: "Unauthorized",
                body: json!({ "error": { "code": "Unauthorized", "message": "not allowed" } }),
                cors: false,
            };
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return Self::internal(Response::name_error(&NameError::Malformed(
                "body is not JSON",
            )));
        };
        let Some(address_text) = body["address"].as_str() else {
            return Self::internal(Response::name_error(&NameError::Malformed("address")));
        };
        let Some(user) = body["discordUserId"].as_str() else {
            return Self::internal(Response::name_error(&NameError::Malformed("discordUserId")));
        };
        let Ok(address) = parse_address(address_text) else {
            return Self::internal(Response::name_error(&NameError::Malformed("address")));
        };
        match self.registry.confirm(now_ms, &address, user) {
            Ok(name) => Self::internal(Response::ok(json!({
                "status": "confirmed",
                "name": name,
                "address": format_address(&address),
            }))),
            Err(error) => Self::internal(self.failure_of(error)),
        }
    }

    fn internal(mut response: Response) -> Response {
        response.cors = false;
        response
    }

    fn failure_of(&self, error: NameErrorOrIo) -> Response {
        match error {
            NameErrorOrIo::Name(error) => Response::name_error(&error),
            NameErrorOrIo::Registry(error) => {
                Response::failure(500, "Internal Server Error", "Internal", &error.to_string())
            }
        }
    }
}

/// Reads the body of a reservation: strictly typed, lengths checked, hex only.
fn parse_reservation(body: &[u8]) -> Result<Reservation, NameError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(NameError::Malformed("body too large"));
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| NameError::Malformed("body is not JSON"))?;
    let name = value["name"]
        .as_str()
        .ok_or(NameError::Malformed("name"))?
        .to_owned();
    let public_key: [u8; 32] = hex::decode(
        value["publicKey"]
            .as_str()
            .ok_or(NameError::Malformed("publicKey"))?,
    )
    .map_err(|_| NameError::Malformed("publicKey"))?
    .try_into()
    .map_err(|_| NameError::Malformed("publicKey"))?;
    let signature: [u8; 64] = hex::decode(
        value["signature"]
            .as_str()
            .ok_or(NameError::Malformed("signature"))?,
    )
    .map_err(|_| NameError::Malformed("signature"))?
    .try_into()
    .map_err(|_| NameError::Malformed("signature"))?;
    let timestamp_ms = value["timestampMs"]
        .as_u64()
        .ok_or(NameError::Malformed("timestampMs"))?;
    Ok(Reservation {
        name,
        public_key,
        timestamp_ms,
        signature,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use chain_types::{Address, PublicKey};
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::names::claim_message;

    const CHAIN: u64 = 20_260_923;
    const NOW: u64 = 1_790_000_000_000;
    const SECRET: &[u8] = b"a-shared-secret-for-the-tests-00";

    fn service() -> (tempfile::TempDir, NamesService) {
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::open(dir.path()).unwrap();
        (dir, NamesService::new(registry, CHAIN, SECRET.to_vec()))
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn address_of(key: &SigningKey) -> Address {
        Address::from_public_key(
            &PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap(),
        )
    }

    fn request(method: &str, path: &str, body: Vec<u8>) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            headers: BTreeMap::new(),
            body,
            peer: "127.0.0.1".into(),
        }
    }

    fn from_source(mut request: Request, ip: &str) -> Request {
        request.headers.insert("cf-connecting-ip".into(), ip.into());
        request
    }

    fn reserve_body(key: &SigningKey, name: &str, timestamp_ms: u64) -> Vec<u8> {
        let address = address_of(key);
        let message = claim_message(CHAIN, name, &address, timestamp_ms);
        serde_json::to_vec(&json!({
            "name": name,
            "publicKey": hex::encode(&key.verifying_key().to_bytes()),
            "timestampMs": timestamp_ms,
            "signature": hex::encode(&key.sign(&message).to_bytes()),
        }))
        .unwrap()
    }

    fn confirm(user: &str, address: &Address) -> Request {
        let mut request = request(
            "POST",
            "/internal/confirm",
            serde_json::to_vec(
                &json!({ "address": format_address(address), "discordUserId": user }),
            )
            .unwrap(),
        );
        request.headers.insert(
            "x-names-secret".into(),
            String::from_utf8(SECRET.to_vec()).unwrap(),
        );
        request
    }

    fn code(response: &Response) -> &str {
        response.body["error"]["code"].as_str().unwrap_or("")
    }

    #[test]
    fn reserving_confirming_and_looking_up_a_name_end_to_end() {
        let (_dir, mut service) = service();
        let alice = key(1);
        let address = address_of(&alice);

        let reserved = service.handle(
            NOW,
            &request("POST", "/names", reserve_body(&alice, "alice", NOW)),
        );
        assert_eq!(reserved.status, 200, "{:?}", reserved.body);
        assert_eq!(reserved.body["status"], "pending");
        assert_eq!(reserved.body["address"], format_address(&address));

        // Pending: the name is free of lookup, the address shows only a status.
        let pending = service.handle(NOW, &request("GET", "/names/alice", vec![]));
        assert_eq!(pending.status, 404);
        let by_address = service.handle(
            NOW,
            &request(
                "GET",
                &format!("/names/by-address/{}", format_address(&address)),
                vec![],
            ),
        );
        assert_eq!(by_address.body["status"], "pending");
        assert!(
            by_address.body.get("name").is_none(),
            "the pending name is not disclosed"
        );
        let taken = service.handle(NOW, &request("GET", "/names/available/alice", vec![]));
        assert_eq!(taken.body["available"], false);

        let confirmed = service.handle(NOW + 10, &confirm("80351110224678912", &address));
        assert_eq!(confirmed.status, 200, "{:?}", confirmed.body);
        assert_eq!(confirmed.body["name"], "alice");

        let resolved = service.handle(NOW + 20, &request("GET", "/names/alice.thry", vec![]));
        assert_eq!(resolved.status, 200);
        assert_eq!(resolved.body["address"], format_address(&address));
        let by_address = service.handle(
            NOW + 20,
            &request(
                "GET",
                &format!("/names/by-address/{}", format_address(&address)),
                vec![],
            ),
        );
        assert_eq!(by_address.body["name"], "alice");
        assert_eq!(by_address.body["status"], "confirmed");
    }

    #[test]
    fn availability_says_why_a_name_cannot_be_used() {
        let (_dir, mut service) = service();
        let free = service.handle(NOW, &request("GET", "/names/available/newname", vec![]));
        assert_eq!(free.body["valid"], true);
        assert_eq!(free.body["available"], true);
        for bad in ["ab", "admin", "a--b"] {
            let answer = service.handle(
                NOW,
                &request("GET", &format!("/names/available/{bad}"), vec![]),
            );
            assert_eq!(answer.body["valid"], false, "{bad}");
            assert_eq!(answer.body["available"], false, "{bad}");
            assert!(answer.body["reason"].as_str().unwrap().len() > 3);
        }
    }

    #[test]
    fn a_bad_reservation_is_refused_with_the_right_status() {
        let (_dir, mut service) = service();
        let alice = key(1);
        let post = |service: &mut NamesService, body: Vec<u8>, ip: &str| {
            service.handle(NOW, &from_source(request("POST", "/names", body), ip))
        };
        // Not JSON, missing fields, a bad hex key.
        assert_eq!(
            code(&post(&mut service, b"nope".to_vec(), "1.1.1.1")),
            "Malformed"
        );
        assert_eq!(
            code(&post(&mut service, b"{}".to_vec(), "1.1.1.2")),
            "Malformed"
        );
        let mut body: Value = serde_json::from_slice(&reserve_body(&alice, "alice", NOW)).unwrap();
        body["publicKey"] = json!("zz");
        assert_eq!(
            code(&post(
                &mut service,
                serde_json::to_vec(&body).unwrap(),
                "1.1.1.3"
            )),
            "Malformed"
        );
        // Oversized body.
        assert_eq!(
            code(&post(
                &mut service,
                vec![b' '; MAX_BODY_BYTES + 1],
                "1.1.1.4"
            )),
            "Malformed"
        );
        // A signature made for another name; a stale timestamp; a reserved name.
        let mut wrong: Value = serde_json::from_slice(&reserve_body(&alice, "alice", NOW)).unwrap();
        wrong["name"] = json!("bobby");
        let refused = post(&mut service, serde_json::to_vec(&wrong).unwrap(), "1.1.1.5");
        assert_eq!((refused.status, code(&refused)), (400, "BadSignature"));
        let stale = service.handle(
            NOW + 10 * 60 * 1000,
            &from_source(
                request("POST", "/names", reserve_body(&alice, "alice", NOW)),
                "1.1.1.6",
            ),
        );
        assert_eq!(code(&stale), "StaleClaim");
        let reserved = post(&mut service, reserve_body(&alice, "admin", NOW), "1.1.1.7");
        assert_eq!(code(&reserved), "Reserved");
        assert_eq!(service.registry().pending_count(), 0, "nothing was stored");
    }

    #[test]
    fn a_taken_name_is_a_conflict_and_a_second_name_for_an_address_too() {
        let (_dir, mut service) = service();
        let (alice, bob) = (key(1), key(2));
        let go = |service: &mut NamesService, key: &SigningKey, name: &str, ip: &str| {
            service.handle(
                NOW,
                &from_source(request("POST", "/names", reserve_body(key, name, NOW)), ip),
            )
        };
        assert_eq!(go(&mut service, &alice, "alice", "2.0.0.1").status, 200);
        let clash = go(&mut service, &bob, "alice", "2.0.0.2");
        assert_eq!((clash.status, code(&clash)), (409, "Taken"));
        service.handle(NOW, &confirm("7", &address_of(&alice)));
        let second = go(&mut service, &alice, "alice2", "2.0.0.1");
        assert_eq!((second.status, code(&second)), (409, "AddressHasName"));
    }

    #[test]
    fn reservations_are_limited_per_source_and_overall() {
        let (_dir, mut service) = service();
        let keys: Vec<SigningKey> = (1..=8).map(key).collect();
        let mut statuses = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let name = format!("name{index}x");
            statuses.push(
                service
                    .handle(
                        NOW,
                        &from_source(
                            request("POST", "/names", reserve_body(key, &name, NOW)),
                            "9.9.9.9",
                        ),
                    )
                    .status,
            );
        }
        assert_eq!(&statuses[..5], &[200; 5]);
        assert_eq!(
            &statuses[5..],
            &[429; 3],
            "the sixth from one source is refused"
        );
        // Another source is unaffected, and after the hour the first is too.
        let other = service.handle(
            NOW,
            &from_source(
                request("POST", "/names", reserve_body(&key(20), "fresh1", NOW)),
                "9.9.9.8",
            ),
        );
        assert_eq!(other.status, 200);
        let later = service.handle(
            NOW + HOUR_MS,
            &from_source(
                request(
                    "POST",
                    "/names",
                    reserve_body(&key(21), "fresh2", NOW + HOUR_MS),
                ),
                "9.9.9.9",
            ),
        );
        assert_eq!(later.status, 200);
    }

    #[test]
    fn lookups_are_limited_per_source() {
        let (_dir, mut service) = service();
        let go = |service: &mut NamesService, at: u64| {
            service
                .handle(
                    at,
                    &from_source(request("GET", "/names/nobody", vec![]), "3.3.3.3"),
                )
                .status
        };
        for _ in 0..LOOKUPS_PER_SOURCE_PER_MINUTE {
            assert_eq!(go(&mut service, NOW), 404);
        }
        assert_eq!(go(&mut service, NOW), 429);
        assert_eq!(go(&mut service, NOW + MINUTE_MS), 404);
    }

    #[test]
    fn only_the_faucet_can_confirm_and_never_through_the_tunnel() {
        let (_dir, mut service) = service();
        let alice = key(1);
        service.handle(
            NOW,
            &request("POST", "/names", reserve_body(&alice, "alice", NOW)),
        );
        let address = address_of(&alice);

        // No secret, a wrong secret, and the right secret arriving through the tunnel.
        let mut none = confirm("5", &address);
        none.headers.remove("x-names-secret");
        assert_eq!(service.handle(NOW, &none).status, 401);
        let mut wrong = confirm("5", &address);
        wrong
            .headers
            .insert("x-names-secret".into(), "not-the-secret".into());
        assert_eq!(service.handle(NOW, &wrong).status, 401);
        let mut tunnelled = confirm("5", &address);
        tunnelled
            .headers
            .insert("cf-connecting-ip".into(), "8.8.8.8".into());
        assert_eq!(service.handle(NOW, &tunnelled).status, 401);
        let mut ray = confirm("5", &address);
        ray.headers.insert("cf-ray".into(), "abc".into());
        assert_eq!(service.handle(NOW, &ray).status, 401);
        assert_eq!(service.registry().confirmed_count(), 0);

        let answered = service.handle(NOW, &confirm("5", &address));
        assert_eq!(answered.status, 200);
        assert!(!answered.cors, "a browser is never meant to call this");
    }

    #[test]
    fn confirming_reports_each_refusal_plainly() {
        let (_dir, mut service) = service();
        let (alice, bob) = (key(1), key(2));
        // No reservation.
        assert_eq!(
            code(&service.handle(NOW, &confirm("5", &address_of(&alice)))),
            "NoReservation"
        );
        service.handle(
            NOW,
            &from_source(
                request("POST", "/names", reserve_body(&alice, "alice", NOW)),
                "4.4.4.1",
            ),
        );
        service.handle(
            NOW,
            &from_source(
                request("POST", "/names", reserve_body(&bob, "bobby", NOW)),
                "4.4.4.2",
            ),
        );
        assert_eq!(
            service
                .handle(NOW, &confirm("5", &address_of(&alice)))
                .status,
            200
        );
        // The same Discord user for a second name; the same address twice.
        assert_eq!(
            code(&service.handle(NOW, &confirm("5", &address_of(&bob)))),
            "DiscordUserHasName"
        );
        assert_eq!(
            code(&service.handle(NOW, &confirm("6", &address_of(&alice)))),
            "AddressHasName"
        );
        // A malformed body.
        let mut broken = confirm("5", &address_of(&bob));
        broken.body = b"{}".to_vec();
        assert_eq!(code(&service.handle(NOW, &broken)), "Malformed");
    }

    #[test]
    fn a_lapsed_reservation_cannot_be_confirmed() {
        let (_dir, mut service) = service();
        let alice = key(1);
        service.handle(
            NOW,
            &request("POST", "/names", reserve_body(&alice, "alice", NOW)),
        );
        let after = NOW + crate::names::PENDING_TTL_MS;
        assert_eq!(
            code(&service.handle(after, &confirm("5", &address_of(&alice)))),
            "NoReservation"
        );
    }

    #[test]
    fn preflight_and_public_answers_allow_any_origin_and_odd_methods_are_refused() {
        let (_dir, mut service) = service();
        let preflight = service.handle(NOW, &request("OPTIONS", "/names", vec![]));
        assert_eq!((preflight.status, preflight.cors), (204, true));
        assert!(
            service
                .handle(NOW, &request("GET", "/names/nobody", vec![]))
                .cors
        );
        assert_eq!(
            service
                .handle(NOW, &request("DELETE", "/names/x", vec![]))
                .status,
            405
        );
        assert_eq!(
            service
                .handle(NOW, &request("GET", "/elsewhere", vec![]))
                .status,
            404
        );
        // A malformed address in the by-address route.
        let bad = service.handle(
            NOW,
            &request("GET", "/names/by-address/not-an-address", vec![]),
        );
        assert_eq!(bad.status, 400);
    }
}
