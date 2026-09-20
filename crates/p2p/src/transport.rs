//! One authenticated transport for the first testnet.
//!
//! Connections are TCP, mutually authenticated with a short Ed25519
//! challenge-response handshake, and accepted only when the remote public key
//! appears in the static trusted-peer table. Frames then carry either an
//! existing `chain-consensus` host message (which already includes block
//! catch-up requests and responses) or one signed transaction.
//!
//! A receiver reads the five-byte frame header first. The message kind gives
//! it a hard size ceiling; [`IngressGate::reserve`] applies the global and
//! per-peer byte budgets to the declared length before a body allocation,
//! decoding, or signature verification occurs. Every frame is signed over a
//! fresh session identifier and sequence number, so authentication continues
//! after the handshake. Only a strictly decoded and verified
//! [`NetworkMessage`] is returned to the caller.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chain_consensus::host::Message;
use chain_consensus::wire::{decode_message, encode_message};
use chain_types::codec::{decode_exact, Encode};
use chain_types::Transaction;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{DropReason, GossipLimits, IngressGate, PeerId};

const PROTOCOL_MAGIC: [u8; 8] = *b"THRYNET1";
const HANDSHAKE_DOMAIN: &[u8] = b"THRYLOS-NETWORK-HANDSHAKE-V1";
const SESSION_DOMAIN: &[u8] = b"THRYLOS-NETWORK-SESSION-V1";
const FRAME_DOMAIN: &[u8] = b"THRYLOS-NETWORK-FRAME-V1";
const CONSENSUS_FRAME: u8 = 0;
const TRANSACTION_FRAME: u8 = 1;
const FRAME_HEADER_BYTES: usize = 5;
const HELLO_BYTES: usize = 72;
const SIGNATURE_BYTES: usize = 64;

/// A consensus frame may contain two nearly-full blocks during catch-up plus
/// their certificates. Larger catch-up ranges use another bounded request.
pub const MAX_CONSENSUS_FRAME_BYTES: usize = 9 * 1024 * 1024;
/// A transaction can never be useful if it cannot fit in the four MiB block.
pub const MAX_TRANSACTION_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CONNECTED_PEERS: usize = 64;

#[derive(Debug)]
pub enum NetworkError {
    Io(io::Error),
    Randomness,
    InvalidConfiguration,
    UnknownPeer,
    AuthenticationFailed,
    TooManyPeers,
    DuplicatePeer,
    FrameTooLarge,
    IngressLimited,
    Malformed,
    InvalidSignature,
    LockPoisoned,
}

impl core::fmt::Display for NetworkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "network I/O: {error}"),
            Self::Randomness => f.write_str("operating-system randomness unavailable"),
            Self::InvalidConfiguration => f.write_str("invalid network configuration"),
            Self::UnknownPeer => f.write_str("peer is not in the static trusted-peer set"),
            Self::AuthenticationFailed => f.write_str("peer authentication failed"),
            Self::TooManyPeers => f.write_str("connected-peer limit reached"),
            Self::DuplicatePeer => f.write_str("peer is already connected"),
            Self::FrameTooLarge => f.write_str("frame exceeds its message-type limit"),
            Self::IngressLimited => f.write_str("frame exceeds an inbound byte budget"),
            Self::Malformed => f.write_str("frame is not a canonical message"),
            Self::InvalidSignature => f.write_str("message signature did not verify"),
            Self::LockPoisoned => f.write_str("network state lock was poisoned"),
        }
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for NetworkError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DropReason> for NetworkError {
    fn from(reason: DropReason) -> Self {
        match reason {
            DropReason::OverBudget => Self::IngressLimited,
            DropReason::Malformed => Self::Malformed,
            DropReason::InvalidSignature => Self::InvalidSignature,
        }
    }
}

/// The transport identity is separate from account and consensus keys.
pub struct NetworkIdentity {
    signing_key: SigningKey,
}

impl NetworkIdentity {
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    pub fn generate() -> Result<Self, NetworkError> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|_| NetworkError::Randomness)?;
        Ok(Self::from_secret_bytes(secret))
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(self.public_key())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedPeer {
    pub address: SocketAddr,
    pub public_key: [u8; 32],
}

impl TrustedPeer {
    pub fn new(address: SocketAddr, public_key: [u8; 32]) -> Result<Self, NetworkError> {
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| NetworkError::InvalidConfiguration)?;
        if key.is_weak() {
            return Err(NetworkError::InvalidConfiguration);
        }
        Ok(Self {
            address,
            public_key,
        })
    }

    pub const fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(self.public_key)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    pub max_peers: usize,
    pub global_inbound_capacity: u64,
    pub per_peer_inbound_capacity: u64,
    pub per_peer_refill_per_second: u64,
    pub io_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_peers: 32,
            global_inbound_capacity: 64 * 1024 * 1024,
            per_peer_inbound_capacity: 16 * 1024 * 1024,
            per_peer_refill_per_second: 4 * 1024 * 1024,
            io_timeout: Duration::from_secs(5),
        }
    }
}

/// Consensus signatures and catch-up certificates depend on the current
/// canonical validator set, so the node supplies this verifier. The transport
/// calls it after strict decode and before returning the message.
pub trait ConsensusVerifier: Send + Sync + 'static {
    fn verify(&self, peer: PeerId, message: &Message) -> bool;
}

impl<F> ConsensusVerifier for F
where
    F: Fn(PeerId, &Message) -> bool + Send + Sync + 'static,
{
    fn verify(&self, peer: PeerId, message: &Message) -> bool {
        self(peer, message)
    }
}

#[derive(Debug, Clone)]
pub enum NetworkMessage {
    Consensus(Message),
    Transaction(Transaction),
}

impl NetworkMessage {
    fn kind_and_bytes(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Consensus(message) => (CONSENSUS_FRAME, encode_message(message)),
            Self::Transaction(transaction) => {
                let mut bytes = Vec::new();
                transaction.encode(&mut bytes);
                (TRANSACTION_FRAME, bytes)
            }
        }
    }
}

struct Shared {
    trusted: BTreeMap<PeerId, TrustedPeer>,
    active: Mutex<BTreeSet<PeerId>>,
    ingress: Mutex<IngressGate>,
    verifier: Arc<dyn ConsensusVerifier>,
    max_peers: usize,
    io_timeout: Duration,
}

pub struct TcpNetwork {
    listener: TcpListener,
    identity: Arc<NetworkIdentity>,
    shared: Arc<Shared>,
}

impl TcpNetwork {
    pub fn bind(
        bind_address: SocketAddr,
        identity: NetworkIdentity,
        trusted_peers: Vec<TrustedPeer>,
        config: TransportConfig,
        verifier: Arc<dyn ConsensusVerifier>,
    ) -> Result<Self, NetworkError> {
        if config.max_peers == 0
            || config.max_peers > MAX_CONNECTED_PEERS
            || trusted_peers.len() > MAX_CONNECTED_PEERS
            || config.per_peer_inbound_capacity == 0
            || config.global_inbound_capacity < config.per_peer_inbound_capacity
            || config.io_timeout.is_zero()
        {
            return Err(NetworkError::InvalidConfiguration);
        }

        let mut trusted = BTreeMap::new();
        for peer in trusted_peers {
            if peer.peer_id() == identity.peer_id()
                || trusted.insert(peer.peer_id(), peer).is_some()
            {
                return Err(NetworkError::InvalidConfiguration);
            }
        }

        let now = Instant::now();
        let ingress = IngressGate::new(
            GossipLimits {
                max_message_bytes: MAX_CONSENSUS_FRAME_BYTES,
                per_peer_bucket_capacity: config.per_peer_inbound_capacity,
                per_peer_refill_per_second: config.per_peer_refill_per_second,
            },
            config.global_inbound_capacity,
            now,
        );
        Ok(Self {
            listener: TcpListener::bind(bind_address)?,
            identity: Arc::new(identity),
            shared: Arc::new(Shared {
                trusted,
                active: Mutex::new(BTreeSet::new()),
                ingress: Mutex::new(ingress),
                verifier,
                max_peers: config.max_peers,
                io_timeout: config.io_timeout,
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, NetworkError> {
        self.listener.local_addr().map_err(Into::into)
    }

    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// Accept one connection. Runtimes call this from their bounded accept
    /// loop; the handshake has a read/write timeout and only allowlisted keys
    /// can consume a peer slot.
    pub fn accept(&self) -> Result<PeerConnection, NetworkError> {
        let (mut stream, _) = self.listener.accept()?;
        configure_stream(&stream, self.shared.io_timeout)?;
        let (peer, session) =
            authenticate_responder(&mut stream, &self.identity, &self.shared.trusted)?;
        self.register(stream, peer, session)
    }

    pub fn connect(&self, peer: PeerId) -> Result<PeerConnection, NetworkError> {
        let trusted = self
            .shared
            .trusted
            .get(&peer)
            .copied()
            .ok_or(NetworkError::UnknownPeer)?;
        let mut stream = TcpStream::connect_timeout(&trusted.address, self.shared.io_timeout)?;
        configure_stream(&stream, self.shared.io_timeout)?;
        let session = authenticate_initiator(&mut stream, &self.identity, &trusted)?;
        self.register(stream, peer, session)
    }

    fn register(
        &self,
        stream: TcpStream,
        peer: PeerId,
        session: [u8; 32],
    ) -> Result<PeerConnection, NetworkError> {
        let mut active = self
            .shared
            .active
            .lock()
            .map_err(|_| NetworkError::LockPoisoned)?;
        if active.contains(&peer) {
            return Err(NetworkError::DuplicatePeer);
        }
        if active.len() >= self.shared.max_peers {
            return Err(NetworkError::TooManyPeers);
        }
        active.insert(peer);
        drop(active);
        Ok(PeerConnection {
            stream,
            peer,
            identity: Arc::clone(&self.identity),
            session,
            send_sequence: 0,
            receive_sequence: 0,
            shared: Arc::clone(&self.shared),
        })
    }
}

pub struct PeerConnection {
    stream: TcpStream,
    peer: PeerId,
    identity: Arc<NetworkIdentity>,
    session: [u8; 32],
    send_sequence: u64,
    receive_sequence: u64,
    shared: Arc<Shared>,
}

impl PeerConnection {
    pub const fn peer_id(&self) -> PeerId {
        self.peer
    }

    pub fn send(&mut self, message: &NetworkMessage) -> Result<(), NetworkError> {
        let (kind, bytes) = message.kind_and_bytes();
        let maximum = maximum_for_kind(kind).ok_or(NetworkError::Malformed)?;
        if bytes.len() > maximum {
            return Err(NetworkError::FrameTooLarge);
        }
        let length = u32::try_from(bytes.len()).map_err(|_| NetworkError::FrameTooLarge)?;
        let mut header = [0u8; FRAME_HEADER_BYTES];
        if let Some(slot) = header.get_mut(0) {
            *slot = kind;
        } else {
            return Err(NetworkError::Malformed);
        }
        let length_bytes = length.to_be_bytes();
        header
            .get_mut(1..)
            .ok_or(NetworkError::Malformed)?
            .copy_from_slice(&length_bytes);
        let next_sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(NetworkError::Malformed)?;
        let digest = frame_digest(
            self.session,
            self.identity.public_key(),
            *self.peer.as_bytes(),
            self.send_sequence,
            &header,
            &bytes,
        );
        let signature = self.identity.signing_key.sign(&digest);
        self.stream.write_all(&header)?;
        self.stream.write_all(&bytes)?;
        self.stream.write_all(&signature.to_bytes())?;
        self.stream.flush()?;
        self.send_sequence = next_sequence;
        Ok(())
    }

    pub fn receive(&mut self) -> Result<NetworkMessage, NetworkError> {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        self.stream.read_exact(&mut header)?;
        let kind = *header.first().ok_or(NetworkError::Malformed)?;
        let length_bytes: [u8; 4] = header
            .get(1..)
            .ok_or(NetworkError::Malformed)?
            .try_into()
            .map_err(|_| NetworkError::Malformed)?;
        let declared = usize::try_from(u32::from_be_bytes(length_bytes))
            .map_err(|_| NetworkError::FrameTooLarge)?;
        let maximum = maximum_for_kind(kind).ok_or(NetworkError::Malformed)?;
        if declared > maximum {
            return Err(NetworkError::FrameTooLarge);
        }

        self.shared
            .ingress
            .lock()
            .map_err(|_| NetworkError::LockPoisoned)?
            .reserve(self.peer, declared, Instant::now())?;

        let mut body = vec![0u8; declared];
        self.stream.read_exact(&mut body)?;
        let mut signature = [0u8; SIGNATURE_BYTES];
        self.stream.read_exact(&mut signature)?;
        let digest = frame_digest(
            self.session,
            *self.peer.as_bytes(),
            self.identity.public_key(),
            self.receive_sequence,
            &header,
            &body,
        );
        VerifyingKey::from_bytes(self.peer.as_bytes())
            .map_err(|_| NetworkError::AuthenticationFailed)?
            .verify_strict(&digest, &Signature::from_bytes(&signature))
            .map_err(|_| NetworkError::InvalidSignature)?;
        self.receive_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(NetworkError::Malformed)?;
        let message = match kind {
            CONSENSUS_FRAME => {
                let message = decode_message(&body).map_err(|_| NetworkError::Malformed)?;
                if !self.shared.verifier.verify(self.peer, &message) {
                    return Err(NetworkError::InvalidSignature);
                }
                NetworkMessage::Consensus(message)
            }
            TRANSACTION_FRAME => {
                let transaction: Transaction =
                    decode_exact(&body).map_err(|_| NetworkError::Malformed)?;
                transaction
                    .verify_signature()
                    .map_err(|_| NetworkError::InvalidSignature)?;
                NetworkMessage::Transaction(transaction)
            }
            _ => return Err(NetworkError::Malformed),
        };
        Ok(message)
    }
}

impl Drop for PeerConnection {
    fn drop(&mut self) {
        if let Ok(mut active) = self.shared.active.lock() {
            active.remove(&self.peer);
        }
    }
}

fn maximum_for_kind(kind: u8) -> Option<usize> {
    match kind {
        CONSENSUS_FRAME => Some(MAX_CONSENSUS_FRAME_BYTES),
        TRANSACTION_FRAME => Some(MAX_TRANSACTION_FRAME_BYTES),
        _ => None,
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), NetworkError> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(())
}

fn nonce() -> Result<[u8; 32], NetworkError> {
    let mut value = [0u8; 32];
    getrandom::fill(&mut value).map_err(|_| NetworkError::Randomness)?;
    Ok(value)
}

fn session_id(
    initiator_key: [u8; 32],
    initiator_nonce: [u8; 32],
    responder_key: [u8; 32],
    responder_nonce: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SESSION_DOMAIN);
    hasher.update(&initiator_key);
    hasher.update(&initiator_nonce);
    hasher.update(&responder_key);
    hasher.update(&responder_nonce);
    *hasher.finalize().as_bytes()
}

fn frame_digest(
    session: [u8; 32],
    sender: [u8; 32],
    receiver: [u8; 32],
    sequence: u64,
    header: &[u8; FRAME_HEADER_BYTES],
    body: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FRAME_DOMAIN);
    hasher.update(&session);
    hasher.update(&sender);
    hasher.update(&receiver);
    hasher.update(&sequence.to_be_bytes());
    hasher.update(header);
    hasher.update(body);
    *hasher.finalize().as_bytes()
}

fn hello(public_key: [u8; 32], challenge: [u8; 32]) -> [u8; HELLO_BYTES] {
    let mut out = [0u8; HELLO_BYTES];
    if let Some(magic) = out.get_mut(..8) {
        magic.copy_from_slice(&PROTOCOL_MAGIC);
    }
    if let Some(key) = out.get_mut(8..40) {
        key.copy_from_slice(&public_key);
    }
    if let Some(nonce) = out.get_mut(40..72) {
        nonce.copy_from_slice(&challenge);
    }
    out
}

fn parse_hello(bytes: &[u8; HELLO_BYTES]) -> Result<([u8; 32], [u8; 32]), NetworkError> {
    if bytes.get(..8) != Some(PROTOCOL_MAGIC.as_slice()) {
        return Err(NetworkError::AuthenticationFailed);
    }
    let public_key = bytes
        .get(8..40)
        .ok_or(NetworkError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| NetworkError::AuthenticationFailed)?;
    let challenge = bytes
        .get(40..72)
        .ok_or(NetworkError::AuthenticationFailed)?
        .try_into()
        .map_err(|_| NetworkError::AuthenticationFailed)?;
    Ok((public_key, challenge))
}

fn authentication_bytes(
    initiator_key: [u8; 32],
    initiator_nonce: [u8; 32],
    responder_key: [u8; 32],
    responder_nonce: [u8; 32],
    role: u8,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HANDSHAKE_DOMAIN.len().saturating_add(129));
    bytes.extend_from_slice(HANDSHAKE_DOMAIN);
    bytes.extend_from_slice(&initiator_key);
    bytes.extend_from_slice(&initiator_nonce);
    bytes.extend_from_slice(&responder_key);
    bytes.extend_from_slice(&responder_nonce);
    bytes.push(role);
    bytes
}

fn authenticate_initiator(
    stream: &mut TcpStream,
    identity: &NetworkIdentity,
    expected: &TrustedPeer,
) -> Result<[u8; 32], NetworkError> {
    let initiator_nonce = nonce()?;
    let initiator_key = identity.public_key();
    stream.write_all(&hello(initiator_key, initiator_nonce))?;
    stream.flush()?;

    let mut responder_hello = [0u8; HELLO_BYTES];
    stream.read_exact(&mut responder_hello)?;
    let (responder_key, responder_nonce) = parse_hello(&responder_hello)?;
    if responder_key != expected.public_key {
        return Err(NetworkError::AuthenticationFailed);
    }
    let mut responder_signature = [0u8; SIGNATURE_BYTES];
    stream.read_exact(&mut responder_signature)?;
    VerifyingKey::from_bytes(&responder_key)
        .map_err(|_| NetworkError::AuthenticationFailed)?
        .verify_strict(
            &authentication_bytes(
                initiator_key,
                initiator_nonce,
                responder_key,
                responder_nonce,
                1,
            ),
            &Signature::from_bytes(&responder_signature),
        )
        .map_err(|_| NetworkError::AuthenticationFailed)?;

    let signature = identity.signing_key.sign(&authentication_bytes(
        initiator_key,
        initiator_nonce,
        responder_key,
        responder_nonce,
        0,
    ));
    stream.write_all(&signature.to_bytes())?;
    stream.flush()?;
    Ok(session_id(
        initiator_key,
        initiator_nonce,
        responder_key,
        responder_nonce,
    ))
}

fn authenticate_responder(
    stream: &mut TcpStream,
    identity: &NetworkIdentity,
    trusted: &BTreeMap<PeerId, TrustedPeer>,
) -> Result<(PeerId, [u8; 32]), NetworkError> {
    let mut initiator_hello = [0u8; HELLO_BYTES];
    stream.read_exact(&mut initiator_hello)?;
    let (initiator_key, initiator_nonce) = parse_hello(&initiator_hello)?;
    let peer = PeerId::from_bytes(initiator_key);
    if !trusted.contains_key(&peer) {
        return Err(NetworkError::UnknownPeer);
    }

    let responder_key = identity.public_key();
    let responder_nonce = nonce()?;
    let signature = identity.signing_key.sign(&authentication_bytes(
        initiator_key,
        initiator_nonce,
        responder_key,
        responder_nonce,
        1,
    ));
    stream.write_all(&hello(responder_key, responder_nonce))?;
    stream.write_all(&signature.to_bytes())?;
    stream.flush()?;

    let mut initiator_signature = [0u8; SIGNATURE_BYTES];
    stream.read_exact(&mut initiator_signature)?;
    VerifyingKey::from_bytes(&initiator_key)
        .map_err(|_| NetworkError::AuthenticationFailed)?
        .verify_strict(
            &authentication_bytes(
                initiator_key,
                initiator_nonce,
                responder_key,
                responder_nonce,
                0,
            ),
            &Signature::from_bytes(&initiator_signature),
        )
        .map_err(|_| NetworkError::AuthenticationFailed)?;
    Ok((
        peer,
        session_id(
            initiator_key,
            initiator_nonce,
            responder_key,
            responder_nonce,
        ),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use chain_consensus::host::{Message, SyncRequest, SyncResponse};
    use chain_types::{
        Address, BlockHeight, ChainId, GasAmount, GasPrice, MoveCall, PublicKey, SequenceNumber,
        Signature as ChainSignature, TransactionBody,
    };

    use super::*;

    fn identity(seed: u8) -> NetworkIdentity {
        NetworkIdentity::from_secret_bytes([seed; 32])
    }

    fn trusted(identity: &NetworkIdentity, address: SocketAddr) -> TrustedPeer {
        TrustedPeer::new(address, identity.public_key()).unwrap()
    }

    fn transaction(seed: u8) -> Transaction {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let sender = PublicKey::from_ed25519_bytes(signing.verifying_key().to_bytes()).unwrap();
        let body = TransactionBody {
            chain_id: ChainId(1),
            sender,
            sequence_number: SequenceNumber(0),
            expiry: BlockHeight(10),
            gas_limit: GasAmount(10),
            max_fee_per_gas: GasPrice(1),
            declared_inputs: Vec::new(),
            call: MoveCall {
                module_address: Address::from_bytes([1; 32]),
                module_name: b"m".to_vec(),
                function_name: b"f".to_vec(),
                type_arguments: Vec::new(),
                arguments: Vec::new(),
            },
        };
        let signature = ChainSignature::from_ed25519_bytes(
            signing
                .sign(&{
                    let mut bytes = Vec::new();
                    body.encode(&mut bytes);
                    bytes
                })
                .to_bytes(),
        );
        Transaction { body, signature }
    }

    #[test]
    fn one_authenticated_connection_carries_transactions_and_catch_up() {
        let a_identity = identity(1);
        let a_peer = a_identity.peer_id();
        let b_identity = identity(2);
        let b_peer = b_identity.peer_id();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&verifier_calls);
        let b = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            b_identity,
            vec![trusted(&a_identity, "127.0.0.1:1".parse().unwrap())],
            TransportConfig::default(),
            Arc::new(move |peer, _: &Message| {
                assert_eq!(peer, a_peer);
                calls.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .unwrap();
        let b_address = b.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut connection = b.accept().unwrap();
            assert_eq!(connection.peer_id(), a_peer);
            match connection.receive().unwrap() {
                NetworkMessage::Transaction(received) => assert_eq!(received, transaction(9)),
                _ => panic!("expected transaction"),
            }
            match connection.receive().unwrap() {
                NetworkMessage::Consensus(Message::SyncRequest(request)) => {
                    assert_eq!(request.from, BlockHeight(7));
                }
                _ => panic!("expected catch-up request"),
            }
            connection
                .send(&NetworkMessage::Consensus(Message::SyncResponse(
                    SyncResponse {
                        requester: Address::from_bytes([3; 32]),
                        commits: Vec::new(),
                    },
                )))
                .unwrap();
            assert!(matches!(
                connection.receive(),
                Err(NetworkError::InvalidSignature)
            ));
        });

        let a = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            a_identity,
            vec![TrustedPeer::new(b_address, *b_peer.as_bytes()).unwrap()],
            TransportConfig::default(),
            Arc::new(|_, _: &Message| true),
        )
        .unwrap();
        let mut connection = a.connect(b_peer).unwrap();
        connection
            .send(&NetworkMessage::Transaction(transaction(9)))
            .unwrap();
        connection
            .send(&NetworkMessage::Consensus(Message::SyncRequest(
                SyncRequest {
                    requester: Address::from_bytes([3; 32]),
                    from: BlockHeight(7),
                },
            )))
            .unwrap();
        match connection.receive().unwrap() {
            NetworkMessage::Consensus(Message::SyncResponse(response)) => {
                assert_eq!(response.requester, Address::from_bytes([3; 32]));
                assert!(response.commits.is_empty());
            }
            _ => panic!("expected catch-up response"),
        }
        let mut invalid = transaction(10);
        invalid.signature = ChainSignature::from_ed25519_bytes([0; 64]);
        connection
            .send(&NetworkMessage::Transaction(invalid))
            .unwrap();
        server.join().unwrap();
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn configuration_enforces_the_compiled_peer_limit_and_unique_allowlist() {
        let local = identity(20);
        let too_many: Vec<TrustedPeer> = (0..=MAX_CONNECTED_PEERS)
            .map(|index| {
                let seed = u8::try_from(index.saturating_add(30)).unwrap();
                trusted(&identity(seed), "127.0.0.1:1".parse().unwrap())
            })
            .collect();
        assert!(matches!(
            TcpNetwork::bind(
                "127.0.0.1:0".parse().unwrap(),
                local,
                too_many,
                TransportConfig::default(),
                Arc::new(|_, _: &Message| true),
            ),
            Err(NetworkError::InvalidConfiguration)
        ));

        let local = identity(21);
        let remote = trusted(&identity(22), "127.0.0.1:1".parse().unwrap());
        assert!(matches!(
            TcpNetwork::bind(
                "127.0.0.1:0".parse().unwrap(),
                local,
                vec![remote, remote],
                TransportConfig::default(),
                Arc::new(|_, _: &Message| true),
            ),
            Err(NetworkError::InvalidConfiguration)
        ));
    }

    #[test]
    fn an_untrusted_key_cannot_complete_the_handshake() {
        let trusted_identity = identity(3);
        let server_identity = identity(4);
        let server = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_identity,
            vec![trusted(&trusted_identity, "127.0.0.1:1".parse().unwrap())],
            TransportConfig::default(),
            Arc::new(|_, _: &Message| true),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || match server.accept() {
            Ok(_) => panic!("untrusted peer was accepted"),
            Err(error) => error,
        });

        let stranger = identity(5);
        let expected_server = identity(4);
        let mut stream = TcpStream::connect(address).unwrap();
        configure_stream(&stream, Duration::from_secs(1)).unwrap();
        let result = authenticate_initiator(
            &mut stream,
            &stranger,
            &TrustedPeer::new(address, expected_server.public_key()).unwrap(),
        );
        assert!(result.is_err());
        assert!(matches!(handle.join().unwrap(), NetworkError::UnknownPeer));
    }

    #[test]
    fn an_oversized_declared_frame_is_rejected_before_body_or_verifier() {
        let a_identity = identity(6);
        let a_peer = a_identity.peer_id();
        let b_identity = identity(7);
        let b_peer = b_identity.peer_id();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&verifier_calls);
        let b = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            b_identity,
            vec![trusted(&a_identity, "127.0.0.1:1".parse().unwrap())],
            TransportConfig::default(),
            Arc::new(move |_, _: &Message| {
                calls.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .unwrap();
        let address = b.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut connection = b.accept().unwrap();
            connection.receive().unwrap_err()
        });

        let a = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            a_identity,
            vec![TrustedPeer::new(address, *b_peer.as_bytes()).unwrap()],
            TransportConfig::default(),
            Arc::new(|_, _: &Message| true),
        )
        .unwrap();
        let mut connection = a.connect(b_peer).unwrap();
        let oversized = u32::try_from(MAX_CONSENSUS_FRAME_BYTES.saturating_add(1)).unwrap();
        let mut header = [0u8; FRAME_HEADER_BYTES];
        header[0] = CONSENSUS_FRAME;
        header[1..].copy_from_slice(&oversized.to_be_bytes());
        connection.stream.write_all(&header).unwrap();
        connection.stream.flush().unwrap();

        assert!(matches!(
            server.join().unwrap(),
            NetworkError::FrameTooLarge
        ));
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 0);
        assert_eq!(connection.peer_id(), b_peer);
        assert_eq!(a_peer, PeerId::from_bytes(identity(6).public_key()));
    }

    #[test]
    fn a_tampered_frame_is_rejected_before_message_decode() {
        let a_identity = identity(8);
        let b_identity = identity(9);
        let b_peer = b_identity.peer_id();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&verifier_calls);
        let b = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            b_identity,
            vec![trusted(&a_identity, "127.0.0.1:1".parse().unwrap())],
            TransportConfig::default(),
            Arc::new(move |_, _: &Message| {
                calls.fetch_add(1, Ordering::SeqCst);
                true
            }),
        )
        .unwrap();
        let address = b.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut connection = b.accept().unwrap();
            connection.receive().unwrap_err()
        });

        let a = TcpNetwork::bind(
            "127.0.0.1:0".parse().unwrap(),
            a_identity,
            vec![TrustedPeer::new(address, *b_peer.as_bytes()).unwrap()],
            TransportConfig::default(),
            Arc::new(|_, _: &Message| true),
        )
        .unwrap();
        let mut connection = a.connect(b_peer).unwrap();
        let mut header = [0u8; FRAME_HEADER_BYTES];
        header[0] = CONSENSUS_FRAME;
        header[1..].copy_from_slice(&1u32.to_be_bytes());
        connection.stream.write_all(&header).unwrap();
        connection.stream.write_all(&[u8::MAX]).unwrap();
        connection
            .stream
            .write_all(&[0u8; SIGNATURE_BYTES])
            .unwrap();
        connection.stream.flush().unwrap();

        assert!(matches!(
            server.join().unwrap(),
            NetworkError::InvalidSignature
        ));
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 0);
    }
}
