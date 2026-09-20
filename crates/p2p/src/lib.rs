//! Authenticated peer transport and bounded ingress.
//!
//! Tier B. Failure if wrong: Halt via DoS.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! The launch transport is deliberately one small protocol: mutually
//! authenticated TCP connections to a static allowlist. The same framed
//! connection carries consensus messages (including block catch-up) and
//! signed transaction submissions. There is no discovery protocol and no
//! second transport.
//!
//! - [`ingress::IngressGate`]: the fixed validation pipeline (size and
//!   rate checks, then strict decode, then signature verification —
//!   in that order, so nothing is ever forwarded before it's
//!   verified), generic over message type and verifier so this crate
//!   carries no opinion on what's actually being gossiped.
//! - [`token_bucket::TokenBucket`]: the per-peer and global byte
//!   budgets that pipeline enforces before decode.
//! - [`queue::BoundedQueue`]: a fixed-capacity queue with an explicit
//!   drop policy, for whatever sits on the "forward + enqueue" side of
//!   that pipeline.
//! - [`transport::TcpNetwork`]: mutual authentication, a static trusted-peer
//!   set and a hard connection cap.
//!
//! [`transport`] checks a frame's kind and declared length against hard
//! per-type caps, then reserves per-peer and global byte budget before it
//! allocates the body. It then verifies the session-bound frame signature,
//! strictly decodes the message, and runs message-level verification. Only a
//! verified value is returned to the node runtime.

#![forbid(unsafe_code)]
// `clippy.toml`'s `disallowed-methods` bans `Instant::now()` workspace-
// wide by default (see its own comment on why) to keep wall-clock time
// out of the deterministic state transition. This crate is never part
// of that: transport timeouts and rate limiting (`token_bucket`) inherently
// use real elapsed time, and neither feeds a state root.
#![allow(clippy::disallowed_methods)]

pub mod ingress;
pub mod peer_id;
pub mod queue;
pub mod token_bucket;
pub mod transport;

pub use ingress::{DropReason, GossipLimits, IngressGate};
pub use peer_id::PeerId;
pub use queue::{BoundedQueue, DropPolicy};
pub use token_bucket::TokenBucket;
pub use transport::{
    ConsensusVerifier, NetworkError, NetworkIdentity, NetworkMessage, PeerConnection, TcpNetwork,
    TransportConfig, TrustedPeer, MAX_CONNECTED_PEERS,
};
