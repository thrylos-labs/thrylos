//! Gossip, peer scoring, discovery.
//!
//! Tier B. Failure if wrong: Halt via DoS.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! This first slice covers the parts of `docs/spec.md`'s "P2P and
//! mempool" section that are deterministic and testable without a
//! real network stack:
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
//! - [`peer_score::PeerScore`]: decaying reputation, so a single bad
//!   message doesn't permanently ban an honest peer but a sustained
//!   drip of them still ends in disconnection.
//! - [`peer_selection::select_outbound_peers`][]: eclipse-resistant
//!   outbound peer selection — IP-subnet/ASN diversity caps, reserved
//!   long-lived slots, always-included trusted peers.
//!
//! Deliberately not attempted here: an actual transport (this crate
//! has no libp2p or networking dependency at all — every type above
//! takes and returns plain bytes/values, ready to be driven by
//! whichever transport eventually wires into it) and discovery as a
//! real protocol (signed, rate-limited peer advertisements would just
//! be another message type flowing through [`ingress::IngressGate`],
//! but there is no discovery *protocol* — announcement format, gossip
//! topology for it — defined yet).

#![forbid(unsafe_code)]
// `clippy.toml`'s `disallowed-methods` bans `Instant::now()` workspace-
// wide by default (see its own comment on why) to keep wall-clock time
// out of the deterministic state transition. This crate is never part
// of that: rate limiting (`token_bucket`) and peer-score decay
// (`peer_score`) are inherently about real elapsed time, and neither
// feeds a state root.
#![allow(clippy::disallowed_methods)]

pub mod ingress;
pub mod peer_id;
pub mod peer_score;
pub mod peer_selection;
pub mod queue;
pub mod token_bucket;

pub use ingress::{DropReason, GossipLimits, IngressGate};
pub use peer_id::PeerId;
pub use peer_score::{PeerScore, PeerScoreConfig};
pub use peer_selection::{select_outbound_peers, Asn, CandidatePeer, SelectionConfig};
pub use queue::{BoundedQueue, DropPolicy};
pub use token_bucket::TokenBucket;
