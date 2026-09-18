//! The inbound gossip validation pipeline. `docs/spec.md`, "P2P and
//! mempool": "Gossip validation order is fixed and non-negotiable:
//! cheap structural checks, then signature verification, then
//! forwarding. Never forward before verifying."
//!
//! ```text
//! Message in -> Size + rate check -> Strict decode -> Signature verify -> Forward + enqueue
//! ```
//!
//! Generic over the message type (via `chain_types::codec::Decode`)
//! and over verification (a caller-supplied closure): this crate
//! carries no opinion on which concrete message — a consensus vote, a
//! mempool transaction, a future discovery announcement — is being
//! gossiped, or which key signed it. That coupling belongs to whoever
//! wires a concrete transport to this pipeline, not to the pipeline
//! itself.

use std::collections::BTreeMap;
use std::time::Instant;

use chain_types::codec::{decode_exact, Decode};

use crate::peer_id::PeerId;
use crate::token_bucket::TokenBucket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Over the message size cap, or the sender's or the global
    /// inbound byte budget — checked before any decode is attempted.
    OverBudget,
    /// Failed strict decoding.
    Malformed,
    /// Decoded, but its signature does not verify.
    InvalidSignature,
}

impl DropReason {
    /// A reasonable default peer-score penalty for this drop reason,
    /// for callers that don't need a different policy: exceeding a
    /// budget is cheap to do by accident (a burst of legitimate
    /// traffic), a malformed message is more clearly not, and an
    /// invalid signature is the least ambiguous sign of a bad peer.
    pub const fn default_penalty(&self) -> i64 {
        match self {
            Self::OverBudget => -1,
            Self::Malformed => -10,
            Self::InvalidSignature => -50,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipLimits {
    pub max_message_bytes: usize,
    pub per_peer_bucket_capacity: u64,
    pub per_peer_refill_per_second: u64,
}

/// Owns the global and per-peer byte budgets an [`IngressGate`] checks
/// against. Kept separate from `IngressGate` only so a caller can size
/// the global bucket once, independent of a per-peer default.
pub struct IngressGate {
    limits: GossipLimits,
    global_bucket: TokenBucket,
    peer_buckets: BTreeMap<PeerId, TokenBucket>,
}

impl IngressGate {
    pub fn new(limits: GossipLimits, global_bucket_capacity: u64, now: Instant) -> Self {
        Self {
            global_bucket: TokenBucket::new(global_bucket_capacity, global_bucket_capacity, now),
            limits,
            peer_buckets: BTreeMap::new(),
        }
    }

    /// Runs `bytes` from `peer` through the full pipeline: size and
    /// rate checks first (so an over-budget or oversized message is
    /// never decoded at all), then strict decode, then `verify`.
    /// `verify` only runs on something that already decoded cleanly.
    pub fn admit<T: Decode>(
        &mut self,
        peer: PeerId,
        bytes: &[u8],
        verify: impl FnOnce(&T) -> bool,
        now: Instant,
    ) -> Result<T, DropReason> {
        if bytes.len() > self.limits.max_message_bytes {
            return Err(DropReason::OverBudget);
        }

        let byte_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if !self.global_bucket.try_consume(byte_len, now) {
            return Err(DropReason::OverBudget);
        }

        let limits = self.limits;
        let peer_bucket = self.peer_buckets.entry(peer).or_insert_with(|| {
            TokenBucket::new(
                limits.per_peer_bucket_capacity,
                limits.per_peer_refill_per_second,
                now,
            )
        });
        if !peer_bucket.try_consume(byte_len, now) {
            return Err(DropReason::OverBudget);
        }

        let value: T = decode_exact(bytes).map_err(|_| DropReason::Malformed)?;
        if !verify(&value) {
            return Err(DropReason::InvalidSignature);
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_types::codec::{CodecError, Encode};

    #[derive(Debug, PartialEq, Eq)]
    struct Msg(u32);

    impl Encode for Msg {
        fn encode(&self, out: &mut Vec<u8>) {
            self.0.encode(out);
        }
    }

    impl Decode for Msg {
        fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
            let (value, used) = u32::decode(input)?;
            Ok((Self(value), used))
        }
    }

    fn limits() -> GossipLimits {
        GossipLimits {
            max_message_bytes: 1024,
            per_peer_bucket_capacity: 1024,
            per_peer_refill_per_second: 1024,
        }
    }

    fn encoded(msg: &Msg) -> Vec<u8> {
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        buf
    }

    #[test]
    fn admits_a_well_formed_signed_message() {
        let now = Instant::now();
        let mut gate = IngressGate::new(limits(), 4096, now);
        let peer = PeerId::from_bytes([1u8; 32]);
        let bytes = encoded(&Msg(42));

        let result: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| true, now);
        assert_eq!(result, Ok(Msg(42)));
    }

    #[test]
    fn rejects_a_message_over_the_size_cap_without_decoding_it() {
        let mut small_limits = limits();
        small_limits.max_message_bytes = 2;
        let now = Instant::now();
        let mut gate = IngressGate::new(small_limits, 4096, now);
        let peer = PeerId::from_bytes([2u8; 32]);
        let bytes = encoded(&Msg(42));

        let result: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| true, now);
        assert_eq!(result, Err(DropReason::OverBudget));
    }

    #[test]
    fn rejects_malformed_bytes_before_verification_would_even_run() {
        let now = Instant::now();
        let mut gate = IngressGate::new(limits(), 4096, now);
        let peer = PeerId::from_bytes([3u8; 32]);
        let truncated = vec![0u8; 1]; // a u32 needs 4 bytes

        let verify_was_called = std::cell::Cell::new(false);
        let result: Result<Msg, DropReason> = gate.admit(
            peer,
            &truncated,
            |_| {
                verify_was_called.set(true);
                true
            },
            now,
        );
        assert_eq!(result, Err(DropReason::Malformed));
        assert!(
            !verify_was_called.get(),
            "must not verify a malformed message"
        );
    }

    #[test]
    fn rejects_a_message_that_fails_verification() {
        let now = Instant::now();
        let mut gate = IngressGate::new(limits(), 4096, now);
        let peer = PeerId::from_bytes([4u8; 32]);
        let bytes = encoded(&Msg(42));

        let result: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| false, now);
        assert_eq!(result, Err(DropReason::InvalidSignature));
    }

    #[test]
    fn a_peer_exceeding_its_own_budget_is_dropped_even_under_the_global_cap() {
        let mut tight_limits = limits();
        tight_limits.per_peer_bucket_capacity = 4;
        tight_limits.per_peer_refill_per_second = 0;
        let now = Instant::now();
        let mut gate = IngressGate::new(tight_limits, 4096, now);
        let peer = PeerId::from_bytes([5u8; 32]);
        let bytes = encoded(&Msg(1));

        let first: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| true, now);
        assert!(first.is_ok());
        let second: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| true, now);
        assert_eq!(second, Err(DropReason::OverBudget));
    }

    #[test]
    fn one_peer_exhausting_the_global_budget_does_not_touch_its_own_per_peer_bucket() {
        let now = Instant::now();
        let mut gate = IngressGate::new(limits(), 4, now); // global cap: 4 bytes total
        let peer = PeerId::from_bytes([6u8; 32]);
        let bytes = encoded(&Msg(1)); // 4 bytes

        assert!(gate.admit::<Msg>(peer, &bytes, |_| true, now).is_ok());
        let second: Result<Msg, DropReason> = gate.admit(peer, &bytes, |_| true, now);
        assert_eq!(second, Err(DropReason::OverBudget));
    }
}
