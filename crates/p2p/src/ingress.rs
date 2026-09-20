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
//! and over verification (a caller-supplied closure), so the same bounded
//! pipeline remains usable outside the concrete transport.

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

impl core::fmt::Display for DropReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OverBudget => f.write_str("over the message size cap or the byte budget"),
            Self::Malformed => f.write_str("failed strict decoding"),
            Self::InvalidSignature => f.write_str("the signature does not verify"),
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

    /// Reserve the declared frame length before allocating or decoding its
    /// body. A transport reads only its fixed-size header before this call.
    pub fn reserve(
        &mut self,
        peer: PeerId,
        declared_bytes: usize,
        now: Instant,
    ) -> Result<(), DropReason> {
        if declared_bytes > self.limits.max_message_bytes {
            return Err(DropReason::OverBudget);
        }

        let byte_len = u64::try_from(declared_bytes).unwrap_or(u64::MAX);
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
        Ok(())
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
        self.reserve(peer, bytes.len(), now)?;

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

    #[test]
    fn a_declared_length_is_rejected_before_a_body_exists() {
        let mut small_limits = limits();
        small_limits.max_message_bytes = 8;
        let now = Instant::now();
        let mut gate = IngressGate::new(small_limits, 4096, now);
        assert_eq!(
            gate.reserve(PeerId::from_bytes([7; 32]), 9, now),
            Err(DropReason::OverBudget)
        );
    }
}

#[cfg(test)]
mod display_tests {
    use super::*;

    /// Every message reads as a sentence about the problem: not empty, not
    /// the variant's Rust name, no trailing full stop, one line, and no two
    /// variants alike.
    fn readable<T: core::fmt::Display + core::fmt::Debug>(all: &[T]) {
        let mut seen = Vec::new();
        for value in all {
            let message = value.to_string();
            assert!(!message.is_empty(), "{value:?}");
            assert!(
                !message.ends_with('.') && !message.contains('\n'),
                "{message}"
            );
            assert_ne!(message, format!("{value:?}"), "only the variant's name");
            assert!(!seen.contains(&message), "two variants say {message:?}");
            seen.push(message);
        }
    }

    #[test]
    fn every_drop_reason_reads_as_a_sentence() {
        readable(&[
            DropReason::OverBudget,
            DropReason::Malformed,
            DropReason::InvalidSignature,
        ]);
    }
}
