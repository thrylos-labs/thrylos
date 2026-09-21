//! A token-bucket rate limiter, in bytes. `docs/spec.md`, "P2P and
//! mempool": "Per-peer and global inbound byte budgets, token-bucket,
//! enforced before decode."
//!
//! Refill uses integer millisecond arithmetic rather than floating-
//! point seconds — `docs/spec.md`'s "no floating point" rule is
//! written for the deterministic state transition specifically, but
//! there's no reason to reach for float math here either when integer
//! math does the same job with no precision surprises.

use std::time::Instant;

#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: u64,
    tokens: u64,
    refill_per_second: u64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u64, refill_per_second: u64, now: Instant) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_second,
            last_refill: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed_millis =
            u64::try_from(now.saturating_duration_since(self.last_refill).as_millis())
                .unwrap_or(u64::MAX);
        let refilled = elapsed_millis
            .saturating_mul(self.refill_per_second)
            .checked_div(1000)
            .unwrap_or(0);
        self.tokens = self.tokens.saturating_add(refilled).min(self.capacity);
        self.last_refill = now;
    }

    /// Refills for elapsed time, then consumes `amount` if enough
    /// tokens are available. Returns whether the consumption
    /// succeeded; on failure, no tokens are spent.
    pub fn try_consume(&mut self, amount: u64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    /// Returns tokens to the bucket after a reservation made as part of a
    /// larger atomic admission check could not be completed.
    pub fn refund(&mut self, amount: u64) {
        self.tokens = self.tokens.saturating_add(amount).min(self.capacity);
    }

    pub const fn tokens(&self) -> u64 {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn starts_full_and_allows_consumption_up_to_capacity() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100, 10, now);
        assert!(bucket.try_consume(100, now));
        assert_eq!(bucket.tokens(), 0);
    }

    #[test]
    fn rejects_consumption_beyond_available_tokens_without_spending_any() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100, 10, now);
        assert!(!bucket.try_consume(101, now));
        assert_eq!(
            bucket.tokens(),
            100,
            "a failed consume must not partially spend tokens"
        );
    }

    #[test]
    fn refills_over_time_up_to_capacity_but_no_further() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100, 10, now);
        assert!(bucket.try_consume(100, now));

        let later = now + Duration::from_secs(5);
        // 10 tokens/sec * 5s = 50 tokens refilled.
        assert!(bucket.try_consume(50, later));
        assert_eq!(bucket.tokens(), 0);

        let much_later = now + Duration::from_secs(1000);
        bucket.try_consume(0, much_later);
        assert_eq!(bucket.tokens(), 100, "refill must clamp at capacity");
    }

    #[test]
    fn a_steady_drip_within_the_refill_rate_never_exhausts_the_bucket() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100, 10, now);
        let mut t = now;
        for _ in 0..20 {
            t += Duration::from_secs(1);
            assert!(
                bucket.try_consume(10, t),
                "10/sec matches the refill rate exactly"
            );
        }
    }

    #[test]
    fn a_refund_restores_tokens_without_exceeding_capacity() {
        let now = Instant::now();
        let mut bucket = TokenBucket::new(100, 0, now);
        assert!(bucket.try_consume(40, now));
        bucket.refund(40);
        bucket.refund(1);
        assert_eq!(bucket.tokens(), 100);
    }
}
