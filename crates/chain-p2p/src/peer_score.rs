//! Decaying peer reputation. `docs/spec.md`, "P2P and mempool": "Peer
//! scoring that decays, so a single bad message does not permanently
//! ban an honest peer and a slow drip of bad messages still ends in
//! disconnection."
//!
//! Decay is linear (score moves toward zero at a fixed rate per
//! second), not exponential: it's simpler to reason about and test,
//! and nothing in the spec's requirement needs the specific shape of
//! the decay curve — only that an isolated penalty fades and a
//! sustained one doesn't.

use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerScoreConfig {
    /// A peer whose score falls to or below this should be
    /// disconnected.
    pub ban_threshold: i64,
    /// How much the score moves toward zero per second of elapsed
    /// time, regardless of sign.
    pub decay_per_second: i64,
}

#[derive(Debug, Clone)]
pub struct PeerScore {
    score: i64,
    last_decay: Instant,
}

impl PeerScore {
    pub const fn new(now: Instant) -> Self {
        Self {
            score: 0,
            last_decay: now,
        }
    }

    pub const fn value(&self) -> i64 {
        self.score
    }

    fn decay(&mut self, now: Instant, config: PeerScoreConfig) {
        let elapsed_secs = now.saturating_duration_since(self.last_decay).as_secs();
        if elapsed_secs == 0 {
            return;
        }
        let elapsed_secs = i64::try_from(elapsed_secs).unwrap_or(i64::MAX);
        let decay_amount = config.decay_per_second.saturating_mul(elapsed_secs);
        self.score = match self.score.cmp(&0) {
            std::cmp::Ordering::Greater => self.score.saturating_sub(decay_amount).max(0),
            std::cmp::Ordering::Less => self.score.saturating_add(decay_amount).min(0),
            std::cmp::Ordering::Equal => 0,
        };
        self.last_decay = now;
    }

    /// Decays for elapsed time, then applies `delta` (negative for a
    /// penalty, positive for a reward).
    pub fn record(&mut self, delta: i64, now: Instant, config: PeerScoreConfig) {
        self.decay(now, config);
        self.score = self.score.saturating_add(delta);
    }

    pub fn should_disconnect(&self, config: PeerScoreConfig) -> bool {
        self.score <= config.ban_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const CONFIG: PeerScoreConfig = PeerScoreConfig {
        ban_threshold: -100,
        decay_per_second: 1,
    };

    #[test]
    fn a_single_penalty_decays_back_toward_zero_over_time() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.record(-10, now, CONFIG);
        assert_eq!(score.value(), -10);

        let later = now + Duration::from_secs(10);
        score.record(0, later, CONFIG);
        assert_eq!(
            score.value(),
            0,
            "10 seconds of decay at 1/sec clears a -10 penalty"
        );
    }

    #[test]
    fn decay_never_overshoots_past_zero() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.record(-5, now, CONFIG);

        let much_later = now + Duration::from_secs(1000);
        score.record(0, much_later, CONFIG);
        assert_eq!(score.value(), 0);
    }

    #[test]
    fn a_sustained_drip_of_penalties_faster_than_decay_still_reaches_the_ban_threshold() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        let mut t = now;
        for _ in 0..50 {
            t += Duration::from_secs(1);
            // -5 per second, decaying only 1 per second: net -4/sec.
            score.record(-5, t, CONFIG);
        }
        assert!(score.should_disconnect(CONFIG));
    }

    #[test]
    fn a_single_bad_message_does_not_cross_the_ban_threshold() {
        let now = Instant::now();
        let mut score = PeerScore::new(now);
        score.record(-10, now, CONFIG);
        assert!(!score.should_disconnect(CONFIG));
    }
}
