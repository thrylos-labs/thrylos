//! The node's clock.
//!
//! The consensus host takes its time from a [`Clock`]: block timestamps, the
//! tolerance for a proposer's clock, the grace before asking for a missed
//! block. On a real node that is the operating system's wall clock, in
//! milliseconds since the Unix epoch, and nothing else.
//!
//! This is the one place the node reads the wall clock. `clippy.toml` bans
//! `SystemTime::now` to keep it out of the deterministic state transition; the
//! host's clock is not that: it only proposes a timestamp, which every other
//! validator then checks against its own clock and against the parent block.

#![allow(clippy::disallowed_methods)]

use std::time::{SystemTime, UNIX_EPOCH};

use chain_consensus::host::Clock;

/// Milliseconds since the Unix epoch, by the operating system's clock. A clock
/// set before the epoch reads as 0.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// The host's [`Clock`] on a real node.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_system_clock_reads_a_plausible_time_and_does_not_go_backwards() {
        let first = SystemClock.now_ms();
        // After 2023-11-14, before the year 2100.
        assert!(first > 1_700_000_000_000, "{first}");
        assert!(first < 4_102_444_800_000, "{first}");
        assert!(SystemClock.now_ms() >= first);
        assert!(now_ms() >= first);
    }
}
