//! Block timestamp rules. `docs/spec.md`, "Transaction validity": "Block
//! timestamps are validated too, because the unbonding and evidence
//! windows are measured in them: strictly greater than the parent's, no
//! more than 5 seconds ahead of the validating node's clock, and a block
//! failing either is rejected rather than clamped. Clamping produces a
//! fork; rejection does not."
//!
//! The two halves live in different places on purpose. "Strictly greater
//! than the parent's" is a function of chain state alone, so the executor
//! enforces it during `execute_block` and every node agrees on it. "No
//! more than 5 seconds ahead of the validating node's clock" depends on a
//! clock, which nothing below the engine API may read (`docs/spec.md`,
//! "Determinism rules": "No wall-clock or system time"), and on which
//! honest nodes legitimately differ by a little — so it cannot be part
//! of execution. It is a check the consensus host makes *before* voting
//! for a block, using a `now` it reads itself and passes in here, which
//! keeps this module pure and testable.
//!
//! That check is only about blocks arriving live. A block already
//! finalised by a quorum, replayed during sync, is older than the local
//! clock by construction and the host need not (and should not) apply it
//! to history.

/// How far ahead of the validating node's own clock a block's timestamp
/// may be, in milliseconds. `docs/spec.md`: 5 seconds.
pub const MAX_TIMESTAMP_AHEAD_MS: u64 = 5_000;

/// Whether `block_ms` is strictly later than `parent_ms`.
pub const fn is_after_parent(parent_ms: u64, block_ms: u64) -> bool {
    block_ms > parent_ms
}

/// Whether `block_ms` is at most [`MAX_TIMESTAMP_AHEAD_MS`] past `now_ms`,
/// the validating node's own reading of the clock. Exactly 5 seconds
/// ahead is accepted; a millisecond more is not.
pub const fn is_within_clock_tolerance(block_ms: u64, now_ms: u64) -> bool {
    block_ms <= now_ms.saturating_add(MAX_TIMESTAMP_AHEAD_MS)
}

/// The timestamp a proposer should give its block: its own clock, unless
/// that is not after the parent's, in which case the first moment that
/// is. Never earlier than validators will accept; if the proposer's clock
/// is so far behind that even this is over the validators' tolerance, the
/// block is rightly rejected and the round moves on.
pub const fn proposal_timestamp(parent_ms: u64, now_ms: u64) -> u64 {
    let earliest = parent_ms.saturating_add(1);
    if now_ms > earliest {
        now_ms
    } else {
        earliest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_must_be_strictly_after_its_parent() {
        assert!(is_after_parent(1_000, 1_001));
        assert!(!is_after_parent(1_000, 1_000), "equal is not after");
        assert!(!is_after_parent(1_000, 999));
    }

    #[test]
    fn a_block_up_to_five_seconds_ahead_of_the_clock_is_accepted_and_no_more() {
        let now = 1_700_000_000_000;
        assert!(is_within_clock_tolerance(now, now));
        assert!(
            is_within_clock_tolerance(now - 60_000, now),
            "the past is fine"
        );
        assert!(
            is_within_clock_tolerance(now + 5_000, now),
            "exactly 5s ahead"
        );
        assert!(
            !is_within_clock_tolerance(now + 5_001, now),
            "a millisecond over"
        );
    }

    #[test]
    fn the_tolerance_does_not_overflow_near_the_end_of_time() {
        assert!(is_within_clock_tolerance(u64::MAX, u64::MAX));
        assert!(is_within_clock_tolerance(u64::MAX, u64::MAX - 5_000));
        assert!(!is_within_clock_tolerance(u64::MAX, u64::MAX - 5_001));
    }

    #[test]
    fn a_proposer_uses_its_clock_when_that_is_after_the_parent() {
        assert_eq!(proposal_timestamp(1_000, 5_000), 5_000);
        assert_eq!(proposal_timestamp(1_000, 1_002), 1_002);
    }

    #[test]
    fn a_proposer_whose_clock_is_not_after_the_parent_takes_the_next_millisecond() {
        assert_eq!(proposal_timestamp(1_000, 1_001), 1_001);
        assert_eq!(proposal_timestamp(1_000, 1_000), 1_001);
        assert_eq!(proposal_timestamp(1_000, 500), 1_001);
    }

    #[test]
    fn what_a_proposer_picks_is_always_after_the_parent() {
        for (parent, now) in [(0, 0), (5, 3), (5, 5), (5, 6), (u64::MAX - 1, 0)] {
            assert!(is_after_parent(parent, proposal_timestamp(parent, now)));
        }
    }
}
