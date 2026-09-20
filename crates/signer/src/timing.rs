//! The timing inequality slashing enforceability depends on.
//! `docs/spec.md`, "Keys, signing and slashing safety": "The timing
//! inequality that must hold in code, not in documentation: unbonding
//! period > max evidence age > fork-choice horizon. If unbonding is
//! less than or equal to max evidence age, a validator can equivocate
//! and complete unbonding before the evidence is admissible, and the
//! slashing is unenforceable. Assert this at genesis, on every
//! parameter change, and in a unit test."

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingError {
    /// `unbonding_period` was not strictly greater than
    /// `max_evidence_age` — a validator could equivocate and finish
    /// unbonding before evidence of it is even admissible.
    UnbondingDoesNotExceedEvidenceAge,
    /// `max_evidence_age` was not strictly greater than
    /// `fork_choice_horizon`.
    EvidenceAgeDoesNotExceedForkChoiceHorizon,
}

impl core::fmt::Display for TimingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnbondingDoesNotExceedEvidenceAge => {
                f.write_str("the unbonding period must be longer than the maximum evidence age")
            }
            Self::EvidenceAgeDoesNotExceedForkChoiceHorizon => {
                f.write_str("the maximum evidence age must be longer than the fork-choice horizon")
            }
        }
    }
}

impl std::error::Error for TimingError {}

/// Check `unbonding_period > max_evidence_age > fork_choice_horizon`.
/// All three must be expressed in the same unit (e.g. block heights, or
/// seconds) — this function doesn't know or care which, only that the
/// ordering holds. Call this at genesis and on every proposed change to
/// any of the three parameters; a proposal that fails this check must
/// be rejected before it ever takes effect, not merely logged.
pub fn assert_slashing_window_ordering(
    unbonding_period: u64,
    max_evidence_age: u64,
    fork_choice_horizon: u64,
) -> Result<(), TimingError> {
    if unbonding_period <= max_evidence_age {
        return Err(TimingError::UnbondingDoesNotExceedEvidenceAge);
    }
    if max_evidence_age <= fork_choice_horizon {
        return Err(TimingError::EvidenceAgeDoesNotExceedForkChoiceHorizon);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_defaults_satisfy_the_ordering() {
        // `docs/spec.md`'s own consensus parameter table: unbonding 21
        // days, max evidence age 14 days. No concrete genesis value is
        // given for fork-choice horizon, so this picks one strictly
        // below 14 days just to exercise a passing case end to end.
        assert!(assert_slashing_window_ordering(21, 14, 7).is_ok());
    }

    #[test]
    fn unbonding_equal_to_evidence_age_is_rejected() {
        assert_eq!(
            assert_slashing_window_ordering(14, 14, 7),
            Err(TimingError::UnbondingDoesNotExceedEvidenceAge)
        );
    }

    #[test]
    fn unbonding_below_evidence_age_is_rejected() {
        assert_eq!(
            assert_slashing_window_ordering(10, 14, 7),
            Err(TimingError::UnbondingDoesNotExceedEvidenceAge)
        );
    }

    #[test]
    fn evidence_age_equal_to_fork_choice_horizon_is_rejected() {
        assert_eq!(
            assert_slashing_window_ordering(21, 14, 14),
            Err(TimingError::EvidenceAgeDoesNotExceedForkChoiceHorizon)
        );
    }

    #[test]
    fn evidence_age_below_fork_choice_horizon_is_rejected() {
        assert_eq!(
            assert_slashing_window_ordering(21, 5, 14),
            Err(TimingError::EvidenceAgeDoesNotExceedForkChoiceHorizon)
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
    fn every_timing_error_reads_as_a_sentence() {
        readable(&[
            TimingError::UnbondingDoesNotExceedEvidenceAge,
            TimingError::EvidenceAgeDoesNotExceedForkChoiceHorizon,
        ]);
    }
}
