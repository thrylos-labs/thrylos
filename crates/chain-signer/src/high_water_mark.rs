//! The position a signer will never sign at or below again.

use chain_types::{BlockHeight, Round};

/// A BFT round's phase, in signing order. Two signatures can legitimately
/// be requested at the same `(height, round)` — one per step — so the
/// high-water mark needs this third dimension: tracking only
/// `(height, round)` would incorrectly refuse the second and third
/// signs within a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Propose = 0,
    Prevote = 1,
    Precommit = 2,
}

/// A monotonic position: `(height, round, step)`. `docs/spec.md`,
/// "Keys, signing and slashing safety": "The signer holds a monotonic
/// high-water mark of (height, round, step), persisted and fsynced
/// before any signature is returned." Field declaration order here is
/// the comparison order the derived `Ord` uses — height first, then
/// round, then step — which must match that precedence exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HighWaterMark {
    pub height: BlockHeight,
    pub round: Round,
    pub step: Step,
}

impl HighWaterMark {
    pub const fn new(height: BlockHeight, round: Round, step: Step) -> Self {
        Self {
            height,
            round,
            step,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn height_dominates_round_and_step() {
        let lower = HighWaterMark::new(BlockHeight(1), Round(999), Step::Precommit);
        let higher = HighWaterMark::new(BlockHeight(2), Round(0), Step::Propose);
        assert!(lower < higher);
    }

    #[test]
    fn round_dominates_step_within_the_same_height() {
        let lower = HighWaterMark::new(BlockHeight(5), Round(1), Step::Precommit);
        let higher = HighWaterMark::new(BlockHeight(5), Round(2), Step::Propose);
        assert!(lower < higher);
    }

    #[test]
    fn steps_order_propose_prevote_precommit_within_the_same_round() {
        let height = BlockHeight(5);
        let round = Round(1);
        assert!(
            HighWaterMark::new(height, round, Step::Propose)
                < HighWaterMark::new(height, round, Step::Prevote)
        );
        assert!(
            HighWaterMark::new(height, round, Step::Prevote)
                < HighWaterMark::new(height, round, Step::Precommit)
        );
    }
}
