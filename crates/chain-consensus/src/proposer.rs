//! Who proposes in a round: a stake-weighted draw from the height's seed.
//!
//! `docs/spec.md`, "Consensus": proposer selection is "VRF, stake-weighted"
//! so that "schedule is unpredictable in advance, so proposers cannot be
//! targeted for DDoS", and "a deterministic round-robin over a public
//! validator set is a targeting list, and that is the whole reason for the
//! extra complexity here."
//!
//! The randomness is the beacon (`chain_types::beacon`): the seed for a
//! height is fixed by the block before it, so nobody — including the
//! validators — can compute a height's proposers until that block is
//! decided. This module is only the draw: given a seed, a height, a round
//! and the validators' voting powers, which validator is it? A pure
//! function, the same on every node.
//!
//! The draw is a hash of the seed, height and round, read as a number and
//! reduced modulo the total voting power, then located among the validators'
//! cumulative powers — so a validator is chosen with probability
//! proportional to its power. The number has 128 bits and the total at most
//! 2^64 times the validator count, so the reduction's bias is smaller than
//! 2^-50 for any set of up to 16,000 validators, which is far below what
//! anything could measure. Each round draws afresh, so a proposer that
//! stays silent costs its round and nothing more.

use chain_types::hash::{hash_with_domain, DomainTag};
use chain_types::{BlockHeight, Hash};

/// The index, among validators with voting powers `powers` in the order
/// given, of the proposer for `round` of `height` under `seed`. `None` if
/// there is nobody to choose: no validators, or none with power.
///
/// A validator with no power is never chosen.
pub fn proposer_index(
    seed: &Hash,
    height: BlockHeight,
    round: u64,
    powers: &[u64],
) -> Option<usize> {
    let total = powers
        .iter()
        .fold(0u128, |sum, power| sum.saturating_add(u128::from(*power)));
    if total == 0 {
        return None;
    }

    let mut payload = Vec::with_capacity(48);
    payload.extend_from_slice(seed.as_bytes());
    payload.extend_from_slice(&height.0.to_le_bytes());
    payload.extend_from_slice(&round.to_le_bytes());
    let draw = hash_with_domain(DomainTag::ProposerDrawV1, &payload);
    let bytes: [u8; 16] = draw.as_bytes().get(..16)?.try_into().ok()?;
    let target = u128::from_le_bytes(bytes).checked_rem(total)?;

    let mut cumulative = 0u128;
    for (index, power) in powers.iter().enumerate() {
        cumulative = cumulative.saturating_add(u128::from(*power));
        if target < cumulative {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        clippy::integer_division,
        clippy::indexing_slicing
    )]

    use super::*;
    use proptest::prelude::*;

    fn seed(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn pick(seed_byte: u8, height: u64, round: u64, powers: &[u64]) -> Option<usize> {
        proposer_index(&seed(seed_byte), BlockHeight(height), round, powers)
    }

    #[test]
    fn the_same_inputs_always_give_the_same_proposer() {
        let powers = [40, 30, 20, 10];
        for round in 0..50 {
            assert_eq!(pick(1, 5, round, &powers), pick(1, 5, round, &powers));
        }
    }

    #[test]
    fn nobody_to_choose_is_none_and_never_a_panic() {
        assert_eq!(pick(1, 1, 0, &[]), None);
        assert_eq!(pick(1, 1, 0, &[0, 0, 0]), None);
    }

    #[test]
    fn a_validator_with_no_power_is_never_chosen() {
        let powers = [0, 10, 0, 5, 0];
        for round in 0..2_000 {
            let chosen = pick(3, 9, round, &powers).unwrap();
            assert!(chosen == 1 || chosen == 3, "chose {chosen}");
        }
    }

    #[test]
    fn a_lone_validator_is_always_chosen() {
        for round in 0..100 {
            assert_eq!(pick(2, 4, round, &[7]), Some(0));
        }
    }

    #[test]
    fn proposers_are_chosen_in_proportion_to_power() {
        let powers = [50u64, 30, 20];
        let mut counts = [0u32; 3];
        let draws = 30_000u64;
        for round in 0..draws {
            counts[pick(11, 100, round, &powers).unwrap()] += 1;
        }
        for (count, power) in counts.iter().zip(powers) {
            let observed = f64::from(*count) / draws as f64;
            let expected = power as f64 / 100.0;
            assert!(
                (observed - expected).abs() < 0.015,
                "power {power}: expected {expected}, observed {observed}"
            );
        }
    }

    #[test]
    fn weighting_is_by_power_not_by_position() {
        // The same powers in another order: each validator still gets its
        // own share, wherever it sits.
        let mut counts = [0u32; 3];
        let powers = [20u64, 50, 30];
        for round in 0..30_000 {
            counts[pick(11, 100, round, &powers).unwrap()] += 1;
        }
        assert!(counts[1] > counts[2] && counts[2] > counts[0], "{counts:?}");
    }

    #[test]
    fn the_seed_the_height_and_the_round_each_change_who_is_chosen() {
        let powers = [1u64; 16];
        let schedule = |seed_byte: u8, height: u64| -> Vec<usize> {
            (0..64)
                .map(|round| pick(seed_byte, height, round, &powers).unwrap())
                .collect()
        };
        assert_ne!(schedule(1, 5), schedule(2, 5), "seed");
        assert_ne!(schedule(1, 5), schedule(1, 6), "height");
        let one = schedule(1, 5);
        assert!(one.windows(2).any(|w| w[0] != w[1]), "round");
    }

    #[test]
    fn every_validator_with_power_is_reached_within_a_bounded_number_of_rounds() {
        // Liveness: a silent proposer costs a round, and the next round
        // draws again, so no validator with power is left out for long.
        let powers = [1u64; 8];
        let mut seen = [false; 8];
        for round in 0..400 {
            seen[pick(5, 12, round, &powers).unwrap()] = true;
        }
        assert!(seen.iter().all(|s| *s), "{seen:?}");
    }

    #[test]
    fn powers_at_the_top_of_u64_neither_overflow_nor_skew_the_choice() {
        let powers = [u64::MAX, u64::MAX, u64::MAX];
        let mut counts = [0u32; 3];
        for round in 0..3_000 {
            counts[pick(7, 1, round, &powers).unwrap()] += 1;
        }
        assert!(counts.iter().all(|c| *c > 800), "{counts:?}");
    }

    proptest! {
        #[test]
        fn the_index_is_always_in_range_and_never_a_powerless_one(
            powers in proptest::collection::vec(0u64..1_000, 1..20),
            seed_byte in any::<u8>(),
            height in 0u64..1_000,
            round in 0u64..1_000,
        ) {
            let chosen = pick(seed_byte, height, round, &powers);
            if powers.iter().all(|p| *p == 0) {
                prop_assert_eq!(chosen, None);
            } else {
                let index = chosen.unwrap();
                prop_assert!(index < powers.len());
                prop_assert!(powers[index] > 0);
            }
        }
    }
}
