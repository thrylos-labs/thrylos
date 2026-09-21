//! The validator-set adapter: a real chain's validators becoming the set
//! consensus runs on, and who proposes from it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::integer_division
)]

use blst::min_pk::SecretKey;
use chain_consensus::context::ThrylosContext;
use chain_consensus::proposer::proposer_index;
use chain_consensus::types::{ConsensusAddress, ConsensusHeight, ConsensusValidatorSet};
use chain_engine_api::ChainView;
use chain_exec::genesis_config::{GenesisConfig, GenesisValidator};
use chain_exec::Executor;
use chain_modules::params::GENESIS_PARAM_VALUES;
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::{Address, BlockHeight, BlsPublicKey, ChainId, Hash, PublicKey};
use malachite_core_types::{Context as _, Round, Validator as _, ValidatorSet as _};

const MIN: u128 = GENESIS_PARAM_VALUES.min_self_stake;

fn public(seed: u8) -> PublicKey {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    PublicKey::from_ed25519_bytes(key.verifying_key().to_bytes()).unwrap()
}

fn bls(seed: u8) -> (BlsPublicKey, BlsSignature) {
    let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    let key = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
    let proof = BlsSignature::from_bytes(
        sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .unwrap();
    (key, proof)
}

fn validator(seed: u8, stake: u128) -> GenesisValidator {
    let (consensus_key, proof_of_possession) = bls(seed);
    GenesisValidator {
        operator: public(seed),
        consensus_key,
        proof_of_possession,
        self_stake: stake,
    }
}

fn executor(stakes: &[(u8, u128)]) -> Executor {
    let config = GenesisConfig::new(
        ChainId(1),
        1_700_000_000_000,
        GENESIS_PARAM_VALUES,
        vec![],
        stakes
            .iter()
            .map(|(seed, stake)| validator(*seed, *stake))
            .collect(),
    )
    .unwrap();
    Executor::from_genesis(&config).unwrap()
}

fn seed(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

#[test]
fn the_set_carries_the_chains_validators_their_keys_and_their_powers() {
    let executor = executor(&[(1, 2 * MIN), (2, 5 * MIN), (3, MIN)]);
    let infos = ChainView::validator_set(&executor).unwrap();
    let set = ConsensusValidatorSet::from_infos(&infos, seed(7));

    assert_eq!(set.count(), 3);
    assert_eq!(set.proposer_seed(), &seed(7));
    assert_eq!(set.total_voting_power(), u64::try_from(8 * MIN).unwrap());
    let address = |s: u8| ConsensusAddress(Address::from_public_key(&public(s)));
    let second = set.get_by_address(&address(2)).unwrap();
    assert_eq!(second.public_key(), &bls(2).0);
    assert_eq!(second.voting_power(), u64::try_from(5 * MIN).unwrap());
    // Malachite's required order: largest power first.
    assert_eq!(set.get_by_index(0).unwrap().address(), &address(2));
    assert_eq!(set.get_by_index(2).unwrap().address(), &address(3));
}

#[test]
fn stake_too_large_for_a_u64_still_gives_a_working_set_with_the_right_proportions() {
    let huge = u128::from(u64::MAX);
    let executor = executor(&[(1, 4 * huge), (2, 2 * huge), (3, huge)]);
    let infos = ChainView::validator_set(&executor).unwrap();
    let set = ConsensusValidatorSet::from_infos(&infos, seed(1));

    // Consensus arithmetic on the scaled powers never overflows...
    assert!(set.total_voting_power() > 0);
    let powers = set.powers();
    assert_eq!(powers.len(), 3);
    // ...and thirds are still thirds: 4 : 2 : 1.
    assert!(powers[0] / 2 >= powers[1] - 1 && powers[0] / 2 <= powers[1] + 1);
}

#[test]
fn the_context_picks_the_proposer_the_draw_picks_from_the_sets_own_order() {
    let executor = executor(&[(1, 2 * MIN), (2, 5 * MIN), (3, MIN)]);
    let infos = ChainView::validator_set(&executor).unwrap();
    let set = ConsensusValidatorSet::from_infos(&infos, seed(9));
    let ctx = ThrylosContext::new(ChainId(1));

    for round in 0..50u32 {
        let chosen = ctx.select_proposer(&set, ConsensusHeight(BlockHeight(4)), Round::new(round));
        let index =
            proposer_index(&seed(9), BlockHeight(4), u64::from(round), &set.powers()).unwrap();
        assert_eq!(chosen.address(), set.get_by_index(index).unwrap().address());
    }
}

#[test]
fn proposers_follow_stake_on_a_real_validator_set() {
    let executor = executor(&[(1, 2 * MIN), (2, 5 * MIN), (3, MIN)]);
    let infos = ChainView::validator_set(&executor).unwrap();
    let set = ConsensusValidatorSet::from_infos(&infos, seed(3));
    let ctx = ThrylosContext::new(ChainId(1));

    let mut counts = std::collections::BTreeMap::new();
    let draws = 16_000u32;
    for round in 0..draws {
        let chosen = ctx.select_proposer(&set, ConsensusHeight(BlockHeight(1)), Round::new(round));
        *counts.entry(*chosen.address()).or_insert(0u32) += 1;
    }
    let share = |s: u8| {
        let address = ConsensusAddress(Address::from_public_key(&public(s)));
        f64::from(counts[&address]) / f64::from(draws)
    };
    assert!((share(2) - 5.0 / 8.0).abs() < 0.02, "{}", share(2));
    assert!((share(1) - 2.0 / 8.0).abs() < 0.02, "{}", share(1));
    assert!((share(3) - 1.0 / 8.0).abs() < 0.02, "{}", share(3));
}

#[test]
fn a_different_seed_is_a_different_schedule_and_the_same_seed_the_same_one() {
    let executor = executor(&[(1, MIN), (2, MIN), (3, MIN), (4, MIN)]);
    let infos = ChainView::validator_set(&executor).unwrap();
    let ctx = ThrylosContext::new(ChainId(1));
    let schedule = |seed_byte: u8| -> Vec<ConsensusAddress> {
        let set = ConsensusValidatorSet::from_infos(&infos, seed(seed_byte));
        (0..40u32)
            .map(|round| {
                *ctx.select_proposer(&set, ConsensusHeight(BlockHeight(9)), Round::new(round))
                    .address()
            })
            .collect()
    };
    assert_eq!(schedule(1), schedule(1));
    assert_ne!(schedule(1), schedule(2));
}

#[test]
fn nodes_with_the_same_chain_and_seed_agree_on_every_proposer() {
    // Two independently built executors (two nodes) and the same seed:
    // identical sets, identical schedule.
    let a = executor(&[(1, 2 * MIN), (2, 5 * MIN), (3, MIN)]);
    let b = executor(&[(1, 2 * MIN), (2, 5 * MIN), (3, MIN)]);
    let set_a = ConsensusValidatorSet::from_infos(&ChainView::validator_set(&a).unwrap(), seed(5));
    let set_b = ConsensusValidatorSet::from_infos(&ChainView::validator_set(&b).unwrap(), seed(5));
    assert_eq!(set_a, set_b);
    let ctx = ThrylosContext::new(ChainId(1));
    for round in 0..100u32 {
        assert_eq!(
            ctx.select_proposer(&set_a, ConsensusHeight(BlockHeight(2)), Round::new(round))
                .address(),
            ctx.select_proposer(&set_b, ConsensusHeight(BlockHeight(2)), Round::new(round))
                .address()
        );
    }
}
