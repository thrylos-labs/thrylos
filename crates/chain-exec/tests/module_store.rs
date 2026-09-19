//! The staking registry running on the executor's real flat state, through
//! the [`StateStore`] adapter: its keys stay in their own corner of the
//! state, the state root and diff see what it does — including the
//! deletions a matured unbonding entry causes — and an aborted operation
//! leaves the state exactly as it was.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use blst::min_pk::SecretKey;
use chain_exec::keys::{base_fee_key, module_state_tag};
use chain_exec::module_store::StateStore;
use chain_modules::params::{ParamValues, DAY_MS, MIN_UNBONDING_PERIOD_MS};
use chain_modules::store::{apply_changes, Overlay, ReadStore, Store};
use chain_modules::{GovernedParams, RegistryError, StakingRegistry, ValidatorId};
use chain_state::{apply, compute_root, diff, StateChange, StateKey, StateValue};
use chain_types::bls::{BlsSignature, DST_PROOF_OF_POSSESSION};
use chain_types::collections::BTreeMap;
use chain_types::{Address, BlsPublicKey};

type State = BTreeMap<StateKey, StateValue>;

const T0: u64 = 200 * DAY_MS;

fn params() -> GovernedParams {
    GovernedParams::new(ParamValues {
        max_block_gas: 60_000_000,
        base_fee_change_denominator: 8,
        min_self_stake: 1_000,
        inflation_bps: 400,
        unbonding_period_ms: MIN_UNBONDING_PERIOD_MS,
        quorum_bps: 3_340,
        veto_threshold_bps: 3_340,
    })
    .unwrap()
}

fn id(seed: u8) -> ValidatorId {
    ValidatorId(Address::from_bytes([seed; 32]))
}

fn operator(seed: u8) -> Address {
    Address::from_bytes([seed.wrapping_add(128); 32])
}

fn staker(n: u8) -> Address {
    Address::from_bytes([n.wrapping_add(64); 32])
}

/// Registers validator `seed` (with real key and proof of possession) in
/// `registry`, whatever store it is over.
fn register<S: Store>(registry: &mut StakingRegistry<S>, seed: u8, stake: u128) {
    let sk = SecretKey::key_gen(&[seed; 32], &[]).unwrap();
    let key = BlsPublicKey::from_bytes(sk.sk_to_pk().to_bytes()).unwrap();
    let pop = BlsSignature::from_bytes(
        sk.sign(&key.to_bytes(), DST_PROOF_OF_POSSESSION, &[])
            .to_bytes(),
    )
    .unwrap();
    registry
        .register_validator(&params(), id(seed), operator(seed), key, &pop, stake)
        .unwrap();
}

/// A state that already holds things belonging to other users of the flat
/// space, including entries in the tags on either side of the modules'.
fn busy_state() -> State {
    let mut state = State::new();
    for (i, tag) in [
        module_state_tag().saturating_sub(1),
        module_state_tag().saturating_add(1),
        0,
        1,
        2,
        3,
        4,
    ]
    .into_iter()
    .enumerate()
    {
        let mut key = vec![tag];
        key.extend_from_slice(&[i as u8; 32]);
        state.insert(StateKey::new(key), StateValue::new(vec![i as u8; 8]));
    }
    state.insert(
        base_fee_key(),
        StateValue::new(vec![7, 0, 0, 0, 0, 0, 0, 0]),
    );
    state
}

fn without_module_keys(state: &State) -> State {
    state
        .iter()
        .filter(|(key, _)| key.as_bytes().first() != Some(&module_state_tag()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[test]
fn the_modules_keys_stay_inside_their_own_tag_and_disturb_nothing_else() {
    let mut state = busy_state();
    let others_before = without_module_keys(&state);

    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    register(&mut registry, 1, 5_000);
    register(&mut registry, 2, 6_000);
    registry.delegate(&id(1), staker(1), 400).unwrap();
    registry
        .begin_unstake(&params(), &id(1), staker(1), 100, T0)
        .unwrap();
    registry.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap();
    registry.assert_invariants().unwrap();

    assert_eq!(
        without_module_keys(&state),
        others_before,
        "accounts, objects and the base fee were not touched"
    );
    assert!(
        state
            .keys()
            .any(|key| key.as_bytes().first() == Some(&module_state_tag())),
        "and the registry's own entries are there"
    );
}

#[test]
fn range_reads_see_only_the_modules_entries_even_with_neighbours_on_both_sides() {
    let mut state = busy_state();
    let mut store = StateStore::new(&mut state);
    store.put(vec![5, 1], vec![1]);
    store.put(vec![5, 2], vec![2]);
    store.put(vec![6, 0], vec![3]);

    // No upper bound, and an empty prefix: everything the modules hold —
    // and none of the neighbours' entries in the tags around theirs.
    let all = store.range(&[], None, usize::MAX);
    assert_eq!(
        all,
        vec![
            (vec![5, 1], vec![1]),
            (vec![5, 2], vec![2]),
            (vec![6, 0], vec![3]),
        ]
    );
    assert_eq!(store.scan_prefix(&[5], usize::MAX).len(), 2);
    assert_eq!(store.range(&[5, 2], None, 1), vec![(vec![5, 2], vec![2])]);
    assert!(store.range(&[9], None, usize::MAX).is_empty());
    assert!(
        store.range(&[6], Some(&[5]), usize::MAX).is_empty(),
        "inverted"
    );
}

#[test]
fn what_the_registry_does_shows_up_in_the_state_root_and_the_diff_deletions_included() {
    let mut state = busy_state();
    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    register(&mut registry, 1, 5_000);
    registry.delegate(&id(1), staker(1), 400).unwrap();
    registry
        .begin_unstake(&params(), &id(1), staker(1), 100, T0)
        .unwrap();

    let before_maturing = state.clone();
    let root_before = compute_root(&state);

    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    let matured = registry.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap();
    assert_eq!(matured.len(), 1);

    assert_ne!(compute_root(&state), root_before, "the root moved");

    let changes = diff(&before_maturing, &state);
    let deletions = changes
        .iter()
        .filter(|(_, change)| **change == StateChange::Delete)
        .count();
    // The entry, its two indexes and the pair count are gone from state.
    assert_eq!(deletions, 4);

    // Replaying the diff on the state before reproduces the state after,
    // and so the same root: what `chain-db` persists is enough to rebuild.
    let mut replayed = before_maturing;
    apply(&mut replayed, &changes);
    assert_eq!(replayed, state);
    assert_eq!(compute_root(&replayed), compute_root(&state));
}

#[test]
fn an_operation_that_fails_on_the_real_state_leaves_the_root_untouched() {
    let mut state = busy_state();
    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    register(&mut registry, 1, 5_000);
    let root = compute_root(&state);

    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    assert_eq!(
        registry.delegate(&id(9), staker(1), 100),
        Err(RegistryError::UnknownValidator)
    );
    assert!(registry
        .begin_unstake(&params(), &id(1), staker(1), 5, T0)
        .is_err());

    assert_eq!(compute_root(&state), root);
}

#[test]
fn a_caller_can_hold_module_writes_back_and_discard_them_like_an_aborted_call() {
    // The shape the executor will use: an overlay over the state's store,
    // committed only if the transaction did not abort.
    let mut state = busy_state();
    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    register(&mut registry, 1, 5_000);
    let root = compute_root(&state);

    // Aborted: dropped without applying.
    {
        let base = StateStore::new(&mut state);
        let mut overlay = Overlay::new(&base);
        StakingRegistry::new(&mut overlay)
            .delegate(&id(1), staker(1), 400)
            .unwrap();
        assert!(!overlay.is_unchanged());
    }
    assert_eq!(compute_root(&state), root, "nothing reached the state");

    // Committed: the changes applied to the state.
    let changes = {
        let base = StateStore::new(&mut state);
        let mut overlay = Overlay::new(&base);
        StakingRegistry::new(&mut overlay)
            .delegate(&id(1), staker(1), 400)
            .unwrap();
        overlay.into_changes()
    };
    let mut base = StateStore::new(&mut state);
    apply_changes(&mut base, changes);
    assert_ne!(compute_root(&state), root);
    assert_eq!(
        StakingRegistry::new(StateStore::new(&mut state))
            .stake_of(&id(1), &staker(1))
            .unwrap(),
        400
    );
}

#[test]
fn the_registry_behaves_the_same_over_the_real_state_as_over_the_in_memory_store() {
    use chain_modules::store::MemStore;

    fn run<S: Store>(mut registry: StakingRegistry<S>) -> (Vec<u128>, Vec<u64>) {
        register(&mut registry, 1, 5_000);
        register(&mut registry, 2, 9_000);
        registry.delegate(&id(1), staker(1), 3_000).unwrap();
        registry.credit_rewards(&id(2), 700).unwrap();
        registry
            .begin_unstake(&params(), &id(1), staker(1), 1_000, T0)
            .unwrap();
        registry.process(T0 + MIN_UNBONDING_PERIOD_MS).unwrap();
        let set = registry.active_set(&params()).unwrap();
        (
            vec![
                registry.total_bonded().unwrap(),
                registry.total_unbonding().unwrap(),
                registry.stake_of(&id(1), &staker(1)).unwrap(),
            ],
            set.iter().map(|v| v.voting_power).collect(),
        )
    }

    let in_memory = run(StakingRegistry::new(MemStore::new()));
    let mut state = busy_state();
    let on_state = run(StakingRegistry::new(StateStore::new(&mut state)));
    assert_eq!(in_memory, on_state);
}

#[test]
fn governance_and_the_registry_share_one_state_and_a_passed_change_shows_in_the_diff() {
    use chain_modules::governance::{
        ProposalKind, ProposalStatus, VoteChoice, TIMELOCK_MS, VOTING_PERIOD_MS,
    };
    use chain_modules::{Governance, ParamChange};
    use chain_types::BlockHeight;

    let mut state = busy_state();

    // Both modules, one state.
    let mut registry = StakingRegistry::new(StateStore::new(&mut state));
    register(&mut registry, 1, 5_000);
    registry.delegate(&id(1), staker(1), 400).unwrap();
    let mut gov = Governance::new(StateStore::new(&mut state));
    gov.init_genesis(params()).unwrap();

    let proposal = gov
        .submit(
            ProposalKind::ParameterChange(ParamChange {
                inflation_bps: Some(700),
                ..ParamChange::default()
            }),
            T0,
            1_000,
        )
        .unwrap();
    gov.vote(proposal, staker(1), 900, VoteChoice::Yes, T0 + 1)
        .unwrap();
    gov.process(T0 + VOTING_PERIOD_MS, BlockHeight(1)).unwrap();

    let before_applying = state.clone();
    let root_before = compute_root(&state);
    let mut gov = Governance::new(StateStore::new(&mut state));
    let events = gov
        .process(T0 + VOTING_PERIOD_MS + TIMELOCK_MS, BlockHeight(2))
        .unwrap();
    assert_eq!(events, vec![(proposal, ProposalStatus::Applied)]);
    assert_eq!(gov.params().unwrap().values().inflation_bps, 700);
    gov.assert_invariants().unwrap();

    // Applying the change moved the root, and what the diff holds is
    // enough to rebuild the state: the new parameters, the proposal's new
    // status, and the open-index entry going away.
    assert_ne!(compute_root(&state), root_before);
    let changes = diff(&before_applying, &state);
    assert!(changes
        .iter()
        .any(|(_, change)| *change == StateChange::Delete));
    let mut replayed = before_applying;
    apply(&mut replayed, &changes);
    assert_eq!(compute_root(&replayed), compute_root(&state));

    // The registry, in the same state, was not disturbed by any of it.
    StakingRegistry::new(StateStore::new(&mut state))
        .assert_invariants()
        .unwrap();
    assert_eq!(
        StakingRegistry::new(StateStore::new(&mut state))
            .stake_of(&id(1), &staker(1))
            .unwrap(),
        400
    );
}
