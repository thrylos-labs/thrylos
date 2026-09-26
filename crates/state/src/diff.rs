//! The set of flat-state changes one block's execution produced.
//!
//! `chain_engine_api::Engine::execute_block` currently computes a fresh
//! [`crate::StateRoot`] from one bounded snapshot of the flat state (see
//! `chain-exec`'s `Executor`) rather than tracking writes incrementally.
//! This module's [`diff`] recovers the same information after the fact, so a
//! caller (namely `chain-db`) can persist and later replay just what changed.
//! Finalisation applies that verified diff and does not execute or clone the
//! state again.
//!
//! A change is either a write or a deletion. Deletion arrived with the
//! native modules: an unbonding entry that has matured, or a share
//! balance withdrawn to nothing, must leave the state, or it would grow
//! without bound and stay in the state root forever.

use crate::key_value::{StateKey, StateValue};
use chain_types::collections::BTreeMap;

/// What one block did to one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateChange {
    /// The key now holds this value (new, or changed).
    Put(StateValue),
    /// The key is now absent.
    Delete,
}

/// Every key one block wrote or removed, relative to the state it was
/// executed on top of. Unchanged keys are not included, even though
/// `chain-exec`'s current executor happens to touch its whole state as a
/// clone internally — this diff reflects logical changes, not incidental
/// copying. A key that was created and removed again within the block
/// is absent from the diff, since relative to the start nothing happened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateDiff(BTreeMap<StateKey, StateChange>);

impl StateDiff {
    pub const fn empty() -> Self {
        Self(BTreeMap::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Every change, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&StateKey, &StateChange)> {
        self.0.iter()
    }
}

/// Every difference between `old` and `new`: keys in `new` whose value
/// differs from (or is absent from) `old`, and keys in `old` that `new`
/// no longer has. Deterministic and order-independent: both inputs are
/// `BTreeMap`s, walked once each in sorted-key order.
pub fn diff(
    old: &BTreeMap<StateKey, StateValue>,
    new: &BTreeMap<StateKey, StateValue>,
) -> StateDiff {
    // One walk down both maps together, in key order: the cost is the size of
    // the state, once, with no lookups. (Values that are the same allocation are
    // recognised without reading them; see `StateValue`.)
    let mut changed = BTreeMap::new();
    let mut old_entries = old.iter().peekable();
    let mut new_entries = new.iter().peekable();
    loop {
        match (old_entries.peek(), new_entries.peek()) {
            (None, None) => break,
            (Some((key, _)), None) => {
                changed.insert((*key).clone(), StateChange::Delete);
                old_entries.next();
            }
            (None, Some((key, value))) => {
                changed.insert((*key).clone(), StateChange::Put((*value).clone()));
                new_entries.next();
            }
            (Some((old_key, old_value)), Some((new_key, new_value))) => {
                match old_key.cmp(new_key) {
                    core::cmp::Ordering::Less => {
                        changed.insert((*old_key).clone(), StateChange::Delete);
                        old_entries.next();
                    }
                    core::cmp::Ordering::Greater => {
                        changed.insert((*new_key).clone(), StateChange::Put((*new_value).clone()));
                        new_entries.next();
                    }
                    core::cmp::Ordering::Equal => {
                        if old_value != new_value {
                            changed
                                .insert((*new_key).clone(), StateChange::Put((*new_value).clone()));
                        }
                        old_entries.next();
                        new_entries.next();
                    }
                }
            }
        }
    }
    StateDiff(changed)
}

/// Replay `diff` on top of `base` in place: every put overwrites (or
/// inserts) its key, every deletion removes it. Applying
/// `diff(old, new)` to `old` yields `new`.
pub fn apply(base: &mut BTreeMap<StateKey, StateValue>, diff: &StateDiff) {
    for (key, change) in &diff.0 {
        match change {
            StateChange::Put(value) => {
                base.insert(key.clone(), value.clone());
            }
            StateChange::Delete => {
                base.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(byte: u8) -> (StateKey, StateValue) {
        (StateKey::new(vec![byte]), StateValue::new(vec![byte, byte]))
    }

    #[test]
    fn diff_is_empty_when_nothing_changed() {
        let mut state = BTreeMap::new();
        let (k, v) = kv(1);
        state.insert(k, v);

        assert!(diff(&state, &state).is_empty());
    }

    #[test]
    fn diff_captures_new_and_changed_keys_but_not_unchanged_ones() {
        let (k1, v1) = kv(1);
        let (k2, v2) = kv(2);
        let mut old = BTreeMap::new();
        old.insert(k1.clone(), v1.clone());

        let mut new = BTreeMap::new();
        new.insert(k1.clone(), v1); // unchanged
        new.insert(k2.clone(), v2.clone()); // new

        let changed = diff(&old, &new);
        assert_eq!(changed.len(), 1);
        assert_eq!(
            changed.iter().next(),
            Some((&k2, &StateChange::Put(v2.clone())))
        );
    }

    #[test]
    fn diff_captures_a_value_change_on_an_existing_key() {
        let (k, v_old) = kv(3);
        let v_new = StateValue::new(vec![9, 9, 9]);
        let mut old = BTreeMap::new();
        old.insert(k.clone(), v_old);
        let mut new = BTreeMap::new();
        new.insert(k.clone(), v_new.clone());

        let changed = diff(&old, &new);
        assert_eq!(changed.len(), 1);
        assert_eq!(
            changed.iter().next(),
            Some((&k, &StateChange::Put(v_new.clone())))
        );
    }

    #[test]
    fn apply_replays_a_diff_onto_a_base_state() {
        let (k1, v1) = kv(1);
        let mut old = BTreeMap::new();
        old.insert(k1.clone(), v1);

        let (k2, v2) = kv(2);
        let mut new = old.clone();
        new.insert(k2.clone(), v2.clone());

        let changed = diff(&old, &new);
        apply(&mut old, &changed);
        assert_eq!(old, new);
    }

    #[test]
    fn a_removed_key_is_a_deletion_in_the_diff() {
        let (k1, v1) = kv(1);
        let (k2, v2) = kv(2);
        let mut old = BTreeMap::new();
        old.insert(k1.clone(), v1);
        old.insert(k2.clone(), v2);
        let mut new = old.clone();
        new.remove(&k1);

        let changed = diff(&old, &new);
        assert_eq!(changed.len(), 1);
        assert_eq!(changed.iter().next(), Some((&k1, &StateChange::Delete)));
    }

    #[test]
    fn apply_replays_deletions_too() {
        let (k1, v1) = kv(1);
        let (k2, v2) = kv(2);
        let (k3, v3) = kv(3);
        let mut old = BTreeMap::new();
        old.insert(k1.clone(), v1);
        old.insert(k2.clone(), v2);

        // One key removed, one added, one changed.
        let mut new = BTreeMap::new();
        new.insert(k2.clone(), StateValue::new(vec![7]));
        new.insert(k3, v3);

        let changed = diff(&old, &new);
        assert_eq!(changed.len(), 3);
        apply(&mut old, &changed);
        assert_eq!(old, new);
    }

    #[test]
    fn a_key_added_and_removed_within_one_block_leaves_no_trace() {
        let (k1, v1) = kv(1);
        let (k2, v2) = kv(2);
        let mut old = BTreeMap::new();
        old.insert(k1, v1);
        let mut new = old.clone();
        new.insert(k2.clone(), v2);
        new.remove(&k2);

        assert!(diff(&old, &new).is_empty());
    }

    fn arbitrary_state() -> impl proptest::strategy::Strategy<Value = BTreeMap<StateKey, StateValue>>
    {
        use proptest::prelude::*;
        proptest::collection::btree_map(
            proptest::collection::vec(0u8..8, 1..3),
            proptest::collection::vec(any::<u8>(), 0..3),
            0..12,
        )
        .prop_map(|raw| {
            raw.into_iter()
                .map(|(key, value)| (StateKey::new(key), StateValue::new(value)))
                .collect()
        })
    }

    proptest::proptest! {
        /// Replaying `diff(old, new)` onto `old` gives `new`, for any two
        /// states — deletions, additions and changes alike.
        #[test]
        fn diff_then_apply_reproduces_the_new_state_for_arbitrary_states(
            old in arbitrary_state(),
            new in arbitrary_state(),
        ) {
            let mut replayed = old.clone();
            apply(&mut replayed, &diff(&old, &new));
            proptest::prop_assert_eq!(&replayed, &new);
            proptest::prop_assert_eq!(crate::compute_root(&replayed), crate::compute_root(&new));
        }
    }
}
