//! The set of flat-state writes one block's execution produced.
//!
//! `chain_engine_api::Engine::execute_block` currently computes a fresh
//! [`crate::StateRoot`] from a full clone of the flat state (see
//! `chain-exec`'s `Executor`) rather than tracking writes incrementally
//! — this module's [`diff`] recovers the same information after the
//! fact, by comparing the state before and after, so a caller (namely
//! `chain-db`) can persist and later replay just what changed, without
//! `chain-exec` itself needing to change how it executes.
//!
//! Deletion is not represented: nothing in this codebase removes a
//! state key today (`chain-exec`'s `Executor` only ever calls
//! `BTreeMap::insert`), so a diff that could express "this key is now
//! absent" would be untested, dead surface. Add that variant when
//! something actually produces a deletion.

use crate::key_value::{StateKey, StateValue};
use chain_types::collections::BTreeMap;

/// Every `(key, value)` written by one block, relative to the state it
/// was executed on top of: keys that are new, or whose value changed.
/// Unchanged keys are not included, even though `chain-exec`'s current
/// executor happens to touch its whole state as a clone internally —
/// this diff reflects logical writes, not incidental copying.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateDiff(BTreeMap<StateKey, StateValue>);

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

    pub fn iter(&self) -> impl Iterator<Item = (&StateKey, &StateValue)> {
        self.0.iter()
    }
}

/// Every key in `new` whose value differs from (or is absent from)
/// `old`. Deterministic and order-independent: both inputs are
/// `BTreeMap`s, walked once each in sorted-key order.
pub fn diff(
    old: &BTreeMap<StateKey, StateValue>,
    new: &BTreeMap<StateKey, StateValue>,
) -> StateDiff {
    let mut changed = BTreeMap::new();
    for (key, new_value) in new {
        if old.get(key) != Some(new_value) {
            changed.insert(key.clone(), new_value.clone());
        }
    }
    StateDiff(changed)
}

/// Replay `diff` on top of `base` in place: every entry in `diff`
/// overwrites (or inserts) the same key in `base`. The inverse
/// operation this module doesn't need yet — nothing removes a key
/// (see this module's doc comment), so there's nothing to un-apply.
pub fn apply(base: &mut BTreeMap<StateKey, StateValue>, diff: &StateDiff) {
    for (key, value) in &diff.0 {
        base.insert(key.clone(), value.clone());
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
        assert_eq!(changed.iter().next(), Some((&k2, &v2)));
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
        assert_eq!(changed.iter().next(), Some((&k, &v_new)));
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
}
