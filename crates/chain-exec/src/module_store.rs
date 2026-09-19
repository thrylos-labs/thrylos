//! The native modules' [`Store`] over the executor's flat state.
//!
//! `chain-modules` keeps its state as byte-keyed entries — one per
//! validator, per share balance, per unbonding entry — behind a small
//! ordered-store trait, and knows nothing of `StateKey`s or of the tags
//! the other users of the flat state have claimed. This adapter is where
//! the two meet: every module key gets [`crate::keys::module_state_tag`]
//! put in front of it, so the modules' whole keyspace is one contiguous
//! range of the state, and a range read over it can never see — or
//! disturb — an account, a Move object, or the base fee.
//!
//! Writes go straight into the map they were given. A caller that must
//! be able to discard them (an aborted transaction) puts an
//! [`chain_modules::store::Overlay`] over this and applies its changes
//! only on success, exactly as the executor already holds back a Move
//! call's [`crate::executor`] effects.

use core::ops::Bound;

use chain_modules::store::{prefix_end, Store};
use chain_state::{StateKey, StateValue};
use chain_types::collections::BTreeMap;

use crate::keys::module_state_tag;

/// The flat state, seen as the modules' store.
pub struct StateStore<'a> {
    state: &'a mut BTreeMap<StateKey, StateValue>,
}

impl<'a> StateStore<'a> {
    pub fn new(state: &'a mut BTreeMap<StateKey, StateValue>) -> Self {
        Self { state }
    }
}

/// `module_key` under the modules' tag.
fn state_key(module_key: &[u8]) -> StateKey {
    let mut bytes = Vec::with_capacity(module_key.len().saturating_add(1));
    bytes.push(module_state_tag());
    bytes.extend_from_slice(module_key);
    StateKey::new(bytes)
}

impl Store for StateStore<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state
            .get(&state_key(key))
            .map(|value| value.as_bytes().to_vec())
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state.insert(state_key(&key), StateValue::new(value));
    }

    fn delete(&mut self, key: &[u8]) {
        self.state.remove(&state_key(key));
    }

    fn range(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let lower = state_key(start);
        // No upper bound in the module's keyspace still stops at the end
        // of the modules' tag, not the end of the whole state.
        let upper = match end {
            Some(end) => Some(state_key(end)),
            None => prefix_end(&[module_state_tag()]).map(StateKey::new),
        };
        if upper.as_ref().is_some_and(|upper| lower >= *upper) {
            return Vec::new();
        }
        let upper_bound = upper.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        self.state
            .range((Bound::Included(&lower), upper_bound))
            .take(limit)
            .filter_map(|(key, value)| {
                // Strip the tag; everything in range has it.
                let module_key = key.as_bytes().get(1..)?.to_vec();
                Some((module_key, value.as_bytes().to_vec()))
            })
            .collect()
    }
}
