//! The state root, kept up to date instead of rebuilt.
//!
//! [`crate::compute_root`] hashes every entry of the state every time it is
//! called. That is the definition of the root, and it is right, but a block
//! changes a handful of entries and there can be a hundred thousand, so
//! doing it for every block costs a third of a second at the state cap
//! (`docs/gas-calibration.md`, "what a block costs as the state grows").
//!
//! [`TrieIndex`] holds enough of the trie to change the root by touching only
//! what a block changed, and it **produces exactly the same root**:
//! commitment version 2, unchanged, so nothing about the chain changes and
//! no reset is needed. The tests hold it to that against `compute_root` on
//! random states and random sequences of changes.
//!
//! How it is laid out. Entries are grouped into 65,536 buckets by the first
//! sixteen bits of their path (the hash of their key). Each bucket holds its
//! entries' leaf hashes, sorted by path, and its subtree root is worked out
//! by the same function `compute_root` uses, from depth 16. Above the
//! buckets sits a complete binary tree of sixteen levels whose nodes each
//! hold a hash and a count of the entries beneath them; a node with no
//! entries is the fixed empty hash for its height, with exactly one it is
//! that entry's leaf hash (the trie's compression of an isolated entry), and
//! with more it is the hash of its two children. A change to one entry
//! redoes one bucket and the sixteen nodes above it.

use chain_types::collections::{BTreeMap, BTreeSet};
use chain_types::Hash;

use crate::diff::{StateChange, StateDiff};
use crate::key_value::{StateKey, StateValue};
use crate::trie::{
    branch_hash, commit_root, empty_subtree_table, leaf_hash, leaf_path, path_bits, subtree_root,
    PathEntry, StateRoot,
};

/// Levels of the fixed tree above the buckets.
const LEVELS: usize = 16;
/// The buckets, and the leaves of that tree.
const BUCKETS: usize = 1 << LEVELS;

#[derive(Clone, Copy)]
struct Node {
    /// Entries beneath this node.
    count: usize,
    hash: Hash,
}

/// The state root of a flat state, maintained across changes. See the module
/// documentation.
#[derive(Clone)]
pub struct TrieIndex {
    /// Each bucket: path to leaf hash, sorted by path.
    buckets: Vec<BTreeMap<Hash, Hash>>,
    /// The tree above the buckets in heap order: node `1` is the root, node
    /// `n` has children `2n` and `2n + 1`, and bucket `b` is node
    /// `BUCKETS + b`. Slot `0` is unused.
    nodes: Vec<Node>,
    /// `empty[h]`: the root of an empty subtree of height `h`.
    empty: Vec<Hash>,
    root: StateRoot,
}

/// What a set of changes would do to a [`TrieIndex`], worked out without
/// touching it. Give it to [`TrieIndex::commit`] to make it so, or drop it.
pub struct TrieUpdate {
    buckets: BTreeMap<usize, BTreeMap<Hash, Hash>>,
    nodes: BTreeMap<usize, Node>,
    root: StateRoot,
}

impl TrieUpdate {
    /// The state root after the changes.
    pub const fn root(&self) -> StateRoot {
        self.root
    }
}

/// The first sixteen bits of `path`, as a bucket number.
fn bucket_of(path: &Hash) -> usize {
    let bytes = path.as_bytes();
    let high = usize::from(bytes.first().copied().unwrap_or(0));
    let low = usize::from(bytes.get(1).copied().unwrap_or(0));
    (high << 8) | low
}

/// The subtree root of one bucket (depth `LEVELS`).
fn bucket_node(bucket: &BTreeMap<Hash, Hash>, empty: &[Hash]) -> Node {
    let entries: Vec<PathEntry> = bucket
        .iter()
        .map(|(path, leaf)| PathEntry {
            bits: path_bits(path),
            leaf_hash: *leaf,
        })
        .collect();
    Node {
        count: entries.len(),
        hash: subtree_root(&entries, LEVELS, empty),
    }
}

/// The empty hash for a node at `depth` (`0` is the root).
fn empty_at(empty: &[Hash], depth: usize) -> Hash {
    empty
        .get(256usize.saturating_sub(depth))
        .copied()
        .unwrap_or_else(|| Hash::from_bytes([0u8; 32]))
}

/// The node above two children, at `depth`.
fn parent(left: Node, right: Node, depth: usize, empty: &[Hash]) -> Node {
    let count = left.count.saturating_add(right.count);
    let hash = match count {
        0 => empty_at(empty, depth),
        1 => {
            if left.count == 1 {
                left.hash
            } else {
                right.hash
            }
        }
        _ => branch_hash(&left.hash, &right.hash),
    };
    Node { count, hash }
}

/// Redo every node above the changed leaves, bottom to top, writing what
/// changed into `overlay`. A node not in `overlay` is read from `base`.
fn propagate(
    base: &[Node],
    empty: &[Hash],
    overlay: &mut BTreeMap<usize, Node>,
    mut dirty: BTreeSet<usize>,
) {
    let read = |overlay: &BTreeMap<usize, Node>, index: usize, depth: usize| -> Node {
        overlay
            .get(&index)
            .copied()
            .or_else(|| base.get(index).copied())
            .unwrap_or(Node {
                count: 0,
                hash: empty_at(empty, depth),
            })
    };
    for depth in (1..=LEVELS).rev() {
        let parents: BTreeSet<usize> = dirty.iter().map(|index| index >> 1).collect();
        let child_depth = depth;
        let parent_depth = depth.saturating_sub(1);
        for &index in &parents {
            let left_index = index << 1;
            let right_index = left_index | 1;
            let left = read(overlay, left_index, child_depth);
            let right = read(overlay, right_index, child_depth);
            overlay.insert(index, parent(left, right, parent_depth, empty));
        }
        dirty = parents;
    }
}

impl TrieIndex {
    /// The index of `state`, built from scratch (once, at start-up or after
    /// the state was replaced wholesale).
    pub fn from_state(state: &BTreeMap<StateKey, StateValue>) -> Self {
        let empty = empty_subtree_table();
        let mut nodes = vec![
            Node {
                count: 0,
                hash: empty_at(&empty, 0),
            };
            BUCKETS.saturating_mul(2)
        ];
        for depth in 0..=LEVELS {
            let hash = empty_at(&empty, depth);
            for index in (1usize << depth)..(1usize << depth.saturating_add(1)) {
                if let Some(node) = nodes.get_mut(index) {
                    *node = Node { count: 0, hash };
                }
            }
        }
        let mut buckets: Vec<BTreeMap<Hash, Hash>> = vec![BTreeMap::new(); BUCKETS];
        let mut touched = BTreeSet::new();
        for (key, value) in state {
            let path = leaf_path(key);
            let bucket = bucket_of(&path);
            if let Some(entries) = buckets.get_mut(bucket) {
                entries.insert(path, leaf_hash(key, value));
                touched.insert(bucket);
            }
        }
        let mut overlay = BTreeMap::new();
        let mut dirty = BTreeSet::new();
        for &bucket in &touched {
            if let Some(entries) = buckets.get(bucket) {
                let index = BUCKETS.saturating_add(bucket);
                overlay.insert(index, bucket_node(entries, &empty));
                dirty.insert(index);
            }
        }
        propagate(&nodes, &empty, &mut overlay, dirty);
        for (index, node) in overlay {
            if let Some(slot) = nodes.get_mut(index) {
                *slot = node;
            }
        }
        let root = nodes
            .get(1)
            .map_or_else(|| empty_at(&empty, 0), |node| node.hash);
        Self {
            buckets,
            nodes,
            empty,
            root: commit_root(root),
        }
    }

    /// The state root now.
    pub const fn root(&self) -> StateRoot {
        self.root
    }

    /// What `diff` would do, without doing it. Cost is the entries in `diff`,
    /// not the entries in the state.
    pub fn prepare(&self, diff: &StateDiff) -> TrieUpdate {
        let mut buckets: BTreeMap<usize, BTreeMap<Hash, Hash>> = BTreeMap::new();
        for (key, change) in diff.iter() {
            let path = leaf_path(key);
            let bucket = bucket_of(&path);
            let entries = buckets
                .entry(bucket)
                .or_insert_with(|| self.buckets.get(bucket).cloned().unwrap_or_default());
            match change {
                StateChange::Put(value) => {
                    entries.insert(path, leaf_hash(key, value));
                }
                StateChange::Delete => {
                    entries.remove(&path);
                }
            }
        }
        let mut overlay = BTreeMap::new();
        let mut dirty = BTreeSet::new();
        for (&bucket, entries) in &buckets {
            let index = BUCKETS.saturating_add(bucket);
            overlay.insert(index, bucket_node(entries, &self.empty));
            dirty.insert(index);
        }
        propagate(&self.nodes, &self.empty, &mut overlay, dirty);
        let root = overlay
            .get(&1)
            .copied()
            .or_else(|| self.nodes.get(1).copied())
            .map_or_else(|| empty_at(&self.empty, 0), |node| node.hash);
        TrieUpdate {
            buckets,
            nodes: overlay,
            root: commit_root(root),
        }
    }

    /// Make an update the index's own. It must have been prepared from this
    /// index as it now stands.
    pub fn commit(&mut self, update: TrieUpdate) {
        for (bucket, entries) in update.buckets {
            if let Some(slot) = self.buckets.get_mut(bucket) {
                *slot = entries;
            }
        }
        for (index, node) in update.nodes {
            if let Some(slot) = self.nodes.get_mut(index) {
                *slot = node;
            }
        }
        self.root = update.root;
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use crate::diff::{apply, diff};
    use crate::trie::{compute_root, empty_root};
    use proptest::prelude::*;

    fn key(n: u32) -> StateKey {
        StateKey::new(n.to_le_bytes().to_vec())
    }

    fn value(n: u32, len: usize) -> StateValue {
        StateValue::new(vec![u8::try_from(n % 251).unwrap(); len])
    }

    #[test]
    fn an_empty_state_has_the_empty_root() {
        let index = TrieIndex::from_state(&BTreeMap::new());
        assert_eq!(index.root(), empty_root());
    }

    #[test]
    fn the_index_of_a_state_has_the_root_compute_root_gives() {
        for size in [1u32, 2, 3, 10, 500, 3_000] {
            let state: BTreeMap<_, _> = (0..size).map(|n| (key(n), value(n, 5))).collect();
            assert_eq!(
                TrieIndex::from_state(&state).root(),
                compute_root(&state),
                "{size} entries"
            );
        }
    }

    #[test]
    fn an_update_is_worked_out_without_changing_the_index() {
        let old: BTreeMap<_, _> = (0..100u32).map(|n| (key(n), value(n, 4))).collect();
        let mut new = old.clone();
        new.insert(key(7), value(999, 4));
        let index = TrieIndex::from_state(&old);
        let update = index.prepare(&diff(&old, &new));
        assert_eq!(update.root(), compute_root(&new));
        assert_eq!(index.root(), compute_root(&old), "still the old state");
    }

    #[test]
    fn deleting_the_last_entry_returns_the_empty_root_and_a_lone_entry_collapses() {
        let mut old = BTreeMap::new();
        old.insert(key(1), value(1, 3));
        let mut index = TrieIndex::from_state(&old);
        let gone = BTreeMap::new();
        let update = index.prepare(&diff(&old, &gone));
        assert_eq!(update.root(), empty_root());
        index.commit(update);
        assert_eq!(index.root(), empty_root());
        let update = index.prepare(&diff(&gone, &old));
        assert_eq!(update.root(), compute_root(&old));
    }

    /// Keys whose paths share their first sixteen bits, so they land in one
    /// bucket and the bucket's own subtree has to be built and rebuilt.
    fn keys_in_one_bucket(wanted: usize) -> Vec<StateKey> {
        let mut seen: BTreeMap<usize, Vec<StateKey>> = BTreeMap::new();
        let mut n = 0u32;
        loop {
            let k = key(n);
            let group = seen.entry(bucket_of(&leaf_path(&k))).or_default();
            group.push(k);
            if group.len() == wanted {
                return group.clone();
            }
            n += 1;
        }
    }

    #[test]
    fn entries_that_share_a_bucket_are_built_and_changed_correctly() {
        let keys = keys_in_one_bucket(4);
        let mut state = BTreeMap::new();
        let mut index = TrieIndex::from_state(&state);
        // Add them one at a time, then overwrite, then remove them one at a time.
        let mut steps: Vec<(usize, Option<u32>)> = (0..4).map(|i| (i, Some(1))).collect();
        steps.push((2, Some(9)));
        steps.extend((0..4).rev().map(|i| (i, None)));
        for (i, change) in steps {
            let mut next = state.clone();
            match change {
                Some(v) => next.insert(keys[i].clone(), value(v, 3)),
                None => next.remove(&keys[i]),
            };
            let changes = diff(&state, &next);
            let update = index.prepare(&changes);
            assert_eq!(update.root(), compute_root(&next), "step on key {i}");
            index.commit(update);
            state = next;
            assert_eq!(index.root(), compute_root(&state));
        }
        assert_eq!(index.root(), empty_root());
        // And built from scratch with all four together.
        let all: BTreeMap<_, _> = keys.iter().map(|k| (k.clone(), value(5, 2))).collect();
        assert_eq!(TrieIndex::from_state(&all).root(), compute_root(&all));
    }

    #[test]
    fn a_no_change_update_keeps_the_root() {
        let state: BTreeMap<_, _> = (0..50u32).map(|n| (key(n), value(n, 2))).collect();
        let index = TrieIndex::from_state(&state);
        assert_eq!(index.prepare(&StateDiff::empty()).root(), index.root());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Whatever a run of blocks does to the state (writes, overwrites,
        /// deletions, keys that come back), the maintained root is the root
        /// `compute_root` gives the resulting state, after every block.
        #[test]
        fn a_run_of_changes_keeps_the_root_equal_to_a_rebuild(
            initial in proptest::collection::vec((0u32..400, 0usize..6), 0..80),
            blocks in proptest::collection::vec(
                proptest::collection::vec((0u32..400, proptest::option::of(0usize..6)), 0..30),
                1..8,
            ),
        ) {
            let mut state: BTreeMap<StateKey, StateValue> =
                initial.iter().map(|&(n, len)| (key(n), value(n, len))).collect();
            let mut index = TrieIndex::from_state(&state);
            prop_assert_eq!(index.root(), compute_root(&state));
            for block in blocks {
                let mut next = state.clone();
                for (n, change) in block {
                    match change {
                        Some(len) => { next.insert(key(n), value(n.wrapping_add(1), len)); }
                        None => { next.remove(&key(n)); }
                    }
                }
                let changes = diff(&state, &next);
                let update = index.prepare(&changes);
                prop_assert_eq!(update.root(), compute_root(&next));
                index.commit(update);
                apply(&mut state, &changes);
                prop_assert_eq!(index.root(), compute_root(&state));
            }
        }
    }
}
