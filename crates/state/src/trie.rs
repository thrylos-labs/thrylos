//! Deterministic Merkle root computation over a flat, sorted key-value
//! state. `docs/spec.md`, "State, storage and sync": "State is a binary
//! Merkle trie over a flat key-value store ... with the flat layout as
//! the source of truth and the trie derived. Hashing is BLAKE3
//! throughout, with a single, versioned domain-separation prefix per
//! node type."
//!
//! A sparse binary trie keyed on `BLAKE3(state key)` rather than the raw
//! key bytes: this normalises every key to a uniform 256-bit path and
//! keeps an adversarially chosen key from skewing the tree. An isolated
//! entry with no sibling sharing its prefix collapses directly to its
//! leaf hash instead of descending all 256 levels — the same compression
//! real sparse/Jellyfish Merkle tries use (this lineage traces to
//! Diem/Aptos, which this spec's Move-based design otherwise follows
//! closely). Two different keys hashing to the same path would silently
//! collide here; relying on that not happening is exactly what a
//! cryptographic hash buys, the same assumption every hash-keyed sparse
//! Merkle trie makes.
//!
//! No proof generation: light-client proofs are explicitly out of scope
//! for v1 (`docs/spec.md`, "Scope and non-goals"). This only computes
//! the root.

use chain_types::collections::BTreeMap;
use chain_types::hash::{hash_with_domain, DomainTag};
use chain_types::Hash;

use crate::key_value::{StateKey, StateValue};

/// The trie root hash of a flat key-value state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateRoot(Hash);

impl StateRoot {
    pub const fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    pub const fn as_hash(&self) -> Hash {
        self.0
    }
}

/// A domain-separated sentinel meaning "no entry here" at the leaf
/// level. A real leaf hash always includes the domain tag plus the
/// actual key and value bytes, so colliding with this fixed all-zero
/// value would require a BLAKE3 preimage — not a practical concern.
fn empty_leaf_sentinel() -> Hash {
    Hash::from_bytes([0u8; 32])
}

/// `table[h]` is the root of an empty subtree covering `h` more bits of
/// depth: `table[0]` is [`empty_leaf_sentinel`], and each subsequent
/// entry combines the previous one with itself. `table[256]` is the
/// root of a completely empty state.
fn empty_subtree_table() -> Vec<Hash> {
    let mut table = Vec::with_capacity(257);
    table.push(empty_leaf_sentinel());
    for _ in 0..256u32 {
        let previous = table.last().copied().unwrap_or_else(empty_leaf_sentinel);
        table.push(branch_hash(&previous, &previous));
    }
    table
}

/// The root of a state with no entries at all.
pub fn empty_root() -> StateRoot {
    let table = empty_subtree_table();
    StateRoot(table.last().copied().unwrap_or_else(empty_leaf_sentinel))
}

fn leaf_hash(key: &StateKey, value: &StateValue) -> Hash {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(value.as_bytes());
    hash_with_domain(DomainTag::TrieLeafV1, &bytes)
}

fn leaf_path(key: &StateKey) -> Hash {
    hash_with_domain(DomainTag::TrieKeyPathV1, key.as_bytes())
}

fn branch_hash(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    hash_with_domain(DomainTag::TrieBranchV1, &bytes)
}

const BIT_MASKS: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

/// `path`'s 256 bits, most-significant-first — the order the trie
/// navigates in.
fn path_bits(path: &Hash) -> Vec<bool> {
    let mut bits = Vec::with_capacity(256);
    for &byte in path.as_bytes() {
        for &mask in &BIT_MASKS {
            bits.push((byte & mask) != 0);
        }
    }
    bits
}

struct PathEntry {
    bits: Vec<bool>,
    leaf_hash: Hash,
}

/// The root of the subtree containing exactly `entries`, all of which
/// share the first `depth` bits of their path (by construction of the
/// caller's recursive descent). `entries` must be sorted by path.
fn subtree_root(entries: &[PathEntry], depth: usize, empty_table: &[Hash]) -> Hash {
    match entries {
        [] => {
            let height = 256usize.saturating_sub(depth);
            empty_table
                .get(height)
                .copied()
                .unwrap_or_else(empty_leaf_sentinel)
        }
        [only] => only.leaf_hash,
        _ => {
            let split =
                entries.partition_point(|entry| !entry.bits.get(depth).copied().unwrap_or(false));
            let (left, right) = entries.split_at(split);
            let left_hash = subtree_root(left, depth.saturating_add(1), empty_table);
            let right_hash = subtree_root(right, depth.saturating_add(1), empty_table);
            branch_hash(&left_hash, &right_hash)
        }
    }
}

/// Compute the state root of `state`, a flat, canonical key-value state.
/// Pure and deterministic: the same `state` always produces the same
/// root, however it was assembled.
pub fn compute_root(state: &BTreeMap<StateKey, StateValue>) -> StateRoot {
    // Group by path (BLAKE3 of the key), not by the key's own ordering.
    // This `BTreeMap` is what gives the recursion below a fixed
    // iteration order (`docs/spec.md`, "Determinism rules": "Any
    // iteration feeding the state root walks a sorted structure").
    let mut by_path: BTreeMap<Hash, Hash> = BTreeMap::new();
    for (key, value) in state {
        by_path.insert(leaf_path(key), leaf_hash(key, value));
    }

    let entries: Vec<PathEntry> = by_path
        .into_iter()
        .map(|(path, leaf)| PathEntry {
            bits: path_bits(&path),
            leaf_hash: leaf,
        })
        .collect();

    let empty_table = empty_subtree_table();
    StateRoot(subtree_root(&entries, 0, &empty_table))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use proptest::prelude::*;

    fn state_of(entries: &[(&[u8], &[u8])]) -> BTreeMap<StateKey, StateValue> {
        let mut state = BTreeMap::new();
        for (key, value) in entries {
            state.insert(StateKey::new(key.to_vec()), StateValue::new(value.to_vec()));
        }
        state
    }

    #[test]
    fn empty_state_matches_empty_root() {
        let state = state_of(&[]);
        assert_eq!(compute_root(&state), empty_root());
    }

    #[test]
    fn empty_root_is_deterministic() {
        assert_eq!(empty_root(), empty_root());
    }

    #[test]
    fn single_entry_root_equals_its_leaf_hash() {
        let state = state_of(&[(b"only-key", b"only-value")]);
        let expected = leaf_hash(
            &StateKey::new(b"only-key".to_vec()),
            &StateValue::new(b"only-value".to_vec()),
        );
        assert_eq!(compute_root(&state).as_hash(), expected);
    }

    #[test]
    fn two_entries_differ_from_either_alone() {
        let both = state_of(&[(b"a", b"1"), (b"b", b"2")]);
        let just_a = state_of(&[(b"a", b"1")]);
        let just_b = state_of(&[(b"b", b"2")]);
        assert_ne!(compute_root(&both), compute_root(&just_a));
        assert_ne!(compute_root(&both), compute_root(&just_b));
    }

    #[test]
    fn changing_a_value_changes_the_root() {
        let original = state_of(&[(b"a", b"1"), (b"b", b"2")]);
        let changed = state_of(&[(b"a", b"1"), (b"b", b"3")]);
        assert_ne!(compute_root(&original), compute_root(&changed));
    }

    #[test]
    fn changing_a_key_changes_the_root() {
        let original = state_of(&[(b"a", b"1")]);
        let changed = state_of(&[(b"c", b"1")]);
        assert_ne!(compute_root(&original), compute_root(&changed));
    }

    #[test]
    fn root_is_independent_of_insertion_order() {
        let mut forward = BTreeMap::new();
        forward.insert(StateKey::new(b"a".to_vec()), StateValue::new(b"1".to_vec()));
        forward.insert(StateKey::new(b"b".to_vec()), StateValue::new(b"2".to_vec()));
        forward.insert(StateKey::new(b"c".to_vec()), StateValue::new(b"3".to_vec()));

        let mut backward = BTreeMap::new();
        backward.insert(StateKey::new(b"c".to_vec()), StateValue::new(b"3".to_vec()));
        backward.insert(StateKey::new(b"b".to_vec()), StateValue::new(b"2".to_vec()));
        backward.insert(StateKey::new(b"a".to_vec()), StateValue::new(b"1".to_vec()));

        assert_eq!(compute_root(&forward), compute_root(&backward));
    }

    #[test]
    fn many_entries_compute_without_panicking() {
        let mut state = BTreeMap::new();
        for i in 0u32..200 {
            let bytes = i.to_le_bytes();
            state.insert(
                StateKey::new(bytes.to_vec()),
                StateValue::new(bytes.to_vec()),
            );
        }
        // Just needs to return; a panic here would fail the test.
        let _ = compute_root(&state);
    }

    proptest! {
        #[test]
        fn compute_root_is_deterministic(entries in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 0..16), proptest::collection::vec(any::<u8>(), 0..16)),
            0..20,
        )) {
            let pairs: Vec<(&[u8], &[u8])> = entries.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
            let state = state_of(&pairs);
            prop_assert_eq!(compute_root(&state), compute_root(&state));
        }

        #[test]
        fn flipping_one_value_byte_almost_always_changes_the_root(
            key in proptest::collection::vec(any::<u8>(), 1..16),
            mut value in proptest::collection::vec(any::<u8>(), 1..16),
        ) {
            let original = state_of(&[(key.as_slice(), value.as_slice())]);
            let original_root = compute_root(&original);

            if let Some(first) = value.get_mut(0) {
                *first ^= 0xFF;
            }
            let flipped = state_of(&[(key.as_slice(), value.as_slice())]);
            prop_assert_ne!(original_root, compute_root(&flipped));
        }
    }
}
