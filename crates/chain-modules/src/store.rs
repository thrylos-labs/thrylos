//! Where the native modules keep their state: an ordered key-value store,
//! as a trait. `docs/spec.md`, "State, storage and sync": state is a flat
//! key-value store with a Merkle trie derived from it, so the modules'
//! state lives *in* that store, one entry per entity — a validator, a
//! staker's share balance, an unbonding entry — rather than in in-memory
//! maps that would have to be serialised whole.
//!
//! The trait knows nothing of chain state's own key type or of the
//! executor: it is byte keys, byte values, and ordered range reads, which
//! is all the modules need. `chain-exec` adapts the real flat state to it
//! under a tag byte of its own; [`MemStore`] serves tests.
//!
//! # Ordered reads
//!
//! The one thing beyond get/put/delete is [`Store::range`], because two
//! things need order: the unbonding queue (everything due by a given time,
//! oldest first) and the slashing correlation window (everything within a
//! span of times). Keys that must sort by a number encode it big-endian
//! (see [`be64`]), so byte order is numeric order.
//!
//! # Rolling back
//!
//! A module operation that fails partway must leave nothing behind, and an
//! aborted transaction must not either. [`Overlay`] gives both: it buffers
//! every write over a base store, reads see the buffer first, and only
//! [`Overlay::into_changes`] followed by [`apply_changes`] reaches the
//! base. Dropping an overlay discards everything — the same "held back,
//! applied only on success" shape the executor already uses for a call's
//! effects, so an abort is rollback by construction rather than by undo.
//!
//! # Corruption
//!
//! Nothing here can fail to read: a store is trusted to return what was
//! written. What can be wrong is a *value* — bytes that no longer decode
//! as the record they should be — which [`load`] reports as [`Corrupt`]
//! for the calling module to surface rather than guess at. No path
//! panics or treats a bad record as absent.

use core::ops::Bound;

use chain_types::codec::{decode_exact, decode_field, CodecError, Decode, Encode};
use chain_types::collections::BTreeMap;

/// An ordered byte-keyed store. Every method is deterministic and
/// order-independent of anything but the store's contents.
pub trait Store {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>);

    /// Removes `key`. Removing a key that is not there is not an error.
    fn delete(&mut self, key: &[u8]);

    /// The entries with `start <= key < end` (no upper bound if `end` is
    /// `None`), in ascending key order, at most `limit` of them.
    fn range(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// The entries whose key starts with `prefix`, ascending, at most
    /// `limit`.
    fn scan_prefix(&self, prefix: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let end = prefix_end(prefix);
        self.range(prefix, end.as_deref(), limit)
    }
}

/// Lets a module borrow a store for one call — `StakingRegistry::new(&mut
/// overlay)` — without taking ownership of it.
impl<S: Store + ?Sized> Store for &mut S {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        (**self).get(key)
    }
    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        (**self).put(key, value);
    }
    fn delete(&mut self, key: &[u8]) {
        (**self).delete(key);
    }
    fn range(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        (**self).range(start, end, limit)
    }
}

/// The smallest key greater than every key that starts with `prefix`:
/// `prefix` with its last byte incremented, dropping trailing `0xFF`s
/// first. `None` if there is no such key (`prefix` empty or all `0xFF`),
/// meaning the range runs to the end of the keyspace.
pub fn prefix_end(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if let Some(next) = last.checked_add(1) {
            end.push(next);
            return Some(end);
        }
    }
    None
}

/// `value` as 8 big-endian bytes, so keys built from it sort numerically.
pub const fn be64(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// The inverse of [`be64`], from the front of `bytes`.
pub fn read_be64(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.get(..8)?.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// A stored value that failed to decode as the record its key promises:
/// corruption, or a schema this code doesn't understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrupt;

/// The record at `key`, if any. A present-but-undecodable record is
/// [`Corrupt`], never silently absent.
pub fn load<T: Decode>(store: &(impl Store + ?Sized), key: &[u8]) -> Result<Option<T>, Corrupt> {
    match store.get(key) {
        None => Ok(None),
        Some(bytes) => decode_exact(&bytes).map(Some).map_err(|_| Corrupt),
    }
}

/// Stores `value`'s canonical encoding at `key`.
pub fn save<T: Encode>(store: &mut (impl Store + ?Sized), key: Vec<u8>, value: &T) {
    let mut bytes = Vec::new();
    value.encode(&mut bytes);
    store.put(key, bytes);
}

/// A key-value entry, decoded: for range reads over records.
pub fn decode_entries<T: Decode>(
    entries: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<(Vec<u8>, T)>, Corrupt> {
    entries
        .into_iter()
        .map(|(key, bytes)| Ok((key, decode_exact(&bytes).map_err(|_| Corrupt)?)))
        .collect()
}

/// Runs `op` against an overlay of `store` and applies what it wrote only
/// if it returns `Ok`: the whole operation happens or none of it does.
/// Every mutating module method is built on this.
pub fn atomically<S: Store, T, E>(
    store: &mut S,
    op: impl FnOnce(&mut Overlay<'_, S>) -> Result<T, E>,
) -> Result<T, E> {
    let mut overlay = Overlay::new(&*store);
    let result = op(&mut overlay);
    if result.is_ok() {
        let changes = overlay.into_changes();
        apply_changes(store, changes);
    }
    result
}

/// `value` as a presence byte (`0` absent, `1` present) and, if present,
/// the value. Strict: [`decode_option`] accepts nothing else.
pub fn encode_option<T: Encode>(value: &Option<T>, out: &mut Vec<u8>) {
    match value {
        None => 0u8.encode(out),
        Some(inner) => {
            1u8.encode(out);
            inner.encode(out);
        }
    }
}

/// The inverse of [`encode_option`], read at `offset` of `input`;
/// returns the value and the offset after it.
pub fn decode_option<T: Decode>(
    input: &[u8],
    offset: usize,
) -> Result<(Option<T>, usize), CodecError> {
    let (present, offset) = decode_field::<u8>(input, offset)?;
    match present {
        0 => Ok((None, offset)),
        1 => {
            let (value, offset) = decode_field::<T>(input, offset)?;
            Ok((Some(value), offset))
        }
        _ => Err(CodecError::InvalidValue),
    }
}

/// Every key prefix the native modules use, in one place so no two
/// collide. Each is the first byte of the keys it names; the layout
/// after it is that module's own, documented where it is built.
pub mod tag {
    pub const VALIDATOR: u8 = 1;
    pub const SHARES: u8 = 2;
    pub const CONSENSUS_KEY: u8 = 3;
    pub const UNBONDING: u8 = 4;
    pub const UNBONDING_BY_MATURITY: u8 = 5;
    pub const UNBONDING_BY_VALIDATOR: u8 = 6;
    pub const UNBONDING_PAIR_COUNT: u8 = 7;
    pub const REGISTRY_META: u8 = 8;
    pub const SLASH_STATUS: u8 = 9;
    pub const SLASH_RECORD: u8 = 10;
    pub const SLASH_BY_TIME: u8 = 11;
    pub const GOV_PARAMS: u8 = 12;
    pub const GOV_META: u8 = 13;
    pub const GOV_PROPOSAL: u8 = 14;
    pub const GOV_VOTE: u8 = 15;
    pub const GOV_OPEN: u8 = 16;
    pub const GOV_FORK: u8 = 17;

    /// Every tag above, for the uniqueness test.
    pub const ALL: [u8; 17] = [
        VALIDATOR,
        SHARES,
        CONSENSUS_KEY,
        UNBONDING,
        UNBONDING_BY_MATURITY,
        UNBONDING_BY_VALIDATOR,
        UNBONDING_PAIR_COUNT,
        REGISTRY_META,
        SLASH_STATUS,
        SLASH_RECORD,
        SLASH_BY_TIME,
        GOV_PARAMS,
        GOV_META,
        GOV_PROPOSAL,
        GOV_VOTE,
        GOV_OPEN,
        GOV_FORK,
    ];
}

/// An in-memory [`Store`]: what tests run the modules against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemStore {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.entries.iter()
    }
}

impl Store for MemStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.entries.get(key).cloned()
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.entries.insert(key, value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.entries.remove(key);
    }

    fn range(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        // `BTreeMap::range` panics on an inverted range; an empty one is
        // the honest answer.
        if end.is_some_and(|end| start >= end) {
            return Vec::new();
        }
        let upper = match end {
            Some(end) => Bound::Excluded(end),
            None => Bound::Unbounded,
        };
        self.entries
            .range::<[u8], _>((Bound::Included(start), upper))
            .take(limit)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

/// Buffers writes over a base store. See the module docs.
pub struct Overlay<'a, B: Store + ?Sized> {
    base: &'a B,
    /// `Some` is a write, `None` a deletion of whatever the base holds.
    changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a, B: Store + ?Sized> Overlay<'a, B> {
    pub fn new(base: &'a B) -> Self {
        Self {
            base,
            changes: BTreeMap::new(),
        }
    }

    /// Everything written or deleted, in key order, ending the overlay
    /// (and its borrow of the base, so the changes can be applied to it).
    /// A key both written and deleted is reported once, as its final
    /// state.
    pub fn into_changes(self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.changes.into_iter().collect()
    }

    pub fn is_unchanged(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Applies `changes` — as [`Overlay::into_changes`] returns them — to
/// `store`.
pub fn apply_changes(store: &mut (impl Store + ?Sized), changes: Vec<(Vec<u8>, Option<Vec<u8>>)>) {
    for (key, value) in changes {
        match value {
            Some(value) => store.put(key, value),
            None => store.delete(&key),
        }
    }
}

impl<B: Store + ?Sized> Store for Overlay<'_, B> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self.changes.get(key) {
            Some(change) => change.clone(),
            None => self.base.get(key),
        }
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.changes.insert(key, Some(value));
    }

    fn delete(&mut self, key: &[u8]) {
        self.changes.insert(key.to_vec(), None);
    }

    fn range(&self, start: &[u8], end: Option<&[u8]>, limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        if end.is_some_and(|end| start >= end) {
            return Vec::new();
        }
        let upper = match end {
            Some(end) => Bound::Excluded(end),
            None => Bound::Unbounded,
        };
        let buffered: Vec<(&Vec<u8>, &Option<Vec<u8>>)> = self
            .changes
            .range::<[u8], _>((Bound::Included(start), upper))
            .collect();

        // Each buffered entry can hide at most one base entry (a
        // deletion, or an overwrite), so reading this many extra from the
        // base guarantees `limit` live entries survive the merge.
        let from_base = limit.saturating_add(buffered.len());
        let base = self.base.range(start, end, from_base);

        let mut base_iter = base.into_iter().peekable();
        let mut buffered_iter = buffered.into_iter().peekable();
        let mut merged = Vec::new();
        while merged.len() < limit {
            let take_buffered = match (base_iter.peek(), buffered_iter.peek()) {
                (None, None) => break,
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some((base_key, _)), Some((buffered_key, _))) => {
                    // On a tie the buffered entry wins; the base one is
                    // dropped below.
                    buffered_key.as_slice() <= base_key.as_slice()
                }
            };
            if take_buffered {
                let Some((key, change)) = buffered_iter.next() else {
                    break;
                };
                if base_iter
                    .peek()
                    .is_some_and(|(base_key, _)| base_key == key)
                {
                    base_iter.next();
                }
                if let Some(value) = change {
                    merged.push((key.clone(), value.clone()));
                }
            } else if let Some(entry) = base_iter.next() {
                merged.push(entry);
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use proptest::prelude::*;

    fn k(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn filled(entries: &[(&[u8], &[u8])]) -> MemStore {
        let mut store = MemStore::new();
        for (key, value) in entries {
            store.put(k(key), k(value));
        }
        store
    }

    // ---- helpers -------------------------------------------------------

    #[test]
    fn prefix_end_increments_the_last_byte_and_skips_saturated_ones() {
        assert_eq!(prefix_end(&[1, 2]), Some(vec![1, 3]));
        assert_eq!(prefix_end(&[1, 0xFF]), Some(vec![2]));
        assert_eq!(prefix_end(&[1, 0xFF, 0xFF]), Some(vec![2]));
        assert_eq!(prefix_end(&[0xFF, 0xFF]), None);
        assert_eq!(prefix_end(&[]), None);
    }

    #[test]
    fn big_endian_keys_sort_numerically() {
        let values = [0u64, 1, 255, 256, 65_535, 65_536, u64::MAX - 1, u64::MAX];
        for pair in values.windows(2) {
            assert!(be64(pair[0]) < be64(pair[1]), "{pair:?}");
        }
        for value in values {
            assert_eq!(read_be64(&be64(value)), Some(value));
        }
        assert_eq!(read_be64(&[1, 2, 3]), None, "too short");
    }

    #[test]
    fn every_tag_is_distinct() {
        let mut seen = std::collections::BTreeSet::new();
        for tag in tag::ALL {
            assert!(seen.insert(tag), "tag {tag} used twice");
        }
    }

    // ---- MemStore ------------------------------------------------------

    #[test]
    fn put_get_delete() {
        let mut store = MemStore::new();
        assert_eq!(store.get(b"a"), None);
        store.put(k(b"a"), k(b"1"));
        assert_eq!(store.get(b"a"), Some(k(b"1")));
        store.put(k(b"a"), k(b"2"));
        assert_eq!(store.get(b"a"), Some(k(b"2")), "overwritten");
        store.delete(b"a");
        assert_eq!(store.get(b"a"), None);
        store.delete(b"a"); // not an error
        assert!(store.is_empty());
    }

    #[test]
    fn range_is_ascending_half_open_and_limited() {
        let store = filled(&[(b"a", b"1"), (b"b", b"2"), (b"c", b"3"), (b"d", b"4")]);
        let keys = |entries: Vec<(Vec<u8>, Vec<u8>)>| -> Vec<Vec<u8>> {
            entries.into_iter().map(|(key, _)| key).collect()
        };
        assert_eq!(
            keys(store.range(b"b", Some(b"d"), 10)),
            vec![k(b"b"), k(b"c")],
            "the end is exclusive, the start inclusive"
        );
        assert_eq!(
            keys(store.range(b"b", None, 10)),
            vec![k(b"b"), k(b"c"), k(b"d")]
        );
        assert_eq!(keys(store.range(b"a", None, 2)), vec![k(b"a"), k(b"b")]);
        assert_eq!(keys(store.range(b"a", None, 0)), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn an_empty_or_inverted_range_is_empty_not_a_panic() {
        let store = filled(&[(b"a", b"1"), (b"b", b"2")]);
        assert!(store.range(b"b", Some(b"a"), 10).is_empty());
        assert!(store.range(b"a", Some(b"a"), 10).is_empty());
    }

    #[test]
    fn scan_prefix_returns_only_that_prefix() {
        let store = filled(&[
            (&[1, 0], b"x"),
            (&[1, 1], b"y"),
            (&[2, 0], b"z"),
            (&[0xFF, 0xFF], b"w"),
        ]);
        assert_eq!(store.scan_prefix(&[1], 10).len(), 2);
        assert_eq!(store.scan_prefix(&[2], 10).len(), 1);
        assert_eq!(
            store.scan_prefix(&[0xFF, 0xFF], 10).len(),
            1,
            "top of the keyspace"
        );
        assert_eq!(store.scan_prefix(&[3], 10).len(), 0);
        assert_eq!(store.scan_prefix(&[1], 1).len(), 1, "limited");
    }

    // ---- load / save ---------------------------------------------------

    #[test]
    fn save_then_load_round_trips_and_a_missing_key_is_none() {
        let mut store = MemStore::new();
        save(&mut store, k(b"n"), &12345u64);
        assert_eq!(load::<u64>(&store, b"n"), Ok(Some(12345)));
        assert_eq!(load::<u64>(&store, b"absent"), Ok(None));
    }

    #[test]
    fn a_value_that_does_not_decode_is_corrupt_not_absent() {
        let mut store = MemStore::new();
        store.put(k(b"n"), vec![1, 2, 3]); // not 8 bytes
        assert_eq!(load::<u64>(&store, b"n"), Err(Corrupt));
        // Trailing bytes are as bad as too few.
        store.put(k(b"m"), vec![0; 9]);
        assert_eq!(load::<u64>(&store, b"m"), Err(Corrupt));
    }

    // ---- Overlay -------------------------------------------------------

    #[test]
    fn an_overlay_reads_through_and_writes_do_not_reach_the_base() {
        let base = filled(&[(b"a", b"1"), (b"b", b"2")]);
        let mut overlay = Overlay::new(&base);
        assert_eq!(overlay.get(b"a"), Some(k(b"1")), "reads fall through");

        overlay.put(k(b"a"), k(b"changed"));
        overlay.put(k(b"c"), k(b"new"));
        overlay.delete(b"b");
        assert_eq!(overlay.get(b"a"), Some(k(b"changed")));
        assert_eq!(overlay.get(b"b"), None, "a deletion hides the base's value");
        assert_eq!(overlay.get(b"c"), Some(k(b"new")));

        drop(overlay);
        assert_eq!(
            base,
            filled(&[(b"a", b"1"), (b"b", b"2")]),
            "dropping is rollback"
        );
    }

    #[test]
    fn applying_an_overlays_changes_commits_them() {
        let mut base = filled(&[(b"a", b"1"), (b"b", b"2")]);
        let mut overlay = Overlay::new(&base);
        overlay.put(k(b"a"), k(b"changed"));
        overlay.put(k(b"c"), k(b"new"));
        overlay.delete(b"b");
        let changes = overlay.into_changes();

        apply_changes(&mut base, changes);
        assert_eq!(base, filled(&[(b"a", b"changed"), (b"c", b"new")]));
    }

    #[test]
    fn a_key_written_then_deleted_in_an_overlay_is_reported_as_deleted() {
        let base = filled(&[(b"a", b"1")]);
        let mut overlay = Overlay::new(&base);
        overlay.put(k(b"a"), k(b"2"));
        overlay.delete(b"a");
        overlay.put(k(b"z"), k(b"9"));
        overlay.delete(b"z");
        assert_eq!(
            overlay.into_changes(),
            vec![(k(b"a"), None), (k(b"z"), None)]
        );
    }

    #[test]
    fn overlays_nest() {
        let base = filled(&[(b"a", b"1")]);
        let mut outer = Overlay::new(&base);
        outer.put(k(b"b"), k(b"2"));
        {
            let mut inner = Overlay::new(&outer);
            inner.put(k(b"c"), k(b"3"));
            inner.delete(b"a");
            assert_eq!(inner.get(b"b"), Some(k(b"2")));
            assert_eq!(inner.get(b"a"), None);
            // Dropped: the outer overlay never sees any of it.
        }
        assert_eq!(outer.get(b"c"), None);
        assert_eq!(outer.get(b"a"), Some(k(b"1")));
    }

    #[test]
    fn an_overlay_range_merges_buffered_entries_and_hides_deleted_ones() {
        let base = filled(&[(b"a", b"1"), (b"c", b"3"), (b"e", b"5"), (b"g", b"7")]);
        let mut overlay = Overlay::new(&base);
        overlay.put(k(b"b"), k(b"new")); // inserted between
        overlay.put(k(b"c"), k(b"over")); // overwrites
        overlay.delete(b"e"); // hides
        overlay.put(k(b"h"), k(b"tail")); // past the base's end

        let all = overlay.range(b"a", None, 100);
        assert_eq!(
            all,
            vec![
                (k(b"a"), k(b"1")),
                (k(b"b"), k(b"new")),
                (k(b"c"), k(b"over")),
                (k(b"g"), k(b"7")),
                (k(b"h"), k(b"tail")),
            ]
        );
    }

    #[test]
    fn a_limited_overlay_range_still_returns_limit_live_entries_past_deletions() {
        // The first three base entries are all deleted in the overlay; a
        // limit of 2 must still return two entries, not run dry.
        let base = filled(&[
            (b"a", b"1"),
            (b"b", b"2"),
            (b"c", b"3"),
            (b"d", b"4"),
            (b"e", b"5"),
        ]);
        let mut overlay = Overlay::new(&base);
        overlay.delete(b"a");
        overlay.delete(b"b");
        overlay.delete(b"c");
        assert_eq!(
            overlay.range(b"a", None, 2),
            vec![(k(b"d"), k(b"4")), (k(b"e"), k(b"5"))]
        );
    }

    #[test]
    fn an_overlay_range_respects_its_bounds() {
        let base = filled(&[(b"a", b"1"), (b"c", b"3")]);
        let mut overlay = Overlay::new(&base);
        overlay.put(k(b"b"), k(b"2"));
        overlay.put(k(b"d"), k(b"4"));
        assert_eq!(
            overlay.range(b"b", Some(b"d"), 10),
            vec![(k(b"b"), k(b"2")), (k(b"c"), k(b"3"))]
        );
        assert!(overlay.range(b"d", Some(b"b"), 10).is_empty());
    }

    #[derive(Debug, Clone)]
    enum Op {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
    }

    fn small_key() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(0u8..4, 0..3)
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (small_key(), proptest::collection::vec(any::<u8>(), 0..3))
                .prop_map(|(key, value)| Op::Put(key, value)),
            small_key().prop_map(Op::Delete),
        ]
    }

    fn run(store: &mut impl Store, ops: &[Op]) {
        for op in ops {
            match op {
                Op::Put(key, value) => store.put(key.clone(), value.clone()),
                Op::Delete(key) => store.delete(key),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// An overlay over a base is indistinguishable, to every read,
        /// from applying the same writes to a copy of the base directly —
        /// and applying its changes to the base yields that same copy.
        #[test]
        fn an_overlay_behaves_exactly_like_writing_to_a_copy(
            base_ops in proptest::collection::vec(op(), 0..12),
            overlay_ops in proptest::collection::vec(op(), 0..12),
            start in small_key(),
            end in proptest::option::of(small_key()),
            limit in 0usize..8,
            probe in small_key(),
        ) {
            let mut base = MemStore::new();
            run(&mut base, &base_ops);

            let mut direct = base.clone();
            run(&mut direct, &overlay_ops);

            let mut overlay = Overlay::new(&base);
            run(&mut overlay, &overlay_ops);

            prop_assert_eq!(overlay.get(&probe), direct.get(&probe));
            prop_assert_eq!(
                overlay.range(&start, end.as_deref(), limit),
                direct.range(&start, end.as_deref(), limit)
            );
            prop_assert_eq!(
                overlay.range(&start, end.as_deref(), usize::MAX),
                direct.range(&start, end.as_deref(), usize::MAX)
            );

            let changes = overlay.into_changes();
            let mut committed = base.clone();
            apply_changes(&mut committed, changes);
            prop_assert_eq!(committed, direct);
        }
    }
}
