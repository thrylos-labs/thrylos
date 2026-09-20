//! Read-back and atomicity of `Db::commit_block` against a real MDBX
//! environment on disk (a `tempfile::tempdir`, not an in-memory stub).

#![allow(clippy::unwrap_used)]

use chain_db::Db;
use chain_engine_api::Block;
use chain_state::{StateDiff, StateKey, StateValue};
use chain_types::{BlockHeight, Hash};

fn block_at(height: u64) -> Block {
    Block {
        parent_block_hash: Hash::from_bytes([0u8; 32]),
        height: BlockHeight(height),
        timestamp_millis: 1_700_000_000_000,
        transactions: Vec::new(),
    }
}

fn diff_with(entries: &[(u8, u8)]) -> StateDiff {
    let mut map = chain_types::collections::BTreeMap::new();
    for (key_byte, value_byte) in entries {
        map.insert(
            StateKey::new(vec![*key_byte]),
            StateValue::new(vec![*value_byte]),
        );
    }
    // `StateDiff` has no public constructor from a map (only `diff()`
    // computes one) — recover one by diffing against an empty base,
    // which is exactly "everything here is new".
    chain_state::diff(&chain_types::collections::BTreeMap::new(), &map)
}

#[test]
fn commit_and_read_back_a_block_root_and_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();

    assert_eq!(db.tip_height().unwrap(), None);
    assert_eq!(db.get_block(BlockHeight(1)).unwrap(), None);

    let block = block_at(1);
    let root = Hash::from_bytes([7u8; 32]);
    let diff = diff_with(&[(1, 10), (2, 20)]);
    db.commit_block(&block, root, &diff).unwrap();

    assert_eq!(db.tip_height().unwrap(), Some(BlockHeight(1)));
    assert_eq!(db.get_block(BlockHeight(1)).unwrap(), Some(block));
    assert_eq!(db.get_root(BlockHeight(1)).unwrap(), Some(root));
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![1])).unwrap(),
        Some(StateValue::new(vec![10]))
    );
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![2])).unwrap(),
        Some(StateValue::new(vec![20]))
    );
    assert_eq!(db.get_state_value(&StateKey::new(vec![99])).unwrap(), None);
}

#[test]
fn a_second_block_s_diff_only_overwrites_the_keys_it_touches() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();

    db.commit_block(
        &block_at(1),
        Hash::from_bytes([1u8; 32]),
        &diff_with(&[(1, 10), (2, 20)]),
    )
    .unwrap();
    db.commit_block(
        &block_at(2),
        Hash::from_bytes([2u8; 32]),
        &diff_with(&[(2, 99)]),
    )
    .unwrap();

    assert_eq!(db.tip_height().unwrap(), Some(BlockHeight(2)));
    // Untouched by block 2's diff — still block 1's value.
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![1])).unwrap(),
        Some(StateValue::new(vec![10]))
    );
    // Overwritten by block 2's diff.
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![2])).unwrap(),
        Some(StateValue::new(vec![99]))
    );
    // Both blocks and both roots stay independently readable.
    assert_eq!(db.get_block(BlockHeight(1)).unwrap(), Some(block_at(1)));
    assert_eq!(db.get_block(BlockHeight(2)).unwrap(), Some(block_at(2)));
    assert_eq!(
        db.get_root(BlockHeight(1)).unwrap(),
        Some(Hash::from_bytes([1u8; 32]))
    );
    assert_eq!(
        db.get_root(BlockHeight(2)).unwrap(),
        Some(Hash::from_bytes([2u8; 32]))
    );
}

#[test]
fn reopening_the_same_path_sees_everything_already_committed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let db = Db::open(dir.path()).unwrap();
        db.commit_block(
            &block_at(1),
            Hash::from_bytes([3u8; 32]),
            &diff_with(&[(5, 50)]),
        )
        .unwrap();
    }

    let reopened = Db::open(dir.path()).unwrap();
    assert_eq!(reopened.tip_height().unwrap(), Some(BlockHeight(1)));
    assert_eq!(
        reopened.get_state_value(&StateKey::new(vec![5])).unwrap(),
        Some(StateValue::new(vec![50]))
    );
}

/// A diff that deletes the keys named by `keys`, recovered the same way
/// [`diff_with`] recovers one: by diffing a state that has them against
/// one that doesn't.
fn deleting(keys: &[u8]) -> StateDiff {
    let mut before = chain_types::collections::BTreeMap::new();
    for key_byte in keys {
        before.insert(StateKey::new(vec![*key_byte]), StateValue::new(vec![0]));
    }
    chain_state::diff(&before, &chain_types::collections::BTreeMap::new())
}

#[test]
fn a_diff_that_deletes_a_key_removes_it_and_leaves_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let root = Hash::from_bytes([1u8; 32]);
    db.commit_block(&block_at(1), root, &diff_with(&[(1, 10), (2, 20), (3, 30)]))
        .unwrap();

    db.commit_block(&block_at(2), root, &deleting(&[2]))
        .unwrap();

    let get = |byte: u8| db.get_state_value(&StateKey::new(vec![byte])).unwrap();
    assert_eq!(get(1), Some(StateValue::new(vec![10])));
    assert_eq!(get(2), None, "deleted");
    assert_eq!(get(3), Some(StateValue::new(vec![30])));
}

#[test]
fn deleting_a_key_the_store_never_held_is_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let root = Hash::from_bytes([1u8; 32]);
    db.commit_block(&block_at(1), root, &diff_with(&[(1, 10)]))
        .unwrap();

    db.commit_block(&block_at(2), root, &deleting(&[9]))
        .unwrap();

    assert_eq!(db.tip_height().unwrap(), Some(BlockHeight(2)));
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![1])).unwrap(),
        Some(StateValue::new(vec![10]))
    );
}

#[test]
fn a_deleted_key_can_be_written_again_later() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let root = Hash::from_bytes([1u8; 32]);
    db.commit_block(&block_at(1), root, &diff_with(&[(4, 40)]))
        .unwrap();
    db.commit_block(&block_at(2), root, &deleting(&[4]))
        .unwrap();
    db.commit_block(&block_at(3), root, &diff_with(&[(4, 41)]))
        .unwrap();
    assert_eq!(
        db.get_state_value(&StateKey::new(vec![4])).unwrap(),
        Some(StateValue::new(vec![41]))
    );
}

#[test]
fn block_commits_are_contiguous_and_cannot_replace_history() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let root = Hash::from_bytes([1u8; 32]);

    let skipped = db
        .commit_block(&block_at(2), root, &StateDiff::empty())
        .unwrap_err();
    assert!(matches!(
        skipped,
        chain_db::DbError::NonSequentialCommit {
            expected: BlockHeight(1),
            actual: BlockHeight(2)
        }
    ));

    db.commit_block(&block_at(1), root, &StateDiff::empty())
        .unwrap();
    let replacement = db
        .commit_block(&block_at(1), root, &StateDiff::empty())
        .unwrap_err();
    assert!(matches!(
        replacement,
        chain_db::DbError::NonSequentialCommit {
            expected: BlockHeight(2),
            actual: BlockHeight(1)
        }
    ));
}

// ---- initialise / load_state ------------------------------------------------

use chain_db::schema::MAX_KEY_BYTES;
use chain_db::DbError;
use chain_types::collections::BTreeMap;

fn entries(pairs: &[(&[u8], &[u8])]) -> BTreeMap<StateKey, StateValue> {
    pairs
        .iter()
        .map(|(k, v)| (StateKey::new(k.to_vec()), StateValue::new(v.to_vec())))
        .collect()
}

const GENESIS_HASH: Hash = Hash::from_bytes([0x11; 32]);
const GENESIS_ROOT: Hash = Hash::from_bytes([0x22; 32]);

#[test]
fn a_new_database_has_no_genesis_and_no_state() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    assert_eq!(db.genesis_hash().unwrap(), None);
    assert!(db.load_state().unwrap().is_empty());
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), None);
    assert_eq!(db.tip_height().unwrap(), None);
}

#[test]
fn initialising_records_the_starting_point_and_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let genesis = entries(&[(b"a", b"1"), (b"b", b"2")]);
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &genesis).unwrap();

    assert_eq!(db.genesis_hash().unwrap(), Some(GENESIS_HASH));
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), Some(GENESIS_ROOT));
    assert_eq!(db.load_state().unwrap(), genesis);
    assert_eq!(
        db.get_state_value(&StateKey::new(b"a".to_vec())).unwrap(),
        Some(StateValue::new(b"1".to_vec()))
    );
    // Genesis is a starting point, not a block: no tip, and the first
    // block is still height 1.
    assert_eq!(db.tip_height().unwrap(), None);
    assert_eq!(db.get_block(BlockHeight(0)).unwrap(), None);
}

#[test]
fn a_chain_is_never_initialised_over() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let genesis = entries(&[(b"a", b"1")]);
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &genesis).unwrap();

    let other = entries(&[(b"z", b"9")]);
    let refused = db.initialise(
        Hash::from_bytes([0x33; 32]),
        Hash::from_bytes([0x44; 32]),
        &other,
    );
    assert_eq!(refused, Err(DbError::AlreadyInitialised));
    assert_eq!(db.genesis_hash().unwrap(), Some(GENESIS_HASH), "unchanged");
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), Some(GENESIS_ROOT));
    assert_eq!(
        db.load_state().unwrap(),
        genesis,
        "not a single entry added"
    );
}

#[test]
fn blocks_committed_without_a_genesis_also_refuse_one() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.commit_block(
        &block_at(1),
        Hash::from_bytes([7; 32]),
        &diff_with(&[(1, 1)]),
    )
    .unwrap();
    let genesis = entries(&[(b"a", b"1")]);
    assert_eq!(
        db.initialise(GENESIS_HASH, GENESIS_ROOT, &genesis),
        Err(DbError::AlreadyInitialised)
    );
    assert_eq!(db.genesis_hash().unwrap(), None);
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), None);
}

#[test]
fn blocks_apply_on_top_of_the_genesis_state_including_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let genesis = entries(&[(b"keep", b"k"), (b"change", b"old"), (b"remove", b"gone")]);
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &genesis).unwrap();

    let after = entries(&[(b"keep", b"k"), (b"change", b"new"), (b"added", b"fresh")]);
    let diff = chain_state::diff(&genesis, &after);
    db.commit_block(&block_at(1), Hash::from_bytes([5; 32]), &diff)
        .unwrap();

    assert_eq!(db.load_state().unwrap(), after);
    assert_eq!(db.tip_height().unwrap(), Some(BlockHeight(1)));
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), Some(GENESIS_ROOT));
    assert_eq!(
        db.get_root(BlockHeight(1)).unwrap(),
        Some(Hash::from_bytes([5; 32]))
    );
    assert_eq!(db.genesis_hash().unwrap(), Some(GENESIS_HASH));
}

#[test]
fn the_first_block_after_genesis_must_be_height_one() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &entries(&[(b"a", b"1")]))
        .unwrap();
    let err = db
        .commit_block(&block_at(2), Hash::from_bytes([1; 32]), &StateDiff::empty())
        .unwrap_err();
    assert!(matches!(err, DbError::NonSequentialCommit { .. }), "{err}");
}

#[test]
fn the_state_survives_a_reopen_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    // Awkward keys and values: every byte value, an empty value, values
    // large enough to spill onto overflow pages, and enough entries to
    // need many pages.
    let mut state = BTreeMap::new();
    for byte in 0..=255u8 {
        state.insert(
            StateKey::new(vec![byte, 0, byte]),
            StateValue::new(vec![byte; 3]),
        );
    }
    state.insert(StateKey::new(vec![0]), StateValue::new(Vec::new()));
    state.insert(
        StateKey::new(vec![0xff; 100]),
        StateValue::new(vec![0xAB; 50_000]),
    );
    for n in 0..3_000u32 {
        state.insert(
            StateKey::new(n.to_be_bytes().to_vec()),
            StateValue::new(n.to_le_bytes().repeat(8)),
        );
    }
    {
        let db = Db::open(dir.path()).unwrap();
        db.initialise(GENESIS_HASH, GENESIS_ROOT, &state).unwrap();
    }
    let db = Db::open(dir.path()).unwrap();
    let loaded = db.load_state().unwrap();
    assert_eq!(loaded.len(), state.len());
    assert!(
        loaded == state,
        "the loaded state differs from what was written"
    );
    assert!(loaded.iter().eq(state.iter()), "and in the same order");
    assert_eq!(db.genesis_hash().unwrap(), Some(GENESIS_HASH));
}

#[test]
fn an_initialisation_that_fails_part_way_leaves_nothing_behind() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    // A key the store will not hold, after entries it will: the whole
    // transaction must roll back, not leave the first of them.
    let mut state = entries(&[(b"a", b"1"), (b"b", b"2")]);
    state.insert(
        StateKey::new(vec![b'z'; MAX_KEY_BYTES + 1]),
        StateValue::new(vec![1]),
    );
    assert_eq!(
        db.initialise(GENESIS_HASH, GENESIS_ROOT, &state),
        Err(DbError::KeyTooLarge {
            length: MAX_KEY_BYTES + 1
        })
    );
    assert_eq!(db.genesis_hash().unwrap(), None);
    assert!(db.load_state().unwrap().is_empty());
    assert_eq!(db.get_root(BlockHeight(0)).unwrap(), None);

    // And it can be initialised properly afterwards.
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &entries(&[(b"a", b"1")]))
        .unwrap();
    assert_eq!(db.load_state().unwrap(), entries(&[(b"a", b"1")]));
}

#[test]
fn the_key_limit_is_exact_and_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(dir.path()).unwrap();
    let longest = StateKey::new(vec![7; MAX_KEY_BYTES]);
    let mut at_the_limit = BTreeMap::new();
    at_the_limit.insert(longest, StateValue::new(vec![1]));
    db.initialise(GENESIS_HASH, GENESIS_ROOT, &at_the_limit)
        .unwrap();
    assert_eq!(db.load_state().unwrap(), at_the_limit);

    // Just over the limit, and far beyond anything MDBX itself could hold,
    // which is what would make the library panic.
    for length in [MAX_KEY_BYTES + 1, 1 << 20] {
        let mut too_long = at_the_limit.clone();
        too_long.insert(StateKey::new(vec![8; length]), StateValue::new(vec![2]));
        let diff = chain_state::diff(&at_the_limit, &too_long);
        assert_eq!(
            db.commit_block(&block_at(1), Hash::from_bytes([1; 32]), &diff),
            Err(DbError::KeyTooLarge { length })
        );
        assert_eq!(db.tip_height().unwrap(), None, "nothing was committed");
        assert_eq!(db.get_block(BlockHeight(1)).unwrap(), None);
        assert_eq!(db.load_state().unwrap(), at_the_limit, "state untouched");
    }

    // A deletion of a key that long is refused the same way.
    let mut with_long_key = at_the_limit.clone();
    with_long_key.insert(
        StateKey::new(vec![9; MAX_KEY_BYTES + 1]),
        StateValue::new(vec![3]),
    );
    let diff = chain_state::diff(&with_long_key, &at_the_limit);
    assert!(matches!(
        db.commit_block(&block_at(1), Hash::from_bytes([1; 32]), &diff),
        Err(DbError::KeyTooLarge { .. })
    ));
}
