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
