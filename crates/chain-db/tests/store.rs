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
