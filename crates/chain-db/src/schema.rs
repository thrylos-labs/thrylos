//! On-disk table names and key encodings.
//!
//! Public — not because external callers are meant to bypass [`crate::
//! Db`], but so the crash-durability test's helper binary
//! (`src/bin/crash_helper.rs`) can drive the exact same tables `Db`
//! uses without duplicating the layout by hand.
//!
//! Heights are encoded big-endian here, deliberately *not* via
//! `chain_types::codec`'s little-endian canonical `Encode`: MDBX
//! compares keys byte-lexicographically, and big-endian is the
//! encoding under which that comparison agrees with numeric height
//! order (needed once pruning or range scans exist — not yet, but the
//! key layout is harder to change later than to get right now). This
//! is a storage-layer choice about on-disk key bytes, unrelated to the
//! wire/consensus canonical encoding: nothing here is signed, hashed,
//! or sent over the network.

use chain_types::BlockHeight;

pub const BLOCKS_TABLE: &str = "blocks";
pub const STATE_TABLE: &str = "state";
pub const ROOTS_TABLE: &str = "roots";
pub const META_TABLE: &str = "meta";

/// The single fixed key in [`META_TABLE`] holding the height of the
/// most recently committed block.
pub const TIP_HEIGHT_KEY: &[u8] = b"tip_height";

pub fn height_key(height: BlockHeight) -> [u8; 8] {
    height.0.to_be_bytes()
}

pub fn height_from_bytes(bytes: &[u8]) -> Option<BlockHeight> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(BlockHeight(u64::from_be_bytes(array)))
}
