//! Test fixture, not a real binary: opens `chain-db`'s exact on-disk
//! schema, performs the writes one block commit would, prints `READY`,
//! then blocks forever — deliberately never calling `commit()`.
//!
//! `tests/crash_durability.rs` spawns this, waits for `READY` (proof
//! the writes were issued), then sends `SIGKILL`. Because the
//! transaction was never committed, MDBX must roll it back entirely —
//! this is what actually exercises that guarantee instead of just
//! trusting the dependency's own documentation for it.
//!
//! Drives `libmdbx` directly rather than going through `chain_db::Db`,
//! since `Db`'s only write path (`commit_block`) commits atomically by
//! design and has no way to stop short of that.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chain_db::schema::{
    height_key, BLOCKS_TABLE, GENESIS_HASH_KEY, META_TABLE, ROOTS_TABLE, STATE_TABLE,
    TIP_HEIGHT_KEY,
};
use chain_engine_api::Block;
use chain_types::codec::Encode;
use chain_types::{BlockHeight, Hash};
use libmdbx::{DatabaseFlags, Environment, EnvironmentFlags, Geometry, Mode, SyncMode, WriteFlags};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = PathBuf::from(
        args.get(1)
            .expect("usage: crash_helper <db_path> <height> [initialise]"),
    );
    let height: u64 = args
        .get(2)
        .expect("usage: crash_helper <db_path> <height> [initialise]")
        .parse()
        .expect("height must be a u64");

    let mut builder = Environment::builder();
    builder
        .set_max_dbs(4)
        .set_flags(EnvironmentFlags {
            mode: Mode::ReadWrite {
                sync_mode: SyncMode::Durable,
            },
            ..Default::default()
        })
        .set_geometry(Geometry {
            size: Some(0..(64 * 1024 * 1024 * 1024)),
            ..Default::default()
        });
    let env = builder.open(&path).expect("open mdbx env");

    let txn = env.begin_rw_sync().expect("begin rw transaction");
    let blocks_db = txn
        .create_db(Some(BLOCKS_TABLE), DatabaseFlags::empty())
        .expect("create blocks table");
    let roots_db = txn
        .create_db(Some(ROOTS_TABLE), DatabaseFlags::empty())
        .expect("create roots table");
    let state_db = txn
        .create_db(Some(STATE_TABLE), DatabaseFlags::empty())
        .expect("create state table");
    let meta_db = txn
        .create_db(Some(META_TABLE), DatabaseFlags::empty())
        .expect("create meta table");

    if args.get(3).is_some_and(|mode| mode == "initialise") {
        // What `Db::initialise` writes, never committed.
        txn.put(
            state_db,
            b"torn-genesis-key",
            b"torn-genesis-value",
            WriteFlags::UPSERT,
        )
        .expect("put genesis state entry");
        txn.put(
            roots_db,
            height_key(BlockHeight(0)),
            [0xCDu8; 32],
            WriteFlags::UPSERT,
        )
        .expect("put genesis root");
        txn.put(meta_db, GENESIS_HASH_KEY, [0xEFu8; 32], WriteFlags::UPSERT)
            .expect("put genesis hash");
    } else {
        let block = Block {
            parent_block_hash: Hash::from_bytes([0u8; 32]),
            height: BlockHeight(height),
            timestamp_millis: 1_700_000_000_000,
            transactions: Vec::new(),
        };
        let mut block_bytes = Vec::new();
        block.encode(&mut block_bytes);

        txn.put(
            blocks_db,
            height_key(BlockHeight(height)),
            block_bytes,
            WriteFlags::UPSERT,
        )
        .expect("put block");
        txn.put(
            roots_db,
            height_key(BlockHeight(height)),
            [0xABu8; 32],
            WriteFlags::UPSERT,
        )
        .expect("put root");
        txn.put(state_db, b"torn-key", b"torn-value", WriteFlags::UPSERT)
            .expect("put state entry");
        txn.put(
            meta_db,
            TIP_HEIGHT_KEY,
            height_key(BlockHeight(height)),
            WriteFlags::UPSERT,
        )
        .expect("put tip height");
    }

    println!("READY");
    std::io::stdout().flush().expect("flush stdout");

    // Hold `txn` alive (never commit, never abort) until killed.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
