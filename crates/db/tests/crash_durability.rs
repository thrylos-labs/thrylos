//! Actually kills a process mid-write (not a simulation of one) and
//! checks the store afterward — `docs/spec.md`, "State, storage and
//! sync": "A crash mid-write leaves the node at block N or N+1, never
//! between." This proves the "N" side: a writer killed before it
//! calls `commit()` leaves no trace at all, relying on MDBX's own
//! stale-writer recovery (reclaiming a dead process's write lock)
//! rather than anything this crate does itself. `tests/store.rs`
//! already covers the "N+1" side — every field of a *returned* `Ok`
//! commit is durable and readable back.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use chain_db::Db;
use chain_engine_api::Block;
use chain_state::{StateDiff, StateKey};
use chain_types::{BlockHeight, Hash};

fn block_at(height: u64) -> Block {
    Block {
        parent_block_hash: Hash::from_bytes([0u8; 32]),
        height: BlockHeight(height),
        timestamp_millis: 1_700_000_000_000,
        transactions: Vec::new(),
    }
}

#[test]
fn a_transaction_killed_before_commit_leaves_no_trace() {
    let dir = tempfile::tempdir().unwrap();

    // A real, fully-committed block 1 to fall back to — dropped before
    // the helper opens its own environment on the same path, since
    // MDBX allows only one live writer.
    {
        let db = Db::open(dir.path()).unwrap();
        db.commit_block(
            &block_at(1),
            Hash::from_bytes([1u8; 32]),
            &StateDiff::empty(),
        )
        .unwrap();
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_crash_helper"))
        .arg(dir.path())
        .arg("2")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn crash_helper");

    let stdout = child.stdout.take().expect("child stdout was not piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read READY line");
    assert_eq!(
        line.trim(),
        "READY",
        "helper did not report readiness before being killed"
    );

    // std::process::Child::kill sends SIGKILL on Unix: the helper's
    // open write transaction is never committed, never even aborted
    // cleanly — the process simply stops existing mid-flight.
    child.kill().expect("SIGKILL the helper");
    child.wait().expect("wait for the killed child");

    let db = Db::open(dir.path()).unwrap();
    assert_eq!(
        db.tip_height().unwrap(),
        Some(BlockHeight(1)),
        "tip must not have advanced past the never-committed block"
    );
    assert_eq!(
        db.get_block(BlockHeight(2)).unwrap(),
        None,
        "the killed transaction's block must not be visible"
    );
    assert_eq!(
        db.get_root(BlockHeight(2)).unwrap(),
        None,
        "the killed transaction's root must not be visible"
    );
    assert_eq!(
        db.get_state_value(&StateKey::new(b"torn-key".to_vec()))
            .unwrap(),
        None,
        "the killed transaction's state write must not be visible"
    );

    // And the side that was never in question: block 1 is untouched.
    assert_eq!(db.get_block(BlockHeight(1)).unwrap(), Some(block_at(1)));
}
