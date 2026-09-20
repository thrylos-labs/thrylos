//! Test fixture, not a real binary: opens a node's chain on the devnet
//! genesis and finalises empty blocks as fast as it can, printing
//! `OPENED <height>` once and `COMMITTED <height>` after each block's
//! finalisation returns.
//!
//! `tests/durable_engine.rs` kills it with `SIGKILL` at an arbitrary moment
//! and reopens the directory. Because the line is printed only after the
//! commit returned, the chain it leaves must be at the last height printed
//! or the one after (a commit that landed just before the kill), never
//! anywhere else and never damaged.

#![allow(clippy::expect_used, clippy::print_stdout)]

use std::io::Write;
use std::path::PathBuf;

use chain_engine_api::{ChainView, Engine};
use chain_node::DurableEngine;
use chain_types::BlockHeight;

fn main() {
    let dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: durable_engine_crash_helper <dir>"),
    );
    let config = chain_genesis::devnet::config().expect("the devnet genesis");
    let mut engine = DurableEngine::open(&dir, &config).expect("open or restore the chain");

    let mut out = std::io::stdout();
    let head = ChainView::head(&engine).expect("the head");
    writeln!(out, "OPENED {}", head.height.0).expect("write");
    out.flush().expect("flush");

    loop {
        let head = ChainView::head(&engine).expect("the head");
        let limits = ChainView::block_limits(&engine).expect("the limits");
        let block = engine.propose_block(
            head.block_hash,
            head.state_root,
            BlockHeight(head.height.0.saturating_add(1)),
            head.timestamp_ms.saturating_add(1_000),
            Vec::new(),
            limits,
        );
        let executed = engine
            .execute_block(head.state_root, &block)
            .expect("an empty block executes");
        engine
            .finalise_block(&block, &executed)
            .expect("an empty block finalises");
        writeln!(out, "COMMITTED {}", block.height.0).expect("write");
        out.flush().expect("flush");
    }
}
