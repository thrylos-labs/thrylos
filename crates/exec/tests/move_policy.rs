//! A node's own limits on Move work (`chain_exec::policy`): what a proposer packs
//! into a block, and that none of it is a rule of the chain.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::integer_division
)]

mod common;

use common::*;

use chain_engine_api::{Block, BlockLimits, Engine, TransactionOutcome};
use chain_exec::policy::{MOVE_CALL_GAS_LIMIT, MOVE_GAS_PER_PROPOSED_BLOCK};
use chain_types::{BlockHeight, GasAmount, Transaction};

const APP: &str = "
module pkg::app {
    entry fun noop() {}
    // Runs until it is out of gas: uses exactly what it is given.
    entry fun spin() { let mut i = 0u64; while (true) { i = i + 1; }; }
}";

struct World {
    chain: Chain,
    package: [u8; 32],
    next_seed: u8,
}

fn world() -> World {
    let (mut chain, mut owner) = rich();
    let package = id_of(&owner, 0);
    let modules: Vec<_> = compile_with_system_packages(APP).into_values().collect();
    assert_eq!(
        chain.run(owner.publish(modules)),
        TransactionOutcome::Success
    );
    World {
        chain,
        package,
        next_seed: 10,
    }
}

impl World {
    /// A call from a fresh funded sender, declaring `gas`.
    fn call(&mut self, function: &str, gas: u64) -> Transaction {
        let mut sender = Publisher::new(self.next_seed);
        self.next_seed += 1;
        self.chain.fund(&sender, 1_000_000_000_000);
        let mut tx = sender.call(self.package, "app", function, vec![]);
        tx.body.gas_limit = GasAmount(gas);
        sender.resign(tx)
    }

    fn propose(&self, candidates: Vec<Transaction>) -> Block {
        self.chain.executor.propose_block(
            self.chain.executor.tip_block_hash(),
            self.chain.executor.state_root(),
            BlockHeight(self.chain.executor.head_height().unwrap() + 1),
            self.chain.now_ms + 1_000,
            candidates,
            BlockLimits {
                max_gas: u64::MAX,
                max_size_bytes: 4 * 1024 * 1024,
            },
        )
    }
}

#[test]
fn a_proposer_stops_packing_move_calls_once_the_ones_it_has_used_their_share() {
    let mut w = world();
    // Calls that use their whole limit: each takes MOVE_CALL_GAS_LIMIT.
    let spins: Vec<Transaction> = (0..6)
        .map(|_| w.call("spin", MOVE_CALL_GAS_LIMIT))
        .collect();
    let block = w.propose(spins);
    let expected =
        usize::try_from(MOVE_GAS_PER_PROPOSED_BLOCK.div_ceil(MOVE_CALL_GAS_LIMIT)).unwrap();
    assert_eq!(
        block.transactions.len(),
        expected,
        "the rest wait for a later block"
    );
}

#[test]
fn ordinary_small_calls_fit_by_the_dozen_and_are_counted_at_the_floor() {
    let mut w = world();
    // A call is charged at least the protocol's floor, so a block holds this many
    // of the lightest calls.
    let floor = chain_types::MIN_GAS_LIMIT;
    let fit = usize::try_from(MOVE_GAS_PER_PROPOSED_BLOCK / floor).unwrap();
    let calls: Vec<Transaction> = (0..fit + 20).map(|_| w.call("noop", floor)).collect();
    let block = w.propose(calls);
    assert_eq!(block.transactions.len(), fit);
}

#[test]
fn the_limit_is_only_on_calls_to_users_packages() {
    let mut w = world();
    let spins: Vec<Transaction> = (0..6)
        .map(|_| w.call("spin", MOVE_CALL_GAS_LIMIT))
        .collect();
    // Native transfers offered after the Move budget is spent are still packed.
    let mut transfers = Vec::new();
    for _ in 0..3 {
        let sender = Publisher::new(w.next_seed);
        w.next_seed += 1;
        w.chain.fund(&sender, 1_000_000_000_000);
        let recipient = Publisher::new(200).address();
        let tx = sender.tx_with(
            0,
            1_000,
            chain_exec::native::COIN_PACKAGE_ADDRESS,
            "transfer",
            vec![recipient.as_bytes().to_vec(), 5u128.to_le_bytes().to_vec()],
        );
        let mut tx = tx;
        tx.body.call.module_name = b"coin".to_vec();
        transfers.push(sender.resign(tx));
    }
    let mut all = spins;
    all.extend(transfers.clone());
    let block = w.propose(all);
    for transfer in &transfers {
        assert!(
            block.transactions.contains(transfer),
            "a native call was left out"
        );
    }
}

#[test]
fn a_block_with_a_call_over_the_limit_is_still_a_valid_block() {
    // The limits are a node's own: another proposer's block is judged by the chain's
    // rules alone, so a call that declares more than the limit (though within the chain's own ceiling) still runs.
    let mut w = world();
    let big = w.call("noop", 70_000);
    let block = Block {
        parent_block_hash: w.chain.executor.tip_block_hash(),
        height: BlockHeight(w.chain.executor.head_height().unwrap() + 1),
        timestamp_millis: w.chain.now_ms + 1_000,
        transactions: vec![big],
    };
    let executed = w
        .chain
        .executor
        .execute_block(w.chain.executor.state_root(), &block)
        .expect("valid, whatever this node would have proposed");
    assert_eq!(executed.outcomes[0], TransactionOutcome::Success);
}
