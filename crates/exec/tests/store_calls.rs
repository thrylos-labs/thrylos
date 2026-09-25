//! The store in real calls: a package that remembers, published and called
//! through real blocks, with what it costs, what an abort leaves behind, who
//! may touch whose drawers, and that it survives a restart and agrees between
//! independent nodes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeMap;

use common::*;

use chain_engine_api::{AbortReason, Engine, TransactionOutcome};
use chain_exec::drawer::{DrawerValue, DRAWER_DEPOSIT_PER_KIB};
use chain_exec::keys::{drawer_key, drawer_tag};
use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
use chain_exec::Executor;
use chain_state::{StateKey, StateValue};
use chain_types::{Address, ChainId};
use move_core_types::account_address::AccountAddress;

const OK: TransactionOutcome = TransactionOutcome::Success;
const FAILED: TransactionOutcome = TransactionOutcome::Aborted(AbortReason::ExecutionFailed);

const APP: &str = "
module pkg::app {
    use thrylos::store;
    use thrylos::signer;

    public struct Counter has key, store, copy, drop { n: u64 }
    public struct Blob has key, store { data: vector<u8> }

    entry fun init(s: &signer) { store::put(signer::address_of(s), 0, Counter { n: 0 }); }
    entry fun bump(s: &signer) {
        let o = signer::address_of(s);
        let mut c = store::take<Counter>(o, 0);
        c.n = c.n + 1;
        store::put(o, 0, c);
    }
    entry fun check(s: &signer, want: u64) {
        assert!(store::read<Counter>(signer::address_of(s), 0).n == want, 100);
    }
    // The same, on someone else's drawer: needs that address declared.
    entry fun init_for(_s: &signer, o: address) { store::put(o, 0, Counter { n: 0 }); }
    entry fun bump_for(_s: &signer, o: address) {
        let mut c = store::take<Counter>(o, 0);
        c.n = c.n + 1;
        store::put(o, 0, c);
    }
    entry fun put_then_abort(s: &signer) {
        store::put(signer::address_of(s), 0, Counter { n: 9 });
        abort 9
    }
    entry fun set_blob(s: &signer, n: u64) {
        let o = signer::address_of(s);
        if (store::has<Blob>(o, 0)) { let Blob { data: _ } = store::take<Blob>(o, 0); };
        let mut data = vector[];
        let mut i = 0;
        while (i < n) { data.push_back(1); i = i + 1; };
        store::put(o, 0, Blob { data });
    }
    entry fun drop_blob(s: &signer) { let Blob { data: _ } = store::take<Blob>(signer::address_of(s), 0); }
}";

struct App {
    chain: Chain,
    owner: Publisher,
    package: [u8; 32],
}

fn deployed() -> App {
    let (mut chain, mut owner) = rich();
    let package = id_of(&owner, 0);
    let modules: Vec<_> = compile_with_system_packages(APP).into_values().collect();
    assert_eq!(chain.run(owner.publish(modules)), OK);
    App {
        chain,
        owner,
        package,
    }
}

impl App {
    fn call(&mut self, function: &str, arguments: Vec<Vec<u8>>) -> TransactionOutcome {
        let tx = self.owner.call(self.package, "app", function, arguments);
        self.chain.run(tx)
    }

    fn call_declaring(
        &mut self,
        function: &str,
        arguments: Vec<Vec<u8>>,
        declared: Vec<Address>,
    ) -> TransactionOutcome {
        let mut tx = self.owner.call(self.package, "app", function, arguments);
        tx.body.call.module_name = b"app".to_vec();
        tx.body.declared_inputs = declared;
        let tx = self.owner.resign(tx);
        self.chain.run(tx)
    }

    fn drawers(&self) -> Vec<(StateKey, StateValue)> {
        self.chain
            .executor
            .state_entries()
            .filter(|(k, _)| k.as_bytes().first() == Some(&drawer_tag()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    fn type_name(&self, what: &str) -> String {
        format!("0x{}::app::{what}", hex(self.package))
    }

    fn balance(&self) -> u128 {
        self.chain.balance(self.owner.address())
    }
}

fn hex(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn u64_arg(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn counter_value(app: &App) -> u64 {
    let drawer = app.drawers().into_iter().next().expect("one drawer").1;
    let value = DrawerValue::from_state(&drawer).unwrap();
    assert_eq!(value.type_name, app.type_name("Counter"));
    u64::from_le_bytes(value.bytes.try_into().unwrap())
}

// ---- a counter that remembers ----------------------------------------------

#[test]
fn a_counter_lives_across_blocks_and_the_state_records_it() {
    let mut app = deployed();
    assert_eq!(app.call("init", vec![]), OK);
    for _ in 0..3 {
        assert_eq!(app.call("bump", vec![]), OK);
    }
    assert_eq!(app.call("check", vec![u64_arg(3)]), OK);
    assert_eq!(
        app.call("check", vec![u64_arg(4)]),
        FAILED,
        "so the read is real"
    );
    assert_eq!(app.drawers().len(), 1);
    assert_eq!(counter_value(&app), 3);
    let (key, _) = &app.drawers()[0];
    let owner = AccountAddress::new(*app.owner.address().as_bytes());
    assert_eq!(*key, drawer_key(owner, 0, &app.type_name("Counter")));
}

#[test]
fn creating_a_drawer_costs_the_deposit_and_updating_it_costs_none() {
    let mut app = deployed();
    let fee_ceiling = 100_000u128; // a call's gas limit, at the base fee of 1
    let (b0, s0) = (app.balance(), app.chain.executor.supply().unwrap());
    assert_eq!(app.call("init", vec![]), OK);
    let (b1, s1) = (app.balance(), app.chain.executor.supply().unwrap());
    let deposit = NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB;
    let paid = b0 - b1;
    assert!(
        paid >= deposit && paid - deposit <= fee_ceiling,
        "paid {paid}"
    );
    // Everything paid is burned: the supply fell by exactly what the sender lost.
    assert_eq!(s0 - s1, paid);
    // Taking the counter out and putting it back the same size owes nothing.
    assert_eq!(app.call("bump", vec![]), OK);
    let paid_again = b1 - app.balance();
    assert!(paid_again <= fee_ceiling, "only gas: {paid_again}");
}

#[test]
fn growing_a_drawer_across_kib_pays_for_the_extra_and_shrinking_owes_nothing() {
    let mut app = deployed();
    let owner_balance = |app: &App| app.balance();
    let b0 = owner_balance(&app);
    assert_eq!(app.call("set_blob", vec![u64_arg(100)]), OK);
    let after_small = owner_balance(&app);
    assert!(b0 - after_small >= NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB);
    // Up to about 3 KiB: two more started KiBs.
    assert_eq!(app.call("set_blob", vec![u64_arg(2_500)]), OK);
    let grown = after_small - owner_balance(&app);
    assert!(
        (2 * DRAWER_DEPOSIT_PER_KIB..3 * DRAWER_DEPOSIT_PER_KIB).contains(&grown),
        "{grown}"
    );
    // Back down: nothing but gas.
    let before_shrink = owner_balance(&app);
    assert_eq!(app.call("set_blob", vec![u64_arg(10)]), OK);
    assert!(before_shrink - owner_balance(&app) < DRAWER_DEPOSIT_PER_KIB);
    // Emptied, no refund.
    let before_drop = owner_balance(&app);
    assert_eq!(app.call("drop_blob", vec![]), OK);
    assert!(
        before_drop - owner_balance(&app) < DRAWER_DEPOSIT_PER_KIB,
        "no refund, nothing owed"
    );
    assert!(app.drawers().is_empty());
}

// ---- what an aborted call leaves -------------------------------------------

#[test]
fn a_call_that_writes_and_then_aborts_leaves_no_drawer_and_costs_only_gas() {
    let mut app = deployed();
    let (b0, s0) = (app.balance(), app.chain.executor.supply().unwrap());
    assert_eq!(app.call("put_then_abort", vec![]), FAILED);
    assert!(app.drawers().is_empty());
    let paid = b0 - app.balance();
    assert!(
        paid > 0 && paid < DRAWER_DEPOSIT_PER_KIB,
        "gas only, not the deposit: {paid}"
    );
    assert_eq!(s0 - app.chain.executor.supply().unwrap(), paid);
}

#[test]
fn a_sender_who_cannot_pay_the_deposit_aborts_and_writes_nothing() {
    let app = deployed();
    let (mut chain, package) = (app.chain, app.package);
    // Enough for a call's maximum fee and a little more, not for the deposit.
    let keep = 100_000u128 * 10 + 1_000_000;
    let mut poor = Publisher::new(77);
    chain.fund(&poor, keep);
    let before = chain.balance(poor.address());
    let tx = poor.call(package, "app", "init", vec![]);
    assert_eq!(
        chain.run(tx),
        TransactionOutcome::Aborted(AbortReason::InsufficientBalance)
    );
    let paid = before - chain.balance(poor.address());
    assert!(
        paid > 0 && paid < 100_000,
        "charged what the VM metered, not the whole limit: {paid}"
    );
    let drawers = chain
        .executor
        .state_entries()
        .filter(|(k, _)| k.as_bytes().first() == Some(&drawer_tag()))
        .count();
    assert_eq!(drawers, 0);
}

// ---- who may touch whose drawers -------------------------------------------

#[test]
fn another_address_is_off_limits_until_the_call_declares_it() {
    let mut app = deployed();
    let other = Publisher::new(50).address();
    let arg = other.as_bytes().to_vec();
    assert_eq!(
        app.call("init_for", vec![arg.clone()]),
        FAILED,
        "not declared"
    );
    assert!(app.drawers().is_empty());
    assert_eq!(
        app.call_declaring("init_for", vec![arg.clone()], vec![other]),
        OK
    );
    assert_eq!(app.drawers().len(), 1);
    // And the same rule to change it.
    assert_eq!(app.call("bump_for", vec![arg.clone()]), FAILED);
    assert_eq!(app.call_declaring("bump_for", vec![arg], vec![other]), OK);
    assert_eq!(counter_value(&app), 1);
}

// ---- restart and agreement -------------------------------------------------

#[test]
fn a_restarted_node_finds_the_drawers_and_carries_on() {
    let mut app = deployed();
    assert_eq!(app.call("init", vec![]), OK);
    assert_eq!(app.call("bump", vec![]), OK);
    let state: BTreeMap<StateKey, StateValue> = app
        .chain
        .executor
        .state_entries()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let restored = Executor::restore(
        ChainId(1),
        state,
        app.chain.executor.tip_block_hash(),
        app.chain.executor.state_root(),
    )
    .expect("the state restores, drawers and all");
    restored.audit().unwrap();
    app.chain.executor = restored;
    assert_eq!(app.call("bump", vec![]), OK);
    assert_eq!(app.call("check", vec![u64_arg(2)]), OK);
    assert_eq!(counter_value(&app), 2);
}

#[test]
fn independent_nodes_running_the_same_calls_reach_the_same_state_root() {
    let mut roots = Vec::new();
    for _ in 0..2 {
        let mut app = deployed();
        for f in ["init", "bump", "bump"] {
            assert_eq!(app.call(f, vec![]), OK);
        }
        assert_eq!(app.call("set_blob", vec![u64_arg(700)]), OK);
        roots.push(app.chain.executor.state_root());
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn the_audit_notices_a_drawer_that_is_not_what_its_key_says() {
    let mut app = deployed();
    assert_eq!(app.call("init", vec![]), OK);
    let mut state: BTreeMap<StateKey, StateValue> = app
        .chain
        .executor
        .state_entries()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (key, value) = app.drawers().remove(0);
    // A Counter under the key of a different type: a key its contents do not give.
    let owner = AccountAddress::new(*app.owner.address().as_bytes());
    let wrong = drawer_key(owner, 0, &app.type_name("Blob"));
    state.remove(&key);
    state.insert(wrong, value);
    let r = chain_exec::drawer::audit(&state);
    assert!(r.is_err(), "{r:?}");
    // Entries that do not decode are refused too.
    state.insert(drawer_key(owner, 6, "T"), StateValue::new(vec![1, 2, 3]));
    assert!(chain_exec::drawer::audit(&state).is_err());
}

// ---- the state cap ---------------------------------------------------------

#[test]
fn a_call_that_would_create_a_drawer_past_the_state_cap_is_left_out_and_a_block_with_it_is_refused()
{
    use chain_engine_api::{Block, BlockLimits, RejectionReason};
    use chain_exec::executor::MAX_STATE_ENTRIES;

    let mut app = deployed();
    // Fill the state to exactly its cap with padding, and restore a node from it.
    let mut state: BTreeMap<StateKey, StateValue> = app
        .chain
        .executor
        .state_entries()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut next = 0u64;
    while state.len() < MAX_STATE_ENTRIES {
        let mut key = vec![250u8];
        key.extend_from_slice(&next.to_be_bytes());
        state.insert(StateKey::new(key), StateValue::new(vec![0u8; 8]));
        next += 1;
    }
    let root = chain_state::compute_root(&state);
    let tip = app.chain.executor.tip_block_hash();
    app.chain.executor =
        Executor::restore(ChainId(1), state, tip, root).expect("a full state restores");

    // `init` would create one more entry than the cap allows.
    let tx = app.owner.call(app.package, "app", "init", vec![]);
    let height = chain_types::BlockHeight(app.chain.executor.head_height().unwrap() + 1);
    let limits = BlockLimits {
        max_gas: u64::MAX,
        max_size_bytes: 4 * 1024 * 1024,
    };
    let proposed = app.chain.executor.propose_block(
        app.chain.executor.tip_block_hash(),
        app.chain.executor.state_root(),
        height,
        app.chain.now_ms + 1_000,
        vec![tx.clone()],
        limits,
    );
    assert!(
        proposed.transactions.is_empty(),
        "the proposer leaves out what would breach the cap"
    );

    // A block that carries it anyway is refused as a whole.
    let forced = Block {
        parent_block_hash: app.chain.executor.tip_block_hash(),
        height,
        timestamp_millis: app.chain.now_ms + 1_000,
        transactions: vec![tx],
    };
    let refused = app
        .chain
        .executor
        .execute_block(app.chain.executor.state_root(), &forced);
    assert_eq!(refused.unwrap_err().reason, RejectionReason::MalformedBlock);
}
