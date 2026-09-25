//! Reading what packages have stored, and simulating calls without committing
//! them: `Executor::read_drawer`, `drawers_of`, `render_drawer` and `simulate`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::disallowed_methods
)]

mod common;

use common::*;

use chain_engine_api::TransactionOutcome;
use chain_exec::drawer::DRAWER_DEPOSIT_PER_KIB;
use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
use chain_exec::simulate::{SimulationFailure, SIMULATE_MAX_GAS};
use chain_exec::view::ViewValue;
use chain_types::{Address, Transaction};
use move_core_types::account_address::AccountAddress;

const OK: TransactionOutcome = TransactionOutcome::Success;

const APP: &str = "
module pkg::app {
    use thrylos::store;
    use thrylos::signer;

    public struct Counter has key, store, copy, drop { n: u64 }
    public struct Inner has store, copy, drop { a: u8, b: u128, c: vector<u16> }
    public struct Rich has key, store, copy, drop {
        owner: address, data: vector<u8>, inner: Inner, maybe: Option<u64>, ok: bool,
    }
    public struct Wrapper<T: store> has key, store, copy, drop { v: T }
    public enum Kind has key, store, copy, drop { A, B(u64), C { x: bool } }

    entry fun init(s: &signer) { store::put(signer::address_of(s), 0, Counter { n: 0 }); }
    entry fun bump(s: &signer) {
        let o = signer::address_of(s);
        let mut c = store::take<Counter>(o, 0);
        c.n = c.n + 1;
        store::put(o, 0, c);
    }
    entry fun bump_for(_s: &signer, o: address) {
        let mut c = store::take<Counter>(o, 0);
        c.n = c.n + 1;
        store::put(o, 0, c);
    }
    entry fun init_more(s: &signer) {
        let o = signer::address_of(s);
        store::put(o, 1, Counter { n: 10 });
        store::put(o, 0, Wrapper<u64> { v: 5 });
        store::put(o, 0, Kind::B(7));
        store::put(o, 0, Rich {
            owner: @0xabc, data: b\"hi\", inner: Inner { a: 7, b: 1 << 100, c: vector[1, 2] },
            maybe: option::some(9), ok: true,
        });
    }
    entry fun aborts(_s: &signer) { abort 77 }
    entry fun spin() { loop {} }

    public fun total(o: address): u64 { store::read<Counter>(o, 0).n }
    public fun mine(s: &signer): u64 { store::read<Counter>(signer::address_of(s), 0).n }
    public fun who(s: &signer): address { signer::address_of(s) }
    public fun pair(): (u64, bool) { (7, true) }
    public fun bytes(): vector<u8> { b\"hi\" }
    public fun nested(): vector<vector<u64>> { vector[vector[1, 2], vector[]] }
    public fun takes_struct(_c: Counter) {}
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
    fn call(&mut self, function: &str, arguments: Vec<Vec<u8>>) {
        let tx = self.owner.call(self.package, "app", function, arguments);
        assert_eq!(self.chain.run(tx), OK, "{function}");
    }

    fn tx(&mut self, function: &str, arguments: Vec<Vec<u8>>) -> Transaction {
        // Not sent: signed by the same key, its sequence number left alone.
        let tx = self.owner.call(self.package, "app", function, arguments);
        self.owner.sequence -= 1;
        tx
    }

    fn type_name(&self, what: &str) -> String {
        format!("0x{}::app::{what}", hex(self.package))
    }

    fn owner(&self) -> AccountAddress {
        AccountAddress::new(*self.owner.address().as_bytes())
    }
}

fn hex(id: [u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn num(n: u64) -> ViewValue {
    ViewValue::Number(n.to_string())
}

// ---- reading drawers -------------------------------------------------------

#[test]
fn a_stored_value_is_read_back_by_owner_slot_and_type() {
    let mut app = deployed();
    app.call("init", vec![]);
    app.call("bump", vec![]);
    app.call("bump", vec![]);
    let name = app.type_name("Counter");
    let drawer = app
        .chain
        .executor
        .read_drawer(app.owner(), 0, &name)
        .unwrap()
        .expect("a counter");
    assert_eq!(drawer.type_name, name);
    assert_eq!(drawer.bytes, 2u64.to_le_bytes());
    // Not there: another slot, another type, another owner.
    assert_eq!(
        app.chain
            .executor
            .read_drawer(app.owner(), 1, &name)
            .unwrap(),
        None
    );
    assert_eq!(
        app.chain
            .executor
            .read_drawer(app.owner(), 0, &app.type_name("Kind"))
            .unwrap(),
        None
    );
    assert_eq!(
        app.chain
            .executor
            .read_drawer(AccountAddress::new([9; 32]), 0, &name)
            .unwrap(),
        None
    );
}

#[test]
fn an_addresss_drawers_are_listed_and_only_its_own() {
    let mut app = deployed();
    app.call("init", vec![]);
    app.call("init_more", vec![]);
    let mine = app.chain.executor.drawers_of(app.owner(), 100);
    let mut described: Vec<(u64, String)> =
        mine.iter().map(|d| (d.slot, d.type_name.clone())).collect();
    described.sort();
    let mut expected = vec![
        (0, app.type_name("Counter")),
        (0, app.type_name("Kind")),
        (0, app.type_name("Rich")),
        (0, app.type_name("Wrapper<u64>")),
        (1, app.type_name("Counter")),
    ];
    expected.sort();
    assert_eq!(described, expected);
    assert!(mine.iter().all(|d| d.bytes > 0));
    // The limit, and an owner with nothing (or a near neighbour's address).
    assert_eq!(app.chain.executor.drawers_of(app.owner(), 2).len(), 2);
    assert!(app
        .chain
        .executor
        .drawers_of(AccountAddress::new([9; 32]), 100)
        .is_empty());
    let mut neighbour = *app
        .owner()
        .into_bytes()
        .as_slice()
        .first_chunk::<32>()
        .unwrap();
    neighbour[31] ^= 1;
    assert!(app
        .chain
        .executor
        .drawers_of(AccountAddress::new(neighbour), 100)
        .is_empty());
}

#[test]
fn a_stored_value_is_decoded_into_its_fields() {
    let mut app = deployed();
    app.call("init", vec![]);
    app.call("bump", vec![]);
    app.call("init_more", vec![]);
    let render = |what: &str, slot: u64| {
        let drawer = app
            .chain
            .executor
            .read_drawer(app.owner(), slot, &app.type_name(what))
            .unwrap()
            .unwrap();
        app.chain.executor.render_drawer(&drawer).expect("a layout")
    };
    let ViewValue::Struct { type_name, fields } = render("Counter", 0) else {
        panic!()
    };
    assert!(type_name.ends_with("::app::Counter"));
    assert_eq!(fields, vec![("n".to_owned(), num(1))]);

    let ViewValue::Struct { fields, .. } = render("Rich", 0) else {
        panic!()
    };
    let by_name: std::collections::BTreeMap<_, _> = fields.into_iter().collect();
    assert_eq!(by_name["ok"], ViewValue::Bool(true));
    assert_eq!(by_name["data"], ViewValue::Vector(vec![num(104), num(105)]));
    let ViewValue::Struct { fields: inner, .. } = &by_name["inner"] else {
        panic!()
    };
    assert_eq!(inner[0], ("a".to_owned(), num(7)));
    assert_eq!(
        inner[1],
        (
            "b".to_owned(),
            ViewValue::Number((1u128 << 100).to_string())
        ),
        "u128 as text"
    );
    assert_eq!(
        inner[2],
        ("c".to_owned(), ViewValue::Vector(vec![num(1), num(2)]))
    );

    let ViewValue::Struct { fields, .. } = render("Wrapper<u64>", 0) else {
        panic!()
    };
    assert_eq!(fields, vec![("v".to_owned(), num(5))]);
    let ViewValue::Variant {
        variant, fields, ..
    } = render("Kind", 0)
    else {
        panic!()
    };
    assert_eq!(variant, "B");
    assert_eq!(fields, vec![("pos0".to_owned(), num(7))]);
}

// ---- simulating ------------------------------------------------------------

#[test]
fn a_simulated_call_reports_what_it_would_do_and_changes_nothing() {
    let mut app = deployed();
    app.call("init", vec![]);
    let root = app.chain.executor.state_root();
    let balance = app.chain.balance(app.owner.address());

    let tx = app.tx("bump", vec![]);
    let sim = app.chain.executor.simulate(&tx).unwrap();
    assert!(sim.gas_used > 0 && sim.gas_used < 1_000, "{}", sim.gas_used);
    assert_eq!(sim.drawers_changed, 1);
    assert_eq!(
        sim.deposit, 0,
        "taking a counter out and putting it back owes nothing"
    );
    assert!(sim.returns.is_empty());

    // A new drawer owes its deposit, reported and not charged.
    let mut fresh = deployed();
    let tx = fresh.tx("init", vec![]);
    let sim = fresh.chain.executor.simulate(&tx).unwrap();
    assert_eq!(
        sim.deposit,
        NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB
    );

    // Nothing moved: state root, balance, drawers.
    assert_eq!(app.chain.executor.state_root(), root);
    assert_eq!(app.chain.balance(app.owner.address()), balance);
    let name = app.type_name("Counter");
    assert_eq!(
        app.chain
            .executor
            .read_drawer(app.owner(), 0, &name)
            .unwrap()
            .unwrap()
            .bytes,
        0u64.to_le_bytes()
    );
}

#[test]
fn a_public_function_is_a_view_that_returns_values() {
    let mut app = deployed();
    app.call("init", vec![]);
    app.call("bump", vec![]);
    app.call("bump", vec![]);
    let owner = app.owner.address();
    let sim = |app: &mut App, f: &str, args: Vec<Vec<u8>>| {
        let tx = app.tx(f, args);
        app.chain.executor.simulate(&tx)
    };
    assert_eq!(sim(&mut app, "mine", vec![]).unwrap().returns, vec![num(2)]);
    assert_eq!(
        sim(&mut app, "who", vec![]).unwrap().returns,
        vec![ViewValue::Address(app.owner())]
    );
    assert_eq!(
        sim(&mut app, "pair", vec![]).unwrap().returns,
        vec![num(7), ViewValue::Bool(true)]
    );
    assert_eq!(
        sim(&mut app, "bytes", vec![]).unwrap().returns,
        vec![ViewValue::Vector(vec![num(104), num(105)])]
    );
    assert_eq!(
        sim(&mut app, "nested", vec![]).unwrap().returns,
        vec![ViewValue::Vector(vec![
            ViewValue::Vector(vec![num(1), num(2)]),
            ViewValue::Vector(vec![])
        ])]
    );
    // Someone else's drawer, read by a view: the address must be declared, as for a call.
    let stranger = Address::from_bytes([61; 32]);
    let arg = vec![owner.as_bytes().to_vec()];
    let mut tx = app.tx("total", arg.clone());
    let plain = app.chain.executor.simulate(&tx);
    // The sender is the owner here, so this one is allowed; a different sender is not.
    assert_eq!(plain.unwrap().returns, vec![num(2)]);
    let mut other = Publisher::new(90);
    tx = other.call(app.package, "app", "total", arg.clone());
    let refused = app.chain.executor.simulate(&tx).unwrap_err();
    assert!(
        matches!(&refused, SimulationFailure::Failed { reason, .. } if reason.contains("code 3")),
        "{refused:?}"
    );
    let mut declared = other.call(app.package, "app", "total", arg);
    declared.body.declared_inputs = vec![owner];
    let declared = other.resign(declared);
    assert_eq!(
        app.chain.executor.simulate(&declared).unwrap().returns,
        vec![num(2)]
    );
    let _ = stranger;
}

#[test]
fn a_simulation_says_how_a_failure_failed() {
    let mut app = deployed();
    let tx = app.tx("aborts", vec![]);
    let failure = app.chain.executor.simulate(&tx).unwrap_err();
    match &failure {
        SimulationFailure::Failed { reason, gas_used } => {
            assert!(reason.contains("aborted with code 77"), "{reason}");
            assert!(*gas_used > 0);
        }
        other => panic!("{other:?}"),
    }
    // An empty drawer is the store's own abort.
    let tx = app.tx("bump", vec![]);
    let failure = app.chain.executor.simulate(&tx).unwrap_err();
    assert!(
        matches!(&failure, SimulationFailure::Failed { reason, .. } if reason.contains("code 1")),
        "{failure:?}"
    );
    // Not callable, not there, wrong arguments, not a package.
    for (f, args, expected) in [
        ("takes_struct", vec![], SimulationFailure::UnknownFunction),
        (
            "nothing_by_this_name",
            vec![],
            SimulationFailure::UnknownFunction,
        ),
        ("total", vec![], SimulationFailure::InvalidArguments),
        (
            "total",
            vec![vec![1, 2, 3]],
            SimulationFailure::InvalidArguments,
        ),
    ] {
        let tx = app.tx(f, args);
        assert_eq!(
            app.chain.executor.simulate(&tx).unwrap_err(),
            expected,
            "{f}"
        );
    }
    let coin = app.owner.tx_with(
        0,
        1_000,
        chain_exec::native::COIN_PACKAGE_ADDRESS,
        "transfer",
        vec![],
    );
    assert_eq!(
        app.chain.executor.simulate(&coin).unwrap_err(),
        SimulationFailure::NotAPackageCall
    );
}

#[test]
fn a_simulation_is_capped_however_much_gas_the_transaction_offers() {
    let mut app = deployed();
    let mut tx = app.tx("spin", vec![]);
    tx.body.gas_limit = chain_types::GasAmount(u64::MAX);
    let started = std::time::Instant::now();
    let failure = app.chain.executor.simulate(&tx).unwrap_err();
    match failure {
        SimulationFailure::Failed { reason, gas_used } => {
            assert!(reason.contains("out of gas"), "{reason}");
            assert!(gas_used <= SIMULATE_MAX_GAS, "{gas_used}");
        }
        other => panic!("{other:?}"),
    }
    // Debug builds run the VM tens of times slower than release; the cap, not the
    // clock, is what is being tested, so the bound is loose.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "it ran far too long"
    );
}

#[test]
fn a_simulation_needs_no_signature_no_sequence_number_and_no_account() {
    let mut app = deployed();
    app.call("init", vec![]);
    // A transaction from someone with no account, a wrong sequence number and a
    // signature that does not match: only its sender and call are read.
    let stranger = Publisher::new(120);
    let mut tx = stranger.tx_with(999, 100_000, app.package, "who", vec![]);
    tx.body.call.module_name = b"app".to_vec();
    tx.signature = app
        .owner
        .tx_with(0, 1, app.package, "who", vec![])
        .signature;
    let sim = app.chain.executor.simulate(&tx).unwrap();
    assert_eq!(
        sim.returns,
        vec![ViewValue::Address(AccountAddress::new(
            *stranger.address().as_bytes()
        ))]
    );
}
