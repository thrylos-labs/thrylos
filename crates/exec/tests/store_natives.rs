//! The `thrylos::store` natives, run in the chain's real runtime against the
//! real framework: round trips, every abort code, gas, and the failures that
//! must never be panics. The rules of the drawers themselves are tested in
//! `crate::drawer`; this is the translation between Move values and bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::Write;
use std::rc::Rc;

use chain_exec::drawer::{
    Access, DrawerOverlay, DrawerValue, CODE_CORRUPT, CODE_EMPTY, CODE_NOT_DECLARED, CODE_OCCUPIED,
    CODE_TOO_LARGE, CODE_TOO_MANY_OPERATIONS, DRAWER_DEPOSIT_PER_KIB, MAX_VALUE_BYTES,
};
use chain_exec::framework::{
    new_runtime, FRAMEWORK_ADDRESS, FRAMEWORK_BUNDLE, STD_ADDRESS, STD_BUNDLE,
};
use chain_exec::keys::{drawer_key, package_key};
use chain_exec::module_resolver::ChainStateModuleResolver;
use chain_exec::native::NEW_ENTRY_STORAGE_DEPOSIT;
use chain_exec::store::StoreExtension;
use chain_state::{StateKey, StateValue};
use chain_types::codec::Encode;
use move_binary_format::errors::VMError;
use move_binary_format::file_format::CompiledModule;
use move_compiler::shared::{NumberFormat, NumericalAddress, PackagePaths};
use move_compiler::Compiler;
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_core_types::vm_status::StatusCode;
use move_vm_runtime::dev_utils::gas_schedule::Gas;
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::natives::extensions::NativeContextExtensions;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;

const SOURCE: &str = "
module pkg::app {
    use thrylos::store;

    public struct Counter has key, store, copy, drop { n: u64 }
    public struct Inner has store, copy, drop { a: u8, b: u128, c: vector<u16> }
    public struct Rich has key, store, copy, drop {
        owner: address, data: vector<u8>, inner: Inner, maybe: Option<u64>, flags: vector<bool>,
    }
    public struct Wrapper<T: store> has key, store, copy, drop { v: T }
    public enum Kind has key, store, copy, drop { A, B(u64), C { x: bool, y: vector<u8> } }
    public struct Blob has key, store { data: vector<u8> }
    public struct Linear has key, store { n: u64 }

    // Seventeen sub-structs of 32 fields each: more layout nodes than the VM will build.
    public struct Wide has store, copy, drop {
        f0: u8, f1: u8, f2: u8, f3: u8, f4: u8, f5: u8, f6: u8, f7: u8, f8: u8, f9: u8, f10: u8,
        f11: u8, f12: u8, f13: u8, f14: u8, f15: u8, f16: u8, f17: u8, f18: u8, f19: u8, f20: u8,
        f21: u8, f22: u8, f23: u8, f24: u8, f25: u8, f26: u8, f27: u8, f28: u8, f29: u8, f30: u8, f31: u8,
    }
    public struct Huge has key, store, copy, drop {
        a0: Wide, a1: Wide, a2: Wide, a3: Wide, a4: Wide, a5: Wide, a6: Wide, a7: Wide, a8: Wide,
        a9: Wide, a10: Wide, a11: Wide, a12: Wide, a13: Wide, a14: Wide, a15: Wide, a16: Wide,
    }
    fun wide(): Wide {
        Wide { f0: 0, f1: 0, f2: 0, f3: 0, f4: 0, f5: 0, f6: 0, f7: 0, f8: 0, f9: 0, f10: 0,
               f11: 0, f12: 0, f13: 0, f14: 0, f15: 0, f16: 0, f17: 0, f18: 0, f19: 0, f20: 0,
               f21: 0, f22: 0, f23: 0, f24: 0, f25: 0, f26: 0, f27: 0, f28: 0, f29: 0, f30: 0, f31: 0 }
    }
    entry fun put_huge(o: address) {
        store::put(o, 0, Huge { a0: wide(), a1: wide(), a2: wide(), a3: wide(), a4: wide(), a5: wide(),
            a6: wide(), a7: wide(), a8: wide(), a9: wide(), a10: wide(), a11: wide(), a12: wide(),
            a13: wide(), a14: wide(), a15: wide(), a16: wide() });
    }

    entry fun init_counter(o: address) { store::put(o, 0, Counter { n: 41 }); }
    entry fun bump(o: address) {
        let mut c = store::take<Counter>(o, 0);
        c.n = c.n + 1;
        store::put(o, 0, c);
    }
    entry fun check_counter(o: address, want: u64) { assert!(store::read<Counter>(o, 0).n == want, 100); }
    entry fun take_empty(o: address) { let _c = store::take<Counter>(o, 0); }
    entry fun read_empty(o: address) { let _c = store::read<Counter>(o, 0); }
    entry fun put_twice(o: address) {
        store::put(o, 0, Counter { n: 1 });
        store::put(o, 0, Counter { n: 2 });
    }
    entry fun has_cycle(o: address) {
        assert!(!store::has<Counter>(o, 3), 1);
        store::put(o, 3, Counter { n: 5 });
        assert!(store::has<Counter>(o, 3), 2);
        let _c = store::take<Counter>(o, 3);
        assert!(!store::has<Counter>(o, 3), 4);
    }
    entry fun many_has(o: address, n: u64) {
        let mut i = 0;
        while (i < n) { store::has<Counter>(o, 0); i = i + 1; };
    }
    entry fun many_puts(o: address, n: u64) {
        let mut i = 0;
        while (i < n) { store::put(o, i, Counter { n: i }); i = i + 1; };
    }
    entry fun rich_roundtrip(o: address) {
        let want = Rich {
            owner: @0xabc, data: b\"hello\", inner: Inner { a: 7, b: 1 << 100, c: vector[1, 2, 3] },
            maybe: option::some(9), flags: vector[true, false, true],
        };
        store::put(o, 0, want);
        let got = store::take<Rich>(o, 0);
        assert!(got.owner == @0xabc && got.data == b\"hello\", 1);
        assert!(got.inner.a == 7 && got.inner.b == (1 << 100) && got.inner.c == vector[1, 2, 3], 2);
        assert!(got.maybe == option::some(9) && got.flags == vector[true, false, true], 3);
        store::put(o, 0, got);
    }
    entry fun generics(o: address) {
        store::put(o, 0, Wrapper<u64> { v: 5 });
        store::put(o, 0, Wrapper<Inner> { v: Inner { a: 1, b: 2, c: vector[] } });
        assert!(store::take<Wrapper<u64>>(o, 0).v == 5, 1);
        assert!(store::take<Wrapper<Inner>>(o, 0).v.b == 2, 2);
    }
    entry fun enums(o: address) {
        store::put(o, 0, Kind::A);
        store::put(o, 1, Kind::B(77));
        store::put(o, 2, Kind::C { x: true, y: b\"z\" });
        assert!(store::take<Kind>(o, 0) == Kind::A, 1);
        assert!(store::take<Kind>(o, 1) == Kind::B(77), 2);
        assert!(store::take<Kind>(o, 2) == Kind::C { x: true, y: b\"z\" }, 3);
    }
    entry fun linear(o: address) {
        store::put(o, 0, Linear { n: 8 });
        let Linear { n } = store::take<Linear>(o, 0);
        assert!(n == 8, 1);
    }
    fun blob(n: u64): Blob {
        let mut data = vector[];
        let mut i = 0;
        while (i < n) { data.push_back(1); i = i + 1; };
        Blob { data }
    }
    entry fun put_blob(o: address, slot: u64, n: u64) { store::put(o, slot, blob(n)); }
    // The same work as `put_blob`, without the store: what the native adds is the difference.
    entry fun build_blob(n: u64) { let Blob { data: _ } = blob(n); }
}
";

fn numerical(last: u8) -> NumericalAddress {
    let mut bytes = [0u8; 32];
    bytes[31] = last;
    NumericalAddress::new(bytes, NumberFormat::Hex)
}

fn sources(package: &str) -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../move");
    let mut files: Vec<String> = std::fs::read_dir(root.join(package).join("sources"))
        .unwrap()
        .map(|e| e.unwrap().path().to_str().unwrap().to_string())
        .collect();
    files.sort();
    files
}

fn compile_app() -> Vec<CompiledModule> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.move");
    writeln!(std::fs::File::create(&path).unwrap(), "{SOURCE}").unwrap();
    let map = BTreeMap::from([
        ("std".to_string(), numerical(1)),
        ("thrylos".to_string(), numerical(2)),
        ("pkg".to_string(), numerical(0)),
    ]);
    let mut deps = sources("stdlib");
    deps.extend(sources("framework"));
    let compiler = Compiler::from_package_paths(
        None,
        vec![PackagePaths {
            name: None,
            paths: vec![path.to_str().unwrap().to_string()],
            named_address_map: map.clone(),
        }],
        vec![PackagePaths {
            name: None,
            paths: deps,
            named_address_map: map,
        }],
    )
    .unwrap();
    let (files, result) = compiler.build().unwrap();
    match result {
        Ok((units, _)) => units.into_iter().map(|u| u.named_module.module).collect(),
        Err(d) => panic!(
            "the test package does not compile:\n{}",
            String::from_utf8_lossy(&move_compiler::diagnostics::report_diagnostics_to_buffer(
                &files, d, false
            ))
        ),
    }
}

struct World {
    state: BTreeMap<StateKey, StateValue>,
    runtime: MoveRuntime,
}

fn world() -> World {
    let modules = compile_app();
    let mut by_name: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for m in &modules {
        let mut bytes = Vec::new();
        m.serialize_with_version(m.version, &mut bytes).unwrap();
        by_name.insert(m.self_id().name().to_string(), bytes);
    }
    let ordered: Vec<Vec<u8>> = by_name.into_values().collect();
    let mut bundle = Vec::new();
    ordered.encode(&mut bundle);
    // Real system packages: what genesis holds.
    let state = BTreeMap::from([
        (
            package_key(STD_ADDRESS),
            StateValue::new(STD_BUNDLE.to_vec()),
        ),
        (
            package_key(FRAMEWORK_ADDRESS),
            StateValue::new(FRAMEWORK_BUNDLE.to_vec()),
        ),
        (package_key(AccountAddress::ZERO), StateValue::new(bundle)),
    ]);
    World {
        state,
        runtime: new_runtime().unwrap(),
    }
}

fn addr(n: u8) -> AccountAddress {
    let mut b = [0u8; 32];
    b[31] = n;
    AccountAddress::new(b)
}

const SENDER: u8 = 1;

const PINNED: [(&str, u64); 7] = [
    ("put 101 bytes", 117),
    ("put 8,002 bytes", 8839),
    ("put a counter", 6),
    ("read a counter", 6),
    ("take and put a counter", 12),
    ("has, put, has, has, take, has", 26),
    ("build 8,000 bytes without the store", 8354),
];

struct Ran {
    result: Result<(), VMError>,
    changes: Vec<(StateKey, Option<StateValue>)>,
    deposit: u128,
    gas: u64,
}

/// Run `function` of `app` as `SENDER`, against `drawers`, with `gas`.
fn run_with(
    world: &World,
    drawers: &BTreeMap<StateKey, StateValue>,
    declared: Vec<AccountAddress>,
    function: &str,
    arguments: Vec<Value>,
    gas: u64,
) -> Ran {
    let resolver = ChainStateModuleResolver::new(&world.state);
    let package = resolver.package(AccountAddress::ZERO).unwrap().unwrap();
    let linkage = LinkageContext::new(package.linkage_table.clone()).unwrap();
    let extensions = Rc::new(RefCell::new(NativeContextExtensions::default()));
    extensions.borrow_mut().add(StoreExtension {
        overlay: DrawerOverlay::new(
            drawers,
            Access {
                sender: addr(SENDER),
                declared,
                unrestricted: false,
            },
        ),
    });
    let mut vm = world
        .runtime
        .make_vm_with_native_extensions(
            ChainStateModuleResolver::new(&world.state),
            linkage,
            extensions.clone(),
        )
        .unwrap();
    let module = ModuleId::new(AccountAddress::ZERO, Identifier::new("app").unwrap());
    let mut meter = chain_exec::gas::ChainGas::new(Gas::new(gas));
    let result = vm
        .execute_function_bypass_visibility(
            &module,
            &Identifier::new(function).unwrap(),
            vec![],
            arguments,
            &mut meter,
            None,
        )
        .map(|_| ());
    let used = gas - u64::from(meter.remaining_gas());
    drop(vm);
    let store = extensions.borrow_mut().remove::<StoreExtension>().unwrap();
    Ran {
        result,
        changes: store.overlay.changes(),
        deposit: store.overlay.deposit(),
        gas: used,
    }
}

fn run(
    world: &World,
    drawers: &BTreeMap<StateKey, StateValue>,
    function: &str,
    arguments: Vec<Value>,
) -> Ran {
    run_with(world, drawers, vec![], function, arguments, 100_000_000)
}

fn apply(
    drawers: &mut BTreeMap<StateKey, StateValue>,
    changes: Vec<(StateKey, Option<StateValue>)>,
) {
    for (k, v) in changes {
        match v {
            Some(v) => {
                drawers.insert(k, v);
            }
            None => {
                drawers.remove(&k);
            }
        }
    }
}

fn mine() -> Value {
    Value::address(addr(SENDER))
}

fn aborted_with(ran: &Ran, code: u64) {
    let err = ran.result.as_ref().unwrap_err();
    assert_eq!(err.major_status(), StatusCode::ABORTED, "{err:?}");
    assert_eq!(err.sub_status(), Some(code), "{err:?}");
    // From the store module, not from the package.
    match err.location() {
        move_binary_format::errors::Location::Module(id) => {
            assert_eq!(
                (*id.address(), id.name().as_str()),
                (FRAMEWORK_ADDRESS, "store")
            )
        }
        other => panic!("{other:?}"),
    }
}

// ---- values and bytes ------------------------------------------------------

#[test]
fn a_counter_survives_calls_as_one_drawer_of_eight_bytes() {
    let w = world();
    let mut drawers = BTreeMap::new();
    for f in ["init_counter", "bump", "bump"] {
        let ran = run(&w, &drawers, f, vec![mine()]);
        ran.result.unwrap_or_else(|e| panic!("{f}: {e:?}"));
        apply(&mut drawers, ran.changes);
    }
    run(&w, &drawers, "check_counter", vec![mine(), Value::u64(43)])
        .result
        .unwrap();
    assert!(
        run(&w, &drawers, "check_counter", vec![mine(), Value::u64(42)])
            .result
            .is_err()
    );
    assert_eq!(drawers.len(), 1);
    let (key, stored) = drawers.iter().next().unwrap();
    let drawer = DrawerValue::from_state(stored).unwrap();
    assert_eq!(drawer.bytes, 43u64.to_le_bytes());
    assert_eq!(
        drawer.type_name,
        format!("0x{}::app::Counter", "0".repeat(64))
    );
    assert_eq!(*key, drawer_key(addr(SENDER), 0, &drawer.type_name));
}

#[test]
fn structs_options_vectors_generics_enums_and_linear_values_round_trip() {
    let w = world();
    for f in ["rich_roundtrip", "generics", "enums", "linear", "has_cycle"] {
        let ran = run(&w, &BTreeMap::new(), f, vec![mine()]);
        ran.result.unwrap_or_else(|e| panic!("{f}: {e:?}"));
    }
    // `rich_roundtrip` puts its value back: that is the one drawer left.
    let ran = run(&w, &BTreeMap::new(), "rich_roundtrip", vec![mine()]);
    assert_eq!(ran.changes.len(), 1);
}

#[test]
fn the_same_calls_write_the_same_bytes_every_time() {
    let a = world();
    let b = world();
    for f in ["rich_roundtrip", "enums", "generics"] {
        let x = run(&a, &BTreeMap::new(), f, vec![mine()]);
        let y = run(&b, &BTreeMap::new(), f, vec![mine()]);
        assert_eq!(x.changes, y.changes, "{f}");
        assert_eq!(x.gas, y.gas, "{f}");
    }
}

// ---- the abort codes -------------------------------------------------------

#[test]
fn an_empty_drawer_an_occupied_one_and_an_undeclared_owner_abort_with_their_codes() {
    let w = world();
    aborted_with(
        &run(&w, &BTreeMap::new(), "take_empty", vec![mine()]),
        CODE_EMPTY,
    );
    aborted_with(
        &run(&w, &BTreeMap::new(), "read_empty", vec![mine()]),
        CODE_EMPTY,
    );
    aborted_with(
        &run(&w, &BTreeMap::new(), "put_twice", vec![mine()]),
        CODE_OCCUPIED,
    );
    // Someone else's drawer, not declared; then declared.
    let other = Value::address(addr(9));
    aborted_with(
        &run(
            &w,
            &BTreeMap::new(),
            "init_counter",
            vec![other.copy_value()],
        ),
        CODE_NOT_DECLARED,
    );
    let ran = run_with(
        &w,
        &BTreeMap::new(),
        vec![addr(9)],
        "init_counter",
        vec![other],
        100_000_000,
    );
    ran.result.unwrap();
    assert_eq!(ran.changes.len(), 1);
}

#[test]
fn the_sixty_fifth_operation_and_the_seventeenth_drawer_abort() {
    let w = world();
    run(
        &w,
        &BTreeMap::new(),
        "many_has",
        vec![mine(), Value::u64(64)],
    )
    .result
    .unwrap();
    aborted_with(
        &run(
            &w,
            &BTreeMap::new(),
            "many_has",
            vec![mine(), Value::u64(65)],
        ),
        CODE_TOO_MANY_OPERATIONS,
    );
    run(
        &w,
        &BTreeMap::new(),
        "many_puts",
        vec![mine(), Value::u64(16)],
    )
    .result
    .unwrap();
    aborted_with(
        &run(
            &w,
            &BTreeMap::new(),
            "many_puts",
            vec![mine(), Value::u64(17)],
        ),
        CODE_TOO_MANY_OPERATIONS,
    );
}

#[test]
fn a_value_over_the_size_limit_aborts_and_one_at_the_limit_is_stored() {
    let w = world();
    // A `Blob` is its bytes plus a length prefix of a few bytes.
    let fits = (MAX_VALUE_BYTES - 2) as u64;
    let ran = run(
        &w,
        &BTreeMap::new(),
        "put_blob",
        vec![mine(), Value::u64(0), Value::u64(fits)],
    );
    ran.result.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ran.changes.len(), 1);
    let over = run(
        &w,
        &BTreeMap::new(),
        "put_blob",
        vec![mine(), Value::u64(0), Value::u64(fits + 100)],
    );
    aborted_with(&over, CODE_TOO_LARGE);
    assert!(over.changes.is_empty(), "an aborted put wrote nothing");
}

#[test]
fn a_type_too_large_for_the_vm_to_lay_out_aborts_with_too_large_and_does_not_panic() {
    let w = world();
    aborted_with(
        &run(&w, &BTreeMap::new(), "put_huge", vec![mine()]),
        CODE_TOO_LARGE,
    );
}

// ---- gas -------------------------------------------------------------------

/// Gas is consensus: every node must charge the same, so the cost of each store
/// operation is pinned to the unit. If one of these numbers changes, the charge
/// (or the VM's own schedule under it) changed, and so did the rules of the chain.
#[test]
fn the_gas_of_store_operations_is_pinned() {
    let w = world();
    let cost = |drawers: &BTreeMap<StateKey, StateValue>, f: &str, args: Vec<Value>| {
        let ran = run(&w, drawers, f, args);
        ran.result.unwrap_or_else(|e| panic!("{f}: {e:?}"));
        (ran.gas, ran.changes)
    };
    let blob = |n: u64| vec![mine(), Value::u64(0), Value::u64(n)];
    let mut got = Vec::new();
    let (g, _) = cost(&BTreeMap::new(), "put_blob", blob(100));
    got.push(("put 101 bytes", g));
    let (g, _) = cost(&BTreeMap::new(), "put_blob", blob(8_000));
    got.push(("put 8,002 bytes", g));
    let (g, c) = cost(&BTreeMap::new(), "init_counter", vec![mine()]);
    got.push(("put a counter", g));
    let mut drawers = BTreeMap::new();
    apply(&mut drawers, c);
    let (g, _) = cost(&drawers, "check_counter", vec![mine(), Value::u64(41)]);
    got.push(("read a counter", g));
    let (g, _) = cost(&drawers, "bump", vec![mine()]);
    got.push(("take and put a counter", g));
    let (g, _) = cost(&BTreeMap::new(), "has_cycle", vec![mine()]);
    got.push(("has, put, has, has, take, has", g));
    let (g, _) = cost(&BTreeMap::new(), "build_blob", vec![Value::u64(8_000)]);
    got.push(("build 8,000 bytes without the store", g));
    let expected: [(&str, u64); 7] = PINNED;
    assert_eq!(
        got.iter().map(|(w, g)| (*w, *g)).collect::<Vec<_>>(),
        expected.to_vec()
    );
}

#[test]
fn the_first_deposit_of_a_new_drawer_is_reported_with_the_call() {
    let w = world();
    let ran = run(&w, &BTreeMap::new(), "init_counter", vec![mine()]);
    ran.result.unwrap();
    assert_eq!(
        ran.deposit,
        NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB
    );
}

#[test]
fn a_native_that_runs_out_of_gas_ends_the_call_cleanly() {
    let w = world();
    let ran = run_with(
        &w,
        &BTreeMap::new(),
        vec![],
        "put_blob",
        vec![mine(), Value::u64(0), Value::u64(3)],
        3,
    );
    let err = ran.result.unwrap_err();
    assert_eq!(err.major_status(), StatusCode::OUT_OF_GAS, "{err:?}");
    assert!(ran.changes.is_empty());
}

// ---- damaged state ----------------------------------------------------------

#[test]
fn a_damaged_drawer_aborts_with_the_corrupt_code() {
    let w = world();
    let name = format!("0x{}::app::Counter", "0".repeat(64));
    let drawers = BTreeMap::from([(
        drawer_key(addr(SENDER), 0, &name),
        StateValue::new(vec![1, 2, 3]),
    )]);
    aborted_with(
        &run(&w, &drawers, "check_counter", vec![mine(), Value::u64(1)]),
        CODE_CORRUPT,
    );
    // A stored value whose bytes do not fit the type is damage too.
    let short = DrawerValue::new(name.clone(), vec![1, 2, 3])
        .unwrap()
        .to_state();
    let drawers = BTreeMap::from([(drawer_key(addr(SENDER), 0, &name), short)]);
    aborted_with(
        &run(&w, &drawers, "check_counter", vec![mine(), Value::u64(1)]),
        CODE_CORRUPT,
    );
}
