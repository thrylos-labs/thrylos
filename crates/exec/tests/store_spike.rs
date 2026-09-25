//! SPIKE for `docs/move-storage-design.md` (stage 2): can a native function
//! store and load a Move value by its type argument, through an extension that
//! borrows the state? Throwaway evidence, not the implementation: the real
//! store replaces this. It answers the design's two open questions:
//!
//! 1. Do `Value::typed_serialize` / `simple_deserialize` and the layout from a
//!    native's type argument round-trip real values (structs, nested structs,
//!    generics, enums, vectors, options), deterministically?
//! 2. Does the pinned compiler accept `has key` on a struct with no `UID`?
//!
//! Plus what an abort raised by a native looks like to the caller.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::type_complexity
)]

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::rc::Rc;
use std::sync::Arc;

use better_any::{Tid, TidAble};
use chain_exec::framework::{
    native_table, FRAMEWORK_ADDRESS, FRAMEWORK_BUNDLE, STD_ADDRESS, STD_BUNDLE,
};
use chain_exec::keys::package_key;
use chain_exec::module_resolver::ChainStateModuleResolver;
use chain_state::{StateKey, StateValue};
use chain_types::codec::Encode;
use move_binary_format::errors::PartialVMResult;
use move_binary_format::file_format::CompiledModule;
use move_compiler::shared::{NumberFormat, NumericalAddress, PackagePaths};
use move_compiler::Compiler;
use move_core_types::account_address::AccountAddress;
use move_core_types::gas_algebra::InternalGas;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_vm_runtime::dev_utils::gas_schedule::{Gas, GasStatus, INITIAL_COST_SCHEDULE};
use move_vm_runtime::execution::values::Value;
use move_vm_runtime::execution::Type;
use move_vm_runtime::natives::extensions::{NativeContextExtensions, NativeExtensionMarker};
use move_vm_runtime::natives::functions::{
    make_table, NativeContext, NativeFunction, NativeFunctions, NativeResult,
};
use move_vm_runtime::pop_arg;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;
use smallvec::smallvec;

// ---- the extension: a borrowed base and a write overlay -------------------

type DrawerKey = (AccountAddress, u64, String);

/// What the real store would hold: the state as the call found it (borrowed,
/// which is the point of the test) and this call's writes.
#[derive(Tid)]
struct StoreView<'a> {
    base: &'a BTreeMap<DrawerKey, Vec<u8>>,
    overlay: BTreeMap<DrawerKey, Option<Vec<u8>>>,
}

impl<'a> NativeExtensionMarker<'a> for StoreView<'a> {}

impl StoreView<'_> {
    fn get(&self, key: &DrawerKey) -> Option<Vec<u8>> {
        match self.overlay.get(key) {
            Some(written) => written.clone(),
            None => self.base.get(key).cloned(),
        }
    }
}

const EMPTY: u64 = 1;
const OCCUPIED: u64 = 2;

fn charge(context: &NativeContext, cost: u64) -> PartialVMResult<bool> {
    context.charge_gas(InternalGas::new(cost))
}

fn key_of(
    context: &NativeContext,
    ty: &Type,
    owner: AccountAddress,
    slot: u64,
) -> PartialVMResult<DrawerKey> {
    let tag = context.type_to_type_tag(ty)?;
    Ok((owner, slot, tag.to_canonical_string(true)))
}

fn native(
    body: fn(&mut NativeContext, Vec<Type>, VecDeque<Value>) -> PartialVMResult<NativeResult>,
) -> NativeFunction {
    Arc::new(body)
}

fn put(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let value = args.pop_back().expect("the value argument");
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    if !charge(context, 2_000)? {
        return Ok(NativeResult::err(context.gas_budget(), 0));
    }
    let ty = ty_args.first().unwrap();
    let key = key_of(context, ty, owner, slot)?;
    let layout = context
        .type_to_type_layout(ty)?
        .expect("a layout for the stored type");
    let bytes = value
        .typed_serialize(&layout)
        .expect("a value serialises with its own layout");
    let view = context.extensions_mut().get_mut::<StoreView>()?;
    if view.get(&key).is_some() {
        return Ok(NativeResult::err(context.gas_used(), OCCUPIED));
    }
    let view = context.extensions_mut().get_mut::<StoreView>()?;
    view.overlay.insert(key, Some(bytes));
    Ok(NativeResult::ok(context.gas_used(), smallvec![]))
}

fn load(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
    remove: bool,
) -> PartialVMResult<NativeResult> {
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    if !charge(context, 2_000)? {
        return Ok(NativeResult::err(context.gas_budget(), 0));
    }
    let ty = ty_args.first().unwrap();
    let key = key_of(context, ty, owner, slot)?;
    let layout = context
        .type_to_type_layout(ty)?
        .expect("a layout for the stored type");
    let view = context.extensions_mut().get_mut::<StoreView>()?;
    let Some(bytes) = view.get(&key) else {
        return Ok(NativeResult::err(context.gas_used(), EMPTY));
    };
    if remove {
        view.overlay.insert(key, None);
    }
    let value =
        Value::simple_deserialize(&bytes, &layout).expect("stored bytes read back with the layout");
    Ok(NativeResult::ok(context.gas_used(), smallvec![value]))
}

fn take(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    load(context, ty_args, args, true)
}

fn read(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    load(context, ty_args, args, false)
}

fn has(
    context: &mut NativeContext,
    ty_args: Vec<Type>,
    mut args: VecDeque<Value>,
) -> PartialVMResult<NativeResult> {
    let slot = pop_arg!(args, u64);
    let owner = pop_arg!(args, AccountAddress);
    let key = key_of(context, ty_args.first().unwrap(), owner, slot)?;
    let there = context.extensions().get::<StoreView>()?.get(&key).is_some();
    Ok(NativeResult::ok(
        InternalGas::new(1_000),
        smallvec![Value::bool(there)],
    ))
}

// ---- the Move side --------------------------------------------------------

const STORE_MOVE: &str = "
module thrylos::store;
public native fun put<T: key>(owner: address, slot: u64, value: T);
public native fun take<T: key>(owner: address, slot: u64): T;
public native fun has<T: key>(owner: address, slot: u64): bool;
public native fun read<T: key + copy>(owner: address, slot: u64): T;
";

const SPIKE_MOVE: &str = "
module pkg::other {
    public struct Theirs has key, store { n: u64 }
    public fun make(): Theirs { Theirs { n: 1 } }
}

module pkg::spike {
use thrylos::store;

// `key` with no UID field: the question in the design.
public struct Counter has key, store, copy, drop { n: u64 }
public struct Inner has store, copy, drop { a: u8, b: u128, c: vector<u16> }
public struct Rich has key, store, copy, drop {
    owner: address, data: vector<u8>, inner: Inner, maybe: Option<u64>, flags: vector<bool>,
}
public struct Wrapper<T: store> has key, store, copy, drop { v: T }
public enum Kind has key, store, copy, drop { A, B(u64), C { x: bool, y: vector<u8> } }
public struct Linear has key, store { n: u64 }

entry fun init_counter(o: address) { store::put(o, 0, Counter { n: 41 }); }
entry fun bump(o: address) {
    let mut c = store::take<Counter>(o, 0);
    c.n = c.n + 1;
    store::put(o, 0, c);
}
entry fun check_counter(o: address, want: u64) { assert!(store::read<Counter>(o, 0).n == want, 100); }

entry fun take_twice(o: address) {
    let _a = store::take<Counter>(o, 0);
    let _b = store::take<Counter>(o, 0);
}
entry fun put_twice(o: address) {
    store::put(o, 0, Counter { n: 1 });
    store::put(o, 0, Counter { n: 2 });
}
entry fun has_cycle(o: address) {
    assert!(!store::has<Counter>(o, 3), 1);
    store::put(o, 3, Counter { n: 5 });
    assert!(store::has<Counter>(o, 3), 2);
    assert!(!store::has<Counter>(o, 4), 3);
    let _c = store::take<Counter>(o, 3);
    assert!(!store::has<Counter>(o, 3), 4);
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
entry fun leave_two(o: address) {
    store::put(o, 0, Counter { n: 1 });
    store::put(o, 1, Counter { n: 2 });
    store::put(o, 0, Wrapper<u64> { v: 3 });
}

public fun put_any<T: key>(o: address, v: T) { store::put(o, 0, v); }
public fun put_foreign(o: address) { store::put(o, 0, pkg::other::make()); }
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

fn compile(
    dir: &std::path::Path,
    name: &str,
    text: &str,
    deps: Vec<String>,
    package_address: u8,
) -> Result<Vec<CompiledModule>, String> {
    let path = dir.join(name);
    writeln!(std::fs::File::create(&path).unwrap(), "{text}").unwrap();
    let map = BTreeMap::from([
        ("std".to_string(), numerical(1)),
        ("thrylos".to_string(), numerical(2)),
        ("pkg".to_string(), numerical(package_address)),
    ]);
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
    .map_err(|e| e.to_string())?;
    let (files, result) = compiler.build().map_err(|e| e.to_string())?;
    match result {
        Ok((units, _)) => Ok(units.into_iter().map(|u| u.named_module.module).collect()),
        Err(d) => Err(String::from_utf8_lossy(
            &move_compiler::diagnostics::report_diagnostics_to_buffer(&files, d, false),
        )
        .into_owned()),
    }
}

fn bundle(modules: &[CompiledModule]) -> StateValue {
    let mut by_name: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for m in modules {
        let mut bytes = Vec::new();
        m.serialize_with_version(m.version, &mut bytes).unwrap();
        by_name.insert(m.self_id().name().to_string(), bytes);
    }
    let ordered: Vec<Vec<u8>> = by_name.into_values().collect();
    let mut out = Vec::new();
    ordered.encode(&mut out);
    StateValue::new(out)
}

struct World {
    state: BTreeMap<StateKey, StateValue>,
    runtime: MoveRuntime,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let mut deps = sources("stdlib");
    deps.extend(sources("framework"));
    // `thrylos::store`, at 0x2, joined to the framework.
    let store = compile(dir.path(), "store.move", STORE_MOVE, deps.clone(), 0)
        .expect("the store module compiles");
    let mut framework_modules: Vec<CompiledModule> =
        chain_types::codec::decode_exact::<Vec<Vec<u8>>>(FRAMEWORK_BUNDLE)
            .unwrap()
            .iter()
            .map(|b| CompiledModule::deserialize_with_defaults(b).unwrap())
            .collect();
    framework_modules.extend(store);
    // The user's package, compiled against the store.
    let store_source = dir.path().join("store.move").to_str().unwrap().to_string();
    let mut user_deps = deps;
    user_deps.push(store_source);
    let spike = compile(dir.path(), "spike.move", SPIKE_MOVE, user_deps, 0)
        .unwrap_or_else(|e| panic!("the spike package does not compile:\n{e}"));

    let mut state = BTreeMap::new();
    state.insert(
        package_key(STD_ADDRESS),
        StateValue::new(STD_BUNDLE.to_vec()),
    );
    state.insert(package_key(FRAMEWORK_ADDRESS), bundle(&framework_modules));
    state.insert(package_key(AccountAddress::ZERO), bundle(&spike));

    let mut table = native_table();
    table.extend(make_table(
        FRAMEWORK_ADDRESS,
        [
            ("store", "put", native(put)),
            ("store", "take", native(take)),
            ("store", "has", native(has)),
            ("store", "read", native(read)),
        ],
    ));
    let runtime = MoveRuntime::new(
        NativeFunctions::new(table).unwrap(),
        chain_exec::move_config::vm_config(),
    );
    World { state, runtime }
}

/// Run `function` of the spike module with `arguments`, against `base`; return
/// the outcome and the overlay the call wrote.
fn call(
    world: &World,
    base: &BTreeMap<DrawerKey, Vec<u8>>,
    function: &str,
    arguments: Vec<Value>,
) -> (
    Result<(), move_binary_format::errors::VMError>,
    BTreeMap<DrawerKey, Option<Vec<u8>>>,
    u64,
) {
    let resolver = ChainStateModuleResolver::new(&world.state);
    let package = resolver.package(AccountAddress::ZERO).unwrap().unwrap();
    let linkage = LinkageContext::new(package.linkage_table.clone()).unwrap();
    let extensions = Rc::new(RefCell::new(NativeContextExtensions::default()));
    extensions.borrow_mut().add(StoreView {
        base,
        overlay: BTreeMap::new(),
    });
    let mut vm = world
        .runtime
        .make_vm_with_native_extensions(
            ChainStateModuleResolver::new(&world.state),
            linkage,
            extensions.clone(),
        )
        .unwrap();
    let module = ModuleId::new(AccountAddress::ZERO, Identifier::new("spike").unwrap());
    let mut meter = GasStatus::new(&INITIAL_COST_SCHEDULE, Gas::new(1_000_000));
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
    let used = 1_000_000 - u64::from(meter.remaining_gas());
    drop(vm);
    let view = extensions.borrow_mut().remove::<StoreView>().unwrap();
    (result, view.overlay, used)
}

fn addr(n: u8) -> AccountAddress {
    let mut b = [0u8; 32];
    b[31] = n;
    AccountAddress::new(b)
}

fn apply(base: &mut BTreeMap<DrawerKey, Vec<u8>>, overlay: BTreeMap<DrawerKey, Option<Vec<u8>>>) {
    for (k, v) in overlay {
        match v {
            Some(bytes) => {
                base.insert(k, bytes);
            }
            None => {
                base.remove(&k);
            }
        }
    }
}

// ---- the questions --------------------------------------------------------

#[test]
fn a_struct_with_key_and_no_uid_compiles_and_a_counter_survives_calls() {
    let w = world();
    let mut base = BTreeMap::new();
    let a = addr(0xaa);
    for f in ["init_counter", "bump", "bump"] {
        let (r, overlay, gas) = call(&w, &base, f, vec![Value::address(a)]);
        r.unwrap_or_else(|e| panic!("{f}: {e:?}"));
        eprintln!("{f}: gas {gas}, wrote {} drawer(s)", overlay.len());
        apply(&mut base, overlay);
    }
    let (r, _, _) = call(
        &w,
        &base,
        "check_counter",
        vec![Value::address(a), Value::u64(43)],
    );
    r.unwrap();
    let (r, _, _) = call(
        &w,
        &base,
        "check_counter",
        vec![Value::address(a), Value::u64(42)],
    );
    assert!(
        r.is_err(),
        "a wrong expectation must fail, so the read is real"
    );
    assert_eq!(base.len(), 1);
    let (key, bytes) = base.iter().next().unwrap();
    eprintln!("drawer key: {key:?}\nstored bytes: {bytes:?}");
    assert_eq!(
        bytes,
        &43u64.to_le_bytes(),
        "BCS of a one-field struct is the field"
    );
    assert!(key.2.ends_with("::spike::Counter"), "{}", key.2);
}

#[test]
fn natives_abort_with_their_own_codes_and_say_where() {
    let w = world();
    let base = BTreeMap::new();
    let (r, _, _) = call(&w, &base, "take_twice", vec![Value::address(addr(1))]);
    let err = r.unwrap_err();
    eprintln!(
        "take on empty: {:?} sub={:?} location={:?}",
        err.major_status(),
        err.sub_status(),
        err.location()
    );
    assert_eq!(err.sub_status(), Some(EMPTY));
    let (r, overlay, _) = call(&w, &base, "put_twice", vec![Value::address(addr(1))]);
    let err = r.unwrap_err();
    eprintln!(
        "put on occupied: {:?} sub={:?} location={:?}",
        err.major_status(),
        err.sub_status(),
        err.location()
    );
    assert_eq!(err.sub_status(), Some(OCCUPIED));
    // The overlay of an aborted call is never applied, so nothing persists.
    let _ = overlay;
}

#[test]
fn has_reports_and_take_empties() {
    let w = world();
    let (r, overlay, _) = call(
        &w,
        &BTreeMap::new(),
        "has_cycle",
        vec![Value::address(addr(2))],
    );
    r.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        overlay.values().filter(|v| v.is_some()).count(),
        0,
        "everything put was taken again"
    );
}

#[test]
fn structs_nested_structs_options_vectors_generics_and_enums_round_trip() {
    let w = world();
    let o = Value::address(addr(3));
    for f in ["rich_roundtrip", "generics", "enums", "linear"] {
        let (r, overlay, gas) = call(&w, &BTreeMap::new(), f, vec![o.copy_value()]);
        r.unwrap_or_else(|e| panic!("{f}: {e:?}"));
        eprintln!(
            "{f}: gas {gas}, left {} drawer(s)",
            overlay.values().filter(|v| v.is_some()).count()
        );
    }
}

#[test]
fn one_owner_and_slot_holds_one_drawer_per_type() {
    let w = world();
    let (r, overlay, _) = call(
        &w,
        &BTreeMap::new(),
        "leave_two",
        vec![Value::address(addr(4))],
    );
    r.unwrap();
    let written: Vec<_> = overlay.iter().filter(|(_, v)| v.is_some()).collect();
    for (k, v) in &written {
        eprintln!("{:?} -> {} bytes", k, v.as_ref().unwrap().len());
    }
    assert_eq!(
        written.len(),
        3,
        "(slot 0, Counter), (slot 1, Counter), (slot 0, Wrapper<u64>)"
    );
}

#[test]
fn the_same_calls_write_the_same_bytes_every_time() {
    let a = world();
    let b = world();
    for f in ["rich_roundtrip", "enums", "leave_two"] {
        let (_, x, _) = call(&a, &BTreeMap::new(), f, vec![Value::address(addr(5))]);
        let (_, y, _) = call(&b, &BTreeMap::new(), f, vec![Value::address(addr(5))]);
        assert_eq!(x, y, "{f}");
    }
}

// ---- the ownership rule (design D7) can be decided from bytecode ----------

/// Every call to a `thrylos::store` function in `module` whose type argument is
/// not a type defined in `module` itself, described for a human.
fn ownership_violations(module: &CompiledModule) -> Vec<String> {
    use move_binary_format::file_format::SignatureToken;
    let mut found = Vec::new();
    for inst in module.function_instantiations() {
        let handle = module.function_handle_at(inst.handle);
        let of = module.module_handle_at(handle.module);
        if *module.address_identifier_at(of.address) != FRAMEWORK_ADDRESS
            || module.identifier_at(of.name).as_str() != "store"
        {
            continue;
        }
        let function = module.identifier_at(handle.name).to_string();
        for token in &module.signature_at(inst.type_parameters).0 {
            let local =
                |datatype| module.datatype_handle_at(datatype).module == module.self_handle_idx();
            let ok = match token {
                SignatureToken::Datatype(d) => local(*d),
                SignatureToken::DatatypeInstantiation(inst) => local(inst.0),
                _ => false,
            };
            if !ok {
                found.push(format!("{function}<{token:?}>"));
            }
        }
    }
    found
}

#[test]
fn the_ownership_rule_is_decidable_by_scanning_function_instantiations() {
    let w = world();
    let bundle: Vec<Vec<u8>> =
        chain_types::codec::decode_exact(w.state[&package_key(AccountAddress::ZERO)].as_bytes())
            .unwrap();
    let mut by_name = BTreeMap::new();
    for bytes in bundle {
        let m = CompiledModule::deserialize_with_defaults(&bytes).unwrap();
        by_name.insert(m.self_id().name().to_string(), m);
    }
    let violations = ownership_violations(&by_name["spike"]);
    for v in &violations {
        eprintln!("violation: {v}");
    }
    // `put_any<T>` (a bare type parameter) and `put<other::Theirs>` are refused;
    // every use of the module's own types (Counter, Rich, Wrapper<u64>, Kind ...) is not.
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(violations
        .iter()
        .any(|v| v.starts_with("put<TypeParameter")));
    assert!(violations.iter().any(|v| v.starts_with("put<Struct")));
    assert!(ownership_violations(&by_name["other"]).is_empty());
}
