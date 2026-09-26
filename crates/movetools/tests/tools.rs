#![allow(clippy::unwrap_used)]

use std::path::Path;

use chain_movetools::{
    build, build_is_stale, check, new_package, run_tests, warnings, write_build, Dependency,
    Options, Outcome,
};
use move_binary_format::file_format::CompiledModule;
use move_core_types::account_address::AccountAddress;

fn write(dir: &Path, file: &str, text: &str) {
    let path = dir.join("sources").join(file);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn package(source: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "m.move", source);
    dir
}

fn options(dir: &Path) -> Options {
    Options {
        dir: dir.to_path_buf(),
        ..Options::default()
    }
}

const GAS: u64 = 10_000_000;

#[test]
fn a_new_package_builds_checks_and_passes_its_own_tests() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("hello");
    new_package(&dir, "hello").unwrap();

    let built = build(&options(&dir)).unwrap();
    assert_eq!(built.modules.keys().collect::<Vec<_>>(), ["hello"]);
    check(&built).unwrap();
    // The tests are compiled out of what is published.
    let module = CompiledModule::deserialize_with_defaults(&built.modules["hello"]).unwrap();
    let functions: Vec<String> = module
        .function_defs()
        .iter()
        .map(|d| {
            module
                .identifier_at(module.function_handle_at(d.function).name)
                .to_string()
        })
        .collect();
    assert!(functions.contains(&"check".to_owned()) && functions.contains(&"add".to_owned()));
    assert!(!functions.contains(&"adds".to_owned()), "{functions:?}");
    // Written where `publish` looks for it.
    let out = write_build(&dir, &built).unwrap();
    assert!(out.join("hello.mv").is_file());

    let report = run_tests(&options(&dir), None, GAS).unwrap();
    assert_eq!(report.passed(), 2, "{report:?}");
    assert!(report.ok());
}

#[test]
fn a_new_package_never_overwrites_and_refuses_bad_names() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("p");
    new_package(&dir, "p").unwrap();
    assert!(new_package(&dir, "p")
        .unwrap_err()
        .contains("already exists"));
    for bad in ["", "Hello", "1abc", "a-b", "a b", "a::b"] {
        assert!(new_package(&root.path().join("x"), bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_failing_test_is_reported_with_why_and_a_passing_one_is_not_blamed() {
    let dir = package(
        "module pkg::m;
         #[test] fun fine() { assert!(1 + 1 == 2, 0); }
         #[test] fun aborts() { assert!(1 + 1 == 3, 42); }
         #[test] #[expected_failure] fun expected_any() { abort 1 }
         #[test] #[expected_failure(abort_code = 7)] fun expected_code() { abort 7 }
         #[test] #[expected_failure(abort_code = 7)] fun wrong_code() { abort 8 }
         #[test] #[expected_failure] fun should_have_failed() {}
         #[test] fun forever() { loop {} }",
    );
    let report = run_tests(&options(dir.path()), None, 100_000).unwrap();
    let by_name = |name: &str| {
        report
            .results
            .iter()
            .find(|r| r.name == format!("m::{name}"))
            .unwrap_or_else(|| panic!("no result for {name}: {report:?}"))
            .outcome
            .clone()
    };
    assert_eq!(by_name("fine"), Outcome::Passed);
    assert_eq!(by_name("expected_any"), Outcome::Passed);
    assert_eq!(by_name("expected_code"), Outcome::Passed);
    match by_name("aborts") {
        Outcome::Failed(why) => assert!(why.contains("42"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(by_name("wrong_code"), Outcome::Failed(_)));
    match by_name("should_have_failed") {
        Outcome::Failed(why) => assert!(why.contains("passed"), "{why}"),
        other => panic!("{other:?}"),
    }
    match by_name("forever") {
        Outcome::Failed(why) => assert!(why.contains("gas"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(!report.ok());
    assert_eq!((report.passed(), report.failed()), (3, 4));
}

#[test]
fn the_filter_selects_by_name() {
    let dir = package(
        "module pkg::m;
         #[test] fun alpha() {}
         #[test] fun beta() {}",
    );
    let report = run_tests(&options(dir.path()), Some("alp"), GAS).unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].name, "m::alpha");
}

#[test]
fn tests_use_the_standard_library_and_the_framework() {
    let dir = package(
        "module pkg::m;
         use std::hash;
         use std::string;
         use thrylos::chain;
         #[test] fun library() {
             let mut v = vector[1u64, 2];
             v.push_back(3);
             assert!(v.length() == 3, 0);
             assert!(hash::sha3_256(b\"x\").length() == 32, 1);
             assert!(string::utf8(b\"abc\").length() == 3, 2);
             let o = option::some(4u64);
             assert!(o.is_some(), 3);
         }
         #[test] fun the_framework_is_there() { assert!(chain::height() == 1, 0); }",
    );
    let report = run_tests(&options(dir.path()), None, GAS).unwrap();
    assert!(report.ok() && report.passed() == 2, "{report:?}");
}

#[test]
fn a_compile_error_is_an_error_with_the_compilers_words_not_an_exit() {
    let dir = package("module pkg::m; fun broken(): u64 { true }");
    let error = build(&options(dir.path())).unwrap_err();
    assert!(error.contains("error"), "{error}");
    assert!(run_tests(&options(dir.path()), None, GAS).is_err());
}

#[test]
fn a_package_with_no_sources_or_no_move_files_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert!(build(&options(dir.path())).unwrap_err().contains("sources"));
    std::fs::create_dir(dir.path().join("sources")).unwrap();
    assert!(build(&options(dir.path()))
        .unwrap_err()
        .contains("no .move files"));
}

#[test]
fn a_dependency_on_a_published_package_builds_and_is_tested_against_its_sources() {
    let lib = tempfile::tempdir().unwrap();
    // The library is written the way it was published: at the address it got.
    write(
        lib.path(),
        "lib.move",
        "module pkg::lib; public fun double(x: u64): u64 { x * 2 }",
    );
    let app = tempfile::tempdir().unwrap();
    write(
        app.path(),
        "app.move",
        "module pkg::app;
         use libdep::lib;
         entry fun run(x: u64) { assert!(lib::double(x) == 10, 1); }
         #[test] fun doubles() { assert!(lib::double(5) == 10, 0); run(5); }",
    );
    let mut opts = options(app.path());
    opts.deps = vec![Dependency {
        name: "libdep".to_owned(),
        dir: lib.path().to_path_buf(),
        address: AccountAddress::new([9; 32]),
    }];

    let built = build(&opts).unwrap();
    // Only this package's own modules come out.
    assert_eq!(built.modules.keys().collect::<Vec<_>>(), ["app"]);
    let module = CompiledModule::deserialize_with_defaults(&built.modules["app"]).unwrap();
    assert!(module
        .immediate_dependencies()
        .iter()
        .any(|d| *d.address() == AccountAddress::new([9; 32])));
    check(&built).unwrap();

    let report = run_tests(&opts, None, GAS).unwrap();
    assert!(report.ok() && report.passed() == 1, "{report:?}");
}

#[test]
fn the_reserved_names_cannot_be_used_for_a_dependency_or_given_twice() {
    let dir = package("module pkg::m; public fun f() {}");
    let lib = package("module pkg::l; public fun f() {}");
    let dep = |name: &str| Dependency {
        name: name.to_owned(),
        dir: lib.path().to_path_buf(),
        address: AccountAddress::new([5; 32]),
    };
    for name in ["std", "thrylos", "pkg"] {
        let mut opts = options(dir.path());
        opts.deps = vec![dep(name)];
        assert!(build(&opts).unwrap_err().contains("reserved"), "{name}");
    }
    let mut opts = options(dir.path());
    opts.deps = vec![dep("same"), dep("same")];
    assert!(build(&opts).unwrap_err().contains("twice"));
}

#[test]
fn a_build_that_the_chain_would_refuse_is_caught_by_check() {
    // A module written at a real address instead of `pkg`.
    let dir = package("module 0x99::m; public fun f() {}");
    let built = build(&options(dir.path())).unwrap();
    assert!(check(&built).unwrap_err().contains("0x0"));
}

#[test]
fn build_tells_a_developer_when_a_module_stores_a_type_it_does_not_define() {
    let dir = package(
        "module pkg::m;
         use thrylos::store;
         public fun leak<T: key>(owner: address, value: T) { store::put(owner, 0, value); }",
    );
    let built = build(&options(dir.path())).unwrap();
    let error = check(&built).unwrap_err();
    assert!(
        error.contains("thrylos::store::put") && error.contains("does not define"),
        "{error}"
    );
    // The same call with the module's own type builds and passes.
    let ok = package(
        "module pkg::m;
         use thrylos::store;
         public struct Mine has key, store { n: u64 }
         entry fun f(owner: address) { store::put(owner, 0, Mine { n: 1 }); }",
    );
    check(&build(&options(ok.path())).unwrap()).unwrap();
}

#[test]
fn tests_can_use_the_store_and_each_starts_with_empty_drawers() {
    let dir = package(
        "module pkg::m;
         use thrylos::store;
         public struct Counter has key, store, copy, drop { n: u64 }

         #[test] fun remembers() {
             store::put(@0xa, 0, Counter { n: 1 });
             assert!(store::has<Counter>(@0xa, 0), 1);
             let mut c = store::take<Counter>(@0xa, 0);
             c.n = c.n + 1;
             store::put(@0xa, 0, c);
             assert!(store::read<Counter>(@0xa, 0).n == 2, 2);
         }
         // Another test's drawer is not here.
         #[test] #[expected_failure(abort_code = 1)] fun starts_empty() {
             let _c = store::take<Counter>(@0xa, 0);
         }
         #[test] #[expected_failure(abort_code = 2)] fun put_twice() {
             store::put(@0xb, 0, Counter { n: 1 });
             store::put(@0xb, 0, Counter { n: 2 });
         }",
    );
    let report = run_tests(&options(dir.path()), None, GAS).unwrap();
    assert!(report.ok() && report.passed() == 3, "{report:?}");
}

#[test]
fn a_package_needs_building_until_it_is_built_and_again_when_its_sources_change() {
    let dir = package("module pkg::m; public fun one(): u64 { 1 }");
    assert!(build_is_stale(dir.path()), "never built");

    let built = build(&options(dir.path())).unwrap();
    write_build(dir.path(), &built).unwrap();
    assert!(!build_is_stale(dir.path()), "just built");

    // A source written after the build makes it stale.
    std::thread::sleep(std::time::Duration::from_millis(50));
    write(
        dir.path(),
        "m.move",
        "module pkg::m; public fun one(): u64 { 2 }",
    );
    assert!(build_is_stale(dir.path()), "a source changed");

    let built = build(&options(dir.path())).unwrap();
    write_build(dir.path(), &built).unwrap();
    assert!(!build_is_stale(dir.path()), "built again");
}

#[test]
fn an_entry_function_no_transaction_can_call_is_warned_about_not_silently_built() {
    let dir = package(
        "module pkg::m;
         use std::string::String;
         entry fun fine(_a: u64, _b: vector<u8>, _c: address) {}
         entry fun takes_text(_s: String) {}
         entry fun generic<T>(_x: u64) {}
         public fun not_entry(_s: String) {}",
    );
    let built = build(&options(dir.path())).unwrap();
    // It still builds and the chain still accepts it: the function just cannot be called.
    check(&built).unwrap();
    let found = warnings(&built);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .any(|line| line.starts_with("m::takes_text") && line.contains("parameter 1")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|line| line.starts_with("m::generic") && line.contains("type parameters")),
        "{found:?}"
    );
}
