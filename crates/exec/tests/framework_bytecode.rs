//! The checked-in bytecode of the system packages is what their sources
//! compile to. Run with `UPDATE_MOVE_BYTECODE=1` to rewrite it after a
//! deliberate change to `move/`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chain_exec::framework::{FRAMEWORK_BUNDLE, STD_BUNDLE};
use chain_types::codec::{decode_exact, Encode};
use move_binary_format::file_format::CompiledModule;
use move_compiler::shared::{NumberFormat, NumericalAddress};
use move_compiler::Compiler;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../move")
}

fn address(last: u8) -> NumericalAddress {
    let mut bytes = [0u8; 32];
    bytes[31] = last;
    NumericalAddress::new(bytes, NumberFormat::Hex)
}

/// The bundle a package's sources compile to: modules ordered by name.
fn compile(dir: &str, names: &[(&str, u8)]) -> Vec<u8> {
    let mut files: Vec<String> = std::fs::read_dir(root().join(dir).join("sources"))
        .unwrap()
        .map(|entry| entry.unwrap().path().to_str().unwrap().to_string())
        .collect();
    files.sort();
    let addresses: BTreeMap<String, NumericalAddress> = names
        .iter()
        .map(|(name, last)| ((*name).to_string(), address(*last)))
        .collect();
    let (_, units) = Compiler::from_files(None, files, vec![], addresses)
        .build_and_report()
        .expect("the system package compiles");
    let modules: BTreeMap<String, Vec<u8>> = units
        .into_iter()
        .map(|unit| {
            let module: CompiledModule = unit.named_module.module;
            let mut bytes = Vec::new();
            module
                .serialize_with_version(module.version, &mut bytes)
                .unwrap();
            (module.self_id().name().to_string(), bytes)
        })
        .collect();
    let ordered: Vec<Vec<u8>> = modules.into_values().collect();
    let mut bundle = Vec::new();
    ordered.encode(&mut bundle);
    bundle
}

fn check(file: &str, fresh: Vec<u8>, checked_in: &[u8]) {
    if std::env::var_os("UPDATE_MOVE_BYTECODE").is_some() {
        std::fs::write(root().join("bytecode").join(file), &fresh).unwrap();
        return;
    }
    assert!(
        fresh == checked_in,
        "move/bytecode/{file} is not what its sources compile to; rerun with UPDATE_MOVE_BYTECODE=1 if that was intended"
    );
}

#[test]
fn the_standard_library_bytecode_is_what_its_sources_compile_to() {
    check("std.bundle", compile("stdlib", &[("std", 1)]), STD_BUNDLE);
}

#[test]
fn the_framework_bytecode_is_what_its_sources_compile_to() {
    check(
        "thrylos.bundle",
        compile("framework", &[("thrylos", 2), ("std", 1)]),
        FRAMEWORK_BUNDLE,
    );
}

#[test]
fn the_bundles_decode_and_every_module_lives_at_its_package_address() {
    for (bundle, address) in [(STD_BUNDLE, 1u8), (FRAMEWORK_BUNDLE, 2u8)] {
        let modules: Vec<Vec<u8>> = decode_exact(bundle).unwrap();
        assert!(!modules.is_empty());
        let mut names = Vec::new();
        for bytes in &modules {
            let module = CompiledModule::deserialize_with_defaults(bytes).unwrap();
            assert_eq!(module.self_id().address().into_bytes()[31], address);
            names.push(module.self_id().name().to_string());
        }
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted, "stored in module-name order");
    }
}
