//! The sources of the chain's two system packages, built into the tool so
//! that `thrylos move build` compiles against exactly what the chain has and
//! needs no files from anywhere else. A test requires this list to be every
//! file under `move/`, and the checked-in bytecode to be what they compile to
//! (`chain-exec`'s `framework_bytecode` test), so the three cannot drift.

/// `(path under move/, contents)`.
pub const SYSTEM_SOURCES: &[(&str, &str)] = &[
    (
        "stdlib/sources/address.move",
        include_str!("../../../move/stdlib/sources/address.move"),
    ),
    (
        "stdlib/sources/ascii.move",
        include_str!("../../../move/stdlib/sources/ascii.move"),
    ),
    (
        "stdlib/sources/bcs.move",
        include_str!("../../../move/stdlib/sources/bcs.move"),
    ),
    (
        "stdlib/sources/bit_vector.move",
        include_str!("../../../move/stdlib/sources/bit_vector.move"),
    ),
    (
        "stdlib/sources/bool.move",
        include_str!("../../../move/stdlib/sources/bool.move"),
    ),
    (
        "stdlib/sources/fixed_point32.move",
        include_str!("../../../move/stdlib/sources/fixed_point32.move"),
    ),
    (
        "stdlib/sources/hash.move",
        include_str!("../../../move/stdlib/sources/hash.move"),
    ),
    (
        "stdlib/sources/internal.move",
        include_str!("../../../move/stdlib/sources/internal.move"),
    ),
    (
        "stdlib/sources/macros.move",
        include_str!("../../../move/stdlib/sources/macros.move"),
    ),
    (
        "stdlib/sources/option.move",
        include_str!("../../../move/stdlib/sources/option.move"),
    ),
    (
        "stdlib/sources/string.move",
        include_str!("../../../move/stdlib/sources/string.move"),
    ),
    (
        "stdlib/sources/type_name.move",
        include_str!("../../../move/stdlib/sources/type_name.move"),
    ),
    (
        "stdlib/sources/u128.move",
        include_str!("../../../move/stdlib/sources/u128.move"),
    ),
    (
        "stdlib/sources/u16.move",
        include_str!("../../../move/stdlib/sources/u16.move"),
    ),
    (
        "stdlib/sources/u256.move",
        include_str!("../../../move/stdlib/sources/u256.move"),
    ),
    (
        "stdlib/sources/u32.move",
        include_str!("../../../move/stdlib/sources/u32.move"),
    ),
    (
        "stdlib/sources/u64.move",
        include_str!("../../../move/stdlib/sources/u64.move"),
    ),
    (
        "stdlib/sources/u8.move",
        include_str!("../../../move/stdlib/sources/u8.move"),
    ),
    (
        "stdlib/sources/uq32_32.move",
        include_str!("../../../move/stdlib/sources/uq32_32.move"),
    ),
    (
        "stdlib/sources/uq64_64.move",
        include_str!("../../../move/stdlib/sources/uq64_64.move"),
    ),
    (
        "stdlib/sources/vector.move",
        include_str!("../../../move/stdlib/sources/vector.move"),
    ),
    (
        "framework/sources/chain.move",
        include_str!("../../../move/framework/sources/chain.move"),
    ),
    (
        "framework/sources/signer.move",
        include_str!("../../../move/framework/sources/signer.move"),
    ),
];

/// Two more library modules that exist only while testing: `std::unit_test`,
/// which the compiler requires of any package compiled with tests, and
/// `std::debug`, which it uses. They are not on the chain and are not in the
/// checked-in bytecode; `thrylos move test` compiles them itself.
pub const TEST_SUPPORT_SOURCES: &[(&str, &str)] = &[
    (
        "test-support/sources/debug.move",
        include_str!("../../../move/test-support/sources/debug.move"),
    ),
    (
        "test-support/sources/unit_test.move",
        include_str!("../../../move/test-support/sources/unit_test.move"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_system_source_is_listed_and_nothing_else() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../move");
        let mut on_disk = Vec::new();
        for package in ["stdlib", "framework", "test-support"] {
            for entry in std::fs::read_dir(root.join(package).join("sources")).unwrap() {
                let name = entry.unwrap().file_name().into_string().unwrap();
                on_disk.push(format!("{package}/sources/{name}"));
            }
        }
        on_disk.sort();
        let mut listed: Vec<String> = SYSTEM_SOURCES
            .iter()
            .chain(TEST_SUPPORT_SOURCES)
            .map(|(p, _)| (*p).to_owned())
            .collect();
        listed.sort();
        assert_eq!(listed, on_disk);
    }
}
