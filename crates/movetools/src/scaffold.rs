//! `thrylos move new`: a package that builds, tests and can be published as it is.

use std::path::Path;

/// Whether `name` can be a Move module and package name here: lower-case
/// letters, digits and underscores, starting with a letter.
pub fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= 64
}

/// Make the package `name` in `dir`, which must not exist yet (nothing is ever
/// overwritten).
pub fn new_package(dir: &Path, name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!(
            "{name:?} is not a usable name: use lower-case letters, digits and underscores, starting with a letter"
        ));
    }
    if dir.exists() {
        return Err(format!(
            "{} already exists; nothing was changed",
            dir.display()
        ));
    }
    let sources = dir.join("sources");
    std::fs::create_dir_all(&sources)
        .map_err(|error| format!("cannot create {}: {error}", sources.display()))?;
    let module = format!(
        "/// A first module. `pkg` is this package: the network gives it its real
/// address when it is published.
module pkg::{name};

/// An entry function is what a transaction can call. Call this one with
/// `thrylos move call <package address> {name} check u64:4 u64:6`.
entry fun check(a: u64, b: u64) {{
    assert!(add(a, b) == 10, 1);
}}

public fun add(a: u64, b: u64): u64 {{
    a + b
}}

#[test]
fun adds() {{
    assert!(add(2, 3) == 5, 0);
}}

#[test]
#[expected_failure(abort_code = 1)]
fun check_aborts_on_the_wrong_sum() {{
    check(1, 1);
}}
"
    );
    std::fs::write(sources.join(format!("{name}.move")), module)
        .map_err(|error| error.to_string())?;
    std::fs::write(dir.join(".gitignore"), "build/\n").map_err(|error| error.to_string())?;
    Ok(())
}
