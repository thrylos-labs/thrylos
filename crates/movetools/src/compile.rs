//! Compiling a package's sources against the chain's system packages.
//!
//! A package is a directory with its Move files under `sources/`. The names
//! `std` (`0x1`), `thrylos` (`0x2`) and `pkg` (`0x0`, the package being built:
//! the network gives it its real address when it is published) are always
//! defined. Other packages already on the chain are used by giving their
//! sources (`deps`) and the address each of their named addresses was published
//! at (`addresses`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use move_compiler::diagnostics::report_diagnostics_to_buffer;
use move_compiler::shared::{Flags, NumberFormat, NumericalAddress, PackagePaths};
use move_compiler::Compiler;
use move_core_types::account_address::AccountAddress;

use crate::sources::{SYSTEM_SOURCES, TEST_SUPPORT_SOURCES};

/// Names every package may use, and what they mean.
pub const RESERVED_ADDRESSES: [(&str, u8); 3] = [("std", 1), ("thrylos", 2), ("pkg", 0)];

/// A package already published on the chain that this one imports from: its
/// sources (which are written with `pkg` for their own package, as any package
/// is) and the address it was published at. This package refers to it as
/// `name::module`.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub dir: PathBuf,
    pub address: AccountAddress,
}

/// What to compile.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The package directory.
    pub dir: PathBuf,
    pub deps: Vec<Dependency>,
}

/// Compiled modules, by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Built {
    pub modules: BTreeMap<String, Vec<u8>>,
}

impl Built {
    /// The modules' bytes in name order, the form `move publish` takes.
    pub fn bytes(&self) -> Vec<Vec<u8>> {
        self.modules.values().cloned().collect()
    }

    pub fn total_bytes(&self) -> usize {
        self.modules.values().map(Vec::len).sum()
    }
}

fn numerical(address: AccountAddress) -> NumericalAddress {
    NumericalAddress::new(address.into_bytes(), NumberFormat::Hex)
}

fn address_of(last: u8) -> NumericalAddress {
    let mut bytes = [0u8; AccountAddress::LENGTH];
    if let Some(slot) = bytes.last_mut() {
        *slot = last;
    }
    numerical(AccountAddress::new(bytes))
}

/// What the system packages' own sources are compiled with.
fn system_addresses() -> BTreeMap<String, NumericalAddress> {
    BTreeMap::from([
        ("std".to_owned(), address_of(1)),
        ("thrylos".to_owned(), address_of(2)),
    ])
}

/// The names the package being built may use: the reserved ones and one for
/// each dependency, none of them twice.
pub(crate) fn address_table(
    options: &Options,
) -> Result<BTreeMap<String, NumericalAddress>, String> {
    let mut table = BTreeMap::new();
    for (name, last) in RESERVED_ADDRESSES {
        table.insert(name.to_owned(), address_of(last));
    }
    for dep in &options.deps {
        if RESERVED_ADDRESSES
            .iter()
            .any(|(reserved, _)| *reserved == dep.name)
        {
            return Err(format!(
                "the dependency name {:?} is reserved: std is 0x1, thrylos is 0x2, pkg is the package being built",
                dep.name
            ));
        }
        if table
            .insert(dep.name.clone(), numerical(dep.address))
            .is_some()
        {
            return Err(format!("the dependency name {:?} is given twice", dep.name));
        }
    }
    Ok(table)
}

/// Files compiled together with one table of named addresses.
#[derive(Clone)]
pub(crate) struct Group {
    pub files: Vec<String>,
    pub addresses: BTreeMap<String, NumericalAddress>,
}

impl Group {
    pub(crate) fn system_of(files: Vec<String>) -> Self {
        Self::system(files)
    }

    fn system(files: Vec<String>) -> Self {
        Self {
            files,
            addresses: system_addresses(),
        }
    }
}

/// The groups a package's dependencies are: the system sources, and each
/// `deps` package with `pkg` meaning the address it was published at.
pub(crate) fn dependency_groups(
    options: &Options,
    system_files: &[String],
) -> Result<Vec<Group>, String> {
    let mut groups = vec![Group::system(system_files.to_vec())];
    for dep in &options.deps {
        let mut addresses = system_addresses();
        addresses.insert("pkg".to_owned(), numerical(dep.address));
        groups.push(Group {
            files: as_strings(&source_files(&dep.dir)?)?,
            addresses,
        });
    }
    Ok(groups)
}

/// Every `.move` file under `dir/sources`, in a fixed order.
pub fn source_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let sources = dir.join("sources");
    if !sources.is_dir() {
        return Err(format!(
            "{} has no sources directory; a package keeps its Move files in sources/ (make one with `thrylos move new`)",
            dir.display()
        ));
    }
    let mut found = Vec::new();
    let mut pending = vec![sources];
    while let Some(next) = pending.pop() {
        let entries = std::fs::read_dir(&next)
            .map_err(|error| format!("cannot read {}: {error}", next.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "move") {
                found.push(path);
            }
        }
    }
    found.sort();
    if found.is_empty() {
        return Err(format!(
            "{} has no .move files",
            dir.join("sources").display()
        ));
    }
    Ok(found)
}

fn as_strings(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    paths
        .iter()
        .map(|path| {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{} is not valid text", path.display()))
        })
        .collect()
}

/// The system packages' sources written to a scratch directory the compiler
/// can read, kept alive as long as this value is.
pub(crate) struct SystemSources {
    _dir: tempfile::TempDir,
    pub files: Vec<String>,
}

impl SystemSources {
    /// The system sources, and the test-support ones if `testing`.
    pub(crate) fn write(testing: bool) -> Result<Self, String> {
        let dir = tempfile::tempdir().map_err(|error| error.to_string())?;
        let mut files = Vec::new();
        let extra: &[(&str, &str)] = if testing { TEST_SUPPORT_SOURCES } else { &[] };
        for (path, text) in SYSTEM_SOURCES.iter().chain(extra) {
            let target = dir.path().join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            std::fs::write(&target, text).map_err(|error| error.to_string())?;
            files.push(
                target
                    .to_str()
                    .ok_or_else(|| "a temporary path is not valid text".to_owned())?
                    .to_owned(),
            );
        }
        files.sort();
        Ok(Self { _dir: dir, files })
    }
}

pub(crate) fn render(
    files: &move_compiler::shared::files::MappedFiles,
    diagnostics: move_compiler::diagnostics::Diagnostics,
) -> String {
    String::from_utf8_lossy(&report_diagnostics_to_buffer(files, diagnostics, false)).into_owned()
}

/// Compile `targets` against `dependencies`, returning the compiler's own words
/// for anything wrong.
pub(crate) fn compile_groups(
    targets: Vec<Group>,
    dependencies: Vec<Group>,
    testing: bool,
) -> Result<Vec<move_compiler::compiled_unit::NamedCompiledModule>, String> {
    let paths = |groups: Vec<Group>| -> Vec<PackagePaths<String, String>> {
        groups
            .into_iter()
            .map(|group| PackagePaths {
                name: None,
                paths: group.files,
                named_address_map: group.addresses,
            })
            .collect()
    };
    let mut compiler = Compiler::from_package_paths(None, paths(targets), paths(dependencies))
        .map_err(|error| error.to_string())?;
    if testing {
        compiler = compiler.set_flags(Flags::testing());
    }
    let (files, result) = compiler.build().map_err(|error| error.to_string())?;
    match result {
        Ok((units, warnings)) => {
            if !warnings.is_empty() {
                eprint!("{}", render(&files, warnings));
            }
            Ok(units.into_iter().map(|unit| unit.named_module).collect())
        }
        Err(diagnostics) => Err(render(&files, diagnostics)),
    }
}

pub(crate) fn serialize(
    module: &move_binary_format::file_format::CompiledModule,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    module
        .serialize_with_version(module.version, &mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

/// Compile the package in `options.dir`.
pub fn build(options: &Options) -> Result<Built, String> {
    let system = SystemSources::write(false)?;
    let target = Group {
        files: as_strings(&source_files(&options.dir)?)?,
        addresses: address_table(options)?,
    };
    let dependencies = dependency_groups(options, &system.files)?;
    let mut modules = BTreeMap::new();
    for unit in compile_groups(vec![target], dependencies, false)? {
        modules.insert(
            unit.module.self_id().name().to_string(),
            serialize(&unit.module)?,
        );
    }
    Ok(Built { modules })
}

/// Where a built package's modules are written.
pub const BUILD_DIR: &str = "build";

/// Write the built modules to `dir/build/<name>.mv`, replacing whatever a
/// previous build left there.
pub fn write_build(dir: &Path, built: &Built) -> Result<PathBuf, String> {
    let out = dir.join(BUILD_DIR);
    if out.exists() {
        std::fs::remove_dir_all(&out)
            .map_err(|error| format!("cannot clear {}: {error}", out.display()))?;
    }
    std::fs::create_dir_all(&out).map_err(|error| error.to_string())?;
    for (name, bytes) in &built.modules {
        std::fs::write(out.join(format!("{name}.mv")), bytes)
            .map_err(|error| format!("cannot write {name}.mv: {error}"))?;
    }
    Ok(out)
}

/// Whether `dir` needs building before it can be published: it has no build, or a
/// source file is newer than the newest built module.
pub fn build_is_stale(dir: &Path) -> bool {
    fn newest(path: &Path) -> Option<std::time::SystemTime> {
        let meta = std::fs::metadata(path).ok()?;
        if meta.is_dir() {
            std::fs::read_dir(path)
                .ok()?
                .filter_map(Result::ok)
                .filter_map(|entry| newest(&entry.path()))
                .max()
        } else {
            meta.modified().ok()
        }
    }
    let built = newest(&dir.join(BUILD_DIR));
    let sources = newest(&dir.join("sources"));
    match (built, sources) {
        (None, _) => true,
        (Some(built), Some(sources)) => sources > built,
        (Some(_), None) => false,
    }
}

/// The `.mv` files of a package directory's last build, in name order.
pub fn built_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let out = dir.join(BUILD_DIR);
    if !out.is_dir() {
        return Err(format!(
            "{} has not been built; run `thrylos move build {}` first",
            dir.display(),
            dir.display()
        ));
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&out)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "mv"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{} holds no .mv files", out.display()));
    }
    Ok(files)
}

/// What the chain would say about `built`, before any fee is paid: the same
/// checks, in the same order, as publishing (`chain_exec::publish::prepare`).
/// Imports of packages other than the system ones cannot be checked here (only
/// the chain knows what is published), so they are accepted.
pub fn check(built: &Built) -> Result<(), String> {
    check_bytes(&built.bytes())
}

/// [`check`] for modules already as bytes, such as `.mv` files.
pub fn check_bytes(modules: &[Vec<u8>]) -> Result<(), String> {
    chain_exec::publish::prepare(
        modules,
        AccountAddress::new([1; AccountAddress::LENGTH]),
        |_| true,
    )
    .map(|_| ())
    .map_err(|error| error.to_string())
}
