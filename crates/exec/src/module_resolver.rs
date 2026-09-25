//! Bridges `chain-state`'s flat key-value store to MoveVM's module
//! resolution interface (`move_core_types::resolver::ModuleResolver`).
//!
//! A package is looked up under [`package_key`] (a published, multi-module
//! package, see `crate::publish`) and otherwise under the older
//! [`module_key`] (the two single-module demo packages made at genesis).
//! Either way the `SerializedPackage` is rebuilt from the stored module bytes
//! on every lookup, by [`build_package`], rather than stored with its own
//! linkage and type-origin tables: everything in them follows from the
//! modules, so there is one way to build it and nothing to keep in step.
//!
//! Packages are immutable and have no upgrade path, so a package's version
//! is always 0 and its original id is its own address.
//!
//! A package's linkage covers every package it needs, not only the ones its
//! modules import directly: the VM requires the whole set. It is completed
//! here by reading each dependency's own linkage. Dependencies must already be
//! published, and an address is derived from a hash, so a package cannot come
//! to depend on itself and the walk always ends; [`MAX_LINK_DEPTH`] only bounds
//! it against damaged state.

use std::collections::BTreeMap;

use chain_types::codec::decode_exact;

use chain_state::{StateKey, StateValue};
use move_binary_format::binary_config::BinaryConfig;
use move_binary_format::file_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::resolver::{ModuleResolver, SerializedPackage};
use move_vm_runtime::dev_utils::storage::generate_type_origins;

use crate::keys::{module_key, package_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverError;

impl core::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("module resolution failed")
    }
}

impl std::error::Error for ResolverError {}

/// How deep a dependency chain is followed when completing a linkage.
const MAX_LINK_DEPTH: usize = 32;

pub struct ChainStateModuleResolver<'a> {
    state: &'a BTreeMap<StateKey, StateValue>,
    binary: BinaryConfig,
}

impl<'a> ChainStateModuleResolver<'a> {
    pub fn new(state: &'a BTreeMap<StateKey, StateValue>) -> Self {
        Self {
            state,
            binary: crate::move_config::binary_config(),
        }
    }

    /// A resolver that also reads modules compiled in test mode, which carry a
    /// mark saying they are not for publishing and are otherwise refused. Only
    /// for running a package's own tests; a chain never uses it.
    pub fn allowing_test_modules(state: &'a BTreeMap<StateKey, StateValue>) -> Self {
        Self {
            state,
            binary: BinaryConfig::new_unpublishable(),
        }
    }

    /// The package published at `address`, if there is one.
    pub fn package(
        &self,
        address: AccountAddress,
    ) -> Result<Option<SerializedPackage>, ResolverError> {
        self.load_package(address, 0)
    }

    /// The package `modules` would make at `id`, linked to everything it needs
    /// as published in this state.
    pub fn linked_package(
        &self,
        id: AccountAddress,
        modules: Vec<CompiledModule>,
    ) -> Result<SerializedPackage, ResolverError> {
        self.link_dependencies(build_package(id, modules)?, 0)
    }

    /// `package` with the linkage of every package it depends on, all the way
    /// down, added to its own.
    fn link_dependencies(
        &self,
        mut package: SerializedPackage,
        depth: usize,
    ) -> Result<SerializedPackage, ResolverError> {
        if depth >= MAX_LINK_DEPTH {
            return Err(ResolverError);
        }
        let dependencies: Vec<AccountAddress> = package
            .linkage_table
            .keys()
            .copied()
            .filter(|address| *address != package.version_id)
            .collect();
        for dependency in dependencies {
            if let Some(found) = self.load_package(dependency, depth.saturating_add(1))? {
                package.linkage_table.extend(found.linkage_table);
            }
        }
        Ok(package)
    }

    fn load_package(
        &self,
        address: AccountAddress,
        depth: usize,
    ) -> Result<Option<SerializedPackage>, ResolverError> {
        let config = &self.binary;
        if let Some(value) = self.state.get(&package_key(address)) {
            let module_bytes: Vec<Vec<u8>> =
                decode_exact(value.as_bytes()).map_err(|_| ResolverError)?;
            let modules = module_bytes
                .iter()
                .map(|bytes| CompiledModule::deserialize_with_config(bytes, config))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ResolverError)?;
            return self
                .link_dependencies(build_package(address, modules)?, depth)
                .map(Some);
        }
        let Some(value) = self.state.get(&module_key(address)) else {
            return Ok(None);
        };
        let module = CompiledModule::deserialize_with_defaults(value.as_bytes())
            .map_err(|_| ResolverError)?;
        build_package(address, vec![module]).map(Some)
    }
}

/// The package `modules` make when published at `id`: each module's bytes
/// by name, linked to itself and to every other package its modules import
/// (which must be published at exactly those addresses), with every type
/// defined here.
pub fn build_package(
    id: AccountAddress,
    modules: Vec<CompiledModule>,
) -> Result<SerializedPackage, ResolverError> {
    if modules.is_empty() {
        return Err(ResolverError);
    }
    let mut linkage_table = BTreeMap::from([(id, id)]);
    let mut serialized = BTreeMap::new();
    for module in &modules {
        if *module.self_id().address() != id {
            return Err(ResolverError);
        }
        for dependency in module.immediate_dependencies() {
            linkage_table.insert(*dependency.address(), *dependency.address());
        }
        let mut bytes = Vec::new();
        module
            .serialize_with_version(module.version, &mut bytes)
            .map_err(|_| ResolverError)?;
        serialized.insert(module.self_id().name().to_owned(), bytes);
    }
    Ok(SerializedPackage {
        version_id: id,
        original_id: id,
        modules: serialized,
        linkage_table,
        type_origin_table: generate_type_origins(id, &modules),
        version: 0,
    })
}

impl ModuleResolver for ChainStateModuleResolver<'_> {
    type Error = ResolverError;

    fn get_packages_static<const N: usize>(
        &self,
        ids: [AccountAddress; N],
    ) -> Result<[Option<SerializedPackage>; N], Self::Error> {
        let mut result: [Option<SerializedPackage>; N] = std::array::from_fn(|_| None);
        for (slot, id) in result.iter_mut().zip(ids.iter()) {
            *slot = self.load_package(*id, 0)?;
        }
        Ok(result)
    }

    fn get_packages<'b>(
        &self,
        ids: impl ExactSizeIterator<Item = &'b AccountAddress>,
    ) -> Result<Vec<Option<SerializedPackage>>, Self::Error> {
        ids.map(|id| self.load_package(*id, 0)).collect()
    }
}
