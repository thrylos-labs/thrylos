//! Bridges `chain-state`'s flat key-value store to MoveVM's module
//! resolution interface (`move_core_types::resolver::ModuleResolver`).
//!
//! Reconstructs a `SerializedPackage` from stored module bytecode on
//! every lookup rather than persisting a package's linkage/type-origin
//! metadata separately: for a single, dependency-free package — all
//! this pass handles, see `crate`'s doc comment — that reconstruction
//! is fully deterministic and needs nothing beyond the raw module
//! bytes themselves.
//!
//! Uses `move_vm_runtime::dev_utils::storage::StoredPackage`'s
//! `..._for_testing` constructor to do that reconstruction. It's a
//! dev-only helper, used here because a production-grade package-
//! publishing pipeline (real multi-module, multi-dependency, multi-
//! version packages) is its own separate piece of work, not part of
//! this pass — see `crate`'s doc comment for what's deferred.

use std::collections::BTreeMap;

use chain_state::{StateKey, StateValue};
use move_binary_format::file_format::CompiledModule;
use move_core_types::account_address::AccountAddress;
use move_core_types::resolver::{ModuleResolver, SerializedPackage};
use move_vm_runtime::dev_utils::storage::StoredPackage;

/// The chain-state key a package's module bytecode is stored under.
/// Only single-module packages are supported in this pass.
pub fn module_state_key(address: AccountAddress) -> StateKey {
    StateKey::new(address.to_vec())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolverError;

impl core::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("module resolution failed")
    }
}

impl std::error::Error for ResolverError {}

pub struct ChainStateModuleResolver<'a> {
    state: &'a BTreeMap<StateKey, StateValue>,
}

impl<'a> ChainStateModuleResolver<'a> {
    pub const fn new(state: &'a BTreeMap<StateKey, StateValue>) -> Self {
        Self { state }
    }

    fn load_package(
        &self,
        address: AccountAddress,
    ) -> Result<Option<SerializedPackage>, ResolverError> {
        let Some(value) = self.state.get(&module_state_key(address)) else {
            return Ok(None);
        };
        let module = CompiledModule::deserialize_with_defaults(value.as_bytes())
            .map_err(|_| ResolverError)?;
        let stored = StoredPackage::from_modules_for_testing(address, vec![module])
            .map_err(|_| ResolverError)?;
        Ok(Some(stored.into_serialized_package()))
    }
}

impl ModuleResolver for ChainStateModuleResolver<'_> {
    type Error = ResolverError;

    fn get_packages_static<const N: usize>(
        &self,
        ids: [AccountAddress; N],
    ) -> Result<[Option<SerializedPackage>; N], Self::Error> {
        let mut result: [Option<SerializedPackage>; N] = std::array::from_fn(|_| None);
        for (slot, id) in result.iter_mut().zip(ids.iter()) {
            *slot = self.load_package(*id)?;
        }
        Ok(result)
    }

    fn get_packages<'b>(
        &self,
        ids: impl ExactSizeIterator<Item = &'b AccountAddress>,
    ) -> Result<Vec<Option<SerializedPackage>>, Self::Error> {
        ids.map(|id| self.load_package(*id)).collect()
    }
}
