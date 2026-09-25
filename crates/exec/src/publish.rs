//! Publishing a Move package: `move::publish`, a protocol call to the
//! reserved package [`MOVE_PACKAGE_ADDRESS`].
//!
//! Each argument is one compiled module, and the modules together are the
//! package. Packages are immutable: there is no upgrade and no delete. The
//! package's address is not chosen by the publisher but derived from who
//! publishes and the sequence number of the publishing transaction
//! (`DomainTag::MovePackageV1`), so it cannot repeat and cannot land on a
//! reserved address. Modules are compiled with the address `0x0` for their
//! own package and the chain fills in the real one, since nobody can know it
//! before the transaction is signed.
//!
//! Everything a node checks is deterministic and bounded before the VM is
//! asked anything: sizes and counts, the module format, that every import is
//! one this stage allows (`0x1` and `0x2`, plus the package's own modules),
//! and the bytecode verifier under a work meter (`crate::move_config`). Only
//! then does the VM validate and link the package. Any failure aborts the
//! transaction, which burns its whole gas limit like every other refused
//! call; nothing is stored.

use chain_engine_api::AbortReason;
use chain_state::{StateKey, StateValue};
use chain_types::codec::Encode;
use chain_types::{hash_with_domain, DomainTag, Transaction};
use move_binary_format::file_format::CompiledModule;
use move_bytecode_verifier::verify_module_with_config_metered;
use move_core_types::account_address::AccountAddress;
use move_vm_runtime::dev_utils::gas_schedule::GasStatus;
use move_vm_runtime::natives::extensions::NativeContextExtensions;
use move_vm_runtime::runtime::MoveRuntime;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use crate::accounting::read_supply;
use crate::effects::{BlockCtx, CallEffects, CallError};
use crate::keys::{package_key, supply_key};
use crate::module_resolver::ChainStateModuleResolver;
use crate::move_config::{
    binary_config, verifier_config, verifier_meter, MAX_MODULES_PER_PACKAGE, MAX_MODULE_BYTES,
    MAX_PACKAGE_BYTES,
};
use crate::native::{debit_sender, State, NEW_ENTRY_STORAGE_DEPOSIT};

/// The reserved package the publish call is addressed to.
pub const MOVE_PACKAGE_ADDRESS: [u8; 32] = [7; 32];
pub const MOVE_MODULE_NAME: &str = "move";
pub const PUBLISH: &str = "publish";

/// Gas for a publish: a base charge and a charge per byte published. It is
/// what the call costs when it succeeds; the verifier's own work is bounded
/// separately by its meter, so a package cannot cost more than this pays for.
pub const PUBLISH_BASE_GAS: u64 = 20_000;
pub const PUBLISH_GAS_PER_BYTE: u64 = 10;

/// Storage deposit per started KiB of package, on top of the flat entry
/// deposit. Burned like the other deposits: 0.01 THRY per KiB, so a full
/// 128 KiB package holds 1.28 THRY of state for good.
pub const PUBLISH_DEPOSIT_PER_KIB: u128 = 10_000_000;

/// The system packages every package may import: the frozen standard library
/// and the Thrylos framework. Any other import must be a package already
/// published on this chain.
pub const SYSTEM_DEPENDENCIES: [AccountAddress; 2] = [AccountAddress::ONE, AccountAddress::TWO];

/// The most packages, counting the standard library and framework and every
/// package those need in turn, a package may depend on. Bounds what loading
/// and linking one package can cost.
pub const MAX_DEPENDENCY_PACKAGES: usize = 16;

/// Whether the call is addressed to the publish package.
pub(crate) fn is_publish_call(tx: &Transaction) -> bool {
    tx.body.call.module_address.as_bytes() == &MOVE_PACKAGE_ADDRESS
}

/// The address a package published by `sender` in the transaction with
/// `sequence_number` gets.
pub fn package_address(sender: &chain_types::Address, sequence_number: u64) -> AccountAddress {
    let mut payload = sender.as_bytes().to_vec();
    payload.extend_from_slice(&sequence_number.to_le_bytes());
    AccountAddress::new(*hash_with_domain(DomainTag::MovePackageV1, &payload).as_bytes())
}

/// Whether `bytes` of package are chargeable within one transaction's gas at
/// most; the fixed part of the gas for a package of that size.
pub fn publish_gas(total_bytes: usize) -> u64 {
    u64::try_from(total_bytes)
        .unwrap_or(u64::MAX)
        .saturating_mul(PUBLISH_GAS_PER_BYTE)
        .saturating_add(PUBLISH_BASE_GAS)
}

fn deposit(total_bytes: usize) -> u128 {
    let kib = u128::try_from(total_bytes.div_ceil(1024)).unwrap_or(u128::MAX);
    kib.saturating_mul(PUBLISH_DEPOSIT_PER_KIB)
        .saturating_add(NEW_ENTRY_STORAGE_DEPOSIT)
}

/// Why a package cannot be published. Only a person reads this (the chain
/// itself just refuses), so the wording is for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishError {
    NoModules,
    TooManyModules {
        found: usize,
    },
    ModuleTooLarge {
        index: usize,
        bytes: usize,
    },
    PackageTooLarge {
        bytes: usize,
    },
    Malformed {
        index: usize,
        reason: String,
    },
    NotAtZero {
        module: String,
        address: AccountAddress,
    },
    DuplicateName {
        module: String,
    },
    UnknownDependency {
        module: String,
        address: AccountAddress,
    },
    Verification {
        module: String,
        reason: String,
    },
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoModules => f.write_str("a package needs at least one module"),
            Self::TooManyModules { found } => write!(
                f,
                "a package has at most {MAX_MODULES_PER_PACKAGE} modules; this has {found}"
            ),
            Self::ModuleTooLarge { index, bytes } => write!(
                f,
                "module {} is {bytes} bytes; the most allowed is {MAX_MODULE_BYTES}",
                index.saturating_add(1)
            ),
            Self::PackageTooLarge { bytes } => write!(
                f,
                "the modules total {bytes} bytes; the most allowed is {MAX_PACKAGE_BYTES}"
            ),
            Self::Malformed { index, reason } => write!(
                f,
                "module {} is not valid compiled Move: {reason}",
                index.saturating_add(1)
            ),
            Self::NotAtZero { module, address } => write!(
                f,
                "module {module} is at address {address}; modules to publish are written at 0x0 \
                 (the network fills in the package's address)"
            ),
            Self::DuplicateName { module } => write!(f, "two modules are both called {module}"),
            Self::UnknownDependency { module, address } => write!(
                f,
                "module {module} imports {address}, which is not the standard library (0x1), the \
                 framework (0x2) or a published package"
            ),
            Self::Verification { module, reason } => {
                write!(f, "module {module} failed bytecode verification: {reason}")
            }
        }
    }
}

impl std::error::Error for PublishError {}

/// Everything about a package that can be decided without running it: sizes
/// and counts, the module format, each module at `0x0` (rewritten to `id`),
/// unique names, imports only from packages `is_published` accepts (or the
/// system ones or the package itself), and the bytecode verifier under its
/// work meter. What the chain does first, and what `thrylos move build` checks
/// so a mistake shows up before a fee is paid.
pub fn prepare(
    raw: &[Vec<u8>],
    id: AccountAddress,
    is_published: impl Fn(&AccountAddress) -> bool,
) -> Result<Vec<CompiledModule>, PublishError> {
    if raw.is_empty() {
        return Err(PublishError::NoModules);
    }
    if raw.len() > MAX_MODULES_PER_PACKAGE {
        return Err(PublishError::TooManyModules { found: raw.len() });
    }
    let mut total = 0usize;
    for (index, module) in raw.iter().enumerate() {
        if module.len() > MAX_MODULE_BYTES {
            return Err(PublishError::ModuleTooLarge {
                index,
                bytes: module.len(),
            });
        }
        total = total.saturating_add(module.len());
    }
    if total > MAX_PACKAGE_BYTES {
        return Err(PublishError::PackageTooLarge { bytes: total });
    }

    let config = binary_config();
    let mut modules = Vec::with_capacity(raw.len());
    let mut names = BTreeSet::new();
    for (index, bytes) in raw.iter().enumerate() {
        let mut module =
            CompiledModule::deserialize_with_config(bytes, &config).map_err(|error| {
                PublishError::Malformed {
                    index,
                    reason: error.to_string(),
                }
            })?;
        let name = module.self_id().name().to_string();
        // Every module names `0x0` as its own package; the chain fills in
        // the real address. Anything else is a package that means to live
        // somewhere it cannot.
        if *module.self_id().address() != AccountAddress::ZERO {
            return Err(PublishError::NotAtZero {
                module: name,
                address: *module.self_id().address(),
            });
        }
        for address in &mut module.address_identifiers {
            if *address == AccountAddress::ZERO {
                *address = id;
            }
        }
        if !names.insert(name.clone()) {
            return Err(PublishError::DuplicateName { module: name });
        }
        for dependency in module.immediate_dependencies() {
            let address = *dependency.address();
            // Already published (packages are immutable, so what it imports
            // now is what it will always import), or one of the system ones.
            if address != id && !SYSTEM_DEPENDENCIES.contains(&address) && !is_published(&address) {
                return Err(PublishError::UnknownDependency {
                    module: name,
                    address,
                });
            }
        }
        modules.push(module);
    }

    let verifier = verifier_config();
    let mut meter = verifier_meter();
    for module in &modules {
        verify_module_with_config_metered(&verifier, module, &mut meter).map_err(|error| {
            PublishError::Verification {
                module: module.self_id().name().to_string(),
                reason: error.to_string(),
            }
        })?;
    }
    Ok(modules)
}

fn refused() -> CallError {
    AbortReason::PublishRefused.into()
}

/// Handle a call addressed to the publish package. Reads `state`, writes
/// nothing: what would change comes back for the caller to apply.
pub(crate) fn call(
    runtime: &MoveRuntime,
    state: &State,
    tx: &Transaction,
    ctx: &BlockCtx,
) -> Result<CallEffects, CallError> {
    let call = &tx.body.call;
    if call.module_name != MOVE_MODULE_NAME.as_bytes() || call.function_name != PUBLISH.as_bytes() {
        return Err(AbortReason::UnknownFunction.into());
    }
    if !call.type_arguments.is_empty() {
        return Err(AbortReason::InvalidArguments.into());
    }

    // The governed kill switch: checked first, before any work on the bytes.
    if !ctx.params.values().publish_enabled {
        return Err(refused());
    }

    let raw = call.arguments.as_slice();
    let sender = tx.sender_address();
    let id = package_address(&sender, tx.body.sequence_number.0);
    if state.contains_key(&package_key(id)) {
        return Err(CallError::Internal);
    }
    // The size checks come first and the gas is checked before any work is
    // done on the bytes: `prepare` does the rest in a fixed order.
    let total_bytes = raw.iter().map(Vec::len).fold(0usize, usize::saturating_add);
    if raw.len() <= MAX_MODULES_PER_PACKAGE
        && total_bytes <= MAX_PACKAGE_BYTES
        && publish_gas(total_bytes) > tx.body.gas_limit.0
    {
        return Err(refused());
    }
    let modules = prepare(raw, id, |address| {
        state.contains_key(&package_key(*address))
    })
    .map_err(|_| refused())?;
    let gas = publish_gas(total_bytes);

    // Sorted by name, so the stored bytes do not depend on the order the
    // publisher listed the modules in.
    let by_name: BTreeMap<_, _> = modules
        .iter()
        .map(|module| (module.self_id().name().to_owned(), module))
        .collect();
    let resolver = ChainStateModuleResolver::new(state);
    let package = resolver
        .linked_package(id, by_name.values().map(|m| (*m).clone()).collect())
        .map_err(|_| refused())?;
    // Everything this package needs, other than itself.
    if package.linkage_table.len().saturating_sub(1) > MAX_DEPENDENCY_PACKAGES {
        return Err(refused());
    }
    let mut unmetered = GasStatus::new_unmetered();
    let extensions = Rc::new(RefCell::new(NativeContextExtensions::default()));
    runtime
        .validate_package(resolver, id, package, &mut unmetered, extensions)
        .map_err(|_| refused())?;

    let mut stored = Vec::new();
    let serialized: Vec<Vec<u8>> = by_name
        .values()
        .map(|module| {
            let mut bytes = Vec::new();
            module
                .serialize_with_version(module.version, &mut bytes)
                .map(|()| bytes)
        })
        .collect::<Result<_, _>>()
        .map_err(|_| CallError::Internal)?;
    serialized.encode(&mut stored);

    let held = deposit(total_bytes);
    let mut changes: Vec<(StateKey, Option<StateValue>)> = Vec::new();
    debit_sender(state, tx, held, &mut changes)?;
    changes.push((package_key(id), Some(StateValue::new(stored))));
    let supply = read_supply(state).ok_or(CallError::Internal)?;
    let after = supply.checked_sub(held).ok_or(CallError::Internal)?;
    let mut supply_bytes = Vec::new();
    after.encode(&mut supply_bytes);
    changes.push((supply_key(), Some(StateValue::new(supply_bytes))));

    Ok(CallEffects {
        changes,
        gas_used: gas,
    })
}
