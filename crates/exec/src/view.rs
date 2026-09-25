//! Reading what packages have stored, for a person: the drawers of an address,
//! and a stored value decoded by its type.
//!
//! Nothing here changes state. A drawer's bytes are BCS of a Move value; to show
//! them as fields the VM is asked for the layout of the drawer's type (which it
//! builds from the published package that defines it), and the bytes are read
//! with that layout. If the layout cannot be had (the type mentions a package the
//! defining package does not link to) the raw bytes are still returned.

use std::collections::BTreeMap;
use std::str::FromStr;

use chain_state::{StateKey, StateValue};
use move_core_types::account_address::AccountAddress;
use move_core_types::annotated_value::MoveValue as Annotated;
use move_core_types::language_storage::TypeTag;
use move_core_types::runtime_value::MoveValue as Runtime;
use move_vm_runtime::runtime::MoveRuntime;
use move_vm_runtime::shared::linkage_context::LinkageContext;

use crate::drawer::DrawerValue;
use crate::keys::drawer_tag;
use crate::module_resolver::ChainStateModuleResolver;

/// A Move value, decoded for showing.
#[derive(Debug, Clone, PartialEq)]
pub enum ViewValue {
    Bool(bool),
    /// A whole number of any width, as decimal text: JSON numbers cannot hold a `u128`.
    Number(String),
    Address(AccountAddress),
    Vector(Vec<ViewValue>),
    Struct {
        type_name: String,
        fields: Vec<(String, ViewValue)>,
    },
    Variant {
        type_name: String,
        variant: String,
        fields: Vec<(String, ViewValue)>,
    },
}

impl ViewValue {
    pub(crate) fn from_annotated(value: &Annotated) -> Self {
        match value {
            Annotated::Bool(b) => Self::Bool(*b),
            Annotated::U8(n) => Self::Number(n.to_string()),
            Annotated::U16(n) => Self::Number(n.to_string()),
            Annotated::U32(n) => Self::Number(n.to_string()),
            Annotated::U64(n) => Self::Number(n.to_string()),
            Annotated::U128(n) => Self::Number(n.to_string()),
            Annotated::U256(n) => Self::Number(n.to_string()),
            Annotated::Address(a) | Annotated::Signer(a) => Self::Address(*a),
            Annotated::Vector(items) => {
                Self::Vector(items.iter().map(Self::from_annotated).collect())
            }
            Annotated::Struct(s) => Self::Struct {
                type_name: s.type_.to_canonical_string(true),
                fields: s
                    .fields
                    .iter()
                    .map(|(name, v)| (name.to_string(), Self::from_annotated(v)))
                    .collect(),
            },
            Annotated::Variant(v) => Self::Variant {
                type_name: v.type_.to_canonical_string(true),
                variant: v.variant_name.to_string(),
                fields: v
                    .fields
                    .iter()
                    .map(|(name, v)| (name.to_string(), Self::from_annotated(v)))
                    .collect(),
            },
        }
    }

    /// From a value with no field names: primitives and vectors of them, which is
    /// all a callable function returns. `None` for anything else.
    pub(crate) fn from_runtime(value: &Runtime) -> Option<Self> {
        Some(match value {
            Runtime::Bool(b) => Self::Bool(*b),
            Runtime::U8(n) => Self::Number(n.to_string()),
            Runtime::U16(n) => Self::Number(n.to_string()),
            Runtime::U32(n) => Self::Number(n.to_string()),
            Runtime::U64(n) => Self::Number(n.to_string()),
            Runtime::U128(n) => Self::Number(n.to_string()),
            Runtime::U256(n) => Self::Number(n.to_string()),
            Runtime::Address(a) => Self::Address(*a),
            Runtime::Vector(items) => Self::Vector(
                items
                    .iter()
                    .map(Self::from_runtime)
                    .collect::<Option<Vec<_>>>()?,
            ),
            _ => return None,
        })
    }
}

/// One drawer of an address, listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawerSummary {
    pub slot: u64,
    pub type_name: String,
    /// Bytes of the value, not counting its type name.
    pub bytes: usize,
}

/// The drawers `owner` has, in slot then key order, at most `limit`.
pub(crate) fn drawers_of(
    state: &BTreeMap<StateKey, StateValue>,
    owner: AccountAddress,
    limit: usize,
) -> Vec<DrawerSummary> {
    let mut prefix = vec![drawer_tag()];
    prefix.extend_from_slice(&owner.to_vec());
    let mut found = Vec::new();
    for (key, value) in state.range(StateKey::new(prefix.clone())..) {
        if !key.as_bytes().starts_with(&prefix) || found.len() >= limit {
            break;
        }
        let Some(slot) = key
            .as_bytes()
            .get(33..41)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
        else {
            continue;
        };
        let Ok(drawer) = DrawerValue::from_state(value) else {
            continue;
        };
        found.push(DrawerSummary {
            slot: u64::from_be_bytes(slot),
            type_name: drawer.type_name,
            bytes: drawer.bytes.len(),
        });
    }
    found
}

/// A stored value read as its type says, or `None` if the type's layout cannot be had.
pub(crate) fn render_drawer(
    runtime: &MoveRuntime,
    state: &BTreeMap<StateKey, StateValue>,
    drawer: &DrawerValue,
) -> Option<ViewValue> {
    let tag = TypeTag::from_str(&drawer.type_name).ok()?;
    let TypeTag::Struct(defining) = &tag else {
        return None;
    };
    let resolver = ChainStateModuleResolver::new(state);
    let package = resolver.package(defining.address).ok()??;
    let linkage = LinkageContext::new(package.linkage_table).ok()?;
    let vm = runtime
        .make_vm(ChainStateModuleResolver::new(state), linkage)
        .ok()?;
    let layout = vm.annotated_type_layout(&tag).ok()?;
    let value: Annotated = bcs::from_bytes_seed(&layout, &drawer.bytes).ok()?;
    Some(ViewValue::from_annotated(&value))
}
