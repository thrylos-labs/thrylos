//! Chain-state key conventions for this crate. `chain-state`'s
//! `StateKey` is fully opaque (see its own doc comment — the "account
//! model" is deliberately undecided there), so this crate must pick and
//! keep straight its own namespacing: module bytecode, object data, and
//! this pass's one scratch result all share one flat key space, and
//! nothing stops two of them colliding unless every key is tagged by
//! what it is.

use chain_state::StateKey;
use move_core_types::account_address::AccountAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum KeyTag {
    ModuleBytecode = 0,
    ObjectData = 1,
    CalculatorResult = 2,
}

fn tagged_key(tag: KeyTag, address: AccountAddress) -> StateKey {
    let mut bytes = vec![tag as u8];
    bytes.extend_from_slice(&address.to_vec());
    StateKey::new(bytes)
}

/// Where a package's module bytecode is stored. Only single-module
/// packages are supported in this pass (see `module_resolver`'s doc
/// comment).
pub fn module_key(address: AccountAddress) -> StateKey {
    tagged_key(KeyTag::ModuleBytecode, address)
}

/// Where a Move object's data lives, keyed by its address.
pub fn object_key(address: AccountAddress) -> StateKey {
    tagged_key(KeyTag::ObjectData, address)
}

/// Where the fixed system `calculator::add` call's result is stored,
/// keyed by the calling transaction's sender.
pub fn calculator_result_key(sender: AccountAddress) -> StateKey {
    tagged_key(KeyTag::CalculatorResult, sender)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_tags_never_collide_on_the_same_address() {
        let addr = AccountAddress::new([7u8; AccountAddress::LENGTH]);
        assert_ne!(module_key(addr), object_key(addr));
        assert_ne!(module_key(addr), calculator_result_key(addr));
        assert_ne!(object_key(addr), calculator_result_key(addr));
    }
}
