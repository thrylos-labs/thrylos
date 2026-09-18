//! Chain-state key conventions for this crate. `chain-state`'s
//! `StateKey` is fully opaque (see its own doc comment) and now shared
//! with `chain-state`'s own account model (`chain_state::account`,
//! reserving tag [`chain_state::account::KEY_TAG`]): module bytecode,
//! object data, and this pass's one scratch result all share the same
//! flat key space account balances live in, and nothing stops two
//! tagged users of that space colliding unless they coordinate their
//! tag bytes. This crate's tags start right after the account model's
//! reservation, computed from that constant rather than hardcoded, so
//! a future change to it can't silently reopen the collision.

use chain_state::StateKey;
use move_core_types::account_address::AccountAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum KeyTag {
    ModuleBytecode = chain_state::account::KEY_TAG + 1,
    ObjectData = chain_state::account::KEY_TAG + 2,
    CalculatorResult = chain_state::account::KEY_TAG + 3,
    BaseFee = chain_state::account::KEY_TAG + 4,
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

/// Where the base fee the *next* block will charge is stored. One fixed
/// key, no address: it is chain-wide state, so it sits in the state
/// root and diff like everything else consensus must agree on.
pub fn base_fee_key() -> StateKey {
    StateKey::new(vec![KeyTag::BaseFee as u8])
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

    #[test]
    fn the_base_fee_key_cannot_collide_with_any_address_keyed_entry() {
        // Address-keyed entries are a tag byte plus 32 address bytes;
        // this one is a bare tag byte, so its length alone separates it,
        // and its tag is distinct too.
        let addr = AccountAddress::new([7u8; AccountAddress::LENGTH]);
        for other in [
            module_key(addr),
            object_key(addr),
            calculator_result_key(addr),
        ] {
            assert_ne!(base_fee_key(), other);
            assert_ne!(base_fee_key().as_bytes().first(), other.as_bytes().first());
        }
    }

    #[test]
    fn none_of_this_crate_s_tags_reuse_the_account_model_s_reserved_tag() {
        for tag in [
            KeyTag::ModuleBytecode as u8,
            KeyTag::ObjectData as u8,
            KeyTag::CalculatorResult as u8,
            KeyTag::BaseFee as u8,
        ] {
            assert_ne!(tag, chain_state::account::KEY_TAG);
        }
    }
}
