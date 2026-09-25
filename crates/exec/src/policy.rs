//! Limits a node applies to the Move calls it *accepts and proposes*, that are
//! **not** rules of the chain. `docs/gas-calibration.md` (option C).
//!
//! Measured on the alpha VPS, a unit of gas spent on plain Move instructions costs
//! 8 to 11 microseconds, so a transaction allowed 15,000,000 gas (a quarter of the
//! block limit) can hold every validator for minutes. The proper fix is
//! recalibrating gas, which changes consensus and waits for the next reset. Until
//! then each validator refuses to take such a call into its mempool and stops
//! packing a block with Move work once enough has been done.
//!
//! Nothing here is checked when a block is *executed*: a block that carries a call
//! over these limits is still a valid block, and every honest validator still runs
//! it. That is the price of not forking, and why this is a stopgap: it protects
//! the network from users, not from a validator that proposes such a block.
//! Removing it needs no fork either.

use chain_types::Transaction;

/// The most gas a call to a user's package may declare, for a node to take it into
/// its mempool. At the worst rate measured this is about 0.2 seconds of a
/// validator's time. A legitimate call uses tens to a few thousand gas.
pub const MOVE_CALL_GAS_LIMIT: u64 = 20_000;

/// The most gas of Move calls a node's proposer will let one block hold, by what
/// the calls actually used when it tried them. Once the total reaches it the
/// proposer leaves the rest for later blocks. A call that used its whole limit can
/// take the total past this by at most one call's worth.
pub const MOVE_GAS_PER_PROPOSED_BLOCK: u64 = 60_000;

/// Whether `tx` calls a package a user published (as opposed to the chain's own
/// protocol calls, publishing itself, or the two fixed demonstration packages),
/// which is the work these limits are about.
pub fn is_user_move_call(tx: &Transaction) -> bool {
    let package = *tx.body.call.module_address.as_bytes();
    !crate::native::is_protocol_call(tx) && package != [1u8; 32] && package != [2u8; 32]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chain_types::{
        Address, BlockHeight, ChainId, GasAmount, GasPrice, MoveCall, PublicKey, SequenceNumber,
        Signature, TransactionBody,
    };

    fn call_to(package: [u8; 32]) -> Transaction {
        Transaction {
            body: TransactionBody {
                chain_id: ChainId(1),
                sender: PublicKey::from_ed25519_bytes(
                    ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .unwrap(),
                sequence_number: SequenceNumber(0),
                expiry: BlockHeight(10),
                gas_limit: GasAmount(1_000),
                max_fee_per_gas: GasPrice(1),
                declared_inputs: Vec::new(),
                call: MoveCall {
                    module_address: Address::from_bytes(package),
                    module_name: b"m".to_vec(),
                    function_name: b"f".to_vec(),
                    type_arguments: Vec::new(),
                    arguments: Vec::new(),
                },
            },
            signature: Signature::from_ed25519_bytes([0; 64]),
        }
    }

    #[test]
    fn only_calls_to_a_users_package_are_limited() {
        for protocol in [
            crate::native::COIN_PACKAGE_ADDRESS,
            crate::native::STAKING_PACKAGE_ADDRESS,
            crate::native::GOVERNANCE_PACKAGE_ADDRESS,
            crate::publish::MOVE_PACKAGE_ADDRESS,
            [1u8; 32],
            [2u8; 32],
        ] {
            assert!(!is_user_move_call(&call_to(protocol)), "{protocol:?}");
        }
        assert!(is_user_move_call(&call_to([0x77; 32])));
        assert!(is_user_move_call(&call_to([0; 32])));
    }

    #[test]
    fn the_limits_are_these() {
        assert_eq!(MOVE_CALL_GAS_LIMIT, 20_000);
        assert_eq!(MOVE_GAS_PER_PROPOSED_BLOCK, 60_000);
        const { assert!(MOVE_CALL_GAS_LIMIT <= MOVE_GAS_PER_PROPOSED_BLOCK) };
    }
}
