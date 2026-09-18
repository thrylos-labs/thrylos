//! Block executor wrapping MoveVM.
//!
//! Tier A. Failure if wrong: Fork.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! The MoveVM dependency itself is pinned in the workspace root
//! `Cargo.toml` (`move-vm-runtime`, a git dependency into
//! `MystenLabs/sui`'s `external-crates/move` — see the comment there for
//! why). `tests/move_vm_proof_of_life.rs` proves that dependency
//! actually compiles and runs real Move code end to end.
//!
//! No production executor exists here yet. Building one means bridging
//! `chain-state`'s trie to MoveVM's storage/resolver interface,
//! enforcing declared-object access, wiring real gas metering to a fee
//! schedule (`chain-modules`, not yet built), and implementing
//! `chain-engine-api::Engine`'s `execute_block` — each a substantial
//! piece of its own.

#![forbid(unsafe_code)]
