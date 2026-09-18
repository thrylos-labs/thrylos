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
//! [`Executor`] is a real, working implementation of
//! `chain_engine_api::Engine`, deliberately narrow:
//!
//! - Two fixed system packages, published at genesis (`genesis` module) —
//!   no module-publishing transaction type yet: a `calculator` module
//!   (plain `u64` arguments only) and a `counter` module with one
//!   mutable object type, one instance of which is seeded at genesis.
//! - Every transaction calls one of those two fixed functions — no
//!   arbitrary module/function dispatch.
//! - Declared-input enforcement for the object case is structural, not
//!   a separate runtime check: Sui's Move has no ambient lookup by
//!   address, so `bump` can only touch the `Counter` passed to it as a
//!   `&mut` argument, which the executor only constructs from a
//!   transaction's own `declared_inputs`. There's still only one object
//!   *type*, and no way to create a new object at runtime (only the one
//!   genesis instance exists) — both real follow-up work.
//! - No real gas metering (`UnmeteredGasMeter`); `gas_used` is stood in
//!   for by the transaction's declared `gas_limit`, not a calibrated
//!   cost model tied to a fee schedule (`chain-modules`, not built yet).
//!
//! Each of those is real, separate follow-up work, not a hidden
//! shortcut — see `module_resolver` and `genesis`'s own doc comments for
//! the specific simplifications each makes (reusing MoveVM's own
//! dev-only test helpers, and compiling Move source via real file I/O
//! at construction time rather than embedding pre-compiled bytecode).

#![forbid(unsafe_code)]

pub mod executor;
pub mod genesis;
pub mod keys;
pub mod module_resolver;

pub use executor::{Executor, ExecutorError};
