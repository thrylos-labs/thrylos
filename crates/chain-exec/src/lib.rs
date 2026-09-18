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
//! - One fixed system package, published at genesis (`genesis` module) —
//!   no module-publishing transaction type yet.
//! - Every transaction calls that one fixed function, with plain `u64`
//!   arguments only — no object arguments.
//! - No declared-input resolution. Sui's Move has no ambient lookup by
//!   address — a function can only touch an object passed to it as an
//!   argument — so once object arguments exist, declared-input
//!   enforcement is largely structural rather than a separate runtime
//!   check. That's still untested here because there are no object
//!   arguments yet.
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
pub mod module_resolver;

pub use executor::{Executor, ExecutorError};
