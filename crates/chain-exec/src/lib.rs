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
//! - Only those two fixed functions exist — no arbitrary module/function
//!   dispatch. A call to anything else is an abort, not a rejection.
//! - Two failure modes, kept apart as `docs/spec.md`'s "Execution"
//!   section requires. A transaction that is *invalid* — wrong chain ID,
//!   bad signature, wrong sequence number, balance that can't cover its
//!   gas limit — rejects the whole block. A valid transaction that
//!   *fails while executing* (unknown function, bad arguments, touching
//!   an undeclared object, a Move abort such as overflow) is aborted:
//!   the block stands, the sender is still charged gas and their
//!   sequence number still advances, and the call's own writes are
//!   discarded. Rollback is structural — call handlers return their
//!   writes instead of applying them — and `ExecutedBlock::outcomes`
//!   reports which happened to each transaction. A third case, an
//!   internal executor failure no transaction can trigger, also rejects
//!   the block rather than charging a sender for a bug of ours.
//! - Declared-input enforcement for the object case is an abort when
//!   the counter isn't declared, and structural underneath that: Sui's
//!   Move has no ambient lookup by address, so `bump` can only touch the
//!   `Counter` passed to it as a `&mut` argument, which the executor
//!   only constructs for a declared address. There's still only one
//!   object *type*, and no way to create a new object at runtime (only
//!   the one genesis instance exists) — both real follow-up work.
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
