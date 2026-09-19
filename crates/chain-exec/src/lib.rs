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
//!   expired (or expiring further ahead than the horizon), bad signature,
//!   wrong sequence number, balance that can't cover its gas limit —
//!   rejects the whole block. A valid transaction that
//!   *fails while executing* (unknown function, bad arguments, touching
//!   an undeclared object, a Move abort such as overflow) is aborted:
//!   the block stands, the sender is still charged gas and their
//!   sequence number still advances, and the call's own writes are
//!   discarded. Rollback is structural — call handlers return their
//!   writes instead of applying them — and `ExecutedBlock::outcomes`
//!   reports which happened to each transaction. A third case, an
//!   internal executor failure no transaction can trigger, also rejects
//!   the block rather than charging a sender for a bug of ours.
//! - A real chain starts from a [`genesis_config::GenesisConfig`] through
//!   `Executor::from_genesis`: its id and start time, its governed
//!   parameters, its allocations and its validators (registered and bonded,
//!   proofs of possession verified). The configuration is valid by
//!   construction and canonically ordered, and its hash is the first block's
//!   parent. Reading one from a file is `chain-genesis`'s job, since parsing
//!   is I/O and does not belong in this crate. `Executor::genesis` remains
//!   for development and tests: default parameters, nothing allocated, no
//!   validators.
//! - The block itself is checked against its parent, both read from state
//!   (a chain-head entry written by every block, so it is in the state
//!   root and diff): the height must be exactly one more, and the
//!   timestamp strictly later. Height matters because a transaction's
//!   expiry is measured against it. The other half of the timestamp rule,
//!   "not more than 5 seconds ahead of the validating node's clock",
//!   needs a clock and so is not here: `chain_engine_api::timestamp` has
//!   it as a pure function for the consensus host to apply before voting.
//! - The native modules' state lives in this same flat state under its own
//!   tag, through `module_store::StateStore`, one entry per entity, and a
//!   transaction reaches them through [`native`]: staking (register a
//!   validator, stake, unstake, unjail, submit equivocation evidence) and
//!   governance (propose, vote), as calls to two reserved system packages.
//!   A call that fails aborts and costs its fee, like any other. The
//!   modules hold no coin; this crate moves it, and keeps the chain's
//!   total supply in state ([`accounting`]) equal to everything held in
//!   accounts, staking pools and unbonding entries.
//! - After a block's transactions the modules' hooks run in a fixed order
//!   ([`hooks`]): matured unbonding is paid out, an epoch's inflation is
//!   minted into the validators' pools, governance advances, and the time
//!   checkpoints that date evidence are kept. The governed parameters
//!   (block gas limit, fee denominator, ...) are read from state at the
//!   start of each block, so a change governance applies governs the
//!   next block. Last of all the block is checked to have neither created
//!   nor destroyed value; one that did is rejected as
//!   `RejectionReason::InvariantViolated`, halting the chain at it.
//! - Native calls are not metered — like every call here they are charged
//!   their declared gas limit — and some do work that grows with the state
//!   (see [`native`]). Metering them by measurement is required before
//!   this carries real value.
//! - Declared-input enforcement for the object case is an abort when
//!   the counter isn't declared, and structural underneath that: Sui's
//!   Move has no ambient lookup by address, so `bump` can only touch the
//!   `Counter` passed to it as a `&mut` argument, which the executor
//!   only constructs for a declared address. There's still only one
//!   object *type*, and no way to create a new object at runtime (only
//!   the one genesis instance exists) — both real follow-up work.
//! - No real gas metering (`UnmeteredGasMeter`); `gas_used` is stood in
//!   for by the transaction's declared `gas_limit`, not a calibrated
//!   per-instruction cost model. What that gas *costs* is real, though:
//!   every transaction in a block pays the same base fee per gas
//!   (`chain_modules::fees`, EIP-1559 on the single dimension of
//!   compute), stored in state so it is part of the state root and diff,
//!   and recomputed from each block's total gas for the next. A
//!   transaction whose `max_fee_per_gas` can't cover it is invalid and
//!   rejects the block, and so does a block over the gas limit. The fee
//!   is burned, with no priority tip — `TransactionBody` has one price
//!   field. The gas limit and fee denominator start where genesis puts them; when
//!   governance can change them they belong in state too.
//!
//! Each of those is real, separate follow-up work, not a hidden
//! shortcut — see `module_resolver` and `genesis`'s own doc comments for
//! the specific simplifications each makes (reusing MoveVM's own
//! dev-only test helpers, and compiling Move source via real file I/O
//! at construction time rather than embedding pre-compiled bytecode).

#![forbid(unsafe_code)]

pub mod accounting;
mod effects;
pub mod executor;
pub mod genesis;
pub mod genesis_config;
pub mod hooks;
pub mod keys;
pub mod module_resolver;
pub mod module_store;
pub mod native;

pub use executor::{Executor, ExecutorError};
