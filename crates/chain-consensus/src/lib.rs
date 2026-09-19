//! BFT engine, fork choice, evidence detection.
//!
//! Tier A. Failure if wrong: Halt or safety break.
//! See `docs/spec.md`, "Crate layout and trust tiers".
//!
//! The consensus engine dependency itself is pinned in the workspace
//! root `Cargo.toml` (`malachite-core-consensus`, a git dependency into
//! `circlefin/malachite`'s low-level, pure/stateless core-consensus
//! library — see the comment there for why this level and not the
//! higher-level channel/actor-based ones).
//! `tests/malachite_proof_of_life.rs` proves that dependency actually
//! drives a round to decision, using Malachite's own `arc-malachitebft-
//! test` harness (its `TestContext`) — a dependency proof-of-life, not
//! this chain's own types.
//!
//! [`context`] and [`types`] are this chain's real `Context`
//! implementation, over `chain-types`' own types and real BLS12-381
//! signing/verification (`chain_types::bls`) rather than test stubs.
//! `tests/context_proof_of_life.rs` drives a round to commit through
//! this real `Context`.
//!
//! Proposer selection (`context::ThrylosContext::select_proposer`) is the
//! stake-weighted beacon draw in [`proposer`]: seeded by randomness the
//! previous block fixed (`chain_types::beacon`), so the schedule cannot be
//! computed before that block is decided, and every node can check the
//! result afterwards. [`certificate`] verifies commit, polka and round
//! certificates against a validator set.
//!
//! [`host`] is the loop around the engine: it owns the engine's I/O,
//! signing through `chain-signer` (guarded so a restart cannot sign two
//! things at one position), execution through `chain-exec`'s `Engine`, and
//! block distribution. It keeps a write-ahead log so that a restart in the
//! middle of a height replays to the state it left, and it catches up from
//! peers when it has missed a height — asking, and then verifying and
//! executing everything it is told for itself. [`wire`] is the byte encoding
//! of what hosts send each other and of what the log holds.
//! `tests/network.rs` runs four hosts, each with a real executor, against a
//! simulated network that carries every message through the wire encoding;
//! it stages every kind of trouble, including a restart of each node after
//! each of the events it handles.
//!
//! The host's storage is a set of traits (`host::ports`) with in-memory
//! implementations for tests; `chain-db`'s `HeightLog` is the durable
//! primitive for the write-ahead log. Not built yet: the durable
//! implementations wired to a node, and observer (non-validator) nodes — see
//! the `host` module docs.

#![forbid(unsafe_code)]

pub mod certificate;
pub mod context;
pub mod evidence;
pub mod host;
pub mod proposer;
pub mod types;
pub mod wire;
