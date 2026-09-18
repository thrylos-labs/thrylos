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
//! Proposer selection (`context::ThrylosContext::select_proposer`) is
//! plain round-robin, **not** the spec's VRF-based scheme — no VRF
//! library has been chosen yet (`docs/spec.md`, "Consensus": a
//! deterministic round-robin "is a targeting list"). It is explicitly a
//! placeholder, flagged insecure, swappable later without touching
//! anything else in this crate.
//!
//! Still missing for a full production integration: a `Host` that owns
//! the engine's I/O loop end-to-end (wiring `chain-signer` for double-
//! sign-safe signing and `chain-exec` for real value production, rather
//! than a test's inline effect handler), and VRF-based proposer
//! selection.

#![forbid(unsafe_code)]

pub mod context;
pub mod types;
