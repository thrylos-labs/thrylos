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
//! test` harness (its `TestContext`) — not yet this chain's own types.
//!
//! No production integration exists here yet. Building one means:
//! implementing `Context` for this chain's own `Address`/`Height`/
//! `Value`/`Vote`/etc. (from `chain-types`), a `Host` that answers the
//! engine's `Effect`s (get validator set, sign votes via `chain-signer`,
//! get a value to propose via `chain-exec`, ...), and proposer selection
//! — which the spec wants VRF-based, and no VRF library has been chosen
//! yet, so a first real integration would start with plain round-robin
//! selection, explicitly flagged as insecure (`docs/spec.md`,
//! "Consensus": a deterministic round-robin "is a targeting list").

#![forbid(unsafe_code)]
