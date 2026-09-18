//! BFT engine, fork choice, evidence detection.
//!
//! Tier A. Failure if wrong: Halt or safety break.
//! See `docs/spec.md`, "Crate layout and trust tiers".

#![forbid(unsafe_code)]
