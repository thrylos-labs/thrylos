//! The only map/set types tier A code may use. Re-exported here so every
//! crate imports them from one place, backed by the `disallowed_types`
//! clippy lint (see `clippy.toml`) which bans `std::collections::HashMap`
//! and `HashSet` outright. See `docs/spec.md`, "Determinism rules": "Only
//! `BTreeMap`/`BTreeSet` re-exported; std maps banned by lint".

pub use std::collections::{BTreeMap, BTreeSet};
