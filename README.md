# Thrylos

A single-client, Move-based proof-of-stake L1 in Rust, optimised for auditability over feature count.

The full technical spec, including the open decisions that still need answers before genesis, is at [docs/spec.md](docs/spec.md). Read the Requirements and Open decisions sections first — most of the parameters in this repo are defaults to be argued with, not settled decisions.

## Layout

Workspace crates under `crates/`, split by trust tier (see spec, "Crate layout and trust tiers"):

| Crate | Role | Tier |
|---|---|---|
| `chain-types` | Consensus-critical types, canonical SSZ-style codec | A |
| `chain-state` | Merkle state trie, account model | A |
| `chain-exec` | Block executor wrapping MoveVM | A |
| `chain-modules` | Staking, rewards, fees, governance, evidence | A |
| `chain-consensus` | BFT engine, fork choice, evidence detection | A |
| `chain-engine-api` | Typed boundary between consensus and execution | A |
| `chain-signer` | Remote signer, slash protection | A |
| `chain-db` | Storage, pruning, snapshots | B |
| `chain-p2p` | Gossip, peer scoring, discovery | B |
| `chain-mempool` | Tx admission, eviction, replacement | B |
| `chain-rpc` | JSON-RPC, tracing | C |

Tier A crates must build byte-identical output on every machine. They carry `[lints] workspace = true` (see root `Cargo.toml` and `clippy.toml`), which forbids `unsafe`, `unwrap`/`expect`/`panic!`, indexing/slicing, integer division, float arithmetic, and non-deterministic collection types. Tier B/C crates are not held to that bar.

## Building

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`deny.toml` and `.github/workflows/ci.yml` cover dependency bans, license checks, and the tier-A "no `rand`" rule.
