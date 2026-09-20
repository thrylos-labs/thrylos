# Thrylos

A single-client, Move-based proof-of-stake L1 in Rust, optimised for auditability over feature count.

The full technical spec, including the open decisions that still need answers before genesis, is at [docs/spec.md](docs/spec.md). Its implementation status and evidence are tracked in the [spec-conformance ledger](docs/spec-conformance.md). Read the Requirements and Open decisions sections first — most of the parameters in this repo are defaults to be argued with, not settled decisions.

## Try it today

There is no node to run yet, but the genesis tool works. The Rust toolchain is pinned in `rust-toolchain.toml`, so `rustup` installs the right one on first use.

```bash
cargo run -p chain-genesis -- devnet > devnet.json   # a four-validator development genesis
cargo run -p chain-genesis -- check devnet.json      # validate it: hash, state root, supply, parameters, validator set
```

Addresses are written `thry1…` (bech32m: a mistyped character is always caught), and amounts are shown in tokens (`THRY`, nine decimal places; the chain itself counts in base units, and genesis files stay in base units). The tool converts and checks both:

```bash
cargo run -p chain-genesis -- address <ed25519-public-key-hex>   # the thry1… address of a key
cargo run -p chain-genesis -- verify-address thry1…              # was it copied correctly? says what is wrong if not
```

`chain-genesis hash <file>` prints only the genesis hash, and `address --hex` prints the raw bytes. Beyond that, the tests are the way in: `cargo test --workspace`.

Fuzzing is described in [fuzz/README.md](fuzz/README.md) and the TLA+ consensus model in [formal/consensus/README.md](formal/consensus/README.md).

## What is working today

Thrylos is pre-genesis. **There is no runnable node binary yet**. The authenticated
TCP transport opens real sockets in loopback tests, while consensus is also
exercised by a simulated four-validator network in one process. RPC is not built.

### Implemented and tested

| Area | What exists |
|---|---|
| **Types and encoding** (`chain-types`) | Canonical, strict byte encoding with round-trip and malformed-input tests; domain-separated hashing; Ed25519 accounts; BLS12-381 validator keys with proof-of-possession; the randomness beacon used to pick proposers |
| **State** (`chain-state`) | Account model and state root; the state diff a block produces |
| **Execution** (`chain-exec`) | Block executor around MoveVM (Mysten's `external-crates/move`, pinned by revision, not patched); hard encoded-block and per-transaction gas bounds; metered Move execution; transaction validity rules; fee accounting; a per-block supply-conservation check; epoch hooks; genesis configuration and the `chain-genesis` file tool |
| **Native modules** (`chain-modules`) | Staking and delegation with share-price rewards, unbonding, double-sign slashing from evidence, fees, and parameter-only governance, all stored in chain state |
| **Consensus** (`chain-consensus`) | Malachite's pure core integrated end to end: stake-weighted proposer selection from a randomness beacon, certificate verification, block judging before voting, a host that will not sign twice at a position, a write-ahead log with replay after a crash, and verified catch-up from peers for a node that missed a height |
| **Storage** (`chain-db`, `chain-node`) | MDBX block and state store with atomic per-block commits and a recorded genesis; a checksummed, torn-write-tolerant height log; the file-backed storage the consensus host keeps (write-ahead log, record of what it signed, commit history); and `DurableEngine`, which commits each block to the database before the chain advances and restores the chain on restart, refusing a database from another genesis or one that fails its root and audit checks. Checked by killing a committing process, and by a four-validator crash sweep that reloads every node's chain from disk |
| **Signer** (`chain-signer`, `chain-node`) | The high-water-mark state machine that refuses to sign at or below a position it has signed, and a separate `chain-signer` process that alone holds the consensus key and its mark and answers over an authenticated Unix socket. The node's ports accept only that client, never a key, and tests kill and restart each side to check the mark never rewinds |
| **Text forms** (`chain-text`) | Checksummed `thry1…` addresses (bech32m: every single-character typo is caught) and `THRY` amounts (nine decimal places, exact, refusing ambiguous input), used by the `chain-genesis` tool. Presentation only: the chain still counts raw address bytes and base units |
| **P2P** (`chain-p2p`) | One mutual-Ed25519-authenticated TCP transport with session-bound signed frames for consensus, block catch-up and transaction submission; static trusted peers; hard frame, byte-rate and connection bounds enforced before decode |
| **Verification** | cargo-fuzz targets for the wire and storage decoders, state transitions, the seven protocol calls and metering cost per gas (smoke-run in CI, longer scheduled runs), and a TLA+ model of one consensus height (safety, and liveness after synchrony) that CI runs through TLC. The model is an abstraction: cryptography, encoding, proposer selection and crash durability stay in the Rust tests |

The consensus tests run four full validators, each with a real executor, against a simulated network that sends every message through the real wire encoding. They stage a silent proposer, a fast clock, a forged reveal, equivocation, a node that never receives blocks, and a restart of each node after each of the events it handles.

### Other runtime libraries

| Area | What exists | What is missing |
|---|---|---|
| **Mempool** (`chain-mempool`) | Admission rules, fee-bump replacement, per-sender eviction, fee-ordered selection for proposals | Cleanup after a block commits |

### Not built yet

* A node binary that wires these pieces together
* JSON-RPC (`chain-rpc` is a placeholder)
* Downtime detection, so jailed validators can actually be released
* Snapshots, pruning and warp sync
* A calibrated gas schedule: metering is fuzzed against a provisional time-per-gas ceiling, but nothing is measured on reference hardware yet
* Observer (non-validator) nodes
* The developer workflow: local network, deploy a Move module, submit a transaction, see it finalize

### Size and audit scope

Line counts are not a target. Audit scope is tracked by trust tier, dependency revision, boundary size, enforced bounds and verification evidence in the [conformance ledger](docs/spec-conformance.md), which also says, requirement by requirement, what is done, partial or missing.

### What "no unsafe, no panics" covers

The lints apply to the crates in this repository. Dependencies (MoveVM, Malachite, `blst`) are upstream code held to no such rules. Tier A also has a few documented `assert!`s where a function's signature leaves no other way to say "this cannot happen."

The architecture and parameters are **not final**.

## Layout

Workspace crates under `crates/`, split by trust tier (see spec, "Crate layout and trust tiers"). Each directory is named for what it does; its Cargo package carries a `chain-` prefix (`crates/db` is `chain-db`), so `cargo test -p chain-db` and `use chain_db::…` are unchanged.

| Directory | Role | Tier |
|---|---|---|
| `types` | Consensus-critical types, canonical SSZ-style codec | A |
| `state` | Merkle state trie, account model | A |
| `exec` | Block executor wrapping MoveVM | A |
| `modules` | Staking, rewards, fees, governance, evidence | A |
| `consensus` | BFT engine, fork choice, evidence detection | A |
| `engine-api` | Typed boundary between consensus and execution | A |
| `signer` | Remote signer, slash protection | A |
| `db` | Storage, pruning, snapshots | B |
| `p2p` | Authenticated transport and bounded ingress | B |
| `mempool` | Tx admission, eviction, replacement | B |
| `rpc` | JSON-RPC, tracing | C |
| `genesis` | Genesis file parsing and the `chain-genesis` checker tool | C |
| `node` | The durable storage the consensus host keeps on disk, and where the node binary will be assembled (not in the spec's table) | B |
| `text` | How people read and write addresses (`thry1…`) and amounts (`THRY`); presentation only (not in the spec's table) | C |

Tier A crates must build byte-identical output on every machine. They carry `[lints] workspace = true` (see root `Cargo.toml` and `clippy.toml`), which forbids `unsafe`, `unwrap`/`expect`/`panic!`, indexing/slicing, integer division, float arithmetic, and non-deterministic collection types. Tier B/C crates are not held to that bar.

## Building

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

`deny.toml` and `.github/workflows/ci.yml` cover dependency bans, license checks, and the tier-A "no `rand`" rule.
