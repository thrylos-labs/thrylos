# Thrylos

**A Move-based proof-of-stake L1 written in Rust, optimised for auditability over feature count.**

**Status:** Pre-genesis · Active development · Contributors welcome

## Join the community

💬 **Discord:** https://discord.gg/nT2Xcy4QB6

Thrylos is an experimental Layer 1 blockchain built around a simple idea:

> Keep the consensus-critical surface small enough that developers can reason about it, test it, and audit it.

Rather than inventing a new VM, consensus protocol or cryptography stack, Thrylos reuses proven components where possible and focuses on deterministic execution, explicit bounds, crash recovery and adversarial testing.

The architecture is still evolving. If you work on Rust, distributed systems, consensus, networking, Move, formal verification or developer tooling, contributions are welcome.

## What works today

Thrylos already runs as a local multi-validator network.

* ✅ Four-validator local devnet
* ✅ MoveVM execution
* ✅ BFT consensus
* ✅ Proof-of-stake validator set
* ✅ Separate validator signer with slash protection
* ✅ Crash recovery and write-ahead logging
* ✅ Authenticated P2P networking
* ✅ Transaction mempool and propagation
* ✅ JSON-RPC
* ✅ Compact block relay
* ✅ Fuzz testing
* ✅ TLA+ consensus model
* ✅ Deterministic consensus-critical crates

Tests deliberately kill validators and signers with `SIGKILL`, restart them from disk and verify that the network converges back onto the same chain without repeating signed consensus positions.

## Try Thrylos locally

### 1. Build

```bash
cargo build -p chain-node --bins
```

### 2. Create a four-validator devnet

```bash
target/debug/chain-node devnet init /tmp/thrylos-devnet
```

### 3. Start it

```bash
target/debug/chain-node devnet start /tmp/thrylos-devnet
```

The command prints the RPC address for each validator and suggested commands to try next.

### 4. Send a transaction

In another terminal:

```bash
target/debug/chain-node devnet bump /tmp/thrylos-devnet
```

This signs a transaction using a funded development account, submits it over RPC and waits for it to be included.

### 5. Check the network

```bash
target/debug/chain-node devnet check /tmp/thrylos-devnet
```

This checks that the validators are still committing blocks and agree on the latest commit certificate.

### Watch blocks

```bash
tail -f /tmp/thrylos-devnet/node1/node.log
```

### Query the RPC

```bash
curl -s \
  -d '{"jsonrpc":"2.0","id":1,"method":"status"}' \
  http://127.0.0.1:26660
```

Run:

```bash
target/debug/chain-node --help
```

for the complete CLI.

For a longer single-machine run, restart testing, compatibility vectors and
the safe boundary for a local explorer, see
[`docs/single-host-testnet.md`](docs/single-host-testnet.md). The fixed hashes
and encodings are recorded in
[`docs/compatibility-vectors.md`](docs/compatibility-vectors.md).

## Contributing

Thrylos is early, and several important parts of the system are intentionally unfinished.

That makes this a good time to get involved.

We'd especially like contributions from people interested in:

* Rust
* distributed systems
* consensus
* peer-to-peer networking
* storage engines
* Move / MoveVM
* fuzzing
* formal verification
* protocol testing
* developer tooling

Take a look at the open issues and Discussions, or find something in the architecture you disagree with and challenge it.

Good technical criticism is a contribution too.

### Build and test everything

```bash
cargo build --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Fuzzing is documented in [`fuzz/README.md`](fuzz/README.md).

The TLA+ consensus model lives in [`formal/consensus`](formal/consensus).

## Design philosophy

Thrylos is intentionally opinionated about its trust surface.

### Reuse instead of invent

Novel VMs, consensus protocols and cryptography all create additional audit surface.

Thrylos therefore uses:

* MoveVM for smart-contract execution
* Malachite for BFT consensus
* BLS12-381 validator signatures
* Ed25519 for accounts and transport identities
* BLAKE3 for hashing

These dependencies are pinned and treated as part of the security boundary.

### Determinism should be enforced

Consensus-critical code should not rely on developers remembering what is safe.

Tier A crates use strict linting and CI rules that restrict things such as:

* `unsafe`
* `unwrap` / `expect`
* `panic!`
* floating-point arithmetic
* non-deterministic collections
* wall-clock time
* ambient randomness

Consensus-critical output should be byte-identical across machines.

### Everything remotely controlled should be bounded

Network frames, queues, block sizes, transaction sizes, peer counts and other attacker-influenced resources have explicit limits.

Unbounded growth in a validator is treated as a protocol risk, not an implementation detail.

## Architecture

The workspace is divided by trust tier.

| Directory    | Role                                            | Tier |
| ------------ | ----------------------------------------------- | ---- |
| `types`      | Consensus-critical types and canonical encoding | A    |
| `state`      | Merkle state and account model                  | A    |
| `exec`       | Block execution around MoveVM                   | A    |
| `modules`    | Staking, rewards, fees, governance and evidence | A    |
| `consensus`  | BFT consensus and certificate verification      | A    |
| `engine-api` | Consensus/execution boundary                    | A    |
| `signer`     | Consensus signer and slash protection           | A    |
| `db`         | Persistent storage                              | B    |
| `p2p`        | Authenticated transport and ingress limits      | B    |
| `mempool`    | Transaction admission and selection             | B    |
| `rpc`        | JSON-RPC                                        | C    |
| `genesis`    | Genesis configuration and tooling               | C    |
| `node`       | Validator runtime                               | B    |
| `text`       | Human-readable addresses and THRY amounts       | C    |

Tier A code is consensus-critical.

A bug there can create a fork, halt the chain or lose funds, so its rules are intentionally stricter.

## Execution

Thrylos integrates MoveVM directly rather than creating a custom Move dialect.

Execution currently supports:

* metered Move calls
* explicit transaction gas limits
* block gas limits
* declared object access
* transaction rollback on Move abort
* fee accounting
* state-root verification
* supply-conservation checks
* staking and governance protocol calls

User module publishing is not yet implemented.

Modules will be immutable in v1.

## Consensus

Thrylos uses a BFT proof-of-stake design with deterministic finality.

Current consensus features include:

* stake-weighted proposer selection
* BLS12-381 validator signatures
* proof-of-possession checking
* commit certificates
* equivocation detection
* write-ahead logging
* crash recovery
* peer catch-up
* separate validator signing process

A committed block is intended to be final rather than part of a probabilistic fork-choice chain.

## Networking

Validators currently use mutually authenticated TCP connections to a static set of trusted peers.

For the first testnet, that same validator membership is fixed in genesis and capped at 65. A node refuses to start unless its local validator and authenticated validator peers exactly cover genesis membership. The transaction-level registration call can bootstrap only an empty development chain; it cannot add a validator after launch.

The networking stack includes:

* Ed25519-authenticated peers
* session-bound signed frames
* bounded incoming and outgoing queues
* connection limits
* frame-size limits
* byte-rate limits
* reconnect backoff
* transaction propagation
* block catch-up
* compact block relay

The first testnet is intentionally keeping discovery and reputation systems out of scope.

## Storage and crash recovery

Blocks and state are stored using MDBX.

Each block is committed atomically with its resulting state.

The node verifies stored state when restarting and refuses to continue if the database does not match the expected genesis or state root.

Tests repeatedly kill nodes while they are running and verify that recovery occurs at a valid block boundary.

## RPC

The node currently exposes six JSON-RPC methods:

* `status`
* `block`
* `commit`
* `account`
* `send_transaction`
* `transaction`

The RPC server is currently intended for local use and listens on loopback.

## Genesis tooling

Generate a development genesis:

```bash
cargo run -p chain-genesis -- devnet > devnet.json
```

Validate it:

```bash
cargo run -p chain-genesis -- check devnet.json
```

Generate the human-readable address for an Ed25519 public key:

```bash
cargo run -p chain-genesis -- address <ed25519-public-key-hex>
```

Verify an address:

```bash
cargo run -p chain-genesis -- verify-address thry1…
```

Thrylos addresses use **bech32m** and begin with `thry1…`.

The native token ticker is **THRY**, with nine decimal places.

## Verification

Thrylos treats testing and verification as part of the protocol design.

Current verification work includes:

* malformed-input codec tests
* state-transition fuzzing
* protocol-call fuzzing
* gas-metering fuzzing
* real-socket networking tests
* validator crash/restart tests
* signer crash/restart tests
* four-validator consensus simulations
* TLA+ safety and liveness modelling

The consensus test suite includes scenarios such as silent proposers, equivocation, forged randomness reveals, validators missing blocks, validator restarts and network catch-up.

## Known limitations

Thrylos is pre-genesis and should not be treated as production-ready.

Known gaps include:

* validator networking beyond the current full-mesh limit
* post-testnet dynamic validator admission and peer key rotation
* real multi-machine testnet operation
* snapshots, pruning and warp sync
* calibrated gas pricing on reference hardware
* observer/non-validator nodes
* downtime detection
* fuller transaction receipts and events
* Move module publishing
* general developer signing/build tooling
* recovery tooling for a halted network

These are active areas for development rather than hidden limitations.

## Specification

The full technical specification is available at [`docs/spec.md`](docs/spec.md).

Implementation status is tracked separately in [`docs/spec-conformance.md`](docs/spec-conformance.md).

The architecture and protocol parameters are **not final**.

Many current values are defaults intended to be challenged rather than permanent decisions.

## Community

💬 **Discord:** https://discord.gg/nT2Xcy4QB6

You can also start a conversation in GitHub Discussions.

If something looks wrong, unclear or unnecessarily complicated, open an issue.

**Thrylos is being built in the open.**
