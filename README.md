# Thrylos

A single-client, Move-based proof-of-stake L1 in Rust, optimised for auditability over feature count.

The full technical spec, including the open decisions that still need answers before genesis, is at [docs/spec.md](docs/spec.md). Its implementation status and evidence are tracked in the [spec-conformance ledger](docs/spec-conformance.md). Read the Requirements and Open decisions sections first — most of the parameters in this repo are defaults to be argued with, not settled decisions.

## Try it today

The Rust toolchain is pinned in `rust-toolchain.toml`, so `rustup` installs the right one on first use.

A local network of four validators runs on your machine, each a `chain-node` process with its own `chain-signer` process holding its key. It makes a block a second, empty unless you send it a transaction:

```bash
cargo build -p chain-node --bins                       # the node and the signer, side by side
target/debug/chain-node devnet init /tmp/thrylos-devnet   # write four validators' files, on 127.0.0.1
target/debug/chain-node devnet start /tmp/thrylos-devnet  # run them (Ctrl-C stops them)
tail -f /tmp/thrylos-devnet/node1/node.log             # "committed block 1 (0 transactions)", ...
target/debug/chain-node devnet bump /tmp/thrylos-devnet   # sign a transaction with a funded test account, send it over RPC, watch it get included
curl -s -d '{"jsonrpc":"2.0","id":1,"method":"status"}' http://127.0.0.1:26660   # node 1's RPC (`devnet init` prints them)
```

`devnet init` takes `--validators <1 to 65>` (four by default), `--base-port <port>` and `--block-interval-ms <ms>` (1000 by default, the spec's one-second target: after committing a block every node waits that long before starting the next height), and refuses a directory that already holds anything. Keep its path short: a signer's Unix socket path may be at most 100 bytes, and it says so if yours is longer. Each node serves a JSON-RPC on the loopback address only, in the ports after the peer ports: `status`, `block`, `commit`, `account` and `send_transaction` (see `chain-rpc`; addresses are `thry1…`, amounts are decimal strings in base units, hashes are hex). `devnet bump [--node n] [--account 1-4] [--amount n]` uses it as a client. **It is insecure by design**: every consensus key is derived from a public seed, exactly as in the development genesis below, so nothing on it can hold value. `devnet start --until-height <n>` runs until every node has committed that height, then stops them all cleanly and exits, which is how the tests use it. A node started later than the others can take a few seconds to catch up, and `start` waits for it.

The genesis tool works on its own too:

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

Thrylos is pre-genesis. There is a `chain-node` binary that runs a validator: it
reads a configuration file, opens or restores its chain from disk, reaches its
signer, connects to its static peers and runs consensus, and `chain-node devnet`
generates and runs a local network of them. Each node has a transaction pool:
a transaction handed to it, by RPC or by a trusted peer, is checked against
the chain, passed on to the others, included by whichever validator proposes next
and run on all of them. A local RPC (five calls, loopback only) reports the chain
and takes transactions. Its tests run
four validators as separate processes, kill them with `SIGKILL` and start them
again; nothing has yet run on more than one machine.

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
| **Peer network** (`chain-node`, `chain-p2p`) | `PeerNetwork` keeps a node connected to its static peers over real sockets: the lower peer ID dials, redials back off and reset, handshakes run on a bounded pool of short threads so a silent stranger holds up only one, and every queue is bounded with a stated overflow policy (`send` never blocks). The transport gained split reader and writer halves, a quiet-link-safe read, and a closer. Tested on loopback: routing across four nodes, transactions, a node leaving and returning on the same port, quiet links staying up, strangers kept out, and prompt shutdown |
| **Node** (`chain-node`) | The `chain-node` binary and the library behind it: a JSON configuration (unknown fields refused, secrets in private files), `run_node`, which assembles a node in the order that fails earliest (signer before any file is created), an event loop that joins the peer network to the driver, and a filter that rejects a vote, proposal or catch-up request naming a different author than the peer it arrived from. Tested by starting four nodes from configuration files, killing and restarting one from its disk while the others carry on, and a node whose signer refuses halting with the reason while the rest finish the chain. `chain-node devnet init` writes the files of a local network (an insecure development genesis for one to 65 validators, fresh transport keys and signer credentials each time, nothing ever overwritten), and `devnet start` runs it as a signer process and a node process per validator, stopping the nodes cleanly through their standard input. Tested by running four real `chain-signer` and `chain-node` processes to a height, then, killing one node with `SIGKILL` at a random moment and starting it again, then killing that node and its signer together and starting both again, then killing every signer and node at random moments eight times over, and checking that all four end on one chain and the victim never repeats a height |
| **Block relay** (`chain-p2p`, `chain-node`) | A block with transactions is announced to peers in compact form (its header, its hash and an eight-byte identifier per transaction) instead of being sent whole; a receiver puts it back together from the transactions it already holds, asks the proposer for any it lacks, checks the result against the announced hash and hands the host an ordinary block. New frame kinds with their own hard size caps, and a relay that is bounded and takes announcements only from the validator named as proposer. At the four MiB cap a proposer uploads 16.6 MiB to 127 peers instead of 508 MiB (0.14 s against 4.3 s at 1 Gbps), measured over real authenticated sockets | Relaying through other validators (the transport holds 64 peers, so more than 65 validators is not a full mesh), answers from any validator that has the block, propagation measured across real networks |
| **Node driver** (`chain-node`) | `NodeRuntime`: the driver around the consensus host, with no sockets or threads. It keeps the host's timers, routes its outbox to everyone or to one validator, and wakes it for its own catch-up requests, all in time supplied by the caller. The four-validator simulation runs on it |
| **Text forms** (`chain-text`) | Checksummed `thry1…` addresses (bech32m: every single-character typo is caught) and `THRY` amounts (nine decimal places, exact, refusing ambiguous input), used by the `chain-genesis` tool. Presentation only: the chain still counts raw address bytes and base units |
| **P2P** (`chain-p2p`) | One mutual-Ed25519-authenticated TCP transport with session-bound signed frames for consensus, block catch-up and transaction submission; static trusted peers; hard frame, byte-rate and connection bounds enforced before decode |
| **Verification** | cargo-fuzz targets for the wire and storage decoders, state transitions, the seven protocol calls and metering cost per gas (smoke-run in CI, longer scheduled runs), and a TLA+ model of one consensus height (safety, and liveness after synchrony) that CI runs through TLC. The model is an abstraction: cryptography, encoding, proposer selection and crash durability stay in the Rust tests |

The consensus tests run four full validators, each with a real executor, against a simulated network that sends every message through the real wire encoding. They stage a silent proposer, a fast clock, a forged reveal, equivocation, a node that never receives blocks, and a restart of each node after each of the events it handles.

### Other runtime libraries

| Area | What exists | What is missing |
|---|---|---|
| **RPC** (`chain-rpc`, `chain-node`) | Five JSON-RPC 2.0 calls over a small HTTP server that only listens on the loopback and is bounded everywhere (workers, backlog, header and body size, time limits, queue to the node): `status`, `block`, `commit`, `account`, `send_transaction`. Answered on the event loop's own thread, a bounded number per pass, so a burst cannot hold up consensus. A refused transaction comes back with the name of the rule it broke. Tested with four real nodes over HTTP (a transaction sent to one, seen included and agreed on at another, with the commit certificate and every refusal) and with the real `devnet bump` command against running processes | Receipts and a transaction index (a client cannot see that a transaction *failed*, only whether it was included), subscriptions, tracing |
| **Mempool** (`chain-mempool`, `chain-node`) | Admission rules, fee-bump replacement, per-sender eviction, fee-ordered selection for proposals, and cleanup after a block commits (what it executed, what its sender can no longer pay for, what has expired). In the node it is one pool that is both the host's source of transactions and the event loop's intake, reading accounts and the base fee from the same chain the host drives, and passing what is new to it on to every peer but the one it came from. Tested end to end: four running nodes, a transaction handed to one, a watcher that only a second node can have told, the counter it bumps run once on all four, and one sender's transactions included in order | Gossip that is smarter than telling everyone |

### Known problems

* **A node that starts later than the others can be slow to join.** When a local network starts, the first node sometimes has committed nothing when the others have committed five blocks. It caught up in every run where the chain kept going (24 of 24); why it starts slowly has not been looked into.

### Not built yet

* More than 65 validators: the transport holds at most 64 peers, so a full mesh stops there. Past it a proposer cannot reach everyone directly, and blocks and votes would need relaying through other validators, which does not exist (the spec's set is 128)
* Receipts: a client can see that its transaction was included, not whether it succeeded in execution (there is no transaction index, and outcomes are not stored)
* A run on separate machines (a local network of separate processes works)
* JSON-RPC (`chain-rpc` is a placeholder)
* Downtime detection, so jailed validators can actually be released
* Snapshots, pruning and warp sync
* A calibrated gas schedule: metering is fuzzed against a provisional time-per-gas ceiling, but nothing is measured on reference hardware yet
* Observer (non-validator) nodes
* The rest of the developer workflow: deploying a Move module (the transaction format carries calls, and there is no publish path yet), and signing tools other than the devnet's own `bump`

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
