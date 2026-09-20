# Specification conformance ledger

2026-09-19

This ledger maps the requirements in [`spec.md`](spec.md) to implementation
and verification evidence. It is the status document; the specification is
the intended protocol. A feature is not conforming merely because a type or
constant exists. It needs an enforced production path and a test, model or
measurement that would fail if the property regressed.

Status meanings:

- **Conforms** — the production path enforces the requirement and automated
  evidence covers the important failure mode.
- **Partial** — a real implementation exists, but a required path, bound or
  verification layer is absent.
- **Missing** — no production implementation exists.
- **Deferred** — explicitly outside v1; it must not silently enter the trust
  surface.
- **Open decision** — product or operating input is required before the
  requirement can be fixed.

## Resolved design disagreements

| ID | Resolution | Reason and evidence |
|---|---|---|
| D-001 | Keep the consensus/execution boundary in-process for v1, with three mutating engine calls and a read-only view. | Process isolation adds a transport and recovery protocol without reducing the code that must be trusted. The narrow typed boundary remains independently testable (`chain-engine-api`). |
| D-002 | Keep validator-specific BLS signatures as a list in certificates. Add aggregate certificates only if the reference-hardware budget fails. | This is Malachite's native model and keeps the validator identity in the signed bytes. Aggregation would require a second signed-message format and participation bitfield. On 2026-09-19 three runs of the production verifier measured 83.9–118.8 ms p99 for 128 signatures; the encoded commit record was 16,584 bytes on an Apple M2 with 8 CPU cores and 16 GB memory. All runs pass the provisional 200 ms and 32 KiB ceilings. Repeat with `cargo test --release -p chain-consensus --test certificate_budget -- --ignored --nocapture`; the result remains provisional until launch reference hardware is named. |
| D-003 | Freeze seven transaction-level protocol calls for staking, evidence and governance; do not expose them as custom MoveVM natives in v1. | The implemented calls cover validator entry, exit, recovery, evidence and minimal governance. Share-price rewards need no claim call, and consensus reads the validator set through the engine view. See `crates/exec/src/native.rs`. |
| D-004 | Keep one dynamic fee dimension, compute, and charge a fixed one-time deposit for persistent bytes. | This reconciles the permanent state-cost requirement with the decision not to build a multidimensional EIP-1559 market. The deposit is still missing in code. |
| D-005 | User modules are immutable in v1. Code or storage-layout replacement requires a named fork and explicit migration. | This removes the transaction-level upgrade and compatibility-checking surface. Governance schedules a named fork but cannot replace code. |
| D-006 | Require no ambient I/O on the consensus execution path; do not require literal `no_std` compatibility. | Pinned MoveVM and Malachite dependencies use `std`. The auditable property is absence of filesystem, network, process and environment inputs during deterministic execution. Genesis still violates this by compiling through temporary files and is tracked below. |
| D-007 | Remove the total-line-count target. Track audit scope by trust tier, dependency revision, boundary size, bounds and verification evidence. | On 2026-09-19 the crate source trees contain 27,096 lines of Rust, including unit tests embedded beside production code, and 33,980 with integration tests. The node and sync paths are still incomplete. Dependency code remains part of the review surface even when first-party glue is short. |
| D-008 | Use one mutually authenticated TCP transport and a static trusted-peer allowlist for the first testnet. | This carries consensus, bounded block catch-up and transaction submission without adding discovery, multiple transports, ASN data or a reputation subsystem. Loopback tests exercise real sockets, mutual Ed25519 authentication and session-bound signed frames. |
| D-009 | Separate the consensus signer with one authenticated Unix-socket protocol; defer remote custody adapters and key rotation. | The signer process exposes only fixed-domain consensus signing, deterministic beacon signing and mark inspection. Keyed BLAKE3 authenticates bounded requests and binds each response to its request without adding TLS, HTTP or a general RPC framework. |

## Scope and architecture

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Single client; no bridge, privacy system, sharding or parallel execution in v1 | **Conforms** | Workspace crate list and dependency graph contain none of these subsystems. | Keep them outside v1 unless the specification and threat model change first. |
| MoveVM and Malachite are reused at pinned revisions rather than forked | **Conforms** | Root `Cargo.toml`; Move and Malachite proof-of-life tests. | Add a documented dependency-upgrade and re-audit procedure. |
| Trust-tier crate split and Tier A lint policy | **Partial** | Workspace lints, `clippy.toml`, CI `tier-a-deps` job. | Add the compiled-symbol float check promised by the spec, dependency/source I/O scan, and eliminate or explicitly type away production panic sites. |
| Engine boundary is narrow and deterministic | **Conforms** | `chain-engine-api::Engine`, `ChainView`; real executor and consensus-host tests. | Add differential fuzzing at the boundary. |
| `chain-node` and `chain-genesis` have explicit trust tiers | **Conforms** | The specification assigns node B and genesis C; both crates inherit the workspace lint policy. | Revisit the tier only if either crate gains consensus-critical logic. |

## Consensus

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Malachite drives single-slot BFT finality | **Conforms** | `chain-consensus` context/host plus four-validator simulated-network tests. | Formal safety and liveness model remains a separate row. |
| Active set is the top 128 validators by stake | **Conforms** | `MAX_ACTIVE_VALIDATORS`; registry cap and ordering tests. | None for the current design. |
| Stake-weighted, previous-block-seeded unpredictable proposer selection | **Conforms** | `chain-consensus::proposer`, BLS beacon, forged-reveal and schedule tests. | Analyse last-revealer withholding in the formal model. |
| BLS keys use proof of possession and subgroup validation | **Conforms** | `chain-types::bls`; registration and genesis validation tests. | None for the current scheme. |
| Certificates use individual validator-specific signatures resolved against the canonical set | **Conforms** | `chain-consensus::certificate`; outsider, duplicate, wrong-key and quorum tests. | Re-run the budget test on named reference hardware before freezing the format for genesis. |
| Certificate verification and propagation fit the round budget | **Partial** | Ignored `certificate_budget` test enforces provisional ceilings of 200 ms p99 and 32 KiB. Three 2026-09-19 development-machine runs measured 83.9–118.8 ms p99 and encoded to 16,584 bytes. | Name launch reference hardware, repeat the blocking measurement there, and measure full-block propagation through the real transport. |
| Safety and eventual-synchrony liveness are model-checked | **Missing** | No TLA+ or Quint model exists. | Model the actual Malachite adapter, proposer beacon, validator-set changes and catch-up assumptions. |
| Four MiB hard block cap is enforced independently of gas | **Conforms** | `Block::encoded_len` measures the canonical representation linearly; proposal clamps caller limits to `MAX_BLOCK_SIZE_BYTES`, while execution and finalisation reject oversized blocks. Tests cover oversized proposals and validation. The transport also rejects consensus envelopes above its bounded two-block catch-up ceiling before allocation. | Keep the block-level check in consensus validation because one bounded envelope can contain more than one block. |
| A transaction cannot consume over 25% of the block execution budget | **Conforms** | `max_transaction_gas` derives one protocol ceiling from the active block limit. Proposal skips larger budgets and validation rejects them with the transaction index; tests cover the boundary and governance-lowered limits. | Retain the same rule when the gas schedule is recalibrated. |

## Execution and contract model

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Invalid transactions reject a block; execution aborts roll back call effects but charge gas | **Conforms** | `chain-exec::Executor` and integration tests cover validation failures, metered Move aborts and structurally rolled-back effects. | Extend the same evidence to immutable user modules when publishing exists. |
| Transactions declare every object they may touch | **Partial** | Enforced for the single counter object. | Generalise it to published modules and runtime-created objects without ambient lookup. |
| MoveVM execution and protocol calls are deterministically metered | **Partial** | The two production Move paths use the pinned VM's tiered meter, stop at the signed budget and report consumed gas on success and abort. The seven Rust protocol calls still charge the declared limit. | Measure and calibrate the Move schedule on reference hardware, then assign measured charges to the seven bounded protocol calls. |
| Gas schedule entries are governance-clamped to 4x genesis values | **Missing** | `chain-modules::params` explicitly records that no gas schedule exists. | Add only after the measured schedule exists. |
| Standard library is embedded unmodified and general user modules can be published | **Missing** | Genesis compiles two fixed demonstration modules; arbitrary dispatch and publishing do not exist. | Embed audited upstream bytecode, implement immutable publication and remove production compiler/file-I/O dependencies. |
| User modules are immutable; replacement is a named fork plus migration | **Partial** | No module-upgrade transaction exists; governance can schedule fork names. | Add the fork rule-selection and migration machinery before the first upgrade. |
| Frozen seven-call protocol boundary | **Partial** | All seven calls are dispatched in `chain-exec::native` and exercised by tests. | Add real metering and one fuzz target per call; freeze byte-level argument schemas. |
| Block execution has no ambient I/O | **Partial** | Per-block execution is in-memory and clock-free. Genesis compilation uses `tempfile` and `std::fs`. | Embed precompiled genesis bytecode and add the source/dependency scan described by D-006. |
| Supply, staking-ledger and governance invariants stop an invalid transition | **Conforms** | Per-block conservation check, module invariant checks and property tests. | Add continuous invariant fuzzing and Kani coverage for arithmetic kernels. |

## State, storage and sync

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| BLAKE3 domain-separated binary Merkle root over sorted flat state | **Conforms** | `chain-state::trie` and property tests. | Retain the simple implementation as a reference when introducing incremental updates. |
| Execution cost is bounded independently of total historical state | **Missing** | Execution and finalisation clone the whole state, recompute the whole root and diff the whole map. | Introduce write-set execution and incremental trie updates; prove equivalence against the reference implementation. |
| Block, root and state diff commit atomically | **Partial** | MDBX transaction and process-kill crash test in `chain-db`. | Wire this store into the real finalisation/restart path. |
| A node restarts from durable canonical chain state | **Missing** | Consensus logs are durable, but no node binary connects executor finalisation to MDBX restoration. | Build the minimal node runtime and replay recovery before networking features. |
| Full replay, snapshot and weak-subjectivity warp produce identical roots in CI | **Missing** | No snapshot or warp implementation. | Implement all three paths and a single cross-mode root-equivalence fixture. |
| Pruning preserves the unbonding window | **Missing** | No pruning implementation. | Add only after snapshot/warp formats and retention invariants are fixed. |
| Persistent state growth pays a fixed deposit | **Missing** | No general creation path or storage deposit exists. | Define byte accounting and deletion refunds together with immutable module/object creation. |
| Signed weak-subjectivity checkpoints constrain initial sync | **Missing** | No checkpoint release or node enforcement path. | Define checkpoint format, signer policy, two publication channels and loud override semantics. |

## Staking, fees and governance

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Dead shares, widened arithmetic, user-adverse rounding and ledger invariants | **Conforms** | `chain-modules::staking` and registry property tests. | Add Kani proofs for the arithmetic core. |
| One-dimensional EIP-1559 compute base fee | **Partial** | Fee arithmetic, state integration, governed block-gas limits and actual MoveVM gas usage are tested. | Replace declared-limit charging for protocol calls and calibrate all charges on reference hardware. |
| Minimal parameter/fork governance with clamps and 48-hour timelock | **Conforms** | Governance lifecycle, clamp, snapshot-voting and fork-lead tests. | Exercise a real binary rule change and migration on testnet. |
| Correlation-aware double-sign slashing; downtime jails without burning | **Partial** | Evidence admission, correlated penalties, jailing and unjailing are implemented. | Add deterministic downtime detection and chain-wide-halt suspension. |
| Unbonding period exceeds evidence age and fork-choice horizon | **Conforms** | Genesis/parameter validation and signer timing tests. | None for current constants. |

## P2P, mempool and external interfaces

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Size/rate check precedes strict decode and signature verification | **Conforms** | `TcpNetwork` reads the five-byte header, checks the per-type size cap and reserves global/per-peer budget before allocating the body; it then verifies the session-bound frame signature, strictly decodes, verifies transaction signatures and invokes the required consensus verifier. Tests prove an oversized declaration never reaches a verifier and a tampered frame never reaches message decoding. | Add malformed-frame fuzzing without changing this ordering. |
| Every remote queue, allocation and loop has a domain-specific bound | **Partial** | Consensus and transaction frame allocations have separate hard caps, connections are capped at 64, catch-up is bounded by frame size, and the reusable queue is fixed-capacity. | Audit the eventual node event loop and mempool handoff once they are wired to the transport. |
| One authenticated transport with static trusted peers and a hard peer limit | **Conforms** | `chain-p2p::TcpNetwork` uses mutual Ed25519 challenge-response authentication and signs every frame over both peers, the fresh session, type, length and sequence number. It rejects keys outside the static allowlist, duplicate peers and configurations above 64 connections. Real loopback tests cover authentication, tamper rejection and both frame types. | Run multi-host soak and partition tests; keep discovery and scoring out of v1 unless measurements require them. |
| Mempool admission, replacement and eviction rules | **Partial** | Pool rules and state-backed account view are tested. | Remove committed/expired transactions and wire the pool to finalisation. |
| Minimal JSON-RPC and tracing | **Missing** | `chain-rpc` is an empty placeholder. | Add only the calls required by the first applications and operators. |
| Observer node mode | **Missing** | Validator host only. | Add after durable replay and sync are complete. |

## Signer, operations and verification

| Spec commitment | Status | Evidence | Work required |
|---|---|---|---|
| Signer persists a monotonic high-water mark before releasing a signature | **Conforms** | `Signer::sign` persists through `FileMarkStore` before constructing a signature. Process tests kill and restart the real signer binary and prove the returned signature's mark survives. | Keep the mark file on signer-owned storage and retain the no-reset rule. |
| Consensus key lives only in a separate signer process | **Conforms** | The `chain-signer` binary alone reads the BLS secret and mark. `NodeDisk::into_ports` accepts only `RemoteSigner`, whose bounded Unix-socket protocol authenticates requests and request-bound responses. Independent node-client and signer-process kill tests prove neither crash rewinds the mark. | Add deployment packaging and secret provisioning without adding a local-signing fallback. |
| Consensus, operator and reward keys are separate and rotatable as specified | **Missing** | Roles and rotations are not implemented end to end. | Specify transaction formats, delays and recovery procedures before genesis. |
| Halt detection and certificate-based recovery runbook is implemented and rehearsed | **Missing** | The prose runbook exists only in the specification. | Add monitoring, release/restart tooling and a chaos-testnet rehearsal. |
| Named forks select old/new rules and run deterministic migrations exactly once | **Missing** | Governance stores activation heights only. | Build rule dispatch, migration receipts, replay tests and abortable activation rehearsal. |
| Reproducible builds, signed releases, checksums and `cargo-audit` CI | **Partial** | Dependencies are pinned and `cargo-deny` runs. | Add reproducible build comparison, `cargo-audit`, artifact signing and key-custody documentation. |
| Canonical codec properties and malformed-input resistance | **Partial** | Property and truncation tests exist. | Add continuous cargo-fuzz targets for every wire/storage decoder. |
| Continuous invariant, differential and metering fuzzing | **Missing** | No cargo-fuzz workspace or corpus exists. | Establish the three independent fuzz campaigns before broadening execution. |
| Loom, Miri and Kani verification | **Missing** | No jobs or harnesses exist. | Add focused boundary/signer concurrency checks and arithmetic proofs. |
| Sixty-day chaos testnet, two audits, contest and bounty | **Missing** | A real transport library exists, but there is no runnable node binary or testnet deployment. | These remain launch gates, not implementation substitutes. |

## Open product decisions

The specification's L1 need, first applications, MEV policy, validator entry,
token schedule, bridge/value cap, emergency powers and reference hardware
remain open. Until owners and applications are named, their numerical defaults
must not be treated as audited requirements.

## Next conformance gate

The next milestone is one **runnable, crash-recoverable validator process**
that joins a static network using the completed bounded transport. Remaining
work, in order:

1. wire executor finalisation and restart to MDBX in `chain-node`, including
   restoration of the canonical block, state root and validator state;
2. drive the consensus host, bounded mempool and block catch-up through
   `TcpNetwork`, supplying a consensus verifier backed by the canonical
   validator set;
3. prove every handoff queue is bounded and disconnect peers after malformed,
   unauthenticated or over-budget frames;
4. run process-kill recovery, multi-host propagation, partition and reconnect
   tests; and
5. embed genesis bytecode, calibrate execution charges, and start the focused
   model/fuzz campaigns before expanding the execution surface.

RPC, observer mode, discovery, snapshots, warp sync and pruning remain outside
this gate.
