# Thrylos — technical spec

Last amended 2026-09-19

Implementation status and evidence are tracked separately in
[`spec-conformance.md`](spec-conformance.md). This document defines the
intended protocol; the ledger records where the repository does and does not
yet implement it.

## Requirements

The weakest part of this document, placed first so it stays visible. Almost every number below was inherited from how chains are usually built rather than requested by someone with a problem. A requirement nobody owns is a habit, and habits are what this design is supposed to be free of.

| Requirement | Who asked | What breaks if it is wrong |
|---|---|---|
| An L1 at all, rather than a rollup | Nobody yet | Everything. A rollup removes the validator set, the bridge and most of this document |
| 1s block time | Nobody yet | Nothing measurable. Chosen because it is conventional |
| 128 validators | Nobody yet | Decentralisation claims, and vote gossip cost at larger sizes |
| Single-slot finality | Design choice, defensible | Deletes fork choice. This one earns its place |
| MoveVM | Design choice, defensible | Contract-level bug classes return |
| Permissionless validator entry | Design choice, defensible | The chain becomes permissioned, which changes what it is |

The blanks are the finding. Fill them by naming the first three applications and the person who wants each one, then check every row against what those applications actually need. Several will change; the L1 assumption itself may not survive.

Until then, treat the parameters in this document as defaults to be argued with, not decisions.

## Scope and non-goals

Thrylos is a single-client, Move-based proof-of-stake L1 in Rust, optimised for auditability over feature count. Every design choice below trades capability for a smaller reasoning surface.

Design principles:

1. Reuse rather than invent. Novel VM, novel consensus and novel cryptography are each an unaudited attack surface. MoveVM is adopted whole, unmodified, for exactly this reason.
2. Determinism is a compile-time and CI concern, not a code-review concern.
3. Every queue, loop and allocation in the state transition is explicitly bounded.
4. Anything that can halt the chain is separated from anything that can lose funds.

Explicitly out of scope for v1:

- In-protocol bridging. The canonical bridge is a separate contract system with its own audit, value cap and pause.
- Custom native functions beyond what the standard library requires, and any modification to MoveVM or the Move language. See the execution section for why.
- A second client implementation. Two clients that disagree is a worse failure than one client that is wrong.
- Privacy features, on-chain governance of the binary, and light-client proofs.
- Horizontal scaling (sharding, parallel execution). Revisit only with a real throughput measurement in hand.

## Crate layout and trust tiers

The workspace splits on one line: crates whose output must be byte-identical on every machine (tier A) and everything else. Tier A denies `unsafe`, `unwrap`, panicking indexing, floating point and ambient I/O at the lint level; the other tiers do not.

| Crate | Role | Tier | Failure if wrong |
|---|---|---|---|
| `chain-types` | Consensus-critical types, canonical SSZ-style codec | A | Fork |
| `chain-state` | Merkle state trie, account model | A | Fork |
| `chain-exec` | Block executor wrapping MoveVM | A | Fork |
| `chain-modules` | Staking, rewards, fees, governance, evidence | A | Fund loss |
| `chain-consensus` | BFT engine, fork choice, evidence detection | A | Halt or safety break |
| `chain-engine-api` | Typed boundary between consensus and execution | A | Fork |
| `chain-db` | Storage, pruning, snapshots | B | Halt, local corruption |
| `chain-p2p` | Authenticated transport and bounded ingress | B | Halt via DoS |
| `chain-mempool` | Tx admission, eviction, replacement | B | DoS, censorship |
| `chain-rpc` | JSON-RPC, tracing | C | Local only |
| `chain-signer` | Remote signer, slash protection | A | Stake burn |
| `chain-node` | Runtime assembly and durable host storage | B | Halt, local corruption |
| `chain-genesis` | Genesis file parsing and inspection CLI | C | Operator error before launch |

The consensus/execution boundary is a typed engine API with three mutating calls: `propose_block`, `execute_block`, `finalise_block`, plus a read-only chain view. The v1 implementation is in-process; process isolation here would add failure modes without removing the need to audit either side. The narrow API keeps inputs explicit, permits differential fuzzing against a reference, and allows a later transport adapter without changing execution semantics.

## Consensus

BFT proof-of-stake with single-slot deterministic finality: a committed block is final, so there is no reorg depth for applications to reason about. Use an existing engine (Malachite or a CometBFT-class Rust implementation) rather than a new protocol.

| Parameter | Value | Why this value |
|---|---|---|
| Active validator set | 128, by stake | Quadratic vote gossip stays cheap; set fits in one message |
| Block time | 1s target, 2s timeout | Timeout > 3x observed p99 propagation |
| Finality | 1 block, 2/3+ stake | No reorg assumptions downstream |
| Proposer selection | VRF, stake-weighted | Schedule is unpredictable in advance, so proposers cannot be targeted for DDoS |
| Max block gas | 60M, governance-adjustable within clamps | Repricing a broken schedule must not require a fork |
| Max block size | 4 MiB hard cap | Independent of gas; caps gossip cost |
| Unbonding period | 21 days | Must exceed max evidence age (see key management) |
| Max evidence age | 14 days | Must exceed weak-subjectivity horizon |
| Min self-stake | Non-zero, clamped in code | Prevents zero-cost validator spam |

Proposer selection uses a VRF seeded by the previous block's certificate: each validator can verify the winner after the fact, but nobody can compute the schedule ahead of time. A deterministic round-robin over a public validator set is a targeting list, and that is the whole reason for the extra complexity here.

Signatures are BLS12-381 with proof-of-possession. A certificate carries one signature and validator identity per participant; entry order has no meaning. Every public key is checked for subgroup membership on registration; verification resolves every identity against the canonical validator set, rejects duplicates and outsiders, verifies each validator-specific signed message, and totals canonical voting power. The certificate never supplies public keys or voting power.

The individual-signature representation is deliberate. It matches Malachite's certificate model and preserves validator identity in the signed bytes, which makes attribution and equivocation evidence direct. Aggregation would require a new address-free signed-message format and participation bitfield. Adopt it only if measurements on the named reference hardware show that individual verification or certificate propagation exceeds its budget; wire compactness alone is not enough reason to add the second representation.

The two properties that need proving, not testing: no two conflicting blocks can both reach 2/3+ at the same height (safety), and a correct proposer's block commits within a bounded number of rounds once the network is synchronous (liveness). Specify these in TLA+ or Quint and model-check the state machine before implementation, not after.

## Execution

MoveVM at a pinned version, adopted unmodified. No added opcodes, no language dialect, no forked prover. The moment the VM is extended, this stops being an integration and becomes a compiler project, which is the failure mode that has consumed several ambitious chains.

Move is chosen because it makes safety a property of the type system rather than a property of the audit. Resources cannot be copied or silently dropped, there is no dynamic dispatch during state mutation, arithmetic aborts rather than wrapping, and access rights are unforgeable values instead of runtime address comparisons. Each of those deletes a bug class the verification plan would otherwise have to hunt.

Block execution is a pure function with no I/O of its own:

```
flowchart LR
  A[Block + parent state] --> B[Decode, strict]
  B --> C[Resolve declared objects]
  C --> D[Per-tx: charge, execute, meter]
  D --> E[New state root]
  D -->|any tx invalid| F[Reject whole block]
```

Rules that hold for every path through it:

- Invalid transaction in a proposed block rejects the block. There is no skip-and-continue path, which would be a fork condition.
- Aborts consume gas and roll back the transaction's effects, but never abort the block.
- Transactions declare the objects they access before execution. A transaction touching an object it did not declare aborts rather than being resolved dynamically.
- Module hooks run in a fixed, compiled-in order and cannot re-enter execution.
- No syscall, clock read, file read or network access exists below the engine API. The executor takes state and a block, and returns state.

On native functions: a native is Rust reachable from attacker-controlled Move bytecode, at native speed, outside the VM's metering assumptions. It sits in both trust worlds at once, which is where mispricing and reentrancy-into-native-state bugs concentrate. Ship only the natives the standard library requires, and give each one its own metering fuzz target and its own audit scope.

## Contract model

The argument for this chain, stated as the property a developer gets: the most common ways to lose money are compile errors here, not audit findings.

| Bug class | In a mutable-state VM | Here |
|---|---|---|
| Reentrancy | Defended by a guard the developer must remember | Does not exist — no dynamic dispatch during mutation |
| Missing access control | A runtime check someone forgets | A capability must be passed in, or it does not compile |
| Lost or duplicated assets | Balance arithmetic, audited by hand | Resources are linear: dropping one is a type error |
| Silent overflow | Unchecked blocks and wrapping | Arithmetic aborts |
| Unsafe upgrade | Proxy patterns with storage-layout traps | User modules are immutable in v1; a replacement is a named protocol fork with an explicit state migration |

The three primitives developers build with:

1. **Resources.** An asset is a value of a linear type. It can be moved, but not copied and not discarded, so a function that fails to return a token does not compile. Conservation of value is checked by the compiler rather than asserted in tests.
2. **Capabilities.** The right to perform a privileged action is an unforgeable value held by whoever holds it. `AdminCap` in an argument list is legible authorisation; there is no equivalent of forgetting an `onlyOwner` modifier.
3. **Declared access.** A transaction names the objects it will touch. This makes static analysis tractable, lets a wallet show a user exactly what a transaction can reach before they sign, and leaves a clean path to parallel execution later without changing the programming model.

What this does not solve, and where audits still go: economic design, oracle dependence, governance capture and protocol-level logic errors. Move removes the mechanical bug classes. It does not remove the ones that require understanding what the protocol is supposed to do, which is where the expensive human review belongs anyway.

The standard library ships unmodified from upstream. User modules may be published but are immutable in v1. There is no transaction-level module upgrade path and governance cannot replace code; a code or storage-layout change is a named protocol fork with an explicit migration. Staking and governance use the fixed protocol entry points in the native-module-boundary section rather than extending MoveVM. Every additional entry point is an audit item and a source of divergence from ecosystem tooling, so the list is frozen for v1.

## State, storage and sync

State is a binary Merkle trie over a flat key-value store (MDBX or redb), with the flat layout as the source of truth and the trie derived. Hashing is BLAKE3 throughout, with a single, versioned domain-separation prefix per node type so that two different structures can never produce the same hash.

Three sync modes must produce byte-identical state roots at the same height:

1. Full replay from genesis.
2. Snapshot sync from a state dump plus header verification.
3. Warp from a weak-subjectivity checkpoint inside the unbonding window.

This equality is a CI test on every commit, not an assumption. Divergence between snapshot-synced and replayed nodes is a bug class that hides for months and then presents as a mysterious minority fork.

Further rules:

- Writes are batched per block and committed atomically with the block header. A crash mid-write leaves the node at block N or N+1, never between.
- Pruning never touches anything inside the unbonding window.
- Persistent bytes created by an account, object or published module pay a one-time storage deposit at a compiled-in price. This is a bound on permanent state growth, not a second dynamic fee market; compute remains the only EIP-1559 dimension at launch. The deposit is returned only when the corresponding state is provably deleted.

## Native modules: staking, fees and governance

These modules hold the funds, so they get the invariant-testing budget. Fees and governance were deleted in an earlier pass and deliberately added back in reduced form: the deletion pass found the floor, and this is what breaks without them.

**Staking and rewards.** Reward distribution is a share-price system and inherits every share-price bug from DeFi: first-depositor inflation, division-before-multiplication dust, and rounding that favours the caller. Mitigations: mint a dead share at genesis so the pool is never empty, fixed-point arithmetic throughout with a single `U256` fixed-point type and no ad-hoc scaling, round *against* the user on every withdrawal path, and assert `sum(shares) * price == total_stake ± 1 wei` as a block-level invariant that halts block production if violated.

**Fees.** EIP-1559 on one dynamic dimension: compute. A fixed gas price plus permissionless submission is a spam economy — an attacker fills every block at constant cost and the only remedy is a fork. A base fee that rises under load prices that attack out without a governance vote. Persistent state growth pays the fixed one-time deposit described above; bandwidth has no separate price at launch. Dynamic state and bandwidth fee dimensions return only if measurement shows they are needed.

**Governance, minimal.** Parameter changes only. No arbitrary code execution, no treasury, no upgradable modules. It exists for two reasons the deletion pass exposed: a permissionless, pseudonymous validator set has no other way to coordinate a fork activation, and a mispriced gas-schedule entry would otherwise be a permanent denial of service.

Every parameter carries a compiled-in clamp, checked at application time, and a proposal outside the clamp fails rather than passing and bricking the chain:

- Block gas limit: 10M–120M, never zero.
- Gas schedule entries: within 4x of their genesis value, per entry.
- Min self-stake: strictly positive, never zero.
- Inflation: 0–10% annualised.
- Unbonding period: never below max evidence age + 7 days.
- Base fee denominator, quorum, veto threshold: bounded ranges, all non-degenerate.

A 48-hour minimum timelock sits between passage and application, so a hostile or mistaken proposal can be observed before it takes effect. Fork activation is the one exception to "parameters only": a proposal may set a named fork's activation height, which is what makes a coordinated upgrade possible without an off-chain social process the validator set cannot run.

## P2P and mempool

This is Tier B rather than deterministic state-transition code, but it remains
security-critical because a mistake can halt or isolate validators. Treat it as
adversarial input handling throughout.

Ingress validation order is fixed and non-negotiable: cheap structural checks,
then transport authentication, strict decode, protocol signature and semantic
verification, then forwarding. Never forward before verifying — a node that
relays unverified messages is free amplification for an attacker.

```
flowchart LR
  A[Message in] --> B[Size + rate check]
  B --> C[Session signature]
  C --> D[Strict decode]
  D --> E[Protocol verify]
  E --> F[Forward + enqueue]
  B -->|over budget| X[Reject]
  C -->|invalid| X
  D -->|malformed| X
  E -->|invalid| X
```

Bounds, all compiled in with no unbounded collection anywhere on the path:

- Per-peer and global inbound byte budgets, token-bucket, enforced before decode.
- Every queue and remotely driven collection has a compiled capacity and an
  explicit overflow policy.
- Message size caps per message type, checked against the declared length before allocation.
- A hard cap on simultaneous authenticated peers.

The first testnet uses one mutually authenticated TCP transport and a static
operator-configured trusted-peer allowlist. There is no discovery protocol,
second transport, ASN database or reputation system in v1. Static topology is
operationally less flexible, but its authentication and failure modes are much
smaller to audit. Add discovery or scoring only after testnet measurements show
that a static topology cannot meet availability requirements. A fresh
challenge-response transcript identifies each connection, and every frame is
signed with its session identifier and sequence number so an authenticated
connection cannot be spliced or replayed.

Mempool admission charges full validation cost before accepting: signature, nonce, balance-covers-max-fee. Replacement requires a strict fee bump above a floor, so replacement cycling cannot be used as free bandwidth. Eviction is by effective fee with a per-sender cap on pending transactions.

## Determinism rules

Every rule below is enforced by a lint, a test or a wrapper type in tier A crates, because determinism reviewed by humans is determinism that eventually fails.

| Rule | Enforcement |
|---|---|
| No floating point in the state transition | `#![deny]` on float types via clippy lint + a CI grep of compiled symbols |
| No `HashMap`/`HashSet` iteration | Only `BTreeMap`/`BTreeSet` re-exported; std maps banned by lint |
| No wall-clock or system time | No `std::time` import; block time comes from the header |
| No randomness | No `rand` in tier A dependency tree, checked by `cargo-deny` |
| No `unsafe` | `#![forbid(unsafe_code)]` in every tier A crate |
| No panics | `unwrap`, `expect`, `panic!`, slicing and integer division banned by lint; all fallible paths return `Result` |
| No overflow | `#[deny(arithmetic_overflow)]`, checked arithmetic wrapper types, `overflow-checks = true` in release |
| No ambient I/O | Consensus execution takes all state and block inputs as arguments; a dependency and source scan rejects filesystem, network, process and environment access on the execution path. Literal `no_std` compatibility is not required because the pinned VM and consensus dependencies use `std` |
| Canonical encoding | Decode is strict; a round-trip property test asserts `encode(decode(x)) == x` byte-for-byte, with fuzzing on malformed inputs |
| Fixed iteration order | Any iteration feeding the state root walks a sorted structure |

A reachable panic in the state transition is not a crash, it is a chain halt and therefore a denial-of-service vulnerability. Treat every `unwrap` found in tier A as a security finding, not a style nit.

One client at launch. Once a second implementation exists, the rule becomes: any state root disagreement halts both rather than letting the larger stake win.

## Metering and DoS bounds

Gas is a claim about wall-clock cost. Any operation where that claim is wrong is a denial-of-service vulnerability, and mispriced operations are the most common way a chain stalls without anyone stealing anything.

The test almost nobody writes, and the single highest-value one here: a fuzzer whose objective function is **maximum milliseconds of execution per unit of gas charged**. Run it continuously against every bytecode instruction, every storage access pattern, and the codec. Any input that exceeds the target ratio is a finding, triaged like a vulnerability.

Stated targets, to be measured on reference hardware and re-measured every release:

- A full block at the gas limit executes in under 200 ms at p99, against a state of at least 100 GB.
- No single transaction exceeds 25% of the block execution budget.
- Worst-case measured cost of any opcode is within 3x its average cost. Anything above 3x gets repriced before launch.
- Verification of a 128-participant certificate completes in at most 200 ms at p99, and its encoded commit record is at most 32 KiB. These ceilings reserve 10% of the 2-second round timeout for certificate verification and less than 1% of the 4 MiB block cap for finality proof data. The release measurement uses the exact production verifier and encoder.

Reference hardware is named explicitly in the spec (core count, disk class, memory) and is deliberately modest, because the validator set decentralises only as far as the cheapest machine that can keep up.

Separate budget, separately enforced: block *propagation* must complete well inside the round timeout at the size cap. A chain that executes fast but gossips slowly halts in exactly the same way.

## Considered and deferred

Recorded so the reasoning survives and nobody re-proposes these in six months. Each was specified, costed and cut on the same grounds: it buys a benchmark number rather than a stated user need, and pays for it in reasoning surface.

| Dropped | Would have bought | Why cut |
|---|---|---|
| Parallel execution | Throughput headroom; ~10% of the latency budget | Schedule-dependent state roots are the hardest bug class in this system — a silent fork. Revisit only with a measured workload that needs it |
| Deferred state roots and pipelining | Execution off the critical path | Splits "ordered" from "result" for every integrator; a standing source of bridge and exchange accounting bugs |
| DAG dissemination | Throughput independent of round time | Solves congestion this chain does not have; a plain BFT round is far easier to model-check |
| Erasure-coded propagation | Proposer bandwidth stops being the ceiling | Unnecessary at 128 validators; compact-block gossip suffices |
| State rent | Node requirements viable in year five | Most user-hostile feature available, for a year-five problem. Revisit when state growth is measured, not predicted |
| Multidimensional fees | State growth and bandwidth priced separately | One dimension (compute) prices the attack that exists today. Watch the other two; add them on measurement |
| Enshrined exploit containment | A structural differentiator | Consensus-critical accounting on the value-transfer path, and it breaks composability. Only justified if it is the product thesis, in which case it ships at genesis or not at all |

Two things were deleted and then added back in reduced form: on-chain governance, now parameters and fork activation only, and the fee market, now one dimension rather than three. That sequence was deliberate. Deleting to find the floor and restoring only what breaks is how you end up with the small version instead of the conventional one — and it is why the governance module here is a few hundred lines rather than a few thousand.

The position this leaves: one client, MoveVM unmodified, single-slot finality, single-dimension fees, governance over parameters only, no bridge, no novel subsystems. Differentiation is not a benchmark figure but two things — a contract model where the common exploits are compile errors, and an operating record that is formally specified, continuously fuzzed and has not halted. The verification plan below is what makes the second claim true, and it is the part worth spending on.

## Transaction validity

Rules every transaction is checked against before it enters a block. Each exists because its absence is an exploit, not a bug.

| Field | Rule | Absent it |
|---|---|---|
| Chain ID | In the signed payload, checked against the node's own | Signatures replay across forks and testnets |
| Scheme byte | Names the signature algorithm, in the signed payload and on every registered key | Adding a second scheme later changes the transaction format, breaking every wallet and every signature in flight |
| Expiry | Valid until a stated block height, max 7,200 ahead | A signed transaction stays executable forever |
| Sequence number | Strictly increments per sender, no gaps accepted | Same transaction executes twice |
| Gas budget | Covered by sender balance at maximum price | Execution begins on a transaction that cannot pay |
| Declared inputs | Every object touched is listed | Dynamic resolution, and the parallelism path closes |

Ed25519 is the only account-signature scheme accepted at launch, and that byte is the entire concession to cryptographic agility. Ed25519 and BLS12-381 are both broken by a sufficiently large quantum computer, but the migration is not designable yet: post-quantum standards and implementations are still moving, and there is no compact drop-in replacement for BLS certificates. At roughly 2.4 KB per ML-DSA signature, 128 individual signatures would add about 300 KiB to each full certificate before framing — below the block cap, but a material change to round gossip and verification. Registering unused post-quantum keys now would provision an algorithm nobody has chosen. The scheme byte keeps the account transaction format stable until the choice can be made; changing the consensus-key scheme remains a named fork.

Block timestamps are validated too, because the unbonding and evidence windows are measured in them: strictly greater than the parent's, no more than 5 seconds ahead of the validating node's clock, and a block failing either is rejected rather than clamped. Clamping produces a fork; rejection does not.

## Weak subjectivity

Replay-from-genesis alone is not safe. A node syncing from nothing can be fed an alternate history signed by validators whose stake unbonded long ago, at zero cost to them — the long-range attack, and it is the reason every proof-of-stake chain publishes checkpoints.

- Each release ships a signed checkpoint: block height and state root, agreed by the release signers.
- A node refuses to sync past a checkpoint older than the unbonding period, and refuses any history conflicting with the newest checkpoint it holds.
- Checkpoints are published in at least two independent places, so a compromised release channel is not sufficient on its own.
- Operators can override with an explicit flag. It is loud, documented, and the wrong default.

## Native module boundary

Signed transactions reach staking and governance through seven frozen protocol calls, dispatched by reserved package and module names and changed only by a fork:

- `register_validator(consensus_key, proof_of_possession, self_stake)`
- `stake(validator, amount)`
- `unstake(validator, shares)` (begins the unbonding period)
- `unjail()`
- `submit_evidence(evidence)`
- `submit_proposal(proposal)`
- `vote(proposal_id, vote)`

These are protocol calls handled at the executor boundary, not custom MoveVM native functions callable from arbitrary bytecode. That smaller boundary avoids representing validator administration, evidence and governance capabilities as a second set of Move resources before there is an application requirement for contract-level composability. Rewards compound into the staking share price and are realised by unstaking, so a separate `claim_rewards` call would duplicate accounting state. Consensus reads the validator set through the read-only engine view rather than a transaction call.

Each state-changing call is metered by measurement and carries its own fuzz target. Nothing else crosses the boundary: no caller-supplied clock, no ambient randomness and no arbitrary native dispatch.

## Halt recovery

A single-client chain halts. The spec says so in the determinism section and then, until now, said nothing about what happens next — which is the runbook that matters most, because it runs during the worst hour the network will have.

1. **Detect.** Validators observe no commit for 10 consecutive round timeouts. Monitoring alerts operators automatically; the condition is machine-detectable, not a judgement call.
2. **Diagnose.** The last committed height and state root are canonical. Every node publishes its last commit certificate; agreement on that certificate defines the recovery point.
3. **Patch.** Fix, reproduce the halt in a regression test, and ship a signed release. A halt with no regression test is not fixed.
4. **Restart.** Validators restart from the agreed height with the new binary. The chain resumes when 2/3+ of stake is back on the same certificate.
5. **Slashing is suspended for the halt window.** Downtime during a chain-wide halt is not the operator's fault, and punishing it would push operators toward unsafe restarts.

The recovery point is a commit certificate, never a state root a single operator asserts. Rehearse this on the chaos testnet — a runbook nobody has executed is a hypothesis.

## Economic security

The question an attacker asks, and that this document previously left unanswered: what does it cost to break the chain, and is that less than what breaking it is worth?

| Quantity | Target at launch |
|---|---|
| Cost to acquire 1/3 of stake (halt) | > 2x the value secured on-chain |
| Cost to acquire 2/3 of stake (finality break) | Above any plausible attacker budget |
| Slashing, double-sign | 5% of stake, scaling to 100% with correlated stake |
| Slashing, downtime | 0%, jailing only |
| Inflation | 3–5% annualised, paid to stakers |

The real constraint is that value secured must not outrun staked value. A chain with $50M staked and $2B bridged in is an arbitrage waiting to be taken, and that relationship is the strongest argument for the bridge value cap in the non-goals. Publish both numbers continuously, and treat their ratio as an operational metric rather than a launch calculation.

## Keys, signing and slashing safety

The failure to design against here is not theft, it is an honest validator getting slashed by their own node. A validator restarting from a truncated write-ahead log signs a second block at the same height, and burns real stake for an honest operator's disk fsync behaviour.

Double-sign protection therefore lives in `chain-signer`, isolated from the node:

1. The signer holds a monotonic high-water mark of (height, round, step), persisted and fsynced *before* any signature is returned.
2. It refuses to sign anything at or below that mark, unconditionally, with no override flag and no reset command.
3. It is a separate process with its own storage, so a node rollback, restore-from-snapshot or container restart cannot rewind it.
4. Consensus keys are BLS with proof-of-possession, held only by the signer; the node never sees them.

The first testnet uses one Unix-domain socket protocol. A 32-byte signer
credential authenticates bounded requests and request-bound responses with
keyed BLAKE3. The protocol exposes only vote/proposal signing under the fixed
consensus domain, deterministic beacon signing and high-water-mark inspection.
The signer rejects key or credential files readable by group or other users,
and writes its mark with mode `0600`. Remote custody systems and consensus-key
rotation are later operational work, not alternate v1 signing paths.

Three key roles, never the same key:

| Key | Held by | Rotatable |
|---|---|---|
| Consensus (BLS) | Remote signer, hot | Yes, with a delay |
| Operator (withdrawals, parameter changes) | Hardware wallet, cold | Yes |
| Reward recipient | Anywhere | Yes, immediately |

The timing inequality that must hold in code, not in documentation:

```
unbonding period > max evidence age > fork-choice horizon
```

If unbonding is less than or equal to max evidence age, a validator can equivocate and complete unbonding before the evidence is admissible, and the slashing is unenforceable. Assert this at genesis, on every parameter change, and in a unit test.

Slashing itself is graduated and correlation-aware: a small penalty for an isolated double-sign, scaled up by the fraction of stake that equivocated in the same window, so a shared-infrastructure failure by one operator is not priced as a coordinated attack. Downtime is jailing, not burning.

## Upgrades and migrations

State migrations run exactly once, on real mainnet state, and are typically written in the last week before the fork by whoever is least busy. They deserve more scrutiny than they get.

Rules:

- Every consensus change is gated behind a named fork activated at a height agreed in advance, never at a timestamp. Old rules stay in the binary and stay tested.
- Migrations are pure functions from old state to new state, deterministic and replayable.
- CI dry-runs every migration against a recent mainnet state snapshot and publishes the resulting state root before the fork. Node operators can verify they compute the same one.
- Fork activation heights sit far enough ahead that operators have at least two weeks to upgrade.
- A fork that fails to reach 2/3 stake on the new binary must be abandonable: the previous binary can still follow the chain until activation, so a missed upgrade is a delay, not a split.

Release integrity is part of the threat model, not an afterthought: reproducible builds, signed releases with published checksums, pinned dependencies with `cargo-deny` and `cargo-audit` in CI, and a documented process for who signs and how their key is held. The largest crypto theft on record was not a contract bug — it was an operational compromise of the approval path.

## Verification plan

The ordering principle: machines run first and exhaust the mechanical bug classes, so that paid human auditors spend their weeks on protocol economics and cross-component reasoning, which is the only thing they can do that tools cannot.

| Layer | Tooling | Target |
|---|---|---|
| Lints and bans | clippy, `cargo-deny`, custom lints | Tier A rules from the determinism table, blocking on merge |
| Unit and property tests | `proptest` | Codec round-trips, fixed-point arithmetic, genesis constants |
| Invariant fuzzing | `cargo-fuzz`, continuous | Staking share/stake equality, no reachable panic |
| Differential fuzzing | vs. upstream MoveVM | Identical results to upstream MoveVM across random module and tx sequences |
| Metering fuzzing | Custom, objective = ms per gas | No operation above the 3x worst-case ratio |
| Concurrency | `loom`, `miri` | No data race or UB in the boundary and signer |
| Formal | TLA+ or Quint, plus `kani` on core arithmetic | Consensus safety and liveness; no overflow in reward maths |
| Chaos testnet | Deliberately Byzantine validators, network partitions, clock skew, disk failures | 60+ days continuous, restarted only for findings |
| Human audit | Two independent firms, staggered | Economics, governance, cross-module interaction |
| Public competition | Audit contest after the firms, before mainnet | Unknown-unknowns at scale |
| Bug bounty | Live from testnet, scaled to secured value | Ongoing |

Two firms rather than one, on staggered scopes, because independent findings barely overlap. Run the AI-assisted tooling continuously alongside all of it — it is good at breadth and at known bug classes, and it is cheap, but the benchmark evidence from earlier this year says treat its output as candidate findings for a human to confirm, not as a verdict.

Launch gate: no unresolved high or critical findings, 60 days of chaos testnet without a halt, and a successful rehearsed fork on testnet including a state migration.

## Open decisions before genesis

Each of these changes the spec materially and none has a defensible default.

- [ ] **Do you need an L1 at all?** A rollup or appchain on an existing stack removes most of the surface above. This spec is only correct if sovereignty is a real requirement.
- [ ] **MEV policy.** Public mempool with an explicit "we do not prevent this", an in-protocol builder slot, or encrypted ordering. Not deciding means the market decides for you, usually badly.
- [ ] **Validator entry.** Permissionless by stake, or permissioned at launch with a published path to opening up.
- [ ] **Token and inflation schedule.** Drives the security budget and therefore the cost of attacking the chain.
- [ ] **Bridge design and value cap.** The single largest historical loss category. Needs its own document.
- [ ] **Emergency powers.** Is there a pause, who holds it, and does it expire? A pause that never expires is a permanent trust assumption; no pause at all means the first live incident is unrecoverable.
- [ ] **Reference hardware spec.** Names the real decentralisation floor.

Repository line count is not a protocol requirement. Audit scope is tracked by trust tier, dependency revision, frozen boundary size, enforced bounds and verification evidence in the conformance ledger. A small first-party wrapper does not make the upstream VM, consensus engine or storage dependency disappear from the audit surface.
