# Move developer testnet: publishing, calls, standard library

Status: **design for review. Nothing is built.** Written 2026-09-25 against the
code at that date and the pinned MoveVM (`MystenLabs/sui` rev `ceaaff1`).
Replaces the plan in GitHub issue #8; the acceptance criteria there are mapped
to stages below.

## What this has to do

Let an application developer write Move, publish it to the testnet, and call it,
using the pinned upstream MoveVM (no Thrylos-specific dialect), with no upgrades:
a published module is immutable.

## What the code does today (verified)

- **It is not general Move.** `crates/exec/src/executor.rs` runs exactly two
  functions, by name: a calculator `add` and a counter `bump`, at two fixed
  addresses installed at genesis (`call_calculator_add`, `call_counter_bump`).
  There is no dispatch on an arbitrary module or function, no argument decoding,
  no return handling.
- **One module per address, no dependencies.** `module_resolver.rs` stores a
  single `CompiledModule` per package address and rebuilds a package from it with
  `StoredPackage::from_modules_for_testing`, a helper the VM marks for tests.
- **The VM is configured for tests:** `VMConfig::new_for_test(false, None)`, and
  gas uses the VM's `INITIAL_COST_SCHEDULE`.
- **The state cap** (100,000 entries, 64 MiB) and the flat 0.01 THRY storage
  deposit per new entry exist and apply.

## What the pinned VM gives us (verified in its source)

- `MoveRuntime::validate_package(...)` deserialises, verifies and links a whole
  package **all or nothing** and returns a user error for bad bytecode. It takes
  a gas meter but does not use it, so **verification is not metered by the VM**:
  we must bound it ourselves.
- `MoveVM::execute_entry_function(module, function, ty_args, args, gas)` runs an
  `entry` function; arguments are already-built `Value`s, so turning bytes into
  arguments by the function's signature is our job.
- `VerifierConfig` has explicit limits (loop depth, basic blocks, generic
  instantiation size, function and struct counts, identifier length, and more)
  that we must set deliberately.
- **Global storage is gone.** `MoveTo`, `MoveFrom` and `BorrowGlobal` exist only
  as `...Deprecated` opcodes, and the config carries `deprecate_global_storage_ops`.
  This is Sui's Move: persistent state is not a VM feature. On Sui it is an
  **object model** that lives outside the core VM, in Sui's own execution crates,
  and those depend on Sui's transaction and object types.

## The finding that shapes everything

**A Move module published to Thrylos cannot remember anything** unless we give it
somewhere to put state, and the VM does not provide that. Publishing and calling
alone would let developers run pure functions (compute and return a value) and
nothing else: no counters, balances, tokens, registries or games. That is a fine
first proof, and a useless place to invite application developers to.

So the work has two halves with very different sizes:

1. **The pipeline:** publish, verify, store, resolve, call, meter, limit. Well
   defined; the VM does most of the hard part.
2. **A state model** for Move code. Not defined by the issue, not provided by the
   VM, and the single biggest design decision here.

## Decisions to make (recommended answer in bold)

### D1. How a package is published
**A native protocol call** (`move` package address, function `publish`), the way
`coin::transfer`, `staking::stake` and `governance::vote` already work: the
existing transaction format carries it, so **no transaction-encoding change** and
no change to signatures, hashes, the wallet or the RPC. The alternative, a new
transaction payload kind, changes the encoding everywhere. It also means the
spec's frozen list of eight protocol calls (D-003) becomes nine, on purpose and
recorded.

### D2. Who can publish, and at which address
**A package's address is derived, not chosen:** `hash(sender, sender's sequence
number)`. The publisher cannot pick an address, so they cannot overwrite a system
package (`0x1`, `0x2`, the coin, staking and governance packages), squat a
famous address, or collide with anyone else. Anyone with an account and gas may
publish; the sender pays. A published package is owned by nobody and can never
change, so there is no owner to authorise anything later.

*To check when building:* whether `validate_for_publish` requires a module's own
address to equal the package address. If it does, the client compiles with the
address it can already compute (it knows its own sender and sequence number), and
`thrylos move build` does that for the developer.

### D3. Where Move state lives (the big one)
Three options:

- **S0, no state.** Publish and call, pure functions and events only. Small and
  safe; developers can prove the pipeline and nothing more.
- **S1, a small Thrylos storage layer** (**recommended, as stage 2**): a few
  native functions in a Thrylos framework (`store`, `borrow_mut`, `take`, keyed
  by owner address and type), with Sui's own "private generics" verifier rule so
  only the module that defines a type can store or take it. State is ordinary
  entries in the flat state, so deposits, the state cap and the state root apply
  unchanged. Contained enough to design and test properly.
- **S2, Sui's full object model.** Objects with IDs, ownership, shared objects,
  dynamic fields, transfer semantics. It is the right long-term answer and a very
  large project that drags in Sui's transaction model. Not now.

**Recommendation: build S0 first as stage 1, and design S1 as its own document
before stage 2.** Do not invite external developers until S1 exists.

### D4. The standard library
**Compile the pinned `move-stdlib` sources once with the pinned compiler, check
the resulting bytecode into the repository, and install it at address `0x1` in
genesis.** Frozen: no upgrade path, and every validator loads identical bytes.
A small Thrylos framework module (`0x2`) supplies natives the stdlib does not:
`sender()`, `block_time_ms()`, `height()` and `event::emit`.

**Consequence you must accept: this needs a new genesis.** The live chain has no
`0x1`, and there is no versioning or activation-height mechanism to add system
modules to a running chain. So stage 1 ships as a **testnet reset**: a new genesis
containing the standard library and the new rules from block 1. Balances, the
faucet's state and the chain id change; the name registry's signed claims commit to
the chain id, so reserved names would have to be reserved again (or the registry
migrated deliberately). It is an alpha and this is acceptable, but it must be said
out loud, not discovered.

### D5. Dependencies
**Status: stage 1 shipped `0x1`/`0x2` only; stage 3 added dependencies on published user packages** (at most 16 packages needed in all, counting the system ones; the linkage is completed transitively when a package is loaded). The original reasoning follows.

**Stage 1: a package may depend only on `0x1` (and `0x2`).** No dependencies on
other users' packages yet. That removes linkage-graph attacks, dependency-depth
limits and version questions while the verifier path is new. Allow dependencies on
published user packages later, with a depth limit, once the base is fuzzed.

### D6. Limits (proposed, to be tuned by measurement)
| Limit | Proposed |
|---|---|
| Package size (all modules together) | 128 KiB (below the 256 KiB transaction cap) |
| Modules per package | 32 |
| One module | 64 KiB |
| Verifier limits | set explicitly from `VerifierConfig`, strict; recorded in the spec |
| Entry function arguments | primitives, `address`, `vector<u8>`, vectors of those, and `String` |
| Type arguments per call | small fixed cap |

### D7. Gas and cost
- **Publication:** a base charge, a per-byte charge, and a **verification charge
  proportional to what the verifier will do** (bytes, function count, basic
  blocks), taken **before** verifying, with the verifier's own meter limits as a
  second wall. Since the VM does not meter verification, this is our DoS defence.
- **Execution:** the VM's gas meter with a **fixed, recorded cost table** (today the
  test schedule); the per-transaction ceiling and block gas cap apply as now.
- **Storage:** a published package creates state, so it pays the storage deposit
  **per byte** (rounded up per KiB, at the same rate as an entry today) and counts
  against the state cap. This is the first place per-byte accounting is needed.

### D8. A kill switch
**A governed parameter that turns publishing off** (default on for the testnet).
If the verifier path turns out to have a problem, publishing can be stopped by a
governance vote without a chain restart. Cheap, and it is exactly the mitigation
the audit's dependency finding asks for.

### D9. The CLI
`thrylos move publish` and `thrylos move call` in stage 1 (they build and sign the
transactions, like `thrylos send`). `thrylos move build` and `thrylos move test`
wrap the pinned `move-compiler` and unit-test runner in stage 3; the compiler is
already a dependency, used to produce the demo modules.

## Stages and acceptance

**Stage 1: pipeline (S0), on a reset testnet.** Genesis with the standard
library; `move::publish`; package storage and a real resolver (multi-module
packages, dependency on `0x1`); production `VMConfig` and verifier limits; a
generic entry-function call with typed argument decoding, return values, events
and the `0x2` natives; gas and deposits; the kill switch; `thrylos move publish`
and `call`. Maps to the issue's criteria: publish valid module, call it, refuse
malformed bytecode, refuse republishing (impossible by construction, and tested),
refuse overwriting system modules (impossible by derivation, and tested), survive
restart (state is ordinary state), identical state on every validator (the
four-node test), no compiler in consensus (bytecode only), and documented limits.

**Stage 2: state.** The S1 storage layer, designed in its own document first.
This is the point at which developers can build applications.

**Stage 3: tooling (done 2026-09-25).** `thrylos move build` and `test`, package dependencies on
user packages, docs and examples.

## Risks

- **This is the largest new attack surface the chain has:** arbitrary bytecode from
  anyone, through a VM and verifier that nobody has reviewed for this use. The
  testnet coin has no value, which is what makes this safe to do now; it is the
  reason to do it before anything else depends on the chain.
- Mitigations in the design: derived addresses, hard size and verifier limits, a
  gas charge that covers verification, deposits, the kill switch, and a new fuzz
  target for the publish path in CI.
- **Consensus determinism:** the VM must behave identically on every validator. The
  existing four-node tests extend to publish-then-call.
- **A testnet reset** (D4) interrupts everyone using the alpha once.

## Order of work inside stage 1

1. Production `VMConfig` and verifier limits, with a test that fixes their values.
2. Package storage keys, the resolver, and `move::publish` with limits and gas.
3. The genesis standard library and the `0x2` natives.
4. Generic entry-function calls with typed argument decoding.
5. Deposits, the kill switch, then the fuzz target.
6. `thrylos move publish` and `call`, then the end-to-end four-node test.
7. Rehearse the reset locally, then on the VPS with a backup, and record it in the
   operations guide.

## Open questions for you

1. **State model:** stage 1 stateless and S1 as stage 2 (recommended), or design S1
   first and build both together?
2. **A testnet reset** for stage 1 (recommended), or find a way to add the standard
   library to the running chain (which needs a versioning mechanism that does not
   exist)?
3. **Package address by derivation** from sender and sequence number?
4. **Dependencies on `0x1` and `0x2` only** in stage 1?
5. **The kill switch** as a governed parameter?

## Status, 2026-09-25

Stage 1 is live on the reset testnet (`rollout-move-reset.md`). Stage 3 is built:
`thrylos move new`, `build` and `test` (crate `chain-movetools`, which compiles
against the chain's own system sources and runs tests in the chain's own runtime),
publishing from a package directory with a local pre-check that says why the network
would refuse it, and dependencies on published user packages. The guide is
`move-developer-guide.md`. Stage 2, storage, is not started and is the reason developers
cannot yet build applications.
