# Gas calibration: what a unit of gas costs in time, measured

Written 2026-09-25. The recalibration it led to is at the end (built, not yet deployed). **The finding that matters is at the top, and it is about the chain that is
running now.**

## The finding

Gas is supposed to be a proxy for the time a validator spends. On the alpha VPS it is not: a
unit of gas spent on plain Move instructions takes **about 8 to 11 microseconds**, while a unit
spent on hashing, stored bytes or publishing takes **about 0.1 to 0.5 microseconds**. That is a
factor of 20 to 100 between kinds of work, and it makes the cheapest way to burn a validator's
time the interpreter itself.

As a real transaction, run to the end of its gas limit (whole block execution, fastest of three
runs, on the VPS):

| A hostile call: an arithmetic loop | Time |
|---|---|
| gas limit 300,000 | **3.5 seconds** |
| gas limit 3,000,000 | **32.7 seconds** |
| the current ceiling for one transaction, 15,000,000 | about 2.5 minutes (extrapolated) |

The chain's block interval is 1 second. A transaction is limited to a quarter of the block gas
limit (60,000,000 gas, so 15,000,000), and a block to 60,000,000, which at these speeds is minutes
to hours. **Anyone who can publish a package (anyone with a funded account, and the faucet gives
10 THRY) can publish a function with a loop and call it with a large gas limit, and every
validator stalls executing it.** It costs the attacker about 0.015 THRY. That is the mechanism of
the nine-hour halt on 2026-09-24, arrived at by a different route: signer and consensus
timeouts while the box is busy.

**This is live** on the public testnet since the reset on 2026-09-25, because the reset shipped
Move calls with the VM's own instruction prices. The kill switch that would stop it
(`publish_enabled`, governed) takes a governance vote: a 7-day voting period and a 48-hour
timelock, so it cannot help quickly. Nothing has been exploited that I know of. I found it by
measuring, not from an incident.

## What was measured

Release build, alpha VPS (one shared vCPU, `DO-Regular`), the four validators and signers running
alongside (so these are with contention: the fastest of 21 runs is reported as the best
estimate). The benchmark is `crates/exec/examples/gas_bench.rs`; the raw output from this run is
kept on the VPS as `/root/gas-bench-2026-09-25.out`.

Calls, through `simulate` (the whole call: loading the package from state, running, unloading):

| Scenario | gas | fastest ms | ns per gas |
|---|---:|---:|---:|
| noop (load the package, run nothing) | 1 | 1.05 | (about 1.05 ms fixed) |
| arithmetic loop, 2,000 iterations | 269 | 3.16 | 11,735 |
| arithmetic loop, 20,000 iterations | 2,681 | 21.6 | **8,058** |
| vector push, 5,000 | 2,636 | 4.77 | 1,810 |
| build a 3,000-byte vector | 1,567 | 2.99 | 1,909 |
| sha3-256 of 26 bytes, 500 times | 3,501 | 1.73 | 495 |
| 64 store operations (32 put + 32 take) | 393 | 1.33 | 3,397 |
| take and put back a stored 16,000-byte value | 9,681 | 1.08 | **112** |
| the same, reading its length | 9,777 | 1.40 | 144 |

Publishing (whole block execution; gas is what the publish is charged):

| Package | bytes | gas | fastest ms | ns per gas |
|---|---:|---:|---:|---:|
| 4 functions | 2,845 | 48,450 | 4.2 | 86 |
| 40 functions | 27,830 | 298,300 | 39.2 | 131 |
| 90 functions | 62,530 | 645,300 | 87.3 | 135 |

Two more facts from the same run: a call has a fixed cost of about a millisecond before it does
anything (the package is loaded from state for each call), and the largest package the limits
allow to be tested (a module is capped at 64 KiB) verifies in about 90 ms.

## What it means

1. **Instruction gas is too cheap by about 10x to 100x** compared with everything else. The VM's
   own schedule (which the chain uses unchanged) prices an instruction at a fraction of a unit of
   gas; a plain instruction takes about 0.2 microseconds. The natives, the store and publishing
   were priced by me on a different footing and come out at 0.1 to 0.5 microseconds per unit.
2. **Even the "cheap" classes are too slow for the block gas limit.** At 60,000,000 gas a block
   and 100 to 500 ns per gas, a block full of hashing or publishing would take 6 to 30 seconds.
   The block gas limit and the price per unit have to be chosen together.
3. **The fixed cost per call (about a millisecond) is close to the 1,000-gas floor a transaction
   already pays**, which is a good sign for that floor.
4. `simulate`'s cap was set from this: 10,000 gas is about 0.1 second of the node's thread at the
   worst rate here (it was 100,000 before the measurement, which is 1 second). It is also rationed
   to one a second per node, and off unless the node's `rpc.simulate` is on.

## A calibration to consider

Choose one ruler and put everything on it. **1 gas = 1 microsecond of the reference machine's
CPU** (the alpha VPS, contended, is a pessimistic reference), and a block's execution budget of
about 300 milliseconds:

| | Now | Proposed |
|---|---|---|
| Block gas limit | 60,000,000 (clamped 10M to 120M) | about 300,000 (the clamps move with it) |
| One transaction | a quarter of the block, 15,000,000 | a quarter, about 75,000 |
| Instruction prices | the VM's, times 1 | the VM's, times about 8 to 10 |
| Store, per byte written | 500 internal units (0.5 gas) | about 0.06 gas |
| Publishing | 20,000 + 10 per byte | about 2,500 + 1.5 per byte |
| Hashing, per byte | 100 internal (0.1 gas) | about 0.05 gas |
| The floor per transaction | 1,000 gas | 1,000 gas (unchanged: it is about a call's fixed cost) |

Fees follow from the price per gas (currently 1 base unit) and stay tiny: a 75,000-gas transaction
is 0.000075 THRY at the base fee. Deposits are not gas and do not change.

This changes what a transaction can afford to do (a 75,000-gas ceiling is roughly 20,000
arithmetic iterations), which is the point of it, and it means moving the block gas limit's
clamps, which live in `chain-modules` and in genesis. It also means the per-block Move work is
bounded by construction instead of by a hope.

### Measured: what a block costs as the state grows (2026-09-25)

The per-block cost that does not depend on gas at all. Every block computes the state root from
scratch, over every entry (`chain_state::compute_root` rebuilds the whole trie), and clones the
state to execute it. Measured with one transfer in the block, so the numbers are the overhead and
not the transaction (`block_cost_by_state_size`, an ignored test in `crates/exec/src/executor.rs`;
release build on the development Mac, which is faster than the VPS):

| Entries in state | Value size | Execute a block | of which the root | of which the clone |
|---:|---:|---:|---:|---:|
| 10 | 8 B | 0.3 ms | 0.2 ms | 0 |
| 25,000 | 8 B | 31 ms | 21 ms | 1.5 ms |
| 99,900 | 8 B | 133 ms | 90 ms | 6 ms |
| 99,900 | 640 B | **361 ms** | **310 ms** | 11 ms |

At the state cap (100,000 entries, 64 MiB) with realistically sized values, **executing an empty-ish
block costs a third of a second on a fast machine before a single instruction runs**, and every
validator pays it for every block. On the one-CPU VPS it will be several times that, more than the
one-second block time. So the state cap and the block time are not compatible today, whatever the
gas is set to; and it means the gas budget above (about 300 ms a block) is not the whole budget.

**Fixed the same day (built, not deployed).** The root's value is unchanged (commitment version
2); only the way it is computed changed, from a rebuild to an update that touches only what the block
changed (`chain_state::TrieIndex`, `crates/state/src/index.rs`). It is held to the definition by
tests: the maintained root equals `compute_root` after every block of random runs of writes,
overwrites and deletions, including entries that share a bucket, and the executor checks it against
`compute_root` on every block in a debug build (so the whole test suite is a differential test) and
on one block in 64 in a release build, where the definition wins if they ever differ. Same benchmark,
after:

| Entries in state | Value size | Execute a block, before | after |
|---:|---:|---:|---:|
| 25,000 | 8 B | 31 ms | 10 ms |
| 99,900 | 8 B | 133 ms | 45 ms |
| 99,900 | 640 B | 361 ms | **58 ms** |

The root no longer shows up. What is left is also O(state): cloning the state to execute on it,
comparing it with the result to find what changed (`chain_state::diff`), and the state-limit check
(about 45 to 60 ms at the cap on the Mac). Removing those means executing against an overlay of
writes instead of a copy, a larger change to the executor; it is not needed for correctness and can
wait for a measurement on the VPS.

**Also not yet measured:** the same run on the VPS.

## Status: option C is built and deployed to the live testnet (2026-09-25)

`chain_exec::policy` holds the node-local limits, tested in `crates/exec/tests/move_policy.rs`
and `crates/node/src/txpool.rs`:

- **A node's mempool refuses a call to a user's package that declares more than 20,000 gas**
  (`MoveCallGasTooHigh`), for transactions from RPC and from peers alike. Protocol calls,
  publishing and the two demonstration packages are not limited.
- **A node's proposer stops packing Move calls into a block once the calls already packed have
  actually used 60,000 gas** (counted as it tries each one, at the protocol's 1,000-gas floor
  at least). The rest wait for a later block. With the 1,000-gas floor that is at least 60 calls
  a block; a block of calls that all burn their whole limit holds three.
- The `thrylos` command's default and maximum gas for `move call` is 20,000.

At the worst rate measured (about 11 microseconds a unit) a block's Move work is bounded at about
0.6 to 0.8 seconds, one transaction at about 0.2 seconds. That is still slow for a one-second
block, which is why this is a stopgap and the calibration below is the fix.

**Not a consensus rule.** A block from another proposer that carries a call over these limits is
still valid, and every validator still runs it. So this protects the network from users but not from
a validator that proposes such a block: all four validators here are the operator's, so that is the
same as trusting the operator's own nodes. Removing the limits needs no fork either.

**Users on an older `thrylos` will be refused** (`MoveCallGasTooHigh`) until they pass
`--gas 20000` or less.

## Ways to act

- **A. Fix the live chain now, then reset later.** A hotfix that caps a Move call's gas at a small
  constant (say 100,000) and rescales instruction prices, deployed as a normal restart of the four
  validators (about five minutes; no reset needed, since state is not replayed). It needs a build
  and deploy on the VPS and is a consensus change made to a live chain, so it should be rehearsed
  first. It shrinks the worst transaction to a fraction of a second but does not bound a whole
  block, which needs the block limit changed too (a governed parameter: 9 days, or the reset).
- **B. Fold it into the storage reset.** Calibrate as above, in the same reset that ships storage.
  Nothing on the live chain changes until then, so the exposure lasts until the reset date.
- **C. Stop the exposure without a consensus change.** Restart the validators with a node-local
  rule that their mempools refuse a Move call whose gas limit is over a small number, and their
  proposers stop filling a block past a small Move-gas total. Not a consensus rule (every honest
  validator still accepts any block), so it is safe to do without a fork and cheap to remove, but
  it depends on all four of the operator's validators running it, and it is a code change and a
  restart too.

Whichever is chosen, the numbers above should be re-measured after the change with the same
benchmark, and `THRYLOS_MAX_NS_PER_GAS` (the fuzz job's ceiling, now one million nanoseconds per
unit of gas) should come down to something a calibrated chain can meet, such as two thousand.

## The recalibration, as built (2026-09-25; ships with the third reset)

Not deployed. It is a consensus change (gas is consensus), so it goes out with a reset, together with
storage, reading state and the stage-3 rules.

### The ruler

**1 gas is about 1 microsecond on the alpha VPS, and 1 gas is 1,000 of the VM's internal units, so one
internal unit is one nanosecond.** Every price is now written as the nanoseconds the operation was
measured to take (`crates/exec/examples/opcode_bench.rs`), rounded up. Where overpricing and
underpricing conflict, the price leans high: overpricing costs a user a fraction of a cent, underpricing
lets one person hold every validator up.

### Two things found in the VM's own schedule, and why it was replaced

The chain had used the VM's built-in prices (`INITIAL_COST_SCHEDULE`), which come from a Diem-era table.
Measuring each kind of instruction showed it could not be tuned by a multiplier:

- **It priced by opcode, not by cost.** A plain instruction was priced at 2 internal units (2 ns) and
  costs about 55; a function call was priced at over 2,000 and costs about 350; a vector borrow at over
  1,300 and costs about 210. A single multiplier (which was the first thing tried, times 10) fixes the
  first and makes calls and vector work absurdly dear, about 100 times too much.
- **It did not count a vector's length when copying, comparing or reading it** (the VM's size measure
  leaves vector contents out). A program could build a vector of thousands of numbers and copy it a
  million times for the price of a million small copies. That is the same kind of hole as the one found
  on 2026-09-25, in a different place.

So `chain_exec::gas` is a meter of our own that implements the VM's `GasMeter` trait, priced by class,
and that counts a vector's contents when it is copied, compared, or read through a reference.

### The prices

Measured on the VPS with the four validators running (the pessimistic reference), in nanoseconds:

| Work | Measured | Priced |
|---|---:|---:|
| A plain instruction (load, store, branch, compare, borrow a field, bit operation) | 53 to 60 | **60** |
| Add, subtract, multiply, divide, remainder (one price for every width, set by `u256`) | 100 to 270 | **280** |
| A call | 320, and 110 for each argument | **350 + 120 per argument** |
| Making or taking apart a struct | 135 for three fields | **90 + 30 per field** |
| Borrow a vector element | 210 | **250** |
| Swap two elements | 175 | **200** |
| Push or pop | 85 | **100** |
| A vector from its elements | 360 for four | **150 + 60 per element** |
| A constant from the module | 107 to 135 | **150, and 1 per 16 bytes** |
| Copy or compare a value | 0.8 and 1.25 per number | **a plain instruction, and 1 for every 4 units of size** (2 per number) |
| A native | 0.5 to 4.4 microseconds | **1,000 fixed; 2,500 for strings; 4,500 for type names; 10 per byte** |
| The store | about 4 microseconds an operation | **4,000 fixed; 60 per byte written; 12 per byte read** |
| Publishing | 0.9 to 1.4 microseconds a byte | **2,500 + 1.5 per byte** |

### The limits

| | Before | After |
|---|---|---|
| Block gas limit | 60,000,000 (clamps 10M to 120M) | **300,000** (clamps 50,000 to 600,000) |
| One transaction | 15,000,000 | **75,000** (a quarter of the block) |
| The floor per transaction | 1,000 | 1,000 (a call's fixed cost is about a millisecond) |
| `simulate` cap | 10,000 | **75,000** (what a transaction may spend) |

Consequence to accept: with 1.5 gas a byte, the most a publish can be inside one transaction is about
48 KB (the package limit of 128 KiB is no longer reachable). That is more than an application needs
today; the block limit can be raised by governance within its new clamps if it turns out not to be.

### How it checks out (the same benchmark, on the VPS, after)

Nothing costs more than a microsecond a gas; the ordinary work costs between 0.5 and 0.95.

| Work | ns per gas |
|---|---:|
| arithmetic loop, run to the end of 75,000 gas (a hostile call) | 510 |
| the same to 150,000 gas | 490 |
| sha3 loop to 150,000 gas | 600 |
| calls, struct work, vector borrow and swap, `u256` | 525 to 930 |
| copying or comparing a 4,096-number vector | 430 to 600 |
| the store, 64 operations; taking and putting a 16,000-byte value | 700 to 730 |
| publishing 2.8 KB, 28 KB, 63 KB | 630, 910, 950 |

A hostile transaction that spends its whole 75,000 gas now holds a validator for about 40 ms (it was
minutes), and a full block of them, at most about 0.3 second.

### What is still open

- **The per-block cost that is not gas.** With the state at its cap a block still costs 45 to 60 ms on
  the Mac (several times that on the VPS) before anything runs: cloning the state, finding what changed,
  and the limits check (see "what a block costs as the state grows"). That needs executing against an
  overlay of writes instead of a copy.
- **Widths.** `u128` and `u256` arithmetic costs more than `u64`, and the VM's opcodes do not say which
  is being used, so all arithmetic is priced at the widest. Ordinary `u64` arithmetic is priced at about
  three times its cost. Nobody will notice at these prices.
- **The node-local stopgap** (`policy.rs`, the 20,000-gas mempool cap and the proposer's per-block
  budget) is still in the tree. With this change it is redundant, since the chain's own limits now bound
  what it bounded. Removing it is a decision for the operator, not something to do in passing.
- **The fuzz job's ceiling** (`THRYLOS_MAX_NS_PER_GAS`, 1,000,000 in CI) is a placeholder that fits none
  of this; it should be set from a measurement in that environment.
- **Every gas figure in the tests** was moved to the new scale, and the genesis golden vectors changed
  (recorded in `compatibility-vectors.md`).

The two benchmarks are `examples/opcode_bench.rs` (nanoseconds per kind of instruction, the source of the
table above) and `examples/gas_bench.rs` (whole calls, publishing, and hostile calls, the check).
