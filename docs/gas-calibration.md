# Gas calibration: what a unit of gas costs in time, measured

Written 2026-09-25. **The finding that matters is at the top, and it is about the chain that is
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

**Not yet measured, and needed before fixing the numbers:** the time to execute a block is also
O(state), because every block clones the state and recomputes its root; that is a cost that scales
with the number of entries, not with gas, and it needs its own measurement at the state cap. And
the same benchmark should be run on hardware you would call the reference, if that is not the VPS.

## Status: option C is built (2026-09-25); not yet deployed

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
