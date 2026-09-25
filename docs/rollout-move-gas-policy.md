# Rollout: the Move gas stopgap (option C)

Status: **plan, built and tested, nothing run on the VPS.** Written 2026-09-25. Why:
`gas-calibration.md`. This is the **node-local** stopgap: it changes no consensus rule, no
state and no on-disk format, so it needs a restart of the validators and nothing else. It is
a restart of the same chain, not a reset.

## What ships, and the choice of what to build

Only the stopgap, on top of exactly what is running. The repository has moved on since the
reset (storage, reading state, the tooling, dependencies between packages) and those changes
touch consensus, so they are **not** deployed here; they wait for the third reset. The
running build is commit `a726a77`, so the stopgap is applied to that and nothing else:
a copy of `a726a77` with these changes, and only these:

- `crates/exec/src/policy.rs` (new), and its two uses in `executor.rs` (the proposer's
  Move-gas budget per block);
- a new `AdmissionError::MoveCallGasTooHigh` (`crates/mempool`), raised by the node's
  mempool admission (`crates/node/src/txpool.rs`), reported by the RPC (`rpc_api.rs`);
- the `thrylos` command: `move call` defaults to and is limited to 20,000 gas.

The diff against `a726a77` is small and is nothing in consensus. To see it:
`diff -r` of `crates/{exec,mempool,node}` between `a726a77` and the hotfix tree, or ask for it as
a patch file.

Tests run on the hotfix tree itself (not only on the main tree): `move_policy` (4),
`policy` (2), the node's `txpool` tests (including the new admission test), and the mempool's.

## What changes for people

- A call to a package that declares more than **20,000 gas** is refused by the nodes
  (`MoveCallGasTooHigh`). A legitimate call uses tens to a few thousand.
- Anyone on an older `thrylos` (default 200,000 gas) gets that refusal until they pass
  `--gas 20000` or update. **Say so on the Discord before the window.**
- The proposers pack at most about 60,000 gas of Move calls into a block (at least 60 of the
  lightest calls), so a burst of heavy calls spreads over several blocks.

## Steps

### 1. Prepare (no downtime)

1. `swapon --show` lists `/swapfile`; `free -m` shows headroom (a one-CPU build needs it).
2. Copy the hotfix tree to the VPS as **its own directory** (`/root/thrylos-hotfix`), so the
   tree the running binaries came from is untouched.
3. Build there, at low priority, one job, only what changes:
   ```
   cd /root/thrylos-hotfix
   export PATH=/root/.cargo/bin:$PATH
   nice -n 19 cargo build --locked --release -j1 --bin chain-node --bin thrylos
   ```
   `chain-signer`, `chain-faucet`, `chain-names` and `chain-explorer` do not change. Expect about
   the time of the last rollout's build (a few minutes to twenty; the box is small).
4. Keep the current `thrylos` for step 3 below: `cp -a /root/thrylos-rust/target/release/thrylos /root/thrylos-old`.

### 2. The window (downtime about a minute)

1. `/root/backup.sh`; note the archive and the current height and hash.
2. `mkdir -p /root/releases/policy-before && cp -a /root/thrylos-rust/target/release/{chain-node,thrylos} /root/releases/policy-before/`
3. `systemctl stop thrylos-faucet thrylos-explorer thrylos-validators`; `pgrep -a chain-`
   prints nothing.
4. Install: `cp -a /root/thrylos-hotfix/target/release/{chain-node,thrylos} /root/thrylos-rust/target/release/`
5. `systemctl start thrylos-validators`; poll the RPC until `status` answers (a small chain
   restores quickly, well under the 2.5 minutes of the big one).
6. `systemctl start thrylos-faucet thrylos-explorer`. All eight units `active`.

### 3. Check it (the point of the exercise)

- Height rising, `halted` null, 3 peers, the same chain id (`20260926`).
- **A call that should still work:** with a funded wallet, publish and call a package with the
  new `thrylos` at its default gas: succeeds. `thrylos move call ... --gas 20001` says the limit
  before sending.
- **A call that should be refused by the node:** with the **old** `thrylos` (`/root/thrylos-old`),
  a Move call at its default 200,000 gas is refused with `MoveCallGasTooHigh`. That is the
  hostile shape, refused at the door.
- A native transfer with a large gas limit is unaffected.
- The public endpoints as in the last rollout (rpc, explorer, wallet, names, site).

### 4. Rolling back

```
systemctl stop thrylos-faucet thrylos-explorer thrylos-validators; pgrep -a chain-   # nothing
cp -a /root/releases/policy-before/* /root/thrylos-rust/target/release/
systemctl start thrylos-validators   # then wait for the RPC
systemctl start thrylos-faucet thrylos-explorer
```

Nothing in this change touches the database, so going back needs nothing else.

## What this does not do

It bounds what users can do to a validator; it does not bound what a *validator's own
proposal* can carry, because it is not a consensus rule. All four validators are the operator's.
It also leaves the block's Move work at up to 0.6 to 0.8 seconds in the worst case, which is
slow for a one-second block. The recalibration (`gas-calibration.md`) in the next reset is the
fix; remove this stopgap only after that.
