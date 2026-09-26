# Rollout: the third testnet reset (gas recalibration, storage, reading state, tooling)

Status: **done, 2026-09-26 about 07:38 UTC** (chain id `20260927`; see `operations-vps.md`). Written 2026-09-26. The mechanics are those of
`rollout-move-reset.md` (read it first; this only says what is different). The reset script
(`scripts/reset-testnet.sh`) is unchanged and the local rehearsal (`scripts/rehearse-reset.sh`) has been
extended to cover what this reset brings.

## Why a reset

Gas is consensus, and so is what a stored value is. The running chain (chain id 20260926, built from
commit `a726a77` plus the node-local gas stopgap) cannot run the new code:

- **Gas**: every price changed, the block gas limit went from 60,000,000 to 300,000 and a transaction
  from 15,000,000 to 75,000, and the governance clamps moved with them. The genesis hash therefore
  changed (`compatibility-vectors.md`).
- **Storage**: a call can now keep values in drawers; the state holds a new kind of entry and the
  framework package at `0x2` has a new module (`thrylos::store`), which is in genesis.
- **Publishing**: modules that keep a type they do not define are refused, and packages may depend on
  other published packages. That changes which packages are valid.

There is no migration, as before: the coin is play money.

## What people will notice

- **Everything is lost**, as in the last reset: balances, transactions, names (a claim commits to the
  chain id), the faucet's history, and every published package.
- **Publishing and calling work as before**, and a package can now remember: the developer guide
  (`move-developer-guide.md`) describes it, and stops saying it is not on the public testnet.
- **Gas figures change.** The most a transaction may use is 75,000 gas (about 75 ms of a validator's
  time). An ordinary call uses a few hundred. The most a publish can be is about 48 KB of bytecode.
  Old wallets and the old `thrylos` still work (a wallet is a key), except that the old CLI's default
  of 200,000 gas is over the limit: everyone should update `thrylos`.
- **`simulate` stays off on the public nodes**, so `thrylos move view` works on a local network and
  not on the public one until it is measured there. `thrylos move resource` and the explorer's stored
  values work on the public one.

## Decision to make before starting: the node-local stopgap

`crates/exec/src/policy.rs` (the 20,000-gas mempool cap and the proposer's per-block budget) is still in
the tree and would ship. The chain's own limits now do what it did. Keep it (harmless: a call is capped
at 20,000 gas, well under the 75,000 ceiling, and the CLI says so), or remove it in a separate change
before building. **This is the operator's call**; the rest of this document works either way.

## What was rehearsed

`scripts/rehearse-reset.sh` on the Mac, with debug binaries (which also check the maintained state root
against a full rebuild on every block), 30 seconds end to end:

1. an old alpha (operators, faucet, names, a running chain) is made, then reset to a new chain id;
2. the new four-validator network starts, reaches height 3, the names service opens its emptied registry,
   the faucet holds exactly its genesis allocation;
3. a user gets THRY from the faucet, publishes a package that imports the standard library, calls it
   (a success and a Move abort);
4. **new:** `thrylos move new`, `test`, `build`, `publish` of a counter package that keeps state; `init`
   and `bump` twice; the value read back with `move resource` (`n = 2`) and `move view` (`2`);
5. **new:** six wallets each send an endless-loop call at once: every one runs out of gas and aborts,
   and the chain goes on making blocks (15 blocks in under 7 seconds, at the rehearsal's 200 ms pace);
6. **new:** the network is stopped and started again: it comes back at the same height, the stored value
   is still 2, and the next call takes it to 3 (the restore path, with drawers in state).

The gas figures were also measured on the VPS itself, with the four validators running
(`gas-calibration.md`, "The recalibration, as built"): nothing costs more than a microsecond a gas.

Not rehearsed, because it cannot be here: the build on the VPS's one CPU, and the public path through
Cloudflare. Those are checked in the window.

## Steps

The same four as `rollout-move-reset.md`, with these differences.

### 0. Beforehand

- Post the notice on the Discord: the date and time, that everything is reset (balances, names, packages),
  that the old chain is kept aside, and that people should update `thrylos`.
- Choose the **new chain id**. It must differ from `20260926`, the current one. A date does well, e.g.
  the day of the reset with a suffix.
- Decide the stopgap (above), and build from a clean, committed tree.

### 1. Prepare (no downtime)

- Sync the tree to the VPS (it was built in `/root/thrylos-main`, not `target-new`) and build **all six binaries**, at low priority, one
  job. The last full build on the VPS took **24 minutes** from a copy of an older `target`; expect about
  that, and do it in the hours before, not in the window. `cp -a target target-new` first, as in the last
  rollout; the disk has room (about 11 GB free at the last look).
- `target-new/release/thrylos --version`, and run `chain-node` and `thrylos` with no arguments to see
  they start.

### 2. The window

As in `rollout-move-reset.md`, using the new chain id; about five minutes' downtime. Also keep the
running binaries in `/root/releases/gas-before/` (they are the hotfix build), for a rollback.

### 3. Check it from outside

As before, and additionally, with a wallet that has THRY: publish the counter package from the developer
guide over the public path and `thrylos move resource` it back. That is the first real proof of storage
on the public network.

### 4. Afterwards

- Update `operations-vps.md` (chain id, start height) and the developer guide's "Where things stand".
- Remove `/root/thrylos-hotfix`, `/root/thrylos-main` (or keep it for the next measurement) and
  `target-new`, and the old `/root/thrylos-old` CLI.
- Say on the Discord that it is done, and what changed.

## Rolling back

Exactly as in `rollout-move-reset.md`: the old chain directory is kept, the old binaries are in
`/root/releases/gas-before/`, and nothing writes to the old chain. Note that rolling back also brings back
the gas hole the stopgap covers, so the stopgap binaries (the hotfix build) are the ones to put back.

## After the reset

- The fuzz ceiling (`THRYLOS_MAX_NS_PER_GAS`, 50,000) has not been measured on the CI runner: read the
  first scheduled run.
- `simulate` on the public nodes is off; turning it on wants a measurement of one-a-second calls at
  75,000 gas on the VPS with the validators running.
- Still open from before: the services run as root, backups are unencrypted and on the same disk, there is
  no firewall or fail2ban, no outside uptime monitor, and the names registry rewrite (N-7).
