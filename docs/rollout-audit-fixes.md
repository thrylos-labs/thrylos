# Rolling the audit fixes out to the alpha VPS

Status: **carried out 2026-09-24** (commit `4f383ac`). Written from a read-only
look at the VPS (`157.230.10.32`); the downtime figure is the measured one.

## What is being shipped

Consensus rules (change what a valid block is or costs):

| Change | Effect a user or operator can see |
|---|---|
| Gas floor `MIN_GAS_LIMIT` = 1,000 | A transaction declaring less gas is refused (mempool) or not executed (block). All shipped clients already declare 1,000. |
| `min_self_stake` clamp and state-aware ceiling | Governance can no longer raise it past what keeps 2/3 of stake qualified. |
| Block-slot quota, sync byte cap, protocol-call cap in `propose_block` | Invisible when nobody is attacking. |
| Storage deposit on new state entries | The first delegation to a validator, and opening a governance proposal, burn 0.01 THRY per new entry. |
| Unbonding-entry deposit | `unstake` burns 0.03 THRY out of the unstaked amount; a stake worth less than that is forfeited. |

Node-local (no consensus effect): mempool sequence window and eviction order,
signer mark-file lock, RPC whole-request deadline, faucet account-age gate
(Discord accounts younger than 7 days are refused; `min_account_age_days`, 0
turns it off), wallet CSP and self-hosted crypto (already live).

## What the VPS looks like

- One `thrylos-validators.service` runs `chain-node devnet start`, which
  supervises **four `chain-node run` processes and four `chain-signer`
  processes** as children, all from `/root/thrylos-rust/target/release/`.
  Stopping the unit stops all eight, so there is **no mixed-version window**:
  every validator switches in one restart. No coordinated multi-host rollout
  is needed while the alpha is a single machine.
- Also from the same directory: `thrylos-faucet`, `thrylos-explorer`.
  `thrylos-tunnel` (cloudflared) and `thrylos-wallet` (static files) do not
  change.
- **1 vCPU, 961 MB RAM (about 200 MB free), no swap**, 17 GB disk free. The
  validators are using most of it. This is the main risk of building on the box.
- Chain state is restored from the database on start, not replayed, and no
  on-disk format changed, so old history is untouched and new rules apply from
  the next block. The signer mark file gains a sibling `signer.mark.lock`.
- Operator balances (spare, unbonded coin): node1 1.30 THRY, node2 2.70 THRY,
  node3 0, node4 0. The new proposal deposit is 0.01 THRY, so node1 and node2
  can still propose; node3 and node4 could not before either (a proposal needs
  a fee), so this is not a regression. `unstake` needs no spare balance.

## Decisions for you before starting

1. **Where to build.** Recommended: on the VPS, in a *separate* target
   directory, niced, with a temporary swapfile (below). The alternative, a
   Linux x86_64 build elsewhere, needs a CI job that uploads artifacts, which
   does not exist yet, and gives the more trustworthy binary
   (`docs/release-signing.md`). For an alpha, building on the box matches how
   every earlier deploy was done.
2. **Faucet age gate.** Default is 7 days. Discord accounts newer than that are
   turned away, so say so in the announcement, or set
   `"min_account_age_days"` in `faucet.json` to something lower (or 0).
3. **Window.** The chain stops for about 3.5 minutes (measured on 2026-09-24: stopped 08:50, producing blocks again 08:53; the four nodes restore state on one vCPU and the RPC answers only after about 2.5 minutes). Committed blocks are safe, but the mempool is in memory, so anything
   pending at the restart is likely dropped; pick a quiet time and tell Discord.

## Steps

### 0. Before touching the VPS (on the Mac)

- Everything committed and pushed; the working tree clean.
- One full `cargo test --workspace` and `cargo clippy --workspace
  --all-targets` on that exact commit. (Suites were run crate by crate while
  developing; one whole-workspace run of the final tree has not been done.)
- Note the commit hash; it goes in the announcement and the manifest.

### 1. Prepare on the VPS (no downtime)

```
ssh root@157.230.10.32           # with -i ~/.ssh/id_ed25519_thrylos_alpha
```

1. **Swap, temporarily** (an OOM kill of the build must not be able to take a
   validator with it):
   `fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile &&
   swapon /swapfile`. Remove it after (`swapoff /swapfile && rm /swapfile`).
2. **Source.** From the Mac, rsync the tree, leaving the VPS's `target/` alone
   (no `--delete`): `rsync -a --exclude target --exclude .git --exclude
   .DS_Store ./ root@157.230.10.32:/root/thrylos-rust/`.
3. **Build into a separate directory**, so the running binaries are never
   overwritten and a supervisor respawn during the build cannot pick up a
   half-new set: `cp -a target target-new`, then in `/root/thrylos-rust`:
   `CARGO_TARGET_DIR=target-new nice -n 19 cargo build --locked --release
   --bin chain-node --bin chain-signer --bin chain-faucet --bin
   chain-explorer --bin thrylos --bin chain-genesis` (the repo's
   `rust-toolchain.toml` selects 1.92.0; run it from that directory). Expect
   it to be slow on one core and to slow block production a little; that is
   the reason for `nice`.
4. **Check the build**: `sha256sum target-new/release/chain-* target-new/release/thrylos`, saved
   to a file.
5. **Fresh backup**: `/root/backup.sh` (the nightly one runs at 03:17).
   Record the height and state root: `curl -s -X POST https://rpc.thrylos.org/
   -H 'content-type: application/json' -d
   '{"jsonrpc":"2.0","id":1,"method":"status"}'`.
6. **Keep the old binaries**: `mkdir -p /root/releases/prev && cp -a
   target/release/chain-* target/release/thrylos /root/releases/prev/`.

### 2. Switch (about 3.5 minutes of downtime)

1. Announce.
2. `systemctl stop thrylos-faucet thrylos-explorer thrylos-validators`
   (stopping the validators unit kills the four nodes and four signers with it).
3. Confirm nothing is left: `pgrep -a chain-` prints nothing. A signer left
   alive would hold the new mark lock and the new one would refuse to start,
   which is the lock working, but it would delay the restart.
4. Swap in the new binaries: `cp -a target-new/release/chain-* target-new/
   release/thrylos target/release/` (the systemd units point at
   `target/release/`, so the units do not change).
5. `systemctl start thrylos-validators`, wait about 10 s, then
   `systemctl start thrylos-faucet thrylos-explorer`.

### 3. Verify (before announcing it is over)

- `status` on the public RPC: `height` is rising, `halted` is `null`,
  `peers` is 3, `stateRoot` continues from the recorded one.
- `journalctl -u thrylos-validators -n 100` and each node's `node.log` show no
  error; `signer.log` shows the four signers up; `signer.mark.lock` exists
  beside each `signer.mark`.
- Send a transfer from https://wallet.thrylos.org (or `thrylos`), to a fresh
  address, and confirm the balance falls by amount + fee + 0.01 THRY deposit.
- Send a transaction declaring 500 gas (a hand-built one, or the wallet
  modified locally) and confirm it is refused with `GasLimitTooLow`.
- `/faucet` in Discord from an account older than 7 days queues; from a newer
  one it is turned away with the age message.
- `chain-explorer` on https://explorer.thrylos.org shows new blocks.

### 4. Roll back, if any check fails

The chain's history is not replayed and no format changed, so going back is
just the reverse of step 2:
`systemctl stop thrylos-faucet thrylos-explorer thrylos-validators`, `cp -a
/root/releases/prev/* target/release/`, start the three units again. Blocks
produced under the new rules stay valid (they are only ever restored, not
re-checked); the old rules then govern new blocks. If the database itself is
damaged, restore the step-1 backup instead, at the cost of every block since it.

### 5. Clean up

Remove the swapfile; keep `/root/releases/prev` for a week; delete
`target-new` once satisfied; update `docs/core-network-alpha.md` and post the
commit hash and `sha256sum` output in the announcement.

## Not covered

- **Validator operators other than you.** This plan is for one machine. Once
  other operators run nodes, a consensus-rule change needs a version, an
  activation height, and everyone upgraded before it, which nothing in the
  code supports yet.
- **Reproducible, signed binaries.** The build above is not one
  (`docs/release-signing.md`); fine for the alpha, not for anything after it.
