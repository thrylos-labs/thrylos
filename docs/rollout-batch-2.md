# Rollout, batch 2: the remaining audit fixes

Status: **plan, nothing run.** Written 2026-09-24. Follows
`docs/rollout-audit-fixes.md`, whose procedure this repeats, with the changes
below. The live VPS is on commit `4f383ac`; this ships `fa158f6` (two commits:
`cdeeb4d`, `fa158f6`). The wallet part of `fa158f6` is already live.

## What ships

Consensus rules (one restart of all four validators, as before):

| Change | What is visible |
|---|---|
| A validator's operator has 7 unbonding slots reserved beyond the shared 512 | Nothing at alpha scale: the queue is nowhere near full. |
| Canonical `BTreeMap` decoding (keys strictly ascending) | Nothing for honest data: everything is written in ascending order. Rehearsed, see below. |

Node-local (take effect when the process restarts):

| Change | Where |
|---|---|
| Mempool offers only a sender's next-runnable transaction | validators |
| Signer refuses to start if its `.mark` file is missing but its `.lock` exists | signers; **both files exist on the VPS**, so no effect on the next start |
| RPC/`thrylos` clients cap responses at 16 MiB | `chain-node`, `thrylos`, `chain-faucet` |
| Faucet and explorer serve connections concurrently (16 at once) with a 10 s whole-request deadline | `chain-faucet`, `chain-explorer` |
| Faucet: optional `min_server_membership_days` (default 0, off) | `faucet.json` |

## What was rehearsed, and what could not be

- **Done, on this Mac:** a devnet created and run with the *pre-audit* binaries
  (commit `d2384af`), given a transaction, stopped, then started with the new
  binaries on the same data directory. It restored and kept producing blocks
  (height 19 to 32, 3 peers, not halted). That covers the on-disk formats and
  the new decoding against data the old code wrote.
- **Not possible:** restoring a copy of the *real* VPS backup on the Mac. The
  old binaries fail on it in exactly the same way (all four nodes exit with
  status 1, no message), so it is the copy, not the new code: either the Linux
  database does not open under macOS, or the backup, taken from a live copy-on-
  write database, was not a clean snapshot. Do not read that failure as a
  problem with this batch.
- **Therefore the real restore happens in the maintenance window,** and the
  plan assumes it can fail: the old binaries are kept, and the rollback below
  is the safety, exactly as in batch 1. A failed restore does not change the
  database (the restore reads and checks; new blocks are what write).
- **A rehearsal on the VPS itself is not practical** while the chain runs: four
  nodes and signers need roughly 500 MB and the box has about 180 MB free.

## Decisions before starting

1. **Faucet membership gate.** Leave `min_server_membership_days` at 0, or set
   it (1 or 2 days is the useful range). It needs `/faucet` used in the server
   rather than a DM. Setting it is a one-line edit to
   `/root/.thrylos-alpha/faucet/faucet.json` and takes effect on the faucet
   restart in this window.
2. **Window.** Batch 1 took 3.5 minutes (stop 08:50, blocks again 08:53).
   Expect the same, most of it the four nodes restoring on one CPU.

## Steps

### 1. Prepare (no downtime)

Same as batch 1, with these differences. Everything is done with
`ssh -i ~/.ssh/id_ed25519_thrylos_alpha root@157.230.10.32`.

1. **Swap**, temporary: `fallocate -l 2G /swapfile && chmod 600 /swapfile &&
   mkswap /swapfile && swapon /swapfile`.
2. **Source**, from the Mac, without touching `target/`: `rsync -a --exclude
   target --exclude .git --exclude .DS_Store ./ root@157.230.10.32:/root/
   thrylos-rust/`. Confirm the tree is the commit you mean: `git rev-parse
   HEAD` (expect `fa158f6`) and a clean `git status`.
3. **Build** into a separate directory so the running binaries stay put. From
   `/root/thrylos-rust`: `cp -a target target-new`, then
   `export PATH=/root/.cargo/bin:$PATH` (a non-login shell does not have it;
   that cost a retry last time) and
   `CARGO_TARGET_DIR=target-new nice -n 19 cargo build --locked --release
   --bin chain-node --bin chain-signer --bin chain-faucet --bin
   chain-explorer --bin thrylos --bin chain-genesis`. Last time: 2 min 46 s.
4. **Checksums**: `sha256sum target-new/release/chain-* target-new/release/
   thrylos > /root/new-binaries-2.sha256`.
5. **Backup**: `/root/backup.sh`; record height and state root from the public
   RPC `status`.
6. **Keep what is running now** (batch 1's binaries) as the rollback set:
   `mkdir -p /root/releases/batch1 && cp -a target/release/chain-* target/
   release/thrylos /root/releases/batch1/`. `/root/releases/prev` (pre-audit)
   stays as it is.
7. Optional: edit `faucet.json` for the membership gate (decision 1).

### 2. Switch (about 3.5 minutes)

1. Announce in Discord.
2. `systemctl stop thrylos-faucet thrylos-explorer thrylos-validators`, then
   `pgrep -a chain-` must print nothing (a leftover signer would hold its lock).
3. `for b in chain-node chain-signer chain-faucet chain-explorer chain-genesis
   thrylos; do cp -f target-new/release/$b target/release/$b; done`, and check
   the checksums match `/root/new-binaries-2.sha256`.
4. `systemctl start thrylos-validators`; **wait for the RPC**, not the clock:
   poll `status` on `127.0.0.1:26660` until `height` appears (about 2.5 min).
5. `systemctl start thrylos-faucet thrylos-explorer`.

### 3. Verify

- Public RPC `status`: height rising, `halted` null, `peers` 3.
- `journalctl -u thrylos-validators` since the restart: no error, halt or
  panic. Each node's directory has `signer.mark` **and** `signer.mark.lock`.
- Faucet: `journalctl -u thrylos-faucet` shows it listening; `/faucet` from an
  old account still queues, from a young one is refused. If the membership gate
  is on, `/faucet` in the server works and in a DM is refused with the
  membership message.
- Explorer: https://explorer.thrylos.org shows new blocks, and still answers
  while a slow client is holding a connection (`nc 127.0.0.1 8080`, say nothing).
- A wallet transfer to a fresh address still deducts amount + fee + 0.01 THRY.

### 4. Roll back, if a check fails

`systemctl stop thrylos-faucet thrylos-explorer thrylos-validators`, `cp -a
/root/releases/batch1/* /root/thrylos-rust/target/release/`, start the three
units again. If the new mark-file check refuses a signer, its message says why;
the rollback binary does not have that check. Restore the step-1 backup only if
the database itself is damaged.

### 5. Clean up

`swapoff /swapfile && rm /swapfile`; `rm -rf /root/thrylos-rust/target-new`;
keep `/root/releases/batch1` and `/root/releases/prev` for a week.

## Open risks

- **The real-state restore is not rehearsed** (above). The rollback is tested
  in principle only; it worked as designed in batch 1 by not being needed.
- **Memory.** About 180 MB free, no swap once cleaned up. A build while the
  chain runs slows block production; run it at `nice -n 19` and keep the swap on
  until it is done.
- **One machine.** As before, a consensus-rule change is safe here only because
  all four validators restart together in one unit.
