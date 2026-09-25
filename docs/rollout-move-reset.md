# Rollout: Move publishing, and the testnet reset it needs

Status: **done, 2026-09-25 12:15 UTC.** Rehearsed locally first. See the section
in `operations-vps.md` for what was run and where the old chain is.
Follows `rollout-batch-2.md` for the mechanics of a chain change, but this one
is different in kind: it **starts the chain over**.

## Why a reset, not an upgrade

Two things in this change alter what a chain's state is, so the new binaries
cannot read the old chain:

- the governed parameters gained one field (`publish_enabled`), which changes
  their stored encoding by a byte and so fails to decode the old ones;
- genesis now holds two more packages (the Move standard library at `0x1` and
  the Thrylos framework at `0x2`), so the genesis hash and state root differ.

There is no migration, on purpose: the testnet is an experiment and the value on
it is play money. The same reset is how any later change of this kind would go.

## What is lost, and what is kept

**Lost (say so before doing it):**

- every balance, including everyone's faucet THRY, and every transaction;
- every reserved and confirmed `.thry` name (a claim commits to the chain id);
- the faucet's request history, so everyone may claim again.

**Kept:** the four operator wallets (`/root/.thrylos-alpha/operators`), the faucet's key
and settings, the names service's configuration and secret, all of Cloudflare, DNS,
the wallet page and the landing page. Wallets people made keep working: a wallet is
a key, and its address is the same on the new chain (with a zero balance).

The old chain is not deleted: it is moved to `network.old-<oldchain>-<time>`, and the
old faucet and names state are kept beside their replacements as `*.old-<oldchain>`.

## What the reset does

`scripts/reset-testnet.sh` (rehearsed end to end by `scripts/rehearse-reset.sh`):

1. refuses to run if any process still uses the network directory, or if the new
   chain id equals the old (a reused id would let old signed transactions replay);
2. reads the operators' public keys from their wallet files and the faucet's;
3. moves the old network aside and runs `chain-node testnet init` with **the same
   ports and block pace** as before, one validator per operator, a **new chain id**,
   and the faucet as the only funded account (100,000 THRY, as before);
4. gives the faucet and the names registry state files with no records, in the same
   shape as before, and points the names configuration at the new chain id.

The new consensus and signer keys are fresh (each `testnet init` makes them); the
operator wallets are the same.

## Rehearsal, done on the Mac

`scripts/rehearse-reset.sh` builds a scratch copy of the VPS's layout, runs the reset
against it and then behaves like a user: the four-node network starts and reaches
height 3, the names service opens its emptied registry, the faucet holds exactly its
genesis allocation, a new wallet gets THRY from the faucet, publishes a package that
imports the standard library, and calls it (one success, one Move abort). It passed.

Not rehearsed, because it cannot be here: the build on the VPS's one CPU, and the
public path through Cloudflare. Those are checked in the window.

## Choose before starting

1. **The new chain id.** Suggested: `20260926` (the old one is `20260923`). It only
   has to be unique to this network and never reused.
2. **A time.** The chain is down for roughly five minutes: nothing has to restore, so it
   is quicker than a normal restart, but the four nodes still start on one CPU.
   Anything people were doing on the testnet stops working until then.

## Steps

### 1. Prepare (no downtime)

1. `swapon --show` lists `/swapfile`. If not, stop.
2. From the Mac, sync the source (the `move/` directory has to be included: the
   system packages' bytecode is compiled into the binaries from it):
   `rsync -a --exclude target --exclude .git --exclude .DS_Store ./ root@157.230.10.32:/root/thrylos-rust/`
3. Build into a copy so nothing running is overwritten, at low priority, one job at a
   time (the Move compiler is memory-hungry, and the box has 961 MB):
   ```
   ssh -i ~/.ssh/id_ed25519_thrylos_alpha root@157.230.10.32
   export PATH=/root/.cargo/bin:$PATH
   cd /root/thrylos-rust
   cp -a target target-new
   CARGO_TARGET_DIR=target-new nice -n 19 cargo build --locked --release -j1 \
     --bin chain-node --bin chain-signer --bin chain-faucet --bin chain-explorer \
     --bin chain-names --bin thrylos
   ```
   Watch it: if `dmesg | tail` shows a process killed for memory, stop and reassess
   (the chain must not be touched while the build is unhealthy).
4. Check the new binaries run: `target-new/release/thrylos --version`.

### 2. The window (downtime starts)

1. `/root/backup.sh`, and note the newest archive in `/root/backups/`. Record the
   current height and state root from `https://rpc.thrylos.org` for the record.
2. Keep the old binaries: `mkdir -p /root/releases/move-before && cp -a
   /root/thrylos-rust/target/release/chain-* /root/releases/move-before/`.
3. `systemctl stop thrylos-faucet thrylos-explorer thrylos-names thrylos-validators`
   and confirm `pgrep -a chain-` prints nothing (a leftover signer holds its lock).
4. Install the new binaries: `cp -a /root/thrylos-rust/target-new/release/{chain-node,chain-signer,chain-faucet,chain-explorer,chain-names,thrylos} /root/thrylos-rust/target/release/`
5. The reset:
   `/root/thrylos-rust/scripts/reset-testnet.sh /root/.thrylos-alpha /root/thrylos-rust/target/release 20260926`
6. `systemctl start thrylos-validators`, then poll the RPC until it answers (it
   should be quick, there is nothing to restore):
   `curl -s -X POST http://127.0.0.1:26660/ -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"status"}'`
   Healthy is `halted` null, 3 peers, height rising, `chainId` 20260926.
7. Before the faucet service starts, prove the whole loop from the VPS (the faucet's
   offline commands are only for use while `run` is not running, as it is not now):
   ```
   T=/root/thrylos-rust/target/release
   $T/thrylos setup --wallet /root/smoke.key
   $T/chain-faucet request /root/.thrylos-alpha/faucet smoke "$($T/thrylos address --wallet /root/smoke.key)"
   $T/chain-faucet work /root/.thrylos-alpha/faucet
   ```
   The smoke request stays in the faucet's history (one request, for a key about to
   be deleted). Then `shred -u /root/smoke.key`.
8. `systemctl start thrylos-faucet thrylos-explorer thrylos-names`; `systemctl is-active
   thrylos-{validators,faucet,explorer,tunnel,wallet,names,site,redirect}` all `active`.

### 3. Check it from outside

- `rpc.thrylos.org` status: new chain id, rising height.
- `explorer.thrylos.org`, `wallet.thrylos.org` (make a wallet: it should get a name step
  and the names service should answer), `names.thrylos.org/names/available/test`.
- From the Mac, with a wallet that has THRY (use `/faucet` in Discord, or the offline
  path above): `thrylos move publish <module.mv> --rpc https://rpc.thrylos.org` and a
  `thrylos move call`. That is the first real proof of publishing over the public path.

### 4. Afterwards

Delete `/root/thrylos-rust/target-new`. Leave the swapfile on. Update
`operations-vps.md` with the new chain id and the height the new chain started at.
The old chain directory (`network.old-*`) can be deleted once nobody needs it; it is
in the backup too.

## Rolling back

If the new chain does not start, or something is wrong that cannot be fixed in the
window:

```
systemctl stop thrylos-faucet thrylos-explorer thrylos-names thrylos-validators
pgrep -a chain-            # nothing
cd /root/.thrylos-alpha
mv network network.failed-move
mv network.old-20260923-* network
mv faucet/state.json.old-20260923 faucet/state.json
mv names/names.json.old-20260923 names/names.json
# and set "chain_id" back to 20260923 in names/names-config.json
cp -a /root/releases/move-before/* /root/thrylos-rust/target/release/
systemctl start thrylos-validators     # then wait for the RPC (about 2.5 minutes: it restores)
systemctl start thrylos-faucet thrylos-explorer thrylos-names
```

The old chain is exactly as it was stopped; nothing wrote to it. If even that fails, restore
the archive from step 2.1.

## What this does not change

Cloudflare and DNS, the tunnel, the unprivileged static servers, the backup cron, and
the fact that the chain, faucet, explorer, names and tunnel still run as root.
