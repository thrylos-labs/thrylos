# Operating the alpha VPS

What runs on the alpha machine, how it is published, and how to change it
safely. Written 2026-09-24 from the machine itself (not from memory), after the
audit fixes, the `.thry` names service and the landing page went live. It
describes one host; nothing here is a design for more than one.

Related: `rollout-audit-fixes.md` and `rollout-batch-2.md` (how the two chain
rollouts were done), `thry-names.md` (the names service), `release-signing.md`.

## The machine

| | |
|---|---|
| Host | A small VPS at `157.230.10.32` (its hostname looks like a DigitalOcean default), Ubuntu 24.04, x86_64 |
| Size | **1 vCPU, 961 MB RAM, no swap**, 24 GB disk (about 16 GB free) |
| Access | `ssh -i ~/.ssh/id_ed25519_thrylos_alpha root@157.230.10.32` (the default key is refused) |
| Memory | Runs at **about 75 MB free**. Anything that builds needs the temporary swapfile first (below). |

Everything is public only through one Cloudflare Tunnel; nothing listens on a
public address. All services bind `127.0.0.1`.

## What runs

Eight systemd units, all enabled at boot.

| Unit | What it is | Listens on | Public name |
|---|---|---|---|
| `thrylos-validators` | `chain-node devnet start` supervising **four validator nodes and four signers** as child processes | RPC `26660`–`26663`, peers `26656`–`26659` | `rpc.thrylos.org` (node 1's RPC, `26660`) |
| `thrylos-faucet` | Discord faucet (`chain-faucet run`) | `8081` | `faucet.thrylos.org` |
| `thrylos-explorer` | read-only explorer (`chain-explorer`) | `8080` | `explorer.thrylos.org` |
| `thrylos-names` | `.thry` name registry (`chain-names run`) | `8083` | `names.thrylos.org` |
| `thrylos-wallet` | static wallet page (`python3 -m http.server`), **as `thrylos-web`** | `8082` | `wallet.thrylos.org` |
| `thrylos-site` | static landing page (`python3 -m http.server`), **as `thrylos-web`** | `8084` | `thrylos.org` |
| `thrylos-redirect` | `deploy/www-redirect.py`, redirects to the apex, **as `thrylos-web`** | `8085` | `www.thrylos.org` |
| `thrylos-tunnel` | `cloudflared`, the tunnel that publishes all of the above | none | |

**Least privilege, so far:** only the three static units run as an unprivileged
account with systemd hardening (no capabilities, read-only filesystem except
nothing, no access to `/root`, no network but IP, no writable or executable
memory). The chain, faucet, explorer, names and tunnel units **still run as
root**, because their data and binaries live under `/root`. Moving them out
(to `/var/lib` and `/opt`, each under its own account) needs a chain restart
and is planned, not done.

Binaries run from `/root/thrylos-rust/target/release/`. There is **one chain
process tree**: stopping `thrylos-validators` stops all four nodes and all four
signers together, and starting it starts them together. So a consensus-rule
change is safe on this machine only because every validator switches in the
same restart; there is no mixed-version window, and that stops being true the
moment a second operator runs a node.

## Where things are

| Path | Contents |
|---|---|
| `/root/thrylos-rust/` | Source, synced from the Mac with rsync (no `.git`), and `target/` (build output) |
| `/root/.thrylos-alpha/network/node1..4/` | Each validator's data: `data/` (chain database, WAL), `node.json`, `signer.key`, `signer.mark` and `signer.mark.lock`, logs |
| `/root/.thrylos-alpha/faucet/` | `faucet.json`, the faucet wallet `faucet.key`, `state.json` |
| `/root/.thrylos-alpha/names/` | `names-config.json`, `names.json` (the registry), `names.secret` |
| `/root/.thrylos-alpha/discord-commands.json` | An **old** copy of the Discord command list (two commands). Not used; the current list comes from `chain-faucet discord-commands`. |
| `/srv/thrylos/{wallet,site,redirect}/` | What the three static units serve. **Owned by root, read-only to the account they run as** (`thrylos-web`), which cannot read anything under `/root`. The old copies in `/root/thrylos-wallet`, `/root/thrylos-site` and `/root/thrylos-redirect` are unused and can be deleted. |
| `/root/.cloudflared/` | `config.yml` (the tunnel's routes), `cert.pem`, the tunnel credentials, and `config.yml.bak-*` |
| `/root/releases/{prev,batch1,batch2}/` | Old binaries kept for rollback (see below) |
| `/root/backups/` | Nightly archives of `/root/.thrylos-alpha`. **Directory `0700`, archives `0600`**, made by `scripts/backup-vps.sh` (installed as `/root/backup.sh`) |
| `/etc/systemd/system/thrylos-*.service` | The units (copies of `deploy/*.service` in the repo, plus the older ones) |

**Secrets** (never commit, never paste): every `signer.key`, `network.key` and
`signer.credential` under `network/node*/`; `faucet/faucet.key`; the faucet's
`discord_public_key` (public, but part of `faucet.json`); `names/names.secret`.
The backups contain all of these.

## The tunnel and DNS

`/root/.cloudflared/config.yml` maps a hostname to a local port. Current rules,
in order (first match wins, the last line is the catch-all):

```
rpc.thrylos.org        -> 127.0.0.1:26660
faucet.thrylos.org     -> 127.0.0.1:8081
explorer.thrylos.org   -> 127.0.0.1:8080
wallet.thrylos.org     -> 127.0.0.1:8082
names.thrylos.org  path ^/internal -> http_status:404      (the faucet-only route is not published)
names.thrylos.org      -> 127.0.0.1:8083
thrylos.org            -> 127.0.0.1:8084
www.thrylos.org        -> 127.0.0.1:8085
(anything else)        -> http_status:404
```

- The tunnel's config is read **only when `thrylos-tunnel` restarts**, and a
  restart drops the RPC, explorer, wallet and everything else for about ten
  seconds while it reconnects.
- To change it: copy the file to `config.yml.bak-<why>`, edit, run
  `cloudflared tunnel --config /root/.cloudflared/config.yml ingress validate`,
  check a hostname with `... ingress rule https://host/path`, then restart.
- A **new hostname also needs a DNS record.** For a name with no record, run on
  the VPS `cloudflared tunnel route dns thrylos-alpha <hostname>`. It **cannot
  replace an existing record** that is not a tunnel CNAME (that is what
  happened with `www`); for those, edit the record in the Cloudflare dashboard
  to a proxied CNAME to `535bd282-9ab2-40da-846a-d41cdafe8910.cfargotunnel.com`.
- `thrylos.org` also carries **email** (Fastmail MX and an SPF TXT record) and
  `docs.thrylos.org` is a separate site. None of those are touched by anything
  here; do not delete records you did not add.

## Checking on it

From anywhere:

```
curl -s -X POST https://rpc.thrylos.org/ -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"status"}'
```

Healthy: `halted` is `null`, `peers` is `3`, and `latest.height` rises about once
a second. Also: `https://explorer.thrylos.org`, `https://wallet.thrylos.org`,
`https://names.thrylos.org/names/available/test`, `https://thrylos.org`, and
`curl -sI https://www.thrylos.org/` (a `301` to the apex).

On the VPS: `systemctl is-active thrylos-{validators,faucet,explorer,tunnel,wallet,names,site,redirect}`,
`journalctl -u <unit> -n 50 --no-pager`, and each node's own log at
`/root/.thrylos-alpha/network/node<N>/node.log`. A restart of the validators is
**not** finished when `systemctl` says active: the RPC only answers after about
2.5 minutes while the four nodes restore state on one CPU. Wait for `status` to
return a height.

## Changing things

### The chain, faucet, explorer or names binaries (Rust)

Follow `rollout-batch-2.md`; in short:

1. **Swap on** (a build can otherwise be killed by the memory limit, and take a
   validator with it): `fallocate -l 2G /swapfile && chmod 600 /swapfile &&
   mkswap /swapfile && swapon /swapfile`.
2. From the Mac, `rsync -a --exclude target --exclude .git --exclude .DS_Store ./
   root@157.230.10.32:/root/thrylos-rust/`. Check the commit (`git rev-parse HEAD`,
   clean `git status`).
3. Build **at low priority and with the full path to cargo** (a non-login SSH
   shell has no `cargo` on `PATH`): `export PATH=/root/.cargo/bin:$PATH; nice -n 19
   cargo build --locked --release --bin <name>`. Building only the named binary
   leaves the others, and so the running ones, untouched. For a change that
   touches the chain, build into a copy (`cp -a target target-new` and
   `CARGO_TARGET_DIR=target-new`) so nothing running is overwritten.
4. Record checksums, take a backup (`/root/backup.sh`), and copy the running
   binaries somewhere in `/root/releases/`.
5. For the **chain**: stop `thrylos-faucet`, `thrylos-explorer`, `thrylos-validators`;
   confirm `pgrep -a chain-` prints nothing (a leftover signer holds its lock);
   copy the new binaries in; start the validators; **poll the RPC** until it
   answers; then start the faucet and explorer. About 3 minutes of downtime.
   For the faucet, explorer or names alone: copy the binary and restart just
   that unit.
6. Swap off (`swapoff /swapfile && rm /swapfile`) and delete `target-new`.

### The wallet and the landing page

```
scripts/deploy-wallet.sh
scripts/deploy-site.sh
```

Both stamp a hash of each asset into its URL, and set the copied files to root ownership on the server (macOS's `rsync` has no `--chown`). **Do not deploy these with a bare
`rsync`.** Cloudflare has browsers cache `.js`, `.css` and images for four hours,
and a stale script beside a new page is not cosmetic: it once ran the old wallet
create flow, which has no name step, next to the new page.

### The faucet's settings

Edit `/root/.thrylos-alpha/faucet/faucet.json` (keep a `.bak-*` copy), then
`systemctl restart thrylos-faucet`. The knobs: `payout`, the daily limits,
`min_account_age_days` (default 7), `min_server_membership_days` (default 0, off),
and `names_registry` / `names_secret_file` (both or neither). The Discord
commands are registered separately with Discord's API, from the output of
`chain-faucet discord-commands`; a change to that list needs re-registering.

### The names registry

State is `names.json`. The service can be restarted freely; the wallet refuses to
create a wallet while it is down. `names.secret` is shared with the faucet's
`names_secret_file`; if it is ever changed, restart both.

## Rolling back

| What | Undo |
|---|---|
| Chain binaries | Stop the three units, `cp -a /root/releases/batch1/* /root/thrylos-rust/target/release/` (the set from before batch 2; `prev` is the pre-audit set), start them, wait for the RPC. |
| Faucet binary | `cp -a /root/releases/batch2/chain-faucet /root/thrylos-rust/target/release/chain-faucet`, and `faucet.json.bak-before-names` if the names settings are the problem, then restart it. |
| Tunnel routes | Copy the relevant `config.yml.bak-*` back and restart `thrylos-tunnel`. The backups are, in order: `before-names`, `before-internal-block`, `before-site`, `before-www-redirect`. |
| Wallet or site | Re-run the deploy script from the previous commit. |

The chain's history is not replayed on start and no on-disk format has changed,
so going back to older binaries does not need the database changed.

## Backups

`/root/backup.sh` (`scripts/backup-vps.sh` in the repo) runs from cron at **03:17** every day and writes
`/root/backups/thrylos-alpha-<UTC timestamp>.tar.gz` of `/root/.thrylos-alpha`,
keeping the newest 14. `tar` reporting "file changed as we read it" is expected:
the database is copy-on-write and is copied while running. Take one by hand
before any change to the chain: `/root/backup.sh`.

The archives hold every key on the machine, so the script makes them private to root
whatever the caller's umask. They are still unencrypted and on the same disk.

**These have not been restored.** A copy of one made on 2026-09-24 would not start
on a Mac (the pre-audit binaries failed on it the same way), which most likely
means a Linux database does not open under macOS, though a torn snapshot is not
ruled out. A restore has never been rehearsed on Linux.

## Things that have gone wrong

- **`cargo: command not found` in a non-login SSH shell.** Use
  `export PATH=/root/.cargo/bin:$PATH`.
- **Old browser cache next to new files** (wallet, above).
- **A pattern that looks like a stuck restart is normal.** After starting the
  validators the RPC is silent for about 2.5 minutes.
- **`cloudflared tunnel route dns` will not overwrite an existing record.** Edit it
  in the dashboard.
- **Wallet showing RPC "CORS" errors once, during a stale-cache session.** Not
  reproduced; the RPC's headers were correct when checked directly.
- **A second signer on the same mark is refused** (by design, not a fault):
  `signer.mark.lock`. A signer whose `.mark` file was deleted while its `.lock`
  remains also refuses to start.

## Known gaps

- **One machine, one operator.** No failover. A consensus-rule change is only
  safe because all four validators restart together.
- **Backups are on the same disk and same host** as the data, so they do not
  protect against losing the droplet, and they contain every key. They are now
  private to root but not encrypted, and not copied anywhere else.
- **The chain, faucet, explorer, names and tunnel still run as root** (see above).
- **No monitoring or alerts.** Alerting was considered and declined. Nothing
  notices the chain halting except someone looking.
- **The restore path is untested** (above).
- **Memory is about 75 MB free with no swap,** and the static pages are served by
  Python's `http.server`. That is fine for the alpha; a traffic spike on
  `thrylos.org` reaches the same machine as the chain. Moving the landing page
  to a static host (Cloudflare Pages) is the easy fix.
- **Not verified live:** the faucet's payout-plus-name path, sending to a `.thry`
  name from a second wallet, and the names service's refusals from real Discord
  accounts (see `thry-names.md`).
