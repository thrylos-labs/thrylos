# Hardening the alpha VPS: what is open, in order

Written 2026-09-26, from a read-only look at the VPS that day (nothing was changed to write it).

## What is already good

- **Only SSH faces the internet.** Every other service listens on `127.0.0.1` and is reached through
  the Cloudflare tunnel (`ss -ltn` shows port 22 on all interfaces and nothing else).
- **SSH is key-only** (`PasswordAuthentication no`), so guessing passwords cannot work; automatic security
  updates are on (`unattended-upgrades` active).
- The three static servers (wallet, site, redirect) already run as an unprivileged user with a read-only
  system (`User=thrylos-web`, `ProtectSystem=strict`).

## What is open, and how much it matters

| Item | Today | Why it matters | Effort and risk |
|---|---|---|---|
| **Outside uptime monitor** | none | An outage is found by someone noticing | **Done in the repository**: `.github/workflows/uptime.yml`. No VPS change. |
| **The chain, faucet, explorer, names and tunnel run as root** | `User=` unset | A bug in any of them (they parse network input) is a bug with root's reach; the chain and faucet hold the keys | Medium. Needs a downtime of about a minute and a rehearsal. |
| **Backups are unencrypted and on the same disk** | `/root/backups`, 14 daily archives, 400 MB each | They contain the operator and faucet keys, and a disk failure loses the chain and its backups together | Small to medium; needs a decision on where they go (below). |
| **No firewall** | `ufw` inactive, `iptables` accept-all | Today only port 22 listens, so it changes little; it is a guard against a service one day binding to `0.0.0.0` by mistake | Small. A wrong rule locks us out of SSH (the provider's console is the way back). |
| **No fail2ban** | inactive | With key-only login there is nothing to guess; it only quietens the logs | Skip unless the logs become a nuisance. |
| **The names registry rewrite (N-7)** | a code item | See the audit notes | Code, not the box. |

## Recommended order

1. **The uptime monitor** (done). Turns "somebody noticed" into an email.
2. **Backups off the box and encrypted.** Suggested shape: the VPS encrypts each archive with `age` to
   a public key whose private half lives only on the operator's Mac (so nothing on the VPS can decrypt
   what it wrote), and the Mac pulls the new archives with `rsync` over the existing SSH key on a
   schedule. No new accounts, no secrets on the VPS. Needs: the operator's `age` public key.
3. **Run the services as an unprivileged user.** Design below.
4. **A firewall**, last, and only with the provider's console open in another window.

## Running the services unprivileged: design

- A system user `thrylos` (no login shell, no home). The data moves from `/root/.thrylos-alpha` to
  `/var/lib/thrylos`, owned by it, mode `0700`; the key files stay `0600`. The configuration files hold
  absolute paths, so they are rewritten in the same step (the reset script's `sed` shows how).
- The binaries move from `/root/thrylos-rust/target/release` to `/opt/thrylos/bin`, owned by root and
  read-only to the service user, so a compromised service cannot replace its own binary.
- Each unit gets `User=thrylos`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`,
  `PrivateTmp`, `ReadWritePaths=/var/lib/thrylos`, and for the chain a memory ceiling below the box's
  (961 MB) so one runaway cannot take the others down.
- `cloudflared` gets its own user the same way; its credentials file is the only secret it needs.
- `/root/backup.sh` (root, cron) is pointed at the new path.
- Downtime is the chain's restart, about a minute; the rollback is moving the directory back and
  restoring the old unit files (kept as `.bak`).
- It must be **rehearsed first** on a scratch copy (a second copy of the data on the VPS, other ports)
  before it touches the live units.

## What to do when something turns red

The uptime run says which check failed. The first look is always
`ssh root@… 'systemctl is-active thrylos-{validators,faucet,explorer,tunnel,wallet,names,site,redirect}'`
and `journalctl -u thrylos-validators -n 50`; `operations-vps.md` has the rest.
