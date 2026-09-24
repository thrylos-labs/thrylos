# `.thry` names for the testnet

Status: **built, tested and deployed to the alpha on 2026-09-24.** (Registry: `crates/node/src/names.rs`, `names_service.rs`, `bin/chain-names.rs`. Faucet: `/name` and confirmation in `faucet_discord.rs`. Wallet: `deploy/wallet/app.js`.) Names are an **off-chain**
convenience for the alpha: the chain never sees them, nothing about consensus
changes, and the registry can be reset with the testnet.

## The rule

A wallet **cannot be created without a name.** The create form asks for one,
checks it is free, and the wallet **reserves** it with a signature from the new
key. The reservation becomes a permanent name when the owner **confirms it in
Discord**, which for most people is the `/faucet` they run anyway. One name per
Discord account.

If the name is taken or the registry cannot be reached, no wallet is created.
That is deliberate, and it means wallet creation depends on the registry being
up (the wallet page itself stays static).

## The life of a name

```
   (nothing) --reserve, signed by the wallet--> PENDING --Discord confirms--> CONFIRMED
                                                   |
                                                   +--72 hours pass--> gone (name is free again)
```

- **Pending:** held for 72 hours. Not resolvable, and the name is not shown to
  anyone. Only the fact that the address has a pending reservation, and when it
  lapses, is visible (see the lookup below).
- **Confirmed:** permanent. Resolvable everywhere. Tied to one Discord user.
- If a pending reservation lapses, the name is free again and the wallet offers
  to reserve it again.

## What the user sees

1. Create wallet: choose `alice`, choose a password. The wallet says *"Reserved.
   Paste your address into `/faucet` in Discord to confirm your name."*
2. Run `/faucet` with that address. The reply says the payout is queued and that
   `alice.thry` is now theirs.
3. The wallet notices on its next refresh (it polls every 10 seconds already)
   and shows *alice.thry, confirmed*.

## Names

- 3 to 20 characters from `a-z`, `0-9` and `-`; must start and end with a letter
  or digit; no `--`. Case is folded to lowercase. Nothing else is accepted, which
  rules out look-alike (homoglyph) characters.
- Shown as `alice.thry`. The `.thry` suffix is display only; the stored name is
  `alice`, and the wallet accepts either form.
- A reserved list is refused (`admin`, `faucet`, `thrylos`, `thry`, `explorer`,
  `wallet`, `rpc`, `validator`, `root`, `support`, `team`, and similar).
- One name per address, one address per name, **one confirmed name per Discord
  user.** Permanent once confirmed: no renaming and no transfer. (A wrong name
  means a new wallet and, from a different Discord account, a new name; this is
  a testnet.)

## The reservation (signed by the wallet)

Ownership of the address is proved by signing, so only someone holding the key
can reserve a name for it.

Signed bytes (all integers little-endian):

```
"thrylos-name-claim-v1"  (21 ASCII bytes, no terminator)
chain_id                 (u64)
name_length              (u8)
name                     (ASCII, lowercase, as stored)
address                  (32 bytes)
timestamp_ms             (u64)
```

Request `POST /names` (JSON):

```json
{ "name": "alice", "publicKey": "<64 hex>", "timestampMs": 1790000000000,
  "signature": "<128 hex>" }
```

The registry checks, in this order, and refuses at the first failure:

1. the body is small (under 1 KiB) and well formed;
2. the name obeys the rules and is not reserved;
3. `timestampMs` is within 5 minutes of the registry's clock (a replayed request
   goes stale);
4. the address is derived from `publicKey` (the same BLAKE3 derivation as the
   chain), and the Ed25519 signature over the bytes above verifies with
   `verify_strict`;
5. the name is free (not confirmed, and not pending for someone else) and the
   address has no confirmed name and no unexpired pending one;
6. the limits below.

The chain id is inside the signed bytes so a request made for one network cannot
be replayed on another.

## Confirming in Discord

The faucet already handles Discord interactions and already enforces the
account-age gate, the optional server-membership gate and the daily limits. It
confirms names in two places:

- **`/faucet address:<thry1…>`.** If the request is *accepted* (it passes the
  gates and the limits and is queued), and the address has a pending
  reservation, and this Discord user has no confirmed name, the reservation
  becomes permanent. A refused request confirms nothing.
- **`/name address:<thry1…>`**, a new command with no payout, for anyone who
  cannot or does not want to claim funds (the daily limit is used up, or the
  faucet is empty). It applies the same age and membership gates, then confirms.
  It is also how a wallet that already existed confirms a name reserved later.

Either way the address given must be the one with the pending reservation. The
reply says what happened, including the refusals (no reservation for that
address, the reservation lapsed, you already have a name).

**How the faucet tells the registry.** The faucet calls the registry on the
loopback interface, `POST /internal/confirm` with `{ "address", "discordUserId" }`,
carrying a shared secret in a header. The secret is a 32-byte random file
(`names.secret`, mode 0600) that both services read; it is compared in constant
time. The endpoint is not exposed through the tunnel. If the registry is
unreachable the faucet still pays out, and says the name could not be confirmed
yet and to run `/name` again.

## The service

A new small binary, `chain-names`, in its own systemd unit, **not** part of the
faucet process. The faucet holds the funded key, and a public write endpoint
should not share a process with it. Cost: one more unit, a Cloudflare Tunnel
route (`names.thrylos.org`) and a DNS record.

- `GET /names/available/<name>`: `{ "name", "valid", "available", "reason"? }`, for the wallet's live check.
- `GET /names/<name>`: `{ "name", "address" }` if confirmed, else 404.
- `GET /names/by-address/<thry1…>`: `{ "status": "confirmed", "name" }`, or
  `{ "status": "pending", "expiresAtMs" }` (no name), or 404.
- `POST /names`: reserve, as above.
- `POST /internal/confirm`: loopback only, shared secret, as above.
- CORS open to any origin on the public routes (the data is public), the same
  posture as the RPC.
- State: one JSON file replaced atomically and synced, like the faucet's
  (`crates/node/src/atomic.rs`). Expired reservations are dropped when read or
  written. Capped at 100,000 confirmed names and 20,000 pending.
- Built on the shared `connection_guard` (16 concurrent connections, 10 s whole-
  request deadline) so slow clients cannot hold it up.
- **Rate limits** on reservations (they cost nothing to make): 5 an hour per
  source address (the tunnel's `CF-Connecting-IP`, trusted only because the
  service listens on loopback behind the tunnel), 500 an hour overall, and 60
  lookups a minute per source. With the 72-hour expiry and the pending cap, a
  script cannot hold names it never confirms for long, and it cannot confirm
  without an aged Discord account that passes the faucet's gates.

## The wallet

- **Create:** name field with a debounced availability check. The key is made in
  memory, the reservation is signed and sent, and only after the registry
  accepts it is the seed encrypted and stored (the password step is unchanged).
  The wallet then shows the pending state and the address to paste into
  `/faucet`, and polls until it reads *confirmed*.
- **Import:** the address is looked up. If confirmed, the name is shown. If it
  has none, the reservation step is required before the wallet can be used.
- **Wallets that already exist** have no name. On unlock they are asked to
  reserve one and **cannot send until it is confirmed**, matching the rule for
  new wallets. They confirm with `/faucet` or `/name`.
- **Sending:** the recipient box accepts `alice` or `alice.thry` as well as a
  `thry1…` address. A name is resolved, and the wallet then **shows the full
  address, with its checksum, and asks for confirmation.** It never sends on a
  name alone, so a wrong or changed mapping cannot silently redirect funds.
- The page's CSP gets one more `connect-src`: the registry host.
- The notice says plainly that names are public, tied to the address for good,
  off-chain, and reset with the testnet.

## The explorer

Later, not needed for launch: show `alice.thry` beside an address it knows,
using the registry's by-address lookup.

## Known limits

- Someone who knows an address that has a pending reservation could run
  `/faucet` or `/name` with it first, and the name would confirm under *their*
  Discord account. The name still points at the right address and works. It
  costs them their one name, and they cannot see the pending name, so it is a
  poor attack. It is accepted.
- No Discord means no name. That fits a testnet whose faucet is Discord-only.
- If the faucet or registry is down for more than 72 hours, reservations lapse
  and people reserve again.
- Names are off-chain: they do not survive a testnet reset, and the registry's
  operator can change what a name resolves to. Trust the address the wallet
  shows, not the name.
- A person with several aged Discord accounts can hold several names. The
  faucet's daily cap and gates bound this, as they do the faucet itself.

## Tests to write with it

- **The reservation:** a valid one is accepted; a wrong key, wrong name, wrong
  chain id, a stale timestamp, a replayed request, a tampered byte and a
  non-canonical signature are each refused. Rules: every reserved name, boundary
  lengths, a leading or trailing hyphen, upper case, non-ASCII and homoglyphs.
- **The life cycle:** pending expires and frees the name; confirm makes it
  permanent; a second confirm and a second name for one Discord user are
  refused; a pending name is not resolvable and its name is not returned.
- **Confirmation paths:** `/faucet` confirms only when the request is accepted;
  `/name` applies the same gates; the address must match; a refused request
  confirms nothing; the shared secret is required and checked in constant time;
  the registry being down does not stop a payout.
- **Uniqueness both ways,** the caps, and the rate limits.
- **The state file** survives a restart and a crash between write and rename.
- **Slow and silent clients** do not stop lookups (as for the faucet).
- **Wallet and registry agree:** a test that signs in JavaScript and verifies in
  Rust over the same bytes, so the two implementations cannot disagree.

## Open decisions (defaults in bold)

1. Separate `chain-names` service (**yes**) or add the routes to the faucet.
2. Names permanent once confirmed (**yes**) or renameable once.
3. Pending reservation lasts **72 hours** (24 is the alternative).
4. A separate `/name` command for confirming without a payout (**yes**), or
   confirm only through `/faucet`.
5. Reserved-name list: **the one above**, extended as you like.
6. Rate limits as stated (**yes**) or tighter.
7. Existing wallets blocked from sending until named (**yes**) or a grace period.

## Deploying

Nothing about the chain changes, so there is no validator restart. Order matters
because the wallet refuses to create a wallet without the registry:

1. **Build and start the registry** (in a separate target directory, as for the
   other services): `chain-names init /root/.thrylos-alpha/names --chain-id
   20260923`, install `deploy/thrylos-names.service`, `systemctl enable --now
   thrylos-names`. It listens on `127.0.0.1:8083`.
2. **Route it.** Add a Cloudflare Tunnel ingress rule for `names.thrylos.org` to
   `127.0.0.1:8083` and a DNS record for the hostname. **Do not route
   `/internal/`**: the service also refuses any request bearing Cloudflare's
   headers, but the route should not exist.
3. **Point the faucet at it.** In `faucet.json` set
   `"names_registry": "127.0.0.1:8083"` and `"names_secret_file":
   "/root/.thrylos-alpha/names/names.secret"`, then restart the faucet.
4. **Register the new Discord command.** `chain-faucet discord-commands` prints
   the definitions, now including `/name`; post them to Discord's
   application-command API as before.
5. **Check it works before the wallet goes out:** `curl
   https://names.thrylos.org/names/available/test` answers, and a signed
   reservation from a scratch key is accepted.
6. **Only then deploy the wallet, with `scripts/deploy-wallet.sh`** (not a bare
   `rsync`). Until the registry answers at `names.thrylos.org`, the new wallet
   cannot create wallets. The script stamps `app.js` with a hash of its
   contents in the URL (`app.js?v=…`): Cloudflare has browsers cache `.js` for
   four hours, and a stale `app.js` beside the new `index.html` runs the old
   create flow, which has no name step. That happened on the first deploy and
   was only noticed in a live test.

Wallets created before this shipped have no name; on unlock they are asked to
reserve one, and confirm it with `/faucet` or `/name`.

## What was verified

### In code and in tests

- The registry, the service and the faucet integration have unit tests; the
  running `chain-names` process is driven over real TCP in
  `crates/node/tests/names_wire.rs` (reserve, confirm with and without the
  secret and through tunnel headers, CORS, restart, slow clients).
- **The wallet's JavaScript signature was verified by the Rust registry:** the
  real wallet page, run against a real `chain-names`, reserved a name, was
  confirmed, and resolved. Also exercised in the browser: live availability,
  reserved and taken names, sending blocked while pending, name recipients
  resolved with a second confirming press, an existing wallet with no name, and
  creation refused with nothing stored when the registry is down.

### Live on the alpha (2026-09-24)

Deployed: `thrylos-names.service` on `127.0.0.1:8083`; a tunnel route for
`names.thrylos.org` with a rule above it that answers 404 for `/internal`; the
faucet on the new binary with `names_registry` and `names_secret_file` set; the
three Discord commands registered; the new wallet.

Observed working:

- The public registry answers lookups, sends the CORS headers and answers the
  browser preflight. `/internal/confirm` returns 404 at the tunnel, and would
  return 401 at the service with a wrong secret or through the tunnel's headers.
- The live wallet page requires a name; refuses a too-short name and a
  reserved one; shows availability from the live registry; and creates the
  wallet only after the live registry has accepted the signed reservation,
  under the chain's real id. The key is stored encrypted.
- **`/name` from a real Discord account confirmed a reserved name end to end:**
  Discord's signed request, the faucet, the local call with the shared secret,
  and the registry. The registry then held one confirmed name tied to that
  address and Discord account, and the logs showed no errors.

### Not yet verified live

- Sending to a name from a second wallet (resolution, the full address shown,
  the second confirming press). Only tested locally.
- `/faucet` confirming a name in the same request as the payout. It needs a new
  wallet and a new name on a day the account's faucet allowance is unused.
- The refusals from a real account: too-young account, an account that already
  has a name, no reservation for the address, a lapsed reservation.
- A registry outage while the faucet pays out (tested against a stand-in only).
- The rate limits, the 72-hour lapse, and the server-membership gate (off).

### Problems found on the way

- **A stale cached script ran beside the new page.** The first wallet deploy
  left browsers holding the previous `app.js` for up to four hours, and that
  script has no name step, so the live wallet created a wallet without asking
  for a name. Found in the first live test; fixed by `scripts/deploy-wallet.sh`
  (see step 6 above).
- **Unexplained cross-origin errors.** During that first, stale session the
  browser reported the RPC's preflight as lacking `Access-Control-Allow-Origin`.
  The RPC's headers were correct when checked directly, and after the fix six
  consecutive calls from the wallet's origin succeeded. The cause was not found;
  if the wallet ever cannot reach the RPC from a browser, look here first.
- **The registry's `POST /internal/confirm` was reachable through the tunnel**
  (refused by the service, but reachable). Closed at the tunnel with the
  `path: ^/internal` rule above.

### Cost of running it

The box has about 100 MB of free memory and no swap. The registry is small and
fits, but a build on the VPS needs the temporary swapfile first.
