# `.thry` names for the testnet

Status: **design, for review; nothing built.** Names are an **off-chain**
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
