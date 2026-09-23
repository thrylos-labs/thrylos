# Core-network alpha

The first useful alpha is a coin network, not an application platform. A user
can create an account, receive test THRY, send it and verify what happened. The
explorer remains read-only. User Move-module publishing and the Move Prover are
not release blockers for this phase.

## First slice

The `thrylos` binary is the public account CLI:

```text
thrylos setup
thrylos address
thrylos balance [address]
thrylos send <amount> <address>
thrylos tx <hash>
thrylos status
thrylos network add <name> <rpc>
thrylos network use <name>
thrylos network list
thrylos network remove <name>
```

`setup` creates one Ed25519 account key at `~/.thrylos/wallet.key`, makes the
file readable only by its owner and refuses to replace it. `THRYLOS_WALLET` or
`--wallet` selects another file. No command prints the private key.

For local development the CLI connects to `127.0.0.1:26660`. `--rpc` accepts
either a local node's `host:port` (plain HTTP) or a public gateway's
`https://host[:port]` URL; TLS is verified with a pure-Rust client
(`rustls`, Mozilla's compiled-in root list) rather than any OS trust store,
so the same check runs the same way on every platform this CLI ships for.
`THRYLOS_RPC` sets it for one shell session, and `thrylos network add/use`
saves it in `~/.thrylos/networks.json` so it does not need to be typed on
every command. Precedence is `--rpc`, then `THRYLOS_RPC`, then the network
`thrylos network use` last selected, then the local-node default.

## Secure public RPC access

Validator RPC stays bound to loopback exactly as `chain-node devnet init`
generates it — nothing in this alpha changes that. What makes it reachable
publicly is a separate TLS-terminating, rate-limited gateway in front of it,
not a change to the node. `deploy/rpc-gateway.nginx.conf` is a template for
that gateway: nginx for TLS (via certbot) and request/connection rate
limiting, reverse-proxying `POST /` to the node's loopback RPC and refusing
everything else. Its rate limit is a starting point, not a load-tested
ceiling; the ship gate below calls for load-testing it before it is trusted
with real traffic. Point `thrylos` at it with `https://` — see above.

## Faucet

The faucet has its own account key, durable request queue and UTC daily limits
for each Discord user, each Thrylos address and the whole service. Its request
IDs are idempotent, and it durably stores a signed transaction before sending
it. After a crash it retries the same transaction bytes and sequence number.

Create one for local testing:

```text
chain-faucet init /tmp/thrylos-faucet
chain-node devnet fund /tmp/thrylos-devnet <address-printed-by-init> --amount 1,000
```

Edit `/tmp/thrylos-faucet/faucet.json` to choose the payout and caps. The
defaults are 10 THRY, one claim per user and address per UTC day, 100 claims
globally per day and at most 1,000 waiting requests.

The same policy can be exercised without Discord:

```text
chain-faucet request /tmp/thrylos-faucet test-user <recipient-thry1-address>
chain-faucet work /tmp/thrylos-faucet
```

For Discord, copy the application's public key—not its bot token—into
`discord_public_key`, print the `/faucet` and `/faucet-status` definitions with
`chain-faucet discord-commands`, register them with Discord's application API,
then run:

```text
chain-faucet run /tmp/thrylos-faucet
```

The service listens on `127.0.0.1:8081`. Put a TLS reverse proxy in front and
configure its HTTPS URL as the Discord Interactions Endpoint URL. Direct public
listening is refused. Every request verifies Discord's Ed25519 signature over
the timestamp and exact body before it is parsed. Discord documents the
[endpoint verification](https://docs.discord.com/developers/interactions/overview#configuring-an-interactions-endpoint-url)
and [interaction response](https://docs.discord.com/developers/interactions/receiving-and-responding)
contracts. Run exactly one faucet process for a directory; do not use the
offline `request` or `work` commands against it while `run` owns it.

## Alpha genesis

`chain-node devnet init` is deliberately insecure: its validator and funded
accounts are derived from small public seeds, so anyone can compute every
secret. A real testnet needs a genesis nothing but its own operators could
have produced, and needs to fund exactly the accounts it means to, not a
fixed set of generic ones. `chain-node testnet init` does that:

```text
thrylos setup --wallet node1-operator.key
thrylos setup --wallet node2-operator.key
chain-faucet init /tmp/thrylos-faucet

chain-node testnet init /tmp/thrylos-alpha \
  --chain-id 90210 \
  --operator "$(thrylos address --hex --wallet node1-operator.key)" \
  --operator "$(thrylos address --hex --wallet node2-operator.key)" \
  --allocate "$(thrylos address --hex --wallet /tmp/thrylos-faucet/faucet.key):5,000,000,000"

chain-node devnet start /tmp/thrylos-alpha
```

Each `--operator` is a validator's own account, made and held exactly like
any other with `thrylos setup`; this command never generates or sees an
operator's secret key, only reads the public key `thrylos address --hex`
prints (an address cannot be turned back into one, so the address alone is
not enough). What it does generate, freshly and randomly, is each
validator's consensus key — never a devnet-style seed. `--allocate` is
repeatable and is the entire funded set: the faucet's own address and
whatever other system accounts are explicitly documented for this network,
nothing implicit. `--chain-id` must be unique to the network; never reuse
devnet's `1337` or another testnet's. Despite `devnet start`'s name, it runs
any generated network, `devnet init`'s or `testnet init`'s, the same way.

## Release binaries

`scripts/release.sh` builds `chain-node`, `chain-genesis`, `chain-faucet`,
`chain-explorer`, `chain-signer` and `thrylos` in release mode and writes
`target/release-artifacts/SHA256SUMS` next to them. It uses the toolchain
pinned in `rust-toolchain.toml` and the checked-in `Cargo.lock` (never
updating it), strips debug info and remaps build paths, so running it twice
on the same commit on the same host produces byte-identical binaries; publish
the checksums with the release so anyone can confirm what they downloaded.

## Ship gate

Ship this slice after all of the following are true:

- Native THRY transfers pass execution, supply-accounting and RPC tests.
- The CLI refuses insecure wallet permissions and confirms a send by default.
- A transaction can be followed from `Sent` to an included success or abort.
- The `deploy/rpc-gateway.nginx.conf` TLS gateway is load-tested while
  validator RPC stays private, and its rate limit is set to what the operator
  is prepared to serve.
- The separately keyed faucet is exercised against the release genesis and its
  caps are set to values the operator is prepared to fund.
- The release genesis was made with `chain-node testnet init`, never `devnet
  init`, has a chain ID unique to this network, and funds only the faucet and
  explicitly documented system accounts.
- The read-only explorer points at the same indexed chain and performs no
  signing.
- `scripts/release.sh` has produced the binaries being shipped, and their
  `SHA256SUMS` are published with them.

Module publishing comes only after this coin loop is stable and after its
bytecode-verification, compatibility and metering rules are specified and
tested.
