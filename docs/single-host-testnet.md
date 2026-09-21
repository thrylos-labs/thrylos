# Single-host testnet runbook

This is the deliberately small test environment used before separate machines
are available. Four validator and signer processes run with separate keys,
logs, ports and databases on one host. It exercises consensus, persistence and
process recovery, but it does not simulate host loss or real network latency.

The development keys are public and must never hold value.

## Start with fresh V2 state

Trie commitment V2 is incompatible with databases created by the earlier
commitment. This project is pre-genesis, so do not build or perform a database
migration: initialise a new directory.

```bash
cargo build --locked -p chain-node --bins
target/debug/chain-node devnet init /tmp/thrylos-testnet
target/debug/chain-node devnet start /tmp/thrylos-testnet
```

Leave the last command running. In another terminal, check the network and
submit a transaction:

```bash
target/debug/chain-node devnet check /tmp/thrylos-testnet
target/debug/chain-node devnet bump /tmp/thrylos-testnet
```

To browse the running network locally:

```bash
target/debug/chain-explorer /tmp/thrylos-testnet
```

Open `http://127.0.0.1:8080`. The explorer is read-only and listens on
loopback. Use `--port <port>` if 8080 is already in use.

For a soak, leave the network running and repeat `devnet check` periodically.
Any `UNHEALTHY` result or process exit is a failure to investigate, not a
condition to ignore. Stop the network with Ctrl-C and start the same directory
again to exercise ordinary recovery.

## Automated crash and restart exercise

The existing process test repeatedly kills validators and signers at random
moments, restarts them from their persisted state and requires the four nodes
to converge on one chain:

```bash
cargo test -p chain-node --test devnet_processes \
  every_process_killed_at_a_random_moment_over_and_over_starts_again_and_the_chain_stays_one \
  -- --nocapture
```

Run this before each testnet release. It complements the manual soak; it does
not replace later multi-host testing.

## Explorer boundary

Keep every validator RPC bound to loopback, as generated. Run the explorer's
backend on the same host and let only that backend call a node RPC such as
`http://127.0.0.1:26660`. Do not expose validator RPC ports directly to the
internet. The explorer stays outside consensus and can be replaced without a
chain upgrade.
