# About Thrylos

Thrylos is a single-client, Move-based proof-of-stake L1, optimised for auditability over feature count. The design reuses existing, reviewed components rather than inventing new ones:

- **Consensus:** BFT proof-of-stake with single-slot finality — a committed block is final, so there's no reorg depth to reason about.
- **Execution:** the pinned MoveVM (from Sui's `move-vm-runtime`), unmodified. Adopting an existing, audited VM instead of writing a new one removes a whole class of unaudited risk.
- **State:** a flat key-value store under a Merkle trie, kept up to date incrementally rather than rebuilt each block.

## Where it is today

The alpha runs as a single host with four validators. Move packages can be published, called, and — since the most recent reset — can keep state: balances, counters, anything a package's own code defines. Gas is priced from measurement (about a microsecond of validator time per unit), not guessed.

It's still early. Public reads of computed (not stored) values, a firewall, and an outside security review of the VM path are all still open. None of that is hidden — the project's own operational notes are public in the [GitHub repo](https://github.com/thrylos-labs/thrylos-rust/tree/main/docs).

The full technical spec — requirements, trust tiers, consensus and state details — is [`docs/spec.md`](https://github.com/thrylos-labs/thrylos-rust/blob/main/docs/spec.md) in the repo.

## No token, no sale

Thrylos has no token sale and no distribution. The testnet coin exists only to pay for transactions on the alpha network and is worth nothing outside it.
