# Developer Q&A

**How do I get testnet coins?**
Ask `/faucet` in the Discord with your wallet address. It pays out a fixed, small amount, limited per day.

**How do I write a Move package?**
`thrylos move new myapp` scaffolds one with a test. Then `thrylos move test`, `thrylos move publish` (builds first if needed), and `thrylos move call`. See [Getting started](./getting-started.md) and [Writing Move on Thrylos](./move-guide.md).

**Can my package remember anything?**
Yes. Values live in "drawers" keyed by an owner address and a slot number. Only the module that defines a type can store or take it — that's what keeps one package from forging another's data. Two working examples are in [Examples](./examples.md).

**What are the gas limits?**
A node currently accepts at most 20,000 gas for a call to a package (a temporary, node-local limit — the chain itself allows up to 75,000). An ordinary call uses tens to a few thousand. Gas is priced at about a microsecond of validator time per unit.

**Can I read a value without paying for a transaction?**
`thrylos move resource` reads stored values for free, on any node. `thrylos move view` (calling a plain function without sending a transaction) needs a node with `simulate` turned on, which local networks have and the public testnet does not yet.

**Will the testnet reset again?**
Yes, whenever a change needs it. Nothing on it should be treated as permanent — every balance, `.thry` name and published package is wiped each time.

**Is there a token sale?**
No. See [About Thrylos](./about.md#no-token-no-sale).

**Where's the code?**
[github.com/thrylos-labs/thrylos-rust](https://github.com/thrylos-labs/thrylos-rust). The full technical spec is [`docs/spec.md`](https://github.com/thrylos-labs/thrylos-rust/blob/main/docs/spec.md) in the repo.

**Something's broken or confusing — where do I say so?**
The Discord. Rough edges found this way get fixed; several already have.
