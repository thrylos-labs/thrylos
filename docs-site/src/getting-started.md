# Getting started

You need the `thrylos` command, built from the [repository](https://github.com/thrylos-labs/thrylos-rust):

```
cargo build --release --bin thrylos
```

Then make a wallet and get some test THRY:

```
thrylos setup                                  # makes ~/.thrylos/wallet.key
```

Ask `/faucet` in the Discord with the address it prints. Publishing and calling a package cost a fraction of a THRY — see [What it costs](./move-guide.md#what-it-costs).

Point the command at the public testnet once:

```
thrylos network add testnet https://rpc.thrylos.org
thrylos network use testnet
```

Then:

```
thrylos move new hello        # a package with one module and two tests
thrylos move test hello       # run its tests
thrylos move publish hello    # publish it (builds first if needed); prints the package address
thrylos move call <address> hello check u64:4 u64:6
```

That's the whole loop. [Writing Move on Thrylos](./move-guide.md) covers packages, storage, gas and what's refused and why. Two working examples — a token and a guestbook — are in [Examples](./examples.md).

## Try it on your own machine first

A local, one-validator network is the quickest way to try everything, with no faucet needed:

```
cargo build --bin chain-node --bin chain-signer --bin thrylos
chain-node devnet init /tmp/net --validators 1
chain-node devnet start /tmp/net           # leave it running
thrylos setup --wallet /tmp/me.key
chain-node devnet fund /tmp/net "$(thrylos address --wallet /tmp/me.key)" --node 1 --account 1 --amount 50
thrylos network add local 127.0.0.1:26657 && thrylos network use local
```

Then use `thrylos move ... --wallet /tmp/me.key` as above. A generated local network is deliberately insecure (its keys are public), and — unlike the public testnet right now — it turns on `simulate`, so `thrylos move view` works there. See [Reading what is stored](./move-guide.md#reading-what-is-stored).
