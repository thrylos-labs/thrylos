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
```

`setup` creates one Ed25519 account key at `~/.thrylos/wallet.key`, makes the
file readable only by its owner and refuses to replace it. `THRYLOS_WALLET` or
`--wallet` selects another file. No command prints the private key.

For local development the CLI connects to `127.0.0.1:26660`. `THRYLOS_RPC` or
`--rpc` selects another `host:port`. The present RPC transport is plain HTTP,
so a public alpha must put authentication, rate limiting and TLS in a gateway
before exposing it; validators continue binding RPC to loopback only.

## Ship gate

Ship this slice after all of the following are true:

- Native THRY transfers pass execution, supply-accounting and RPC tests.
- The CLI refuses insecure wallet permissions and confirms a send by default.
- A transaction can be followed from `Sent` to an included success or abort.
- A public TLS RPC gateway is load-tested while validator RPC stays private.
- A separately keyed faucet can fund an address with per-user, per-address and
  global daily caps; its key is never a validator or treasury key.
- The read-only explorer points at the same indexed chain and performs no
  signing.

The Discord faucet is the next slice because a newly created account otherwise
cannot do anything. Module publishing comes only after this coin loop is stable
and after its bytecode-verification, compatibility and metering rules are
specified and tested.
