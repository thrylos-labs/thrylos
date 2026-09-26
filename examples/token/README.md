# A token

A fungible token in one Move module (`sources/token.move`, about a hundred lines and seven
tests). It is the smallest real use of Thrylos storage: balances live in drawers, and only this
module can make, change or destroy one, so nobody else's package can forge them.

One package holds many tokens: a token is a number (its `id`), and a balance is a drawer at
(owner, id).

| Function | What it does |
|---|---|
| `create(id, total)` | make token `id`, all of it held by the caller |
| `transfer(id, to, amount)` | send from the caller to `to` (the command declares `to` for you) |
| `register(id)` | make an empty balance for yourself (pay for your own drawer) |
| `burn(id, amount)` | the creator destroys some of their own units |
| `balance_of(owner, id)` | a view: what `owner` holds |
| `total_supply(creator, id)` | a view: the supply, given the creator's address |

## Try it on your own machine

```
examples/token/try-it.sh
```

It starts a one-validator local network, makes two wallets, tests and publishes the package,
creates a token, sends some, reads the balances back, and checks that an overdraft and a burn
by someone else are refused.

## On the testnet

It is published on the public testnet (chain `20260927`) at
`thry1f5a2kfvgd5ua68vq7eqsgrmqqqt5uup8ujwg2jsxha40z9pzmdeqhk0hgh`, with token 1 created (1,000,000 units, 250 of them sent to another address).
Read it yourself:

```
thrylos move resource thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk \
  thry1f5a2kfvgd5ua68vq7eqsgrmqqqt5uup8ujwg2jsxha40z9pzmdeqhk0hgh::token::Supply --slot 1 --rpc https://rpc.thrylos.org
```

To publish your own copy:

```
thrylos move test examples/token
thrylos move publish examples/token --rpc https://rpc.thrylos.org      # builds it first
thrylos move call <package> token create u64:1 u64:1000 --rpc https://rpc.thrylos.org
thrylos move call <package> token transfer u64:1 address:<friend> u64:250 --rpc https://rpc.thrylos.org
thrylos move resource <friend> <package>::token::Balance --slot 1 --rpc https://rpc.thrylos.org
```

Costs: publishing is about 0.02 THRY (a deposit for the package, 907 bytes, which is kept). Making a token
makes two drawers (0.04 THRY); the first `transfer` to a new address makes theirs (0.02 THRY, paid
by the sender). Deposits are burned, not refunded. `balance_of` and `total_supply` are views and
need a node with `simulate` on, which the public nodes do not have yet; `move resource` reads the
same balances anywhere.
