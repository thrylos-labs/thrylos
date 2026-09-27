# Examples

Two working Move packages, both in [`examples/`](https://github.com/thrylos-labs/thrylos-rust/tree/main/examples) in the repo, and both live on the public testnet right now. Each has a `try-it.sh` that runs the whole thing on a local network in a few seconds, with no faucet needed.

## A token

A fungible token in one module, about a hundred lines with seven tests — the smallest real use of storage. Balances live in drawers, and only this module can make, change or destroy one, so nobody else's package can forge them. One package holds many tokens: a token is a number (its `id`), and a balance is a drawer at `(owner, id)`.

| Function | What it does |
|---|---|
| `create(id, total)` | make token `id`, all of it held by the caller |
| `transfer(id, to, amount)` | send from the caller to `to` |
| `register(id)` | make an empty balance for yourself |
| `burn(id, amount)` | the creator destroys some of their own units |
| `balance_of(owner, id)` | a view: what `owner` holds |
| `total_supply(creator, id)` | a view: the supply |

**Published at** `thry1f5a2kfvgd5ua68vq7eqsgrmqqqt5uup8ujwg2jsxha40z9pzmdeqhk0hgh`, with token `1` created (1,000,000 units). Read it:

```
thrylos move resource thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk \
  thry1f5a2kfvgd5ua68vq7eqsgrmqqqt5uup8ujwg2jsxha40z9pzmdeqhk0hgh::token::Supply \
  --slot 1 --rpc https://rpc.thrylos.org
```

Full source and README: [`examples/token`](https://github.com/thrylos-labs/thrylos-rust/tree/main/examples/token).

## A guestbook

Where the token is one value per owner, this is many small values in one place: the book is a counter at `(owner, slot 0)` and each entry is its own drawer at `(owner, slot = its number)`, so a book can grow without any one value getting big. Anyone can open a book at their own address, and anyone can sign anyone's — signing costs the visitor a small deposit, which is what keeps a book from being flooded for free.

| Function | What it does |
|---|---|
| `open(title)` | open the caller's guestbook |
| `sign(book, message)` | add an entry (1 to 280 bytes of UTF-8) |
| `remove(number)` | the owner removes an entry (numbers are not reused) |
| `written(book)` / `title(book)` / `message(book, n)` / `author(book, n)` | views |

**Published at** `thry10vh7vwhlzzvy027f9llrl34c9cgv6he8nuycwuypupaed4y6clvs9gwjke`. There's a book at `thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk` — **sign it:**

```
thrylos move call thry10vh7vwhlzzvy027f9llrl34c9cgv6he8nuycwuypupaed4y6clvs9gwjke guestbook sign \
  address:thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk string:"Hello!" \
  --rpc https://rpc.thrylos.org
```

Full source and README: [`examples/guestbook`](https://github.com/thrylos-labs/thrylos-rust/tree/main/examples/guestbook).

Both examples show the same rule at work: **a module may store only types it defines**, which is what keeps one package's data safe from another's code. See [Writing Move on Thrylos](./move-guide.md#only-the-module-that-defines-a-type-may-store-it).
