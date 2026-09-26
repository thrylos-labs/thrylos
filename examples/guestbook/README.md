# A guestbook

Anyone can open a guestbook at their own address, and anyone can sign anyone's. One module,
`sources/guestbook.move`, about a hundred and fifty lines with its tests.

Where the [token](../token/README.md) is one value per owner, this is **many small values in one
place**: the book is a counter at (owner, slot 0) and each entry is its own drawer at (owner, slot =
its number), so a book can grow without any one value getting big. A visitor writes into the *book
owner's* drawers, which is why the call declares the owner's address (the `thrylos` command does it
for you, because the owner is an `address:` argument).

| Function | What it does |
|---|---|
| `open(title)` | open the caller's guestbook |
| `sign(book, message)` | add an entry to the book at address `book` (1 to 280 bytes of UTF-8) |
| `remove(number)` | the book's owner removes an entry (numbers are not reused) |
| `written(book)` | a view: how many entries have been written |
| `title(book)` | a view: the book's title |
| `message(book, number)` | a view: an entry's text |
| `author(book, number)` | a view: who wrote it |

Signing costs the visitor a deposit for the new drawer (about 0.02 THRY, burned), which is what
keeps a book from being flooded for free.

## Try it on your own machine

```
examples/guestbook/try-it.sh
```

A one-validator local network and three wallets: a book is opened, signed by two visitors, read
back, and an entry removed, and the things that must fail (an empty message, a book nobody opened,
someone else removing an entry, a second book at one address) are checked to fail.

## On the testnet

It is published on the public testnet (chain `20260927`) at
`thry10vh7vwhlzzvy027f9llrl34c9cgv6he8nuycwuypupaed4y6clvs9gwjke`. There is a book at
`thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk` with one entry in it; **sign it**:

```
thrylos move call thry10vh7vwhlzzvy027f9llrl34c9cgv6he8nuycwuypupaed4y6clvs9gwjke guestbook sign \
  address:thry1z32r7w9myt0t7l3t8zyucrgsjxplysn6c6rc4knx9yr0whqjmj4s5qpffk string:"Hello!" --rpc https://rpc.thrylos.org
```

To publish your own copy:

```
thrylos move publish examples/guestbook --rpc https://rpc.thrylos.org
thrylos move call <package> guestbook open string:"My guestbook" --rpc https://rpc.thrylos.org
thrylos move call <package> guestbook sign address:<owner> string:"Hello!" --rpc https://rpc.thrylos.org
thrylos move resources <owner> --rpc https://rpc.thrylos.org        # the book and every entry
thrylos move resource <owner> <package>::guestbook::Entry --slot 0 --rpc https://rpc.thrylos.org
```

`move resource` shows an entry's author and message decoded; the views (`written`, `message`, ...)
need a node with `simulate` on, which the public nodes do not have yet.

## What it shows about Move on Thrylos

- Entry functions cannot take a `String`, so `open` and `sign` take `vector<u8>` and make the
  `String` inside (which checks it is UTF-8). Views cannot return one either, so they return bytes.
- A module may store only types it defines: `Book` and `Entry` are this module's, so nobody else's
  package can write to a book, only this one (whose code decides who may sign and who may remove).
