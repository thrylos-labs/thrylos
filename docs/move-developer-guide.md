# Writing and publishing Move on the Thrylos testnet

A guide for someone who wants to put a Move package on the alpha testnet. It is
accurate for the code as of 2026-09-25 and says plainly what does not work yet.

**Where things stand.** Packages can be published, called, tested, and now can **keep
state**: they store values in *drawers* (see "Storing things") and you can read them back.
**That part is built and tested in the repository but is not on the public testnet yet:**
the public testnet is on an earlier build where packages compute but remember nothing, and
the storage goes live with the next testnet reset (which will delete published packages, as
every reset does). To try storage today, run a local network (see "Try it on your own
machine"). The testnet's coin has no value and it is reset whenever a change needs it.

## Get started

You need the `thrylos` command (built from this repository: `cargo build --release
--bin thrylos`) and a wallet with some test THRY (`thrylos setup`, then the faucet
in Discord; publishing costs a fraction of a THRY, see "What it costs").

```
thrylos move new hello        # a package with one module and two tests
thrylos move test hello       # run its tests
thrylos move build hello      # compile it, and check what the network will check
thrylos move publish hello    # publish it; prints the package address
thrylos move call <address> hello check u64:4 u64:6
```

Point the commands at the network with `--rpc https://rpc.thrylos.org`, or once with
`thrylos network add testnet https://rpc.thrylos.org` and `thrylos network use testnet`.

### Try it on your own machine

A local network is the quickest way to try everything here, storage included, with no faucet:

```
cargo build --bin chain-node --bin chain-signer --bin thrylos
chain-node devnet init /tmp/net --validators 1
chain-node devnet start /tmp/net           # leave it running
thrylos setup --wallet /tmp/me.key
chain-node devnet fund /tmp/net "$(thrylos address --wallet /tmp/me.key)" --node 1 --account 1 --amount 50
thrylos network add local 127.0.0.1:26657 && thrylos network use local
```

Then use `thrylos move ... --wallet /tmp/me.key` as below. (A generated network is
deliberately insecure: its keys are public. `devnet init` also turns on `simulate`, which
public nodes leave off; see "Reading what is stored".)

## A package

A package is a directory with Move files under `sources/`. `thrylos move new` writes
this one:

```move
module pkg::hello;

entry fun check(a: u64, b: u64) {
    assert!(add(a, b) == 10, 1);
}

public fun add(a: u64, b: u64): u64 { a + b }

#[test]
fun adds() { assert!(add(2, 3) == 5, 0); }

#[test]
#[expected_failure(abort_code = 1)]
fun check_aborts_on_the_wrong_sum() { check(1, 1); }
```

Three names are always defined:

| Name | Address | What |
|---|---|---|
| `pkg` | `0x0` | **This package.** You do not choose your package's address; the network gives it one when you publish, and rewrites `pkg` to it. Write `module pkg::name`. |
| `std` | `0x1` | The Move standard library, frozen |
| `thrylos` | `0x2` | The Thrylos framework |

**The standard library** is the upstream one, unmodified, except that `std::debug` and
`std::unit_test` are left out on the chain (they exist only while testing):
`address`, `ascii`, `bcs`, `bit_vector`, `bool`, `fixed_point32`, `hash`, `internal`,
`macros`, `option`, `string`, `type_name`, `u8` to `u256`, `uq32_32`, `uq64_64`, `vector`.

**The framework** has two modules:

- `thrylos::chain`: `block_time_ms()`, `height()`, `chain_id()`, what a function may
  know about the block it runs in.
- `thrylos::signer`: `address_of(&signer)`. An entry function whose first parameter is
  `signer` or `&signer` is given the transaction's sender there.

## Entry functions and calls

A transaction can call a function that is `entry`, has no type parameters and returns
nothing. Every other parameter must be a `bool`, `u8` to `u256`, an `address`, or a
vector of those (up to three deep). A struct, a reference or an object cannot be passed.
A function that does not fit is simply not callable, and the call aborts.

Arguments are written `type:value`:

```
bool:true   u8:7   u64:5   u256:123   address:thry1...
bytes:0x0a0b     string:hello       (both are a vector<u8>)
vec:u64:1,2,3    raw:0x...          (raw: bytes you have already encoded)
```

A call is charged for the gas it uses, up to `--gas` (default and maximum **20,000** while the
network's gas prices are being recalibrated: nodes refuse a call to a package that declares
more, see `docs/gas-calibration.md`; 20,000 is thousands of times what an ordinary call
uses). A Move abort
costs what had been used; running out of gas, or a call the network cannot make sense
of, costs the whole limit.

## Tests

`thrylos move test` compiles the package with its tests and runs each `#[test]`
function in the same Move runtime the network uses, with the same natives and limits
(`std::debug::print` works, and prints). `#[expected_failure]` and abort codes are
honoured. Tests with arguments are skipped. `--filter text` runs only tests whose name
contains it. Test code is never published: modules compiled for testing carry a mark
the network refuses.

## Depending on another package

A package may use another that is already published. Give its sources, a name to call
it, and the address it was published at:

```
thrylos move build app --dep helper=../helper@thry1...
```

```move
module pkg::app;
use helper::helper;      // "helper" is the name you gave; the module is helper::helper
```

The dependency's sources are written like any package's (with `pkg` for itself); the
tool compiles them with `pkg` meaning that address. A package may need at most 16
others in all, counting the standard library, the framework and everything they need in
turn. Packages cannot be changed once published, so what you import is what you always
get.

## Storing things

A package remembers by putting values in **drawers**. Every address has drawers. A drawer is
named by a **type** and a **slot number** (a `u64`), and holds one value of that type. The
framework module `thrylos::store` has four functions:

```move
use thrylos::store;

store::put<T: key>(owner: address, slot: u64, value: T);   // fill an empty drawer
store::take<T: key>(owner: address, slot: u64): T;         // empty it, giving the value
store::has<T: key>(owner: address, slot: u64): bool;
store::read<T: key + copy>(owner: address, slot: u64): T;  // a copy; leaves it there
```

`put` never replaces a value (one without `drop` could not be destroyed, which is what Move's
types are for), so changing a value is taking it out and putting it back:

```move
module pkg::counter;

use thrylos::store;
use thrylos::signer;

public struct Counter has key, store, copy, drop { n: u64 }

entry fun init(s: &signer) {
    store::put(signer::address_of(s), 0, Counter { n: 0 });
}

entry fun bump(s: &signer) {
    let owner = signer::address_of(s);
    let mut c = store::take<Counter>(owner, 0);
    c.n = c.n + 1;
    store::put(owner, 0, c);
}

// A view: a public function that returns a value (see "Reading what is stored").
public fun mine(s: &signer): u64 {
    store::read<Counter>(signer::address_of(s), 0).n
}

#[test]
fun counts() {
    store::put(@0xa, 0, Counter { n: 0 });
    let mut c = store::take<Counter>(@0xa, 0);
    c.n = c.n + 1;
    store::put(@0xa, 0, c);
    assert!(store::read<Counter>(@0xa, 0).n == 1, 0);
}
```

Try it (each line is a real result from a local network):

```
thrylos move test counter                         # [ PASS ] counter::counts
thrylos move publish counter                      # Package address: thry1...
thrylos move call <package> counter init
thrylos move call <package> counter bump          # twice
thrylos move view <package> counter mine          # Returns[0]: "2"
thrylos move resource <you> <package>::counter::Counter
#   Value: { "_type": "...::counter::Counter", "n": "2" }
#   Bytes: 0x0200000000000000
```

A stored type needs the `key` ability. Use a slot number to keep many values of one type for
one address (a game's pieces, a market's orders); a module that needs only one uses slot `0`.
A value is stored as its Move (BCS) encoding, so anything Move can hold can be stored,
including vectors, options, structs inside structs, generics and enums.

### Only the module that defines a type may store it

This is what makes storage safe. A module may put in and take out of drawers only **types it
defines itself**. If the token module defines `Token`, then only the token module's code can ever
hold a `Token` or keep one in a drawer, so nobody else's package can reach or forge its balances.
`thrylos move build` (and the network, when you publish) refuses a module that breaks this:

```
module thief calls thrylos::store::put with theirs::Token, which the module does not
define; only the module that defines a type may keep it in a drawer
```

The same goes for a function generic over the stored type
(`public fun put_any<T: key>(...) { store::put(...) }`): it would let anyone store any type
through your module, so it is refused. Your own generic type instantiated with a type
parameter (`store::put(o, 0, Wrapper<T> { v })`) is fine, since `Wrapper` is yours. Types from
`std`, from another module (even in the same package) and from other packages are not yours.

### Whose drawers a call may touch

A call may touch only drawers owned by its **sender**, and by addresses it **declares**. Say
which ones when you call:

```
thrylos move call <package> ledger bump_for address:thry1... --input thry1...
```

A call that touches any other owner aborts. This lets everything that watches the chain know
what a transaction touches before it runs. (Tests run by `thrylos move test` are the exception:
they may touch any address's drawers, since there is no transaction.)

### What storing does when it goes wrong

A store operation that fails aborts with a code from module `0x2::store`, so you can tell it
from your own codes:

| Code | Meaning |
|---|---|
| 1 | `take` or `read` of an empty drawer |
| 2 | `put` into a drawer that already holds a value |
| 3 | the drawer's owner is neither the sender nor declared |
| 4 | the value (over 16 KiB) or its type is too large to store |
| 5 | too many operations (over 64) or drawers changed (over 16) in one call |
| 6 | a stored value could not be read back (damaged state; not something a call can cause) |

An aborted call changes nothing it wrote, as with everything else.

## Reading what is stored

```
thrylos move resources <owner>                      # what an address has stored
thrylos move resource <owner> <package>::<module>::<Type> [--slot 1]
thrylos move view <package> <module> <function> [type:value ...] [--input <address>]...
```

`resource` prints a stored value decoded into its fields (numbers as text, addresses as
`thry1…`) and its raw bytes. The explorer shows the same on an account's page.

`view` asks a node what a call **would** do without sending it, so it costs nothing and
changes nothing. It can call any `public` function, not only `entry` ones, and prints what it
returns (numbers, addresses, booleans and vectors of them). For a call that would change
something it says how many stored values and what deposit. If the call would fail it says
why: `the call would fail: aborted with code 1 in 0x2::store`.

`view` uses the node's `simulate` method, which runs Move code on the node's own thread. A
node serves it only if its configuration turns it on (`"rpc": { ..., "simulate": true }`), it
is capped at 10,000 gas, and a node answers one a second. A local network has it on. The
public testnet's nodes have it off unless said otherwise on the Discord.

## What it costs

| | |
|---|---|
| Gas for publishing | 20,000, plus 10 for each byte |
| Storage deposit for a package | 0.01 THRY for each started KiB, plus 0.01 THRY. Kept by the network. Packages cannot be deleted. |
| Gas for a store operation | about 2 gas, plus 0.1 gas for each byte read and 0.5 for each byte written |
| Storage deposit for a drawer | when a call makes a drawer that did not exist: 0.01 THRY, plus 0.01 THRY for each started KiB it holds. When a call makes an existing drawer bigger: 0.01 THRY for each extra KiB. Nothing when it stays the same size or shrinks |
| Fee | gas used times the base fee (currently 1 base unit) |

The deposit is worked out at the end of the call, from the state before it to the state after,
so taking a value out and putting it back the same size costs nothing, and a call that fails
costs only its gas. **A deposit is burned and never refunded**, even if you later take the
value out: storage is paid for once. A small counter therefore costs 0.02 THRY the first time
and nothing more for each update (a few gas). A 2 KiB package costs about 0.03 THRY plus a
small fee. If you cannot pay the deposit the call aborts with `InsufficientBalance` and
writes nothing.

The gas figures are the VM's own schedule plus the store's; they are not yet calibrated to real
hardware, so treat them as a bound and not a price.

## Limits

| | |
|---|---|
| Modules in a package | 32 |
| One module | 64 KiB |
| A whole package | 128 KiB |
| Other packages a package needs | 16 |
| One stored value | 16 KiB |
| Store operations in one call | 64 |
| Drawers one call may change | 16 |
| A type's name, as stored | 256 bytes |
| The state, in all | 100,000 entries and 64 MiB, for everything on the chain |
| Verifier | fixed limits on loops, nesting, size of definitions and total work; `move build` runs the same checks, so a package that builds passes them |

Every module is checked in a fixed order before the VM sees it: sizes, format, that it
is written at `0x0`, names unique, imports only from `0x1`, `0x2`, published packages or
itself, then the bytecode verifier under a work meter, then the rule about stored types,
then the VM's own validation. `thrylos move publish` runs all of that but the last, which
needs the network, first, and tells you why if it would be refused.

## Things that are refused, and why

- Any address other than `pkg` for your own modules: the network chooses it.
- A dependency on something not published (or on a system package other than `0x1`, `0x2`).
- Keeping in a drawer a type your module does not define, including through a function
  generic over the type.
- Publishing at all, if governance has switched publishing off (a kill switch for an
  emergency).
- Modules compiled with `#[test]` support.
- A module that declares its own `native` functions.

## Not yet

- **Events.** Nothing stores or reports them yet; read state back with `resource` and `view`.
- **Refunds** for taking a value out of a drawer.
- **Objects with their own identities**, shared objects, dynamic fields and moving a stored
  value between owners as a first-class thing. A drawer is keyed by owner, slot and type.
- **Editing a stored value in place.** You take it out and put it back.
- Generic entry functions, struct or object arguments to a call, tests that take arguments,
  and package upgrades.
- Any promise that the testnet keeps its state: it is reset when a change needs it, and the
  `.thry` names, balances, packages and everything stored go with it. The next reset is the one
  that brings storage to the public testnet.
