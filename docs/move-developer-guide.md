# Writing and publishing Move on the Thrylos testnet

A guide for someone who wants to put a Move package on the alpha testnet. It is
accurate for the code as of 2026-09-25 and says plainly what does not work yet.

**The most important limit first: packages cannot store anything yet.** A package
can be published, and its `entry` functions can be called and can compute, assert
and abort, but nothing they do is kept between calls. There are no objects, no
tables and no events. That is the next stage of work (a storage layer, designed
separately), and until it exists this is a place to learn Move on a real chain and
to try the publishing rules, not to build an application. The testnet is also reset
whenever a change needs it, and its coin has no value.

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

A call is charged for the gas it uses, up to `--gas` (default 200,000). A Move abort
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

## What it costs

| | |
|---|---|
| Gas for publishing | 20,000, plus 10 for each byte |
| Storage deposit | 0.01 THRY for each started KiB, plus 0.01 THRY. It is kept by the network, not refunded (nothing can be deleted). |
| Fee | gas used times the base fee (currently 1 base unit) |

A 2 KiB package therefore costs about 0.03 THRY plus a small fee.

## Limits

| | |
|---|---|
| Modules in a package | 32 |
| One module | 64 KiB |
| A whole package | 128 KiB |
| Other packages a package needs | 16 |
| Verifier | fixed limits on loops, nesting, size of definitions and total work; `move build` runs the same checks, so a package that builds passes them |

Every module is checked in a fixed order before the VM sees it: sizes, format, that it
is written at `0x0`, names unique, imports only from `0x1`, `0x2`, published packages or
itself, then the bytecode verifier under a work meter, then the VM's own validation.
`thrylos move publish` runs all of that but the last two things that need the network
first, and tells you why if it would be refused.

## Things that are refused, and why

- Any address other than `pkg` for your own modules: the network chooses it.
- A dependency on something not published (or on a system package other than `0x1`, `0x2`).
- Publishing at all, if governance has switched publishing off (a kill switch for an
  emergency).
- Modules compiled with `#[test]` support.

## Not yet

Storage (objects, tables), events, generic entry functions, struct or object arguments,
return values, package upgrades, and any promise that the testnet keeps its state: it is
reset when a change needs it, and the `.thry` names, balances and packages go with it.
