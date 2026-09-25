# Move storage: letting a package remember things (stage 2)

Status: **design, defaults approved 2026-09-25, slot kept. The spike is done and passed (see "Spike results"); the store itself is not built.**
Follows `move-publishing-design.md` (stage 1, live, and stage 3, the tooling, built).
Written against the code at that date and the pinned MoveVM (`MystenLabs/sui` rev
`ceaaff1`).

## What this has to do

Today a published package can compute and abort, and nothing it does is kept
(`move-developer-guide.md`, "Not yet"). This stage gives Move code somewhere to put
state, so a developer can write a counter, a token, a registry, a game, and read it
back. It has to do that without changing the VM, without weakening what stage 1
guarantees (deterministic, bounded, every byte paid for), and small enough to design and
test properly.

## Why the VM does not give us this

The pinned VM has no global storage: `MoveTo`, `MoveFrom` and `BorrowGlobal` exist only
as `...Deprecated` opcodes. This is Sui's Move, where state is an object model built
outside the core VM. So state is ours to build, as native functions in the `0x2`
framework, on the executor's existing flat state.

What the VM does give us (**the APIs exist in the pinned source; that they compose as
below is what the first spike must prove**):

- `NativeContext::type_to_type_layout` and `type_to_type_tag` for a native's type
  argument, so a native can turn a `Value` into bytes and back with
  `Value::typed_serialize` / `Value::simple_deserialize` (BCS, deterministic).
- `NativeContext::type_to_abilities`, `charge_gas` and `gas_budget`.
- `NativeContextExtensions`, already used for `BlockInfo`: a native reaches whatever
  the executor put there, here a view of the state and a write overlay.

## The model, in one paragraph

Every address has drawers. A drawer is named by a **type** and a **slot number**, and
holds one value of that type. A module can `put` a value into a drawer, `take` it out
(which empties the drawer), check whether one is `has`, or `read` a copy of a value whose
type can be copied. Only the module that **defines** a type can use drawers of that
type; that is what makes a token module's balances safe from everyone else. A drawer is
one entry in the chain's flat state, so the storage deposit, the state cap and the state
root all apply with no new machinery.

```move
public struct Counter has key, store { n: u64 }

entry fun bump(who: &signer) {
    let owner = signer::address_of(who);
    let mut c = store::take<Counter>(owner, 0);
    c.n = c.n + 1;
    store::put(owner, 0, c);
}
```

## Decisions

Each is stated with what was chosen. **The first four are the defaults you approved.**

### D1. Drawer store, not Sui's object model. (Approved)

The alternative, objects with their own IDs, shared objects, transfer and dynamic
fields, is the right long-term shape and a very large project that brings in Sui's
transaction model. Nothing here blocks it later: a drawer is just state.

### D2. Declared inputs are enforced. (Approved)

`docs/spec.md`, "Execution", says a transaction declares what it touches and touching
anything else aborts; the demo counter already does this. So every store native checks
that the drawer's **owner address** is the transaction's sender or is listed in
`declared_inputs`, else it aborts. The cost is that a developer says up front which
addresses a call will use (`thrylos move call ... --input <address>`); the benefit is
that the rule exists from the first day, and every later thing that wants to know what a
transaction touches (parallel execution, fee estimation, explorers) can rely on it.
Retrofitting it would break every package.

*To settle when building:* the existing limit on the length of `declared_inputs` (the
codec has a general collection cap; a small specific cap such as 16 is proposed).

### D3. Deposits are burned, never refunded. (Approved)

A drawer that is new, or has grown, pays the same rate as a published package: 0.01
THRY for each started KiB of growth, plus a flat 0.01 THRY when the entry did not exist.
The amount is computed **at the end of the call, from the state before it to the state
after**, so `take` then `put` of a same-size value costs nothing, and a call that writes
and then aborts costs nothing beyond its gas. Taking a value out frees the entry but
refunds nothing: storage is paid for once. It cannot be gamed and needs no escrow
accounting; if it proves too harsh a refund can be designed later without changing the
API.

If the sender cannot afford the deposit the call aborts (`InsufficientBalance`) and
nothing is written.

### D4. Reading state is by RPC and by simulation; events wait. (Approved)

- **`move_resource(owner, type, slot)`**: the drawer's raw bytes and its type tag, with
  a JSON rendering when the type's layout can be found. Cheap, and enough to look at
  state.
- **`simulate(transaction)`**: runs a call against the latest state **without
  committing**, and returns the outcome, the gas it used and its return values. In this
  mode only, a `public` function that is not `entry` can be called and can return
  primitives and vectors of them, which gives packages "view" functions. On the chain
  itself the stage 1 rule is unchanged: an entry function returns nothing.
- **Events** need somewhere to be stored and reported (receipts, RPC, explorer); nothing
  does that yet. Left out, and listed under "Not in this stage".

### D5. One value per (owner, type, slot). (Mine, for your review)

The approved sketch was "one drawer per type". That would make anything with many items,
a game's pieces, a market's orders, need a synthetic owner address for each. A `u64`
**slot** in the drawer's name removes that at almost no cost, and it is much cheaper to
have now than to add: the `0x2` framework is frozen by genesis, so changing its API means
another reset. A module that wants exactly one value uses slot `0`. If you would rather
keep it to one per type, drop the slot everywhere below; nothing else changes.

### D6. The framework API

A new `0x2` module, `thrylos::store`, four native functions:

```move
module thrylos::store;

public native fun put<T: key>(owner: address, slot: u64, value: T);
public native fun take<T: key>(owner: address, slot: u64): T;
public native fun has<T: key>(owner: address, slot: u64): bool;
public native fun read<T: key + copy>(owner: address, slot: u64): T;
```

- `put` aborts if the drawer is occupied. It never overwrites: a value without `drop`
  cannot be silently destroyed, which is the whole point of Move's types.
- `take` and `read` abort if the drawer is empty. `read` leaves the value in place.
- Abort codes: 1 empty, 2 occupied, 3 owner not declared, 4 value too large, 5 too many
  operations, 6 corrupt (a stored value could not be read back: damaged state). They are raised from the module `0x2::store`, so a developer can tell them
  from their own.
- `T` must have `key`, the ability that means "may be stored at the top level". The spike
  confirmed the pinned compiler accepts `key` on a struct or an enum with no `UID` field.

### D7. Only the defining module may use its type's drawers.

The rule that makes storage safe, and the one piece of new verification. When a package
is published (`chain_exec::publish::prepare`, so `thrylos move build` runs it too), for
every call in its modules to a `thrylos::store` function:

- the type argument must be a struct or enum **defined in the calling module**, possibly
  instantiated with anything; and
- it must **not** be a bare type parameter of the enclosing function.

The second half closes the obvious loophole: `public fun put_any<T: key>(a, v: T) {
store::put(a, 0, v) }` would let anyone store any type through your module. Refusing a
type parameter refuses that. Because Move lets only the defining module create or take
apart a struct, the module that defines `Token` is the only code that can ever hold or
build one, and now the only code that can put it in or take it out of a drawer.

It is a small pass over the module's function-instantiation table, decided from the
bytecode alone, so it is deterministic and cheap. It needs its own tests, one for every
way of trying to get round it, and a place in the publish fuzz target.

### D8. What a drawer holds, and its key

- **State key:** a new `KeyTag::MoveDrawer`, then the owner (32 bytes), the slot (8 bytes,
  big-endian) and a 32-byte hash of the type tag. Fixed size, so no key can be built to
  collide with another kind of entry.
- **State value:** the type tag's text (at most 256 bytes) then the BCS bytes of the value.
  Keeping the tag in the value lets `move_resource` show what a drawer is, and means a
  hash collision could never make one type read another's bytes (the tag is compared).
- **Limits (proposed, to tune):** a value at most 16 KiB; at most 64 store operations and 16
  drawers written in one call; the chain's state cap (100,000 entries, 64 MiB) applies as
  it does to accounts.

### D9. How a call runs

Nothing about atomicity changes: a call's writes are returned as `CallEffects` and applied
only on success. The store adds one thing to the call's setup.

1. The executor puts a `StoreView` into the VM's native extensions: a read-only view of
   the state, the sender, the `declared_inputs`, and a write overlay (a `BTreeMap` from
   key to the new value or a deletion, so ordering is fixed).
2. Each native reads through the overlay first, then the state, and writes only to the
   overlay. Later operations in the same call see earlier ones.
3. When the function returns, the overlay becomes the call's state changes. The deposit
   (D3) is worked out by comparing it with the state as the call found it, debited from
   the sender and burned from the supply, in the same effects.

Nothing is written outside `CallEffects`, so an abort, an out-of-gas or an unaffordable
deposit leaves no trace, as today.

### D10. Gas

Each native charges before it works: a base amount, a per-byte amount for the bytes it
serialises or reads, and a higher per-byte amount for a write. Charged inside the VM's own
meter, so it shares the transaction's limit. Like the rest of the schedule these are a
safety bound until measured on reference hardware, and are on the list to calibrate before
the reset (below).

## The reset this needs

`thrylos::store` is a new module in the `0x2` framework, and `0x2` is part of genesis.
There is no mechanism to add system code to a running chain, so **this is a third testnet
reset, and it wipes published packages**, not only balances and names. That is the price of
freezing the framework, and it is the reason to spend it once:

- **Batched into this reset (all change the genesis or the rules from block 1):** the store,
  calibrated native and instruction gas, the `declared_inputs` cap, and anything found in
  review of the framework's API (D5 and D6 are the last cheap moment to change it).
- **Not needing a reset:** `simulate`, `move_resource`, the CLI, the guide, the explorer.
  These can ship before or after, and should ship before, so developers can use them.
- **Until then:** no new consensus features. Anything that needs a new genesis waits for this
  one, so nobody publishes packages that are about to be wiped for a smaller reason.
- The reset itself is `scripts/reset-testnet.sh`, rehearsed the same way, with the same
  losses spelled out first.

## Risks

- **A wrong rule in D7 is a theft bug.** If a type could be stored by a module that does
  not define it, one package could read or forge another's balances. It is small and
  checkable, so it gets the most tests: every bypass attempted, a fuzz target that mutates
  modules that call `store`, and a review of the pass against Sui's equivalent before the
  reset.
- **Serialisation inside a native** is where determinism could leak: the value's layout must
  come from the type only, the size must be bounded before serialising, and nothing may
  depend on hash-map order. Bounded by D8's limits and the VM's own depth limits, and
  covered by a four-node test where every node must end on one state root.
- **State growth.** Drawers are the first thing a user can create in bulk. The deposit
  (about 1,000 THRY to fill the state cap) and the cap are the defence, as for accounts; the
  proposer already stops short of the cap, and a test must show a store-heavy block does the
  same.
- **The declared-inputs rule is friction** for developers, and will feel like it. The guide
  has to explain it plainly, and the CLI has to make `--input` easy.

## Stages and acceptance

**Stage 2a: the store, unreleased.** `KeyTag::MoveDrawer`; the `StoreView` extension and
the four natives; the D7 verification pass; deposits; gas; the `thrylos::store` source and
its checked-in bytecode; tests below. Not deployed.

**Stage 2b: reading.** `move_resource` and `simulate` in the RPC, `thrylos move view` and
`resource` in the CLI, the explorer showing a drawer. Can be deployed to the current chain
(they only read).

**Stage 2c: the reset.** Calibrate gas, rehearse, back up, reset, verify, update the guide
and the ops docs.

Acceptance:

- A counter package: `put`, then `take`/`put` incremented, across blocks and across a node
  restart, on four nodes with one state root.
- `take` on an empty drawer, `put` on an occupied one, an owner not declared, a value over
  16 KiB, and too many operations each abort with the right code and change nothing.
- A call that writes and then aborts leaves state and supply as if it never ran, except the
  gas.
- Deposit: a new drawer, a grown one, an unchanged one and a shrunk one each cost what D3
  says; an unaffordable one aborts with nothing written; the supply audit passes after
  every block.
- D7: a package that uses another module's type, a bare type parameter, a type from `std`,
  or a type from another package is refused at publish; the defining module's own use is
  accepted; every attempt is also a test in the fuzz target's corpus.
- A block with more new drawers than the state cap allows is trimmed by the proposer and
  refused by `apply_block`.
- `move_resource` returns what was stored; `simulate` runs a view function and commits
  nothing (the state root is unchanged afterwards).

## Order of work

1. **The spike (done, passed):** a native that serialises and deserialises a `Value` from
   its type argument, reading and writing through an extension, and the `key` ability
   question.
2. **Keys, the state value format, the overlay, and the deposit calculation, with tests that
   need no VM (done):** `crates/exec/src/drawer.rs` and `keys::drawer_key`. The key is
   `KeyTag::Drawer` (`KEY_TAG + 11`), the owner, the slot big-endian and a domain-separated
   hash of the type name (`DomainTag::MoveDrawerTypeV1`), always 73 bytes. `DrawerOverlay`
   is the one place the rules live: owner access, the 64-operation and 16-drawer limits, the
   16 KiB value limit, never overwriting, reads that see the call's own writes, changes that
   leave out writes ending where they began, and the deposit from the state before to the
   state after. Checked against a plain model over 2,000 random calls, and by breaking each
   rule in turn.
3. **The four natives and their gas; the `thrylos::store` source; the regenerated framework
   bundle (done):** `crates/exec/src/store.rs`, `move/framework/sources/store.move`,
   `move/bytecode/thrylos.bundle`. Two changes from the design as written: a stored value that
   cannot be read back aborts with a sixth code, **6, corrupt**, instead of failing the call,
   because the VM turns its own invariant errors into panics in debug builds and a store
   native must never do that; and the gas of every operation is pinned to the unit by a test,
   since gas is consensus. Also tested: a type too large for the VM to lay out aborts with 4
   and does not panic, and each rule was broken in turn to check a test notices.
4. **The D7 pass in `prepare`, with its bypass tests (done):** `chain_exec::publish::store_violations`,
   run by `prepare` on every module after the verifier, so the chain and `thrylos move build`
   apply it identically. It accepts a type argument only if it is a struct or enum the module
   names as its own **and has a definition for** (a hand-made handle claiming a foreign type
   proves nothing), instantiated with anything, and refuses a bare type parameter, another
   module's type (same package or another), a type from `std`, and any other kind of type.
   `crates/exec/tests/store_ownership.rs` publishes each attempt through the real chain, and
   each part of the rule was broken in turn to check a test notices. The address-and-name test
   is exact: a package's own module called `store` is not treated as the framework's.
5. **Wire the store into `entry::call`; effects and deposits; the counter acceptance test
   (done):** `entry.rs` installs a `StoreExtension` (a `DrawerOverlay` over the state, the
   sender, and the transaction's `declared_inputs`) next to `BlockInfo`; after the call it
   applies the overlay's changes and, if the drawers grew, debits the deposit from the sender
   and burns it from the supply in the same effects. A sender who cannot pay ends the call at
   the gas it had metered, with `InsufficientBalance` and nothing written. `Executor::audit`
   now checks every drawer is well formed. `thrylos move test` runs store-using tests (each
   with empty drawers and every address open) and `thrylos move call --input <address>` declares
   inputs. Tests: `crates/exec/tests/store_calls.rs` (counter across blocks, deposits for a
   new, grown, shrunk and emptied drawer, aborts leaving nothing, declared inputs, restart from
   state, two independent nodes agreeing on the state root, the state cap) and a four-process
   network test that publishes a counter written with the tools, changes it through different
   nodes, restarts one, and checks all four agree.
6. The publish fuzz target extended with store-calling modules.
7. Stage 2b (RPC, simulate, CLI, explorer), the guide, then calibration and the reset
   rehearsal.

## Not in this stage

Events (D4), refunds (D3), objects with their own IDs and transfer, shared objects and
dynamic fields (D1), borrowing a stored value in place (values are taken out and put back),
struct or object arguments to entry functions, and package upgrades. Each can be added
later; the ones that touch the framework's API wait for the next reset, which is the reason
D5 and D6 are the part to argue about now.

## Spike results (2026-09-25)

`store_spike.rs`, seven tests, all passing. It was throwaway evidence (in-memory store, no
deposits, gas or limits) and is deleted now that the real natives exist and are tested by
`crates/exec/tests/store_natives.rs`. What it settled:

- **`has key` without a `UID` compiles**, for structs and enums, so D6 stands as written.
- **A native can store and load a value from its type argument.** `type_to_type_layout` and
  `type_to_type_tag` on the `T` a native is given, then `Value::typed_serialize` to write and
  `Value::simple_deserialize` to read, round-tripped a one-field struct, a struct with an
  address, a vector, a nested struct with a `u128` and a `vector<u16>`, an `Option<u64>` and
  a `vector<bool>`, a generic `Wrapper<u64>` and `Wrapper<Inner>`, and an enum with unit,
  tuple and struct variants. A value with no `drop` (`Linear`) can be taken and unpacked.
- **The bytes are BCS and the same every run:** a two-node comparison of the bytes written by
  the same calls was identical. A `Counter { n: 43 }` is the 8 bytes of `43`.
- **Two drawers of different types at one owner and slot coexist**, because the type is part
  of the key (the key holds the type's canonical string, e.g.
  `0x0…0::spike::Wrapper<u64>`, which will carry the real package address on the chain).
- **An extension can borrow the state.** `StoreView<'a> { base: &'a BTreeMap, overlay }`
  works as a native extension; the overlay is taken back out with `remove` after the VM is
  dropped. So the real store can hold `&state` and return its writes as `CallEffects`.
- **A native's abort reaches the caller as `ABORTED` with the native's own code and the
  location `0x2::store`**, so D6's codes are distinguishable from a developer's.
- **The ownership rule (D7) is decidable from bytecode.** Scanning a module's function
  instantiations for `thrylos::store` calls found exactly the two bad ones in a test module:
  `put<T>` with a bare type parameter and `put` of a type defined in a different module, and
  none of the module's own types (plain, generic or enum).

What the spike did **not** prove, and the real work must:

- **No `expect`.** The spike unwraps two things the real natives must turn into aborts:
  `type_to_type_layout` returning `None` (a type too large or deep for the VM's limits) and
  `typed_serialize` returning `None`. Both become `store` aborts (code 4), never a panic,
  and there must be a test for a type at the layout limit.
- **Size before cost.** A value's serialised size is known only after serialising it, so the
  native charges for the bytes after doing the work and aborts if the budget or the 16 KiB
  cap is passed. The work is bounded by the gas the function already spent building the
  value, but that needs a test with a large vector.
- **Everything around it:** gas per operation, deposits, the declared-inputs check, the key
  format, the state cap, persistence across restart and four-node agreement.
- Two API notes for whoever builds it: the value argument is taken with `args.pop_back()`
  (`pop_arg!` does not cast to a bare `Value`), and `Type` is `move_vm_runtime::execution::Type`.

The design does not change. The next step is item 2 of "Order of work".

## For your review

Two things in this document are mine and were not in what you approved: the **slot** in D5
(kept, 2026-09-25) and the **`key` versus `store`** ability in D6 (settled by the spike:
`key`). Everything else is the four defaults, made specific.
