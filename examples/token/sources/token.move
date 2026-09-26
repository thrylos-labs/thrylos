/// A fungible token, in about a hundred lines.
///
/// One package can hold many tokens: a token is a number (its `id`, chosen by
/// whoever creates it), and every balance is a drawer at (owner, id). Only this
/// module defines `Balance` and `Supply`, so only this module's code can ever make,
/// change or destroy one: nobody else's package can forge a balance, which is the
/// whole point of the storage rule (`docs/move-developer-guide.md`).
///
/// What to notice:
/// - money moves by taking a value out of a drawer and putting it back changed;
/// - a call may touch only drawers of its sender and of addresses it *declares*,
///   so a transfer names its recipient twice: as an argument and with `--input`;
/// - a drawer that did not exist costs a one-off deposit, paid by whoever made
///   the call that made it, so `transfer` to a new address costs the sender
///   0.02 THRY the first time.
module pkg::token;

use thrylos::signer;
use thrylos::store;

// ---- abort codes ---------------------------------------------------------

/// The token id is already taken (its supply record exists).
const EAlreadyExists: u64 = 1;
/// The sender has too little of the token.
const EInsufficient: u64 = 2;
/// Adding would overflow a `u64`.
const EOverflow: u64 = 3;
/// The sender holds none of this token yet (`register` first, or receive some).
const ENoBalance: u64 = 4;
/// A token was asked for that does not exist.
const ENoSuchToken: u64 = 5;
/// Only the token's creator may do this.
const ENotCreator: u64 = 6;

// ---- what is stored ------------------------------------------------------

/// What one address holds of one token. Lives at (owner, token id).
public struct Balance has key, store, copy, drop { amount: u64 }

/// A token's record. Lives at (creator, token id), next to the creator's own
/// `Balance` (a different type, so a different drawer).
public struct Supply has key, store, copy, drop { total: u64, creator: address }

// ---- making a token ------------------------------------------------------

/// Create token `id` with `total` units, all held by the caller.
entry fun create(s: &signer, id: u64, total: u64) {
    let me = signer::address_of(s);
    assert!(!store::has<Supply>(me, id), EAlreadyExists);
    store::put(me, id, Supply { total, creator: me });
    store::put(me, id, Balance { amount: total });
}

/// Burn `amount` of the caller's own units of the token, and shrink the supply
/// with them. Only the creator keeps the supply record, so only the creator may.
entry fun burn(s: &signer, id: u64, amount: u64) {
    let me = signer::address_of(s);
    assert!(store::has<Supply>(me, id), ENotCreator);
    take_from(me, id, amount);
    let mut supply = store::take<Supply>(me, id);
    supply.total = supply.total - amount;
    store::put(me, id, supply);
}

// ---- holding and moving --------------------------------------------------

/// Make an empty balance for the caller. Anyone may send to an address that has
/// none (the drawer is made for them), but whoever makes the call that makes a
/// drawer pays its deposit: registering yourself is how you pay for your own.
entry fun register(s: &signer, id: u64) {
    let me = signer::address_of(s);
    if (!store::has<Balance>(me, id)) {
        store::put(me, id, Balance { amount: 0 });
    };
}

/// Send `amount` of token `id` from the caller to `to`. Declare `to` when
/// calling (`--input <to>`), since this touches their drawer.
entry fun transfer(s: &signer, id: u64, to: address, amount: u64) {
    let me = signer::address_of(s);
    take_from(me, id, amount);
    give_to(to, id, amount);
}

// ---- reading -------------------------------------------------------------

/// What `owner` holds of token `id` (0 if nothing). A view: call it with
/// `thrylos move view ... --input <owner>`.
public fun balance_of(owner: address, id: u64): u64 {
    if (store::has<Balance>(owner, id)) store::read<Balance>(owner, id).amount else 0
}

/// The total supply of token `id`, given its creator's address.
public fun total_supply(creator: address, id: u64): u64 {
    assert!(store::has<Supply>(creator, id), ENoSuchToken);
    store::read<Supply>(creator, id).total
}

// ---- the two halves of a move --------------------------------------------

fun take_from(owner: address, id: u64, amount: u64) {
    assert!(store::has<Balance>(owner, id), ENoBalance);
    let mut b = store::take<Balance>(owner, id);
    assert!(b.amount >= amount, EInsufficient);
    b.amount = b.amount - amount;
    store::put(owner, id, b);
}

fun give_to(owner: address, id: u64, amount: u64) {
    if (store::has<Balance>(owner, id)) {
        let mut b = store::take<Balance>(owner, id);
        assert!(b.amount <= 18446744073709551615 - amount, EOverflow);
        b.amount = b.amount + amount;
        store::put(owner, id, b);
    } else {
        store::put(owner, id, Balance { amount });
    };
}

// ---- tests ---------------------------------------------------------------

#[test_only]
const ALICE: address = @0xa11ce;
#[test_only]
const BOB: address = @0xb0b;

#[test]
fun a_created_token_is_all_the_creators() {
    // In tests the drawers may be touched at any address, so a test plays both
    // sides without a signer.
    store::put(ALICE, 7, Supply { total: 1000, creator: ALICE });
    store::put(ALICE, 7, Balance { amount: 1000 });
    assert!(balance_of(ALICE, 7) == 1000, 0);
    assert!(balance_of(BOB, 7) == 0, 1);
    assert!(total_supply(ALICE, 7) == 1000, 2);
}

#[test]
fun a_transfer_moves_units_and_creates_the_recipients_drawer() {
    store::put(ALICE, 1, Balance { amount: 100 });
    take_from(ALICE, 1, 30);
    give_to(BOB, 1, 30);
    assert!(balance_of(ALICE, 1) == 70, 0);
    assert!(balance_of(BOB, 1) == 30, 1);
    // A second transfer adds to what is there.
    take_from(ALICE, 1, 20);
    give_to(BOB, 1, 20);
    assert!(balance_of(BOB, 1) == 50, 2);
    assert!(balance_of(ALICE, 1) == 50, 3);
}

#[test]
fun different_token_ids_are_different_tokens() {
    store::put(ALICE, 1, Balance { amount: 5 });
    store::put(ALICE, 2, Balance { amount: 9 });
    take_from(ALICE, 2, 9);
    assert!(balance_of(ALICE, 1) == 5, 0);
    assert!(balance_of(ALICE, 2) == 0, 1);
}

#[test, expected_failure(abort_code = EInsufficient)]
fun you_cannot_send_more_than_you_have() {
    store::put(ALICE, 1, Balance { amount: 10 });
    take_from(ALICE, 1, 11);
}

#[test, expected_failure(abort_code = ENoBalance)]
fun you_cannot_send_what_you_never_held() {
    take_from(BOB, 1, 1);
}

#[test, expected_failure(abort_code = EOverflow)]
fun a_balance_cannot_overflow() {
    store::put(BOB, 1, Balance { amount: 18446744073709551615 });
    give_to(BOB, 1, 1);
}

#[test, expected_failure(abort_code = ENoSuchToken)]
fun the_supply_of_a_token_that_does_not_exist_is_an_error() {
    total_supply(ALICE, 99);
}
