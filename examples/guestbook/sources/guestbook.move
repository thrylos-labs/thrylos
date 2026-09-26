/// A guestbook: anyone can open one, anyone can sign anyone's.
///
/// Where the token example is one value per owner, this is many small values in one
/// place: a book is a counter at (owner, slot 0) and each entry is its own drawer at
/// (owner, slot = its number), so the book can grow without any one value getting big.
///
/// What to notice:
/// - a visitor writes into the *book owner's* drawers, so the owner's address is
///   declared on the call (the `thrylos` command does it for you: it is an `address:`
///   argument);
/// - signing costs the visitor a small deposit for the new drawer (0.02 THRY, burned),
///   which is what keeps a book from being flooded for free;
/// - the owner can remove an entry, and only the owner can, because `remove` checks
///   the signer against the book.
module pkg::guestbook;

use std::string::{Self, String};
use thrylos::signer;
use thrylos::store;

// ---- abort codes ---------------------------------------------------------

/// This address already has a guestbook.
const EAlreadyOpen: u64 = 1;
/// There is no guestbook at that address.
const ENoBook: u64 = 2;
/// The message is empty or longer than 280 bytes.
const EBadMessage: u64 = 3;
/// No such entry (never written, or removed).
const ENoEntry: u64 = 4;
/// Only the book's owner may do this.
const ENotOwner: u64 = 5;

const MAX_MESSAGE_BYTES: u64 = 280;

// ---- what is stored ------------------------------------------------------

/// The book itself. Lives at (owner, 0).
public struct Book has key, store, copy, drop {
    title: String,
    /// How many entries have ever been written; the next one gets this number.
    written: u64,
}

/// One signature. Lives at (book owner, its number).
public struct Entry has key, store, copy, drop {
    author: address,
    message: String,
}

// ---- opening and signing -------------------------------------------------

/// Open the caller's guestbook.
/// (Entry functions take plain bytes, not `String`; the module makes the `String`, which
/// aborts on text that is not valid UTF-8.)
entry fun open(s: &signer, title: vector<u8>) {
    let me = signer::address_of(s);
    assert!(!store::has<Book>(me, 0), EAlreadyOpen);
    store::put(me, 0, Book { title: string::utf8(title), written: 0 });
}

/// Sign the guestbook of `book`. The entry gets the next number.
entry fun sign(s: &signer, book: address, message: vector<u8>) {
    let len = message.length();
    assert!(len > 0 && len <= MAX_MESSAGE_BYTES, EBadMessage);
    let message = string::utf8(message);
    assert!(store::has<Book>(book, 0), ENoBook);
    let mut b = store::take<Book>(book, 0);
    store::put(book, b.written, Entry { author: signer::address_of(s), message });
    b.written = b.written + 1;
    store::put(book, 0, b);
}

/// Remove entry `number` from the caller's own book. Numbers are not reused.
entry fun remove(s: &signer, number: u64) {
    let me = signer::address_of(s);
    assert!(store::has<Book>(me, 0), ENotOwner);
    assert!(store::has<Entry>(me, number), ENoEntry);
    let _gone = store::take<Entry>(me, number);
}

// ---- reading -------------------------------------------------------------

/// How many entries have been written in `book`'s guestbook (removed ones included).
public fun written(book: address): u64 {
    assert!(store::has<Book>(book, 0), ENoBook);
    store::read<Book>(book, 0).written
}

/// The title of `book`'s guestbook, as text (UTF-8 bytes).
public fun title(book: address): vector<u8> {
    assert!(store::has<Book>(book, 0), ENoBook);
    *store::read<Book>(book, 0).title.as_bytes()
}

/// The text of entry `number`.
public fun message(book: address, number: u64): vector<u8> {
    assert!(store::has<Entry>(book, number), ENoEntry);
    *store::read<Entry>(book, number).message.as_bytes()
}

/// Who wrote entry `number`.
public fun author(book: address, number: u64): address {
    assert!(store::has<Entry>(book, number), ENoEntry);
    store::read<Entry>(book, number).author
}

// ---- tests ---------------------------------------------------------------

#[test_only]
const OWNER: address = @0x0;
#[test_only]
const VISITOR: address = @0x7;

#[test_only]
fun open_at(owner: address, title: vector<u8>) {
    store::put(owner, 0, Book { title: string::utf8(title), written: 0 });
}

#[test_only]
fun write_at(book: address, author: address, text: vector<u8>) {
    let mut b = store::take<Book>(book, 0);
    store::put(book, b.written, Entry { author, message: string::utf8(text) });
    b.written = b.written + 1;
    store::put(book, 0, b);
}

#[test]
fun entries_get_the_next_number_and_are_read_back() {
    open_at(OWNER, b"visitors");
    write_at(OWNER, VISITOR, b"hello");
    write_at(OWNER, @0x8, b"second");
    assert!(written(OWNER) == 2, 0);
    assert!(title(OWNER) == b"visitors", 1);
    assert!(message(OWNER, 0) == b"hello", 2);
    assert!(author(OWNER, 0) == VISITOR, 3);
    assert!(message(OWNER, 1) == b"second", 4);
    assert!(author(OWNER, 1) == @0x8, 5);
}

#[test]
fun two_books_do_not_mix() {
    open_at(OWNER, b"a");
    open_at(@0x9, b"b");
    write_at(OWNER, VISITOR, b"in a");
    assert!(written(OWNER) == 1, 0);
    assert!(written(@0x9) == 0, 1);
}

#[test, expected_failure(abort_code = ENoBook)]
fun a_book_that_was_never_opened_has_nothing() {
    written(@0xdead);
}

#[test, expected_failure(abort_code = ENoEntry)]
fun an_entry_that_was_never_written_is_an_error() {
    open_at(OWNER, b"a");
    message(OWNER, 0);
}

#[test]
fun a_removed_entry_is_gone_and_its_number_is_not_reused() {
    open_at(OWNER, b"a");
    write_at(OWNER, VISITOR, b"one");
    write_at(OWNER, VISITOR, b"two");
    let _gone = store::take<Entry>(OWNER, 0);
    assert!(!store::has<Entry>(OWNER, 0), 0);
    assert!(message(OWNER, 1) == b"two", 1);
    write_at(OWNER, VISITOR, b"three");
    assert!(message(OWNER, 2) == b"three", 2);
    assert!(written(OWNER) == 3, 3);
}
