/// Storage for a package: drawers.
///
/// Every address has drawers. A drawer is named by a type and a slot number and
/// holds one value of that type. Only the module that defines a type may use
/// drawers of that type (the network refuses a package that does otherwise), so
/// a module's values cannot be reached by anyone else's code.
///
/// A call may touch only drawers owned by its sender or by an address it
/// declared as an input. Each call may do at most 64 store operations, change at
/// most 16 drawers, and hold at most 16 KiB in one.
///
/// These abort with the code below, from this module (`0x2::store`), so they can
/// be told from a package's own codes.
module thrylos::store;

/// `take` or `read` of an empty drawer.
#[allow(unused_const)]
const EEmpty: u64 = 1;
/// `put` into a drawer that already holds a value.
#[allow(unused_const)]
const EOccupied: u64 = 2;
/// The drawer's owner is neither the sender nor a declared input.
#[allow(unused_const)]
const ENotDeclared: u64 = 3;
/// The value, or its type's name, is too large to store.
#[allow(unused_const)]
const ETooLarge: u64 = 4;
/// Too many store operations, or drawers changed, in one call.
#[allow(unused_const)]
const ETooManyOperations: u64 = 5;
/// A stored value could not be read back. Damaged state, which no transaction
/// can cause.
#[allow(unused_const)]
const ECorrupt: u64 = 6;

/// Fill the drawer of type `T` at (`owner`, `slot`). It never replaces a value.
public native fun put<T: key>(owner: address, slot: u64, value: T);

/// Empty the drawer and return what was in it.
public native fun take<T: key>(owner: address, slot: u64): T;

/// Whether the drawer holds a value.
public native fun has<T: key>(owner: address, slot: u64): bool;

/// A copy of what is in the drawer, leaving it there.
public native fun read<T: key + copy>(owner: address, slot: u64): T;
