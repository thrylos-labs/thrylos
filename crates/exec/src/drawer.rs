//! Move drawers: what a package's stored values are in chain state, and the
//! rules for changing them within one call. `docs/move-storage-design.md`.
//!
//! A drawer is named by an owner address, a slot number and a type, and holds
//! one value of that type. This module knows nothing of the Move VM: it is the
//! state format and the bookkeeping the store natives will call, so that
//! every rule that matters (who may touch what, how much may be written, what
//! it costs) is decided here, in plain code with plain tests, and the natives
//! only translate.
//!
//! - **The key** is `keys::drawer_key`: fixed size, the type reduced to a hash.
//! - **The value** ([`DrawerValue`]) is the type's canonical name and the BCS
//!   bytes of the value. The name is kept so a reader can see what a drawer
//!   holds, and so a hash collision could never make one type read another's
//!   bytes: [`DrawerOverlay`] compares it.
//! - **A call's changes** go through a [`DrawerOverlay`]: reads see earlier
//!   writes in the same call, nothing reaches the state until the call
//!   succeeds and the overlay's changes are applied, and the deposit is worked
//!   out from the state as it was to the state as it would be.

use std::collections::BTreeMap;

use chain_state::{StateKey, StateValue};
use chain_types::codec::{decode_exact, decode_field, CodecError, Decode, Encode};
use move_core_types::account_address::AccountAddress;

use crate::keys::drawer_key;
use crate::native::NEW_ENTRY_STORAGE_DEPOSIT;

/// The most bytes of BCS a drawer may hold.
pub const MAX_VALUE_BYTES: usize = 16 * 1024;
/// The longest canonical type name a drawer may be keyed by.
pub const MAX_TYPE_NAME_BYTES: usize = 256;
/// Store operations (`put`, `take`, `has`, `read`) in one call.
pub const MAX_OPERATIONS_PER_CALL: usize = 64;
/// Distinct drawers one call may change.
pub const MAX_DRAWERS_WRITTEN_PER_CALL: usize = 16;
/// Storage deposit for each started KiB a drawer grows by, on top of the flat
/// entry deposit when the drawer is new. Burned, never refunded.
pub const DRAWER_DEPOSIT_PER_KIB: u128 = 10_000_000;

/// The abort codes the store natives raise, from module `0x2::store`.
pub const CODE_EMPTY: u64 = 1;
pub const CODE_OCCUPIED: u64 = 2;
pub const CODE_NOT_DECLARED: u64 = 3;
pub const CODE_TOO_LARGE: u64 = 4;
pub const CODE_TOO_MANY_OPERATIONS: u64 = 5;
/// A stored drawer could not be read back. State damage, which no transaction
/// can cause; an abort of its own (not an invariant error, which the VM turns
/// into a panic in debug builds) so the call ends deterministically.
pub const CODE_CORRUPT: u64 = 6;

/// Why an operation on a drawer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawerError {
    /// `take` or `read` of a drawer with nothing in it.
    Empty,
    /// `put` into a drawer that already holds a value.
    Occupied,
    /// The drawer's owner is neither the sender nor a declared input.
    NotDeclared,
    /// The value or the type name is over its limit.
    TooLarge,
    /// Over [`MAX_OPERATIONS_PER_CALL`] operations, or over
    /// [`MAX_DRAWERS_WRITTEN_PER_CALL`] drawers written.
    TooManyOperations,
    /// A stored entry that is not a drawer value: damaged state. Not a thing a
    /// transaction can cause.
    Corrupt,
}

impl DrawerError {
    /// The code the native aborts with.
    pub const fn abort_code(self) -> u64 {
        match self {
            Self::Empty => CODE_EMPTY,
            Self::Occupied => CODE_OCCUPIED,
            Self::NotDeclared => CODE_NOT_DECLARED,
            Self::TooLarge => CODE_TOO_LARGE,
            Self::TooManyOperations => CODE_TOO_MANY_OPERATIONS,
            Self::Corrupt => CODE_CORRUPT,
        }
    }
}

impl core::fmt::Display for DrawerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the drawer is empty",
            Self::Occupied => "the drawer already holds a value",
            Self::NotDeclared => "the drawer's owner is not the sender or a declared input",
            Self::TooLarge => "the value or its type name is over the limit",
            Self::TooManyOperations => "too many store operations or drawers written in one call",
            Self::Corrupt => "a stored drawer is not a valid drawer value",
        })
    }
}

impl std::error::Error for DrawerError {}

/// What a drawer holds: the canonical name of its type and the value's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawerValue {
    pub type_name: String,
    pub bytes: Vec<u8>,
}

impl DrawerValue {
    /// `None` if either part is over its limit.
    pub fn new(type_name: String, bytes: Vec<u8>) -> Option<Self> {
        (type_name.len() <= MAX_TYPE_NAME_BYTES && bytes.len() <= MAX_VALUE_BYTES)
            .then_some(Self { type_name, bytes })
    }

    /// As stored in state.
    pub fn to_state(&self) -> StateValue {
        let mut out = Vec::new();
        self.encode(&mut out);
        StateValue::new(out)
    }

    /// From what state holds, all of it or nothing.
    pub fn from_state(value: &StateValue) -> Result<Self, DrawerError> {
        decode_exact(value.as_bytes()).map_err(|_| DrawerError::Corrupt)
    }
}

impl Encode for DrawerValue {
    fn encode(&self, out: &mut Vec<u8>) {
        self.type_name.as_bytes().to_vec().encode(out);
        self.bytes.encode(out);
    }
}

impl Decode for DrawerValue {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (name, offset) = decode_field::<Vec<u8>>(input, 0)?;
        let (bytes, offset) = decode_field::<Vec<u8>>(input, offset)?;
        // Held to the same limits on the way in as on the way out, so a stored
        // entry that could not have been written is not read either.
        let type_name = String::from_utf8(name).map_err(|_| CodecError::InvalidValue)?;
        if type_name.len() > MAX_TYPE_NAME_BYTES || bytes.len() > MAX_VALUE_BYTES {
            return Err(CodecError::InvalidValue);
        }
        Ok((Self { type_name, bytes }, offset))
    }
}

/// Whose drawers a call may touch: the sender's, and those it declared.
#[derive(Debug, Clone)]
pub struct Access {
    pub sender: AccountAddress,
    pub declared: Vec<AccountAddress>,
}

impl Access {
    fn allows(&self, owner: AccountAddress) -> bool {
        owner == self.sender || self.declared.contains(&owner)
    }
}

/// The started KiBs in `bytes`: 0 for 0 bytes, 1 for 1 to 1024, 2 for 1025...
fn kib(bytes: usize) -> u128 {
    u128::try_from(bytes.div_ceil(1024)).unwrap_or(u128::MAX)
}

/// One call's view of the drawers: the state as it found it, and what the call
/// has written since.
pub struct DrawerOverlay<'a> {
    base: &'a BTreeMap<StateKey, StateValue>,
    access: Access,
    writes: BTreeMap<StateKey, Option<DrawerValue>>,
    operations: usize,
}

impl<'a> DrawerOverlay<'a> {
    pub fn new(base: &'a BTreeMap<StateKey, StateValue>, access: Access) -> Self {
        Self {
            base,
            access,
            writes: BTreeMap::new(),
            operations: 0,
        }
    }

    /// Count an operation, refusing the one past the limit, and check the owner
    /// is one this call may touch. Checked before anything is looked up, so a
    /// refused call learns nothing about drawers it may not touch.
    fn begin(&mut self, owner: AccountAddress) -> Result<(), DrawerError> {
        if self.operations >= MAX_OPERATIONS_PER_CALL {
            return Err(DrawerError::TooManyOperations);
        }
        self.operations = self.operations.saturating_add(1);
        if self.access.allows(owner) {
            Ok(())
        } else {
            Err(DrawerError::NotDeclared)
        }
    }

    /// What is in the drawer now, this call's writes included. A stored entry
    /// of another type at the same key (a hash collision) reads as empty.
    fn current(&self, key: &StateKey, type_name: &str) -> Result<Option<DrawerValue>, DrawerError> {
        let found = match self.writes.get(key) {
            Some(written) => written.clone(),
            None => match self.base.get(key) {
                Some(stored) => Some(DrawerValue::from_state(stored)?),
                None => None,
            },
        };
        Ok(found.filter(|value| value.type_name == type_name))
    }

    pub fn has(
        &mut self,
        owner: AccountAddress,
        slot: u64,
        type_name: &str,
    ) -> Result<bool, DrawerError> {
        self.begin(owner)?;
        let key = drawer_key(owner, slot, type_name);
        Ok(self.current(&key, type_name)?.is_some())
    }

    /// A copy of the value, leaving it in place.
    pub fn read(
        &mut self,
        owner: AccountAddress,
        slot: u64,
        type_name: &str,
    ) -> Result<DrawerValue, DrawerError> {
        self.begin(owner)?;
        let key = drawer_key(owner, slot, type_name);
        self.current(&key, type_name)?.ok_or(DrawerError::Empty)
    }

    /// The value, leaving the drawer empty.
    pub fn take(
        &mut self,
        owner: AccountAddress,
        slot: u64,
        type_name: &str,
    ) -> Result<DrawerValue, DrawerError> {
        self.begin(owner)?;
        let key = drawer_key(owner, slot, type_name);
        let value = self.current(&key, type_name)?.ok_or(DrawerError::Empty)?;
        self.writes.insert(key, None);
        Ok(value)
    }

    /// Fill an empty drawer. Never replaces a value: one without `drop` could
    /// not be destroyed, which is what Move's types are for.
    pub fn put(
        &mut self,
        owner: AccountAddress,
        slot: u64,
        value: DrawerValue,
    ) -> Result<(), DrawerError> {
        self.begin(owner)?;
        if value.bytes.len() > MAX_VALUE_BYTES || value.type_name.len() > MAX_TYPE_NAME_BYTES {
            return Err(DrawerError::TooLarge);
        }
        let key = drawer_key(owner, slot, &value.type_name);
        if self.current(&key, &value.type_name)?.is_some() {
            return Err(DrawerError::Occupied);
        }
        // The drawers this call would change, counting this one.
        let already = self.writes.contains_key(&key);
        if !already && self.writes.len() >= MAX_DRAWERS_WRITTEN_PER_CALL {
            return Err(DrawerError::TooManyOperations);
        }
        self.writes.insert(key, Some(value));
        Ok(())
    }

    /// What this call changes in state, in key order, leaving out writes that
    /// end where they began (a value put and taken again, a drawer emptied
    /// that was already empty, a value put back as it was).
    pub fn changes(&self) -> Vec<(StateKey, Option<StateValue>)> {
        self.writes
            .iter()
            .filter_map(|(key, written)| {
                let after = written.as_ref().map(DrawerValue::to_state);
                (self.base.get(key) != after.as_ref()).then(|| (key.clone(), after))
            })
            .collect()
    }

    /// The storage deposit the call owes, from the state it found to the state
    /// it leaves. A drawer that is new pays the flat entry deposit and each
    /// started KiB it holds; one that grows pays for each started KiB it grows
    /// by; one that shrinks, is emptied or is unchanged pays nothing.
    pub fn deposit(&self) -> u128 {
        let mut owed: u128 = 0;
        for (key, after) in self.changes() {
            let Some(after) = after else { continue };
            let new_kib = kib(after.as_bytes().len());
            let owed_here = match self.base.get(&key) {
                None => NEW_ENTRY_STORAGE_DEPOSIT
                    .saturating_add(new_kib.saturating_mul(DRAWER_DEPOSIT_PER_KIB)),
                Some(before) => new_kib
                    .saturating_sub(kib(before.as_bytes().len()))
                    .saturating_mul(DRAWER_DEPOSIT_PER_KIB),
            };
            owed = owed.saturating_add(owed_here);
        }
        owed
    }

    /// Operations counted so far.
    pub fn operations(&self) -> usize {
        self.operations
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use crate::keys::{drawer_tag, module_key, object_key, package_key};

    fn addr(n: u8) -> AccountAddress {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        AccountAddress::new(bytes)
    }

    const ME: u8 = 1;
    const OTHER: u8 = 2;

    fn access() -> Access {
        Access {
            sender: addr(ME),
            declared: vec![],
        }
    }

    fn value(name: &str, size: usize) -> DrawerValue {
        DrawerValue::new(name.to_owned(), vec![7; size]).unwrap()
    }

    fn empty() -> BTreeMap<StateKey, StateValue> {
        BTreeMap::new()
    }

    /// A state that already holds `value` at (owner, slot).
    fn holding(owner: u8, slot: u64, v: &DrawerValue) -> BTreeMap<StateKey, StateValue> {
        BTreeMap::from([(drawer_key(addr(owner), slot, &v.type_name), v.to_state())])
    }

    // ---- the key ----------------------------------------------------------

    #[test]
    fn a_key_is_a_tag_the_owner_the_slot_and_a_hash_of_the_type() {
        let key = drawer_key(addr(9), 0x0102_0304_0506_0708, "0x1::m::T");
        let bytes = key.as_bytes();
        assert_eq!(bytes.len(), 1 + 32 + 8 + 32);
        assert_eq!(bytes[0], drawer_tag());
        assert_eq!(&bytes[1..33], addr(9).to_vec().as_slice());
        assert_eq!(
            &bytes[33..41],
            [1, 2, 3, 4, 5, 6, 7, 8],
            "big-endian, so slots sort"
        );
    }

    #[test]
    fn the_key_pins_its_exact_bytes() {
        // A change to the layout or the hash is a change to every stored drawer.
        let key = drawer_key(addr(1), 0, "T");
        let hex: String = key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "0b000000000000000000000000000000000000000000000000000000000000000100000000000000006969cf44b8191844e1906fc1eb4abff091a898382aab928bad4a2fc9ce8eeb1e"
        );
        assert_eq!(
            key.as_bytes()[41..]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            chain_types::hash_with_domain(chain_types::DomainTag::MoveDrawerTypeV1, b"T")
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        assert_eq!(drawer_tag(), chain_state::account::KEY_TAG + 11);
    }

    #[test]
    fn every_part_of_the_name_changes_the_key() {
        let base = drawer_key(addr(1), 0, "0x1::m::T");
        assert_ne!(base, drawer_key(addr(2), 0, "0x1::m::T"));
        assert_ne!(base, drawer_key(addr(1), 1, "0x1::m::T"));
        assert_ne!(base, drawer_key(addr(1), 0, "0x1::m::U"));
        assert_ne!(base, drawer_key(addr(1), 0, "0x1::m::T<u64>"));
        assert_eq!(base, drawer_key(addr(1), 0, "0x1::m::T"));
    }

    #[test]
    fn a_drawer_key_cannot_be_another_kinds_key() {
        let drawer = drawer_key(addr(1), 0, "T");
        for other in [
            module_key(addr(1)),
            object_key(addr(1)),
            package_key(addr(1)),
        ] {
            assert_ne!(drawer, other);
            assert_ne!(
                drawer.as_bytes()[0],
                other.as_bytes()[0],
                "a different tag byte"
            );
        }
        // Not an account key either: the account tag is reserved below ours.
        assert!(drawer.as_bytes()[0] > chain_state::account::KEY_TAG);
    }

    #[test]
    fn a_long_type_name_is_no_longer_a_key() {
        let long = "x".repeat(10_000);
        assert_eq!(drawer_key(addr(1), 0, &long).as_bytes().len(), 73);
    }

    // ---- the value --------------------------------------------------------

    #[test]
    fn a_value_round_trips_through_state() {
        let v = DrawerValue::new("0x2::m::T<u64>".to_owned(), vec![1, 2, 3]).unwrap();
        assert_eq!(DrawerValue::from_state(&v.to_state()).unwrap(), v);
        let empty_value = DrawerValue::new(String::new(), vec![]).unwrap();
        assert_eq!(
            DrawerValue::from_state(&empty_value.to_state()).unwrap(),
            empty_value
        );
    }

    #[test]
    fn a_value_over_its_limits_cannot_be_made() {
        assert!(DrawerValue::new("T".into(), vec![0; MAX_VALUE_BYTES]).is_some());
        assert!(DrawerValue::new("T".into(), vec![0; MAX_VALUE_BYTES + 1]).is_none());
        assert!(DrawerValue::new("x".repeat(MAX_TYPE_NAME_BYTES), vec![]).is_some());
        assert!(DrawerValue::new("x".repeat(MAX_TYPE_NAME_BYTES + 1), vec![]).is_none());
    }

    #[test]
    fn stored_bytes_that_are_not_a_drawer_value_are_corrupt() {
        let good = value("T", 4).to_state();
        // Trailing byte, truncated, and a type name that is not text.
        let mut trailing = good.as_bytes().to_vec();
        trailing.push(0);
        assert_eq!(
            DrawerValue::from_state(&StateValue::new(trailing)),
            Err(DrawerError::Corrupt)
        );
        let truncated = good.as_bytes()[..good.as_bytes().len() - 1].to_vec();
        assert_eq!(
            DrawerValue::from_state(&StateValue::new(truncated)),
            Err(DrawerError::Corrupt)
        );
        let mut not_text = Vec::new();
        vec![0xffu8, 0xfe].encode(&mut not_text);
        vec![1u8].encode(&mut not_text);
        assert_eq!(
            DrawerValue::from_state(&StateValue::new(not_text)),
            Err(DrawerError::Corrupt)
        );
        // Over the limits: an entry that could not have been written.
        let mut huge = Vec::new();
        b"T".to_vec().encode(&mut huge);
        vec![0u8; MAX_VALUE_BYTES + 1].encode(&mut huge);
        assert_eq!(
            DrawerValue::from_state(&StateValue::new(huge)),
            Err(DrawerError::Corrupt)
        );
        assert_eq!(
            DrawerValue::from_state(&StateValue::new(vec![])),
            Err(DrawerError::Corrupt)
        );
    }

    // ---- the operations ---------------------------------------------------

    #[test]
    fn put_then_read_take_and_has() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(o.has(addr(ME), 0, "T"), Ok(false));
        o.put(addr(ME), 0, value("T", 8)).unwrap();
        assert_eq!(o.has(addr(ME), 0, "T"), Ok(true));
        assert_eq!(o.read(addr(ME), 0, "T").unwrap(), value("T", 8));
        assert_eq!(o.has(addr(ME), 0, "T"), Ok(true), "read leaves it");
        assert_eq!(o.take(addr(ME), 0, "T").unwrap(), value("T", 8));
        assert_eq!(o.has(addr(ME), 0, "T"), Ok(false));
    }

    #[test]
    fn take_and_read_of_an_empty_drawer_and_put_into_a_full_one_are_refused() {
        let base = holding(ME, 0, &value("T", 4));
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(
            o.take(addr(ME), 1, "T"),
            Err(DrawerError::Empty),
            "another slot"
        );
        assert_eq!(
            o.read(addr(ME), 0, "U"),
            Err(DrawerError::Empty),
            "another type"
        );
        assert_eq!(
            o.put(addr(ME), 0, value("T", 1)),
            Err(DrawerError::Occupied)
        );
        // A different type at the same owner and slot is a different drawer.
        o.put(addr(ME), 0, value("U", 1)).unwrap();
        assert_eq!(o.take(addr(ME), 0, "T").unwrap(), value("T", 4));
    }

    #[test]
    fn a_call_reads_its_own_writes_and_the_state_is_never_touched() {
        let base = holding(ME, 0, &value("T", 4));
        let before = base.clone();
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(o.take(addr(ME), 0, "T").unwrap(), value("T", 4));
        assert_eq!(
            o.take(addr(ME), 0, "T"),
            Err(DrawerError::Empty),
            "already taken by this call"
        );
        o.put(addr(ME), 0, value("T", 9)).unwrap();
        assert_eq!(o.read(addr(ME), 0, "T").unwrap(), value("T", 9));
        assert_eq!(
            base, before,
            "the overlay borrows the state and never writes it"
        );
    }

    #[test]
    fn the_owner_must_be_the_sender_or_declared() {
        let base = holding(OTHER, 0, &value("T", 4));
        let mut o = DrawerOverlay::new(&base, access());
        for result in [
            o.has(addr(OTHER), 0, "T").map(|_| ()),
            o.read(addr(OTHER), 0, "T").map(|_| ()),
            o.take(addr(OTHER), 0, "T").map(|_| ()),
            o.put(addr(OTHER), 1, value("T", 1)),
        ] {
            assert_eq!(result, Err(DrawerError::NotDeclared));
        }
        // The same call, with the owner declared.
        let mut declared = DrawerOverlay::new(
            &base,
            Access {
                sender: addr(ME),
                declared: vec![addr(OTHER)],
            },
        );
        assert_eq!(declared.take(addr(OTHER), 0, "T").unwrap(), value("T", 4));
        // A refusal reveals nothing about what is there: the same error for a
        // drawer that exists and one that does not.
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(o.take(addr(OTHER), 0, "T"), o.take(addr(OTHER), 5, "T"));
    }

    #[test]
    fn a_value_over_the_size_limit_is_refused_and_one_at_it_is_not() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        let over = DrawerValue {
            type_name: "T".into(),
            bytes: vec![0; MAX_VALUE_BYTES + 1],
        };
        assert_eq!(o.put(addr(ME), 0, over), Err(DrawerError::TooLarge));
        o.put(addr(ME), 0, value("T", MAX_VALUE_BYTES)).unwrap();
    }

    #[test]
    fn the_sixty_fifth_operation_is_refused() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        for _ in 0..MAX_OPERATIONS_PER_CALL {
            o.has(addr(ME), 0, "T").unwrap();
        }
        assert_eq!(o.operations(), MAX_OPERATIONS_PER_CALL);
        assert_eq!(o.has(addr(ME), 0, "T"), Err(DrawerError::TooManyOperations));
        assert_eq!(
            o.put(addr(ME), 0, value("T", 1)),
            Err(DrawerError::TooManyOperations)
        );
    }

    #[test]
    fn the_seventeenth_drawer_written_is_refused_but_rewriting_one_is_not() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        for slot in 0..MAX_DRAWERS_WRITTEN_PER_CALL as u64 {
            o.put(addr(ME), slot, value("T", 1)).unwrap();
        }
        assert_eq!(
            o.put(addr(ME), 99, value("T", 1)),
            Err(DrawerError::TooManyOperations)
        );
        // Taking and putting a drawer already written does not count again.
        o.take(addr(ME), 0, "T").unwrap();
        o.put(addr(ME), 0, value("T", 2)).unwrap();
    }

    #[test]
    fn a_stored_entry_that_is_damaged_fails_the_call_it_is_read_by() {
        let key = drawer_key(addr(ME), 0, "T");
        let base = BTreeMap::from([(key, StateValue::new(vec![1, 2, 3]))]);
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(o.has(addr(ME), 0, "T"), Err(DrawerError::Corrupt));
        assert_eq!(DrawerError::Corrupt.abort_code(), CODE_CORRUPT);
    }

    #[test]
    fn an_entry_of_another_type_at_the_same_key_reads_as_empty() {
        // What a hash collision would look like: the key is `T`'s, the value says `U`.
        let key = drawer_key(addr(ME), 0, "T");
        let base = BTreeMap::from([(key, value("U", 4).to_state())]);
        let mut o = DrawerOverlay::new(&base, access());
        assert_eq!(o.has(addr(ME), 0, "T"), Ok(false));
        assert_eq!(o.take(addr(ME), 0, "T"), Err(DrawerError::Empty));
    }

    #[test]
    fn every_refusal_has_the_designs_code() {
        assert_eq!(DrawerError::Empty.abort_code(), 1);
        assert_eq!(DrawerError::Occupied.abort_code(), 2);
        assert_eq!(DrawerError::NotDeclared.abort_code(), 3);
        assert_eq!(DrawerError::TooLarge.abort_code(), 4);
        assert_eq!(DrawerError::TooManyOperations.abort_code(), 5);
        assert_eq!(DrawerError::Corrupt.abort_code(), 6);
    }

    // ---- what a call changes, and what it costs ---------------------------

    fn apply(
        state: &mut BTreeMap<StateKey, StateValue>,
        changes: Vec<(StateKey, Option<StateValue>)>,
    ) {
        for (key, change) in changes {
            match change {
                Some(v) => {
                    state.insert(key, v);
                }
                None => {
                    state.remove(&key);
                }
            }
        }
    }

    #[test]
    fn changes_are_what_the_call_did_in_key_order() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 5, value("T", 2)).unwrap();
        o.put(addr(ME), 1, value("T", 2)).unwrap();
        let changes = o.changes();
        assert_eq!(changes.len(), 2);
        assert!(
            changes[0].0 < changes[1].0,
            "sorted, whatever order the calls came in"
        );
        let mut state = base.clone();
        apply(&mut state, changes);
        assert_eq!(state.len(), 2);
    }

    #[test]
    fn a_write_that_ends_where_it_began_changes_nothing() {
        // Put and taken again: nothing.
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", 2)).unwrap();
        o.take(addr(ME), 0, "T").unwrap();
        assert!(o.changes().is_empty());
        assert_eq!(o.deposit(), 0);
        // Taken and put back exactly as it was: nothing.
        let v = value("T", 300);
        let base = holding(ME, 0, &v);
        let mut o = DrawerOverlay::new(&base, access());
        let taken = o.take(addr(ME), 0, "T").unwrap();
        o.put(addr(ME), 0, taken).unwrap();
        assert!(o.changes().is_empty());
        assert_eq!(o.deposit(), 0);
    }

    #[test]
    fn a_taken_drawer_is_a_deletion() {
        let base = holding(ME, 0, &value("T", 4));
        let mut o = DrawerOverlay::new(&base, access());
        o.take(addr(ME), 0, "T").unwrap();
        let changes = o.changes();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].1, None);
        assert_eq!(o.deposit(), 0, "no refund, and nothing owed");
    }

    /// The bytes an entry of `payload` bytes and type name `name` takes in state.
    fn stored_len(name: &str, payload: usize) -> usize {
        value(name, payload).to_state().as_bytes().len()
    }

    #[test]
    fn a_new_drawer_pays_the_flat_deposit_and_each_started_kib() {
        let base = empty();
        // Small: one started KiB.
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", 8)).unwrap();
        assert_eq!(
            o.deposit(),
            NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB
        );
        // Just over a KiB of stored bytes: two.
        let payload = 1024 - stored_len("T", 0) + 1;
        assert_eq!(kib(stored_len("T", payload)), 2);
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", payload)).unwrap();
        assert_eq!(
            o.deposit(),
            NEW_ENTRY_STORAGE_DEPOSIT + 2 * DRAWER_DEPOSIT_PER_KIB
        );
        // Exactly a KiB: one.
        let payload = 1024 - stored_len("T", 0);
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", payload)).unwrap();
        assert_eq!(
            o.deposit(),
            NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB
        );
        // Two new drawers pay twice.
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", 8)).unwrap();
        o.put(addr(ME), 1, value("T", 8)).unwrap();
        assert_eq!(
            o.deposit(),
            2 * (NEW_ENTRY_STORAGE_DEPOSIT + DRAWER_DEPOSIT_PER_KIB)
        );
    }

    #[test]
    fn a_drawer_that_grows_pays_for_the_extra_kibs_only() {
        let small = value("T", 8);
        let base = holding(ME, 0, &small);
        // Grown within the same KiB: free.
        let mut o = DrawerOverlay::new(&base, access());
        o.take(addr(ME), 0, "T").unwrap();
        o.put(addr(ME), 0, value("T", 500)).unwrap();
        assert_eq!(o.deposit(), 0);
        // Grown across into a third KiB: two more.
        let mut o = DrawerOverlay::new(&base, access());
        o.take(addr(ME), 0, "T").unwrap();
        o.put(addr(ME), 0, value("T", 2_100)).unwrap();
        assert_eq!(kib(stored_len("T", 2_100)), 3);
        assert_eq!(
            o.deposit(),
            2 * DRAWER_DEPOSIT_PER_KIB,
            "the flat deposit was paid when it was made"
        );
    }

    #[test]
    fn a_drawer_that_shrinks_pays_nothing_and_is_not_refunded() {
        let base = holding(ME, 0, &value("T", 5_000));
        let mut o = DrawerOverlay::new(&base, access());
        o.take(addr(ME), 0, "T").unwrap();
        o.put(addr(ME), 0, value("T", 10)).unwrap();
        assert_eq!(o.deposit(), 0);
        assert_eq!(
            o.changes().len(),
            1,
            "it is a real change, just not a costly one"
        );
    }

    #[test]
    fn a_deposit_is_counted_once_however_many_times_the_call_rewrites_the_drawer() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", 8)).unwrap();
        for size in [900, 3_000, 40, 2_500] {
            o.take(addr(ME), 0, "T").unwrap();
            o.put(addr(ME), 0, value("T", size)).unwrap();
        }
        // Only where it ends counts: 2,500 payload bytes is three started KiBs.
        assert_eq!(kib(stored_len("T", 2_500)), 3);
        assert_eq!(
            o.deposit(),
            NEW_ENTRY_STORAGE_DEPOSIT + 3 * DRAWER_DEPOSIT_PER_KIB
        );
    }

    #[test]
    fn a_refused_operation_changes_nothing_that_was_already_done() {
        let base = empty();
        let mut o = DrawerOverlay::new(&base, access());
        o.put(addr(ME), 0, value("T", 8)).unwrap();
        let before = o.changes();
        assert!(o.put(addr(ME), 0, value("T", 8)).is_err());
        assert!(o.take(addr(ME), 9, "T").is_err());
        assert!(o.put(addr(OTHER), 0, value("T", 8)).is_err());
        assert_eq!(o.changes(), before);
    }

    // ---- against a plain model --------------------------------------------

    /// A small deterministic generator, so a failure repeats.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn the_overlay_agrees_with_a_plain_model_over_thousands_of_random_calls() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut state: BTreeMap<StateKey, StateValue> = BTreeMap::new();
        let mut model: BTreeMap<(u8, u64, &'static str), Vec<u8>> = BTreeMap::new();
        let names = ["A", "B<u64>"];

        for _call in 0..2_000 {
            let mut overlay = DrawerOverlay::new(
                &state,
                Access {
                    sender: addr(ME),
                    declared: vec![addr(OTHER)],
                },
            );
            let mut working = model.clone();
            let mut poisoned = false;
            for _ in 0..(1 + rng.next() % 6) {
                let owner = [ME, OTHER, 3][(rng.next() % 3) as usize];
                let slot = rng.next() % 3;
                let name = names[(rng.next() % 2) as usize];
                let payload = vec![(rng.next() % 250) as u8; (rng.next() % 40) as usize];
                let allowed = owner != 3;
                let present = working.contains_key(&(owner, slot, name));
                match rng.next() % 4 {
                    0 => {
                        let r = overlay.put(
                            addr(owner),
                            slot,
                            DrawerValue::new(name.into(), payload.clone()).unwrap(),
                        );
                        match (allowed, present) {
                            (false, _) => assert_eq!(r, Err(DrawerError::NotDeclared)),
                            (true, true) => assert_eq!(r, Err(DrawerError::Occupied)),
                            (true, false) => {
                                r.unwrap();
                                working.insert((owner, slot, name), payload);
                            }
                        }
                    }
                    1 => {
                        let r = overlay.take(addr(owner), slot, name);
                        match (allowed, present) {
                            (false, _) => assert_eq!(r, Err(DrawerError::NotDeclared)),
                            (true, false) => assert_eq!(r, Err(DrawerError::Empty)),
                            (true, true) => {
                                assert_eq!(
                                    r.unwrap().bytes,
                                    working.remove(&(owner, slot, name)).unwrap()
                                );
                            }
                        }
                    }
                    2 => {
                        let r = overlay.read(addr(owner), slot, name);
                        match (allowed, present) {
                            (false, _) => assert_eq!(r, Err(DrawerError::NotDeclared)),
                            (true, false) => assert_eq!(r, Err(DrawerError::Empty)),
                            (true, true) => {
                                assert_eq!(&r.unwrap().bytes, &working[&(owner, slot, name)])
                            }
                        }
                    }
                    _ => {
                        let r = overlay.has(addr(owner), slot, name);
                        if allowed {
                            assert_eq!(r, Ok(present));
                        } else {
                            assert_eq!(r, Err(DrawerError::NotDeclared));
                        }
                    }
                }
                // Now and then the call aborts as a whole, and its overlay is thrown away.
                if rng.next().is_multiple_of(40) {
                    poisoned = true;
                    break;
                }
            }
            let owed = overlay.deposit();
            let changes = overlay.changes();
            if poisoned {
                continue; // an aborted call's overlay is never applied
            }
            // The deposit is exactly what the plain arithmetic says.
            let mut expect: u128 = 0;
            for (key, after) in &changes {
                if let Some(after) = after {
                    expect += match state.get(key) {
                        None => {
                            NEW_ENTRY_STORAGE_DEPOSIT
                                + kib(after.as_bytes().len()) * DRAWER_DEPOSIT_PER_KIB
                        }
                        Some(before) => {
                            kib(after.as_bytes().len()).saturating_sub(kib(before.as_bytes().len()))
                                * DRAWER_DEPOSIT_PER_KIB
                        }
                    };
                }
            }
            assert_eq!(owed, expect);
            apply(&mut state, changes);
            model = working;
            // State and model hold the same drawers.
            assert_eq!(state.len(), model.len());
            for ((owner, slot, name), bytes) in &model {
                let stored =
                    DrawerValue::from_state(&state[&drawer_key(addr(*owner), *slot, name)])
                        .unwrap();
                assert_eq!((&stored.type_name[..], &stored.bytes), (*name, bytes));
            }
        }
    }
}
