//! Opaque state keys and values. `docs/spec.md`'s "account model" half
//! of this crate's scope is deferred — see the crate-level doc comment —
//! so both are just length-prefixed byte strings for now, with no
//! assumed internal structure.

use std::sync::Arc;

use chain_types::codec::{CodecError, Decode, Encode};

/// The canonical encoding of a byte string: what `Vec<u8>` encodes to (a `u32`
/// length, then the bytes), without copying them first.
fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX).encode(out);
    out.extend_from_slice(bytes);
}

/// Cloning a key or a value shares its bytes instead of copying them: a block is
/// executed on a copy of the whole state, and nearly all of it is not touched,
/// so the copy costs a reference count for each entry and not their bytes, and
/// finding what changed is a pointer comparison for each entry that did not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateKey(Arc<[u8]>);

impl StateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for StateKey {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_bytes(&self.0, out);
    }
}

impl Decode for StateKey {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = Vec::<u8>::decode(input)?;
        Ok((Self(Arc::from(bytes)), used))
    }
}

/// See [`StateKey`]. Equality compares the pointers first, then the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateValue(Arc<[u8]>);

impl StateValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for StateValue {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_bytes(&self.0, out);
    }
}

impl Decode for StateValue {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = Vec::<u8>::decode(input)?;
        Ok((Self(Arc::from(bytes)), used))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use chain_types::codec::decode_exact;

    #[test]
    fn state_key_round_trips() {
        let key = StateKey::new(vec![1, 2, 3]);
        let mut buf = Vec::new();
        key.encode(&mut buf);
        assert_eq!(decode_exact::<StateKey>(&buf).unwrap(), key);
    }

    #[test]
    fn state_value_round_trips_including_empty() {
        let value = StateValue::new(Vec::new());
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(decode_exact::<StateValue>(&buf).unwrap(), value);
    }
}
