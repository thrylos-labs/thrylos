//! Opaque state keys and values. `docs/spec.md`'s "account model" half
//! of this crate's scope is deferred — see the crate-level doc comment —
//! so both are just length-prefixed byte strings for now, with no
//! assumed internal structure.

use chain_types::codec::{CodecError, Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateKey(Vec<u8>);

impl StateKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for StateKey {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for StateKey {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = Vec::<u8>::decode(input)?;
        Ok((Self(bytes), used))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateValue(Vec<u8>);

impl StateValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Encode for StateValue {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for StateValue {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (bytes, used) = Vec::<u8>::decode(input)?;
        Ok((Self(bytes), used))
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
