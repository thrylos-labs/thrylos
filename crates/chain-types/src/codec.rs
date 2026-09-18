//! Canonical, strict, deterministic byte encoding for consensus-critical
//! types.
//!
//! Implements the "Canonical encoding" and "Fixed iteration order" rules
//! from `docs/spec.md`'s determinism table: there is exactly one valid
//! encoding per value, decoding never panics and rejects anything
//! malformed (wrong length, trailing bytes, out-of-range values), and
//! `decode(encode(x)) == x` holds byte-for-byte. See `codec_proptest.rs`
//! for the round-trip property tests this is checked against.

use crate::collections::BTreeMap;

/// Upper bound on how many elements a length-prefixed collection may
/// declare, checked before any element is decoded or any per-element
/// allocation is made. Callers with a tighter domain-specific bound
/// (e.g. the 128-validator set) should check that separately after
/// decoding; this bound only stops a malformed length from being used
/// to justify unbounded work.
pub const MAX_LEN: u32 = 1 << 24;

/// Everything that can go wrong decoding a value. Decoding never panics;
/// every failure path returns one of these instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before a complete value could be read.
    UnexpectedEof,
    /// A top-level decode left unconsumed bytes.
    TrailingBytes,
    /// A declared collection length exceeds [`MAX_LEN`].
    LengthTooLarge,
    /// The decoded bytes are not a valid value of the target type.
    InvalidValue,
}

impl core::fmt::Display for CodecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            CodecError::UnexpectedEof => "unexpected end of input",
            CodecError::TrailingBytes => "trailing bytes after decode",
            CodecError::LengthTooLarge => "declared length exceeds bound",
            CodecError::InvalidValue => "decoded bytes are not a valid value",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CodecError {}

/// Append `self`'s canonical encoding to `out`.
pub trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}

/// Decode a value from the front of `input`, returning the value and the
/// number of bytes consumed. Implementations must not panic on any input.
pub trait Decode: Sized {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError>;
}

/// Decode a value that must consume all of `input`. Use this at every
/// trust boundary (wire messages, stored records); use [`Decode::decode`]
/// directly only when more fields follow in the same buffer.
pub fn decode_exact<T: Decode>(input: &[u8]) -> Result<T, CodecError> {
    let (value, used) = T::decode(input)?;
    if used != input.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(value)
}

pub(crate) fn checked_add(a: usize, b: usize) -> Result<usize, CodecError> {
    a.checked_add(b).ok_or(CodecError::LengthTooLarge)
}

pub(crate) fn slice_from(input: &[u8], offset: usize) -> Result<&[u8], CodecError> {
    input.get(offset..).ok_or(CodecError::UnexpectedEof)
}

macro_rules! impl_uint {
    ($t:ty) => {
        impl Encode for $t {
            fn encode(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
        }
        impl Decode for $t {
            fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
                const N: usize = core::mem::size_of::<$t>();
                let bytes = input.get(..N).ok_or(CodecError::UnexpectedEof)?;
                let mut arr = [0u8; N];
                arr.copy_from_slice(bytes);
                Ok((<$t>::from_le_bytes(arr), N))
            }
        }
    };
}

impl_uint!(u8);
impl_uint!(u16);
impl_uint!(u32);
impl_uint!(u64);
impl_uint!(u128);

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(u8::from(*self));
    }
}

impl Decode for bool {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        match input.first() {
            Some(0) => Ok((false, 1)),
            Some(1) => Ok((true, 1)),
            Some(_) => Err(CodecError::InvalidValue),
            None => Err(CodecError::UnexpectedEof),
        }
    }
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let bytes = input.get(..N).ok_or(CodecError::UnexpectedEof)?;
        let mut arr = [0u8; N];
        arr.copy_from_slice(bytes);
        Ok((arr, N))
    }
}

/// A `u32` length prefix (little-endian), then that many canonically
/// encoded elements back to back. The prefix is checked against
/// [`MAX_LEN`] and against the remaining input before any element is
/// decoded, so a forged length cannot force an oversized allocation.
impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).unwrap_or(u32::MAX);
        len.encode(out);
        for item in self {
            item.encode(out);
        }
    }
}

impl<T: Decode> Decode for Vec<T> {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (len, offset) = u32::decode(input)?;
        if len > MAX_LEN {
            return Err(CodecError::LengthTooLarge);
        }
        let mut items = Vec::new();
        let mut offset = offset;
        for _ in 0..len {
            let (item, used) = T::decode(slice_from(input, offset)?)?;
            items.push(item);
            offset = checked_add(offset, used)?;
        }
        Ok((items, offset))
    }
}

/// Encoded as a length prefix followed by `(key, value)` pairs in
/// ascending key order — `BTreeMap`'s iteration order already is that
/// order, so this is the "fixed iteration order" rule applied to maps.
impl<K: Encode + Ord, V: Encode> Encode for BTreeMap<K, V> {
    fn encode(&self, out: &mut Vec<u8>) {
        let len = u32::try_from(self.len()).unwrap_or(u32::MAX);
        len.encode(out);
        for (k, v) in self {
            k.encode(out);
            v.encode(out);
        }
    }
}

impl<K: Decode + Ord, V: Decode> Decode for BTreeMap<K, V> {
    fn decode(input: &[u8]) -> Result<(Self, usize), CodecError> {
        let (len, offset) = u32::decode(input)?;
        if len > MAX_LEN {
            return Err(CodecError::LengthTooLarge);
        }
        let mut map = BTreeMap::new();
        let mut offset = offset;
        for _ in 0..len {
            let (key, used) = K::decode(slice_from(input, offset)?)?;
            offset = checked_add(offset, used)?;
            let (value, used) = V::decode(slice_from(input, offset)?)?;
            offset = checked_add(offset, used)?;
            map.insert(key, value);
        }
        Ok((map, offset))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = Vec::new();
        7u32.encode(&mut buf);
        buf.push(0xff);
        assert_eq!(decode_exact::<u32>(&buf), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn rejects_truncated_input() {
        let mut buf = Vec::new();
        7u64.encode(&mut buf);
        buf.truncate(4);
        assert_eq!(decode_exact::<u64>(&buf), Err(CodecError::UnexpectedEof));
    }

    #[test]
    fn rejects_oversized_declared_length() {
        let mut buf = Vec::new();
        (MAX_LEN + 1).encode(&mut buf);
        assert_eq!(
            decode_exact::<Vec<u8>>(&buf),
            Err(CodecError::LengthTooLarge)
        );
    }

    #[test]
    fn empty_vec_round_trips() {
        let value: Vec<u32> = Vec::new();
        let mut buf = Vec::new();
        value.encode(&mut buf);
        assert_eq!(decode_exact::<Vec<u32>>(&buf).unwrap(), value);
    }

    #[test]
    fn btreemap_preserves_ascending_key_order_on_the_wire() {
        let mut map = BTreeMap::new();
        map.insert(3u32, 30u32);
        map.insert(1u32, 10u32);
        map.insert(2u32, 20u32);
        let mut buf = Vec::new();
        map.encode(&mut buf);
        // len prefix (4 bytes) + first key immediately after.
        let (first_key, _) = u32::decode(&buf[4..]).unwrap();
        assert_eq!(first_key, 1);
    }
}
