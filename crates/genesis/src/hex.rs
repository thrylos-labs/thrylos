//! Hexadecimal, strictly: what a genesis file spells keys, proofs and
//! hashes in.
//!
//! Accepts an optional `0x` prefix and either case, and nothing else — no
//! whitespace, no separators, no odd lengths — and the length must be
//! exactly the one asked for, so a truncated or padded key is an error
//! rather than a different key.

use core::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// A character that is not a hexadecimal digit.
    InvalidDigit,
    /// An odd number of digits.
    OddLength,
    /// The wrong number of bytes.
    WrongLength { expected: usize, found: usize },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidDigit => f.write_str("not a hexadecimal digit"),
            Self::OddLength => f.write_str("an odd number of hexadecimal digits"),
            Self::WrongLength { expected, found } => {
                write!(f, "expected {expected} bytes, found {found}")
            }
        }
    }
}

impl std::error::Error for HexError {}

fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => digit.checked_sub(b'0'),
        b'a'..=b'f' => digit.checked_sub(b'a')?.checked_add(10),
        b'A'..=b'F' => digit.checked_sub(b'A')?.checked_add(10),
        _ => None,
    }
}

/// Decodes exactly `N` bytes.
pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let digits = text.strip_prefix("0x").unwrap_or(text).as_bytes();
    if digits.iter().any(|d| nibble(*d).is_none()) {
        return Err(HexError::InvalidDigit);
    }
    let pairs = digits.chunks_exact(2);
    if !pairs.remainder().is_empty() {
        return Err(HexError::OddLength);
    }
    let found = digits.len().checked_div(2).unwrap_or(0);
    if found != N {
        return Err(HexError::WrongLength { expected: N, found });
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(pairs) {
        if let [high, low] = pair {
            let (Some(high), Some(low)) = (nibble(*high), nibble(*low)) else {
                return Err(HexError::InvalidDigit);
            };
            *slot = high
                .checked_mul(16)
                .and_then(|shifted| shifted.checked_add(low))
                .ok_or(HexError::InvalidDigit)?;
        }
    }
    Ok(out)
}

/// Lowercase, with no prefix.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn decodes_either_case_with_or_without_the_prefix() {
        assert_eq!(decode::<2>("0aFf"), Ok([0x0a, 0xff]));
        assert_eq!(decode::<2>("0x0aff"), Ok([0x0a, 0xff]));
        assert_eq!(
            decode::<2>("0X0aff"),
            Err(HexError::InvalidDigit),
            "only 0x"
        );
    }

    #[test]
    fn refuses_anything_that_is_not_exactly_n_bytes_of_hex() {
        assert_eq!(
            decode::<2>("0aff00"),
            Err(HexError::WrongLength {
                expected: 2,
                found: 3
            })
        );
        assert_eq!(
            decode::<2>("0a"),
            Err(HexError::WrongLength {
                expected: 2,
                found: 1
            })
        );
        assert_eq!(
            decode::<2>(""),
            Err(HexError::WrongLength {
                expected: 2,
                found: 0
            })
        );
        assert_eq!(decode::<2>("0af"), Err(HexError::OddLength));
        assert_eq!(decode::<2>("0agf"), Err(HexError::InvalidDigit));
        assert_eq!(decode::<2>(" 0aff"), Err(HexError::InvalidDigit));
        assert_eq!(decode::<2>("0a ff"), Err(HexError::InvalidDigit));
        assert_eq!(decode::<2>("0a\nff"), Err(HexError::InvalidDigit));
        assert_eq!(decode::<0>(""), Ok([]));
    }

    #[test]
    fn a_multibyte_character_is_an_invalid_digit_not_a_panic() {
        assert_eq!(decode::<2>("0aé"), Err(HexError::InvalidDigit));
    }

    #[test]
    fn encodes_lowercase_without_a_prefix_and_round_trips() {
        assert_eq!(encode(&[0x0a, 0xff, 0x00]), "0aff00");
        let bytes: Vec<u8> = (0..=255).collect();
        let text = encode(&bytes);
        assert_eq!(text.len(), 512);
        let back = decode::<256>(&text).unwrap();
        assert_eq!(back.as_slice(), bytes.as_slice());
    }
}
