//! Lowercase hexadecimal, for the byte strings the interface shows (hashes,
//! transactions, signatures). Input may carry a `0x` prefix and either case.

/// `bytes` as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // A nibble is always below 16, so `from_digit` always answers.
        out.extend(char::from_digit(u32::from(byte >> 4), 16));
        out.extend(char::from_digit(u32::from(byte & 0x0f), 16));
    }
    out
}

/// Why a string is not hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// A character that is not a hex digit.
    NotHex,
    /// An odd number of digits.
    OddLength,
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotHex => f.write_str("contains a character that is not a hex digit"),
            Self::OddLength => f.write_str("has an odd number of hex digits"),
        }
    }
}

impl std::error::Error for HexError {}

fn digit(byte: u8) -> Option<u8> {
    // ASCII-only: `char::from(u8)` maps a byte above 0x7f to a non-digit.
    char::from(byte)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

/// The bytes `text` spells, with or without a `0x` prefix.
pub fn decode(text: &str) -> Result<Vec<u8>, HexError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    bytes
        .chunks_exact(2)
        .map(|pair| match pair {
            [high, low] => match (digit(*high), digit(*low)) {
                (Some(high), Some(low)) => Ok(high << 4 | low),
                _ => Err(HexError::NotHex),
            },
            _ => Err(HexError::OddLength),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
        assert_eq!(encode(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn a_prefix_and_capitals_are_accepted_and_nothing_else_is() {
        assert_eq!(decode("0xAbCd").unwrap(), vec![0xab, 0xcd]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(decode("zz"), Err(HexError::NotHex));
        assert_eq!(decode("ab cd"), Err(HexError::OddLength));
        assert_eq!(decode("ab  cd"), Err(HexError::NotHex));
        assert_eq!(decode("0x0x00"), Err(HexError::NotHex));
    }
}
