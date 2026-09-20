//! Addresses as text: bech32m ([BIP-350]) with the prefix `thry`.
//!
//! ```text
//! thry1 qqqqqqqq…(52 characters)…  xxxxxx
//! └┬──┘ └────────┬──────────────┘  └──┬──┘
//!  │             │                    └ checksum: catches typos
//!  │             └ the 32 address bytes, 5 bits to a character
//!  └ says which chain this is for
//! ```
//!
//! Why this and not hex with a checksum in the letter case (as Ethereum does):
//! bech32m's checksum is guaranteed to catch every single-character typo and
//! every swap of two neighbours, and any burst of up to four wrong
//! characters; a case-based checksum only catches most typos, and is lost as
//! soon as the text passes through anything that changes case. The prefix
//! stops an address for another chain being accepted here. The alphabet has no
//! `1`, `b`, `i` or `o`, so the characters people confuse are not in it.
//!
//! Text may be written in all lower case or all upper case (upper case suits
//! QR codes) but not mixed, as the standard requires.
//!
//! [BIP-350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

use chain_types::Address;

/// The prefix that says an address is for this chain.
pub const ADDRESS_PREFIX: &str = "thry";

const ADDRESS_BYTES: usize = 32;
/// 32 bytes is 256 bits, which is 52 characters of 5 bits (with 4 spare).
const DATA_CHARACTERS: usize = 52;
const CHECKSUM_CHARACTERS: usize = 6;
/// `thry`, the separator, the data and the checksum.
const TEXT_CHARACTERS: usize = 4 + 1 + DATA_CHARACTERS + CHECKSUM_CHARACTERS;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [(u32, u32); 5] = [
    (1, 0x3b6a_57b2),
    (2, 0x2650_8e6d),
    (4, 0x1ea1_19fa),
    (8, 0x3d42_33dd),
    (16, 0x2a14_62b3),
];
/// What separates bech32m from the original bech32.
const BECH32M_CONSTANT: u32 = 0x2bc8_30a3;

/// Why some text is not an address, in the order a person would want to be
/// told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    /// 64 hex digits: probably a raw address or a public key, not the text
    /// form.
    LooksLikeHex,
    MixedCase,
    MissingSeparator,
    /// An address for something else.
    WrongPrefix {
        found: String,
    },
    /// `position` counts characters from 1.
    InvalidCharacter {
        character: char,
        position: usize,
    },
    /// Too short or too long: usually a copy that lost or gained something.
    WrongLength {
        found: usize,
    },
    /// The right shape, but a character is wrong somewhere.
    BadChecksum,
    /// A valid bech32m string that does not hold an address.
    NotAnAddress,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("the address is empty"),
            Self::LooksLikeHex => write!(
                f,
                "this looks like raw hex, not an address: addresses are written {ADDRESS_PREFIX}1…"
            ),
            Self::MixedCase => f.write_str("the address mixes upper and lower case"),
            Self::MissingSeparator => write!(
                f,
                "this is not an address: it should start {ADDRESS_PREFIX}1"
            ),
            Self::WrongPrefix { found } => write!(
                f,
                "this address starts {found:?}, not {ADDRESS_PREFIX:?}: it is for something else"
            ),
            Self::InvalidCharacter {
                character,
                position,
            } => write!(
                f,
                "character {position} ({character:?}) cannot appear in an address"
            ),
            Self::WrongLength { found } => write!(
                f,
                "the address is {found} characters, not {TEXT_CHARACTERS}: it looks {}",
                if *found < TEXT_CHARACTERS {
                    "truncated"
                } else {
                    "too long"
                }
            ),
            Self::BadChecksum => f.write_str(
                "the address has a typo: its checksum does not match, so a character is wrong",
            ),
            Self::NotAnAddress => f.write_str("this is not an address"),
        }
    }
}

impl std::error::Error for AddressError {}

/// The bech32 checksum: a polynomial over 5-bit values.
fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut checksum: u32 = 1;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (mask, generator) in GENERATOR {
            if top & mask != 0 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

/// The prefix as 5-bit values, the way the checksum sees it.
fn expand(prefix: &str) -> impl Iterator<Item = u8> + '_ {
    prefix
        .bytes()
        .map(|byte| byte >> 5)
        .chain(core::iter::once(0))
        .chain(prefix.bytes().map(|byte| byte & 31))
}

fn checksum(prefix: &str, data: &[u8]) -> [u8; CHECKSUM_CHARACTERS] {
    let values = expand(prefix)
        .chain(data.iter().copied())
        .chain([0u8; CHECKSUM_CHARACTERS]);
    let modulo = polymod(values) ^ BECH32M_CONSTANT;
    let mut out = [0u8; CHECKSUM_CHARACTERS];
    for (slot, shift) in out.iter_mut().zip([25u32, 20, 15, 10, 5, 0]) {
        *slot = u8::try_from((modulo >> shift) & 31).unwrap_or(0);
    }
    out
}

fn verifies(prefix: &str, values: &[u8]) -> bool {
    polymod(expand(prefix).chain(values.iter().copied())) == BECH32M_CONSTANT
}

/// Bytes as 5-bit values, padding the last with zeros.
fn to_five_bit(bytes: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(bytes.len().saturating_mul(8));
    for byte in bytes {
        for mask in [128u8, 64, 32, 16, 8, 4, 2, 1] {
            bits.push(byte & mask != 0);
        }
    }
    bits.chunks(5)
        .map(|group| {
            (0..5).fold(0u8, |value, position| {
                value.wrapping_mul(2) | u8::from(group.get(position) == Some(&true))
            })
        })
        .collect()
}

/// 5-bit values back to bytes; `None` unless the spare bits are all zero.
fn from_five_bit(values: &[u8]) -> Option<Vec<u8>> {
    let mut bits = Vec::with_capacity(values.len().saturating_mul(5));
    for value in values {
        for mask in [16u8, 8, 4, 2, 1] {
            bits.push(value & mask != 0);
        }
    }
    let whole = bits.len().checked_div(8)?.checked_mul(8)?;
    if bits.get(whole..)?.iter().any(|bit| *bit) {
        return None;
    }
    Some(
        bits.get(..whole)?
            .chunks(8)
            .map(|group| {
                group
                    .iter()
                    .fold(0u8, |byte, bit| byte.wrapping_mul(2) | u8::from(*bit))
            })
            .collect(),
    )
}

/// The text form of `address`: `thry1` and 58 more characters.
pub fn format_address(address: &Address) -> String {
    encode(ADDRESS_PREFIX, address.as_bytes())
}

fn encode(prefix: &str, bytes: &[u8]) -> String {
    let data = to_five_bit(bytes);
    let checksum = checksum(prefix, &data);
    let mut out = String::with_capacity(TEXT_CHARACTERS);
    out.push_str(prefix);
    out.push('1');
    out.extend(
        data.iter()
            .chain(checksum.iter())
            .filter_map(|value| CHARSET.get(usize::from(*value)).copied())
            .map(char::from),
    );
    out
}

/// The prefix and the 5-bit values (checksum still on) of well-formed
/// bech32 text, lower-cased; the error says what is wrong first.
fn split(text: &str) -> Result<(String, Vec<u8>), AddressError> {
    let original: Vec<char> = text.chars().collect();
    let has_lower = original.iter().any(char::is_ascii_lowercase);
    let has_upper = original.iter().any(char::is_ascii_uppercase);
    if has_lower && has_upper {
        return Err(AddressError::MixedCase);
    }
    let lower: Vec<char> = original.iter().map(char::to_ascii_lowercase).collect();
    let Some(separator) = lower.iter().rposition(|c| *c == '1') else {
        return Err(AddressError::MissingSeparator);
    };
    let invalid = |index: usize| AddressError::InvalidCharacter {
        character: original.get(index).copied().unwrap_or_default(),
        position: index.saturating_add(1),
    };
    let prefix: String = lower.get(..separator).unwrap_or_default().iter().collect();
    for (index, character) in lower.iter().enumerate().take(separator) {
        if !('!'..='~').contains(character) {
            return Err(invalid(index));
        }
    }
    let mut values = Vec::new();
    let first = separator.saturating_add(1);
    for (index, character) in lower.iter().enumerate().skip(first) {
        let value = u8::try_from(*character)
            .ok()
            .and_then(|byte| CHARSET.iter().position(|c| *c == byte))
            .and_then(|position| u8::try_from(position).ok())
            .ok_or_else(|| invalid(index))?;
        values.push(value);
    }
    Ok((prefix, values))
}

/// The address `text` names, if it is one, copied correctly.
///
/// Surrounding whitespace is ignored. The error says what is wrong in the
/// order a person would want to know: empty, raw hex, mixed case, no `1`
/// separator, another chain's prefix, a character that cannot appear,
/// truncation, and only then the checksum.
pub fn parse_address(text: &str) -> Result<Address, AddressError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    if text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AddressError::LooksLikeHex);
    }
    let (prefix, values) = split(text)?;
    if prefix != ADDRESS_PREFIX {
        return Err(AddressError::WrongPrefix { found: prefix });
    }
    let length = text.chars().count();
    if length != TEXT_CHARACTERS {
        return Err(AddressError::WrongLength { found: length });
    }
    if !verifies(&prefix, &values) {
        return Err(AddressError::BadChecksum);
    }
    let data = values
        .get(..DATA_CHARACTERS)
        .ok_or(AddressError::NotAnAddress)?;
    let bytes = from_five_bit(data).ok_or(AddressError::NotAnAddress)?;
    let bytes: [u8; ADDRESS_BYTES] = bytes.try_into().map_err(|_| AddressError::NotAnAddress)?;
    Ok(Address::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use proptest::prelude::*;

    /// The longest bech32 string the standard allows.
    const MAX_CHARACTERS: usize = 90;

    fn address(bytes: [u8; 32]) -> Address {
        Address::from_bytes(bytes)
    }

    fn some_address() -> Address {
        address(core::array::from_fn(|i| u8::try_from(i * 7 + 3).unwrap()))
    }

    /// Decodes any bech32m string: the standard's own rules, for the
    /// standard's own test vectors.
    fn decode_any(text: &str) -> Result<(String, Vec<u8>), AddressError> {
        if text.chars().count() > MAX_CHARACTERS {
            return Err(AddressError::WrongLength { found: text.len() });
        }
        let (prefix, values) = split(text)?;
        if prefix.is_empty() || values.len() < CHECKSUM_CHARACTERS {
            return Err(AddressError::NotAnAddress);
        }
        if !verifies(&prefix, &values) {
            return Err(AddressError::BadChecksum);
        }
        let cut = values.len() - CHECKSUM_CHARACTERS;
        Ok((prefix, values[..cut].to_vec()))
    }

    /// From BIP-350: strings that are valid bech32m.
    #[test]
    fn the_standards_valid_test_vectors_decode_and_encode_back() {
        for text in [
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ] {
            let (prefix, data) = decode_any(text).unwrap_or_else(|e| panic!("{text}: {e}"));
            let mut again = format!("{prefix}1");
            for value in data.iter().chain(checksum(&prefix, &data).iter()) {
                again.push(char::from(CHARSET[usize::from(*value)]));
            }
            assert_eq!(again, text.to_ascii_lowercase(), "{text}");
        }
    }

    /// From BIP-350: strings that are not valid bech32m.
    #[test]
    fn the_standards_invalid_test_vectors_are_refused() {
        for text in [
            "\u{20}1xj0phk",
            "\u{7f}1g6xzxy",
            "\u{80}1vctc34",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
            "qyrz8wqd2c9m",
            "1qyrz8wqd2c9m",
            "y1b0jsk6g",
            "lt1igcx5c0",
            "in1muywd",
            "mm1crxm3i",
            "au1s5cgom",
            "M1VUXWEZ",
            "16plkw9",
            "1p2gdwpf",
        ] {
            assert!(decode_any(text).is_err(), "{text:?} should be refused");
        }
    }

    /// Produced by the reference algorithm in BIP-350 (its Python code,
    /// which reproduces all of that standard's valid vectors), independently
    /// of this implementation.
    #[rustfmt::skip]
    const REFERENCE: [(&str, &str); 7] = [
        ("0000000000000000000000000000000000000000000000000000000000000000", "thry1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq9spsz0"),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "thry1llllllllllllllllllllllllllllllllllllllllllllllllllls8wzptc"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "thry1qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0svy2jzk"),
        ("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "thry1urs79clyuhnw068fat47em0walc0ruhn7n6ldalcl8a0hl8almlsgagmdh"),
        ("0000000000000000000000000000000000000000000000000000000000000001", "thry1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqss3fghu"),
        ("0100000000000000000000000000000000000000000000000000000000000000", "thry1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrk3xcs"),
        ("aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55", "thry14f2654d22k49t2j44f2654d22k49t2j44f2654d22k49t2j44f2scut02l"),
    ];

    fn from_hex(hex: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
    }

    #[test]
    fn addresses_match_the_reference_algorithm_both_ways() {
        for (hex, text) in REFERENCE {
            let bytes = from_hex(hex);
            assert_eq!(format_address(&address(bytes)), text);
            assert_eq!(parse_address(text).unwrap().as_bytes(), &bytes);
            assert_eq!(text.len(), TEXT_CHARACTERS);
        }
    }

    #[test]
    fn every_single_character_typo_is_caught() {
        let good = format_address(&some_address());
        let characters: Vec<char> = good.chars().collect();
        let mut tried = 0;
        // Every position after the prefix, changed to every other character
        // the alphabet has.
        for position in ADDRESS_PREFIX.len() + 1..characters.len() {
            for replacement in CHARSET.iter().map(|c| char::from(*c)) {
                if replacement == characters[position] {
                    continue;
                }
                let mut typo = characters.clone();
                typo[position] = replacement;
                let typo: String = typo.into_iter().collect();
                assert_eq!(
                    parse_address(&typo),
                    Err(AddressError::BadChecksum),
                    "{typo}"
                );
                tried += 1;
            }
        }
        assert_eq!(tried, (DATA_CHARACTERS + CHECKSUM_CHARACTERS) * 31);
    }

    #[test]
    fn swapping_two_neighbouring_characters_is_caught() {
        let good = format_address(&some_address());
        let characters: Vec<char> = good.chars().collect();
        let mut swaps = 0;
        for position in ADDRESS_PREFIX.len() + 1..characters.len() - 1 {
            if characters[position] == characters[position + 1] {
                continue;
            }
            let mut swapped = characters.clone();
            swapped.swap(position, position + 1);
            let swapped: String = swapped.into_iter().collect();
            assert_eq!(parse_address(&swapped), Err(AddressError::BadChecksum));
            swaps += 1;
        }
        assert!(swaps > 40, "{swaps}");
    }

    #[test]
    fn a_lost_or_extra_character_says_so_before_anything_about_the_checksum() {
        let good = format_address(&some_address());
        let short = &good[..good.len() - 1];
        assert_eq!(
            parse_address(short),
            Err(AddressError::WrongLength { found: 62 })
        );
        let long = format!("{good}q");
        assert_eq!(
            parse_address(&long),
            Err(AddressError::WrongLength { found: 64 })
        );
        let message = parse_address(short).unwrap_err().to_string();
        assert!(message.contains("truncated"), "{message}");
        let message = parse_address(&long).unwrap_err().to_string();
        assert!(message.contains("too long"), "{message}");
    }

    #[test]
    fn upper_case_and_padding_are_fine_but_mixed_case_is_not() {
        let good = format_address(&some_address());
        assert_eq!(
            parse_address(&good.to_ascii_uppercase()).unwrap(),
            some_address()
        );
        assert_eq!(
            parse_address(&format!("  {good}\n")).unwrap(),
            some_address(),
            "a pasted line break does no harm"
        );
        let mut mixed = good.clone();
        mixed.replace_range(6..7, &good[6..7].to_ascii_uppercase());
        assert_eq!(parse_address(&mixed), Err(AddressError::MixedCase));
    }

    #[test]
    fn text_that_is_not_an_address_says_what_it_is_instead() {
        let good = format_address(&some_address());
        let hex = "ab".repeat(32);
        for (text, expected) in [
            ("", AddressError::Empty),
            ("   ", AddressError::Empty),
            (hex.as_str(), AddressError::LooksLikeHex),
            ("nonsense", AddressError::MissingSeparator),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                AddressError::WrongPrefix { found: "bc".into() },
            ),
        ] {
            assert_eq!(parse_address(text), Err(expected), "{text:?}");
        }
        // A character outside the alphabet, and where it is.
        let mut broken: Vec<char> = good.chars().collect();
        broken[10] = 'b';
        let broken: String = broken.into_iter().collect();
        assert_eq!(
            parse_address(&broken),
            Err(AddressError::InvalidCharacter {
                character: 'b',
                position: 11
            })
        );
        let message = parse_address(&broken).unwrap_err().to_string();
        assert!(message.contains("character 11"), "{message}");
    }

    #[test]
    fn a_valid_bech32m_string_that_holds_another_kind_of_value_is_not_an_address() {
        // Right prefix, right length, right checksum, but the spare bits of
        // the last data character are not zero.
        let mut data = vec![0u8; DATA_CHARACTERS];
        *data.last_mut().unwrap() = 1;
        let mut text = format!("{ADDRESS_PREFIX}1");
        for value in data.iter().chain(checksum(ADDRESS_PREFIX, &data).iter()) {
            text.push(char::from(CHARSET[usize::from(*value)]));
        }
        assert_eq!(text.len(), TEXT_CHARACTERS);
        assert_eq!(parse_address(&text), Err(AddressError::NotAnAddress));
    }

    #[test]
    fn every_error_reads_as_a_sentence() {
        for error in [
            AddressError::Empty,
            AddressError::LooksLikeHex,
            AddressError::MixedCase,
            AddressError::MissingSeparator,
            AddressError::WrongPrefix { found: "bc".into() },
            AddressError::InvalidCharacter {
                character: 'b',
                position: 3,
            },
            AddressError::WrongLength { found: 10 },
            AddressError::BadChecksum,
            AddressError::NotAnAddress,
        ] {
            let message = error.to_string();
            assert!(!message.is_empty() && !message.ends_with('.'), "{message}");
        }
    }

    proptest! {
        #[test]
        fn any_address_survives_a_round_trip_through_text(bytes in any::<[u8; 32]>()) {
            let text = format_address(&address(bytes));
            prop_assert_eq!(text.len(), TEXT_CHARACTERS);
            prop_assert!(text.starts_with("thry1"));
            prop_assert_eq!(parse_address(&text).unwrap(), address(bytes));
        }

        #[test]
        fn no_text_at_all_can_make_parsing_panic(text in ".{0,120}") {
            let _ = parse_address(&text);
        }
    }
}
