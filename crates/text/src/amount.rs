//! Amounts as people write them: tokens, not base units.
//!
//! The chain counts in whole numbers of **base units**, and so does every
//! genesis file and every transaction. A person counts in tokens. One
//! [`TICKER`] is [`BASE_UNITS_PER_TOKEN`] base units, so `1000000000` base
//! units is `1 THRY` and `1` base unit is `0.000000001 THRY`.
//!
//! **Why nine decimal places.** The fee market prices gas in whole base
//! units, with a floor of 1 per gas (`chain-modules`, `MIN_BASE_FEE`), and
//! integer rounding makes small prices sticky. The base unit therefore has to
//! be tiny next to a token for the floor not to be a real cost, which rules
//! out six decimals: a 21,000-gas call would cost at least 0.021 tokens.
//! Eighteen, as Ethereum uses, would leave a 64-bit balance able to hold only
//! about 18 tokens, and Move code conventionally keeps balances in 64 bits.
//! Nine (Sui's choice) is fine enough for the fee market and lets a supply of
//! a billion tokens fit in 64 bits.
//!
//! This is a convention for display and typing, not a rule of the protocol.
//!
//! Two properties matter more than looks:
//!
//! - **Formatting is exact.** Every base unit appears; only trailing zeros
//!   are dropped. `parse_amount(&format_amount(x))` is `x` for every `x`.
//! - **Parsing refuses anything ambiguous.** `1,5` could be one and a half
//!   or fifteen, so it is an error, not a guess. So is a tenth decimal place,
//!   which would be silently rounded away.

/// Decimal places between a token and its base unit.
pub const DECIMALS: u32 = 9;
/// Base units in one token.
pub const BASE_UNITS_PER_TOKEN: u128 = 10u128.pow(DECIMALS);
/// The token's ticker, as written after an amount.
pub const TICKER: &str = "THRY";

/// Why some text is not an amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountError {
    Empty,
    /// A character that cannot appear in an amount (including a sign or an
    /// exponent).
    InvalidCharacter(char),
    /// Nothing before or after the decimal point (`.5`, `1.`).
    MissingDigits,
    /// A comma that does not separate groups of three digits, or a comma
    /// after the decimal point. `1,5` is refused rather than guessed at.
    AmbiguousComma,
    /// More decimal places than [`DECIMALS`].
    TooManyDecimals,
    /// Does not fit in 128 bits of base units.
    TooLarge,
}

impl core::fmt::Display for AmountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("the amount is empty"),
            Self::InvalidCharacter(character) => {
                write!(f, "{character:?} cannot appear in an amount")
            }
            Self::MissingDigits => f.write_str(
                "the amount needs digits on both sides of the decimal point: write 0.5, not .5",
            ),
            Self::AmbiguousComma => f.write_str(
                "commas may only separate groups of three digits, as in 1,000: write 1.5, not 1,5",
            ),
            Self::TooManyDecimals => write!(
                f,
                "an amount has at most {DECIMALS} decimal places: anything finer would be lost"
            ),
            Self::TooLarge => f.write_str("the amount is too large"),
        }
    }
}

impl std::error::Error for AmountError {}

/// The decimal places as a width.
fn places() -> usize {
    usize::try_from(DECIMALS).unwrap_or(9)
}

/// `1234567` as `1,234,567`.
fn group_thousands(digits: &str) -> String {
    let length = digits.len();
    let mut out = String::with_capacity(length.saturating_add(length.saturating_div(3)));
    for (index, digit) in digits.chars().enumerate() {
        let remaining = length.saturating_sub(index);
        if index > 0 && remaining.checked_rem(3) == Some(0) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// `base_units` as tokens: `1500000000` is `1.5 THRY`, `1000000000000` is
/// `1,000 THRY`, `1` is `0.000000001 THRY`. Exact, with only trailing zeros
/// after the point left out.
pub fn format_amount(base_units: u128) -> String {
    let whole = base_units.checked_div(BASE_UNITS_PER_TOKEN).unwrap_or(0);
    let fraction = base_units.checked_rem(BASE_UNITS_PER_TOKEN).unwrap_or(0);
    let mut text = group_thousands(&whole.to_string());
    if fraction != 0 {
        let width = places();
        let digits = format!("{fraction:0>width$}");
        text.push('.');
        text.push_str(digits.trim_end_matches('0'));
    }
    text.push(' ');
    text.push_str(TICKER);
    text
}

/// Whole digits, optionally with `,` between groups of three.
fn whole_digits(text: &str) -> Result<String, AmountError> {
    if text.is_empty() {
        return Err(AmountError::MissingDigits);
    }
    if !text.contains(',') {
        return Ok(text.to_owned());
    }
    let mut digits = String::new();
    for (index, group) in text.split(',').enumerate() {
        let well_formed = if index == 0 {
            (1..=3).contains(&group.len())
        } else {
            group.len() == 3
        };
        if !well_formed {
            return Err(AmountError::AmbiguousComma);
        }
        digits.push_str(group);
    }
    Ok(digits)
}

/// The base units in `text`: `1.5`, `1,000`, `0.000000001` and `2 THRY` are
/// amounts. The ticker is optional and any case.
pub fn parse_amount(text: &str) -> Result<u128, AmountError> {
    let mut text = text.trim();
    let upper = text.to_ascii_uppercase();
    if let Some(number) = upper.strip_suffix(TICKER) {
        text = text.get(..number.len()).unwrap_or(text).trim_end();
    }
    if text.is_empty() {
        return Err(AmountError::Empty);
    }
    if let Some(bad) = text
        .chars()
        .find(|c| !(c.is_ascii_digit() || *c == '.' || *c == ','))
    {
        return Err(AmountError::InvalidCharacter(bad));
    }
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (text, None),
    };
    if fraction.is_some_and(|f| f.contains('.')) {
        return Err(AmountError::InvalidCharacter('.'));
    }
    if fraction.is_some_and(|f| f.contains(',')) {
        return Err(AmountError::AmbiguousComma);
    }
    let whole = whole_digits(whole)?;
    let fraction = fraction.unwrap_or("0");
    if fraction.is_empty() {
        return Err(AmountError::MissingDigits);
    }
    let width = places();
    if fraction.len() > width {
        return Err(AmountError::TooManyDecimals);
    }
    let whole: u128 = whole.parse().map_err(|_| AmountError::TooLarge)?;
    let padded = format!("{fraction:0<width$}");
    let fraction: u128 = padded.parse().map_err(|_| AmountError::TooLarge)?;
    whole
        .checked_mul(BASE_UNITS_PER_TOKEN)
        .and_then(|units| units.checked_add(fraction))
        .ok_or(AmountError::TooLarge)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;
    use proptest::prelude::*;

    #[test]
    fn amounts_read_as_tokens_with_only_the_needed_places() {
        for (base_units, text) in [
            (0, "0 THRY"),
            (1, "0.000000001 THRY"),
            (10, "0.00000001 THRY"),
            (999_999_999, "0.999999999 THRY"),
            (1_000_000_000, "1 THRY"),
            (1_500_000_000, "1.5 THRY"),
            (1_000_000_001, "1.000000001 THRY"),
            (999_000_000_000, "999 THRY"),
            (1_000_000_000_000, "1,000 THRY"),
            (1_234_567_890_123_456_789, "1,234,567,890.123456789 THRY"),
            (
                u128::MAX,
                "340,282,366,920,938,463,463,374,607,431.768211455 THRY",
            ),
        ] {
            assert_eq!(format_amount(base_units), text);
            assert_eq!(parse_amount(text).unwrap(), base_units, "{text}");
        }
    }

    #[test]
    fn the_ticker_and_the_commas_are_optional_when_typing() {
        for text in ["1.5", "1.5 THRY", "1.5THRY", " 1.5 thry ", "1.500000000"] {
            assert_eq!(parse_amount(text).unwrap(), 1_500_000_000, "{text:?}");
        }
        assert_eq!(parse_amount("1000").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_amount("1,000").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_amount("1,234,567").unwrap(), 1_234_567_000_000_000);
        assert_eq!(parse_amount("0").unwrap(), 0);
        assert_eq!(parse_amount("007").unwrap(), 7_000_000_000);
    }

    #[test]
    fn anything_ambiguous_is_refused_rather_than_guessed() {
        for (text, expected) in [
            ("", AmountError::Empty),
            ("THRY", AmountError::Empty),
            ("   ", AmountError::Empty),
            ("1,5", AmountError::AmbiguousComma),
            ("1,00", AmountError::AmbiguousComma),
            ("1,0000", AmountError::AmbiguousComma),
            (",100", AmountError::AmbiguousComma),
            ("1,,000", AmountError::AmbiguousComma),
            ("1.5,5", AmountError::AmbiguousComma),
            (".5", AmountError::MissingDigits),
            ("1.", AmountError::MissingDigits),
            (".", AmountError::MissingDigits),
            ("1.0000000001", AmountError::TooManyDecimals),
            ("-1", AmountError::InvalidCharacter('-')),
            ("+1", AmountError::InvalidCharacter('+')),
            ("1e3", AmountError::InvalidCharacter('e')),
            ("1_000", AmountError::InvalidCharacter('_')),
            ("1 000", AmountError::InvalidCharacter(' ')),
            ("1.2.3", AmountError::InvalidCharacter('.')),
            ("$5", AmountError::InvalidCharacter('$')),
            (
                "340282366920938463463374607431.768211456",
                AmountError::TooLarge,
            ),
            (
                "1000000000000000000000000000000000000000",
                AmountError::TooLarge,
            ),
        ] {
            assert_eq!(parse_amount(text), Err(expected), "{text:?}");
        }
    }

    #[test]
    fn every_error_reads_as_a_sentence() {
        for error in [
            AmountError::Empty,
            AmountError::InvalidCharacter('x'),
            AmountError::MissingDigits,
            AmountError::AmbiguousComma,
            AmountError::TooManyDecimals,
            AmountError::TooLarge,
        ] {
            let message = error.to_string();
            assert!(!message.is_empty() && !message.ends_with('.'), "{message}");
        }
    }

    proptest! {
        #[test]
        fn formatting_then_parsing_gives_back_the_same_amount(base_units in any::<u128>()) {
            prop_assert_eq!(parse_amount(&format_amount(base_units)).unwrap(), base_units);
        }

        #[test]
        fn every_base_unit_shows_in_the_text(base_units in any::<u128>()) {
            // Without the ticker, the commas and the point, the digits are
            // the amount in base units: nothing is rounded.
            let text = format_amount(base_units);
            let number = text.trim_end_matches(TICKER).trim_end();
            let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
            let whole: u128 = whole.replace(',', "").parse().unwrap();
            let fraction: u128 = format!("{fraction:0<9}").parse().unwrap();
            prop_assert_eq!(whole * BASE_UNITS_PER_TOKEN + fraction, base_units);
        }

        #[test]
        fn no_text_at_all_can_make_parsing_panic(text in ".{0,80}") {
            let _ = parse_amount(&text);
        }
    }
}
