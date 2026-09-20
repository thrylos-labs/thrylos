//! Numbers as people read them: durations in days and hours, basis points as
//! percentages. Presentation only; nothing here feeds the chain.

/// `ms` as whole days, hours, minutes, seconds and milliseconds, largest
/// first, leaving out the units that are zero: `21 d`, `1 h 30 min`.
pub fn duration(ms: u64) -> String {
    const UNITS: [(&str, u64); 5] = [
        ("d", 86_400_000),
        ("h", 3_600_000),
        ("min", 60_000),
        ("s", 1_000),
        ("ms", 1),
    ];
    let mut rest = ms;
    let mut parts = Vec::new();
    for (name, size) in UNITS {
        let count = rest.checked_div(size).unwrap_or(0);
        rest = rest.checked_rem(size).unwrap_or(0);
        if count > 0 {
            parts.push(format!("{count} {name}"));
        }
    }
    if parts.is_empty() {
        "0 ms".to_owned()
    } else {
        parts.join(" ")
    }
}

/// Basis points as a percentage with two decimals: `3340` is `33.40%`.
pub fn percent_bps(bps: u128) -> String {
    let whole = bps.checked_div(100).unwrap_or(0);
    let fraction = bps.checked_rem(100).unwrap_or(0);
    format!("{whole}.{fraction:02}%")
}

fn div(numerator: u64, denominator: u64) -> u64 {
    numerator.checked_div(denominator).unwrap_or(0)
}

fn rem(numerator: u64, denominator: u64) -> u64 {
    numerator.checked_rem(denominator).unwrap_or(0)
}

/// `ms` since the Unix epoch as a UTC date and time: `1700000000000` is
/// `2023-11-14 22:13:20 UTC`, and milliseconds appear only when there are
/// some. The proleptic Gregorian calendar, by the days-to-civil-date
/// algorithm (H. Hinnant, public domain), which needs no date library.
pub fn utc_date_time(ms: u64) -> String {
    let millis = rem(ms, 1_000);
    let seconds = div(ms, 1_000);
    let second_of_day = rem(seconds, 86_400);
    let days = div(seconds, 86_400);

    // Days since 0000-03-01, split into 400-year eras.
    let shifted = days.saturating_add(719_468);
    let era = div(shifted, 146_097);
    let day_of_era = shifted.saturating_sub(era.saturating_mul(146_097));
    let year_of_era = div(
        day_of_era
            .saturating_sub(div(day_of_era, 1_460))
            .saturating_add(div(day_of_era, 36_524))
            .saturating_sub(div(day_of_era, 146_096)),
        365,
    );
    let day_of_year = day_of_era.saturating_sub(
        year_of_era
            .saturating_mul(365)
            .saturating_add(div(year_of_era, 4))
            .saturating_sub(div(year_of_era, 100)),
    );
    // Months counted from March, so the leap day is the last day of the year.
    let month_from_march = div(day_of_year.saturating_mul(5).saturating_add(2), 153);
    let day = day_of_year
        .saturating_sub(div(
            month_from_march.saturating_mul(153).saturating_add(2),
            5,
        ))
        .saturating_add(1);
    let month = if month_from_march < 10 {
        month_from_march.saturating_add(3)
    } else {
        month_from_march.saturating_sub(9)
    };
    let year = year_of_era
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(month <= 2));

    let (hour, minute, second) = (
        div(second_of_day, 3_600),
        div(rem(second_of_day, 3_600), 60),
        rem(second_of_day, 60),
    );
    let fraction = if millis == 0 {
        String::new()
    } else {
        format!(".{millis:03}")
    };
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}{fraction} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_use_the_units_they_need_and_no_others() {
        assert_eq!(duration(0), "0 ms");
        assert_eq!(duration(1), "1 ms");
        assert_eq!(duration(1_000), "1 s");
        assert_eq!(duration(90 * 60_000), "1 h 30 min");
        assert_eq!(duration(1_814_400_000), "21 d");
        assert_eq!(duration(86_400_000 + 1), "1 d 1 ms");
        assert_eq!(
            duration(2 * 86_400_000 + 3 * 3_600_000 + 4 * 60_000 + 5_006),
            "2 d 3 h 4 min 5 s 6 ms"
        );
        assert_eq!(duration(u64::MAX), "213503982334 d 14 h 25 min 51 s 615 ms");
    }

    #[test]
    fn basis_points_read_as_percentages_with_two_decimals() {
        assert_eq!(percent_bps(0), "0.00%");
        assert_eq!(percent_bps(1), "0.01%");
        assert_eq!(percent_bps(400), "4.00%");
        assert_eq!(percent_bps(3_340), "33.40%");
        assert_eq!(percent_bps(10_000), "100.00%");
        assert_eq!(percent_bps(12_345), "123.45%");
    }

    /// Expected values from Python's `datetime`, an independent calendar:
    /// leap days, the century that is not a leap year (2100) and the one that
    /// is (2000, 2400), every month start of two years, and the edges of a
    /// second, a day and a year.
    #[test]
    fn dates_match_an_independent_calendar() {
        for (ms, expected) in [
            (0, "1970-01-01 00:00:00 UTC"),
            (1, "1970-01-01 00:00:00.001 UTC"),
            (999, "1970-01-01 00:00:00.999 UTC"),
            (1000, "1970-01-01 00:00:01 UTC"),
            (86399999, "1970-01-01 23:59:59.999 UTC"),
            (86400000, "1970-01-02 00:00:00 UTC"),
            (946684799999, "1999-12-31 23:59:59.999 UTC"),
            (946684800000, "2000-01-01 00:00:00 UTC"),
            (951696000000, "2000-02-28 00:00:00 UTC"),
            (951782400000, "2000-02-29 00:00:00 UTC"),
            (951868800000, "2000-03-01 00:00:00 UTC"),
            (1700000000000, "2023-11-14 22:13:20 UTC"),
            (1709164799000, "2024-02-28 23:59:59 UTC"),
            (1709208000000, "2024-02-29 12:00:00 UTC"),
            (1709251200000, "2024-03-01 00:00:00 UTC"),
            (1735689599500, "2024-12-31 23:59:59.500 UTC"),
            (1735689600000, "2025-01-01 00:00:00 UTC"),
            (4102444800000, "2100-01-01 00:00:00 UTC"),
            (4107456000000, "2100-02-28 00:00:00 UTC"),
            (4107542400000, "2100-03-01 00:00:00 UTC"),
            (13574563200000, "2400-02-29 00:00:00 UTC"),
            (13574649600000, "2400-03-01 00:00:00 UTC"),
            (253402300799999, "9999-12-31 23:59:59.999 UTC"),
            (1672531200000, "2023-01-01 00:00:00 UTC"),
            (1675209600000, "2023-02-01 00:00:00 UTC"),
            (1677628800000, "2023-03-01 00:00:00 UTC"),
            (1680307200000, "2023-04-01 00:00:00 UTC"),
            (1682899200000, "2023-05-01 00:00:00 UTC"),
            (1685577600000, "2023-06-01 00:00:00 UTC"),
            (1688169600000, "2023-07-01 00:00:00 UTC"),
            (1690848000000, "2023-08-01 00:00:00 UTC"),
            (1693526400000, "2023-09-01 00:00:00 UTC"),
            (1696118400000, "2023-10-01 00:00:00 UTC"),
            (1698796800000, "2023-11-01 00:00:00 UTC"),
            (1701388800000, "2023-12-01 00:00:00 UTC"),
            (1704067200000, "2024-01-01 00:00:00 UTC"),
            (1706745600000, "2024-02-01 00:00:00 UTC"),
            (1711929600000, "2024-04-01 00:00:00 UTC"),
            (1714521600000, "2024-05-01 00:00:00 UTC"),
            (1717200000000, "2024-06-01 00:00:00 UTC"),
            (1719792000000, "2024-07-01 00:00:00 UTC"),
            (1722470400000, "2024-08-01 00:00:00 UTC"),
            (1725148800000, "2024-09-01 00:00:00 UTC"),
            (1727740800000, "2024-10-01 00:00:00 UTC"),
            (1730419200000, "2024-11-01 00:00:00 UTC"),
            (1733011200000, "2024-12-01 00:00:00 UTC"),
        ] {
            assert_eq!(utc_date_time(ms), expected, "{ms}");
        }
    }

    #[test]
    fn the_largest_time_does_not_panic_and_still_reads_as_a_date() {
        let text = utc_date_time(u64::MAX);
        assert!(
            text.ends_with(" UTC") && text.contains('-') && text.contains(':'),
            "{text}"
        );
    }
}
