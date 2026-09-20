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
}
