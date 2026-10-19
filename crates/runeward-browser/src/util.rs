//! Small Go formatting helpers for error messages.

use std::time::Duration;

/// Quotes s roughly like Go's `%q`.
pub(crate) fn go_quote(s: &str) -> String {
    format!("{s:?}")
}

/// Formats d like Go's `time.Duration.String` (`30s`, `1.5s`, `100ms`,
/// `1m30s`, `2h0m0s`).
pub(crate) fn go_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns == 0 {
        return "0s".to_owned();
    }
    if ns < 1_000 {
        return format!("{ns}ns");
    }
    if ns < 1_000_000 {
        return format!("{}µs", frac(ns, 1_000));
    }
    if ns < 1_000_000_000 {
        return format!("{}ms", frac(ns, 1_000_000));
    }
    const MIN: u128 = 60 * 1_000_000_000;
    const HOUR: u128 = 60 * MIN;
    let (h, m, s) = (ns / HOUR, (ns % HOUR) / MIN, ns % MIN);
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    out.push_str(&format!("{}s", frac(s, 1_000_000_000)));
    out
}

/// v / unit with the remainder as a trimmed decimal fraction.
fn frac(v: u128, unit: u128) -> String {
    let (int, rem) = (v / unit, v % unit);
    if rem == 0 {
        return int.to_string();
    }
    let width = unit.ilog10() as usize;
    let digits = format!("{rem:0width$}");
    format!("{int}.{}", digits.trim_end_matches('0'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_like_go() {
        for (d, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(5), "5ns"),
            (Duration::from_nanos(1_500), "1.5µs"),
            (Duration::from_millis(100), "100ms"),
            (Duration::from_millis(1_500), "1.5s"),
            (Duration::from_secs(30), "30s"),
            (Duration::from_secs(90), "1m30s"),
            (Duration::from_secs(7200), "2h0m0s"),
            (Duration::from_nanos(3_600_000_000_001), "1h0m0.000000001s"),
        ] {
            assert_eq!(go_duration(d), want);
        }
    }
}
