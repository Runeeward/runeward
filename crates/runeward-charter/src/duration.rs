//! Go `time.ParseDuration` syntax for Charter durations.
//!
//! Charters written for the Go implementation use Go duration strings
//! (`"90s"`, `"1h30m"`, `"1.5h"`, `"300ms"`), whose grammar differs from
//! humantime's: units are mandatory except for a bare `"0"`, fractions apply to
//! any unit, units concatenate without spaces, and a sign is allowed. This is a
//! direct port so the same strings are accepted and rejected.

use std::time::Duration;

/// A duration string did not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DurationError {
    #[error("time: invalid duration {0:?}")]
    Invalid(String),
    #[error("time: missing unit in duration {0:?}")]
    MissingUnit(String),
    #[error("time: unknown unit {unit:?} in duration {input:?}")]
    UnknownUnit { unit: String, input: String },
}

const NANOS_PER_SEC: u64 = 1_000_000_000;
const LIMIT: u64 = 1 << 63;

fn unit_nanos(unit: &str) -> Option<u64> {
    Some(match unit {
        "ns" => 1,
        // Go accepts the ASCII spelling, the micro sign and the Greek mu.
        "us" | "\u{00b5}s" | "\u{03bc}s" => 1_000,
        "ms" => 1_000_000,
        "s" => NANOS_PER_SEC,
        "m" => 60 * NANOS_PER_SEC,
        "h" => 3600 * NANOS_PER_SEC,
        _ => return None,
    })
}

/// Parses a Go duration string into signed nanoseconds, exactly as Go's
/// `time.ParseDuration` does (including its overflow limits).
pub fn parse_go_duration(input: &str) -> Result<i64, DurationError> {
    let invalid = || DurationError::Invalid(input.to_owned());
    let mut s = input;
    let mut neg = false;
    if let Some(rest) = s.strip_prefix('-') {
        neg = true;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(invalid());
    }

    let mut total: u64 = 0;
    while !s.is_empty() {
        let first = s.as_bytes()[0];
        if !(first == b'.' || first.is_ascii_digit()) {
            return Err(invalid());
        }
        let before = s.len();
        let (whole, rest) = leading_int(s).ok_or_else(invalid)?;
        s = rest;
        let pre = before != s.len();

        let (mut frac, mut scale, mut post) = (0u64, 1f64, false);
        if let Some(rest) = s.strip_prefix('.') {
            let before = rest.len();
            let (f, sc, rest) = leading_fraction(rest);
            (frac, scale, s) = (f, sc, rest);
            post = before != s.len();
        }
        if !pre && !post {
            return Err(invalid());
        }

        let end = s
            .bytes()
            .position(|c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if end == 0 {
            return Err(DurationError::MissingUnit(input.to_owned()));
        }
        let (unit_str, rest) = s.split_at(end);
        s = rest;
        let unit = unit_nanos(unit_str).ok_or_else(|| DurationError::UnknownUnit {
            unit: unit_str.to_owned(),
            input: input.to_owned(),
        })?;

        if whole > LIMIT / unit {
            return Err(invalid());
        }
        let mut v = whole * unit;
        if frac > 0 {
            // Matches Go's float arithmetic so rounding is identical.
            let extra = (frac as f64 * (unit as f64 / scale)) as u64;
            v = v.checked_add(extra).ok_or_else(invalid)?;
            if v > LIMIT {
                return Err(invalid());
            }
        }
        total = total.checked_add(v).ok_or_else(invalid)?;
        if total > LIMIT {
            return Err(invalid());
        }
    }

    if neg {
        // total <= 2^63, so the negation always fits.
        return Ok(0i64.wrapping_sub_unsigned(total));
    }
    i64::try_from(total).map_err(|_| invalid())
}

/// Parses a Go duration string into a [`Duration`].
///
/// Negative values clamp to zero: Go callers treat any non-positive limit as
/// "unset", and a [`Duration`] cannot be negative.
pub fn parse_duration(input: &str) -> Result<Duration, DurationError> {
    let nanos = parse_go_duration(input)?;
    Ok(Duration::from_nanos(u64::try_from(nanos).unwrap_or(0)))
}

/// Consumes leading decimal digits, failing on overflow past 2^63.
fn leading_int(s: &str) -> Option<(u64, &str)> {
    let end = s
        .bytes()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(s.len());
    let mut x: u64 = 0;
    for c in s[..end].bytes() {
        if x > LIMIT / 10 {
            return None;
        }
        x = x * 10 + u64::from(c - b'0');
        if x > LIMIT {
            return None;
        }
    }
    Some((x, &s[end..]))
}

/// Consumes fractional digits, silently dropping precision on overflow.
fn leading_fraction(s: &str) -> (u64, f64, &str) {
    let end = s
        .bytes()
        .position(|c| !c.is_ascii_digit())
        .unwrap_or(s.len());
    let (mut x, mut scale, mut overflow) = (0u64, 1f64, false);
    for c in s[..end].bytes() {
        if overflow {
            continue;
        }
        if x > (LIMIT - 1) / 10 {
            overflow = true;
            continue;
        }
        let y = x * 10 + u64::from(c - b'0');
        if y > LIMIT {
            overflow = true;
            continue;
        }
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i64 = 1_000_000;
    const S: i64 = 1_000 * MS;

    #[test]
    fn accepts_go_syntax() {
        let cases: &[(&str, i64)] = &[
            ("0", 0),
            ("+0", 0),
            ("-0", 0),
            ("5s", 5 * S),
            ("30m", 30 * 60 * S),
            ("90s", 90 * S),
            ("1h30m", 90 * 60 * S),
            ("1.5h", 90 * 60 * S),
            ("300ms", 300 * MS),
            ("-1.5h", -90 * 60 * S),
            ("+5s", 5 * S),
            (".5s", 500 * MS),
            ("1.s", S),
            ("1.004s", 1004 * MS),
            ("100.00100s", 100 * S + MS),
            ("10ns", 10),
            ("11us", 11_000),
            ("12µs", 12_000),
            ("12μs", 12_000),
            ("3h2m1.5s", 3 * 3600 * S + 2 * 60 * S + 1500 * MS),
            ("0.3333333333333333333h", 20 * 60 * S),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
            ("9223372036.854775807s", i64::MAX),
            ("0.100000000000000000000h", 6 * 60 * S),
            ("9223372036854775807.1ns", i64::MAX),
            ("1.9999999999999999999999ns", 2),
        ];
        for (input, want) in cases {
            assert_eq!(parse_go_duration(input), Ok(*want), "{input}");
        }
    }

    #[test]
    fn rejects_what_go_rejects() {
        for input in [
            "",
            "3",
            "-",
            "s",
            ".",
            "-.",
            ".s",
            "+.s",
            "1d",
            "1 s",
            "1h ",
            "x1s",
            "9223372036854775808ns",
            "9223372036.854775808s",
            "3000000h",
        ] {
            assert!(parse_go_duration(input).is_err(), "{input:?} should fail");
        }
        assert_eq!(
            parse_go_duration("3").expect_err("must fail").to_string(),
            r#"time: missing unit in duration "3""#
        );
        assert_eq!(
            parse_go_duration("1d").expect_err("must fail").to_string(),
            r#"time: unknown unit "d" in duration "1d""#
        );
        assert_eq!(
            parse_go_duration("").expect_err("must fail").to_string(),
            r#"time: invalid duration """#
        );
    }

    #[test]
    fn std_duration_clamps_negative() {
        assert_eq!(parse_duration("1m30s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("-5m"), Ok(Duration::ZERO));
    }
}
