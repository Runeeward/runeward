//! Go `time.Time` compatibility: `RFC3339Nano` formatting, the parser behind
//! `Time.UnmarshalJSON`, and Go's zero time.
//!
//! Record hashes cover the formatted timestamp, so formatting must match Go
//! byte for byte. Timestamps keep the offset they were written with (Go's JSON
//! encoding preserves the location), while hashing always uses UTC.

use chrono::{DateTime, Datelike, FixedOffset, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};

/// A timestamp as Go's JSON encoding round-trips it: an instant plus the
/// offset it was recorded in.
pub type Time = DateTime<FixedOffset>;

/// Go's zero `time.Time` (January 1, year 1, 00:00:00 UTC). An event whose
/// time is zero is stamped with the current time on append, as in Go.
pub fn zero() -> Time {
    NaiveDate::from_ymd_opt(1, 1, 1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|n| Utc.from_utc_datetime(&n).fixed_offset())
        .unwrap_or_default()
}

/// Reports whether t is Go's zero instant, regardless of its offset.
pub fn is_zero(t: &Time) -> bool {
    t.naive_utc() == zero().naive_utc()
}

/// The current time in UTC, as Go's `time.Now().UTC()`.
pub fn now() -> Time {
    Utc::now().fixed_offset()
}

/// Formats t like Go's `t.Format(time.RFC3339Nano)`: trailing fraction zeros
/// are stripped, no fraction is written when it is zero, and a zero offset is
/// written as `Z`.
pub fn format_rfc3339_nano(t: &Time) -> String {
    let local = t.naive_local();
    let mut out = String::with_capacity(35);
    push_year(&mut out, local.year());
    push2(&mut out, '-', local.month());
    push2(&mut out, '-', local.day());
    push2(&mut out, 'T', local.hour());
    push2(&mut out, ':', local.minute());
    push2(&mut out, ':', local.second());
    let nanos = local.nanosecond().min(999_999_999);
    if nanos > 0 {
        let frac = format!("{nanos:09}");
        out.push('.');
        out.push_str(frac.trim_end_matches('0'));
    }
    let offset = t.offset().local_minus_utc();
    if offset == 0 {
        out.push('Z');
    } else {
        // Go truncates the offset to whole minutes when formatting.
        let mut zone = offset / 60;
        if zone < 0 {
            out.push('-');
            zone = -zone;
        } else {
            out.push('+');
        }
        out.push_str(&format!("{:02}:{:02}", zone / 60, zone % 60));
    }
    out
}

/// Formats t in UTC; this is the form record hashes cover.
pub fn format_utc(t: &Time) -> String {
    format_rfc3339_nano(&t.with_timezone(&Utc).fixed_offset())
}

/// Go writes the year zero-padded to four digits, with a leading minus for
/// negative years and more digits past 9999.
fn push_year(out: &mut String, year: i32) {
    if year < 0 {
        out.push('-');
    }
    out.push_str(&format!("{:04}", year.unsigned_abs()));
}

fn push2(out: &mut String, sep: char, v: u32) {
    out.push(sep);
    out.push_str(&format!("{v:02}"));
}

/// An RFC 3339 timestamp Go would also reject.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("parsing time {input:?} as RFC3339: {reason}")]
pub struct ParseTimeError {
    input: String,
    reason: &'static str,
}

/// Parses s as Go's `Time.UnmarshalJSON` does: strict RFC 3339 first, then
/// the lenient `time.Parse(time.RFC3339, s)` fallback, which also accepts a
/// one-digit hour, a comma before the fraction, and zone offsets up to
/// `24:60`. `T` and `Z` must be upper case; more than nine fraction digits are
/// truncated.
pub fn parse_rfc3339(s: &str) -> Result<Time, ParseTimeError> {
    let fail = |reason| ParseTimeError {
        input: s.to_owned(),
        reason,
    };
    let mut cur = Cursor { b: s.as_bytes() };

    let year = cur.fixed(4).ok_or_else(|| fail("bad year"))?;
    cur.lit(b'-').ok_or_else(|| fail("expected '-'"))?;
    let month = cur.fixed(2).ok_or_else(|| fail("bad month"))?;
    cur.lit(b'-').ok_or_else(|| fail("expected '-'"))?;
    let day = cur.fixed(2).ok_or_else(|| fail("bad day"))?;
    cur.lit(b'T').ok_or_else(|| fail("expected 'T'"))?;
    let hour = cur.hour().ok_or_else(|| fail("bad hour"))?;
    cur.lit(b':').ok_or_else(|| fail("expected ':'"))?;
    let minute = cur.fixed(2).ok_or_else(|| fail("bad minute"))?;
    cur.lit(b':').ok_or_else(|| fail("expected ':'"))?;
    let second = cur.fixed(2).ok_or_else(|| fail("bad second"))?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(fail("time out of range"));
    }

    let mut nanos = 0u32;
    if cur.b.len() >= 2 && matches!(cur.b[0], b'.' | b',') && cur.b[1].is_ascii_digit() {
        let n = 1 + cur.b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        // Go keeps at most nine digits and scales shorter fractions up.
        let digits = &cur.b[1..n.min(10)];
        for i in 0..9 {
            nanos = nanos * 10 + digits.get(i).map_or(0, |d| u32::from(d - b'0'));
        }
        cur.b = &cur.b[n..];
    }

    let offset = match cur.b {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), h1, h2, b':', m1, m2] => {
            let hh = two_digits(*h1, *h2).ok_or_else(|| fail("bad zone offset"))?;
            let mm = two_digits(*m1, *m2).ok_or_else(|| fail("bad zone offset"))?;
            if hh > 24 || mm > 60 {
                return Err(fail("zone offset out of range"));
            }
            let secs = i32::try_from((hh * 60 + mm) * 60).map_err(|_| fail("bad zone offset"))?;
            if *sign == b'-' { -secs } else { secs }
        }
        _ => return Err(fail("bad zone")),
    };

    let date = i32::try_from(year)
        .ok()
        .and_then(|y| NaiveDate::from_ymd_opt(y, month, day))
        .ok_or_else(|| fail("day out of range"))?;
    let naive: NaiveDateTime = date
        .and_hms_nano_opt(hour, minute, second, nanos)
        .ok_or_else(|| fail("time out of range"))?;
    // chrono cannot represent an offset of a full day, which Go's lenient
    // parser would accept ("+24:00").
    let zone = FixedOffset::east_opt(offset).ok_or_else(|| fail("zone offset out of range"))?;
    zone.from_local_datetime(&naive)
        .single()
        .ok_or_else(|| fail("time out of range"))
}

fn two_digits(a: u8, b: u8) -> Option<u32> {
    (a.is_ascii_digit() && b.is_ascii_digit())
        .then(|| u32::from(a - b'0') * 10 + u32::from(b - b'0'))
}

struct Cursor<'a> {
    b: &'a [u8],
}

impl Cursor<'_> {
    /// Consumes exactly n ASCII digits.
    fn fixed(&mut self, n: usize) -> Option<u32> {
        let digits = self.b.get(..n)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        self.b = &self.b[n..];
        Some(
            digits
                .iter()
                .fold(0, |acc, d| acc * 10 + u32::from(d - b'0')),
        )
    }

    /// Go's fallback parser reads the hour as one or two digits.
    fn hour(&mut self) -> Option<u32> {
        match self.b {
            [a, b, ..] if a.is_ascii_digit() && b.is_ascii_digit() => self.fixed(2),
            [a, ..] if a.is_ascii_digit() => self.fixed(1),
            _ => None,
        }
    }

    fn lit(&mut self, c: u8) -> Option<()> {
        let (&first, rest) = self.b.split_first()?;
        (first == c).then(|| self.b = rest)
    }
}

/// Serializes a timestamp as Go's `Time.MarshalJSON`, which refuses years
/// outside `[0, 9999]`.
pub(crate) fn serialize<S: serde::Serializer>(t: &Time, s: S) -> Result<S::Ok, S::Error> {
    let year = t.naive_local().year();
    if !(0..=9999).contains(&year) {
        return Err(serde::ser::Error::custom(
            "Time.MarshalJSON: year outside of range [0,9999]",
        ));
    }
    s.serialize_str(&format_rfc3339_nano(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Time {
        parse_rfc3339(s).unwrap_or_else(|e| panic!("{e}"))
    }

    // Expected values were produced by Go 1.26 (json.Marshal of the parsed
    // time, and t.UTC().Format(time.RFC3339Nano)).
    #[test]
    fn round_trips_like_go() {
        let cases = [
            (
                "2026-10-19T12:00:00.100000000+05:30",
                "2026-10-19T12:00:00.1+05:30",
                "2026-10-19T06:30:00.1Z",
            ),
            (
                "2026-10-19T12:00:00-00:00",
                "2026-10-19T12:00:00Z",
                "2026-10-19T12:00:00Z",
            ),
            (
                "2026-10-19T12:00:00+00:00",
                "2026-10-19T12:00:00Z",
                "2026-10-19T12:00:00Z",
            ),
            (
                "0001-01-01T00:00:00Z",
                "0001-01-01T00:00:00Z",
                "0001-01-01T00:00:00Z",
            ),
            (
                "2026-10-19T1:00:00Z",
                "2026-10-19T01:00:00Z",
                "2026-10-19T01:00:00Z",
            ),
            (
                "2026-10-19T12:00:00.1234567891Z",
                "2026-10-19T12:00:00.123456789Z",
                "2026-10-19T12:00:00.123456789Z",
            ),
            (
                "2026-10-19T12:00:00,5Z",
                "2026-10-19T12:00:00.5Z",
                "2026-10-19T12:00:00.5Z",
            ),
            (
                "2026-10-19T13:00:03+01:00",
                "2026-10-19T13:00:03+01:00",
                "2026-10-19T12:00:03Z",
            ),
            (
                "2026-10-19T12:00:02.000001Z",
                "2026-10-19T12:00:02.000001Z",
                "2026-10-19T12:00:02.000001Z",
            ),
        ];
        for (input, json, utc) in cases {
            let t = parse(input);
            assert_eq!(format_rfc3339_nano(&t), json, "{input}");
            assert_eq!(format_utc(&t), utc, "{input}");
        }
    }

    #[test]
    fn rejects_what_go_rejects() {
        for bad in [
            "2026-10-19t12:00:00Z",
            "2026-10-19T12:00:00z",
            "2026-10-19T12:00:00.Z",
            "2026-02-30T12:00:00Z",
            "2026-10-19T24:00:00Z",
            "2026-10-19T12:00:60Z",
            "2026-10-19T12:00:00",
            "2026-10-19T12:00:00+0100",
            "2026-10-19T12:00:00Z ",
            "26-10-19T12:00:00Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn zero_time_and_out_of_range_years() {
        assert!(is_zero(&zero()));
        assert!(is_zero(&parse("0001-01-01T01:00:00+01:00")));
        assert!(!is_zero(&now()));
        let neg = NaiveDate::from_ymd_opt(-5, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|n| Utc.from_utc_datetime(&n).fixed_offset())
            .expect("date");
        assert_eq!(format_rfc3339_nano(&neg), "-0005-01-01T00:00:00Z");
        assert!(serde_json::to_string(&Wrap(neg)).is_err());
        // Offsets with seconds are truncated to minutes, as in Go.
        let zone = FixedOffset::west_opt(3600 * 5 + 30 * 60 + 15).expect("zone");
        let far = zone
            .from_local_datetime(
                &NaiveDate::from_ymd_opt(12000, 1, 1)
                    .and_then(|d| d.and_hms_opt(0, 0, 0))
                    .expect("date"),
            )
            .single()
            .expect("time");
        assert_eq!(format_rfc3339_nano(&far), "12000-01-01T00:00:00-05:30");
    }

    #[derive(serde::Serialize)]
    struct Wrap(#[serde(serialize_with = "serialize")] Time);
}
