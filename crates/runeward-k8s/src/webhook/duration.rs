//! A port of Go's `time.ParseDuration`, so `RUNEWARD_WEBHOOK_POLICY_CACHE_TTL`
//! accepts exactly the values the Go webhook accepted (`10m`, `1h30m`,
//! `1.5h`, `500ms`, `-1s`, ...).

/// Parses a Go duration string into signed nanoseconds. Returns `None` where
/// Go returns an error.
pub(crate) fn parse_go_duration(s: &str) -> Option<i128> {
    const LIMIT: u64 = 1 << 63;
    let mut s = s.as_bytes();
    let mut neg = false;
    if let Some((&c, rest)) = s.split_first()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        s = rest;
    }
    if s == b"0" {
        return Some(0);
    }
    if s.is_empty() {
        return None;
    }
    let mut total: u64 = 0;
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return None;
        }
        // Integer part.
        let before = s.len();
        let (mut v, rest) = leading_int(s)?;
        s = rest;
        let pre = before != s.len();
        // Fractional part.
        let (mut f, mut scale, mut post) = (0u64, 1f64, false);
        if let Some((&b'.', rest)) = s.split_first() {
            s = rest;
            let before = s.len();
            let (ff, sc, rest) = leading_fraction(s);
            f = ff;
            scale = sc;
            s = rest;
            post = before != s.len();
        }
        if !pre && !post {
            return None;
        }
        // Unit.
        let end = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if end == 0 {
            return None;
        }
        let unit: u64 = match &s[..end] {
            b"ns" => 1,
            b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1_000,
            b"ms" => 1_000_000,
            b"s" => 1_000_000_000,
            b"m" => 60 * 1_000_000_000,
            b"h" => 3_600 * 1_000_000_000,
            _ => return None,
        };
        s = &s[end..];
        if v > LIMIT / unit {
            return None;
        }
        v *= unit;
        if f > 0 {
            // Truncation toward zero, as Go's int(float64) conversion.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                clippy::cast_precision_loss
            )]
            let frac = (f as f64 * (unit as f64 / scale)) as u64;
            v = v.checked_add(frac)?;
            if v > LIMIT {
                return None;
            }
        }
        total = total.checked_add(v)?;
        if total > LIMIT {
            return None;
        }
    }
    if neg {
        return Some(-i128::from(total));
    }
    if total > LIMIT - 1 {
        return None;
    }
    Some(i128::from(total))
}

fn leading_int(s: &[u8]) -> Option<(u64, &[u8])> {
    const LIMIT: u64 = 1 << 63;
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if x > LIMIT / 10 {
            return None;
        }
        x = x * 10 + u64::from(s[i] - b'0');
        if x > LIMIT {
            return None;
        }
        i += 1;
    }
    Some((x, &s[i..]))
}

fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    const LIMIT: u64 = 1 << 63;
    let (mut x, mut scale, mut overflow) = (0u64, 1f64, false);
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        if !overflow {
            if x > (LIMIT - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + u64::from(s[i] - b'0');
                if y > LIMIT {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, &s[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_go_parse_duration() {
        // Expected values recorded from Go's time.ParseDuration.
        for (input, want) in [
            ("10m", Some(600_000_000_000)),
            ("1h30m", Some(5_400_000_000_000)),
            ("1.5h", Some(5_400_000_000_000)),
            ("500ms", Some(500_000_000)),
            ("-1s", Some(-1_000_000_000)),
            ("-0", Some(0)),
            ("+5s", Some(5_000_000_000)),
            (".5s", Some(500_000_000)),
            ("5.s", Some(5_000_000_000)),
            ("1\u{b5}s", Some(1_000)),
            ("1\u{3bc}s", Some(1_000)),
            ("3", None),
            ("", None),
            ("1e3s", None),
            ("9223372036854775807ns", Some(9_223_372_036_854_775_807)),
            ("9223372036854775808ns", None),
            ("2562047h", Some(9_223_369_200_000_000_000)),
            ("2562048h", None),
            ("0.000000001s", Some(1)),
            ("0.0000000001s", Some(0)),
            ("1.0000000001s", Some(1_000_000_000)),
            ("1h-5m", None),
            ("1h 5m", None),
            ("0", Some(0)),
            (".s", None),
            ("1x", None),
        ] {
            assert_eq!(parse_go_duration(input), want, "{input:?}");
        }
    }
}
