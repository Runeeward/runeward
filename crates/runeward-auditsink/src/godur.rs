//! Go's `time.ParseDuration`, so duration env vars accept the same syntax
//! ("1m", "1h30m", "1.5s", "250ms", "10us").

/// Parses a Go duration string into signed nanoseconds.
pub(crate) fn parse_duration_nanos(s: &str) -> Option<i64> {
    let mut rest = s;
    let neg = match rest.as_bytes().first() {
        Some(b'-') => {
            rest = &rest[1..];
            true
        }
        Some(b'+') => {
            rest = &rest[1..];
            false
        }
        _ => false,
    };
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let int_part = &rest[..int_len];
        rest = &rest[int_len..];
        let mut frac_part = "";
        if let Some(r) = rest.strip_prefix('.') {
            let frac_len = r.bytes().take_while(u8::is_ascii_digit).count();
            frac_part = &r[..frac_len];
            rest = &r[frac_len..];
            if int_part.is_empty() && frac_part.is_empty() {
                return None;
            }
        } else if int_part.is_empty() {
            return None;
        }
        let unit_len = rest
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(rest.len());
        let unit: u128 = match &rest[..unit_len] {
            "ns" => 1,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        rest = &rest[unit_len..];

        let whole: u128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().ok()?
        };
        let mut v = whole.checked_mul(unit)?;
        if !frac_part.is_empty() {
            // Go keeps at most the digits that still matter, truncating.
            let digits = &frac_part[..frac_part.len().min(30)];
            let f: u128 = digits.parse().ok()?;
            let scale = 10u128.checked_pow(u32::try_from(digits.len()).ok()?)?;
            v = v.checked_add(f.checked_mul(unit)? / scale)?;
        }
        total = total.checked_add(v)?;
        if total > i64::MAX as u128 + u128::from(neg) {
            return None;
        }
    }
    let total = i128::try_from(total).ok()?;
    i64::try_from(if neg { -total } else { total }).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_duration_nanos as p;

    #[test]
    fn go_duration_syntax() {
        const S: i64 = 1_000_000_000;
        assert_eq!(p("1m"), Some(60 * S));
        assert_eq!(p("30s"), Some(30 * S));
        assert_eq!(p("1h30m"), Some(5400 * S));
        assert_eq!(p("1.5s"), Some(1_500_000_000));
        assert_eq!(p(".5s"), Some(500_000_000));
        assert_eq!(p("250ms"), Some(250_000_000));
        assert_eq!(p("10us"), Some(10_000));
        assert_eq!(p("10µs"), Some(10_000));
        assert_eq!(p("7ns"), Some(7));
        assert_eq!(p("-2s"), Some(-2 * S));
        assert_eq!(p("+2s"), Some(2 * S));
        assert_eq!(p("0"), Some(0));
        assert_eq!(p(""), None);
        assert_eq!(p("10"), None);
        assert_eq!(p("1x"), None);
        assert_eq!(p("."), None);
        assert_eq!(p("s"), None);
        assert_eq!(p("9999999999h"), None);
    }
}
