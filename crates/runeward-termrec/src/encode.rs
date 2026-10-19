//! Go `encoding/json` number and string encoding details.

use runeward_ledger::gojson;

/// Formats f like Go's `encoding/json` float64 encoder: shortest round-trip
/// digits, plain decimal unless the magnitude is below 1e-6 or at least
/// 1e21, in which case exponent form with at least one exponent digit and an
/// explicit `+` for positive exponents (`1e-7`, `1e+21`).
pub(crate) fn go_float(f: f64) -> String {
    let abs = f.abs();
    if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
        // Rust's `{:e}` is shortest round-trip with a minimal exponent
        // (`1e-7`, `1e21`); Go writes `1e-07` then trims it to `1e-7`, and
        // keeps the sign on positive exponents.
        let s = format!("{f:e}");
        match s.split_once('e') {
            Some((mant, exp)) if !exp.starts_with('-') => format!("{mant}e+{exp}"),
            _ => s,
        }
    } else {
        // Display is the shortest round-trip decimal, without a trailing
        // `.0` for integral values, as Go writes it.
        format!("{f}")
    }
}

/// Encodes bytes as a JSON string the way Go's `encoding/json` encodes a
/// `string` holding them: valid UTF-8 with Go's escapes, and every byte that
/// does not start a valid sequence written as the escape `\ufffd` on its
/// own.
pub(crate) fn go_json_string(mut bytes: &[u8]) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len() + 2);
    out.push(b'"');
    loop {
        let (valid, invalid) = match std::str::from_utf8(bytes) {
            Ok(s) => (s, false),
            // valid_up_to marks a UTF-8 boundary, so this cannot fail.
            Err(e) => (
                std::str::from_utf8(&bytes[..e.valid_up_to()]).unwrap_or_default(),
                true,
            ),
        };
        let quoted = gojson::marshal(valid)?;
        out.extend_from_slice(&quoted[1..quoted.len() - 1]);
        if !invalid {
            break;
        }
        out.extend_from_slice(b"\\ufffd");
        bytes = bytes.get(valid.len() + 1..).unwrap_or_default();
    }
    out.push(b'"');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_like_go() {
        for (f, want) in [
            (0.0, "0"),
            (1.0, "1"),
            (0.5, "0.5"),
            (1e-9, "1e-9"),
            (1.5e-7, "1.5e-7"),
            (1e-6, "0.000001"),
            (0.001234567, "0.001234567"),
            (3.333333333, "3.333333333"),
            (5400.0, "5400"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1.2345e100, "1.2345e+100"),
            (1e-100, "1e-100"),
            (-2.5, "-2.5"),
        ] {
            assert_eq!(go_float(f), want, "{f}");
        }
    }

    #[test]
    fn strings_like_go() {
        let enc = |b: &[u8]| String::from_utf8(go_json_string(b).expect("encode")).expect("utf8");
        assert_eq!(enc(b"ok"), r#""ok""#);
        assert_eq!(enc(b"a\xe2\x82b"), r#""a\ufffd\ufffdb""#);
        assert_eq!(enc(b"\xff<"), r#""\ufffd\u003c""#);
        // A real U+FFFD is valid UTF-8 and stays literal.
        assert_eq!(enc("\u{FFFD}é".as_bytes()), "\"\u{FFFD}é\"");
    }
}
