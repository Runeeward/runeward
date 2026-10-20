//! JSON encoding that matches Go's `encoding/json` byte for byte for the
//! shapes the webhook emits: serde's struct field order plus Go's HTML-safe
//! string escaping (`<`, `>`, `&`, U+2028 and U+2029 become `\uXXXX`).

use serde::Serialize;
use serde_json::ser::Formatter;
use std::io;

#[derive(Debug, Clone, Copy, Default)]
struct GoFormatter;

impl Formatter for GoFormatter {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (i, ch) in fragment.char_indices() {
            let esc = match ch {
                '<' => "\\u003c",
                '>' => "\\u003e",
                '&' => "\\u0026",
                '\u{2028}' => "\\u2028",
                '\u{2029}' => "\\u2029",
                _ => continue,
            };
            writer.write_all(&fragment.as_bytes()[start..i])?;
            writer.write_all(esc.as_bytes())?;
            start = i + ch.len_utf8();
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }
}

/// Serializes `value` compactly the way Go's `json.Marshal` would.
pub(crate) fn to_vec<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter);
    value.serialize(&mut ser)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_go() {
        // Expected output recorded from Go's json.Marshal.
        let got = to_vec("\x01\x08\x0c\n\r\t\x7f\"\\/<>&\u{2028}\u{2029}\u{e9}\u{1f600}")
            .expect("encode");
        assert_eq!(
            String::from_utf8(got).expect("utf8"),
            "\"\\u0001\\b\\f\\n\\r\\t\x7f\\\"\\\\/\\u003c\\u003e\\u0026\\u2028\\u2029\u{e9}\u{1f600}\""
        );
    }
}
