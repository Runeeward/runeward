//! JSON encoding and decoding with Go `encoding/json` semantics.
//!
//! Ledger lines, export bundles and evidence documents are compared byte for
//! byte with files the Go implementation wrote, and hashes are recomputed from
//! decoded records, so both directions follow Go rather than serde defaults.
//!
//! Encoding: serde_json already escapes like Go for control characters,
//! quotes and backslashes; Go additionally escapes `<`, `>` and `&` (HTML
//! safety) and U+2028/U+2029 (JavaScript line terminators). Indented output
//! matches `json.Encoder` with `SetIndent("", "  ")`.
//!
//! Decoding (see [`GoDecode`]): object keys match field names
//! case-insensitively, `null` leaves scalars untouched and clears slices and
//! maps, unknown keys are ignored, and a repeated key decodes into the value
//! the earlier one produced (so maps merge).

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::ser::{CompactFormatter, Formatter, PrettyFormatter};

/// A serde_json formatter that adds Go's extra string escapes on top of an
/// inner (compact or pretty) formatter.
#[derive(Debug)]
pub struct GoFormatter<F> {
    inner: F,
}

impl GoFormatter<CompactFormatter> {
    /// The formatter behind `json.Marshal`.
    pub fn compact() -> Self {
        Self {
            inner: CompactFormatter,
        }
    }
}

impl GoFormatter<PrettyFormatter<'static>> {
    /// The formatter behind `json.Encoder` with a two-space indent.
    pub fn indented() -> Self {
        Self {
            inner: PrettyFormatter::with_indent(b"  "),
        }
    }
}

macro_rules! delegate {
    ($($name:ident $(($arg:ident: $ty:ty))?),* $(,)?) => {
        $(
            fn $name<W: ?Sized + io::Write>(&mut self, w: &mut W $(, $arg: $ty)?) -> io::Result<()> {
                self.inner.$name(w $(, $arg)?)
            }
        )*
    };
}

impl<F: Formatter> Formatter for GoFormatter<F> {
    delegate!(
        begin_array,
        end_array,
        begin_array_value(first: bool),
        end_array_value,
        begin_object,
        end_object,
        begin_object_key(first: bool),
        end_object_key,
        begin_object_value,
        end_object_value,
    );

    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        w: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut start = 0;
        for (i, c) in fragment.char_indices() {
            let esc: &[u8] = match c {
                '<' => b"\\u003c",
                '>' => b"\\u003e",
                '&' => b"\\u0026",
                '\u{2028}' => b"\\u2028",
                '\u{2029}' => b"\\u2029",
                _ => continue,
            };
            w.write_all(&fragment.as_bytes()[start..i])?;
            w.write_all(esc)?;
            start = i + c.len_utf8();
        }
        w.write_all(&fragment.as_bytes()[start..])
    }
}

/// Encodes v as Go's `json.Marshal` does (no trailing newline).
pub fn marshal<T: Serialize + ?Sized>(v: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter::compact());
    v.serialize(&mut ser)?;
    Ok(out)
}

/// Encodes v as a `json.Encoder` with `SetIndent("", "  ")` does, including
/// the trailing newline.
pub fn marshal_indent<T: Serialize + ?Sized>(v: &T) -> serde_json::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);
    let mut ser = serde_json::Serializer::with_formatter(&mut out, GoFormatter::indented());
    v.serialize(&mut ser)?;
    out.push(b'\n');
    Ok(out)
}

/// Writes the indented encoding of v to w in one write, so a failed encode
/// leaves w untouched, as with Go's encoder.
pub fn encode_indent<W: io::Write, T: Serialize + ?Sized>(mut w: W, v: &T) -> io::Result<()> {
    let buf = marshal_indent(v).map_err(io::Error::other)?;
    w.write_all(&buf)
}

/// Decodes a value in place with Go `encoding/json` semantics.
pub(crate) trait GoDecode {
    fn go_decode<'de, D: Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error>;
}

/// Seed that decodes into an existing value.
pub(crate) struct Into<'a, T>(pub(crate) &'a mut T);

impl<'de, T: GoDecode> DeserializeSeed<'de> for Into<'_, T> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        self.0.go_decode(d)
    }
}

macro_rules! scalar_decode {
    ($($ty:ty),*) => {$(
        // null leaves a scalar unchanged.
        impl GoDecode for $ty {
            fn go_decode<'de, D: Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error> {
                if let Some(v) = Option::<$ty>::deserialize(d)? {
                    *self = v;
                }
                Ok(())
            }
        }
    )*};
}
scalar_decode!(String, i64, bool);

impl GoDecode for crate::gotime::Time {
    fn go_decode<'de, D: Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error> {
        if let Some(s) = Option::<String>::deserialize(d)? {
            *self = crate::gotime::parse_rfc3339(&s).map_err(serde::de::Error::custom)?;
        }
        Ok(())
    }
}

/// Elements are decoded from a zero value; null clears the slice.
impl<T: GoDecode + Default> GoDecode for Vec<T> {
    fn go_decode<'de, D: Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error> {
        struct Elem<T>(T);
        impl<'de, T: GoDecode + Default> Deserialize<'de> for Elem<T> {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let mut v = T::default();
                v.go_decode(d)?;
                Ok(Elem(v))
            }
        }
        *self = Option::<Vec<Elem<T>>>::deserialize(d)?
            .map(|v| v.into_iter().map(|e| e.0).collect())
            .unwrap_or_default();
        Ok(())
    }
}

/// Entries merge into an existing map; null clears it, and a null value is
/// stored as the empty string.
impl GoDecode for BTreeMap<String, String> {
    fn go_decode<'de, D: Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error> {
        match Option::<BTreeMap<String, Option<String>>>::deserialize(d)? {
            None => self.clear(),
            Some(m) => self.extend(m.into_iter().map(|(k, v)| (k, v.unwrap_or_default()))),
        }
        Ok(())
    }
}

/// Reports whether a JSON object key selects the field named `field` (lower
/// case ASCII). Go folds keys to upper case, mapping U+017F (long s) to `S`
/// and U+212A (Kelvin sign) to `K` via Unicode simple folding.
pub(crate) fn key_matches(key: &str, field: &str) -> bool {
    let mut f = field.bytes();
    for c in key.chars() {
        let folded = match c {
            '\u{017F}' => b'S',
            '\u{212A}' => b'K',
            c if c.is_ascii() => (c as u8).to_ascii_uppercase(),
            _ => return false,
        };
        if f.next().map(|b| b.to_ascii_uppercase()) != Some(folded) {
            return false;
        }
    }
    f.next().is_none()
}

/// Visitor for a struct decoded field by field into an existing value.
pub(crate) struct StructVisitor<'a, T> {
    pub(crate) target: &'a mut T,
    pub(crate) name: &'static str,
    pub(crate) field: for<'f> fn(&'f mut T, &str) -> Option<FieldSlot<'f>>,
}

/// A mutable reference to one decodable field.
pub(crate) enum FieldSlot<'a> {
    Str(&'a mut String),
    Int(&'a mut i64),
    Bool(&'a mut bool),
    Time(&'a mut crate::gotime::Time),
    Strings(&'a mut Vec<String>),
    Meta(&'a mut BTreeMap<String, String>),
    Events(&'a mut Vec<crate::Event>),
    Findings(&'a mut Vec<crate::evidence::Finding>),
    Policy(&'a mut crate::evidence::PolicySnapshot),
    Bundle(&'a mut crate::Bundle),
}

impl<'de, T> Visitor<'de> for StructVisitor<'_, T> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a JSON object for {}", self.name)
    }

    // null leaves the whole struct unchanged.
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let StructVisitor { target, field, .. } = self;
        while let Some(key) = map.next_key::<String>()? {
            match field(&mut *target, &key) {
                Some(FieldSlot::Str(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Int(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Bool(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Time(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Strings(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Meta(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Events(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Findings(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Policy(v)) => map.next_value_seed(Into(v))?,
                Some(FieldSlot::Bundle(v)) => map.next_value_seed(Into(v))?,
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// Implements [`GoDecode`] and `Deserialize` for a struct from a table of
/// JSON names, field names and slot kinds.
macro_rules! go_struct {
    ($ty:ident { $($json:literal => $field:ident: $slot:ident),* $(,)? }) => {
        impl $crate::gojson::GoDecode for $ty {
            fn go_decode<'de, D: serde::Deserializer<'de>>(&mut self, d: D) -> Result<(), D::Error> {
                fn field<'a>(t: &'a mut $ty, key: &str) -> Option<$crate::gojson::FieldSlot<'a>> {
                    $(
                        if $crate::gojson::key_matches(key, $json) {
                            return Some($crate::gojson::FieldSlot::$slot(&mut t.$field));
                        }
                    )*
                    None
                }
                d.deserialize_any($crate::gojson::StructVisitor {
                    target: self,
                    name: stringify!($ty),
                    field,
                })
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let mut v = <$ty>::default();
                $crate::gojson::GoDecode::go_decode(&mut v, d)?;
                Ok(v)
            }
        }
    };
}
pub(crate) use go_struct;

#[cfg(test)]
mod tests {
    use super::*;

    // Expected output from Go 1.26 json.Marshal.
    #[test]
    fn escapes_strings_like_go() {
        let s = "<a>&\u{2028}\u{2029}\u{8}\u{c}\n\r\t\u{1}\u{1f}\u{7f}\"\\é😀";
        let got = String::from_utf8(marshal(s).expect("marshal")).expect("utf8");
        assert_eq!(
            got,
            "\"\\u003ca\\u003e\\u0026\\u2028\\u2029\\b\\f\\n\\r\\t\\u0001\\u001f\u{7f}\\\"\\\\é😀\""
        );
    }

    #[test]
    fn sorts_and_escapes_map_keys_like_go() {
        let m: BTreeMap<&str, &str> =
            [("<k>", "v"), ("B", "1"), ("a", "2"), ("é", "3"), ("Z", "4")].into();
        let got = String::from_utf8(marshal(&m).expect("marshal")).expect("utf8");
        assert_eq!(
            got,
            r#"{"\u003ck\u003e":"v","B":"1","Z":"4","a":"2","é":"3"}"#
        );
    }

    #[test]
    fn indents_like_go_encoder() {
        #[derive(Serialize)]
        struct S {
            a: Vec<i64>,
            b: Vec<i64>,
            c: BTreeMap<String, String>,
        }
        let got = marshal_indent(&S {
            a: vec![1, 2],
            b: vec![],
            c: BTreeMap::new(),
        })
        .expect("marshal");
        assert_eq!(
            String::from_utf8(got).expect("utf8"),
            "{\n  \"a\": [\n    1,\n    2\n  ],\n  \"b\": [],\n  \"c\": {}\n}\n"
        );
    }

    #[test]
    fn folds_keys_like_go() {
        assert!(key_matches("seq", "seq"));
        assert!(key_matches("SEQ", "seq"));
        assert!(key_matches("\u{017F}eq", "seq"));
        assert!(key_matches("\u{212A}ey_id", "key_id"));
        assert!(!key_matches("seqq", "seq"));
        assert!(!key_matches("se", "seq"));
        assert!(!key_matches("sé", "se"));
    }
}
