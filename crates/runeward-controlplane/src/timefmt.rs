//! serde adapters encoding timestamps like Go's `time.Time` JSON, so state
//! files round-trip byte for byte with the Go control plane.

use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Deserializer, Serializer};

pub(crate) fn serialize<S: Serializer>(t: &Time, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&gotime::format_rfc3339_nano(t))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Time, D::Error> {
    match Option::<String>::deserialize(d)? {
        Some(s) => gotime::parse_rfc3339(&s).map_err(serde::de::Error::custom),
        None => Ok(gotime::zero()),
    }
}

/// A `*time.Time` with `omitempty`: `None` is omitted (pair with
/// `skip_serializing_if = "Option::is_none"`), `null` reads as `None`.
pub(crate) mod opt {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(t: &Option<Time>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => super::serialize(t, s),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Time>, D::Error> {
        match Option::<String>::deserialize(d)? {
            Some(s) => gotime::parse_rfc3339(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

/// Decodes a value where JSON `null` means the zero value, as in Go.
pub(crate) fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
