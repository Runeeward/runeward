//! serde adapters that encode `time.Time` fields like Go's `encoding/json`.

use runeward_ledger::gotime::{self, Time};
use serde::{Deserialize, Deserializer, Serializer};

/// A `time.Time` field: RFC 3339 with nanoseconds; `null` decodes to the zero
/// time (Go leaves the field untouched).
pub(crate) fn serialize<S: Serializer>(t: &Time, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&gotime::format_rfc3339_nano(t))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Time, D::Error> {
    match Option::<String>::deserialize(d)? {
        Some(s) => gotime::parse_rfc3339(&s).map_err(serde::de::Error::custom),
        None => Ok(gotime::zero()),
    }
}

/// A `time.Time` field where the zero time means "unset". Go's `omitempty`
/// never omits a struct, so `None` is written as the zero time and the zero
/// time reads back as `None`.
pub(crate) mod opt {
    use super::*;

    pub(crate) fn serialize<S: Serializer>(t: &Option<Time>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => super::serialize(t, s),
            None => super::serialize(&gotime::zero(), s),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Time>, D::Error> {
        let t = super::deserialize(d)?;
        Ok((!gotime::is_zero(&t)).then_some(t))
    }
}

/// Decodes a scalar or collection where JSON `null` means the zero value, as
/// Go does.
pub(crate) fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}
