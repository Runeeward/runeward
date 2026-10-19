//! Encodes `DateTime<Utc>` fields like Go's `time.Time` JSON (RFC 3339 with
//! trailing fraction zeros trimmed), so state files such as `snapshots.json`
//! stay byte-identical to the ones the Go control plane writes.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serializer};

/// Formats `t` as Go's `t.UTC().Format(time.RFC3339Nano)`.
pub fn format(t: &DateTime<Utc>) -> String {
    let s = t.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let Some((head, frac)) = s.trim_end_matches('Z').split_once('.') else {
        return s;
    };
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        format!("{head}Z")
    } else {
        format!("{head}.{frac}Z")
    }
}

pub(crate) fn serialize<S: Serializer>(t: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format(t))
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    DateTime::<Utc>::deserialize(d)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn trims_fraction_like_go() {
        let t = Utc
            .timestamp_opt(1_700_000_000, 123_450_000)
            .single()
            .expect("time");
        assert_eq!(format(&t), "2023-11-14T22:13:20.12345Z");
        let t = Utc.timestamp_opt(1_700_000_000, 0).single().expect("time");
        assert_eq!(format(&t), "2023-11-14T22:13:20Z");
        assert_eq!(format(&crate::go_zero_time()), "0001-01-01T00:00:00Z");
    }
}
