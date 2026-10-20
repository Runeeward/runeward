//! Per-client-IP token-bucket rate limiting (`RUNEWARD_RATE_LIMIT`).

use std::num::NonZeroU32;
use std::time::Duration;

use governor::{DefaultKeyedRateLimiter, Quota};

/// The environment variable holding the per-IP request rate.
pub const RATE_LIMIT_ENV: &str = "RUNEWARD_RATE_LIMIT";

/// The v1-safe default rate, in requests per second per client IP.
pub const DEFAULT_RATE_LIMIT: f64 = 50.0;

/// Keeps the per-IP table bounded: idle buckets are dropped past this size.
const RETAIN_THRESHOLD: usize = 10_000;

/// A per-client-IP limiter with a burst of twice the rate.
pub(crate) struct RateLimiter {
    inner: DefaultKeyedRateLimiter<String>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter").finish_non_exhaustive()
    }
}

/// Parses a `RUNEWARD_RATE_LIMIT` value: empty means the default, `0` or
/// `off` disables, and an invalid or non-positive number disables (as Go).
pub fn parse_rate_limit(v: Option<&str>) -> Option<f64> {
    let v = v.unwrap_or_default().trim();
    if v.is_empty() {
        return Some(DEFAULT_RATE_LIMIT);
    }
    if v.eq_ignore_ascii_case("off") || v == "0" {
        return None;
    }
    v.parse::<f64>().ok().filter(|r| r.is_finite() && *r > 0.0)
}

impl RateLimiter {
    /// A limiter allowing `rps` requests per second with a burst of
    /// `max(1, floor(2 * rps))`.
    pub(crate) fn new(rps: f64) -> Option<Self> {
        if !rps.is_finite() || rps <= 0.0 {
            return None;
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let burst = ((rps * 2.0) as u64).clamp(1, u64::from(u32::MAX)) as u32;
        let period = Duration::from_secs_f64(1.0 / rps);
        let quota = Quota::with_period(period)?.allow_burst(NonZeroU32::new(burst)?);
        Some(Self {
            inner: DefaultKeyedRateLimiter::keyed(quota),
        })
    }

    /// Takes one token for `ip`; false when the bucket is empty.
    pub(crate) fn allow(&self, ip: &str) -> bool {
        if self.inner.len() > RETAIN_THRESHOLD {
            self.inner.retain_recent();
        }
        self.inner.check_key(&ip.to_owned()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_values() {
        assert_eq!(parse_rate_limit(None), Some(50.0));
        assert_eq!(parse_rate_limit(Some(" ")), Some(50.0));
        assert_eq!(parse_rate_limit(Some("OFF")), None);
        assert_eq!(parse_rate_limit(Some("0")), None);
        assert_eq!(parse_rate_limit(Some("-3")), None);
        assert_eq!(parse_rate_limit(Some("bogus")), None);
        assert_eq!(parse_rate_limit(Some("2.5")), Some(2.5));
    }

    #[test]
    fn burst_then_refuse() {
        let l = RateLimiter::new(1.0).expect("limiter");
        assert!(l.allow("a") && l.allow("a"), "burst of two");
        assert!(!l.allow("a"), "bucket empty");
        assert!(l.allow("b"), "per-IP buckets");
        let l = RateLimiter::new(0.1).expect("tiny rate");
        assert!(l.allow("a"), "burst is at least one");
        assert!(!l.allow("a"));
    }
}
