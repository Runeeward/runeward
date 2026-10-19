//! Per-principal rate limiting (`RUNEWARD_PRINCIPAL_RATE_LIMIT`).
//!
//! The REST server already limits per client IP. Behind a shared proxy or
//! NAT many principals share one IP, and one principal can spread over
//! many; this limiter keys a token bucket by the authenticated principal
//! instead, so one noisy tenant cannot starve the rest. The REST server and
//! the MCP HTTP transport consult it after authentication. Off unless the
//! variable is set; hardened mode requires it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Requests per second allowed per principal (burst twice that). Empty,
/// `0`, `off` or an invalid value disables per-principal limiting.
pub const PRINCIPAL_RATE_LIMIT_ENV: &str = "RUNEWARD_PRINCIPAL_RATE_LIMIT";

/// Idle buckets are dropped once the table grows past this.
const RETAIN_THRESHOLD: usize = 10_000;

/// A monotonic time source (injectable for tests).
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Parses a [`PRINCIPAL_RATE_LIMIT_ENV`] value.
pub fn parse_principal_rate_limit(v: Option<&str>) -> Option<f64> {
    let v = v.unwrap_or_default().trim();
    if v.is_empty() || v == "0" || v.eq_ignore_ascii_case("off") {
        return None;
    }
    v.parse::<f64>().ok().filter(|r| r.is_finite() && *r > 0.0)
}

/// The rate configured in the environment, if any.
pub fn principal_rate_limit_from_env() -> Option<f64> {
    parse_principal_rate_limit(std::env::var(PRINCIPAL_RATE_LIMIT_ENV).ok().as_deref())
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token bucket per principal name.
pub struct PrincipalLimiter {
    rate: f64,
    burst: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
    clock: Clock,
}

impl std::fmt::Debug for PrincipalLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrincipalLimiter")
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .finish_non_exhaustive()
    }
}

impl PrincipalLimiter {
    /// `rps` requests per second per principal with a burst of
    /// `max(1, floor(2 * rps))`; `None` for a non-positive rate.
    pub fn new(rps: f64) -> Option<Self> {
        Self::with_clock(rps, Arc::new(Instant::now))
    }

    /// [`PrincipalLimiter::new`] with an explicit clock.
    pub fn with_clock(rps: f64, clock: Clock) -> Option<Self> {
        if !rps.is_finite() || rps <= 0.0 {
            return None;
        }
        Some(Self {
            rate: rps,
            burst: (rps * 2.0).floor().max(1.0),
            buckets: Mutex::new(HashMap::new()),
            clock,
        })
    }

    /// The limiter configured by [`PRINCIPAL_RATE_LIMIT_ENV`], if any.
    pub fn from_env() -> Option<Self> {
        principal_rate_limit_from_env().and_then(Self::new)
    }

    /// The configured rate (requests per second).
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Takes one token for `principal`; false when its bucket is empty.
    pub fn allow(&self, principal: &str) -> bool {
        let now = (self.clock)();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() > RETAIN_THRESHOLD {
            let (rate, burst) = (self.rate, self.burst);
            buckets.retain(|_, b| {
                b.tokens + now.saturating_duration_since(b.last).as_secs_f64() * rate < burst
            });
        }
        let b = buckets.entry(principal.to_owned()).or_insert(Bucket {
            tokens: self.burst,
            last: now,
        });
        let elapsed = now.saturating_duration_since(b.last);
        b.tokens = (b.tokens + elapsed.as_secs_f64() * self.rate).min(self.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long until `principal` has a token again (zero when it has one).
    pub fn retry_after(&self, principal: &str) -> Duration {
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        match buckets.get(principal) {
            Some(b) if b.tokens < 1.0 => Duration::from_secs_f64((1.0 - b.tokens) / self.rate),
            _ => Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn env_values() {
        assert_eq!(parse_principal_rate_limit(None), None);
        assert_eq!(parse_principal_rate_limit(Some(" ")), None);
        assert_eq!(parse_principal_rate_limit(Some("OFF")), None);
        assert_eq!(parse_principal_rate_limit(Some("0")), None);
        assert_eq!(parse_principal_rate_limit(Some("-1")), None);
        assert_eq!(parse_principal_rate_limit(Some("nan")), None);
        assert_eq!(parse_principal_rate_limit(Some("2.5")), Some(2.5));
        assert!(PrincipalLimiter::new(0.0).is_none());
    }

    #[test]
    fn buckets_are_per_principal_and_refill_with_the_clock() {
        let base = Instant::now();
        let ms = Arc::new(AtomicU64::new(0));
        let m = Arc::clone(&ms);
        let l = PrincipalLimiter::with_clock(
            1.0,
            Arc::new(move || base + Duration::from_millis(m.load(Ordering::SeqCst))),
        )
        .expect("limiter");
        assert!(l.allow("alice") && l.allow("alice"), "burst of two");
        assert!(!l.allow("alice"), "bucket empty");
        assert_eq!(l.retry_after("alice"), Duration::from_secs(1));
        assert!(l.allow("bob"), "per principal");
        ms.store(500, Ordering::SeqCst);
        assert!(!l.allow("alice"), "half a token");
        ms.store(1_000, Ordering::SeqCst);
        assert!(l.allow("alice"), "refilled");
        assert_eq!(l.retry_after("carol"), Duration::ZERO);
    }

    #[test]
    fn tiny_rates_still_allow_one() {
        let l = PrincipalLimiter::new(0.1).expect("limiter");
        assert!(l.allow("a"));
        assert!(!l.allow("a"));
    }
}
