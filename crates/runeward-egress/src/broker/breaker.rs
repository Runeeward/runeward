//! Retry-storm circuit breaker, per sandbox (one broker) × endpoint.
//!
//! When an inspected endpoint's upstream answers `429 Too Many Requests` or
//! `503 Service Unavailable`, the breaker opens for the upstream's
//! `Retry-After` (seconds or an HTTP date, capped at [`MAX_RETRY_AFTER`];
//! [`DEFAULT_RETRY_AFTER`] when absent). While it is open the broker sheds
//! further calls to that endpoint immediately with a 503 JSON refusal
//! (`code: "shed"`) instead of letting an agent's retry loop hammer an
//! upstream that already said "not now". Shed calls never reach the
//! upstream, never spend a budget and never ask for approval; they are
//! recorded with the `shed` reason code and counted separately from policy
//! denies.
//!
//! An endpoint with a `health_path` may close a 503 breaker early: at most
//! once per [`PROBE_INTERVAL`] an arriving call triggers a `GET` of that
//! path (without the endpoint's credential), and a 2xx answer closes the
//! breaker and lets the call through. A 429 breaker is always waited out,
//! since the upstream told this client specifically to slow down.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

/// Longest window the breaker honours from a `Retry-After` header.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// Window used when a 429/503 carries no (parseable) `Retry-After`.
pub const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);

/// Minimum spacing between `health_path` probes of one endpoint.
pub const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// A monotonic time source; injectable so tests need no wall-clock waits.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// The real monotonic clock.
pub fn system_clock() -> Clock {
    Arc::new(Instant::now)
}

/// Which upstream answer opened a breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trip {
    /// 429: always waited out.
    TooManyRequests,
    /// 503: may be closed early by a healthy `health_path` probe.
    Unavailable,
}

impl Trip {
    pub(crate) fn status(self) -> u16 {
        match self {
            Self::TooManyRequests => 429,
            Self::Unavailable => 503,
        }
    }
}

/// What the breaker says about one arriving call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Closed: forward as usual.
    Pass,
    /// Open: refuse without contacting the upstream.
    Shed {
        /// Time until the window passes.
        remaining: Duration,
        /// What opened it.
        trip: Trip,
    },
    /// Open on a 503, and this call may probe the health path.
    Probe,
}

#[derive(Debug, Clone, Copy)]
struct Open {
    until: Instant,
    trip: Trip,
    last_probe: Option<Instant>,
}

/// Breaker state for every endpoint of one broker.
pub(crate) struct Breakers {
    open: Mutex<HashMap<usize, Open>>,
    shed: Mutex<HashMap<usize, u64>>,
    clock: Clock,
}

impl std::fmt::Debug for Breakers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Breakers")
            .field("open", &*lock(&self.open))
            .field("shed", &*lock(&self.shed))
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Breakers {
    pub(crate) fn new(clock: Clock) -> Self {
        Self {
            open: Mutex::new(HashMap::new()),
            shed: Mutex::new(HashMap::new()),
            clock,
        }
    }

    pub(crate) fn set_clock(&mut self, clock: Clock) {
        self.clock = clock;
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Decides whether a call to endpoint `ep` may go upstream.
    /// `can_probe` says whether the endpoint has a `health_path`.
    pub(crate) fn admit(&self, ep: usize, can_probe: bool) -> Admit {
        let now = self.now();
        let mut open = lock(&self.open);
        let Some(o) = open.get_mut(&ep) else {
            return Admit::Pass;
        };
        if now >= o.until {
            open.remove(&ep);
            return Admit::Pass;
        }
        let may_probe = can_probe
            && o.trip == Trip::Unavailable
            && o.last_probe
                .is_none_or(|t| now.saturating_duration_since(t) >= PROBE_INTERVAL);
        if may_probe {
            o.last_probe = Some(now);
            return Admit::Probe;
        }
        Admit::Shed {
            remaining: o.until.saturating_duration_since(now),
            trip: o.trip,
        }
    }

    /// Feeds an upstream status back. 429 and 503 open (or extend) the
    /// breaker for `retry_after` (already parsed and capped). Returns
    /// whether the breaker is now open.
    pub(crate) fn observe(&self, ep: usize, status: u16, retry_after: Option<Duration>) -> bool {
        let trip = match status {
            429 => Trip::TooManyRequests,
            503 => Trip::Unavailable,
            _ => return false,
        };
        let window = retry_after
            .unwrap_or(DEFAULT_RETRY_AFTER)
            .min(MAX_RETRY_AFTER);
        if window.is_zero() {
            return false;
        }
        let now = self.now();
        let until = now + window;
        let mut open = lock(&self.open);
        let entry = open.entry(ep).or_insert(Open {
            until,
            trip,
            last_probe: None,
        });
        entry.until = entry.until.max(until);
        // A 429 is the stronger signal: never let a later 503 make it
        // probe-closable.
        if trip == Trip::TooManyRequests {
            entry.trip = Trip::TooManyRequests;
        }
        true
    }

    /// Closes endpoint `ep`'s breaker (a healthy probe).
    pub(crate) fn close(&self, ep: usize) {
        lock(&self.open).remove(&ep);
    }

    /// Counts one shed call.
    pub(crate) fn count_shed(&self, ep: usize) {
        *lock(&self.shed).entry(ep).or_insert(0) += 1;
    }

    /// Shed calls so far, by endpoint index.
    pub(crate) fn shed_counts(&self) -> HashMap<usize, u64> {
        lock(&self.shed).clone()
    }
}

/// Parses a `Retry-After` value: delay-seconds or an HTTP date relative to
/// `now`. A date in the past is a zero delay. The result is capped at
/// [`MAX_RETRY_AFTER`].
pub(crate) fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<Duration> {
    let v = value.trim();
    let d = if let Ok(secs) = v.parse::<u64>() {
        Duration::from_secs(secs)
    } else {
        let at = DateTime::parse_from_rfc2822(v).ok()?.with_timezone(&Utc);
        (at - now).to_std().unwrap_or(Duration::ZERO)
    };
    Some(d.min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A manual clock: `base + offset_ms`.
    fn manual() -> (Clock, Arc<AtomicU64>) {
        let base = Instant::now();
        let off = Arc::new(AtomicU64::new(0));
        let o = Arc::clone(&off);
        (
            Arc::new(move || base + Duration::from_millis(o.load(Ordering::SeqCst))),
            off,
        )
    }

    #[test]
    fn retry_after_seconds_dates_and_cap() {
        let now = DateTime::parse_from_rfc3339("2026-10-19T12:00:00Z")
            .expect("t")
            .with_timezone(&Utc);
        assert_eq!(parse_retry_after("7", now), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after(" 120 ", now), Some(MAX_RETRY_AFTER));
        assert_eq!(
            parse_retry_after("Mon, 19 Oct 2026 12:00:10 GMT", now),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            parse_retry_after("Mon, 19 Oct 2026 11:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon", now), None);
        assert_eq!(parse_retry_after("-1", now), None);
    }

    #[test]
    fn opens_sheds_and_closes_when_the_window_passes() {
        let (clock, off) = manual();
        let b = Breakers::new(clock);
        assert_eq!(b.admit(0, false), Admit::Pass);
        assert!(!b.observe(0, 500, None), "only 429/503 trip");
        assert!(!b.observe(0, 503, Some(Duration::ZERO)), "zero window");
        assert!(b.observe(0, 503, Some(Duration::from_secs(2))));
        assert_eq!(
            b.admit(0, false),
            Admit::Shed {
                remaining: Duration::from_secs(2),
                trip: Trip::Unavailable
            }
        );
        assert_eq!(b.admit(1, false), Admit::Pass, "per endpoint");
        off.store(1_500, Ordering::SeqCst);
        assert!(matches!(b.admit(0, false), Admit::Shed { .. }));
        off.store(2_000, Ordering::SeqCst);
        assert_eq!(b.admit(0, false), Admit::Pass);
        assert_eq!(b.admit(0, false), Admit::Pass);
    }

    #[test]
    fn missing_retry_after_uses_default_and_cap_applies() {
        let (clock, off) = manual();
        let b = Breakers::new(clock);
        b.observe(0, 429, None);
        off.store(DEFAULT_RETRY_AFTER.as_millis() as u64 - 1, Ordering::SeqCst);
        assert!(matches!(b.admit(0, false), Admit::Shed { .. }));
        off.store(DEFAULT_RETRY_AFTER.as_millis() as u64, Ordering::SeqCst);
        assert_eq!(b.admit(0, false), Admit::Pass);

        b.observe(0, 503, Some(Duration::from_secs(3600)));
        let Admit::Shed { remaining, .. } = b.admit(0, false) else {
            panic!("open");
        };
        assert_eq!(remaining, MAX_RETRY_AFTER);
    }

    #[test]
    fn probes_only_503_breakers_and_at_most_once_per_interval() {
        let (clock, off) = manual();
        let b = Breakers::new(clock);
        b.observe(0, 503, Some(Duration::from_secs(10)));
        assert!(
            matches!(b.admit(0, false), Admit::Shed { .. }),
            "no health path"
        );
        assert_eq!(b.admit(0, true), Admit::Probe);
        assert!(
            matches!(b.admit(0, true), Admit::Shed { .. }),
            "probe spacing"
        );
        off.store(PROBE_INTERVAL.as_millis() as u64, Ordering::SeqCst);
        assert_eq!(b.admit(0, true), Admit::Probe);
        b.close(0);
        assert_eq!(b.admit(0, true), Admit::Pass);

        // A 429 is waited out even with a health path, and is not
        // downgraded by a later 503.
        b.observe(1, 429, Some(Duration::from_secs(10)));
        b.observe(1, 503, Some(Duration::from_secs(10)));
        assert!(matches!(
            b.admit(1, true),
            Admit::Shed {
                trip: Trip::TooManyRequests,
                ..
            }
        ));
    }

    #[test]
    fn shed_counts_are_per_endpoint() {
        let b = Breakers::new(system_clock());
        b.count_shed(2);
        b.count_shed(2);
        b.count_shed(0);
        let c = b.shed_counts();
        assert_eq!(c.get(&2), Some(&2));
        assert_eq!(c.get(&0), Some(&1));
    }
}
