//! Per-session cost and loop guardrails from a Charter's `[rationing]`.
//!
//! Every limit is opt-in: a zero or empty value disables that guard.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use runeward_charter::{DurationError, Limits, parse_go_duration};

/// A guardrail refused an action. Messages match the Go sentinels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum GuardError {
    /// The session ran past its wall-clock budget.
    #[error("policy: wall-clock deadline exceeded")]
    WallClock,
    /// The session used up its exec budget.
    #[error("policy: max execs exceeded")]
    MaxExecs,
    /// The session used up its outbound-request budget.
    #[error("policy: egress budget exceeded")]
    EgressBudget,
    /// A failure loop tripped the detector.
    #[error("policy: runaway loop detected")]
    LoopDetected,
}

impl GuardError {
    /// A stable machine-readable code for the refusal.
    pub fn code(self) -> &'static str {
        match self {
            Self::WallClock => "wall_clock_exceeded",
            Self::MaxExecs => "max_execs_exceeded",
            Self::EgressBudget => "egress_budget_exceeded",
            Self::LoopDetected => "loop_detected",
        }
    }
}

/// A monotonic clock reading as an offset from an arbitrary origin.
pub type Clock = Arc<dyn Fn() -> Duration + Send + Sync>;

/// Enforces wall-clock, exec-count and egress budgets and detects failure
/// loops. Safe for concurrent use.
pub struct Guard {
    /// `None` disables the guard.
    wall_clock: Option<Duration>,
    /// 0 = unlimited.
    max_execs: i64,
    /// 0 = unlimited.
    egress_limit: i64,
    /// `None` disables loop detection.
    loop_window: Option<Duration>,
    /// 0 disables loop detection.
    loop_threshold: i64,
    now: Clock,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    start: Option<Duration>,
    execs: i64,
    egress: i64,
    tripped: bool,
    loop_key: String,
    /// Sliding window of failure timestamps per key.
    failures: HashMap<String, Vec<Duration>>,
}

impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("wall_clock", &self.wall_clock)
            .field("max_execs", &self.max_execs)
            .field("egress_limit", &self.egress_limit)
            .field("loop_window", &self.loop_window)
            .field("loop_threshold", &self.loop_threshold)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Parses a Go duration, mapping zero and negative values to "disabled".
fn positive_duration(s: &str) -> Result<Option<Duration>, DurationError> {
    if s.is_empty() {
        return Ok(None);
    }
    let nanos = parse_go_duration(s)?;
    Ok(u64::try_from(nanos)
        .ok()
        .filter(|n| *n > 0)
        .map(Duration::from_nanos))
}

impl Guard {
    /// Builds a guard from `limits` using the system monotonic clock. Fails
    /// if `wall_clock` or `loop_window` is set but not a valid Go duration.
    pub fn new(limits: &Limits) -> Result<Self, DurationError> {
        let origin = Instant::now();
        Self::with_clock(limits, Arc::new(move || origin.elapsed()))
    }

    /// Like [`Guard::new`] with an injected clock (for tests and replay).
    pub fn with_clock(limits: &Limits, now: Clock) -> Result<Self, DurationError> {
        Ok(Self {
            wall_clock: positive_duration(&limits.wall_clock)?,
            max_execs: limits.max_execs,
            egress_limit: limits.egress_requests,
            loop_window: positive_duration(&limits.loop_window)?,
            loop_threshold: limits.loop_threshold,
            now,
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The state is plain counters, valid even if a holder panicked.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records the session start for wall-clock enforcement; only the first
    /// call takes effect. Without it the wall-clock guard is inert.
    pub fn start(&self) {
        let mut s = self.lock();
        if s.start.is_none() {
            s.start = Some((self.now)());
        }
    }

    /// Must be called before each tool invocation. Checks the wall-clock
    /// deadline, a tripped loop and the exec budget, in that order, and
    /// counts the exec only when it is permitted.
    pub fn check_exec(&self) -> Result<(), GuardError> {
        let mut s = self.lock();
        if let (Some(limit), Some(start)) = (self.wall_clock, s.start)
            && (self.now)().saturating_sub(start) >= limit
        {
            return Err(GuardError::WallClock);
        }
        if s.tripped {
            return Err(GuardError::LoopDetected);
        }
        if self.max_execs > 0 && s.execs >= self.max_execs {
            return Err(GuardError::MaxExecs);
        }
        s.execs += 1;
        Ok(())
    }

    /// Must be called before each outbound request.
    pub fn check_egress(&self) -> Result<(), GuardError> {
        let mut s = self.lock();
        if self.egress_limit > 0 && s.egress >= self.egress_limit {
            return Err(GuardError::EgressBudget);
        }
        s.egress += 1;
        Ok(())
    }

    /// Records the outcome of an action identified by `key`. A success clears
    /// the key's failure window; once a key reaches `loop_threshold` failures
    /// within `loop_window` the detector trips and stays tripped until
    /// [`Guard::reset`].
    pub fn record_outcome(&self, key: &str, failed: bool) {
        let mut s = self.lock();
        if !failed {
            s.failures.remove(key);
            return;
        }
        let Some(window) = self.loop_window else {
            return;
        };
        if self.loop_threshold <= 0 {
            return;
        }
        let now = (self.now)();
        let times = s.failures.entry(key.to_owned()).or_default();
        // Keep timestamps strictly after the cutoff (now - window).
        times.retain(|t| t.saturating_add(window) > now);
        times.push(now);
        let count = i64::try_from(times.len()).unwrap_or(i64::MAX);
        if count >= self.loop_threshold {
            s.tripped = true;
            s.loop_key = key.to_owned();
        }
    }

    /// Whether a failure loop has tripped, and the key responsible.
    pub fn loop_tripped(&self) -> Option<String> {
        let s = self.lock();
        s.tripped.then(|| s.loop_key.clone())
    }

    /// Clears counters, failure windows and tripped state for a fresh
    /// session; the parsed limits are kept.
    pub fn reset(&self) {
        *self.lock() = State::default();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use super::*;

    #[derive(Clone, Default)]
    struct FakeClock(Arc<AtomicU64>);

    impl FakeClock {
        fn clock(&self) -> Clock {
            let t = self.0.clone();
            Arc::new(move || Duration::from_nanos(t.load(Ordering::SeqCst)))
        }
        fn advance(&self, d: Duration) {
            let n = u64::try_from(d.as_nanos()).expect("fits");
            self.0.fetch_add(n, Ordering::SeqCst);
        }
    }

    fn limits(f: impl FnOnce(&mut Limits)) -> Limits {
        let mut l = Limits::default();
        f(&mut l);
        l
    }

    fn guard(l: &Limits, clk: &FakeClock) -> Guard {
        Guard::with_clock(l, clk.clock()).expect("guard")
    }

    #[test]
    fn bad_durations() {
        assert!(Guard::new(&limits(|l| l.wall_clock = "not-a-duration".into())).is_err());
        assert!(Guard::new(&limits(|l| l.loop_window = "nope".into())).is_err());
    }

    #[test]
    fn max_execs() {
        let g = Guard::new(&limits(|l| l.max_execs = 3)).expect("guard");
        g.start();
        for i in 0..3 {
            assert_eq!(g.check_exec(), Ok(()), "exec {i}");
        }
        assert_eq!(g.check_exec(), Err(GuardError::MaxExecs));
    }

    #[test]
    fn max_execs_unlimited() {
        let g = Guard::new(&Limits::default()).expect("guard");
        g.start();
        for _ in 0..1000 {
            assert_eq!(g.check_exec(), Ok(()));
        }
    }

    #[test]
    fn egress_budget() {
        let g = Guard::new(&limits(|l| l.egress_requests = 2)).expect("guard");
        assert_eq!(g.check_egress(), Ok(()));
        assert_eq!(g.check_egress(), Ok(()));
        assert_eq!(g.check_egress(), Err(GuardError::EgressBudget));
    }

    #[test]
    fn wall_clock() {
        let clk = FakeClock::default();
        let g = guard(&limits(|l| l.wall_clock = "10ms".into()), &clk);
        g.start();
        assert_eq!(g.check_exec(), Ok(()));
        clk.advance(Duration::from_millis(10));
        assert_eq!(g.check_exec(), Err(GuardError::WallClock));
    }

    #[test]
    fn wall_clock_disabled_without_start() {
        let clk = FakeClock::default();
        let g = guard(&limits(|l| l.wall_clock = "10ms".into()), &clk);
        clk.advance(Duration::from_secs(3600));
        assert_eq!(g.check_exec(), Ok(()));
    }

    #[test]
    fn negative_wall_clock_disables() {
        let clk = FakeClock::default();
        let g = guard(&limits(|l| l.wall_clock = "-1s".into()), &clk);
        g.start();
        clk.advance(Duration::from_secs(3600));
        assert_eq!(g.check_exec(), Ok(()));
    }

    fn loop_limits() -> Limits {
        limits(|l| {
            l.loop_window = "1s".into();
            l.loop_threshold = 3;
        })
    }

    #[test]
    fn loop_trips_within_window() {
        let clk = FakeClock::default();
        let g = guard(&loop_limits(), &clk);
        g.record_outcome("k", true);
        clk.advance(Duration::from_millis(100));
        g.record_outcome("k", true);
        assert_eq!(g.loop_tripped(), None);
        clk.advance(Duration::from_millis(100));
        g.record_outcome("k", true);
        assert_eq!(g.loop_tripped().as_deref(), Some("k"));
        assert_eq!(g.check_exec(), Err(GuardError::LoopDetected));
    }

    #[test]
    fn loop_spaced_beyond_window() {
        let clk = FakeClock::default();
        let g = guard(&loop_limits(), &clk);
        for _ in 0..5 {
            g.record_outcome("k", true);
            clk.advance(Duration::from_secs(2));
        }
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn loop_exactly_window_apart_ages_out() {
        // Go keeps timestamps strictly After(now - window).
        let clk = FakeClock::default();
        let g = guard(
            &limits(|l| {
                l.loop_window = "1s".into();
                l.loop_threshold = 2;
            }),
            &clk,
        );
        g.record_outcome("k", true);
        clk.advance(Duration::from_secs(1));
        g.record_outcome("k", true);
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn loop_below_threshold() {
        let clk = FakeClock::default();
        let g = guard(&loop_limits(), &clk);
        g.record_outcome("k", true);
        g.record_outcome("k", true);
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn loop_success_resets_window() {
        let clk = FakeClock::default();
        let g = guard(&loop_limits(), &clk);
        g.record_outcome("k", true);
        g.record_outcome("k", true);
        g.record_outcome("k", false);
        g.record_outcome("k", true);
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn loop_per_key_isolation() {
        let clk = FakeClock::default();
        let g = guard(&loop_limits(), &clk);
        for k in ["a", "b", "a", "b"] {
            g.record_outcome(k, true);
        }
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn loop_disabled() {
        let g = Guard::new(&Limits::default()).expect("guard");
        for _ in 0..100 {
            g.record_outcome("k", true);
        }
        assert_eq!(g.loop_tripped(), None);
    }

    #[test]
    fn reset() {
        let g = Guard::new(&limits(|l| {
            l.max_execs = 1;
            l.loop_window = "1s".into();
            l.loop_threshold = 2;
        }))
        .expect("guard");
        g.start();
        let _ = g.check_exec();
        g.record_outcome("k", true);
        g.record_outcome("k", true);
        assert!(g.loop_tripped().is_some());
        g.reset();
        assert_eq!(g.loop_tripped(), None);
        g.start();
        assert_eq!(g.check_exec(), Ok(()));
    }

    #[test]
    fn concurrent_access() {
        let g = Arc::new(
            Guard::new(&limits(|l| {
                l.loop_window = "1s".into();
                l.loop_threshold = 1000;
            }))
            .expect("guard"),
        );
        g.start();
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let g = g.clone();
                thread::spawn(move || {
                    let _ = g.check_exec();
                    let _ = g.check_egress();
                    g.record_outcome("shared", true);
                    let _ = g.loop_tripped();
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
    }

    #[test]
    fn error_messages_match_go() {
        assert_eq!(
            GuardError::WallClock.to_string(),
            "policy: wall-clock deadline exceeded"
        );
        assert_eq!(
            GuardError::MaxExecs.to_string(),
            "policy: max execs exceeded"
        );
        assert_eq!(
            GuardError::EgressBudget.to_string(),
            "policy: egress budget exceeded"
        );
        assert_eq!(
            GuardError::LoopDetected.to_string(),
            "policy: runaway loop detected"
        );
    }
}
