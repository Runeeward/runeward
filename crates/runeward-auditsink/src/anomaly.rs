//! A lightweight, in-process behavioural anomaly detector that plugs into
//! the audit-sink chain.
//!
//! It watches the stream of ledger events and emits structured `tracing`
//! warnings when a session's activity crosses configurable thresholds:
//! contacting too many distinct network destinations, bursting shell
//! executions, or accumulating denials. It keeps only small per-session
//! summaries in memory and never blocks the caller, so it is safe to add to
//! a [`Multi`](crate::Multi) alongside the real sinks.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::Duration;

use chrono::TimeDelta;
use runeward_ledger::Event;
use runeward_ledger::gotime::{self, Time};

use crate::queue::lock;
use crate::{Error, Sink};

/// Distinct network destinations per session before a novel-host anomaly
/// fires. Default 20.
pub const ENV_MAX_HOSTS: &str = "RUNEWARD_ANOMALY_MAX_HOSTS";
/// Shell execs within the window that trip an exec-burst anomaly. Default 30.
pub const ENV_EXEC_BURST: &str = "RUNEWARD_ANOMALY_EXEC_BURST";
/// Sliding window for exec-burst detection, in Go duration syntax.
/// Default 1m.
pub const ENV_WINDOW: &str = "RUNEWARD_ANOMALY_WINDOW";
/// Deny verdicts per session before a denial-spike anomaly fires. Default 10.
pub const ENV_MAX_DENIES: &str = "RUNEWARD_ANOMALY_MAX_DENIES";

const DEFAULT_MAX_HOSTS: usize = 20;
const DEFAULT_EXEC_BURST: usize = 30;
const DEFAULT_WINDOW: Duration = Duration::from_secs(60);
const DEFAULT_MAX_DENIES: usize = 10;

/// Minimum interval between warnings for the same (session, kind) pair, so a
/// sustained anomaly logs at most once per minute.
const WARN_COOLDOWN: TimeDelta = TimeDelta::minutes(1);

/// How many times each anomaly kind has fired (after rate limiting) since
/// the detector was created.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub novel_host: usize,
    pub exec_burst: usize,
    pub denial_spike: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    NovelHost,
    ExecBurst,
    DenialSpike,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::NovelHost => "novel_host",
            Kind::ExecBurst => "exec_burst",
            Kind::DenialSpike => "denial_spike",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Kind::NovelHost => "session contacted an unusual number of distinct destinations",
            Kind::ExecBurst => "session exceeded the shell execution burst threshold",
            Kind::DenialSpike => "session exceeded the denial spike threshold",
        }
    }
}

/// The kind-specific fields of a warning.
enum Detail<'a> {
    NovelHost {
        host: &'a str,
        distinct_hosts: usize,
        threshold: usize,
    },
    ExecBurst {
        execs_in_window: usize,
        threshold: usize,
        window: Duration,
    },
    DenialSpike {
        denies: usize,
        threshold: usize,
    },
}

impl Detail<'_> {
    fn kind(&self) -> Kind {
        match self {
            Detail::NovelHost { .. } => Kind::NovelHost,
            Detail::ExecBurst { .. } => Kind::ExecBurst,
            Detail::DenialSpike { .. } => Kind::DenialSpike,
        }
    }
}

/// The small rolling summary tracked for one session.
#[derive(Default)]
struct SessionState {
    /// Distinct destinations contacted with an allowed verdict.
    hosts: HashSet<String>,
    /// Shell-exec timestamps within the current window, oldest first.
    exec_times: VecDeque<Time>,
    denies: usize,
    /// Last warning time per kind, for rate limiting.
    last_warn: HashMap<Kind, Time>,
}

struct Inner {
    sessions: HashMap<String, SessionState>,
    counts: Counts,
}

type Clock = Box<dyn Fn() -> Time + Send + Sync>;

/// Inspects audit events and warns on anomalous per-session behaviour. It
/// implements [`Sink`] so it composes into a [`Multi`](crate::Multi), and is
/// safe for concurrent use.
pub struct Detector {
    /// Supplies the time for events that carry none; overridable in tests.
    now: Clock,
    max_hosts: usize,
    exec_burst: usize,
    window: Duration,
    max_denies: usize,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("max_hosts", &self.max_hosts)
            .field("exec_burst", &self.exec_burst)
            .field("window", &self.window)
            .field("max_denies", &self.max_denies)
            .finish_non_exhaustive()
    }
}

impl Default for Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector {
    /// A detector with thresholds read from the environment, falling back to
    /// the documented defaults when a variable is unset or invalid.
    pub fn new() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// [`Detector::new`] with an explicit variable lookup.
    pub fn from_lookup<F>(lookup: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        Self {
            now: Box::new(gotime::now),
            max_hosts: env_int(&lookup, ENV_MAX_HOSTS, DEFAULT_MAX_HOSTS),
            exec_burst: env_int(&lookup, ENV_EXEC_BURST, DEFAULT_EXEC_BURST),
            window: env_duration(&lookup, ENV_WINDOW, DEFAULT_WINDOW),
            max_denies: env_int(&lookup, ENV_MAX_DENIES, DEFAULT_MAX_DENIES),
            inner: Mutex::new(Inner {
                sessions: HashMap::new(),
                counts: Counts::default(),
            }),
        }
    }

    /// A snapshot of the anomaly counters.
    pub fn counts(&self) -> Counts {
        lock(&self.inner).counts
    }

    /// Emits a rate-limited warning and, when not suppressed, bumps the
    /// matching counter.
    fn warn(counts: &mut Counts, st: &mut SessionState, t: Time, ev: &Event, detail: Detail<'_>) {
        let kind = detail.kind();
        if let Some(last) = st.last_warn.get(&kind)
            && t.signed_duration_since(*last) < WARN_COOLDOWN
        {
            return;
        }
        st.last_warn.insert(kind, t);
        match kind {
            Kind::NovelHost => counts.novel_host += 1,
            Kind::ExecBurst => counts.exec_burst += 1,
            Kind::DenialSpike => counts.denial_spike += 1,
        }

        const MSG: &str = "agent activity anomaly detected";
        let (anomaly, description) = (kind.as_str(), kind.description());
        let (session_id, sandbox, profile) = (&ev.session_id, &ev.sandbox, &ev.profile);
        match detail {
            Detail::NovelHost {
                host,
                distinct_hosts,
                threshold,
            } => tracing::warn!(
                anomaly,
                description,
                session_id,
                sandbox,
                profile,
                host,
                distinct_hosts,
                threshold,
                "{MSG}"
            ),
            Detail::ExecBurst {
                execs_in_window,
                threshold,
                window,
            } => tracing::warn!(
                anomaly, description, session_id, sandbox, profile,
                execs_in_window, threshold, window = ?window, "{MSG}"
            ),
            Detail::DenialSpike { denies, threshold } => tracing::warn!(
                anomaly,
                description,
                session_id,
                sandbox,
                profile,
                denies,
                threshold,
                "{MSG}"
            ),
        }
    }
}

impl Sink for Detector {
    /// Inspects one event and raises anomaly warnings as needed.
    fn emit(&self, ev: &Event) {
        let t = if gotime::is_zero(&ev.time) {
            (self.now)()
        } else {
            ev.time
        };

        let mut guard = lock(&self.inner);
        let Inner { sessions, counts } = &mut *guard;
        let st = sessions.entry(ev.session_id.clone()).or_default();

        match ev.tool.as_str() {
            "net" | "browser" if ev.verdict == "allow" => {
                let host = parse_host(&ev.action);
                if !host.is_empty() && !st.hosts.contains(&host) {
                    st.hosts.insert(host.clone());
                    if st.hosts.len() > self.max_hosts {
                        let detail = Detail::NovelHost {
                            host: &host,
                            distinct_hosts: st.hosts.len(),
                            threshold: self.max_hosts,
                        };
                        Self::warn(counts, st, t, ev, detail);
                    }
                }
            }
            "shell" => {
                append_within_window(&mut st.exec_times, t, self.window);
                if st.exec_times.len() > self.exec_burst {
                    let detail = Detail::ExecBurst {
                        execs_in_window: st.exec_times.len(),
                        threshold: self.exec_burst,
                        window: self.window,
                    };
                    Self::warn(counts, st, t, ev, detail);
                }
            }
            _ => {}
        }

        if ev.verdict == "deny" {
            st.denies += 1;
            if st.denies > self.max_denies {
                let detail = Detail::DenialSpike {
                    denies: st.denies,
                    threshold: self.max_denies,
                };
                Self::warn(counts, st, t, ev, detail);
            }
        }
    }

    /// The detector holds no external resources.
    fn close(&self) -> Result<(), Error> {
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "anomaly"
    }
}

/// Appends `t` and drops entries older than `window` before it, keeping the
/// deque bounded by the sliding window.
fn append_within_window(times: &mut VecDeque<Time>, t: Time, window: Duration) {
    times.push_back(t);
    let cutoff = TimeDelta::from_std(window)
        .ok()
        .and_then(|w| t.checked_sub_signed(w));
    if let Some(cutoff) = cutoff {
        while times.front().is_some_and(|x| *x < cutoff) {
            times.pop_front();
        }
    }
}

/// Extracts a best-effort, lowercased hostname from an action that may be a
/// bare host, a "host:port", or a full URL; "" when nothing host-like is
/// found.
fn parse_host(action: &str) -> String {
    let mut s = action.trim();
    if s.is_empty() {
        return String::new();
    }
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s = &s[..i];
    }
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    if s.starts_with('[')
        && let Some(i) = s.find(']')
    {
        return s[1..i].trim().to_lowercase();
    }
    if let Some(i) = s.rfind(':') {
        s = &s[..i];
    }
    s.trim().to_lowercase()
}

/// A positive integer from the named variable, or `def`.
fn env_int(lookup: &dyn Fn(&str) -> Option<String>, name: &str, def: usize) -> usize {
    match lookup(name).map(|v| v.trim().parse::<i64>()) {
        Some(Ok(n)) if n > 0 => usize::try_from(n).unwrap_or(def),
        _ => def,
    }
}

/// A positive Go-syntax duration from the named variable, or `def`.
fn env_duration(lookup: &dyn Fn(&str) -> Option<String>, name: &str, def: Duration) -> Duration {
    match lookup(name).and_then(|v| crate::godur::parse_duration_nanos(v.trim())) {
        Some(n) if n > 0 => Duration::from_nanos(n.unsigned_abs()),
        _ => def,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::testutil::env;

    fn base() -> Time {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .unwrap_or_default()
            .fixed_offset()
    }

    fn ms(n: usize) -> TimeDelta {
        TimeDelta::milliseconds(i64::try_from(n).unwrap_or(i64::MAX))
    }

    fn secs(n: usize) -> TimeDelta {
        TimeDelta::seconds(i64::try_from(n).unwrap_or(i64::MAX))
    }

    /// A detector with default thresholds and a controllable clock anchored
    /// at the base time.
    fn new_test_detector() -> (Detector, Arc<AtomicI64>) {
        let mut d = Detector::from_lookup(env(&[]));
        let offset_ms = Arc::new(AtomicI64::new(0));
        let o = offset_ms.clone();
        d.now = Box::new(move || base() + TimeDelta::milliseconds(o.load(Ordering::SeqCst)));
        (d, offset_ms)
    }

    fn event(session: &str, tool: &str, action: &str, verdict: &str, when: Time) -> Event {
        Event {
            session_id: session.into(),
            tool: tool.into(),
            action: action.into(),
            verdict: verdict.into(),
            time: when,
            ..Event::default()
        }
    }

    fn shell_event(session: &str, when: Time) -> Event {
        event(session, "shell", "echo hi", "allow", when)
    }

    fn net_event(session: &str, action: &str, when: Time) -> Event {
        event(session, "net", action, "allow", when)
    }

    fn deny_event(session: &str, when: Time) -> Event {
        event(session, "shell", "rm -rf /", "deny", when)
    }

    #[test]
    fn exec_burst_within_window() {
        let (d, _) = new_test_detector();
        for i in 0..d.exec_burst + 5 {
            d.emit(&shell_event("s1", base() + ms(i)));
        }
        assert_eq!(d.counts().exec_burst, 1, "exactly 1 (rate limited)");
    }

    #[test]
    fn exec_burst_spaced_beyond_window_does_not_fire() {
        let (d, _) = new_test_detector();
        let window = TimeDelta::from_std(d.window).unwrap_or_default();
        for i in 0..d.exec_burst + 5 {
            let when = base() + window * i32::try_from(2 * i).unwrap_or(i32::MAX);
            d.emit(&shell_event("s1", when));
        }
        assert_eq!(d.counts().exec_burst, 0, "events outside window");
    }

    #[test]
    fn novel_host_threshold() {
        let (d, _) = new_test_detector();
        for i in 0..=d.max_hosts {
            let action = format!("https://host{i}.example.com:443/path");
            d.emit(&net_event("s1", &action, base() + secs(i)));
        }
        assert_eq!(d.counts().novel_host, 1);
    }

    #[test]
    fn novel_host_repeated_same_host_does_not_fire() {
        let (d, _) = new_test_detector();
        for i in 0..d.max_hosts + 50 {
            d.emit(&net_event(
                "s1",
                "https://only.example.com/x",
                base() + secs(i),
            ));
        }
        assert_eq!(d.counts().novel_host, 0, "single distinct host");
    }

    #[test]
    fn novel_host_ignores_denied_and_other_tools() {
        let (d, _) = new_test_detector();
        for i in 0..d.max_hosts * 2 {
            let action = format!("host{i}.example.com");
            d.emit(&event("s1", "net", &action, "deny", base() + secs(i)));
            d.emit(&event(
                "s2",
                "file.read",
                &action,
                "allow",
                base() + secs(i),
            ));
        }
        assert_eq!(d.counts().novel_host, 0);
    }

    #[test]
    fn browser_counts_as_network() {
        let (d, _) = new_test_detector();
        for i in 0..=d.max_hosts {
            let action = format!("https://host{i}.example.com/");
            d.emit(&event("s1", "browser", &action, "allow", base() + secs(i)));
        }
        assert_eq!(d.counts().novel_host, 1);
    }

    #[test]
    fn denial_spike_threshold() {
        let (d, _) = new_test_detector();
        for i in 0..=d.max_denies {
            d.emit(&deny_event("s1", base() + ms(i)));
        }
        assert_eq!(d.counts().denial_spike, 1);
    }

    #[test]
    fn sessions_tracked_independently() {
        let (d, _) = new_test_detector();
        for i in 0..d.exec_burst + 5 {
            d.emit(&shell_event("s1", base() + ms(i)));
        }
        for i in 0..d.exec_burst / 2 {
            d.emit(&shell_event("s2", base() + ms(i)));
        }
        assert_eq!(d.counts().exec_burst, 1, "only s1 should trip");
    }

    #[test]
    fn rate_limit_recovers_after_cooldown() {
        let (d, _) = new_test_detector();
        for i in 0..d.exec_burst + 2 {
            d.emit(&shell_event("s1", base() + ms(i)));
        }
        assert_eq!(d.counts().exec_burst, 1, "after first burst");

        // A second burst more than a cooldown later fires again.
        let second = base() + WARN_COOLDOWN * 2;
        for i in 0..d.exec_burst + 2 {
            d.emit(&shell_event("s1", second + ms(i)));
        }
        assert_eq!(d.counts().exec_burst, 2, "after second burst");
    }

    #[test]
    fn zero_time_uses_clock() {
        let (d, offset) = new_test_detector();
        for _ in 0..d.exec_burst + 1 {
            d.emit(&shell_event("s1", gotime::zero()));
        }
        assert_eq!(d.counts().exec_burst, 1);
        // Two windows later on the clock, the old execs have aged out.
        offset.store(180_000, Ordering::SeqCst);
        d.emit(&shell_event("s1", gotime::zero()));
        let inner = lock(&d.inner);
        assert_eq!(inner.sessions["s1"].exec_times.len(), 1);
    }

    #[test]
    fn thresholds_from_env() {
        let d = Detector::from_lookup(env(&[
            (ENV_MAX_HOSTS, "3"),
            (ENV_EXEC_BURST, " 4 "),
            (ENV_WINDOW, "1h30m"),
            (ENV_MAX_DENIES, "5"),
        ]));
        assert_eq!(d.max_hosts, 3);
        assert_eq!(d.exec_burst, 4);
        assert_eq!(d.window, Duration::from_secs(5400));
        assert_eq!(d.max_denies, 5);

        let d = Detector::from_lookup(env(&[
            (ENV_MAX_HOSTS, "0"),
            (ENV_EXEC_BURST, "-4"),
            (ENV_WINDOW, "-1s"),
            (ENV_MAX_DENIES, "ten"),
        ]));
        assert_eq!(d.max_hosts, DEFAULT_MAX_HOSTS);
        assert_eq!(d.exec_burst, DEFAULT_EXEC_BURST);
        assert_eq!(d.window, DEFAULT_WINDOW);
        assert_eq!(d.max_denies, DEFAULT_MAX_DENIES);
    }

    #[test]
    fn parse_host_cases() {
        let cases = [
            ("https://example.com/path", "example.com"),
            ("example.com:443", "example.com"),
            ("http://user:pass@Foo.com/", "foo.com"),
            ("bare.host", "bare.host"),
            ("[::1]:8080", "::1"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(parse_host(input), want, "parse_host({input:?})");
        }
    }

    #[test]
    fn detector_composes_into_multi() {
        let (d, _) = new_test_detector();
        let m = crate::Multi::new(vec![Box::new(d)]);
        m.emit(&shell_event("s1", base()));
        assert_eq!(m.kinds(), vec!["anomaly"]);
        assert!(m.close().is_ok());
    }
}
