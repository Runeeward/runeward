//! Per-sandbox and per-Charter token and spend accounting with budget checks.
//!
//! Usage is also exported as Prometheus counters on the default registry,
//! labeled by Charter (`profile`). The metric names are identical to the Go
//! implementation because the shipped Grafana dashboards and Prometheus alert
//! rules query them:
//!
//! * `runeward_usage_tokens_total{profile}`
//! * `runeward_usage_cost_usd_total{profile}`

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use prometheus::{CounterVec, Opts};

/// Name of the token counter.
pub const TOKENS_METRIC: &str = "runeward_usage_tokens_total";
/// Name of the spend counter.
pub const COST_METRIC: &str = "runeward_usage_cost_usd_total";

struct Metrics {
    tokens: CounterVec,
    cost_usd: CounterVec,
}

/// Registered exactly once per process, as in Go, so creating many trackers
/// (e.g. in tests) never double-registers.
static METRICS: LazyLock<Metrics> = LazyLock::new(|| Metrics {
    tokens: counter("tokens_total", "Total tokens consumed, labeled by profile."),
    cost_usd: counter("cost_usd_total", "Total spend in USD, labeled by profile."),
});

fn counter(name: &str, help: &str) -> CounterVec {
    let opts = Opts::new(name, help)
        .namespace("runeward")
        .subsystem("usage");
    #[allow(clippy::expect_used)] // static, well-formed metric definitions
    let vec = CounterVec::new(opts, &["profile"]).expect("valid counter definition");
    if let Err(err) = prometheus::register(Box::new(vec.clone())) {
        // Still count in-process; only the export is lost.
        tracing::warn!(metric = name, error = %err, "runeward: usage metric not registered");
    }
    vec
}

/// A running total of tokens and spend.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Usage {
    /// Model tokens consumed.
    pub tokens: i64,
    /// Spend in US dollars.
    pub cost_usd: f64,
}

impl Usage {
    fn add(&mut self, tokens: i64, cost_usd: f64) {
        self.tokens = self.tokens.saturating_add(tokens);
        self.cost_usd += cost_usd;
    }
}

#[derive(Debug, Default)]
struct Totals {
    sandbox: HashMap<String, Usage>,
    profile: HashMap<String, Usage>,
}

/// Accumulates usage per sandbox and per Charter. Safe for concurrent use.
#[derive(Debug, Default)]
pub struct Tracker {
    totals: Mutex<Totals>,
}

impl Tracker {
    /// A ready-to-use tracker.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Totals> {
        self.totals.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Adds tokens and cost to both the sandbox and Charter (`profile`)
    /// totals and increments the Prometheus counters for the Charter.
    /// Negative inputs are clamped to zero.
    pub fn record(&self, profile: &str, sandbox: &str, tokens: i64, cost_usd: f64) {
        let tokens = tokens.max(0);
        // `!(x > 0)` also clamps NaN, which Go would propagate.
        let cost_usd = if cost_usd > 0.0 { cost_usd } else { 0.0 };
        {
            let mut t = self.lock();
            t.sandbox
                .entry(sandbox.to_owned())
                .or_default()
                .add(tokens, cost_usd);
            t.profile
                .entry(profile.to_owned())
                .or_default()
                .add(tokens, cost_usd);
        }
        let m = &*METRICS;
        #[allow(clippy::cast_precision_loss)] // counters are f64, as in Go
        m.tokens.with_label_values(&[profile]).inc_by(tokens as f64);
        m.cost_usd.with_label_values(&[profile]).inc_by(cost_usd);
    }

    /// Current totals for a sandbox; unknown sandboxes are zero.
    pub fn usage(&self, sandbox: &str) -> Usage {
        self.lock()
            .sandbox
            .get(sandbox)
            .copied()
            .unwrap_or_default()
    }

    /// Cumulative totals for a Charter; unknown Charters are zero.
    pub fn profile_usage(&self, profile: &str) -> Usage {
        self.lock()
            .profile
            .get(profile)
            .copied()
            .unwrap_or_default()
    }

    /// Reports whether a sandbox's usage meets or exceeds a positive limit,
    /// returning a human-readable explanation when it does. A limit `<= 0`
    /// means "no limit" for that dimension.
    pub fn over(&self, sandbox: &str, max_tokens: i64, max_cost_usd: f64) -> Option<String> {
        let u = self.usage(sandbox);
        if max_tokens > 0 && u.tokens >= max_tokens {
            return Some(format!(
                "token budget exhausted: {}/{} tokens used",
                u.tokens, max_tokens
            ));
        }
        if max_cost_usd > 0.0 && u.cost_usd >= max_cost_usd {
            return Some(format!(
                "cost budget exhausted: ${:.4}/${:.4} spent",
                u.cost_usd, max_cost_usd
            ));
        }
        None
    }

    /// Drops a sandbox's entry (typically when it is killed); Charter totals
    /// are cumulative and kept.
    pub fn forget(&self, sandbox: &str) {
        self.lock().sandbox.remove(sandbox);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn usage(tokens: i64, cost_usd: f64) -> Usage {
        Usage { tokens, cost_usd }
    }

    #[test]
    fn record_accumulates() {
        let tr = Tracker::new();
        tr.record("prof-a", "sbx-1", 100, 0.50);
        tr.record("prof-a", "sbx-1", 50, 0.25);
        tr.record("prof-a", "sbx-2", 10, 0.10);
        assert_eq!(tr.usage("sbx-1"), usage(150, 0.75));
        assert_eq!(tr.usage("sbx-2"), usage(10, 0.10));
        let p = tr.profile_usage("prof-a");
        assert_eq!(p.tokens, 160);
        // Same float sums as Go's 0.50 + 0.25 + 0.10.
        assert_eq!(p.cost_usd, 0.50 + 0.25 + 0.10);
        assert!((p.cost_usd - 0.85).abs() < 1e-12);
    }

    #[test]
    fn unknown_is_zero() {
        let tr = Tracker::new();
        assert_eq!(tr.usage("nope"), Usage::default());
        assert_eq!(tr.profile_usage("nope"), Usage::default());
    }

    #[test]
    fn over_token_limit() {
        let tr = Tracker::new();
        tr.record("p", "s", 90, 0.0);
        assert_eq!(tr.over("s", 100, 0.0), None);
        tr.record("p", "s", 10, 0.0);
        assert_eq!(
            tr.over("s", 100, 0.0).as_deref(),
            Some("token budget exhausted: 100/100 tokens used")
        );
        tr.record("p", "s", 5, 0.0);
        assert!(tr.over("s", 100, 0.0).is_some());
    }

    #[test]
    fn over_cost_limit() {
        let tr = Tracker::new();
        tr.record("p", "s", 0, 4.99);
        assert_eq!(tr.over("s", 0, 5.0), None);
        tr.record("p", "s", 0, 0.01);
        assert_eq!(
            tr.over("s", 0, 5.0).as_deref(),
            Some("cost budget exhausted: $5.0000/$5.0000 spent")
        );
    }

    #[test]
    fn zero_and_negative_limits_unlimited() {
        let tr = Tracker::new();
        tr.record("p", "s", 1_000_000, 1_000_000.0);
        assert_eq!(tr.over("s", 0, 0.0), None);
        assert_eq!(tr.over("s", -1, -1.0), None);
    }

    #[test]
    fn negative_inputs_clamped() {
        let tr = Tracker::new();
        tr.record("p", "s", -100, -5.0);
        assert_eq!(tr.usage("s"), Usage::default());
        tr.record("p", "s", 50, 1.0);
        tr.record("p", "s", -10, -0.5);
        assert_eq!(tr.usage("s"), usage(50, 1.0));
    }

    #[test]
    fn forget_keeps_profile_totals() {
        let tr = Tracker::new();
        tr.record("prof", "sbx", 100, 2.0);
        tr.forget("sbx");
        assert_eq!(tr.usage("sbx"), Usage::default());
        assert_eq!(tr.profile_usage("prof"), usage(100, 2.0));
    }

    #[test]
    fn concurrent_record() {
        let tr = Arc::new(Tracker::new());
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let tr = tr.clone();
                thread::spawn(move || {
                    for _ in 0..200 {
                        tr.record("prof", "sbx", 1, 0.01);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        assert_eq!(tr.usage("sbx").tokens, 50 * 200);
    }

    #[test]
    fn metrics_exported_with_go_names() {
        let tr = Tracker::new();
        tr.record("metrics-test-profile", "sbx", 7, 0.5);
        let families = prometheus::gather();
        let find = |name: &str| {
            families
                .iter()
                .find(|f| f.name() == name)
                .unwrap_or_else(|| panic!("metric {name} not registered"))
        };
        for (name, want) in [(TOKENS_METRIC, 7.0), (COST_METRIC, 0.5)] {
            let fam = find(name);
            let metric = fam
                .get_metric()
                .iter()
                .find(|m| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == "profile" && l.value() == "metrics-test-profile")
                })
                .expect("labeled series");
            assert_eq!(metric.get_counter().get_value(), want, "{name}");
        }
        assert_eq!(
            find(TOKENS_METRIC).help(),
            "Total tokens consumed, labeled by profile."
        );
    }
}
