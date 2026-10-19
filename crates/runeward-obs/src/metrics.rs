//! Prometheus metrics, with the same names as the Go build.

use std::sync::LazyLock;

use prometheus::{
    Counter, CounterVec, Encoder, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry,
    TextEncoder,
};

struct Metrics {
    registry: Registry,
    actions_total: CounterVec,
    action_duration: HistogramVec,
    sandboxes_created: Counter,
    build_info: GaugeVec,
}

// The names and label sets below are static and valid, so registration
// cannot fail; `expect` documents that invariant.
#[allow(clippy::expect_used)]
static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let registry = Registry::new();

    let actions_total = CounterVec::new(
        Opts::new(
            "total",
            "Governed actions processed, labeled by tool and verdict.",
        )
        .namespace("runeward")
        .subsystem("actions"),
        &["tool", "verdict"],
    )
    .expect("actions_total");
    let action_duration = HistogramVec::new(
        HistogramOpts::new(
            "duration_seconds",
            "Wall-clock duration of executed governed actions.",
        )
        .namespace("runeward")
        .subsystem("actions")
        .buckets(prometheus::DEFAULT_BUCKETS.to_vec()),
        &["tool"],
    )
    .expect("action_duration");
    let sandboxes_created = Counter::with_opts(
        Opts::new("created_total", "Total number of sandboxes created.")
            .namespace("runeward")
            .subsystem("sandboxes"),
    )
    .expect("sandboxes_created");
    let build_info = GaugeVec::new(
        Opts::new(
            "build_info",
            "Build metadata; always 1, labeled by version.",
        )
        .namespace("runeward"),
        &["version"],
    )
    .expect("build_info");

    registry
        .register(Box::new(actions_total.clone()))
        .expect("register actions_total");
    registry
        .register(Box::new(action_duration.clone()))
        .expect("register action_duration");
    registry
        .register(Box::new(sandboxes_created.clone()))
        .expect("register sandboxes_created");
    registry
        .register(Box::new(build_info.clone()))
        .expect("register build_info");

    Metrics {
        registry,
        actions_total,
        action_duration,
        sandboxes_created,
        build_info,
    }
});

/// The registry behind `/metrics`; other crates may register their own
/// collectors on it.
pub fn registry() -> &'static Registry {
    &METRICS.registry
}

/// Records one governed action outcome. A non-positive `duration_ms`
/// (denied or non-executed actions) skips the duration observation.
pub fn record_action(tool: &str, verdict: &str, duration_ms: i64) {
    METRICS
        .actions_total
        .with_label_values(&[tool, verdict])
        .inc();
    if duration_ms > 0 {
        METRICS
            .action_duration
            .with_label_values(&[tool])
            .observe(duration_ms as f64 / 1000.0);
    }
}

/// Bumps the sandbox-creation counter.
pub fn inc_sandbox_created() {
    METRICS.sandboxes_created.inc();
}

/// Publishes the running version as a `build_info` gauge.
pub fn set_build_info(version: &str) {
    METRICS.build_info.with_label_values(&[version]).set(1.0);
}

/// Renders the Prometheus text exposition for `/metrics`, returning the
/// content type and body so any HTTP layer can serve it.
pub fn metrics_handler() -> (&'static str, Vec<u8>) {
    let encoder = TextEncoder::new();
    let mut body = Vec::new();
    if let Err(err) = encoder.encode(&METRICS.registry.gather(), &mut body) {
        tracing::warn!(%err, "obs: encoding metrics failed");
    }
    (prometheus::TEXT_FORMAT, body)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scrape() -> String {
        let (ct, body) = metrics_handler();
        assert_eq!(ct, "text/plain; version=0.0.4");
        String::from_utf8(body).unwrap()
    }

    #[test]
    fn records_actions_with_go_names() {
        record_action("metrics-test", "allow", 1500);
        record_action("metrics-test", "deny", 0);
        let out = scrape();
        assert!(
            out.contains("# TYPE runeward_actions_total counter"),
            "{out}"
        );
        assert!(out.contains(r#"runeward_actions_total{tool="metrics-test",verdict="allow"} 1"#));
        assert!(out.contains(r#"runeward_actions_total{tool="metrics-test",verdict="deny"} 1"#));
        assert!(out.contains("# TYPE runeward_actions_duration_seconds histogram"));
        assert!(out.contains(r#"runeward_actions_duration_seconds_count{tool="metrics-test"} 1"#));
        assert!(out.contains(r#"runeward_actions_duration_seconds_sum{tool="metrics-test"} 1.5"#));
        assert!(out.contains(
            r#"runeward_actions_duration_seconds_bucket{tool="metrics-test",le="2.5"} 1"#
        ));
        assert!(
            out.contains(
                r#"runeward_actions_duration_seconds_bucket{tool="metrics-test",le="1"} 0"#
            )
        );
    }

    #[test]
    fn sandbox_counter_and_build_info() {
        inc_sandbox_created();
        set_build_info("9.9.9-test");
        let out = scrape();
        assert!(out.contains("# TYPE runeward_sandboxes_created_total counter"));
        assert!(out.contains("runeward_sandboxes_created_total "));
        assert!(out.contains(r#"runeward_build_info{version="9.9.9-test"} 1"#));
        assert!(
            out.contains(
                "# HELP runeward_build_info Build metadata; always 1, labeled by version."
            )
        );
    }

    #[test]
    fn default_buckets_match_go() {
        assert_eq!(
            prometheus::DEFAULT_BUCKETS,
            &[
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
            ]
        );
    }
}
