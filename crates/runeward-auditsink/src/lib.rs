//! Streams audit ledger events to external sinks (webhook, SIEM, OTLP
//! collector or file) in real time.
//!
//! Sinks sit on the ledger append path: [`Sink::emit`] never blocks the
//! caller and never fails. Network sinks buffer events in a bounded queue
//! drained by a background worker thread; when the queue overflows the oldest
//! event is dropped and counted rather than stalling the producer.
//!
//! The JSON written to files and webhooks is the ledger's Go-compatible
//! encoding ([`Event::to_json`]), so consumers see the same bytes whichever
//! implementation produced them.
//!
//! [`anomaly`] adds a per-session behavioural detector that composes into a
//! [`Multi`] alongside the real sinks.

pub mod anomaly;
mod file;
mod godur;
mod otlp;
mod queue;
mod webhook;

#[cfg(test)]
mod testhttp;

use std::collections::BTreeMap;
use std::fmt;
use std::io;

use runeward_ledger::Event;

pub use file::FileSink;
pub use otlp::{OtlpSink, OtlpSinkConfig};
pub use webhook::{WebhookConfig, WebhookSink};

/// Receives audit events. `emit` must be non-blocking and must never fail or
/// stall the caller. `close` flushes best-effort and stops any workers.
pub trait Sink: Send + Sync {
    /// Hands one event to the sink. Never blocks, never fails.
    fn emit(&self, ev: &Event);

    /// Flushes best-effort and stops background work. Calling it more than
    /// once is harmless.
    fn close(&self) -> Result<(), Error>;

    /// A short name for the sink's kind ("file", "webhook", "otlp", ...),
    /// used in diagnostics.
    fn kind(&self) -> &'static str {
        "custom"
    }
}

/// Fans a single event out to several sinks. A `Multi` with no sinks is a
/// no-op, so callers never have to special-case "nothing configured".
#[derive(Default)]
pub struct Multi {
    sinks: Vec<Box<dyn Sink>>,
}

impl Multi {
    /// Builds a fan-out over `sinks`.
    pub fn new(sinks: Vec<Box<dyn Sink>>) -> Self {
        Self { sinks }
    }

    /// Adds another sink to the fan-out.
    pub fn push(&mut self, sink: Box<dyn Sink>) {
        self.sinks.push(sink);
    }

    /// Number of underlying sinks.
    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    /// Reports whether nothing is configured (the sink is a no-op).
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    /// The kind of each underlying sink, in fan-out order.
    pub fn kinds(&self) -> Vec<&'static str> {
        self.sinks.iter().map(|s| s.kind()).collect()
    }
}

impl fmt::Debug for Multi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Multi")
            .field("sinks", &self.kinds())
            .finish()
    }
}

impl Sink for Multi {
    fn emit(&self, ev: &Event) {
        for s in &self.sinks {
            s.emit(ev);
        }
    }

    /// Closes every underlying sink, returning the first error while still
    /// closing the rest.
    fn close(&self) -> Result<(), Error> {
        let mut first = None;
        for s in &self.sinks {
            if let Err(e) = s.close() {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }

    fn kind(&self) -> &'static str {
        if self.sinks.is_empty() {
            "nop"
        } else {
            "multi"
        }
    }
}

/// Errors from building or closing a sink.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Obviously bad configuration (malformed URL, header or list).
    #[error("auditsink: {0}")]
    Config(String),
    /// The audit file could not be opened.
    #[error("open audit file {path:?}: {source}")]
    OpenFile {
        path: String,
        #[source]
        source: io::Error,
    },
    /// An I/O error while closing a sink.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// The OTLP exporter could not be built or shut down cleanly.
    #[error("otlp: {0}")]
    Otlp(String),
}

/// POSTs each event as JSON to the given URL when set.
pub const ENV_WEBHOOK_URL: &str = "RUNEWARD_AUDIT_WEBHOOK_URL";
/// Optionally adds one "Key: Value" header to every webhook request, e.g.
/// "Authorization: Bearer <token>".
pub const ENV_WEBHOOK_HEADER: &str = "RUNEWARD_AUDIT_WEBHOOK_HEADER";
/// Appends each event as one JSON line to the file when set.
pub const ENV_FILE: &str = "RUNEWARD_AUDIT_FILE";
/// Exports each event as an OTLP log record when set.
pub const ENV_OTLP_ENDPOINT: &str = "RUNEWARD_AUDIT_OTLP_ENDPOINT";
/// Optional OTLP headers as "k=v,k2=v2".
pub const ENV_OTLP_HEADERS: &str = "RUNEWARD_AUDIT_OTLP_HEADERS";
/// Forces plain-HTTP OTLP transport when true.
pub const ENV_OTLP_INSECURE: &str = "RUNEWARD_AUDIT_OTLP_INSECURE";
/// Sets resource attribute "service.name".
pub const ENV_OTLP_SERVICE_NAME: &str = "RUNEWARD_AUDIT_OTLP_SERVICE_NAME";
/// Sets resource attributes as "k=v,k2=v2".
pub const ENV_OTLP_RESOURCE_ATTRS: &str = "RUNEWARD_AUDIT_OTLP_RESOURCE_ATTRS";

/// Builds a sink from the process environment. With no relevant variables
/// set it returns an empty (no-op) [`Multi`]. It fails only on obviously bad
/// configuration: a malformed URL, an unopenable file, a malformed header or
/// list.
pub fn from_env() -> Result<Multi, Error> {
    from_lookup(|k| std::env::var(k).ok())
}

/// [`from_env`] with an explicit variable lookup, for callers (and tests)
/// that resolve configuration from somewhere other than the process
/// environment.
pub fn from_lookup<F>(lookup: F) -> Result<Multi, Error>
where
    F: Fn(&str) -> Option<String>,
{
    let get = |k: &str| lookup(k).map(|v| v.trim().to_owned()).unwrap_or_default();
    let mut multi = Multi::default();

    let raw = get(ENV_WEBHOOK_URL);
    if !raw.is_empty() {
        let u = reqwest::Url::parse(&raw)
            .map_err(|e| Error::Config(format!("invalid {ENV_WEBHOOK_URL}: {e}")))?;
        if u.scheme() != "http" && u.scheme() != "https" {
            return Err(Error::Config(format!(
                "{ENV_WEBHOOK_URL} must be an http(s) URL, got {raw:?}"
            )));
        }
        if u.host_str().unwrap_or_default().is_empty() {
            return Err(Error::Config(format!(
                "{ENV_WEBHOOK_URL} has no host: {raw:?}"
            )));
        }

        let mut cfg = WebhookConfig::new(raw);
        let h = get(ENV_WEBHOOK_HEADER);
        if !h.is_empty() {
            let Some((k, v)) = h.split_once(':') else {
                return Err(Error::Config(format!(
                    "{ENV_WEBHOOK_HEADER} must be \"Key: Value\" form, got {h:?}"
                )));
            };
            let key = k.trim();
            if key.is_empty() {
                return Err(Error::Config(format!(
                    "{ENV_WEBHOOK_HEADER} has empty header name: {h:?}"
                )));
            }
            cfg.header = Some((key.to_owned(), v.trim().to_owned()));
        }
        multi.push(Box::new(WebhookSink::new(cfg)));
    }

    let path = get(ENV_FILE);
    if !path.is_empty() {
        let fs = FileSink::open(&path).map_err(|e| Error::Config(format!("{ENV_FILE}: {e}")))?;
        multi.push(Box::new(fs));
    }

    let endpoint = get(ENV_OTLP_ENDPOINT);
    if !endpoint.is_empty() {
        let mut cfg = OtlpSinkConfig::new(endpoint);

        let raw = get(ENV_OTLP_HEADERS);
        if !raw.is_empty() {
            cfg.headers = parse_kv_list(&raw)
                .map_err(|e| Error::Config(format!("invalid {ENV_OTLP_HEADERS}: {e}")))?;
        }
        let raw = get(ENV_OTLP_INSECURE);
        if !raw.is_empty() {
            cfg.insecure = parse_go_bool(&raw).ok_or_else(|| {
                Error::Config(format!(
                    "invalid {ENV_OTLP_INSECURE}: strconv.ParseBool: parsing {raw:?}: invalid syntax"
                ))
            })?;
        }
        let raw = get(ENV_OTLP_RESOURCE_ATTRS);
        if !raw.is_empty() {
            cfg.resource_attributes = parse_kv_list(&raw)
                .map_err(|e| Error::Config(format!("invalid {ENV_OTLP_RESOURCE_ATTRS}: {e}")))?;
        }
        cfg.service_name = get(ENV_OTLP_SERVICE_NAME);

        let sink =
            OtlpSink::new(cfg).map_err(|e| Error::Config(format!("{ENV_OTLP_ENDPOINT}: {e}")))?;
        multi.push(Box::new(sink));
    }

    Ok(multi)
}

/// Parses "k=v,k2=v2", trimming whitespace and skipping empty items. At least
/// one pair is required.
fn parse_kv_list(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for part in raw.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        let Some((k, v)) = item.split_once('=') else {
            return Err(format!("invalid item {item:?} (want key=value)"));
        };
        let key = k.trim();
        if key.is_empty() {
            return Err(format!("empty key in {item:?}"));
        }
        out.insert(key.to_owned(), v.trim().to_owned());
    }
    if out.is_empty() {
        return Err("no key=value pairs found".to_owned());
    }
    Ok(out)
}

/// Go's `strconv.ParseBool`.
fn parse_go_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::collections::HashMap;

    use chrono::{TimeZone, Utc};
    use runeward_ledger::Event;

    pub fn sample_event() -> Event {
        Event {
            seq: 7,
            time: Utc
                .with_ymd_and_hms(2026, 7, 4, 17, 0, 0)
                .single()
                .unwrap_or_default()
                .fixed_offset(),
            session_id: "sess-abc".into(),
            sandbox: "sbx-1".into(),
            profile: "default".into(),
            tool: "shell".into(),
            action: "rm -rf /tmp/x".into(),
            args: vec!["-rf".into(), "/tmp/x".into()],
            verdict: "allow".into(),
            hash: "deadbeef".into(),
            ..Event::default()
        }
    }

    /// An environment lookup over fixed pairs.
    pub fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::testutil::{env, sample_event};
    use super::*;

    #[test]
    fn from_env_nop_when_unset() {
        let s = from_lookup(env(&[(ENV_WEBHOOK_URL, ""), (ENV_FILE, "")])).unwrap();
        assert_eq!(s.kind(), "nop");
        assert!(s.is_empty());
        s.emit(&sample_event());
        s.close().unwrap();
    }

    #[test]
    fn from_env_invalid_url() {
        assert!(from_lookup(env(&[(ENV_WEBHOOK_URL, "not-a-valid-scheme://%zz")])).is_err());
    }

    #[test]
    fn from_env_rejects_non_http_url() {
        assert!(from_lookup(env(&[(ENV_WEBHOOK_URL, "ftp://example.com/hook")])).is_err());
    }

    #[test]
    fn from_env_bad_header() {
        let r = from_lookup(env(&[
            (ENV_WEBHOOK_URL, "https://example.com/hook"),
            (ENV_WEBHOOK_HEADER, "no-colon-here"),
        ]));
        assert!(r.is_err());
    }

    #[test]
    fn from_env_empty_header_name() {
        let r = from_lookup(env(&[
            (ENV_WEBHOOK_URL, "https://example.com/hook"),
            (ENV_WEBHOOK_HEADER, " : value"),
        ]));
        assert!(r.is_err());
    }

    #[test]
    fn from_env_builds_multi() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = from_lookup(env(&[
            (ENV_WEBHOOK_URL, "https://example.com/hook"),
            (ENV_FILE, path.to_str().unwrap()),
        ]))
        .unwrap();
        assert_eq!(s.kind(), "multi");
        assert_eq!(s.kinds(), vec!["webhook", "file"]);
        s.close().unwrap();
    }

    #[test]
    fn from_env_builds_otlp_sink() {
        let s = from_lookup(env(&[
            (ENV_WEBHOOK_URL, ""),
            (ENV_FILE, ""),
            (ENV_OTLP_ENDPOINT, "http://localhost:4318/v1/logs"),
            (ENV_OTLP_HEADERS, "authorization=Bearer x"),
            (ENV_OTLP_INSECURE, "true"),
            (ENV_OTLP_SERVICE_NAME, "runeward"),
            (ENV_OTLP_RESOURCE_ATTRS, "deployment.environment=test"),
        ]))
        .unwrap();
        assert_eq!(s.kinds(), vec!["otlp"]);
        let _ = s.close();
    }

    #[test]
    fn from_env_rejects_invalid_otlp_vars() {
        let ep = (ENV_OTLP_ENDPOINT, "http://localhost:4318/v1/logs");
        assert!(from_lookup(env(&[ep, (ENV_OTLP_HEADERS, "not-valid")])).is_err());
        assert!(from_lookup(env(&[ep, (ENV_OTLP_INSECURE, "not-bool")])).is_err());
        assert!(from_lookup(env(&[ep, (ENV_OTLP_RESOURCE_ATTRS, "bad-attrs")])).is_err());
        assert!(from_lookup(env(&[(ENV_OTLP_ENDPOINT, "ftp://collector/v1/logs")])).is_err());
    }

    #[test]
    fn from_env_builds_otlp_and_file_sinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = from_lookup(env(&[
            (ENV_WEBHOOK_URL, ""),
            (ENV_OTLP_ENDPOINT, "http://localhost:4318/v1/logs"),
            (ENV_OTLP_INSECURE, "true"),
            (ENV_FILE, path.to_str().unwrap()),
        ]))
        .unwrap();
        assert_eq!(s.len(), 2);
        let _ = s.close();
    }

    #[test]
    fn kv_list_parsing() {
        let m = parse_kv_list(" a = 1 ,, b=2=3 ").unwrap();
        assert_eq!(m.get("a").map(String::as_str), Some("1"));
        assert_eq!(m.get("b").map(String::as_str), Some("2=3"));
        assert!(parse_kv_list(" , ").is_err());
        assert!(parse_kv_list("=v").is_err());
    }

    #[test]
    fn go_bool_parsing() {
        for t in ["1", "t", "T", "TRUE", "true", "True"] {
            assert_eq!(parse_go_bool(t), Some(true), "{t}");
        }
        for f in ["0", "f", "F", "FALSE", "false", "False"] {
            assert_eq!(parse_go_bool(f), Some(false), "{f}");
        }
        assert_eq!(parse_go_bool("yes"), None);
        assert_eq!(parse_go_bool("tRUE"), None);
    }

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<i64>>,
        fail_close: bool,
    }

    struct Shared(Arc<Recorder>);

    impl Sink for Shared {
        fn emit(&self, ev: &Event) {
            self.0.seen.lock().unwrap().push(ev.seq);
        }
        fn close(&self) -> Result<(), Error> {
            if self.0.fail_close {
                Err(Error::Otlp("boom".into()))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn multi_fans_out_and_returns_first_close_error() {
        let a = Arc::new(Recorder::default());
        let b = Arc::new(Recorder {
            fail_close: true,
            ..Recorder::default()
        });
        let c = Arc::new(Recorder::default());
        let m = Multi::new(vec![
            Box::new(Shared(a.clone())),
            Box::new(Shared(b.clone())),
            Box::new(Shared(c.clone())),
        ]);
        m.emit(&sample_event());
        for r in [&a, &b, &c] {
            assert_eq!(*r.seen.lock().unwrap(), vec![7]);
        }
        assert!(matches!(m.close(), Err(Error::Otlp(_))));
    }
}
