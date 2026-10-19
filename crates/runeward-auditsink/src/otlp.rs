//! A sink that exports each event as an OTLP log record over HTTP/protobuf.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use chrono::Utc;
use opentelemetry::logs::{AnyValue, Logger as _, LoggerProvider as _, Severity};
use opentelemetry::{Key, KeyValue, SpanId, TraceFlags, TraceId};
use opentelemetry_otlp::{LogExporter, Protocol, WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use runeward_ledger::{Event, gotime};

use crate::queue::{DropCounter, DropQueue, Joiner, lock};
use crate::{Error, Sink};

/// Bounds how long `close` waits for the worker to drain, and then again for
/// the exporter to flush and shut down.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-export HTTP timeout (the OTLP exporter default).
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
/// Instrumentation scope and event name of every audit record.
const SCOPE: &str = "runeward.audit";

/// Configures OTLP audit export. Only `endpoint` is required: the full
/// logs URL, e.g. `https://collector:4318/v1/logs`.
#[derive(Debug, Clone, Default)]
pub struct OtlpSinkConfig {
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    /// Forces plain HTTP even for an `https://` endpoint.
    pub insecure: bool,
    /// Sets resource attribute `service.name` when non-empty.
    pub service_name: String,
    pub resource_attributes: BTreeMap<String, String>,
    /// Overrides the default bounded queue size (1024) when > 0.
    pub queue_size: usize,
}

impl OtlpSinkConfig {
    /// A config exporting to `endpoint` with every other setting at its
    /// default.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            ..Self::default()
        }
    }
}

struct Shared {
    queue: DropQueue<Event>,
    drops: DropCounter,
}

/// Exports audit events as OTLP log records through a bounded queue and a
/// background worker; `emit` never blocks.
pub struct OtlpSink {
    shared: Arc<Shared>,
    joiner: Joiner<Result<(), String>>,
}

impl std::fmt::Debug for OtlpSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtlpSink").finish_non_exhaustive()
    }
}

impl OtlpSink {
    /// Validates the config, builds the exporter and starts the worker.
    pub fn new(cfg: OtlpSinkConfig) -> Result<Self, Error> {
        let endpoint = cfg.endpoint.trim();
        if endpoint.is_empty() {
            return Err(Error::Otlp("endpoint is required".into()));
        }
        let mut url = parse_endpoint(endpoint)?;
        if cfg.insecure && url.scheme() == "https" {
            // Go's exporter dials plain HTTP whenever insecure is set.
            let _ = url.set_scheme("http");
        }
        let shared = Arc::new(Shared {
            queue: DropQueue::new(cfg.queue_size),
            drops: DropCounter::default(),
        });

        // The exporter's blocking HTTP client owns an internal runtime that
        // must not be created or dropped inside an async context, so the
        // whole pipeline lives on the worker thread.
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let (done, joiner) = Joiner::new();
        let worker_shared = shared.clone();
        let endpoint = url.to_string();
        thread::Builder::new()
            .name("auditsink-otlp".into())
            .spawn(move || {
                let provider = match build_provider(&endpoint, &cfg) {
                    Ok(p) => {
                        let _ = ready_tx.send(Ok(()));
                        p
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let logger = provider.logger(SCOPE);
                while let Some(ev) = worker_shared.queue.pop() {
                    let mut rec = logger.create_log_record();
                    RecordFields::from_event(&ev).apply(&mut rec);
                    logger.emit(rec);
                }
                let mut result = provider.force_flush().map_err(|e| e.to_string());
                if let Err(e) = provider.shutdown_with_timeout(CLOSE_TIMEOUT) {
                    result = result.and(Err(e.to_string()));
                }
                let _ = done.send(result);
            })
            .map_err(|e| Error::Otlp(format!("start worker: {e}")))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { shared, joiner }),
            Ok(Err(e)) => Err(Error::Otlp(e)),
            Err(_) => Err(Error::Otlp("worker exited during setup".into())),
        }
    }
}

impl Sink for OtlpSink {
    fn emit(&self, ev: &Event) {
        if self.shared.queue.push(ev.clone())
            && let Some(n) = self.shared.drops.record()
        {
            tracing::warn!(
                dropped_total = n,
                "auditsink: otlp queue full, dropping events"
            );
        }
    }

    /// Drains the queue, then flushes and shuts the exporter down.
    fn close(&self) -> Result<(), Error> {
        self.shared.queue.close();
        match self.joiner.wait(CLOSE_TIMEOUT * 2) {
            Ok(Some(Err(e))) => Err(Error::Otlp(e)),
            Ok(_) => Ok(()),
            Err(()) => {
                tracing::warn!("auditsink: otlp close timed out flushing queue");
                Err(Error::Otlp("close timed out flushing queue".into()))
            }
        }
    }

    fn kind(&self) -> &'static str {
        "otlp"
    }
}

impl Drop for OtlpSink {
    fn drop(&mut self) {
        self.shared.queue.close();
    }
}

fn build_provider(endpoint: &str, cfg: &OtlpSinkConfig) -> Result<SdkLoggerProvider, String> {
    let client = otlp_reqwest::blocking::Client::builder()
        .timeout(EXPORT_TIMEOUT)
        .tls_backend_preconfigured(ring_tls_config()?)
        .build()
        .map_err(|e| format!("create otlp http client: {e}"))?;

    let mut builder = LogExporter::builder()
        .with_http()
        .with_http_client(client)
        .with_protocol(Protocol::HttpBinary)
        .with_endpoint(endpoint)
        .with_timeout(EXPORT_TIMEOUT);
    if !cfg.headers.is_empty() {
        let headers: HashMap<String, String> = cfg
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        builder = builder.with_headers(headers);
    }
    let exporter = builder
        .build()
        .map_err(|e| format!("create otlp exporter: {e}"))?;

    let mut res = Resource::builder();
    let svc = cfg.service_name.trim();
    if !svc.is_empty() {
        res = res.with_service_name(svc.to_owned());
    }
    res = res.with_attributes(
        cfg.resource_attributes
            .iter()
            .map(|(k, v)| KeyValue::new(k.clone(), v.clone())),
    );

    Ok(SdkLoggerProvider::builder()
        .with_resource(res.build())
        .with_simple_exporter(exporter)
        .build())
}

/// A rustls client config on the ring provider with the webpki roots.
fn ring_tls_config() -> Result<rustls::ClientConfig, String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn parse_endpoint(raw: &str) -> Result<reqwest::Url, Error> {
    let u =
        reqwest::Url::parse(raw).map_err(|e| Error::Otlp(format!("invalid endpoint URL: {e}")))?;
    if u.scheme() != "http" && u.scheme() != "https" {
        return Err(Error::Otlp(format!(
            "endpoint must use http(s), got {raw:?}"
        )));
    }
    if u.host_str().unwrap_or_default().is_empty() {
        return Err(Error::Otlp(format!("endpoint has no host: {raw:?}")));
    }
    Ok(u)
}

/// Everything an audit event contributes to its OTLP log record, kept
/// separate from the SDK record so the mapping can be inspected in tests.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RecordFields {
    pub timestamp: SystemTime,
    pub severity: Severity,
    pub severity_text: Option<&'static str>,
    pub body: String,
    pub attributes: Vec<(String, AnyValue)>,
    pub trace: Option<(TraceId, SpanId, TraceFlags)>,
}

impl RecordFields {
    pub(crate) fn from_event(ev: &Event) -> Self {
        let timestamp = if gotime::is_zero(&ev.time) {
            SystemTime::now()
        } else {
            SystemTime::from(ev.time.with_timezone(&Utc))
        };
        let (severity, severity_text) = severity_for_verdict(&ev.verdict);

        let s = |v: &str| AnyValue::String(v.to_owned().into());
        let mut attributes: Vec<(String, AnyValue)> = vec![
            ("runeward.audit.seq".into(), AnyValue::Int(ev.seq)),
            ("runeward.session_id".into(), s(&ev.session_id)),
            ("runeward.sandbox".into(), s(&ev.sandbox)),
            ("runeward.profile".into(), s(&ev.profile)),
            ("runeward.tool".into(), s(&ev.tool)),
            ("runeward.action".into(), s(&ev.action)),
            ("runeward.verdict".into(), s(&ev.verdict)),
            ("runeward.exit_code".into(), AnyValue::Int(ev.exit_code)),
            ("runeward.duration_ms".into(), AnyValue::Int(ev.duration_ms)),
            ("runeward.hash".into(), s(&ev.hash)),
            ("runeward.prev_hash".into(), s(&ev.prev_hash)),
        ];
        if let Some(reason) = ev
            .meta
            .get("reason")
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
        {
            attributes.push(("runeward.reason".into(), s(reason)));
        }
        if !ev.args.is_empty() {
            let vals = ev.args.iter().map(|a| s(a)).collect();
            attributes.push(("runeward.args".into(), AnyValue::ListAny(Box::new(vals))));
        }
        // meta is a BTreeMap, so this is already sorted by key.
        for (k, v) in &ev.meta {
            attributes.push((format!("runeward.meta.{k}"), s(v)));
        }

        Self {
            timestamp,
            severity,
            severity_text,
            body: ev.action.clone(),
            attributes,
            trace: trace_context(&ev.meta),
        }
    }

    fn apply<R: opentelemetry::logs::LogRecord>(self, rec: &mut R) {
        rec.set_timestamp(self.timestamp);
        rec.set_observed_timestamp(SystemTime::now());
        rec.set_event_name(SCOPE);
        rec.set_body(AnyValue::String(self.body.into()));
        rec.set_severity_number(self.severity);
        if let Some(text) = self.severity_text {
            rec.set_severity_text(text);
        }
        rec.add_attributes(self.attributes.into_iter().map(|(k, v)| (Key::new(k), v)));
        if let Some((tid, sid, flags)) = self.trace {
            rec.set_trace_context(tid, sid, Some(flags));
        }
    }
}

/// Maps a verdict to an OTLP severity: deny is WARN, everything else INFO.
/// The severity text is the normalised verdict for allow/deny and the raw
/// verdict otherwise.
fn severity_for_verdict(verdict: &str) -> (Severity, Option<&'static str>) {
    match verdict.trim().to_lowercase().as_str() {
        "allow" => (Severity::Info, Some("allow")),
        "deny" => (Severity::Warn, Some("deny")),
        _ => (Severity::Info, intern(verdict)),
    }
}

/// Interns a severity text: the SDK only takes `&'static str`, and verdicts
/// come from a small closed set. The table is capped so a hostile stream of
/// distinct verdicts cannot grow memory without bound; past the cap the
/// severity text is left unset.
fn intern(s: &str) -> Option<&'static str> {
    const MAX_INTERNED: usize = 64;
    static TABLE: LazyLock<Mutex<HashSet<&'static str>>> =
        LazyLock::new(|| Mutex::new(HashSet::new()));
    if s.is_empty() {
        return Some("");
    }
    let mut t = lock(&TABLE);
    if let Some(v) = t.get(s) {
        return Some(v);
    }
    if t.len() >= MAX_INTERNED {
        return None;
    }
    let leaked: &'static str = Box::leak(s.to_owned().into_boxed_str());
    t.insert(leaked);
    Some(leaked)
}

/// Extracts the trace context an event carries in its metadata: a W3C
/// `traceparent`, or else `trace_id` + `span_id` (+ optional `trace_flags`).
fn trace_context(meta: &BTreeMap<String, String>) -> Option<(TraceId, SpanId, TraceFlags)> {
    if meta.is_empty() {
        return None;
    }
    if let Some(tp) = meta
        .get("traceparent")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        && let Some(ctx) = parse_traceparent(tp)
    {
        return Some(ctx);
    }
    let tid = parse_trace_id(meta.get("trace_id").map_or("", String::as_str))?;
    let sid = parse_span_id(meta.get("span_id").map_or("", String::as_str))?;
    let flags = meta
        .get("trace_flags")
        .and_then(|f| parse_trace_flags(f))
        .unwrap_or(TraceFlags::new(0));
    Some((tid, sid, flags))
}

fn parse_traceparent(s: &str) -> Option<(TraceId, SpanId, TraceFlags)> {
    let parts: Vec<&str> = s.trim().split('-').collect();
    if parts.len() != 4 {
        return None;
    }
    let tid = parse_trace_id(parts[1])?;
    let sid = parse_span_id(parts[2])?;
    let flags = parse_uint_base(parts[3], 16)?;
    Some((tid, sid, TraceFlags::new(u8::try_from(flags).ok()?)))
}

/// Decodes exactly `N` bytes of lowercase hex, as Go's trace ID parsers do.
fn decode_lower_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn parse_trace_id(s: &str) -> Option<TraceId> {
    let id = TraceId::from_bytes(decode_lower_hex::<16>(s.trim())?);
    (id != TraceId::INVALID).then_some(id)
}

fn parse_span_id(s: &str) -> Option<SpanId> {
    let id = SpanId::from_bytes(decode_lower_hex::<8>(s.trim())?);
    (id != SpanId::INVALID).then_some(id)
}

/// Parses flags like Go's `strconv.ParseUint(s, 0, 8)`: decimal, `0x` hex,
/// `0o`/leading-zero octal or `0b` binary.
fn parse_trace_flags(s: &str) -> Option<TraceFlags> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let v = parse_uint_base0(t)?;
    Some(TraceFlags::new(u8::try_from(v).ok()?))
}

fn parse_uint_base0(s: &str) -> Option<u64> {
    let lower = s.get(..2).map(str::to_ascii_lowercase);
    let (digits, base) = match lower.as_deref() {
        Some("0x") => (&s[2..], 16),
        Some("0o") => (&s[2..], 8),
        Some("0b") => (&s[2..], 2),
        _ if s.len() > 1 && s.starts_with('0') => (&s[1..], 8),
        _ => (s, 10),
    };
    if s.contains('_') && !underscores_ok(s) {
        return None;
    }
    parse_uint_base(&digits.replace('_', ""), base)
}

/// Go's rule for underscores in base-0 literals: only between digits, or
/// directly after a base prefix.
fn underscores_ok(s: &str) -> bool {
    let b = s.as_bytes();
    let mut saw = '^';
    let mut i = 0;
    let mut hex = false;
    if b.len() >= 2 && b[0] == b'0' && matches!(b[1].to_ascii_lowercase(), b'x' | b'o' | b'b') {
        hex = b[1].eq_ignore_ascii_case(&b'x');
        i = 2;
        saw = '0';
    }
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_digit() || (hex && c.is_ascii_hexdigit()) {
            saw = '0';
        } else if c == b'_' {
            if saw != '0' {
                return false;
            }
            saw = '_';
        } else {
            if saw == '_' {
                return false;
            }
            saw = '!';
        }
        i += 1;
    }
    saw != '_'
}

fn parse_uint_base(s: &str, base: u32) -> Option<u64> {
    if s.is_empty() || s.starts_with('+') || s.starts_with('-') {
        return None;
    }
    u64::from_str_radix(s, base).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue as PbAny, KeyValue as PbKv, any_value};
    use prost::Message;

    use super::*;

    /// Go's test allows 2s for 100k emits. A blocking emit would instead wait
    /// on the hung endpoint (held for 60s), so a looser bound keeps the test
    /// meaningful while tolerating heavily loaded CI hosts.
    const EMIT_BUDGET: Duration = Duration::from_secs(15);
    use crate::testhttp::{Request, Server};
    use crate::testutil::sample_event;

    fn attr<'a>(fields: &'a RecordFields, key: &str) -> Option<&'a AnyValue> {
        fields
            .attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    #[test]
    fn event_record_maps_fields_and_context_trace() {
        let mut ev = sample_event();
        ev.exit_code = 13;
        ev.duration_ms = 2250;
        ev.meta.insert("reason".into(), "blocked by policy".into());
        ev.meta.insert(
            "traceparent".into(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into(),
        );

        let f = RecordFields::from_event(&ev);
        let str_attr = |k| AnyValue::String(String::from(k).into());
        assert_eq!(attr(&f, "runeward.session_id"), Some(&str_attr("sess-abc")));
        assert_eq!(
            attr(&f, "runeward.reason"),
            Some(&str_attr("blocked by policy"))
        );
        assert_eq!(attr(&f, "runeward.duration_ms"), Some(&AnyValue::Int(2250)));
        assert_eq!(attr(&f, "runeward.exit_code"), Some(&AnyValue::Int(13)));
        assert_eq!(attr(&f, "runeward.audit.seq"), Some(&AnyValue::Int(7)));

        let (tid, sid, flags) = trace_context(&ev.meta).unwrap();
        assert_eq!(tid.to_string(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(sid.to_string(), "00f067aa0ba902b7");
        assert_eq!(flags, TraceFlags::new(0x01));
        assert_eq!(f.trace, Some((tid, sid, flags)));
        assert_eq!(f.body, "rm -rf /tmp/x");
        assert_eq!(f.timestamp, SystemTime::from(ev.time.with_timezone(&Utc)));
    }

    #[test]
    fn attribute_order_matches_go() {
        let mut ev = sample_event();
        ev.meta.insert("zeta".into(), "z".into());
        ev.meta.insert("alpha".into(), "a".into());
        let keys: Vec<String> = RecordFields::from_event(&ev)
            .attributes
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(
            keys,
            [
                "runeward.audit.seq",
                "runeward.session_id",
                "runeward.sandbox",
                "runeward.profile",
                "runeward.tool",
                "runeward.action",
                "runeward.verdict",
                "runeward.exit_code",
                "runeward.duration_ms",
                "runeward.hash",
                "runeward.prev_hash",
                "runeward.args",
                "runeward.meta.alpha",
                "runeward.meta.zeta",
            ]
        );
    }

    #[test]
    fn severity_mapping() {
        assert_eq!(
            severity_for_verdict("allow"),
            (Severity::Info, Some("allow"))
        );
        assert_eq!(
            severity_for_verdict(" DENY "),
            (Severity::Warn, Some("deny"))
        );
        assert_eq!(severity_for_verdict("Ask"), (Severity::Info, Some("Ask")));
        assert_eq!(severity_for_verdict(""), (Severity::Info, Some("")));
    }

    #[test]
    fn trace_context_from_ids() {
        let mut meta = BTreeMap::new();
        meta.insert("trace_id".into(), "4bf92f3577b34da6a3ce929d0e0e4736".into());
        meta.insert("span_id".into(), "00f067aa0ba902b7".into());
        let (_, _, flags) = trace_context(&meta).unwrap();
        assert_eq!(flags, TraceFlags::new(0));

        meta.insert("trace_flags".into(), "0x01".into());
        assert_eq!(trace_context(&meta).unwrap().2, TraceFlags::new(1));
        meta.insert("trace_flags".into(), "1".into());
        assert_eq!(trace_context(&meta).unwrap().2, TraceFlags::new(1));
        meta.insert("trace_flags".into(), "bogus".into());
        assert_eq!(trace_context(&meta).unwrap().2, TraceFlags::new(0));

        // A malformed traceparent falls back to the explicit IDs.
        meta.insert("traceparent".into(), "garbage".into());
        assert!(trace_context(&meta).is_some());

        // Uppercase, all-zero or short IDs are rejected, as in Go.
        meta.insert("trace_id".into(), "4BF92F3577B34DA6A3CE929D0E0E4736".into());
        assert!(trace_context(&meta).is_none());
        meta.insert("trace_id".into(), "0".repeat(32));
        assert!(trace_context(&meta).is_none());
        meta.insert("trace_id".into(), "4bf9".into());
        assert!(trace_context(&meta).is_none());
        assert!(trace_context(&BTreeMap::new()).is_none());
    }

    #[test]
    fn uint_base0_parsing() {
        assert_eq!(parse_uint_base0("10"), Some(10));
        assert_eq!(parse_uint_base0("0x1f"), Some(31));
        assert_eq!(parse_uint_base0("0X1F"), Some(31));
        assert_eq!(parse_uint_base0("010"), Some(8));
        assert_eq!(parse_uint_base0("0o10"), Some(8));
        assert_eq!(parse_uint_base0("0b11"), Some(3));
        assert_eq!(parse_uint_base0("0"), Some(0));
        assert_eq!(parse_uint_base0("1_0"), Some(10));
        assert_eq!(parse_uint_base0("0x_1"), Some(1));
        assert_eq!(parse_uint_base0("_1"), None);
        assert_eq!(parse_uint_base0("1__0"), None);
        assert_eq!(parse_uint_base0("1_"), None);
        assert_eq!(parse_uint_base0("-1"), None);
        assert_eq!(parse_uint_base0("0x"), None);
        assert!(parse_trace_flags("256").is_none());
    }

    fn str_of(v: &Option<PbAny>) -> Option<&str> {
        str_in(v.as_ref()?)
    }

    fn str_in(v: &PbAny) -> Option<&str> {
        match v.value.as_ref()? {
            any_value::Value::StringValue(s) => Some(s),
            _ => None,
        }
    }

    fn find<'a>(attrs: &'a [PbKv], key: &str) -> Option<&'a Option<PbAny>> {
        attrs.iter().find(|kv| kv.key == key).map(|kv| &kv.value)
    }

    #[test]
    fn otlp_sink_delivers_to_http_collector() {
        let (tx, rx) = mpsc::channel::<Request>();
        let srv = Server::start(move |r| {
            let _ = tx.send(r);
            200
        });

        let mut cfg = OtlpSinkConfig::new(srv.url("/v1/logs"));
        cfg.headers
            .insert("Authorization".into(), "Bearer token".into());
        cfg.insecure = true;
        cfg.service_name = "runeward-test".into();
        cfg.resource_attributes
            .insert("deployment.environment".into(), "test".into());
        let sink = OtlpSink::new(cfg).unwrap();

        let mut ev = sample_event();
        ev.verdict = "deny".into();
        ev.meta.insert("reason".into(), "blocked by policy".into());
        ev.meta.insert(
            "traceparent".into(),
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".into(),
        );
        sink.emit(&ev);
        sink.close().unwrap();

        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("collector got no request");
        assert_eq!(r.method, "POST");
        assert!(r.path.ends_with("/v1/logs"), "path = {}", r.path);
        assert_eq!(r.header("authorization"), Some("Bearer token"));
        assert_eq!(r.header("content-type"), Some("application/x-protobuf"));

        let req = ExportLogsServiceRequest::decode(r.body.as_slice()).unwrap();
        assert_eq!(req.resource_logs.len(), 1);
        let rl = &req.resource_logs[0];
        let res_attrs = &rl.resource.as_ref().unwrap().attributes;
        assert_eq!(
            str_of(find(res_attrs, "service.name").unwrap()),
            Some("runeward-test")
        );
        assert_eq!(
            str_of(find(res_attrs, "deployment.environment").unwrap()),
            Some("test")
        );

        let sl = &rl.scope_logs[0];
        assert_eq!(sl.scope.as_ref().unwrap().name, "runeward.audit");
        assert_eq!(sl.log_records.len(), 1);
        let lr = &sl.log_records[0];
        assert_eq!(lr.event_name, "runeward.audit");
        assert_eq!(lr.severity_number, 13);
        assert_eq!(lr.severity_text, "deny");
        assert_eq!(str_of(&lr.body), Some("rm -rf /tmp/x"));
        let want_ns = ev.time.timestamp_nanos_opt().unwrap() as u64;
        assert_eq!(lr.time_unix_nano, want_ns);
        assert!(lr.observed_time_unix_nano > 0);
        assert_eq!(hex(&lr.trace_id), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(hex(&lr.span_id), "00f067aa0ba902b7");
        assert_eq!(lr.flags & 0xff, 1);

        let a = &lr.attributes;
        assert_eq!(
            str_of(find(a, "runeward.session_id").unwrap()),
            Some("sess-abc")
        );
        assert_eq!(str_of(find(a, "runeward.verdict").unwrap()), Some("deny"));
        assert_eq!(
            str_of(find(a, "runeward.reason").unwrap()),
            Some("blocked by policy")
        );
        assert_eq!(
            str_of(find(a, "runeward.meta.reason").unwrap()),
            Some("blocked by policy")
        );
        match find(a, "runeward.audit.seq")
            .unwrap()
            .as_ref()
            .unwrap()
            .value
        {
            Some(any_value::Value::IntValue(7)) => {}
            ref other => panic!("seq = {other:?}"),
        }
        match &find(a, "runeward.args").unwrap().as_ref().unwrap().value {
            Some(any_value::Value::ArrayValue(arr)) => {
                let vals: Vec<_> = arr.values.iter().map(str_in).collect();
                assert_eq!(vals, vec![Some("-rf"), Some("/tmp/x")]);
            }
            other => panic!("args = {other:?}"),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn otlp_sink_emit_does_not_block_when_collector_hangs() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        let srv = Server::start(move |_| {
            let _ = lock(&release_rx).recv_timeout(Duration::from_secs(60));
            200
        });
        let mut cfg = OtlpSinkConfig::new(srv.url("/v1/logs"));
        cfg.insecure = true;
        cfg.queue_size = 8;
        let sink = Arc::new(OtlpSink::new(cfg).unwrap());

        let s2 = sink.clone();
        let start = Instant::now();
        thread::spawn(move || {
            for i in 0..100_000 {
                let mut ev = sample_event();
                ev.seq = i;
                s2.emit(&ev);
            }
        })
        .join()
        .unwrap();
        assert!(
            start.elapsed() < EMIT_BUDGET,
            "emits took {:?}",
            start.elapsed()
        );
        assert!(sink.shared.drops.total() > 0);

        drop(release_tx);
        sink.close().unwrap();
    }

    #[test]
    fn new_otlp_sink_rejects_bad_endpoints() {
        assert!(OtlpSink::new(OtlpSinkConfig::new("  ")).is_err());
        assert!(OtlpSink::new(OtlpSinkConfig::new("ftp://collector/v1/logs")).is_err());
        assert!(OtlpSink::new(OtlpSinkConfig::new("not a url")).is_err());
    }

    #[test]
    fn insecure_forces_plain_http() {
        let (tx, rx) = mpsc::channel::<Request>();
        let srv = Server::start(move |r| {
            let _ = tx.send(r);
            200
        });
        let endpoint = srv.url("/v1/logs").replacen("http://", "https://", 1);
        let mut cfg = OtlpSinkConfig::new(endpoint);
        cfg.insecure = true;
        let sink = OtlpSink::new(cfg).unwrap();
        sink.emit(&sample_event());
        sink.close().unwrap();
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("collector got no request");
        assert_eq!(r.path, "/v1/logs");
    }
}
