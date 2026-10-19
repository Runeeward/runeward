//! The broker's data path: TLS termination for inspected endpoints, the
//! per-request decision, credential substitution, forwarding, response
//! scrubbing, and guarded splicing for opaque tunnels.

use std::convert::Infallible;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::upgrade::OnUpgrade;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::breaker::{self, Admit};
use super::credentials;
use super::rules::{self, Evaluation, Facts, Outcome, RuleKind};
use super::{ApprovalOutcome, ApprovalRequest, Broker, EndpointSpec, MAX_INSPECT_BODY};
use crate::decision_log::{Decision, ReasonCode, Verdict};
use crate::logger::Sink;
use crate::netutil::{join_host_port, parse_ip};
use crate::proxy::{ProxyBody, READ_HEADER_TIMEOUT, dial, http_error};
use crate::resolve::{PinnedTarget, host_with_default_port};
use crate::sni::extract_sni;
use crate::transparent::{PEEK_LIMIT, PEEK_TIMEOUT};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a breaker `health_path` probe may take.
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Largest TLS record gathered for the SNI check on opaque tunnels.
const MAX_HELLO: usize = 16 * 1024 + 5;

/// Where an inspected request goes.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// Destination host the connection was approved for.
    pub(crate) host: String,
    /// Destination port.
    pub(crate) port: String,
    /// The approved upstream address.
    pub(crate) pinned: PinnedTarget,
    /// TLS towards the upstream, or `None` for plain HTTP.
    pub(crate) upstream_tls: Option<Arc<rustls::ClientConfig>>,
    /// The inspected endpoint, if the destination is one.
    pub(crate) endpoint: Option<usize>,
}

/// The request's authority: the URI's, else the `Host` header.
fn request_authority<B>(req: &Request<B>) -> String {
    if let Some(a) = req.uri().authority() {
        return a.as_str().to_string();
    }
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn authority_matches(authority: &str, target: &Target) -> bool {
    match host_with_default_port(authority, &target.port) {
        Ok((h, p)) => h.eq_ignore_ascii_case(&target.host) && p == target.port,
        Err(_) => false,
    }
}

fn is_upgrade(h: &HeaderMap) -> bool {
    h.contains_key(header::UPGRADE)
        && h.get_all(header::CONNECTION).iter().any(|v| {
            v.to_str().is_ok_and(|s| {
                s.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
        })
}

fn json_response(
    status: StatusCode,
    code: ReasonCode,
    verdict: Verdict,
    message: &str,
    d: &Decision,
) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": message,
        "code": code.as_str(),
        "verdict": verdict.as_str(),
        "endpoint": d.endpoint,
        "rule": d.rule,
        "tool": d.tool,
        "refusal": refusal(status, code, message),
    });
    let body = Full::new(Bytes::from(body.to_string()))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(
        "x-runeward-decision",
        HeaderValue::from_static(code.as_str()),
    );
    resp
}

/// The standard "nothing ran" refusal object the control plane's REST and
/// MCP surfaces use (`runeward_controlplane::refusal`), so an agent can
/// handle a broker refusal the same way. Only a shed call is retryable.
fn refusal(status: StatusCode, code: ReasonCode, message: &str) -> serde_json::Value {
    let reason = match code {
        ReasonCode::Shed => "shed",
        ReasonCode::Budget => "budget",
        ReasonCode::Approval => "approval",
        _ if status == StatusCode::BAD_REQUEST || status == StatusCode::PAYLOAD_TOO_LARGE => {
            "request"
        }
        _ => "policy",
    };
    serde_json::json!({
        "refused": true,
        "reason": reason,
        "retryable": code == ReasonCode::Shed,
        "request_id": hex_id(),
        "message": message,
    })
}

fn hex_id() -> String {
    rand::random::<[u8; 8]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A refusal before it is turned into a response.
struct Refusal {
    status: StatusCode,
    code: ReasonCode,
    verdict: Verdict,
    why: String,
}

impl Refusal {
    fn new(status: StatusCode, code: ReasonCode, verdict: Verdict, why: impl Into<String>) -> Self {
        Self {
            status,
            code,
            verdict,
            why: why.into(),
        }
    }
}

impl Broker {
    /// Scrubs, logs and records a decision; returns what was recorded.
    pub(crate) fn record(&self, sink: &Sink, d: Decision) -> Decision {
        let d = self.scrub_decision(d);
        let verdict = d
            .verdict
            .map_or(if d.allow { "allow" } else { "deny" }, |v| v.as_str());
        sink.logf(format_args!(
            "egress: {} {} {} {}{} [{}] ({}: {})",
            verdict.to_uppercase(),
            d.protocol.as_deref().unwrap_or("-"),
            d.method.as_deref().unwrap_or("-"),
            d.host,
            d.path.as_deref().unwrap_or(""),
            d.endpoint.as_deref().unwrap_or("-"),
            d.reason_code.map_or("-", ReasonCode::as_str),
            d.reason,
        ));
        sink.record_entry(d.clone());
        d
    }

    fn refuse(&self, sink: &Sink, mut d: Decision, r: Refusal) -> Response<ProxyBody> {
        d.allow = false;
        d.verdict = Some(r.verdict);
        d.reason_code = Some(r.code);
        d.reason = r.why;
        let d = self.record(sink, d);
        let message = match r.code {
            ReasonCode::Approval => format!(
                "approval required: {}. This call needs human approval and no approval queue is connected, so the broker refused it; ask the operator to approve it or tag the rule's effect in the Charter",
                d.reason
            ),
            ReasonCode::PlaceholderMisuse => format!(
                "{}; credential placeholders only work against the endpoint that owns them",
                d.reason
            ),
            _ => d.reason.clone(),
        };
        json_response(r.status, r.code, r.verdict, &message, &d)
    }

    /// Decides, rewrites and forwards one HTTP request bound for `target`.
    pub(crate) async fn handle(
        self: &Arc<Self>,
        mut req: Request<Incoming>,
        target: &Target,
        sink: &Sink,
    ) -> Response<ProxyBody> {
        let spec = target.endpoint.map(|i| &self.endpoints[i]);
        let mut d = self.endpoint_decision(target.endpoint);
        d.host = target.host.clone();
        d.ip = target.pinned.ip.to_string();
        d.method = Some(req.method().to_string());

        let authority = request_authority(&req);
        let host_hdr = req
            .headers()
            .get(header::HOST)
            .map(|v| v.to_str().unwrap_or("\u{0}").to_string());
        if !authority_matches(&authority, target)
            || host_hdr.is_some_and(|h| !authority_matches(&h, target))
        {
            return self.refuse(
                sink,
                d,
                Refusal::new(
                    StatusCode::BAD_REQUEST,
                    ReasonCode::Denied,
                    Verdict::Deny,
                    "host header does not match the connection's destination",
                ),
            );
        }

        let path = match rules::normalize_path(req.uri().path()) {
            Ok(p) => p,
            Err(e) => {
                d.path = Some(req.uri().path().to_string());
                return self.refuse(
                    sink,
                    d,
                    Refusal::new(
                        StatusCode::BAD_REQUEST,
                        ReasonCode::Denied,
                        Verdict::Deny,
                        format!("refused request path: {e}"),
                    ),
                );
            }
        };
        d.path = Some(path.clone());

        let on_upgrade = is_upgrade(req.headers()).then(|| hyper::upgrade::on(&mut req));
        let (mut parts, body) = req.into_parts();
        let body = match Limited::new(body, MAX_INSPECT_BODY).collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return self.refuse(
                    sink,
                    d,
                    Refusal::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        ReasonCode::Denied,
                        Verdict::Deny,
                        format!(
                            "request body exceeds the {MAX_INSPECT_BODY}-byte inspection limit"
                        ),
                    ),
                );
            }
        };

        // A placeholder may only travel to the endpoint that owns it.
        let owned = spec.and_then(|s| s.credential);
        let pq = parts
            .uri
            .path_and_query()
            .map_or("/", |p| p.as_str())
            .to_string();
        let misused: Vec<&str> = self
            .vault
            .scan_request(&pq, &parts.headers, &body)
            .into_iter()
            .filter(|i| Some(*i) != owned)
            .map(|i| self.vault.slots[i].name.as_str())
            .collect();
        if !misused.is_empty() {
            d.credential = Some(misused.join(","));
            let why = format!(
                "placeholder for credential {} sent to {}",
                misused.join(", "),
                target.host
            );
            return self.refuse(
                sink,
                d,
                Refusal::new(
                    StatusCode::FORBIDDEN,
                    ReasonCode::PlaceholderMisuse,
                    Verdict::Deny,
                    why,
                ),
            );
        }

        let mut pq = pq;
        if let (Some(i), Some(spec)) = (target.endpoint, spec) {
            if let Some(shed) = self.breaker_gate(i, spec, target, sink, &d).await {
                return shed;
            }
            if let Err(r) = self
                .decide(i, spec, parts.method.as_str(), &path, &body, &mut d, sink)
                .await
            {
                return self.refuse(sink, d, r);
            }
            if let Some(ci) = spec.credential {
                let slot = &self.vault.slots[ci];
                match credentials::apply(slot, &mut parts.headers, &pq) {
                    Ok(rewritten) => pq = rewritten,
                    Err(e) => {
                        return self.refuse(
                            sink,
                            d,
                            Refusal::new(
                                StatusCode::BAD_REQUEST,
                                ReasonCode::Denied,
                                Verdict::Deny,
                                format!("cannot attach credential: {e}"),
                            ),
                        );
                    }
                }
                d.credential = Some(slot.name.clone());
            }
            self.record(sink, d);
        }

        let scrub = owned.filter(|_| target.endpoint.is_some());
        match self
            .forward(parts, body, &pq, &authority, target, on_upgrade, scrub)
            .await
        {
            Ok(resp) => {
                if let Some(i) = target.endpoint {
                    self.observe_upstream(i, resp.status(), resp.headers(), sink);
                }
                resp
            }
            Err(e) => {
                sink.logf(format_args!(
                    "egress: upstream {} failed: {}",
                    target.pinned,
                    self.scrub(&e.to_string())
                ));
                http_error(StatusCode::BAD_GATEWAY, "Bad Gateway")
            }
        }
    }

    /// Consults endpoint `i`'s retry-storm breaker. Returns the shed
    /// refusal when the call must not go upstream; `None` lets it through
    /// (breaker closed, or closed just now by a healthy probe).
    async fn breaker_gate(
        &self,
        i: usize,
        spec: &EndpointSpec,
        target: &Target,
        sink: &Sink,
        d: &Decision,
    ) -> Option<Response<ProxyBody>> {
        let health = spec.ep.health_path.as_str();
        let (remaining, trip) = match self.breakers.admit(i, !health.is_empty()) {
            Admit::Pass => return None,
            Admit::Shed { remaining, trip } => (remaining, trip),
            Admit::Probe => {
                match self.probe(target, health).await {
                    Ok((status, _)) if status.is_success() => {
                        self.breakers.close(i);
                        sink.logf(format_args!(
                            "egress: breaker for {} closed: {health} answered {status}",
                            spec.label()
                        ));
                        return None;
                    }
                    Ok((status, retry_after)) => {
                        self.breakers.observe(i, status.as_u16(), retry_after);
                    }
                    Err(e) => sink.logf(format_args!(
                        "egress: health probe {health} for {} failed: {}",
                        spec.label(),
                        self.scrub(&e.to_string())
                    )),
                }
                match self.breakers.admit(i, false) {
                    Admit::Shed { remaining, trip } => (remaining, trip),
                    _ => return None,
                }
            }
        };
        self.breakers.count_shed(i);
        // Whole seconds, rounded up, never 0 while the breaker is open.
        let secs = (remaining.as_millis().div_ceil(1000)).max(1);
        let why = format!(
            "shed: upstream {} answered {}; not retrying it for {secs}s",
            spec.label(),
            trip.status()
        );
        let mut resp = self.refuse(
            sink,
            d.clone(),
            Refusal::new(
                StatusCode::SERVICE_UNAVAILABLE,
                ReasonCode::Shed,
                Verdict::Deny,
                why,
            ),
        );
        if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        Some(resp)
    }

    /// Feeds an upstream answer to endpoint `i`'s breaker.
    fn observe_upstream(&self, i: usize, status: StatusCode, headers: &HeaderMap, sink: &Sink) {
        let retry_after = headers
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| breaker::parse_retry_after(v, chrono::Utc::now()));
        if self.breakers.observe(i, status.as_u16(), retry_after) {
            sink.logf(format_args!(
                "egress: breaker for {} open: upstream answered {status}",
                self.endpoints[i].label()
            ));
        }
    }

    /// `GET`s `path` from the target's upstream without credentials and
    /// returns the status and parsed `Retry-After`.
    async fn probe(
        &self,
        target: &Target,
        path: &str,
    ) -> Result<(StatusCode, Option<std::time::Duration>), BoxError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::HOST, join_host_port(&target.host, &target.port))
            .header(header::USER_AGENT, "runeward-egress-health")
            .body(Full::new(Bytes::new()))?;
        let fut = async {
            let stream = dial(&target.pinned).await?;
            match &target.upstream_tls {
                Some(cfg) => {
                    let name = rustls::pki_types::ServerName::try_from(target.host.clone())?;
                    let tls = tokio_rustls::TlsConnector::from(Arc::clone(cfg))
                        .connect(name, stream)
                        .await?;
                    send(tls, req).await
                }
                None => send(stream, req).await,
            }
        };
        let resp = tokio::time::timeout(PROBE_TIMEOUT, fut)
            .await
            .map_err(|_| "health probe timed out")??;
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| breaker::parse_retry_after(v, chrono::Utc::now()));
        Ok((resp.status(), retry_after))
    }

    /// Runs the endpoint's rules, budgets, audit mode and approval hook.
    /// On success `d` holds the allow decision to record.
    #[allow(clippy::too_many_arguments)]
    async fn decide(
        &self,
        i: usize,
        spec: &EndpointSpec,
        http_method: &str,
        path: &str,
        body: &[u8],
        d: &mut Decision,
        sink: &Sink,
    ) -> Result<(), Refusal> {
        let calls = if spec.protocol.rpc() && http_method == Method::POST.as_str() {
            match rules::parse_rpc(body) {
                Ok(c) => c,
                Err(why) => {
                    return self.audit_or(
                        spec,
                        d,
                        Refusal::new(
                            StatusCode::FORBIDDEN,
                            ReasonCode::Denied,
                            Verdict::Deny,
                            why,
                        ),
                    );
                }
            }
        } else {
            Vec::new()
        };
        let facts = |rpc| Facts {
            http_method,
            path,
            rpc,
        };
        let evals: Vec<Evaluation> = if calls.is_empty() {
            vec![rules::evaluate(&spec.ep, spec.protocol, &facts(None))]
        } else {
            calls
                .iter()
                .map(|c| rules::evaluate(&spec.ep, spec.protocol, &facts(Some(c))))
                .collect()
        };
        let pick = evals
            .iter()
            .find(|e| matches!(e.outcome, Outcome::Deny(_)))
            .or_else(|| {
                evals
                    .iter()
                    .find(|e| matches!(e.outcome, Outcome::RequireApproval(_)))
            })
            .or_else(|| evals.iter().find(|e| e.tool.is_some() || e.rule.is_some()))
            .unwrap_or(&evals[0]);
        if let Some(m) = &pick.rpc_method {
            d.method = Some(m.clone());
        }
        d.tool = pick.tool.clone();
        d.effect = pick.effect.map(|e| e.as_str().to_string());
        d.rule = pick.rule.map(|r| r.to_string());

        let mut matched: Vec<usize> = evals
            .iter()
            .filter_map(|e| e.rule)
            .filter(|r| r.kind == RuleKind::Allow)
            .map(|r| r.index)
            .collect();
        matched.dedup();

        let problem = match &pick.outcome {
            Outcome::Deny(why) => Some(Refusal::new(
                StatusCode::FORBIDDEN,
                ReasonCode::Denied,
                Verdict::Deny,
                why.clone(),
            )),
            Outcome::RequireApproval(why) => Some(Refusal::new(
                StatusCode::FORBIDDEN,
                ReasonCode::Approval,
                Verdict::RequireApproval,
                why.clone(),
            )),
            Outcome::Allow => self.take_budget(i, &matched).err().map(|why| {
                Refusal::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    ReasonCode::Budget,
                    Verdict::Deny,
                    why,
                )
            }),
        };
        let Some(problem) = problem else {
            allow(d, "allowed by endpoint rules");
            return Ok(());
        };
        if spec.audit || problem.code != ReasonCode::Approval {
            return self.audit_or(spec, d, problem);
        }
        let Some(hook) = &self.approval else {
            return Err(problem);
        };

        // Surface the require-approval decision, then wait for the answer.
        let mut pending = d.clone();
        pending.allow = false;
        pending.verdict = Some(Verdict::RequireApproval);
        pending.reason_code = Some(ReasonCode::Approval);
        pending.reason = problem.why.clone();
        let pending = self.record(sink, pending);
        match hook
            .request_approval(ApprovalRequest {
                sandbox_id: self.sandbox_id().to_string(),
                decision: pending,
            })
            .await
        {
            ApprovalOutcome::Approved => match self.take_budget(i, &matched) {
                Ok(()) => {
                    allow(d, &format!("approved: {}", problem.why));
                    Ok(())
                }
                Err(why) => Err(Refusal::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    ReasonCode::Budget,
                    Verdict::Deny,
                    why,
                )),
            },
            ApprovalOutcome::Denied(why) => Err(Refusal::new(
                StatusCode::FORBIDDEN,
                ReasonCode::Denied,
                Verdict::Deny,
                format!("approval denied: {why}"),
            )),
            ApprovalOutcome::Unavailable => Err(problem),
        }
    }

    /// In audit mode, turns a refusal into a forwarded would-deny.
    fn audit_or(&self, spec: &EndpointSpec, d: &mut Decision, r: Refusal) -> Result<(), Refusal> {
        if !spec.audit {
            return Err(r);
        }
        d.allow = true;
        d.verdict = Some(Verdict::Allow);
        d.reason_code = Some(ReasonCode::AuditWouldDeny);
        d.reason = format!(
            "audit mode: would have refused ({}): {}",
            r.code.as_str(),
            r.why
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        mut parts: hyper::http::request::Parts,
        body: Bytes,
        pq: &str,
        authority: &str,
        target: &Target,
        on_upgrade: Option<OnUpgrade>,
        scrub: Option<usize>,
    ) -> Result<Response<ProxyBody>, BoxError> {
        let authority = if authority.is_empty() {
            join_host_port(&target.host, &target.port)
        } else {
            authority.to_string()
        };
        parts.uri = pq.parse::<Uri>()?;
        parts.version = Version::HTTP_11;
        parts.headers.remove(header::PROXY_AUTHORIZATION);
        parts.headers.remove("proxy-connection");
        parts
            .headers
            .insert(header::HOST, HeaderValue::from_str(&authority)?);
        let req = Request::from_parts(parts, Full::new(body));

        let stream = dial(&target.pinned).await?;
        let mut resp = match &target.upstream_tls {
            Some(cfg) => {
                let name = rustls::pki_types::ServerName::try_from(target.host.clone())?;
                let tls = tokio_rustls::TlsConnector::from(Arc::clone(cfg))
                    .connect(name, stream)
                    .await?;
                send(tls, req).await?
            }
            None => send(stream, req).await?,
        };

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client) = on_upgrade
        {
            let upstream = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                let (Ok(c), Ok(u)) = tokio::join!(client, upstream) else {
                    return;
                };
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(c), &mut TokioIo::new(u)).await;
            });
        }

        let slot = scrub.map(|i| &self.vault.slots[i]);
        let Some((secret, placeholder)) =
            slot.and_then(|s| s.secret.as_ref().map(|sec| (sec.expose(), &s.placeholder)))
        else {
            return Ok(resp.map(BodyExt::boxed));
        };
        // Never hand the real secret back to the sandbox (echo endpoints,
        // error pages): swap it for the placeholder in headers and body.
        let (mut parts, body) = resp.into_parts();
        let names: Vec<_> = parts.headers.keys().cloned().collect();
        for name in names {
            let values: Vec<HeaderValue> = parts.headers.get_all(&name).iter().cloned().collect();
            if !values
                .iter()
                .any(|v| v.to_str().is_ok_and(|s| s.contains(secret)))
            {
                continue;
            }
            parts.headers.remove(&name);
            for v in values {
                let s = String::from_utf8_lossy(v.as_bytes()).replace(secret, placeholder);
                if let Ok(hv) = HeaderValue::from_str(&s) {
                    parts.headers.append(name.clone(), hv);
                }
            }
        }
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Ok(Response::from_parts(parts, body.boxed()));
        }
        parts.headers.remove(header::CONTENT_LENGTH);
        let body = ScrubBody {
            inner: body,
            needle: secret.as_bytes().to_vec(),
            with: placeholder.as_bytes().to_vec(),
            held: BytesMut::new(),
            trailers: None,
            done: false,
        };
        Ok(Response::from_parts(parts, body.boxed()))
    }

    /// Serves an intercepted client connection to an inspected endpoint.
    /// `prefix` holds bytes already read from `stream` (transparent mode);
    /// TLS is terminated with a leaf from the sandbox CA when the client
    /// speaks it, otherwise the stream is served as plain HTTP.
    pub(crate) async fn serve_intercepted<S>(
        self: Arc<Self>,
        mut stream: S,
        mut prefix: Vec<u8>,
        mut target: Target,
        sink: Sink,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if prefix.is_empty() {
            let mut buf = vec![0u8; PEEK_LIMIT];
            let n = match tokio::time::timeout(PEEK_TIMEOUT, stream.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                _ => 0,
            };
            if n == 0 {
                return;
            }
            buf.truncate(n);
            prefix = buf;
        }
        let tls = prefix[0] == 0x16;
        let io = Rewind {
            prefix,
            pos: 0,
            inner: stream,
        };
        if !tls {
            target.upstream_tls = None;
            self.serve_http(io, target, sink).await;
            return;
        }
        let cfg = match self.ca.server_config(&target.host) {
            Ok(c) => c,
            Err(e) => {
                sink.logf(format_args!("egress: mint leaf for {}: {e}", target.host));
                return;
            }
        };
        let tls = match tokio_rustls::TlsAcceptor::from(cfg).accept(io).await {
            Ok(t) => t,
            Err(e) => {
                sink.logf(format_args!(
                    "egress: client TLS handshake for {} failed (does the sandbox trust the broker CA?): {e}",
                    target.host
                ));
                return;
            }
        };
        if let Some(sni) = tls.get_ref().1.server_name()
            && !sni.eq_ignore_ascii_case(&target.host)
        {
            let mut d = self.endpoint_decision(target.endpoint);
            d.host = target.host.clone();
            d.ip = target.pinned.ip.to_string();
            d.verdict = Some(Verdict::Deny);
            d.reason_code = Some(ReasonCode::Denied);
            d.reason = format!("tls sni {sni:?} does not match the connection's destination");
            self.record(&sink, d);
            return;
        }
        target.upstream_tls = Some(Arc::clone(&self.upstream_tls));
        self.serve_http(tls, target, sink).await;
    }

    async fn serve_http<IO>(self: Arc<Self>, io: IO, target: Target, sink: Sink)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let target = Arc::new(target);
        let sink = Arc::new(sink);
        let svc = hyper::service::service_fn(move |req| {
            let this = Arc::clone(&self);
            let target = Arc::clone(&target);
            let sink = Arc::clone(&sink);
            async move { Ok::<_, Infallible>(this.handle(req, &target, &sink).await) }
        });
        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(READ_HEADER_TIMEOUT);
        let _ = builder
            .serve_connection(TokioIo::new(io), svc)
            .with_upgrades()
            .await;
    }

    /// Splices an opaque tunnel. The client's first TLS record is checked
    /// against `sni_host` (when given); plaintext client bytes are scanned
    /// for credential placeholders and the tunnel is cut on a hit.
    pub(crate) async fn guarded_splice<C, U>(
        &self,
        client: C,
        upstream: U,
        prefix: Vec<u8>,
        sni_host: Option<String>,
        base: Decision,
        sink: &Sink,
    ) where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut ur, mut uw) = tokio::io::split(upstream);
        let up = async {
            let mut first = prefix;
            if first.is_empty() {
                let mut buf = vec![0u8; PEEK_LIMIT];
                match cr.read(&mut buf).await {
                    Ok(n) if n > 0 => first.extend_from_slice(&buf[..n]),
                    _ => {
                        let _ = uw.shutdown().await;
                        return Ok(());
                    }
                }
            }
            if first[0] == 0x16 {
                // Gather the whole first record so the SNI is visible.
                loop {
                    let want = if first.len() >= 5 {
                        5 + usize::from(u16::from_be_bytes([first[3], first[4]]))
                    } else {
                        5
                    };
                    if first.len() >= want.min(MAX_HELLO) {
                        break;
                    }
                    let mut buf = vec![0u8; PEEK_LIMIT];
                    match cr.read(&mut buf).await {
                        Ok(n) if n > 0 => first.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                if let Some(want) = &sni_host
                    && parse_ip(want).is_none()
                    && let Some(sni) = extract_sni(&first)
                    && !sni.eq_ignore_ascii_case(want)
                {
                    return Err((
                        ReasonCode::Denied,
                        format!("tls sni {sni:?} does not match endpoint host {want:?}"),
                        None,
                    ));
                }
                if uw.write_all(&first).await.is_ok() {
                    let _ = tokio::io::copy(&mut cr, &mut uw).await;
                }
                let _ = uw.shutdown().await;
                return Ok(());
            }
            // Plaintext: scan everything for placeholders, with an overlap
            // window so one split across reads is still caught.
            let keep = self.vault.max_placeholder_len().saturating_sub(1);
            let mut tail: Vec<u8> = Vec::new();
            let mut chunk = first;
            loop {
                if self.has_placeholders() {
                    let mut window = std::mem::take(&mut tail);
                    window.extend_from_slice(&chunk);
                    let hits = self.vault.scan_bytes(&window);
                    if !hits.is_empty() {
                        let names: Vec<&str> = hits
                            .iter()
                            .map(|&i| self.vault.slots[i].name.as_str())
                            .collect();
                        return Err((
                            ReasonCode::PlaceholderMisuse,
                            format!(
                                "placeholder for credential {} sent in an opaque tunnel",
                                names.join(", ")
                            ),
                            Some(names.join(",")),
                        ));
                    }
                    tail = window[window.len().saturating_sub(keep)..].to_vec();
                }
                if uw.write_all(&chunk).await.is_err() {
                    break;
                }
                let mut buf = vec![0u8; 16 * 1024];
                match cr.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        chunk = buf;
                    }
                    _ => break,
                }
            }
            let _ = uw.shutdown().await;
            Ok(())
        };
        let down = async {
            let _ = tokio::io::copy(&mut ur, &mut cw).await;
            let _ = cw.shutdown().await;
        };
        tokio::pin!(up, down);
        let violation = tokio::select! {
            r = &mut up => {
                if r.is_ok() {
                    (&mut down).await;
                }
                r.err()
            }
            () = &mut down => (&mut up).await.err(),
        };
        if let Some((code, why, credential)) = violation {
            let mut d = base;
            d.allow = false;
            d.verdict = Some(Verdict::Deny);
            d.reason_code = Some(code);
            d.reason = why;
            d.credential = credential;
            self.record(sink, d);
        }
    }
}

fn allow(d: &mut Decision, why: &str) {
    d.allow = true;
    d.verdict = Some(Verdict::Allow);
    d.reason_code = Some(ReasonCode::Allowed);
    d.reason = why.to_string();
}

/// Sends one HTTP/1.1 request over `io`, keeping the connection upgradable.
async fn send<IO>(io: IO, req: Request<Full<Bytes>>) -> Result<Response<Incoming>, BoxError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    Ok(sender.send_request(req).await?)
}

/// A stream that replays already-read bytes before reading on.
pub(crate) struct Rewind<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = buf.remaining().min(self.prefix.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A response body with every occurrence of `needle` replaced by `with`,
/// including occurrences split across chunks.
struct ScrubBody {
    inner: Incoming,
    needle: Vec<u8>,
    with: Vec<u8>,
    held: BytesMut,
    trailers: Option<HeaderMap>,
    done: bool,
}

/// Replaces complete occurrences in `held`, returns what can be emitted and
/// keeps back a trailing partial match.
fn scrub_step(held: &mut BytesMut, needle: &[u8], with: &[u8]) -> Bytes {
    let n = needle.len();
    let h = &held[..];
    let mut out = Vec::with_capacity(h.len());
    let mut i = 0;
    while i + n <= h.len() {
        if &h[i..i + n] == needle {
            out.extend_from_slice(with);
            i += n;
        } else {
            out.push(h[i]);
            i += 1;
        }
    }
    let rest = &h[i..];
    let keep = (1..=rest.len())
        .rev()
        .find(|&k| needle.starts_with(&rest[rest.len() - k..]))
        .unwrap_or(0);
    out.extend_from_slice(&rest[..rest.len() - keep]);
    let kept = rest[rest.len() - keep..].to_vec();
    held.clear();
    held.extend_from_slice(&kept);
    Bytes::from(out)
}

impl Body for ScrubBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = &mut *self;
        loop {
            if this.done {
                if !this.held.is_empty() {
                    return Poll::Ready(Some(Ok(Frame::data(this.held.split().freeze()))));
                }
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => this.done = true,
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        this.held.extend_from_slice(&data);
                        let out = scrub_step(&mut this.held, &this.needle, &this.with);
                        if !out.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(out))));
                        }
                    }
                    Err(frame) => {
                        this.trailers = frame.into_trailers().ok();
                        this.done = true;
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_step_handles_splits() {
        let needle = b"SECRET";
        let mut held = BytesMut::new();
        let mut out = Vec::new();
        for chunk in [&b"a SEC"[..], b"RET b SE", b"CRET", b"SE"] {
            held.extend_from_slice(chunk);
            out.extend_from_slice(&scrub_step(&mut held, needle, b"ph"));
        }
        out.extend_from_slice(&held);
        assert_eq!(out, b"a ph b phSE");
    }

    #[test]
    fn refusal_objects_follow_the_reason_code() {
        let r = refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::Shed,
            "slow down",
        );
        assert_eq!(r["refused"], true);
        assert_eq!(r["reason"], "shed");
        assert_eq!(r["retryable"], true);
        assert_eq!(r["message"], "slow down");
        assert_eq!(r["request_id"].as_str().map(str::len), Some(16));
        for (status, code, want) in [
            (StatusCode::FORBIDDEN, ReasonCode::Denied, "policy"),
            (
                StatusCode::FORBIDDEN,
                ReasonCode::PlaceholderMisuse,
                "policy",
            ),
            (StatusCode::BAD_REQUEST, ReasonCode::Denied, "request"),
            (StatusCode::TOO_MANY_REQUESTS, ReasonCode::Budget, "budget"),
            (StatusCode::FORBIDDEN, ReasonCode::Approval, "approval"),
        ] {
            let r = refusal(status, code, "m");
            assert_eq!(r["reason"], want, "{code:?}");
            assert_eq!(r["retryable"], false, "{code:?}");
        }
    }

    #[test]
    fn upgrade_detection() {
        let mut h = HeaderMap::new();
        h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert!(!is_upgrade(&h));
        h.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, Upgrade"),
        );
        assert!(is_upgrade(&h));
    }
}
