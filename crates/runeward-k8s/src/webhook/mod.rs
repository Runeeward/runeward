//! The runeward admission webhook enforcing ClusterPolicy defaults and
//! guardrails on Citadel and Cohort resources.
//!
//! The decision logic ([`decide`]) is a pure function over a policy snapshot;
//! [`Server`] wires it to the Kubernetes AdmissionReview contract on
//! `/validate` and `/mutate` (plus `/healthz`), and [`run`] does the whole
//! startup: load or mint the serving certificate ([`load_or_create_cert`]),
//! self-register the webhook configurations ([`register`]) and serve HTTPS.
//!
//! AdmissionReview responses and JSONPatch documents are byte-identical to
//! the Go webhook's for the same requests (checked against recorded
//! fixtures).

mod cert;
mod certstore;
mod duration;
mod gojson;
mod policy;
mod register;
mod server;

pub use cert::{CERT_VALIDITY, CertBundle, generate_cert};
pub use certstore::{
    CERT_SECRET_CA_KEY, CERT_SECRET_CERT_KEY, CERT_SECRET_KEY_KEY, cert_from_secret,
    load_or_create_cert,
};
pub use policy::{Decision, Policy, decide, match_glob};
pub use register::{
    CONFIG_NAME, mutating_configuration, register, validating_configuration, webhook_rules,
};
pub use server::{RunOptions, run, serve_tls, shutdown_signal, tls_config};

use crate::crd::ClusterPolicy;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine as _;
use http::{HeaderValue, StatusCode, header};
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Annotation stamped on resources whose profile came from a ClusterPolicy
/// default.
pub const DEFAULTED_ANNOTATION: &str = "runeward.dev/cluster-policy-defaulted";

/// How stale a cached policy snapshot may be before the webhook stops
/// trusting it during an API-server outage.
pub const DEFAULT_POLICY_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

/// Environment variable overriding [`DEFAULT_POLICY_CACHE_TTL`] (a Go
/// duration such as `5m`; `0`, `off` or `none` disables the cache).
pub const POLICY_CACHE_TTL_ENV: &str = "RUNEWARD_WEBHOOK_POLICY_CACHE_TTL";

/// Largest AdmissionReview body accepted.
const MAX_BODY_BYTES: usize = 32 << 20;

/// Errors from webhook startup.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Kubernetes API call failed.
    #[error("{context}: {error}")]
    Kube {
        /// What was being attempted.
        context: String,
        /// The underlying client error.
        error: Box<kube::Error>,
    },
    /// Generating the serving certificate failed.
    #[error("generate certificate: {0}")]
    Cert(rcgen::Error),
    /// The serving certificate or key could not be loaded into rustls.
    #[error("load serving certificate: {0}")]
    Tls(String),
    /// Binding or serving failed.
    #[error("serve webhook: {0}")]
    Io(#[from] std::io::Error),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// Boxed error returned by a [`PolicySource`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Future returned by [`PolicySource::list`].
pub type ListFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<Policy>, BoxError>> + Send + 'a>>;

/// Where the webhook reads the current ClusterPolicies from.
pub trait PolicySource: Send + Sync {
    /// Lists every ClusterPolicy as a [`Policy`].
    fn list(&self) -> ListFuture<'_>;
}

/// [`PolicySource`] backed by the cluster-scoped `clusterpolicies` resource.
#[derive(Clone)]
pub struct KubePolicySource {
    api: Api<DynamicObject>,
}

impl std::fmt::Debug for KubePolicySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubePolicySource").finish_non_exhaustive()
    }
}

impl KubePolicySource {
    /// Builds a source listing ClusterPolicies through `client`.
    pub fn new(client: kube::Client) -> Self {
        let ar = ApiResource::erase::<ClusterPolicy>(&());
        Self {
            api: Api::all_with(client, &ar),
        }
    }
}

impl PolicySource for KubePolicySource {
    fn list(&self) -> ListFuture<'_> {
        Box::pin(async move {
            let list = self.api.list(&ListParams::default()).await?;
            let mut out = Vec::with_capacity(list.items.len());
            for item in &list.items {
                out.push(Policy::from_object(&serde_json::to_value(item)?));
            }
            Ok(out)
        })
    }
}

/// Which admission endpoint a request hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// `/validate`: admit or reject.
    Validate,
    /// `/mutate`: default an empty `spec.profile`; always admits.
    Mutate,
}

/// An HTTP reply from [`Server::admit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// HTTP status.
    pub status: StatusCode,
    /// `Content-Type` header value.
    pub content_type: &'static str,
    /// Response body.
    pub body: Vec<u8>,
}

impl Reply {
    fn json(body: Vec<u8>) -> Self {
        Self {
            status: StatusCode::OK,
            content_type: "application/json",
            body,
        }
    }

    /// A plain-text error, shaped like Go's `http.Error`.
    fn error(status: StatusCode, msg: &str) -> Self {
        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: format!("{msg}\n").into_bytes(),
        }
    }
}

impl IntoResponse for Reply {
    fn into_response(self) -> Response {
        let mut resp = (self.status, self.body).into_response();
        let headers = resp.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(self.content_type),
        );
        if self.status != StatusCode::OK {
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
        }
        resp
    }
}

#[derive(Debug, Default)]
struct PolicyCache {
    loaded: bool,
    policies: Vec<Policy>,
    at: Option<Instant>,
}

/// Serves the admission endpoints. It lists ClusterPolicies on every request
/// so policy changes take effect without a restart, keeping a last-known-good
/// snapshot so a transient API-server blip doesn't deny every admission. A
/// never-populated or too-stale cache still fails closed.
pub struct Server {
    source: Box<dyn PolicySource>,
    cache_ttl: Duration,
    cache: Mutex<PolicyCache>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("cache_ttl", &self.cache_ttl)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Builds a server reading policies from `source`, with the cache TTL
    /// taken from [`POLICY_CACHE_TTL_ENV`].
    pub fn new(source: impl PolicySource + 'static) -> Self {
        Self {
            source: Box::new(source),
            cache_ttl: policy_cache_ttl(std::env::var(POLICY_CACHE_TTL_ENV).ok().as_deref()),
            cache: Mutex::new(PolicyCache::default()),
        }
    }

    /// Overrides the last-known-good cache TTL (zero disables the cache).
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// The configured cache TTL.
    pub fn cache_ttl(&self) -> Duration {
        self.cache_ttl
    }

    /// The axum router exposing `/validate`, `/mutate` and `/healthz`.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/validate", any(validate))
            .route("/mutate", any(mutate))
            .route(
                "/healthz",
                any(|| async { ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], "ok") }),
            )
            .fallback(|| async { Reply::error(StatusCode::NOT_FOUND, "404 page not found") })
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .with_state(self)
    }

    /// Returns the current policy set and whether it came from the cache. On
    /// a live-list success the cache is refreshed; on failure a snapshot
    /// within the TTL is used, otherwise the error is returned.
    async fn policy_snapshot(&self) -> Result<(Vec<Policy>, bool), String> {
        match self.source.list().await {
            Ok(live) => {
                let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
                c.policies.clone_from(&live);
                c.at = Some(Instant::now());
                c.loaded = true;
                Ok((live, false))
            }
            Err(e) => {
                let c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
                let fresh = c.at.is_some_and(|at| at.elapsed() <= self.cache_ttl);
                if c.loaded && !self.cache_ttl.is_zero() && fresh {
                    return Ok((c.policies.clone(), true));
                }
                Err(format!("list clusterpolicies: {e}"))
            }
        }
    }

    /// Handles one AdmissionReview body for `endpoint`.
    pub async fn admit(&self, endpoint: Endpoint, body: &[u8]) -> Reply {
        let req = match decode(body) {
            Ok(r) => r,
            Err(reply) => return reply,
        };
        match endpoint {
            Endpoint::Validate => self.validate(&req).await,
            Endpoint::Mutate => self.mutate(&req).await,
        }
    }

    async fn validate(&self, req: &Decoded) -> Reply {
        let policies = match self.policy_snapshot().await {
            Ok((p, from_cache)) => {
                if from_cache {
                    tracing::warn!(
                        resource = %req.resource,
                        "webhook: validate using last-known-good policy cache (live list failed)"
                    );
                }
                p
            }
            Err(e) => {
                // Fail closed: without the policy set we can't prove the
                // resource is allowed, so deny rather than admit it
                // ungoverned.
                tracing::warn!(resource = %req.resource, error = %e, "webhook: validate failed (denying, fail-closed)");
                let msg = format!("runeward webhook could not evaluate ClusterPolicies: {e}");
                return write_review(req, false, Some(&msg), None);
            }
        };
        let d = decide(&policies, &req.namespace, &req.labels, &req.profile);
        if !d.allowed {
            tracing::info!(
                resource = %req.resource, namespace = %req.namespace, name = %req.name,
                reason = %d.reason, "webhook: deny"
            );
            return write_review(req, false, Some(&d.reason), None);
        }
        write_review(req, true, None, None)
    }

    async fn mutate(&self, req: &Decoded) -> Reply {
        let policies = match self.policy_snapshot().await {
            Ok((p, _)) => p,
            Err(e) => {
                tracing::warn!(resource = %req.resource, error = %e, "webhook: mutate failed (admitting unchanged)");
                return write_review(req, true, None, None);
            }
        };
        let d = decide(&policies, &req.namespace, &req.labels, &req.profile);
        if d.profile.is_empty() || d.profile == req.profile {
            return write_review(req, true, None, None);
        }
        let patch = match profile_patch(req.annotations_present, &d.profile) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "webhook: build patch failed");
                return write_review(req, true, None, None);
            }
        };
        tracing::info!(
            resource = %req.resource, namespace = %req.namespace, name = %req.name,
            profile = %d.profile, "webhook: default"
        );
        write_review(req, true, None, Some(&patch))
    }
}

async fn validate(State(s): State<Arc<Server>>, body: Bytes) -> Reply {
    s.admit(Endpoint::Validate, &body).await
}

async fn mutate(State(s): State<Arc<Server>>, body: Bytes) -> Reply {
    s.admit(Endpoint::Mutate, &body).await
}

/// Reads `RUNEWARD_WEBHOOK_POLICY_CACHE_TTL`-style values: unset/empty is the
/// default, `0`/`off`/`none` disables, a non-negative Go duration is used,
/// anything else falls back to the default.
fn policy_cache_ttl(v: Option<&str>) -> Duration {
    match v.unwrap_or_default() {
        "" => DEFAULT_POLICY_CACHE_TTL,
        "0" | "off" | "none" => Duration::ZERO,
        v => match duration::parse_go_duration(v) {
            Some(ns) if ns >= 0 => Duration::from_nanos(u64::try_from(ns).unwrap_or(u64::MAX)),
            _ => DEFAULT_POLICY_CACHE_TTL,
        },
    }
}

#[derive(Deserialize)]
struct InReview<'a> {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default, rename = "apiVersion")]
    api_version: Option<String>,
    #[serde(default, borrow)]
    request: Option<InRequest<'a>>,
}

#[derive(Deserialize)]
struct InRequest<'a> {
    #[serde(default)]
    uid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    resource: Option<InResource>,
    #[serde(default, borrow)]
    object: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct InResource {
    #[serde(default)]
    resource: Option<String>,
}

/// The parts of an AdmissionReview the webhook acts on.
struct Decoded {
    kind: String,
    api_version: String,
    uid: String,
    name: String,
    namespace: String,
    resource: String,
    profile: String,
    labels: BTreeMap<String, String>,
    annotations_present: bool,
}

fn decode(body: &[u8]) -> Result<Decoded, Reply> {
    let review: InReview<'_> = serde_json::from_slice(body).map_err(|e| {
        Reply::error(
            StatusCode::BAD_REQUEST,
            &format!("decode AdmissionReview: {e}"),
        )
    })?;
    let Some(req) = review.request else {
        return Err(Reply::error(
            StatusCode::BAD_REQUEST,
            "AdmissionReview has no request",
        ));
    };
    let obj = match req.object {
        Some(raw) => decode_object(raw.get())
            .map_err(|e| Reply::error(StatusCode::BAD_REQUEST, &format!("decode object: {e}")))?,
        None => Value::Object(serde_json::Map::new()),
    };
    let metadata = obj.get("metadata");
    let string_map = |key: &str| -> Option<BTreeMap<String, String>> {
        let Some(Value::Object(m)) = metadata.and_then(|m| m.get(key)) else {
            return None;
        };
        m.iter()
            .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
            .collect()
    };
    Ok(Decoded {
        kind: review.kind.unwrap_or_default(),
        api_version: review.api_version.unwrap_or_default(),
        uid: req.uid.unwrap_or_default(),
        name: req.name.unwrap_or_default(),
        namespace: req.namespace.unwrap_or_default(),
        resource: req.resource.and_then(|r| r.resource).unwrap_or_default(),
        profile: obj
            .get("spec")
            .and_then(|s| s.get("profile"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        labels: string_map("labels").unwrap_or_default(),
        annotations_present: string_map("annotations").is_some(),
    })
}

/// Decodes the request object the way the Go unstructured decoder does: it
/// must be a JSON object with a non-empty string `kind`.
fn decode_object(raw: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let go_type = match &v {
        Value::Object(_) | Value::Null => None,
        Value::Array(_) => Some("array"),
        Value::String(_) => Some("string"),
        Value::Number(_) => Some("number"),
        Value::Bool(_) => Some("bool"),
    };
    if let Some(t) = go_type {
        return Err(format!(
            "json: cannot unmarshal {t} into Go value of type map[string]interface {{}}"
        ));
    }
    match v.get("kind").and_then(Value::as_str) {
        Some(k) if !k.is_empty() => Ok(v),
        _ => Err(format!("Object 'Kind' is missing in '{raw}'")),
    }
}

#[derive(Serialize)]
struct PatchOp<'a> {
    op: &'static str,
    path: String,
    value: PatchValue<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PatchValue<'a> {
    Str(&'a str),
    Map(BTreeMap<&'static str, &'static str>),
}

/// Builds the RFC 6902 JSONPatch setting `spec.profile` and stamping
/// [`DEFAULTED_ANNOTATION`], creating the annotations map when the object has
/// none (or has one Go's accessor would not read as a string map).
fn profile_patch(annotations_present: bool, profile: &str) -> serde_json::Result<Vec<u8>> {
    let mut ops = vec![PatchOp {
        op: "add",
        path: "/spec/profile".to_owned(),
        value: PatchValue::Str(profile),
    }];
    if annotations_present {
        ops.push(PatchOp {
            op: "add",
            path: format!(
                "/metadata/annotations/{}",
                escape_json_pointer(DEFAULTED_ANNOTATION)
            ),
            value: PatchValue::Str("true"),
        });
    } else {
        ops.push(PatchOp {
            op: "add",
            path: "/metadata/annotations".to_owned(),
            value: PatchValue::Map(BTreeMap::from([(DEFAULTED_ANNOTATION, "true")])),
        });
    }
    gojson::to_vec(&ops)
}

/// Escapes `~` and `/` per RFC 6901 for use in a patch path.
fn escape_json_pointer(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

#[derive(Serialize)]
struct OutReview<'a> {
    kind: &'a str,
    #[serde(rename = "apiVersion")]
    api_version: &'a str,
    response: OutResponse<'a>,
}

#[derive(Serialize)]
struct OutResponse<'a> {
    uid: &'a str,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<OutStatus<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    patch: Option<String>,
    #[serde(rename = "patchType", skip_serializing_if = "Option::is_none")]
    patch_type: Option<&'static str>,
}

#[derive(Serialize)]
struct OutStatus<'a> {
    metadata: EmptyObject,
    #[serde(skip_serializing_if = "str::is_empty")]
    message: &'a str,
}

#[derive(Serialize)]
struct EmptyObject {}

/// Wraps the response in an AdmissionReview envelope, preserving the
/// request's kind/apiVersion (defaulting each when empty).
fn write_review(
    req: &Decoded,
    allowed: bool,
    message: Option<&str>,
    patch: Option<&[u8]>,
) -> Reply {
    let out = OutReview {
        kind: if req.kind.is_empty() {
            "AdmissionReview"
        } else {
            &req.kind
        },
        api_version: if req.api_version.is_empty() {
            "admission.k8s.io/v1"
        } else {
            &req.api_version
        },
        response: OutResponse {
            uid: &req.uid,
            allowed,
            status: message.map(|m| OutStatus {
                metadata: EmptyObject {},
                message: m,
            }),
            patch: patch.map(|p| base64::engine::general_purpose::STANDARD.encode(p)),
            patch_type: patch.map(|_| "JSONPatch"),
        },
    };
    match gojson::to_vec(&out) {
        Ok(mut body) => {
            // Go's json.Encoder terminates each value with a newline.
            body.push(b'\n');
            Reply::json(body)
        }
        Err(e) => Reply::error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("encode response: {e}"),
        ),
    }
}

#[cfg(test)]
mod tests;
