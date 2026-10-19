//! Test support shared by the webhook and controller tests: a mock Kubernetes
//! API server behind a [`kube::Client`].

use http::{Method, Request, header};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use std::sync::{Arc, Mutex, PoisonError};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// One request seen by the mock API server.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub(crate) method: Method,
    /// The URI path (no query).
    pub(crate) path: String,
    /// The raw query string (empty when absent).
    pub(crate) query: String,
    pub(crate) body: Option<Value>,
}

/// Maps (method, path with `?query` when present, 1-based call number) to a
/// status and JSON body; a `null` body echoes the request body back.
pub(crate) type Responder = dyn Fn(&Method, &str, usize) -> (u16, Value) + Send + Sync;

/// Like [`Responder`], additionally given the decoded request body.
pub(crate) type BodyResponder =
    dyn Fn(&Method, &str, Option<&Value>, usize) -> (u16, Value) + Send + Sync;

pub(crate) type Log = Arc<Mutex<Vec<Recorded>>>;

/// A Kubernetes `Status` failure body.
pub(crate) fn status(code: u16, reason: &str) -> (u16, Value) {
    (
        code,
        json!({"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure", "message": reason, "reason": reason, "code": code}),
    )
}

/// A client whose every request is answered by `responder` and recorded.
pub(crate) fn mock_client(responder: Arc<Responder>) -> (kube::Client, Log) {
    mock_client_with_body(Arc::new(move |m, p, _, n| responder(m, p, n)))
}

/// [`mock_client`] for responders that inspect the request body.
pub(crate) fn mock_client_with_body(responder: Arc<BodyResponder>) -> (kube::Client, Log) {
    let log: Log = Arc::default();
    let log2 = Arc::clone(&log);
    let svc = tower::service_fn(move |req: Request<kube::client::Body>| {
        let log = Arc::clone(&log2);
        let responder = Arc::clone(&responder);
        async move {
            let method = req.method().clone();
            let path = req.uri().path().to_owned();
            let query = req.uri().query().unwrap_or_default().to_owned();
            let bytes = req.into_body().collect().await?.to_bytes();
            let body: Option<Value> = if bytes.is_empty() {
                None
            } else {
                Some(serde_json::from_slice(&bytes)?)
            };
            let n = {
                let mut l = log.lock().unwrap_or_else(PoisonError::into_inner);
                l.push(Recorded {
                    method: method.clone(),
                    path: path.clone(),
                    query: query.clone(),
                    body: body.clone(),
                });
                l.len()
            };
            let target = if query.is_empty() {
                path
            } else {
                format!("{path}?{query}")
            };
            let (code, mut v) = responder(&method, &target, body.as_ref(), n);
            if v.is_null() {
                v = body.unwrap_or_default();
            }
            let resp = http::Response::builder()
                .status(code)
                .header(header::CONTENT_TYPE, "application/json")
                .body(kube::client::Body::from(serde_json::to_vec(&v)?))?;
            Ok::<_, BoxError>(resp)
        }
    });
    (kube::Client::new(svc, "default"), log)
}

/// A snapshot of the requests recorded so far.
pub(crate) fn recorded(log: &Log) -> Vec<Recorded> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}
