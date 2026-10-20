//! Webhook tests: Go fixture replay, the policy cache, cert persistence and
//! self-registration against a mock API server, and TLS serving.

use super::*;
use http::{Method, Request};
use http_body_util::BodyExt as _;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tower::ServiceExt as _;

/// Recorded by running the Go handler (`internal/webhook`) over the same
/// requests.
const GO_FIXTURES: &str = include_str!("../../tests/fixtures/go_admission.json");

fn fixtures() -> Value {
    serde_json::from_str(GO_FIXTURES).expect("parse Go fixtures")
}

/// A scripted [`PolicySource`]: each call returns the next result, repeating
/// the last one when the script runs out.
struct Scripted {
    results: Vec<Result<Vec<Policy>, String>>,
    calls: AtomicUsize,
}

impl Scripted {
    fn new(results: Vec<Result<Vec<Policy>, String>>) -> Self {
        Self {
            results,
            calls: AtomicUsize::new(0),
        }
    }
}

impl PolicySource for Scripted {
    fn list(&self) -> ListFuture<'_> {
        let i = self.calls.fetch_add(1, Ordering::SeqCst);
        let r = self.results[i.min(self.results.len() - 1)].clone();
        Box::pin(async move { r.map_err(BoxError::from) })
    }
}

async fn call(
    router: Router,
    method: &str,
    path: &str,
    body: &str,
) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("method"))
        .uri(path)
        .body(axum::body::Body::from(body.to_owned()))
        .expect("request");
    let resp = router.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

#[tokio::test]
async fn admission_matches_go_fixtures() {
    let fx = fixtures();
    let cases = fx["admission"].as_array().expect("admission cases");
    assert!(cases.len() >= 40, "fixture set shrank");
    // Responses whose text is Go-runtime specific (encoding/json syntax
    // errors): only the status, headers and message prefix must match.
    let prefix_only = ["invalid json", "empty body"];
    for c in cases {
        let name = c["name"].as_str().expect("name");
        let policies: Vec<Policy> = c["policies"]
            .as_array()
            .map(|ps| ps.iter().map(Policy::from_object).collect())
            .unwrap_or_default();
        let result = match c.get("listError").and_then(Value::as_str) {
            Some(e) => Err(e.to_owned()),
            None => Ok(policies),
        };
        let server =
            Arc::new(Server::new(Scripted::new(vec![result])).with_cache_ttl(Duration::ZERO));
        let (status, headers, body) = call(
            server.router(),
            c["method"].as_str().expect("method"),
            c["path"].as_str().expect("path"),
            c["body"].as_str().unwrap_or_default(),
        )
        .await;
        let want_body = c["response"].as_str().expect("response");
        assert_eq!(
            u64::from(status.as_u16()),
            c["status"].as_u64().expect("status"),
            "{name}: status"
        );
        if let Some(want) = c["headers"].get("Content-Type").and_then(Value::as_str) {
            assert_eq!(headers[header::CONTENT_TYPE], want, "{name}: content-type");
        }
        if let Some(want) = c["headers"]
            .get("X-Content-Type-Options")
            .and_then(Value::as_str)
        {
            assert_eq!(
                headers[header::X_CONTENT_TYPE_OPTIONS],
                want,
                "{name}: nosniff"
            );
        }
        let got = String::from_utf8(body).expect("utf8 body");
        if prefix_only.contains(&name) {
            let prefix = want_body.split_once(": ").map(|(p, _)| p).expect("prefix");
            assert!(got.starts_with(&format!("{prefix}: ")), "{name}: {got:?}");
            assert!(got.ends_with('\n'), "{name}: trailing newline");
        } else {
            assert_eq!(got, want_body, "{name}: body");
        }
    }
}

fn patch_ops(annotations: Option<Value>) -> Vec<Value> {
    let mut meta = json!({"name": "sb"});
    if let Some(a) = annotations {
        meta["annotations"] = a;
    }
    let obj = json!({"apiVersion": "runeward.dev/v1alpha1", "kind": "Citadel", "metadata": meta, "spec": {}});
    let body = json!({"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {"uid": "u", "object": obj}});
    let Ok(req) = decode(body.to_string().as_bytes()) else {
        panic!("decode failed");
    };
    let patch = profile_patch(req.annotations_present, "baseline").expect("patch");
    serde_json::from_slice(&patch).expect("patch json")
}

#[test]
fn profile_patch_no_annotations() {
    let ops = patch_ops(None);
    assert_eq!(ops.len(), 2);
    assert_eq!(
        ops[0],
        json!({"op": "add", "path": "/spec/profile", "value": "baseline"})
    );
    assert_eq!(ops[1]["path"], "/metadata/annotations");
    assert_eq!(ops[1]["value"], json!({DEFAULTED_ANNOTATION: "true"}));
}

#[test]
fn profile_patch_existing_annotations() {
    let ops = patch_ops(Some(json!({"existing": "1"})));
    assert_eq!(
        ops[1]["path"],
        "/metadata/annotations/runeward.dev~1cluster-policy-defaulted"
    );
    assert_eq!(ops[1]["value"], "true");
}

#[test]
fn json_pointer_escaping() {
    assert_eq!(escape_json_pointer("a~b/c"), "a~0b~1c");
}

fn review(uid: &str) -> String {
    json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": uid,
            "namespace": "apps",
            "resource": {"resource": "citadels"},
            "object": {"apiVersion": "runeward.dev/v1alpha1", "kind": "Citadel", "metadata": {"name": "c"}, "spec": {"profile": "team-web"}}
        }
    })
    .to_string()
}

fn allowed(reply: &Reply) -> bool {
    let v: Value = serde_json::from_slice(&reply.body).expect("review json");
    v["response"]["allowed"].as_bool().expect("allowed")
}

#[tokio::test]
async fn cache_serves_last_known_good_within_ttl() {
    let permissive = vec![Policy {
        allowed_profiles: vec!["team-*".into()],
        ..Policy::default()
    }];
    let s = Server::new(Scripted::new(vec![Ok(permissive), Err("down".into())]))
        .with_cache_ttl(Duration::from_secs(600));
    assert!(allowed(
        &s.admit(Endpoint::Validate, review("1").as_bytes()).await
    ));
    // The live list now fails; the fresh cache still admits.
    assert!(allowed(
        &s.admit(Endpoint::Validate, review("2").as_bytes()).await
    ));
}

#[tokio::test]
async fn cache_disabled_or_stale_fails_closed() {
    let ok = || Ok(vec![Policy::default()]);
    let s =
        Server::new(Scripted::new(vec![ok(), Err("down".into())])).with_cache_ttl(Duration::ZERO);
    assert!(allowed(
        &s.admit(Endpoint::Validate, review("1").as_bytes()).await
    ));
    let r = s.admit(Endpoint::Validate, review("2").as_bytes()).await;
    assert!(!allowed(&r));
    let v: Value = serde_json::from_slice(&r.body).expect("json");
    assert_eq!(
        v["response"]["status"]["message"],
        "runeward webhook could not evaluate ClusterPolicies: list clusterpolicies: down"
    );

    let s = Server::new(Scripted::new(vec![ok(), Err("down".into())]))
        .with_cache_ttl(Duration::from_millis(1));
    assert!(allowed(
        &s.admit(Endpoint::Validate, review("1").as_bytes()).await
    ));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!allowed(
        &s.admit(Endpoint::Validate, review("2").as_bytes()).await
    ));

    // Never loaded: fails closed even with a TTL...
    let s = Server::new(Scripted::new(vec![Err("down".into())]))
        .with_cache_ttl(Duration::from_secs(600));
    assert!(!allowed(
        &s.admit(Endpoint::Validate, review("1").as_bytes()).await
    ));
    // ...while the mutating endpoint admits unchanged.
    assert!(allowed(
        &s.admit(Endpoint::Mutate, review("2").as_bytes()).await
    ));
}

#[test]
fn cache_ttl_env_values() {
    assert_eq!(policy_cache_ttl(None), DEFAULT_POLICY_CACHE_TTL);
    assert_eq!(policy_cache_ttl(Some("")), DEFAULT_POLICY_CACHE_TTL);
    for off in ["0", "off", "none", "0s", "-0"] {
        assert_eq!(policy_cache_ttl(Some(off)), Duration::ZERO, "{off}");
    }
    assert_eq!(policy_cache_ttl(Some("1m30s")), Duration::from_secs(90));
    assert_eq!(policy_cache_ttl(Some("250ms")), Duration::from_millis(250));
    assert_eq!(policy_cache_ttl(Some("-5m")), DEFAULT_POLICY_CACHE_TTL);
    assert_eq!(policy_cache_ttl(Some("soon")), DEFAULT_POLICY_CACHE_TTL);
    assert_eq!(policy_cache_ttl(Some("10")), DEFAULT_POLICY_CACHE_TTL);
}

// ---------------------------------------------------------------------------
// Mock API server.

use crate::testutil::{mock_client, recorded, status};

const SECRET_PATH: &str = "/api/v1/namespaces/runeward/secrets/runeward-webhook-cert";
const SECRETS_PATH: &str = "/api/v1/namespaces/runeward/secrets";

fn names() -> Vec<String> {
    RunOptions::default().dns_names()
}

async fn load(client: kube::Client) -> Result<CertBundle, Error> {
    load_or_create_cert(Some(client), "runeward", "runeward-webhook-cert", &names()).await
}

#[tokio::test]
async fn cert_secret_created_when_missing() {
    let (client, log) = mock_client(Arc::new(|m, _, _| {
        if *m == Method::GET {
            status(404, "NotFound")
        } else {
            (201, Value::Null)
        }
    }));
    let b = load(client).await.expect("load_or_create_cert");
    let calls = recorded(&log);
    assert_eq!(calls.len(), 2);
    assert_eq!(
        (&calls[0].method, calls[0].path.as_str()),
        (&Method::GET, SECRET_PATH)
    );
    assert_eq!(
        (&calls[1].method, calls[1].path.as_str()),
        (&Method::POST, SECRETS_PATH)
    );
    let created: k8s_openapi::api::core::v1::Secret =
        serde_json::from_value(calls[1].body.clone().expect("body")).expect("secret");
    assert_eq!(created.type_.as_deref(), Some("kubernetes.io/tls"));
    assert_eq!(
        created.metadata.name.as_deref(),
        Some("runeward-webhook-cert")
    );
    assert_eq!(
        created.metadata.labels.clone().unwrap_or_default()["app.kubernetes.io/managed-by"],
        "runeward"
    );
    assert_eq!(cert_from_secret(&created), Some(b));
}

fn secret_json(cert: &CertBundle) -> Value {
    use base64::engine::general_purpose::STANDARD;
    json!({
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": "runeward-webhook-cert", "namespace": "runeward"},
        "type": "kubernetes.io/tls",
        "data": {
            "tls.crt": STANDARD.encode(&cert.cert_pem),
            "tls.key": STANDARD.encode(&cert.key_pem),
            "ca.crt": STANDARD.encode(&cert.ca_pem),
        }
    })
}

#[tokio::test]
async fn cert_secret_reused_when_complete() {
    let existing = generate_cert(&names()).expect("cert");
    let body = secret_json(&existing);
    let (client, log) = mock_client(Arc::new(move |_, _, _| (200, body.clone())));
    assert_eq!(load(client).await.expect("load"), existing);
    assert_eq!(
        recorded(&log).len(),
        1,
        "no create when the Secret is complete"
    );
}

#[tokio::test]
async fn cert_secret_race_adopts_winner() {
    let winner = generate_cert(&names()).expect("cert");
    let body = secret_json(&winner);
    let (client, log) = mock_client(Arc::new(move |m, _, n| match (m.as_str(), n) {
        ("GET", 1) => status(404, "NotFound"),
        ("POST", _) => status(409, "AlreadyExists"),
        _ => (200, body.clone()),
    }));
    assert_eq!(load(client).await.expect("load"), winner);
    assert_eq!(recorded(&log).len(), 3);
}

#[tokio::test]
async fn cert_secret_incomplete_after_race_errors() {
    let (client, _) = mock_client(Arc::new(|m, _, _| {
        if *m == Method::POST {
            status(409, "AlreadyExists")
        } else {
            (
                200,
                json!({"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "runeward-webhook-cert"}, "data": {"tls.crt": ""}}),
            )
        }
    }));
    let err = load(client).await.expect_err("incomplete");
    assert_eq!(
        err.to_string(),
        "cert secret \"runeward-webhook-cert\" exists but is incomplete"
    );
}

#[tokio::test]
async fn cert_secret_read_error_propagates() {
    let (client, log) = mock_client(Arc::new(|_, _, _| status(500, "InternalError")));
    let err = load(client).await.expect_err("read error");
    assert!(
        err.to_string()
            .starts_with("read cert secret \"runeward-webhook-cert\": "),
        "{err}"
    );
    assert_eq!(recorded(&log).len(), 1);
}

#[tokio::test]
async fn cert_without_client_is_ephemeral() {
    let b = load_or_create_cert(None, "runeward", "x", &names())
        .await
        .expect("ephemeral");
    assert!(!b.ca_pem.is_empty());
}

/// Drops fields the API server (or Go's fake clientset) fills in that are not
/// part of the desired object.
fn normalize(mut v: Value) -> Value {
    if let Some(m) = v["metadata"].as_object_mut() {
        m.remove("resourceVersion");
        m.remove("creationTimestamp");
    }
    v
}

#[test]
fn webhook_configurations_match_go() {
    let fx = fixtures();
    let v = serde_json::to_value(validating_configuration(
        b"CA-PEM-2",
        "runeward-webhook",
        "runeward",
    ))
    .expect("vwc");
    assert_eq!(
        normalize(v),
        normalize(fx["validatingWebhookConfiguration"].clone())
    );
    let m = serde_json::to_value(mutating_configuration(
        b"CA-PEM-2",
        "runeward-webhook",
        "runeward",
    ))
    .expect("mwc");
    assert_eq!(
        normalize(m),
        normalize(fx["mutatingWebhookConfiguration"].clone())
    );
}

const VWC_PATH: &str = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations";
const MWC_PATH: &str = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations";

#[tokio::test]
async fn register_creates_then_updates() {
    // First run: nothing exists, so both configurations are created.
    let (client, log) = mock_client(Arc::new(|m, _, _| {
        if *m == Method::GET {
            status(404, "NotFound")
        } else {
            (201, Value::Null)
        }
    }));
    register(client, b"CA", "runeward-webhook", "runeward")
        .await
        .expect("register");
    let calls: Vec<(String, String)> = recorded(&log)
        .into_iter()
        .map(|r| (r.method.to_string(), r.path))
        .collect();
    assert_eq!(
        calls,
        vec![
            ("GET".to_owned(), format!("{VWC_PATH}/runeward.dev")),
            ("POST".to_owned(), VWC_PATH.to_owned()),
            ("GET".to_owned(), format!("{MWC_PATH}/runeward.dev")),
            ("POST".to_owned(), MWC_PATH.to_owned()),
        ]
    );

    // Second run: both exist, so they are replaced carrying the existing
    // resourceVersion.
    let (client, log) = mock_client(Arc::new(|m, path, _| {
        if *m == Method::GET {
            let kind = if path.contains("validating") {
                "ValidatingWebhookConfiguration"
            } else {
                "MutatingWebhookConfiguration"
            };
            (
                200,
                json!({"apiVersion": "admissionregistration.k8s.io/v1", "kind": kind, "metadata": {"name": "runeward.dev", "resourceVersion": "42"}}),
            )
        } else {
            (200, Value::Null)
        }
    }));
    register(client, b"CA2", "runeward-webhook", "runeward")
        .await
        .expect("register");
    let calls = recorded(&log);
    assert_eq!(calls.len(), 4);
    for (i, path) in [(1, VWC_PATH), (3, MWC_PATH)] {
        assert_eq!(calls[i].method, Method::PUT);
        assert_eq!(calls[i].path, format!("{path}/runeward.dev"));
        let body = calls[i].body.as_ref().expect("body");
        assert_eq!(body["metadata"]["resourceVersion"], "42");
        assert_eq!(body["webhooks"][0]["clientConfig"]["caBundle"], "Q0Ey");
    }
}

#[tokio::test]
async fn register_propagates_errors() {
    let (client, _) = mock_client(Arc::new(|_, _, _| status(403, "Forbidden")));
    let err = register(client, b"CA", "s", "n")
        .await
        .expect_err("forbidden");
    assert!(
        err.to_string().starts_with("register validating webhook: "),
        "{err}"
    );
}

#[tokio::test]
async fn kube_policy_source_lists_cluster_policies() {
    let (client, log) = mock_client(Arc::new(|_, _, _| {
        (
            200,
            json!({
                "apiVersion": "runeward.dev/v1alpha1", "kind": "ClusterPolicyList", "metadata": {},
                "items": [
                    {"apiVersion": "runeward.dev/v1alpha1", "kind": "ClusterPolicy", "metadata": {"name": "a"}, "spec": {"defaultProfile": "baseline", "allowedProfiles": ["baseline", 3]}},
                    {"apiVersion": "runeward.dev/v1alpha1", "kind": "ClusterPolicy", "metadata": {"name": "b"}, "spec": {"requiredLabels": ["team"]}}
                ]
            }),
        )
    }));
    let got = KubePolicySource::new(client).list().await.expect("list");
    assert_eq!(
        got,
        vec![
            Policy {
                default_profile: "baseline".into(),
                ..Policy::default()
            },
            Policy {
                required_labels: vec!["team".into()],
                ..Policy::default()
            },
        ]
    );
    assert_eq!(
        recorded(&log)[0].path,
        "/apis/runeward.dev/v1alpha1/clusterpolicies"
    );
}

#[test]
fn run_options_defaults() {
    let o = RunOptions::default();
    assert_eq!(o.port, 8443);
    assert_eq!(o.service_name(), "runeward-webhook");
    assert_eq!(o.cert_secret_name(), "runeward-webhook-cert");
    assert_eq!(
        o.dns_names(),
        vec![
            "runeward-webhook.runeward.svc".to_owned(),
            "runeward-webhook.runeward.svc.cluster.local".to_owned()
        ]
    );
    let o = RunOptions {
        service: "hook".into(),
        namespace: "ops".into(),
        ..RunOptions::default()
    };
    assert_eq!(o.cert_secret_name(), "hook-cert");
    assert_eq!(o.dns_names()[0], "hook.ops.svc");
}

// ---------------------------------------------------------------------------
// TLS serving end to end.

async fn https_post(
    addr: SocketAddr,
    ca_pem: &[u8],
    alpn: &[u8],
    path: &str,
    body: String,
) -> (StatusCode, Vec<u8>) {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem) {
        roots.add(c.expect("ca")).expect("root");
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let name =
        rustls::pki_types::ServerName::try_from("runeward-webhook.runeward.svc").expect("name");
    let tls = connector.connect(name, tcp).await.expect("tls handshake");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn), "ALPN");
    let h2 = alpn == b"h2";
    let io = hyper_util::rt::TokioIo::new(tls);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://runeward-webhook.runeward.svc{path}"))
        .body(http_body_util::Full::new(bytes::Bytes::from(body)))
        .expect("req");
    let resp = if h2 {
        let (mut send, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .expect("h2 handshake");
        tokio::spawn(conn);
        send.send_request(req).await.expect("send")
    } else {
        let (mut send, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .expect("h1 handshake");
        tokio::spawn(conn);
        send.send_request(req).await.expect("send")
    };
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn serves_admission_over_tls() {
    let bundle = generate_cert(&names()).expect("cert");
    let tls = tls_config(&bundle).expect("tls config");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = Arc::new(
        Server::new(Scripted::new(vec![Ok(vec![Policy {
            denied_profiles: vec!["team-*".into()],
            ..Policy::default()
        }])]))
        .with_cache_ttl(Duration::ZERO),
    );
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(serve_tls(listener, tls, server.router(), async {
        let _ = stop_rx.await;
    }));

    for alpn in [b"h2".as_slice(), b"http/1.1".as_slice()] {
        let (status, body) =
            https_post(addr, &bundle.ca_pem, alpn, "/validate", review("tls")).await;
        assert_eq!(status, StatusCode::OK);
        let v: Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(v["response"]["uid"], "tls");
        assert_eq!(v["response"]["allowed"], false);
        let (status, body) =
            https_post(addr, &bundle.ca_pem, alpn, "/healthz", String::new()).await;
        assert_eq!(
            (status, body.as_slice()),
            (StatusCode::OK, b"ok".as_slice())
        );
    }

    stop_tx.send(()).expect("stop");
    tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("server stops")
        .expect("join")
        .expect("serve");
}
