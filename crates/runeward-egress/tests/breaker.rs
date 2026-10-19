//! Retry-storm circuit breaker against loopback upstreams: 429/503 open a
//! per-endpoint breaker for the upstream's `Retry-After`, further calls are
//! shed with a 503 `shed` refusal without reaching the upstream, and a
//! `health_path` can close a 503 breaker early. Time is a manual clock, so
//! nothing here waits on the wall clock.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{policy, start_proxy};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use runeward_charter::Endpoint;
use runeward_egress::resolve::StaticResolver;
use runeward_egress::{Broker, Proxy, ReasonCode, Verdict, list_decisions};
use tokio::net::TcpListener;

/// Shared upstream state.
#[derive(Default)]
struct Upstream {
    /// While set, `/work` and `/healthz` answer 503.
    down: AtomicBool,
    /// Requests seen, by kind.
    work: AtomicUsize,
    health: AtomicUsize,
}

async fn serve(
    req: Request<Incoming>,
    st: Arc<Upstream>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let reply = |status: u16, retry: Option<&str>| {
        let mut b = Response::builder().status(status);
        if let Some(r) = retry {
            b = b.header("retry-after", r);
        }
        Ok(b.body(Full::new(Bytes::from_static(b"{}"))).expect("resp"))
    };
    match req.uri().path() {
        "/healthz" => {
            st.health.fetch_add(1, Ordering::SeqCst);
            if st.down.load(Ordering::SeqCst) {
                reply(503, None)
            } else {
                reply(200, None)
            }
        }
        "/limited" => {
            st.work.fetch_add(1, Ordering::SeqCst);
            reply(429, Some("20"))
        }
        _ => {
            st.work.fetch_add(1, Ordering::SeqCst);
            if st.down.load(Ordering::SeqCst) {
                reply(503, Some("120"))
            } else {
                reply(200, None)
            }
        }
    }
}

async fn start_upstream() -> (SocketAddr, Arc<Upstream>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let st = Arc::new(Upstream::default());
    let s = Arc::clone(&st);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = ln.accept().await {
            let s = Arc::clone(&s);
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| serve(req, Arc::clone(&s)));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, st)
}

/// A manual monotonic clock: `base + offset`.
fn manual_clock() -> (runeward_egress::broker::breaker::Clock, Arc<AtomicU64>) {
    let base = Instant::now();
    let off = Arc::new(AtomicU64::new(0));
    let o = Arc::clone(&off);
    (
        Arc::new(move || base + Duration::from_millis(o.load(Ordering::SeqCst))),
        off,
    )
}

fn advance(off: &AtomicU64, secs: u64) {
    off.fetch_add(secs * 1000, Ordering::SeqCst);
}

async fn setup(
    sandbox: &str,
    health_path: &str,
) -> (
    SocketAddr,
    String,
    Arc<Upstream>,
    Arc<Broker>,
    Arc<AtomicU64>,
) {
    let (origin, st) = start_upstream().await;
    let ep = Endpoint {
        name: "api".into(),
        host: "api.test".into(),
        port: origin.port(),
        protocol: "rest".into(),
        health_path: health_path.into(),
        ..Endpoint::default()
    };
    let (clock, off) = manual_clock();
    let b = Arc::new(
        Broker::with_secret_values(sandbox, vec![ep], vec![], HashMap::new())
            .expect("broker")
            .with_clock(clock),
    );
    let p = Proxy::new(policy("deny", vec![]))
        .with_resolver(Arc::new(StaticResolver::new(vec![
            "127.0.0.1".parse::<IpAddr>().expect("ip"),
        ])))
        .with_broker(Arc::clone(&b));
    let (proxy, stop) = start_proxy(p).await;
    std::mem::forget(stop);
    (proxy, format!("api.test:{}", origin.port()), st, b, off)
}

async fn get(proxy: SocketAddr, authority: &str, path: &str) -> common::Resp {
    common::roundtrip(
        proxy,
        &format!(
            "GET http://{authority}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await
}

fn json(r: &common::Resp) -> serde_json::Value {
    serde_json::from_str(&r.body).unwrap_or_else(|_| panic!("json: {}", r.body))
}

#[tokio::test]
async fn too_many_requests_opens_the_breaker_and_sheds_until_retry_after() {
    let sb = "sb-breaker-429";
    let (proxy, auth, st, b, off) = setup(sb, "/healthz").await;

    // The upstream's own 429 passes through and opens the breaker.
    let r = get(proxy, &auth, "/limited").await;
    assert_eq!(r.status, 429);
    assert_eq!(st.work.load(Ordering::SeqCst), 1);

    // Further calls are shed without reaching the upstream, and a health
    // path never closes a 429 breaker early.
    for _ in 0..3 {
        let r = get(proxy, &auth, "/work").await;
        assert_eq!(r.status, 503, "{}", r.body);
        let v = json(&r);
        assert_eq!(v["code"], "shed");
        assert_eq!(v["verdict"], "deny");
        assert_eq!(v["refusal"]["reason"], "shed");
        assert_eq!(v["refusal"]["retryable"], true);
        assert_eq!(r.header("retry-after").as_deref(), Some("20"));
        assert_eq!(r.header("x-runeward-decision").as_deref(), Some("shed"));
    }
    assert_eq!(
        st.work.load(Ordering::SeqCst),
        1,
        "shed calls never go upstream"
    );
    assert_eq!(st.health.load(Ordering::SeqCst), 0, "429s are waited out");
    assert_eq!(b.shed_counts().get("api"), Some(&3));

    // Shed decisions carry their own reason code, apart from policy denies.
    let d = list_decisions(sb).pop().expect("decision");
    assert_eq!(d.reason_code, Some(ReasonCode::Shed));
    assert_eq!(d.verdict, Some(Verdict::Deny));
    assert_eq!(d.endpoint.as_deref(), Some("api"));
    assert!(
        !list_decisions(sb)
            .iter()
            .any(|d| d.reason_code == Some(ReasonCode::Denied)),
        "no policy denies recorded"
    );

    // Partway through the window it is still open, with less to wait.
    advance(&off, 15);
    let r = get(proxy, &auth, "/work").await;
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after").as_deref(), Some("5"));

    // Once the window passes, calls flow again.
    advance(&off, 5);
    let r = get(proxy, &auth, "/work").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(st.work.load(Ordering::SeqCst), 2);
    assert_eq!(b.shed_counts().get("api"), Some(&4));
}

#[tokio::test]
async fn unavailable_is_capped_and_closed_early_by_a_healthy_probe() {
    let sb = "sb-breaker-503";
    let (proxy, auth, st, b, off) = setup(sb, "/healthz").await;
    st.down.store(true, Ordering::SeqCst);

    let r = get(proxy, &auth, "/work").await;
    assert_eq!(r.status, 503);
    assert_ne!(json(&r)["code"], "shed", "the upstream's own answer");
    assert_eq!(st.work.load(Ordering::SeqCst), 1);

    // The next call probes the health path; still down, so it is shed with
    // the window capped at 30s (the upstream asked for 120).
    let r = get(proxy, &auth, "/work").await;
    assert_eq!(r.status, 503);
    assert_eq!(json(&r)["code"], "shed");
    assert_eq!(r.header("retry-after").as_deref(), Some("30"));
    assert_eq!(st.health.load(Ordering::SeqCst), 1);

    // Probes are spaced out; a storm of calls does not become a storm of
    // probes.
    for _ in 0..5 {
        assert_eq!(json(&get(proxy, &auth, "/work").await)["code"], "shed");
    }
    assert_eq!(st.health.load(Ordering::SeqCst), 1);
    assert_eq!(st.work.load(Ordering::SeqCst), 1);

    // The upstream recovers: the next probe closes the breaker and the call
    // goes through, well before the window would have passed.
    st.down.store(false, Ordering::SeqCst);
    advance(&off, 1);
    let r = get(proxy, &auth, "/work").await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(st.health.load(Ordering::SeqCst), 2);
    assert_eq!(st.work.load(Ordering::SeqCst), 2);
    assert_eq!(get(proxy, &auth, "/work").await.status, 200);
    assert_eq!(b.shed_counts().get("api"), Some(&6));
}

#[tokio::test]
async fn without_a_health_path_a_503_is_waited_out() {
    let sb = "sb-breaker-503-wait";
    let (proxy, auth, st, _b, off) = setup(sb, "").await;
    st.down.store(true, Ordering::SeqCst);
    assert_eq!(get(proxy, &auth, "/work").await.status, 503);
    st.down.store(false, Ordering::SeqCst);
    advance(&off, 29);
    let r = get(proxy, &auth, "/work").await;
    assert_eq!(json(&r)["code"], "shed");
    assert_eq!(st.health.load(Ordering::SeqCst), 0);
    advance(&off, 1);
    assert_eq!(get(proxy, &auth, "/work").await.status, 200);
}
