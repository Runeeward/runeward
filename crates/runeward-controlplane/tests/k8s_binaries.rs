//! Opt-in end-to-end test of endpoint `binaries` on a real Kubernetes
//! cluster.
//!
//! Runs only with `RUNEWARD_TEST_K8S=1`, against the kubeconfig context in
//! `RUNEWARD_KUBE_CONTEXT` (or the current one). It needs:
//!
//! - `RUNEWARD_EGRESS_IMAGE`: the egress image from
//!   `deploy/Dockerfile.egress` (it carries `runeward-supervisor`), pullable
//!   by the nodes (for kind: `kind load docker-image` and
//!   `RUNEWARD_EGRESS_PULL_POLICY=Never`);
//! - `RW_IT_SANDBOX_IMAGE`: a sandbox image with `curl`, `wget` and
//!   `python3` (no supervisor needed: the Pod gets it from the egress image);
//! - `RW_IT_UPSTREAM_IP`: an address of this machine the Pods can reach
//!   (for kind, run the test in a container on the `kind` Docker network
//!   and pass that container's address; see docs/E2E-TESTING.md).
//!
//! It serves plain HTTP on every interface, publishes it in the cluster as
//! a selector-less Service, and creates Citadels from Charters with strict
//! egress, a non-root agent and one `tcp` endpoint that allows only
//! `/usr/bin/curl`. It then proves that:
//!
//! - `curl` reaches the upstream through the strict-egress sidecar;
//! - `python3`, `wget` and a copy of curl at another path are refused before
//!   the upstream sees anything;
//! - the perimeter list and the signed ledger record the attributed binary,
//!   `binary_enforced`, and reason code `binary` for the refusals;
//! - the supervisor reported binary attribution `enforced`;
//! - with the attribution helper killed, even `curl` is refused (fail
//!   closed);
//! - with `mode = "audit"`, `python3` is forwarded and recorded as
//!   `audit-would-deny` with `binary_enforced = false`.
//!
//! Everything the test creates (the Citadels, the Service and its
//! EndpointSlice) is removed on the way out.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointPort, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, DeleteParams, PostParams};
use kube::config::KubeConfigOptions;
use runeward_backend::{BackendConfig, K8s};
use runeward_charter::SignedCharters;
use runeward_controlplane::{CreateOptions, Manager, ManagerConfig};
use runeward_egress::ReasonCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const AGENT_UID: &str = "1500";
const BODY: &str = "hello-from-upstream";
const SERVICE: &str = "rw-it-binaries-upstream";

fn enabled() -> bool {
    std::env::var("RUNEWARD_TEST_K8S").is_ok_and(|v| v == "1")
}

fn backend_config() -> BackendConfig {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for k in [
        "RUNEWARD_KUBE_CONTEXT",
        "RUNEWARD_EGRESS_IMAGE",
        "RUNEWARD_EGRESS_PULL_POLICY",
        "RUNEWARD_K8S_NAMESPACE",
    ] {
        if let Ok(v) = std::env::var(k) {
            pairs.push((k.to_owned(), v));
        }
    }
    BackendConfig::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())))
}

/// A plain-HTTP origin on every interface that counts requests.
async fn start_upstream() -> (u16, Arc<AtomicUsize>) {
    let ln = TcpListener::bind("0.0.0.0:0").await.expect("bind");
    let port = ln.local_addr().expect("addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = ln.accept().await {
            let count = Arc::clone(&count);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tcp.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
                let _ = tcp.write_all(resp.as_bytes()).await;
                let _ = tcp.shutdown().await;
            });
        }
    });
    (port, hits)
}

async fn kube_client() -> kube::Client {
    let config = match std::env::var("RUNEWARD_KUBE_CONTEXT") {
        Ok(context) => kube::Config::from_kubeconfig(&KubeConfigOptions {
            context: Some(context),
            ..KubeConfigOptions::default()
        })
        .await
        .expect("kubeconfig"),
        Err(_) => kube::Config::infer().await.expect("kubeconfig"),
    };
    kube::Client::try_from(config).expect("client")
}

/// Publishes the upstream (`ip:port`) in the cluster as
/// `SERVICE.<namespace>.svc.cluster.local:80`, and removes it on drop.
struct Upstream {
    services: Api<Service>,
    slices: Api<EndpointSlice>,
}

impl Upstream {
    async fn publish(client: kube::Client, namespace: &str, ip: &str, port: u16) -> Self {
        let services: Api<Service> = Api::namespaced(client.clone(), namespace);
        let slices: Api<EndpointSlice> = Api::namespaced(client, namespace);
        let up = Self { services, slices };
        up.remove().await;
        let svc = Service {
            metadata: ObjectMeta {
                name: Some(SERVICE.into()),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    port: 80,
                    protocol: Some("TCP".into()),
                    ..ServicePort::default()
                }]),
                ..ServiceSpec::default()
            }),
            ..Service::default()
        };
        up.services
            .create(&PostParams::default(), &svc)
            .await
            .expect("create the upstream Service");
        let slice = EndpointSlice {
            metadata: ObjectMeta {
                name: Some(SERVICE.into()),
                labels: Some(BTreeMap::from([(
                    "kubernetes.io/service-name".to_owned(),
                    SERVICE.to_owned(),
                )])),
                ..ObjectMeta::default()
            },
            address_type: "IPv4".into(),
            endpoints: Some(vec![Endpoint {
                addresses: vec![ip.to_owned()],
                ..Endpoint::default()
            }]),
            ports: Some(vec![EndpointPort {
                name: Some("http".into()),
                port: Some(i32::from(port)),
                protocol: Some("TCP".into()),
                ..EndpointPort::default()
            }]),
        };
        up.slices
            .create(&PostParams::default(), &slice)
            .await
            .expect("create the upstream EndpointSlice");
        up
    }

    async fn remove(&self) {
        let _ = self.slices.delete(SERVICE, &DeleteParams::default()).await;
        let _ = self
            .services
            .delete(SERVICE, &DeleteParams::default())
            .await;
    }
}

fn charter(image: &str, host: &str, mode: &str) -> String {
    format!(
        r#"
[host]
type = "k8s"
image = "{image}"
workdir = "/workspace"

[process]
run_as_user = "{AGENT_UID}"

[network]
default = "deny"
enforce = "strict"

[[endpoint]]
name = "upstream"
host = "{host}"
port = 80
protocol = "tcp"
binaries = ["/usr/bin/curl"]
{mode}
"#
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn endpoint_binaries_enforced_on_kubernetes() {
    if !enabled() {
        eprintln!("skipped: set RUNEWARD_TEST_K8S=1 to run against a cluster");
        return;
    }
    let image = std::env::var("RW_IT_SANDBOX_IMAGE").expect("RW_IT_SANDBOX_IMAGE");
    let upstream_ip = std::env::var("RW_IT_UPSTREAM_IP").expect("RW_IT_UPSTREAM_IP");
    let k = K8s::new(backend_config()).await.expect("k8s");
    k.ensure_namespace().await.expect("namespace");
    let namespace = k.namespace().to_owned();
    let (port, hits) = start_upstream().await;
    let up = Upstream::publish(kube_client().await, &namespace, &upstream_ip, port).await;
    let host = format!("{SERVICE}.{namespace}.svc.cluster.local");

    let enforced = tokio::spawn(enforced(image.clone(), host.clone(), Arc::clone(&hits)));
    let r = enforced.await;
    let audited = if r.is_ok() {
        tokio::spawn(audited(image, host, Arc::clone(&hits))).await
    } else {
        Ok(())
    };
    up.remove().await;
    if let Err(e) = r.and(audited) {
        std::panic::resume_unwind(e.into_panic());
    }
}

/// A manager over one Charter, with ledger and state in `dir`.
async fn manager(dir: &std::path::Path, name: &str, charter: &str) -> Arc<Manager> {
    let charters = dir.join("charters");
    std::fs::create_dir_all(&charters).expect("mkdir");
    std::fs::write(charters.join(format!("{name}.toml")), charter).expect("charter");
    let mut cfg = ManagerConfig::from_lookup(|_| None);
    cfg.config_dir = Some(charters);
    cfg.state_dir = Some(dir.join("state"));
    cfg.signed_charters = SignedCharters::Disabled;
    cfg.sweep_interval = None;
    cfg.supervisor_report_wait = Duration::from_secs(60);
    Manager::builder(cfg)
        .backend_config(backend_config())
        .build()
        .await
        .expect("manager")
}

async fn sh(mgr: &Manager, id: &str, script: &str) -> runeward_controlplane::ToolResult {
    let r = mgr
        .shell(id, &["sh".into(), "-c".into(), script.to_owned()], "")
        .await
        .expect("shell");
    println!(
        "$ {script}\n  exit={} stdout={:?} stderr={:?}",
        r.exit_code, r.stdout, r.stderr
    );
    r
}

fn python_get(url: &str) -> String {
    format!(
        "python3 -c \"import urllib.request,sys\ntry:\n  print(urllib.request.urlopen('{url}', timeout=20).read().decode())\nexcept Exception as e:\n  print('refused:', e); sys.exit(3)\""
    )
}

/// Waits until `n` perimeter decisions match `want`, then returns them all.
async fn perimeter_until(
    mgr: &Manager,
    id: &str,
    n: usize,
    want: impl Fn(&runeward_egress::Decision) -> bool,
) -> Vec<runeward_egress::Decision> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let p = mgr.perimeter(id).expect("perimeter");
        if p.iter().filter(|d| want(d)).count() >= n || std::time::Instant::now() > deadline {
            for d in &p {
                println!(
                    "perimeter: allow={} endpoint={:?} binary={:?} enforced={:?} code={:?} reason={}",
                    d.allow, d.endpoint, d.binary, d.binary_enforced, d.reason_code, d.reason
                );
            }
            return p;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits until `n` egress ledger entries match `want`, then returns all.
async fn ledger_until(
    mgr: &Manager,
    n: usize,
    want: impl Fn(&runeward_ledger::Event) -> bool,
) -> Vec<runeward_ledger::Event> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let ledger = Arc::clone(mgr.ledger());
        let records = tokio::task::spawn_blocking(move || ledger.records().expect("records"))
            .await
            .expect("join");
        if records.iter().filter(|e| want(e)).count() >= n || std::time::Instant::now() > deadline {
            return records;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn enforced(image: String, host: String, hits: Arc<AtomicUsize>) {
    println!("== enforce");
    let dir = tempfile::tempdir().expect("tmp");
    let mgr = manager(dir.path(), "binaries", &charter(&image, &host, "")).await;
    let sb = mgr
        .create_sandbox("binaries", CreateOptions::default())
        .await
        .expect("create the Citadel");
    println!("created {} ({})", sb.id, sb.image);
    let id = sb.id.clone();
    let url = format!("http://{host}/hello");
    let work = tokio::spawn(enforced_checks(Arc::clone(&mgr), id.clone(), url, hits));
    let result = work.await;
    mgr.kill_sandbox(&id).await.expect("kill");
    mgr.close().await.expect("close");
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn enforced_checks(mgr: Arc<Manager>, id: String, url: String, hits: Arc<AtomicUsize>) {
    let before = hits.load(Ordering::SeqCst);
    {
        let r = sh(&mgr, &id, "id -u").await;
        assert_eq!(r.stdout.trim(), AGENT_UID);

        // 1. The listed binary reaches the endpoint.
        let r = sh(&mgr, &id, &format!("curl -sS --max-time 20 {url}")).await;
        assert_eq!(r.exit_code, 0, "curl: {}", r.stderr);
        assert_eq!(r.stdout.trim(), BODY);
        assert_eq!(hits.load(Ordering::SeqCst), before + 1);

        // 2. Unlisted binaries are refused, and nothing reaches the
        // upstream.
        let r = sh(&mgr, &id, &python_get(&url)).await;
        assert_eq!(r.exit_code, 3, "python3 must be refused: {}", r.stdout);
        assert!(!r.stdout.contains(BODY), "{}", r.stdout);
        let r = sh(&mgr, &id, &format!("wget -q -T 20 -t 1 -O - {url}")).await;
        assert_ne!(r.exit_code, 0, "wget must be refused: {}", r.stdout);
        assert!(!r.stdout.contains(BODY), "{}", r.stdout);
        let r = sh(
            &mgr,
            &id,
            &format!("cp /usr/bin/curl /tmp/curl && /tmp/curl -sS --max-time 20 {url}"),
        )
        .await;
        assert_ne!(r.exit_code, 0, "a copy of curl is not curl: {}", r.stdout);
        assert_eq!(
            hits.load(Ordering::SeqCst),
            before + 1,
            "only the allowed call landed"
        );

        // The supervisor ran the helper.
        let info = mgr
            .list_sandbox_infos()
            .into_iter()
            .find(|i| i.sandbox.id == id)
            .expect("info");
        let ev = info.enforcement.expect("enforcement evidence");
        println!("enforcement: {ev:?}");
        assert_eq!(ev.binary_attribution, "enforced");
        assert_eq!(ev.uid, Some(1500));

        // 3. The perimeter list and the signed ledger record the binary and
        // binary_enforced.
        let is_binary = |d: &runeward_egress::Decision| d.reason_code == Some(ReasonCode::Binary);
        let perimeter = perimeter_until(&mgr, &id, 3, is_binary).await;
        let allowed = perimeter
            .iter()
            .find(|d| d.allow && d.endpoint.as_deref() == Some("upstream"))
            .expect("allowed decision");
        assert_eq!(allowed.binary.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(allowed.binary_enforced, Some(true));
        let refused: Vec<_> = perimeter.iter().filter(|d| is_binary(d)).collect();
        for want in ["python3", "wget", "/tmp/curl"] {
            assert!(
                refused
                    .iter()
                    .any(|d| d.binary.as_deref().is_some_and(|b| b.contains(want))),
                "{want}: {refused:?}"
            );
        }
        assert!(
            refused
                .iter()
                .all(|d| !d.allow && d.binary_enforced == Some(true))
        );
        let is_binary_entry = |e: &runeward_ledger::Event| {
            e.tool == "egress" && e.meta.get("reason_code").map(String::as_str) == Some("binary")
        };
        let records = ledger_until(&mgr, 3, is_binary_entry).await;
        let denied = records
            .iter()
            .find(|e| {
                e.tool == "egress" && e.meta.get("binary").is_some_and(|b| b.contains("python3"))
            })
            .expect("python3 refusal chronicled");
        println!("ledger: {:?}", denied.meta);
        assert_eq!(denied.verdict, "deny");
        assert_eq!(denied.meta["binary_enforced"], "true");
        assert_eq!(denied.meta["reason_code"], "binary");
        let allowed = records
            .iter()
            .find(|e| {
                e.tool == "egress"
                    && e.meta.get("binary").map(String::as_str) == Some("/usr/bin/curl")
            })
            .expect("curl allow chronicled");
        assert_eq!(allowed.meta["binary_enforced"], "true");
        let report = records
            .iter()
            .find(|e| e.tool == "supervisor" && e.action == "report")
            .expect("supervisor report chronicled");
        assert_eq!(report.meta["binary_attribution"], "enforced");

        // 5. The agent can kill the helper (same uid); then nothing is
        // attributed and even curl is refused.
        let r = sh(
            &mgr,
            &id,
            "for p in /proc/[0-9]*; do set -- $(tr '\\0' ' ' < $p/cmdline 2>/dev/null); \
             if [ \"$2\" = attribution-helper ]; then echo killed ${p#/proc/}; kill -9 ${p#/proc/}; fi; done; \
             sleep 1; for p in /proc/[0-9]*; do set -- $(tr '\\0' ' ' < $p/cmdline 2>/dev/null); \
             [ \"$2\" = attribution-helper ] && echo alive ${p#/proc/}; done; true",
        )
        .await;
        assert!(r.stdout.contains("killed"), "{}", r.stdout);
        assert!(!r.stdout.contains("alive"), "{}", r.stdout);
        let r = sh(&mgr, &id, &format!("curl -sS --max-time 20 {url}")).await;
        assert_ne!(r.exit_code, 0, "curl must be refused without the helper");
        assert!(!r.stdout.contains(BODY), "{}", r.stdout);
        assert_eq!(hits.load(Ordering::SeqCst), before + 1, "fail closed");
        let perimeter = perimeter_until(&mgr, &id, 4, is_binary).await;
        let last = perimeter
            .iter()
            .rev()
            .find(|d| is_binary(d))
            .expect("refusal");
        assert!(!last.allow && last.binary_enforced == Some(true));
        mgr.verify_ledger().await.expect("signed ledger verifies");
    }
}

async fn audited(image: String, host: String, hits: Arc<AtomicUsize>) {
    println!("== audit");
    let dir = tempfile::tempdir().expect("tmp");
    let mgr = manager(
        dir.path(),
        "binaries-audit",
        &charter(&image, &host, "mode = \"audit\""),
    )
    .await;
    let sb = mgr
        .create_sandbox("binaries-audit", CreateOptions::default())
        .await
        .expect("create the audit Citadel");
    println!("created {} ({})", sb.id, sb.image);
    let id = sb.id.clone();
    let url = format!("http://{host}/hello");
    let work = tokio::spawn(audited_checks(Arc::clone(&mgr), id.clone(), url, hits));
    let result = work.await;
    mgr.kill_sandbox(&id).await.expect("kill");
    mgr.close().await.expect("close");
    if let Err(e) = result {
        std::panic::resume_unwind(e.into_panic());
    }
}

async fn audited_checks(mgr: Arc<Manager>, id: String, url: String, hits: Arc<AtomicUsize>) {
    let before = hits.load(Ordering::SeqCst);

    // 4. An unlisted binary is forwarded and recorded as audit-would-deny.
    let r = sh(&mgr, &id, &python_get(&url)).await;
    assert_eq!(r.exit_code, 0, "audit forwards python3: {}", r.stdout);
    assert_eq!(r.stdout.trim(), BODY);
    assert_eq!(hits.load(Ordering::SeqCst), before + 1);
    let is_audit =
        |d: &runeward_egress::Decision| d.reason_code == Some(ReasonCode::AuditWouldDeny);
    let perimeter = perimeter_until(&mgr, &id, 1, is_audit).await;
    let d = perimeter
        .iter()
        .find(|d| is_audit(d))
        .expect("audit-would-deny");
    assert!(d.allow);
    assert!(
        d.binary.as_deref().is_some_and(|b| b.contains("python3")),
        "{d:?}"
    );
    assert_eq!(d.binary_enforced, Some(false));
    let records = ledger_until(&mgr, 1, |e| {
        e.tool == "egress"
            && e.meta.get("reason_code").map(String::as_str) == Some("audit-would-deny")
    })
    .await;
    let e = records
        .iter()
        .find(|e| {
            e.tool == "egress"
                && e.meta.get("reason_code").map(String::as_str) == Some("audit-would-deny")
        })
        .expect("audit-would-deny chronicled");
    println!("ledger: {:?}", e.meta);
    assert_eq!(e.meta["binary_enforced"], "false");
    mgr.verify_ledger().await.expect("signed ledger verifies");
}
