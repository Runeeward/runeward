//! Runs the Kubernetes backend against an in-memory API server and compares
//! the objects it creates with the ones the Go implementation creates for
//! the same scenarios (`fixtures/go-k8s-objects.json`), and ports the Go
//! namespace/NetworkPolicy tenancy tests.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use kube::Client;
use regex::Regex;
use runeward_backend::config::{
    EGRESS_IMAGE_ENV, EGRESS_PULL_POLICY_ENV, ISOLATION_PROBE_ENV, K8S_NETWORK_POLICY_ENV,
    K8S_PSA_ENFORCE_ENV,
};
use runeward_backend::k8s::{quantity_binary_si, quantity_milli_decimal_si, wrap_command};
use runeward_backend::{
    Backend, BackendConfig, IsolationTier, K8s, LABEL_PROFILE, Resources, Spec,
};
use runeward_charter::{Network, NetworkRule};
use serde_json::{Value, json};

/// Objects keyed by collection path, then name.
type Store = Arc<Mutex<BTreeMap<String, BTreeMap<String, Value>>>>;

const NS: &str = "runeward";

/// A store entry (not an API path) holding injected faults: a collection
/// name (`pods`, `secrets`, ...) maps to `{"persist": bool}` and makes its
/// POSTs fail with 500; `phase` overrides the Pod phase GET reports.
const FAULTS: &str = "faults";

fn lock(s: &Store) -> std::sync::MutexGuard<'_, BTreeMap<String, BTreeMap<String, Value>>> {
    s.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn status(code: StatusCode, reason: &str) -> Response<Full<Bytes>> {
    let body = json!({
        "kind": "Status", "apiVersion": "v1", "metadata": {},
        "status": "Failure", "reason": reason, "message": reason, "code": code.as_u16(),
    });
    respond(code, &body)
}

fn respond(code: StatusCode, v: &Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(v.to_string())))
        .unwrap_or_default()
}

/// The namespace segment of a namespaced path, if any.
fn namespace_of(path: &str) -> Option<String> {
    let mut parts = path.split('/');
    while let Some(p) = parts.next() {
        if p == "namespaces" {
            let ns = parts.next()?;
            // `/api/v1/namespaces/<ns>` alone is the namespace itself.
            return parts.next().map(|_| ns.to_owned());
        }
    }
    None
}

async fn handle(store: Store, req: Request<kube::client::Body>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let (parent, last) = path.rsplit_once('/').unwrap_or(("", ""));
    match method {
        Method::POST => {
            let mut obj: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let name = obj["metadata"]["name"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if let Some(ns) = namespace_of(&format!("{path}/x")) {
                obj["metadata"]["namespace"] = json!(ns);
            }
            let mut s = lock(&store);
            let fault = s.get(FAULTS).and_then(|f| f.get(last)).cloned();
            let coll = s.entry(path.clone()).or_default();
            if coll.contains_key(&name) {
                return status(StatusCode::CONFLICT, "AlreadyExists");
            }
            if let Some(f) = fault {
                // The server may persist an object and still answer with
                // an error (a timeout between the write and the reply).
                if f["persist"] == true {
                    coll.insert(name, obj);
                }
                return status(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
            }
            coll.insert(name, obj.clone());
            respond(StatusCode::CREATED, &obj)
        }
        Method::GET => {
            let s = lock(&store);
            let phase = s
                .get(FAULTS)
                .and_then(|f| f.get("phase"))
                .and_then(Value::as_str)
                .unwrap_or("Running")
                .to_owned();
            match s.get(parent).and_then(|c| c.get(last)) {
                Some(obj) => {
                    let mut obj = obj.clone();
                    if parent.ends_with("/pods") {
                        obj["status"] = json!({
                            "phase": phase,
                            "podIP": "10.1.2.3",
                            "containerStatuses": [{
                                "name": "sandbox", "ready": true, "restartCount": 0,
                                "image": "", "imageID": "",
                            }],
                        });
                    }
                    respond(StatusCode::OK, &obj)
                }
                None => status(StatusCode::NOT_FOUND, "NotFound"),
            }
        }
        Method::PUT => {
            let obj: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let mut s = lock(&store);
            s.entry(parent.to_owned())
                .or_default()
                .insert(last.to_owned(), obj.clone());
            respond(StatusCode::OK, &obj)
        }
        Method::DELETE => {
            let mut s = lock(&store);
            match s.get_mut(parent).and_then(|c| c.remove(last)) {
                Some(obj) => respond(StatusCode::OK, &obj),
                None => status(StatusCode::NOT_FOUND, "NotFound"),
            }
        }
        _ => status(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

fn fake_client(store: &Store) -> Client {
    let store = store.clone();
    let svc = tower::service_fn(move |req: Request<kube::client::Body>| {
        let store = store.clone();
        async move { Ok::<_, Infallible>(handle(store, req).await) }
    });
    Client::new(svc, NS)
}

fn collection(store: &Store, path: &str) -> Vec<Value> {
    lock(store)
        .get(path)
        .map(|c| c.values().cloned().collect())
        .unwrap_or_default()
}

static HEX_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new("[0-9a-f]{32}").expect("re"));

/// Normalises an object for comparison with Go's JSON: drops `apiVersion`/
/// `kind` (Go's typed fakes omit TypeMeta), nulls, and empty arrays/objects
/// (Go marshals zero structs as `{}`), keeping `emptyDir` and `podSelector`
/// whose emptiness is meaningful; sorts `env` by name (Go map order is
/// random) and masks ids.
fn normalize(v: &Value) -> Value {
    fn walk(v: &Value, key: &str) -> Option<Value> {
        match v {
            Value::Null => None,
            Value::Array(a) => {
                let mut items: Vec<Value> = a.iter().filter_map(|x| walk(x, "")).collect();
                if key == "env" {
                    items.sort_by_key(|e| e["name"].as_str().unwrap_or_default().to_owned());
                }
                (!items.is_empty()).then_some(Value::Array(items))
            }
            Value::Object(m) => {
                let out: serde_json::Map<String, Value> = m
                    .iter()
                    .filter(|(k, _)| !(key == "root" && (*k == "apiVersion" || *k == "kind")))
                    .filter_map(|(k, x)| walk(x, k).map(|x| (k.clone(), x)))
                    .collect();
                if out.is_empty() && key != "emptyDir" && key != "podSelector" {
                    None
                } else {
                    Some(Value::Object(out))
                }
            }
            Value::String(s) => Some(Value::String(HEX_ID.replace_all(s, "<ID>").into_owned())),
            other => Some(other.clone()),
        }
    }
    walk(v, "root").unwrap_or(Value::Null)
}

fn normalize_all(items: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = items.iter().map(normalize).collect();
    out.sort_by_key(|o| {
        o["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    });
    out
}

fn go_fixture() -> Value {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-k8s-objects.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("read")).expect("parse")
}

fn deny_network(enforce: &str) -> Network {
    Network {
        default: "deny".into(),
        rules: vec![
            NetworkRule {
                hostname: "example.com".into(),
                ..NetworkRule::default()
            },
            NetworkRule {
                verdict: "deny".into(),
                cidr: "10.0.0.0/8".into(),
                ..NetworkRule::default()
            },
        ],
        enforce: enforce.into(),
    }
}

fn demo(profile: &str) -> Spec {
    Spec {
        profile: profile.into(),
        labels: BTreeMap::from([(LABEL_PROFILE.to_owned(), profile.to_owned())]),
        ..Spec::default()
    }
}

struct Scenario {
    name: &'static str,
    env: Vec<(&'static str, &'static str)>,
    spec: Spec,
    pre_namespace: Option<Value>,
    want_tier: IsolationTier,
}

fn scenarios() -> Vec<Scenario> {
    let psa = |enforce: &str| {
        json!({
            "pod-security.kubernetes.io/enforce": enforce,
            "pod-security.kubernetes.io/enforce-version": "latest",
            "pod-security.kubernetes.io/warn": "baseline",
            "pod-security.kubernetes.io/warn-version": "latest",
            "pod-security.kubernetes.io/audit": "baseline",
            "pod-security.kubernetes.io/audit-version": "latest",
        })
    };
    vec![
        Scenario {
            name: "minimal",
            env: vec![],
            spec: demo("demo"),
            pre_namespace: None,
            want_tier: IsolationTier::Container,
        },
        Scenario {
            name: "hardened",
            env: vec![
                (K8S_NETWORK_POLICY_ENV, "true"),
                (K8S_PSA_ENFORCE_ENV, "restricted"),
            ],
            spec: Spec {
                image: "example/img:1".into(),
                workdir: "/work".into(),
                user: "1000".into(),
                command: ["/bin/sh", "-c", "sleep infinity"]
                    .map(String::from)
                    .to_vec(),
                env: BTreeMap::from([("FOO".into(), "bar baz".into()), ("A".into(), "1".into())]),
                runtime_class: "gvisor".into(),
                read_only: true,
                seccomp: "profiles/strict.json".into(),
                apparmor: "runtime/default".into(),
                resources: Resources {
                    memory_bytes: 512 << 20,
                    nano_cpus: 1_500_000_000,
                },
                ide_port: 8080,
                ..demo("hard")
            },
            pre_namespace: None,
            want_tier: IsolationTier::Kernel,
        },
        Scenario {
            name: "apparmor-localhost",
            env: vec![(K8S_PSA_ENFORCE_ENV, "baseline")],
            spec: Spec {
                apparmor: "my-profile".into(),
                resources: Resources {
                    memory_bytes: 1 << 30,
                    nano_cpus: 2_000_000_000,
                },
                ..demo("aa")
            },
            pre_namespace: Some(json!({"metadata": {"name": NS, "labels": {
                "runeward.managed": "true", "team": "a"}}})),
            want_tier: IsolationTier::Container,
        },
        Scenario {
            name: "apparmor-unconfined",
            env: vec![],
            spec: Spec {
                apparmor: "unconfined".into(),
                ..demo("aa")
            },
            pre_namespace: Some(json!({"metadata": {"name": NS, "labels": psa("privileged")}})),
            want_tier: IsolationTier::Container,
        },
        Scenario {
            name: "cooperative",
            env: vec![],
            spec: Spec {
                network: deny_network(""),
                env: BTreeMap::from([("X".into(), "y".into())]),
                ..demo("net")
            },
            pre_namespace: None,
            want_tier: IsolationTier::Container,
        },
        Scenario {
            name: "strict",
            env: vec![
                (EGRESS_IMAGE_ENV, "registry.example/egress:2"),
                (EGRESS_PULL_POLICY_ENV, "Never"),
                (K8S_NETWORK_POLICY_ENV, "1"),
            ],
            spec: Spec {
                network: deny_network("l3"),
                ..demo("strict")
            },
            pre_namespace: None,
            want_tier: IsolationTier::Container,
        },
    ]
}

#[tokio::test]
async fn created_objects_match_go() {
    let go = go_fixture();
    for sc in scenarios() {
        let store: Store = Arc::default();
        if let Some(ns) = &sc.pre_namespace {
            lock(&store)
                .entry("/api/v1/namespaces".into())
                .or_default()
                .insert(NS.into(), ns.clone());
        }
        // The in-memory API server cannot exec, so these scenarios trust
        // runtime names; `probe_failure_downgrades` covers the probe.
        let cfg =
            BackendConfig::from_pairs(sc.env.iter().copied()).with(ISOLATION_PROBE_ENV, "off");
        let k = K8s::with_client(fake_client(&store), cfg);
        let sb = k.create(sc.spec).await.expect("create");
        assert_eq!(sb.backend, "k8s");
        assert_eq!(sb.isolation, sc.want_tier, "{}", sc.name);

        let want = &go[sc.name];
        let base = format!("/api/v1/namespaces/{NS}");
        let ns = lock(&store)["/api/v1/namespaces"][NS].clone();
        assert_eq!(
            normalize(&ns),
            normalize(&want["namespace"]),
            "{}: namespace",
            sc.name
        );
        for (key, path) in [
            ("pvcs", format!("{base}/persistentvolumeclaims")),
            ("configmaps", format!("{base}/configmaps")),
            ("pods", format!("{base}/pods")),
            (
                "networkpolicies",
                format!("/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies"),
            ),
        ] {
            let got = normalize_all(&collection(&store, &path));
            let want = normalize_all(want[key].as_array().map(Vec::as_slice).unwrap_or(&[]));
            if key == "pods" || key == "pvcs" {
                assert_eq!(got.len(), 1, "{}: {key}", sc.name);
            }
            assert_eq!(
                serde_json::to_string_pretty(&got).expect("json"),
                serde_json::to_string_pretty(&want).expect("json"),
                "{}: {key}",
                sc.name
            );
        }

        // Kill removes everything the sandbox owns.
        k.kill(&sb.id).await.expect("kill");
        for path in [
            format!("{base}/pods"),
            format!("{base}/persistentvolumeclaims"),
            format!("{base}/configmaps"),
        ] {
            assert!(collection(&store, &path).is_empty(), "{}: {path}", sc.name);
        }
    }
}

#[tokio::test]
async fn runtime_class_handler_decides_the_tier() {
    let store: Store = Arc::default();
    lock(&store)
        .entry("/apis/node.k8s.io/v1/runtimeclasses".into())
        .or_default()
        .insert(
            "sandboxed".into(),
            json!({"metadata": {"name": "sandboxed"}, "handler": "kata-qemu"}),
        );
    let cfg = BackendConfig::default().with(ISOLATION_PROBE_ENV, "off");
    let k = K8s::with_client(fake_client(&store), cfg);
    let spec = Spec {
        runtime_class: "sandboxed".into(),
        ..demo("rc")
    };
    let sb = k.create(spec).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Kernel);
    let ev = sb.isolation_evidence.as_ref().expect("evidence");
    assert_eq!(ev.runtime, "kata-qemu");
    let ip = k
        .reachable()
        .expect("reachable")
        .container_ip(&sb.id)
        .await
        .expect("ip");
    assert_eq!(ip, "10.1.2.3");
    assert!(k.exists(&sb.id).await);
    assert!(!k.exists("nope").await);
}

#[tokio::test]
async fn ensure_namespace_sets_psa_labels() {
    let store: Store = Arc::default();
    let k = K8s::with_client(fake_client(&store), BackendConfig::default());
    k.ensure_namespace().await.expect("ensure");
    let ns = lock(&store)["/api/v1/namespaces"][NS].clone();
    let labels = &ns["metadata"]["labels"];
    assert_eq!(labels["pod-security.kubernetes.io/enforce"], "privileged");
    assert_eq!(labels["pod-security.kubernetes.io/warn"], "baseline");
    assert_eq!(labels["pod-security.kubernetes.io/audit"], "baseline");
    assert_eq!(labels["runeward.managed"], "true");
}

#[tokio::test]
async fn ensure_namespace_patches_existing_psa_labels() {
    let store: Store = Arc::default();
    lock(&store)
        .entry("/api/v1/namespaces".into())
        .or_default()
        .insert(
            NS.into(),
            json!({"metadata": {"name": NS, "labels": {"runeward.managed": "true"}}}),
        );
    let k = K8s::with_client(fake_client(&store), BackendConfig::default());
    k.ensure_namespace().await.expect("ensure");
    let ns = lock(&store)["/api/v1/namespaces"][NS].clone();
    assert_eq!(
        ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"],
        "privileged"
    );
}

#[tokio::test]
async fn ensure_network_policy_gated_by_env() {
    let path = format!("/apis/networking.k8s.io/v1/namespaces/{NS}/networkpolicies");
    let store: Store = Arc::default();
    let k = K8s::with_client(fake_client(&store), BackendConfig::default());
    k.ensure_network_policy().await.expect("disabled");
    assert!(collection(&store, &path).is_empty());

    let cfg = BackendConfig::from_pairs([(K8S_NETWORK_POLICY_ENV, "true")]);
    let k = K8s::with_client(fake_client(&store), cfg);
    k.ensure_network_policy().await.expect("enabled");
    let nps = collection(&store, &path);
    assert_eq!(nps.len(), 1);
    let np = &nps[0];
    assert_eq!(np["metadata"]["name"], "runeward-default-deny");
    assert!(np["spec"]["ingress"].as_array().is_none_or(Vec::is_empty));
    let ports = np["spec"]["egress"][0]["ports"].as_array().expect("ports");
    assert_eq!(ports.len(), 2);
    assert!(ports.iter().all(|p| p["port"] == 53));
    // Idempotent: AlreadyExists is not an error.
    k.ensure_network_policy().await.expect("idempotent");
}

#[test]
fn quantities_match_go() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-quantities.json");
    let q: HashMap<String, HashMap<String, String>> =
        serde_json::from_str(&std::fs::read_to_string(p).expect("read")).expect("parse");
    for (bytes, want) in &q["memory"] {
        let n: i64 = bytes.parse().expect("int");
        assert_eq!(&quantity_binary_si(n), want, "memory {n}");
    }
    for (nanos, want) in &q["cpu_nanos"] {
        let n: i64 = nanos.parse().expect("int");
        assert_eq!(&quantity_milli_decimal_si(n / 1_000_000), want, "cpu {n}");
    }
}

#[test]
fn wrap_command_matches_go() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-wrap-command.json");
    let w: HashMap<String, Vec<String>> =
        serde_json::from_str(&std::fs::read_to_string(p).expect("read")).expect("parse");
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    let env = |k: &str, v: &str| BTreeMap::from([(k.to_owned(), v.to_owned())]);
    let none = BTreeMap::new();
    assert_eq!(wrap_command("", &none, &s(&["ls", "-la"])), w["plain"]);
    assert_eq!(wrap_command("/w s", &none, &s(&["ls"])), w["workdir"]);
    assert_eq!(wrap_command("", &env("A", "it's"), &s(&["env"])), w["env"]);
    assert_eq!(
        wrap_command("/w", &env("B", "x y"), &s(&["sh", "-c", "echo $B"])),
        w["both"]
    );
    assert_eq!(
        wrap_command("", &env("A;id", "x"), &s(&["env"])),
        w["bad-env"]
    );
}

#[tokio::test]
async fn probe_failure_downgrades_a_vm_runtime() {
    let store: Store = Arc::default();
    lock(&store)
        .entry("/apis/node.k8s.io/v1/runtimeclasses".into())
        .or_default()
        .insert(
            "kata-fc".into(),
            json!({"metadata": {"name": "kata-fc"}, "handler": "kata-fc"}),
        );
    // The fake API server has no exec endpoint, so the probe fails: the
    // kata-fc claim cannot be confirmed and the sandbox reports container.
    let k = K8s::with_client(fake_client(&store), BackendConfig::default());
    let spec = Spec {
        runtime_class: "kata-fc".into(),
        ..demo("vm")
    };
    let sb = k.create(spec).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Container);
    let ev = sb.isolation_evidence.expect("evidence");
    assert_eq!(ev.runtime, "kata-fc");
    assert!(ev.signals[0].starts_with("probe:failed="), "{ev:?}");
    assert!(ev.signals.contains(&"claim:vm".to_owned()), "{ev:?}");
}

fn inject(store: &Store, key: &str, v: Value) {
    lock(store)
        .entry(FAULTS.into())
        .or_default()
        .insert(key.into(), v);
}

/// Every object of sandbox `id` left in the store (namespace-level objects
/// such as the default-deny policy are shared and not counted).
fn leftovers(store: &Store, id: &str) -> Vec<String> {
    lock(store)
        .iter()
        .filter(|(path, _)| path.as_str() != FAULTS)
        .flat_map(|(path, objs)| {
            objs.keys()
                .filter(|n| n.contains(id))
                .map(move |n| format!("{path}/{n}"))
        })
        .collect()
}

#[tokio::test]
async fn failed_create_leaves_no_objects_behind() {
    let id = "00112233445566778899aabbccddeeff";
    let spec = || {
        let broker =
            runeward_egress::Broker::with_secret_values(id, vec![], vec![], HashMap::new())
                .expect("broker");
        Spec {
            id: id.into(),
            network: deny_network("l3"),
            broker: Some(runeward_backend::BrokerHandle::new(Arc::new(broker))),
            ide_port: 8080,
            seed_dir: None,
            ..demo("leak")
        }
    };
    let cfg = || BackendConfig::from_pairs([(K8S_NETWORK_POLICY_ENV, "true")]);

    // Each object's create fails in turn, including a Pod the server kept
    // although the client saw an error.
    for (coll, persist) in [
        ("configmaps", false),
        ("secrets", false),
        ("pods", false),
        ("pods", true),
    ] {
        let store: Store = Arc::default();
        inject(&store, coll, json!({"persist": persist}));
        let k = K8s::with_client(fake_client(&store), cfg());
        k.create(spec()).await.expect_err(coll);
        assert_eq!(leftovers(&store, id), Vec::<String>::new(), "{coll}");
    }

    // The Pod never runs (a VM that cannot boot).
    let store: Store = Arc::default();
    inject(&store, "phase", json!("Failed"));
    let k = K8s::with_client(fake_client(&store), cfg());
    let err = k.create(spec()).await.expect_err("pod failed");
    assert!(err.to_string().contains("Failed"), "{err}");
    assert_eq!(leftovers(&store, id), Vec::<String>::new());

    // Seeding fails after the IDE NetworkPolicy exists (the fake API server
    // has no exec endpoint).
    let store: Store = Arc::default();
    let seed = tempfile::tempdir().expect("seed");
    std::fs::write(seed.path().join("a.txt"), "a").expect("write");
    let k = K8s::with_client(fake_client(&store), cfg());
    k.create(Spec {
        seed_dir: Some(seed.path().to_path_buf()),
        ..spec()
    })
    .await
    .expect_err("seed fails");
    assert_eq!(leftovers(&store, id), Vec::<String>::new());

    // A rebuild around a kept workspace keeps the PVC.
    let store: Store = Arc::default();
    let k = K8s::with_client(fake_client(&store), cfg());
    let sb = k.create(spec()).await.expect("create");
    k.stop(&sb.id).await.expect("stop");
    inject(&store, "pods", json!({"persist": false}));
    let k = K8s::with_client(fake_client(&store), cfg());
    k.start(id, spec()).await.expect_err("rebuild fails");
    let left = leftovers(&store, id);
    assert_eq!(left.len(), 1, "{left:?}");
    assert!(left[0].contains("/persistentvolumeclaims/"), "{left:?}");
}
