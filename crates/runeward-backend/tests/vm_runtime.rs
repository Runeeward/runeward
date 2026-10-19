//! Opt-in end-to-end checks that a sandbox's isolation tier comes from
//! in-sandbox evidence.
//!
//! - `RUNEWARD_TEST_DOCKER=1`: the engine's default runtime (runc/crun)
//!   must be reported as `container`, with the guest kernel equal to the
//!   engine's.
//! - `RUNEWARD_TEST_VM_RUNTIME=<runtime>` (for example `krun`, `kata-fc`,
//!   `kata-qemu`): creates a sandbox under that runtime and asserts the
//!   evidence proves `vm`. Needs a Linux host with `/dev/kvm` and the
//!   runtime registered with the engine (`runeward runtime install`).
//!   `RUNEWARD_TEST_VM_ENGINE` picks `docker` (default), `podman` or `k8s`
//!   (a RuntimeClass of that name); `RUNEWARD_TEST_VM_IMAGE` overrides the
//!   `alpine` image.
#![cfg(unix)]

use std::sync::Arc;

use runeward_backend::{Backend, BackendConfig, Docker, IsolationTier, K8s, Spec};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_owned()
}

fn spec(runtime_class: &str) -> Spec {
    let image = env("RUNEWARD_TEST_VM_IMAGE");
    Spec {
        profile: "vm-it".into(),
        image: if image.is_empty() {
            "alpine".into()
        } else {
            image
        },
        runtime_class: runtime_class.into(),
        ..Spec::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn default_runtime_reports_shared_kernel() {
    if env("RUNEWARD_TEST_DOCKER") != "1" {
        eprintln!("skipping: set RUNEWARD_TEST_DOCKER=1 to run");
        return;
    }
    let d = Docker::docker(BackendConfig::default())
        .await
        .expect("docker backend");
    let sb = d.create(spec("")).await.expect("create");
    let result = (sb.isolation, sb.isolation_evidence.clone());
    d.kill(&sb.id).await.expect("kill");
    let (tier, ev) = result;
    let ev = ev.expect("evidence");
    eprintln!("evidence: {ev:?}");
    assert_eq!(tier, IsolationTier::Container, "{ev:?}");
    assert!(ev.signals.contains(&"kernel:shared".to_owned()), "{ev:?}");
    assert_eq!(ev.guest_kernel, ev.host_kernel);
}

#[tokio::test(flavor = "multi_thread")]
async fn vm_runtime_is_vm_from_evidence() {
    let runtime = env("RUNEWARD_TEST_VM_RUNTIME");
    if runtime.is_empty() {
        eprintln!("skipping: set RUNEWARD_TEST_VM_RUNTIME=<runtime> on a KVM host to run");
        return;
    }
    let engine = env("RUNEWARD_TEST_VM_ENGINE");
    let cfg = BackendConfig::from_env();
    let be: Arc<dyn Backend> = match engine.as_str() {
        "" | "docker" => Arc::new(Docker::docker(cfg).await.expect("docker backend")),
        "podman" => Arc::new(Docker::podman(cfg).await.expect("podman backend")),
        "k8s" => Arc::new(K8s::new(cfg).await.expect("k8s backend")),
        other => panic!("unknown RUNEWARD_TEST_VM_ENGINE {other:?}"),
    };
    let sb = be.create(spec(&runtime)).await.expect("create");
    let result = (sb.isolation, sb.isolation_evidence.clone());
    be.kill(&sb.id).await.expect("kill");
    let (tier, ev) = result;
    let ev = ev.expect("evidence");
    eprintln!("evidence: {ev:?}");
    assert_eq!(tier, IsolationTier::Vm, "{ev:?}");
    assert!(!ev.guest_kernel.is_empty() && !ev.host_kernel.is_empty());
    assert_ne!(ev.guest_kernel, ev.host_kernel);
    assert!(
        ev.signals.iter().any(|s| s.starts_with("hypervisor:")),
        "{ev:?}"
    );
}
