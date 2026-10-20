//! Opt-in end-to-end checks that a sandbox's isolation tier comes from
//! in-sandbox evidence.
//!
//! - `RUNEWARD_TEST_DOCKER=1`: the engine's default runtime (runc/crun)
//!   must be reported as `container`, with the guest kernel equal to the
//!   engine's.
//! - `RUNEWARD_TEST_VM_RUNTIME=<runtime>` (for example
//!   `io.containerd.kata-qemu.v2`, `io.containerd.kata-clh.v2` or `krun`
//!   on Docker, `kata-qemu` as a Kubernetes RuntimeClass): creates a
//!   sandbox under that runtime and asserts the evidence proves `vm`. Needs
//!   a Linux host with `/dev/kvm` and the runtime available to the engine.
//!   `RUNEWARD_TEST_VM_HYPERVISOR=qemu|cloud-hypervisor|firecracker`
//!   additionally asserts the hypervisor process found on the host (Docker
//!   or Podman on the same machine only).
//!   `RUNEWARD_TEST_VM_ENGINE` picks `docker` (default), `podman` or `k8s`
//!   (a RuntimeClass of that name); `RUNEWARD_TEST_VM_IMAGE` overrides the
//!   `alpine` image.
#![cfg(unix)]

use std::sync::Arc;

use runeward_backend::{
    Backend, BackendConfig, Docker, IsolationTier, K8s, Spec, container_name,
    egress_container_name, volume_name,
};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_owned()
}

/// Force-removes the container, egress sidecar and workspace volume of
/// one sandbox through the engine CLI on drop, so a failed create or a
/// failed assertion leaves nothing behind (Docker and Podman only; the
/// Kubernetes backend rolls back its own objects).
struct Cleanup {
    cli: Option<&'static str>,
    id: String,
}

impl Cleanup {
    fn new(cli: Option<&'static str>) -> Self {
        Self {
            cli,
            id: hex::encode(rand::random::<[u8; 16]>()),
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let Some(cli) = self.cli else {
            return;
        };
        let id = &self.id;
        let (ctr, sidecar, vol) = (
            container_name(id),
            egress_container_name(id),
            volume_name(id),
        );
        for args in [
            ["rm", "-f", "-v", ctr.as_str()],
            ["rm", "-f", "-v", sidecar.as_str()],
            ["volume", "rm", "-f", vol.as_str()],
        ] {
            let _ = std::process::Command::new(cli).args(args).output();
        }
    }
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
    let guard = Cleanup::new(Some("docker"));
    let sb = d
        .create(Spec {
            id: guard.id.clone(),
            ..spec("")
        })
        .await
        .expect("create");
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
    let (be, guard): (Arc<dyn Backend>, Cleanup) = match engine.as_str() {
        "" | "docker" => (
            Arc::new(Docker::docker(cfg).await.expect("docker backend")),
            Cleanup::new(Some("docker")),
        ),
        "podman" => (
            Arc::new(Docker::podman(cfg).await.expect("podman backend")),
            Cleanup::new(Some("podman")),
        ),
        "k8s" => (
            Arc::new(K8s::new(cfg).await.expect("k8s backend")),
            Cleanup::new(None),
        ),
        other => panic!("unknown RUNEWARD_TEST_VM_ENGINE {other:?}"),
    };
    let sb = be
        .create(Spec {
            id: guard.id.clone(),
            ..spec(&runtime)
        })
        .await
        .expect("create");
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
    assert!(!ev.hypervisor.is_empty(), "{ev:?}");
    let want = env("RUNEWARD_TEST_VM_HYPERVISOR");
    if !want.is_empty() {
        assert_eq!(ev.hypervisor, want, "{ev:?}");
    }
}
