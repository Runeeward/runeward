use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A Linux KVM host with a reachable Docker engine.
fn linux_kvm() -> HostFacts {
    HostFacts {
        os: "linux".into(),
        arch: "x86_64".into(),
        root: true,
        kvm: KvmAccess::Usable,
        engine_reachable: true,
        engine_os: "Ubuntu 24.04.1 LTS".into(),
        registered: vec!["runc".into()],
        ..HostFacts::default()
    }
}

fn status_of(p: &Plan, name: &str) -> Option<CheckStatus> {
    p.checks.iter().find(|c| c.name == name).map(|c| c.status)
}

fn daemon_content(p: &Plan) -> serde_json::Value {
    let content = p
        .steps
        .iter()
        .find_map(|s| match s {
            Step::WriteDaemonJson { content, .. } => Some(content.clone()),
            _ => None,
        })
        .expect("daemon.json step");
    serde_json::from_str(&content).expect("valid json")
}

#[test]
fn parses_runtimes_and_engines() {
    for r in VmRuntime::ALL {
        assert_eq!(VmRuntime::parse(r.as_str()), Ok(r));
    }
    assert_eq!(VmRuntime::parse("Firecracker"), Ok(VmRuntime::KataFc));
    assert!(VmRuntime::parse("youki").is_err());
    assert_eq!(Engine::parse("kubernetes"), Ok(Engine::K8s));
    assert!(Engine::parse("lxc").is_err());
    assert!(!VmRuntime::Gvisor.needs_kvm());
    assert!(VmRuntime::Kata.needs_kvm());
    assert!(VmRuntime::KataFc.needs_kvm());
    assert_eq!(kata_runtime_type(""), "io.containerd.kata.v2");
    assert_eq!(kata_shim_name("qemu"), "containerd-shim-kata-qemu-v2");
    assert!(VmRuntime::Krun.needs_kvm());
}

#[test]
fn gvisor_docker_plan_matches_go() {
    let mut facts = linux_kvm();
    facts.daemon_json =
        Some(r#"{"log-driver": "journald", "runtimes": {"custom": {"path": "/x"}}}"#.into());
    let p = plan(&Request::new(VmRuntime::Gvisor, Engine::Docker), &facts);
    assert!(!p.blocked(), "{:?}", p.checks);
    assert_eq!(p.runtime_class, "runsc");
    let base = "https://storage.googleapis.com/gvisor/releases/release/latest/x86_64";
    assert_eq!(
        p.steps[..4],
        [
            Step::Download {
                url: format!("{base}/runsc"),
                name: "runsc".into(),
                verify: Verify::Sha512Sidecar(format!("{base}/runsc.sha512")),
            },
            Step::Download {
                url: format!("{base}/containerd-shim-runsc-v1"),
                name: "containerd-shim-runsc-v1".into(),
                verify: Verify::Sha512Sidecar(format!("{base}/containerd-shim-runsc-v1.sha512")),
            },
            Step::Install {
                name: "runsc".into(),
                dest: "/usr/local/bin/runsc".into(),
            },
            Step::Install {
                name: "containerd-shim-runsc-v1".into(),
                dest: "/usr/local/bin/containerd-shim-runsc-v1".into(),
            },
        ]
    );
    let d = daemon_content(&p);
    assert_eq!(d["log-driver"], "journald");
    assert_eq!(d["runtimes"]["custom"]["path"], "/x");
    assert_eq!(d["runtimes"]["runsc"]["path"], "/usr/local/bin/runsc");
    assert_eq!(status_of(&p, "kvm"), Some(CheckStatus::Ok));
    let text = p.render();
    assert!(text.contains("Dry-run (default): nothing above was executed."));
    assert!(text.contains("runtime_class = \"runsc\""));
}

#[test]
fn gvisor_sha256_pin_and_arch() {
    let mut req = Request::new(VmRuntime::Gvisor, Engine::Docker);
    req.sha256 = "ABCDEF0123".into();
    req.version = "20240101".into();
    let mut facts = linux_kvm();
    facts.arch = "aarch64".into();
    let p = plan(&req, &facts);
    match &p.steps[0] {
        Step::Download { url, verify, .. } => {
            assert!(url.ends_with("/20240101/arm64/runsc"), "{url}");
            assert_eq!(verify, &Verify::Sha256("abcdef0123".into()));
        }
        s => panic!("{s:?}"),
    }
    // The shim is always sidecar-verified, as in Go.
    assert!(matches!(
        &p.steps[1],
        Step::Download {
            verify: Verify::Sha512Sidecar(_),
            ..
        }
    ));
    facts.arch = "riscv64".into();
    let p = plan(&req, &facts);
    assert_eq!(status_of(&p, "arch"), Some(CheckStatus::Fail));
    assert!(p.blocked());
}

#[test]
fn gvisor_on_desktop_engine_warns_but_vm_runtimes_fail() {
    let mut facts = linux_kvm();
    facts.engine_os = "OrbStack".into();
    let p = plan(&Request::new(VmRuntime::Gvisor, Engine::Docker), &facts);
    assert_eq!(status_of(&p, "engine"), Some(CheckStatus::Warn));
    for rt in [VmRuntime::Kata, VmRuntime::Krun] {
        let p = plan(&Request::new(rt, Engine::Docker), &facts);
        assert_eq!(status_of(&p, "engine"), Some(CheckStatus::Fail), "{rt:?}");
        assert!(p.blocked());
        assert!(p.render().contains("nested VM runtimes are unavailable"));
    }
    let mut mac = linux_kvm();
    mac.os = "macos".into();
    mac.engine_os = "Docker Desktop".into();
    let p = plan(&Request::new(VmRuntime::Kata, Engine::Docker), &mac);
    assert_eq!(status_of(&p, "os"), Some(CheckStatus::Fail));
}

#[test]
fn kvm_checks() {
    let mut facts = linux_kvm();
    facts.binaries.insert(
        "containerd-shim-kata-v2".into(),
        "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2".into(),
    );
    let req = Request::new(VmRuntime::Kata, Engine::Docker);
    assert!(!plan(&req, &facts).blocked());

    facts.kvm = KvmAccess::Missing;
    let p = plan(&req, &facts);
    assert_eq!(status_of(&p, "kvm"), Some(CheckStatus::Fail));
    assert!(p.checks.iter().any(|c| c.detail.contains("firmware")));

    facts.virtualised = true;
    let p = plan(&req, &facts);
    assert!(
        p.checks
            .iter()
            .any(|c| c.name == "kvm" && c.detail.contains("nested virtualisation"))
    );

    facts.kvm = KvmAccess::NoPermission;
    facts.nested = Some(true);
    let p = plan(&req, &facts);
    assert_eq!(status_of(&p, "kvm"), Some(CheckStatus::Warn));
    assert_eq!(status_of(&p, "nested"), Some(CheckStatus::Ok));
    assert!(!p.blocked());

    facts.nested = Some(false);
    assert_eq!(
        status_of(&plan(&req, &facts), "nested"),
        Some(CheckStatus::Warn)
    );
}

#[test]
fn kata_docker_uses_runtime_types_without_daemon_json() {
    let mut facts = linux_kvm();
    // Not installed: guidance only, apply refused.
    let p = plan(&Request::new(VmRuntime::Kata, Engine::Docker), &facts);
    assert_eq!(status_of(&p, "kata"), Some(CheckStatus::Fail));
    assert!(matches!(p.steps[0], Step::Manual { .. }));

    // Kata 4 static install (runtime-rs shim): link the shim onto dockerd's
    // PATH and use the containerd runtime type; daemon.json is untouched.
    let shim = PathBuf::from("/opt/kata/runtime-rs/bin/containerd-shim-kata-v2");
    facts
        .binaries
        .insert("containerd-shim-kata-v2".into(), shim.clone());
    let p = plan(&Request::new(VmRuntime::Kata, Engine::Docker), &facts);
    assert!(!p.blocked(), "{:?}", p.checks);
    assert_eq!(p.runtime_class, "io.containerd.kata.v2");
    assert!(p.steps.contains(&Step::Link {
        target: shim.clone(),
        link: "/usr/local/bin/containerd-shim-kata-v2".into(),
    }));
    assert!(
        !p.steps
            .iter()
            .any(|s| matches!(s, Step::WriteDaemonJson { .. }))
    );
    assert_eq!(status_of(&p, "hypervisor-config"), Some(CheckStatus::Warn));

    // A named hypervisor: io.containerd.kata-clh.v2 and its shim name, plus
    // the configuration.toml step (runtime-rs ignores the shim name).
    let mut req = Request::new(VmRuntime::Kata, Engine::Docker);
    req.hypervisor = "clh".into();
    let p = plan(&req, &facts);
    assert_eq!(p.runtime_class, "io.containerd.kata-clh.v2");
    assert!(p.steps.contains(&Step::Link {
        target: shim.clone(),
        link: "/usr/local/bin/containerd-shim-kata-clh-v2".into(),
    }));
    assert!(p.render().contains("runtime-rs/configuration.toml"));
    req.hypervisor = "dragonfly".into();
    assert_eq!(
        status_of(&plan(&req, &facts), "hypervisor"),
        Some(CheckStatus::Fail)
    );

    // Legacy kata-runtime only: registered by path, as the Go installer did.
    let mut legacy = linux_kvm();
    legacy
        .binaries
        .insert("kata-runtime".into(), "/usr/bin/kata-runtime".into());
    let p = plan(&Request::new(VmRuntime::Kata, Engine::Docker), &legacy);
    assert_eq!(
        daemon_content(&p)["runtimes"]["kata"]["path"],
        "/usr/bin/kata-runtime"
    );
}

#[test]
fn kata_fc_is_refused_on_docker_and_podman() {
    let mut facts = linux_kvm();
    facts.binaries.insert(
        "containerd-shim-kata-v2".into(),
        "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2".into(),
    );
    for engine in [Engine::Docker, Engine::Podman] {
        let p = plan(&Request::new(VmRuntime::KataFc, engine), &facts);
        assert!(p.blocked());
        let text = p.render();
        assert!(text.contains("devmapper snapshotter"), "{text}");
        assert!(text.contains("native Firecracker driver"), "{text}");
    }
    let p = plan(&Request::new(VmRuntime::KataFc, Engine::K8s), &facts);
    assert!(!p.blocked());
    assert_eq!(status_of(&p, "kata-fc-config"), Some(CheckStatus::Warn));
    assert!(p.render().contains("reconnect_timeout_ms = 45000"));
}

#[tokio::test]
async fn apply_links_the_kata_shim() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("opt/containerd-shim-kata-v2");
    std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
    std::fs::write(&target, b"shim").expect("write");
    let mut facts = linux_kvm();
    facts
        .binaries
        .insert("containerd-shim-kata-v2".into(), target.clone());
    let mut req = Request::new(VmRuntime::Kata, Engine::Docker);
    req.hypervisor = "qemu".into();
    req.bin_dir = root.path().join("bin");
    let link = root.path().join("bin/containerd-shim-kata-qemu-v2");
    std::fs::create_dir_all(root.path().join("bin")).expect("mkdir");
    std::fs::write(&link, b"stale").expect("stale");
    apply(&plan(&req, &facts)).await.expect("apply");
    assert_eq!(std::fs::read_link(&link).expect("link"), target);
}

#[test]
fn krun_plans_are_refused() {
    let mut facts = linux_kvm();
    facts.binaries.insert("krun".into(), "/usr/bin/krun".into());
    for engine in [Engine::Docker, Engine::Podman, Engine::K8s] {
        let p = plan(&Request::new(VmRuntime::Krun, engine), &facts);
        assert_eq!(status_of(&p, "exec"), Some(CheckStatus::Fail), "{engine:?}");
        assert!(p.blocked(), "{engine:?}");
        assert!(p.render().contains("does not support exec"), "{engine:?}");
        assert!(
            !p.steps.iter().any(|s| matches!(
                s,
                Step::WriteDaemonJson { .. } | Step::ApplyRuntimeClass { .. }
            )),
            "{engine:?}: {:?}",
            p.steps
        );
    }
}

#[test]
fn k8s_runtime_classes() {
    let mut facts = linux_kvm();
    facts
        .binaries
        .insert("kubectl".into(), "/usr/bin/kubectl".into());
    let p = plan(&Request::new(VmRuntime::Gvisor, Engine::K8s), &facts);
    assert_eq!(p.runtime_class, "gvisor");
    // The Go installer's exact manifest.
    assert_eq!(
        p.steps.last(),
        Some(&Step::ApplyRuntimeClass {
            manifest: "apiVersion: node.k8s.io/v1\nkind: RuntimeClass\nmetadata:\n  name: gvisor\nhandler: runsc\n".into()
        })
    );
    assert!(p.checks.iter().all(|c| c.status != CheckStatus::Fail));

    let mut req = Request::new(VmRuntime::Kata, Engine::K8s);
    req.runtime_class = "sandboxed".into();
    let p = plan(&req, &facts);
    assert_eq!(p.runtime_class, "sandboxed");
    assert_eq!(
        p.steps.last(),
        Some(&Step::ApplyRuntimeClass {
            manifest: runtime_class_manifest("sandboxed", "kata")
        })
    );
    assert_eq!(status_of(&p, "nodes"), Some(CheckStatus::Warn));

    let p = plan(&Request::new(VmRuntime::KataFc, Engine::K8s), &facts);
    let Some(Step::ApplyRuntimeClass { manifest }) = p.steps.last() else {
        panic!("{:?}", p.steps);
    };
    let v: serde_json::Value = serde_json::from_str(manifest).expect("json manifest");
    assert_eq!(v["apiVersion"], "node.k8s.io/v1");
    assert_eq!(v["kind"], "RuntimeClass");
    assert_eq!(v["metadata"]["name"], "kata-fc");
    assert_eq!(v["handler"], "kata-fc");
    assert_eq!(v["overhead"]["podFixed"]["memory"], "130Mi");
    assert_eq!(
        v["scheduling"]["nodeSelector"]["katacontainers.io/kata-runtime"],
        "true"
    );

    let rc = runtime_class_object(VmRuntime::Krun, "krun");
    assert_eq!(rc.handler, "krun");
    assert!(rc.overhead.is_none());

    facts.binaries.clear();
    let p = plan(&Request::new(VmRuntime::Kata, Engine::K8s), &facts);
    assert_eq!(status_of(&p, "kubectl"), Some(CheckStatus::Warn));
}

#[test]
fn daemon_json_merge() {
    let entry = serde_json::json!({"path": "/usr/local/bin/runsc"});
    let fresh = merge_docker_runtime(None, "runsc", entry.clone()).expect("fresh");
    assert_eq!(
        fresh,
        "{\n  \"runtimes\": {\n    \"runsc\": {\n      \"path\": \"/usr/local/bin/runsc\"\n    }\n  }\n}"
    );
    assert_eq!(
        merge_docker_runtime(Some("  "), "runsc", entry.clone()).expect("blank"),
        fresh
    );
    let replaced = merge_docker_runtime(
        Some(
            r#"{"runtimes": {"runsc": {"path": "/old"}, "other": {"path": "/o"}}, "debug": true}"#,
        ),
        "runsc",
        entry.clone(),
    )
    .expect("merge");
    let v: serde_json::Value = serde_json::from_str(&replaced).expect("json");
    assert_eq!(v["runtimes"]["runsc"]["path"], "/usr/local/bin/runsc");
    assert_eq!(v["runtimes"]["other"]["path"], "/o");
    assert_eq!(v["debug"], true);
    assert!(merge_docker_runtime(Some("{nope"), "runsc", entry.clone()).is_err());
    assert!(merge_docker_runtime(Some("[]"), "runsc", entry.clone()).is_err());
    assert!(merge_docker_runtime(Some(r#"{"runtimes": 3}"#), "runsc", entry).is_err());

    // A broken daemon.json blocks the plan instead of being clobbered.
    let mut facts = linux_kvm();
    facts.daemon_json = Some("{nope".into());
    let p = plan(&Request::new(VmRuntime::Gvisor, Engine::Docker), &facts);
    assert_eq!(status_of(&p, "daemon.json"), Some(CheckStatus::Fail));
}

#[test]
fn checksum_helpers() {
    assert_eq!(
        parse_checksum_sidecar("deadbeef  runsc\n").expect("parse"),
        "deadbeef"
    );
    assert!(parse_checksum_sidecar(" \n").is_err());
    let dir = tempfile::tempdir().expect("tempdir");
    let f = dir.path().join("bin");
    std::fs::write(&f, b"hello").expect("write");
    let sha256 = hex::encode(Sha256::digest(b"hello"));
    assert!(verify_digest::<Sha256>(&f, &sha256.to_uppercase()).is_ok());
    let err = verify_digest::<Sha256>(&f, "00").expect_err("mismatch");
    assert!(err.contains("failing closed"), "{err}");
}

/// Serves fixed bodies by path over HTTP/1.1 (404 for anything else).
async fn serve(files: HashMap<String, Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let files = Arc::new(files);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let files = Arc::clone(&files);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (status, body) = match files.get(&path) {
                    Some(b) => ("200 OK", b.clone()),
                    None => ("404 Not Found", b"missing".to_vec()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn apply_downloads_verifies_installs_and_merges() {
    let runsc = b"#!/bin/sh\necho runsc\n".to_vec();
    let shim = b"#!/bin/sh\necho shim\n".to_vec();
    let sha512 = |b: &[u8]| format!("{}  file\n", hex::encode(Sha512::digest(b)));
    let base = serve(HashMap::from([
        ("/latest/x86_64/runsc".to_owned(), runsc.clone()),
        (
            "/latest/x86_64/runsc.sha512".to_owned(),
            sha512(&runsc).into_bytes(),
        ),
        (
            "/latest/x86_64/containerd-shim-runsc-v1".to_owned(),
            shim.clone(),
        ),
        (
            "/latest/x86_64/containerd-shim-runsc-v1.sha512".to_owned(),
            sha512(&shim).into_bytes(),
        ),
    ]))
    .await;
    let root = tempfile::tempdir().expect("tempdir");
    let mut req = Request::new(VmRuntime::Gvisor, Engine::Docker);
    req.release_base = base.clone();
    req.bin_dir = root.path().join("bin");
    req.daemon_json = root.path().join("etc/docker/daemon.json");
    let mut facts = linux_kvm();
    facts.daemon_json = Some(r#"{"debug": true}"#.into());
    let p = plan(&req, &facts);
    let log = apply(&p).await.expect("apply");
    assert!(
        log.iter().any(|l| l.starts_with("verified runsc (sha512 ")),
        "{log:?}"
    );
    let installed = root.path().join("bin/runsc");
    assert_eq!(std::fs::read(&installed).expect("installed"), runsc);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&installed)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755);
    }
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&req.daemon_json).expect("daemon.json"))
            .expect("json");
    assert_eq!(written["debug"], true);
    assert_eq!(
        written["runtimes"]["runsc"]["path"],
        root.path().join("bin/runsc").to_string_lossy().as_ref()
    );

    // A wrong pin fails closed and installs nothing.
    let other = tempfile::tempdir().expect("tempdir");
    req.bin_dir = other.path().join("bin");
    req.sha256 = "00".repeat(32);
    let err = apply(&plan(&req, &facts)).await.expect_err("mismatch");
    assert!(err.to_string().contains("checksum mismatch"), "{err}");
    assert!(!other.path().join("bin/runsc").exists());

    // A missing sidecar is refused.
    req.sha256.clear();
    req.release_base = format!("{base}/nowhere");
    let err = apply(&plan(&req, &facts)).await.expect_err("404");
    assert!(err.to_string().contains("download"), "{err}");
}

#[tokio::test]
async fn apply_without_root_prints_sudo_commands() {
    let mut facts = linux_kvm();
    facts.root = false;
    // A legacy kata-runtime is registered in daemon.json.
    facts
        .binaries
        .insert("kata-runtime".into(), "/usr/bin/kata-runtime".into());
    let p = plan(&Request::new(VmRuntime::Kata, Engine::Docker), &facts);
    let log = apply(&p).await.expect("apply");
    assert!(
        log.iter()
            .any(|l| l.starts_with("sudo tee /etc/docker/daemon.json")),
        "{log:?}"
    );
    assert!(log.iter().any(|l| l == "sudo systemctl restart docker"));
}

#[tokio::test]
async fn apply_refuses_blocked_plans() {
    let mut facts = linux_kvm();
    facts.kvm = KvmAccess::Missing;
    let p = plan(&Request::new(VmRuntime::KataFc, Engine::Docker), &facts);
    let err = apply(&p).await.expect_err("blocked");
    assert!(err.to_string().starts_with("refusing to apply"), "{err}");
}
