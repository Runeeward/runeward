//! The backend against a fake monitor: the real guest agent's request
//! handling runs in-process on the test host (no VM, no KVM), so exec,
//! files, workspace streams, egress and sleep/wake are exercised end to end
//! through the same protocol a guest speaks.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use runeward_charter::{File, Network, NetworkRule};
use runeward_vmagent::proto::InitRequest;
use runeward_vmagent::server::{Agent, HelperMode, Platform, Reaper, forward_egress};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use super::rootfs::{Image, ImageConfig};
use super::vmm::{LaunchPlan, Vmm};
use super::*;

/// A "guest" whose probe output is canned (or the test host's own).
#[derive(Debug)]
struct FakeGuest {
    probe: Option<String>,
}

impl Platform for FakeGuest {
    fn init(&self, req: &InitRequest) -> std::result::Result<(), String> {
        std::fs::create_dir_all(&req.workdir).map_err(|e| e.to_string())
    }

    fn probe(&self) -> String {
        self.probe
            .clone()
            .unwrap_or_else(|| runeward_vmagent::probe::collect(Path::new("/")))
    }
}

/// Firecracker as seen from the guest (the virtio-mmio command line and the
/// hypervisor CPU flag), with a kernel that is not the host's.
const GUEST_PROBE: &str = "
@@osrelease
6.1.155
@@version
Linux version 6.1.155 (runeward-test)
@@cpuflags
flags\t\t: fpu vme de pse hypervisor
@@dmi
@@hypervisor
@@devicetree
@@cmdline
console=ttyS0 reboot=k panic=1 pci=off virtio_mmio.device=4K@0xd0000000:5
@@mounts
/dev/vdb /workspace ext4 rw,relatime 0 0
@@dmesg
";

/// A monitor that starts `sleep` as its "VMM" and serves the agent
/// in-process on the VM directory's socket.
#[derive(Debug)]
struct FakeVmm {
    probe: Option<String>,
    /// Makes the "VMM" exit at once, like a VM that fails to boot.
    crash: bool,
}

#[async_trait]
impl Vmm for FakeVmm {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    async fn launch(&self, plan: &LaunchPlan) -> Result<Child> {
        std::fs::write(plan.log_path(), "fake vmm booting\n").expect("log");
        if self.crash {
            return Command::new("/bin/sh")
                .args(["-c", "echo 'kvm: no such device' >&2; exit 1"])
                .stderr(std::process::Stdio::from(
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(plan.log_path())
                        .expect("log"),
                ))
                .spawn()
                .map_err(|e| BackendError::io("spawn", e));
        }
        let sock = plan.dir.join("agent.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = UnixListener::bind(&sock).map_err(|e| BackendError::io("bind", e))?;
        let agent = Agent::new(
            HelperMode::InProcess,
            Box::new(FakeGuest {
                probe: self.probe.clone(),
            }),
            Reaper::per_child(),
        );
        std::thread::spawn(move || {
            for conn in listener.incoming().flatten() {
                let a = Arc::clone(&agent);
                std::thread::spawn(move || a.serve(conn));
            }
        });
        let fwd = std::net::TcpListener::bind("127.0.0.1:0").expect("forwarder");
        let port = fwd.local_addr().expect("addr").port();
        std::fs::write(plan.dir.join("egress.port"), port.to_string()).expect("port");
        let up = self.egress_socket(&plan.dir);
        std::thread::spawn(move || {
            forward_egress(fwd, move || std::os::unix::net::UnixStream::connect(&up))
        });
        Command::new("sleep")
            .arg("3600")
            .process_group(0)
            .spawn()
            .map_err(|e| BackendError::io("spawn", e))
    }

    async fn connect(&self, dir: &Path) -> io::Result<UnixStream> {
        UnixStream::connect(dir.join("agent.sock")).await
    }

    fn egress_socket(&self, dir: &Path) -> PathBuf {
        dir.join("egress.sock")
    }
}

#[derive(Debug)]
struct FakeImages(PathBuf);

#[async_trait]
impl Images for FakeImages {
    async fn ensure(&self, reference: &str) -> Result<Image> {
        if reference.contains("missing") {
            return Err(BackendError::msg(format!(
                "pull image {reference}: not found"
            )));
        }
        Ok(Image {
            reference: reference.to_owned(),
            digest: format!("sha256:{}", "ab".repeat(32)),
            rootfs: self.0.clone(),
            config: ImageConfig {
                env: vec!["IMAGE_VAR=from-image".into(), "PATH=/usr/bin:/bin".into()],
                user: String::new(),
                working_dir: String::new(),
            },
        })
    }
}

#[derive(Debug)]
struct FakeDisks;

#[async_trait]
impl Disks for FakeDisks {
    async fn make_workspace(&self, path: &Path, size: u64) -> Result<()> {
        let f = std::fs::File::create(path).map_err(|e| BackendError::io("disk", e))?;
        f.set_len(size).map_err(|e| BackendError::io("disk", e))
    }
}

struct Harness {
    be: MicroVm,
    _root: tempfile::TempDir,
    work: tempfile::TempDir,
}

fn harness_with(vmm: FakeVmm) -> Harness {
    // Short paths: Unix socket names are limited.
    let root = tempfile::Builder::new()
        .prefix("rwmv")
        .tempdir_in("/tmp")
        .expect("root");
    let work = tempfile::tempdir().expect("work");
    let rootfs = root.path().join("image.ext4");
    std::fs::write(&rootfs, b"").expect("rootfs");
    let mut vmms: BTreeMap<&'static str, Arc<dyn Vmm>> = BTreeMap::new();
    vmms.insert("firecracker", Arc::new(vmm));
    let mut be = MicroVm::with_parts(
        BackendConfig::default(),
        root.path().to_path_buf(),
        Arc::new(FakeImages(rootfs)),
        Arc::new(FakeDisks),
        vmms,
        "firecracker",
    );
    be.stop_grace = Duration::from_millis(200);
    Harness {
        be,
        _root: root,
        work,
    }
}

fn harness() -> Harness {
    harness_with(FakeVmm {
        probe: Some(GUEST_PROBE.into()),
        crash: false,
    })
}

impl Harness {
    fn spec(&self) -> Spec {
        Spec {
            profile: "demo".into(),
            image: "example.test/demo:1".into(),
            workdir: self.work.path().to_string_lossy().into_owned(),
            env: BTreeMap::from([("CHARTER_VAR".into(), "set".into())]),
            command: vec!["sleep".into(), "2".into()],
            ..Spec::default()
        }
    }
}

/// Reports whether a process exists (and is not a zombie we still hold).
fn alive(pid: u32) -> bool {
    pid != 0
        && std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

async fn sh(be: &MicroVm, id: &str, script: &str) -> ExecResult {
    be.exec(id, ExecRequest::new(["/bin/sh", "-c", script]))
        .await
        .expect("exec")
}

#[tokio::test]
async fn lifecycle_exec_files_sleep_wake_and_kill() {
    let h = harness();
    let sb = h.be.create(h.spec()).await.expect("create");
    assert_eq!(sb.backend, "microvm");
    assert_eq!(sb.id.len(), 32);
    assert!(h.be.exists(&sb.id).await);

    let r = sh(
        &h.be,
        &sb.id,
        "echo $IMAGE_VAR $CHARTER_VAR $HTTPS_PROXY; echo oops >&2; exit 5",
    )
    .await;
    assert_eq!(r.exit_code, 5);
    assert_eq!(
        r.stdout.trim(),
        "from-image set http://127.0.0.1:3128",
        "image env, charter env and the in-guest proxy"
    );
    assert_eq!(r.stderr, "oops\n");

    h.be.copy_files(
        &sb.id,
        &[File {
            path: "notes/hello.txt".into(),
            mode: "0600".into(),
            content: "hello".into(),
            ..File::default()
        }],
    )
    .await
    .expect("copy");
    let written = h.work.path().join("notes/hello.txt");
    assert_eq!(std::fs::read_to_string(&written).expect("read"), "hello");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&written)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let mut tar = Vec::new();
    h.be.export_workspace(&sb.id, &mut tar)
        .await
        .expect("export");
    let names: Vec<String> = ::tar::Archive::new(tar.as_slice())
        .entries()
        .expect("entries")
        .map(|e| {
            e.expect("entry")
                .path()
                .expect("path")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("notes/hello.txt")),
        "{names:?}"
    );

    // Sleep: the VMM goes away, the workspace and identity stay.
    let vmm_pid = h.be.read_state(&sb.id).expect("state").pid;
    assert!(alive(vmm_pid), "the VMM runs");
    h.be.stop(&sb.id).await.expect("stop");
    assert!(!alive(vmm_pid), "stop powered the VMM off");
    let listed = h.be.list().await.expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].status, "stopped");
    let woke = h.be.start(&sb.id, h.spec()).await.expect("start");
    assert_eq!(woke.id, sb.id);
    assert_eq!(woke.isolation, IsolationTier::Vm);
    let r = sh(&h.be, &sb.id, "cat notes/hello.txt").await;
    assert_eq!(r.stdout, "hello", "the workspace survived sleep/wake");
    assert_eq!(h.be.list().await.expect("list")[0].status, "running");

    let snap = h.be.snapshot(&sb.id, "s1").await.expect("snapshot");
    assert!(Path::new(&snap.location).is_file());

    let vmm_pid = h.be.read_state(&sb.id).expect("state").pid;
    h.be.kill(&sb.id).await.expect("kill");
    assert!(!alive(vmm_pid), "kill stopped the VMM");
    assert!(!h.be.exists(&sb.id).await);
    assert!(!h.be.vm_dir(&sb.id).exists(), "nothing left behind");
    assert!(h.be.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn evidence_is_vm_only_with_guest_markers_and_a_running_monitor() {
    let h = harness();
    let sb = h.be.create(h.spec()).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Vm);
    let ev = sb.isolation_evidence.expect("evidence");
    assert_eq!(ev.runtime, "firecracker");
    assert_eq!(ev.guest_kernel, "6.1.155");
    assert_eq!(ev.hypervisor, "firecracker");
    for s in [
        "kernel:separate",
        "hypervisor:cmdline=virtio_mmio",
        "host:hypervisor=firecracker",
        "verdict:vm",
    ] {
        assert!(ev.signals.iter().any(|x| x == s), "{s} in {:?}", ev.signals);
    }
    h.be.kill(&sb.id).await.expect("kill");

    // The test host's own probe: the same kernel as the host (or none on a
    // non-Linux host) is never a VM, whatever the monitor is called.
    let h = harness_with(FakeVmm {
        probe: None,
        crash: false,
    });
    let sb = h.be.create(h.spec()).await.expect("create");
    assert_eq!(sb.isolation, IsolationTier::Container);
    let ev = sb.isolation_evidence.expect("evidence");
    assert!(
        ev.signals.iter().any(|s| s == "verdict:container"),
        "{:?}",
        ev.signals
    );
    assert!(ev.hypervisor.is_empty());
    h.be.kill(&sb.id).await.expect("kill");
}

#[tokio::test]
async fn egress_from_the_guest_goes_through_the_charter_policy() {
    let h = harness();
    let spec = Spec {
        network: Network {
            default: "deny".into(),
            rules: vec![NetworkRule {
                hostname: "allowed.example".into(),
                ..NetworkRule::default()
            }],
            enforce: "strict".into(),
        },
        ..h.spec()
    };
    let sb = h.be.create(spec).await.expect("create");
    let port: u16 = std::fs::read_to_string(h.be.vm_dir(&sb.id).join("egress.port"))
        .expect("port")
        .parse()
        .expect("port");
    // What a guest process does with HTTPS_PROXY: CONNECT through the
    // in-guest forwarder, which can only reach the host's policy.
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    s.write_all(b"CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n\r\n")
        .await
        .expect("write");
    let mut buf = vec![0u8; 128];
    let n = s.read(&mut buf).await.expect("read");
    let head = String::from_utf8_lossy(&buf[..n]);
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    let decisions = runeward_egress::list_decisions(&sb.id);
    assert!(
        decisions.iter().any(|d| d.host.contains("denied.example")),
        "{decisions:?}"
    );
    h.be.kill(&sb.id).await.expect("kill");
    assert!(
        !h.be.vm_dir(&sb.id).join("egress.sock").exists(),
        "egress socket removed"
    );
}

#[tokio::test]
async fn exec_timeouts_and_pty_attach() {
    let h = harness();
    let sb = h.be.create(h.spec()).await.expect("create");
    let mut req = ExecRequest::new(["sleep", "30"]);
    req.timeout = Some(Duration::from_millis(300));
    let started = Instant::now();
    let r = h.be.exec(&sb.id, req).await.expect("exec");
    assert_eq!(r.exit_code, -1);
    assert!(started.elapsed() < Duration::from_secs(10));

    let (w, mut rd) = tokio::io::duplex(4096);
    let stream = PtyStream {
        stdout: Some(Box::new(w)),
        command: ["/bin/sh", "-c", "echo out; echo err >&2; exit 2"]
            .map(String::from)
            .to_vec(),
        ..PtyStream::default()
    };
    let err = h.be.attach_pty(&sb.id, stream).await.expect_err("exit 2");
    assert_eq!(err.to_string(), "exit status 2");
    let mut merged = String::new();
    rd.read_to_string(&mut merged).await.expect("read");
    assert!(merged.contains("out") && merged.contains("err"), "{merged}");
    h.be.kill(&sb.id).await.expect("kill");
}

#[tokio::test]
async fn unsupported_settings_are_refused_before_anything_boots() {
    let h = harness();
    for (spec, want) in [
        (
            Spec {
                seccomp: "/etc/profile.json".into(),
                ..h.spec()
            },
            "seccomp",
        ),
        (
            Spec {
                apparmor: "runeward".into(),
                ..h.spec()
            },
            "apparmor",
        ),
        (
            Spec {
                ide_port: 8080,
                ..h.spec()
            },
            "network device",
        ),
        (
            Spec {
                runtime_class: "kata-qemu".into(),
                ..h.spec()
            },
            "not a microVM monitor",
        ),
        (
            Spec {
                broker: Some(crate::BrokerHandle(Arc::new(
                    runeward_egress::Broker::with_secret_values(
                        "sb",
                        vec![runeward_charter::Endpoint {
                            name: "gh".into(),
                            host: "api.github.com".into(),
                            binaries: vec!["/usr/bin/gh".into()],
                            ..runeward_charter::Endpoint::default()
                        }],
                        vec![],
                        std::collections::HashMap::new(),
                    )
                    .expect("broker"),
                ))),
                ..h.spec()
            },
            "endpoint binaries",
        ),
        (
            Spec {
                runtime_class: "libkrun".into(),
                ..h.spec()
            },
            "not available",
        ),
    ] {
        let err = h.be.create(spec).await.expect_err(want);
        assert!(err.to_string().contains(want), "{err}");
    }
    assert!(h.be.list().await.expect("list").is_empty());
}

#[tokio::test]
async fn failed_boots_and_pulls_leave_nothing_behind() {
    let h = harness_with(FakeVmm {
        probe: None,
        crash: true,
    });
    let err = h.be.create(h.spec()).await.expect_err("crash");
    assert!(err.to_string().contains("exited during boot"), "{err}");
    assert!(err.to_string().contains("no such device"), "{err}");
    let h = harness();
    let err =
        h.be.create(Spec {
            image: "example.test/missing:1".into(),
            ..h.spec()
        })
        .await
        .expect_err("pull");
    assert!(err.to_string().contains("not found"), "{err}");
    assert!(h.be.list().await.expect("list").is_empty());
    let vms = h.be.dir.join("vms");
    let left = std::fs::read_dir(&vms).map(|d| d.count()).unwrap_or(0);
    assert_eq!(left, 0, "no VM directory left behind");
}

#[test]
fn sizes_and_names() {
    let cfg = BackendConfig::default();
    let spec = Spec {
        resources: crate::types::Resources {
            memory_bytes: 512 << 20,
            nano_cpus: 1_500_000_000,
        },
        ..Spec::default()
    };
    assert_eq!(guest_size(&spec, &cfg), (512, 2));
    assert_eq!(vmm_key("Firecracker"), Some("firecracker"));
    assert_eq!(vmm_key("krun"), Some("libkrun"));
    assert_eq!(vmm_key(""), None);
    assert_eq!(vmm_key("runc"), Some("?"));
    let out = ExecOutput {
        exit: runeward_vmagent::proto::Exit {
            code: -1,
            signal: Some(9),
        },
        ..ExecOutput::default()
    };
    assert_eq!(exit_code(&out), 137);
}

#[test]
fn agent_binary_must_match_the_host() {
    let d = tempfile::tempdir().expect("tempdir");
    let p = d.path().join("agent");
    std::fs::write(&p, b"#!/bin/sh\n").expect("write");
    assert!(check_agent(&p).is_err());
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    let m = host_elf_machine().unwrap_or(62);
    elf[18..20].copy_from_slice(&m.to_le_bytes());
    std::fs::write(&p, &elf).expect("write");
    assert!(check_agent(&p).is_ok());
    elf[18..20].copy_from_slice(&(m ^ 1).to_le_bytes());
    std::fs::write(&p, &elf).expect("write");
    assert!(check_agent(&p).is_err());
}
