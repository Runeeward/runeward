//! Virtual machine monitors: Firecracker and libkrun.
//!
//! Both boot the same guest: the Rune Box agent as PID 1, the image disk
//! read-only as `/dev/vda`, the workspace disk as `/dev/vdb`, one vsock
//! device and **no network device**. They differ in how the host reaches
//! the guest's vsock ports:
//!
//! - Firecracker multiplexes host-initiated connections over one Unix
//!   socket (`CONNECT <port>\n`, answered `OK <port>\n`) and delivers
//!   guest-initiated connections to port `P` on `<uds>_P`;
//! - libkrun maps each port to its own Unix socket.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use async_trait::async_trait;
use runeward_vmagent::proto::{self, KrunConfig};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};

use crate::error::{BackendError, Result};

/// The guest kernel command line for Firecracker (the agent reads the
/// `RUNEWARD_VM_*` words from `/proc/cmdline`).
pub(crate) fn firecracker_boot_args(workspace: bool) -> String {
    let mut s = format!(
        "console=ttyS0 reboot=k panic=1 pci=off quiet rdinit=/init {}=/dev/vda",
        proto::cmdline::LOWER
    );
    if workspace {
        s.push_str(&format!(" {}=/dev/vdb", proto::cmdline::WORKSPACE));
    }
    s
}

/// Everything a VMM needs to boot one sandbox.
#[derive(Debug, Clone)]
pub(crate) struct LaunchPlan {
    /// The sandbox's state directory (sockets, logs, VMM config).
    pub(crate) dir: PathBuf,
    /// A short name for the VMM process (Firecracker `--id`).
    pub(crate) name: String,
    /// The read-only image disk.
    pub(crate) rootfs: PathBuf,
    /// The workspace disk.
    pub(crate) workspace: Option<PathBuf>,
    /// vCPUs.
    pub(crate) vcpus: u8,
    /// Guest memory in MiB.
    pub(crate) mem_mib: u32,
}

impl LaunchPlan {
    /// The VMM's own output (and the guest console for Firecracker).
    pub(crate) fn log_path(&self) -> PathBuf {
        self.dir.join("vmm.log")
    }
}

/// A virtual machine monitor.
#[async_trait]
pub(crate) trait Vmm: Send + Sync + fmt::Debug {
    /// The runtime name recorded in isolation evidence (`firecracker`,
    /// `libkrun`).
    fn name(&self) -> &'static str;

    /// Boots the VM; the returned process is the VMM.
    async fn launch(&self, plan: &LaunchPlan) -> Result<Child>;

    /// Opens a stream to the guest agent of the VM in `dir`.
    async fn connect(&self, dir: &Path) -> io::Result<UnixStream>;

    /// The host Unix socket the guest's egress connections arrive on.
    fn egress_socket(&self, dir: &Path) -> PathBuf;
}

/// Opens `path` for the VMM's stdout and stderr.
fn log_file(path: &Path) -> Result<(Stdio, Stdio)> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| BackendError::io(format!("open {}", path.display()), e))?;
    let g = f
        .try_clone()
        .map_err(|e| BackendError::io(format!("open {}", path.display()), e))?;
    Ok((f.into(), g.into()))
}

fn spawn(mut cmd: Command, what: &str, plan: &LaunchPlan) -> Result<Child> {
    let (out, err) = log_file(&plan.log_path())?;
    cmd.stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        // Its own process group: a signal to the control plane's group
        // does not take the VMs down with it.
        .process_group(0)
        .kill_on_drop(false);
    cmd.spawn()
        .map_err(|e| BackendError::io(format!("start {what}"), e))
}

/// Firecracker, booted from a config file without its API socket.
#[derive(Debug, Clone)]
pub(crate) struct Firecracker {
    pub(crate) bin: PathBuf,
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
}

impl Firecracker {
    /// The vsock Unix socket of a VM directory.
    fn uds(dir: &Path) -> PathBuf {
        dir.join("v.sock")
    }

    /// The `--config-file` document.
    pub(crate) fn config(&self, plan: &LaunchPlan) -> serde_json::Value {
        let mut drives = vec![json!({
            "drive_id": "image",
            "path_on_host": plan.rootfs,
            "is_root_device": false,
            "is_read_only": true,
        })];
        if let Some(ws) = &plan.workspace {
            drives.push(json!({
                "drive_id": "workspace",
                "path_on_host": ws,
                "is_root_device": false,
                "is_read_only": false,
            }));
        }
        json!({
            "boot-source": {
                "kernel_image_path": self.kernel,
                "initrd_path": self.initramfs,
                "boot_args": firecracker_boot_args(plan.workspace.is_some()),
            },
            "drives": drives,
            "machine-config": {
                "vcpu_count": plan.vcpus.max(1),
                "mem_size_mib": plan.mem_mib.max(128),
                "smt": false,
            },
            "vsock": {
                "guest_cid": 3,
                "uds_path": Self::uds(&plan.dir),
            },
            // No "network-interfaces": the guest gets no NIC.
        })
    }
}

#[async_trait]
impl Vmm for Firecracker {
    fn name(&self) -> &'static str {
        "firecracker"
    }

    async fn launch(&self, plan: &LaunchPlan) -> Result<Child> {
        let cfg_path = plan.dir.join("firecracker.json");
        let doc = serde_json::to_vec_pretty(&self.config(plan))
            .map_err(|e| BackendError::msg(e.to_string()))?;
        std::fs::write(&cfg_path, doc).map_err(|e| BackendError::io("write VM config", e))?;
        // Firecracker binds the vsock socket itself and refuses a stale
        // one; the egress socket next to it is already being served.
        let _ = std::fs::remove_file(Self::uds(&plan.dir));
        let mut cmd = Command::new(&self.bin);
        cmd.arg("--no-api")
            .arg("--config-file")
            .arg(&cfg_path)
            .arg("--id")
            .arg(&plan.name)
            .arg("--level")
            .arg("Warning");
        spawn(cmd, "firecracker", plan)
    }

    async fn connect(&self, dir: &Path) -> io::Result<UnixStream> {
        let mut s = UnixStream::connect(Self::uds(dir)).await?;
        s.write_all(format!("CONNECT {}\n", proto::AGENT_PORT).as_bytes())
            .await?;
        // Read the acknowledgement byte by byte: anything after it is the
        // agent's.
        let mut line = Vec::new();
        let mut r = BufReader::with_capacity(1, &mut s);
        r.read_until(b'\n', &mut line).await?;
        if !line.starts_with(b"OK ") {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "vsock connect to port {}: {:?}",
                    proto::AGENT_PORT,
                    String::from_utf8_lossy(&line).trim()
                ),
            ));
        }
        Ok(s)
    }

    fn egress_socket(&self, dir: &Path) -> PathBuf {
        PathBuf::from(format!(
            "{}_{}",
            Self::uds(dir).display(),
            proto::EGRESS_PORT
        ))
    }
}

/// libkrun, through the `runeward-krun` helper.
#[derive(Debug, Clone)]
pub(crate) struct Libkrun {
    pub(crate) helper: PathBuf,
    pub(crate) library: String,
    pub(crate) agent: PathBuf,
}

impl Libkrun {
    fn agent_socket(dir: &Path) -> PathBuf {
        dir.join("agent.sock")
    }

    /// The helper's configuration.
    pub(crate) fn config(&self, plan: &LaunchPlan) -> KrunConfig {
        let mut env = vec![format!("{}=/dev/vda", proto::cmdline::LOWER)];
        if plan.workspace.is_some() {
            env.push(format!("{}=/dev/vdb", proto::cmdline::WORKSPACE));
        }
        KrunConfig {
            library: self.library.clone(),
            vcpus: plan.vcpus.max(1),
            ram_mib: plan.mem_mib.max(128),
            agent: self.agent.to_string_lossy().into_owned(),
            rootfs: plan.rootfs.to_string_lossy().into_owned(),
            workspace: plan
                .workspace
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            agent_socket: Self::agent_socket(&plan.dir).to_string_lossy().into_owned(),
            egress_socket: self.egress_socket(&plan.dir).to_string_lossy().into_owned(),
            env,
            console: plan.dir.join("console.log").to_string_lossy().into_owned(),
        }
    }
}

#[async_trait]
impl Vmm for Libkrun {
    fn name(&self) -> &'static str {
        "libkrun"
    }

    async fn launch(&self, plan: &LaunchPlan) -> Result<Child> {
        let cfg_path = plan.dir.join("krun.json");
        let doc = serde_json::to_vec_pretty(&self.config(plan))
            .map_err(|e| BackendError::msg(e.to_string()))?;
        std::fs::write(&cfg_path, doc).map_err(|e| BackendError::io("write VM config", e))?;
        // libkrun creates the agent socket itself and refuses a stale one.
        let _ = std::fs::remove_file(Self::agent_socket(&plan.dir));
        let mut cmd = Command::new(&self.helper);
        cmd.arg(&cfg_path);
        if let Some(dir) = Path::new(&self.library)
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
        {
            // libkrun loads libkrunfw by name; look next to libkrun first.
            let var = if cfg!(target_os = "macos") {
                "DYLD_LIBRARY_PATH"
            } else {
                "LD_LIBRARY_PATH"
            };
            cmd.env(var, dir);
        }
        spawn(cmd, "runeward-krun", plan)
    }

    async fn connect(&self, dir: &Path) -> io::Result<UnixStream> {
        UnixStream::connect(Self::agent_socket(dir)).await
    }

    fn egress_socket(&self, dir: &Path) -> PathBuf {
        dir.join("egress.sock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> LaunchPlan {
        LaunchPlan {
            dir: PathBuf::from("/vms/abc"),
            name: "rw-abc".into(),
            rootfs: PathBuf::from("/images/sha256-x.ext4"),
            workspace: Some(PathBuf::from("/vms/abc/workspace.ext4")),
            vcpus: 2,
            mem_mib: 512,
        }
    }

    #[test]
    fn firecracker_config_has_no_network_and_a_read_only_image() {
        let fc = Firecracker {
            bin: "firecracker".into(),
            kernel: "/k/vmlinux".into(),
            initramfs: "/k/agent.cpio".into(),
        };
        let c = fc.config(&plan());
        assert!(c.get("network-interfaces").is_none());
        assert_eq!(c["drives"][0]["is_read_only"], true);
        assert_eq!(c["drives"][1]["is_read_only"], false);
        assert_eq!(c["machine-config"]["vcpu_count"], 2);
        assert_eq!(c["vsock"]["uds_path"], "/vms/abc/v.sock");
        let args = c["boot-source"]["boot_args"].as_str().expect("args");
        assert!(args.contains("RUNEWARD_VM_LOWER=/dev/vda"), "{args}");
        assert!(args.contains("RUNEWARD_VM_WS=/dev/vdb"), "{args}");
        assert!(args.contains("rdinit=/init"), "{args}");
        assert_eq!(
            fc.egress_socket(Path::new("/vms/abc")),
            PathBuf::from("/vms/abc/v.sock_10790")
        );
        assert!(!firecracker_boot_args(false).contains("RUNEWARD_VM_WS"));
    }

    #[test]
    fn libkrun_config() {
        let k = Libkrun {
            helper: "runeward-krun".into(),
            library: "libkrun.so.1".into(),
            agent: "/opt/runeward/runeward-vmagent".into(),
        };
        let c = k.config(&plan());
        assert_eq!(c.rootfs, "/images/sha256-x.ext4");
        assert_eq!(c.workspace, "/vms/abc/workspace.ext4");
        assert_eq!(c.agent_socket, "/vms/abc/agent.sock");
        assert_eq!(c.egress_socket, "/vms/abc/egress.sock");
        assert!(c.env.contains(&"RUNEWARD_VM_WS=/dev/vdb".to_owned()));
        assert_eq!((c.vcpus, c.ram_mib), (2, 512));
    }
}
