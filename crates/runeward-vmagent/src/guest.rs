//! PID 1 in the guest (Linux only).
//!
//! Boot: mount `/proc`, `/sys` and `/dev`, bring up loopback (the only
//! interface: the guest has no NIC), start the egress forwarder on
//! [`proto::GUEST_PROXY_ADDR`] and serve the protocol on vsock
//! [`proto::AGENT_PORT`].
//!
//! [`Request::Init`](crate::proto::Request::Init) then builds the sandbox
//! root: the image disk (`RUNEWARD_VM_LOWER`, attached read-only by the
//! VMM) under an overlay whose upper layer is guest memory, `/proc`,
//! `/sys`, `/dev` inside it, the workspace disk (`RUNEWARD_VM_WS`) at the
//! workspace directory, and the agent `chroot`s into it. Nothing the
//! sandbox writes outside the workspace reaches a host file.

use std::fs;
use std::io;
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sys::reboot::{RebootMode, reboot};
use nix::sys::signal::{Signal, kill};
use nix::sys::socket::{
    AddressFamily, Backlog, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, VsockAddr,
    bind, connect, listen, recv, sendto, socket,
};
use nix::unistd::{Gid, Pid, Uid, chown};

use crate::proto::{self, InitRequest, cmdline};
use crate::server::{Agent, HelperMode, Platform, Reaper};

/// Where the agent assembles the sandbox root before entering it.
const SCRATCH: &str = "/newroot";

/// `VMADDR_CID_ANY`.
const CID_ANY: u32 = u32::MAX;

/// Boot parameters from the kernel command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootParams {
    /// The image disk.
    pub lower: String,
    /// The workspace disk (empty: none).
    pub workspace: String,
    /// The vsock port to serve.
    pub port: u32,
}

/// Parses `KEY=value` words of the kernel command line.
pub fn parse_cmdline(line: &str) -> BootParams {
    let mut p = BootParams {
        port: proto::AGENT_PORT,
        ..BootParams::default()
    };
    for w in line.split_whitespace() {
        let Some((k, v)) = w.split_once('=') else {
            continue;
        };
        match k {
            cmdline::LOWER => p.lower = v.to_owned(),
            cmdline::WORKSPACE => p.workspace = v.to_owned(),
            cmdline::PORT => p.port = v.parse().unwrap_or(proto::AGENT_PORT),
            _ => {}
        }
    }
    p
}

fn log(msg: &str) {
    eprintln!("runeward-vmagent: {msg}");
}

/// Mounts `fstype` at `target`, creating the directory; EBUSY (already
/// mounted) is fine.
fn mount_fs(
    src: &str,
    target: &str,
    fstype: &str,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<(), String> {
    let _ = fs::create_dir_all(target);
    match mount(Some(src), target, Some(fstype), flags, data) {
        Ok(()) | Err(nix::errno::Errno::EBUSY) => Ok(()),
        Err(e) => Err(format!("mount {fstype} at {target}: {e}")),
    }
}

/// Brings up `lo` (ifindex 1) over rtnetlink.
fn loopback_up() -> io::Result<()> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkRoute,
    )?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
    // nlmsghdr (len, RTM_NEWLINK, NLM_F_REQUEST|NLM_F_ACK, seq, pid) +
    // ifinfomsg (AF_UNSPEC, type 0, index 1, flags IFF_UP, change IFF_UP).
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&32u32.to_ne_bytes());
    msg.extend_from_slice(&16u16.to_ne_bytes());
    msg.extend_from_slice(&5u16.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&[0, 0]);
    msg.extend_from_slice(&0u16.to_ne_bytes());
    msg.extend_from_slice(&1i32.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes());
    sendto(
        fd.as_raw_fd(),
        &msg,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )?;
    let mut buf = [0u8; 256];
    let n = recv(fd.as_raw_fd(), &mut buf, MsgFlags::empty())?;
    // NLMSG_ERROR carries the errno right after the header (0 = ack).
    if n >= 20 {
        let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if err != 0 {
            return Err(io::Error::from_raw_os_error(-err));
        }
    }
    Ok(())
}

/// Wraps an accepted socket descriptor.
#[allow(unsafe_code)]
fn owned(fd: std::os::fd::RawFd) -> OwnedFd {
    // SAFETY: `fd` was just returned by accept(2) and is owned by nobody
    // else; it is wrapped exactly once.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

fn vsock_listen(port: u32) -> io::Result<OwnedFd> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    bind(fd.as_raw_fd(), &VsockAddr::new(CID_ANY, port))?;
    listen(&fd, Backlog::new(64).map_err(io::Error::from)?)?;
    Ok(fd)
}

fn vsock_connect(cid: u32, port: u32) -> io::Result<UnixStream> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )?;
    connect(fd.as_raw_fd(), &VsockAddr::new(cid, port))?;
    // A connected stream socket: reads, writes and shutdown(2) are all the
    // std type needs.
    Ok(UnixStream::from(fd))
}

/// The guest platform.
#[derive(Debug)]
struct Guest {
    params: BootParams,
    workdir: Mutex<Option<PathBuf>>,
}

impl Guest {
    fn root_path(rel: &str) -> PathBuf {
        Path::new(SCRATCH)
            .join("root")
            .join(rel.trim_start_matches('/'))
    }

    /// Hands a fresh workspace disk the image directory's owner and mode,
    /// and drops `lost+found` so exports do not trip over it.
    fn prepare_workspace(ws: &Path, image_dir: &Path) {
        let entries: Vec<_> = fs::read_dir(ws)
            .map(|d| d.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        let fresh = entries.is_empty() || (entries.len() == 1 && entries[0] == "lost+found");
        if !fresh {
            return;
        }
        let _ = fs::remove_dir(ws.join("lost+found"));
        if let Ok(md) = fs::metadata(image_dir) {
            let _ = chown(
                ws,
                Some(Uid::from_raw(md.uid())),
                Some(Gid::from_raw(md.gid())),
            );
            let _ = fs::set_permissions(ws, fs::Permissions::from_mode(md.mode() & 0o7777));
        }
    }

    fn write_hosts(hostname: &str) {
        let hosts = format!(
            "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\t{hostname}\n"
        );
        let _ = fs::write(Self::root_path("/etc/hosts"), hosts);
        let _ = fs::write(Self::root_path("/etc/hostname"), format!("{hostname}\n"));
    }
}

impl Platform for Guest {
    fn init(&self, req: &InitRequest) -> Result<(), String> {
        let p = &self.params;
        if p.lower.is_empty() {
            return Err(format!("no image disk ({} unset)", cmdline::LOWER));
        }
        mount_fs(
            "tmpfs",
            SCRATCH,
            "tmpfs",
            MsFlags::empty(),
            Some("mode=0755"),
        )?;
        let at = |s: &str| format!("{SCRATCH}/{s}");
        for d in ["lower", "upper", "work", "root"] {
            fs::create_dir_all(at(d)).map_err(|e| format!("mkdir {}: {e}", at(d)))?;
        }
        mount_fs(&p.lower, &at("lower"), "ext4", MsFlags::MS_RDONLY, None)?;
        let data = format!(
            "lowerdir={},upperdir={},workdir={}",
            at("lower"),
            at("upper"),
            at("work")
        );
        mount_fs(
            "overlay",
            &at("root"),
            "overlay",
            MsFlags::empty(),
            Some(&data),
        )?;
        let root = |rel: &str| Self::root_path(rel).to_string_lossy().into_owned();
        let nosuid = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        mount_fs("proc", &root("/proc"), "proc", nosuid, None)?;
        mount_fs(
            "sysfs",
            &root("/sys"),
            "sysfs",
            nosuid | MsFlags::MS_RDONLY,
            None,
        )?;
        mount_fs(
            "devtmpfs",
            &root("/dev"),
            "devtmpfs",
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        )?;
        mount_fs(
            "devpts",
            &root("/dev/pts"),
            "devpts",
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
        )?;
        let _ = fs::remove_file(root("/dev/ptmx"));
        let _ = std::os::unix::fs::symlink("pts/ptmx", root("/dev/ptmx"));
        mount_fs(
            "shm",
            &root("/dev/shm"),
            "tmpfs",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777"),
        )?;
        if req.read_only {
            mount_fs(
                "tmpfs",
                &root("/tmp"),
                "tmpfs",
                MsFlags::MS_NOSUID,
                Some("mode=1777,size=512m"),
            )?;
        }
        let workdir = if req.workdir.is_empty() {
            "/workspace".to_owned()
        } else {
            req.workdir.clone()
        };
        if !p.workspace.is_empty() {
            let ws = root(&workdir);
            mount_fs(&p.workspace, &ws, "ext4", MsFlags::empty(), None)?;
            Self::prepare_workspace(
                Path::new(&ws),
                &Path::new(&at("lower")).join(workdir.trim_start_matches('/')),
            );
            *self.workdir.lock().unwrap_or_else(|e| e.into_inner()) = Some(PathBuf::from(&workdir));
        } else {
            let _ = fs::create_dir_all(root(&workdir));
        }
        if !req.hostname.is_empty() {
            nix::unistd::sethostname(&req.hostname).map_err(|e| format!("sethostname: {e}"))?;
            Self::write_hosts(&req.hostname);
        }
        nix::unistd::chroot(Path::new(&at("root"))).map_err(|e| format!("chroot: {e}"))?;
        std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
        Ok(())
    }

    fn seal(&self) -> Result<(), String> {
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("remount the root read-only: {e}"))
    }

    fn shutdown(&self) {
        poweroff(
            self.workdir
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        );
    }
}

/// Stops every process, flushes and unmounts the workspace, and reboots
/// (with `reboot=k` the VMM exits).
fn poweroff(workspace: Option<PathBuf>) {
    let _ = kill(Pid::from_raw(-1), Signal::SIGTERM);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && others_alive() {
        thread::sleep(Duration::from_millis(100));
    }
    let _ = kill(Pid::from_raw(-1), Signal::SIGKILL);
    thread::sleep(Duration::from_millis(100));
    nix::unistd::sync();
    if let Some(ws) = workspace
        && let Err(e) = umount2(&ws, MntFlags::empty())
    {
        log(&format!("unmount {}: {e}; detaching", ws.display()));
        let _ = umount2(&ws, MntFlags::MNT_DETACH);
    }
    nix::unistd::sync();
    let _ = reboot(RebootMode::RB_AUTOBOOT);
}

/// Reports whether any process other than PID 1 and kernel threads is
/// left.
fn others_alive() -> bool {
    let Ok(d) = fs::read_dir("/proc") else {
        return false;
    };
    d.flatten().any(|e| {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            return false;
        };
        // Kernel threads have an empty command line.
        pid > 1 && fs::read(e.path().join("cmdline")).is_ok_and(|c| !c.is_empty())
    })
}

/// Opens `/dev/console` as stdout and stderr.
fn console() {
    if let Ok(f) = fs::OpenOptions::new().write(true).open("/dev/console") {
        let _ = nix::unistd::dup2_stdout(&f);
        let _ = nix::unistd::dup2_stderr(&f);
    }
}

fn fatal(msg: &str) -> ! {
    log(&format!("fatal: {msg}"));
    nix::unistd::sync();
    let _ = reboot(RebootMode::RB_AUTOBOOT);
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

/// Runs the guest: never returns.
pub fn boot() -> ! {
    let nosuid = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
    for (src, target, fstype, flags, data) in [
        ("proc", "/proc", "proc", nosuid, None),
        ("sysfs", "/sys", "sysfs", nosuid, None),
        (
            "devtmpfs",
            "/dev",
            "devtmpfs",
            MsFlags::MS_NOSUID,
            Some("mode=0755"),
        ),
    ] {
        if let Err(e) = mount_fs(src, target, fstype, flags, data) {
            log(&e);
        }
    }
    console();
    let params = parse_cmdline(&fs::read_to_string("/proc/cmdline").unwrap_or_default());
    log(&format!("booting: {params:?}"));
    if let Err(e) = loopback_up() {
        log(&format!("bring up lo: {e}"));
    }
    let reaper = Reaper::global();
    let port = params.port;
    let agent = Agent::new(
        HelperMode::SelfExec(PathBuf::from("/proc/self/exe")),
        Box::new(Guest {
            params,
            workdir: Mutex::new(None),
        }),
        reaper,
    );
    match TcpListener::bind(proto::GUEST_PROXY_ADDR) {
        Ok(l) => {
            thread::spawn(move || {
                crate::server::forward_egress(l, || {
                    vsock_connect(proto::HOST_CID, proto::EGRESS_PORT)
                });
            });
        }
        Err(e) => log(&format!(
            "egress forwarder on {}: {e}",
            proto::GUEST_PROXY_ADDR
        )),
    }
    let listener = match vsock_listen(port) {
        Ok(l) => l,
        Err(e) => fatal(&format!("listen on vsock port {port}: {e}")),
    };
    log(&format!("ready on vsock port {port}"));
    loop {
        match nix::sys::socket::accept4(listener.as_raw_fd(), SockFlag::SOCK_CLOEXEC) {
            Ok(fd) => {
                let conn = UnixStream::from(owned(fd));
                let a = Arc::clone(&agent);
                thread::spawn(move || a.serve(conn));
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => {
                log(&format!("accept: {e}"));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_parameters() {
        let p = parse_cmdline(
            "console=ttyS0 reboot=k RUNEWARD_VM_LOWER=/dev/vda RUNEWARD_VM_WS=/dev/vdb RUNEWARD_VM_PORT=4000 -- x",
        );
        assert_eq!(p.lower, "/dev/vda");
        assert_eq!(p.workspace, "/dev/vdb");
        assert_eq!(p.port, 4000);
        assert_eq!(parse_cmdline("").port, proto::AGENT_PORT);
    }
}
