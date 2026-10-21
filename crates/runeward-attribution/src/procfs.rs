//! Finding which processes hold a TCP socket, from `/proc`.
//!
//! The lookup reads, under a proc root (normally `/proc`):
//!
//! - `net/tcp` and `net/tcp6`: the reader's network namespace's TCP sockets,
//!   to find the inode of the socket whose local address (and, when given,
//!   peer address) matches the query;
//! - `<pid>/task/<tid>/fd/*`: every thread's descriptors (threads made with
//!   `clone` without `CLONE_FILES` have their own table), to find the
//!   processes holding `socket:[<inode>]`;
//! - `<pid>/exe`: each holder's executable, by path (`readlink`) and by file
//!   identity (`stat` follows the link to the running file).
//!
//! Reading another process's descriptors or executable needs ptrace read
//! access to it (same uid and dumpable, or `CAP_SYS_PTRACE`). A process the
//! reader cannot inspect might hold the socket, so it makes the answer
//! [`Status::Incomplete`], which the broker refuses. Processes that exit
//! mid-scan are skipped: they no longer hold anything.

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::binaries::BinarySet;
use crate::{Answer, Holder, MAX_HOLDERS, Query, SCHEMA, Status};

/// One row of `/proc/net/tcp{,6}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpEntry {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    /// The kernel's state code (`01` established, `0A` listen, ...).
    pub state: u8,
    pub inode: u64,
}

/// TCP state code for a listening socket.
const TCP_LISTEN: u8 = 0x0A;

/// Parses a `/proc/net/tcp` or `/proc/net/tcp6` table. Malformed rows are
/// skipped.
pub fn parse_tcp_table(text: &str) -> Vec<TcpEntry> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 {
                return None;
            }
            Some(TcpEntry {
                local: parse_addr(f[1])?,
                remote: parse_addr(f[2])?,
                state: u8::from_str_radix(f[3], 16).ok()?,
                inode: f[9].parse().ok()?,
            })
        })
        .collect()
}

/// Parses `ADDR:PORT` as the kernel prints it: the address as 32-bit words
/// in host byte order, the port as plain hex.
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(a)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(&a[i * 8..i * 8 + 8])?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn word(hex8: &str) -> Option<[u8; 4]> {
    Some(u32::from_str_radix(hex8, 16).ok()?.to_ne_bytes())
}

/// Compares socket addresses with IPv4-mapped IPv6 folded to IPv4.
fn same(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

/// Lookups against one proc root.
#[derive(Debug, Clone)]
pub struct ProcFs {
    root: PathBuf,
    /// Processes never reported as holders: the helper itself and the
    /// supervisor that started it (both non-dumpable, neither holds agent
    /// sockets).
    skip: BTreeSet<u32>,
}

/// The holders of a set of sockets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Holders {
    pub pids: BTreeSet<u32>,
    /// Processes whose descriptors could not be read.
    pub uninspectable: BTreeSet<u32>,
}

impl ProcFs {
    /// Lookups under `root`, ignoring the processes in `skip`.
    pub fn new(root: impl Into<PathBuf>, skip: impl IntoIterator<Item = u32>) -> Self {
        Self {
            root: root.into(),
            skip: skip.into_iter().collect(),
        }
    }

    /// The inodes of non-listening TCP sockets whose local address is
    /// `local` and, when `remote` is set, whose peer is `remote`.
    pub fn sockets(&self, local: SocketAddr, remote: Option<SocketAddr>) -> io::Result<Vec<u64>> {
        let mut out = Vec::new();
        let mut read_any = false;
        for table in ["net/tcp", "net/tcp6"] {
            let text = match std::fs::read_to_string(self.root.join(table)) {
                Ok(t) => t,
                // IPv6 may be disabled.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            read_any = true;
            out.extend(
                parse_tcp_table(&text)
                    .into_iter()
                    .filter(|e| {
                        e.inode != 0
                            && e.state != TCP_LISTEN
                            && same(e.local, local)
                            && remote.is_none_or(|r| same(e.remote, r))
                    })
                    .map(|e| e.inode),
            );
        }
        if !read_any {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no TCP socket table under the proc root",
            ));
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Every process holding one of `inodes`.
    pub fn holders(&self, inodes: &[u64]) -> io::Result<Holders> {
        let wanted: BTreeSet<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
        let mut out = Holders::default();
        for entry in std::fs::read_dir(&self.root)? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            if self.skip.contains(&pid) {
                continue;
            }
            match self.process_holds(&entry.path(), &wanted) {
                Ok(true) => {
                    out.pids.insert(pid);
                }
                Ok(false) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    out.uninspectable.insert(pid);
                }
            }
        }
        Ok(out)
    }

    /// Whether any thread of the process at `dir` holds one of `wanted`.
    fn process_holds(&self, dir: &Path, wanted: &BTreeSet<String>) -> io::Result<bool> {
        let mut any_task = false;
        for task in std::fs::read_dir(dir.join("task"))? {
            let Ok(task) = task else { continue };
            any_task = true;
            let fds = match std::fs::read_dir(task.path().join("fd")) {
                Ok(f) => f,
                // The thread exited.
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            for fd in fds {
                let Ok(fd) = fd else { continue };
                match std::fs::read_link(fd.path()) {
                    Ok(t) if wanted.contains(t.to_string_lossy().as_ref()) => return Ok(true),
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
        }
        if !any_task {
            // A process with no readable task list has exited.
            return Err(io::Error::new(io::ErrorKind::NotFound, "no tasks"));
        }
        Ok(false)
    }

    /// The executable of `pid`: its path and the Charter binaries it is.
    pub fn exe(&self, pid: u32, binaries: &BinarySet) -> io::Result<Holder> {
        let link = self.root.join(pid.to_string()).join("exe");
        let exe = std::fs::read_link(&link)?.to_string_lossy().into_owned();
        let md = std::fs::metadata(&link)?;
        Ok(Holder {
            pid,
            exe,
            matches: binaries.matches(&md),
        })
    }

    /// Answers `q` (without its MAC).
    pub fn attribute(&self, q: &Query, binaries: &BinarySet) -> Answer {
        if q.schema != SCHEMA {
            return Answer::to(q, Status::Error, "unknown query schema");
        }
        let Ok(local) = q.local.parse::<SocketAddr>() else {
            return Answer::to(q, Status::Error, "local is not ip:port");
        };
        let remote = if q.remote.is_empty() {
            None
        } else {
            match q.remote.parse::<SocketAddr>() {
                Ok(r) => Some(r),
                Err(_) => return Answer::to(q, Status::Error, "remote is not ip:port"),
            }
        };
        let inodes = match self.sockets(local, remote) {
            Ok(i) => i,
            Err(e) => return Answer::to(q, Status::Error, format!("read socket table: {e}")),
        };
        if inodes.is_empty() {
            return Answer::to(q, Status::NotFound, "no such connection in the sandbox");
        }
        let found = match self.holders(&inodes) {
            Ok(h) => h,
            Err(e) => return Answer::to(q, Status::Error, format!("scan processes: {e}")),
        };
        let mut a = Answer::to(q, Status::Attributed, "");
        let mut uninspectable = found.uninspectable;
        for pid in found.pids {
            match self.exe(pid, binaries) {
                Ok(h) => a.holders.push(h),
                // Exited since the scan: it no longer holds the socket.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    uninspectable.insert(pid);
                }
            }
            if a.holders.len() >= MAX_HOLDERS {
                uninspectable.insert(u32::MAX);
                break;
            }
        }
        if !uninspectable.is_empty() {
            a.status = Status::Incomplete;
            a.detail = format!(
                "{} process(es) in the sandbox could not be inspected and might hold the connection",
                uninspectable.len()
            );
        } else if a.holders.is_empty() {
            a.status = Status::NotFound;
            a.detail = "no process in the sandbox holds the connection".into();
        }
        a
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    // 127.0.0.1:8080 -> 10.0.0.5:443 established (inode 1001), a listener
    // on 0.0.0.0:22 (inode 1002), and an inode-0 TIME_WAIT row.
    fn hex_v4(ip: [u8; 4]) -> String {
        format!("{:08X}", u32::from_ne_bytes(ip))
    }

    fn row(local: ([u8; 4], u16), remote: ([u8; 4], u16), state: u8, inode: u64) -> String {
        format!(
            "   0: {}:{:04X} {}:{:04X} {state:02X} 00000000:00000000 00:00000000 00000000  1500        0 {inode} 1 0000000000000000 20 4 30 10 -1",
            hex_v4(local.0),
            local.1,
            hex_v4(remote.0),
            remote.1
        )
    }

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[test]
    fn parses_ipv4_and_ipv6_rows() {
        let text = format!(
            "{HEADER}\n{}\n{}\nbroken row\n",
            row(([172, 17, 0, 2], 40000), ([93, 184, 216, 34], 443), 1, 1001),
            row(([0, 0, 0, 0], 22), ([0, 0, 0, 0], 0), 0x0A, 1002),
        );
        let got = parse_tcp_table(&text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].local, "172.17.0.2:40000".parse().expect("addr"));
        assert_eq!(got[0].remote, "93.184.216.34:443".parse().expect("addr"));
        assert_eq!((got[0].state, got[0].inode), (1, 1001));
        assert_eq!(got[1].state, TCP_LISTEN);

        // ::ffff:172.17.0.2 port 40000, as the kernel prints it.
        let mapped: Ipv6Addr = "::ffff:172.17.0.2".parse().expect("v6");
        let words: String = mapped
            .octets()
            .chunks(4)
            .map(|c| format!("{:08X}", u32::from_ne_bytes([c[0], c[1], c[2], c[3]])))
            .collect();
        let v6 = format!(
            "{HEADER}\n   0: {words}:9C40 {}:01BB 01 0:0 0:0 0 1500 0 2001 1\n",
            "0".repeat(32)
        );
        let got = parse_tcp_table(&v6);
        assert_eq!(got.len(), 1);
        assert!(same(
            got[0].local,
            "172.17.0.2:40000".parse().expect("addr")
        ));
    }

    /// A fake proc root: `procs` is (pid, exe target, [(tid, [fd link])]).
    struct Fake {
        dir: tempfile::TempDir,
    }

    impl Fake {
        fn new(tcp: &str) -> Self {
            let dir = tempfile::tempdir().expect("tmp");
            std::fs::create_dir_all(dir.path().join("proc/net")).expect("mkdir");
            std::fs::write(dir.path().join("proc/net/tcp"), tcp).expect("tcp");
            Self { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.path().join("proc")
        }

        fn bin(&self, name: &str) -> String {
            let p = self.dir.path().join("bin").join(name);
            std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
            std::fs::write(&p, name).expect("bin");
            p.display().to_string()
        }

        fn process(&self, pid: u32, exe: &str, tasks: &[(u32, &[&str])]) {
            let pdir = self.root().join(pid.to_string());
            std::fs::create_dir_all(&pdir).expect("mkdir");
            symlink(exe, pdir.join("exe")).expect("exe");
            for (tid, links) in tasks {
                let fd = pdir.join("task").join(tid.to_string()).join("fd");
                std::fs::create_dir_all(&fd).expect("mkdir");
                for (n, l) in links.iter().enumerate() {
                    symlink(l, fd.join(n.to_string())).expect("fd");
                }
            }
        }
    }

    fn query(local: &str, remote: &str) -> Query {
        Query {
            schema: SCHEMA.into(),
            nonce: "n".into(),
            local: local.into(),
            remote: remote.into(),
        }
    }

    fn table() -> String {
        format!(
            "{HEADER}\n{}\n{}\n{}\n",
            row(([172, 17, 0, 2], 40000), ([10, 0, 0, 5], 443), 1, 1001),
            row(([172, 17, 0, 2], 40001), ([10, 0, 0, 5], 443), 1, 1003),
            row(([0, 0, 0, 0], 22), ([0, 0, 0, 0], 0), 0x0A, 1002),
        )
    }

    #[test]
    fn attributes_the_holder_by_file_identity() {
        let f = Fake::new(&table());
        let curl = f.bin("curl");
        let python = f.bin("python3.11");
        let python_link = f.dir.path().join("bin/python3");
        symlink(&python, &python_link).expect("symlink");
        let set = BinarySet::snapshot(&[curl.clone(), python_link.display().to_string()]);
        // pid 10 (curl) holds 1001; pid 11 (python) holds 1003 in a second
        // thread with its own fd table; pid 12 holds unrelated things.
        f.process(10, &curl, &[(10, &["socket:[1001]", "pipe:[5]"])]);
        f.process(
            11,
            &python,
            &[(11, &["/dev/null"]), (13, &["socket:[1003]"])],
        );
        f.process(12, &curl, &[(12, &["socket:[1002]", "socket:[99]"])]);
        let p = ProcFs::new(f.root(), [1]);

        let a = p.attribute(&query("172.17.0.2:40000", "10.0.0.5:443"), &set);
        assert_eq!(a.status, Status::Attributed, "{a:?}");
        assert_eq!(a.holders.len(), 1);
        assert_eq!(
            (a.holders[0].pid, a.holders[0].exe.as_str()),
            (10, curl.as_str())
        );
        assert_eq!(a.holders[0].matches, vec![curl.clone()]);

        // The interpreter is identified through the listed symlink.
        let a = p.attribute(&query("172.17.0.2:40001", ""), &set);
        assert_eq!(a.status, Status::Attributed, "{a:?}");
        assert_eq!(a.holders[0].pid, 11);
        assert_eq!(a.holders[0].exe, python);
        assert_eq!(
            a.holders[0].matches,
            vec![python_link.display().to_string()]
        );

        // A wrong peer, an unknown port and the listener are not found.
        for (l, r) in [
            ("172.17.0.2:40000", "10.0.0.6:443"),
            ("172.17.0.2:40009", ""),
            ("0.0.0.0:22", ""),
        ] {
            let a = p.attribute(&query(l, r), &set);
            assert_eq!(a.status, Status::NotFound, "{l} {r}: {a:?}");
        }
    }

    #[test]
    fn shared_sockets_report_every_holder_and_skip_the_supervisor() {
        let f = Fake::new(&table());
        let curl = f.bin("curl");
        let sh = f.bin("sh");
        let set = BinarySet::snapshot(std::slice::from_ref(&curl));
        f.process(10, &curl, &[(10, &["socket:[1001]"])]);
        f.process(20, &sh, &[(20, &["socket:[1001]"])]);
        // The supervisor (pid 1) is skipped even though it would match.
        f.process(1, &sh, &[(1, &["socket:[1001]"])]);
        let p = ProcFs::new(f.root(), [1]);
        let a = p.attribute(&query("172.17.0.2:40000", ""), &set);
        assert_eq!(a.status, Status::Attributed);
        let pids: Vec<u32> = a.holders.iter().map(|h| h.pid).collect();
        assert_eq!(pids, [10, 20]);
        assert!(a.holders[1].matches.is_empty());
    }

    #[test]
    fn no_holder_and_bad_queries() {
        let f = Fake::new(&table());
        let set = BinarySet::default();
        let p = ProcFs::new(f.root(), []);
        let a = p.attribute(&query("172.17.0.2:40000", ""), &set);
        assert_eq!(a.status, Status::NotFound);
        assert!(a.detail.contains("no process"), "{}", a.detail);
        for q in [
            query("nope", ""),
            query("172.17.0.2:40000", "nope"),
            Query {
                schema: "other".into(),
                ..query("172.17.0.2:40000", "")
            },
        ] {
            assert_eq!(p.attribute(&q, &set).status, Status::Error, "{q:?}");
        }
        let empty = ProcFs::new(f.dir.path().join("missing"), []);
        assert_eq!(
            empty.attribute(&query("172.17.0.2:40000", ""), &set).status,
            Status::Error
        );
    }

    #[test]
    fn uninspectable_processes_make_the_answer_incomplete() {
        use std::os::unix::fs::PermissionsExt as _;
        let f = Fake::new(&table());
        let curl = f.bin("curl");
        let set = BinarySet::snapshot(std::slice::from_ref(&curl));
        f.process(10, &curl, &[(10, &["socket:[1001]"])]);
        f.process(30, &curl, &[(30, &["socket:[7]"])]);
        let fd = f.root().join("30/task/30/fd");
        std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o000)).expect("chmod");
        if std::fs::read_dir(&fd).is_ok() {
            // Running as root: permissions do not apply.
            std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            return;
        }
        let p = ProcFs::new(f.root(), []);
        let a = p.attribute(&query("172.17.0.2:40000", ""), &set);
        std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        assert_eq!(a.status, Status::Incomplete, "{a:?}");
        assert_eq!(a.holders.len(), 1, "the readable holder is still listed");
    }
}
