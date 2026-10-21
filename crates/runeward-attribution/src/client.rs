//! The broker side: asks the helper who holds a connection.

use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::{Answer, Error, Key, MAX_LINE, Query};

/// How long the broker waits for an answer by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

fn connect(socket: &str) -> Result<UnixStream, Error> {
    let unreachable = |e: std::io::Error| Error::Unreachable(e.to_string());
    match socket.strip_prefix('@') {
        Some(name) => connect_abstract(name, socket),
        None if socket.starts_with('/') => UnixStream::connect(socket).map_err(unreachable),
        None => Err(Error::Socket(socket.to_owned())),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn connect_abstract(name: &str, socket: &str) -> Result<UnixStream, Error> {
    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|_| Error::Socket(socket.to_owned()))?;
    UnixStream::connect_addr(&addr).map_err(|e| Error::Unreachable(e.to_string()))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn connect_abstract(_name: &str, socket: &str) -> Result<UnixStream, Error> {
    Err(Error::Socket(socket.to_owned()))
}

/// Asks the helper at `socket` who holds the connection whose sandbox-side
/// address is `local` (peer `remote`), and returns the authenticated answer.
/// Blocking; bounded by `timeout` per read and write.
pub fn query(
    socket: &str,
    key: &Key,
    local: SocketAddr,
    remote: Option<SocketAddr>,
    timeout: Duration,
) -> Result<Answer, Error> {
    let q = Query::new(local, remote);
    let s = connect(socket)?;
    let io = |e: std::io::Error| Error::Unreachable(e.to_string());
    s.set_read_timeout(Some(timeout)).map_err(io)?;
    s.set_write_timeout(Some(timeout)).map_err(io)?;
    let mut line = serde_json::to_vec(&q).map_err(|e| Error::Rejected(e.to_string()))?;
    line.push(b'\n');
    (&s).write_all(&line).map_err(io)?;
    let mut buf = Vec::new();
    (&s).take(MAX_LINE as u64 * 2)
        .read_to_end(&mut buf)
        .map_err(io)?;
    Answer::from_wire(&buf, key, &q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binaries::BinarySet;
    use crate::procfs::ProcFs;
    use crate::{Status, server};

    #[test]
    fn query_round_trip_over_a_path_socket() {
        let dir = tempfile::tempdir().expect("tmp");
        let sock = dir.path().join("a.sock").display().to_string();
        let listener = server::bind(&sock).expect("bind");
        let key = Key::generate();
        let k2 = key.clone();
        let proc_root = dir.path().join("proc");
        std::fs::create_dir_all(proc_root.join("net")).expect("mkdir");
        std::fs::write(proc_root.join("net/tcp"), "header\n").expect("tcp");
        let t = std::thread::spawn(move || {
            let proc = ProcFs::new(proc_root, []);
            for _ in 0..3 {
                let (s, _) = listener.accept().expect("accept");
                let _ = server::handle(s, &k2, &proc, &BinarySet::default());
            }
        });
        let local: SocketAddr = "10.1.2.3:5000".parse().expect("addr");
        let a = query(&sock, &key, local, None, DEFAULT_TIMEOUT).expect("answer");
        assert_eq!(a.status, Status::NotFound);
        assert_eq!(a.local, "10.1.2.3:5000");

        // A broker with the wrong key rejects a genuine answer.
        let err =
            query(&sock, &Key::generate(), local, None, DEFAULT_TIMEOUT).expect_err("wrong key");
        assert_eq!(err, Error::Rejected("bad MAC".into()));

        // A garbage query still gets an authenticated (error) answer.
        let mut s = UnixStream::connect(&sock).expect("connect");
        s.write_all(b"not json\n").expect("write");
        let mut buf = String::new();
        s.read_to_string(&mut buf).expect("read");
        let (line, mac) = buf.split_once('\n').expect("two lines");
        assert!(key.verify(line.as_bytes(), mac.trim()));
        assert!(line.contains("\"error\""), "{line}");
        t.join().expect("server");

        // Nobody listening.
        let err = query(&sock, &key, local, None, DEFAULT_TIMEOUT).expect_err("gone");
        assert!(matches!(err, Error::Unreachable(_)), "{err:?}");
        assert!(matches!(
            query("relative", &key, local, None, DEFAULT_TIMEOUT),
            Err(Error::Socket(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_sockets_work_on_linux() {
        let name = format!("@runeward-attribution-test-{}", std::process::id());
        let listener = server::bind(&name).expect("bind abstract");
        let key = Key::generate();
        let k2 = key.clone();
        let t = std::thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            let proc = ProcFs::new("/proc", []);
            let _ = server::handle(s, &k2, &proc, &BinarySet::default());
        });
        let local: SocketAddr = "10.1.2.3:5000".parse().expect("addr");
        let a = query(&name, &key, local, None, DEFAULT_TIMEOUT).expect("answer");
        assert_eq!(a.status, Status::NotFound);
        t.join().expect("server");
    }
}
