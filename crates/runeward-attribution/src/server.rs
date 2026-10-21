//! The helper side: answers queries on a Unix socket.

use std::io::{self, BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use crate::binaries::BinarySet;
use crate::procfs::ProcFs;
use crate::{Answer, Error, Key, MAX_LINE, Query, Status};

/// How long one client may take to send its query.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Binds `socket`: `@name` is an abstract socket (Linux only, scoped to the
/// network namespace), anything else a filesystem path.
pub fn bind(socket: &str) -> Result<UnixListener, Error> {
    match socket.strip_prefix('@') {
        Some(name) => bind_abstract(name, socket),
        None if socket.starts_with('/') => {
            UnixListener::bind(socket).map_err(|e| Error::Unreachable(format!("bind: {e}")))
        }
        None => Err(Error::Socket(socket.to_owned())),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_abstract(name: &str, socket: &str) -> Result<UnixListener, Error> {
    #[cfg(target_os = "android")]
    use std::os::android::net::SocketAddrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::linux::net::SocketAddrExt as _;
    if name.is_empty() {
        return Err(Error::Socket(socket.to_owned()));
    }
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())
        .map_err(|_| Error::Socket(socket.to_owned()))?;
    UnixListener::bind_addr(&addr).map_err(|e| Error::Unreachable(format!("bind: {e}")))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bind_abstract(_name: &str, socket: &str) -> Result<UnixListener, Error> {
    Err(Error::Socket(socket.to_owned()))
}

/// Answers one client: reads a query line, writes the authenticated
/// answer. Malformed queries get an authenticated `error` answer.
pub fn handle(
    stream: UnixStream,
    key: &Key,
    proc: &ProcFs,
    binaries: &BinarySet,
) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(READ_TIMEOUT))?;
    let mut line = Vec::new();
    BufReader::new((&stream).take(MAX_LINE as u64)).read_until(b'\n', &mut line)?;
    let answer = match serde_json::from_slice::<Query>(&line) {
        Ok(q) => proc.attribute(&q, binaries),
        Err(_) => Answer::to(&Query::default(), Status::Error, "malformed query"),
    };
    (&stream).write_all(&answer.to_wire(key))
}

/// Serves `listener` forever, one client at a time. Errors on a single
/// client are dropped; the loop only ends when `accept` fails for good.
pub fn serve(
    listener: &UnixListener,
    key: &Key,
    proc: &ProcFs,
    binaries: &BinarySet,
) -> io::Result<()> {
    loop {
        match listener.accept() {
            Ok((s, _)) => {
                let _ = handle(s, key, proc, binaries);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
