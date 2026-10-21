//! The host <-> guest agent protocol.
//!
//! The host opens one stream per operation (a vsock connection to
//! [`AGENT_PORT`], reached through the VMM's Unix socket), sends one
//! [`Kind::Request`] frame, and then exchanges frames until the guest sends
//! a terminal frame ([`Kind::Exit`], [`Kind::Result`] or [`Kind::Error`])
//! and closes the stream. Closing the stream early cancels the operation:
//! the agent kills whatever it started for it.
//!
//! A frame is a one-byte [`Kind`], a big-endian `u32` payload length (at
//! most [`MAX_FRAME`]) and the payload. Control payloads are JSON; data
//! payloads (stdin, stdout, stderr) are raw bytes.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// Bumped on incompatible changes; [`Request::Hello`] reports it.
pub const PROTOCOL_VERSION: u32 = 1;

/// The guest vsock port the agent listens on.
pub const AGENT_PORT: u32 = 10789;

/// The host vsock port the guest's egress forwarder connects to. The host
/// serves the Charter's egress proxy there; the guest has no other way out.
pub const EGRESS_PORT: u32 = 10790;

/// The well-known host CID (`VMADDR_CID_HOST`).
pub const HOST_CID: u32 = 2;

/// Where the in-guest egress forwarder listens; sandbox processes reach the
/// proxy through `HTTP(S)_PROXY` pointing here.
pub const GUEST_PROXY_ADDR: &str = "127.0.0.1:3128";

/// The largest payload a frame may carry.
pub const MAX_FRAME: usize = 1 << 20;

/// Kernel command line keys the agent reads at boot (no secrets go here:
/// the command line is world-readable inside the guest).
pub mod cmdline {
    /// The read-only image disk (`/dev/vda`).
    pub const LOWER: &str = "RUNEWARD_VM_LOWER";
    /// The workspace disk (`/dev/vdb`); absent for no persistent disk.
    pub const WORKSPACE: &str = "RUNEWARD_VM_WS";
    /// The vsock port to listen on (defaults to [`super::AGENT_PORT`]).
    pub const PORT: &str = "RUNEWARD_VM_PORT";
}

/// What a frame carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Host -> guest, first frame: a JSON [`Request`].
    Request = 0x01,
    /// Host -> guest: bytes for the process's stdin (or a file body).
    Stdin = 0x02,
    /// Host -> guest: stdin is finished.
    StdinEof = 0x03,
    /// Host -> guest: a JSON [`Resize`] for a TTY.
    Resize = 0x04,
    /// Host -> guest: a JSON [`Signal`] for the process group.
    Signal = 0x05,
    /// Guest -> host: process stdout (or file contents).
    Stdout = 0x10,
    /// Guest -> host: process stderr.
    Stderr = 0x11,
    /// Guest -> host, terminal: a JSON [`Exit`].
    Exit = 0x12,
    /// Guest -> host, terminal: a JSON [`ErrorBody`].
    Error = 0x13,
    /// Guest -> host, terminal: an operation-specific JSON result.
    Result = 0x14,
    /// Guest -> host: a JSON [`Started`] once the process runs.
    Started = 0x15,
}

impl Kind {
    /// Parses a kind byte.
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Request,
            0x02 => Self::Stdin,
            0x03 => Self::StdinEof,
            0x04 => Self::Resize,
            0x05 => Self::Signal,
            0x10 => Self::Stdout,
            0x11 => Self::Stderr,
            0x12 => Self::Exit,
            0x13 => Self::Error,
            0x14 => Self::Result,
            0x15 => Self::Started,
            _ => return None,
        })
    }

    /// Reports whether the frame ends an operation.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Exit | Self::Error | Self::Result)
    }
}

/// Encodes one frame.
pub fn encode(kind: Kind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind as u8);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Encodes a JSON control frame.
pub fn encode_json<T: Serialize>(kind: Kind, body: &T) -> Vec<u8> {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    encode(kind, &json)
}

/// Parses a frame header into its kind and payload length.
pub fn parse_header(h: [u8; 5]) -> io::Result<(Kind, usize)> {
    let kind = Kind::from_u8(h[0]).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown frame kind {:#04x}", h[0]),
        )
    })?;
    let len = u32::from_be_bytes([h[1], h[2], h[3], h[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds {MAX_FRAME}"),
        ));
    }
    Ok((kind, len))
}

/// Reads one frame; `Ok(None)` on a clean end of stream before a header.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<(Kind, Vec<u8>)>> {
    let mut h = [0u8; 5];
    let mut got = 0;
    while got < h.len() {
        match r.read(&mut h[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let (kind, len) = parse_header(h)?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((kind, payload)))
}

/// Writes one frame.
pub fn write_frame(w: &mut impl Write, kind: Kind, payload: &[u8]) -> io::Result<()> {
    w.write_all(&encode(kind, payload))?;
    w.flush()
}

/// A request: the first frame of every operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Readiness check; answered with a [`HelloResult`].
    Hello,
    /// Prepares the sandbox root and workspace (once per boot).
    Init(InitRequest),
    /// Collects isolation evidence; answered with a [`ProbeResult`].
    Probe,
    /// Starts the sandbox's main (keep-alive) process.
    Start(StartRequest),
    /// Runs a command, streaming its I/O.
    Exec(ExecSpec),
    /// A file operation.
    File(FileRequest),
    /// Reports the main process state; answered with a [`StatusResult`].
    Status,
    /// Stops every process, flushes the workspace and powers off.
    Shutdown,
}

/// How to prepare the guest's root filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InitRequest {
    /// The guest hostname.
    pub hostname: String,
    /// The workspace directory, where the workspace disk is mounted.
    pub workdir: String,
    /// Remounts the root read-only once the sandbox is staged (see
    /// [`StartRequest`]).
    pub read_only: bool,
    /// Environment every process starts with (image `ENV`, the Charter's
    /// env, proxy and CA variables). Request env is layered on top.
    pub env: BTreeMap<String, String>,
    /// The default identity (`uid[:gid]` or `name[:group]`); empty is root.
    pub user: String,
    /// Directories that stay writable when the root is read-only (the
    /// supervisor's state directory, as container engines keep a volume
    /// there).
    pub writable: Vec<String>,
}

/// The main process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StartRequest {
    /// argv of the keep-alive process.
    pub argv: Vec<String>,
    /// Identity it runs as; empty uses the [`InitRequest::user`].
    pub user: String,
}

/// A command to run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecSpec {
    /// argv, executed directly (never through a shell).
    pub argv: Vec<String>,
    /// Extra environment on top of the sandbox's.
    pub env: BTreeMap<String, String>,
    /// Working directory; empty uses the workspace.
    pub workdir: String,
    /// Identity; empty uses the sandbox default.
    pub user: String,
    /// Allocates a terminal (stdout and stderr merge into it).
    pub tty: bool,
    /// Initial terminal rows.
    pub rows: u16,
    /// Initial terminal columns.
    pub cols: u16,
}

/// A file operation, performed as `user` (never as the agent's root unless
/// `user` says so), so a link planted by the sandbox cannot redirect it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileRequest {
    /// What to do.
    pub action: FileAction,
    /// The target (absolute, or relative to the workspace).
    pub path: String,
    /// Mode for written files and created directories.
    pub mode: u32,
    /// Identity; empty uses the sandbox default.
    pub user: String,
}

/// File operations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileAction {
    /// Writes stdin to `path` (parents created), at `mode`.
    #[default]
    Write,
    /// Streams `path` back as stdout frames.
    Read,
    /// Creates `path` and its parents.
    Mkdir,
    /// Answers a [`FileStat`].
    Stat,
    /// Answers a [`Vec<DirEntry>`].
    List,
    /// Extracts a tar from stdin into the directory `path`.
    TarIn,
    /// Streams a tar of the directory `path`'s contents (relative names).
    TarOut,
}

/// A terminal size change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resize {
    /// Rows.
    pub rows: u16,
    /// Columns.
    pub cols: u16,
}

/// A signal for the process group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// The signal number (`9` kills).
    pub signal: i32,
}

/// The process is running.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Started {
    /// Its guest pid.
    pub pid: i32,
}

/// How a process ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exit {
    /// The exit status, `-1` when killed by a signal.
    pub code: i32,
    /// The terminating signal, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
}

/// A failed operation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What went wrong.
    pub message: String,
}

/// The answer to [`Request::Hello`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloResult {
    /// [`PROTOCOL_VERSION`] of the agent.
    pub protocol: u32,
    /// The agent's version.
    pub version: String,
    /// Whether [`Request::Init`] already ran this boot.
    pub initialized: bool,
}

/// The answer to [`Request::Probe`]: the same `@@section` text the shell
/// probe prints, collected by the agent itself so images without a shell
/// still produce evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeResult {
    /// The probe sections.
    pub output: String,
}

/// The answer to [`Request::Status`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusResult {
    /// `none` (not started), `running` or `exited`.
    pub main: String,
    /// The main process's exit, once it exited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<Exit>,
}

/// The answer to [`FileAction::Stat`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileStat {
    /// `file`, `dir`, `symlink` or `other`.
    pub kind: String,
    /// Size in bytes.
    pub size: u64,
    /// Permission bits.
    pub mode: u32,
    /// Owner uid.
    pub uid: u32,
    /// Owner gid.
    pub gid: u32,
    /// Modification time (seconds since the epoch).
    pub mtime: i64,
}

/// One entry of [`FileAction::List`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DirEntry {
    /// The entry name.
    pub name: String,
    /// Its metadata (not following links).
    pub stat: FileStat,
}

/// Configuration for the libkrun helper (`runeward-krun <config.json>`).
///
/// Shared here so the backend writes exactly what the helper reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct KrunConfig {
    /// The libkrun library to load (`libkrun.so.1`, a path, ...).
    pub library: String,
    /// vCPUs.
    pub vcpus: u8,
    /// Guest RAM in MiB.
    pub ram_mib: u32,
    /// The guest agent binary, served as the guest's `/init.krun`.
    pub agent: String,
    /// The read-only image disk (`/dev/vda` in the guest).
    pub rootfs: String,
    /// The workspace disk (`/dev/vdb`), if any.
    pub workspace: String,
    /// Host Unix socket the host connects to for the agent's vsock port.
    pub agent_socket: String,
    /// Host Unix socket the guest's egress connections arrive on.
    pub egress_socket: String,
    /// Kernel command line variables for the agent (`KEY=value`).
    pub env: Vec<String>,
    /// Guest console output file.
    pub console: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, Kind::Stdout, b"hello").expect("write");
        buf.extend(encode_json(
            Kind::Exit,
            &Exit {
                code: 3,
                signal: None,
            },
        ));
        let mut r = buf.as_slice();
        let (k, p) = read_frame(&mut r).expect("read").expect("frame");
        assert_eq!((k, p.as_slice()), (Kind::Stdout, &b"hello"[..]));
        let (k, p) = read_frame(&mut r).expect("read").expect("frame");
        assert_eq!(k, Kind::Exit);
        let e: Exit = serde_json::from_slice(&p).expect("json");
        assert_eq!(e.code, 3);
        assert!(read_frame(&mut r).expect("eof").is_none());
    }

    #[test]
    fn oversized_and_unknown_frames_are_refused() {
        let mut h = [0x10, 0, 0, 0, 0];
        h[1..].copy_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        assert!(parse_header(h).is_err());
        assert!(parse_header([0x7f, 0, 0, 0, 0]).is_err());
        let mut short: &[u8] = &[0x10, 0, 0];
        assert!(read_frame(&mut short).is_err());
    }

    #[test]
    fn requests_are_tagged_json() {
        let r = Request::File(FileRequest {
            action: FileAction::TarOut,
            path: "/workspace".into(),
            ..FileRequest::default()
        });
        let j = serde_json::to_string(&r).expect("json");
        assert!(j.contains(r#""op":"file""#), "{j}");
        assert!(j.contains(r#""action":"tar-out""#), "{j}");
        let back: Request = serde_json::from_str(&j).expect("parse");
        assert_eq!(back, r);
        let hello: Request = serde_json::from_str(r#"{"op":"hello"}"#).expect("hello");
        assert_eq!(hello, Request::Hello);
        assert!(Kind::Exit.is_terminal() && !Kind::Stdout.is_terminal());
    }
}
