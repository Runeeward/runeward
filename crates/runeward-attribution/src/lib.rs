//! Binary attribution for egress: which executable inside a sandbox holds
//! the TCP connection the egress broker just accepted.
//!
//! A Charter `[[endpoint]]` may list `binaries`, the executables allowed to
//! use it. The broker runs outside the sandbox and only sees a TCP peer, so
//! it asks the in-sandbox supervisor, which can see the sandbox's processes:
//!
//! 1. The broker accepts a connection for an endpoint with `binaries` and,
//!    before it forwards a byte or attaches a credential, sends a [`Query`]
//!    naming the connection's sandbox-side address (`local`) and the address
//!    the sandbox dialled (`remote`), plus a fresh random nonce.
//! 2. The supervisor's attribution helper finds the socket in
//!    `/proc/net/tcp{,6}` (the sandbox's network namespace), finds every
//!    process in the sandbox's PID namespace holding that socket
//!    (`/proc/<pid>/task/<tid>/fd`), and identifies each holder's executable
//!    by the device and inode of `/proc/<pid>/exe`, compared against the
//!    Charter's binaries as they were when the sandbox started
//!    ([`binaries::BinarySet`]).
//! 3. It answers with an [`Answer`] authenticated by HMAC-SHA256 under a
//!    per-sandbox [`Key`] that only the control plane, the broker and the
//!    helper hold. The broker checks the MAC, the nonce and the echoed
//!    addresses, then [`evaluate`]s the answer against the endpoint's list.
//!
//! # What "binary" means
//!
//! The executable file the kernel is running for the process: the target of
//! `/proc/<pid>/exe`, matched by file identity, so a listed symlink
//! (`/usr/bin/python3`) matches the file it points to and a copy of an
//! allowed binary elsewhere does not. For an interpreter the binary is the
//! interpreter: `python3 script.py` and a `#!/usr/bin/env python3` script
//! are both `python3`, so listing an interpreter allows every program it
//! runs. Scripts are never identified by name; argv is chosen by the caller
//! and proves nothing.
//!
//! # Threat model
//!
//! The agent is untrusted and runs as the same uid as the helper, but it
//! cannot forge an answer: the key is read by the helper from a root-only
//! file before it drops privileges and is never in the agent's environment,
//! files or reach (the helper is non-dumpable and the agent's seccomp filter
//! denies `ptrace`, `process_vm_*` and `pidfd_getfd`). The channel is a Unix
//! socket in the sandbox's network namespace, which the broker shares; the
//! agent can connect to it or squat its name if the helper dies, but every
//! answer it could produce fails the MAC check, and nonces stop replay.
//!
//! Everything that goes wrong fails closed: no answer, a bad MAC, a socket
//! nobody holds, a holder the helper cannot inspect (another uid, a
//! non-dumpable process) or a holder that is not allowed all deny. When one
//! socket is held by several processes, every holder must be allowed.
//!
//! Residual risks, documented in `docs/security-model.md`:
//!
//! - Binary identity is not code identity. An allowed interpreter runs any
//!   script, and an allowed dynamically linked binary can be made to load
//!   attacker code (`LD_PRELOAD`, plugins, extensions). List static,
//!   single-purpose binaries.
//! - Attribution happens once per connection, when it is accepted. A holder
//!   that later passes the socket to another process (`SCM_RIGHTS`,
//!   inheritance) is not re-checked.
//! - Killing the helper (same uid) only denies the sandbox's own
//!   binary-restricted endpoints.

#[cfg(unix)]
pub mod binaries;
#[cfg(unix)]
pub mod client;
#[cfg(unix)]
pub mod procfs;
#[cfg(unix)]
pub mod server;

/// How long the broker waits for an answer by default.
pub const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

use std::net::SocketAddr;

use hmac::{Hmac, KeyInit, Mac};
use rand::TryRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// The `schema` of every [`Query`] and [`Answer`].
pub const SCHEMA: &str = "runeward.attribution.v1";

/// The socket the helper listens on by default: an abstract Unix socket
/// (leading `@`), scoped to the sandbox's network namespace.
pub const DEFAULT_SOCKET: &str = "@runeward-attribution";

/// Largest query or answer line accepted, in bytes.
pub const MAX_LINE: usize = 64 * 1024;

/// Most holders reported for one socket.
pub const MAX_HOLDERS: usize = 32;

/// Length of a [`Key`] in bytes.
pub const KEY_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// The per-sandbox key authenticating answers. Never printed by `Debug`,
/// wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(Zeroizing<Vec<u8>>);

impl Key {
    /// A fresh random key.
    pub fn generate() -> Self {
        let mut b = Zeroizing::new(vec![0u8; KEY_LEN]);
        rand::rngs::SysRng
            .try_fill_bytes(&mut b)
            .expect("system random source");
        Self(b)
    }

    /// Parses a key from lowercase or uppercase hex.
    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let b = Zeroizing::new(hex::decode(s.trim()).map_err(|_| Error::Key)?);
        if b.len() != KEY_LEN {
            return Err(Error::Key);
        }
        Ok(Self(b))
    }

    /// The key as hex. The returned string is wiped on drop.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(&*self.0))
    }

    fn hmac(&self) -> HmacSha256 {
        // HMAC accepts keys of any length, so this cannot fail.
        <HmacSha256 as KeyInit>::new_from_slice(&self.0)
            .unwrap_or_else(|_| unreachable!("HMAC accepts any key length"))
    }

    /// The MAC (hex) of one answer line, domain-separated by [`SCHEMA`].
    pub fn mac(&self, line: &[u8]) -> String {
        let mut m = self.hmac();
        m.update(SCHEMA.as_bytes());
        m.update(b"\n");
        m.update(line);
        hex::encode(m.finalize().into_bytes())
    }

    /// Checks a MAC from [`Key::mac`] in constant time.
    pub fn verify(&self, line: &[u8], mac_hex: &str) -> bool {
        let Ok(tag) = hex::decode(mac_hex.trim()) else {
            return false;
        };
        let mut m = self.hmac();
        m.update(SCHEMA.as_bytes());
        m.update(b"\n");
        m.update(line);
        m.verify_slice(&tag).is_ok()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(«redacted»)")
    }
}

/// Errors from this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// A key is not 32 bytes of hex.
    #[error("attribution key must be {KEY_LEN} bytes of hex")]
    Key,
    /// The helper could not be reached or did not answer in time.
    #[error("attribution helper unreachable: {0}")]
    Unreachable(String),
    /// The answer was malformed, unauthenticated or for another query.
    #[error("attribution answer rejected: {0}")]
    Rejected(String),
    /// The socket name is not usable on this platform.
    #[error("attribution socket {0:?} is not supported here")]
    Socket(String),
}

/// A question from the broker: who holds the TCP socket whose local address
/// is `local` (and, when set, whose peer is `remote`)?
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Query {
    pub schema: String,
    /// Random, single use; echoed in the answer.
    pub nonce: String,
    /// The sandbox-side address of the connection (`ip:port`).
    pub local: String,
    /// The address the sandbox dialled (`ip:port`); empty matches any.
    pub remote: String,
}

impl Query {
    /// A query with a fresh nonce.
    pub fn new(local: SocketAddr, remote: Option<SocketAddr>) -> Self {
        let mut n = [0u8; 16];
        rand::rngs::SysRng
            .try_fill_bytes(&mut n)
            .expect("system random source");
        Self {
            schema: SCHEMA.into(),
            nonce: hex::encode(n),
            local: local.to_string(),
            remote: remote.map(|r| r.to_string()).unwrap_or_default(),
        }
    }
}

/// The outcome class of an [`Answer`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Every holder of the socket was identified.
    Attributed,
    /// No socket matched, or nobody in the sandbox holds it.
    #[default]
    NotFound,
    /// The socket has holders the helper could not inspect.
    Incomplete,
    /// The query was malformed or the lookup failed.
    Error,
}

impl Status {
    /// The wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attributed => "attributed",
            Self::NotFound => "not-found",
            Self::Incomplete => "incomplete",
            Self::Error => "error",
        }
    }
}

/// A process holding the socket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Holder {
    pub pid: u32,
    /// The executable path as the kernel reports it (`/proc/<pid>/exe`).
    pub exe: String,
    /// The Charter binaries that are the same file as `exe`.
    pub matches: Vec<String>,
}

/// The helper's answer. On the wire it is one JSON line followed by one
/// line holding its MAC.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Answer {
    pub schema: String,
    pub nonce: String,
    pub local: String,
    pub remote: String,
    pub status: Status,
    pub holders: Vec<Holder>,
    /// Why the status is not `attributed` (no secrets, no paths outside the
    /// sandbox).
    pub detail: String,
}

impl Answer {
    /// An answer to `q` with `status` and no holders.
    pub fn to(q: &Query, status: Status, detail: impl Into<String>) -> Self {
        Self {
            schema: SCHEMA.into(),
            nonce: q.nonce.clone(),
            local: q.local.clone(),
            remote: q.remote.clone(),
            status,
            holders: Vec::new(),
            detail: detail.into(),
        }
    }

    /// The two wire lines: the answer and its MAC, each newline-terminated.
    pub fn to_wire(&self, key: &Key) -> Vec<u8> {
        let line = serde_json::to_vec(self).unwrap_or_default();
        let mut out = Vec::with_capacity(line.len() + 66);
        out.extend_from_slice(&line);
        out.push(b'\n');
        out.extend_from_slice(key.mac(&line).as_bytes());
        out.push(b'\n');
        out
    }

    /// Parses and authenticates the two wire lines, and checks the answer
    /// is for `q`.
    pub fn from_wire(buf: &[u8], key: &Key, q: &Query) -> Result<Self, Error> {
        let text = std::str::from_utf8(buf).map_err(|_| Error::Rejected("not UTF-8".into()))?;
        let mut lines = text.split('\n');
        let line = lines.next().unwrap_or_default();
        let mac = lines.next().unwrap_or_default();
        if line.is_empty() || mac.is_empty() {
            return Err(Error::Rejected("truncated".into()));
        }
        if !key.verify(line.as_bytes(), mac) {
            return Err(Error::Rejected("bad MAC".into()));
        }
        let a: Self = serde_json::from_str(line)
            .map_err(|e| Error::Rejected(format!("malformed answer: {e}")))?;
        if a.schema != SCHEMA || a.nonce != q.nonce || a.local != q.local || a.remote != q.remote {
            return Err(Error::Rejected("answer is for a different query".into()));
        }
        Ok(a)
    }
}

/// The broker's decision about one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Every holder is an allowed binary.
    pub allowed: bool,
    /// The attributed executable(s), comma-separated; empty when unknown.
    pub binary: String,
    /// Why, for the decision log.
    pub reason: String,
}

/// Decides whether a connection whose attribution is `answer` may use an
/// endpoint that allows `allowed` binaries. Anything but a complete
/// attribution where every holder matches an allowed binary is refused.
pub fn evaluate(allowed: &[String], answer: Result<&Answer, &Error>) -> Outcome {
    let a = match answer {
        Ok(a) => a,
        Err(e) => {
            return Outcome {
                allowed: false,
                binary: String::new(),
                reason: format!("binary unknown: {e}"),
            };
        }
    };
    let mut exes: Vec<&str> = a.holders.iter().map(|h| h.exe.as_str()).collect();
    exes.sort_unstable();
    exes.dedup();
    let binary = exes.join(",");
    if a.status != Status::Attributed || a.holders.is_empty() {
        let detail = if a.detail.is_empty() {
            a.status.as_str().to_owned()
        } else {
            format!("{}: {}", a.status.as_str(), a.detail)
        };
        return Outcome {
            allowed: false,
            binary,
            reason: format!("binary unknown ({detail})"),
        };
    }
    if let Some(h) = a
        .holders
        .iter()
        .find(|h| !h.matches.iter().any(|m| allowed.contains(m)))
    {
        return Outcome {
            allowed: false,
            binary,
            reason: format!("binary {:?} is not allowed for this endpoint", h.exe),
        };
    }
    Outcome {
        allowed: true,
        binary,
        reason: "binary allowed".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> Query {
        Query::new(
            "172.17.0.2:40000".parse().expect("addr"),
            Some("93.184.216.34:443".parse().expect("addr")),
        )
    }

    fn holder(exe: &str, matches: &[&str]) -> Holder {
        Holder {
            pid: 7,
            exe: exe.into(),
            matches: matches.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn keys_round_trip_and_redact() {
        let k = Key::generate();
        assert_eq!(Key::from_hex(&k.to_hex()).expect("hex"), k);
        assert_eq!(format!("{k:?}"), "Key(«redacted»)");
        assert_eq!(Key::from_hex("abcd"), Err(Error::Key));
        assert_eq!(Key::from_hex("zz"), Err(Error::Key));
        assert_ne!(Key::generate(), k);
    }

    #[test]
    fn wire_answers_are_authenticated_and_bound_to_the_query() {
        let key = Key::generate();
        let query = q();
        let mut a = Answer::to(&query, Status::Attributed, "");
        a.holders.push(holder("/usr/bin/curl", &["/usr/bin/curl"]));
        let wire = a.to_wire(&key);
        assert_eq!(Answer::from_wire(&wire, &key, &query), Ok(a.clone()));

        // Another key, a tampered body, another query, truncation.
        let other = Key::generate();
        assert!(matches!(
            Answer::from_wire(&wire, &other, &query),
            Err(Error::Rejected(m)) if m == "bad MAC"
        ));
        let tampered = String::from_utf8(wire.clone())
            .expect("utf8")
            .replace("curl", "wget");
        assert!(Answer::from_wire(tampered.as_bytes(), &key, &query).is_err());
        let replay = q();
        assert!(matches!(
            Answer::from_wire(&wire, &key, &replay),
            Err(Error::Rejected(m)) if m.contains("different query")
        ));
        assert!(Answer::from_wire(&wire[..10], &key, &query).is_err());
        assert!(Answer::from_wire(b"", &key, &query).is_err());
    }

    #[test]
    fn evaluate_requires_every_holder_to_match() {
        let allowed = vec!["/usr/bin/curl".to_owned(), "/usr/bin/gh".to_owned()];
        let query = q();
        let mut a = Answer::to(&query, Status::Attributed, "");
        a.holders.push(holder("/usr/bin/curl", &["/usr/bin/curl"]));
        let o = evaluate(&allowed, Ok(&a));
        assert!(o.allowed, "{o:?}");
        assert_eq!(o.binary, "/usr/bin/curl");

        // A second holder that is not allowed poisons the connection.
        a.holders
            .push(holder("/usr/bin/python3.11", &["/usr/bin/python3"]));
        let o = evaluate(&allowed, Ok(&a));
        assert!(!o.allowed);
        assert_eq!(o.binary, "/usr/bin/curl,/usr/bin/python3.11");
        assert!(o.reason.contains("python3.11"), "{}", o.reason);

        // Matching another endpoint's binary is not enough.
        a.holders = vec![holder("/usr/bin/python3.11", &["/usr/bin/python3"])];
        assert!(!evaluate(&allowed, Ok(&a)).allowed);
        // A holder no Charter binary matches.
        a.holders = vec![holder("/tmp/curl", &[])];
        assert!(!evaluate(&allowed, Ok(&a)).allowed);
    }

    #[test]
    fn evaluate_fails_closed() {
        let allowed = vec!["/usr/bin/curl".to_owned()];
        let query = q();
        for status in [Status::NotFound, Status::Incomplete, Status::Error] {
            let mut a = Answer::to(&query, status, "why");
            a.holders.push(holder("/usr/bin/curl", &["/usr/bin/curl"]));
            let o = evaluate(&allowed, Ok(&a));
            assert!(!o.allowed, "{status:?}");
            assert!(o.reason.contains(status.as_str()), "{}", o.reason);
        }
        let empty = Answer::to(&query, Status::Attributed, "");
        assert!(!evaluate(&allowed, Ok(&empty)).allowed);
        let e = Error::Unreachable("connection refused".into());
        let o = evaluate(&allowed, Err(&e));
        assert!(!o.allowed && o.binary.is_empty());
        assert!(o.reason.contains("unreachable"), "{}", o.reason);
    }
}
