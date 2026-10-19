//! The hash-chained JSON Lines ledger.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::LedgerError;
use crate::gojson::{self, go_struct};
use crate::gotime::{self, Time};
use crate::sign::Signer;

/// A single audited action. Callers fill in the descriptive fields;
/// [`Ledger::append`] assigns `seq`, `time` (when zero), `prev_hash` and
/// `hash`.
///
/// Field order and the omitted-when-empty fields mirror the Go JSON encoding,
/// so records written by either implementation are byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub seq: i64,
    /// Kept in the offset it was recorded in; hashing uses UTC.
    #[serde(serialize_with = "gotime::serialize")]
    pub time: Time,

    pub session_id: String,
    pub sandbox: String,
    pub profile: String,
    /// The action surface, e.g. "shell", "file.read", "net", "approval".
    pub tool: String,
    /// The primary argument: the command, path, or hostname.
    pub action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    pub verdict: String,

    pub exit_code: i64,
    pub duration_ms: i64,

    /// Sorted by key, both on the wire and when hashing, so the record hash
    /// is independent of insertion order.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,

    pub redacted: bool,
    /// SHA-256 hex of the original payload, recorded when `redacted` is true
    /// so plaintext can later be proven to match.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub payload_hash: String,

    /// Empty for the genesis record.
    pub prev_hash: String,
    pub hash: String,

    /// Set when the ledger has a [`Signer`]. Both are excluded from the
    /// record hash so signing does not alter the chain.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sig: String,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            seq: 0,
            time: gotime::zero(),
            session_id: String::new(),
            sandbox: String::new(),
            profile: String::new(),
            tool: String::new(),
            action: String::new(),
            args: Vec::new(),
            verdict: String::new(),
            exit_code: 0,
            duration_ms: 0,
            meta: BTreeMap::new(),
            redacted: false,
            payload_hash: String::new(),
            prev_hash: String::new(),
            hash: String::new(),
            key_id: String::new(),
            sig: String::new(),
        }
    }
}

go_struct!(Event {
    "seq" => seq: Int,
    "time" => time: Time,
    "session_id" => session_id: Str,
    "sandbox" => sandbox: Str,
    "profile" => profile: Str,
    "tool" => tool: Str,
    "action" => action: Str,
    "args" => args: Strings,
    "verdict" => verdict: Str,
    "exit_code" => exit_code: Int,
    "duration_ms" => duration_ms: Int,
    "meta" => meta: Meta,
    "redacted" => redacted: Bool,
    "payload_hash" => payload_hash: Str,
    "prev_hash" => prev_hash: Str,
    "hash" => hash: Str,
    "key_id" => key_id: Str,
    "sig" => sig: Str,
});

impl Event {
    /// Encodes the event as one compact JSON line body (no newline), exactly
    /// as Go's `json.Marshal` would.
    pub fn to_json(&self) -> serde_json::Result<Vec<u8>> {
        gojson::marshal(self)
    }

    /// Recomputes the chain hash for this record from its current fields.
    pub fn compute_hash(&self) -> String {
        hash_event(self)
    }
}

/// An append-only, hash-chained audit log backed by a JSON Lines file.
///
/// Every record embeds the SHA-256 hash of the previous one, so any edit,
/// insertion or reorder breaks the chain and is caught by [`Ledger::verify`].
/// [`Ledger::open`] takes an advisory file lock so only one process writes a
/// given ledger. Methods take `&self` and serialize internally, so a ledger
/// can be shared across threads or tasks behind an `Arc`; they do blocking
/// file I/O, so async callers should use `spawn_blocking`.
#[derive(Debug)]
pub struct Ledger {
    path: PathBuf,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    file: Option<File>,
    /// Hash of the most recent record, "" when empty.
    tip_hash: String,
    seq: i64,
    signer: Option<Signer>,
}

impl Ledger {
    /// Opens or creates the ledger file at path and recovers the chain tip
    /// and sequence number so appends continue an existing chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        let mut opts = OpenOptions::new();
        opts.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&path).map_err(|source| LedgerError::Open {
            path: path.clone(),
            source,
        })?;
        // A second process appending concurrently would interleave sequence
        // numbers and break the chain.
        lock_file(&file, &path)?;

        let recs = read_all(&path)?;
        let (tip_hash, seq) = recs
            .last()
            .map(|tip| (tip.hash.clone(), tip.seq))
            .unwrap_or_default();
        Ok(Self {
            path,
            inner: Mutex::new(Inner {
                file: Some(file),
                tip_hash,
                seq,
                signer: None,
            }),
        })
    }

    /// The ledger file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attaches a signer so subsequent appends sign each record; `None`
    /// disables signing.
    pub fn set_signer(&self, signer: Option<Signer>) {
        self.lock().signer = signer;
    }

    /// Releases the file handle (and with it the writer lock). Later appends
    /// fail; reads keep working. Closing twice is a no-op.
    pub fn close(&self) {
        self.lock().file = None;
    }

    /// Writes ev as one JSON line with the chain fields set, fsyncs, and
    /// returns the stored event.
    pub fn append(&self, mut ev: Event) -> Result<Event, LedgerError> {
        let mut inner = self.lock();
        let Inner {
            file,
            tip_hash,
            seq,
            signer,
        } = &mut *inner;
        let Some(file) = file.as_mut() else {
            return Err(LedgerError::Closed);
        };

        ev.seq = *seq + 1;
        if gotime::is_zero(&ev.time) {
            ev.time = gotime::now();
        }
        ev.prev_hash = tip_hash.clone();
        ev.hash = hash_event(&ev);
        if let Some(signer) = signer {
            ev.key_id = signer.key_id().to_owned();
            ev.sig = signer.sign(&ev.hash);
        }

        let mut line = ev.to_json().map_err(|source| LedgerError::Marshal {
            seq: ev.seq,
            source,
        })?;
        line.push(b'\n');
        file.write_all(&line).map_err(|source| LedgerError::Write {
            seq: ev.seq,
            source,
        })?;
        file.sync_all().map_err(|source| LedgerError::Sync {
            seq: ev.seq,
            source,
        })?;

        *seq = ev.seq;
        tip_hash.clone_from(&ev.hash);
        Ok(ev)
    }

    /// Returns every event in the ledger, in write order.
    pub fn records(&self) -> Result<Vec<Event>, LedgerError> {
        let _guard = self.lock();
        read_all(&self.path)
    }

    /// Recomputes every record's hash and chain linkage, returning an error
    /// identifying the first bad record.
    pub fn verify(&self) -> Result<(), LedgerError> {
        let recs = self.records()?;
        let mut prev = "";
        for (i, ev) in recs.iter().enumerate() {
            check_link(i, ev, prev)?;
            prev = &ev.hash;
        }
        Ok(())
    }

    /// Returns the ordered events for a single session.
    pub fn replay(&self, session_id: &str) -> Result<Vec<Event>, LedgerError> {
        let mut recs = self.records()?;
        recs.retain(|ev| ev.session_id == session_id);
        Ok(recs)
    }

    /// Writes a pretty-printed JSON array of a session's events to w. An
    /// empty session id exports everything.
    pub fn export<W: io::Write>(&self, w: W, session_id: &str) -> Result<(), LedgerError> {
        let events = self.select(session_id)?;
        gojson::encode_indent(w, &events).map_err(LedgerError::Export)
    }

    /// Reads the records for a session, or all of them when `session_id` is
    /// empty. `None` stands for Go's nil slice: a full export of an empty
    /// ledger encodes as `null`, a session export as `[]`.
    pub(crate) fn select(&self, session_id: &str) -> Result<Option<Vec<Event>>, LedgerError> {
        let mut recs = self.records()?;
        if session_id.is_empty() {
            return Ok((!recs.is_empty()).then_some(recs));
        }
        recs.retain(|ev| ev.session_id == session_id);
        Ok(Some(recs))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic mid-append cannot leave the chain state half-updated (it
        // is assigned only after a successful write), so poisoning is safe
        // to ignore.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Checks record i's sequence number, link to `prev` and stored hash.
pub(crate) fn check_link(i: usize, ev: &Event, prev: &str) -> Result<(), LedgerError> {
    let index = i + 1;
    if usize::try_from(ev.seq).ok() != Some(index) {
        return Err(LedgerError::OutOfOrder { index, seq: ev.seq });
    }
    if ev.prev_hash != prev {
        return Err(LedgerError::BrokenChain {
            seq: ev.seq,
            prev_hash: ev.prev_hash.clone(),
            expected: prev.to_owned(),
        });
    }
    let want = hash_event(ev);
    if ev.hash != want {
        return Err(LedgerError::Tampered {
            seq: ev.seq,
            stored: ev.hash.clone(),
            recomputed: want,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn lock_file(file: &File, path: &Path) -> Result<(), LedgerError> {
    // Non-blocking: a second writer would silently break the chain, so fail
    // fast at startup instead. Released when the file is closed.
    fs2::FileExt::try_lock_exclusive(file).map_err(|source| LedgerError::Locked {
        path: path.to_path_buf(),
        source,
    })
}

/// The single-writer guarantee is only enforced on unix, as in Go: Windows
/// locks are mandatory and would block the reader handles the ledger opens.
#[cfg(not(unix))]
fn lock_file(_file: &File, _path: &Path) -> Result<(), LedgerError> {
    Ok(())
}

/// Returns a copy of ev with payload fields replaced by their
/// `sha256:<hex>` digests and `redacted` set. `payload_hash` records the
/// hash of the original payload so plaintext can later be proven to match
/// without touching the ledger. With no sensitive values the whole payload
/// (action, args, meta values) is redacted; otherwise only strings exactly
/// equal to a sensitive value are. Structural fields are always preserved.
pub fn redact<S: AsRef<str>>(mut ev: Event, sensitive: &[S]) -> Event {
    ev.payload_hash = hash_payload(&ev);
    ev.redacted = true;

    let hit = |s: &str| sensitive.is_empty() || sensitive.iter().any(|x| x.as_ref() == s);
    if hit(&ev.action) {
        ev.action = redact_string(&ev.action);
    }
    for a in &mut ev.args {
        if hit(a) {
            *a = redact_string(a);
        }
    }
    for v in ev.meta.values_mut() {
        if hit(v) {
            *v = redact_string(v);
        }
    }
    ev
}

/// Replaces a non-empty string with its `sha256:<hex>` digest.
pub(crate) fn redact_string(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    format!("sha256:{}", hex::encode(Sha256::digest(s.as_bytes())))
}

/// The SHA-256 record hash over the event's core fields plus `prev_hash`, in
/// a fixed order. Each field is length-prefixed so no value can imitate
/// another; meta keys are sorted; `hash`, `sig` and `key_id` are excluded.
pub(crate) fn hash_event(ev: &Event) -> String {
    let mut h = Sha256::new();
    put_int(&mut h, ev.seq);
    put_str(&mut h, &gotime::format_utc(&ev.time));
    put_str(&mut h, &ev.session_id);
    put_str(&mut h, &ev.sandbox);
    put_str(&mut h, &ev.profile);
    put_str(&mut h, &ev.tool);
    put_str(&mut h, &ev.action);
    put_strs(&mut h, &ev.args);
    put_str(&mut h, &ev.verdict);
    put_int(&mut h, ev.exit_code);
    put_int(&mut h, ev.duration_ms);
    put_meta(&mut h, &ev.meta);
    put_str(&mut h, if ev.redacted { "1" } else { "0" });
    put_str(&mut h, &ev.payload_hash);
    put_str(&mut h, &ev.prev_hash);
    hex::encode(h.finalize())
}

/// Hashes just the payload (action, args, sorted meta) with the same
/// encoding as [`hash_event`].
pub(crate) fn hash_payload(ev: &Event) -> String {
    let mut h = Sha256::new();
    put_str(&mut h, &ev.action);
    put_strs(&mut h, &ev.args);
    put_meta(&mut h, &ev.meta);
    hex::encode(h.finalize())
}

fn put_strs(h: &mut Sha256, v: &[String]) {
    put_len(h, v.len());
    for s in v {
        put_str(h, s);
    }
}

/// BTreeMap iterates in byte order of the keys, matching Go's sort.Strings.
fn put_meta(h: &mut Sha256, m: &BTreeMap<String, String>) {
    put_len(h, m.len());
    for (k, v) in m {
        put_str(h, k);
        put_str(h, v);
    }
}

/// Writes an 8-byte big-endian length prefix followed by the bytes.
fn put_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

fn put_int(h: &mut Sha256, i: i64) {
    put_str(h, &i.to_string());
}

fn put_len(h: &mut Sha256, n: usize) {
    put_str(h, &n.to_string());
}

/// Parses every record from path in order. A missing file is an empty
/// ledger; empty lines are skipped.
pub(crate) fn read_all(path: &Path) -> Result<Vec<Event>, LedgerError> {
    let read_err = |source| LedgerError::Read {
        path: path.to_path_buf(),
        source,
    };
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(read_err(e)),
    };
    let mut r = BufReader::new(file);
    let mut events = Vec::new();
    let mut buf = Vec::new();
    let mut line = 0;
    loop {
        line += 1;
        buf.clear();
        let n = r.read_until(b'\n', &mut buf).map_err(read_err)?;
        if n == 0 {
            break;
        }
        let trimmed = trim_trailing_newline(&buf);
        if !trimmed.is_empty() {
            let ev = serde_json::from_slice(trimmed).map_err(|source| LedgerError::Parse {
                path: path.to_path_buf(),
                line,
                source,
            })?;
            events.push(ev);
        }
    }
    Ok(events)
}

/// Drops a single trailing "\n" or "\r\n".
fn trim_trailing_newline(b: &[u8]) -> &[u8] {
    match b {
        [rest @ .., b'\r', b'\n'] | [rest @ .., b'\n'] => rest,
        _ => b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn new_ledger() -> (Ledger, tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let l = Ledger::open(&path).expect("open");
        (l, dir, path)
    }

    fn append_sample(l: &Ledger, session: &str, tool: &str, action: &str) -> Event {
        l.append(Event {
            session_id: session.into(),
            sandbox: "sbx-1".into(),
            profile: "default".into(),
            tool: tool.into(),
            action: action.into(),
            verdict: "allow".into(),
            meta: [("z".into(), "last".into()), ("a".into(), "first".into())].into(),
            ..Event::default()
        })
        .expect("append")
    }

    #[test]
    fn append_chains_and_verifies() {
        let (l, _dir, _) = new_ledger();
        let e1 = append_sample(&l, "s1", "shell", "ls -la");
        let e2 = append_sample(&l, "s1", "file.read", "/etc/hosts");
        let e3 = append_sample(&l, "s1", "net", "example.com");
        assert_eq!((e1.seq, e2.seq, e3.seq), (1, 2, 3));
        assert_eq!(e1.prev_hash, "");
        assert_eq!(e2.prev_hash, e1.hash);
        assert_eq!(e3.prev_hash, e2.hash);
        assert!(
            !gotime::is_zero(&e1.time),
            "append should set time when zero"
        );
        l.verify().expect("verify intact chain");
    }

    #[test]
    fn verify_detects_tampering() {
        let (l, _dir, path) = new_ledger();
        for a in ["echo one", "echo two", "echo three"] {
            append_sample(&l, "s1", "shell", a);
        }
        l.verify().expect("precondition");

        // Rewrite the second record's action, leaving its stored hash.
        let text = std::fs::read_to_string(&path).expect("read");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut ev: Event = serde_json::from_str(&lines[1]).expect("parse");
        ev.action = "echo TAMPERED".into();
        lines[1] = String::from_utf8(ev.to_json().expect("marshal")).expect("utf8");
        std::fs::write(&path, lines.join("\n") + "\n").expect("write");

        let err = l
            .verify()
            .expect_err("tampered record must fail")
            .to_string();
        assert!(err.contains("seq 2") && err.contains("tampered"), "{err}");
    }

    #[test]
    fn reopen_continues_chain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let l1 = Ledger::open(&path).expect("open 1");
        append_sample(&l1, "s1", "shell", "first");
        let b = append_sample(&l1, "s1", "shell", "second");
        l1.close();
        drop(l1);

        let l2 = Ledger::open(&path).expect("open 2");
        let c = l2
            .append(Event {
                session_id: "s1".into(),
                tool: "shell".into(),
                action: "third".into(),
                ..Event::default()
            })
            .expect("append after reopen");
        assert_eq!(c.seq, 3);
        assert_eq!(c.prev_hash, b.hash);
        l2.verify().expect("verify after reopen");
    }

    #[test]
    fn second_writer_is_locked_out() {
        let (l, _dir, path) = new_ledger();
        let err = Ledger::open(&path).expect_err("second open must fail");
        assert!(matches!(err, LedgerError::Locked { .. }), "{err}");
        l.close();
        Ledger::open(&path).expect("open after close");
    }

    #[test]
    fn append_after_close_fails() {
        let (l, _dir, _) = new_ledger();
        l.close();
        l.close();
        assert!(matches!(
            l.append(Event::default()),
            Err(LedgerError::Closed)
        ));
        assert!(l.records().expect("records").is_empty());
    }

    #[test]
    fn replay_filters_by_session() {
        let (l, _dir, _) = new_ledger();
        for (s, a) in [
            ("s1", "a"),
            ("s2", "b"),
            ("s1", "c"),
            ("s2", "d"),
            ("s1", "e"),
        ] {
            append_sample(&l, s, "shell", a);
        }
        let got = l.replay("s1").expect("replay");
        let actions: Vec<_> = got.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, ["a", "c", "e"]);
        assert!(got.iter().all(|e| e.session_id == "s1"));
        assert!(got.windows(2).all(|w| w[0].seq < w[1].seq));
    }

    #[test]
    fn export_produces_valid_json() {
        let (l, _dir, _) = new_ledger();
        let mut buf = Vec::new();
        l.export(&mut buf, "").expect("export empty");
        assert_eq!(buf, b"null\n", "Go encodes a nil slice as null");
        buf.clear();
        l.export(&mut buf, "s1").expect("export empty session");
        assert_eq!(buf, b"[]\n");

        append_sample(&l, "s1", "shell", "a");
        append_sample(&l, "s2", "shell", "b");
        append_sample(&l, "s1", "shell", "c");
        buf.clear();
        l.export(&mut buf, "s1").expect("export s1");
        let events: Vec<Event> = serde_json::from_slice(&buf).expect("valid JSON array");
        assert_eq!(events.len(), 2);
        buf.clear();
        l.export(&mut buf, "").expect("export all");
        let events: Vec<Event> = serde_json::from_slice(&buf).expect("valid JSON array");
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn redact_hashes_payload_and_verifies() {
        let (l, _dir, _) = new_ledger();
        let raw = Event {
            session_id: "s1".into(),
            tool: "shell".into(),
            action: "curl -H 'Authorization: Bearer secret-token' https://api".into(),
            args: vec!["secret-token".into(), "keep-me".into()],
            meta: [
                ("token".into(), "secret-token".into()),
                ("region".into(), "us".into()),
            ]
            .into(),
            ..Event::default()
        };
        let before = hash_payload(&raw);
        let red = redact(raw.clone(), &["secret-token"]);
        assert!(red.redacted);
        assert_eq!(red.payload_hash, before);
        assert!(red.args[0].starts_with("sha256:"));
        assert_eq!(red.args[1], "keep-me");
        assert_ne!(red.meta["token"], "secret-token");
        assert_eq!(red.meta["region"], "us");
        // Only exact matches are redacted.
        assert_eq!(red.action, raw.action);

        let stored = l.append(red).expect("append redacted");
        assert_eq!(stored.hash, hash_event(&stored));
        l.verify().expect("verify with redacted event");

        let all = redact(raw, &[] as &[&str]);
        assert!(all.action.starts_with("sha256:"));
        assert!(all.args.iter().all(|a| a.starts_with("sha256:")));
        assert!(all.meta.values().all(|v| v.starts_with("sha256:")));
    }

    #[test]
    fn hash_is_map_order_independent() {
        let mk = |pairs: [(&str, &str); 3]| Event {
            seq: 1,
            tool: "shell".into(),
            meta: pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            ..Event::default()
        };
        let a = mk([("a", "1"), ("b", "2"), ("c", "3")]);
        let b = mk([("c", "3"), ("b", "2"), ("a", "1")]);
        assert_eq!(hash_event(&a), hash_event(&b));
    }

    #[test]
    fn decodes_with_go_semantics() {
        let line = r#"{"SEQ":5,"ſession_id":"s","time":"2026-10-19T12:00:00Z","meta":{"a":"1"},"Meta":{"b":null},"args":["x"],"ARGS":null,"tool":null,"unknown":[1,{"x":2}]}"#;
        let ev: Event = serde_json::from_str(line).expect("decode");
        assert_eq!(ev.seq, 5);
        assert_eq!(ev.session_id, "s");
        assert_eq!(
            ev.meta,
            [("a".into(), "1".into()), ("b".into(), String::new())].into()
        );
        assert!(ev.args.is_empty());
        assert_eq!(ev.tool, "");
        assert!(serde_json::from_str::<Event>(r#"{"seq":1.5}"#).is_err());
        assert!(serde_json::from_str::<Event>(r#"{"seq":"1"}"#).is_err());
        assert!(serde_json::from_str::<Event>(r#"{"time":"2026-10-19t12:00:00Z"}"#).is_err());
        assert!(serde_json::from_str::<Event>("[]").is_err());
        let zero: Event = serde_json::from_str("{}").expect("empty object");
        assert_eq!(zero, Event::default());
        assert_eq!(
            String::from_utf8(zero.to_json().expect("marshal")).expect("utf8"),
            r#"{"seq":0,"time":"0001-01-01T00:00:00Z","session_id":"","sandbox":"","profile":"","tool":"","action":"","verdict":"","exit_code":0,"duration_ms":0,"redacted":false,"prev_hash":"","hash":""}"#
        );
    }

    #[test]
    fn ledger_is_send_sync_and_shared() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Ledger>();

        let (l, _dir, _) = new_ledger();
        let l = std::sync::Arc::new(l);
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let l = l.clone();
                std::thread::spawn(move || {
                    for j in 0..10 {
                        append_sample(&l, "s", "shell", &format!("{i}-{j}"));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread");
        }
        assert_eq!(l.records().expect("records").len(), 80);
        l.verify().expect("verify concurrent appends");
    }
}
