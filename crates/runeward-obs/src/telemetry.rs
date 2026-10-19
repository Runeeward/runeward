//! Optional, anonymous usage events. Telemetry is OFF by default and only
//! active when the operator explicitly opts in AND configures an endpoint,
//! so runeward never phones home without consent.
//!
//! Enable with:
//!
//! ```text
//! RUNEWARD_TELEMETRY=1
//! RUNEWARD_TELEMETRY_ENDPOINT=https://your-collector.example/ingest
//! ```
//!
//! The `DO_NOT_TRACK` convention (<https://consoledonottrack.com>) always
//! wins. Events carry only the runeward version, OS and architecture plus any
//! explicit, non-identifying properties the caller passes: no hostnames, no
//! paths, no profile contents, no IDs.

use std::collections::BTreeMap;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;

/// The opt-in flag.
pub const ENABLE_ENV: &str = "RUNEWARD_TELEMETRY";
/// Where events are POSTed.
pub const ENDPOINT_ENV: &str = "RUNEWARD_TELEMETRY_ENDPOINT";
/// The cross-tool opt-out; set to a true value it disables telemetry.
pub const DO_NOT_TRACK_ENV: &str = "DO_NOT_TRACK";

const SEND_TIMEOUT: Duration = Duration::from_secs(2);

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// Reports whether telemetry should be sent: opt-in flag set, an endpoint
/// configured, and `DO_NOT_TRACK` not set.
pub fn enabled() -> bool {
    enabled_with(env)
}

/// [`enabled`] with an explicit variable lookup.
pub fn enabled_with<F>(lookup: F) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    let get = |k| lookup(k).unwrap_or_default();
    if is_true(&get(DO_NOT_TRACK_ENV)) {
        return false;
    }
    is_true(&get(ENABLE_ENV)) && !get(ENDPOINT_ENV).trim().is_empty()
}

fn is_true(s: &str) -> bool {
    matches!(
        s.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// The wire payload; field order and names match the Go build.
#[derive(Debug, Serialize)]
struct Payload<'a> {
    event: &'a str,
    version: &'a str,
    os: &'static str,
    arch: &'static str,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    props: &'a BTreeMap<String, String>,
    time: String,
}

fn payload(version: &str, name: &str, props: &BTreeMap<String, String>) -> Option<Vec<u8>> {
    let ev = Payload {
        event: name,
        version,
        os: go_os(),
        arch: go_arch(),
        props,
        time: chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    };
    runeward_ledger::gojson::marshal(&ev).ok()
}

/// Sends an anonymous event best-effort. It returns immediately (the send
/// happens on a background thread with a short timeout) and never errors;
/// when telemetry is disabled it is a no-op and returns `None`. The handle
/// may be joined to wait for the send, or simply dropped.
pub fn report(
    version: &str,
    name: &str,
    props: BTreeMap<String, String>,
) -> Option<JoinHandle<()>> {
    report_with(env, version, name, props)
}

/// [`report`] with an explicit variable lookup.
pub fn report_with<F>(
    lookup: F,
    version: &str,
    name: &str,
    props: BTreeMap<String, String>,
) -> Option<JoinHandle<()>>
where
    F: Fn(&str) -> Option<String>,
{
    if !enabled_with(&lookup) {
        return None;
    }
    let endpoint = lookup(ENDPOINT_ENV).unwrap_or_default().trim().to_owned();
    let body = payload(version, name, &props)?;
    thread::Builder::new()
        .name("runeward-telemetry".into())
        .spawn(move || send(&endpoint, body))
        .ok()
}

fn send(endpoint: &str, body: Vec<u8>) {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    rt.block_on(async {
        let Ok(client) = reqwest::Client::builder().timeout(SEND_TIMEOUT).build() else {
            return;
        };
        let _ = client
            .post(endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await;
    });
}

/// A one-line, human-readable disclosure of the current telemetry state,
/// suitable for logging at startup.
pub fn notice() -> String {
    notice_with(env)
}

/// [`notice`] with an explicit variable lookup.
pub fn notice_with<F>(lookup: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    if enabled_with(&lookup) {
        let endpoint = lookup(ENDPOINT_ENV).unwrap_or_default();
        return format!(
            "telemetry enabled: anonymous usage events (version, os, arch) sent to {}; unset {ENABLE_ENV} to disable",
            endpoint.trim()
        );
    }
    format!("telemetry disabled (opt in with {ENABLE_ENV}=1 and {ENDPOINT_ENV})")
}

/// The OS name as Go's `runtime.GOOS` spells it.
fn go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// The architecture as Go's `runtime.GOARCH` spells it.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        "loongarch64" => "loong64",
        "powerpc64" if cfg!(target_endian = "little") => "ppc64le",
        "powerpc64" => "ppc64",
        "mips64" if cfg!(target_endian = "little") => "mips64le",
        "mips" if cfg!(target_endian = "little") => "mipsle",
        other => other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn opt_in_semantics() {
        let ep = (ENDPOINT_ENV, "https://collector.example/ingest");
        assert!(!enabled_with(lookup(&[])));
        assert!(!enabled_with(lookup(&[ep])));
        assert!(!enabled_with(lookup(&[(ENABLE_ENV, "1")])));
        assert!(!enabled_with(lookup(&[
            (ENABLE_ENV, "1"),
            (ENDPOINT_ENV, "  ")
        ])));
        for on in ["1", "true", "YES", " on "] {
            assert!(enabled_with(lookup(&[(ENABLE_ENV, on), ep])), "{on}");
        }
        for off in ["0", "false", "no", "2", ""] {
            assert!(!enabled_with(lookup(&[(ENABLE_ENV, off), ep])), "{off}");
        }
        // DO_NOT_TRACK always wins, but only when it is a true value.
        assert!(!enabled_with(lookup(&[
            (ENABLE_ENV, "1"),
            ep,
            (DO_NOT_TRACK_ENV, "1")
        ])));
        assert!(enabled_with(lookup(&[
            (ENABLE_ENV, "1"),
            ep,
            (DO_NOT_TRACK_ENV, "0")
        ])));
    }

    #[test]
    fn notice_text() {
        assert_eq!(
            notice_with(lookup(&[])),
            "telemetry disabled (opt in with RUNEWARD_TELEMETRY=1 and RUNEWARD_TELEMETRY_ENDPOINT)"
        );
        assert_eq!(
            notice_with(lookup(&[
                (ENABLE_ENV, "1"),
                (ENDPOINT_ENV, " https://c.example/i ")
            ])),
            "telemetry enabled: anonymous usage events (version, os, arch) sent to https://c.example/i; unset RUNEWARD_TELEMETRY to disable"
        );
    }

    #[test]
    fn payload_shape_matches_go() {
        let body = payload("0.4.0", "start", &BTreeMap::new()).unwrap();
        let text = String::from_utf8(body).unwrap();
        let prefix = format!(
            r#"{{"event":"start","version":"0.4.0","os":"{}","arch":"{}","time":""#,
            go_os(),
            go_arch()
        );
        assert!(text.starts_with(&prefix), "{text}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let t = v["time"].as_str().unwrap();
        assert_eq!(t.len(), 20, "RFC3339 seconds in UTC: {t}");
        assert!(t.ends_with('Z'));

        let mut props = BTreeMap::new();
        props.insert("z".to_owned(), "<1>".to_owned());
        props.insert("a".to_owned(), "x".to_owned());
        let text = String::from_utf8(payload("v", "e", &props).unwrap()).unwrap();
        // Keys sorted and HTML characters escaped, as Go's encoder does.
        assert!(
            text.contains(r#""props":{"a":"x","z":"\u003c1\u003e"},"time":"#),
            "{text}"
        );
    }

    #[test]
    fn go_platform_names() {
        assert_ne!(go_os(), "macos");
        assert!(!["x86_64", "aarch64"].contains(&go_arch()));
    }

    #[test]
    fn disabled_report_is_noop() {
        assert!(report_with(lookup(&[]), "v", "e", BTreeMap::new()).is_none());
    }

    #[test]
    fn report_posts_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel::<(String, Vec<String>, Vec<u8>)>();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut w = stream.try_clone().unwrap();
            let mut r = BufReader::new(stream);
            let mut start = String::new();
            r.read_line(&mut start).unwrap();
            let mut headers = Vec::new();
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                headers.push(h.trim().to_lowercase());
            }
            let len: usize = headers
                .iter()
                .find_map(|h| h.strip_prefix("content-length:"))
                .map(|v| v.trim().parse().unwrap())
                .unwrap_or(0);
            let mut body = vec![0; len];
            r.read_exact(&mut body).unwrap();
            w.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
            tx.send((start, headers, body)).unwrap();
        });

        let endpoint = format!("http://{addr}/ingest");
        let mut props = BTreeMap::new();
        props.insert("mode".to_owned(), "cli".to_owned());
        let h = report_with(
            lookup(&[(ENABLE_ENV, "1"), (ENDPOINT_ENV, &endpoint)]),
            "0.4.0",
            "start",
            props,
        )
        .unwrap();
        h.join().unwrap();

        let (start, headers, body) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(start.starts_with("POST /ingest "), "{start}");
        assert!(headers.contains(&"content-type: application/json".to_owned()));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["event"], "start");
        assert_eq!(v["version"], "0.4.0");
        assert_eq!(v["props"]["mode"], "cli");
    }
}
