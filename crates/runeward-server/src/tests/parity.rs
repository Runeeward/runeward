//! Wire parity with the Go server.
//!
//! `testdata/parity/requests.json` is a representative request set and
//! `go_responses.json` what the Go server answered (recorded with the same
//! Charters and injected fake Citadels). Each request is replayed here and
//! must produce the same status, the same JSON shape (keys and value types,
//! recursively; ids, times and other values are ignored) and the same
//! error message. Deliberate deviations are listed in `deviations.json`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use serde::Deserialize;
use serde_json::Value;

use super::support::*;

const REQUESTS: &str = include_str!("../../testdata/parity/requests.json");
const GO_RESPONSES: &str = include_str!("../../testdata/parity/go_responses.json");
const DEVIATIONS: &str = include_str!("../../testdata/parity/deviations.json");
const PARITY_CHARTER: &str = include_str!("../../testdata/parity/parity.toml");
const TEAM_CHARTER: &str = include_str!("../../testdata/parity/team-dev.toml");

/// Fields the Rust server adds to Go's objects.
const ADDED_FIELDS: &[&str] = &[
    "isolation",
    "isolation_evidence",
    "enforcement",
    // The standard refusal (runeward_controlplane::refusal).
    "refusal",
];

#[derive(Debug, Deserialize)]
struct ParityRequest {
    name: String,
    server: String,
    method: String,
    path: String,
    body: Option<String>,
    headers: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GoResponse {
    name: String,
    status: u16,
    content_type: String,
    body: Value,
}

#[derive(Debug, Deserialize)]
struct Deviations {
    /// Requests whose error message differs on purpose.
    messages: BTreeMap<String, String>,
    /// Requests whose shape differs on purpose, by JSON path.
    shapes: BTreeMap<String, String>,
}

fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Records every shape difference between `go` and `rust` under `path`.
fn shape_diff(path: &str, go: &Value, rust: &Value, out: &mut Vec<String>) {
    match (go, rust) {
        (Value::Object(g), Value::Object(r)) => {
            for (k, gv) in g {
                let p = format!("{path}.{k}");
                match r.get(k) {
                    Some(rv) => shape_diff(&p, gv, rv, out),
                    None => out.push(format!("{p}: missing in Rust")),
                }
            }
            for k in r.keys() {
                if !g.contains_key(k) && !ADDED_FIELDS.contains(&k.as_str()) {
                    out.push(format!("{path}.{k}: only in Rust"));
                }
            }
        }
        (Value::Array(g), Value::Array(r)) => {
            if g.is_empty() != r.is_empty() {
                out.push(format!(
                    "{path}: array emptiness differs ({} vs {})",
                    g.len(),
                    r.len()
                ));
            }
            if let (Some(gv), Some(rv)) = (g.first(), r.first()) {
                shape_diff(&format!("{path}[0]"), gv, rv, out);
            }
        }
        (g, r) if kind(g) != kind(r) => {
            out.push(format!("{path}: {} in Go, {} in Rust", kind(g), kind(r)));
        }
        _ => {}
    }
}

async fn routers() -> (Harness, BTreeMap<&'static str, Router>) {
    let h = harness_with(
        |_| {},
        |dir| {
            std::fs::write(dir.join("charters/parity.toml"), PARITY_CHARTER).expect("charter");
            std::fs::write(dir.join("charters/team-dev.toml"), TEAM_CHARTER).expect("charter");
        },
    )
    .await;
    h.inject("cit-1", "parity", "").await;
    h.inject("cit-a", "team-dev", "team-alpha").await;
    let store = authz_store(
        h.dir.path(),
        r#"{"principals":[
            {"name":"admin","token":"tok-admin","admin":true},
            {"name":"alice","tenant":"team-alpha","token":"tok-alice","allowed_profiles":["team-*"]},
            {"name":"eve","tenant":"team-other","token":"tok-eve","allowed_profiles":["team-*"]},
            {"name":"reviewer","tenant":"team-alpha","token":"tok-reviewer","can_approve":true,"allowed_profiles":["team-*"]}
        ]}"#,
    );
    let mk = || server(&h).version("parity");
    let mut m = BTreeMap::new();
    m.insert("open", mk().router());
    m.insert("token", mk().token("s3cret").router());
    m.insert("rbac", mk().authz(Some(Arc::clone(&store))).router());
    (h, m)
}

/// The open server only holds `cit-1` in Go; hide `cit-a` from its
/// listings by comparing against the RBAC tenant's view instead.
fn scrub_foreign(name: &str, v: &mut Value) {
    if matches!(name, "list citadels" | "token ok")
        && let Some(list) = v.get_mut("sandboxes").and_then(Value::as_array_mut)
    {
        list.retain(|s| s["id"] != "cit-a");
    }
}

/// Charter-not-found messages embed the (temporary) search path.
fn without_search_path(msg: &str) -> &str {
    msg.split_once(" (searched ").map_or(msg, |(head, _)| head)
}

#[tokio::test]
async fn responses_match_go() {
    let requests: Vec<ParityRequest> = serde_json::from_str(REQUESTS).expect("requests");
    let golden: Vec<GoResponse> = serde_json::from_str(GO_RESPONSES).expect("go responses");
    let deviations: Deviations = serde_json::from_str(DEVIATIONS).expect("deviations");
    assert_eq!(requests.len(), golden.len(), "re-record go_responses.json");
    let (_h, routers) = routers().await;

    let mut failures = Vec::new();
    for (pr, go) in requests.iter().zip(&golden) {
        assert_eq!(pr.name, go.name, "fixture order");
        let headers: Vec<(&str, &str)> = pr
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let r = &routers[pr.server.as_str()];
        let resp = send(r, req(&pr.method, &pr.path, &headers, pr.body.as_deref())).await;
        if resp.status.as_u16() != go.status {
            failures.push(format!(
                "{}: status {} (Go {}) body {}",
                pr.name,
                resp.status,
                go.status,
                resp.text()
            ));
            continue;
        }
        let go_json = go.content_type.starts_with("application/json");
        let rust_json = resp.header("content-type").starts_with("application/json");
        if go_json != rust_json {
            failures.push(format!(
                "{}: content type {:?} (Go {:?})",
                pr.name,
                resp.header("content-type"),
                go.content_type
            ));
            continue;
        }
        if !go_json {
            continue;
        }
        let mut rust = resp.json();
        scrub_foreign(&pr.name, &mut rust);
        let mut diffs = Vec::new();
        shape_diff("$", &go.body, &rust, &mut diffs);
        if !diffs.is_empty() && !deviations.shapes.contains_key(&pr.name) {
            failures.push(format!("{}: {}", pr.name, diffs.join("; ")));
        }
        if let (Some(ge), Some(re)) = (go.body["error"].as_str(), rust["error"].as_str())
            && without_search_path(ge) != without_search_path(re)
            && !deviations.messages.contains_key(&pr.name)
        {
            failures.push(format!("{}: error {re:?} (Go {ge:?})", pr.name));
        }
        if go.body["code"] != rust["code"] {
            failures.push(format!(
                "{}: code {} (Go {})",
                pr.name, rust["code"], go.body["code"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "parity failures:\n{}",
        failures.join("\n")
    );
}
