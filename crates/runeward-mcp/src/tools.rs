//! Tool inputs (with schemars-generated JSON schemas), the tool table and
//! the tool-list digest.

use std::sync::{Arc, OnceLock};

use rmcp::handler::server::common::schema_for_input;
use rmcp::model::Tool;
use rmcp::schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Declares a tool input struct. Every field is required unless marked
/// `#[serde(default)]` (Go's `omitempty`); unknown fields are rejected
/// (`additionalProperties: false`, as the Go SDK infers).
macro_rules! input {
    ($(#[$m:meta])* $name:ident { $($body:tt)* }) => {
        $(#[$m])*
        #[derive(Debug, Default, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        #[schemars(crate = "rmcp::schemars")]
        pub(crate) struct $name { $($body)* }
    };
}

input!(
    /// Tools without arguments.
    NoInput {}
);

input!(ProfileIn {
    #[schemars(description = "the Charter to validate")]
    pub(crate) profile: String,
});

input!(CreateCitadelIn {
    #[schemars(description = "the runeward Charter (profile) to provision (e.g. dev)")]
    pub(crate) profile: String,
    #[serde(default)]
    #[schemars(description = "optional admin-only local directory copied into the fresh workspace")]
    pub(crate) copy_from: String,
    #[serde(default)]
    #[schemars(description = "optional parent Citadel for delegated-agent lineage")]
    pub(crate) parent_citadel: String,
    #[serde(default)]
    #[schemars(description = "optional caller-supplied run correlation id")]
    pub(crate) run_id: String,
    #[serde(default)]
    #[schemars(description = "agent name, such as codex or claude")]
    pub(crate) agent: String,
    #[serde(default)]
    #[schemars(description = "model provider")]
    pub(crate) provider: String,
    #[serde(default)]
    #[schemars(description = "model identifier")]
    pub(crate) model: String,
});

input!(ShellIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the command as an argv array, e.g. [\"ls\",\"-la\"]")]
    pub(crate) command: Vec<String>,
    #[serde(default)]
    #[schemars(description = "optional working directory")]
    pub(crate) workdir: String,
});

input!(BrowserIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the URL to load")]
    pub(crate) url: String,
    #[serde(default)]
    #[schemars(description = "'text' (default) or 'screenshot'")]
    pub(crate) mode: String,
});

input!(SandboxIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
});

input!(BrowserActIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the browser session id from runeward_browser_open")]
    pub(crate) session: String,
    #[schemars(description = "navigate|eval|text|html|screenshot|click|type|wait|title|url")]
    pub(crate) action: String,
    #[serde(default)]
    #[schemars(description = "URL for action=navigate")]
    pub(crate) url: String,
    #[serde(default)]
    #[schemars(description = "CSS selector for click/type/wait")]
    pub(crate) selector: String,
    #[serde(default)]
    #[schemars(description = "JavaScript source for action=eval")]
    pub(crate) expr: String,
    #[serde(default)]
    #[schemars(description = "text to type for action=type")]
    pub(crate) text: String,
    #[serde(default)]
    #[schemars(description = "optional per-action timeout in ms")]
    pub(crate) timeout_ms: i64,
});

input!(BrowserCloseIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the browser session id")]
    pub(crate) session: String,
});

input!(PythonIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "Python source to execute")]
    pub(crate) code: String,
});

input!(NodeIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "JavaScript source to execute")]
    pub(crate) code: String,
});

input!(ReadFileIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the file path to read")]
    pub(crate) path: String,
});

input!(WriteFileIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the file path to write")]
    pub(crate) path: String,
    #[schemars(description = "the file content")]
    pub(crate) content: String,
});

input!(ListFilesIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[serde(default)]
    #[schemars(description = "the directory to list (default .)")]
    pub(crate) path: String,
});

input!(SearchFilesIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "the text to search for")]
    pub(crate) query: String,
    #[serde(default)]
    #[schemars(description = "the root to search under (default .)")]
    pub(crate) path: String,
});

input!(ReportUsageIn {
    pub(crate) sandbox: String,
    pub(crate) tokens: i64,
    pub(crate) cost_usd: f64,
});

input!(PublishConversationIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[schemars(description = "turn role: user, assistant, tool, or system")]
    pub(crate) role: String,
    #[schemars(description = "turn content; secrets are redacted before broadcast")]
    pub(crate) content: String,
    #[serde(default)]
    #[schemars(description = "optional agent run id")]
    pub(crate) run_id: String,
});

input!(ListConversationIn {
    #[schemars(description = "the citadel id")]
    pub(crate) sandbox: String,
    #[serde(default)]
    #[schemars(description = "return messages newer than this id")]
    pub(crate) after_id: u64,
    #[serde(default)]
    #[schemars(description = "maximum messages, 1-500")]
    pub(crate) limit: i64,
});

input!(SnapshotIn {
    pub(crate) sandbox: String,
    #[serde(default)]
    pub(crate) name: String,
});

input!(CreateCohortIn {
    #[schemars(description = "the runeward Charter (profile) to provision the Cohort from")]
    pub(crate) profile: String,
});

input!(FleetIn {
    #[schemars(description = "the cohort id")]
    pub(crate) fleet: String,
});

input!(AddTaskIn {
    #[schemars(description = "the cohort id")]
    pub(crate) fleet: String,
    #[schemars(description = "the task description/payload")]
    pub(crate) payload: String,
});

input!(HeartbeatIn {
    #[schemars(description = "the cohort id")]
    pub(crate) fleet: String,
    #[schemars(description = "the task id")]
    pub(crate) task: String,
    #[schemars(description = "the signed lease token returned by claim or heartbeat")]
    pub(crate) lease_token: String,
});

input!(CompleteTaskIn {
    #[schemars(description = "the cohort id")]
    pub(crate) fleet: String,
    #[schemars(description = "the task id")]
    pub(crate) task: String,
    #[schemars(description = "the signed lease token returned by claim or heartbeat")]
    pub(crate) lease_token: String,
    #[serde(default)]
    #[schemars(description = "the successful result output")]
    pub(crate) result: String,
});

input!(FailTaskIn {
    #[schemars(description = "the cohort id")]
    pub(crate) fleet: String,
    #[schemars(description = "the task id")]
    pub(crate) task: String,
    #[schemars(description = "the signed lease token returned by claim or heartbeat")]
    pub(crate) lease_token: String,
    #[serde(default)]
    #[schemars(description = "the failure message")]
    pub(crate) error: String,
    #[serde(default)]
    #[schemars(description = "whether to requeue the task for retry")]
    pub(crate) requeue: bool,
});

fn tool<T: JsonSchema + 'static>(name: &'static str, description: &'static str) -> Tool {
    // Every input above is a struct, so the schema root is an object.
    let mut schema = schema_for_input::<T>()
        .map(|s| s.as_ref().clone())
        .unwrap_or_default();
    // `#[serde(default)]` makes schemars emit `"default": ""` / `0` /
    // `false`; the Go schemas only mark such fields optional.
    if let Some(Value::Object(props)) = schema.get_mut("properties") {
        for prop in props.values_mut() {
            if let Value::Object(p) = prop {
                p.remove("default");
            }
        }
    }
    Tool::new(name, description, Arc::new(schema))
}

/// Builds the tool table, sorted by name (the order the Go SDK lists).
fn build() -> Vec<Tool> {
    let mut tools = vec![
        tool::<NoInput>(
            "runeward_whoami",
            "Return the authenticated Runeward principal and its effective launch and approval scopes.",
        ),
        tool::<NoInput>(
            "runeward_server_info",
            "Return the server name and version, a SHA-256 digest of the canonical JSON of every tool definition (so clients can detect a stale or tampered tool list), and the caller's identity.",
        ),
        tool::<NoInput>(
            "runeward_list_charters",
            "List the Runeward Charters this principal is allowed to launch.",
        ),
        tool::<ProfileIn>(
            "runeward_readiness",
            "Validate one launchable Charter and report policy, runtime, and image readiness.",
        ),
        tool::<CreateCitadelIn>(
            "runeward_create_citadel",
            "Provision a governed, isolated Citadel (sandbox) from a named runeward Charter (profile) and return its id. Use this before running any other tool.",
        ),
        tool::<NoInput>(
            "runeward_list_citadels",
            "List Citadels visible to the authenticated principal.",
        ),
        tool::<NoInput>(
            "runeward_list_runs",
            "List durable agent runs and parent/child lineage visible to the authenticated tenant.",
        ),
        tool::<ShellIn>(
            "runeward_shell",
            "Run a shell command (argv form) in a Citadel. Subject to policy: may be denied or require human approval.",
        ),
        tool::<BrowserIn>(
            "runeward_browser",
            "Fetch a URL with a headless browser inside the Citadel and return the rendered page. mode 'text' returns the rendered DOM HTML; 'screenshot' returns a base64 PNG. Subject to policy (tool 'browser', arg = url) and the profile's egress allowlist.",
        ),
        tool::<SandboxIn>(
            "runeward_browser_open",
            "Open a STATEFUL, CDP-driven browser session inside the Citadel and return its session id. The page (cookies, DOM, storage) persists across runeward_browser_act calls until runeward_browser_close. Subject to policy (tool 'browser') and the profile's egress allowlist.",
        ),
        tool::<BrowserActIn>(
            "runeward_browser_act",
            "Run one action against an open browser session. action is one of navigate|eval|text|html|screenshot|click|type|wait|title|url. Provide url (navigate), selector (click/type/wait), expr (eval JS), or text (type). Returns the textual value, or a base64 PNG for screenshot. Governed per action.",
        ),
        tool::<BrowserCloseIn>(
            "runeward_browser_close",
            "Close an open browser session (shuts down the in-sandbox Chromium and frees its resources).",
        ),
        tool::<PythonIn>(
            "runeward_python",
            "Run a Python 3 snippet in a Citadel via python3 -c.",
        ),
        tool::<NodeIn>(
            "runeward_node",
            "Run a JavaScript snippet in a Citadel via node -e.",
        ),
        tool::<ReadFileIn>(
            "runeward_read_file",
            "Read a file from a Citadel and return its contents.",
        ),
        tool::<WriteFileIn>(
            "runeward_write_file",
            "Write content to a file in a Citadel (creating parent directories). May require approval.",
        ),
        tool::<ListFilesIn>(
            "runeward_list_files",
            "List a directory in a Citadel (ls -la).",
        ),
        tool::<SearchFilesIn>(
            "runeward_search_files",
            "Recursively search for text in a Citadel (grep -rn).",
        ),
        tool::<NoInput>(
            "runeward_list_conclave",
            "List pending human-in-the-loop Conclave (approval) requests across all Citadels.",
        ),
        tool::<SandboxIn>(
            "runeward_kill_citadel",
            "Tear down a Citadel (sandbox) and free its resources.",
        ),
        tool::<ReportUsageIn>(
            "runeward_report_usage",
            "Report model token and cost usage for budget enforcement on a Citadel.",
        ),
        tool::<PublishConversationIn>(
            "runeward_publish_conversation",
            "Publish one user, assistant, tool, or system turn to a Citadel's read-only Live chat TTY. Agent harnesses should call this for each turn they want human observers to follow.",
        ),
        tool::<ListConversationIn>(
            "runeward_list_conversation",
            "Return the bounded, redacted Live chat history for a Citadel.",
        ),
        tool::<SnapshotIn>(
            "runeward_snapshot_citadel",
            "Create a tenant-scoped recovery snapshot of a Citadel workspace.",
        ),
        tool::<NoInput>(
            "runeward_list_snapshots",
            "List recovery snapshots visible to the authenticated principal.",
        ),
        tool::<SandboxIn>(
            "runeward_export_evidence",
            "Return the portable signed evidence document for a Citadel, including its resolved Charter and Chronicle bundle.",
        ),
        tool::<NoInput>(
            "runeward_verify_chronicle",
            "Verify the Chronicle hash chain and signatures before trusting or exporting evidence.",
        ),
        tool::<CreateCohortIn>(
            "runeward_create_cohort",
            "Provision a Cohort (fleet): N governed Citadels (from the Charter's [cohort].replicas) sharing an atomic Command Board seeded from the Charter's task_board. Returns the cohort id and member citadel ids.",
        ),
        tool::<NoInput>(
            "runeward_list_cohorts",
            "List all Cohorts with their Citadel members and Command Board stats.",
        ),
        tool::<FleetIn>(
            "runeward_list_tasks",
            "List the tasks on a Cohort's Command Board with their state, owner, and results.",
        ),
        tool::<AddTaskIn>(
            "runeward_add_task",
            "Add a task to a Cohort's Command Board.",
        ),
        tool::<FleetIn>(
            "runeward_claim_task",
            "Atomically claim the next pending task from a Cohort's Command Board for a worker. Returns the task, or reports the board is empty.",
        ),
        tool::<HeartbeatIn>(
            "runeward_heartbeat_task",
            "Extend the lease on a task a worker still holds so the Cohort sweeper does not requeue it as a dead worker.",
        ),
        tool::<CompleteTaskIn>(
            "runeward_complete_task",
            "Mark a claimed task as done with its result.",
        ),
        tool::<FailTaskIn>(
            "runeward_fail_task",
            "Mark a claimed task as failed. Set requeue=true to return it to the pending pool for retry.",
        ),
        tool::<FleetIn>(
            "runeward_kill_cohort",
            "Tear down a Cohort (fleet) and all its Citadels.",
        ),
    ];
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

struct Table {
    tools: Vec<Tool>,
    digest: String,
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(|| {
        let tools = build();
        let value = serde_json::to_value(&tools).unwrap_or(Value::Null);
        let digest = hex::encode(Sha256::digest(canonical_json(&value).as_bytes()));
        Table {
            tools,
            digest: format!("sha256:{digest}"),
        }
    })
}

/// Every tool definition the server lists, sorted by name.
pub fn tool_definitions() -> &'static [Tool] {
    &table().tools
}

/// `sha256:<hex>` over [`canonical_json`] of the `tools/list` array (the
/// serialized [`tool_definitions`]).
pub fn tool_list_digest() -> &'static str {
    &table().digest
}

/// Serializes `v` with object keys sorted (by UTF-16-agnostic byte order)
/// and no insignificant whitespace, independent of serde_json's map
/// ordering features. Strings and numbers use serde_json's encoding.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&map[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thirty_six_unique_prefixed_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 36);
        let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(names.iter().all(|n| n.starts_with("runeward_")));
        names.dedup();
        assert_eq!(names.len(), 36);
        for t in tools {
            assert_eq!(t.input_schema.get("type"), Some(&Value::from("object")));
        }
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let v = serde_json::json!({"b": [{"z": 1, "a": "x\"y"}], "a": null});
        assert_eq!(canonical_json(&v), r#"{"a":null,"b":[{"a":"x\"y","z":1}]}"#);
    }

    #[test]
    fn digest_is_stable_and_covers_definitions() {
        let d = tool_list_digest();
        assert!(d.starts_with("sha256:") && d.len() == 7 + 64, "{d}");
        let mut tools = tool_definitions().to_vec();
        tools[0].description = Some("tampered".into());
        let value = serde_json::to_value(&tools).expect("tools");
        let tampered = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical_json(&value).as_bytes()))
        );
        assert_ne!(tampered, d);
    }
}
