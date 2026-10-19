//! Policy simulation: evaluates actions against a named or inline Charter
//! without a sandbox, with a first-match trace.

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use runeward_charter::{Charter, HostType, PolicyRule, Verdict};
use runeward_policy::{Action, CelEngine, Evaluator, RuleEngine};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::respond::{decode, error, json};
use crate::state::{Caller, SharedState};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ActionRequest {
    name: String,
    tool: String,
    arg: String,
    command: String,
    args: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SimulateRequest {
    profile_name: String,
    profile: Option<Value>,
    actions: Vec<ActionRequest>,
}

pub(crate) async fn simulate(State(s): State<SharedState>, caller: Caller, body: Body) -> Response {
    let req: SimulateRequest = match decode(body).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let inline = match req.profile {
        None | Some(Value::Null) => None,
        Some(v) => match serde_json::from_value::<Charter>(v) {
            Ok(c) => Some(c),
            Err(e) => return error(StatusCode::BAD_REQUEST, format!("json: {e}")),
        },
    };
    if req.actions.is_empty() {
        return error(StatusCode::BAD_REQUEST, "actions is required");
    }
    // Non-admins may only simulate Charters they may launch; inline bodies
    // are admin/open-mode only so callers cannot probe arbitrary policy.
    if let Some(p) = caller.scoped() {
        if inline.is_some() {
            return error(
                StatusCode::FORBIDDEN,
                "not authorized to simulate inline profiles",
            );
        }
        let name = req.profile_name.trim();
        if name.is_empty() {
            return error(
                StatusCode::FORBIDDEN,
                "not authorized to simulate this profile",
            );
        }
        if !p.can_launch(name) {
            return error(
                StatusCode::FORBIDDEN,
                format!("not authorized to launch profile {name}"),
            );
        }
    }
    let charter = match resolve_profile(&s, &req.profile_name, inline).await {
        Ok(c) => c,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let engine = match engine_for(&charter) {
        Ok(e) => e,
        Err(e) => return error(StatusCode::BAD_REQUEST, e),
    };
    let results: Vec<Value> = req
        .actions
        .iter()
        .map(|a| {
            let mut arg = a.arg.trim().to_owned();
            if arg.is_empty() {
                a.command.trim().clone_into(&mut arg);
            }
            if arg.is_empty()
                && let Some(args) = a.args.as_ref().filter(|v| !v.is_empty())
            {
                arg = args.join(" ");
            }
            let act = Action::new(a.tool.trim(), arg).with_args(a.args.clone().unwrap_or_default());
            let dec = engine.evaluate(&act);
            json!({
                "name": a.name,
                "tool": act.tool,
                "arg": act.arg,
                "args": a.args,
                "verdict": dec.verdict,
                "reason": dec.reason,
                "matched_rule": dec.rule.as_ref().map(rule_json),
                "trace": first_match_trace(&charter, &act),
            })
        })
        .collect();
    json(
        StatusCode::OK,
        &json!({
            "profile": {"name": charter.name, "source": charter.source.to_string_lossy()},
            "results": results,
        }),
    )
}

fn rule_json(r: &PolicyRule) -> Value {
    json!({
        "tool": r.tool,
        "match": r.match_glob,
        "match_argv": r.match_argv,
        "verdict": r.verdict,
        "reason": r.reason,
    })
}

async fn resolve_profile(
    s: &SharedState,
    name: &str,
    inline: Option<Charter>,
) -> Result<Charter, String> {
    let name = name.trim();
    match (name.is_empty(), inline) {
        (true, None) => Err("profile_name or profile is required".into()),
        (false, Some(_)) => Err("provide profile_name or profile, not both".into()),
        (false, None) => s.mgr.load_profile(name).await.map_err(|e| e.to_string()),
        (true, Some(mut c)) => {
            if !c.rego.file.is_empty() {
                return Err("inline profiles may not load a Rego file from the server host; use rego.module or a named policy".into());
            }
            if c.name.is_empty() {
                c.name = "inline".into();
            }
            if c.host.host_type == HostType::Unset {
                c.host.host_type = HostType::Container;
            }
            if c.host.workdir.is_empty() {
                c.host.workdir = "/workspace".into();
            }
            if c.host.image.is_empty() {
                c.host.image = "ghcr.io/runewardd/runeward-sandbox:latest".into();
            }
            c.validate()
                .map_err(|e| format!("invalid inline profile: {e}"))?;
            Ok(c)
        }
    }
}

/// The engine the simulation uses; the no-match verdict is the Charter's
/// `policy_default` (deny or allow) and ignores the server environment.
fn engine_for(c: &Charter) -> Result<Box<dyn Evaluator>, String> {
    if c.uses_policy_bundle() {
        let reference = c
            .policy_bundle
            .as_ref()
            .map(|b| b.r#ref.as_str())
            .unwrap_or_default();
        return Err(format!(
            "profile {:?} uses an OCI policy bundle ({reference}), which is not supported by policy simulation",
            c.name
        ));
    }
    let no_match = runeward_policy::no_match_verdict(Some(c), None);
    runeward_policy::engine_for_charter(c, no_match).map_err(|e| e.to_string())
}

fn first_match_trace(c: &Charter, act: &Action) -> Vec<Value> {
    let mut trace = Vec::new();
    if c.uses_cel() {
        for (i, rule) in c.cel.iter().enumerate() {
            let matched = CelEngine::new(std::slice::from_ref(rule), Verdict::Deny)
                .is_ok_and(|e| e.evaluate(act).rule.is_some());
            trace.push(json!({
                "index": i + 1,
                "engine": "cel",
                "expr": rule.expr,
                "verdict": rule.verdict,
                "matched": matched,
            }));
            if matched {
                break;
            }
        }
    } else if c.uses_rego() {
        trace.push(json!({"index": 1, "engine": "rego", "query": c.rego.query, "matched": true}));
    } else {
        for (i, rule) in c.policy.iter().enumerate() {
            let matched = RuleEngine::new(vec![rule.clone()], Verdict::Deny)
                .evaluate(act)
                .rule
                .is_some();
            trace.push(json!({
                "index": i + 1,
                "engine": "builtin",
                "tool": rule.tool,
                "match": rule.match_glob,
                "match_argv": rule.match_argv,
                "verdict": rule.verdict,
                "matched": matched,
            }));
            if matched {
                break;
            }
        }
    }
    trace
}
