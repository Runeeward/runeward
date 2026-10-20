//! The Rego authority engine (`policy_engine = "rego"`), backed by regorus.
//!
//! The module is parsed (Rego v1 syntax) and analysed once at construction,
//! so a malformed policy fails fast. Each evaluation runs the query
//! (`data.runeward.decision` by default) against the input
//! `{"tool": …, "arg": …}`. The result may be a bare verdict string or an
//! object `{"verdict": …, "reason": …}`; anything else, or an undefined
//! result, falls back to the default verdict.

use std::fmt;
use std::num::NonZeroU32;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Duration;

use regorus::utils::limits::ExecutionTimerConfig;
use runeward_charter::{PolicyRule, Verdict};

use crate::decision::{Action, Decision, EngineKind, Evaluator, default_or_allow};

/// The decision entrypoint used when a Charter sets no query.
pub const DEFAULT_REGO_QUERY: &str = "data.runeward.decision";

/// Upper bound on one evaluation, matching the Go engine's context timeout.
const EVAL_TIMEOUT: Duration = Duration::from_secs(5);

/// A Rego module or query failed to prepare.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policy: prepare rego query {query:?}: {message}")]
pub struct RegoError {
    /// The query being prepared.
    pub query: String,
    /// The parser or analyser message.
    pub message: String,
}

/// An authority engine backed by a Rego module. Safe for concurrent use:
/// each evaluation runs on a clone of the prepared engine.
#[derive(Clone)]
pub struct RegoEngine {
    engine: Option<regorus::Engine>,
    query: String,
    def: Verdict,
}

impl fmt::Debug for RegoEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegoEngine")
            .field("query", &self.query)
            .field("def", &self.def)
            .finish_non_exhaustive()
    }
}

impl RegoEngine {
    /// Compiles and prepares `module`. An empty `query` means
    /// [`DEFAULT_REGO_QUERY`]; an unset `def` means allow.
    pub fn new(module: &str, query: &str, def: Verdict) -> Result<Self, RegoError> {
        let query = if query.is_empty() {
            DEFAULT_REGO_QUERY
        } else {
            query
        };
        let err = |e: &dyn fmt::Display| RegoError {
            query: query.to_owned(),
            message: e.to_string(),
        };
        let mut engine = regorus::Engine::new();
        // regorus defaults to v1; keep it explicit for parity with the Go
        // engine, which opts into v1.
        engine.set_rego_v0(false);
        engine.set_execution_timer_config(ExecutionTimerConfig {
            limit: EVAL_TIMEOUT,
            check_interval: NonZeroU32::MIN,
        });
        engine
            .add_policy("policy.rego".to_owned(), module.to_owned())
            .map_err(|e| err(&e))?;
        // Analyse the modules now (the analogue of Go's PrepareForEval) with a
        // trivial query, and check the decision query parses, without
        // evaluating the policy itself.
        engine
            .eval_query("true".to_owned(), false)
            .map_err(|e| err(&e))?;
        check_query_syntax(&mut engine.clone(), query).map_err(|e| err(&e))?;
        Ok(Self {
            engine: Some(engine),
            query: query.to_owned(),
            def: default_or_allow(def),
        })
    }

    /// The prepared decision query.
    pub fn query(&self) -> &str {
        &self.query
    }

    fn eval(&self, action: &Action) -> Result<Option<regorus::Value>, String> {
        let mut engine = self
            .engine
            .clone()
            .ok_or_else(|| "rego engine not prepared".to_owned())?;
        let input = serde_json::json!({ "tool": action.tool, "arg": action.arg });
        engine.set_input(regorus::Value::from(input));
        let results = engine
            .eval_query(self.query.clone(), false)
            .map_err(|e| e.to_string())?;
        Ok(results
            .result
            .into_iter()
            .next()
            .and_then(|r| r.expressions.into_iter().next())
            .map(|e| e.value)
            .filter(|v| *v != regorus::Value::Undefined))
    }
}

/// Parses `query` without evaluating the policy: a leading `false` statement
/// fails before the query itself is evaluated.
fn check_query_syntax(engine: &mut regorus::Engine, query: &str) -> Result<(), String> {
    engine
        .eval_query(format!("false; {query}"), false)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl Evaluator for RegoEngine {
    /// Evaluation errors (and panics) fail closed to deny with a synthesized
    /// rule; undefined results and unrecognized verdicts return the default
    /// verdict with no rule.
    fn evaluate(&self, action: &Action) -> Decision {
        let deny = |reason: String| {
            Decision::eval_error(EngineKind::Rego, &action.tool, &action.arg, reason, None)
        };
        let value = match catch_unwind(AssertUnwindSafe(|| self.eval(action))) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return deny(format!("policy: rego evaluation error: {e}")),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_owned());
                return deny(format!("policy: rego evaluation panic: {msg}"));
            }
        };
        match value.as_ref().and_then(parse_result) {
            Some((verdict, reason)) => Decision::matched(
                EngineKind::Rego,
                PolicyRule {
                    tool: action.tool.clone(),
                    match_glob: action.arg.clone(),
                    match_argv: String::new(),
                    verdict,
                    reason,
                },
                None,
            ),
            None => Decision::no_match(EngineKind::Rego, self.def.clone()),
        }
    }

    fn kind(&self) -> EngineKind {
        EngineKind::Rego
    }
}

/// Accepts a bare verdict string or an object `{"verdict", "reason"}`
/// (a non-string reason is treated as empty).
fn parse_result(v: &regorus::Value) -> Option<(Verdict, String)> {
    let (verdict, reason) = match v {
        regorus::Value::String(s) => (s.to_string(), String::new()),
        regorus::Value::Object(obj) => {
            let get = |k: &str| match obj.get(&regorus::Value::from(k)) {
                Some(regorus::Value::String(s)) => s.to_string(),
                _ => String::new(),
            };
            (get("verdict"), get("reason"))
        }
        _ => return None,
    };
    let verdict = Verdict::parse(&verdict);
    verdict.is_valid().then_some((verdict, reason))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBJECT_MODULE: &str = r#"package runeward

default decision := {"verdict": "allow"}

decision := {"verdict": "deny", "reason": "no rm"} if {
	input.tool == "shell"
	startswith(input.arg, "rm ")
}

decision := {"verdict": "require-approval", "reason": "review /etc"} if {
	input.tool == "file.write"
	startswith(input.arg, "/etc/")
}
"#;

    const STRING_MODULE: &str = r#"package runeward

default decision := "allow"

decision := "deny" if {
	input.tool == "shell"
	startswith(input.arg, "rm ")
}
"#;

    #[test]
    fn object_decisions() {
        let e = RegoEngine::new(OBJECT_MODULE, "", Verdict::Allow).expect("prepare");
        let cases = [
            ("deny rm", "shell", "rm -rf /", Verdict::Deny, "no rm"),
            (
                "approve etc write",
                "file.write",
                "/etc/x",
                Verdict::RequireApproval,
                "review /etc",
            ),
            ("default allow", "shell", "ls", Verdict::Allow, ""),
        ];
        for (name, tool, arg, verdict, reason) in cases {
            let dec = e.evaluate(&Action::new(tool, arg));
            assert_eq!(dec.verdict, verdict, "{name}");
            assert_eq!(dec.reason, reason, "{name}");
            // The module's own default object still synthesizes a rule.
            let rule = dec.rule.expect(name);
            assert_eq!(rule.tool, tool, "{name}");
            assert_eq!(rule.match_glob, arg, "{name}");
        }
    }

    #[test]
    fn string_decisions() {
        let e = RegoEngine::new(STRING_MODULE, "", Verdict::Allow).expect("prepare");
        assert_eq!(
            e.evaluate(&Action::new("shell", "rm -rf /")).verdict,
            Verdict::Deny
        );
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn invalid_module() {
        assert!(RegoEngine::new("package runeward\n\ndecision := {", "", Verdict::Allow).is_err());
    }

    #[test]
    fn invalid_query() {
        assert!(RegoEngine::new(STRING_MODULE, "data.runeward.[", Verdict::Allow).is_err());
    }

    #[test]
    fn v0_syntax_rejected() {
        let v0 = "package runeward\n\ndecision = \"deny\" { input.tool == \"shell\" }\n";
        assert!(RegoEngine::new(v0, "", Verdict::Allow).is_err());
    }

    #[test]
    fn default_on_unrecognized() {
        let e = RegoEngine::new(
            "package runeward\n\ndefault decision := \"bogus\"\n",
            "",
            Verdict::Deny,
        )
        .expect("prepare");
        let dec = e.evaluate(&Action::new("shell", "ls"));
        assert_eq!(dec.verdict, Verdict::Deny);
        assert!(dec.rule.is_none());
        assert_eq!(dec.code, crate::ReasonCode::NoMatch);
    }

    #[test]
    fn undefined_falls_back_to_default() {
        let e = RegoEngine::new(
            "package runeward\n\ndecision := \"deny\" if input.tool == \"shell\"\n",
            "",
            Verdict::RequireApproval,
        )
        .expect("prepare");
        let dec = e.evaluate(&Action::new("net", "x"));
        assert_eq!(dec.verdict, Verdict::RequireApproval);
        assert!(dec.rule.is_none());
    }

    #[test]
    fn eval_error_fails_closed() {
        // An unprepared engine, as in the Go test's zero-value RegoEngine.
        let e = RegoEngine {
            engine: None,
            query: DEFAULT_REGO_QUERY.to_owned(),
            def: Verdict::Allow,
        };
        let dec = e.evaluate(&Action::new("shell", "0"));
        assert_eq!(dec.verdict, Verdict::Deny);
        assert!(dec.reason.contains("rego evaluation"), "{}", dec.reason);
        assert!(dec.rule.is_some());
    }

    #[test]
    fn conflicting_outputs_fail_closed() {
        let module = r#"package runeward

decision := "allow" if input.tool == "shell"
decision := "deny" if startswith(input.arg, "rm")
"#;
        let e = RegoEngine::new(module, "", Verdict::Allow).expect("prepare");
        let dec = e.evaluate(&Action::new("shell", "rm x"));
        assert_eq!(dec.verdict, Verdict::Deny);
        assert!(
            dec.reason.starts_with("policy: rego evaluation error: "),
            "{}",
            dec.reason
        );
        assert_eq!(dec.code, crate::ReasonCode::EvaluationError);
        // Inputs that do not hit the conflict still evaluate.
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn custom_query() {
        let module = "package custom\n\nverdict := \"require-approval\"\n";
        let e = RegoEngine::new(module, "data.custom.verdict", Verdict::Allow).expect("prepare");
        assert_eq!(e.query(), "data.custom.verdict");
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::RequireApproval
        );
    }
}
