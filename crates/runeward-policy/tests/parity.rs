//! Decision parity with the Go engines.
//!
//! `fixtures/go-decisions.json` was recorded by running the Go
//! `internal/policy` engines over every example Charter that defines policy
//! (`examples/`, `examples/safe/`) plus the feature-focused Charters in
//! `fixtures/charters/`, for each action in `fixtures/parity-actions.json`.
//! Every Rust decision must match: verdict, reason and the attached rule.
//! Evaluation-error reasons embed engine-specific error text, so only their
//! `… evaluation error: ` prefix is compared.

use std::path::{Path, PathBuf};

use runeward_charter::{Options, SignedCharters, Verdict, load};
use runeward_policy::{Action, ReasonCode, engine_for_charter, no_match_verdict};
use serde::Deserialize;

#[derive(Deserialize)]
struct Recorded {
    charter: String,
    engine: String,
    default: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    tool: String,
    arg: String,
    #[serde(default)]
    args: Vec<String>,
    verdict: String,
    reason: String,
    rule: Option<Rule>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct Rule {
    tool: String,
    #[serde(rename = "match")]
    match_glob: String,
    match_argv: String,
    verdict: String,
    reason: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Reduces an evaluation-error reason to its engine-independent prefix.
fn normalize(reason: &str) -> String {
    const MARKERS: [&str; 2] = ["evaluation error: ", "evaluation panic: "];
    for m in MARKERS {
        if let Some(i) = reason.find(m) {
            return reason[..i + m.len()].to_owned();
        }
    }
    reason.to_owned()
}

#[test]
fn decisions_match_go() {
    let data = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go-decisions.json"),
    )
    .expect("read fixture");
    let recorded: Vec<Recorded> = serde_json::from_str(&data).expect("parse fixture");
    assert!(recorded.len() >= 30, "fixture covers too few Charters");

    let mut failures = Vec::new();
    let mut checked = 0usize;
    for rec in &recorded {
        let (dir, name) = rec.charter.rsplit_once('/').expect("dir/name");
        let opts = Options {
            config_dir: Some(repo_root().join(dir)),
            working_dir: None,
            signed: SignedCharters::Disabled,
        };
        let charter = load(name, &opts).unwrap_or_else(|e| panic!("load {}: {e}", rec.charter));
        let default = no_match_verdict(Some(&charter), None);
        assert_eq!(default.as_str(), rec.default, "{}: default", rec.charter);
        let engine = engine_for_charter(&charter, default.clone())
            .unwrap_or_else(|e| panic!("engine {}: {e}", rec.charter));
        assert_eq!(
            engine.kind().as_str(),
            rec.engine,
            "{}: engine",
            rec.charter
        );

        for c in &rec.cases {
            checked += 1;
            let action = Action::new(c.tool.clone(), c.arg.clone()).with_args(c.args.clone());
            let d = engine.evaluate(&action);
            let got_rule = d.rule.as_ref().map(|r| Rule {
                tool: r.tool.clone(),
                match_glob: r.match_glob.clone(),
                match_argv: r.match_argv.clone(),
                verdict: r.verdict.to_string(),
                reason: normalize(&r.reason),
            });
            let want_rule = c.rule.as_ref().map(|r| Rule {
                tool: r.tool.clone(),
                match_glob: r.match_glob.clone(),
                match_argv: r.match_argv.clone(),
                verdict: r.verdict.clone(),
                reason: normalize(&r.reason),
            });
            let ok = d.verdict.as_str() == c.verdict
                && normalize(&d.reason) == normalize(&c.reason)
                && got_rule == want_rule;
            if !ok {
                failures.push(format!(
                    "{} {:?} {:?}: go=({}, {:?}, {:?}) rust=({}, {:?}, {:?})",
                    rec.charter,
                    c.tool,
                    c.arg,
                    c.verdict,
                    c.reason,
                    want_rule,
                    d.verdict,
                    d.reason,
                    got_rule
                ));
            }
            // Structured context is consistent with the parity fields.
            let want_code = if d.reason.contains("evaluation error: ") {
                ReasonCode::EvaluationError
            } else if d.rule.is_some() {
                ReasonCode::RuleMatched
            } else {
                ReasonCode::NoMatch
            };
            assert_eq!(d.code, want_code, "{} {:?}", rec.charter, c.arg);
            if d.code == ReasonCode::NoMatch {
                assert_eq!(d.verdict, default);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} decisions differ from Go:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(checked > 2000, "only {checked} decisions checked");
    // Sanity: the fixture exercises every verdict.
    for v in [Verdict::Allow, Verdict::Deny, Verdict::RequireApproval] {
        assert!(
            recorded
                .iter()
                .flat_map(|r| &r.cases)
                .any(|c| c.verdict == v.as_str()),
            "fixture never yields {v}"
        );
    }
}
