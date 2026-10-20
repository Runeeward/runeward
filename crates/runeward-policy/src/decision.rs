//! The request and response types shared by every authority engine.

use std::fmt;

use runeward_charter::{PolicyRule, Verdict};

/// A single tool invocation an engine is asked to authorize.
///
/// The struct is `#[non_exhaustive]` so later inputs (an effect class, the
/// route a call targets, structured body fields) can be added without
/// breaking callers; build one with [`Action::new`] and the `with_*` methods.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Action {
    /// The action surface, e.g. `shell`, `file.read`, `net`.
    pub tool: String,
    /// The command line, path or hostname the tool acts on.
    pub arg: String,
    /// The raw argument vector when the tool is invoked with one (e.g.
    /// `shell`). It powers argv-aware rule matching; empty for tools without
    /// an argv, in which case `arg` is split on whitespace.
    pub args: Vec<String>,
}

impl Action {
    /// An action with no argument vector.
    pub fn new(tool: impl Into<String>, arg: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            arg: arg.into(),
            args: Vec::new(),
        }
    }

    /// Sets the raw argument vector.
    #[must_use]
    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }
}

/// Which authority engine rendered a [`Decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EngineKind {
    /// The built-in first-match glob/argv rules (`[[policy]]`).
    Builtin,
    /// CEL rules (`[[cel]]`).
    Cel,
    /// A Rego module (`[rego]` or a Rego policy bundle).
    Rego,
}

impl EngineKind {
    /// The engine's name as used in Charters and traces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Cel => "cel",
            Self::Rego => "rego",
        }
    }
}

impl fmt::Display for EngineKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stable, machine-readable explanation of why a [`Decision`] was rendered.
///
/// `#[non_exhaustive]`: later guardrails (budgets, effect classes, isolation
/// floors) add their own codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReasonCode {
    /// A rule (or a Rego decision) matched and supplied the verdict.
    RuleMatched,
    /// Nothing matched; the engine's default verdict applies.
    NoMatch,
    /// The engine failed while evaluating and failed closed to deny.
    EvaluationError,
}

impl ReasonCode {
    /// The code's wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuleMatched => "rule_matched",
            Self::NoMatch => "no_match",
            Self::EvaluationError => "evaluation_error",
        }
    }
}

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of evaluating an [`Action`].
///
/// `verdict`, `reason` and `rule` carry the same values the Go engines
/// produce; `code`, `engine` and `rule_index` add structured context for
/// audit records and traces.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decision {
    /// What to do with the action.
    pub verdict: Verdict,
    /// Human-readable explanation (shown to approvers, recorded in the
    /// ledger); empty for default decisions.
    pub reason: String,
    /// Machine-readable explanation.
    pub code: ReasonCode,
    /// The engine that rendered the decision.
    pub engine: EngineKind,
    /// The rule that produced this decision; `None` when the engine fell
    /// back to its default verdict. CEL and Rego decisions synthesize one
    /// (`match` holds the CEL expression, or the action's argument for Rego).
    pub rule: Option<PolicyRule>,
    /// Zero-based position of the matched rule in its rule list, when the
    /// engine has one (builtin and CEL).
    pub rule_index: Option<usize>,
}

impl Decision {
    /// A default (no-match) decision.
    pub fn no_match(engine: EngineKind, verdict: Verdict) -> Self {
        Self {
            verdict,
            reason: String::new(),
            code: ReasonCode::NoMatch,
            engine,
            rule: None,
            rule_index: None,
        }
    }

    /// A decision produced by a matched rule.
    pub fn matched(engine: EngineKind, rule: PolicyRule, index: Option<usize>) -> Self {
        Self {
            verdict: rule.verdict.clone(),
            reason: rule.reason.clone(),
            code: ReasonCode::RuleMatched,
            engine,
            rule: Some(rule),
            rule_index: index,
        }
    }

    /// A fail-closed deny after an evaluation error. A synthesized rule
    /// (tool, `matched`, deny, reason) is attached, as in Go.
    pub fn eval_error(
        engine: EngineKind,
        tool: &str,
        matched: &str,
        reason: String,
        index: Option<usize>,
    ) -> Self {
        Self {
            verdict: Verdict::Deny,
            reason: reason.clone(),
            code: ReasonCode::EvaluationError,
            engine,
            rule: Some(PolicyRule {
                tool: tool.to_owned(),
                match_glob: matched.to_owned(),
                match_argv: String::new(),
                verdict: Verdict::Deny,
                reason,
            }),
            rule_index: index,
        }
    }
}

/// Renders a [`Decision`] for an [`Action`], so the control plane can select
/// an engine per Charter without caring which is in use.
pub trait Evaluator: Send + Sync + fmt::Debug {
    /// Evaluates one action. Never fails: engine errors fail closed to deny.
    fn evaluate(&self, action: &Action) -> Decision;

    /// Which engine this is.
    fn kind(&self) -> EngineKind;
}

/// Returns `def`, or allow when it is unset (the Go `def == ""` fallback).
pub(crate) fn default_or_allow(def: Verdict) -> Verdict {
    if def == Verdict::Unset {
        Verdict::Allow
    } else {
        def
    }
}
