//! Rune Box's authority engines, session guardrails and usage accounting.
//!
//! * [`RuleEngine`] evaluates an [`Action`] against a Charter's ordered
//!   `[[policy]]` rules, strictly first-match-wins (`match` globs over the
//!   argument, `match_argv` globs over the executable, seeing through shell
//!   wrappers).
//! * [`CelEngine`] and [`RegoEngine`] express the same decision in CEL or
//!   Rego.
//! * [`engine_for_charter`] / [`engine_for_charter_with_bundle`] build the
//!   engine a Charter selects, including signed OCI policy bundles; every
//!   engine is used through the [`Evaluator`] trait.
//! * [`Guard`] caps wall-clock time, exec count and egress, and detects
//!   failure loops.
//! * [`accounting`] tracks token and spend usage per sandbox and Charter.
//! * [`check_subsumption`] proves a child Charter grants no more than its
//!   parent's, so derived agents may run under a narrower Charter.
//!
//! Engines never fail at evaluation time: errors fail closed to deny with
//! [`ReasonCode::EvaluationError`].
//!
//! # Extension points
//!
//! [`Action`], [`Decision`], [`ReasonCode`] and [`EngineKind`] are
//! `#[non_exhaustive]` so the planned policy features can be added without
//! breaking callers: per-action effect classes (read / write / irreversible,
//! with untagged actions treated as irreversible and gated on approval),
//! per-route call budgets, rules over structured body and argument fields, an
//! audit (dry-run) mode alongside enforce, and a minimum isolation floor.
//! Each would add inputs to `Action`, a reason code, and, for audit mode, a
//! wrapping [`Evaluator`] that records the would-be decision.

pub mod accounting;
mod build;
mod cel;
mod decision;
mod guard;
mod rego;
mod rules;
pub mod subsume;

pub use build::{
    BuildError, POLICY_DEFAULT_ENV, engine_for_bundle, engine_for_charter,
    engine_for_charter_with_bundle, no_match_verdict, no_match_verdict_from_env,
};
pub use cel::{CelEngine, CelError};
pub use decision::{Action, Decision, EngineKind, Evaluator, ReasonCode};
pub use guard::{Clock, Guard, GuardError};
pub use rego::{DEFAULT_REGO_QUERY, RegoEngine, RegoError};
pub use rules::{RuleEngine, match_glob};
pub use subsume::{Proof, Refusal, charters_equivalent, check_subsumption};
