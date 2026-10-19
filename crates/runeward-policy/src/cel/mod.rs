//! The CEL authority engine (`policy_engine = "cel"`).
//!
//! Each rule is a boolean CEL expression over the string variables `tool` and
//! `arg`; the first rule that evaluates to `true` wins, otherwise the default
//! verdict applies. Rules are parsed and type-checked up front (see
//! [`check`]), so a malformed rule fails at construction rather than silently
//! mis-authorizing at run time.
//!
//! Evaluation uses `cel-interpreter`, with two shims for parity with the
//! cel-go engine the Go implementation used:
//!
//! * `&&`, `||`, `!` and `?:` at the logical skeleton of a rule follow CEL's
//!   commutative error semantics (`error && false` is `false`, `error || true`
//!   is `true`), where `cel-interpreter` would propagate the left error.
//! * `size()` on strings counts Unicode code points, not bytes.

mod check;

use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};

use cel_interpreter::extractors::This;
use cel_interpreter::objects::Value;
use cel_interpreter::{Context, ExecutionError, FunctionContext};
use cel_parser::ast::{Expr, IdedExpr, operators};
use runeward_charter::{CelRule, PolicyRule, Verdict};

use self::check::Ty;
use crate::decision::{Action, Decision, EngineKind, Evaluator, default_or_allow};

/// A CEL rule set failed to compile.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CelError {
    /// A rule has no expression.
    #[error("policy: cel rule {index}: empty expr")]
    EmptyExpr {
        /// Zero-based rule index.
        index: usize,
    },
    /// A rule failed to parse or type-check.
    #[error("policy: cel rule {index} ({expr:?}): {message}")]
    Compile {
        /// Zero-based rule index.
        index: usize,
        /// The rule's expression.
        expr: String,
        /// The parser or checker message.
        message: String,
    },
    /// A rule's expression does not yield a bool.
    #[error("policy: cel rule {index} ({expr:?}): expression must return bool, got {got}")]
    NotBool {
        /// Zero-based rule index.
        index: usize,
        /// The rule's expression.
        expr: String,
        /// The inferred result type.
        got: String,
    },
}

struct CompiledRule {
    expr: IdedExpr,
    verdict: Verdict,
    src: CelRule,
}

/// An authority engine backed by CEL rules. Safe for concurrent use.
pub struct CelEngine {
    rules: Vec<CompiledRule>,
    def: Verdict,
}

impl fmt::Debug for CelEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CelEngine")
            .field(
                "rules",
                &self.rules.iter().map(|r| &r.src).collect::<Vec<_>>(),
            )
            .field("def", &self.def)
            .finish()
    }
}

impl CelEngine {
    /// Compiles `rules` with a default verdict (allow when unset). Each
    /// expression must yield a bool over `tool` and `arg`; an unset rule
    /// verdict means allow.
    pub fn new(rules: &[CelRule], def: Verdict) -> Result<Self, CelError> {
        let vars = [("tool", Ty::String), ("arg", Ty::String)];
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, r) in rules.iter().enumerate() {
            if r.expr.is_empty() {
                return Err(CelError::EmptyExpr { index });
            }
            let compile_err = |message: String| CelError::Compile {
                index,
                expr: r.expr.clone(),
                message,
            };
            let expr = parse(&r.expr).map_err(compile_err)?;
            let ty = check::check(&expr, &vars).map_err(compile_err)?;
            if ty != Ty::Bool {
                return Err(CelError::NotBool {
                    index,
                    expr: r.expr.clone(),
                    got: ty.to_string(),
                });
            }
            compiled.push(CompiledRule {
                expr,
                verdict: default_or_allow(r.verdict.clone()),
                src: r.clone(),
            });
        }
        Ok(Self {
            rules: compiled,
            def: default_or_allow(def),
        })
    }
}

impl Evaluator for CelEngine {
    /// The first rule whose expression is true wins. An evaluation error
    /// fails closed to deny; no match returns the default verdict with no
    /// rule.
    fn evaluate(&self, action: &Action) -> Decision {
        let ctx = context(action);
        for (i, r) in self.rules.iter().enumerate() {
            match eval_logical(&r.expr, &ctx) {
                Err(err) => {
                    let reason = format!("policy: cel rule {i} evaluation error: {err}");
                    return Decision::eval_error(
                        EngineKind::Cel,
                        &action.tool,
                        &r.src.expr,
                        reason,
                        Some(i),
                    );
                }
                Ok(Value::Bool(true)) => {
                    let rule = PolicyRule {
                        tool: action.tool.clone(),
                        match_glob: r.src.expr.clone(),
                        match_argv: String::new(),
                        verdict: r.verdict.clone(),
                        reason: r.src.reason.clone(),
                    };
                    return Decision::matched(EngineKind::Cel, rule, Some(i));
                }
                Ok(_) => {}
            }
        }
        Decision::no_match(EngineKind::Cel, self.def.clone())
    }

    fn kind(&self) -> EngineKind {
        EngineKind::Cel
    }
}

/// Parses a CEL expression. The ANTLR runtime behind `cel-parser` panics on
/// some malformed inputs instead of reporting an error, so the panic is
/// contained and reported as a parse error.
fn parse(src: &str) -> Result<IdedExpr, String> {
    match catch_unwind(AssertUnwindSafe(|| cel_parser::Parser::new().parse(src))) {
        Ok(Ok(expr)) => Ok(expr),
        Ok(Err(errs)) => Err(errs.to_string()),
        Err(_) => Err("ERROR: <input>: syntax error".to_owned()),
    }
}

/// Builds the evaluation context: the standard library with the `size`
/// shim, plus `tool` and `arg`.
fn context(action: &Action) -> Context<'static> {
    let mut ctx = Context::default();
    ctx.add_function("size", size);
    ctx.add_variable_from_value("tool", action.tool.clone());
    ctx.add_variable_from_value("arg", action.arg.clone());
    ctx
}

/// `size()` with CEL semantics: strings count code points.
fn size(ftx: &FunctionContext, This(this): This<Value>) -> Result<i64, ExecutionError> {
    let n = match this {
        Value::String(s) => s.chars().count(),
        Value::Bytes(b) => b.len(),
        Value::List(l) => l.len(),
        Value::Map(m) => m.map.len(),
        other => return Err(ftx.error(format!("cannot determine the size of {other:?}"))),
    };
    i64::try_from(n).map_err(|_| ftx.error("integer overflow"))
}

/// Evaluates the logical skeleton of an expression with CEL's commutative
/// error semantics, delegating every other node to `cel-interpreter`.
fn eval_logical(e: &IdedExpr, ctx: &Context<'_>) -> Result<Value, ExecutionError> {
    let Expr::Call(call) = &e.expr else {
        return Value::resolve(e, ctx);
    };
    if call.target.is_some() {
        return Value::resolve(e, ctx);
    }
    match (call.func_name.as_str(), call.args.as_slice()) {
        (operators::LOGICAL_AND, [a, b]) => {
            let l = as_bool(eval_logical(a, ctx), &call.func_name);
            if matches!(l, Ok(false)) {
                return Ok(Value::Bool(false));
            }
            let r = as_bool(eval_logical(b, ctx), &call.func_name);
            match (l, r) {
                (_, Ok(false)) => Ok(Value::Bool(false)),
                (Ok(true), Ok(true)) => Ok(Value::Bool(true)),
                (Err(err), _) | (_, Err(err)) => Err(err),
                (Ok(false), _) => Ok(Value::Bool(false)),
            }
        }
        (operators::LOGICAL_OR, [a, b]) => {
            let l = as_bool(eval_logical(a, ctx), &call.func_name);
            if matches!(l, Ok(true)) {
                return Ok(Value::Bool(true));
            }
            let r = as_bool(eval_logical(b, ctx), &call.func_name);
            match (l, r) {
                (_, Ok(true)) => Ok(Value::Bool(true)),
                (Ok(false), Ok(false)) => Ok(Value::Bool(false)),
                (Err(err), _) | (_, Err(err)) => Err(err),
                (Ok(true), _) => Ok(Value::Bool(true)),
            }
        }
        (operators::LOGICAL_NOT, [a]) => {
            as_bool(eval_logical(a, ctx), &call.func_name).map(|b| Value::Bool(!b))
        }
        (operators::CONDITIONAL, [c, t, f]) => {
            if as_bool(eval_logical(c, ctx), &call.func_name)? {
                eval_logical(t, ctx)
            } else {
                eval_logical(f, ctx)
            }
        }
        _ => Value::resolve(e, ctx),
    }
}

fn as_bool(v: Result<Value, ExecutionError>, func: &str) -> Result<bool, ExecutionError> {
    match v? {
        Value::Bool(b) => Ok(b),
        other => Err(ExecutionError::function_error(
            func,
            format!("no such overload for {other:?}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cel(expr: &str, verdict: Verdict, reason: &str) -> CelRule {
        CelRule {
            expr: expr.into(),
            verdict,
            reason: reason.into(),
        }
    }

    #[test]
    fn evaluate() {
        let eng = CelEngine::new(
            &[
                cel(
                    r#"tool == "shell" && arg.startsWith("rm ")"#,
                    Verdict::Deny,
                    "no rm",
                ),
                cel(
                    r#"tool == "file.write" && arg.startsWith("/etc/")"#,
                    Verdict::RequireApproval,
                    "review /etc",
                ),
                cel(
                    r#"tool == "net" && arg.endsWith(".internal")"#,
                    Verdict::Allow,
                    "",
                ),
            ],
            Verdict::Deny,
        )
        .expect("compile");
        let cases = [
            ("shell", "rm -rf /", Verdict::Deny),
            ("shell", "ls -la", Verdict::Deny),
            ("file.write", "/etc/motd", Verdict::RequireApproval),
            ("file.write", "/workspace/x", Verdict::Deny),
            ("net", "db.svc.internal", Verdict::Allow),
        ];
        for (tool, arg, want) in cases {
            assert_eq!(
                eng.evaluate(&Action::new(tool, arg)).verdict,
                want,
                "{tool} {arg}"
            );
        }
    }

    #[test]
    fn compile_errors() {
        assert!(matches!(
            CelEngine::new(&[cel("arg", Verdict::Unset, "")], Verdict::Unset),
            Err(CelError::NotBool { .. })
        ));
        assert!(matches!(
            CelEngine::new(&[cel(r#"nope == "x""#, Verdict::Unset, "")], Verdict::Unset),
            Err(CelError::Compile { .. })
        ));
        assert!(matches!(
            CelEngine::new(&[cel("", Verdict::Unset, "")], Verdict::Unset),
            Err(CelError::EmptyExpr { index: 0 })
        ));
        assert!(matches!(
            CelEngine::new(&[cel("tool ==", Verdict::Unset, "")], Verdict::Unset),
            Err(CelError::Compile { .. })
        ));
    }

    #[test]
    fn runtime_error_fails_closed() {
        let eng = CelEngine::new(
            &[cel(
                r#"tool == "shell" && (1 / int(arg)) > 0"#,
                Verdict::Allow,
                "",
            )],
            Verdict::Allow,
        )
        .expect("compile");
        let dec = eng.evaluate(&Action::new("shell", "0"));
        assert_eq!(dec.verdict, Verdict::Deny);
        assert!(
            dec.reason.contains("cel rule 0 evaluation error"),
            "reason = {:?}",
            dec.reason
        );
        assert!(dec.rule.is_some());
        assert_eq!(dec.code, crate::ReasonCode::EvaluationError);
    }

    #[test]
    fn error_absorption_is_commutative() {
        // cel-go: `error && false` is false, `error || true` is true.
        let eng = CelEngine::new(
            &[
                cel(
                    r#"(1 / int(arg)) > 0 && tool == "nope""#,
                    Verdict::Deny,
                    "a",
                ),
                cel(
                    r#"(1 / int(arg)) > 0 || tool == "shell""#,
                    Verdict::RequireApproval,
                    "b",
                ),
            ],
            Verdict::Allow,
        )
        .expect("compile");
        let dec = eng.evaluate(&Action::new("shell", "0"));
        assert_eq!(dec.verdict, Verdict::RequireApproval);
        assert_eq!(dec.reason, "b");
    }

    #[test]
    fn unset_rule_verdict_is_allow_and_rule_synthesized() {
        let eng = CelEngine::new(
            &[cel(r#"tool == "net""#, Verdict::Unset, "r")],
            Verdict::Deny,
        )
        .expect("compile");
        let dec = eng.evaluate(&Action::new("net", "x"));
        assert_eq!(dec.verdict, Verdict::Allow);
        let rule = dec.rule.expect("rule");
        assert_eq!(rule.tool, "net");
        assert_eq!(rule.match_glob, r#"tool == "net""#);
        assert_eq!(dec.rule_index, Some(0));
    }

    #[test]
    fn size_counts_code_points() {
        let eng = CelEngine::new(&[cel("size(arg) == 2", Verdict::Deny, "")], Verdict::Allow)
            .expect("compile");
        assert_eq!(eng.evaluate(&Action::new("x", "éé")).verdict, Verdict::Deny);
    }

    #[test]
    fn engines_are_evaluators() {
        fn assert_eval<T: Evaluator>() {}
        assert_eval::<CelEngine>();
        assert_eval::<crate::RuleEngine>();
        assert_eval::<crate::RegoEngine>();
    }
}
