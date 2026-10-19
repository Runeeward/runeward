//! A small static type checker for CEL rule expressions.
//!
//! `cel-interpreter` parses and evaluates but does not type-check, while the
//! Go engine compiles rules against a declared environment (`tool` and `arg`,
//! both strings) and rejects unknown identifiers, unknown functions, operand
//! type mismatches and non-bool results at construction time. This checker
//! reproduces those compile-time rejections for the standard CEL library so a
//! malformed rule fails fast instead of silently never matching.
//!
//! It is deliberately conservative: when a type cannot be inferred it becomes
//! `dyn`, which is accepted everywhere except as the rule's result type (Go
//! also rejects a `dyn` result, since its output type is not `bool`).

use std::collections::HashMap;
use std::fmt;

use cel_parser::ast::{EntryExpr, Expr, IdedExpr, operators};
use cel_parser::reference::Val;

/// The inferred static type of an expression.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Ty {
    Bool,
    Int,
    Uint,
    Double,
    String,
    Bytes,
    Null,
    Timestamp,
    Duration,
    List(Box<Ty>),
    Map(Box<Ty>, Box<Ty>),
    Dyn,
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool => f.write_str("bool"),
            Self::Int => f.write_str("int"),
            Self::Uint => f.write_str("uint"),
            Self::Double => f.write_str("double"),
            Self::String => f.write_str("string"),
            Self::Bytes => f.write_str("bytes"),
            Self::Null => f.write_str("null_type"),
            Self::Timestamp => f.write_str("google.protobuf.Timestamp"),
            Self::Duration => f.write_str("google.protobuf.Duration"),
            Self::List(e) => write!(f, "list({e})"),
            Self::Map(k, v) => write!(f, "map({k}, {v})"),
            Self::Dyn => f.write_str("dyn"),
        }
    }
}

impl Ty {
    fn is_dyn(&self) -> bool {
        matches!(self, Self::Dyn)
    }

    fn is_numeric(&self) -> bool {
        matches!(self, Self::Int | Self::Uint | Self::Double)
    }

    /// Reports whether a value of `self` may flow where `want` is expected.
    fn assignable(&self, want: &Ty) -> bool {
        match (self, want) {
            (Self::Dyn, _) | (_, Self::Dyn) => true,
            (Self::List(a), Self::List(b)) => a.assignable(b),
            (Self::Map(ak, av), Self::Map(bk, bv)) => ak.assignable(bk) && av.assignable(bv),
            (a, b) => a == b,
        }
    }

    /// The common type of two branches (list elements, ternary arms).
    /// An empty list literal's `list(dyn)` unifies with any list, so the
    /// accumulators of `map()`/`filter()` keep their element type.
    fn join(&self, other: &Ty) -> Ty {
        match (self, other) {
            (a, b) if a == b => a.clone(),
            (Ty::List(a), Ty::List(b)) => Ty::List(Box::new(a.join_elem(b))),
            (Ty::Map(ak, av), Ty::Map(bk, bv)) => {
                Ty::Map(Box::new(ak.join_elem(bk)), Box::new(av.join_elem(bv)))
            }
            _ => Ty::Dyn,
        }
    }

    fn join_elem(&self, other: &Ty) -> Ty {
        match (self, other) {
            (Ty::Dyn, t) | (t, Ty::Dyn) => t.clone(),
            (a, b) => a.join(b),
        }
    }
}

/// Type-checks `expr` in an environment declaring `vars`, returning the
/// expression's result type.
pub(crate) fn check(expr: &IdedExpr, vars: &[(&str, Ty)]) -> Result<Ty, String> {
    let mut scope: Vec<HashMap<String, Ty>> = vec![
        vars.iter()
            .map(|(n, t)| ((*n).to_owned(), t.clone()))
            .collect(),
    ];
    infer(expr, &mut scope)
}

fn lookup(scope: &[HashMap<String, Ty>], name: &str) -> Option<Ty> {
    scope.iter().rev().find_map(|s| s.get(name).cloned())
}

fn no_overload(func: &str, args: &[Ty]) -> String {
    let list = args
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    format!("found no matching overload for '{func}' applied to '({list})'")
}

fn infer(e: &IdedExpr, scope: &mut Vec<HashMap<String, Ty>>) -> Result<Ty, String> {
    match &e.expr {
        Expr::Unspecified => Err("unspecified expression".to_owned()),
        Expr::Literal(v) => Ok(match v {
            Val::String(_) => Ty::String,
            Val::Boolean(_) => Ty::Bool,
            Val::Int(_) => Ty::Int,
            Val::UInt(_) => Ty::Uint,
            Val::Double(_) => Ty::Double,
            Val::Bytes(_) => Ty::Bytes,
            Val::Null => Ty::Null,
        }),
        Expr::Ident(name) => {
            lookup(scope, name).ok_or_else(|| format!("undeclared reference to '{name}'"))
        }
        Expr::List(list) => {
            let mut elem: Option<Ty> = None;
            for el in &list.elements {
                let t = infer(el, scope)?;
                elem = Some(elem.map_or(t.clone(), |e| e.join(&t)));
            }
            Ok(Ty::List(Box::new(elem.unwrap_or(Ty::Dyn))))
        }
        Expr::Map(map) => {
            let (mut kt, mut vt): (Option<Ty>, Option<Ty>) = (None, None);
            for entry in &map.entries {
                let EntryExpr::MapEntry(me) = &entry.expr else {
                    return Err("unexpected struct field in map literal".to_owned());
                };
                let k = infer(&me.key, scope)?;
                let v = infer(&me.value, scope)?;
                if !matches!(k, Ty::Int | Ty::Uint | Ty::String | Ty::Bool | Ty::Dyn) {
                    return Err(format!("unsupported map key type: {k}"));
                }
                kt = Some(kt.map_or(k.clone(), |p| p.join(&k)));
                vt = Some(vt.map_or(v.clone(), |p| p.join(&v)));
            }
            Ok(Ty::Map(
                Box::new(kt.unwrap_or(Ty::Dyn)),
                Box::new(vt.unwrap_or(Ty::Dyn)),
            ))
        }
        Expr::Struct(s) => Err(format!("undeclared reference to '{}'", s.type_name)),
        Expr::Select(sel) => {
            let operand = infer(&sel.operand, scope)?;
            let field_ty = match &operand {
                Ty::Dyn => Ty::Dyn,
                Ty::Map(k, v) if k.assignable(&Ty::String) => (**v).clone(),
                other => {
                    return Err(format!("type '{other}' does not support field selection"));
                }
            };
            if sel.test { Ok(Ty::Bool) } else { Ok(field_ty) }
        }
        Expr::Comprehension(c) => {
            let range = infer(&c.iter_range, scope)?;
            let (v1, v2) = match &range {
                Ty::List(e) => (Ty::Int, (**e).clone()),
                Ty::Map(k, v) => ((**k).clone(), (**v).clone()),
                Ty::Dyn => (Ty::Dyn, Ty::Dyn),
                other => {
                    return Err(format!(
                        "expression of type '{other}' cannot be range of a comprehension (must be list, map, or dynamic)"
                    ));
                }
            };
            let accu = infer(&c.accu_init, scope)?;
            let mut frame = HashMap::new();
            match &c.iter_var2 {
                Some(second) => {
                    frame.insert(c.iter_var.clone(), v1);
                    frame.insert(second.clone(), v2);
                }
                None => {
                    // One-variable form: the element for lists, the key for maps.
                    let single = if matches!(range, Ty::List(_)) { v2 } else { v1 };
                    frame.insert(c.iter_var.clone(), single);
                }
            }
            frame.insert(c.accu_var.clone(), accu.clone());
            scope.push(frame);
            let res = (|| {
                infer(&c.loop_cond, scope)?;
                let step = infer(&c.loop_step, scope)?;
                // map()/filter() grow a list accumulator whose element type
                // comes from the step; refine it before checking the result.
                if let (Ty::List(_), Ty::List(_)) = (&accu, &step)
                    && let Some(f) = scope.last_mut()
                {
                    f.insert(c.accu_var.clone(), step.clone());
                }
                infer(&c.result, scope)
            })();
            scope.pop();
            res
        }
        Expr::Call(call) => {
            let target = match &call.target {
                Some(t) => Some(infer(t, scope)?),
                None => None,
            };
            let args = call
                .args
                .iter()
                .map(|a| infer(a, scope))
                .collect::<Result<Vec<_>, _>>()?;
            check_call(&call.func_name, target, &args)
        }
    }
}

fn check_call(func: &str, target: Option<Ty>, args: &[Ty]) -> Result<Ty, String> {
    let all: Vec<Ty> = target.iter().cloned().chain(args.iter().cloned()).collect();
    let bad = || no_overload(func, &all);
    match (func, target.as_ref(), args) {
        (operators::LOGICAL_AND | operators::LOGICAL_OR, None, [a, b]) => {
            if a.assignable(&Ty::Bool) && b.assignable(&Ty::Bool) {
                Ok(Ty::Bool)
            } else {
                Err(bad())
            }
        }
        (operators::LOGICAL_NOT | operators::NOT_STRICTLY_FALSE, None, [a]) => {
            if a.assignable(&Ty::Bool) {
                Ok(Ty::Bool)
            } else {
                Err(bad())
            }
        }
        (operators::CONDITIONAL, None, [c, t, f]) => {
            if c.assignable(&Ty::Bool) {
                Ok(t.join(f))
            } else {
                Err(bad())
            }
        }
        (operators::EQUALS | operators::NOT_EQUALS, None, [a, b]) => {
            let comparable = a.assignable(b)
                || b.assignable(a)
                || (a.is_numeric() && b.is_numeric())
                || matches!(a, Ty::Null)
                || matches!(b, Ty::Null);
            if comparable { Ok(Ty::Bool) } else { Err(bad()) }
        }
        (
            operators::LESS
            | operators::LESS_EQUALS
            | operators::GREATER
            | operators::GREATER_EQUALS,
            None,
            [a, b],
        ) => {
            let ok = a.is_dyn()
                || b.is_dyn()
                || (a.is_numeric() && b.is_numeric())
                || (a == b
                    && matches!(
                        a,
                        Ty::String | Ty::Bytes | Ty::Bool | Ty::Timestamp | Ty::Duration
                    ));
            if ok { Ok(Ty::Bool) } else { Err(bad()) }
        }
        (operators::ADD, None, [a, b]) => match (a, b) {
            (Ty::Dyn, o) | (o, Ty::Dyn) => Ok(if matches!(o, Ty::List(_)) {
                Ty::List(Box::new(Ty::Dyn))
            } else {
                Ty::Dyn
            }),
            (Ty::List(x), Ty::List(y)) => Ok(Ty::List(Box::new(x.join_elem(y)))),
            (Ty::Timestamp, Ty::Duration) | (Ty::Duration, Ty::Timestamp) => Ok(Ty::Timestamp),
            (x, y)
                if x == y
                    && matches!(
                        x,
                        Ty::Int | Ty::Uint | Ty::Double | Ty::String | Ty::Bytes | Ty::Duration
                    ) =>
            {
                Ok(x.clone())
            }
            _ => Err(bad()),
        },
        (operators::SUBSTRACT, None, [a, b]) => match (a, b) {
            (Ty::Dyn, _) | (_, Ty::Dyn) => Ok(Ty::Dyn),
            (Ty::Timestamp, Ty::Timestamp) => Ok(Ty::Duration),
            (Ty::Timestamp, Ty::Duration) => Ok(Ty::Timestamp),
            (x, y) if x == y && matches!(x, Ty::Int | Ty::Uint | Ty::Double | Ty::Duration) => {
                Ok(x.clone())
            }
            _ => Err(bad()),
        },
        (operators::MULTIPLY | operators::DIVIDE, None, [a, b]) => match (a, b) {
            (Ty::Dyn, _) | (_, Ty::Dyn) => Ok(Ty::Dyn),
            (x, y) if x == y && x.is_numeric() => Ok(x.clone()),
            _ => Err(bad()),
        },
        (operators::MODULO, None, [a, b]) => match (a, b) {
            (Ty::Dyn, _) | (_, Ty::Dyn) => Ok(Ty::Dyn),
            (x, y) if x == y && matches!(x, Ty::Int | Ty::Uint) => Ok(x.clone()),
            _ => Err(bad()),
        },
        (operators::NEGATE, None, [a]) => match a {
            Ty::Dyn | Ty::Int | Ty::Double => Ok(a.clone()),
            _ => Err(bad()),
        },
        (operators::INDEX, None, [c, i]) => match c {
            Ty::Dyn => Ok(Ty::Dyn),
            Ty::List(e) if i.assignable(&Ty::Int) || i.is_numeric() => Ok((**e).clone()),
            Ty::Map(k, v) if i.assignable(k) || (k.is_numeric() && i.is_numeric()) => {
                Ok((**v).clone())
            }
            _ => Err(bad()),
        },
        (operators::IN, None, [x, c]) => match c {
            Ty::Dyn => Ok(Ty::Bool),
            Ty::List(e) if x.assignable(e) || (x.is_numeric() && e.is_numeric()) => Ok(Ty::Bool),
            Ty::Map(k, _) if x.assignable(k) || (x.is_numeric() && k.is_numeric()) => Ok(Ty::Bool),
            _ => Err(bad()),
        },
        // String predicates.
        ("startsWith" | "endsWith" | "contains" | "matches", Some(t), [a])
            if t.assignable(&Ty::String) && a.assignable(&Ty::String) =>
        {
            Ok(Ty::Bool)
        }
        ("matches", None, [t, a]) if t.assignable(&Ty::String) && a.assignable(&Ty::String) => {
            Ok(Ty::Bool)
        }
        ("size", Some(t), []) | ("size", None, [t])
            if matches!(
                t,
                Ty::Dyn | Ty::String | Ty::Bytes | Ty::List(_) | Ty::Map(_, _)
            ) =>
        {
            Ok(Ty::Int)
        }
        // Conversions.
        ("int", None, [Ty::Dyn | Ty::Int | Ty::Uint | Ty::Double | Ty::String | Ty::Timestamp]) => {
            Ok(Ty::Int)
        }
        ("uint", None, [Ty::Dyn | Ty::Int | Ty::Uint | Ty::Double | Ty::String]) => Ok(Ty::Uint),
        ("double", None, [Ty::Dyn | Ty::Int | Ty::Uint | Ty::Double | Ty::String]) => {
            Ok(Ty::Double)
        }
        ("string", None, [a]) if !matches!(a, Ty::List(_) | Ty::Map(_, _) | Ty::Null) => {
            Ok(Ty::String)
        }
        ("bytes", None, [Ty::Dyn | Ty::String | Ty::Bytes]) => Ok(Ty::Bytes),
        ("timestamp", None, [Ty::Dyn | Ty::String | Ty::Int | Ty::Timestamp]) => Ok(Ty::Timestamp),
        ("duration", None, [Ty::Dyn | Ty::String | Ty::Duration]) => Ok(Ty::Duration),
        (
            "getFullYear" | "getMonth" | "getDayOfYear" | "getDayOfMonth" | "getDate"
            | "getDayOfWeek" | "getHours" | "getMinutes" | "getSeconds" | "getMilliseconds",
            Some(Ty::Dyn | Ty::Timestamp | Ty::Duration),
            [] | [_],
        ) => Ok(Ty::Int),
        (
            operators::LOGICAL_AND
            | operators::LOGICAL_OR
            | operators::LOGICAL_NOT
            | operators::NOT_STRICTLY_FALSE
            | operators::CONDITIONAL
            | operators::EQUALS
            | operators::NOT_EQUALS
            | operators::LESS
            | operators::LESS_EQUALS
            | operators::GREATER
            | operators::GREATER_EQUALS
            | operators::ADD
            | operators::SUBSTRACT
            | operators::MULTIPLY
            | operators::DIVIDE
            | operators::MODULO
            | operators::NEGATE
            | operators::INDEX
            | operators::IN
            | "startsWith"
            | "endsWith"
            | "contains"
            | "matches"
            | "size"
            | "int"
            | "uint"
            | "double"
            | "string"
            | "bytes"
            | "timestamp"
            | "duration"
            | "getFullYear"
            | "getMonth"
            | "getDayOfYear"
            | "getDayOfMonth"
            | "getDate"
            | "getDayOfWeek"
            | "getHours"
            | "getMinutes"
            | "getSeconds"
            | "getMilliseconds",
            _,
            _,
        ) => Err(bad()),
        _ => Err(format!("undeclared reference to '{func}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(src: &str) -> Result<Ty, String> {
        let e = cel_parser::Parser::new()
            .parse(src)
            .map_err(|e| e.to_string())?;
        check(&e, &[("tool", Ty::String), ("arg", Ty::String)])
    }

    #[test]
    fn infers_bool_for_rule_shapes() {
        for src in [
            r#"tool == "shell" && arg.startsWith("rm ")"#,
            r#"tool == "shell" && (arg.startsWith("rm ") || arg.contains("mkfs"))"#,
            r#"arg.matches("^(apt|apt-get|pip3?) .*")"#,
            r#"size(arg) > 3"#,
            r#"arg in ["a", "b"]"#,
            r#"["a", "b"].exists(x, arg.startsWith(x))"#,
            r#"["a", "b"].all(x, x != arg)"#,
        ] {
            assert_eq!(ty(src), Ok(Ty::Bool), "{src}");
        }
    }

    #[test]
    fn rejects_go_compile_errors() {
        assert!(ty("arg").is_ok_and(|t| t == Ty::String));
        assert!(ty(r#"nope == "x""#).is_err());
        assert!(ty(r#"tool == 1"#).is_err());
        assert!(ty(r#"arg.lowerAscii() == "x""#).is_err());
        assert!(ty(r#"max(1, 2) == 2"#).is_err());
        assert!(ty(r#"arg.foo == "x""#).is_err());
        assert!(ty(r#"arg && true"#).is_err());
    }

    #[test]
    fn list_and_map_element_types() {
        assert_eq!(ty("[true][0]"), Ok(Ty::Bool));
        assert_eq!(ty(r#"{"a": true}["a"]"#), Ok(Ty::Bool));
        assert_eq!(
            ty(r#"["a"].map(x, x + arg)"#),
            Ok(Ty::List(Box::new(Ty::String)))
        );
        assert_eq!(
            ty(r#"["a"].filter(x, x == arg)"#),
            Ok(Ty::List(Box::new(Ty::String)))
        );
    }
}
