//! Request-level rules for inspected endpoints: path normalisation, glob
//! matching, JSON-RPC/MCP body parsing and the deny-wins evaluation.
//!
//! Everything here is pure so it can be tested without sockets.

use runeward_charter::{Endpoint, RequestRule};

/// Inspected endpoint protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// No inspection; CONNECT tunnel with an SNI check only.
    Tcp,
    /// HTTP method + path rules.
    Rest,
    /// Like REST on the upgrade request; frames are not inspected.
    Websocket,
    /// JSON-RPC over HTTP with `tools/call` tool matching.
    Mcp,
    /// JSON-RPC over HTTP, method matching.
    JsonRpc,
}

impl Protocol {
    /// Parses the Charter spelling (empty means `tcp`).
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "" | "tcp" => Self::Tcp,
            "rest" => Self::Rest,
            "websocket" => Self::Websocket,
            "mcp" => Self::Mcp,
            "json-rpc" => Self::JsonRpc,
            _ => return None,
        })
    }

    /// The Charter spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Rest => "rest",
            Self::Websocket => "websocket",
            Self::Mcp => "mcp",
            Self::JsonRpc => "json-rpc",
        }
    }

    /// Whether requests are terminated and inspected.
    pub fn inspected(self) -> bool {
        self != Self::Tcp
    }

    pub(crate) fn rpc(self) -> bool {
        matches!(self, Self::Mcp | Self::JsonRpc)
    }
}

/// Effect classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// No side effects.
    Read,
    /// Reversible side effects.
    Write,
    /// Side effects that cannot be undone.
    Irreversible,
}

impl Effect {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "read" => Self::Read,
            "write" => Self::Write,
            "irreversible" => Self::Irreversible,
            _ => return None,
        })
    }

    /// The Charter spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Irreversible => "irreversible",
        }
    }
}

/// Why a request path was refused before any rule ran.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// The path does not start with `/`.
    #[error("path must start with /")]
    NotAbsolute,
    /// `%2F` or `%5C` (or a raw backslash) could smuggle a separator past
    /// the rules.
    #[error("path contains an encoded or alternative separator")]
    EncodedSeparator,
    /// A `.` or `..` segment (literal or percent-encoded).
    #[error("path contains a dot segment")]
    DotSegment,
    /// `//` inside the path.
    #[error("path contains an empty segment")]
    EmptySegment,
    /// Bad percent-encoding, invalid UTF-8 or a control character.
    #[error("path is not validly encoded")]
    Malformed,
}

/// Validates and percent-decodes a request path (no query string). Attacks
/// that make a rule see a different path than the upstream server are
/// refused rather than normalised away.
pub fn normalize_path(raw: &str) -> Result<String, PathError> {
    if !raw.starts_with('/') {
        return Err(PathError::NotAbsolute);
    }
    if raw.contains('\\') {
        return Err(PathError::EncodedSeparator);
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or(PathError::Malformed)?;
            let hex = std::str::from_utf8(hex).map_err(|_| PathError::Malformed)?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| PathError::Malformed)?;
            if v == b'/' || v == b'\\' {
                return Err(PathError::EncodedSeparator);
            }
            out.push(v);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    let decoded = String::from_utf8(out).map_err(|_| PathError::Malformed)?;
    if decoded.chars().any(char::is_control) {
        return Err(PathError::Malformed);
    }
    let segments: Vec<&str> = decoded[1..].split('/').collect();
    let last = segments.len() - 1;
    for (i, seg) in segments.iter().enumerate() {
        if *seg == "." || *seg == ".." {
            return Err(PathError::DotSegment);
        }
        // A trailing slash is fine; an empty segment elsewhere is not.
        if seg.is_empty() && i != last {
            return Err(PathError::EmptySegment);
        }
    }
    Ok(decoded)
}

/// Matches a decoded path against a rule glob: `*` matches exactly one
/// non-empty segment (or, inside a segment, any run of characters), `**`
/// matches any number of segments. A single trailing slash is ignored.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    fn segs(s: &str) -> Vec<&str> {
        let s = s.strip_prefix('/').unwrap_or(s);
        let s = s.strip_suffix('/').unwrap_or(s);
        if s.is_empty() {
            Vec::new()
        } else {
            s.split('/').collect()
        }
    }
    fn go(p: &[&str], s: &[&str]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((&"**", rest)) => (0..=s.len()).any(|k| go(rest, &s[k..])),
            Some((seg, rest)) => match s.split_first() {
                Some((first, srest)) => {
                    !first.is_empty() && glob(seg, first, false) && go(rest, srest)
                }
                None => false,
            },
        }
    }
    go(&segs(pattern), &segs(path))
}

/// `*`-only glob. With `cross_slash` false, `*` never matches `/` (callers
/// split on `/` already, so it only matters for tool and method globs).
pub fn glob(pattern: &str, s: &str, cross_slash: bool) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = s.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ti));
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some((sp, st)) = star {
            if !cross_slash && t[st] == '/' {
                return false;
            }
            pi = sp + 1;
            ti = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// One JSON-RPC message from a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcCall {
    /// The method, or `None` for a response object.
    pub method: Option<String>,
    /// `params.name` of a `tools/call`.
    pub tool: Option<String>,
}

/// Parses a JSON-RPC body (single message or batch).
pub fn parse_rpc(body: &[u8]) -> Result<Vec<RpcCall>, String> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "request body is not JSON-RPC".to_string())?;
    let msgs = match v {
        serde_json::Value::Array(a) if !a.is_empty() => a,
        serde_json::Value::Array(_) => return Err("empty JSON-RPC batch".into()),
        other => vec![other],
    };
    msgs.into_iter()
        .map(|m| {
            let obj = m
                .as_object()
                .ok_or_else(|| "JSON-RPC message is not an object".to_string())?;
            let method = match obj.get("method") {
                None => None,
                Some(serde_json::Value::String(s)) => Some(s.clone()),
                Some(_) => return Err("JSON-RPC method is not a string".into()),
            };
            let tool = (method.as_deref() == Some("tools/call"))
                .then(|| {
                    obj.get("params")
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .map(str::to_string)
                })
                .flatten();
            Ok(RpcCall { method, tool })
        })
        .collect()
}

/// Which rule list a [`RuleRef`] points into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `[[endpoint.allow]]`.
    Allow,
    /// `[[endpoint.deny]]`.
    Deny,
}

/// A rule by list and index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleRef {
    /// Allow or deny list.
    pub kind: RuleKind,
    /// Index in that list.
    pub index: usize,
}

impl std::fmt::Display for RuleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let k = match self.kind {
            RuleKind::Allow => "allow",
            RuleKind::Deny => "deny",
        };
        write!(f, "{k}[{}]", self.index)
    }
}

/// What the rules decided for one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Forward.
    Allow,
    /// Refuse, with a reason.
    Deny(String),
    /// Needs approval, with a reason.
    RequireApproval(String),
}

/// The evaluation of one call (one HTTP request, or one message of a
/// JSON-RPC batch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// The result.
    pub outcome: Outcome,
    /// The rule that decided, if any.
    pub rule: Option<RuleRef>,
    /// Effect class of the decision.
    pub effect: Option<Effect>,
    /// JSON-RPC method, when there was one.
    pub rpc_method: Option<String>,
    /// MCP tool name.
    pub tool: Option<String>,
}

/// The request facts rules match against.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// HTTP method.
    pub http_method: &'a str,
    /// Normalised path.
    pub path: &'a str,
    /// JSON-RPC message (mcp/json-rpc only).
    pub rpc: Option<&'a RpcCall>,
}

fn rule_matches(protocol: Protocol, r: &RequestRule, f: &Facts<'_>) -> bool {
    if !r.path.is_empty() && !path_matches(&r.path, f.path) {
        return false;
    }
    if protocol.rpc() {
        let method = f.rpc.and_then(|c| c.method.as_deref());
        if !r.method.is_empty() && !method.is_some_and(|m| glob(&r.method, m, true)) {
            return false;
        }
        if !r.tool.is_empty() {
            let Some(tool) = f.rpc.and_then(|c| c.tool.as_deref()) else {
                return false;
            };
            if method != Some("tools/call") || !glob(&r.tool, tool, true) {
                return false;
            }
        }
        true
    } else {
        r.method.is_empty() || r.method == "*" || r.method.eq_ignore_ascii_case(f.http_method)
    }
}

/// MCP traffic that is protocol housekeeping rather than an action: the
/// lifecycle handshake, pings, notifications, responses to server requests
/// and the transport's non-POST requests (SSE stream, session close). It is
/// allowed unless a deny rule matches, so Charters only list real actions.
fn mcp_housekeeping(f: &Facts<'_>) -> bool {
    match f.rpc {
        None => true,
        Some(c) => match c.method.as_deref() {
            None => true,
            Some(m) => m == "initialize" || m == "ping" || m.starts_with("notifications/"),
        },
    }
}

/// Evaluates one call against an endpoint's rules. Deny rules always win;
/// when any allow rule exists, one must match. For MCP `tools/call`, an
/// untagged or irreversible tool requires approval.
pub fn evaluate(ep: &Endpoint, protocol: Protocol, f: &Facts<'_>) -> Evaluation {
    let rpc_method = f.rpc.and_then(|c| c.method.clone());
    let tool = f.rpc.and_then(|c| c.tool.clone());
    let base = |outcome, rule: Option<RuleRef>, effect| Evaluation {
        outcome,
        rule,
        effect,
        rpc_method: rpc_method.clone(),
        tool: tool.clone(),
    };
    let effect_of = |r: &RequestRule| Effect::parse(&r.effect);

    if let Some((i, r)) = ep
        .deny
        .iter()
        .enumerate()
        .find(|(_, r)| rule_matches(protocol, r, f))
    {
        let why = if r.reason.is_empty() {
            "matched a deny rule".to_string()
        } else {
            r.reason.clone()
        };
        return base(
            Outcome::Deny(why),
            Some(RuleRef {
                kind: RuleKind::Deny,
                index: i,
            }),
            effect_of(r),
        );
    }

    let is_tool_call = protocol == Protocol::Mcp && rpc_method.as_deref() == Some("tools/call");
    if protocol == Protocol::Mcp && !is_tool_call && mcp_housekeeping(f) {
        return base(Outcome::Allow, None, None);
    }
    if protocol.rpc() && f.rpc.is_some_and(|c| c.method.is_none()) {
        // A JSON-RPC response to a server request is not an action.
        return base(Outcome::Allow, None, None);
    }
    if is_tool_call && tool.is_none() {
        return base(
            Outcome::Deny("tools/call without params.name".into()),
            None,
            None,
        );
    }

    let matched = ep
        .allow
        .iter()
        .enumerate()
        .find(|(_, r)| rule_matches(protocol, r, f));
    let (rule, effect) = match matched {
        Some((i, r)) => (
            Some(RuleRef {
                kind: RuleKind::Allow,
                index: i,
            }),
            effect_of(r),
        ),
        None if !ep.allow.is_empty() => {
            return base(Outcome::Deny("no allow rule matched".into()), None, None);
        }
        None => (None, None),
    };

    if is_tool_call {
        let effect = effect.unwrap_or(Effect::Irreversible);
        if effect == Effect::Irreversible {
            let why = match matched {
                Some((_, r)) if !r.effect.is_empty() => "MCP tool is tagged irreversible",
                _ => "MCP tool is untagged and counts as irreversible",
            };
            return base(
                Outcome::RequireApproval(why.into()),
                rule,
                Some(Effect::Irreversible),
            );
        }
        return base(Outcome::Allow, rule, Some(effect));
    }
    base(Outcome::Allow, rule, effect)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr(method: &str, path: &str, tool: &str, effect: &str) -> RequestRule {
        RequestRule {
            method: method.into(),
            path: path.into(),
            tool: tool.into(),
            effect: effect.into(),
            ..RequestRule::default()
        }
    }

    fn facts<'a>(m: &'a str, p: &'a str, rpc: Option<&'a RpcCall>) -> Facts<'a> {
        Facts {
            http_method: m,
            path: p,
            rpc,
        }
    }

    #[test]
    fn normalize_rejects_attacks() {
        assert_eq!(normalize_path("/a/b%20c/").as_deref(), Ok("/a/b c/"));
        assert_eq!(normalize_path("/").as_deref(), Ok("/"));
        for (p, want) in [
            ("a/b", PathError::NotAbsolute),
            ("/a%2Fb", PathError::EncodedSeparator),
            ("/a%2fb", PathError::EncodedSeparator),
            ("/a%5cb", PathError::EncodedSeparator),
            ("/a\\b", PathError::EncodedSeparator),
            ("/a/../b", PathError::DotSegment),
            ("/a/%2e%2e/b", PathError::DotSegment),
            ("/a/%2E%2e", PathError::DotSegment),
            ("/a/./b", PathError::DotSegment),
            ("/a//b", PathError::EmptySegment),
            ("/a%zz", PathError::Malformed),
            ("/a%", PathError::Malformed),
            ("/a%00b", PathError::Malformed),
            ("/a%ff", PathError::Malformed),
        ] {
            assert_eq!(normalize_path(p), Err(want), "{p}");
        }
    }

    #[test]
    fn path_globs() {
        let cases = [
            ("/repos/*", "/repos/acme", true),
            ("/repos/*", "/repos/acme/x", false),
            ("/repos/*", "/repos/", false),
            ("/repos/**", "/repos", true),
            ("/repos/**", "/repos/a/b/c", true),
            ("/repos/*/hooks/**", "/repos/acme/hooks/1", true),
            ("/repos/*/hooks/**", "/repos/acme/x/hooks/1", false),
            ("/v*/items", "/v2/items", true),
            ("/v*/items", "/x2/items", false),
            ("/**/admin", "/a/b/admin", true),
            ("/a", "/a/", true),
            ("/", "/", true),
            ("/**", "/anything/at/all", true),
        ];
        for (p, s, want) in cases {
            assert_eq!(path_matches(p, s), want, "{p} vs {s}");
        }
    }

    #[test]
    fn tool_globs_cross_slash() {
        assert!(glob("deploy_*", "deploy_prod", true));
        assert!(glob("*", "a/b", true));
        assert!(!glob("a*", "a/b", false));
        assert!(glob("*_read", "file_read", true));
        assert!(!glob("file_*", "files_x", true));
    }

    #[test]
    fn rest_deny_wins_and_allow_required() {
        let ep = Endpoint {
            allow: vec![
                rr("GET", "/repos/**", "", "read"),
                rr("POST", "/repos/*/issues", "", "write"),
            ],
            deny: vec![rr("", "/repos/*/hooks/**", "", "")],
            ..Endpoint::default()
        };
        let e = evaluate(
            &ep,
            Protocol::Rest,
            &facts("GET", "/repos/acme/hooks/1", None),
        );
        assert!(matches!(e.outcome, Outcome::Deny(_)));
        assert_eq!(e.rule.map(|r| r.to_string()).as_deref(), Some("deny[0]"));

        let e = evaluate(&ep, Protocol::Rest, &facts("get", "/repos/acme", None));
        assert_eq!(e.outcome, Outcome::Allow);
        assert_eq!(e.effect, Some(Effect::Read));

        let e = evaluate(
            &ep,
            Protocol::Rest,
            &facts("POST", "/repos/acme/issues", None),
        );
        assert_eq!(e.effect, Some(Effect::Write));
        assert_eq!(e.rule.map(|r| r.to_string()).as_deref(), Some("allow[1]"));

        let e = evaluate(&ep, Protocol::Rest, &facts("DELETE", "/repos/acme", None));
        assert_eq!(e.outcome, Outcome::Deny("no allow rule matched".into()));

        // No allow rules: everything not denied is allowed.
        let open = Endpoint {
            deny: vec![rr("DELETE", "", "", "")],
            ..Endpoint::default()
        };
        assert_eq!(
            evaluate(&open, Protocol::Rest, &facts("GET", "/x", None)).outcome,
            Outcome::Allow
        );
        assert!(matches!(
            evaluate(&open, Protocol::Rest, &facts("DELETE", "/x", None)).outcome,
            Outcome::Deny(_)
        ));
    }

    fn call(method: &str, tool: Option<&str>) -> RpcCall {
        RpcCall {
            method: Some(method.into()),
            tool: tool.map(str::to_string),
        }
    }

    #[test]
    fn mcp_tools() {
        let ep = Endpoint {
            allow: vec![
                rr("tools/list", "", "", ""),
                rr("", "", "search_*", "read"),
                rr("", "", "deploy", ""),
                rr("", "", "drop_db", "irreversible"),
            ],
            deny: vec![rr("", "", "search_secrets", "")],
            ..Endpoint::default()
        };
        let ev = |c: &RpcCall| evaluate(&ep, Protocol::Mcp, &facts("POST", "/mcp", Some(c)));

        let e = ev(&call("tools/call", Some("search_code")));
        assert_eq!((e.outcome, e.effect), (Outcome::Allow, Some(Effect::Read)));
        assert!(matches!(
            ev(&call("tools/call", Some("search_secrets"))).outcome,
            Outcome::Deny(_)
        ));
        let e = ev(&call("tools/call", Some("deploy")));
        assert!(matches!(e.outcome, Outcome::RequireApproval(ref r) if r.contains("untagged")));
        assert_eq!(e.effect, Some(Effect::Irreversible));
        assert!(matches!(
            ev(&call("tools/call", Some("drop_db"))).outcome,
            Outcome::RequireApproval(ref r) if r.contains("tagged irreversible")
        ));
        assert!(matches!(
            ev(&call("tools/call", Some("unknown"))).outcome,
            Outcome::Deny(_)
        ));
        assert!(matches!(
            ev(&call("tools/call", None)).outcome,
            Outcome::Deny(_)
        ));
        assert_eq!(ev(&call("tools/list", None)).outcome, Outcome::Allow);
        assert!(matches!(
            ev(&call("resources/read", None)).outcome,
            Outcome::Deny(_)
        ));
        // Housekeeping is implicit.
        assert_eq!(ev(&call("initialize", None)).outcome, Outcome::Allow);
        assert_eq!(
            ev(&call("notifications/initialized", None)).outcome,
            Outcome::Allow
        );
        assert_eq!(
            evaluate(&ep, Protocol::Mcp, &facts("GET", "/mcp", None)).outcome,
            Outcome::Allow
        );

        // No allow rules at all: tool calls are untagged.
        let bare = Endpoint::default();
        assert!(matches!(
            evaluate(
                &bare,
                Protocol::Mcp,
                &facts("POST", "/", Some(&call("tools/call", Some("x"))))
            )
            .outcome,
            Outcome::RequireApproval(_)
        ));
    }

    #[test]
    fn json_rpc_methods() {
        let ep = Endpoint {
            allow: vec![rr("eth_get*", "", "", "read")],
            deny: vec![rr("eth_getLogs", "", "", "")],
            ..Endpoint::default()
        };
        let ev = |m: &str| {
            evaluate(
                &ep,
                Protocol::JsonRpc,
                &facts("POST", "/", Some(&call(m, None))),
            )
            .outcome
        };
        assert_eq!(ev("eth_getBalance"), Outcome::Allow);
        assert!(matches!(ev("eth_getLogs"), Outcome::Deny(_)));
        assert!(matches!(ev("eth_sendTransaction"), Outcome::Deny(_)));
        // tools/call has no special meaning outside MCP.
        assert!(matches!(ev("tools/call"), Outcome::Deny(_)));
    }

    #[test]
    fn rpc_parsing() {
        let got = parse_rpc(
            br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}},{"jsonrpc":"2.0","id":2,"result":{}}]"#,
        )
        .expect("parse");
        assert_eq!(got[0], call("tools/call", Some("x")));
        assert_eq!(got[1].method, None);
        assert!(parse_rpc(b"not json").is_err());
        assert!(parse_rpc(b"[]").is_err());
        assert!(parse_rpc(br#"{"method":1}"#).is_err());
        assert!(parse_rpc(b"[1]").is_err());
    }
}
