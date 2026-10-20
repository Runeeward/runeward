//! The built-in first-match-wins rule engine (`[[policy]]`).
//!
//! Rules are evaluated strictly in order: there is deliberately no
//! deny-precedence pass, so the operator controls precedence through rule
//! ordering.

use runeward_charter::{PolicyRule, Verdict};

use crate::decision::{Action, Decision, EngineKind, Evaluator, default_or_allow};

/// Evaluates actions against an ordered rule list with a default verdict.
#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    rules: Vec<PolicyRule>,
    def: Verdict,
}

impl RuleEngine {
    /// Builds an engine from ordered rules and a default verdict (allow when
    /// unset).
    pub fn new(rules: Vec<PolicyRule>, def: Verdict) -> Self {
        Self {
            rules,
            def: default_or_allow(def),
        }
    }

    /// The rules, in evaluation order.
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }

    /// Reports whether a single rule matches `action`: its tool equals the
    /// action's (or is `*`), its `match` glob matches the argument (empty
    /// matches anything), and its `match_argv` glob matches the executable.
    pub fn rule_matches(rule: &PolicyRule, action: &Action) -> bool {
        tool_matches(&rule.tool, &action.tool)
            && (rule.match_glob.is_empty() || match_glob(&rule.match_glob, &action.arg))
            && (rule.match_argv.is_empty() || argv_matches(&rule.match_argv, action))
    }
}

impl Evaluator for RuleEngine {
    /// The first matching rule wins; no match returns the default verdict
    /// with no rule.
    fn evaluate(&self, action: &Action) -> Decision {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| Self::rule_matches(r, action))
            .map_or_else(
                || Decision::no_match(EngineKind::Builtin, self.def.clone()),
                |(i, r)| Decision::matched(EngineKind::Builtin, r.clone(), Some(i)),
            )
    }

    fn kind(&self) -> EngineKind {
        EngineKind::Builtin
    }
}

fn tool_matches(rule_tool: &str, action_tool: &str) -> bool {
    rule_tool == "*" || rule_tool == action_tool
}

/// Reports whether the action's executable matches `pattern`. It inspects
/// argv[0], and when the command runs through a shell wrapper (`sh -c "…"`,
/// including `env` prefixes and busybox multicall forms) also the first token
/// of the wrapped script.
fn argv_matches(pattern: &str, action: &Action) -> bool {
    argv_candidates(action)
        .iter()
        .any(|c| match_glob(pattern, c))
}

/// The executable names a `match_argv` rule tests: argv[0], its basename and,
/// for shell wrappers, the first token of the `-c` script plus its basename.
fn argv_candidates(action: &Action) -> Vec<&str> {
    let argv: Vec<&str> = if action.args.is_empty() {
        action.arg.split_whitespace().collect()
    } else {
        action.args.iter().map(String::as_str).collect()
    };
    let Some(first) = argv.first() else {
        return Vec::new();
    };
    let mut out = vec![*first, base_name(first)];
    if let Some(tok) = wrapped_shell_token(&argv) {
        out.push(tok);
        out.push(base_name(tok));
    }
    out
}

fn wrapped_shell_token<'a>(argv: &[&'a str]) -> Option<&'a str> {
    let mut unwrapped = unwrap_env_prefix(argv);
    let first = unwrapped.first()?;
    if base_name(first) == "busybox" {
        if unwrapped.len() < 2 || !is_shell_name(unwrapped[1]) {
            return None;
        }
        unwrapped = &unwrapped[1..];
    }
    if !is_shell_name(unwrapped[0]) {
        return None;
    }
    let i = unwrapped
        .iter()
        .skip(1)
        .position(|a| *a == "-c")
        .map(|p| p + 1)?;
    let script = unwrapped.get(i + 1)?;
    script.split_whitespace().next()
}

fn unwrap_env_prefix<'s, 'a>(argv: &'s [&'a str]) -> &'s [&'a str] {
    if argv.is_empty() || base_name(argv[0]) != "env" {
        return argv;
    }
    let mut i = 1;
    while i < argv.len() {
        let a = argv[i];
        if a == "--" {
            return &argv[i + 1..];
        } else if a.starts_with('-') || is_env_assignment(a) {
            i += 1;
        } else {
            return &argv[i..];
        }
    }
    &[]
}

fn is_env_assignment(s: &str) -> bool {
    s.find('=').is_some_and(|eq| eq > 0)
}

fn is_shell_name(p: &str) -> bool {
    matches!(
        base_name(p),
        "sh" | "bash" | "dash" | "ash" | "ksh" | "zsh" | "fish" | "busybox"
    )
}

fn base_name(p: &str) -> &str {
    p.rfind('/').map_or(p, |i| &p[i + 1..])
}

/// Reports whether `s` matches `pattern` as an anchored, full-string glob.
///
/// `*` matches any run of bytes and `?` exactly one byte; unlike shell or
/// `filepath.Match` globs, both cross `/`. There are no character classes or
/// escapes. Linear backtracking over bytes, byte-for-byte compatible with the
/// Go matcher.
pub fn match_glob(pattern: &str, s: &str) -> bool {
    let (p, s) = (pattern.as_bytes(), s.as_bytes());
    let (mut si, mut pi) = (0usize, 0usize);
    // The last '*' position and where in s it started matching.
    let mut star: Option<usize> = None;
    let mut star_mark = 0usize;
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            si += 1;
            pi += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_mark = si;
            pi += 1;
        } else if let Some(st) = star {
            // Mismatch: let the last '*' absorb one more byte of s.
            pi = st + 1;
            star_mark += 1;
            si = star_mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(tool: &str, glob: &str, verdict: Verdict, reason: &str) -> PolicyRule {
        PolicyRule {
            tool: tool.into(),
            match_glob: glob.into(),
            verdict,
            reason: reason.into(),
            ..PolicyRule::default()
        }
    }

    fn argv_rule(tool: &str, argv: &str, verdict: Verdict, reason: &str) -> PolicyRule {
        PolicyRule {
            tool: tool.into(),
            match_argv: argv.into(),
            verdict,
            reason: reason.into(),
            ..PolicyRule::default()
        }
    }

    #[test]
    fn match_glob_table() {
        let cases: &[(&str, &str, &str, bool)] = &[
            ("empty pattern empty string", "", "", true),
            ("empty pattern nonempty", "", "x", false),
            ("literal match", "rm", "rm", true),
            ("literal mismatch", "rm", "ls", false),
            ("star matches all", "*", "anything at all", true),
            ("star matches empty", "*", "", true),
            ("prefix star", "rm -rf*", "rm -rf /tmp", true),
            ("prefix star no suffix", "rm -rf*", "rm -rf", true),
            ("prefix star mismatch", "rm -rf*", "rmdir /tmp", false),
            ("star crosses slash", "/etc/*", "/etc/passwd", true),
            (
                "star crosses nested slash",
                "/etc/*",
                "/etc/ssh/sshd_config",
                true,
            ),
            (
                "star mid pattern crosses slash",
                "/*/passwd",
                "/etc/passwd",
                true,
            ),
            (
                "star mid pattern deep slash",
                "/*/passwd",
                "/etc/deep/passwd",
                true,
            ),
            ("question single char", "r?", "rm", true),
            ("question requires a char", "r?", "r", false),
            ("question matches slash", "a?b", "a/b", true),
            ("suffix glob", "*.go", "main.go", true),
            ("suffix glob dir", "*.go", "internal/policy/main.go", true),
            ("suffix glob mismatch", "*.go", "main.py", false),
            ("double star greedy", "a*b*c", "axxbyyc", true),
            ("double star backtrack", "a*c", "aXcXc", true),
            ("trailing stars", "abc***", "abc", true),
            ("leading star literal tail", "*passwd", "/etc/passwd", true),
            ("question and star", "?*", "x", true),
            ("question and star empty", "?*", "", false),
            ("exact host", "api.example.com", "api.example.com", true),
            (
                "wildcard subdomain",
                "*.example.com",
                "api.example.com",
                true,
            ),
            (
                "wildcard subdomain root fails",
                "*.example.com",
                "example.com",
                false,
            ),
        ];
        for (name, pattern, s, want) in cases {
            assert_eq!(
                match_glob(pattern, s),
                *want,
                "{name}: {pattern:?} vs {s:?}"
            );
        }
    }

    #[test]
    fn evaluate_allow_deny_approve() {
        let e = RuleEngine::new(
            vec![
                rule("shell", "rm -rf*", Verdict::Deny, "destructive"),
                rule(
                    "net",
                    "*.internal",
                    Verdict::RequireApproval,
                    "internal host",
                ),
                rule("file.read", "/etc/*", Verdict::Allow, "config read"),
            ],
            Verdict::Deny,
        );
        let cases = [
            ("shell", "rm -rf /", Verdict::Deny, "destructive", false),
            (
                "net",
                "db.internal",
                Verdict::RequireApproval,
                "internal host",
                false,
            ),
            (
                "file.read",
                "/etc/hosts",
                Verdict::Allow,
                "config read",
                false,
            ),
            ("python", "print(1)", Verdict::Deny, "", true),
        ];
        for (tool, arg, verdict, reason, rule_none) in cases {
            let d = e.evaluate(&Action::new(tool, arg));
            assert_eq!(d.verdict, verdict, "{tool} {arg}");
            assert_eq!(d.reason, reason, "{tool} {arg}");
            assert_eq!(d.rule.is_none(), rule_none, "{tool} {arg}");
        }
    }

    #[test]
    fn evaluate_first_match_wins() {
        let e = RuleEngine::new(
            vec![
                rule("shell", "git *", Verdict::Allow, "first"),
                rule("shell", "git push*", Verdict::Deny, "second"),
            ],
            Verdict::Allow,
        );
        let d = e.evaluate(&Action::new("shell", "git push origin main"));
        assert_eq!(d.verdict, Verdict::Allow);
        assert_eq!(d.reason, "first");
        assert_eq!(d.rule_index, Some(0));
        assert_eq!(d.code, crate::ReasonCode::RuleMatched);
    }

    #[test]
    fn evaluate_default_when_empty() {
        let e = RuleEngine::new(Vec::new(), Verdict::Unset);
        let d = e.evaluate(&Action::new("shell", "ls"));
        assert_eq!(d.verdict, Verdict::Allow);
        assert!(d.rule.is_none());
        assert_eq!(d.code, crate::ReasonCode::NoMatch);
    }

    #[test]
    fn evaluate_wildcard_tool() {
        let e = RuleEngine::new(
            vec![rule("*", "*secret*", Verdict::Deny, "secrets")],
            Verdict::Allow,
        );
        for tool in ["shell", "file.read", "net", "python"] {
            let d = e.evaluate(&Action::new(tool, "cat the-secret-file"));
            assert_eq!(d.verdict, Verdict::Deny, "{tool}");
        }
        let d = e.evaluate(&Action::new("shell", "cat readme"));
        assert_eq!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn evaluate_empty_match_matches_all() {
        let e = RuleEngine::new(
            vec![rule("net", "", Verdict::RequireApproval, "all egress")],
            Verdict::Allow,
        );
        assert_eq!(
            e.evaluate(&Action::new("net", "anything.example.com"))
                .verdict,
            Verdict::RequireApproval
        );
        assert_eq!(
            e.evaluate(&Action::new("shell", "ls")).verdict,
            Verdict::Allow
        );
    }

    #[test]
    fn match_argv_catches_wrappers_and_paths() {
        let e = RuleEngine::new(
            vec![argv_rule("shell", "rm", Verdict::Deny, "no rm")],
            Verdict::Allow,
        );
        let sh = |arg: &str, args: &[&str]| Action::new("shell", arg).with_args(args.to_vec());
        let deny = [
            ("bare rm", sh("rm -rf /tmp/x", &["rm", "-rf", "/tmp/x"])),
            (
                "abs path rm",
                sh("/bin/rm -rf /tmp/x", &["/bin/rm", "-rf", "/tmp/x"]),
            ),
            (
                "sh -c wrapper",
                sh("sh -c 'rm -rf /'", &["sh", "-c", "rm -rf /"]),
            ),
            ("bash -c wrapper", sh("", &["/bin/bash", "-c", "rm file"])),
            ("dash -c wrapper", sh("", &["dash", "-c", "rm file"])),
            ("ash -c wrapper", sh("", &["ash", "-c", "rm file"])),
            ("ksh -c wrapper", sh("", &["ksh", "-c", "rm file"])),
            ("zsh -c wrapper", sh("", &["zsh", "-c", "rm file"])),
            ("fish -c wrapper", sh("", &["fish", "-c", "rm file"])),
            (
                "busybox shell wrapper",
                sh("", &["busybox", "sh", "-c", "rm file"]),
            ),
            (
                "env sh wrapper",
                sh("", &["/usr/bin/env", "sh", "-c", "rm file"]),
            ),
            (
                "env assignment wrapper",
                sh("", &["env", "FOO=1", "bash", "-c", "rm file"]),
            ),
            (
                "env option and dashdash wrapper",
                sh("", &["env", "-i", "--", "sh", "-c", "rm file"]),
            ),
        ];
        for (name, a) in deny {
            assert_eq!(e.evaluate(&a).verdict, Verdict::Deny, "{name}");
        }
        let allow = [
            ("different tool exe", sh("", &["remove", "x"])),
            ("ls", sh("", &["ls", "-la"])),
            ("echo mentions rm", sh("", &["echo", "rm"])),
            (
                "busybox non-shell applet",
                sh("", &["busybox", "echo", "-c", "rm file"]),
            ),
            ("env with no command", sh("", &["env", "FOO=1"])),
        ];
        for (name, a) in allow {
            assert_eq!(e.evaluate(&a).verdict, Verdict::Allow, "{name}");
        }
    }

    #[test]
    fn match_argv_falls_back_to_arg_when_no_argv() {
        let e = RuleEngine::new(
            vec![argv_rule("shell", "curl", Verdict::Deny, "")],
            Verdict::Allow,
        );
        assert_eq!(
            e.evaluate(&Action::new("shell", "curl http://x")).verdict,
            Verdict::Deny
        );
    }

    #[test]
    fn glob_question_matches_one_byte() {
        // Go matches bytewise; a two-byte UTF-8 char needs two '?'.
        assert!(!match_glob("?", "é"));
        assert!(match_glob("??", "é"));
    }
}
