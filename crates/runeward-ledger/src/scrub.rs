//! Secret scrubbing for ledger payloads and free-form tool output.
//!
//! Patterns are written for Go's RE2 semantics. The one difference that
//! matters is `\s`: RE2 treats it as ASCII whitespace while Rust's regex
//! crate is Unicode-aware, so the patterns spell out `[\t\n\f\r ]`.

use std::sync::LazyLock;

use regex::Regex;

use crate::ledger::{Event, hash_payload, redact_string};

/// Replaces a detected (but undeclared) secret substring. Declared secrets
/// in event payloads are hashed instead, so they remain provably linkable to
/// a known value; pattern matches are simply masked.
pub const REDACT_MASK: &str = "[REDACTED]";

/// Common credential shapes, so a secret pasted into a command argument,
/// code snippet or metadata value is masked even when it was never declared.
/// Intentionally conservative to avoid mangling ordinary payloads.
const SECRET_PATTERNS: &[&str] = &[
    // PEM private key blocks (any key type).
    r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    // JSON Web Tokens.
    r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
    // Provider-specific tokens.
    r"AKIA[0-9A-Z]{16}",                          // AWS access key id
    r"gh[pousr]_[A-Za-z0-9]{20,}",                // GitHub tokens
    r"github_pat_[A-Za-z0-9_]{20,}",              // GitHub PATs
    r"xox[a-z]-[A-Za-z0-9-]{10,}",                // Slack tokens
    r"AIza[0-9A-Za-z_\-]{35}",                    // Google API key
    r"sk-ant-[A-Za-z0-9_\-]{10,}",                // Anthropic keys
    r"sk-proj-[A-Za-z0-9_\-]{10,}",               // OpenAI project keys
    r"sk-[A-Za-z0-9_\-]{20,}",                    // OpenAI-style keys
    r"(?i)bearer[\t\n\f\r ]+[A-Za-z0-9._\-]{8,}", // Authorization: Bearer <token>
];

fn compile(re: &str) -> Regex {
    #[allow(clippy::expect_used)]
    Regex::new(re).expect("built-in scrub pattern compiles")
}

static BUILTIN: LazyLock<Vec<Regex>> =
    LazyLock::new(|| SECRET_PATTERNS.iter().map(|p| compile(p)).collect());

static HIGH_ENTROPY_TOKEN: LazyLock<Regex> = LazyLock::new(|| compile(r"[A-Za-z0-9+/=_-]{40,}"));

/// Masks the value in key=value / key: value pairs whose key names a
/// credential. Group 1 is the key-and-separator prefix to keep; group 2 is
/// the value to mask.
static SECRET_KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    compile(
        r#"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)[\t\n\f\r ]*[=:][\t\n\f\r ]*)("[^"]+"|'[^']+'|[^\t\n\f\r "'&;]+)"#,
    )
});

static DEFAULT: LazyLock<Scrubber> = LazyLock::new(Scrubber::default);

/// Applies the built-in and optional operator-provided scrub patterns.
#[derive(Debug, Clone)]
pub struct Scrubber {
    patterns: Vec<Regex>,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new([])
    }
}

impl Scrubber {
    /// Returns a scrubber that always includes the built-in secret patterns,
    /// followed by `extra`.
    pub fn new(extra: impl IntoIterator<Item = Regex>) -> Self {
        let mut patterns = BUILTIN.clone();
        patterns.extend(extra);
        Self { patterns }
    }

    /// Returns a copy of ev with secrets removed from its payload fields
    /// (action, args, meta values). A payload exactly equal to a declared
    /// secret is replaced by its `sha256:<hex>` digest; declared secrets
    /// embedded in longer strings and credential-shaped substrings are
    /// masked. Structural fields are preserved. When nothing changes, ev is
    /// returned as is (`redacted` stays false) so clean events remain fully
    /// readable; otherwise `payload_hash` records the original payload's
    /// hash so the plaintext can later be proven to match.
    pub fn scrub<S: AsRef<str>>(&self, ev: Event, sensitive: &[S]) -> Event {
        let mut set: Vec<&str> = Vec::with_capacity(sensitive.len());
        for s in sensitive.iter().map(AsRef::as_ref) {
            if !s.is_empty() && !set.contains(&s) {
                set.push(s);
            }
        }

        let mut changed = false;
        let mut scrub = |s: &str| {
            let out = self.scrub_value(s, &set);
            changed |= out != s;
            out
        };
        let action = scrub(&ev.action);
        let args: Vec<String> = ev.args.iter().map(|a| scrub(a)).collect();
        let meta = ev.meta.iter().map(|(k, v)| (k.clone(), scrub(v))).collect();
        if !changed {
            return ev;
        }
        let payload_hash = hash_payload(&ev);
        Event {
            action,
            args,
            meta,
            redacted: true,
            payload_hash,
            ..ev
        }
    }

    /// Masks declared secrets and pattern-detected credentials in a free-form
    /// string (e.g. tool stdout/stderr) so they are not returned to clients
    /// in cleartext. Declared secrets are masked rather than hashed here,
    /// since the result is meant to stay human-readable.
    pub fn scrub_string<S: AsRef<str>>(&self, input: &str, sensitive: &[S]) -> String {
        if input.is_empty() {
            return String::new();
        }
        let mut out = input.to_owned();
        for secret in sensitive.iter().map(AsRef::as_ref) {
            if !secret.is_empty() {
                out = out.replace(secret, REDACT_MASK);
            }
        }
        self.mask_patterns(out)
    }

    /// Declared-secret hashing and pattern masking for one payload string.
    fn scrub_value(&self, s: &str, sensitive: &[&str]) -> String {
        if s.is_empty() {
            return String::new();
        }
        // Exact match on a declared secret: hash the whole value.
        if sensitive.contains(&s) {
            return redact_string(s);
        }
        // A declared secret embedded in a larger string: mask the occurrence.
        let mut out = s.to_owned();
        for secret in sensitive {
            out = out.replace(secret, REDACT_MASK);
        }
        self.mask_patterns(out)
    }

    fn mask_patterns(&self, s: String) -> String {
        let mut s = SECRET_KEY_VALUE
            .replace_all(&s, format!("${{1}}{REDACT_MASK}").as_str())
            .into_owned();
        for re in &self.patterns {
            s = re.replace_all(&s, REDACT_MASK).into_owned();
        }
        HIGH_ENTROPY_TOKEN
            .replace_all(&s, |caps: &regex::Captures<'_>| {
                let token = &caps[0];
                if looks_like_secret_blob(token) {
                    REDACT_MASK.to_owned()
                } else {
                    token.to_owned()
                }
            })
            .into_owned()
    }
}

/// [`Scrubber::scrub`] with the built-in patterns only.
pub fn scrub<S: AsRef<str>>(ev: Event, sensitive: &[S]) -> Event {
    DEFAULT.scrub(ev, sensitive)
}

/// [`Scrubber::scrub_string`] with the built-in patterns only.
pub fn scrub_string<S: AsRef<str>>(input: &str, sensitive: &[S]) -> String {
    DEFAULT.scrub_string(input, sensitive)
}

/// Heuristic for long tokens: a hex run needs 48+ characters with digits and
/// letters; anything else needs three character classes. Plain identifiers
/// with separators (container ids, pod hostnames) are left alone.
fn looks_like_secret_blob(token: &str) -> bool {
    if token.len() < 40 {
        return false;
    }
    let mut is_hex = true;
    let (mut lower, mut upper, mut digit, mut other) = (false, false, false, false);
    for c in token.chars() {
        match c {
            'a'..='z' => {
                lower = true;
                is_hex &= c <= 'f';
            }
            'A'..='Z' => {
                upper = true;
                is_hex &= c <= 'F';
            }
            '0'..='9' => digit = true,
            '+' | '/' | '=' => {
                other = true;
                is_hex = false;
            }
            // Separators common in identifiers rule out pure hex but are not
            // a secret signal on their own.
            '-' | '_' => is_hex = false,
            _ => return false,
        }
    }
    if is_hex {
        return token.len() >= 48 && digit && (lower || upper);
    }
    let classes = [lower, upper, digit, other].iter().filter(|b| **b).count();
    classes >= 3 && digit && (lower || upper)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: &[&str] = &[];

    #[test]
    fn scrub_string_basics() {
        assert!(!scrub_string("token=hunter2 ok", &["hunter2"]).contains("hunter2"));
        let gh = format!("ghp_{}", "a".repeat(36));
        assert!(!scrub_string(&format!("using {gh}"), NONE).contains(&gh));
        let clean = "just some regular output";
        assert_eq!(scrub_string(clean, NONE), clean);
        assert_eq!(scrub_string("", NONE), "");
    }

    #[test]
    fn declared_secret_hashed() {
        let raw = Event {
            tool: "shell".into(),
            action: "deploy".into(),
            args: vec!["secret-token".into(), "keep-me".into()],
            meta: [
                ("token".into(), "secret-token".into()),
                ("region".into(), "us".into()),
            ]
            .into(),
            ..Event::default()
        };
        let before = hash_payload(&raw);
        let got = scrub(raw.clone(), &["secret-token"]);
        assert!(got.redacted);
        assert_eq!(got.payload_hash, before);
        assert!(got.args[0].starts_with("sha256:"));
        assert_eq!(got.args[1], "keep-me");
        assert_eq!(got.meta["region"], "us");
        assert_eq!(raw.args[0], "secret-token");
    }

    #[test]
    fn undeclared_secret_patterns() {
        // Provider-shaped fixtures are split so repository secret scanning
        // does not mistake a synthetic value for a live credential.
        let google = format!("{}{}", "AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q");
        let cases = [
            (
                "aws-access-key-id",
                "export AWS_KEY=AKIAIOSFODNN7EXAMPLE".to_owned(),
            ),
            (
                "anthropic-key",
                "ANTHROPIC_API_KEY=sk-ant-api03-0123456789abcdefABCDEF".into(),
            ),
            (
                "openai-project-key",
                "OPENAI_API_KEY=sk-proj-myproj_0123456789abcdefABCDEF".into(),
            ),
            (
                "openai-key",
                "OPENAI_API_KEY=sk-0123456789abcdefABCDEF0123456789".into(),
            ),
            (
                "aws-secret-access-key",
                "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            ),
            (
                "github-ghp",
                "token is ghp_0123456789abcdefghijABCDEFGHIJ0123".into(),
            ),
            (
                "github-gho",
                "token is gho_0123456789abcdefghijABCDEFGHIJ0123".into(),
            ),
            (
                "github-ghs",
                "token is ghs_0123456789abcdefghijABCDEFGHIJ0123".into(),
            ),
            (
                "github-ghr",
                "token is ghr_0123456789abcdefghijABCDEFGHIJ0123".into(),
            ),
            (
                "github-pat",
                "token is github_pat_11ABCDEF_0123456789abcdefghijklmnopqrstuvwxyz".into(),
            ),
            ("google-api-key", format!("GOOGLE_API_KEY={google}")),
            (
                "slack-token",
                "SLACK_BOT_TOKEN=xoxb-123456789012-123456789012-abcDEFghiJKL".into(),
            ),
            (
                "bearer",
                "curl -H 'Authorization: Bearer abcdef123456.token'".into(),
            ),
            ("kv", "run with password=hunter2super here".into()),
            (
                "high-entropy-base64",
                "blob=QWxhZGRpbjpPcGVuU2VzYW1lLzEyMzQ1Njc4OUFCQ0RFRkdISQ==".into(),
            ),
            (
                "high-entropy-hex",
                "hex=0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        ];
        for (name, action) in cases {
            let got = scrub(
                Event {
                    tool: "shell".into(),
                    action: action.clone(),
                    ..Event::default()
                },
                NONE,
            );
            assert!(got.redacted, "{name}: expected redaction for {action:?}");
            assert!(got.action.contains(REDACT_MASK), "{name}: {:?}", got.action);
        }
    }

    #[test]
    fn high_entropy_avoids_simple_blobs() {
        let clean = "hex=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(scrub_string(clean, NONE), clean);
    }

    #[test]
    fn keeps_identifier_hostnames() {
        for id in [
            "runeward-24daaf633799a22bcc94dfff65674bb4",
            "pod-abc123def456abc123def456abc123def4560000",
        ] {
            assert_eq!(scrub_string(id, NONE), id);
        }
        let blob = "QWxhZGRpbjpPcGVuU2VzYW1lLzEyMzQ1Njc4OUFCQ0RFRkdISQ==";
        assert!(scrub_string(blob, NONE).contains(REDACT_MASK));
    }

    #[test]
    fn clean_payload_untouched() {
        let raw = Event {
            tool: "shell".into(),
            action: "ls -la".into(),
            args: vec!["ls".into(), "-la".into()],
            ..Event::default()
        };
        let got = scrub(raw.clone(), NONE);
        assert_eq!(got, raw);
        assert!(!got.redacted && got.payload_hash.is_empty());
    }

    #[test]
    fn keeps_key_drops_value() {
        let got = scrub(
            Event {
                tool: "shell".into(),
                action: "DB_PASSWORD=supersecret123".into(),
                ..Event::default()
            },
            NONE,
        );
        assert!(!got.action.contains("supersecret123"), "{}", got.action);
        assert!(got.action.contains("DB_PASSWORD="), "{}", got.action);
    }

    #[test]
    fn ascii_whitespace_only_like_re2() {
        // RE2's \s does not include U+00A0, so the value after a
        // non-breaking space is not treated as a key=value secret.
        assert_eq!(
            scrub_string("password=\u{a0}x", NONE),
            "password=[REDACTED]"
        );
        assert_eq!(scrub_string("password\u{a0}=x", NONE), "password\u{a0}=x");
        // (?i) uses Unicode simple folding in both engines (Kelvin sign).
        assert_eq!(
            scrub_string("to\u{212A}en=x", NONE),
            "to\u{212A}en=[REDACTED]"
        );
    }

    #[test]
    fn custom_patterns() {
        let s = Scrubber::new([Regex::new(r"RUNETOKEN-[0-9]{4}").expect("regex")]);
        let got = s.scrub(
            Event {
                tool: "shell".into(),
                action: "send RUNETOKEN-4242 now".into(),
                ..Event::default()
            },
            NONE,
        );
        assert!(got.redacted);
        assert!(!got.action.contains("RUNETOKEN-4242"));
        let out = s.scrub_string(
            "stdout RUNETOKEN-4242 and ghp_0123456789abcdefghijABCDEFGHIJ0123",
            NONE,
        );
        assert!(!out.contains("RUNETOKEN-4242"));
        assert!(!out.contains("ghp_0123456789abcdefghijABCDEFGHIJ0123"));
    }
}
