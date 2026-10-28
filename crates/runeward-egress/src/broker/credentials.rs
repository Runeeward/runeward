//! Credential placeholders: the sandbox only ever holds an opaque
//! `rwph_<random>` token; the broker swaps it for the real secret on
//! requests to the endpoint that owns it and refuses it everywhere else.

use base64::Engine as _;
use hyper::HeaderMap;
use hyper::header::{self, HeaderName, HeaderValue};
use rand::TryRng;
use zeroize::Zeroize;

/// Prefix of every placeholder.
pub const PLACEHOLDER_PREFIX: &str = "rwph_";

/// Shown instead of a secret in anything the broker logs or records.
pub const SCRUBBED: &str = "«redacted»";

/// A resolved secret. Its `Debug` never prints the value and the memory is
/// wiped on drop.
pub(crate) struct Secret(String);

impl Secret {
    pub(crate) fn new(s: String) -> Self {
        Self(s)
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(«redacted»)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// How a credential is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Inject {
    /// `Authorization: Bearer <secret>`.
    Bearer,
    /// `Authorization: Basic base64(<secret>)`; a secret without `:` is the
    /// user name with an empty password.
    Basic,
    /// `<Name>: <secret>`.
    Header(HeaderName),
    /// `?<param>=<secret>`.
    Query(String),
}

impl Inject {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "" | "bearer" => Some(Self::Bearer),
            "basic" => Some(Self::Basic),
            _ => {
                if let Some(h) = s.strip_prefix("header:") {
                    HeaderName::from_bytes(h.as_bytes()).ok().map(Self::Header)
                } else {
                    s.strip_prefix("query:")
                        .filter(|q| !q.is_empty())
                        .map(|q| Self::Query(q.to_string()))
                }
            }
        }
    }
}

/// One `[[credential]]` with its per-sandbox placeholder.
#[derive(Debug)]
pub(crate) struct Slot {
    pub(crate) name: String,
    pub(crate) placeholder: String,
    pub(crate) placeholder_env: String,
    pub(crate) inject: Inject,
    /// The Charter spelling of `inject`, kept for the sidecar export.
    pub(crate) inject_src: String,
    /// `None` when no endpoint uses the credential (nothing to inject).
    pub(crate) secret: Option<Secret>,
}

/// Reports whether `p` has the shape [`new_placeholder`] produces (prefix
/// plus at least 128 bits of lowercase hex), so an imported placeholder is
/// as unguessable as a fresh one.
pub(crate) fn valid_placeholder(p: &str) -> bool {
    p.strip_prefix(PLACEHOLDER_PREFIX).is_some_and(|hex| {
        hex.len() >= 32
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A fresh opaque placeholder: the prefix plus 160 random bits as hex.
pub(crate) fn new_placeholder() -> String {
    let mut b = [0u8; 20];
    rand::rngs::SysRng
        .try_fill_bytes(&mut b)
        .expect("system random source");
    let mut s = String::with_capacity(PLACEHOLDER_PREFIX.len() + 40);
    s.push_str(PLACEHOLDER_PREFIX);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Decodes `Basic <b64>` credentials, if `value` is one.
fn basic_decoded(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(rest.trim())
        .ok()?;
    String::from_utf8(raw).ok()
}

fn basic_encode(userpass: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(userpass)
    )
}

/// Percent-decodes `s` leniently (invalid escapes are kept).
pub(crate) fn percent_decode_lossy(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(v) = b
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn query_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The placeholder set for one sandbox.
#[derive(Debug, Default)]
pub(crate) struct Vault {
    pub(crate) slots: Vec<Slot>,
}

impl Vault {
    /// Indices of every slot whose placeholder occurs in `haystack`.
    fn hits_in(&self, haystack: &[u8], out: &mut Vec<usize>) {
        for (i, s) in self.slots.iter().enumerate() {
            if !out.contains(&i) && contains(haystack, s.placeholder.as_bytes()) {
                out.push(i);
            }
        }
    }

    /// Every credential whose placeholder appears anywhere in the request:
    /// the target (raw and percent-decoded), header names and values
    /// (including inside `Basic` credentials) and the body.
    pub(crate) fn scan_request(
        &self,
        target: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Vec<usize> {
        let mut hits = Vec::new();
        if self.slots.is_empty() {
            return hits;
        }
        self.hits_in(target.as_bytes(), &mut hits);
        self.hits_in(percent_decode_lossy(target).as_bytes(), &mut hits);
        for (name, value) in headers {
            self.hits_in(name.as_str().as_bytes(), &mut hits);
            self.hits_in(value.as_bytes(), &mut hits);
            if let Some(dec) = value.to_str().ok().and_then(basic_decoded) {
                self.hits_in(dec.as_bytes(), &mut hits);
            }
        }
        self.hits_in(body, &mut hits);
        hits
    }

    /// Every credential whose placeholder appears in raw bytes.
    pub(crate) fn scan_bytes(&self, data: &[u8]) -> Vec<usize> {
        let mut hits = Vec::new();
        self.hits_in(data, &mut hits);
        hits
    }

    /// Longest placeholder length (for streaming scans).
    pub(crate) fn max_placeholder_len(&self) -> usize {
        self.slots
            .iter()
            .map(|s| s.placeholder.len())
            .max()
            .unwrap_or(0)
    }

    /// Replaces every resolved secret in `s` with [`SCRUBBED`].
    pub(crate) fn scrub(&self, s: &str) -> String {
        let mut out = s.to_string();
        for slot in &self.slots {
            if let Some(sec) = &slot.secret
                && !sec.expose().is_empty()
                && out.contains(sec.expose())
            {
                out = out.replace(sec.expose(), SCRUBBED);
            }
        }
        out
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Swaps `slot`'s placeholder for its secret in headers and the query, then
/// attaches the secret as configured if it is not already present. Returns
/// the rewritten path-and-query.
pub(crate) fn apply(
    slot: &Slot,
    headers: &mut HeaderMap,
    path_and_query: &str,
) -> Result<String, String> {
    let Some(secret) = slot.secret.as_ref().map(Secret::expose) else {
        return Ok(path_and_query.to_string());
    };
    let ph = slot.placeholder.as_str();
    let bad_value = || "credential is not a valid header value".to_string();

    // 1. Substitute wherever the agent put the placeholder.
    let names: Vec<HeaderName> = headers.keys().cloned().collect();
    for name in names {
        let values: Vec<HeaderValue> = headers.get_all(&name).iter().cloned().collect();
        if !values.iter().any(|v| {
            contains(v.as_bytes(), ph.as_bytes())
                || v.to_str()
                    .ok()
                    .and_then(basic_decoded)
                    .is_some_and(|d| d.contains(ph))
        }) {
            continue;
        }
        headers.remove(&name);
        for v in values {
            let text = v.to_str().map_err(|_| bad_value())?;
            let replaced = match basic_decoded(text) {
                Some(dec) if dec.contains(ph) => basic_encode(&dec.replace(ph, secret)),
                _ => text.replace(ph, secret),
            };
            let mut hv = HeaderValue::from_str(&replaced).map_err(|_| bad_value())?;
            hv.set_sensitive(true);
            headers.append(name.clone(), hv);
        }
    }
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p, Some(q.replace(ph, &query_encode(secret)))),
        None => (path_and_query, None),
    };

    // 2. Attach per `inject` unless already there.
    let set = |headers: &mut HeaderMap, name: HeaderName, value: String| -> Result<(), String> {
        let mut hv = HeaderValue::from_str(&value).map_err(|_| bad_value())?;
        hv.set_sensitive(true);
        headers.insert(name, hv);
        Ok(())
    };
    let header_has = |headers: &HeaderMap, name: &HeaderName| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.contains(secret) || basic_decoded(v).is_some_and(|d| d.contains(secret))
            })
    };
    let mut query = query;
    match &slot.inject {
        Inject::Bearer => {
            if !header_has(headers, &header::AUTHORIZATION) {
                set(headers, header::AUTHORIZATION, format!("Bearer {secret}"))?;
            }
        }
        Inject::Basic => {
            if !header_has(headers, &header::AUTHORIZATION) {
                let userpass = if secret.contains(':') {
                    secret.to_string()
                } else {
                    format!("{secret}:")
                };
                set(headers, header::AUTHORIZATION, basic_encode(&userpass))?;
            }
        }
        Inject::Header(name) => {
            if !header_has(headers, name) {
                set(headers, name.clone(), secret.to_string())?;
            }
        }
        Inject::Query(param) => {
            let want = format!("{}={}", query_encode(param), query_encode(secret));
            let q = query.unwrap_or_default();
            let mut parts: Vec<&str> = q
                .split('&')
                .filter(|kv| !kv.is_empty())
                .filter(|kv| {
                    let k = kv.split_once('=').map_or(*kv, |(k, _)| k);
                    percent_decode_lossy(k) != *param || **kv == *want
                })
                .collect();
            if !parts.contains(&want.as_str()) {
                parts.push(&want);
            }
            query = Some(parts.join("&"));
        }
    }
    Ok(match query {
        Some(q) if !q.is_empty() => format!("{path}?{q}"),
        _ => path.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(inject: &str, secret: &str) -> Slot {
        Slot {
            name: "c".into(),
            placeholder: "rwph_abc".into(),
            placeholder_env: String::new(),
            inject: Inject::parse(inject).expect("inject"),
            inject_src: inject.into(),
            secret: Some(Secret::new(secret.into())),
        }
    }

    fn hdr(h: &HeaderMap, n: &str) -> Option<String> {
        h.get(n).map(|v| v.to_str().expect("str").to_string())
    }

    #[test]
    fn placeholders_are_random_and_prefixed() {
        let a = new_placeholder();
        assert!(a.starts_with("rwph_") && a.len() == 45, "{a}");
        assert_ne!(a, new_placeholder());
    }

    #[test]
    fn bearer_substitutes_or_attaches() {
        let s = slot("bearer", "s3cr3t");
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_static("token rwph_abc"));
        h.insert("x-other", HeaderValue::from_static("a rwph_abc b"));
        let pq = apply(&s, &mut h, "/p?k=rwph_abc&z=1").expect("apply");
        assert_eq!(hdr(&h, "authorization").as_deref(), Some("token s3cr3t"));
        assert_eq!(hdr(&h, "x-other").as_deref(), Some("a s3cr3t b"));
        assert_eq!(pq, "/p?k=s3cr3t&z=1");
        assert!(h.get("authorization").expect("auth").is_sensitive());

        let mut h = HeaderMap::new();
        apply(&s, &mut h, "/").expect("apply");
        assert_eq!(hdr(&h, "authorization").as_deref(), Some("Bearer s3cr3t"));
    }

    #[test]
    fn basic_inside_base64() {
        let s = slot("basic", "tok");
        let mut h = HeaderMap::new();
        h.insert(
            "authorization",
            HeaderValue::from_str(&basic_encode("x-access-token:rwph_abc")).expect("hv"),
        );
        apply(&s, &mut h, "/").expect("apply");
        assert_eq!(
            hdr(&h, "authorization"),
            Some(basic_encode("x-access-token:tok"))
        );
        let mut h = HeaderMap::new();
        apply(&s, &mut h, "/").expect("apply");
        assert_eq!(hdr(&h, "authorization"), Some(basic_encode("tok:")));
    }

    #[test]
    fn header_and_query_injection() {
        let s = slot("header:X-Api-Key", "k&y");
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_static("wrong"));
        apply(&s, &mut h, "/").expect("apply");
        assert_eq!(hdr(&h, "x-api-key").as_deref(), Some("k&y"));

        let s = slot("query:key", "k&y");
        let mut h = HeaderMap::new();
        assert_eq!(apply(&s, &mut h, "/p").expect("q"), "/p?key=k%26y");
        assert_eq!(
            apply(&s, &mut h, "/p?a=1&key=old").expect("q"),
            "/p?a=1&key=k%26y"
        );
        assert_eq!(
            apply(&s, &mut h, "/p?key=rwph_abc").expect("q"),
            "/p?key=k%26y"
        );
        assert!(h.get("authorization").is_none());
    }

    #[test]
    fn scan_and_scrub() {
        let v = Vault {
            slots: vec![slot("bearer", "s3cr3t")],
        };
        let mut h = HeaderMap::new();
        assert!(v.scan_request("/x", &h, b"").is_empty());
        assert_eq!(v.scan_request("/x?a=%72wph_abc", &h, b""), vec![0]);
        assert_eq!(v.scan_request("/x", &h, b"{\"t\":\"rwph_abc\"}"), vec![0]);
        h.insert(
            "authorization",
            HeaderValue::from_str(&basic_encode("u:rwph_abc")).expect("hv"),
        );
        assert_eq!(v.scan_request("/x", &h, b""), vec![0]);
        assert_eq!(v.scrub("got s3cr3t!"), "got «redacted»!");
        assert_eq!(
            format!("{:?}", Secret::new("s3cr3t".into())),
            "Secret(«redacted»)"
        );
    }
}
