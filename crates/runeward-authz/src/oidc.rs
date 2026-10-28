//! RS256 OIDC bearer-token verification with JWKS fetch and caching.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Url;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{Error, Principal, decode_first_value};

/// Issuer URL; setting it enables OIDC.
pub const ENV_OIDC_ISSUER: &str = "RUNEWARD_OIDC_ISSUER";
/// Required audience (`aud`) when OIDC is enabled.
pub const ENV_OIDC_AUDIENCE: &str = "RUNEWARD_OIDC_AUDIENCE";
/// Optional explicit JWKS URL; when unset it is discovered from the issuer.
pub const ENV_OIDC_JWKS_URL: &str = "RUNEWARD_OIDC_JWKS_URL";

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REDIRECTS: usize = 10;
const MAX_JSON_BYTES: usize = 2 << 20;
const MAX_TOKEN_BYTES: usize = 32 * 1024;
/// Minimum interval between cache-miss JWKS refreshes.
const REFRESH_COOLDOWN: Duration = Duration::from_secs(30);
/// Allowed clock skew for `nbf`, in seconds.
const NBF_LEEWAY_SECS: i64 = 30;

#[derive(Deserialize)]
struct Discovery {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
}

#[derive(Deserialize)]
struct JsonWebKeySet {
    #[serde(default)]
    keys: Option<Vec<JsonWebKey>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct JsonWebKey {
    kid: Option<String>,
    kty: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TokenHeader {
    alg: Option<String>,
    kid: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Claims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Value,
    exp: Option<i64>,
    nbf: Option<i64>,
    preferred_username: Option<String>,
    email: Option<String>,
    runeward_tenant: Option<String>,
    runeward_profiles: Option<Vec<String>>,
    runeward_approval_profiles: Option<Vec<String>>,
    runeward_can_approve: Option<bool>,
    runeward_admin: Option<bool>,
}

/// Validates RS256 OIDC JWTs and maps signed Runeward claims onto the same
/// [`Principal`] model used by local authz files.
///
/// Signing keys are cached by `kid`. A token naming an unknown `kid` triggers
/// a JWKS refresh at most once every 30 seconds, so attacker-chosen key ids
/// cannot turn the control plane into a request amplifier against the
/// identity provider.
pub struct OidcVerifier {
    issuer: String,
    audience: String,
    jwks_url: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, RsaKey>>,
    /// Serializes refreshes; holds the time of the last successful one.
    last_refresh: tokio::sync::Mutex<Option<Instant>>,
    /// The monotonic clock the refresh cooldown is measured with
    /// (injectable so tests never depend on wall time).
    now: fn() -> Instant,
}

impl fmt::Debug for OidcVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key_count = self.keys.read().map_or(0, |k| k.len());
        f.debug_struct("OidcVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwks_url", &self.jwks_url)
            .field("keys", &key_count)
            .finish_non_exhaustive()
    }
}

/// An RS256 signing key from the issuer's JWKS: the big-endian modulus and
/// public exponent.
#[derive(Clone)]
struct RsaKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

impl RsaKey {
    /// Reports whether `signature` is a valid RSASSA-PKCS1-v1_5 SHA-256
    /// signature of `message`; moduli below 2048 bits never verify.
    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        RsaPublicKeyComponents {
            n: &self.n,
            e: &self.e,
        }
        .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
        .is_ok()
    }
}

fn oidc_err(msg: impl Into<String>) -> Error {
    Error::Oidc(msg.into())
}

/// The HTTP client for discovery and JWKS fetches: a 10 second timeout and a
/// redirect policy that keeps every hop secure and on the original origin.
fn oidc_http_client() -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(
            |attempt| match check_redirect(attempt.url(), attempt.previous()) {
                Ok(()) => attempt.follow(),
                Err(e) => attempt.error(e),
            },
        ))
        .build()
        .map_err(|e| oidc_err(format!("build OIDC HTTP client: {e}")))
}

/// The redirect rule: at most 10 hops, each to a secure endpoint with the same
/// origin as the first request. `via` holds the URLs already requested.
fn check_redirect(next: &Url, via: &[Url]) -> Result<(), String> {
    if via.len() >= MAX_REDIRECTS {
        return Err("OIDC endpoint redirected too many times".to_owned());
    }
    require_secure_endpoint(next.as_str()).map_err(|e| e.to_string())?;
    if let Some(first) = via.first()
        && !same_origin(first.as_str(), next.as_str())
    {
        return Err("OIDC endpoint redirect changed origin".to_owned());
    }
    Ok(())
}

/// The host of `u` as Go's `URL.Hostname` reports it (IPv6 without brackets).
fn hostname(u: &Url) -> String {
    let host = u.host_str().unwrap_or_default();
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned()
}

/// Requires an absolute HTTPS URL without credentials or fragment; plain HTTP
/// is allowed only for loopback hosts.
fn require_secure_endpoint(raw: &str) -> Result<(), Error> {
    let invalid = || oidc_err(format!("invalid OIDC endpoint {raw:?}"));
    let u = Url::parse(raw).map_err(|_| invalid())?;
    let host = hostname(&u);
    if host.is_empty()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some_and(|f| !f.is_empty())
    {
        return Err(invalid());
    }
    if u.scheme() == "https" {
        return Ok(());
    }
    let host = host.to_ascii_lowercase();
    if u.scheme() == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return Ok(());
    }
    Err(oidc_err(
        "OIDC endpoints must use HTTPS (HTTP is allowed only for loopback development)",
    ))
}

/// Whether `a` and `b` share scheme, host and effective port.
fn same_origin(a: &str, b: &str) -> bool {
    let (Ok(left), Ok(right)) = (Url::parse(a), Url::parse(b)) else {
        return false;
    };
    left.scheme().eq_ignore_ascii_case(right.scheme())
        && hostname(&left).eq_ignore_ascii_case(&hostname(&right))
        && effective_port(&left) == effective_port(&right)
}

fn effective_port(u: &Url) -> Option<u16> {
    u.port().or(match u.scheme() {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    })
}

/// Decodes `bytes` as JSON that must be an object (or `null`, the zero value),
/// mirroring Go's `json.Unmarshal` into a struct.
fn parse_object<T: DeserializeOwned + Default>(bytes: &[u8]) -> Option<T> {
    match serde_json::from_slice::<Value>(bytes).ok()? {
        Value::Null => Some(T::default()),
        v @ Value::Object(_) => serde_json::from_value(v).ok(),
        _ => None,
    }
}

fn audience_contains(aud: &Value, want: &str) -> bool {
    match aud {
        Value::String(s) => s == want,
        Value::Array(items) => items.iter().any(|i| i.as_str() == Some(want)),
        _ => false,
    }
}

/// The first non-blank value, trimmed.
fn first_claim(values: &[Option<&str>]) -> String {
    values
        .iter()
        .flatten()
        .map(|v| v.trim())
        .find(|v| !v.is_empty())
        .unwrap_or_default()
        .to_owned()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Strips leading zero bytes from a big-endian integer.
fn trim_leading_zeros(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[start..]
}

impl OidcVerifier {
    /// Configures OIDC from `RUNEWARD_OIDC_ISSUER`, `RUNEWARD_OIDC_AUDIENCE`
    /// and `RUNEWARD_OIDC_JWKS_URL`. Returns `Ok(None)` when the issuer is
    /// unset; once it is set, every configuration problem is an error.
    pub async fn from_env() -> Result<Option<Self>, Error> {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let issuer = var(ENV_OIDC_ISSUER);
        if issuer.trim().trim_end_matches('/').is_empty() {
            return Ok(None);
        }
        let jwks_url = var(ENV_OIDC_JWKS_URL);
        Self::new(&issuer, &var(ENV_OIDC_AUDIENCE), Some(jwks_url.as_str()))
            .await
            .map(Some)
    }

    /// Configures a verifier for `issuer` and `audience` and loads its keys.
    ///
    /// When `jwks_url` is `None` or blank, the issuer's
    /// `/.well-known/openid-configuration` is fetched; the advertised issuer
    /// must match and the `jwks_uri` must share the issuer's origin. Every
    /// endpoint must be HTTPS (HTTP only on loopback).
    pub async fn new(issuer: &str, audience: &str, jwks_url: Option<&str>) -> Result<Self, Error> {
        let issuer = issuer.trim().trim_end_matches('/').to_owned();
        let audience = audience.trim().to_owned();
        if audience.is_empty() {
            return Err(oidc_err(format!(
                "{ENV_OIDC_AUDIENCE} is required when {ENV_OIDC_ISSUER} is configured"
            )));
        }
        require_secure_endpoint(&issuer)?;
        let mut v = Self {
            issuer,
            audience,
            jwks_url: jwks_url.unwrap_or_default().trim().to_owned(),
            client: oidc_http_client()?,
            keys: RwLock::new(HashMap::new()),
            last_refresh: tokio::sync::Mutex::new(None),
            now: Instant::now,
        };
        if v.jwks_url.is_empty() {
            let discovery: Discovery = v
                .get_json(&format!("{}/.well-known/openid-configuration", v.issuer))
                .await
                .map_err(|e| oidc_err(format!("discover OIDC provider: {e}")))?;
            let advertised = discovery.issuer.unwrap_or_default();
            if !advertised.is_empty() && advertised.trim_end_matches('/') != v.issuer {
                return Err(oidc_err("OIDC discovery issuer mismatch"));
            }
            v.jwks_url = discovery.jwks_uri.unwrap_or_default().trim().to_owned();
            if v.jwks_url.is_empty() {
                return Err(oidc_err("OIDC provider did not advertise jwks_uri"));
            }
            if !same_origin(&v.issuer, &v.jwks_url) {
                return Err(oidc_err(format!(
                    "OIDC discovery jwks_uri must share the issuer origin; set {ENV_OIDC_JWKS_URL} explicitly to trust a different origin"
                )));
            }
        }
        require_secure_endpoint(&v.jwks_url)?;
        v.refresh_keys(true).await?;
        Ok(v)
    }

    /// The configured issuer, without trailing slashes.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The required audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The JWKS URL keys are loaded from.
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    async fn get_json<T: DeserializeOwned>(&self, endpoint: &str) -> Result<T, String> {
        require_secure_endpoint(endpoint).map_err(|e| e.to_string())?;
        let mut resp = self
            .client
            .get(endpoint)
            .send()
            .await
            .map_err(|e| error_chain(&e))?;
        let status = resp.status().as_u16();
        if status / 100 != 2 {
            return Err(format!("{endpoint} returned HTTP {status}"));
        }
        let mut body = Vec::new();
        while body.len() < MAX_JSON_BYTES {
            match resp.chunk().await.map_err(|e| error_chain(&e))? {
                Some(chunk) => {
                    let take = chunk.len().min(MAX_JSON_BYTES - body.len());
                    body.extend_from_slice(&chunk[..take]);
                }
                None => break,
            }
        }
        let value = decode_first_value(&body)?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    /// Reloads the JWKS. Unless `force` is set, a refresh within the cooldown
    /// of the previous one is skipped. Refreshes are serialized.
    async fn refresh_keys(&self, force: bool) -> Result<(), Error> {
        let mut last = self.last_refresh.lock().await;
        let now = (self.now)();
        if !force && last.is_some_and(|t| now.saturating_duration_since(t) < REFRESH_COOLDOWN) {
            return Ok(());
        }
        let set: JsonWebKeySet = self
            .get_json(&self.jwks_url)
            .await
            .map_err(|e| oidc_err(format!("load OIDC keys: {e}")))?;
        let mut keys = HashMap::new();
        for key in set.keys.unwrap_or_default() {
            let s = |v: &Option<String>| v.clone().unwrap_or_default();
            let (kty, n, e, key_use, alg) = (
                s(&key.kty),
                s(&key.n),
                s(&key.e),
                s(&key.key_use),
                s(&key.alg),
            );
            if kty != "RSA"
                || n.is_empty()
                || e.is_empty()
                || (!key_use.is_empty() && key_use != "sig")
                || (!alg.is_empty() && alg != "RS256")
            {
                continue;
            }
            let Ok(n_bytes) = URL_SAFE_NO_PAD.decode(n.as_bytes()) else {
                continue;
            };
            let Ok(e_bytes) = URL_SAFE_NO_PAD.decode(e.as_bytes()) else {
                continue;
            };
            if e_bytes.is_empty() || e_bytes.len() > 4 {
                continue;
            }
            let exponent = e_bytes
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            if exponent <= 1 {
                continue;
            }
            keys.insert(
                s(&key.kid),
                RsaKey {
                    n: trim_leading_zeros(&n_bytes).to_vec(),
                    e: trim_leading_zeros(&e_bytes).to_vec(),
                },
            );
        }
        if keys.is_empty() {
            return Err(oidc_err("OIDC JWKS contains no usable RS256 keys"));
        }
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = keys;
        *last = Some((self.now)());
        Ok(())
    }

    fn key(&self, kid: &str) -> Option<RsaKey> {
        self.keys
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(kid)
            .cloned()
    }

    /// Authenticates a JWT and derives a least-privilege [`Principal`] from
    /// its signed Runeward claims (`runeward_tenant`, `runeward_profiles`,
    /// `runeward_approval_profiles`, `runeward_can_approve`,
    /// `runeward_admin`). Tokens without `runeward_profiles` can launch
    /// nothing.
    ///
    /// The token must be RS256 with a `kid`, signed by a cached or freshly
    /// fetched JWKS key, with a matching issuer, a non-empty subject, an
    /// unexpired `exp`, an `nbf` no more than 30 seconds in the future, and
    /// the configured audience.
    pub async fn verify(&self, token: &str) -> Result<Principal, Error> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(oidc_err("OIDC token exceeds maximum size"));
        }
        let parts: Vec<&str> = token.split('.').collect();
        let [header_b64, payload_b64, signature_b64] = parts[..] else {
            return Err(oidc_err("OIDC token is not a JWT"));
        };
        let header = URL_SAFE_NO_PAD
            .decode(header_b64.as_bytes())
            .ok()
            .and_then(|h| parse_object::<TokenHeader>(&h))
            .unwrap_or_default();
        let kid = header.kid.unwrap_or_default();
        if header.alg.as_deref() != Some("RS256") || kid.is_empty() {
            return Err(oidc_err("unsupported OIDC token header"));
        }
        let key = match self.key(&kid) {
            Some(key) => key,
            None => {
                self.refresh_keys(false).await?;
                self.key(&kid)
                    .ok_or_else(|| oidc_err("OIDC signing key not found"))?
            }
        };
        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature_b64.as_bytes()) else {
            return Err(oidc_err("invalid OIDC signature encoding"));
        };
        let message = &token[..header_b64.len() + 1 + payload_b64.len()];
        if !key.verifies(message.as_bytes(), &signature) {
            return Err(oidc_err("invalid OIDC signature"));
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64.as_bytes())
            .map_err(|_| oidc_err("invalid OIDC claims encoding"))?;
        let claims: Claims =
            parse_object(&payload).ok_or_else(|| oidc_err("invalid OIDC claims"))?;

        let now = unix_now();
        let iss = claims.iss.as_deref().unwrap_or_default();
        let sub = claims.sub.as_deref().unwrap_or_default();
        let exp = claims.exp.unwrap_or_default();
        let nbf = claims.nbf.unwrap_or_default();
        if iss.trim_end_matches('/') != self.issuer
            || sub.is_empty()
            || exp <= now
            || (nbf != 0 && nbf > now.saturating_add(NBF_LEEWAY_SECS))
            || !audience_contains(&claims.aud, &self.audience)
        {
            return Err(oidc_err("OIDC claims validation failed"));
        }
        Ok(Principal {
            name: first_claim(&[
                claims.preferred_username.as_deref(),
                claims.email.as_deref(),
                Some(sub),
            ]),
            tenant: first_claim(&[claims.runeward_tenant.as_deref(), Some(sub)]),
            token: String::new(),
            allowed_profiles: claims.runeward_profiles.unwrap_or_default(),
            can_approve: claims.runeward_can_approve.unwrap_or_default(),
            approval_profiles: claims.runeward_approval_profiles.unwrap_or_default(),
            admin: claims.runeward_admin.unwrap_or_default(),
        })
    }

    #[cfg(test)]
    fn for_test(
        issuer: &str,
        audience: &str,
        jwks_url: &str,
        keys: HashMap<String, RsaKey>,
        last_refresh: Option<Instant>,
    ) -> Self {
        Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            jwks_url: jwks_url.to_owned(),
            client: oidc_http_client().expect("client"),
            keys: RwLock::new(keys),
            last_refresh: tokio::sync::Mutex::new(last_refresh),
            now: Instant::now,
        }
    }

    /// Replaces the cooldown clock.
    #[cfg(test)]
    fn with_clock(mut self, now: fn() -> Instant) -> Self {
        self.now = now;
        self
    }
}

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(s) = source {
        let text = s.to_string();
        if !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = s.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use crate::test_support::{assert_child_passed, child_command, child_test_name, is_child};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};

    use axum::Router;
    use axum::routing::get;
    use rsa::pkcs1v15::SigningKey;
    // rsa 0.9 signs with the digest 0.10 line, so take its own sha2.
    use rsa::sha2::Sha256;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::json;

    /// One 2048-bit key per test binary; generation is slow in debug builds.
    fn test_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("keygen"))
    }

    fn other_key() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("keygen"))
    }

    fn decoding_key(key: &RsaPublicKey) -> RsaKey {
        RsaKey {
            n: key.n().to_bytes_be(),
            e: key.e().to_bytes_be(),
        }
    }

    fn jwk(key: &RsaPublicKey, kid: &str) -> Value {
        json!({
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        })
    }

    fn signed_jwt_with_alg(key: &RsaPrivateKey, alg: &str, kid: &str, claims: &Value) -> String {
        let header = json!({"alg": alg, "kid": kid, "typ": "JWT"});
        let unsigned = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signer = SigningKey::<Sha256>::new(key.clone());
        let signature = signer.sign(unsigned.as_bytes()).to_bytes();
        format!("{unsigned}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn signed_jwt(key: &RsaPrivateKey, kid: &str, claims: &Value) -> String {
        signed_jwt_with_alg(key, "RS256", kid, claims)
    }

    fn in_a_minute() -> i64 {
        unix_now() + 60
    }

    fn verifier_with_test_key() -> OidcVerifier {
        let keys = HashMap::from([("test".to_owned(), decoding_key(&test_key().to_public_key()))]);
        OidcVerifier::for_test("https://issuer.example", "runeward", "", keys, None)
    }

    /// Serves discovery and a JWKS on a loopback port, counting JWKS fetches.
    async fn serve_idp(
        jwks: Value,
        jwks_uri_override: Option<String>,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let issuer = format!("http://{}", listener.local_addr().expect("addr"));
        let fetches = Arc::new(AtomicUsize::new(0));
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": jwks_uri_override.unwrap_or_else(|| format!("{issuer}/jwks")),
        });
        let counter = fetches.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let j = jwks.clone();
                    async move { axum::Json(j) }
                }),
            );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (issuer, fetches)
    }

    #[tokio::test]
    async fn verify_maps_tenant_and_scopes() {
        let token = signed_jwt(
            test_key(),
            "test",
            &json!({
                "iss": "https://issuer.example", "sub": "subject-1", "aud": ["other", "runeward"],
                "exp": in_a_minute(), "preferred_username": "codex-agent",
                "runeward_tenant": "team-alpha", "runeward_profiles": ["dev-*"],
                "runeward_approval_profiles": ["dev-review"], "runeward_can_approve": true,
            }),
        );
        let p = verifier_with_test_key()
            .verify(&token)
            .await
            .expect("verify");
        assert_eq!(p.name, "codex-agent");
        assert_eq!(p.tenant_id(), "team-alpha");
        assert!(p.can_launch("dev-one"));
        assert!(p.can_approve_profile("dev-review"));
        assert!(p.token.is_empty());
        assert!(!p.admin);
    }

    #[tokio::test]
    async fn verify_name_and_tenant_fallbacks() {
        let v = verifier_with_test_key();
        let base = json!({"iss": "https://issuer.example/", "sub": "s-1", "aud": "runeward", "exp": in_a_minute()});
        let p = v
            .verify(&signed_jwt(test_key(), "test", &base))
            .await
            .expect("verify");
        assert_eq!((p.name.as_str(), p.tenant_id()), ("s-1", "s-1"));
        assert!(!p.may_launch());
        let mut with_email = base.clone();
        with_email["email"] = json!("dev@example.com");
        with_email["preferred_username"] = json!("   ");
        let p = v
            .verify(&signed_jwt(test_key(), "test", &with_email))
            .await
            .expect("verify");
        assert_eq!(p.name, "dev@example.com");
    }

    #[tokio::test]
    async fn verify_rejects_wrong_audience_and_tampering() {
        let v = verifier_with_test_key();
        let mut claims = json!({"iss": "https://issuer.example", "sub": "s", "aud": "wrong", "exp": in_a_minute()});
        assert!(
            v.verify(&signed_jwt(test_key(), "test", &claims))
                .await
                .is_err()
        );

        claims["aud"] = json!("runeward");
        let token = signed_jwt(test_key(), "test", &claims);
        assert!(v.verify(&token).await.is_ok());
        let mut tampered = token.into_bytes();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let tampered = String::from_utf8(tampered).expect("utf-8");
        assert!(v.verify(&tampered).await.is_err());
    }

    #[tokio::test]
    async fn verify_rejects_bad_claims() {
        let v = verifier_with_test_key();
        let good = json!({"iss": "https://issuer.example", "sub": "s", "aud": "runeward", "exp": in_a_minute()});
        let mutations: &[(&str, Value)] = &[
            ("iss", json!("https://evil.example")),
            ("sub", json!("")),
            ("exp", json!(unix_now() - 1)),
            ("nbf", json!(unix_now() + 3600)),
            ("aud", json!(["other"])),
            ("aud", json!(5)),
        ];
        for (field, value) in mutations {
            let mut claims = good.clone();
            claims[*field] = value.clone();
            let err = v
                .verify(&signed_jwt(test_key(), "test", &claims))
                .await
                .expect_err(field);
            assert_eq!(err.to_string(), "OIDC claims validation failed", "{field}");
        }
        let mut skewed = good.clone();
        skewed["nbf"] = json!(unix_now() + 10);
        assert!(
            v.verify(&signed_jwt(test_key(), "test", &skewed))
                .await
                .is_ok()
        );

        // A time claim of the wrong JSON type fails the whole claim set
        // rather than being skipped as absent.
        for (field, value) in [
            ("exp", json!("tomorrow")),
            ("nbf", json!((unix_now() + 3600).to_string())),
        ] {
            let mut wrong_type = good.clone();
            wrong_type[field] = value;
            let err = v
                .verify(&signed_jwt(test_key(), "test", &wrong_type))
                .await
                .expect_err("typed claims");
            assert_eq!(err.to_string(), "invalid OIDC claims", "{field}");
        }
    }

    #[tokio::test]
    async fn verify_rejects_bad_headers_and_shapes() {
        let v = verifier_with_test_key();
        let claims = json!({"iss": "https://issuer.example", "sub": "s", "aud": "runeward", "exp": in_a_minute()});
        let hs = signed_jwt_with_alg(test_key(), "HS256", "test", &claims);
        let no_kid = signed_jwt(test_key(), "", &claims);
        for token in [hs.as_str(), no_kid.as_str()] {
            let err = v.verify(token).await.expect_err("header");
            assert_eq!(err.to_string(), "unsupported OIDC token header");
        }
        let err = v.verify("a.b").await.expect_err("shape");
        assert_eq!(err.to_string(), "OIDC token is not a JWT");
        let good = signed_jwt(test_key(), "test", &claims);
        let bad_sig = format!("{}.!!!", good.rsplit_once('.').expect("dot").0);
        let err = v.verify(&bad_sig).await.expect_err("sig encoding");
        assert_eq!(err.to_string(), "invalid OIDC signature encoding");
        let wrong_key = signed_jwt(other_key(), "test", &claims);
        let err = v.verify(&wrong_key).await.expect_err("wrong key");
        assert_eq!(err.to_string(), "invalid OIDC signature");
    }

    /// A fixed reference instant for the cooldown tests.
    fn epoch() -> Instant {
        static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        *EPOCH.get_or_init(Instant::now)
    }

    #[tokio::test]
    async fn unknown_key_refresh_is_rate_limited() {
        // The clock is frozen at the last refresh, so however long the key
        // generation below takes on a loaded machine, the cooldown holds.
        let v = OidcVerifier::for_test(
            "https://issuer.example",
            "runeward",
            "not-a-valid-url",
            HashMap::new(),
            Some(epoch()),
        )
        .with_clock(epoch);
        let token = signed_jwt(
            test_key(),
            "attacker-controlled-kid",
            &json!({"iss": "https://issuer.example", "sub": "s", "aud": "runeward", "exp": in_a_minute()}),
        );
        let err = v.verify(&token).await.expect_err("cache miss");
        assert_eq!(err.to_string(), "OIDC signing key not found");
    }

    #[tokio::test]
    async fn rejects_oversized_token() {
        let v = OidcVerifier::for_test("", "", "", HashMap::new(), None);
        let err = v
            .verify(&"\0".repeat(32 * 1024 + 1))
            .await
            .expect_err("oversized");
        assert_eq!(err.to_string(), "OIDC token exceeds maximum size");
    }

    #[test]
    fn require_secure_oidc_endpoint() {
        for endpoint in [
            "https://issuer.example",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            require_secure_endpoint(endpoint).unwrap_or_else(|e| panic!("{endpoint}: {e}"));
        }
        assert!(require_secure_endpoint("http://issuer.example").is_err());
        for endpoint in [
            "https://user@issuer.example",
            "https://issuer.example/#fragment",
            "not-a-valid-url",
        ] {
            assert!(require_secure_endpoint(endpoint).is_err(), "{endpoint}");
        }
    }

    #[test]
    fn origin_and_redirect_policy() {
        assert!(same_origin(
            "https://issuer.example",
            "https://ISSUER.example:443/jwks"
        ));
        assert!(!same_origin(
            "https://issuer.example",
            "https://keys.example/jwks"
        ));
        assert!(!same_origin(
            "https://issuer.example",
            "https://issuer.example:8443/jwks"
        ));

        let first = Url::parse("https://issuer.example/start").expect("url");
        let cross = Url::parse("https://keys.example/jwks").expect("url");
        assert!(check_redirect(&cross, std::slice::from_ref(&first)).is_err());
        let same = Url::parse("https://issuer.example/jwks").expect("url");
        assert!(check_redirect(&same, std::slice::from_ref(&first)).is_ok());
        let insecure = Url::parse("http://issuer.example/jwks").expect("url");
        assert!(check_redirect(&insecure, std::slice::from_ref(&first)).is_err());
        let many = vec![first; MAX_REDIRECTS];
        assert!(check_redirect(&same, &many).is_err());
    }

    #[tokio::test]
    async fn new_discovers_jwks_and_verifies() {
        let public = test_key().to_public_key();
        let jwks = json!({"keys": [
            {"kty": "EC", "kid": "ec"},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
            jwk(&public, "k1"),
        ]});
        let (issuer, fetches) = serve_idp(jwks, None).await;
        let v = OidcVerifier::new(&format!("{issuer}/"), " runeward ", None)
            .await
            .expect("new");
        assert_eq!(v.issuer(), issuer);
        assert_eq!(v.jwks_url(), format!("{issuer}/jwks"));
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        assert!(v.key("enc").is_none() && v.key("ec").is_none());

        let token = signed_jwt(
            test_key(),
            "k1",
            &json!({"iss": issuer, "sub": "s", "aud": "runeward", "exp": in_a_minute(), "runeward_admin": true}),
        );
        let p = v.verify(&token).await.expect("verify");
        assert!(p.admin);

        // An unknown kid inside the cooldown does not refetch.
        let unknown = signed_jwt(
            test_key(),
            "k2",
            &json!({"iss": issuer, "sub": "s", "aud": "runeward", "exp": in_a_minute()}),
        );
        assert!(v.verify(&unknown).await.is_err());
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_kid_refreshes_after_cooldown() {
        let public = test_key().to_public_key();
        let (issuer, fetches) = serve_idp(json!({"keys": [jwk(&public, "rotated")]}), None).await;
        let v = OidcVerifier::for_test(
            &issuer,
            "runeward",
            &format!("{issuer}/jwks"),
            HashMap::new(),
            Some(epoch()),
        )
        .with_clock(|| epoch() + REFRESH_COOLDOWN + Duration::from_secs(1));
        let token = signed_jwt(
            test_key(),
            "rotated",
            &json!({"iss": issuer, "sub": "s", "aud": "runeward", "exp": in_a_minute()}),
        );
        v.verify(&token).await.expect("verify after refresh");
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn new_rejects_bad_configuration() {
        let err = OidcVerifier::new("https://issuer.example", "", None)
            .await
            .expect_err("audience");
        assert!(err.to_string().contains(ENV_OIDC_AUDIENCE), "{err}");

        let err = OidcVerifier::new("http://issuer.example", "aud", None)
            .await
            .expect_err("insecure");
        assert!(err.to_string().contains("HTTPS"), "{err}");

        let (issuer, _) = serve_idp(
            json!({"keys": []}),
            Some("https://keys.example/jwks".into()),
        )
        .await;
        let err = OidcVerifier::new(&issuer, "aud", None)
            .await
            .expect_err("cross-origin jwks");
        assert!(err.to_string().contains("share the issuer origin"), "{err}");

        let (issuer, _) = serve_idp(json!({"keys": [{"kty": "EC"}]}), None).await;
        let err = OidcVerifier::new(&issuer, "aud", None)
            .await
            .expect_err("no keys");
        assert_eq!(err.to_string(), "OIDC JWKS contains no usable RS256 keys");

        let err = OidcVerifier::new(&issuer, "aud", Some(&format!("{issuer}/missing")))
            .await
            .expect_err("404");
        assert!(err.to_string().contains("returned HTTP 404"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn store_from_env_with_oidc() {
        let name = child_test_name(module_path!(), "store_from_env_with_oidc");
        if is_child(&name) {
            let token = std::env::var("RUNEWARD_TEST_OIDC_TOKEN").expect("token");
            let store = Store::from_env()
                .await
                .expect("from_env")
                .expect("OIDC-only store");
            assert!(store.is_empty());
            assert!(store.oidc().is_some());
            let p = store.identify(&token).await.expect("identify");
            assert_eq!(p.name, "oidc-user");
            assert!(store.identify("not-a-token").await.is_none());
            return;
        }
        let public = test_key().to_public_key();
        let (issuer, _) = serve_idp(json!({"keys": [jwk(&public, "k1")]}), None).await;
        let token = signed_jwt(
            test_key(),
            "k1",
            &json!({"iss": issuer, "sub": "s", "aud": "runeward", "exp": in_a_minute(), "preferred_username": "oidc-user"}),
        );
        let cmd = child_command(
            &name,
            &[
                (ENV_OIDC_ISSUER, issuer.as_str()),
                (ENV_OIDC_AUDIENCE, "runeward"),
                ("RUNEWARD_TEST_OIDC_TOKEN", token.as_str()),
            ],
            &[crate::ENV_FILE, ENV_OIDC_JWKS_URL],
        );
        let out = tokio::process::Command::from(cmd)
            .output()
            .await
            .expect("spawn child");
        assert_child_passed(&name, &out);
    }

    #[tokio::test]
    async fn from_env_requires_audience() {
        let name = child_test_name(module_path!(), "from_env_requires_audience");
        if !is_child(&name) {
            crate::test_support::run_child(
                &name,
                &[(ENV_OIDC_ISSUER, "https://issuer.example")],
                &[ENV_OIDC_AUDIENCE, ENV_OIDC_JWKS_URL, crate::ENV_FILE],
            );
            return;
        }
        let err = Store::from_env().await.expect_err("audience required");
        assert!(err.to_string().contains(ENV_OIDC_AUDIENCE), "{err}");
    }
}
