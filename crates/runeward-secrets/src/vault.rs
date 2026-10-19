//! `vault://<mount>/<path>#<field>` references (HashiCorp Vault KV v2).

use std::fmt;

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::http::{chain, client_or_default, decode_body, default_client};
use crate::resolver::{Error, ResolveFuture, Resolver, split_scheme};

/// Reads secrets from a HashiCorp Vault KV v2 mount over its HTTP API. A
/// reference has the form:
///
/// ```text
/// vault://<mount>/<path>#<field>
/// ```
///
/// e.g. `vault://kv/database/prod#password` reads field `password` from the
/// logical path `database/prod` on the `kv` mount, issuing
/// `GET ${addr}/v1/<mount>/data/<path>` with `X-Vault-Token: <token>` and
/// returning `.data.data.<field>` from the JSON response.
#[derive(Clone, Default)]
pub struct VaultResolver {
    /// Vault base URL, e.g. `https://vault:8200` (no trailing `/v1`).
    pub addr: String,
    /// Authenticates the read; sent as the `X-Vault-Token` header.
    pub token: String,
    /// HTTP client for the read; `None` selects a client with a short default
    /// timeout.
    pub client: Option<reqwest::Client>,
}

impl fmt::Debug for VaultResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResolver")
            .field("addr", &self.addr)
            .field("token", &redacted(&self.token))
            .finish_non_exhaustive()
    }
}

pub(crate) fn redacted(s: &str) -> &'static str {
    if s.is_empty() { "" } else { "<redacted>" }
}

/// The subset of a KV v2 read we consume: the nested `data.data` object.
#[derive(Deserialize)]
struct KvResponse {
    #[serde(default)]
    data: Option<KvData>,
}

#[derive(Deserialize)]
struct KvData {
    #[serde(default)]
    data: Option<Map<String, Value>>,
}

impl VaultResolver {
    /// Constructs a resolver from `VAULT_ADDR` and `VAULT_TOKEN`. Missing
    /// values surface as errors at resolve time (fail-closed), not at
    /// construction, so the default dispatcher never fails just because Vault
    /// is unused.
    pub fn from_env() -> Self {
        Self {
            addr: std::env::var("VAULT_ADDR")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_owned(),
            token: std::env::var("VAULT_TOKEN").unwrap_or_default(),
            client: default_client().ok(),
        }
    }

    /// Reads a single field from a Vault KV v2 secret named by `reference`.
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        let (mount, path, field) = parse_vault_ref(reference)?;
        let addr = self.addr.trim_end_matches('/');
        if addr.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: VAULT_ADDR is not set"
            )));
        }
        if self.token.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: VAULT_TOKEN is not set"
            )));
        }

        let endpoint = format!("{addr}/v1/{mount}/data/{path}");
        let url = reqwest::Url::parse(&endpoint).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: build request: {e}"
            ))
        })?;
        let client = client_or_default(self.client.as_ref()).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: build request: {}",
                chain(&e)
            ))
        })?;
        let resp = client
            .get(url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                Error::new(format!(
                    "secret reference {reference:?}: vault request failed: {}",
                    chain(&e)
                ))
            })?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(Error::new(format!(
                "secret reference {reference:?}: vault returned status {status} for {mount}/{path}"
            )));
        }

        let kv: KvResponse = decode_body(resp).await.map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: decode vault response: {e}"
            ))
        })?;
        let raw = kv
            .data
            .and_then(|d| d.data)
            .and_then(|mut m| m.remove(field));
        let Some(raw) = raw else {
            return Err(Error::new(format!(
                "secret reference {reference:?}: field {field:?} not present in secret {mount}/{path}"
            )));
        };
        let Value::String(val) = raw else {
            return Err(Error::new(format!(
                "secret reference {reference:?}: field {field:?} is not a string"
            )));
        };
        if val.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: field {field:?} is empty"
            )));
        }
        Ok(val)
    }
}

impl Resolver for VaultResolver {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(VaultResolver::resolve(self, reference))
    }
}

/// Splits `vault://<mount>/<path>#<field>` into its parts.
fn parse_vault_ref(reference: &str) -> Result<(&str, &str, &str), Error> {
    let rest = match split_scheme(reference) {
        Some((scheme, rest)) if scheme == "vault" => rest,
        _ => {
            return Err(Error::new(format!(
                "secret reference {reference:?} is not a vault:// reference"
            )));
        }
    };
    let Some(hash) = rest.rfind('#') else {
        return Err(Error::new(format!(
            "secret reference {reference:?}: missing #<field> (expected vault://<mount>/<path>#<field>)"
        )));
    };
    let field = &rest[hash + 1..];
    let locator = &rest[..hash];
    if field.is_empty() {
        return Err(Error::new(format!(
            "secret reference {reference:?}: empty field after # (expected vault://<mount>/<path>#<field>)"
        )));
    }

    let missing = || {
        Error::new(format!(
            "secret reference {reference:?}: missing <mount>/<path> (expected vault://<mount>/<path>#<field>)"
        ))
    };
    let locator = locator.strip_prefix('/').unwrap_or(locator);
    let Some(slash) = locator.find('/') else {
        return Err(missing());
    };
    let mount = &locator[..slash];
    let path = locator[slash + 1..].trim_matches('/');
    if mount.is_empty() || path.is_empty() {
        return Err(missing());
    }
    Ok((mount, path, field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::IntoResponse;

    /// Serves a KV v2 response for one path and 404 for everything else,
    /// recording the token header it was called with.
    async fn fake_vault(want_path: &'static str, body: Value) -> (String, Arc<Mutex<String>>) {
        let got_token = Arc::new(Mutex::new(String::new()));
        let recorded = got_token.clone();
        let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
            let recorded = recorded.clone();
            let body = body.clone();
            async move {
                let token = headers
                    .get("X-Vault-Token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                *recorded.lock().expect("lock") = token;
                if uri.path() != want_path {
                    return (StatusCode::NOT_FOUND, "not found").into_response();
                }
                axum::Json(body).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), got_token)
    }

    async fn resolver() -> (VaultResolver, Arc<Mutex<String>>) {
        let body =
            serde_json::json!({"data": {"data": {"password": "s3cret", "num": 3, "blank": ""}}});
        let (url, token) = fake_vault("/v1/kv/data/database/prod", body).await;
        let r = VaultResolver {
            addr: url,
            token: "test-token".into(),
            client: Some(reqwest::Client::new()),
        };
        (r, token)
    }

    #[tokio::test]
    async fn resolves_field_and_sends_token() {
        let (r, token) = resolver().await;
        let got = r
            .resolve("vault://kv/database/prod#password")
            .await
            .expect("resolve");
        assert_eq!(got, "s3cret");
        assert_eq!(*token.lock().expect("lock"), "test-token");
    }

    #[tokio::test]
    async fn missing_field() {
        let (r, _) = resolver().await;
        assert!(
            r.resolve("vault://kv/database/prod#username")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn non_string_and_empty_fields() {
        let (r, _) = resolver().await;
        let err = r
            .resolve("vault://kv/database/prod#num")
            .await
            .expect_err("non-string");
        assert!(err.to_string().contains("is not a string"), "{err}");
        let err = r
            .resolve("vault://kv/database/prod#blank")
            .await
            .expect_err("empty");
        assert!(err.to_string().contains("is empty"), "{err}");
    }

    #[tokio::test]
    async fn not_found() {
        let (r, _) = resolver().await;
        let err = r
            .resolve("vault://kv/does/not/exist#password")
            .await
            .expect_err("404");
        assert!(err.to_string().contains("status 404"), "{err}");
    }

    #[tokio::test]
    async fn missing_addr() {
        let (r, _) = resolver().await;
        let bad = VaultResolver {
            addr: String::new(),
            ..r
        };
        assert!(
            bad.resolve("vault://kv/database/prod#password")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn missing_token() {
        let (r, _) = resolver().await;
        let bad = VaultResolver {
            token: String::new(),
            ..r
        };
        assert!(
            bad.resolve("vault://kv/database/prod#password")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn malformed_refs() {
        let (r, _) = resolver().await;
        for reference in [
            "vault://kv/database/prod",
            "vault://kv/database/prod#",
            "vault://kv#password",
            "vault://#password",
        ] {
            assert!(r.resolve(reference).await.is_err(), "{reference}");
        }
    }

    #[test]
    fn parse_vault_ref_parts() {
        assert_eq!(
            parse_vault_ref("vault:///kv/a/b/#f").expect("parse"),
            ("kv", "a/b", "f")
        );
        assert_eq!(
            parse_vault_ref("vault://kv/a#b#c").expect("parse"),
            ("kv", "a#b", "c")
        );
    }

    #[test]
    fn debug_redacts_token() {
        let r = VaultResolver {
            addr: "https://vault".into(),
            token: "hvs.secret".into(),
            client: None,
        };
        assert!(!format!("{r:?}").contains("hvs.secret"));
    }
}
