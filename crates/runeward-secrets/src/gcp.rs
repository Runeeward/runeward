//! `gcp://` references (Google Secret Manager).

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

use crate::http::{chain, client_or_default, decode_body, default_client, read_limited};
use crate::resolver::{Error, ResolveFuture, Resolver, split_scheme};
use crate::vault::redacted;

/// GCE metadata server base used to fetch a service-account access token when
/// no token is supplied out of band.
const METADATA_DEFAULT_BASE: &str = "http://metadata.google.internal";
const SECRET_MANAGER_BASE: &str = "https://secretmanager.googleapis.com";

/// Reads secrets from Google Secret Manager over its REST API. A reference has
/// either the fully-qualified form:
///
/// ```text
/// gcp://projects/<proj>/secrets/<name>/versions/<ver>
/// ```
///
/// or the shorthand, which fills in the project from `GOOGLE_CLOUD_PROJECT`
/// and defaults the version to `latest`:
///
/// ```text
/// gcp://<name>            projects/<proj>/secrets/<name>/versions/latest
/// gcp://<name>#<version>  projects/<proj>/secrets/<name>/versions/<version>
/// ```
///
/// Authorization uses an OAuth2 access token (`token`, else
/// `GOOGLE_OAUTH_ACCESS_TOKEN`, else the GCE metadata server). Service-account
/// JWT signing is intentionally out of scope.
#[derive(Clone, Default)]
pub struct GcpResolver {
    /// Default project for shorthand references.
    pub project: String,
    /// Overrides the `https://secretmanager.googleapis.com` base URL.
    pub endpoint: String,
    /// Bearer access token; when empty, `GOOGLE_OAUTH_ACCESS_TOKEN` and then
    /// the metadata server are tried.
    pub token: String,
    /// Overrides the GCE metadata server base URL.
    pub metadata_base: String,
    /// HTTP client for calls; `None` selects a client with a short default
    /// timeout.
    pub client: Option<reqwest::Client>,
}

impl fmt::Debug for GcpResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcpResolver")
            .field("project", &self.project)
            .field("endpoint", &self.endpoint)
            .field("token", &redacted(&self.token))
            .field("metadata_base", &self.metadata_base)
            .finish_non_exhaustive()
    }
}

/// The subset of the AccessSecretVersion response we consume: `payload.data`
/// is standard base64.
#[derive(Deserialize)]
struct AccessResponse {
    #[serde(default)]
    payload: Option<Payload>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    data: Option<String>,
}

/// The metadata server's token response.
#[derive(Deserialize)]
struct MetadataToken {
    #[serde(default)]
    access_token: Option<String>,
}

impl GcpResolver {
    /// Constructs a resolver from `GOOGLE_CLOUD_PROJECT` and
    /// `GOOGLE_OAUTH_ACCESS_TOKEN`. Missing values surface as errors at
    /// resolve time (fail-closed).
    pub fn from_env() -> Self {
        Self {
            project: std::env::var("GOOGLE_CLOUD_PROJECT").unwrap_or_default(),
            token: std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN").unwrap_or_default(),
            client: default_client().ok(),
            ..Self::default()
        }
    }

    /// Fetches and decodes a secret payload from Secret Manager named by
    /// `reference`.
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        let name = self.parse_gcp_ref(reference)?;

        let client = client_or_default(self.client.as_ref()).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: build request: {}",
                chain(&e)
            ))
        })?;

        let token = self
            .token(&client)
            .await
            .map_err(|e| Error::new(format!("secret reference {reference:?}: {e}")))?;

        let base = if self.endpoint.is_empty() {
            SECRET_MANAGER_BASE
        } else {
            &self.endpoint
        };
        let endpoint = format!("{}/v1/{name}:access", base.trim_end_matches('/'));
        let url = reqwest::Url::parse(&endpoint).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: build request: {e}"
            ))
        })?;

        let mut resp = client
            .get(url)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .map_err(|e| {
                Error::new(format!(
                    "secret reference {reference:?}: secretmanager request failed: {}",
                    chain(&e)
                ))
            })?;

        let status = resp.status().as_u16();
        if status != 200 {
            let msg = read_limited(&mut resp, 4096).await;
            return Err(Error::new(format!(
                "secret reference {reference:?}: secretmanager returned status {status}: {}",
                String::from_utf8_lossy(&msg).trim()
            )));
        }

        let out: AccessResponse = decode_body(resp).await.map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: decode secretmanager response: {e}"
            ))
        })?;
        let data = out.payload.and_then(|p| p.data).unwrap_or_default();
        if data.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: secret {name} has empty payload"
            )));
        }
        let decoded = STANDARD.decode(data.as_bytes()).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: decode secret payload: {e}"
            ))
        })?;
        if decoded.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: secret {name} decoded to empty value"
            )));
        }
        Ok(String::from_utf8_lossy(&decoded).into_owned())
    }

    /// Resolves the bearer token: `self.token`, then
    /// `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE metadata server.
    async fn token(&self, client: &reqwest::Client) -> Result<String, String> {
        if !self.token.is_empty() {
            return Ok(self.token.clone());
        }
        if let Ok(t) = std::env::var("GOOGLE_OAUTH_ACCESS_TOKEN")
            && !t.is_empty()
        {
            return Ok(t);
        }
        self.metadata_token(client).await
    }

    /// Fetches an access token from the GCE metadata server.
    async fn metadata_token(&self, client: &reqwest::Client) -> Result<String, String> {
        let base = if self.metadata_base.is_empty() {
            METADATA_DEFAULT_BASE
        } else {
            &self.metadata_base
        };
        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/default/token",
            base.trim_end_matches('/')
        );
        let url =
            reqwest::Url::parse(&url).map_err(|e| format!("build metadata token request: {e}"))?;

        let resp = client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| {
                format!(
                    "no access token: r.Token, GOOGLE_OAUTH_ACCESS_TOKEN unset and metadata server unreachable: {}",
                    chain(&e)
                )
            })?;

        let status = resp.status().as_u16();
        if status != 200 {
            return Err(format!(
                "metadata server returned status {status} fetching access token"
            ));
        }
        let tok: MetadataToken = decode_body(resp)
            .await
            .map_err(|e| format!("decode metadata token response: {e}"))?;
        match tok.access_token {
            Some(t) if !t.is_empty() => Ok(t),
            _ => Err("metadata server returned an empty access token".to_owned()),
        }
    }

    /// Resolves `reference` to a fully-qualified resource name of the form
    /// `projects/<proj>/secrets/<name>/versions/<ver>`.
    fn parse_gcp_ref(&self, reference: &str) -> Result<String, Error> {
        let rest = match split_scheme(reference) {
            Some((scheme, rest)) if scheme == "gcp" => rest,
            _ => {
                return Err(Error::new(format!(
                    "secret reference {reference:?} is not a gcp:// reference"
                )));
            }
        };
        if rest.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: missing <name> (expected gcp://<name>[#<version>] or gcp://projects/<proj>/secrets/<name>/versions/<ver>)"
            )));
        }

        // Fully-qualified form is passed through verbatim.
        if rest.starts_with("projects/") {
            if !rest.contains("/secrets/") || !rest.contains("/versions/") {
                return Err(Error::new(format!(
                    "secret reference {reference:?}: expected gcp://projects/<proj>/secrets/<name>/versions/<ver>"
                )));
            }
            return Ok(rest.to_owned());
        }

        // Shorthand: gcp://<name>[#<version>], project from GOOGLE_CLOUD_PROJECT.
        let (name, version) = match rest.rfind('#') {
            Some(hash) => {
                let version = &rest[hash + 1..];
                if version.is_empty() {
                    return Err(Error::new(format!(
                        "secret reference {reference:?}: empty version after # (expected gcp://<name>#<version>)"
                    )));
                }
                (&rest[..hash], version)
            }
            None => (rest, "latest"),
        };
        if name.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: missing <name> (expected gcp://<name>[#<version>])"
            )));
        }
        if name.contains('/') {
            return Err(Error::new(format!(
                "secret reference {reference:?}: shorthand <name> must not contain '/'; use the full projects/.../secrets/.../versions/... form"
            )));
        }
        if self.project.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: GOOGLE_CLOUD_PROJECT is not set (needed for shorthand gcp://<name>)"
            )));
        }
        Ok(format!(
            "projects/{}/secrets/{name}/versions/{version}",
            self.project
        ))
    }
}

impl Resolver for GcpResolver {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(GcpResolver::resolve(self, reference))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{child_test_name, is_child, run_child};
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::response::IntoResponse;

    #[derive(Default, Clone)]
    struct Seen {
        auth: String,
        flavor: String,
        path: String,
    }

    type Handler = fn(&Uri) -> (StatusCode, String);

    async fn serve(handler: Handler) -> (String, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let recorded = seen.clone();
        let app = Router::new().fallback(move |uri: Uri, headers: HeaderMap| {
            let recorded = recorded.clone();
            async move {
                let h = |k: &str| {
                    headers
                        .get(k)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                        .to_owned()
                };
                *recorded.lock().expect("lock") = Seen {
                    auth: h("Authorization"),
                    flavor: h("Metadata-Flavor"),
                    path: uri.path().to_owned(),
                };
                handler(&uri).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), seen)
    }

    fn payload(value: &str) -> (StatusCode, String) {
        (
            StatusCode::OK,
            format!(r#"{{"payload":{{"data":"{}"}}}}"#, STANDARD.encode(value)),
        )
    }

    fn resolver(endpoint: String, project: &str, token: &str) -> GcpResolver {
        GcpResolver {
            project: project.into(),
            endpoint,
            token: token.into(),
            client: Some(reqwest::Client::new()),
            ..GcpResolver::default()
        }
    }

    #[tokio::test]
    async fn resolve_shorthand() {
        let (url, seen) = serve(|_| payload("hunter2")).await;
        let got = resolver(url, "my-proj", "tok-123")
            .resolve("gcp://db-password")
            .await
            .expect("resolve");
        assert_eq!(got, "hunter2");
        let seen = seen.lock().expect("lock").clone();
        assert_eq!(seen.auth, "Bearer tok-123");
        assert_eq!(
            seen.path,
            "/v1/projects/my-proj/secrets/db-password/versions/latest:access"
        );
    }

    #[tokio::test]
    async fn resolve_version_and_full_form() {
        let (url, seen) = serve(|_| payload("v")).await;
        let r = resolver(url, "my-proj", "tok");

        r.resolve("gcp://name#3").await.expect("shorthand#ver");
        assert_eq!(
            seen.lock().expect("lock").path,
            "/v1/projects/my-proj/secrets/name/versions/3:access"
        );

        r.resolve("gcp://projects/other/secrets/thing/versions/7")
            .await
            .expect("full form");
        assert_eq!(
            seen.lock().expect("lock").path,
            "/v1/projects/other/secrets/thing/versions/7:access"
        );
    }

    #[tokio::test]
    async fn resolve_metadata_token() {
        // The env fallback must be absent so the metadata server is consulted.
        let name = child_test_name(module_path!(), "resolve_metadata_token");
        if !is_child(&name) {
            run_child(&name, &[], &["GOOGLE_OAUTH_ACCESS_TOKEN"]);
            return;
        }
        let (api, api_seen) = serve(|_| payload("secret")).await;
        let (meta, meta_seen) = serve(|uri| {
            if uri.path() != "/computeMetadata/v1/instance/service-accounts/default/token" {
                return (StatusCode::NOT_FOUND, "404 page not found".to_owned());
            }
            (
                StatusCode::OK,
                r#"{"access_token":"meta-token","expires_in":3599,"token_type":"Bearer"}"#
                    .to_owned(),
            )
        })
        .await;
        let r = GcpResolver {
            metadata_base: meta,
            ..resolver(api, "p", "")
        };
        let got = r.resolve("gcp://name").await.expect("resolve");
        assert_eq!(got, "secret");
        assert_eq!(api_seen.lock().expect("lock").auth, "Bearer meta-token");
        assert_eq!(meta_seen.lock().expect("lock").flavor, "Google");
    }

    #[tokio::test]
    async fn resolve_env_token_fallback() {
        let name = child_test_name(module_path!(), "resolve_env_token_fallback");
        if !is_child(&name) {
            run_child(&name, &[("GOOGLE_OAUTH_ACCESS_TOKEN", "env-token")], &[]);
            return;
        }
        let (api, seen) = serve(|_| payload("secret")).await;
        resolver(api, "p", "")
            .resolve("gcp://name")
            .await
            .expect("resolve");
        assert_eq!(seen.lock().expect("lock").auth, "Bearer env-token");
    }

    #[tokio::test]
    async fn resolve_missing_project() {
        let r = GcpResolver {
            token: "tok".into(),
            ..GcpResolver::default()
        };
        let err = r.resolve("gcp://name").await.expect_err("missing project");
        assert!(err.to_string().contains("GOOGLE_CLOUD_PROJECT"), "{err}");
    }

    #[tokio::test]
    async fn resolve_non_200() {
        let (url, _) = serve(|_| (StatusCode::FORBIDDEN, r#"{"error":"denied"}"#.to_owned())).await;
        let err = resolver(url, "p", "tok")
            .resolve("gcp://name")
            .await
            .expect_err("non-200");
        assert!(err.to_string().contains("status 403"), "{err}");
    }

    #[tokio::test]
    async fn resolve_decode_failure() {
        let (url, _) = serve(|_| {
            (
                StatusCode::OK,
                r#"{"payload":{"data":"!!!not-base64!!!"}}"#.to_owned(),
            )
        })
        .await;
        let err = resolver(url, "p", "tok")
            .resolve("gcp://name")
            .await
            .expect_err("decode");
        assert!(err.to_string().contains("decode secret payload"), "{err}");
    }

    #[test]
    fn parse_gcp_ref_cases() {
        let r = GcpResolver {
            project: "p".into(),
            ..GcpResolver::default()
        };
        let ok = [
            ("gcp://name", "projects/p/secrets/name/versions/latest"),
            ("gcp://name#4", "projects/p/secrets/name/versions/4"),
            (
                "gcp://projects/x/secrets/y/versions/1",
                "projects/x/secrets/y/versions/1",
            ),
        ];
        for (reference, want) in ok {
            assert_eq!(r.parse_gcp_ref(reference).expect(reference), want);
        }
        for reference in [
            "gcp://",
            "gcp://name#",
            "gcp://projects/x/secrets/y",
            "aws://name",
            "gcp://a/b",
        ] {
            assert!(r.parse_gcp_ref(reference).is_err(), "{reference}");
        }
    }

    #[test]
    fn parse_gcp_ref_no_project_shorthand() {
        assert!(GcpResolver::default().parse_gcp_ref("gcp://name").is_err());
    }
}
