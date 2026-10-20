//! `aws://<secretId>[#<jsonKey>]` references (AWS Secrets Manager).

use std::fmt;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::http::{chain, client_or_default, decode_body, default_client, read_limited};
use crate::resolver::{Error, ResolveFuture, Resolver, split_scheme};
use crate::vault::redacted;

const SERVICE: &str = "secretsmanager";
const CONTENT_TYPE: &str = "application/x-amz-json-1.1";
const TARGET: &str = "secretsmanager.GetSecretValue";

/// Reads secrets from AWS Secrets Manager over its JSON API, authenticating
/// requests with AWS Signature Version 4 implemented here (HMAC-SHA256), so no
/// SDK is required.
///
/// A reference has the form:
///
/// ```text
/// aws://<secretId>            return the raw SecretString
/// aws://<secretId>#<jsonKey>  parse SecretString as JSON and return <jsonKey>
/// ```
///
/// where `<secretId>` is a secret name or ARN. ARNs contain `:` and `/`, so the
/// whole locator up to an optional `#` is treated verbatim as the SecretId.
#[derive(Clone, Default)]
pub struct AwsResolver {
    /// Selects the regional Secrets Manager endpoint, e.g. `us-east-1`.
    pub region: String,
    /// SigV4 access key id.
    pub access_key_id: String,
    /// SigV4 secret access key.
    pub secret_access_key: String,
    /// When set, sent as `X-Amz-Security-Token` for temporary (STS)
    /// credentials.
    pub session_token: String,
    /// Overrides the derived `https://secretsmanager.<region>.amazonaws.com/`
    /// base URL; used by tests to point at a local server.
    pub endpoint: String,
    /// HTTP client for the call; `None` selects a client with a short default
    /// timeout.
    pub client: Option<reqwest::Client>,
}

impl fmt::Debug for AwsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsResolver")
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &redacted(&self.secret_access_key))
            .field("session_token", &redacted(&self.session_token))
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

/// The subset of the GetSecretValue response we consume.
#[derive(Deserialize)]
struct GetSecretValueResponse {
    #[serde(rename = "SecretString", default)]
    secret_string: Option<String>,
}

/// Headers produced by [`AwsResolver::sign_v4`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedHeaders {
    pub(crate) amz_date: String,
    pub(crate) security_token: Option<String>,
    pub(crate) authorization: String,
}

impl AwsResolver {
    /// Constructs a resolver from the standard AWS environment variables
    /// (`AWS_REGION`, falling back to `AWS_DEFAULT_REGION`;
    /// `AWS_ACCESS_KEY_ID`; `AWS_SECRET_ACCESS_KEY`; `AWS_SESSION_TOKEN`).
    /// Missing values surface as errors at resolve time (fail-closed).
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).unwrap_or_default();
        let mut region = var("AWS_REGION");
        if region.is_empty() {
            region = var("AWS_DEFAULT_REGION");
        }
        Self {
            region,
            access_key_id: var("AWS_ACCESS_KEY_ID"),
            secret_access_key: var("AWS_SECRET_ACCESS_KEY"),
            session_token: var("AWS_SESSION_TOKEN"),
            endpoint: String::new(),
            client: default_client().ok(),
        }
    }

    /// Fetches a secret from Secrets Manager named by `reference`.
    pub async fn resolve(&self, reference: &str) -> Result<String, Error> {
        let (secret_id, json_key) = parse_aws_ref(reference)?;
        if self.region.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: AWS_REGION (or AWS_DEFAULT_REGION) is not set"
            )));
        }
        if self.access_key_id.is_empty() || self.secret_access_key.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set"
            )));
        }

        let endpoint = if self.endpoint.is_empty() {
            format!("https://secretsmanager.{}.amazonaws.com/", self.region)
        } else {
            self.endpoint.clone()
        };
        let build_err = |e: String| {
            Error::new(format!(
                "secret reference {reference:?}: build request: {e}"
            ))
        };
        let url = reqwest::Url::parse(&endpoint).map_err(|e| build_err(e.to_string()))?;

        let body = format!(
            "{{\"SecretId\":{}}}",
            serde_json::to_string(secret_id).map_err(|e| build_err(e.to_string()))?
        );
        let signed = self
            .sign_v4("POST", &url, body.as_bytes(), Utc::now())
            .map_err(|e| {
                Error::new(format!("secret reference {reference:?}: sign request: {e}"))
            })?;

        let client = client_or_default(self.client.as_ref()).map_err(|e| build_err(chain(&e)))?;
        let mut req = client
            .post(url)
            .header("Content-Type", CONTENT_TYPE)
            .header("X-Amz-Target", TARGET)
            .header("X-Amz-Date", &signed.amz_date)
            .header("Authorization", &signed.authorization);
        if let Some(token) = &signed.security_token {
            req = req.header("X-Amz-Security-Token", token);
        }
        let mut resp = req.body(body).send().await.map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: secretsmanager request failed: {}",
                chain(&e)
            ))
        })?;

        let status = resp.status().as_u16();
        if status != 200 {
            let msg = read_limited(&mut resp, 4096).await;
            return Err(Error::new(format!(
                "secret reference {reference:?}: secretsmanager returned status {status}: {}",
                String::from_utf8_lossy(&msg).trim()
            )));
        }

        let out: GetSecretValueResponse = decode_body(resp).await.map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: decode secretsmanager response: {e}"
            ))
        })?;
        let secret = out.secret_string.unwrap_or_default();
        if secret.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: secret {secret_id:?} has no SecretString"
            )));
        }

        let Some(json_key) = json_key else {
            return Ok(secret);
        };

        let fields: Option<Map<String, Value>> = serde_json::from_str(&secret).map_err(|e| {
            Error::new(format!(
                "secret reference {reference:?}: SecretString is not a JSON object (needed for #{json_key}): {e}"
            ))
        })?;
        let Some(raw) = fields.and_then(|mut m| m.remove(json_key)) else {
            return Err(Error::new(format!(
                "secret reference {reference:?}: key {json_key:?} not present in secret {secret_id:?}"
            )));
        };
        let Value::String(val) = raw else {
            return Err(Error::new(format!(
                "secret reference {reference:?}: key {json_key:?} is not a string"
            )));
        };
        if val.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: key {json_key:?} is empty"
            )));
        }
        Ok(val)
    }

    /// Computes the AWS Signature Version 4 headers for a Secrets Manager
    /// `GetSecretValue` request to `url` with payload `body` at `now`.
    ///
    /// Signed headers are `content-type`, `host`, `x-amz-date`,
    /// `x-amz-target` and, when a session token is present,
    /// `x-amz-security-token`.
    pub(crate) fn sign_v4(
        &self,
        method: &str,
        url: &reqwest::Url,
        body: &[u8],
        now: DateTime<Utc>,
    ) -> Result<SignedHeaders, String> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();

        let host = match (url.host_str(), url.port()) {
            (Some(h), Some(p)) if !h.is_empty() => format!("{h}:{p}"),
            (Some(h), None) if !h.is_empty() => h.to_owned(),
            _ => return Err("request URL has no host".to_owned()),
        };
        let security_token = (!self.session_token.is_empty()).then(|| self.session_token.clone());

        let payload_hash = hex_sha256(body);

        let mut signed: Vec<(&str, &str)> = vec![
            ("content-type", CONTENT_TYPE),
            ("host", &host),
            ("x-amz-date", &amz_date),
            ("x-amz-target", TARGET),
        ];
        if let Some(token) = &security_token {
            signed.push(("x-amz-security-token", token.trim()));
        }
        signed.sort_by(|a, b| a.0.cmp(b.0));
        let signed_headers = signed.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
        let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();

        let canonical_uri = if url.path().is_empty() {
            "/"
        } else {
            url.path()
        };
        let canonical_query = url.query().unwrap_or("");

        let canonical_request = [
            method,
            canonical_uri,
            canonical_query,
            &canonical_headers,
            &signed_headers,
            &payload_hash,
        ]
        .join("\n");

        let credential_scope = [
            date_stamp.as_str(),
            self.region.as_str(),
            SERVICE,
            "aws4_request",
        ]
        .join("/");
        let string_to_sign = [
            "AWS4-HMAC-SHA256",
            &amz_date,
            &credential_scope,
            &hex_sha256(canonical_request.as_bytes()),
        ]
        .join("\n");

        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
        let signing_key = hmac_sha256(&k_service, b"aws4_request");
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );
        Ok(SignedHeaders {
            amz_date,
            security_token,
            authorization,
        })
    }
}

impl Resolver for AwsResolver {
    fn resolve<'a>(&'a self, reference: &'a str) -> ResolveFuture<'a> {
        Box::pin(AwsResolver::resolve(self, reference))
    }
}

/// Splits `aws://<secretId>[#<jsonKey>]` into its parts. The secretId may be a
/// name or an ARN (which itself contains `:` and `/`), so everything before an
/// optional trailing `#` is taken verbatim.
fn parse_aws_ref(reference: &str) -> Result<(&str, Option<&str>), Error> {
    let mut rest = match split_scheme(reference) {
        Some((scheme, rest)) if scheme == "aws" => rest,
        _ => {
            return Err(Error::new(format!(
                "secret reference {reference:?} is not an aws:// reference"
            )));
        }
    };
    let mut json_key = None;
    if let Some(hash) = rest.rfind('#') {
        let key = &rest[hash + 1..];
        rest = &rest[..hash];
        if key.is_empty() {
            return Err(Error::new(format!(
                "secret reference {reference:?}: empty key after # (expected aws://<secretId>#<jsonKey>)"
            )));
        }
        json_key = Some(key);
    }
    if rest.is_empty() {
        return Err(Error::new(format!(
            "secret reference {reference:?}: missing <secretId> (expected aws://<secretId>[#<jsonKey>])"
        )));
    }
    Ok((rest, json_key))
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC accepts keys of any length, so construction cannot fail.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap_or_else(|_| unreachable!());
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use chrono::TimeZone;

    #[derive(Default, Clone)]
    struct Seen {
        auth: String,
        target: String,
        security_token: String,
        body: String,
    }

    async fn serve(status: StatusCode, response: &'static str) -> (String, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let recorded = seen.clone();
        let app = Router::new().fallback(move |headers: HeaderMap, body: Bytes| {
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
                    target: h("X-Amz-Target"),
                    security_token: h("X-Amz-Security-Token"),
                    body: String::from_utf8_lossy(&body).into_owned(),
                };
                (status, response).into_response()
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/"), seen)
    }

    fn test_resolver(endpoint: String) -> AwsResolver {
        AwsResolver {
            region: "us-east-1".into(),
            access_key_id: "AKIAEXAMPLE".into(),
            secret_access_key: "secretkey".into(),
            endpoint,
            client: Some(reqwest::Client::new()),
            ..AwsResolver::default()
        }
    }

    #[tokio::test]
    async fn resolve_secret_string() {
        let (url, seen) = serve(StatusCode::OK, r#"{"SecretString":"s3cret"}"#).await;
        let got = test_resolver(url)
            .resolve("aws://prod/db-password")
            .await
            .expect("resolve");
        assert_eq!(got, "s3cret");
        let seen = seen.lock().expect("lock").clone();
        assert!(seen.auth.starts_with("AWS4-HMAC-SHA256 "), "{}", seen.auth);
        assert!(
            seen.auth.contains("Credential=AKIAEXAMPLE/")
                && seen.auth.contains("SignedHeaders=")
                && seen.auth.contains("Signature="),
            "{}",
            seen.auth
        );
        assert_eq!(seen.target, "secretsmanager.GetSecretValue");
        assert_eq!(seen.body, r#"{"SecretId":"prod/db-password"}"#);
    }

    #[tokio::test]
    async fn resolve_json_key() {
        let (url, _) = serve(
            StatusCode::OK,
            r#"{"SecretString":"{\"password\":\"p\",\"user\":\"u\"}"}"#,
        )
        .await;
        let got = test_resolver(url)
            .resolve("aws://prod/creds#password")
            .await
            .expect("resolve");
        assert_eq!(got, "p");
    }

    #[tokio::test]
    async fn resolve_arn() {
        let (url, seen) = serve(StatusCode::OK, r#"{"SecretString":"arn-value"}"#).await;
        let arn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf";
        let got = test_resolver(url)
            .resolve(&format!("aws://{arn}"))
            .await
            .expect("resolve");
        assert_eq!(got, "arn-value");
        assert!(seen.lock().expect("lock").body.contains(arn));
    }

    #[tokio::test]
    async fn resolve_session_token() {
        let (url, seen) = serve(StatusCode::OK, r#"{"SecretString":"v"}"#).await;
        let mut r = test_resolver(url);
        r.session_token = "session-token-xyz".into();
        r.resolve("aws://name").await.expect("resolve");
        assert_eq!(
            seen.lock().expect("lock").security_token,
            "session-token-xyz"
        );
    }

    #[tokio::test]
    async fn resolve_missing_creds() {
        let r = AwsResolver {
            region: "us-east-1".into(),
            endpoint: "http://127.0.0.1:0/".into(),
            ..AwsResolver::default()
        };
        let err = r.resolve("aws://name").await.expect_err("missing creds");
        assert!(err.to_string().contains("AWS_ACCESS_KEY_ID"), "{err}");
    }

    #[tokio::test]
    async fn resolve_missing_region() {
        let r = AwsResolver {
            access_key_id: "a".into(),
            secret_access_key: "b".into(),
            ..AwsResolver::default()
        };
        let err = r.resolve("aws://name").await.expect_err("missing region");
        assert!(err.to_string().contains("AWS_REGION"), "{err}");
    }

    #[tokio::test]
    async fn resolve_non_200() {
        let (url, _) = serve(
            StatusCode::BAD_REQUEST,
            r#"{"__type":"ResourceNotFoundException"}"#,
        )
        .await;
        let err = test_resolver(url)
            .resolve("aws://missing")
            .await
            .expect_err("non-200");
        let msg = err.to_string();
        assert!(msg.contains("status 400"), "{msg}");
        assert!(msg.contains("ResourceNotFoundException"), "{msg}");
    }

    #[tokio::test]
    async fn resolve_missing_json_key() {
        let (url, _) = serve(StatusCode::OK, r#"{"SecretString":"{\"user\":\"u\"}"}"#).await;
        let err = test_resolver(url)
            .resolve("aws://creds#password")
            .await
            .expect_err("missing key");
        assert!(err.to_string().contains("not present"), "{err}");
    }

    #[tokio::test]
    async fn resolve_empty_secret_string() {
        let (url, _) = serve(StatusCode::OK, r#"{"SecretBinary":"AAAA"}"#).await;
        let err = test_resolver(url)
            .resolve("aws://bin")
            .await
            .expect_err("no SecretString");
        assert!(err.to_string().contains("has no SecretString"), "{err}");
    }

    #[test]
    fn parse_aws_ref_cases() {
        let ok: &[(&str, &str, Option<&str>)] = &[
            ("aws://name", "name", None),
            ("aws://name#field", "name", Some("field")),
            (
                "aws://arn:aws:secretsmanager:us-east-1:1:secret:x/y",
                "arn:aws:secretsmanager:us-east-1:1:secret:x/y",
                None,
            ),
        ];
        for (reference, id, key) in ok {
            assert_eq!(parse_aws_ref(reference).expect(reference), (*id, *key));
        }
        for reference in ["aws://", "aws://name#", "vault://x"] {
            assert!(parse_aws_ref(reference).is_err(), "{reference}");
        }
    }

    /// Vectors produced by the Go reference signer (`AWSResolver.signV4`) for
    /// the same inputs, so the two implementations sign byte-identically.
    #[test]
    fn sign_v4_matches_go_vectors() {
        let now = Utc
            .with_ymd_and_hms(2024, 1, 2, 3, 4, 5)
            .single()
            .expect("time");
        let base = AwsResolver {
            region: "us-east-1".into(),
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            ..AwsResolver::default()
        };
        let cases = [
            (
                "https://secretsmanager.us-east-1.amazonaws.com/",
                "",
                "prod/db-password",
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=a1fd8c5aa574a7aca33dd9fb34d2b44e10e83f07d55aff12f931761db7426cb8",
            ),
            (
                "https://secretsmanager.us-east-1.amazonaws.com/",
                "session-token-xyz",
                "prod/db-password",
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=8778ac68a0916fdddc7647c8726dbfd71993bac40c2edb8d76c19d9b5a3112b5",
            ),
            (
                "http://127.0.0.1:8080/custom/path?b=2&a=1",
                "",
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=752c45dbd73b0d5742abe98aae54e950e8f0c688c81273c2f74a49d2fb3a70c4",
            ),
        ];
        for (endpoint, token, id, want) in cases {
            let r = AwsResolver {
                session_token: token.into(),
                ..base.clone()
            };
            let url = reqwest::Url::parse(endpoint).expect("url");
            let body = format!(r#"{{"SecretId":"{id}"}}"#);
            let signed = r.sign_v4("POST", &url, body.as_bytes(), now).expect("sign");
            assert_eq!(signed.amz_date, "20240102T030405Z");
            assert_eq!(signed.authorization, want, "{endpoint} token={token:?}");
            assert_eq!(
                signed.security_token.as_deref(),
                (!token.is_empty()).then_some(token)
            );
        }
    }

    #[test]
    fn debug_redacts_secrets() {
        let r = AwsResolver {
            secret_access_key: "very-secret".into(),
            session_token: "sess-secret".into(),
            ..AwsResolver::default()
        };
        let dbg = format!("{r:?}");
        assert!(
            !dbg.contains("very-secret") && !dbg.contains("sess-secret"),
            "{dbg}"
        );
    }
}
