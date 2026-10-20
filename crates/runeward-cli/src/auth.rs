//! `runeward auth`: log in with the OIDC device flow (or a token from
//! stdin), show the stored login without its token, or remove it.

use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use base64::Engine as _;
use chrono::{SecondsFormat, TimeZone, Utc};
use runeward_credentials::Login;
use runeward_ledger::gotime::Time;
use serde::Deserialize;
use serde::de::DeserializeOwned;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DeviceDiscovery {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

/// A token-endpoint response; `error` carries RFC 8628 polling states.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeviceToken {
    /// The API access token.
    pub access_token: String,
    /// The ID token (used only when no access token is returned).
    pub id_token: String,
    /// Lifetime in seconds.
    pub expires_in: i64,
    /// `authorization_pending`, `slow_down`, or a terminal error.
    pub error: String,
}

/// Decoded auth responses that may legitimately carry a non-2xx status.
pub trait AuthBody {
    /// Whether a non-2xx response is a JSON error the caller handles.
    fn is_protocol_error(&self) -> bool {
        false
    }
}

impl AuthBody for DeviceDiscovery {}
impl AuthBody for DeviceAuthorization {}
impl AuthBody for DeviceToken {
    fn is_protocol_error(&self) -> bool {
        !self.error.is_empty()
    }
}

/// `auth login`.
pub async fn login(
    issuer: &str,
    client_id: &str,
    audience: &str,
    scope: &str,
    token_stdin: bool,
) -> Result<()> {
    if token_stdin {
        let mut data = Vec::new();
        std::io::stdin().take(64 << 10).read_to_end(&mut data)?;
        let token = String::from_utf8_lossy(&data).trim().to_owned();
        if token.is_empty() {
            bail!("empty token");
        }
        runeward_credentials::save(Login::new(token))?;
        return Ok(());
    }
    if issuer.is_empty() || client_id.is_empty() {
        bail!("--issuer and --client-id are required for OIDC login");
    }
    oidc_device_login(issuer, client_id, audience, scope).await
}

/// `auth status`.
pub fn status() -> Result<()> {
    let stored = runeward_credentials::load().map_err(|_| anyhow!("not logged in"))?;
    let now = runeward_ledger::gotime::now();
    let state = if stored.is_expired_at(&now) {
        "expired"
    } else {
        "valid"
    };
    let expires = stored
        .expires_at
        .map_or_else(|| "0001-01-01T00:00:00Z".to_owned(), |t| rfc3339(&t));
    println!(
        "status={state} issuer={} audience={} expires={expires}",
        stored.issuer, stored.audience
    );
    Ok(())
}

/// `auth logout`.
pub fn logout() -> Result<()> {
    Ok(runeward_credentials::delete()?)
}

/// Go's `time.RFC3339` rendering.
fn rfc3339(t: &Time) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

async fn oidc_device_login(
    issuer: &str,
    client_id: &str,
    audience: &str,
    scope: &str,
) -> Result<()> {
    let issuer = issuer.trim().trim_end_matches('/').to_owned();
    require_secure_auth_endpoint(&issuer)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let discovery: DeviceDiscovery =
        fetch(client.get(format!("{issuer}/.well-known/openid-configuration"))).await?;
    if discovery.device_authorization_endpoint.is_empty() || discovery.token_endpoint.is_empty() {
        bail!("OIDC provider does not support device authorization");
    }
    require_secure_auth_endpoint(&discovery.device_authorization_endpoint)
        .map_err(|e| anyhow!("device authorization endpoint: {e}"))?;
    require_secure_auth_endpoint(&discovery.token_endpoint)
        .map_err(|e| anyhow!("token endpoint: {e}"))?;
    let mut form = vec![("client_id", client_id), ("scope", scope)];
    if !audience.is_empty() {
        form.push(("audience", audience));
    }
    let device: DeviceAuthorization = fetch(
        client
            .post(&discovery.device_authorization_endpoint)
            .form(&form),
    )
    .await?;
    let verification = first_set(&[&device.verification_uri_complete, &device.verification_uri]);
    println!("Open {verification} and enter code {}", device.user_code);

    let mut interval = Duration::from_secs(u64::try_from(device.interval).unwrap_or(0).max(5));
    let deadline =
        Instant::now() + Duration::from_secs(u64::try_from(device.expires_in).unwrap_or(0));
    while Instant::now() < deadline {
        tokio::time::sleep(interval).await;
        let token: DeviceToken = fetch(client.post(&discovery.token_endpoint).form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", device.device_code.as_str()),
            ("client_id", client_id),
        ]))
        .await?;
        match token.error.as_str() {
            "authorization_pending" => continue,
            "slow_down" => {
                interval += Duration::from_secs(5);
                continue;
            }
            "" => {}
            other => bail!("OIDC device flow: {other}"),
        }
        // The access token targets the API audience; an ID token usually
        // targets the CLI client id, so it is only a fallback.
        let credential = first_set(&[&token.access_token, &token.id_token]);
        if credential.is_empty() {
            bail!("OIDC provider returned no usable token");
        }
        let expires = token_expiry(&credential).unwrap_or_else(|| {
            let at = Utc::now() + chrono::Duration::seconds(token.expires_in);
            at.fixed_offset()
        });
        runeward_credentials::save(Login {
            token: credential,
            issuer: issuer.clone(),
            client_id: client_id.to_owned(),
            audience: audience.to_owned(),
            expires_at: Some(expires),
        })?;
        println!("Runeward login saved.");
        return Ok(());
    }
    bail!("OIDC device authorization expired")
}

fn first_set(values: &[&str]) -> String {
    values
        .iter()
        .find(|v| !v.trim().is_empty())
        .map(|v| (*v).to_owned())
        .unwrap_or_default()
}

/// Authentication endpoints must use HTTPS, except loopback development.
pub fn require_secure_auth_endpoint(raw: &str) -> Result<()> {
    let u = url::Url::parse(raw)
        .ok()
        .filter(|u| u.host_str().is_some_and(|h| !h.is_empty()))
        .ok_or_else(|| {
            anyhow!(
                "invalid authentication endpoint {}",
                crate::common::go_quote(raw)
            )
        })?;
    let host = u
        .host_str()
        .unwrap_or_default()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase();
    let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
    if u.scheme() == "https" || (u.scheme() == "http" && loopback) {
        return Ok(());
    }
    bail!("authentication endpoints must use HTTPS (HTTP is allowed only for loopback development)")
}

async fn fetch<T: DeserializeOwned + Default + AuthBody>(
    req: reqwest::RequestBuilder,
) -> Result<T> {
    let resp = req.send().await?;
    let status = resp.status().as_u16();
    let mut data = Vec::new();
    let body = resp.bytes().await?;
    data.extend_from_slice(&body[..body.len().min(2 << 20)]);
    decode_auth_response(status, &data)
}

/// Decodes an OIDC endpoint response. A non-2xx status is an error unless
/// the body is a protocol error the device-flow loop handles (RFC 8628
/// `authorization_pending` and `slow_down`).
pub fn decode_auth_response<T: DeserializeOwned + AuthBody>(status: u16, data: &[u8]) -> Result<T> {
    let ok = status / 100 == 2;
    let out: T = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(e) if ok => return Err(e.into()),
        Err(_) => bail!("OIDC endpoint returned HTTP {status}"),
    };
    if !ok && !out.is_protocol_error() {
        bail!("OIDC endpoint returned HTTP {status}");
    }
    Ok(out)
}

/// The `exp` claim of a JWT, if present and positive.
pub fn token_expiry(token: &str) -> Option<Time> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    #[derive(Deserialize)]
    struct Claims {
        #[serde(default)]
        exp: i64,
    }
    let claims: Claims = serde_json::from_slice(&payload).ok()?;
    if claims.exp <= 0 {
        return None;
    }
    Utc.timestamp_opt(claims.exp, 0)
        .single()
        .map(|t| t.fixed_offset())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn device_flow_json_error_is_returned_to_polling_loop() {
        let token: DeviceToken =
            decode_auth_response(400, br#"{"error":"authorization_pending"}"#).unwrap();
        assert_eq!(token.error, "authorization_pending");
        let err = decode_auth_response::<DeviceDiscovery>(400, br#"{"error":"x"}"#).unwrap_err();
        assert_eq!(err.to_string(), "OIDC endpoint returned HTTP 400");
        let err = decode_auth_response::<DeviceToken>(502, b"<html>").unwrap_err();
        assert_eq!(err.to_string(), "OIDC endpoint returned HTTP 502");
    }

    #[test]
    fn auth_endpoint_requires_tls_outside_loopback() {
        assert!(require_secure_auth_endpoint("http://issuer.example").is_err());
        require_secure_auth_endpoint("http://127.0.0.1:9090").unwrap();
        require_secure_auth_endpoint("http://[::1]:9090").unwrap();
        require_secure_auth_endpoint("https://issuer.example").unwrap();
        assert!(require_secure_auth_endpoint("not a url").is_err());
    }

    #[test]
    fn token_expiry_reads_the_exp_claim() {
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let jwt = format!("{}.{}.sig", b64("{}"), b64(r#"{"exp":1700000000}"#));
        assert_eq!(
            rfc3339(&token_expiry(&jwt).unwrap()),
            "2023-11-14T22:13:20Z"
        );
        assert!(token_expiry("opaque").is_none());
        let none = format!("{}.{}.sig", b64("{}"), b64(r#"{"sub":"x"}"#));
        assert!(token_expiry(&none).is_none());
    }
}
