//! Shared HTTP helpers for the network-backed resolvers.

use std::error::Error as StdError;
use std::time::Duration;

use serde::de::DeserializeOwned;

/// Bounds a single backend call so a hung server can't block sandbox creation
/// indefinitely.
pub(crate) const BACKEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds the default client used when a resolver has none configured.
pub(crate) fn default_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder().timeout(BACKEND_TIMEOUT).build()
}

/// Returns `client` or a freshly built default client.
pub(crate) fn client_or_default(
    client: Option<&reqwest::Client>,
) -> Result<reqwest::Client, reqwest::Error> {
    match client {
        Some(c) => Ok(c.clone()),
        None => default_client(),
    }
}

/// Formats an error with its full source chain, `outer: inner: ...`.
pub(crate) fn chain(err: &dyn StdError) -> String {
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

/// Reads at most `limit` bytes of the response body, ignoring read errors
/// (the body is only used for diagnostics).
pub(crate) async fn read_limited(resp: &mut reqwest::Response, limit: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    while buf.len() < limit {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(limit - buf.len());
                buf.extend_from_slice(&chunk[..take]);
            }
            _ => break,
        }
    }
    buf
}

/// Decodes the first JSON value in `bytes`, ignoring anything after it, as
/// Go's `json.Decoder.Decode` does.
pub(crate) fn decode_first<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    match serde_json::Deserializer::from_slice(bytes)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) => Err(e.to_string()),
        None => Err("EOF".to_owned()),
    }
}

/// Reads the whole response body and decodes its first JSON value.
pub(crate) async fn decode_body<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, String> {
    let bytes = resp.bytes().await.map_err(|e| chain(&e))?;
    decode_first(&bytes)
}
