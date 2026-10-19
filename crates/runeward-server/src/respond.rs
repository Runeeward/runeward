//! JSON responses, error bodies and request decoding with Go's semantics.

use axum::body::{Body, to_bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use runeward_controlplane::refusal::{Refusal, RefusalReason};
use runeward_controlplane::{Error, ToolResult};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Caps every request body the control plane reads (16 MiB), so a peer
/// cannot exhaust memory by streaming an unbounded body.
pub(crate) const MAX_REQUEST_BODY_BYTES: usize = 16 << 20;

/// Go's `writeJSON`: `application/json`, HTML-escaped like `encoding/json`
/// and terminated by a newline.
pub(crate) fn json<T: Serialize + ?Sized>(status: StatusCode, v: &T) -> Response {
    let mut body = match runeward_ledger::gojson::marshal(v) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "encode JSON response");
            return internal_error_with_id();
        }
    };
    body.push(b'\n');
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Go's `writeError`: `{"error": msg, "code": <class>}`, plus the
/// standard `refusal` object when the status says nothing ran.
pub(crate) fn error(status: StatusCode, msg: impl AsRef<str>) -> Response {
    let refusal =
        RefusalReason::from_http_status(status.as_u16()).map(|r| Refusal::new(r, msg.as_ref()));
    error_with(status, msg, refusal.as_ref())
}

/// [`error`] with an explicit refusal (or none).
fn error_with(status: StatusCode, msg: impl AsRef<str>, refusal: Option<&Refusal>) -> Response {
    let mut body = json!({"error": msg.as_ref(), "code": error_code(status)});
    if let Some(r) = refusal {
        r.attach(&mut body);
    }
    json(status, &body)
}

/// A governed result: refused ones (deny, pending approval) carry the
/// standard `refusal` object.
pub(crate) fn tool_json(status: StatusCode, res: &ToolResult) -> Response {
    let Some(refusal) = Refusal::for_result(res) else {
        return json(status, res);
    };
    let mut body = serde_json::to_value(res).unwrap_or(Value::Null);
    refusal.attach(&mut body);
    json(status, &body)
}

/// The machine-readable class for an error status.
pub(crate) fn error_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "authentication_required",
        StatusCode::FORBIDDEN => "authz_denied",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::BAD_REQUEST | StatusCode::METHOD_NOT_ALLOWED => "invalid_request",
        _ => "internal_error",
    }
}

/// Go's `writeServerError`: caller-actionable errors become 4xx with their
/// message; anything else is an opaque 500 with a correlation id that is
/// logged next to the real error.
pub(crate) fn server_error(err: &Error) -> Response {
    let msg = err.to_string();
    if let Some(code) = err.client_status()
        && let Ok(status) = StatusCode::from_u16(code)
    {
        return error_with(status, &msg, Refusal::for_error(err, &msg).as_ref());
    }
    let id = new_request_id();
    tracing::error!(request_id = %id, error = %err, "internal error serving request");
    match Refusal::for_error(err, refusal_message(err)) {
        Some(r) => internal_refusal(&id, &r),
        None => internal_error(&id),
    }
}

/// A caller-safe summary for refusals behind an opaque 500.
fn refusal_message(err: &Error) -> &'static str {
    match err {
        Error::IsolationFloor { .. } => {
            "the sandbox could not provide the Charter's isolation floor and was torn down before anything ran"
        }
        _ => "the call was refused before it ran",
    }
}

fn internal_error(id: &str) -> Response {
    json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({"error": "internal server error", "code": "internal_error", "request_id": id}),
    )
}

/// An opaque 500 for an error that nonetheless proves nothing ran (an
/// isolation floor refusal): the detail stays in the log, the body says
/// why in refusal terms.
fn internal_refusal(id: &str, refusal: &Refusal) -> Response {
    let mut body =
        json!({"error": "internal server error", "code": "internal_error", "request_id": id});
    refusal.clone().with_request_id(id).attach(&mut body);
    json(StatusCode::INTERNAL_SERVER_ERROR, &body)
}

fn internal_error_with_id() -> Response {
    let id = new_request_id();
    let body = format!(
        "{{\"code\":\"internal_error\",\"error\":\"internal server error\",\"request_id\":\"{id}\"}}\n"
    );
    let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// The current request's id (`X-Request-Id`), else a short random hex id,
/// correlating a client-visible error with a log line.
pub(crate) fn new_request_id() -> String {
    runeward_controlplane::refusal::current_request_id()
        .unwrap_or_else(runeward_controlplane::refusal::new_request_id)
}

/// Go's `http.NotFound`.
pub(crate) fn not_found_text() -> Response {
    text(StatusCode::NOT_FOUND, "404 page not found\n")
}

/// A `text/plain` body, as Go's `http.Error` writes.
pub(crate) fn text(status: StatusCode, body: &'static str) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// Why a request body could not be decoded. The message is safe to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeError(pub(crate) String);

impl DecodeError {
    /// Go's `io.EOF`: the body was empty. Some endpoints accept that.
    pub(crate) fn is_eof(&self) -> bool {
        self.0 == "EOF"
    }

    pub(crate) fn into_response(self) -> Response {
        error(StatusCode::BAD_REQUEST, self.0)
    }
}

/// Reads at most [`MAX_REQUEST_BODY_BYTES`] of a body.
pub(crate) async fn read_body(body: Body) -> Result<bytes::Bytes, DecodeError> {
    to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| DecodeError("http: request body too large".into()))
}

/// Go's `decodeJSON`: decodes the first JSON value of the body into `T`
/// (whose fields should deny unknown keys). An empty body is `EOF`; a JSON
/// `null`, or `null` members, leave the zero value like Go's decoder.
pub(crate) async fn decode<T: DeserializeOwned + Default>(body: Body) -> Result<T, DecodeError> {
    let bytes = read_body(body).await?;
    decode_bytes(&bytes)
}

/// [`decode`] over an in-memory body.
pub(crate) fn decode_bytes<T: DeserializeOwned + Default>(bytes: &[u8]) -> Result<T, DecodeError> {
    let value = first_value(bytes)?;
    let value = match value {
        Value::Null => return Ok(T::default()),
        Value::Object(mut m) => {
            m.retain(|_, v| !v.is_null());
            Value::Object(m)
        }
        v => v,
    };
    serde_json::from_value(value).map_err(|e| DecodeError(go_decode_message(&e.to_string())))
}

/// Rewrites serde's unknown-field error the way Go's decoder words it.
fn go_decode_message(msg: &str) -> String {
    if let Some(rest) = msg.strip_prefix("unknown field `")
        && let Some((field, _)) = rest.split_once('`')
    {
        return format!("json: unknown field \"{field}\"");
    }
    format!("json: {msg}")
}

/// [`decode`] that treats an empty body as the zero value (the Go handlers
/// that ignore `io.EOF`).
pub(crate) async fn decode_optional<T: DeserializeOwned + Default>(
    body: Body,
) -> Result<T, DecodeError> {
    match decode(body).await {
        Err(e) if e.is_eof() => Ok(T::default()),
        r => r,
    }
}

fn first_value(bytes: &[u8]) -> Result<Value, DecodeError> {
    match serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .next()
    {
        None => Err(DecodeError("EOF".into())),
        Some(Ok(v)) => Ok(v),
        Some(Err(e)) if e.is_eof() => Err(DecodeError("unexpected EOF".into())),
        Some(Err(e)) => Err(DecodeError(format!("json: {e}"))),
    }
}

/// Rejects object keys outside `known`, as Go's `DisallowUnknownFields`
/// does for types this crate does not own.
pub(crate) fn reject_unknown_fields(bytes: &[u8], known: &[&str]) -> Result<(), DecodeError> {
    if let Ok(Value::Object(m)) = first_value(bytes) {
        for k in m.keys() {
            if !known.contains(&k.as_str()) {
                return Err(DecodeError(format!("json: unknown field \"{k}\"")));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(default, deny_unknown_fields)]
    struct Req {
        name: String,
        n: i64,
    }

    #[test]
    fn decoding_follows_go() {
        assert_eq!(
            decode_bytes::<Req>(b"").expect_err("empty"),
            DecodeError("EOF".into())
        );
        assert_eq!(
            decode_bytes::<Req>(b"  \n").expect_err("blank"),
            DecodeError("EOF".into())
        );
        assert_eq!(
            decode_bytes::<Req>(br#"{"name":"a"} trailing"#).expect("first value"),
            Req {
                name: "a".into(),
                n: 0
            }
        );
        assert_eq!(
            decode_bytes::<Req>(br#"{"name":null}"#).expect("null member"),
            Req::default()
        );
        assert_eq!(decode_bytes::<Req>(b"null").expect("null"), Req::default());
        let err = decode_bytes::<Req>(br#"{"bogus":1}"#).expect_err("unknown");
        assert_eq!(err.0, r#"json: unknown field "bogus""#);
        assert!(decode_bytes::<Req>(br#"{"name":"#).is_err());
        assert_eq!(error_code(StatusCode::BAD_GATEWAY), "internal_error");
        assert_eq!(
            error_code(StatusCode::METHOD_NOT_ALLOWED),
            "invalid_request"
        );
    }
}
