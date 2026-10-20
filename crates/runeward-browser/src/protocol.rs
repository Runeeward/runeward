//! The wire contract between the control plane and the in-sandbox driver.
//! Each driver connection carries exactly one [`Command`] and one
//! [`CommandResult`], as JSON identical to the Go `browser.Command` and
//! `browser.Result` (encode with [`Command::to_json`] /
//! [`CommandResult::to_json`] to also get Go's HTML-safe escaping).

use runeward_ledger::gojson;
use serde::{Deserialize, Deserializer, Serialize};

fn nullable<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// A single browser action requested over the driver's control socket.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Command {
    /// The operation: `navigate`, `eval`, `text`, `html`, `screenshot`,
    /// `click`, `type`, `wait`, `title`, `url`, `close` or `ping`.
    #[serde(default, deserialize_with = "nullable")]
    pub action: String,
    /// The driver's shared control secret.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub token: String,
    /// Target for `navigate`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub url: String,
    /// CSS selector for `click`, `type` and `wait`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub selector: String,
    /// JavaScript source for `eval`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub expr: String,
    /// Text to enter for `type`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub text: String,
    /// Timeout in milliseconds; 0 means the driver default.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_zero"
    )]
    pub timeout_ms: i64,
}

/// The driver's reply to a [`Command`] (Go's `browser.Result`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CommandResult {
    /// Whether the action succeeded.
    #[serde(default, deserialize_with = "nullable")]
    pub ok: bool,
    /// The failure message.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub error: String,
    /// The textual payload (eval result, text, html, title, url).
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub value: String,
    /// A base64 PNG for `screenshot`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub screenshot: String,
}

impl CommandResult {
    /// A successful result with no payload.
    pub fn ok() -> Self {
        Self {
            ok: true,
            ..Self::default()
        }
    }

    /// A failed result carrying `msg`.
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            error: msg.into(),
            ..Self::default()
        }
    }

    /// A successful result carrying `value`.
    pub fn value(value: impl Into<String>) -> Self {
        Self {
            ok: true,
            value: value.into(),
            ..Self::default()
        }
    }

    /// The JSON Go's `json.Marshal` writes for this result.
    pub fn to_json(&self) -> Vec<u8> {
        marshal(self)
    }
}

impl Command {
    /// A command with just an action.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            ..Self::default()
        }
    }

    /// The JSON Go's `json.Marshal` writes for this command.
    pub fn to_json(&self) -> Vec<u8> {
        marshal(self)
    }
}

fn marshal<T: Serialize>(v: &T) -> Vec<u8> {
    // Plain structs of strings, a bool and an integer always encode.
    gojson::marshal(v).unwrap_or_default()
}

/// Decodes one wire value like Go's `json.Unmarshal` into a struct: the
/// value must be a JSON object (or `null`, which yields the default).
pub(crate) fn decode_object<T>(v: serde_json::Value) -> Result<T, serde_json::Error>
where
    T: for<'de> Deserialize<'de> + Default,
{
    match v {
        serde_json::Value::Null => Ok(T::default()),
        serde_json::Value::Object(_) => serde_json::from_value(v),
        other => Err(<serde_json::Error as serde::de::Error>::custom(format!(
            "cannot unmarshal {} into a JSON object",
            match other {
                serde_json::Value::Array(_) => "array",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Number(_) => "number",
                _ => "bool",
            }
        ))),
    }
}

/// Decodes a complete JSON document into `T` with [`decode_object`] rules.
pub fn decode<T>(data: &[u8]) -> Result<T, serde_json::Error>
where
    T: for<'de> Deserialize<'de> + Default,
{
    decode_object(serde_json::from_slice(data)?)
}
