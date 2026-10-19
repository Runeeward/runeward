//! A minimal Chrome DevTools Protocol client for one page-level DevTools
//! WebSocket.
//!
//! Calls are matched to responses by id; unsolicited events go to one-shot
//! subscribers. A background task demultiplexes the socket. The client is
//! meant for sequential use by one caller (the driver serializes actions).

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{Sink, SinkExt, StreamExt};
use runeward_ledger::gojson;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::util::{go_duration, go_quote};

/// How long a CDP call waits for its response unless overridden.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Set to `1`, `true`, `yes` or `on` to allow navigating to loopback,
/// private and link-local addresses.
pub const ENV_ALLOW_PRIVATE_ADDRS: &str = "RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS";

/// How often [`Client::wait_selector`] polls.
const WAIT_POLL: Duration = Duration::from_millis(100);

/// A CDP client failure. Messages match the Go client.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CdpError {
    /// The WebSocket could not be opened.
    #[error("cdp dial {url}: {reason}")]
    Dial {
        /// The DevTools URL.
        url: String,
        /// Why the dial failed.
        reason: String,
    },
    /// The connection is closed; carries the read error when there was one.
    #[error("cdp connection closed{}", .0.as_ref().map(|e| format!(": {e}")).unwrap_or_default())]
    Closed(Option<String>),
    /// Sending a request failed.
    #[error("cdp {method}: write: {reason}")]
    Write {
        /// The CDP method.
        method: String,
        /// Why the write failed.
        reason: String,
    },
    /// The browser answered with a protocol error.
    #[error("cdp {method}: {message} (code {code})")]
    Remote {
        /// The CDP method.
        method: String,
        /// The browser's message.
        message: String,
        /// The browser's error code.
        code: i64,
    },
    /// No response arrived in time.
    #[error("cdp {method}: timeout after {}", go_duration(*.after))]
    Timeout {
        /// The CDP method.
        method: String,
        /// The call timeout that expired.
        after: Duration,
    },
    /// A response could not be decoded.
    #[error("cdp {method}: decode: {reason}")]
    Decode {
        /// The CDP method.
        method: String,
        /// Why decoding failed.
        reason: String,
    },
    /// The evaluated script threw.
    #[error("eval exception: {0}")]
    EvalException(String),
    /// Anything else, already formatted (navigation policy, missing
    /// elements, wait timeouts, value decoding).
    #[error("{0}")]
    Other(String),
}

/// The CDP envelope for responses and events.
#[derive(Debug, Deserialize)]
struct CdpMessage {
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    result: Option<Box<RawValue>>,
    #[serde(default)]
    error: Option<RemoteError>,
}

#[derive(Debug, Deserialize)]
struct RemoteError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// The `Runtime.evaluate` result payload.
#[derive(Debug, Deserialize)]
struct EvalResponse {
    #[serde(default)]
    result: EvalResult,
    #[serde(default, rename = "exceptionDetails")]
    exception_details: Option<ExceptionDetails>,
}

#[derive(Debug, Default, Deserialize)]
struct EvalResult {
    #[serde(default, rename = "type")]
    typ: Option<String>,
    /// Kept raw; JSON `null` is kept as the text `null`, as Go's
    /// `json.RawMessage` does.
    #[serde(default, deserialize_with = "raw_keep_null")]
    value: Option<Box<RawValue>>,
}

fn raw_keep_null<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Box<RawValue>>, D::Error> {
    Box::<RawValue>::deserialize(d).map(Some)
}

#[derive(Debug, Default, Deserialize)]
struct ExceptionDetails {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    exception: Option<ExceptionObject>,
}

#[derive(Debug, Default, Deserialize)]
struct ExceptionObject {
    #[serde(default)]
    description: Option<String>,
}

type WsSink = Pin<Box<dyn Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Send>>;

#[derive(Default)]
struct State {
    next_id: i64,
    pending: HashMap<i64, oneshot::Sender<CdpMessage>>,
    subs: HashMap<String, Vec<oneshot::Sender<()>>>,
    closed: bool,
    err: Option<String>,
}

struct Shared {
    state: Mutex<State>,
    /// Becomes true when the read loop exits.
    done: watch::Sender<bool>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records the terminal read error and wakes every waiting caller.
    fn fail(&self, err: Option<String>) {
        let mut s = self.lock();
        if !s.closed {
            s.closed = true;
            s.err = err;
            s.pending.clear();
            s.subs.clear();
            self.done.send_replace(true);
        }
    }

    fn closed_err(&self) -> CdpError {
        CdpError::Closed(self.lock().err.clone())
    }
}

/// A CDP client for one page-level DevTools WebSocket.
pub struct Client {
    shared: Arc<Shared>,
    sink: tokio::sync::Mutex<WsSink>,
    reader: JoinHandle<()>,
    call_timeout: Duration,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("call_timeout", &self.call_timeout)
            .field("closed", &self.shared.lock().closed)
            .finish_non_exhaustive()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl Client {
    /// Connects to a page-level DevTools WebSocket URL.
    pub async fn dial(ws_url: &str) -> Result<Self, CdpError> {
        // No message size limit, like the Go client; the peer is the local
        // browser.
        let config = WebSocketConfig::default()
            .max_message_size(None)
            .max_frame_size(None);
        let (ws, _) = tokio_tungstenite::connect_async_with_config(ws_url, Some(config), true)
            .await
            .map_err(|e| CdpError::Dial {
                url: ws_url.to_owned(),
                reason: e.to_string(),
            })?;
        Ok(Self::new(ws))
    }

    /// Wraps an already-connected DevTools WebSocket and starts its read
    /// loop. Must be called within a Tokio runtime.
    pub fn new<S>(ws: WebSocketStream<S>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sink, mut stream) = ws.split();
        let (done, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                next_id: 1,
                ..State::default()
            }),
            done,
        });
        let reader_shared = Arc::clone(&shared);
        let reader = tokio::spawn(async move {
            let shared = reader_shared;
            loop {
                let data = match stream.next().await {
                    Some(Ok(Message::Text(t))) => t.as_bytes().to_vec(),
                    Some(Ok(Message::Binary(b))) => b.to_vec(),
                    Some(Ok(Message::Close(_))) | None => {
                        shared.fail(Some("websocket: close".to_owned()));
                        return;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => {
                        shared.fail(Some(e.to_string()));
                        return;
                    }
                };
                let Ok(msg) = serde_json::from_slice::<CdpMessage>(&data) else {
                    continue;
                };
                match (msg.id, msg.method.as_deref()) {
                    (Some(id), _) if id != 0 => {
                        let tx = shared.lock().pending.remove(&id);
                        if let Some(tx) = tx {
                            let _ = tx.send(msg);
                        }
                    }
                    (_, Some(method)) if !method.is_empty() => {
                        // One-shot: deliver to and clear every subscriber.
                        let subs = shared.lock().subs.remove(method);
                        for tx in subs.into_iter().flatten() {
                            let _ = tx.send(());
                        }
                    }
                    _ => {}
                }
            }
        });
        Self {
            shared,
            sink: tokio::sync::Mutex::new(Box::pin(sink)),
            reader,
            call_timeout: DEFAULT_CALL_TIMEOUT,
        }
    }

    /// Overrides [`DEFAULT_CALL_TIMEOUT`]; zero restores the default.
    pub fn set_call_timeout(&mut self, timeout: Duration) {
        self.call_timeout = if timeout.is_zero() {
            DEFAULT_CALL_TIMEOUT
        } else {
            timeout
        };
    }

    /// Closes the connection and stops the read loop.
    pub async fn close(&self) {
        let _ = self.sink.lock().await.close().await;
        self.reader.abort();
        self.shared.fail(None);
    }

    async fn wait_done(&self) {
        let mut rx = self.shared.done.subscribe();
        let _ = rx.wait_for(|d| *d).await;
    }

    /// Sends a CDP method and waits for its response.
    async fn call(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> Result<Option<Box<RawValue>>, CdpError> {
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut s = self.shared.lock();
            if s.closed {
                return Err(CdpError::Closed(s.err.clone()));
            }
            let id = s.next_id;
            s.next_id += 1;
            s.pending.insert(id, tx);
            id
        };
        let mut env = json!({ "id": id, "method": method });
        if let Some(p) = params {
            env["params"] = p;
        }
        let body = gojson::marshal(&env).unwrap_or_default();
        let text = String::from_utf8(body).unwrap_or_default();
        let sent = self.sink.lock().await.send(Message::text(text)).await;
        if let Err(e) = sent {
            self.shared.lock().pending.remove(&id);
            return Err(CdpError::Write {
                method: method.to_owned(),
                reason: e.to_string(),
            });
        }

        let timeout = self.call_timeout;
        tokio::select! {
            msg = rx => match msg {
                Ok(msg) => match msg.error {
                    Some(e) => Err(CdpError::Remote { method: method.to_owned(), message: e.message, code: e.code }),
                    None => Ok(msg.result),
                },
                Err(_) => Err(self.shared.closed_err()),
            },
            () = self.wait_done() => {
                self.shared.lock().pending.remove(&id);
                Err(self.shared.closed_err())
            }
            () = tokio::time::sleep(timeout) => {
                self.shared.lock().pending.remove(&id);
                Err(CdpError::Timeout { method: method.to_owned(), after: timeout })
            }
        }
    }

    /// Registers a one-shot listener for the next occurrence of `method`.
    fn subscribe(&self, method: &str) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.shared
            .lock()
            .subs
            .entry(method.to_owned())
            .or_default()
            .push(tx);
        rx
    }

    /// Drops subscribers whose receivers are gone.
    fn prune_subs(&self, method: &str) {
        let mut s = self.shared.lock();
        if let Some(subs) = s.subs.get_mut(method) {
            subs.retain(|tx| !tx.is_closed());
            if subs.is_empty() {
                s.subs.remove(method);
            }
        }
    }

    /// Enables the Page domain, navigates to `url` and waits up to `timeout`
    /// (zero means the default) for `Page.loadEventFired`. A load-wait
    /// timeout is not an error: the page is often usable anyway.
    pub async fn navigate(&self, url: &str, timeout: Duration) -> Result<(), CdpError> {
        validate_navigate_url(url)?;
        self.call("Page.enable", None).await?;
        // Subscribe before navigating so the event cannot be missed.
        let load = self.subscribe("Page.loadEventFired");
        let res = self.navigate_and_wait(url, timeout, load).await;
        self.prune_subs("Page.loadEventFired");
        res
    }

    async fn navigate_and_wait(
        &self,
        url: &str,
        timeout: Duration,
        load: oneshot::Receiver<()>,
    ) -> Result<(), CdpError> {
        self.call("Page.navigate", Some(json!({ "url": url })))
            .await?;
        let timeout = if timeout.is_zero() {
            DEFAULT_CALL_TIMEOUT
        } else {
            timeout
        };
        tokio::select! {
            r = load => {
                if r.is_err() {
                    return Err(self.shared.closed_err());
                }
            }
            () = self.wait_done() => return Err(self.shared.closed_err()),
            () = tokio::time::sleep(timeout) => {}
        }
        Ok(())
    }

    /// Runs `expr` with `Runtime.evaluate` (awaiting promises) and returns
    /// the value as a string: strings verbatim, other values as their JSON.
    pub async fn eval(&self, expr: &str) -> Result<String, CdpError> {
        let raw = self
            .call(
                "Runtime.evaluate",
                Some(json!({
                    "expression": expr,
                    "returnByValue": true,
                    "awaitPromise": true,
                })),
            )
            .await?;
        let decode_err = |reason: String| CdpError::Decode {
            method: "Runtime.evaluate".to_owned(),
            reason,
        };
        let raw = raw.ok_or_else(|| decode_err("unexpected end of JSON input".to_owned()))?;
        let r: Option<EvalResponse> =
            serde_json::from_str(raw.get()).map_err(|e| decode_err(e.to_string()))?;
        let r = r.unwrap_or(EvalResponse {
            result: EvalResult::default(),
            exception_details: None,
        });
        if let Some(ex) = r.exception_details {
            let mut msg = ex.exception.and_then(|e| e.description).unwrap_or_default();
            if msg.is_empty() {
                msg = ex.text.unwrap_or_default();
            }
            return Err(CdpError::EvalException(msg));
        }
        stringify_value(
            r.result.typ.as_deref().unwrap_or_default(),
            r.result.value.as_deref(),
        )
    }

    /// `document.body.innerText`, or `""` when there is no body.
    pub async fn text(&self) -> Result<String, CdpError> {
        self.eval("document.body ? document.body.innerText : ''")
            .await
    }

    /// The full serialized document.
    pub async fn html(&self) -> Result<String, CdpError> {
        self.eval("document.documentElement.outerHTML").await
    }

    /// `document.title`.
    pub async fn title(&self) -> Result<String, CdpError> {
        self.eval("document.title").await
    }

    /// The current `location.href`.
    pub async fn url(&self) -> Result<String, CdpError> {
        self.eval("location.href").await
    }

    /// Captures the viewport as a base64-encoded PNG.
    pub async fn screenshot(&self) -> Result<String, CdpError> {
        #[derive(Deserialize)]
        struct Shot {
            #[serde(default)]
            data: Option<String>,
        }
        let raw = self
            .call("Page.captureScreenshot", Some(json!({ "format": "png" })))
            .await?;
        let decode_err = |reason: String| CdpError::Decode {
            method: "Page.captureScreenshot".to_owned(),
            reason,
        };
        let raw = raw.ok_or_else(|| decode_err("unexpected end of JSON input".to_owned()))?;
        let shot: Option<Shot> =
            serde_json::from_str(raw.get()).map_err(|e| decode_err(e.to_string()))?;
        Ok(shot.and_then(|s| s.data).unwrap_or_default())
    }

    /// Finds `selector`, scrolls it into view and clicks it, through
    /// `Runtime.evaluate` (no DOM or Input domain needed).
    pub async fn click(&self, selector: &str) -> Result<(), CdpError> {
        let sel = js_string(selector);
        let expr = format!(
            "(function(){{var el=document.querySelector({sel});\
             if(!el){{return false;}}el.scrollIntoView({{block:'center'}});el.click();return true;}})()"
        );
        if !self.eval_bool(&expr).await? {
            return Err(CdpError::Other(format!(
                "click: no element matches {}",
                go_quote(selector)
            )));
        }
        Ok(())
    }

    /// Focuses `selector`, sets its value (or text) and dispatches `input`
    /// and `change` events so frameworks see the change.
    pub async fn type_text(&self, selector: &str, text: &str) -> Result<(), CdpError> {
        let sel = js_string(selector);
        let val = js_string(text);
        let expr = format!(
            "(function(){{var el=document.querySelector({sel});if(!el){{return false;}}\
             el.focus();if('value' in el){{el.value={val};}}else{{el.textContent={val};}}\
             el.dispatchEvent(new Event('input',{{bubbles:true}}));\
             el.dispatchEvent(new Event('change',{{bubbles:true}}));return true;}})()"
        );
        if !self.eval_bool(&expr).await? {
            return Err(CdpError::Other(format!(
                "type: no element matches {}",
                go_quote(selector)
            )));
        }
        Ok(())
    }

    /// Polls until an element matches `selector` or `timeout` (zero means
    /// the default) elapses.
    pub async fn wait_selector(&self, selector: &str, timeout: Duration) -> Result<(), CdpError> {
        let expr = format!("!!document.querySelector({})", js_string(selector));
        let timeout = if timeout.is_zero() {
            DEFAULT_CALL_TIMEOUT
        } else {
            timeout
        };
        let deadline = Instant::now() + timeout;
        loop {
            if self.eval_bool(&expr).await? {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(CdpError::Other(format!(
                    "wait: selector {} not found within {}",
                    go_quote(selector),
                    go_duration(timeout)
                )));
            }
            tokio::time::sleep(WAIT_POLL).await;
        }
    }

    async fn eval_bool(&self, expr: &str) -> Result<bool, CdpError> {
        Ok(self.eval(expr).await? == "true")
    }
}

/// Renders a `Runtime.evaluate` value: `undefined` or a missing value is
/// `""`, a string is returned verbatim, anything else as its raw JSON.
pub fn stringify_value(typ: &str, value: Option<&RawValue>) -> Result<String, CdpError> {
    let Some(value) = value else {
        return Ok(String::new());
    };
    if typ == "undefined" || value.get().is_empty() {
        return Ok(String::new());
    }
    if typ == "string" {
        return serde_json::from_str::<Option<String>>(value.get())
            .map(Option::unwrap_or_default)
            .map_err(|e| CdpError::Other(e.to_string()));
    }
    Ok(value.get().to_owned())
}

/// Encodes s as a JavaScript string literal (via JSON) for embedding in an
/// eval snippet.
fn js_string(s: &str) -> String {
    String::from_utf8(gojson::marshal(s).unwrap_or_default()).unwrap_or_default()
}

/// Enforces safe navigation targets: `about:blank`, or `http`/`https` URLs
/// whose host is not loopback, private or link-local unless
/// `RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS` allows it.
pub fn validate_navigate_url(raw: &str) -> Result<(), CdpError> {
    validate_navigate_url_with(
        raw,
        allow_private_from(env::var(ENV_ALLOW_PRIVATE_ADDRS).ok().as_deref()),
    )
}

/// Reports whether an `RUNEWARD_BROWSER_ALLOW_PRIVATE_ADDRS` value enables
/// private targets.
pub fn allow_private_from(v: Option<&str>) -> bool {
    matches!(
        v.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// [`validate_navigate_url`] with the private-address override given
/// explicitly.
///
/// URLs are parsed with the WHATWG rules browsers use, so numeric host
/// spellings such as `http://2130706433/` or `http://127.1/` are recognised
/// as the loopback addresses the browser would connect to.
pub fn validate_navigate_url_with(raw: &str, allow_private: bool) -> Result<(), CdpError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CdpError::Other("navigate: url is required".to_owned()));
    }
    if raw.eq_ignore_ascii_case("about:blank") {
        return Ok(());
    }
    let u = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            return Err(CdpError::Other(
                "navigate: url scheme \"\" is not allowed".to_owned(),
            ));
        }
        Err(url::ParseError::EmptyHost) => {
            return Err(CdpError::Other("navigate: url host is required".to_owned()));
        }
        Err(e) => return Err(CdpError::Other(format!("navigate: invalid url: {e}"))),
    };
    let scheme = u.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(CdpError::Other(format!(
            "navigate: url scheme {} is not allowed",
            go_quote(scheme)
        )));
    }
    let Some(host) = u.host() else {
        return Err(CdpError::Other("navigate: url host is required".to_owned()));
    };
    if is_private_host(&host) && !allow_private {
        let shown = match &host {
            url::Host::Ipv6(a) => a.to_string(),
            other => other.to_string(),
        };
        return Err(CdpError::Other(format!(
            "navigate: target host {} is blocked",
            go_quote(&shown)
        )));
    }
    Ok(())
}

fn is_private_host(host: &url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(d) => {
            let d = d.trim().to_ascii_lowercase();
            let d = d.trim_end_matches('.');
            d == "localhost" || d.ends_with(".localhost")
        }
        url::Host::Ipv4(a) => is_private_ip(IpAddr::V4(*a)),
        url::Host::Ipv6(a) => is_private_ip(IpAddr::V6(*a)),
    }
}

/// Go's `netip` loopback, private, link-local unicast and link-local
/// multicast checks (IPv4-mapped IPv6 addresses are unmapped first).
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(a) => private_v4(a),
        IpAddr::V6(a) => private_v6(a),
    }
}

fn private_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    a.is_loopback()
        || a.is_private()
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 224 && o[1] == 0 && o[2] == 0)
}

fn private_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    a.is_loopback()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xff0f) == 0xff02
}
