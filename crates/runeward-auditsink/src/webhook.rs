//! A sink that POSTs each event as JSON to a URL from a background worker.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use runeward_ledger::Event;

use crate::queue::{DropCounter, DropQueue, Joiner};
use crate::{Error, Sink};

/// Caps a single POST attempt.
const POST_TIMEOUT: Duration = Duration::from_secs(5);
/// Attempts per event (initial + retries).
const MAX_TRIES: u32 = 3;
/// Delay before the first retry; it doubles each time.
const BASE_BACKOFF: Duration = Duration::from_millis(200);
/// Bounds how long `close` waits to flush the queue.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Configures a webhook sink. Only `url` is required.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    /// One extra header sent with every request, e.g.
    /// `("Authorization", "Bearer <token>")`.
    pub header: Option<(String, String)>,
    /// The HTTP client to use; `None` builds one with a per-request timeout.
    pub client: Option<reqwest::Client>,
    /// Overrides the default bounded queue size (1024) when > 0.
    pub queue_size: usize,
}

impl WebhookConfig {
    /// A config posting to `url` with every other setting at its default.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            header: None,
            client: None,
            queue_size: 0,
        }
    }
}

struct Shared {
    url: String,
    queue: DropQueue<Event>,
    drops: DropCounter,
}

/// POSTs each event as JSON to a URL. A single background worker drains a
/// bounded queue so `emit` never blocks the caller; on overflow the oldest
/// queued event is dropped.
pub struct WebhookSink {
    shared: Arc<Shared>,
    joiner: Joiner<()>,
}

impl std::fmt::Debug for WebhookSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSink")
            .field("url", &self.shared.url)
            .finish_non_exhaustive()
    }
}

impl WebhookSink {
    /// Builds the sink and starts its worker thread.
    pub fn new(cfg: WebhookConfig) -> Self {
        let shared = Arc::new(Shared {
            url: cfg.url,
            queue: DropQueue::new(cfg.queue_size),
            drops: DropCounter::default(),
        });
        let (done, joiner) = Joiner::new();
        let worker = Worker {
            shared: shared.clone(),
            header: cfg.header,
            client: cfg.client,
        };
        let spawned = thread::Builder::new()
            .name("auditsink-webhook".into())
            .spawn(move || {
                worker.run();
                let _ = done.send(());
            });
        if let Err(err) = spawned {
            tracing::warn!(%err, "auditsink: could not start webhook worker; events will be dropped");
        }
        Self { shared, joiner }
    }
}

impl Sink for WebhookSink {
    fn emit(&self, ev: &Event) {
        if self.shared.queue.push(ev.clone())
            && let Some(n) = self.shared.drops.record()
        {
            tracing::warn!(url = %self.shared.url, dropped_total = n,
                "auditsink: webhook queue full, dropping events");
        }
    }

    /// Signals the worker to drain and stop, waiting up to five seconds.
    fn close(&self) -> Result<(), Error> {
        self.shared.queue.close();
        if self.joiner.wait(CLOSE_TIMEOUT).is_err() {
            tracing::warn!(url = %self.shared.url, "auditsink: webhook close timed out flushing queue");
        }
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "webhook"
    }
}

impl Drop for WebhookSink {
    fn drop(&mut self) {
        // Let a worker that was never closed drain and exit on its own.
        self.shared.queue.close();
    }
}

struct Worker {
    shared: Arc<Shared>,
    header: Option<(String, String)>,
    client: Option<reqwest::Client>,
}

impl Worker {
    fn run(self) {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                tracing::warn!(%err, "auditsink: webhook worker runtime failed to start");
                return;
            }
        };
        // Built here, inside the worker's own runtime thread, so a caller
        // running inside an async runtime never owns it.
        let client = match self.client.clone() {
            Some(c) => c,
            None => match reqwest::Client::builder().timeout(POST_TIMEOUT).build() {
                Ok(c) => c,
                Err(err) => {
                    tracing::warn!(%err, "auditsink: webhook client failed to build");
                    return;
                }
            },
        };
        while let Some(ev) = self.shared.queue.pop() {
            self.deliver(&rt, &client, &ev);
        }
    }

    /// POSTs one event with retries and backoff. Failures are logged but
    /// never surface to the producer.
    fn deliver(&self, rt: &tokio::runtime::Runtime, client: &reqwest::Client, ev: &Event) {
        let body = match ev.to_json() {
            Ok(b) => b,
            Err(err) => {
                tracing::warn!(%err, seq = ev.seq, "auditsink: marshal event failed");
                return;
            }
        };
        let mut backoff = BASE_BACKOFF;
        for attempt in 1..=MAX_TRIES {
            if rt.block_on(self.post(client, body.clone())) {
                return;
            }
            if attempt < MAX_TRIES {
                if self.shared.queue.wait_closed(backoff) {
                    return;
                }
                backoff *= 2;
            }
        }
        tracing::warn!(url = %self.shared.url, seq = ev.seq, tries = MAX_TRIES,
            "auditsink: webhook delivery failed after retries");
    }

    /// One POST attempt; true on a 2xx response.
    async fn post(&self, client: &reqwest::Client, body: Vec<u8>) -> bool {
        let mut req = client
            .post(&self.shared.url)
            .timeout(POST_TIMEOUT)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some((k, v)) = &self.header {
            req = req.header(k.as_str(), v.as_str());
        }
        match req.send().await {
            Ok(resp) => {
                let ok = resp.status().is_success();
                // Drain the body so the connection can be reused.
                let _ = resp.bytes().await;
                ok
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Instant;

    use super::*;

    /// Go's test allows 2s for 100k emits. A blocking emit would instead wait
    /// on the hung endpoint (held for 60s), so a looser bound keeps the test
    /// meaningful while tolerating heavily loaded CI hosts.
    const EMIT_BUDGET: Duration = Duration::from_secs(15);
    use crate::testhttp::{Request, Server};
    use crate::testutil::sample_event;

    #[test]
    fn webhook_sink_delivers_event() {
        let (tx, rx) = mpsc::channel::<Request>();
        let srv = Server::start(move |r| {
            let _ = tx.send(r);
            200
        });
        let mut cfg = WebhookConfig::new(srv.url("/hook"));
        cfg.header = Some(("Authorization".into(), "Bearer secret-token".into()));
        let s = WebhookSink::new(cfg);

        let want = sample_event();
        s.emit(&want);

        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("webhook server got no event");
        let got: Event = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(got.seq, want.seq);
        assert_eq!(got.session_id, want.session_id);
        assert_eq!(got.tool, want.tool);
        assert_eq!(got.action, want.action);
        assert_eq!(got.verdict, want.verdict);
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/hook");
        assert_eq!(r.header("content-type"), Some("application/json"));
        assert_eq!(r.header("authorization"), Some("Bearer secret-token"));
        // The payload is the ledger's Go-compatible JSON, byte for byte.
        assert_eq!(r.body, want.to_json().unwrap());
        s.close().unwrap();
    }

    #[test]
    fn webhook_sink_retries() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel::<()>();
        let a = attempts.clone();
        let srv = Server::start(move |_| {
            if a.fetch_add(1, Ordering::SeqCst) + 1 < 2 {
                return 500;
            }
            let _ = tx.send(());
            200
        });
        let s = WebhookSink::new(WebhookConfig::new(srv.url("/")));
        s.emit(&sample_event());
        rx.recv_timeout(Duration::from_secs(10))
            .expect("webhook did not succeed after retry");
        assert!(attempts.load(Ordering::SeqCst) >= 2, "retry expected");
        s.close().unwrap();
    }

    #[test]
    fn webhook_gives_up_after_max_tries() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let a = attempts.clone();
        let srv = Server::start(move |_| {
            a.fetch_add(1, Ordering::SeqCst);
            503
        });
        let s = WebhookSink::new(WebhookConfig::new(srv.url("/")));
        s.emit(&sample_event());
        let deadline = Instant::now() + Duration::from_secs(10);
        while attempts.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        // 200ms + 400ms of backoff fit well inside the wait; no fourth try.
        thread::sleep(Duration::from_millis(300));
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        s.close().unwrap();
    }

    /// Emit returns quickly even when the endpoint hangs and the queue is
    /// saturated.
    #[test]
    fn emit_does_not_block_on_slow_endpoint() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let release_rx = std::sync::Mutex::new(release_rx);
        let srv = Server::start(move |_| {
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(60));
            200
        });
        let mut cfg = WebhookConfig::new(srv.url("/"));
        cfg.queue_size = 8;
        let s = Arc::new(WebhookSink::new(cfg));

        let s2 = s.clone();
        let start = Instant::now();
        let h = thread::spawn(move || {
            for i in 0..100_000 {
                let mut ev = sample_event();
                ev.seq = i;
                s2.emit(&ev);
            }
        });
        h.join().unwrap();
        assert!(
            start.elapsed() < EMIT_BUDGET,
            "100k emits took {:?}",
            start.elapsed()
        );
        assert!(s.shared.drops.total() > 0);

        drop(release_tx);
        s.close().unwrap();
    }
}
