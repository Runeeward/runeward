//! Minimal prefixed decision logger.

use std::fmt;

use crate::decision_log::{Decision, sandbox_id_from_log_prefix};

/// Emits allow/deny lines through `tracing` with a fixed prefix (for example
/// `"runeward-egress sb-123 "`). A proxy without a logger discards them.
///
/// When a proxy has no explicit sandbox id, one is derived from a prefix of
/// the form `"runeward-egress <sandbox-id> ..."`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Logger {
    prefix: String,
}

impl Logger {
    /// Creates a logger that prepends `prefix` to every line.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// The configured prefix.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Logs one line.
    pub fn log(&self, args: fmt::Arguments<'_>) {
        tracing::info!(target: "runeward_egress", "{}{}", self.prefix, args);
    }
}

/// Shared logging/recording context for the proxy front ends.
#[derive(Debug, Clone, Default)]
pub(crate) struct Sink {
    pub(crate) sandbox_id: String,
    pub(crate) logger: Option<Logger>,
    /// Live decision stream (set when a broker is attached).
    pub(crate) events: Option<tokio::sync::broadcast::Sender<Decision>>,
}

impl Sink {
    pub(crate) fn logf(&self, args: fmt::Arguments<'_>) {
        if let Some(l) = &self.logger {
            l.log(args);
        }
    }

    pub(crate) fn sandbox_id(&self) -> String {
        let id = self.sandbox_id.trim();
        if !id.is_empty() {
            return id.to_string();
        }
        self.logger
            .as_ref()
            .map(|l| sandbox_id_from_log_prefix(l.prefix()))
            .unwrap_or_default()
    }

    pub(crate) fn record(&self, host: &str, ip: &str, allow: bool, reason: &str) {
        self.record_entry(Decision {
            host: host.to_string(),
            ip: ip.to_string(),
            allow,
            reason: reason.to_string(),
            ..Decision::default()
        });
    }

    /// Records a full decision in the per-sandbox ring and publishes it on
    /// the live stream, stamping the time.
    pub(crate) fn record_entry(&self, mut d: Decision) {
        d.timestamp = chrono::Utc::now();
        d.host = d.host.trim().to_string();
        d.ip = d.ip.trim().to_string();
        d.reason = d.reason.trim().to_string();
        if let Some(tx) = &self.events {
            // No subscribers is fine.
            let _ = tx.send(d.clone());
        }
        crate::decision_log::record_decision_entry(&self.sandbox_id(), d);
    }
}
