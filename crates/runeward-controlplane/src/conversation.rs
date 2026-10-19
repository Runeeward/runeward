//! A Citadel's live conversation feed: redacted, display-safe turns for
//! read-only observers. Operational visibility, not a replacement for the
//! signed Chronicle.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use runeward_ledger::gotime::{self, Time};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::actor::actor_or;
use crate::error::{Error, Result};
use crate::manager::Manager;
use crate::sessions::lock;

const HISTORY_LIMIT: usize = 500;
const CONTENT_LIMIT: usize = 64 << 10;
const SUBSCRIBER_BUFFER: usize = 64;

/// One turn of the feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConversationMessage {
    pub id: u64,
    pub sandbox: String,
    pub role: String,
    pub author: String,
    pub content: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    #[serde(with = "crate::timefmt")]
    pub created_at: Time,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub redacted: bool,
}

#[derive(Debug)]
struct Stream {
    next_id: u64,
    history: VecDeque<ConversationMessage>,
    live: broadcast::Sender<ConversationMessage>,
}

impl Stream {
    fn new() -> Self {
        Self {
            next_id: 0,
            history: VecDeque::new(),
            live: broadcast::channel(SUBSCRIBER_BUFFER).0,
        }
    }
}

/// Per-Citadel feeds.
#[derive(Debug, Default)]
pub(crate) struct ConversationHub {
    streams: Mutex<HashMap<String, Stream>>,
}

impl ConversationHub {
    fn publish(&self, mut msg: ConversationMessage) -> ConversationMessage {
        let mut streams = lock(&self.streams);
        let s = streams
            .entry(msg.sandbox.clone())
            .or_insert_with(Stream::new);
        s.next_id += 1;
        msg.id = s.next_id;
        s.history.push_back(msg.clone());
        while s.history.len() > HISTORY_LIMIT {
            s.history.pop_front();
        }
        // No receivers is fine; slow receivers lag and lose old updates.
        let _ = s.live.send(msg.clone());
        msg
    }

    fn history(&self, sandbox: &str, after: u64, limit: usize) -> Vec<ConversationMessage> {
        let streams = lock(&self.streams);
        let Some(s) = streams.get(sandbox) else {
            return Vec::new();
        };
        let out: Vec<_> = s.history.iter().filter(|m| m.id > after).cloned().collect();
        let skip = out.len().saturating_sub(limit);
        out.into_iter().skip(skip).collect()
    }

    fn subscribe(&self, sandbox: &str) -> broadcast::Receiver<ConversationMessage> {
        lock(&self.streams)
            .entry(sandbox.to_owned())
            .or_insert_with(Stream::new)
            .live
            .subscribe()
    }

    /// Drops a Citadel's feed; live subscriptions end.
    pub(crate) fn forget(&self, sandbox: &str) {
        lock(&self.streams).remove(sandbox);
    }
}

/// A live view of future turns. Slow observers skip turns they missed
/// (recover them with [`Manager::conversation_history`]) instead of
/// blocking the agent. Dropping it unsubscribes.
#[derive(Debug)]
pub struct ConversationSubscription {
    rx: broadcast::Receiver<ConversationMessage>,
}

impl ConversationSubscription {
    /// The next turn, or `None` once the Citadel is gone.
    pub async fn recv(&mut self) -> Option<ConversationMessage> {
        loop {
            match self.rx.recv().await {
                Ok(m) => return Some(m),
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

/// Removes terminal control characters (C0 except tab/CR/LF, DEL and C1)
/// while keeping ordinary Unicode: the feed is rendered in xterm.js and
/// must never set titles, links or the clipboard.
pub(crate) fn safe_tty_text(v: &str) -> String {
    v.chars()
        .filter(|&c| {
            matches!(c, '\n' | '\r' | '\t') || !(c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c))
        })
        .collect()
}

impl Manager {
    /// Adds a turn and broadcasts it. The author is the authenticated actor
    /// (callers cannot spoof it); declared and pattern-detected secrets are
    /// scrubbed before storage or fan-out.
    pub async fn publish_conversation(
        &self,
        sandbox: &str,
        role: &str,
        content: &str,
        run_id: &str,
    ) -> Result<ConversationMessage> {
        let sess = self.session(sandbox)?;
        let role = role.trim().to_lowercase();
        if !matches!(role.as_str(), "user" | "assistant" | "tool" | "system") {
            return Err(Error::other(
                "conversation role must be user, assistant, tool, or system",
            ));
        }
        if content.is_empty() {
            return Err(Error::other("conversation content must not be empty"));
        }
        if content.len() > CONTENT_LIMIT {
            return Err(Error::other(format!(
                "conversation content exceeds {CONTENT_LIMIT} bytes"
            )));
        }
        let mut author = actor_or(&sess.actor);
        if author.is_empty() {
            author.clone_from(&role);
        }
        let run_id = if run_id.trim().is_empty() {
            sess.run_id.as_str()
        } else {
            run_id.trim()
        };
        let scrubbed = sess.scrub(content);
        let msg = ConversationMessage {
            id: 0,
            sandbox: sandbox.to_owned(),
            role,
            author: safe_tty_text(&author),
            content: safe_tty_text(&scrubbed),
            run_id: safe_tty_text(run_id),
            created_at: gotime::now(),
            redacted: scrubbed != content,
        };
        Ok(self.conversation.publish(msg))
    }

    /// At most `limit` turns newer than `after` (`limit` 0 or above 500
    /// means 500).
    pub fn conversation_history(
        &self,
        sandbox: &str,
        after: u64,
        limit: usize,
    ) -> Result<Vec<ConversationMessage>> {
        self.session(sandbox)?;
        let limit = if limit == 0 || limit > HISTORY_LIMIT {
            HISTORY_LIMIT
        } else {
            limit
        };
        Ok(self.conversation.history(sandbox, after, limit))
    }

    /// Streams future turns until the Citadel is removed.
    pub fn subscribe_conversation(&self, sandbox: &str) -> Result<ConversationSubscription> {
        self.session(sandbox)?;
        Ok(ConversationSubscription {
            rx: self.conversation.subscribe(sandbox),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_control_sequences() {
        assert_eq!(
            safe_tty_text("ok\x1b]52;c;bad\x07\tline\r\n\u{85}é"),
            "ok]52;c;bad\tline\r\né"
        );
    }

    #[test]
    fn history_window() {
        let hub = ConversationHub::default();
        for i in 0..(HISTORY_LIMIT + 5) {
            hub.publish(ConversationMessage {
                id: 0,
                sandbox: "s".into(),
                role: "user".into(),
                author: "a".into(),
                content: i.to_string(),
                run_id: String::new(),
                created_at: gotime::now(),
                redacted: false,
            });
        }
        let all = hub.history("s", 0, HISTORY_LIMIT);
        assert_eq!(all.len(), HISTORY_LIMIT);
        assert_eq!(all[0].id, 6);
        let tail = hub.history("s", 0, 2);
        assert_eq!(tail.iter().map(|m| m.id).collect::<Vec<_>>(), [504, 505]);
        assert!(hub.history("s", 505, 10).is_empty());
        assert!(hub.history("other", 0, 10).is_empty());
    }
}
