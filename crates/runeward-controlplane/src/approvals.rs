//! Human-in-the-loop approvals (the Conclave inbox).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use runeward_ledger::gotime::{self, Time};
use serde::Serialize;
use tokio::sync::oneshot;

/// The JSON projection of a pending approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalView {
    pub id: String,
    pub sandbox: String,
    pub tool: String,
    pub action: String,
    pub reason: String,
    #[serde(with = "crate::timefmt")]
    pub created: Time,
}

#[derive(Debug)]
struct Pending {
    view: ApprovalView,
    /// Delivers true on approve, false on deny.
    decided: oneshot::Sender<bool>,
}

/// A concurrency-safe registry of pending approvals. A blocked tool call
/// waits on the receiver returned by [`ApprovalStore::create`].
#[derive(Debug, Default)]
pub struct ApprovalStore {
    pending: Mutex<HashMap<String, Pending>>,
}

impl ApprovalStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Registers a pending approval and returns its view and the receiver
    /// the waiting call blocks on.
    pub fn create(
        &self,
        sandbox: &str,
        tool: &str,
        action: &str,
        reason: &str,
    ) -> (ApprovalView, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let view = ApprovalView {
            id: crate::new_id(),
            sandbox: sandbox.to_owned(),
            tool: tool.to_owned(),
            action: action.to_owned(),
            reason: reason.to_owned(),
            created: gotime::now(),
        };
        self.lock().insert(
            view.id.clone(),
            Pending {
                view: view.clone(),
                decided: tx,
            },
        );
        (view, rx)
    }

    /// Every pending approval, in no particular order.
    pub fn list(&self) -> Vec<ApprovalView> {
        self.lock().values().map(|p| p.view.clone()).collect()
    }

    /// One pending approval, without resolving it.
    pub fn get(&self, id: &str) -> Option<ApprovalView> {
        self.lock().get(id).map(|p| p.view.clone())
    }

    /// Delivers a decision and removes the approval; reports whether it was
    /// pending.
    pub fn resolve(&self, id: &str, approve: bool) -> bool {
        self.resolve_view(id, approve).is_some()
    }

    /// Like [`ApprovalStore::resolve`], returning what was resolved so the
    /// caller can record who decided it.
    pub fn resolve_view(&self, id: &str, approve: bool) -> Option<ApprovalView> {
        let p = self.lock().remove(id)?;
        // The waiter may already have timed out; the decision is then moot.
        let _ = p.decided.send(approve);
        Some(p.view)
    }

    /// Drops an approval without a decision (a timed-out or abandoned
    /// waiter), so the inbox holds no orphans.
    pub(crate) fn forget(&self, id: &str) {
        self.lock().remove(id);
    }
}

/// Forgets an approval when the waiting call goes away without a decision.
pub(crate) struct ForgetOnDrop<'a> {
    pub(crate) store: &'a ApprovalStore,
    pub(crate) id: String,
}

impl Drop for ForgetOnDrop<'_> {
    fn drop(&mut self) {
        self.store.forget(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_delivers_once() {
        let s = ApprovalStore::new();
        let (view, rx) = s.create("sb", "shell", "rm -rf /", "dangerous");
        assert_eq!(view.id.len(), 32);
        assert_eq!(s.get(&view.id), Some(view.clone()));
        assert_eq!(s.list().len(), 1);
        assert!(s.resolve(&view.id, true));
        assert!(!s.resolve(&view.id, false), "already resolved");
        assert_eq!(rx.await, Ok(true));
        assert!(s.list().is_empty());

        let (view, rx) = s.create("sb", "shell", "x", "");
        drop(rx);
        assert!(s.resolve(&view.id, false), "a gone waiter still resolves");
        let v = serde_json::to_value(&view).expect("json");
        assert!(v["created"].as_str().expect("created").ends_with('Z'));
    }
}
