//! The authenticated actor a call runs on behalf of.
//!
//! Go threads the actor through `context.Context`; here it is a tokio
//! task-local set with [`with_actor`]. Tenant ownership stays on the
//! session; the actor only changes who a Chronicle event is attributed to.

use std::future::Future;

tokio::task_local! {
    static ACTOR: String;
}

/// Runs `fut` with Chronicle events attributed to `actor` (trimmed). An
/// empty actor leaves the current attribution unchanged.
pub async fn with_actor<F: Future>(actor: &str, fut: F) -> F::Output {
    let actor = actor.trim();
    if actor.is_empty() {
        return fut.await;
    }
    ACTOR.scope(actor.to_owned(), fut).await
}

/// The actor set by an enclosing [`with_actor`], if any.
pub fn current_actor() -> Option<String> {
    ACTOR
        .try_with(Clone::clone)
        .ok()
        .filter(|a| !a.trim().is_empty())
}

/// The current actor, else `fallback`.
pub(crate) fn actor_or(fallback: &str) -> String {
    current_actor().unwrap_or_else(|| fallback.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scoped_actor() {
        assert_eq!(current_actor(), None);
        let got = with_actor(" codex ", async { current_actor() }).await;
        assert_eq!(got.as_deref(), Some("codex"));
        let got = with_actor("", async { actor_or("creator") }).await;
        assert_eq!(got, "creator");
    }
}
