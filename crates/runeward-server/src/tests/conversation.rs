//! Ports of Go `internal/server/conversation_test.go`, plus feed checks.

use std::time::Duration;

use axum::http::Method;

use super::support::*;
use crate::state::{TicketKind, TicketScope};

#[tokio::test]
async fn conversation_ticket_is_scoped_and_single_use() {
    let h = harness().await;
    let r = router_with_token(&h, "s3cret");
    h.inject("cit-1", "parity", "").await;
    let mint = post(
        &r,
        "/v1/tickets",
        Some("s3cret"),
        r#"{"kind":"conversation","sandbox_id":"cit-1"}"#,
    )
    .await;
    assert_eq!(mint.status, 201, "{}", mint.text());
    let ticket = mint.json()["ticket"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    // Not a WebSocket handshake, but authenticated: the handler answers.
    let uri = format!("/v1/citadels/cit-1/conversation/stream?ticket={ticket}");
    assert_eq!(
        get(&r, &uri, None).await.status,
        400,
        "first use passes auth"
    );
    assert_eq!(get(&r, &uri, None).await.status, 401, "second use");
}

#[tokio::test]
async fn ticket_scopes_are_enforced() {
    let h = harness().await;
    let s = crate::state::AppState {
        mgr: h.mgr.clone(),
        token: String::new(),
        authz: None,
        dashboard: false,
        version: String::new(),
        limiter: None,
        principal_limiter: None,
        tickets: Default::default(),
        ide_sessions: Default::default(),
        ide_client: crate::handlers::ide::proxy_client(),
    };
    let scope = TicketScope::sandbox(TicketKind::Conversation, "cit-1");
    let (t, _) = s
        .issue_ticket(scope.clone(), None, Duration::from_secs(60))
        .expect("issue");
    let path = "/v1/citadels/cit-1/conversation/stream";
    assert!(s.consume_ticket(&t, &scope, &Method::GET, path).is_some());
    assert!(
        s.consume_ticket(&t, &scope, &Method::GET, path).is_none(),
        "single use"
    );

    let (t, _) = s
        .issue_ticket(scope.clone(), None, Duration::from_secs(60))
        .expect("issue");
    let other = TicketScope::sandbox(TicketKind::Conversation, "cit-2");
    assert!(
        s.consume_ticket(&t, &other, &Method::GET, path).is_none(),
        "other citadel"
    );
    assert!(
        s.consume_ticket(&t, &scope, &Method::GET, path).is_none(),
        "burned by the mismatch"
    );

    let (t, _) = s
        .issue_ticket(scope.clone(), None, Duration::from_secs(60))
        .expect("issue");
    let terminal = TicketScope::sandbox(TicketKind::Terminal, "cit-1");
    assert!(
        s.consume_ticket(&t, &terminal, &Method::GET, path)
            .is_none(),
        "other kind"
    );

    assert!(
        s.issue_ticket(
            TicketScope::sandbox(TicketKind::Ide, " "),
            None,
            Duration::ZERO
        )
        .is_err(),
        "sandbox scope required"
    );
}

#[tokio::test]
async fn conversation_routes_hide_unknown_citadel() {
    let h = harness().await;
    let r = server(&h).router();
    assert_eq!(
        get(&r, "/v1/citadels/missing/conversation", None)
            .await
            .status,
        404
    );
    let resp = post(
        &r,
        "/v1/citadels/missing/conversation",
        None,
        r#"{"role":"assistant","content":"hello"}"#,
    )
    .await;
    assert_eq!(resp.status, 404);
}

#[tokio::test]
async fn conversation_publish_and_history() {
    let h = harness().await;
    h.inject("cit-1", "parity", "").await;
    let r = server(&h).router();
    for i in 0..3 {
        let resp = post(
            &r,
            "/v1/citadels/cit-1/conversation",
            None,
            &format!(r#"{{"role":"assistant","content":"turn {i}"}}"#),
        )
        .await;
        assert_eq!(resp.status, 201, "{}", resp.text());
    }
    let all = get(&r, "/v1/citadels/cit-1/conversation", None)
        .await
        .json();
    assert_eq!(all["messages"].as_array().map(Vec::len), Some(3));
    let after = get(
        &r,
        "/v1/citadels/cit-1/conversation?after_id=1&limit=1",
        None,
    )
    .await
    .json();
    assert_eq!(after["messages"][0]["id"], 3, "{after}");
    for bad in ["?limit=0", "?limit=501", "?after_id=-1"] {
        let resp = get(&r, &format!("/v1/citadels/cit-1/conversation{bad}"), None).await;
        assert_eq!(resp.status, 400, "{bad}");
    }
}
