//! The embedded single-page dashboard (`web/` at the repository root).
//!
//! The assets are compiled in from the repository's `web/` directory in
//! place and carry no content hash, so every response is `no-store`: a
//! reload always picks up the running binary's dashboard.

use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::respond::not_found_text;

/// `web/index.html`.
pub const INDEX_HTML: &[u8] = include_bytes!("../../../web/index.html");
/// `web/app.js`.
pub const APP_JS: &[u8] = include_bytes!("../../../web/app.js");
/// `web/style.css`.
pub const STYLE_CSS: &[u8] = include_bytes!("../../../web/style.css");
/// `web/logo.png`.
pub const LOGO_PNG: &[u8] = include_bytes!("../../../web/logo.png");

const NO_STORE: &str = "no-store, max-age=0, must-revalidate";

/// An embedded asset by request path, with its content type.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    match path {
        "/" => Some((INDEX_HTML, "text/html; charset=utf-8")),
        "/app.js" => Some((APP_JS, "text/javascript; charset=utf-8")),
        "/style.css" => Some((STYLE_CSS, "text/css; charset=utf-8")),
        "/logo.png" => Some((LOGO_PNG, "image/png")),
        _ => None,
    }
}

/// Serves the dashboard like Go's `http.FileServerFS` over the embedded
/// files: `/` is `index.html`, `/index.html` redirects to `./`, anything
/// else is 404.
pub(crate) async fn dashboard(req: Request) -> Response {
    let path = req.uri().path();
    let mut resp = if path == "/index.html" {
        let mut r = StatusCode::MOVED_PERMANENTLY.into_response();
        r.headers_mut()
            .insert(header::LOCATION, HeaderValue::from_static("./"));
        r
    } else if let Some((body, content_type)) = asset(path) {
        let mut r = if req.method() == Method::HEAD {
            let mut r = ().into_response();
            r.headers_mut()
                .insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
            r
        } else {
            body.into_response()
        };
        r.headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        r.headers_mut()
            .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        r
    } else {
        not_found_text()
    };
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn html() -> &'static str {
        std::str::from_utf8(INDEX_HTML).expect("utf-8 index.html")
    }

    fn app() -> &'static str {
        std::str::from_utf8(APP_JS).expect("utf-8 app.js")
    }

    #[test]
    fn prepared_ide_link_uses_same_tab() {
        let html = html();
        let start = html
            .find(r#"id="ide-link""#)
            .expect("prepared IDE link is missing");
        let end = html[start..]
            .find("</a>")
            .expect("prepared IDE link is malformed");
        let link = &html[start..start + end];
        assert!(
            !link.contains(r#"target="_blank""#),
            "prepared IDE fallback must use the current tab so it still works when new tabs are blocked"
        );
    }

    #[test]
    fn agent_group_picker_drives_readiness() {
        assert!(
            html().contains(r#"id="fleet-setup-note""#),
            "agent groups must show readiness for the selected Charter"
        );
        assert!(
            app().contains(r##"$("#fleet-profile-select").addEventListener("change", refreshSelectedProfileReadiness)"##),
            "agent-group Charter changes must refresh readiness"
        );
        assert!(
            app().contains(
                r##"state.activeView === "fleets" ? $("#fleet-create-btn") : $("#create-btn")"##
            ),
            "agent-group creation must be gated by readiness"
        );
    }

    #[test]
    fn sandbox_tabs_expose_accessible_state() {
        for marker in [
            r#"id="tabs" role="tablist""#,
            r#"id="tab-terminal" class="tab active" data-tab="terminal" role="tab" aria-selected="true""#,
            r#"id="pane-terminal" class="tab-pane active" data-pane="terminal" role="tabpanel""#,
        ] {
            assert!(
                html().contains(marker),
                "dashboard is missing accessible tab marker {marker:?}"
            );
        }
        assert!(
            app().contains(r#"t.setAttribute("aria-selected", String(active))"#),
            "tab activation must update aria-selected"
        );
        assert!(
            app().contains(r##"enableArrowKeyTabs("#tabs .tab")"##),
            "sandbox tabs must support arrow-key navigation"
        );
    }

    #[test]
    fn dashboard_avoids_generic_html_injection_helper() {
        assert!(
            !app().contains(r#"k === "html""#),
            "DOM helper must not expose a generic innerHTML injection path"
        );
    }

    #[test]
    fn live_chat_explains_empty_connected_state() {
        assert!(
            app().contains("connected; waiting for an agent to publish conversation turns"),
            "live chat must explain why a connected stream is empty"
        );
    }

    #[test]
    fn assets_resolve() {
        assert!(asset("/").is_some_and(|(b, _)| b == INDEX_HTML));
        assert!(asset("/logo.png").is_some_and(|(b, t)| b == LOGO_PNG && t == "image/png"));
        assert!(asset("/app.js/extra").is_none());
        assert!(asset("/index.html").is_none(), "redirects instead");
    }
}
