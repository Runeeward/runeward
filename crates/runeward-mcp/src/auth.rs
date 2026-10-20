//! Caller identity: the stdio principal, per-request HTTP bearer tokens and
//! the tenancy checks every tool shares.

use std::sync::Arc;

use runeward_authz::{ENV_FILE, Principal, Store};

use crate::ENV_MCP_DEFAULT_TOKEN;

/// The authenticated caller of one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The tenant boundary that owns created resources.
    pub owner: String,
    /// The acting principal Chronicle events are attributed to.
    pub actor: String,
    /// The RBAC principal; `None` when no authz store is configured (one
    /// shared, fully trusted boundary).
    pub principal: Option<Arc<Principal>>,
}

impl Identity {
    fn from_principal(p: Arc<Principal>) -> Self {
        Self {
            owner: p.tenant_id().to_owned(),
            actor: p.name.clone(),
            principal: Some(p),
        }
    }

    /// Reports whether the caller may launch `profile`.
    pub fn can_launch(&self, profile: &str) -> bool {
        self.principal
            .as_ref()
            .is_none_or(|p| p.can_launch(profile))
    }

    /// Reports whether the caller is an RBAC administrator.
    pub fn is_admin(&self) -> bool {
        self.principal.as_ref().is_some_and(|p| p.admin)
    }

    /// Reports whether the caller may see Conclave decisions.
    pub fn may_approve(&self) -> bool {
        self.principal.as_ref().is_none_or(|p| p.may_approve())
    }

    /// Reports whether a resource owned by `owner` is visible: always
    /// without RBAC or for administrators, else only within the tenant.
    pub fn sees(&self, owner: &str) -> bool {
        self.principal.is_none() || self.is_admin() || owner == self.owner
    }

    /// Reports whether RBAC is in force for this caller.
    pub fn rbac(&self) -> bool {
        self.principal.is_some()
    }
}

/// Extracts the token from an `Authorization: Bearer <token>` header value
/// (scheme case-insensitive, exactly two fields), as the Go server does.
pub fn parse_bearer_token(header: &str) -> Option<&str> {
    let mut fields = header.split_whitespace();
    let scheme = fields.next()?;
    let token = fields.next()?;
    if fields.next().is_some() || !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    Some(token)
}

/// A principal already identified by the HTTP auth layer, carried in the
/// request extensions so tool calls do not identify the token twice.
#[derive(Debug, Clone)]
pub(crate) struct Authenticated(pub(crate) Arc<Principal>);

/// Resolves the caller of a tool call (Go's `principalResolver`).
#[derive(Debug, Clone)]
pub(crate) struct Resolver {
    store: Option<Arc<Store>>,
    stdio: Identity,
}

impl Resolver {
    /// Builds the resolver. `default_principal` names the stdio caller
    /// without RBAC; with a store, `default_token` must identify a principal
    /// (an empty token leaves stdio calls refused with a clear error).
    pub(crate) async fn new(
        store: Option<Arc<Store>>,
        default_principal: &str,
        default_token: &str,
    ) -> Result<Self, String> {
        let mut r = Self::http_only(store, default_principal);
        let Some(store) = r.store.clone() else {
            return Ok(r);
        };
        let token = default_token.trim();
        if token.is_empty() {
            return Ok(r);
        }
        match store.identify(token).await {
            Some(p) => {
                r.stdio = Identity::from_principal(p);
                Ok(r)
            }
            None => Err(format!(
                "{ENV_MCP_DEFAULT_TOKEN} does not match any principal in {ENV_FILE}"
            )),
        }
    }

    /// A resolver that never identifies a stdio token (HTTP callers are
    /// identified per request).
    pub(crate) fn http_only(store: Option<Arc<Store>>, default_principal: &str) -> Self {
        let name = match default_principal.trim() {
            "" => "mcp-stdio",
            n => n,
        };
        Self {
            store,
            stdio: Identity {
                owner: name.to_owned(),
                actor: name.to_owned(),
                principal: None,
            },
        }
    }

    /// Resolves the caller: `http` is `None` for stdio (no HTTP request).
    pub(crate) async fn resolve(
        &self,
        http: Option<&http::request::Parts>,
    ) -> Result<Identity, String> {
        let Some(parts) = http else {
            if self.store.is_some() && self.stdio.principal.is_none() {
                return Err(format!(
                    "{ENV_MCP_DEFAULT_TOKEN} or `runeward auth login` is required for MCP stdio when authentication is configured"
                ));
            }
            return Ok(self.stdio.clone());
        };
        let header = parts
            .headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let Some(token) = parse_bearer_token(header) else {
            return Err("missing bearer token".into());
        };
        let Some(store) = &self.store else {
            // Legacy HTTP mode is authenticated by the outer shared-token
            // middleware: one shared ownership boundary, no per-principal
            // RBAC.
            return Ok(Identity {
                owner: "mcp-http".into(),
                actor: "mcp-http".into(),
                principal: None,
            });
        };
        if let Some(Authenticated(p)) = parts.extensions.get::<Authenticated>() {
            return Ok(Identity::from_principal(Arc::clone(p)));
        }
        store
            .identify(token)
            .await
            .map(Identity::from_principal)
            .ok_or_else(|| "unknown bearer token".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_parsing_matches_go() {
        assert_eq!(parse_bearer_token("Bearer abc123"), Some("abc123"));
        assert_eq!(parse_bearer_token("  bearer   abc  "), Some("abc"));
        assert_eq!(parse_bearer_token("Token nope"), None);
        assert_eq!(parse_bearer_token("Bearer"), None);
        assert_eq!(parse_bearer_token("Bearer a b"), None);
        assert_eq!(parse_bearer_token(""), None);
    }

    fn store() -> Arc<Store> {
        let principals = vec![
            Principal {
                name: "stdio-owner".into(),
                tenant: "team-one".into(),
                token: "tok-stdio".into(),
                allowed_profiles: vec!["dev-*".into()],
                ..Principal::default()
            },
            Principal {
                name: "http-owner".into(),
                tenant: "team-two".into(),
                token: "tok-http".into(),
                allowed_profiles: vec!["prod-*".into()],
                ..Principal::default()
            },
        ];
        Arc::new(Store::from_principals(principals).expect("store"))
    }

    fn parts(auth: Option<&str>) -> http::request::Parts {
        let mut b = http::Request::builder().uri("/mcp");
        if let Some(a) = auth {
            b = b.header("Authorization", a);
        }
        b.body(()).expect("request").into_parts().0
    }

    #[tokio::test]
    async fn resolver_uses_authz_for_stdio_and_http() {
        let r = Resolver::new(Some(store()), "", "tok-stdio")
            .await
            .expect("resolver");
        let stdio = r.resolve(None).await.expect("stdio");
        assert_eq!(
            (stdio.owner.as_str(), stdio.actor.as_str()),
            ("team-one", "stdio-owner")
        );
        assert!(stdio.can_launch("dev-x") && !stdio.can_launch("prod-x"));
        let http = r
            .resolve(Some(&parts(Some("Bearer tok-http"))))
            .await
            .expect("http");
        assert_eq!(
            (http.owner.as_str(), http.actor.as_str()),
            ("team-two", "http-owner")
        );
        assert_eq!(
            r.resolve(Some(&parts(Some("Bearer nope")))).await,
            Err("unknown bearer token".into())
        );
        assert_eq!(
            r.resolve(Some(&parts(None))).await,
            Err("missing bearer token".into())
        );
    }

    #[tokio::test]
    async fn resolver_errors_match_go() {
        let err = Resolver::new(Some(store()), "", "wrong")
            .await
            .expect_err("unknown default token");
        assert_eq!(
            err,
            "RUNEWARD_MCP_DEFAULT_TOKEN does not match any principal in RUNEWARD_AUTHZ_FILE"
        );
        let r = Resolver::new(Some(store()), "", "")
            .await
            .expect("resolver");
        let err = r.resolve(None).await.expect_err("stdio needs a token");
        assert!(err.starts_with("RUNEWARD_MCP_DEFAULT_TOKEN or `runeward auth login`"));

        let legacy = Resolver::new(None, " agent-7 ", "ignored")
            .await
            .expect("legacy");
        let id = legacy.resolve(None).await.expect("stdio");
        assert_eq!(
            (id.owner.as_str(), id.actor.as_str()),
            ("agent-7", "agent-7")
        );
        assert!(id.can_launch("anything") && id.may_approve() && !id.is_admin());
        let id = legacy
            .resolve(Some(&parts(Some("Bearer whatever"))))
            .await
            .expect("legacy http");
        assert_eq!(id.owner, "mcp-http");
    }
}
