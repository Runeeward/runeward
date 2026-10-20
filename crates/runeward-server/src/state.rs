//! Shared server state: the Manager, credentials, tickets and IDE cookie
//! sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use runeward_authz::{Principal, Store};
use runeward_controlplane::Manager;

use crate::limit::RateLimiter;

/// What a short-lived ticket may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketKind {
    Terminal,
    Conversation,
    Download,
    Ide,
}

impl TicketKind {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "terminal" => Some(Self::Terminal),
            "conversation" => Some(Self::Conversation),
            "download" => Some(Self::Download),
            "ide" => Some(Self::Ide),
            _ => None,
        }
    }

    /// Kinds bound to one Citadel.
    pub(crate) fn sandbox_scoped(self) -> bool {
        matches!(self, Self::Terminal | Self::Conversation | Self::Ide)
    }
}

/// The resource a ticket is valid for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TicketScope {
    pub(crate) kind: TicketKind,
    pub(crate) sandbox_id: String,
    pub(crate) path: String,
}

impl TicketScope {
    pub(crate) fn sandbox(kind: TicketKind, sandbox_id: &str) -> Self {
        Self {
            kind,
            sandbox_id: sandbox_id.to_owned(),
            path: String::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ApiTicket {
    pub(crate) scope: TicketScope,
    pub(crate) principal: Option<Arc<Principal>>,
    pub(crate) expires_at: SystemTime,
}

/// A browser IDE session established by a consumed IDE ticket, so
/// code-server subresources and WebSockets authenticate by cookie.
#[derive(Debug, Clone)]
pub(crate) struct IdeCookieSession {
    pub(crate) sandbox_id: String,
    pub(crate) principal: Option<Arc<Principal>>,
    pub(crate) expires_at: SystemTime,
}

/// State shared by every handler and middleware.
pub(crate) struct AppState {
    pub(crate) mgr: Arc<Manager>,
    /// Legacy single bearer token; ignored when `authz` is set.
    pub(crate) token: String,
    /// Multi-principal RBAC (static principals and OIDC).
    pub(crate) authz: Option<Arc<Store>>,
    /// Whether the dashboard is mounted at `/`.
    pub(crate) dashboard: bool,
    /// Embedded in evidence exports.
    pub(crate) version: String,
    pub(crate) limiter: Option<RateLimiter>,
    /// Per-principal limiting (`RUNEWARD_PRINCIPAL_RATE_LIMIT`).
    pub(crate) principal_limiter: Option<runeward_controlplane::PrincipalLimiter>,
    pub(crate) tickets: Mutex<HashMap<String, ApiTicket>>,
    pub(crate) ide_sessions: Mutex<HashMap<String, IdeCookieSession>>,
    pub(crate) ide_client: crate::handlers::ide::ProxyClient,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("auth_token", &!self.token.is_empty())
            .field("rbac", &self.authz.is_some())
            .field("dashboard", &self.dashboard)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

pub(crate) type SharedState = Arc<AppState>;

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A fresh 128-bit hex id for tickets and cookie sessions.
pub(crate) fn random_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

impl AppState {
    /// Mints a single-use ticket. Sandbox-scoped kinds need a sandbox id.
    pub(crate) fn issue_ticket(
        &self,
        scope: TicketScope,
        principal: Option<Arc<Principal>>,
        ttl: Duration,
    ) -> Result<(String, SystemTime), String> {
        let ttl = if ttl.is_zero() {
            Duration::from_secs(30)
        } else {
            ttl
        };
        if scope.kind.sandbox_scoped() && scope.sandbox_id.trim().is_empty() {
            return Err(match scope.kind {
                TicketKind::Terminal => "terminal ticket requires sandbox scope",
                TicketKind::Conversation => "conversation ticket requires sandbox scope",
                _ => "ide ticket requires sandbox scope",
            }
            .into());
        }
        let id = random_id();
        let now = SystemTime::now();
        let expires_at = now + ttl;
        let mut tickets = lock(&self.tickets);
        tickets.retain(|_, t| now < t.expires_at);
        tickets.insert(
            id.clone(),
            ApiTicket {
                scope,
                principal,
                expires_at,
            },
        );
        Ok((id, expires_at))
    }

    /// Consumes `ticket` (it is single use even when it does not match) and
    /// returns its principal when it is live and scoped to `want`. Download
    /// tickets only authorize GET/HEAD of their path.
    pub(crate) fn consume_ticket(
        &self,
        ticket: &str,
        want: &TicketScope,
        method: &axum::http::Method,
        path: &str,
    ) -> Option<Option<Arc<Principal>>> {
        let t = lock(&self.tickets).remove(ticket)?;
        if SystemTime::now() > t.expires_at || t.scope.kind != want.kind {
            return None;
        }
        if want.kind.sandbox_scoped() {
            if t.scope.sandbox_id.is_empty() || t.scope.sandbox_id != want.sandbox_id {
                return None;
            }
        } else {
            if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
                return None;
            }
            if !t.scope.path.is_empty() && t.scope.path != path {
                return None;
            }
        }
        Some(t.principal)
    }

    /// Whether `id` names a Cohort owned by tenant `owner`. Legacy Cohorts
    /// without an owner belong to a tenant only when every member does.
    pub(crate) fn fleet_owned_by(&self, id: &str, owner: &str) -> bool {
        let Some(v) = self.mgr.fleet_view(id) else {
            return false;
        };
        if owner.trim().is_empty() {
            return false;
        }
        if !v.owner.is_empty() {
            return v.owner == owner;
        }
        let members = v.sandboxes.unwrap_or_default();
        if members.is_empty() {
            return false;
        }
        members
            .iter()
            .all(|sb| self.mgr.sandbox_owner(sb).is_some_and(|o| o == owner))
    }

    /// Whether a snapshot belongs to the principal's tenant.
    pub(crate) fn snapshot_visible_to(&self, p: &Principal, id: &str) -> bool {
        self.mgr
            .snapshot_owner(id)
            .is_some_and(|o| !o.is_empty() && o == p.tenant_id())
    }
}

/// The authenticated RBAC principal of a request: `None` in legacy
/// single-token or open mode (full rights, no named identity).
#[derive(Debug, Clone)]
pub(crate) struct Caller(pub(crate) Option<Arc<Principal>>);

impl Caller {
    pub(crate) fn get(&self) -> Option<&Principal> {
        self.0.as_deref()
    }

    /// A principal that is not an administrator: tenant scoping applies.
    pub(crate) fn scoped(&self) -> Option<&Principal> {
        self.get().filter(|p| !p.admin)
    }

    /// The (tenant, actor) pair new resources are attributed to.
    pub(crate) fn identity(&self) -> (String, String) {
        self.get()
            .map(|p| (p.tenant_id().to_owned(), p.name.clone()))
            .unwrap_or_default()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(parts.extensions.get::<Arc<Principal>>().cloned()))
    }
}
