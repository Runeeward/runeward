//! In-sandbox governance wiring: the request broker for `[[endpoint]]` and
//! `[[credential]]`, its approvals and decision trail, and the
//! `runeward-supervisor` plan and enforcement evidence for `[filesystem]`
//! and `[process]`.
//!
//! # Broker
//!
//! When a Charter declares endpoints or credentials, create resolves every
//! credential an endpoint uses through the Manager's secret resolver (fail
//! closed), builds a [`Broker`] for a sandbox id chosen up front, adds the
//! credential placeholders to the sandbox environment and the resolved
//! values to the session's redaction set, and hands the broker to the
//! backend ([`runeward_backend::Spec::broker`]).
//!
//! - `require-approval` decisions go to the Conclave inbox through
//!   [`BrokerApprovals`]: the agent's request is held open until a human
//!   approves or denies it, or until `approval_wait` passes (then it is
//!   refused, like a governed call that comes back pending).
//! - Every broker decision (allow, deny, budget, audit-would-deny,
//!   placeholder-misuse, approval) is recorded in the signed ledger as a
//!   tool `egress` event with the decision fields in `meta`, and stays on
//!   the Citadel's perimeter list ([`Manager::perimeter`]).
//!
//! # Supervisor
//!
//! When a Charter has `[filesystem]` or `[process]`, the backend runs the
//! agent under the supervisor. It is *required* (the create fails without
//! it) when `landlock = "required"` or `[process]` is set; a best-effort
//! `[filesystem]` may run without it on an image that lacks the binary, and
//! that is recorded. After create the enforcement report is read, recorded
//! in the ledger as evidence (tool `supervisor`), checked (a refused start,
//! a root agent, or `required` Landlock that is not enforced fail closed),
//! and summarised as [`IsolationEvidence`] on the session and
//! [`crate::SandboxInfo`].

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use runeward_auditsink::Sink;
use runeward_backend::{Backend, BrokerHandle, Sandbox, Spec, SupervisorSpec};
use runeward_charter::{Charter, Verdict};
use runeward_egress::{
    ApprovalFuture, ApprovalHook, ApprovalOutcome, ApprovalRequest, Broker, Decision,
};
use runeward_ledger::{Event, Ledger};
use runeward_supervisor::config::LandlockMode;
use runeward_supervisor::{Report, SupervisorConfig};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::approvals::ApprovalStore;
use crate::error::{Error, Result};
use crate::manager::{Manager, append_audit_to, session_event};
use crate::sessions::{Session, lock};

/// What the in-sandbox supervisor reported enforcing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IsolationEvidence {
    /// `enforced` (the supervisor started the agent and reported) or
    /// `absent` (best effort, and the backend could not run it: an image
    /// without the supervisor on Docker/Podman; on Kubernetes, no agent
    /// identity in the Charter or no Firecracker drive left for its init
    /// container).
    pub supervisor: String,
    /// Whether the Charter required the supervisor.
    pub required: bool,
    /// Landlock as configured: `best-effort`, `required` or `off`.
    pub landlock_requested: String,
    /// Landlock as delivered: `enforced`, `unsupported`, `off` (empty when
    /// absent).
    pub landlock: String,
    /// The Landlock ABI the ruleset was built for.
    pub landlock_abi: u32,
    /// The self-protection seccomp filter is installed.
    pub seccomp: bool,
    pub no_new_privs: bool,
    /// The agent's uid and gid.
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Every capability set of the agent is empty.
    pub capabilities_dropped: bool,
    /// Landlock, not only file modes, keeps the agent out of the
    /// supervisor's own files.
    pub protected_by_landlock: bool,
}

impl IsolationEvidence {
    fn absent(required: bool, requested: LandlockMode) -> Self {
        Self {
            supervisor: "absent".into(),
            required,
            landlock_requested: requested.as_str().into(),
            landlock: String::new(),
            landlock_abi: 0,
            seccomp: false,
            no_new_privs: false,
            uid: None,
            gid: None,
            capabilities_dropped: false,
            protected_by_landlock: false,
        }
    }

    fn from_report(r: &Report, required: bool) -> Self {
        let c = &r.capabilities;
        Self {
            supervisor: "enforced".into(),
            required,
            landlock_requested: r.landlock.requested.clone(),
            landlock: r.landlock.status.clone(),
            landlock_abi: r.landlock.abi,
            seccomp: r.seccomp.enabled,
            no_new_privs: r.no_new_privs,
            uid: r.uid,
            gid: r.gid,
            capabilities_dropped: c.effective.is_empty()
                && c.permitted.is_empty()
                && c.inheritable.is_empty()
                && c.ambient.is_empty(),
            protected_by_landlock: r.protected_by_landlock,
        }
    }
}

/// Everything decided before the backend create, carried to the session.
pub(crate) struct Governance {
    pub(crate) sandbox_id: String,
    pub(crate) broker: Option<Arc<Broker>>,
    pub(crate) approvals: Option<Arc<BrokerApprovals>>,
    /// Subscribed before create so no early decision is missed.
    decisions: Option<broadcast::Receiver<Decision>>,
    pub(crate) supervisor: Option<SupervisorSpec>,
}

impl std::fmt::Debug for Governance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Governance")
            .field("sandbox_id", &self.sandbox_id)
            .field("broker", &self.broker.is_some())
            .field("supervisor", &self.supervisor)
            .finish_non_exhaustive()
    }
}

impl Governance {
    /// Puts the broker (with the sandbox id it was built for) and the
    /// supervisor plan into the Spec.
    pub(crate) fn apply(&self, spec: &mut Spec) {
        if self.broker.is_some() {
            spec.id.clone_from(&self.sandbox_id);
        }
        spec.broker = self.broker.clone().map(BrokerHandle::new);
        spec.supervisor.clone_from(&self.supervisor);
    }
}

/// Whether the Charter needs the supervisor, and whether it requires it.
pub(crate) fn supervisor_spec(c: &Charter, broker: bool) -> Result<Option<SupervisorSpec>> {
    if c.filesystem.is_none() && c.process.is_none() {
        return Ok(None);
    }
    let workdir = if c.host.workdir.is_empty() {
        "/workspace"
    } else {
        c.host.workdir.as_str()
    };
    let mut config = SupervisorConfig::from_charter(c, workdir)
        .map_err(|e| Error::other(format!("supervisor config: {e}")))?;
    if broker && config.filesystem.landlock != LandlockMode::Off {
        // The agent must read the broker CA bundle to trust inspected
        // endpoints.
        config
            .filesystem
            .read_only
            .push(runeward_backend::incell::BROKER_CA_DIR.into());
    }
    let required = c.process.is_some()
        || c.filesystem
            .as_ref()
            .is_some_and(|f| f.landlock == "required");
    Ok(Some(SupervisorSpec { config, required }))
}

impl Manager {
    /// Decides the in-sandbox governance for a create: builds the broker
    /// (resolving its secrets, fail closed), adds placeholders to `env` and
    /// resolved values to `secrets`, and plans the supervisor.
    pub(crate) async fn prepare_governance(
        &self,
        c: &Charter,
        env: &mut BTreeMap<String, String>,
        secrets: &mut Vec<String>,
    ) -> Result<Governance> {
        self.prepare_governance_for(c, env, secrets, None).await
    }

    /// [`Manager::prepare_governance`] for a known sandbox id (a sleeping
    /// workspace rebuilt after a restart keeps its id).
    pub(crate) async fn prepare_governance_for(
        &self,
        c: &Charter,
        env: &mut BTreeMap<String, String>,
        secrets: &mut Vec<String>,
        sandbox_id: Option<&str>,
    ) -> Result<Governance> {
        let sandbox_id = sandbox_id.map_or_else(crate::new_id, str::to_owned);
        let mut gov = Governance {
            sandbox_id: sandbox_id.clone(),
            broker: None,
            approvals: None,
            decisions: None,
            supervisor: None,
        };
        if !c.endpoints.is_empty() || !c.credentials.is_empty() {
            let mut values = HashMap::new();
            for cred in &c.credentials {
                if !c.endpoints.iter().any(|e| e.credential == cred.name) {
                    continue;
                }
                let v = self.resolver.resolve(&cred.source).await.map_err(|e| {
                    Error::other(format!(
                        "credential {:?}: resolve {:?}: {e}",
                        cred.name, cred.source
                    ))
                })?;
                if !v.is_empty() {
                    secrets.push(v.clone());
                }
                values.insert(cred.name.clone(), v);
            }
            let mut broker = Broker::with_secret_values(
                &sandbox_id,
                c.endpoints.clone(),
                c.credentials.clone(),
                values,
            )
            .map_err(|e| Error::other(format!("request broker: {e}")))?;
            if let Some(path) = &self.config.broker_upstream_ca {
                let pem = tokio::fs::read_to_string(path).await.map_err(|e| {
                    Error::other(format!(
                        "request broker: read {}: {e}",
                        crate::config::BROKER_UPSTREAM_CA_ENV
                    ))
                })?;
                broker = broker
                    .with_upstream_roots_pem(&pem)
                    .map_err(|e| Error::other(format!("request broker: {e}")))?;
            }
            for (k, v) in broker.placeholder_env() {
                if env.contains_key(&k) {
                    return Err(Error::other(format!(
                        "credential placeholder_env {k:?} collides with an [[env]] entry"
                    )));
                }
                env.insert(k, v);
            }
            let approvals = Arc::new(BrokerApprovals {
                store: Arc::clone(&self.approvals),
                wait: self.config.approval_wait.filter(|d| !d.is_zero()),
                ledger: Arc::clone(&self.ledger),
                sink: Arc::clone(&self.sink),
                session: OnceLock::new(),
            });
            let hook: Arc<dyn ApprovalHook> = approvals.clone();
            let broker = Arc::new(broker.with_approval_hook(hook));
            gov.decisions = Some(broker.subscribe());
            gov.broker = Some(broker);
            gov.approvals = Some(approvals);
        }
        gov.supervisor = supervisor_spec(c, gov.broker.is_some())?;
        Ok(gov)
    }

    /// Checks what the backend delivered against the plan: the pre-chosen
    /// id, and the supervisor's report. Returns the evidence (and the raw
    /// report line) to keep; an error means the sandbox must be discarded.
    pub(crate) async fn verify_governance(
        &self,
        be: &dyn Backend,
        sb: &Sandbox,
        gov: &Governance,
    ) -> Result<Option<(IsolationEvidence, String)>> {
        if gov.broker.is_some() && sb.id != gov.sandbox_id {
            return Err(Error::other(format!(
                "the {} backend ignored the sandbox id its request broker was built for",
                be.name()
            )));
        }
        let Some(sup) = &gov.supervisor else {
            return Ok(None);
        };
        let deadline = tokio::time::Instant::now() + self.config.supervisor_report_wait;
        let text = loop {
            match be.supervisor_report(&sb.id).await? {
                None => {
                    if sup.required {
                        return Err(Error::other(format!(
                            "the {} backend did not run the required in-sandbox supervisor",
                            be.name()
                        )));
                    }
                    return Ok(Some((
                        IsolationEvidence::absent(false, sup.config.filesystem.landlock),
                        String::new(),
                    )));
                }
                Some(t) if t.lines().any(|l| !l.trim().is_empty()) => break t,
                Some(_) if tokio::time::Instant::now() >= deadline => {
                    return Err(Error::other(
                        "the in-sandbox supervisor did not report its enforcement in time",
                    ));
                }
                Some(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        };
        let (report, line) = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| Report::parse(l).ok().map(|r| (r, l.trim().to_owned())))
            .find(|(r, _)| r.mode == "init")
            .ok_or_else(|| Error::other("the in-sandbox supervisor's report is unreadable"))?;
        check_report(&report, &sup.config)?;
        Ok(Some((
            IsolationEvidence::from_report(&report, sup.required),
            line,
        )))
    }

    /// Wires a registered session to its broker (approvals, decision pump)
    /// and records the supervisor evidence.
    pub(crate) async fn attach_governance(
        &self,
        sess: &Arc<Session>,
        gov: Governance,
        report_line: &str,
    ) {
        if let Some(a) = &gov.approvals {
            let _ = a.session.set(Arc::downgrade(sess));
        }
        if let Some(rx) = gov.decisions {
            let task = tokio::spawn(pump_decisions(
                Arc::clone(&self.ledger),
                Arc::clone(&self.sink),
                Arc::downgrade(sess),
                rx,
            ));
            lock(&sess.tasks).push(task);
        }
        if let Some(ev) = sess.enforcement() {
            let ev = ev.clone();
            let action = if ev.supervisor == "absent" {
                "absent"
            } else {
                "report"
            };
            let reason = if ev.supervisor == "absent" {
                "the backend did not run runeward-supervisor (Docker/Podman: no binary in the image; Kubernetes: no agent identity in the Charter, or no Firecracker drive left for its init container); best-effort confinement skipped"
            } else {
                ""
            };
            let line = report_line.to_owned();
            let event = session_event(
                sess,
                "supervisor",
                action,
                &[],
                Verdict::Allow.as_str(),
                0,
                0,
                reason,
                |m| evidence_meta(m, &ev, &line),
            );
            self.append_audit(event).await;
        }
    }

    /// The Citadel's perimeter list: its egress decisions, oldest first,
    /// including every request-broker decision with its endpoint, method,
    /// path, tool, rule, verdict and reason code.
    pub fn perimeter(&self, id: &str) -> Result<Vec<Decision>> {
        self.session(id)?;
        Ok(runeward_egress::list_decisions(id))
    }
}

/// Fails closed on a report that does not show the configured confinement.
fn check_report(r: &Report, cfg: &SupervisorConfig) -> Result<()> {
    if r.schema != runeward_supervisor::report::REPORT_SCHEMA {
        return Err(Error::other(format!(
            "the in-sandbox supervisor reported an unknown schema {:?}",
            r.schema
        )));
    }
    if !r.ok {
        return Err(Error::other(format!(
            "the in-sandbox supervisor refused to start the agent: {}",
            r.error.as_deref().unwrap_or("no reason given")
        )));
    }
    if r.uid.is_none_or(|u| u == 0) {
        return Err(Error::other(
            "the in-sandbox supervisor reported the agent running as root",
        ));
    }
    if cfg.filesystem.landlock == LandlockMode::Required && r.landlock.status != "enforced" {
        return Err(Error::other(format!(
            "landlock = \"required\" but the supervisor reported Landlock {:?}",
            r.landlock.status
        )));
    }
    Ok(())
}

fn evidence_meta(m: &mut BTreeMap<String, String>, ev: &IsolationEvidence, line: &str) {
    m.insert("supervisor".into(), ev.supervisor.clone());
    m.insert("supervisor_required".into(), ev.required.to_string());
    m.insert("landlock_requested".into(), ev.landlock_requested.clone());
    if !ev.landlock.is_empty() {
        m.insert("landlock".into(), ev.landlock.clone());
        m.insert("landlock_abi".into(), ev.landlock_abi.to_string());
        m.insert("seccomp".into(), ev.seccomp.to_string());
        m.insert("no_new_privs".into(), ev.no_new_privs.to_string());
        m.insert(
            "capabilities_dropped".into(),
            ev.capabilities_dropped.to_string(),
        );
        m.insert(
            "protected_by_landlock".into(),
            ev.protected_by_landlock.to_string(),
        );
    }
    if let Some(u) = ev.uid {
        m.insert("uid".into(), u.to_string());
    }
    if let Some(g) = ev.gid {
        m.insert("gid".into(), g.to_string());
    }
    if !line.is_empty() {
        m.insert("report".into(), line.to_owned());
    }
}

/// A one-line description of what a decision was about.
pub(crate) fn decision_summary(d: &Decision) -> String {
    let method = d.method.as_deref().unwrap_or_default();
    let path = d.path.as_deref().unwrap_or_default();
    match (&d.tool, method.is_empty()) {
        (Some(tool), _) => format!("{} tools/call {tool}", d.host).trim().to_owned(),
        (None, false) => format!("{method} {}{path}", d.host),
        (None, true) => d.host.clone(),
    }
}

/// The ledger verdict for a decision.
fn decision_verdict(d: &Decision) -> &'static str {
    match d.verdict {
        Some(v) => v.as_str(),
        None if d.allow => "allow",
        None => "deny",
    }
}

/// The decision fields as ledger `meta`.
pub(crate) fn decision_meta(m: &mut BTreeMap<String, String>, d: &Decision) {
    let mut put = |k: &str, v: &str| {
        if !v.is_empty() {
            m.insert(k.into(), v.into());
        }
    };
    put("host", &d.host);
    put("ip", &d.ip);
    put("allow", if d.allow { "true" } else { "false" });
    for (k, v) in [
        ("endpoint", &d.endpoint),
        ("protocol", &d.protocol),
        ("method", &d.method),
        ("path", &d.path),
        ("tool", &d.tool),
        ("effect", &d.effect),
        ("rule", &d.rule),
        ("credential", &d.credential),
    ] {
        if let Some(v) = v {
            put(k, v);
        }
    }
    if let Some(c) = d.reason_code {
        put("reason_code", c.as_str());
    }
    if let Some(b) = &d.binaries {
        put("binaries", &b.join(","));
    }
    put("decided_at", &d.timestamp.to_rfc3339());
}

/// The ledger event for one broker decision.
fn egress_event(sess: &Session, d: &Decision) -> Event {
    let ok = d.allow;
    session_event(
        sess,
        "egress",
        &decision_summary(d),
        &[],
        decision_verdict(d),
        if ok { 0 } else { -1 },
        0,
        &d.reason,
        |m| decision_meta(m, d),
    )
}

/// Records every decision from the broker's stream until the stream (or the
/// session) ends. A lagging pump records how many decisions it missed
/// rather than dropping them silently.
async fn pump_decisions(
    ledger: Arc<Ledger>,
    sink: Arc<dyn Sink>,
    sess: Weak<Session>,
    mut rx: broadcast::Receiver<Decision>,
) {
    loop {
        let ev = match rx.recv().await {
            Ok(d) => {
                let Some(s) = sess.upgrade() else { return };
                egress_event(&s, &d)
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let Some(s) = sess.upgrade() else { return };
                session_event(
                    &s,
                    "egress",
                    "decisions-dropped",
                    &[],
                    Verdict::Deny.as_str(),
                    -1,
                    0,
                    &format!("the ledger fell behind and missed {n} egress decisions"),
                    |m| {
                        m.insert("dropped".into(), n.to_string());
                    },
                )
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };
        append_audit_to(&ledger, &sink, ev).await;
    }
}

/// Routes broker `require-approval` decisions into the Conclave inbox.
pub(crate) struct BrokerApprovals {
    store: Arc<ApprovalStore>,
    wait: Option<Duration>,
    ledger: Arc<Ledger>,
    sink: Arc<dyn Sink>,
    /// Set once the session exists; until then approvals are unavailable
    /// (and the request is refused).
    session: OnceLock<Weak<Session>>,
}

impl std::fmt::Debug for BrokerApprovals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerApprovals")
            .field("wait", &self.wait)
            .finish_non_exhaustive()
    }
}

/// Forgets an approval when the waiting request goes away undecided.
struct ForgetOwned {
    store: Arc<ApprovalStore>,
    id: String,
}

impl Drop for ForgetOwned {
    fn drop(&mut self) {
        self.store.forget(&self.id);
    }
}

impl ApprovalHook for BrokerApprovals {
    fn request_approval(&self, req: ApprovalRequest) -> ApprovalFuture {
        let sess = self.session.get().and_then(Weak::upgrade);
        let store = Arc::clone(&self.store);
        let ledger = Arc::clone(&self.ledger);
        let sink = Arc::clone(&self.sink);
        let wait = self.wait;
        Box::pin(async move {
            let Some(sess) = sess else {
                return ApprovalOutcome::Unavailable;
            };
            if !sess.state().accepts_calls() {
                return ApprovalOutcome::Unavailable;
            }
            let d = req.decision;
            let action = decision_summary(&d);
            let reason = if d.reason.trim().is_empty() {
                "approval required".to_owned()
            } else {
                d.reason.clone()
            };
            let (view, decided) = store.create(&sess.sandbox.id, "egress", &action, &reason);
            let _forget = ForgetOwned {
                store: Arc::clone(&store),
                id: view.id.clone(),
            };
            let id = view.id.clone();
            let ev = session_event(
                &sess,
                "approval",
                &action,
                &[],
                Verdict::RequireApproval.as_str(),
                -1,
                0,
                &reason,
                |m| {
                    decision_meta(m, &d);
                    m.insert("approval_id".into(), id);
                },
            );
            drop(sess);
            append_audit_to(&ledger, &sink, ev).await;
            let outcome = match wait {
                Some(w) => tokio::time::timeout(w, decided).await.ok(),
                None => Some(decided.await),
            };
            match outcome {
                Some(Ok(true)) => ApprovalOutcome::Approved,
                Some(Ok(false)) => ApprovalOutcome::Denied("denied by approver".into()),
                // Timed out, or the inbox dropped the decision.
                _ => ApprovalOutcome::Unavailable,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use runeward_charter::{Filesystem, Process};

    use super::*;

    #[test]
    fn supervisor_requirement_follows_the_charter() {
        let mut c = Charter::default();
        assert!(supervisor_spec(&c, false).expect("none").is_none());
        c.filesystem = Some(Filesystem {
            read_only: vec!["/usr".into()],
            ..Filesystem::default()
        });
        let s = supervisor_spec(&c, true).expect("fs").expect("spec");
        assert!(!s.required, "best-effort may run without the binary");
        assert!(
            s.config
                .filesystem
                .read_only
                .contains(&runeward_backend::incell::BROKER_CA_DIR.to_owned()),
            "the agent can read the broker trust bundle"
        );
        assert!(
            s.config
                .filesystem
                .read_write
                .contains(&"/workspace".to_owned())
        );
        c.filesystem.as_mut().expect("fs").landlock = "required".into();
        assert!(
            supervisor_spec(&c, false)
                .expect("fs")
                .expect("spec")
                .required
        );
        c.filesystem = None;
        c.process = Some(Process {
            run_as_user: "1500".into(),
            ..Process::default()
        });
        let s = supervisor_spec(&c, false).expect("proc").expect("spec");
        assert!(s.required);
        assert_eq!(s.config.process.user, "1500");
    }

    fn report(status: &str, uid: Option<u32>) -> Report {
        Report {
            ok: true,
            mode: "init".into(),
            uid,
            landlock: runeward_supervisor::report::LandlockReport {
                requested: "required".into(),
                status: status.into(),
                abi: 6,
                ..Default::default()
            },
            ..Report::default()
        }
    }

    #[test]
    fn reports_fail_closed() {
        let mut cfg = SupervisorConfig::default().with_argv(["a"]);
        cfg.filesystem.landlock = LandlockMode::Required;
        assert!(check_report(&report("enforced", Some(1500)), &cfg).is_ok());
        let err = check_report(&report("unsupported", Some(1500)), &cfg).expect_err("weak");
        assert!(err.to_string().contains("required"), "{err}");
        assert!(check_report(&report("enforced", Some(0)), &cfg).is_err());
        assert!(check_report(&report("enforced", None), &cfg).is_err());
        let mut refused = report("refused", Some(1500));
        refused.ok = false;
        refused.error = Some("no landlock".into());
        let err = check_report(&refused, &cfg).expect_err("refused");
        assert!(err.to_string().contains("no landlock"), "{err}");
        cfg.filesystem.landlock = LandlockMode::BestEffort;
        assert!(check_report(&report("unsupported", Some(1500)), &cfg).is_ok());
        let ev = IsolationEvidence::from_report(&report("enforced", Some(1500)), true);
        assert_eq!(ev.landlock, "enforced");
        assert!(ev.capabilities_dropped);
    }

    #[test]
    fn decision_summaries_and_meta() {
        let mut d = Decision {
            host: "api.test".into(),
            ..Decision::default()
        };
        assert_eq!(decision_summary(&d), "api.test");
        d.method = Some("POST".into());
        d.path = Some("/v1/x".into());
        assert_eq!(decision_summary(&d), "POST api.test/v1/x");
        d.tool = Some("deploy".into());
        assert_eq!(decision_summary(&d), "api.test tools/call deploy");
        d.reason_code = Some(runeward_egress::ReasonCode::PlaceholderMisuse);
        d.binaries = Some(vec!["/a".into(), "/b".into()]);
        let mut m = BTreeMap::new();
        decision_meta(&mut m, &d);
        assert_eq!(m["reason_code"], "placeholder-misuse");
        assert_eq!(m["binaries"], "/a,/b");
        assert_eq!(m["allow"], "false");
        assert_eq!(decision_verdict(&d), "deny");
        d.verdict = Some(runeward_egress::Verdict::RequireApproval);
        assert_eq!(decision_verdict(&d), "require-approval");
    }
}
