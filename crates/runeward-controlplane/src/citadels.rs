//! Creating, listing and tearing down governed sandboxes (Citadels), and
//! the per-sandbox calls that are not tool executions.

use std::sync::Arc;

use runeward_backend::{
    Backend, IsolationTier, PtyStream, Sandbox, spec_from_charter, verify_runtime_capabilities,
};
use runeward_charter::{Charter, IsolationLevel, Severity, Verdict};
use runeward_ledger::{Event, Scrubber};
use runeward_policy::{Action, Guard};
use serde::Serialize;

use crate::actor::actor_or;
use crate::env::{compile_scrub_patterns, new_engine, resolve_env};
use crate::error::{Error, Result};
use crate::govern::or_reason;
use crate::governance::IsolationEvidence;
use crate::manager::{Manager, blocking};
use crate::sessions::{Session, SessionState, lock};
use crate::workspaces::live_sandbox;

/// Client-reported usage deltas above these are ignored.
pub(crate) const MAX_CLIENT_USAGE_TOKEN_DELTA: i64 = 1_000_000_000;
pub(crate) const MAX_CLIENT_USAGE_COST_DELTA: f64 = 1_000_000.0;

/// Per-create overrides that are not part of the Charter.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// One-time copy into the fresh workspace (overrides `host.copy_from`;
    /// `~/` is expanded). The host directory is never mounted.
    pub copy_from: String,
    /// Tenant owner for RBAC visibility; empty means unowned.
    pub owner: String,
    /// The authenticated principal; `owner` is its tenant boundary.
    pub actor: String,
    /// Links a delegated child to an existing parent Citadel. The child
    /// must share the parent's tenant, and its Charter must be the
    /// parent's or provably no broader
    /// ([`runeward_policy::check_subsumption`]).
    pub parent_sandbox: String,
    /// Run id (default: a fresh id).
    pub run_id: String,
    pub agent: String,
    pub provider: String,
    pub model: String,
}

/// A sandbox handle with its owner and isolation tier, for listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct SandboxInfo {
    pub sandbox: Sandbox,
    pub owner: String,
    /// The tier the backend reported for this sandbox.
    pub isolation: IsolationTier,
    /// What the in-sandbox supervisor reported enforcing (Charters with
    /// `[filesystem]` or `[process]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<IsolationEvidence>,
}

/// A lightweight Charter descriptor for listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProfileInfo {
    pub name: String,
    pub host: String,
    pub egress: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub image: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// One user-actionable setup diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessCheck {
    pub name: String,
    /// `ok`, `warn` or `fail`.
    pub status: String,
    pub message: String,
}

/// Whether a Charter's sandbox runtime can be launched (distinct from
/// control-plane liveness).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub profile: String,
    pub checks: Vec<ReadinessCheck>,
}

fn check(name: &str, status: &str, message: impl Into<String>) -> ReadinessCheck {
    ReadinessCheck {
        name: name.into(),
        status: status.into(),
        message: message.into(),
    }
}

/// Maps a Charter isolation level onto the backend tier scale.
fn tier_of(level: IsolationLevel) -> IsolationTier {
    match level {
        IsolationLevel::Process => IsolationTier::Process,
        IsolationLevel::Container => IsolationTier::Container,
        IsolationLevel::Kernel => IsolationTier::Kernel,
        IsolationLevel::Vm => IsolationTier::Vm,
    }
}

/// Refuses a sandbox whose reported tier is below the Charter's
/// `[isolation] minimum`. An unparsable floor fails closed. `evidence` is
/// the probe's record, when the backend took one: a probe that could not
/// run explains the low tier better than "use a stronger runtime".
pub(crate) fn check_isolation_floor(
    c: &Charter,
    backend: &str,
    actual: IsolationTier,
    evidence: Option<&runeward_backend::IsolationEvidence>,
) -> Result<()> {
    if c.isolation.is_unset() {
        return Ok(());
    }
    let ok = c
        .isolation
        .minimum_level()
        .is_some_and(|min| actual >= tier_of(min));
    if ok {
        return Ok(());
    }
    Err(Error::IsolationFloor {
        charter: c.name.clone(),
        required: c.isolation.minimum.clone(),
        actual: actual.as_str().into(),
        backend: backend.into(),
        hint: floor_hint(evidence),
    })
}

/// The advice in an [`Error::IsolationFloor`].
fn floor_hint(evidence: Option<&runeward_backend::IsolationEvidence>) -> String {
    let failed = evidence.and_then(|e| {
        e.signals
            .iter()
            .find_map(|s| s.strip_prefix("probe:failed="))
    });
    match failed {
        Some(why) => format!(
            "the isolation probe could not run in the sandbox ({why}), so no stronger isolation could be confirmed; the runtime must allow commands to be executed in a running sandbox (see docs/isolation.md)"
        ),
        None => "configure a stronger runtime (for example host.runtime_class) or lower [isolation] minimum".into(),
    }
}

/// Tears a half-created sandbox down, ignoring failures.
async fn discard(be: &dyn Backend, id: &str) {
    let _ = be.kill(id).await;
}

impl Manager {
    /// Resolves a Charter by name from the configured search path.
    pub async fn load_profile(&self, name: &str) -> Result<Charter> {
        let opts = self.config.charter_options();
        let name = name.to_owned();
        blocking(move || runeward_charter::load(&name, &opts).map_err(Error::other)).await
    }

    /// The resolvable Charters with their host, egress mode, image and
    /// capabilities.
    pub async fn list_profiles(&self) -> Result<Vec<ProfileInfo>> {
        let opts = self.config.charter_options();
        blocking(move || {
            let mut out = Vec::new();
            for name in runeward_charter::list(&opts) {
                let mut info = ProfileInfo {
                    name: name.clone(),
                    host: "container".into(),
                    egress: "open".into(),
                    image: String::new(),
                    capabilities: Vec::new(),
                };
                if let Ok(c) = runeward_charter::load(&name, &opts) {
                    info.image.clone_from(&c.host.image);
                    info.capabilities = runeward_backend::charter_capabilities(&c);
                    if !c.host.host_type.as_str().is_empty() {
                        info.host = c.host.host_type.as_str().into();
                    }
                    if c.network.deny_by_default() {
                        info.egress = "deny-by-default".into();
                    }
                }
                out.push(info);
            }
            Ok(out)
        })
        .await
    }

    /// Optional runtimes (`python`, `node`, `browser`) the sandbox's Charter
    /// declares; empty means shell and files only.
    pub fn sandbox_capabilities(&self, id: &str) -> Vec<String> {
        self.session_opt(id)
            .map(|s| runeward_backend::charter_capabilities(&s.charter))
            .unwrap_or_default()
    }

    /// Validates a Charter and probes its runtime. Host paths and raw
    /// engine stderr are never included.
    pub async fn check_readiness(&self, name: &str) -> ReadinessReport {
        let mut report = ReadinessReport {
            ready: false,
            profile: name.to_owned(),
            checks: Vec::new(),
        };
        let c = match self.load_profile(name).await {
            Ok(c) => c,
            Err(_) => {
                report.checks.push(check(
                    "policy",
                    "fail",
                    format!("policy could not be loaded; run `runeward doctor {name}` on the server host"),
                ));
                return report;
            }
        };
        let findings = runeward_charter::lint(&c);
        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = findings.len() - errors;
        let status = if errors > 0 {
            "fail"
        } else if warnings > 0 {
            "warn"
        } else {
            "ok"
        };
        report.checks.push(check(
            "policy",
            status,
            format!("{errors} errors, {warnings} warnings"),
        ));
        let mut ide_ready = true;
        if c.ide.enabled {
            let ide = self.ide_readiness();
            ide_ready = ide.status == "ok";
            report.checks.push(ide);
        }
        let be = match self.registry.open(&c, &self.backend_config).await {
            Ok(be) => be,
            Err(_) => {
                report.checks.push(check(
                    "runtime",
                    "fail",
                    "sandbox runtime is unavailable; start Docker/Podman or check Kubernetes access, then run `runeward doctor`",
                ));
                return report;
            }
        };
        report
            .checks
            .push(check("runtime", "ok", format!("{} reachable", be.name())));
        let prerequisites = resolve_env(&c, &self.resolver).await.is_ok();
        report.checks.push(if prerequisites {
            check("secrets", "ok", "required environment and secret sources resolved")
        } else {
            check(
                "secrets",
                "fail",
                "required environment or secret source is unavailable; check the server configuration and retry",
            )
        });
        let image = &c.host.image;
        report.checks.push(if image.ends_with(":dev") || !image.contains('/') {
            check(
                "image",
                "warn",
                "local/development image selected; use a published immutable image for shared environments",
            )
        } else {
            check("image", "ok", image.clone())
        });
        report.ready = errors == 0 && prerequisites && ide_ready;
        report
    }

    /// Resolves every `[[env]]` source of a Charter without exposing values
    /// (shared by readiness and `doctor`).
    pub async fn check_profile_prerequisites(&self, c: &Charter) -> Result<()> {
        resolve_env(c, &self.resolver).await.map(drop)
    }

    /// Loads a Charter, provisions a sandbox on its backend and registers a
    /// governed session for it.
    ///
    /// The backend-reported isolation tier is checked against the Charter's
    /// `[isolation] minimum` right after the sandbox exists and before
    /// anything executes in it; a weaker sandbox is torn down and refused.
    pub async fn create_sandbox(&self, profile: &str, opts: CreateOptions) -> Result<Sandbox> {
        let mut c = self.load_profile(profile).await?;
        let mut parent_run_id = String::new();
        let mut lineage = None;
        if !opts.parent_sandbox.is_empty() {
            let parent = self
                .session_opt(&opts.parent_sandbox)
                .filter(|p| p.owner == opts.owner)
                .ok_or_else(|| Error::not_found("parent citadel not found"))?;
            let proof = match runeward_policy::check_subsumption(
                &parent.charter,
                &c,
                self.config.policy_default.as_deref(),
            ) {
                Ok(proof) => proof,
                Err(refusal) => {
                    let reason = format!(
                        "delegated child charter {:?} is not provably within parent charter {:?}: {refusal}",
                        c.name, parent.charter.name
                    );
                    self.record(
                        &parent,
                        "citadel",
                        "delegate",
                        &[c.name.clone()],
                        Verdict::Deny.as_str(),
                        -1,
                        0,
                        &reason,
                    )
                    .await;
                    return Err(Error::forbidden(reason));
                }
            };
            parent_run_id.clone_from(&parent.run_id);
            lineage = Some((parent.charter.name.clone(), proof));
        }
        let run_id = if opts.run_id.trim().is_empty() {
            crate::new_id()
        } else {
            opts.run_id.clone()
        };
        let extra = compile_scrub_patterns(&c.audit.scrub_patterns)?;
        let (mut env, mut secrets) = resolve_env(&c, &self.resolver).await?;
        let gov = self.prepare_governance(&c, &mut env, &mut secrets).await?;
        let be = self.registry.open(&c, &self.backend_config).await?;
        let mut spec = spec_from_charter(&c, env.clone());
        gov.apply(&mut spec);
        if !opts.copy_from.is_empty() {
            spec.seed_dir = Some(runeward_backend::expand_home(&opts.copy_from));
        }
        let sb = be.create(spec).await?;

        if let Err(e) =
            check_isolation_floor(&c, be.name(), sb.isolation, sb.isolation_evidence.as_ref())
        {
            discard(be.as_ref(), &sb.id).await;
            self.record_refused_create(&c, &sb, &opts, &e).await;
            return Err(e);
        }
        let (evidence, report_line) = match self.verify_governance(be.as_ref(), &sb, &gov).await {
            Ok(Some((ev, line))) => (Some(ev), line),
            Ok(None) => (None, String::new()),
            Err(e) => {
                discard(be.as_ref(), &sb.id).await;
                self.record_refused_create(&c, &sb, &opts, &e).await;
                return Err(e);
            }
        };
        if let Err(e) = verify_runtime_capabilities(be.as_ref(), &sb.id, &mut c).await {
            discard(be.as_ref(), &sb.id).await;
            return Err(e.into());
        }
        let guard = match Guard::new(&c.limits) {
            Ok(g) => g,
            Err(e) => {
                discard(be.as_ref(), &sb.id).await;
                return Err(Error::other(e));
            }
        };
        guard.start();
        let engine = match new_engine(&c, self.config.policy_default.as_deref()).await {
            Ok(e) => e,
            Err(e) => {
                discard(be.as_ref(), &sb.id).await;
                return Err(e);
            }
        };
        let mut builder = Session::builder(sb.clone(), Arc::clone(&be), c)
            .engine(engine)
            .guard(guard)
            .env(env)
            .owner(opts.owner.clone())
            .actor(first_non_empty(opts.actor.trim(), &opts.owner))
            .run_id(run_id)
            .parent_run_id(parent_run_id)
            .agent(opts.agent.trim())
            .provider(opts.provider.trim())
            .model(opts.model.trim())
            .secrets(secrets)
            .scrubber(Scrubber::new(extra));
        if let Some((parent_charter, proof)) = lineage {
            builder = builder
                .charter_lineage(proof.method())
                .parent_charter(parent_charter)
                .charter_proof(proof.summary());
        }
        if let Some(b) = &gov.broker {
            builder = builder.broker(Arc::clone(b));
        }
        if let Some(ev) = evidence {
            builder = builder.enforcement(ev);
        }
        let sess = match builder.build() {
            Ok(s) => s,
            Err(e) => {
                discard(be.as_ref(), &sb.id).await;
                return Err(e);
            }
        };
        *lock(&sess.state) = SessionState::Creating;
        let sess = Arc::new(sess);
        lock(&self.sessions).insert(sb.id.clone(), Arc::clone(&sess));
        self.attach_governance(&sess, gov, &report_line).await;

        if let Err(e) = self.start_ide(&sess).await {
            self.abandon(&sess).await;
            return Err(Error::other(format!("start experimental ide: {e}")));
        }
        if let Err(e) = self.register_run(&sess).await {
            self.abandon(&sess).await;
            return Err(Error::other(format!("persist run: {e}")));
        }
        sess.transition(SessionState::Running)?;
        runeward_obs::inc_sandbox_created();
        self.record(
            &sess,
            "sandbox",
            "create",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            "",
        )
        .await;
        Ok(sb)
    }

    /// Removes a session that failed before it was registered.
    async fn abandon(&self, sess: &Session) {
        sess.stop_tasks();
        discard(sess.backend.as_ref(), &sess.sandbox.id).await;
        lock(&self.sessions).remove(&sess.sandbox.id);
    }

    /// Chronicles a create refused by the isolation floor.
    async fn record_refused_create(
        &self,
        c: &Charter,
        sb: &Sandbox,
        opts: &CreateOptions,
        e: &Error,
    ) {
        let mut ev = Event {
            session_id: sb.id.clone(),
            sandbox: sb.id.clone(),
            profile: c.name.clone(),
            tool: "sandbox".into(),
            action: "create".into(),
            verdict: Verdict::Deny.as_str().into(),
            exit_code: -1,
            ..Event::default()
        };
        ev.meta
            .insert("isolation".into(), sb.isolation.as_str().into());
        ev.meta
            .insert("isolation_minimum".into(), c.isolation.minimum.clone());
        if let Some(evidence) = &sb.isolation_evidence {
            ev.meta.extend(evidence.ledger_meta());
        }
        ev.meta.insert("reason".into(), e.to_string());
        let actor = actor_or(first_non_empty(opts.actor.trim(), &opts.owner));
        if !actor.is_empty() {
            ev.meta.insert("actor".into(), actor);
        }
        if !opts.owner.is_empty() {
            ev.meta.insert("tenant".into(), opts.owner.clone());
        }
        runeward_obs::record_action("sandbox", Verdict::Deny.as_str(), 0);
        self.append_audit(ev).await;
    }

    /// Registers a session built elsewhere (tests and embedders; Go's
    /// `InjectSession`). No backend create happens and no run is recorded.
    pub fn inject_session(&self, sess: Session) -> Arc<Session> {
        let sess = Arc::new(sess);
        lock(&self.sessions).insert(sess.sandbox.id.clone(), Arc::clone(&sess));
        sess
    }

    /// The handle for a sandbox id. A sleeping persistent Citadel reports
    /// status `sleeping`.
    pub fn sandbox(&self, id: &str) -> Option<Sandbox> {
        match self.session_opt(id) {
            Some(s) => Some(live_sandbox(&s)),
            None => self.dormant(id).map(|r| r.sandbox()),
        }
    }

    /// The live session for a sandbox id.
    pub fn session_handle(&self, id: &str) -> Option<Arc<Session>> {
        self.session_opt(id)
    }

    /// Every governed sandbox, including sleeping persistent Citadels.
    pub fn list_sandboxes(&self) -> Vec<Sandbox> {
        self.list_sandbox_infos()
            .into_iter()
            .map(|i| i.sandbox)
            .collect()
    }

    /// Every governed sandbox with its owner and isolation tier, for
    /// per-principal views. Sleeping persistent Citadels are included
    /// with status `sleeping`.
    pub fn list_sandbox_infos(&self) -> Vec<SandboxInfo> {
        let mut out: Vec<SandboxInfo> = lock(&self.sessions)
            .values()
            .map(|s| SandboxInfo {
                sandbox: live_sandbox(s),
                owner: s.owner.clone(),
                isolation: s.isolation(),
                enforcement: s.enforcement().cloned(),
            })
            .collect();
        out.extend(self.dormant_records().into_iter().map(|r| SandboxInfo {
            sandbox: r.sandbox(),
            isolation: r.isolation,
            owner: r.owner,
            enforcement: None,
        }));
        out
    }

    /// The owner of a sandbox: `None` when unknown, `Some("")` when unowned.
    pub fn sandbox_owner(&self, id: &str) -> Option<String> {
        match self.session_opt(id) {
            Some(s) => Some(s.owner.clone()),
            None => self.dormant(id).map(|r| r.owner),
        }
    }

    /// Tears a sandbox down: cancels its agent sessions, drops its
    /// conversation feed and usage, Chronicles the kill and finishes its
    /// run.
    pub async fn kill_sandbox(&self, id: &str) -> Result<()> {
        self.agents.cancel_for(id);
        self.drop_schedules_for_citadel(id).await;
        if let Some(rec) = self.dormant(id) {
            return self.kill_dormant(rec).await;
        }
        let sess = lock(&self.sessions)
            .remove(id)
            .ok_or_else(|| Error::not_found(format!("sandbox {id:?} not found")))?;
        if self.is_workspace(id) {
            self.untrack_workspace(id).await;
        }
        {
            let mut st = lock(&sess.state);
            *st = SessionState::Terminating;
        }
        self.accounting.forget(id);
        self.conversation.forget(id);
        self.record_ide_close(&sess).await;
        self.record(
            &sess,
            "sandbox",
            "kill",
            &[],
            Verdict::Allow.as_str(),
            0,
            0,
            "",
        )
        .await;
        let killed = sess.backend.kill(id).await;
        sess.stop_tasks();
        *lock(&sess.state) = SessionState::Terminated;
        let run = self
            .finish_run(
                &sess.run_id,
                killed.as_ref().err().map(ToString::to_string).as_deref(),
            )
            .await;
        killed?;
        run
    }

    /// Attributes reported model usage to a sandbox and Chronicles it; once
    /// the Charter's budget is exceeded the governed path denies further
    /// calls. Absurd deltas are ignored.
    pub async fn record_usage(&self, id: &str, tokens: i64, cost_usd: f64) -> Result<()> {
        let sess = self.session(id)?;
        if tokens < 0 || cost_usd < 0.0 {
            return Err(Error::other("usage deltas must be non-negative"));
        }
        if !cost_usd.is_finite() {
            return Err(Error::other("cost_usd must be finite"));
        }
        if tokens > MAX_CLIENT_USAGE_TOKEN_DELTA || cost_usd > MAX_CLIENT_USAGE_COST_DELTA {
            return Ok(());
        }
        let u = self.accounting.usage(id);
        if tokens > i64::MAX - u.tokens || cost_usd > f64::MAX - u.cost_usd {
            return Ok(());
        }
        self.accounting
            .record(&sess.charter.name, id, tokens, cost_usd);
        let u = self.accounting.usage(id);
        let mut ev = Event {
            session_id: id.to_owned(),
            sandbox: id.to_owned(),
            profile: sess.charter.name.clone(),
            tool: "usage".into(),
            action: "report".into(),
            verdict: Verdict::Allow.as_str().into(),
            ..Event::default()
        };
        ev.meta.insert("tokens".into(), tokens.to_string());
        ev.meta.insert("cost_usd".into(), go_float(cost_usd));
        ev.meta.insert("tokens_tot".into(), u.tokens.to_string());
        ev.meta.insert("cost_usd_tot".into(), go_float(u.cost_usd));
        ev.meta.insert("run_id".into(), sess.run_id.clone());
        if !sess.owner.is_empty() {
            ev.meta.insert("tenant".into(), sess.owner.clone());
        }
        let actor = actor_or(&sess.actor);
        if !actor.is_empty() {
            ev.meta.insert("actor".into(), actor);
        }
        self.append_audit(ev).await;
        Ok(())
    }

    /// Wires an interactive terminal to the sandbox. A raw terminal bypasses
    /// per-action policy, so the attach itself is policy-gated as tool
    /// `terminal` (require-approval is treated as deny) and audited.
    pub async fn attach_terminal(&self, id: &str, stream: PtyStream) -> Result<()> {
        // Held for the whole attachment, so an attached terminal keeps a
        // persistent workspace awake.
        let sess = self.awake_session(id).await?;
        let dec = sess.engine.evaluate(&Action::new("terminal", "attach"));
        if dec.verdict != Verdict::Allow {
            let reason = or_reason(&dec.reason, "terminal attach denied by policy");
            self.record(&sess, "terminal", "attach", &[], "deny", -1, 0, &reason)
                .await;
            return Err(Error::other(reason));
        }
        self.record(&sess, "terminal", "attach", &[], "allow", 0, 0, "")
            .await;
        Ok(sess.backend.attach_pty(id, stream).await?)
    }
}

pub(crate) fn first_non_empty<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a.is_empty() { b } else { a }
}

/// Formats a float like Go's `strconv.FormatFloat(f, 'f', -1, 64)`.
/// Rust's shortest round-trip `Display` never uses an exponent, as Go's
/// `'f'` format does not.
pub(crate) fn go_float(f: f64) -> String {
    format!("{f}")
}

#[cfg(test)]
mod tests {
    use runeward_charter::Isolation;

    use super::*;

    #[test]
    fn isolation_floor() {
        let mut c = Charter {
            name: "c".into(),
            ..Charter::default()
        };
        assert!(check_isolation_floor(&c, "docker", IsolationTier::Process, None).is_ok());
        c.isolation = Isolation {
            minimum: "kernel".into(),
        };
        let err =
            check_isolation_floor(&c, "docker", IsolationTier::Container, None).expect_err("weak");
        assert!(
            err.to_string().contains(
                "requires isolation \"kernel\" but the docker backend provided \"container\""
            ),
            "{err}"
        );
        assert!(
            err.to_string().contains("configure a stronger runtime"),
            "{err}"
        );
        // A probe that could not run says so instead.
        let ev = runeward_backend::IsolationEvidence {
            runtime: "krun".into(),
            signals: vec![
                "probe:failed=podman exec: the handler does not support exec".into(),
                "verdict:container".into(),
            ],
            ..runeward_backend::IsolationEvidence::default()
        };
        let err = check_isolation_floor(&c, "podman", IsolationTier::Container, Some(&ev))
            .expect_err("weak");
        let msg = err.to_string();
        assert!(
            msg.contains("isolation probe could not run in the sandbox (podman exec: the handler does not support exec)"),
            "{msg}"
        );
        assert!(!msg.contains("stronger runtime"), "{msg}");
        assert!(check_isolation_floor(&c, "docker", IsolationTier::Kernel, None).is_ok());
        assert!(check_isolation_floor(&c, "vm", IsolationTier::Vm, None).is_ok());
        c.isolation.minimum = "bogus".into();
        assert!(
            check_isolation_floor(&c, "vm", IsolationTier::Vm, None).is_err(),
            "fail closed"
        );
    }

    #[test]
    fn floats_like_go() {
        assert_eq!(go_float(0.25), "0.25");
        assert_eq!(go_float(3.0), "3");
        assert_eq!(go_float(0.0), "0");
    }
}
