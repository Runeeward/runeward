//! Scheduled agent runs (`schedules.json`).
//!
//! A schedule belongs to one Cohort or one Citadel and fires on a cron
//! expression (5 fields, UTC) or a fixed interval (a Go duration, at least
//! 1m). Schedules live in the control-plane state, outside any sandbox, so
//! they can wake a sleeping workspace. Each firing:
//!
//! 1. picks the target Citadel (a Cohort's first member that exists);
//! 2. asks the Citadel's policy about tool `schedule`, action `fire`;
//! 3. runs the optional `precheck` command in the sandbox (a governed
//!    `shell` call) and stops unless it exits 0, so cheap idle checks never
//!    start an expensive agent;
//! 4. starts a fresh agent session with the schedule's command (the
//!    `prompt`, when set, is appended as the last argument), which goes
//!    through policy, guardrails and budgets like any other call.
//!
//! Missed windows are never backfilled: after a restart or a slow tick the
//! next firing is computed from now. A firing is skipped while the
//! previous one's agent session is still active. At most 50 schedules may
//! target one Cohort or Citadel. Agents may manage their own schedules
//! over MCP only when the Charter sets `[schedule] self_service = true`.

use std::sync::Arc;
use std::time::Duration;

use croner::Cron;
use croner::parser::{CronParser, Seconds, Year};
use runeward_charter::Verdict;
use runeward_ledger::gotime::{self, Time};
use runeward_policy::Action;
use serde::{Deserialize, Serialize};

use crate::actor::{actor_or, with_actor};
use crate::agent_sessions::StartAgentSessionOptions;
use crate::error::{Error, Result};
use crate::govern::or_reason;
use crate::manager::Manager;
use crate::sessions::lock;
use crate::statefile::marshal_indent;
use crate::timefmt::nullable;

pub(crate) const SCHEDULES_FILE_NAME: &str = "schedules.json";

/// Most schedules targeting one Cohort or Citadel.
pub const MAX_SCHEDULES_PER_TARGET: usize = 50;
/// Shortest interval between firings.
pub const MIN_SCHEDULE_INTERVAL: Duration = Duration::from_secs(60);
/// Largest prompt, in bytes.
pub const MAX_SCHEDULE_PROMPT_BYTES: usize = 16 << 10;
/// Most argv entries in a command or precheck.
pub const MAX_SCHEDULE_ARGS: usize = 64;

/// What to schedule.
#[derive(Debug, Clone, Default)]
pub struct ScheduleSpec {
    /// Target Cohort (exactly one of `cohort_id` and `citadel_id`).
    pub cohort_id: String,
    /// Target Citadel.
    pub citadel_id: String,
    /// 5-field cron expression in UTC (exactly one of `cron` and `every`).
    pub cron: String,
    /// Fixed interval as a Go duration (`"30m"`), at least 1m.
    pub every: String,
    /// The agent command (argv).
    pub command: Vec<String>,
    /// Appended to `command` as its last argument when set.
    pub prompt: String,
    pub agent: String,
    pub model: String,
    /// Runs first; the agent starts only if it exits 0.
    pub precheck: Vec<String>,
}

/// A stored schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    #[serde(default, deserialize_with = "nullable")]
    pub id: String,
    /// The tenant of the target.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub owner: String,
    /// The principal that created it.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub actor: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub cohort_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub citadel_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub cron: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub every: String,
    #[serde(default, deserialize_with = "nullable")]
    pub command: Vec<String>,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub prompt: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub agent: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub model: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub precheck: Vec<String>,
    /// Created by an agent through `[schedule] self_service`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub self_service: bool,
    #[serde(with = "crate::timefmt", default = "gotime::zero")]
    pub created_at: Time,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_fire_at: Option<Time>,
    #[serde(
        with = "crate::timefmt::opt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_fired_at: Option<Time>,
    /// `started`, `skipped_precheck`, `skipped_busy`, `denied` or `error`.
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub last_outcome: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub last_reason: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "String::is_empty"
    )]
    pub last_session_id: String,
    #[serde(
        default,
        deserialize_with = "nullable",
        skip_serializing_if = "is_zero"
    )]
    pub fire_count: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// The result of one firing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduleFiring {
    pub schedule_id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub citadel_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// When a schedule fires.
enum Timing {
    Cron(Box<Cron>),
    Every(Duration),
}

impl Timing {
    fn of(cron: &str, every: &str) -> Result<Self> {
        let (c, e) = (cron.trim(), every.trim());
        match (c.is_empty(), e.is_empty()) {
            (true, true) | (false, false) => {
                Err(Error::bad_input("set exactly one of cron and every"))
            }
            (false, true) => {
                // Classic five-field crontab, as croner 2 parsed by default:
                // no seconds or year field, and `N/step` still accepted.
                let parsed = CronParser::builder()
                    .seconds(Seconds::Disallowed)
                    .year(Year::Disallowed)
                    .sloppy_ranges(true)
                    .build()
                    .parse(c)
                    .map_err(|err| Error::bad_input(format!("cron {c:?}: {err}")))?;
                Ok(Self::Cron(Box::new(parsed)))
            }
            (true, false) => {
                let nanos = runeward_charter::parse_go_duration(e)
                    .map_err(|err| Error::bad_input(format!("every: {err}")))?;
                let d = u64::try_from(nanos)
                    .map(Duration::from_nanos)
                    .unwrap_or_default();
                if d < MIN_SCHEDULE_INTERVAL {
                    return Err(Error::bad_input(format!(
                        "every must be at least 1m, got {e:?}"
                    )));
                }
                Ok(Self::Every(d))
            }
        }
    }

    /// The first firing strictly after `t`.
    fn next_after(&self, t: Time) -> Option<Time> {
        match self {
            Self::Every(d) => chrono::Duration::from_std(*d).ok().map(|d| t + d),
            Self::Cron(c) => c
                .find_next_occurrence(&t.with_timezone(&chrono::Utc), false)
                .ok()
                .map(|n| n.fixed_offset()),
        }
    }

    /// Refuses timings that fire more often than once a minute.
    fn check_min_interval(&self) -> Result<()> {
        let Self::Cron(_) = self else {
            return Ok(());
        };
        let mut t = gotime::now();
        let mut prev: Option<Time> = None;
        for _ in 0..5 {
            let Some(n) = self.next_after(t) else {
                return Err(Error::bad_input("cron expression never fires"));
            };
            if let Some(p) = prev
                && (n - p).num_seconds() < 60
            {
                return Err(Error::bad_input("schedules may fire at most once a minute"));
            }
            prev = Some(n);
            t = n;
        }
        Ok(())
    }
}

fn check_argv(field: &str, argv: &[String], required: bool) -> Result<()> {
    if required && argv.is_empty() {
        return Err(Error::bad_input(format!("{field} is required")));
    }
    if argv.len() > MAX_SCHEDULE_ARGS {
        return Err(Error::bad_input(format!(
            "{field} has more than {MAX_SCHEDULE_ARGS} arguments"
        )));
    }
    if argv.iter().map(String::len).sum::<usize>() > MAX_SCHEDULE_PROMPT_BYTES {
        return Err(Error::bad_input(format!(
            "{field} exceeds {MAX_SCHEDULE_PROMPT_BYTES} bytes"
        )));
    }
    Ok(())
}

impl Schedule {
    fn timing(&self) -> Option<Timing> {
        Timing::of(&self.cron, &self.every).ok()
    }

    fn targets(&self, cohort: &str, citadel: &str) -> bool {
        (!cohort.is_empty() && self.cohort_id == cohort)
            || (!citadel.is_empty() && self.citadel_id == citadel)
    }
}

impl Manager {
    /// The tenant owning a schedule target, or not found.
    fn schedule_target_owner(&self, spec: &ScheduleSpec) -> Result<String> {
        match (spec.cohort_id.trim(), spec.citadel_id.trim()) {
            ("", "") => Err(Error::bad_input(
                "set exactly one of cohort_id and citadel_id",
            )),
            (c, "") => self
                .fleet_owner(c)
                .ok_or_else(|| Error::not_found(format!("cohort {c:?} not found"))),
            ("", c) => self
                .sandbox_owner(c)
                .ok_or_else(|| Error::not_found(format!("citadel {c:?} not found"))),
            _ => Err(Error::bad_input(
                "set exactly one of cohort_id and citadel_id",
            )),
        }
    }

    /// Creates a schedule (operator path: no Charter opt-in needed). The
    /// schedule belongs to the target's tenant and is attributed to the
    /// acting principal.
    pub async fn create_schedule(&self, spec: ScheduleSpec) -> Result<Schedule> {
        self.insert_schedule(spec, false).await
    }

    /// Creates a schedule on behalf of an agent: allowed only when the
    /// target's Charter sets `[schedule] self_service = true`.
    pub async fn create_self_schedule(&self, spec: ScheduleSpec) -> Result<Schedule> {
        if !self
            .self_service_allowed(&spec.cohort_id, &spec.citadel_id)
            .await?
        {
            return Err(Error::forbidden(
                "agents are not allowed to schedule runs here: the Charter does not set [schedule] self_service = true",
            ));
        }
        self.insert_schedule(spec, true).await
    }

    /// Whether the target's Charter allows agent self-service scheduling.
    pub async fn self_service_allowed(&self, cohort: &str, citadel: &str) -> Result<bool> {
        let (cohort, citadel) = (cohort.trim(), citadel.trim());
        if !citadel.is_empty() {
            if let Some(s) = self.session_opt(citadel) {
                return Ok(s.charter.schedule_self_service());
            }
            let rec = self
                .dormant(citadel)
                .ok_or_else(|| Error::not_found(format!("citadel {citadel:?} not found")))?;
            return Ok(self
                .load_profile(&rec.profile)
                .await?
                .schedule_self_service());
        }
        let f = self
            .fleet(cohort)
            .ok_or_else(|| Error::not_found(format!("cohort {cohort:?} not found")))?;
        Ok(self.load_profile(&f.profile).await?.schedule_self_service())
    }

    async fn insert_schedule(&self, spec: ScheduleSpec, self_service: bool) -> Result<Schedule> {
        let owner = self.schedule_target_owner(&spec)?;
        let timing = Timing::of(&spec.cron, &spec.every)?;
        timing.check_min_interval()?;
        check_argv("command", &spec.command, true)?;
        check_argv("precheck", &spec.precheck, false)?;
        if spec.prompt.len() > MAX_SCHEDULE_PROMPT_BYTES {
            return Err(Error::bad_input(format!(
                "prompt exceeds {MAX_SCHEDULE_PROMPT_BYTES} bytes"
            )));
        }
        let now = gotime::now();
        let s = Schedule {
            id: crate::new_id(),
            owner,
            actor: actor_or(""),
            cohort_id: spec.cohort_id.trim().to_owned(),
            citadel_id: spec.citadel_id.trim().to_owned(),
            cron: spec.cron.trim().to_owned(),
            every: spec.every.trim().to_owned(),
            command: spec.command,
            prompt: spec.prompt,
            agent: spec.agent.trim().to_owned(),
            model: spec.model.trim().to_owned(),
            precheck: spec.precheck,
            self_service,
            created_at: now,
            next_fire_at: timing.next_after(now),
            last_fired_at: None,
            last_outcome: String::new(),
            last_reason: String::new(),
            last_session_id: String::new(),
            fire_count: 0,
        };
        {
            let _op = self.schedule_op.lock().await;
            {
                let mut map = lock(&self.schedules);
                let n = map
                    .values()
                    .filter(|x| x.targets(&s.cohort_id, &s.citadel_id))
                    .count();
                if n >= MAX_SCHEDULES_PER_TARGET {
                    return Err(Error::bad_input(format!(
                        "at most {MAX_SCHEDULES_PER_TARGET} schedules per cohort or citadel"
                    )));
                }
                map.insert(s.id.clone(), s.clone());
            }
            if let Err(e) = self.save_schedules().await {
                lock(&self.schedules).remove(&s.id);
                return Err(Error::other(format!("persist schedule: {e}")));
            }
        }
        self.record_schedule(&s, "create", Verdict::Allow.as_str(), "")
            .await;
        Ok(s)
    }

    /// Every schedule, oldest first.
    pub fn list_schedules(&self) -> Vec<Schedule> {
        let mut out: Vec<Schedule> = lock(&self.schedules).values().cloned().collect();
        out.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        out
    }

    /// The schedules targeting a Cohort or a Citadel.
    pub fn schedules_for(&self, cohort: &str, citadel: &str) -> Vec<Schedule> {
        let mut out = self.list_schedules();
        out.retain(|s| s.targets(cohort, citadel));
        out
    }

    /// One schedule.
    pub fn schedule(&self, id: &str) -> Option<Schedule> {
        lock(&self.schedules).get(id).cloned()
    }

    /// Removes a schedule; reports whether it existed.
    pub async fn delete_schedule(&self, id: &str) -> Result<bool> {
        let removed = {
            let _op = self.schedule_op.lock().await;
            let Some(s) = lock(&self.schedules).remove(id) else {
                return Ok(false);
            };
            if let Err(e) = self.save_schedules().await {
                lock(&self.schedules).insert(id.to_owned(), s);
                return Err(Error::other(format!("persist schedule removal: {e}")));
            }
            s
        };
        self.record_schedule(&removed, "delete", Verdict::Allow.as_str(), "")
            .await;
        Ok(true)
    }

    pub(crate) async fn drop_schedules_for_citadel(&self, id: &str) {
        self.drop_schedules_where(|s| s.citadel_id == id).await;
    }

    pub(crate) async fn drop_schedules_for_cohort(&self, id: &str) {
        self.drop_schedules_where(|s| s.cohort_id == id).await;
    }

    async fn drop_schedules_where(&self, f: impl Fn(&Schedule) -> bool) {
        let _op = self.schedule_op.lock().await;
        let before = lock(&self.schedules).len();
        lock(&self.schedules).retain(|_, s| !f(s));
        if lock(&self.schedules).len() != before
            && let Err(e) = self.save_schedules().await
        {
            tracing::error!(error = %e, "runeward: persist schedule removal");
        }
    }

    async fn save_schedules(&self) -> Result<()> {
        if self.state.dir().is_none() {
            return Ok(());
        }
        let data = marshal_indent(&self.list_schedules())?;
        self.write_state(SCHEDULES_FILE_NAME, data).await
    }

    /// Restores schedules; missed windows are skipped (the next firing is
    /// computed from now).
    pub(crate) async fn load_schedules(&self) -> Result<()> {
        let Some(data) = self.read_state(SCHEDULES_FILE_NAME).await? else {
            return Ok(());
        };
        let items: Vec<Schedule> = serde_json::from_slice::<Option<Vec<Schedule>>>(&data)
            .map_err(|e| Error::other(format!("decode {SCHEDULES_FILE_NAME}: {e}")))?
            .unwrap_or_default();
        let now = gotime::now();
        let mut map = lock(&self.schedules);
        for mut s in items {
            if s.id.is_empty() {
                continue;
            }
            if s.next_fire_at.is_none_or(|n| n <= now) {
                s.next_fire_at = s.timing().and_then(|t| t.next_after(now));
            }
            map.insert(s.id.clone(), s);
        }
        Ok(())
    }

    /// Fires every schedule whose time has come, once each (no backfill),
    /// and waits for the firings.
    pub async fn fire_due_schedules(self: &Arc<Self>) -> Vec<ScheduleFiring> {
        let now = gotime::now();
        let due: Vec<Schedule> = {
            let _op = self.schedule_op.lock().await;
            let mut due = Vec::new();
            {
                let mut map = lock(&self.schedules);
                for s in map.values_mut() {
                    if s.next_fire_at.is_some_and(|n| n <= now) {
                        s.next_fire_at = s.timing().and_then(|t| t.next_after(now));
                        due.push(s.clone());
                    }
                }
            }
            if !due.is_empty()
                && let Err(e) = self.save_schedules().await
            {
                tracing::error!(error = %e, "runeward: persist schedule times");
            }
            due
        };
        let mut handles = Vec::new();
        for s in due {
            let mgr = Arc::clone(self);
            handles.push(tokio::spawn(async move { mgr.fire(s).await }));
        }
        let mut out = Vec::new();
        for h in handles {
            if let Ok(f) = h.await {
                out.push(f);
            }
        }
        out
    }

    /// Fires a schedule now, regardless of its next time.
    pub async fn run_schedule_now(self: &Arc<Self>, id: &str) -> Result<ScheduleFiring> {
        let s = self
            .schedule(id)
            .ok_or_else(|| Error::not_found(format!("schedule {id:?} not found")))?;
        Ok(self.fire(s).await)
    }

    async fn fire(self: &Arc<Self>, s: Schedule) -> ScheduleFiring {
        let actor = if s.actor.is_empty() {
            format!("schedule:{}", s.id)
        } else {
            s.actor.clone()
        };
        let mut firing = with_actor(&actor, self.fire_inner(&s)).await;
        firing.schedule_id.clone_from(&s.id);
        {
            let _op = self.schedule_op.lock().await;
            let changed = {
                let mut map = lock(&self.schedules);
                match map.get_mut(&s.id) {
                    Some(cur) => {
                        cur.last_fired_at = Some(gotime::now());
                        cur.last_outcome.clone_from(&firing.outcome);
                        cur.last_reason.clone_from(&firing.reason);
                        if !firing.session_id.is_empty() {
                            cur.last_session_id.clone_from(&firing.session_id);
                        }
                        cur.fire_count += 1;
                        true
                    }
                    None => false,
                }
            };
            if changed && let Err(e) = self.save_schedules().await {
                tracing::error!(error = %e, "runeward: persist schedule firing");
            }
        }
        let verdict = match firing.outcome.as_str() {
            "denied" => Verdict::Deny.as_str(),
            "error" => "error",
            _ => Verdict::Allow.as_str(),
        };
        let reason = if firing.reason.is_empty() {
            firing.outcome.clone()
        } else {
            format!("{}: {}", firing.outcome, firing.reason)
        };
        with_actor(&actor, self.record_schedule(&s, "fire", verdict, &reason)).await;
        firing
    }

    async fn fire_inner(self: &Arc<Self>, s: &Schedule) -> ScheduleFiring {
        let mut out = ScheduleFiring {
            schedule_id: s.id.clone(),
            outcome: "error".into(),
            citadel_id: String::new(),
            session_id: String::new(),
            reason: String::new(),
        };
        if !s.last_session_id.is_empty()
            && self
                .agent_session(&s.last_session_id)
                .is_some_and(|a| a.status.is_active())
        {
            "skipped_busy".clone_into(&mut out.outcome);
            "the previous run is still active".clone_into(&mut out.reason);
            return out;
        }
        let citadel = if s.citadel_id.is_empty() {
            self.fleet(&s.cohort_id).and_then(|f| {
                f.members()
                    .iter()
                    .find(|id| self.sandbox_owner(id).is_some())
                    .cloned()
            })
        } else {
            Some(s.citadel_id.clone())
        };
        let Some(citadel) = citadel.filter(|c| self.sandbox_owner(c).is_some()) else {
            "no target citadel exists".clone_into(&mut out.reason);
            return out;
        };
        out.citadel_id.clone_from(&citadel);
        let mut command = s.command.clone();
        if !s.prompt.is_empty() {
            command.push(s.prompt.clone());
        }
        // Ask policy before waking anything when the session is in memory.
        let sess = match self.session_opt(&citadel) {
            Some(sess) => sess,
            None => match self.awake_session(&citadel).await {
                Ok(b) => Arc::clone(b.arc()),
                Err(e) => {
                    out.reason = e.to_string();
                    return out;
                }
            },
        };
        let dec = sess
            .engine
            .evaluate(&Action::new("schedule", "fire").with_args(command.clone()));
        if dec.verdict != Verdict::Allow {
            "denied".clone_into(&mut out.outcome);
            out.reason = or_reason(&dec.reason, "scheduled run denied by policy");
            return out;
        }
        drop(sess);
        if !s.precheck.is_empty() {
            match self.shell(&citadel, &s.precheck, "").await {
                Err(e) => {
                    out.reason = format!("precheck: {e}");
                    return out;
                }
                Ok(r) if r.verdict != Verdict::Allow => {
                    "denied".clone_into(&mut out.outcome);
                    out.reason = format!("precheck: {}", or_reason(&r.reason, "denied"));
                    return out;
                }
                Ok(r) if r.exit_code != 0 => {
                    "skipped_precheck".clone_into(&mut out.outcome);
                    out.reason = format!("precheck exited {}", r.exit_code);
                    return out;
                }
                Ok(_) => {}
            }
        }
        let opts = StartAgentSessionOptions {
            command,
            agent: s.agent.clone(),
            model: s.model.clone(),
            cohort_id: s.cohort_id.clone(),
            task_id: String::new(),
        };
        match self.start_agent_session(&citadel, opts).await {
            Ok(a) => {
                "started".clone_into(&mut out.outcome);
                out.session_id = a.id;
            }
            Err(e) => out.reason = e.to_string(),
        }
        out
    }

    async fn record_schedule(&self, s: &Schedule, action: &str, verdict: &str, reason: &str) {
        let target = if s.citadel_id.is_empty() {
            format!("fleet:{}", s.cohort_id)
        } else {
            s.citadel_id.clone()
        };
        let mut ev = runeward_ledger::Event {
            session_id: target.clone(),
            sandbox: s.citadel_id.clone(),
            tool: "schedule".into(),
            action: action.into(),
            args: vec![s.id.clone()],
            verdict: verdict.into(),
            ..runeward_ledger::Event::default()
        };
        if let Some(sess) = (!s.citadel_id.is_empty())
            .then(|| self.session_opt(&s.citadel_id))
            .flatten()
        {
            ev.profile.clone_from(&sess.charter.name);
            ev.meta.insert("run_id".into(), sess.run_id.clone());
        }
        let actor = actor_or(&s.actor);
        for (k, v) in [
            ("actor", actor.as_str()),
            ("tenant", s.owner.as_str()),
            ("cohort", s.cohort_id.as_str()),
            ("reason", reason),
        ] {
            if !v.is_empty() {
                ev.meta.insert(k.into(), v.into());
            }
        }
        let timing = if s.cron.is_empty() {
            format!("every {}", s.every)
        } else {
            format!("cron {}", s.cron)
        };
        ev.meta.insert("timing".into(), timing);
        runeward_obs::record_action("schedule", verdict, 0);
        self.append_audit(ev).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timings() {
        assert!(Timing::of("", "").is_err());
        assert!(Timing::of("*/5 * * * *", "5m").is_err());
        assert!(Timing::of("", "30s").is_err(), "below the minimum");
        assert!(Timing::of("", "soon").is_err());
        assert!(Timing::of("not cron", "").is_err());
        assert!(Timing::of("* * * * * *", "").is_err(), "no seconds field");
        assert!(Timing::of("0 0 1 1 * 2030", "").is_err(), "no year field");
        Timing::of("0/30 * * * *", "").expect("start/step without a range");

        let every = Timing::of("", "1h").expect("every");
        let t = gotime::now();
        assert_eq!(every.next_after(t), Some(t + chrono::Duration::hours(1)));

        let cron = Timing::of("*/15 * * * *", "").expect("cron");
        cron.check_min_interval().expect("15 minutes is fine");
        let next = cron.next_after(t).expect("next");
        assert!(next > t);
        assert_eq!(next.timestamp() % (15 * 60), 0);
        Timing::of("* * * * *", "")
            .expect("every minute")
            .check_min_interval()
            .expect("once a minute is the minimum");
    }
}
