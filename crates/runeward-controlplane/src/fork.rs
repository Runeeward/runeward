//! Forking a Citadel: a new, independent Citadel holding a copy of the
//! source's workspace disk.
//!
//! The source is woken if it sleeps, snapshotted, and the snapshot is
//! restored into a new sandbox with a new run whose `forked_from` names the
//! source run. The fork may use another Charter (and resource caps), but
//! only an administrator may fork into a weaker isolation floor or broader
//! egress than the source has; the source's policy must allow
//! `citadel`/`fork`. Both Citadels Chronicle the fork.

use runeward_backend::{Resources, Sandbox};
use runeward_charter::{Charter, IsolationLevel, Verdict};
use runeward_policy::Action;

use crate::actor::actor_or;
use crate::error::{Error, Result};
use crate::govern::or_reason;
use crate::manager::Manager;
use crate::snapshots::LaunchIdentity;

/// How to fork a Citadel.
#[derive(Debug, Clone, Default)]
pub struct ForkOptions {
    /// The fork's Charter; empty keeps the source's.
    pub profile: String,
    /// Resource caps for the fork (zero fields keep the Charter's).
    pub resources: Option<Resources>,
    /// Lets the fork have a weaker isolation floor or broader egress than
    /// the source. Only for administrators.
    pub admin: bool,
    /// The requesting principal (defaults to the task's actor, then the
    /// source's creator).
    pub actor: String,
    /// Optional caller-chosen run id.
    pub run_id: String,
    pub agent: String,
    pub provider: String,
    pub model: String,
}

/// The weakest isolation a Charter accepts (unset is the weakest).
fn floor(c: &Charter) -> IsolationLevel {
    c.isolation
        .minimum_level()
        .unwrap_or(IsolationLevel::Process)
}

/// Refuses a fork Charter that is less contained than the source's:
/// a weaker isolation floor, open egress where the source denies by
/// default, cooperative instead of strict enforcement, or any allow rule
/// or endpoint the source does not have.
pub(crate) fn check_no_widening(src: &Charter, dst: &Charter) -> Result<()> {
    if floor(dst) < floor(src) {
        return Err(Error::forbidden(format!(
            "fork charter {:?} has a weaker isolation floor ({}) than the source ({})",
            dst.name,
            floor(dst).as_str(),
            floor(src).as_str()
        )));
    }
    let (s, d) = (&src.network, &dst.network);
    if s.deny_by_default() {
        if !d.deny_by_default() {
            return Err(Error::forbidden(format!(
                "fork charter {:?} allows egress by default; the source denies it",
                dst.name
            )));
        }
        if s.strict_egress() && !d.strict_egress() {
            return Err(Error::forbidden(format!(
                "fork charter {:?} does not enforce egress strictly like the source",
                dst.name
            )));
        }
        let allowed = |r: &runeward_charter::NetworkRule| r.verdict == "allow";
        if let Some(r) = d
            .rules
            .iter()
            .filter(|r| allowed(r))
            .find(|r| !s.rules.contains(r))
        {
            return Err(Error::forbidden(format!(
                "fork charter {:?} allows egress to {} that the source does not",
                dst.name,
                if r.hostname.is_empty() {
                    &r.cidr
                } else {
                    &r.hostname
                }
            )));
        }
    }
    let port = |p: u16| if p == 0 { 443 } else { p };
    for e in &dst.endpoints {
        if !src
            .endpoints
            .iter()
            .any(|x| x.host == e.host && port(x.port) == port(e.port))
        {
            return Err(Error::forbidden(format!(
                "fork charter {:?} adds endpoint {}:{} that the source does not have",
                dst.name,
                e.host,
                port(e.port)
            )));
        }
    }
    Ok(())
}

impl Manager {
    /// Copies a Citadel's workspace into a new, independent Citadel (see
    /// the module docs). The fork belongs to the source's tenant.
    pub async fn fork_citadel(&self, id: &str, opts: ForkOptions) -> Result<Sandbox> {
        let src = self.awake_session(id).await?;
        let actor = if opts.actor.trim().is_empty() {
            actor_or(&src.actor)
        } else {
            opts.actor.trim().to_owned()
        };
        let target = if opts.profile.trim().is_empty() {
            src.charter.name.clone()
        } else {
            opts.profile.trim().to_owned()
        };
        let dec = src
            .engine
            .evaluate(&Action::new("citadel", "fork").with_args(vec![target.clone()]));
        if dec.verdict != Verdict::Allow {
            let reason = or_reason(&dec.reason, "fork denied by policy");
            self.record(&src, "citadel", "fork", &[target], "deny", -1, 0, &reason)
                .await;
            return Err(Error::forbidden(reason));
        }
        let c = self.load_profile(&target).await?;
        if !opts.admin {
            if let Err(e) = check_no_widening(&src.charter, &c) {
                self.record(
                    &src,
                    "citadel",
                    "fork",
                    &[target],
                    "deny",
                    -1,
                    0,
                    &e.to_string(),
                )
                .await;
                return Err(e);
            }
            if let Some(r) = opts.resources {
                let base = runeward_backend::resources_from_limits(&src.charter.limits);
                let over = |want: i64, have: i64| have > 0 && want > have;
                if over(r.nano_cpus, base.nano_cpus) || over(r.memory_bytes, base.memory_bytes) {
                    return Err(Error::forbidden(
                        "fork resources may not exceed the source Charter's limits",
                    ));
                }
            }
        }
        let mut snap = src
            .backend
            .snapshot(id, &format!("fork-of-{id}"))
            .await
            .map_err(|e| Error::other(format!("snapshot source workspace: {e}")))?;
        snap.profile.clone_from(&c.name);
        let ident = LaunchIdentity {
            owner: src.owner.clone(),
            actor: actor.clone(),
            run_id: opts.run_id.trim().to_owned(),
            forked_from: src.run_id.clone(),
            agent: opts.agent,
            provider: opts.provider,
            model: opts.model,
            resources: opts.resources.filter(|r| *r != Resources::default()),
        };
        let restored = self.restore_into(c, &snap, ident).await;
        // The tarball was only a transport for the copy.
        if !snap.location.is_empty() {
            let _ = tokio::fs::remove_file(&snap.location).await;
        }
        let fork = restored?;
        let new_id = fork.sandbox.id.clone();
        self.record(
            &src,
            "citadel",
            "fork",
            std::slice::from_ref(&new_id),
            Verdict::Allow.as_str(),
            0,
            0,
            &format!("forked to {new_id}"),
        )
        .await;
        self.record(
            &fork,
            "citadel",
            "fork",
            &[id.to_owned()],
            Verdict::Allow.as_str(),
            0,
            0,
            &format!("forked from {id} (run {})", src.run_id),
        )
        .await;
        Ok(fork.sandbox.clone())
    }
}

#[cfg(test)]
mod tests {
    use runeward_charter::{Endpoint, Isolation, Network, NetworkRule};

    use super::*;

    fn charter(name: &str) -> Charter {
        Charter {
            name: name.into(),
            ..Charter::default()
        }
    }

    fn allow(host: &str) -> NetworkRule {
        NetworkRule {
            verdict: "allow".into(),
            hostname: host.into(),
            cidr: String::new(),
        }
    }

    #[test]
    fn forks_may_narrow_but_not_widen() {
        let mut src = charter("src");
        src.isolation = Isolation {
            minimum: "kernel".into(),
        };
        src.network = Network {
            default: "deny".into(),
            rules: vec![allow("api.example.com"), allow("pypi.org")],
            enforce: String::new(),
        };
        src.endpoints = vec![Endpoint {
            host: "api.example.com".into(),
            ..Endpoint::default()
        }];

        let mut same = src.clone();
        same.name = "same".into();
        assert!(check_no_widening(&src, &same).is_ok());

        let mut narrower = same.clone();
        narrower.network.rules = vec![allow("pypi.org")];
        narrower.endpoints.clear();
        narrower.isolation.minimum = "vm".into();
        assert!(check_no_widening(&src, &narrower).is_ok());

        let mut weaker = same.clone();
        weaker.isolation.minimum = "container".into();
        assert!(matches!(
            check_no_widening(&src, &weaker),
            Err(Error::Forbidden(_))
        ));

        let mut open = same.clone();
        open.network.default = "allow".into();
        assert!(check_no_widening(&src, &open).is_err());

        let mut wider = same.clone();
        wider.network.rules.push(allow("evil.example"));
        let err = check_no_widening(&src, &wider).expect_err("wider");
        assert!(err.to_string().contains("evil.example"), "{err}");

        let mut more_endpoints = same.clone();
        more_endpoints.endpoints.push(Endpoint {
            host: "other.example".into(),
            ..Endpoint::default()
        });
        assert!(check_no_widening(&src, &more_endpoints).is_err());

        // An open source puts no egress constraint on the fork.
        let mut open_src = charter("open");
        open_src.isolation = src.isolation.clone();
        open_src.endpoints = src.endpoints.clone();
        assert!(check_no_widening(&open_src, &wider).is_ok());
    }
}
