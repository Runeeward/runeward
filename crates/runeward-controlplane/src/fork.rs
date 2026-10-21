//! Forking a Citadel: a new, independent Citadel holding a copy of the
//! source's workspace disk.
//!
//! The source is woken if it sleeps, snapshotted, and the snapshot is
//! restored into a new sandbox with a new run whose `forked_from` names the
//! source run. The fork may use another Charter (and resource caps), but
//! only one provably no broader than the source's
//! ([`runeward_policy::check_subsumption`]) unless an administrator
//! overrides it; the source's policy must allow `citadel`/`fork`. Both
//! Citadels Chronicle the fork, the new one with how its Charter was
//! admitted.

use runeward_backend::{Resources, Sandbox};
use runeward_charter::Verdict;
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
    /// Lets the fork use a Charter that is not provably within the
    /// source's (recorded as `admin-override`). Only for administrators.
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
        let lineage = match runeward_policy::check_subsumption(
            &src.charter,
            &c,
            self.config.policy_default.as_deref(),
        ) {
            Ok(proof) => (proof.method().to_owned(), proof.summary()),
            Err(refusal) if opts.admin => ("admin-override".to_owned(), refusal.to_string()),
            Err(refusal) => {
                let reason = format!(
                    "fork charter {:?} is not provably within source charter {:?}: {refusal}",
                    c.name, src.charter.name
                );
                self.record(&src, "citadel", "fork", &[target], "deny", -1, 0, &reason)
                    .await;
                return Err(Error::forbidden(reason));
            }
        };
        if !opts.admin
            && let Some(r) = opts.resources
        {
            let base = runeward_backend::resources_from_limits(&src.charter.limits);
            let over = |want: i64, have: i64| have > 0 && want > have;
            if over(r.nano_cpus, base.nano_cpus) || over(r.memory_bytes, base.memory_bytes) {
                return Err(Error::forbidden(
                    "fork resources may not exceed the source Charter's limits",
                ));
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
            charter_lineage: lineage.0,
            parent_charter: src.charter.name.clone(),
            charter_proof: lineage.1,
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
    use runeward_charter::{Charter, Endpoint, Isolation, Network, NetworkRule};
    use runeward_policy::check_subsumption;

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

    /// The fork admission rule: narrower Charters pass, wider ones are
    /// refused naming the dimension.
    #[test]
    fn forks_may_narrow_but_not_widen() {
        let check = |src: &Charter, dst: &Charter| check_subsumption(src, dst, None);
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
        assert_eq!(check(&src, &same).expect("same").method(), "subsumed");
        assert_eq!(check(&src, &src).expect("exact").method(), "exact");

        let mut narrower = same.clone();
        narrower.network.rules = vec![allow("pypi.org")];
        narrower.endpoints.clear();
        narrower.isolation.minimum = "vm".into();
        assert!(check(&src, &narrower).is_ok());

        let mut weaker = same.clone();
        weaker.isolation.minimum = "container".into();
        assert_eq!(
            check(&src, &weaker).expect_err("weaker").dimension,
            "isolation"
        );

        let mut open = same.clone();
        open.network.default = "allow".into();
        assert_eq!(check(&src, &open).expect_err("open").dimension, "network");

        let mut wider = same.clone();
        wider.network.rules.push(allow("evil.example"));
        let err = check(&src, &wider).expect_err("wider");
        assert!(err.to_string().contains("evil.example"), "{err}");

        let mut more_endpoints = same.clone();
        more_endpoints.endpoints.push(Endpoint {
            host: "other.example".into(),
            ..Endpoint::default()
        });
        assert!(check(&src, &more_endpoints).is_err());

        // A source with no egress gate at all puts no egress constraint on
        // the fork.
        let mut open_src = charter("open");
        open_src.isolation = src.isolation.clone();
        assert!(check(&open_src, &wider).is_ok());
    }
}
