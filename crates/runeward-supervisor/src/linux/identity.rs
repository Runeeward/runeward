//! Resolving and switching to the agent's identity, and clearing
//! capabilities.

use std::path::PathBuf;

use caps::CapSet;
use nix::unistd::{Gid, Group, Uid, User, getgroups, getresgid, getresuid, setgroups};
use nix::unistd::{setresgid, setresuid};

use crate::config::ProcessConfig;
use crate::report::CapsReport;

/// The identity the agent will run as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub uid: Uid,
    pub gid: Gid,
    /// From the passwd entry, when there is one.
    pub name: Option<String>,
    pub home: Option<PathBuf>,
}

fn numeric(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Resolves the configured identity against the sandbox's user database.
/// Returns `None` when no user is configured. Must run before Landlock
/// hides `/etc/passwd`.
pub fn resolve(p: &ProcessConfig) -> Result<Option<Identity>, String> {
    let user = p.user.trim();
    if user.is_empty() {
        if !p.group.trim().is_empty() {
            return Err("process.group is set without process.user".into());
        }
        return Ok(None);
    }
    let (uid, entry) = match numeric(user) {
        Some(n) => {
            let uid = Uid::from_raw(n);
            let entry = User::from_uid(uid).map_err(|e| format!("look up uid {n}: {e}"))?;
            (uid, entry)
        }
        None => {
            let entry = User::from_name(user)
                .map_err(|e| format!("look up user {user:?}: {e}"))?
                .ok_or_else(|| format!("process.user {user:?} does not exist in the sandbox"))?;
            (entry.uid, Some(entry))
        }
    };

    let group = p.group.trim();
    let gid = if group.is_empty() {
        entry
            .as_ref()
            .map_or_else(|| Gid::from_raw(uid.as_raw()), |e| e.gid)
    } else if let Some(n) = numeric(group) {
        Gid::from_raw(n)
    } else {
        Group::from_name(group)
            .map_err(|e| format!("look up group {group:?}: {e}"))?
            .ok_or_else(|| format!("process.group {group:?} does not exist in the sandbox"))?
            .gid
    };

    if uid.is_root() {
        return Err(
            "process.user resolves to uid 0; running the agent as root is not allowed".into(),
        );
    }
    if gid.as_raw() == 0 {
        return Err(
            "process.group resolves to gid 0; running the agent as root is not allowed".into(),
        );
    }
    Ok(Some(Identity {
        uid,
        gid,
        name: entry.as_ref().map(|e| e.name.clone()),
        home: entry.map(|e| e.dir),
    }))
}

/// Drops the bounding set (when privileged), switches uid/gid/groups, clears
/// the inheritable and ambient sets, and verifies the result. Refuses to
/// leave the process running as root.
pub fn drop_privileges(id: Option<&Identity>) -> Result<(), String> {
    let ruid = getresuid().map_err(|e| format!("getresuid: {e}"))?;
    let privileged = ruid.effective.is_root();

    if privileged {
        let Some(id) = id else {
            return Err("the supervisor runs as root and no process.user is configured; refusing to run the agent as root".into());
        };
        // Best effort: without CAP_SETPCAP the bounding set stays, which
        // no_new_privs already makes harmless. The report shows what is left.
        let _ = caps::clear(None, CapSet::Bounding);
        setgroups(&[id.gid]).map_err(|e| format!("setgroups: {e}"))?;
        setresgid(id.gid, id.gid, id.gid).map_err(|e| format!("setresgid: {e}"))?;
        setresuid(id.uid, id.uid, id.uid).map_err(|e| format!("setresuid: {e}"))?;
    } else if let Some(id) = id {
        let rgid = getresgid().map_err(|e| format!("getresgid: {e}"))?;
        let same_uid = [ruid.real, ruid.effective, ruid.saved]
            .iter()
            .all(|u| *u == id.uid);
        let same_gid = [rgid.real, rgid.effective, rgid.saved]
            .iter()
            .all(|g| *g == id.gid);
        if !(same_uid && same_gid) {
            return Err(format!(
                "cannot switch to uid {} gid {}: the supervisor is not root",
                id.uid, id.gid
            ));
        }
    }

    for set in [
        CapSet::Ambient,
        CapSet::Inheritable,
        CapSet::Effective,
        CapSet::Permitted,
    ] {
        caps::clear(None, set).map_err(|e| format!("clear {set:?} capabilities: {e}"))?;
    }

    let after = getresuid().map_err(|e| format!("getresuid: {e}"))?;
    let gids = getresgid().map_err(|e| format!("getresgid: {e}"))?;
    if [after.real, after.effective, after.saved]
        .iter()
        .any(|u| u.is_root())
        || [gids.real, gids.effective, gids.saved]
            .iter()
            .any(|g| g.as_raw() == 0)
    {
        return Err("still running as root after the identity switch".into());
    }
    if let Some(id) = id
        && (after.effective != id.uid || gids.effective != id.gid)
    {
        return Err(format!(
            "identity switch did not take effect (uid {} gid {})",
            after.effective, gids.effective
        ));
    }
    Ok(())
}

/// The current uid, gid and supplementary groups.
pub fn current() -> (u32, u32, Vec<u32>) {
    let groups = getgroups()
        .map(|g| g.into_iter().map(Gid::as_raw).collect())
        .unwrap_or_default();
    (Uid::effective().as_raw(), Gid::effective().as_raw(), groups)
}

/// The capability sets of the calling thread.
pub fn caps_report() -> CapsReport {
    let read = |set| {
        let mut v: Vec<String> = caps::read(None, set)
            .map(|s| s.iter().map(|c| c.to_string().to_lowercase()).collect())
            .unwrap_or_else(|_| vec!["<unreadable>".to_owned()]);
        v.sort();
        v
    };
    CapsReport {
        effective: read(CapSet::Effective),
        permitted: read(CapSet::Permitted),
        inheritable: read(CapSet::Inheritable),
        ambient: read(CapSet::Ambient),
        bounding: read(CapSet::Bounding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_parsing() {
        assert_eq!(numeric("1500"), Some(1500));
        assert_eq!(numeric("-1"), None);
        assert_eq!(numeric(""), None);
        assert_eq!(numeric("bob"), None);
    }

    #[test]
    fn resolves_numeric_ids_without_passwd_entries() {
        let id = resolve(&ProcessConfig {
            user: "4242424".into(),
            group: String::new(),
        })
        .expect("resolve")
        .expect("some");
        assert_eq!(id.uid.as_raw(), 4_242_424);
        assert_eq!(id.gid.as_raw(), 4_242_424, "gid defaults to the uid");
        assert!(id.home.is_none());
    }

    #[test]
    fn refuses_root_and_unknown_names() {
        for (user, group) in [("root", ""), ("1500", "0"), ("no-such-user-xyz", "")] {
            let p = ProcessConfig {
                user: user.into(),
                group: group.into(),
            };
            assert!(resolve(&p).is_err(), "{user}:{group}");
        }
        let p = ProcessConfig {
            user: String::new(),
            group: "1500".into(),
        };
        assert!(resolve(&p).is_err());
        assert_eq!(resolve(&ProcessConfig::default()), Ok(None));
    }
}
