//! Resolving `uid[:gid]` and `name[:group]` identities against the guest's
//! `/etc/passwd` and `/etc/group`, as a container engine does for `-u`.

use std::path::Path;

/// A resolved identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// User id.
    pub uid: u32,
    /// Primary group id.
    pub gid: u32,
    /// Supplementary groups (from `/etc/group` membership).
    pub groups: Vec<u32>,
    /// Home directory (`/` when unknown).
    pub home: String,
    /// User name (the uid when the account is not in `/etc/passwd`).
    pub name: String,
}

impl Identity {
    /// root.
    pub fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
            home: "/root".into(),
            name: "root".into(),
        }
    }
}

#[derive(Debug, Clone)]
struct Passwd {
    name: String,
    uid: u32,
    gid: u32,
    home: String,
}

#[derive(Debug, Clone)]
struct Group {
    name: String,
    gid: u32,
    members: Vec<String>,
}

fn passwd(root: &Path) -> Vec<Passwd> {
    let data = std::fs::read_to_string(root.join("etc/passwd")).unwrap_or_default();
    data.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 6 {
                return None;
            }
            Some(Passwd {
                name: f[0].to_owned(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].to_owned(),
            })
        })
        .collect()
}

fn groups(root: &Path) -> Vec<Group> {
    let data = std::fs::read_to_string(root.join("etc/group")).unwrap_or_default();
    data.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 3 {
                return None;
            }
            Some(Group {
                name: f[0].to_owned(),
                gid: f[2].parse().ok()?,
                members: f
                    .get(3)
                    .map(|m| {
                        m.split(',')
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            })
        })
        .collect()
}

/// Resolves `spec` (`""`, `uid`, `uid:gid`, `name`, `name:group`) against
/// the account files under `root`. Unknown numeric ids are accepted as
/// they are (like Docker); unknown names are an error.
pub fn resolve(spec: &str, root: &Path) -> Result<Identity, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(Identity::root());
    }
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let users = passwd(root);
    let all_groups = groups(root);
    let entry = match user.parse::<u32>() {
        Ok(uid) => users
            .iter()
            .find(|p| p.uid == uid)
            .cloned()
            .or(Some(Passwd {
                name: uid.to_string(),
                uid,
                gid: uid,
                home: "/".into(),
            })),
        Err(_) => users.iter().find(|p| p.name == user).cloned(),
    }
    .ok_or_else(|| format!("unable to find user {user}: no matching entries in passwd file"))?;
    // A bare numeric uid without a passwd entry gets gid 0, as Docker does.
    let known = users.iter().any(|p| p.uid == entry.uid);
    let mut gid = if known { entry.gid } else { 0 };
    if let Some(g) = group.filter(|g| !g.is_empty()) {
        gid = match g.parse::<u32>() {
            Ok(n) => n,
            Err(_) => all_groups
                .iter()
                .find(|x| x.name == g)
                .map(|x| x.gid)
                .ok_or_else(|| {
                    format!("unable to find group {g}: no matching entries in group file")
                })?,
        };
    }
    let mut supplementary: Vec<u32> = all_groups
        .iter()
        .filter(|g| g.members.iter().any(|m| m == &entry.name))
        .map(|g| g.gid)
        .collect();
    if !supplementary.contains(&gid) {
        supplementary.insert(0, gid);
    }
    Ok(Identity {
        uid: entry.uid,
        gid,
        groups: supplementary,
        home: if entry.home.is_empty() {
            "/".into()
        } else {
            entry.home
        },
        name: entry.name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(d.path().join("etc")).expect("etc");
        std::fs::write(
            d.path().join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nagent:x:1500:1500::/home/agent:/bin/sh\n",
        )
        .expect("passwd");
        std::fs::write(
            d.path().join("etc/group"),
            "root:x:0:\nagent:x:1500:\nstaff:x:50:agent,other\n",
        )
        .expect("group");
        d
    }

    #[test]
    fn resolves_names_ids_and_groups() {
        let r = root();
        assert_eq!(resolve("", r.path()).expect("root"), Identity::root());
        let a = resolve("agent", r.path()).expect("agent");
        assert_eq!((a.uid, a.gid, a.home.as_str()), (1500, 1500, "/home/agent"));
        assert_eq!(a.groups, vec![1500, 50]);
        let s = resolve("agent:staff", r.path()).expect("agent:staff");
        assert_eq!(s.gid, 50);
        let n = resolve("4242", r.path()).expect("unknown uid");
        assert_eq!((n.uid, n.gid, n.home.as_str()), (4242, 0, "/"));
        let n = resolve("4242:7", r.path()).expect("uid:gid");
        assert_eq!(n.gid, 7);
        assert!(resolve("nobody-here", r.path()).is_err());
        assert!(resolve("agent:nogroup", r.path()).is_err());
    }
}
