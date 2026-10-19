//! Small path helpers with Go semantics.

use std::path::{Path, PathBuf};

/// Go's `path.Clean`: the shortest lexically equivalent slash path.
pub(crate) fn clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// Go's `path.Dir`.
pub(crate) fn dir(p: &str) -> String {
    let d = match p.rfind('/') {
        Some(i) => &p[..=i],
        None => "",
    };
    clean(d)
}

/// Expands a leading `~/` to the user's home directory.
pub fn expand_home(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/")
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest);
    }
    PathBuf::from(p)
}

/// Go's `os.UserCacheDir`, falling back to the temp dir like the Go backend.
pub(crate) fn user_cache_dir() -> PathBuf {
    let home = std::env::home_dir().filter(|h| !h.as_os_str().is_empty());
    if cfg!(target_os = "macos") {
        if let Some(h) = home {
            return h.join("Library").join("Caches");
        }
    } else {
        if let Some(x) = std::env::var_os("XDG_CACHE_HOME")
            && Path::new(&x).is_absolute()
        {
            return PathBuf::from(x);
        }
        if let Some(h) = home {
            return h.join(".cache");
        }
    }
    std::env::temp_dir()
}

/// The directory snapshots are written to.
pub(crate) fn snapshot_dir() -> PathBuf {
    user_cache_dir().join("runeward").join("snapshots")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_matches_go() {
        for (input, want) in [
            ("", "."),
            (".", "."),
            ("a/b", "a/b"),
            ("a//b/", "a/b"),
            ("./x", "x"),
            ("..", ".."),
            ("../a", "../a"),
            ("a/../../b", "../b"),
            ("a/../b", "b"),
            ("/../a", "/a"),
            ("/", "/"),
            ("/a/./b/../c", "/a/c"),
        ] {
            assert_eq!(clean(input), want, "{input:?}");
        }
    }

    #[test]
    fn dir_matches_go() {
        for (input, want) in [
            ("/root/.gitconfig", "/root"),
            ("notes/a.txt", "notes"),
            ("top.txt", "."),
            ("/x", "/"),
            ("a/b/", "a/b"),
        ] {
            assert_eq!(dir(input), want, "{input:?}");
        }
    }

    #[test]
    fn expand_home_only_expands_tilde_slash() {
        assert_eq!(expand_home("/abs"), PathBuf::from("/abs"));
        assert_eq!(expand_home("~user/x"), PathBuf::from("~user/x"));
        if let Some(h) = std::env::home_dir() {
            assert_eq!(expand_home("~/x"), h.join("x"));
        }
    }
}
