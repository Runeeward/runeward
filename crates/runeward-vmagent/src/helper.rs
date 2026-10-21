//! The agent's helper modes, run in a child process:
//!
//! - `__run --uid U --gid G --groups a,b --cwd DIR -- argv...` switches to
//!   the identity, enters `DIR` and executes argv (status 127 when it is
//!   not found, 126 when it cannot run, as container engines report);
//! - `__file --uid U --gid G --groups a,b --action A --mode M -- PATH`
//!   switches identity and performs a file operation (see
//!   [`crate::fileops`]), printing a JSON result or streaming on stdout.
//!
//! Switching identity first means everything the helper touches is
//! checked with the sandbox user's permissions, never the agent's root.

use std::ffi::CString;
use std::io::{self, Write};
use std::path::Path;

use nix::unistd::{Gid, Uid};

use crate::users::Identity;

/// The identity flags for a helper invocation.
pub fn identity_args(id: &Identity) -> Vec<String> {
    let groups: Vec<String> = id.groups.iter().map(u32::to_string).collect();
    vec![
        "--uid".into(),
        id.uid.to_string(),
        "--gid".into(),
        id.gid.to_string(),
        "--groups".into(),
        groups.join(","),
    ]
}

/// Parsed helper flags.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HelperArgs {
    /// Target uid.
    pub uid: Option<u32>,
    /// Target gid.
    pub gid: Option<u32>,
    /// Supplementary groups.
    pub groups: Vec<u32>,
    /// Working directory (`__run`).
    pub cwd: String,
    /// File action (`__file`).
    pub action: String,
    /// File mode (`__file`).
    pub mode: u32,
    /// Everything after `--`.
    pub rest: Vec<String>,
}

/// Parses the flags after the mode word.
pub fn parse(args: &[String]) -> Result<HelperArgs, String> {
    let mut out = HelperArgs::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        match a.as_str() {
            "--" => {
                out.rest = it.cloned().collect();
                break;
            }
            "--uid" => out.uid = Some(val()?.parse().map_err(|e| format!("--uid: {e}"))?),
            "--gid" => out.gid = Some(val()?.parse().map_err(|e| format!("--gid: {e}"))?),
            "--groups" => {
                out.groups = val()?
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse().map_err(|e| format!("--groups: {e}")))
                    .collect::<Result<_, _>>()?;
            }
            "--cwd" => out.cwd = val()?,
            "--action" => out.action = val()?,
            "--mode" => out.mode = val()?.parse().map_err(|e| format!("--mode: {e}"))?,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    Ok(out)
}

/// Drops to the requested identity (groups, then gid, then uid). A
/// non-root caller may only "switch" to itself.
fn switch(a: &HelperArgs) -> Result<(), String> {
    let (Some(uid), Some(gid)) = (a.uid, a.gid) else {
        return Ok(());
    };
    if !nix::unistd::geteuid().is_root() {
        if nix::unistd::geteuid().as_raw() == uid {
            return Ok(());
        }
        return Err(format!("cannot switch to uid {uid}: the agent is not root"));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let groups: Vec<Gid> = a.groups.iter().map(|g| Gid::from_raw(*g)).collect();
        nix::unistd::setgroups(&groups).map_err(|e| format!("setgroups: {e}"))?;
    }
    nix::unistd::setgid(Gid::from_raw(gid)).map_err(|e| format!("setgid {gid}: {e}"))?;
    nix::unistd::setuid(Uid::from_raw(uid)).map_err(|e| format!("setuid {uid}: {e}"))?;
    Ok(())
}

/// `__run`: never returns on success.
pub fn run(args: &[String]) -> i32 {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("runeward-vmagent: {e}");
            return 126;
        }
    };
    if a.rest.is_empty() {
        eprintln!("runeward-vmagent: no command");
        return 126;
    }
    if let Err(e) = switch(&a) {
        eprintln!("runeward-vmagent: {e}");
        return 126;
    }
    if !a.cwd.is_empty()
        && let Err(e) = std::env::set_current_dir(&a.cwd)
    {
        eprintln!("runeward-vmagent: chdir to cwd ({:?}): {e}", a.cwd);
        return 126;
    }
    let argv: Result<Vec<CString>, _> = a.rest.iter().map(|s| CString::new(s.as_bytes())).collect();
    let Ok(argv) = argv else {
        eprintln!("runeward-vmagent: argument contains a NUL byte");
        return 126;
    };
    let err = match nix::unistd::execvp(&argv[0], &argv) {
        Ok(never) => match never {},
        Err(e) => e,
    };
    eprintln!("runeward-vmagent: exec {:?}: {err}", a.rest[0]);
    if err == nix::errno::Errno::ENOENT {
        127
    } else {
        126
    }
}

/// `__file`.
pub fn file(args: &[String]) -> i32 {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let (Some(action), Some(path)) = (crate::server::parse_action(&a.action), a.rest.first())
    else {
        eprintln!("usage: __file --action A [--mode M] -- PATH");
        return 2;
    };
    if let Err(e) = switch(&a) {
        eprintln!("{e}");
        return 1;
    }
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut inp = stdin.lock();
    let mut out = stdout.lock();
    match crate::fileops::run(action, Path::new(path), a.mode, &mut inp, &mut out) {
        Ok(Some(v)) => {
            let _ = writeln!(out, "{v}");
            let _ = out.flush();
            0
        }
        Ok(None) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_helper_flags() {
        let args: Vec<String> = [
            "--uid", "1500", "--gid", "50", "--groups", "50,1500", "--cwd", "/w", "--", "ls", "-l",
        ]
        .map(String::from)
        .to_vec();
        let a = parse(&args).expect("parse");
        assert_eq!(a.uid, Some(1500));
        assert_eq!(a.gid, Some(50));
        assert_eq!(a.groups, vec![50, 1500]);
        assert_eq!(a.cwd, "/w");
        assert_eq!(a.rest, vec!["ls", "-l"]);
        assert!(parse(&["--uid".into()]).is_err());
        assert!(parse(&["--bogus".into()]).is_err());
        let id = Identity {
            uid: 1,
            gid: 2,
            groups: vec![2, 3],
            home: "/".into(),
            name: "x".into(),
        };
        let back = parse(&identity_args(&id)).expect("round trip");
        assert_eq!(
            (back.uid, back.gid, back.groups),
            (Some(1), Some(2), vec![2, 3])
        );
    }
}
