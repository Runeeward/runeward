//! The Linux supervisor: confinement, launch, reaping and signal forwarding.

pub mod identity;
pub mod landlock;
pub mod seccomp;

use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::errno::Errno;
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::sys::{prctl, ptrace};
use nix::unistd::{Pid, getpid};

use crate::config::{ENV_PREFIX, SupervisorConfig};
use crate::report::Report;
use crate::{EXIT_INTERNAL, EXIT_REFUSED, EXIT_SPAWN, Invocation, Mode};

use identity::Identity;

/// Where report lines go.
struct Sink {
    file: Option<File>,
    stderr: bool,
}

impl Sink {
    fn open(cfg: &SupervisorConfig) -> Result<Self, String> {
        let file = if cfg.report_path.is_empty() {
            None
        } else {
            let path = Path::new(&cfg.report_path);
            if let Some(dir) = path.parent() {
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(dir)
                    .map_err(|e| format!("create report directory {}: {e}", dir.display()))?;
            }
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| format!("open report file {}: {e}", path.display()))?,
            )
        };
        Ok(Self {
            file,
            stderr: cfg.report_stderr,
        })
    }

    fn write(&mut self, r: &Report) {
        let line = r.to_line();
        if let Some(f) = &mut self.file {
            let _ = f.write_all(line.as_bytes()).and_then(|()| f.flush());
        }
        if self.stderr || self.file.is_none() && !r.ok {
            eprint!("runeward-supervisor: {line}");
        }
    }
}

fn say(msg: &str) {
    eprintln!("runeward-supervisor: {msg}");
}

/// Signals PID 1 forwards to the agent (plus SIGCHLD, which it handles).
/// Synchronous fault signals, terminal job-control stops and SIGKILL/SIGSTOP
/// (which cannot be caught) are left alone.
fn forwarded() -> SigSet {
    // Only the standard signals: glibc reserves some real-time ones.
    let mut set = SigSet::empty();
    for s in Signal::iterator() {
        set.add(s);
    }
    for s in [
        Signal::SIGKILL,
        Signal::SIGSTOP,
        Signal::SIGSEGV,
        Signal::SIGBUS,
        Signal::SIGFPE,
        Signal::SIGILL,
        Signal::SIGTRAP,
        Signal::SIGSYS,
        Signal::SIGABRT,
        Signal::SIGTTIN,
        Signal::SIGTTOU,
    ] {
        set.remove(s);
    }
    set
}

/// Runs the supervisor and returns the process exit code.
pub fn run(inv: Invocation) -> i32 {
    let Invocation {
        mode,
        config: cfg,
        config_path,
    } = inv;

    let mut sink = match Sink::open(&cfg) {
        Ok(s) => s,
        Err(e) => {
            say(&format!("refusing to start: {e}"));
            return EXIT_REFUSED;
        }
    };
    let mut report = Report {
        mode: match mode {
            Mode::Init => "init",
            Mode::Exec => "exec",
        }
        .into(),
        pid1: getpid() == Pid::from_raw(1),
        argv0: cfg.argv.first().cloned().unwrap_or_default(),
        ..Report::default()
    };

    // Block forwarded signals before anything else, so none is lost or
    // acts on the supervisor between here and the wait loop. The agent's
    // copy is unblocked again in the child (see `unblock_in_child`).
    let signals = forwarded();
    if mode == Mode::Init
        && let Err(e) = signals.thread_block()
    {
        report.error = Some(format!("block signals: {e}"));
        sink.write(&report);
        return EXIT_INTERNAL;
    }

    let id = match confine(&cfg, mode, config_path.as_deref(), &mut report) {
        Ok(id) => id,
        Err(e) => {
            say(&format!("refusing to start the agent: {e}"));
            report.error = Some(e);
            sink.write(&report);
            return EXIT_REFUSED;
        }
    };

    let mut cmd = command(&cfg, id.as_ref());
    match mode {
        Mode::Exec => {
            report.ok = true;
            report.agent_pid = Some(std::process::id());
            sink.write(&report);
            let err = cmd.exec();
            report.ok = false;
            report.error = Some(format!("exec {}: {err}", report.argv0));
            say(report.error.as_deref().unwrap_or_default());
            sink.write(&report);
            EXIT_SPAWN
        }
        Mode::Init => match unblock_in_child(&mut cmd, signals).spawn() {
            Err(e) => {
                report.error = Some(format!("start {}: {e}", report.argv0));
                say(report.error.as_deref().unwrap_or_default());
                sink.write(&report);
                EXIT_SPAWN
            }
            Ok(child) => {
                let pid = Pid::from_raw(child.id().cast_signed());
                report.ok = true;
                report.agent_pid = Some(child.id());
                sink.write(&report);
                // The child is reaped through waitpid below, not Child::wait.
                drop(child);
                supervise(pid, &signals)
            }
        },
    }
}

/// Applies every layer in order and fills in the report. On success the
/// calling thread is confined exactly as the agent will be.
fn confine(
    cfg: &SupervisorConfig,
    mode: Mode,
    config_path: Option<&Path>,
    report: &mut Report,
) -> Result<Option<Identity>, String> {
    let protected = cfg.protected(config_path);
    report.protected_paths = protected.iter().map(|p| p.display().to_string()).collect();
    let write_protected: Vec<PathBuf> = std::env::current_exe().into_iter().collect();
    cfg.check_protected(&protected, &write_protected)
        .map_err(|e| e.to_string())?;

    // Resolve the identity while /etc/passwd is still visible.
    let id = identity::resolve(&cfg.process)?;

    if mode == Mode::Init {
        // Adopt orphans even when not PID 1 (PID 1 adopts them anyway).
        prctl::set_child_subreaper(true).map_err(|e| format!("set child subreaper: {e}"))?;
    }
    prctl::set_no_new_privs().map_err(|e| format!("set no_new_privs: {e}"))?;

    report.landlock = landlock::apply(&cfg.filesystem)?;
    report.protected_by_landlock = report.landlock.status == "enforced";

    identity::drop_privileges(id.as_ref())?;

    if cfg.seccomp {
        report.seccomp = seccomp::apply()?;
    }

    // Keep the agent (same uid) from reading this process's memory through
    // /proc. Changing uid already reset it; make it explicit.
    prctl::set_dumpable(false).map_err(|e| format!("clear dumpable: {e}"))?;

    report.no_new_privs = prctl::get_no_new_privs().unwrap_or(false);
    let (uid, gid, groups) = identity::current();
    report.uid = Some(uid);
    report.gid = Some(gid);
    report.groups = groups;
    report.capabilities = identity::caps_report();
    Ok(id)
}

/// Builds the agent command: argv, environment and working directory.
fn command(cfg: &SupervisorConfig, id: Option<&Identity>) -> Command {
    let mut cmd = Command::new(&cfg.argv[0]);
    cmd.args(&cfg.argv[1..]);
    if cfg.inherit_env {
        let ours: Vec<OsString> = std::env::vars_os()
            .map(|(k, _)| k)
            .filter(|k| k.to_string_lossy().starts_with(ENV_PREFIX))
            .collect();
        for k in ours {
            cmd.env_remove(k);
        }
    } else {
        cmd.env_clear();
    }
    if let Some(id) = id {
        if let Some(home) = &id.home {
            cmd.env("HOME", home);
        }
        if let Some(name) = &id.name {
            cmd.env("USER", name).env("LOGNAME", name);
        }
    }
    cmd.envs(&cfg.env);
    if !cfg.workdir.is_empty() {
        cmd.current_dir(&cfg.workdir);
    }
    cmd
}

/// Unblocks `signals` in the agent between fork and exec. The signal mask
/// survives exec, and std does not reset it, so without this the agent
/// would start with every forwarded signal blocked.
///
/// This is the crate's only `unsafe`: `pre_exec` is unsafe because the
/// closure runs in the forked child, where only async-signal-safe work is
/// allowed.
#[allow(unsafe_code)]
fn unblock_in_child(cmd: &mut Command, signals: SigSet) -> &mut Command {
    // SAFETY: the closure only calls pthread_sigmask (async-signal-safe) on a
    // `Copy` SigSet captured by value. It allocates nothing, takes no locks
    // and touches no state shared with the parent; the Errno-to-io::Error
    // conversion stores the raw code without allocating.
    unsafe { cmd.pre_exec(move || signals.thread_unblock().map_err(std::io::Error::from)) }
}

/// Waits for signals: forwards them to the agent and reaps children until
/// the agent exits, then returns its exit code (128 + signal when killed).
fn supervise(agent: Pid, signals: &SigSet) -> i32 {
    loop {
        let sig = match signals.wait() {
            Ok(s) => s,
            Err(e) => {
                say(&format!("wait for signals: {e}"));
                return EXIT_INTERNAL;
            }
        };
        if sig == Signal::SIGCHLD {
            if let Some(code) = reap(agent) {
                return code;
            }
        } else if let Err(e) = kill(agent, sig)
            && e != Errno::ESRCH
        {
            say(&format!("forward {sig} to agent: {e}"));
        }
    }
}

/// Reaps every exited child. Returns the agent's exit code once it is gone.
fn reap(agent: Pid) -> Option<i32> {
    let mut agent_code = None;
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) if pid == agent => agent_code = Some(code),
            Ok(WaitStatus::Signaled(pid, sig, _)) if pid == agent => {
                agent_code = Some(128 + sig as i32);
            }
            // A child that made the supervisor its tracer (PTRACE_TRACEME,
            // possible only with seccomp off) would stay stopped forever:
            // detach and hand the signal back.
            Ok(WaitStatus::Stopped(pid, sig)) => {
                let _ = ptrace::detach(pid, sig);
            }
            Ok(WaitStatus::PtraceEvent(pid, _, _) | WaitStatus::PtraceSyscall(pid)) => {
                let _ = ptrace::detach(pid, None);
            }
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return agent_code,
            Ok(_) => {}
            Err(Errno::EINTR) => {}
            Err(e) => {
                say(&format!("reap children: {e}"));
                return agent_code;
            }
        }
    }
}
