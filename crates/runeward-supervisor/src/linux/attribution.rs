//! The binary attribution helper.
//!
//! `init` starts it before confining itself, when the config has
//! `attribution`: a copy of this binary run as `attribution-helper`, with
//! its settings (including the key) written to its stdin, never put on its
//! command line or in its environment. The helper:
//!
//! 1. pins the listed binaries by file identity, while the image is exactly
//!    as it started;
//! 2. binds the attribution socket, before the agent exists, so the agent
//!    cannot take the name first;
//! 3. drops to the agent's identity (it must share the agent's uid to read
//!    the agent's `/proc/<pid>/fd` without `CAP_SYS_PTRACE`), sets
//!    `no_new_privs`, installs the self-protection seccomp filter and
//!    becomes non-dumpable, so the agent cannot read the key out of it.
//!    It deliberately has no Landlock domain: Landlock only lets a process
//!    inspect processes inside its own domain (or a nested one), and the
//!    agent's domain is a sibling, so a Landlocked helper could not read the
//!    agent's descriptors at all. The same rule keeps a Landlocked agent from
//!    inspecting the helper;
//! 4. prints one `ready <json>` line and answers queries until it dies.
//!
//! The agent can kill the helper (same uid). That only makes every
//! binary-restricted endpoint refuse, since the broker treats a missing
//! answer as an unknown binary.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::sys::prctl;
use nix::sys::signal::{SigSet, Signal};
use nix::unistd::getppid;
use runeward_attribution::binaries::BinarySet;
use runeward_attribution::procfs::ProcFs;
use runeward_attribution::{Key, server};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use super::{identity, seccomp};
use crate::config::{AttributionConfig, ProcessConfig};
use crate::report::AttributionReport;

/// How long `init` waits for the helper to report ready.
pub const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest settings document the helper reads from stdin.
const MAX_INPUT: u64 = 1 << 20;

/// What `init` hands the helper on stdin.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperInput {
    attribution: AttributionConfig,
    process: ProcessConfig,
}

/// Starts the helper and waits until it answers on its socket. Returns what
/// it reported; any failure means the agent must not start.
pub fn start(
    cfg: &AttributionConfig,
    process: &ProcessConfig,
) -> Result<AttributionReport, String> {
    let exe = std::env::current_exe().map_err(|e| format!("attribution: locate self: {e}"))?;
    let mut child = Command::new(exe)
        .arg(crate::ATTRIBUTION_HELPER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("attribution: start helper: {e}"))?;
    let input = Zeroizing::new(
        serde_json::to_vec(&HelperInput {
            attribution: cfg.clone(),
            process: process.clone(),
        })
        .unwrap_or_default(),
    );
    let fed = child
        .stdin
        .take()
        .ok_or_else(|| "attribution: helper stdin".to_owned())
        .and_then(|mut s| {
            s.write_all(&input)
                .map_err(|e| format!("attribution: feed helper: {e}"))
        });
    let stdout = child.stdout.take();
    let line = fed.and_then(|()| {
        let out = stdout.ok_or_else(|| "attribution: helper stdout".to_owned())?;
        // Read the ready line on a short-lived thread so a hung helper can
        // be timed out; it is joined before returning, so the supervisor is
        // single-threaded again when it confines itself.
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(out).read_line(&mut line);
            let _ = tx.send(line);
        });
        let got = rx.recv_timeout(READY_TIMEOUT);
        if got.is_err() {
            let _ = child.kill();
        }
        let _ = reader.join();
        got.map_err(|_| "attribution: the helper did not report ready in time".to_owned())
    });
    let parsed = line.and_then(|l| {
        l.trim()
            .strip_prefix("ready ")
            .and_then(|j| serde_json::from_str::<AttributionReport>(j).ok())
            .ok_or_else(|| "attribution: the helper failed to start (see its stderr)".to_owned())
    });
    match parsed {
        Ok(r) => Ok(r),
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(e)
        }
    }
}

/// The helper's entry point; returns an exit code only on failure.
pub fn helper_main() -> i32 {
    match helper() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("runeward-supervisor: attribution helper: {e}");
            crate::EXIT_REFUSED
        }
    }
}

fn helper() -> Result<(), String> {
    let parent = getppid();
    // The mask is inherited from init, which blocks what it forwards.
    let _ = SigSet::all().thread_unblock();

    let mut buf = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(MAX_INPUT)
        .read_to_end(&mut buf)
        .map_err(|e| format!("read settings: {e}"))?;
    let mut input: HelperInput =
        serde_json::from_slice(&buf).map_err(|e| format!("settings are not valid JSON: {e}"))?;
    drop(buf);
    let key = Key::from_hex(&input.attribution.key).map_err(|e| e.to_string())?;
    input.attribution.key.zeroize();
    let a = &input.attribution;
    let binaries = BinarySet::snapshot(&a.binaries);
    let listener = server::bind(&a.socket).map_err(|e| e.to_string())?;

    let id = identity::resolve(&input.process)?;
    prctl::set_no_new_privs().map_err(|e| format!("set no_new_privs: {e}"))?;
    identity::drop_privileges(id.as_ref())?;
    seccomp::apply()?;
    prctl::set_dumpable(false).map_err(|e| format!("clear dumpable: {e}"))?;
    // Set after the identity switch, which clears it; then make sure init
    // did not die in between.
    prctl::set_pdeathsig(Signal::SIGKILL).map_err(|e| format!("set pdeathsig: {e}"))?;
    if getppid() != parent {
        return Err("the supervisor exited".into());
    }

    let proc = ProcFs::new(
        "/proc",
        [
            std::process::id(),
            u32::try_from(parent.as_raw()).unwrap_or(0),
        ],
    );
    let report = AttributionReport {
        status: "enforced".into(),
        socket: a.socket.clone(),
        pid: Some(std::process::id()),
        pinned: binaries.pinned(),
        missing: binaries.missing().to_vec(),
    };
    {
        let mut out = std::io::stdout().lock();
        writeln!(
            out,
            "ready {}",
            serde_json::to_string(&report).unwrap_or_default()
        )
        .and_then(|()| out.flush())
        .map_err(|e| format!("report ready: {e}"))?;
    }
    server::serve(&listener, &key, &proc, &binaries).map_err(|e| format!("serve: {e}"))
}
