//! `runeward runtime`: inspect this host for VM-grade isolation runtimes
//! (gVisor's runsc, Kata Containers) registered with Docker and/or
//! Kubernetes, print setup guidance, and install them ([`install`]).
//!
//! Every probe shells out defensively with a timeout; missing tooling is
//! informational, never fatal.

pub mod install;

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::process::Command;

use crate::tabwriter::TabWriter;

/// Bounds every probe so a wedged engine or API server cannot hang it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What one hardened runtime looks like across the inspectable backends.
#[derive(Debug, Clone, Default)]
struct RuntimeStatus {
    name: &'static str,
    docker_handles: &'static [&'static str],
    docker_found: Vec<String>,
    k8s_found: Vec<String>,
}

impl RuntimeStatus {
    fn available(&self) -> bool {
        !self.docker_found.is_empty() || !self.k8s_found.is_empty()
    }
}

/// The output of a bounded shell-out: stdout, or the first line of the
/// failure detail.
pub(crate) async fn probe(
    bin: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<String, String> {
    let child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(timeout, child).await {
        Err(_) => Err("signal: killed".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(out)) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        Ok(Ok(out)) => {
            let detail = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            if detail.is_empty() {
                Err(exit_status_text(&out.status))
            } else {
                Err(detail)
            }
        }
    }
}

/// Go's `*exec.ExitError` text.
fn exit_status_text(status: &std::process::ExitStatus) -> String {
    match status.code() {
        Some(c) => format!("exit status {c}"),
        None => "signal: killed".into(),
    }
}

/// `runeward runtime [check] [--strict]`. A diagnostic, not a gate: it
/// fails only under `--strict` when nothing VM-grade is available.
pub async fn check(strict: bool) -> Result<()> {
    let mut statuses = vec![
        RuntimeStatus {
            name: "gVisor",
            docker_handles: &["runsc"],
            ..RuntimeStatus::default()
        },
        RuntimeStatus {
            name: "Kata",
            docker_handles: &["kata", "kata-runtime", "kata-qemu", "kata-clh"],
            ..RuntimeStatus::default()
        },
    ];
    let mut out = String::new();
    out.push_str("runeward runtime check\n======================\n\n");
    inspect_docker(&mut out, &mut statuses).await;
    out.push('\n');
    inspect_kube(&mut out, &mut statuses).await;
    out.push('\n');

    let mut tw = TabWriter::default();
    tw.push("RUNTIME\tDOCKER\tKUBERNETES\tSTATUS\n");
    let mut any_available = false;
    for s in &statuses {
        any_available |= s.available();
        tw.push(&format!(
            "{}\t{}\t{}\t{}\n",
            s.name,
            join_or_dash(&s.docker_found),
            join_or_dash(&s.k8s_found),
            if s.available() {
                "available"
            } else {
                "missing"
            }
        ));
    }
    tw.flush(&mut out);
    out.push('\n');

    for s in &statuses {
        if !s.available() {
            missing_guidance(&mut out, s.name);
        }
    }
    if any_available {
        out.push_str("At least one VM-grade runtime is available. Set `runtime_class` in a\n");
        out.push_str("Charter's [host] block to use it (see `runeward runtime guide`).\n");
    } else {
        out.push_str("No VM-grade isolation runtime detected. Run `runeward runtime guide`\n");
        out.push_str("for full setup instructions, or see docs/security-model.md.\n");
    }
    std::io::stdout().write_all(out.as_bytes())?;
    if strict && !any_available {
        bail!("no hardened runtime (gVisor/Kata) available");
    }
    Ok(())
}

/// Records which hardened handlers the docker engine has registered.
async fn inspect_docker(out: &mut String, statuses: &mut [RuntimeStatus]) {
    out.push_str("Docker\n------\n");
    let Some(bin) = runeward_backend::look_path("docker") else {
        out.push_str(
            "  docker not found in PATH — skipping (install Docker to inspect its runtimes).\n",
        );
        return;
    };
    let stdout = match probe(
        &bin,
        &["info", "--format", "{{json .Runtimes}}"],
        PROBE_TIMEOUT,
    )
    .await
    {
        Ok(s) => s,
        Err(detail) => {
            let _ = writeln!(
                out,
                "  docker engine not reachable — skipping ({}).",
                first_line(&detail)
            );
            return;
        }
    };
    let runtimes: serde_json::Map<String, serde_json::Value> =
        match serde_json::from_str(stdout.trim()) {
            Ok(m) => m,
            Err(e) => {
                let _ = writeln!(out, "  could not parse docker runtimes — skipping ({e}).");
                return;
            }
        };
    let mut names: Vec<String> = runtimes.keys().cloned().collect();
    names.sort();
    let _ = writeln!(out, "  registered runtimes: {}", join_or_dash(&names));
    for s in statuses.iter_mut() {
        for h in s.docker_handles {
            if names.iter().any(|n| n == h) {
                s.docker_found.push((*h).to_owned());
            }
        }
    }
}

/// Matches RuntimeClasses (via kubectl) against the hardened handlers.
async fn inspect_kube(out: &mut String, statuses: &mut [RuntimeStatus]) {
    out.push_str("Kubernetes\n----------\n");
    let Some(bin) = runeward_backend::look_path("kubectl") else {
        out.push_str(
            "  kubectl not found in PATH — skipping (install kubectl to inspect RuntimeClasses).\n",
        );
        return;
    };
    let stdout = match probe(&bin, &["get", "runtimeclass", "-o", "name"], PROBE_TIMEOUT).await {
        Ok(s) => s,
        Err(detail) => {
            let _ = writeln!(
                out,
                "  cluster not reachable — skipping ({}).",
                first_line(&detail)
            );
            return;
        }
    };
    let mut classes: Vec<String> = stdout
        .trim()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        // `-o name` prints "runtimeclass.node.k8s.io/<name>".
        .map(|l| l.split_once('/').map_or(l, |(_, n)| n).to_owned())
        .collect();
    classes.sort();
    let _ = writeln!(out, "  RuntimeClasses: {}", join_or_dash(&classes));
    // Match on the class name containing a known handler token (the
    // conventional naming); reading each handler would need more calls.
    for s in statuses.iter_mut() {
        for c in &classes {
            let lc = c.to_lowercase();
            if s.docker_handles
                .iter()
                .any(|h| lc == *h || lc.contains(h.trim_end_matches("-runtime")))
                && !s.k8s_found.contains(c)
            {
                s.k8s_found.push(c.clone());
            }
        }
    }
}

fn missing_guidance(out: &mut String, name: &str) {
    match name {
        "gVisor" => out.push_str(concat!(
            "gVisor is not registered. To enable it:\n",
            "  1. Install runsc: https://gvisor.dev/docs/user_guide/install/\n",
            "  2. Docker: add a runtimes entry to /etc/docker/daemon.json, e.g.\n",
            "       { \"runtimes\": { \"runsc\": { \"path\": \"/usr/local/bin/runsc\" } } }\n",
            "     then `sudo systemctl restart docker`.\n",
            "  3. Kubernetes: create a RuntimeClass named `gvisor` (handler: runsc).\n",
            "  4. Point runeward at it: set `runtime_class = \"gvisor\"` in the Charter [host].\n",
            "\n",
        )),
        "Kata" => out.push_str(concat!(
            "Kata Containers is not registered. To enable it:\n",
            "  1. Install Kata: https://github.com/kata-containers/kata-containers\n",
            "  2. Docker: add a runtimes entry to /etc/docker/daemon.json, e.g.\n",
            "       { \"runtimes\": { \"kata\": { \"path\": \"/usr/bin/kata-runtime\" } } }\n",
            "     then `sudo systemctl restart docker`.\n",
            "  3. Kubernetes: create a RuntimeClass named `kata` (handler: kata).\n",
            "  4. Point runeward at it: set `runtime_class = \"kata\"` in the Charter [host].\n",
            "\n",
        )),
        _ => {}
    }
}

/// `runeward runtime guide`.
pub fn guide() -> Result<()> {
    std::io::stdout().write_all(GUIDE.as_bytes())?;
    Ok(())
}

const GUIDE: &str = r#"runeward VM-grade isolation setup guide
=======================================

runeward can run each Citadel under a hardened, VM-grade runtime instead of the
host kernel's default runc. Two options are supported today:

  - gVisor (runsc): an application kernel in userspace; strong syscall isolation.
  - Kata Containers: lightweight VMs; hardware-virtualization isolation.

How runeward consumes it
------------------------
A Charter's [host] block may set:

    [host]
    type          = "docker"   # or "k8s"
    runtime_class = "gvisor"    # maps to the runtime/RuntimeClass name

  - Docker: runtime_class is passed as "docker run --runtime <value>". The value
    must be a runtime registered with the docker engine (see below). If it isn't
    registered, container creation fails closed with a clear error.
  - Kubernetes: runtime_class is set as the Pod's "runtimeClassName". The named
    RuntimeClass must exist in the cluster, or the Pod is rejected.

In both cases an unregistered runtime fails closed — runeward never silently
falls back to the default runtime. See docs/security-model.md.

gVisor (runsc)
--------------
1. Install runsc: https://gvisor.dev/docs/user_guide/install/
2. Docker: register runsc as a runtime in /etc/docker/daemon.json:

       {
         "runtimes": {
           "runsc": { "path": "/usr/local/bin/runsc" }
         }
       }

   Restart the engine: sudo systemctl restart docker
   Verify: docker info --format '{{json .Runtimes}}'  (should list "runsc")
3. Kubernetes: create a RuntimeClass whose handler is runsc:

       apiVersion: node.k8s.io/v1
       kind: RuntimeClass
       metadata:
         name: gvisor
       handler: runsc

4. Use it: set runtime_class = "gvisor" in the Charter [host] block.

Kata Containers
---------------
1. Install Kata: https://github.com/kata-containers/kata-containers
2. Docker: register the kata runtime in /etc/docker/daemon.json:

       {
         "runtimes": {
           "kata": { "path": "/usr/bin/kata-runtime" }
         }
       }

   Restart the engine: sudo systemctl restart docker
   Verify: docker info --format '{{json .Runtimes}}'  (should list "kata")
3. Kubernetes: create a RuntimeClass whose handler is kata:

       apiVersion: node.k8s.io/v1
       kind: RuntimeClass
       metadata:
         name: kata
       handler: kata

4. Use it: set runtime_class = "kata" in the Charter [host] block.

Verify your setup any time with: runeward runtime check
"#;

fn join_or_dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".into()
    } else {
        items.join(", ")
    }
}

/// The text before the first newline, trimmed.
pub(crate) fn first_line(s: &str) -> &str {
    match s.find('\n') {
        Some(i) => s[..i].trim(),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_match_go() {
        assert_eq!(join_or_dash(&[]), "-");
        assert_eq!(join_or_dash(&["a".into(), "b".into()]), "a, b");
        assert_eq!(first_line("one \ntwo"), "one");
        assert_eq!(first_line("only"), "only");
    }
}
