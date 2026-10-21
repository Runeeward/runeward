//! Human-readable, redacted rendering of a resolved Charter.

use std::fmt::Write as _;
use std::io;

use crate::governance::RequestRule;
use crate::schema::{Charter, EnvVar};
use crate::tabwriter::TabWriter;

/// Placeholder shown instead of secret values.
pub const REDACTED: &str = "«redacted»";

/// Renders a Charter as the `runeward print` view. Secret env values are never
/// shown, only their source kind.
pub fn render(p: &Charter) -> String {
    let mut w = String::new();
    // Writing to a String cannot fail; `let _` keeps the formatting terse.
    let _ = render_into(&mut w, p);
    w
}

/// Writes [`render`] output to `dst`, propagating write errors.
pub fn print(dst: &mut impl io::Write, p: &Charter) -> io::Result<()> {
    dst.write_all(render(p).as_bytes())
}

fn render_into(w: &mut String, p: &Charter) -> std::fmt::Result {
    writeln!(w, "policy (Charter): {}", p.name)?;
    writeln!(w, "source:  {}", p.source.display())?;
    writeln!(w)?;

    let mut tw = TabWriter::default();
    let mut row = |k: &str, v: &str| tw.push(&format!("{k}\t{v}\n"));
    let h = &p.host;
    row("host.type", h.host_type.as_str());
    if !h.name.is_empty() {
        row("host.name", &h.name);
    }
    row("host.image", &h.image);
    row("host.workdir", &h.workdir);
    if !h.user.is_empty() {
        row("host.user", &h.user);
    }
    if !h.copy_from.is_empty() {
        row(
            "host.copy_from",
            &format!("{} (copied into workspace at create)", h.copy_from),
        );
    }
    if !h.runtime_class.is_empty() {
        row("host.runtime_class", &h.runtime_class);
    }
    tw.flush(w);

    if !p.prompt.inline.is_empty() || !p.prompt.file.is_empty() {
        writeln!(w, "\n[prompt]")?;
        if !p.prompt.file.is_empty() {
            writeln!(w, "  file: {}", p.prompt.file)?;
        }
        if !p.prompt.inline.is_empty() {
            writeln!(w, "  inline: {}", first_line(&p.prompt.inline))?;
        }
    }

    if !p.env.is_empty() {
        writeln!(w, "\n[env]")?;
        let mut etw = TabWriter::default();
        for e in &p.env {
            etw.push(&format!(
                "  {}\t= {}\t({})\n",
                e.name,
                env_display(e),
                env_source(e)
            ));
        }
        etw.flush(w);
    }

    if !p.files.is_empty() {
        writeln!(w, "\n[files]")?;
        for f in &p.files {
            let mode = if f.mode.is_empty() { "0444" } else { &f.mode };
            writeln!(w, "  {} (mode {mode})", f.path)?;
        }
    }

    writeln!(w, "\n[network]")?;
    if p.network.deny_by_default() {
        writeln!(w, "  default: deny (allowlist below)")?;
    } else {
        writeln!(w, "  default: allow (OPEN — no egress restriction)")?;
    }
    for r in &p.network.rules {
        let target = if r.hostname.is_empty() {
            &r.cidr
        } else {
            &r.hostname
        };
        let v = if r.verdict.is_empty() {
            "allow"
        } else {
            &r.verdict
        };
        writeln!(w, "  {v:<5} {target}")?;
    }
    render_broker(w, p)?;

    if p.uses_cel() {
        writeln!(w, "\n[policy] engine: cel")?;
        let mut ptw = TabWriter::default();
        for r in &p.cel {
            let v = if r.verdict.as_str().is_empty() {
                "allow"
            } else {
                r.verdict.as_str()
            };
            ptw.push(&format!("  {}\t-> {v}\n", r.expr));
        }
        ptw.flush(w);
    } else if !p.policy.is_empty() {
        writeln!(w, "\n[policy] engine: builtin")?;
        let mut ptw = TabWriter::default();
        for r in &p.policy {
            let m = if r.match_glob.is_empty() {
                "*"
            } else {
                &r.match_glob
            };
            ptw.push(&format!("  {}\t{m}\t-> {}\n", r.tool, r.verdict));
        }
        ptw.flush(w);
    }

    let l = &p.limits;
    if !l.is_empty() {
        writeln!(w, "\n[budgets and limits / rationing]")?;
        if !l.wall_clock.is_empty() {
            writeln!(w, "  wall_clock: {}", l.wall_clock)?;
        }
        if l.max_execs > 0 {
            writeln!(w, "  max_execs: {}", l.max_execs)?;
        }
        if l.egress_requests > 0 {
            writeln!(w, "  egress_requests: {}", l.egress_requests)?;
        }
        if l.loop_threshold > 0 {
            let window = if l.loop_window.is_empty() {
                "60s"
            } else {
                &l.loop_window
            };
            writeln!(w, "  loop: {} within {window}", l.loop_threshold)?;
        }
    }

    if let Some(fleet) = &p.fleet {
        writeln!(w, "\n[cohort]")?;
        writeln!(w, "  replicas: {}", fleet.replicas)?;
        if !fleet.task_board.is_empty() {
            writeln!(w, "  tasks: {} seeded", fleet.task_board.len())?;
        }
    }

    if p.ide.enabled {
        writeln!(w, "\n[ide]")?;
        writeln!(w, "  enabled: true")?;
        writeln!(w, "  port: {}", p.ide.port)?;
        writeln!(w, "  path: {}", p.ide.path)?;
        if !p.ide.agents.is_empty() {
            writeln!(w, "  agents: {}", p.ide.agents.join(", "))?;
        }
    }

    writeln!(w, "\n[signed audit / chronicle]")?;
    writeln!(w, "  redact: {}", p.audit.redact_enabled())?;
    if !p.audit.sink.is_empty() {
        writeln!(w, "  sink: {}", p.audit.sink)?;
    }
    render_governance_isolation(w, p)?;
    render_governance_filesystem(w, p)?;
    render_governance_process(w, p)?;
    render_workspace(w, p)?;
    render_schedule(w, p)?;
    Ok(())
}

fn env_display(e: &EnvVar) -> &str {
    if e.is_secret() || e.value.is_empty() {
        REDACTED
    } else {
        &e.value
    }
}

fn env_source(e: &EnvVar) -> &'static str {
    if !e.op.is_empty() {
        "1password"
    } else if !e.file.is_empty() {
        "file"
    } else if !e.value.is_empty() {
        "literal"
    } else {
        "unset"
    }
}

fn first_line(s: &str) -> String {
    match s.split_once('\n') {
        Some((first, _)) => format!("{first} …"),
        None => s.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// [[credential]] / [[endpoint]] (egress broker) rendering.
// ---------------------------------------------------------------------------

/// Renders credentials and endpoints. Credential sources are references
/// (`vault://...`), not secrets, so they are shown; resolved values never
/// reach a Charter and so can never be printed.
fn render_broker(w: &mut String, p: &Charter) -> std::fmt::Result {
    if !p.credentials.is_empty() {
        writeln!(
            w,
            "\n[credentials] (agent sees a placeholder; broker injects)"
        )?;
        let mut tw = TabWriter::default();
        for c in &p.credentials {
            let inject = if c.inject.is_empty() {
                "bearer"
            } else {
                &c.inject
            };
            let env = if c.placeholder_env.is_empty() {
                "-"
            } else {
                &c.placeholder_env
            };
            tw.push(&format!(
                "  {}\t{}\tinject={inject}\tenv={env}\n",
                c.name, c.source
            ));
        }
        tw.flush(w);
    }
    if p.endpoints.is_empty() {
        return Ok(());
    }
    writeln!(w, "\n[endpoints]")?;
    for e in &p.endpoints {
        let port = if e.port == 0 { 443 } else { e.port };
        let protocol = if e.protocol.is_empty() {
            "tcp"
        } else {
            &e.protocol
        };
        let mode = if e.mode.is_empty() {
            "enforce"
        } else {
            &e.mode
        };
        let name = if e.name.is_empty() { &e.host } else { &e.name };
        write!(w, "  {name}: {}:{port} {protocol} ({mode})", e.host)?;
        if !e.credential.is_empty() {
            write!(w, " credential={}", e.credential)?;
        }
        if e.max_calls > 0 {
            write!(w, " max_calls={}", e.max_calls)?;
        }
        if !e.health_path.is_empty() {
            write!(w, " health={}", e.health_path)?;
        }
        writeln!(w)?;
        if !e.binaries.is_empty() {
            writeln!(w, "    binaries: {}", e.binaries.join(", "))?;
        }
        let mut tw = TabWriter::default();
        for (kind, rules) in [("allow", &e.allow), ("deny", &e.deny)] {
            for r in rules {
                tw.push(&format!("    {kind}\t{}\n", rule_summary(r)));
            }
        }
        tw.flush(w);
    }
    Ok(())
}

fn rule_summary(r: &RequestRule) -> String {
    let or_any = |s: &str| {
        if s.is_empty() {
            "*".to_owned()
        } else {
            s.to_owned()
        }
    };
    let mut out = format!("{}\t{}", or_any(&r.method), or_any(&r.path));
    if !r.tool.is_empty() {
        out.push_str(&format!("\ttool={}", r.tool));
    }
    if !r.effect.is_empty() {
        out.push_str(&format!(" effect={}", r.effect));
    }
    if r.max_calls > 0 {
        out.push_str(&format!(" max_calls={}", r.max_calls));
    }
    if !r.reason.is_empty() {
        out.push_str(&format!(" ({})", r.reason));
    }
    out
}

#[cfg(test)]
mod broker_tests {
    use super::*;
    use crate::governance::{Credential, Endpoint};

    #[test]
    fn renders_credentials_and_endpoints() {
        let p = Charter {
            credentials: vec![Credential {
                name: "github".into(),
                source: "vault://kv/data/github#token".into(),
                placeholder_env: "GITHUB_TOKEN".into(),
                inject: String::new(),
            }],
            endpoints: vec![Endpoint {
                name: "gh".into(),
                host: "api.github.com".into(),
                protocol: "rest".into(),
                credential: "github".into(),
                binaries: vec!["/usr/bin/gh".into()],
                health_path: "/zen".into(),
                allow: vec![RequestRule {
                    method: "GET".into(),
                    path: "/repos/**".into(),
                    effect: "read".into(),
                    max_calls: 5,
                    ..RequestRule::default()
                }],
                deny: vec![RequestRule {
                    path: "/repos/*/hooks/**".into(),
                    ..RequestRule::default()
                }],
                ..Endpoint::default()
            }],
            ..Charter::default()
        };
        let out = render(&p);
        assert!(
            out.contains(
                "  github  vault://kv/data/github#token  inject=bearer  env=GITHUB_TOKEN\n"
            ),
            "{out}"
        );
        assert!(
            out.contains("  gh: api.github.com:443 rest (enforce) credential=github health=/zen\n"),
            "{out}"
        );
        assert!(out.contains("    binaries: /usr/bin/gh\n"), "{out}");
        assert!(
            out.contains("    allow  GET  /repos/** effect=read max_calls=5\n"),
            "{out}"
        );
        assert!(out.contains("    deny   *    /repos/*/hooks/**\n"), "{out}");
        // Endpoints follow the network section.
        assert!(out.find("[network]") < out.find("[endpoints]"), "{out}");
    }

    #[test]
    fn omitted_when_absent() {
        let out = render(&Charter::default());
        assert!(!out.contains("[credentials]") && !out.contains("[endpoints]"));
    }
}

// Governance sections: [isolation], [filesystem], [process]. Each renders
// only when present, so older Charters print unchanged.

fn render_governance_isolation(w: &mut String, p: &Charter) -> std::fmt::Result {
    if p.isolation.is_unset() {
        return Ok(());
    }
    writeln!(w, "\n[isolation]")?;
    writeln!(w, "  minimum: {}", p.isolation.minimum)
}

fn render_governance_filesystem(w: &mut String, p: &Charter) -> std::fmt::Result {
    let Some(fs) = &p.filesystem else {
        return Ok(());
    };
    writeln!(w, "\n[filesystem]")?;
    if fs.landlock.is_empty() {
        writeln!(w, "  landlock: best-effort (default)")?;
    } else if fs.landlock == "off" {
        writeln!(w, "  landlock: off (paths below are NOT enforced)")?;
    } else {
        writeln!(w, "  landlock: {}", fs.landlock)?;
    }
    let list = |v: &[String]| {
        if v.is_empty() {
            "(none)".to_owned()
        } else {
            v.join(", ")
        }
    };
    writeln!(w, "  read_only: {}", list(&fs.read_only))?;
    writeln!(w, "  read_write: {}", list(&fs.read_write))?;
    let workdir = if p.host.workdir.is_empty() {
        "host.workdir"
    } else {
        &p.host.workdir
    };
    if fs.include_workdir {
        writeln!(w, "  workdir: {workdir} (read-write)")
    } else {
        writeln!(w, "  workdir: {workdir} (not included)")
    }
}

fn render_workspace(w: &mut String, p: &Charter) -> std::fmt::Result {
    let Some(ws) = &p.workspace else {
        return Ok(());
    };
    writeln!(w, "\n[workspace]")?;
    writeln!(w, "  persist: {}", ws.persist)?;
    if ws.idle_timeout.trim().is_empty() {
        writeln!(w, "  idle_timeout: (never sleeps on idle)")
    } else {
        writeln!(w, "  idle_timeout: {}", ws.idle_timeout.trim())
    }
}

fn render_schedule(w: &mut String, p: &Charter) -> std::fmt::Result {
    let Some(s) = &p.schedule else {
        return Ok(());
    };
    writeln!(w, "\n[schedule]")?;
    writeln!(w, "  self_service: {}", s.self_service)
}

fn render_governance_process(w: &mut String, p: &Charter) -> std::fmt::Result {
    let Some(proc_) = &p.process else {
        return Ok(());
    };
    writeln!(w, "\n[process]")?;
    if proc_.run_as_user.is_empty() {
        writeln!(w, "  run_as_user: (host.user)")?;
    } else {
        writeln!(w, "  run_as_user: {}", proc_.run_as_user)?;
    }
    if !proc_.run_as_group.is_empty() {
        writeln!(w, "  run_as_group: {}", proc_.run_as_group)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Failing;

    impl io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn propagates_writer_errors() {
        assert!(print(&mut Failing, &Charter::default()).is_err());
    }

    #[test]
    fn redacts_secrets() {
        let p = Charter {
            env: vec![
                EnvVar {
                    name: "PLAIN".into(),
                    value: "visible".into(),
                    ..EnvVar::default()
                },
                EnvVar {
                    name: "FLAGGED".into(),
                    value: "hunter2".into(),
                    secret: true,
                    ..EnvVar::default()
                },
            ],
            ..Charter::default()
        };
        let out = render(&p);
        assert!(out.contains("PLAIN    = visible     (literal)"), "{out}");
        assert!(out.contains("FLAGGED  = «redacted»  (literal)"), "{out}");
        assert!(!out.contains("hunter2"));
    }

    #[test]
    fn renders_workspace_and_schedule() {
        use crate::{Schedule, Workspace};
        let base = Charter::default();
        let plain = render(&base);
        let p = Charter {
            workspace: Some(Workspace {
                persist: true,
                idle_timeout: "15m".into(),
            }),
            schedule: Some(Schedule { self_service: true }),
            ..base
        };
        let out = render(&p);
        let tail = out.strip_prefix(plain.as_str()).expect("appended");
        assert_eq!(
            tail,
            "\n[workspace]\n  persist: true\n  idle_timeout: 15m\n\n[schedule]\n  self_service: true\n"
        );
    }

    #[test]
    fn renders_governance_sections() {
        use crate::{Filesystem, Isolation, Process};
        let base = Charter::default();
        let plain = render(&base);
        let p = Charter {
            isolation: Isolation {
                minimum: "kernel".into(),
            },
            filesystem: Some(Filesystem {
                read_only: vec!["/usr".into(), "/lib".into()],
                landlock: "required".into(),
                ..Filesystem::default()
            }),
            process: Some(Process {
                run_as_user: "1500".into(),
                run_as_group: "1600".into(),
            }),
            ..base
        };
        let out = render(&p);
        let tail = out
            .strip_prefix(plain.as_str())
            .expect("appended after the existing view");
        assert_eq!(
            tail,
            "\n[isolation]\n  minimum: kernel\n\n[filesystem]\n  landlock: required\n  read_only: /usr, /lib\n  read_write: (none)\n  workdir: host.workdir (read-write)\n\n[process]\n  run_as_user: 1500\n  run_as_group: 1600\n"
        );

        let off = Charter {
            filesystem: Some(Filesystem {
                landlock: "off".into(),
                include_workdir: false,
                ..Filesystem::default()
            }),
            process: Some(Process::default()),
            ..Charter::default()
        };
        let out = render(&off);
        assert!(
            out.contains("landlock: off (paths below are NOT enforced)"),
            "{out}"
        );
        assert!(out.contains("(not included)"), "{out}");
        assert!(out.contains("run_as_user: (host.user)"), "{out}");
    }
}
