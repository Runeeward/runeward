//! Human-readable, redacted rendering of a resolved Charter.

use std::fmt::Write as _;
use std::io;

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
