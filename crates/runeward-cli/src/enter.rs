//! `runeward enter`: provision a sandbox from a Charter and attach an
//! interactive terminal (or run one command), then tear it down.

use std::io::{IsTerminal, Write};
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use runeward_backend::{Backend, ExecRequest, PtyStream, TermSize};
use tokio::sync::mpsc;

use crate::common::{load_profile, resolve_env};

/// `runeward enter <charter> [-- command...]`.
pub async fn run(name: &str, inner: &[String], keep: bool, config_dir: &str) -> Result<()> {
    let p = load_profile(name, config_dir)?;
    let (env, warnings) = resolve_env(&p, &runeward_secrets::Dispatcher::from_env()).await;
    for w in warnings {
        eprintln!("warning: {w}");
    }
    let be = runeward_backend::for_charter(&p).await?;
    eprintln!(
        "runeward: provisioning {} via {} backend...",
        crate::common::go_quote(name),
        be.name()
    );
    let spec = runeward_backend::spec_from_charter(&p, env);
    let sb = be.create(spec).await?;
    eprintln!("runeward: citadel {} ready", sb.id);

    let result = if inner.is_empty() {
        attach_shell(&be, &sb.id).await
    } else {
        run_inner(&be, &sb.id, inner, &p.host.workdir).await
    };

    if keep {
        eprintln!("runeward: citadel {} kept (id: {})", sb.id, sb.id);
    } else {
        eprintln!("\nruneward: tearing down citadel {}", sb.id);
        let _ = be.kill(&sb.id).await;
    }
    result
}

/// Runs one command and relays its output and exit status.
async fn run_inner(
    be: &Arc<dyn Backend>,
    id: &str,
    command: &[String],
    workdir: &str,
) -> Result<()> {
    let mut req = ExecRequest::new(command.iter().cloned());
    req.workdir = workdir.to_owned();
    let res = be.exec(id, req).await?;
    print!("{}", res.stdout);
    std::io::stdout().flush()?;
    eprint!("{}", res.stderr);
    if res.exit_code != 0 {
        bail!("command exited with code {}", res.exit_code);
    }
    Ok(())
}

/// Puts the terminal in raw mode for the session and restores it on drop.
struct RawMode;

impl RawMode {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().map_err(|e| anyhow!("set raw terminal: {e}"))?;
        Ok(Self)
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Attaches stdin/stdout to an interactive shell in the sandbox. On a
/// terminal it switches to raw mode and follows window resizes.
async fn attach_shell(be: &Arc<dyn Backend>, id: &str) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    let mut stream = PtyStream {
        stdin: Some(Box::new(tokio::io::stdin())),
        stdout: Some(Box::new(tokio::io::stdout())),
        stderr: None,
        tty,
        command: Vec::new(),
        resize: None,
    };
    let mut _raw = None;
    let mut watcher = None;
    if tty {
        _raw = Some(RawMode::enable()?);
        let (tx, rx) = mpsc::channel(1);
        stream.resize = Some(rx);
        watcher = Some(tokio::spawn(watch_resize(tx)));
    }
    let result = be.attach_pty(id, stream).await;
    if let Some(w) = watcher {
        w.abort();
    }
    Ok(result?)
}

/// Bounds a terminal dimension to the `u16` the PTY protocol carries.
pub fn clamp_term_dimension(value: i64) -> u16 {
    u16::try_from(value.max(0)).unwrap_or(u16::MAX)
}

/// The current terminal size, if stdout is a terminal.
fn current_size() -> Option<TermSize> {
    let (cols, rows) = crossterm::terminal::size().ok()?;
    Some(TermSize {
        rows: clamp_term_dimension(i64::from(rows)),
        cols: clamp_term_dimension(i64::from(cols)),
    })
}

/// Sends the size without blocking; a pending update is enough.
fn send_size(tx: &mpsc::Sender<TermSize>) {
    if let Some(size) = current_size() {
        let _ = tx.try_send(size);
    }
}

/// Primes `tx` with the current size, then follows resizes: SIGWINCH on
/// unix, and on Windows (which has no resize signal) a short poll of the
/// console size.
async fn watch_resize(tx: mpsc::Sender<TermSize>) {
    send_size(&tx);
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let Ok(mut winch) = signal(SignalKind::window_change()) else {
            return;
        };
        while winch.recv().await.is_some() {
            send_size(&tx);
        }
    }
    #[cfg(not(unix))]
    {
        let mut last = current_size();
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
        loop {
            tick.tick().await;
            let now = current_size();
            if now != last {
                if let Some(size) = now {
                    let _ = tx.try_send(size);
                }
                last = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_term_dimension_bounds_to_u16() {
        for (name, input, want) in [
            ("negative", -1, 0),
            ("zero", 0, 0),
            ("ordinary", 120, 120),
            ("maximum", 65535, 65535),
            ("overflow", 65536, 65535),
        ] {
            assert_eq!(clamp_term_dimension(input), want, "{name}");
        }
    }
}
