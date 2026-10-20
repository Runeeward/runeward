//! `runeward-egress`: a deny-by-default egress proxy enforcing a
//! [`runeward_egress::Policy`] on sandbox traffic, either cooperatively
//! (`HTTP(S)_PROXY`) or transparently behind iptables (strict mode).

use std::ffi::OsString;
use std::io;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use clap::builder::BoolishValueParser;
use runeward_egress::broker::{BrokerConfig, DecisionLine};
use runeward_egress::{
    Broker, Logger, Policy, Proxy, STRICT_PROXY_UID, STRICT_REDIRECT_PORT, TransparentProxy,
    load_policy, setup_redirect,
};

/// Lets the Docker backend pass the policy inline (JSON) instead of a mounted
/// file, so no host bind-mount is needed for the sidecar.
const POLICY_ENV: &str = "RUNEWARD_EGRESS_POLICY";

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[command(
    name = "runeward-egress",
    version,
    about = "Deny-by-default egress proxy for Rune Box sandboxes"
)]
struct Args {
    /// Forward-proxy listen address (cooperative HTTP(S)_PROXY mode); loopback by default.
    #[arg(long, default_value = "127.0.0.1:8888")]
    addr: String,

    /// Path to a JSON policy file; if empty, RUNEWARD_EGRESS_POLICY or deny-all.
    #[arg(long, default_value = "")]
    policy: String,

    /// Run as a transparent proxy for iptables-redirected traffic (linux only).
    #[arg(long, num_args = 0..=1, require_equals = true, default_value = "false",
          default_missing_value = "true", value_parser = BoolishValueParser::new())]
    transparent: bool,

    /// Transparent proxy listen port / iptables REDIRECT target.
    #[arg(long, default_value_t = STRICT_REDIRECT_PORT)]
    redirect_port: u16,

    /// Install iptables redirect rules and exit (init-container mode, linux only).
    #[arg(long, num_args = 0..=1, require_equals = true, default_value = "false",
          default_missing_value = "true", value_parser = BoolishValueParser::new())]
    setup_iptables: bool,

    /// Uid the transparent proxy runs as (exempt from redirect).
    #[arg(long, default_value_t = STRICT_PROXY_UID)]
    proxy_uid: u32,

    /// Request-broker document (`runeward.egress.broker.v1`): endpoints,
    /// resolved credentials, placeholders and the sandbox CA keypair. Read
    /// once at startup, before dropping privileges, then removed when
    /// possible. Holds secrets: pass it only as a 0600 file or a mounted
    /// Secret, never inline.
    #[arg(long, default_value = "")]
    broker_config: String,

    /// Sandbox id for decision logs (defaults to the broker document's).
    #[arg(long, default_value = "")]
    sandbox_id: String,
}

const LONG_FLAGS: [&str; 8] = [
    "addr",
    "policy",
    "transparent",
    "redirect-port",
    "setup-iptables",
    "proxy-uid",
    "broker-config",
    "sandbox-id",
];

/// Accepts Go-style single-dash long flags (`-addr x`, `-transparent`) by
/// rewriting them to `--addr`, so existing invocations keep working.
fn normalize_args(args: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut out = Vec::new();
    let mut passthrough = false;
    for (i, a) in args.into_iter().enumerate() {
        if i == 0 || passthrough {
            out.push(a);
            continue;
        }
        if a == "--" {
            passthrough = true;
            out.push(a);
            continue;
        }
        if let Some(rest) = a
            .to_str()
            .and_then(|s| s.strip_prefix('-'))
            .filter(|r| !r.starts_with('-'))
            && LONG_FLAGS.contains(&rest.split('=').next().unwrap_or(rest))
        {
            out.push(OsString::from(format!("--{rest}")));
            continue;
        }
        out.push(a);
    }
    out
}

/// Resolves the policy from `--policy` (file) or `RUNEWARD_EGRESS_POLICY`
/// (inline JSON); neither means deny-all.
fn resolve_policy(path: &str) -> Result<Policy, runeward_egress::PolicyError> {
    if !path.is_empty() {
        return load_policy(path);
    }
    match std::env::var(POLICY_ENV) {
        Ok(raw) if !raw.is_empty() => Policy::from_json(&raw),
        _ => Ok(Policy {
            default: "deny".into(),
            rules: Vec::new(),
        }),
    }
}

/// Reads the broker document and removes the file (best effort: a mounted
/// Secret is read-only and stays). Called while still privileged.
fn load_broker_config(path: &str) -> Result<BrokerConfig, String> {
    let raw =
        zeroize::Zeroizing::new(std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?);
    let cfg = BrokerConfig::from_json(&raw).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(path);
    Ok(cfg)
}

/// Accepts Go's `:port` shorthand (every interface), as the container
/// image's default `--addr :8888` uses.
fn listen_addr(addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr.to_string(),
    }
}

fn policy_default(p: &Policy) -> &str {
    if p.default.is_empty() {
        "allow"
    } else {
        &p.default
    }
}

/// Switches the process to `uid`/`gid` (same number) so the transparent
/// proxy's own upstream traffic runs as the iptables-exempt uid. Called
/// before the async runtime starts, so the process is still single-threaded.
#[cfg(target_os = "linux")]
fn drop_privileges(uid: u32) -> io::Result<()> {
    use nix::unistd::{Gid, Uid, setgid, setuid};
    setgid(Gid::from_raw(uid))?;
    setuid(Uid::from_raw(uid))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn drop_privileges(_uid: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "dropping privileges is only supported on linux",
    ))
}

fn fatal(logger: &Logger, msg: std::fmt::Arguments<'_>) -> ExitCode {
    tracing::error!(target: "runeward_egress", "{}{}", logger.prefix(), msg);
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args = Args::parse_from(normalize_args(std::env::args_os()));
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_target(false)
        .with_ansi(false)
        .init();
    let logger = Logger::new("runeward-egress ");

    // The broker document is root-only in combined mode: read it before
    // the privilege drop below.
    let broker_cfg = if args.broker_config.is_empty() {
        None
    } else {
        match load_broker_config(&args.broker_config) {
            Ok(c) => Some(c),
            Err(e) => return fatal(&logger, format_args!("load broker config: {e}")),
        }
    };

    if args.setup_iptables {
        if let Err(e) = setup_redirect(args.proxy_uid, args.redirect_port) {
            return fatal(&logger, format_args!("setup-iptables: {e}"));
        }
        logger.log(format_args!(
            "iptables redirect installed (uid={} -> :{})",
            args.proxy_uid, args.redirect_port
        ));
        if !args.transparent {
            // Init-container mode: rules installed, nothing more to do.
            return ExitCode::SUCCESS;
        }
        // Combined mode (Docker single-container sidecar): drop to the exempt
        // uid, then serve the transparent proxy below.
        if let Err(e) = drop_privileges(args.proxy_uid) {
            return fatal(
                &logger,
                format_args!("drop privileges to uid {}: {e}", args.proxy_uid),
            );
        }
        logger.log(format_args!("dropped privileges to uid {}", args.proxy_uid));
    }

    let policy = match resolve_policy(&args.policy) {
        Ok(p) => p,
        Err(e) => return fatal(&logger, format_args!("load policy: {e}")),
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fatal(&logger, format_args!("start runtime: {e}")),
    };
    let broker = match broker_cfg.as_ref().map(Broker::from_sidecar_config) {
        None => None,
        Some(Ok(b)) => Some(Arc::new(b)),
        Some(Err(e)) => return fatal(&logger, format_args!("broker config: {e}")),
    };
    drop(broker_cfg);
    runtime.block_on(run(args, policy, broker, logger))
}

/// Prints every broker decision as one [`DecisionLine`] per stdout line,
/// for the control plane to ingest. Logs go to stderr.
fn spawn_decision_stream(broker: &Broker, sandbox_id: String) {
    let mut rx = broker.subscribe();
    tokio::spawn(async move {
        use std::io::Write as _;
        loop {
            let d = match rx.recv().await {
                Ok(d) => d,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(target: "runeward_egress", "decision stream dropped {n} decisions");
                    continue;
                }
                Err(_) => return,
            };
            let mut line = DecisionLine::new(&sandbox_id, &d).to_line();
            line.push('\n');
            // One short line per decision; the reader is the container
            // runtime's log pipe.
            let mut out = io::stdout().lock();
            if out
                .write_all(line.as_bytes())
                .and_then(|()| out.flush())
                .is_err()
            {
                return;
            }
        }
    });
}

async fn run(args: Args, policy: Policy, broker: Option<Arc<Broker>>, logger: Logger) -> ExitCode {
    let sandbox_id = if args.sandbox_id.is_empty() {
        broker
            .as_ref()
            .map(|b| b.sandbox_id().to_string())
            .unwrap_or_default()
    } else {
        args.sandbox_id.clone()
    };
    if let Some(b) = &broker {
        spawn_decision_stream(b, sandbox_id.clone());
        logger.log(format_args!(
            "request broker loaded for sandbox {sandbox_id} ({} placeholders)",
            b.placeholders().len()
        ));
    }
    if args.transparent {
        let listen = format!(":{}", args.redirect_port);
        logger.log(format_args!(
            "transparent proxy listening on {listen} (default={:?}, rules={})",
            policy_default(&policy),
            policy.rules.len()
        ));
        let mut tp = TransparentProxy::new(policy)
            .with_sandbox_id(sandbox_id.clone())
            .with_logger(logger.clone());
        if let Some(b) = broker {
            tp = tp.with_broker(b);
        }
        let tp = Arc::new(tp);
        // IPv4 only: the iptables setup drops IPv6 egress.
        let bind = format!("0.0.0.0:{}", args.redirect_port);
        if let Err(e) = tp.serve(&bind).await {
            return fatal(&logger, format_args!("transparent serve: {e}"));
        }
        return ExitCode::SUCCESS;
    }

    logger.log(format_args!(
        "listening on {} (default={:?}, rules={})",
        args.addr,
        policy_default(&policy),
        policy.rules.len()
    ));
    let listener = match tokio::net::TcpListener::bind(listen_addr(&args.addr)).await {
        Ok(l) => l,
        Err(e) => return fatal(&logger, format_args!("serve: {e}")),
    };
    let mut proxy = Proxy::new(policy)
        .with_sandbox_id(sandbox_id)
        .with_logger(logger.clone());
    if let Some(b) = broker {
        proxy = proxy.with_broker(b);
    }
    let proxy = Arc::new(proxy);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(proxy.serve_with_shutdown(listener, async move {
        let _ = stop_rx.await;
    }));
    tokio::pin!(server);

    tokio::select! {
        res = &mut server => match res {
            Ok(Ok(())) => ExitCode::SUCCESS,
            Ok(Err(e)) => fatal(&logger, format_args!("serve: {e}")),
            Err(e) => fatal(&logger, format_args!("serve: {e}")),
        },
        sig = wait_for_signal() => {
            logger.log(format_args!("received {sig}, shutting down"));
            let _ = stop_tx.send(());
            match tokio::time::timeout(SHUTDOWN_TIMEOUT, server).await {
                Ok(_) => ExitCode::SUCCESS,
                Err(_) => fatal(&logger, format_args!("shutdown: context deadline exceeded")),
            }
        }
    }
}

/// Resolves on SIGINT or SIGTERM with the signal's Go-style name.
async fn wait_for_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {
                _ = tokio::signal::ctrl_c() => "interrupt",
                _ = term.recv() => "terminated",
            },
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                "interrupt"
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "interrupt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: &[&str]) -> Args {
        let raw = std::iter::once("runeward-egress")
            .chain(v.iter().copied())
            .map(OsString::from);
        Args::try_parse_from(normalize_args(raw)).expect("parse")
    }

    #[test]
    fn go_port_shorthand_binds_every_interface() {
        assert_eq!(listen_addr(":8888"), "0.0.0.0:8888");
        assert_eq!(listen_addr("127.0.0.1:8888"), "127.0.0.1:8888");
        assert_eq!(listen_addr("[::1]:8888"), "[::1]:8888");
    }

    #[test]
    fn defaults_match_go() {
        let a = parse(&[]);
        assert_eq!(a.addr, "127.0.0.1:8888");
        assert_eq!(a.policy, "");
        assert!(!a.transparent && !a.setup_iptables);
        assert_eq!(a.redirect_port, 15001);
        assert_eq!(a.proxy_uid, 1337);
        assert!(a.broker_config.is_empty() && a.sandbox_id.is_empty());
    }

    #[test]
    fn broker_flags_parse() {
        let a = parse(&[
            "--transparent",
            "--broker-config",
            "/etc/runeward/broker.json",
            "-sandbox-id=abc",
        ]);
        assert_eq!(a.broker_config, "/etc/runeward/broker.json");
        assert_eq!(a.sandbox_id, "abc");
    }

    #[test]
    fn broker_config_file_is_read_then_removed() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("broker.json");
        let b = Broker::with_secret_values(
            "0123456789abcdef0123456789abcdef",
            Vec::new(),
            Vec::new(),
            Default::default(),
        )
        .expect("broker");
        std::fs::write(&p, &*b.sidecar_config().to_json()).expect("write");
        let ps = p.display().to_string();
        let cfg = load_broker_config(&ps).expect("load");
        assert_eq!(cfg.sandbox_id, b.sandbox_id());
        assert!(!p.exists(), "removed after reading");
        assert!(load_broker_config(&ps).is_err());
        std::fs::write(&p, b"{\"schema\":\"nope\"}").expect("write");
        assert!(load_broker_config(&ps).is_err());
    }

    #[test]
    fn backend_invocations_parse() {
        // Docker combined mode.
        let a = parse(&[
            "--setup-iptables",
            "--transparent",
            "--redirect-port",
            "15001",
            "--proxy-uid",
            "1337",
        ]);
        assert!(a.setup_iptables && a.transparent);
        // Kubernetes sidecar.
        let a = parse(&[
            "--transparent",
            "--redirect-port",
            "15001",
            "--policy",
            "/etc/runeward/policy.json",
        ]);
        assert!(a.transparent);
        assert_eq!(a.policy, "/etc/runeward/policy.json");
    }

    #[test]
    fn go_style_single_dash_and_bool_values() {
        let a = parse(&["-addr", "0.0.0.0:1", "-transparent=false", "-proxy-uid=7"]);
        assert_eq!(a.addr, "0.0.0.0:1");
        assert!(!a.transparent);
        assert_eq!(a.proxy_uid, 7);
        assert!(parse(&["--setup-iptables=true"]).setup_iptables);
    }

    #[test]
    fn policy_resolution_defaults_to_deny() {
        // Only the no-env path is exercised to avoid mutating process env.
        if std::env::var_os(POLICY_ENV).is_none() {
            let p = resolve_policy("").expect("policy");
            assert_eq!(p.default, "deny");
            assert!(p.rules.is_empty());
        }
        assert!(resolve_policy("/nonexistent/policy.json").is_err());
    }
}
