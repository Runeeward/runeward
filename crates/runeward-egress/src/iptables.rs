//! iptables/ip6tables rules that force sandbox egress through the
//! transparent proxy (strict / L3 mode). Rule construction is portable and
//! unit-tested; executing it is Linux-only.

use std::io;
use std::net::IpAddr;

/// Optionally restricts DNS egress to a comma-separated list of resolver IPs.
/// When set, DNS (port 53) to any other destination is dropped, so a workload
/// can't tunnel data out over DNS to an arbitrary server. Unset keeps DNS
/// open.
pub const DNS_RESOLVERS_ENV: &str = "RUNEWARD_DNS_RESOLVERS";

/// nat-table chain redirecting outbound TCP to the proxy.
pub const CHAIN: &str = "RUNEWARD_OUT";
/// filter-table chain dropping non-DNS UDP.
pub const UDP_CHAIN: &str = "RUNEWARD_UDP";
/// filter-table chain confining TCP DNS to the pinned resolvers.
pub const DNS_TCP_CHAIN: &str = "RUNEWARD_DNST";
/// ip6tables chain dropping IPv6 egress.
pub const CHAIN6: &str = "RUNEWARD_OUT6";

/// Returns the valid resolver IPs from a `RUNEWARD_DNS_RESOLVERS` value
/// (garbage entries are skipped rather than failing setup).
pub fn parse_dns_resolvers(raw: &str) -> Vec<String> {
    raw.trim()
        .split(',')
        .map(str::trim)
        .filter(|f| !f.is_empty() && f.parse::<IpAddr>().is_ok())
        .map(str::to_string)
        .collect()
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_string()).collect()
}

/// Best-effort deletions run before setup so re-runs don't stack rules.
pub fn flush_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", CHAIN]),
        args(&["-t", "nat", "-F", CHAIN]),
        args(&["-t", "nat", "-X", CHAIN]),
        args(&["-t", "filter", "-D", "OUTPUT", "-p", "udp", "-j", UDP_CHAIN]),
        args(&["-t", "filter", "-F", UDP_CHAIN]),
        args(&["-t", "filter", "-X", UDP_CHAIN]),
        args(&[
            "-t",
            "filter",
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            DNS_TCP_CHAIN,
        ]),
        args(&["-t", "filter", "-F", DNS_TCP_CHAIN]),
        args(&["-t", "filter", "-X", DNS_TCP_CHAIN]),
    ]
}

/// The IPv4 rules (in order) that redirect outbound TCP to `redirect_port`,
/// exempting `proxy_uid`, loopback and DNS; drop non-DNS UDP (QUIC/HTTP3
/// bypass); and, when `resolvers` is non-empty, confine UDP and TCP DNS to
/// them.
pub fn redirect_steps(
    proxy_uid: u32,
    redirect_port: u16,
    resolvers: &[String],
) -> Vec<Vec<String>> {
    let uid = proxy_uid.to_string();
    let port = redirect_port.to_string();
    let uid = uid.as_str();

    let mut steps = vec![
        args(&["-t", "nat", "-N", CHAIN]),
        // Don't redirect the proxy's own egress back to itself.
        args(&[
            "-t",
            "nat",
            "-A",
            CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "RETURN",
        ]),
        args(&["-t", "nat", "-A", CHAIN, "-o", "lo", "-j", "RETURN"]),
        // Let DNS through (not redirected) so name resolution keeps working;
        // destination filtering, if any, happens in the filter table below.
        args(&[
            "-t", "nat", "-A", CHAIN, "-p", "udp", "--dport", "53", "-j", "RETURN",
        ]),
        args(&[
            "-t", "nat", "-A", CHAIN, "-p", "tcp", "--dport", "53", "-j", "RETURN",
        ]),
        args(&[
            "-t",
            "nat",
            "-A",
            CHAIN,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-ports",
            &port,
        ]),
        args(&["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", CHAIN]),
        // Drop non-DNS UDP (QUIC/HTTP3 bypass) via a filter-table chain.
        args(&["-t", "filter", "-N", UDP_CHAIN]),
        args(&[
            "-t",
            "filter",
            "-A",
            UDP_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "RETURN",
        ]),
        args(&["-t", "filter", "-A", UDP_CHAIN, "-o", "lo", "-j", "RETURN"]),
    ];
    // DNS destination policy for UDP: only the configured resolvers when set,
    // otherwise any :53. Everything else falls through to the DROP.
    if resolvers.is_empty() {
        steps.push(args(&[
            "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "--dport", "53", "-j", "RETURN",
        ]));
    } else {
        for ip in resolvers {
            steps.push(args(&[
                "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-d", ip, "--dport", "53", "-j",
                "RETURN",
            ]));
        }
    }
    steps.push(args(&[
        "-t", "filter", "-A", UDP_CHAIN, "-p", "udp", "-j", "DROP",
    ]));
    steps.push(args(&[
        "-t", "filter", "-A", "OUTPUT", "-p", "udp", "-j", UDP_CHAIN,
    ]));

    // With pinned resolvers, also confine TCP DNS (DoT/large responses) so DNS
    // can't be a covert channel over TCP either.
    if !resolvers.is_empty() {
        steps.push(args(&["-t", "filter", "-N", DNS_TCP_CHAIN]));
        steps.push(args(&[
            "-t",
            "filter",
            "-A",
            DNS_TCP_CHAIN,
            "-m",
            "owner",
            "--uid-owner",
            uid,
            "-j",
            "RETURN",
        ]));
        steps.push(args(&[
            "-t",
            "filter",
            "-A",
            DNS_TCP_CHAIN,
            "-o",
            "lo",
            "-j",
            "RETURN",
        ]));
        for ip in resolvers {
            steps.push(args(&[
                "-t",
                "filter",
                "-A",
                DNS_TCP_CHAIN,
                "-p",
                "tcp",
                "-d",
                ip,
                "--dport",
                "53",
                "-j",
                "RETURN",
            ]));
        }
        steps.push(args(&[
            "-t",
            "filter",
            "-A",
            DNS_TCP_CHAIN,
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            "DROP",
        ]));
        steps.push(args(&[
            "-t",
            "filter",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--dport",
            "53",
            "-j",
            DNS_TCP_CHAIN,
        ]));
    }
    steps
}

/// Best-effort deletions of a prior IPv6 chain.
pub fn ipv6_flush_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-D", "OUTPUT", "-j", CHAIN6]),
        args(&["-F", CHAIN6]),
        args(&["-X", CHAIN6]),
    ]
}

/// ip6tables rules dropping all IPv6 egress except loopback and DNS (the
/// proxy is IPv4-only, so this forces traffic onto the proxied path).
pub fn ipv6_drop_steps() -> Vec<Vec<String>> {
    vec![
        args(&["-N", CHAIN6]),
        args(&["-A", CHAIN6, "-o", "lo", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-p", "udp", "--dport", "53", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-p", "tcp", "--dport", "53", "-j", "RETURN"]),
        args(&["-A", CHAIN6, "-j", "DROP"]),
        args(&["-A", "OUTPUT", "-j", CHAIN6]),
    ]
}

/// Runs the full setup sequence through `run(program, args)`: best-effort
/// flush, fail-fast IPv4 steps, then best-effort IPv6 drop.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn setup_redirect_with<F>(
    mut run: F,
    proxy_uid: u32,
    redirect_port: u16,
    resolvers: &[String],
) -> io::Result<()>
where
    F: FnMut(&str, &[String]) -> io::Result<()>,
{
    for a in flush_steps() {
        let _ = run("iptables", &a);
    }
    for a in redirect_steps(proxy_uid, redirect_port, resolvers) {
        run("iptables", &a)
            .map_err(|e| io::Error::new(e.kind(), format!("iptables {}: {e}", a.join(" "))))?;
    }
    // Some environments lack IPv6/ip6tables entirely, which is fine (nothing
    // to bypass through), so failures here are ignored.
    for a in ipv6_flush_steps().into_iter().chain(ipv6_drop_steps()) {
        let _ = run("ip6tables", &a);
    }
    Ok(())
}

/// Installs the iptables rules redirecting outbound TCP to the transparent
/// proxy on `redirect_port`, exempting `proxy_uid`, loopback and DNS, and
/// closing the UDP/QUIC and IPv6 bypasses. Reads [`DNS_RESOLVERS_ENV`]. Runs
/// once, privileged, before the sandbox starts.
#[cfg(target_os = "linux")]
pub fn setup_redirect(proxy_uid: u32, redirect_port: u16) -> io::Result<()> {
    let resolvers = parse_dns_resolvers(&std::env::var(DNS_RESOLVERS_ENV).unwrap_or_default());
    setup_redirect_with(run_command, proxy_uid, redirect_port, &resolvers)
}

/// Unsupported off Linux.
#[cfg(not(target_os = "linux"))]
pub fn setup_redirect(_proxy_uid: u32, _redirect_port: u16) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "iptables egress redirect is only supported on linux",
    ))
}

#[cfg(target_os = "linux")]
fn run_command(program: &str, args: &[String]) -> io::Result<()> {
    let out = std::process::Command::new(program).args(args).output()?;
    if out.status.success() {
        return Ok(());
    }
    let mut combined = out.stdout;
    combined.extend_from_slice(&out.stderr);
    Err(io::Error::other(format!(
        "{}: {}",
        out.status,
        String::from_utf8_lossy(&combined).trim()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resolvers_skips_garbage() {
        assert!(parse_dns_resolvers("").is_empty());
        assert_eq!(
            parse_dns_resolvers(" 1.1.1.1, nope ,,2606:4700::1111 "),
            vec!["1.1.1.1".to_string(), "2606:4700::1111".to_string()]
        );
    }

    fn joined(steps: &[Vec<String>]) -> Vec<String> {
        steps.iter().map(|s| s.join(" ")).collect()
    }

    #[test]
    fn steps_without_resolvers() {
        let s = joined(&redirect_steps(1337, 15001, &[]));
        assert_eq!(s[0], "-t nat -N RUNEWARD_OUT");
        assert!(
            s.contains(&"-t nat -A RUNEWARD_OUT -m owner --uid-owner 1337 -j RETURN".to_string())
        );
        assert!(
            s.contains(&"-t nat -A RUNEWARD_OUT -p tcp -j REDIRECT --to-ports 15001".to_string())
        );
        assert!(s.contains(&"-t filter -A RUNEWARD_UDP -p udp --dport 53 -j RETURN".to_string()));
        assert_eq!(
            s.last().map(String::as_str),
            Some("-t filter -A OUTPUT -p udp -j RUNEWARD_UDP")
        );
        assert!(!s.iter().any(|l| l.contains("RUNEWARD_DNST")));
        assert_eq!(s.len(), 13);
    }

    #[test]
    fn steps_with_resolvers() {
        let r = vec!["10.0.0.2".to_string(), "10.0.0.3".to_string()];
        let s = joined(&redirect_steps(7, 9, &r));
        assert!(!s.contains(&"-t filter -A RUNEWARD_UDP -p udp --dport 53 -j RETURN".to_string()));
        assert!(s.contains(
            &"-t filter -A RUNEWARD_UDP -p udp -d 10.0.0.3 --dport 53 -j RETURN".to_string()
        ));
        assert!(s.contains(&"-t filter -N RUNEWARD_DNST".to_string()));
        assert!(s.contains(
            &"-t filter -A RUNEWARD_DNST -p tcp -d 10.0.0.2 --dport 53 -j RETURN".to_string()
        ));
        assert_eq!(
            s.last().map(String::as_str),
            Some("-t filter -A OUTPUT -p tcp --dport 53 -j RUNEWARD_DNST")
        );
        let drop_udp = s
            .iter()
            .position(|l| l == "-t filter -A RUNEWARD_UDP -p udp -j DROP");
        let allow_udp = s
            .iter()
            .position(|l| l.contains("RUNEWARD_UDP -p udp -d 10.0.0.3"));
        assert!(allow_udp < drop_udp);
    }

    #[test]
    fn setup_sequence_is_best_effort_where_go_is() {
        let mut calls = Vec::new();
        let res = setup_redirect_with(
            |prog, a| {
                calls.push(format!("{prog} {}", a.join(" ")));
                // Flushes and ip6tables fail; real steps succeed.
                if prog == "ip6tables" || a.iter().any(|x| x == "-D" || x == "-F" || x == "-X") {
                    Err(io::Error::other("nope"))
                } else {
                    Ok(())
                }
            },
            1337,
            15001,
            &[],
        );
        assert!(res.is_ok());
        assert_eq!(calls.len(), flush_steps().len() + 13 + 9);
        assert!(
            calls
                .last()
                .is_some_and(|c| c == "ip6tables -A OUTPUT -j RUNEWARD_OUT6")
        );
    }

    #[test]
    fn setup_stops_on_first_failing_step() {
        let mut n = 0;
        let err = setup_redirect_with(
            |_, a| {
                n += 1;
                if a.join(" ") == "-t nat -A OUTPUT -p tcp -j RUNEWARD_OUT" {
                    Err(io::Error::other("boom"))
                } else {
                    Ok(())
                }
            },
            1,
            2,
            &[],
        )
        .expect_err("must fail");
        assert!(
            err.to_string()
                .contains("iptables -t nat -A OUTPUT -p tcp -j RUNEWARD_OUT: boom")
        );
        assert_eq!(n, flush_steps().len() + 7);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_off_linux() {
        let err = setup_redirect(1337, 15001).expect_err("unsupported");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
