//! Host/port helpers mirroring the Go standard library semantics the egress
//! policy was written against (`net.SplitHostPort`, `net.JoinHostPort`,
//! `net.ParseIP`, `net.IPNet.Contains`).

use std::net::IpAddr;

use ipnet::IpNet;

/// Error returned by [`split_host_port`]; the message mirrors Go's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("address {addr}: {reason}")]
pub struct SplitError {
    addr: String,
    reason: &'static str,
}

fn split_err(addr: &str, reason: &'static str) -> SplitError {
    SplitError {
        addr: addr.to_string(),
        reason,
    }
}

/// Splits `host:port` or `[host]:port` into host and port, like Go's
/// `net.SplitHostPort`. The port is returned verbatim (not validated).
pub fn split_host_port(hostport: &str) -> Result<(String, String), SplitError> {
    const MISSING_PORT: &str = "missing port in address";
    const TOO_MANY_COLONS: &str = "too many colons in address";

    let Some(i) = hostport.rfind(':') else {
        return Err(split_err(hostport, MISSING_PORT));
    };
    let (host, j, k);
    if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else {
            return Err(split_err(hostport, "missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            return Err(split_err(hostport, MISSING_PORT));
        }
        if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(split_err(hostport, TOO_MANY_COLONS));
            }
            return Err(split_err(hostport, MISSING_PORT));
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return Err(split_err(hostport, TOO_MANY_COLONS));
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') {
        return Err(split_err(hostport, "unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(split_err(hostport, "unexpected ']' in address"));
    }
    Ok((host.to_string(), hostport[i + 1..].to_string()))
}

/// Joins host and port, bracketing hosts that contain a colon (IPv6), like
/// Go's `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Parses an IPv4 or IPv6 literal (no brackets, no zone), like Go's
/// `net.ParseIP`. IPv4-mapped IPv6 addresses are canonicalised to IPv4, which
/// matches how Go prints and compares them.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Reports whether `net` contains `ip` with Go `IPNet.Contains` semantics:
/// IPv4-mapped IPv6 addresses match IPv4 networks; otherwise families must
/// agree.
pub fn net_contains(net: &IpNet, ip: IpAddr) -> bool {
    match (net, ip.to_canonical()) {
        (IpNet::V4(n), IpAddr::V4(a)) => n.contains(&a),
        (IpNet::V6(n), IpAddr::V6(a)) => n.contains(&a),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_matches_go() {
        let ok = |s: &str| split_host_port(s).expect(s);
        assert_eq!(ok("example.com:443"), ("example.com".into(), "443".into()));
        assert_eq!(ok("[::1]:80"), ("::1".into(), "80".into()));
        assert_eq!(ok("host:"), ("host".into(), String::new()));
        assert!(split_host_port("example.com").is_err());
        assert!(split_host_port("::1").is_err());
        assert!(split_host_port("[::1]").is_err());
        assert!(split_host_port("[::1]:80:90").is_err());
        assert!(split_host_port("a]:80").is_err());
    }

    #[test]
    fn join_brackets_ipv6() {
        assert_eq!(join_host_port("::1", "80"), "[::1]:80");
        assert_eq!(join_host_port("1.2.3.4", "80"), "1.2.3.4:80");
    }

    #[test]
    fn mapped_ipv4_matches_v4_net() {
        let net: IpNet = "10.0.0.0/8".parse().expect("cidr");
        let ip = "::ffff:10.1.2.3".parse::<IpAddr>().expect("ip");
        assert!(net_contains(&net, ip));
        let v6: IpNet = "::/0".parse().expect("cidr");
        assert!(!net_contains(&v6, "10.1.2.3".parse().expect("ip")));
    }
}
