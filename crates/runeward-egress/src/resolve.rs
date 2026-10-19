//! DNS-to-IP pinning: a hostname is resolved once, at decision time, and the
//! proxy dials exactly that IP. This closes DNS-rebinding races between the
//! policy check and the connect.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use crate::netutil::{join_host_port, parse_ip, split_host_port};

/// Bound on a single hostname lookup.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Boxed future returned by [`Resolver::lookup`].
pub type LookupFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Resolves hostnames to IP addresses. Injectable so tests (and future
/// callers with their own DNS policy) can control resolution.
pub trait Resolver: Send + Sync {
    /// Returns every address `host` resolves to.
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a>;
}

/// The system resolver (`getaddrinfo` via tokio).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup<'a>(&'a self, host: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host, 0)).await?;
            Ok(addrs.map(|a| a.ip()).collect())
        })
    }
}

/// A resolver backed by a fixed answer list; useful for tests and for
/// pinning a hostname to a known address.
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    answers: Vec<IpAddr>,
}

impl StaticResolver {
    /// Resolves every hostname to `answers`.
    pub fn new(answers: Vec<IpAddr>) -> Self {
        Self { answers }
    }
}

impl Resolver for StaticResolver {
    fn lookup<'a>(&'a self, _host: &'a str) -> LookupFuture<'a> {
        let answers = self.answers.clone();
        Box::pin(async move { Ok(answers) })
    }
}

/// The default resolver used by the proxies.
pub fn system_resolver() -> Arc<dyn Resolver> {
    Arc::new(SystemResolver)
}

/// A policy-approved upstream: the pinned IP and the (unvalidated) port from
/// the request. Its [`Display`](fmt::Display) form is `ip:port`
/// (bracketed for IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedTarget {
    /// The IP the connection is pinned to.
    pub ip: IpAddr,
    /// The port as given by the client.
    pub port: String,
}

impl PinnedTarget {
    /// The socket address to dial; fails if the port isn't a valid number.
    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        let port = self.port.parse::<u16>().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid port {:?}", self.port),
            )
        })?;
        Ok(SocketAddr::new(self.ip, port))
    }
}

impl fmt::Display for PinnedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&join_host_port(&self.ip.to_string(), &self.port))
    }
}

/// Splits an authority into host and port, falling back to `default_port`
/// when it carries none. Brackets and surrounding space are stripped from
/// the host.
pub fn host_with_default_port(authority: &str, default_port: &str) -> io::Result<(String, String)> {
    if authority.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty authority",
        ));
    }
    if let Ok((h, p)) = split_host_port(authority) {
        return Ok((trim_brackets(h.trim()).to_string(), p));
    }
    Ok((
        trim_brackets(authority.trim()).to_string(),
        default_port.to_string(),
    ))
}

fn trim_brackets(s: &str) -> &str {
    s.trim_matches(|c| c == '[' || c == ']')
}

/// Picks the IP to pin `host` to. IP literals pin to themselves. Otherwise
/// the host is resolved; `dst_hint` (the original destination of a
/// redirected connection) wins if it is among the answers, then the first
/// IPv4 answer, then the first answer.
pub async fn pick_pinned_ip(
    resolver: &dyn Resolver,
    host: &str,
    dst_hint: Option<IpAddr>,
) -> io::Result<IpAddr> {
    if let Some(ip) = parse_ip(host) {
        return Ok(ip);
    }
    let addrs = tokio::time::timeout(RESOLVE_TIMEOUT, resolver.lookup(host))
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, format!("lookup {host}: timeout"))
        })??;
    let addrs: Vec<IpAddr> = addrs.into_iter().map(|a| a.to_canonical()).collect();
    let Some(first) = addrs.first().copied() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no IPs resolved for {host:?}"),
        ));
    };
    if let Some(hint) = dst_hint.map(|h| h.to_canonical())
        && addrs.contains(&hint)
    {
        return Ok(hint);
    }
    Ok(addrs.into_iter().find(IpAddr::is_ipv4).unwrap_or(first))
}

/// Resolves and pins `host` (see [`pick_pinned_ip`]) and pairs it with
/// `port`.
pub async fn pinned_addr_for_host(
    resolver: &dyn Resolver,
    host: &str,
    port: &str,
    dst_hint: Option<IpAddr>,
) -> io::Result<PinnedTarget> {
    let ip = pick_pinned_ip(resolver, host, dst_hint).await?;
    Ok(PinnedTarget {
        ip,
        port: port.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[tokio::test]
    async fn pinned_addr_prefers_original_dst() {
        let r = StaticResolver::new(vec![ip("203.0.113.4"), ip("198.51.100.9")]);
        let got = pinned_addr_for_host(&r, "api.example.com", "443", Some(ip("198.51.100.9")))
            .await
            .expect("pin");
        assert_eq!(got.to_string(), "198.51.100.9:443");
    }

    #[tokio::test]
    async fn pinned_addr_prefers_ipv4_then_first() {
        let r = StaticResolver::new(vec![ip("2001:db8::1"), ip("192.0.2.7")]);
        let got = pinned_addr_for_host(&r, "h.test", "80", None)
            .await
            .expect("pin");
        assert_eq!(got.to_string(), "192.0.2.7:80");
        let r = StaticResolver::new(vec![ip("2001:db8::1")]);
        let got = pinned_addr_for_host(&r, "h.test", "80", None)
            .await
            .expect("pin");
        assert_eq!(got.to_string(), "[2001:db8::1]:80");
    }

    #[tokio::test]
    async fn pinned_addr_ip_literal_and_empty_answer() {
        let r = StaticResolver::new(vec![]);
        let got = pinned_addr_for_host(&r, "10.0.0.1", "1", None)
            .await
            .expect("literal");
        assert_eq!(got.to_string(), "10.0.0.1:1");
        assert!(pinned_addr_for_host(&r, "h.test", "1", None).await.is_err());
    }

    #[test]
    fn host_with_default_port_cases() {
        let hp = |a: &str, d: &str| host_with_default_port(a, d).expect(a);
        assert_eq!(hp("example.com", "80"), ("example.com".into(), "80".into()));
        assert_eq!(
            hp("example.com:8443", "80"),
            ("example.com".into(), "8443".into())
        );
        assert_eq!(hp("[::1]:443", "80"), ("::1".into(), "443".into()));
        assert_eq!(hp("[::1]", "80"), ("::1".into(), "80".into()));
        assert!(host_with_default_port("", "80").is_err());
    }
}
