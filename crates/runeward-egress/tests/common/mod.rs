//! Loopback helpers shared by the integration tests (no root, no network).

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use runeward_egress::{Policy, Rule};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

pub fn rule(verdict: &str, hostname: &str, cidr: &str) -> Rule {
    Rule {
        verdict: verdict.into(),
        hostname: hostname.into(),
        cidr: cidr.into(),
    }
}

pub fn policy(default: &str, rules: Vec<Rule>) -> Policy {
    Policy {
        default: default.into(),
        rules,
    }
}

/// A raw TCP listener that reads one line and writes back `reply`.
pub async fn start_line_target(reply: &'static str) -> SocketAddr {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    tokio::spawn(async move {
        let Ok((conn, _)) = ln.accept().await else {
            return;
        };
        let mut br = BufReader::new(conn);
        let mut line = String::new();
        let _ = br.read_line(&mut line).await;
        let _ = br.get_mut().write_all(reply.as_bytes()).await;
    });
    addr
}

/// A minimal HTTP/1.1 origin answering every request with 200 and `body`.
/// Each request head it receives is sent on the returned channel.
pub async fn start_origin(
    body: &'static str,
) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<String>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((conn, _)) = ln.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = serve_origin_conn(conn, body, tx).await;
            });
        }
    });
    (addr, rx)
}

pub async fn serve_origin_conn<S>(
    conn: S,
    body: &str,
    tx: tokio::sync::mpsc::UnboundedSender<String>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut br = BufReader::new(conn);
    let head = read_head(&mut br).await?;
    let _ = tx.send(head);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Origin: yes\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    br.get_mut().write_all(resp.as_bytes()).await?;
    br.get_mut().flush().await
}

/// Reads an HTTP head (through the blank line).
pub async fn read_head<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> std::io::Result<String> {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await? == 0 {
            break;
        }
        let end = line == "\r\n" || line == "\n";
        head.push_str(&line);
        if end {
            break;
        }
    }
    Ok(head)
}

/// A parsed HTTP response.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub head: String,
    pub body: String,
}

impl Resp {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    }
}

/// Reads one response (head plus a Content-Length body, if any).
pub async fn read_response<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Resp {
    let head = read_head(r).await.expect("head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("bad status line in {head:?}"));
    let mut resp = Resp {
        status,
        head,
        body: String::new(),
    };
    if let Some(n) = resp
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
    {
        let mut buf = vec![0; n];
        r.read_exact(&mut buf).await.expect("body");
        resp.body = String::from_utf8(buf).expect("utf8");
    }
    resp
}

/// Starts `proxy` on an ephemeral loopback port; the returned sender stops it.
pub async fn start_proxy(proxy: runeward_egress::Proxy) -> (SocketAddr, oneshot::Sender<()>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = ln.local_addr().expect("addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(Arc::new(proxy).serve_with_shutdown(ln, async move {
        let _ = rx.await;
    }));
    (addr, tx)
}

/// Sends raw bytes to `addr` and reads one response.
pub async fn roundtrip(addr: SocketAddr, raw: &str) -> Resp {
    let conn = TcpStream::connect(addr).await.expect("connect");
    let mut br = BufReader::new(conn);
    br.get_mut().write_all(raw.as_bytes()).await.expect("write");
    read_response(&mut br).await
}

/// Opens a CONNECT tunnel through the proxy and returns the response and the
/// (possibly tunnelled) stream.
pub async fn connect_via(proxy: SocketAddr, target: &str) -> (Resp, BufReader<TcpStream>) {
    let conn = TcpStream::connect(proxy).await.expect("connect");
    let mut br = BufReader::new(conn);
    br.get_mut()
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let head = read_head(&mut br).await.expect("head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status");
    (
        Resp {
            status,
            head,
            body: String::new(),
        },
        br,
    )
}
