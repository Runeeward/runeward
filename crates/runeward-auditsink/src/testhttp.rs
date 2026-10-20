//! A minimal loopback HTTP/1.1 server for sink tests.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

/// One request as the server saw it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Handler = dyn Fn(Request) -> u16 + Send + Sync;

/// Serves every request on 127.0.0.1 with `handler`, which returns the
/// status code to answer with (and may block to simulate a hung endpoint).
pub struct Server {
    addr: SocketAddr,
}

impl Server {
    pub fn start(handler: impl Fn(Request) -> u16 + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let handler: Arc<Handler> = Arc::new(handler);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let h = handler.clone();
                thread::spawn(move || serve(stream, &*h));
            }
        });
        Self { addr }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

fn serve(stream: TcpStream, handler: &Handler) {
    let Ok(write_half) = stream.try_clone() else {
        return;
    };
    let mut writer = write_half;
    let mut reader = BufReader::new(stream);
    while let Some(req) = read_request(&mut reader) {
        let code = handler(req);
        let resp = format!("HTTP/1.1 {code} Test\r\ncontent-length: 0\r\n\r\n");
        if writer.write_all(resp.as_bytes()).is_err() {
            return;
        }
    }
}

fn read_request(r: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    if r.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).ok()? == 0 {
            return None;
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).ok()?;
    Some(Request {
        method,
        path,
        headers,
        body,
    })
}
