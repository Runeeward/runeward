//! Hostname sniffing for the transparent proxy: TLS SNI from a ClientHello,
//! or the `Host` header from a plain HTTP request.

fn be16(b: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([b[0], b[1]]))
}

/// Parses the SNI host from a TLS ClientHello, returning `None` if `data`
/// isn't a ClientHello or has no SNI extension. The result is lowercased.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record header: type(1) version(2) length(2). Handshake = 22.
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let rec_len = be16(&data[3..5]);
    let mut buf = &data[5..];
    if buf.len() > rec_len {
        buf = &buf[..rec_len];
    }
    // Handshake header: type(1) length(3). ClientHello = 1.
    if buf.len() < 4 || buf[0] != 0x01 {
        return None;
    }
    let hs = &buf[4..];
    // ClientHello: version(2) random(32), then session_id, cipher_suites,
    // compression_methods, extensions.
    if hs.len() < 34 {
        return None;
    }
    let mut p = &hs[34..];

    // session_id
    let sid_len = usize::from(*p.first()?);
    p = p.get(1 + sid_len..)?;
    // cipher_suites
    if p.len() < 2 {
        return None;
    }
    let cs_len = be16(p);
    p = p.get(2 + cs_len..)?;
    // compression_methods
    let cm_len = usize::from(*p.first()?);
    p = p.get(1 + cm_len..)?;
    // extensions
    if p.len() < 2 {
        return None;
    }
    let ext_total = be16(p);
    p = &p[2..];
    if p.len() > ext_total {
        p = &p[..ext_total];
    }
    while p.len() >= 4 {
        let ext_type = be16(p);
        let ext_len = be16(&p[2..4]);
        p = &p[4..];
        if p.len() < ext_len {
            return None;
        }
        let body = &p[..ext_len];
        p = &p[ext_len..];
        if ext_type != 0x0000 {
            continue; // not server_name
        }
        // ServerNameList: list_length(2), then entries type(1) len(2) name.
        if body.len() < 2 {
            return None;
        }
        let list_len = be16(body);
        let mut snl = &body[2..];
        if snl.len() > list_len {
            snl = &snl[..list_len];
        }
        while snl.len() >= 3 {
            let name_type = snl[0];
            let name_len = be16(&snl[1..3]);
            snl = &snl[3..];
            if snl.len() < name_len {
                return None;
            }
            let name = &snl[..name_len];
            snl = &snl[name_len..];
            if name_type == 0x00 {
                // host_name
                return Some(String::from_utf8_lossy(name).to_lowercase());
            }
        }
    }
    None
}

/// Extracts the `Host` header (lowercased, without port or brackets) from
/// the leading bytes of a plain HTTP request.
pub fn http_host_from_peek(data: &[u8]) -> Option<String> {
    // Only treat data as HTTP if it starts with a known method token.
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"PATCH ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
    ];
    if !METHODS.iter().any(|m| data.starts_with(m)) {
        return None;
    }
    const KEY: &[u8] = b"host:";
    for line in split_crlf(data) {
        if line.is_empty() {
            break;
        }
        if line.len() >= KEY.len() && line[..KEY.len()].eq_ignore_ascii_case(KEY) {
            let raw = String::from_utf8_lossy(&line[KEY.len()..]);
            let mut host = raw.trim();
            if let Some(i) = host.rfind(':')
                && !host[i..].contains(']')
            {
                host = &host[..i];
            }
            return Some(host.trim_matches(|c| c == '[' || c == ']').to_lowercase());
        }
    }
    None
}

/// Splits on `\r\n` like Go's `bytes.Split(data, "\r\n")`.
fn split_crlf(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(data);
    std::iter::from_fn(move || {
        let cur = rest?;
        match cur.windows(2).position(|w| w == b"\r\n") {
            Some(i) => {
                rest = Some(&cur[i + 2..]);
                Some(&cur[..i])
            }
            None => {
                rest = None;
                Some(cur)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Returns the ClientHello bytes rustls emits for `server_name`.
    fn capture_client_hello(server_name: &str) -> Vec<u8> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name =
            rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("server name");
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).expect("client");
        let mut out = Vec::new();
        conn.write_tls(&mut out).expect("write hello");
        out
    }

    #[test]
    fn extracts_sni() {
        let hello = capture_client_hello("api.example.com");
        assert_eq!(extract_sni(&hello).as_deref(), Some("api.example.com"));
    }

    #[test]
    fn extract_sni_rejects_non_tls() {
        assert_eq!(extract_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
        assert_eq!(extract_sni(&[]), None);
    }

    #[test]
    fn extract_sni_truncated_hello() {
        let hello = capture_client_hello("api.example.com");
        for n in 0..hello.len() {
            // Must never panic on any prefix.
            let _ = extract_sni(&hello[..n]);
        }
    }

    #[test]
    fn http_host_cases() {
        let cases: [(&str, &[u8], Option<&str>); 6] = [
            (
                "simple",
                b"GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n",
                Some("example.com"),
            ),
            (
                "with-port",
                b"POST / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
                Some("example.com"),
            ),
            (
                "case",
                b"GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n",
                Some("example.com"),
            ),
            (
                "ipv6",
                b"GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
                Some("::1"),
            ),
            ("not-http", b"\x16\x03\x01hello", None),
            ("no-host", b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", None),
        ];
        for (name, data, want) in cases {
            assert_eq!(http_host_from_peek(data).as_deref(), want, "{name}");
        }
    }
}
