//! HTTP proxy SERVER — the inbound side of fnd_10's "HTTP proxy servers support".
//!
//! An application (or `curl -x http://127.0.0.1:PORT http://host/…`) can point at
//! us as a plain HTTP proxy. Two request shapes arrive:
//!   * `CONNECT host:port HTTP/1.1`  — a tunnel (used for HTTPS).
//!   * `GET http://host/path HTTP/1.1` (absolute-form) — a forwarded HTTP request;
//!     we connect to the host through the rule engine and replay the request with
//!     the URI reduced to origin-form (`/path`).
//!
//! The request-line parsing is pure + unit-tested; `serve` does the I/O.

use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpReq {
    Connect { host: String, port: u16 },
    Forward { method: String, host: String, port: u16, origin_uri: String },
}

fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    // IPv6 literal: [::1]:8080
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let after = &rest[end + 1..];
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(default_port);
            return Some((host, port));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(port) => Some((h.to_string(), port)),
            Err(_) => Some((s.to_string(), default_port)), // trailing non-numeric colon
        },
        None => Some((s.to_string(), default_port)),
    }
}

fn strip_origin(uri: &str) -> String {
    // "http://host:8080/a/b?c" -> "/a/b?c"; if no path, "/".
    if let Some(after_scheme) = uri.find("://") {
        let rest = &uri[after_scheme + 3..];
        match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".to_string(),
        }
    } else if uri.starts_with('/') {
        uri.to_string()
    } else {
        format!("/{uri}")
    }
}

/// Parse an HTTP request line, e.g. `CONNECT example.com:443 HTTP/1.1` or
/// `GET http://example.com/path HTTP/1.1`. Headers are consumed by the caller.
pub fn parse_request_line(line: &str) -> Option<HttpReq> {
    let mut it = line.trim_end().split_whitespace();
    let method = it.next()?.to_string();
    let target = it.next()?;
    it.next()?; // version — must be present (HTTP/1.x)
    let method_up = method.to_ascii_uppercase();
    if method_up == "CONNECT" {
        let (host, port) = split_host_port(target, 443)?;
        return Some(HttpReq::Connect { host, port });
    }
    // absolute-form implies a proxy request
    if let Some(after_scheme) = target.find("://") {
        let scheme = target[..after_scheme].to_ascii_lowercase();
        let default_port = if scheme == "https" { 443 } else { 80 };
        let rest = &target[after_scheme + 3..];
        let authority = match rest.find('/') {
            Some(i) => &rest[..i],
            None => rest,
        };
        let (host, port) = split_host_port(authority, default_port)?;
        let origin_uri = strip_origin(target);
        return Some(HttpReq::Forward { method, host, port, origin_uri });
    }
    None // origin-form / other — not a proxy request we serve
}

/// Read request lines + headers from the stream until the blank line, returning
/// the parsed request plus the raw header block (so forwarding can replay it).
fn read_head(stream: &mut TcpStream) -> std::io::Result<(String, Vec<String>)> {
    let mut line = String::new();
    let mut c = [0u8; 1];
    loop {
        let n = stream.read(&mut c)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        if c[0] == b'\n' {
            break;
        }
        if c[0] != b'\r' {
            line.push(c[0] as char);
        }
    }
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        loop {
            let n = stream.read(&mut c)?;
            if n == 0 {
                return Ok((line, headers));
            }
            if c[0] == b'\n' {
                break;
            }
            if c[0] != b'\r' {
                h.push(c[0] as char);
            }
        }
        if h.is_empty() {
            return Ok((line, headers));
        }
        headers.push(h);
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "proxy-connection" || n.starts_with("proxy-") || n == "keep-alive" || n == "te" || n == "trailer" || n == "transfer-encoding" || n == "upgrade"
}

/// Serve one HTTP proxy request. CONNECT tunnels via `tunnel`; absolute-form
/// forwards by replaying the request (origin-form URI, non-hop-by-hop headers)
/// to the upstream and copying the response back. `connect` establishes the
/// upstream (rule-routed) TCP stream.
pub fn handle<F, T>(stream: &mut TcpStream, connect: F, tunnel: T) -> std::io::Result<()>
where
    F: Fn(&str, u16) -> std::io::Result<TcpStream>,
    T: Fn(TcpStream, TcpStream) -> std::io::Result<()>,
{
    let (request_line, headers) = read_head(stream)?;
    let req = match parse_request_line(&request_line) {
        Some(r) => r,
        None => {
            stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")?;
            return Ok(());
        }
    };
    match req {
        HttpReq::Connect { host, port } => {
            let upstream = connect(&host, port)?;
            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
            let client = stream.try_clone()?;
            tunnel(client, upstream)
        }
        HttpReq::Forward { method, host, port, origin_uri } => {
            let mut upstream = connect(&host, port)?;
            let mut replay = format!("{method} {origin_uri} HTTP/1.1\r\n");
            for h in &headers {
                let name = h.split(':').next().unwrap_or("");
                if !is_hop_by_hop(name) {
                    replay.push_str(h);
                    replay.push_str("\r\n");
                }
            }
            replay.push_str("\r\n");
            upstream.write_all(replay.as_bytes())?;
            // stream the response back
            let mut buf = [0u8; 16 * 1024];
            loop {
                match upstream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect() {
        assert_eq!(
            parse_request_line("CONNECT example.com:443 HTTP/1.1"),
            Some(HttpReq::Connect { host: "example.com".into(), port: 443 })
        );
    }

    #[test]
    fn parses_absolute_get_default_port() {
        match parse_request_line("GET http://example.com/a/b?q=1 HTTP/1.1") {
            Some(HttpReq::Forward { method, host, port, origin_uri }) => {
                assert_eq!(method, "GET");
                assert_eq!(host, "example.com");
                assert_eq!(port, 80); // http default
                assert_eq!(origin_uri, "/a/b?q=1");
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }

    #[test]
    fn parses_absolute_get_with_explicit_port() {
        match parse_request_line("POST http://127.0.0.1:8080/path HTTP/1.1") {
            Some(HttpReq::Forward { host, port, origin_uri, .. }) => {
                assert_eq!(host, "127.0.0.1");
                assert_eq!(port, 8080);
                assert_eq!(origin_uri, "/path");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn https_scheme_defaults_443_and_no_path_is_slash() {
        match parse_request_line("GET https://secure.example.com HTTP/1.1") {
            Some(HttpReq::Forward { host, port, origin_uri, .. }) => {
                assert_eq!(host, "secure.example.com");
                assert_eq!(port, 443);
                assert_eq!(origin_uri, "/");
            }
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn rejects_origin_form_and_garbage() {
        // origin-form GET is a normal server request, not a proxy request
        assert_eq!(parse_request_line("GET /index.html HTTP/1.1"), None);
        assert_eq!(parse_request_line("not a request"), None);
        assert_eq!(parse_request_line(""), None);
    }

    #[test]
    fn ipv6_authority_with_port() {
        match parse_request_line("CONNECT [::1]:8443 HTTP/1.1") {
            Some(HttpReq::Connect { host, port }) => {
                assert_eq!(host, "::1");
                assert_eq!(port, 8443);
            }
            other => panic!("got {other:?}"),
        }
    }
}
