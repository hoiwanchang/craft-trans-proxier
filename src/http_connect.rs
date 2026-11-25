use crate::base64;
use crate::config::ProxyServer;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::TcpStream;

fn buf_read_until_double_crlf(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while buf.len() < max_bytes {
        let n = stream.read(&mut b)?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "connection closed before HTTP response"));
        }
        buf.push(b[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(buf);
        }
    }
    Err(Error::new(ErrorKind::InvalidData, "HTTP response headers too large"))
}

pub fn connect(stream: &mut TcpStream, proxy: &ProxyServer, host: &str, port: u16) -> Result<(), Error> {
    let host_port = format!("{}:{}", host, port);
    let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", host_port, host_port);
    if let (Some(u), Some(p)) = (proxy.username.as_deref(), proxy.password.as_deref()) {
        let cred = base64::encode(format!("{}:{}", u, p).as_bytes());
        request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;

    let response = buf_read_until_double_crlf(stream, 64 * 1024)?;
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("").to_string();

    if status_line.contains(" 200") || status_line.contains(" 201") || status_line.contains(" 204") {
        return Ok(());
    }
    if status_line.contains(" 407") {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("Proxy Server requires authentication for \"{}\"", host_port),
        ));
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        format!("CONNECT {} failed: {}", host_port, status_line),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn fake_http_proxy(expect_host: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = conn.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(request.starts_with("CONNECT "));
            assert!(request.contains(expect_host));
            std::thread::sleep(std::time::Duration::from_millis(50));
            conn.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        });
        port
    }

    #[test]
    fn connect_succeeds_on_200() {
        let port = fake_http_proxy("example.com:80");
        let proxy = ProxyServer {
            id: 1,
            name: "fake".into(),
            kind: crate::config::ProxyKind::Http,
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            timeout_secs: 5,
        };
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).unwrap();
        assert!(connect(&mut stream, &proxy, "example.com", 80).is_ok());
    }

    #[test]
    fn connect_fails_on_407_with_auth_hint() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = conn.read(&mut buf).unwrap();
            conn.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").unwrap();
        });
        let proxy = ProxyServer {
            id: 1,
            name: "fake".into(),
            kind: crate::config::ProxyKind::Http,
            host: "127.0.0.1".into(),
            port,
            username: None,
            password: None,
            timeout_secs: 5,
        };
        let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).unwrap();
        let err = connect(&mut stream, &proxy, "example.com", 80).unwrap_err();
        assert!(err.to_string().contains("authentication"));
    }
}
