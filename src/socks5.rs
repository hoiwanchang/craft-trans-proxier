use crate::config::ProxyServer;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};

fn parse_ip_or_domain(host: &str) -> (u8, Vec<u8>) {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        (0x01, ip.octets().to_vec())
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        (0x04, ip.octets().to_vec())
    } else {
        (0x03, host.as_bytes().to_vec())
    }
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "connection closed mid-handshake"));
        }
        filled += n;
    }
    Ok(())
}

fn send_greeting_and_authenticate(
    stream: &mut TcpStream,
    proxy: &ProxyServer,
) -> Result<(), Error> {
    let mut methods = vec![0x00u8];
    if proxy.username.is_some() && proxy.password.is_some() {
        methods.push(0x02);
    }
    stream.write_all(&[0x05, methods.len() as u8])?;
    stream.write_all(&methods)?;
    let mut reply = [0u8; 2];
    read_exact(stream, &mut reply)?;
    if reply[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 greeting reply"));
    }
    match reply[1] {
        0x00 => Ok(()),
        0x02 => {
            let (u, p) = (proxy.username.as_deref().unwrap(), proxy.password.as_deref().unwrap());
            let ub = u.as_bytes();
            let pb = p.as_bytes();
            if ub.len() > 255 || pb.len() > 255 {
                return Err(Error::new(ErrorKind::InvalidInput, "username/password too long"));
            }
            stream.write_all(&[0x01, ub.len() as u8])?;
            stream.write_all(ub)?;
            stream.write_all(&[pb.len() as u8])?;
            stream.write_all(pb)?;
            let mut sub = [0u8; 2];
            read_exact(stream, &mut sub)?;
            if sub[0] != 0x01 {
                return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 auth sub-negotiation reply"));
            }
            if sub[1] == 0x01 {
                return Err(Error::new(ErrorKind::PermissionDenied, "SOCKS5 proxy rejected credentials"));
            }
            Ok(())
        }
        other => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("SOCKS5 proxy requires unsupported method 0x{other:02x}"),
        )),
    }
}

pub fn connect(stream: &mut TcpStream, proxy: &ProxyServer, host: &str, port: u16) -> Result<(), Error> {
    send_greeting_and_authenticate(stream, proxy)?;

    let (atyp, addr_data) = parse_ip_or_domain(host);
    let mut req = vec![0x05, 0x01, 0x00, atyp];
    match atyp {
        0x01 => req.extend_from_slice(&addr_data),
        0x04 => req.extend_from_slice(&addr_data),
        0x03 => {
            req.push(addr_data.len() as u8);
            req.extend_from_slice(&addr_data);
        }
        _ => return Err(Error::new(ErrorKind::InvalidInput, "unsupported ATYP")),
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req)?;

    let mut head = [0u8; 4];
    read_exact(stream, &mut head)?;
    if head[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 reply version"));
    }
    let code = head[1];
    if code != 0x00 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("SOCKS5 connection failed: reply code {}", code),
        ));
    }
    let atyp = head[3];
    let addr_len = match atyp {
        0x01 => 4usize,
        0x04 => 16usize,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len)?;
            len[0] as usize
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 reply ATYP")),
    };
    let mut addr = vec![0u8; addr_len];
    read_exact(stream, &mut addr)?;
    let mut port_bytes = [0u8; 2];
    read_exact(stream, &mut port_bytes)?;
    Ok(())
}

pub fn resolve_to_ip(host: &str, port: u16) -> Result<IpAddr, Error> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| Error::new(ErrorKind::NotFound, format!("cannot resolve {}:{}", host, port)))
}

// --- SOCKS5 UDP ASSOCIATE datagram framing (RFC 1928 section 7) -------------
// +----+------+------+----------+----------+----------+
// |RSV  |FRAG  | ATYP   | BND.ADDR | BND.PORT | data     |
// +----+------+------+----------+----------+----------+
// |2    |1     |1       |varies    |2         |varies    |

/// Client side of SOCKS5 UDP ASSOCIATE: negotiate with `proxy` over the (already
/// connected) `stream`, returning the proxy's UDP relay endpoint to send framed
/// datagrams to. The caller must keep `stream` open for the association's life.
pub fn udp_associate(stream: &mut TcpStream, proxy: &ProxyServer) -> Result<SocketAddr, Error> {
    send_greeting_and_authenticate(stream, proxy)?;
    // UDP ASSOCIATE, DST.ADDR = 0.0.0.0:0 (we forward to whatever the app targets)
    stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?;
    let mut head = [0u8; 4];
    read_exact(stream, &mut head)?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(Error::new(ErrorKind::InvalidData, format!("SOCKS5 UDP ASSOCIATE failed: {}", head[1])));
    }
    // Parse BND.ADDR/BND.PORT (the relay address the proxy advertises).
    let ip = match head[3] {
        0x01 => {
            let mut a = [0u8; 4];
            read_exact(stream, &mut a)?;
            IpAddr::from(a)
        }
        0x03 => {
            // Domain bound address is uncommon; we cannot dial it without the
            // proxy's IP, so fall back to the proxy host.
            let mut len = [0u8; 1];
            read_exact(stream, &mut len)?;
            let mut d = vec![0u8; len[0] as usize];
            read_exact(stream, &mut d)?;
            resolve_to_ip(&proxy.host, 0)?
        }
        0x04 => {
            let mut a = [0u8; 16];
            read_exact(stream, &mut a)?;
            IpAddr::from(a)
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "bad ATYP in UDP reply")),
    };
    let mut pb = [0u8; 2];
    read_exact(stream, &mut pb)?;
    let mut port = u16::from_be_bytes(pb);
    if port == 0 {
        port = proxy.port; // some proxies echo 0 and reuse their own port
    }
    Ok(SocketAddr::new(ip, port))
}

/// Wrap a UDP payload with the SOCKS5 request header carrying the destination.
pub fn udp_frame(dst: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(0)
    match dst {
        SocketAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Parse a framed SOCKS5 UDP datagram into (origin/destination address, payload).
pub fn parse_udp_frame(buf: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buf.len() < 8 {
        return None;
    }
    // buf[0..2] RSV, buf[2] FRAG (0 = whole datagram), buf[3] ATYP.
    if buf[2] != 0 {
        return None; // fragmentation not supported in this build
    }
    let (addr, hdr_len) = match buf[3] {
        0x01 => {
            if buf.len() < 10 {
                return None;
            }
            let ip = [buf[4], buf[5], buf[6], buf[7]];
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (SocketAddr::from((IpAddr::from(ip), port)), 10usize)
        }
        0x04 => {
            if buf.len() < 22 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[4..20]);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (SocketAddr::from((IpAddr::from(ip), port)), 22usize)
        }
        _ => return None,
    };
    Some((addr, &buf[hdr_len..]))
}

#[cfg(test)]
mod udp_tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn udp_frame_roundtrips_v4() {
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443));
        let framed = udp_frame(&dst, b"hello-udp");
        let (parsed, payload) = parse_udp_frame(&framed).unwrap();
        assert_eq!(parsed, dst);
        assert_eq!(payload, b"hello-udp");
    }

    #[test]
    fn parse_rejects_fragmented_and_short() {
        let mut f = udp_frame(
            &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80)),
            b"x",
        );
        f[2] = 1; // set FRAG != 0
        assert!(parse_udp_frame(&f).is_none());
        assert!(parse_udp_frame(&[0, 0, 0]).is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DNS-through-the-proxy has to survive an IPv6 resolver: a query dialled at
    /// 2606:4700:4700::1111:53 must go out as ATYP 0x04 with 16 address bytes, not as
    /// a 22-character "domain" that the egress proxy would try to resolve itself.
    #[test]
    fn connect_frames_an_ipv6_resolver_target_as_atyp4() {
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut g = [0u8; 3];
            c.read_exact(&mut g).unwrap();
            c.write_all(&[0x05, 0x00]).unwrap(); // no auth
            let mut req = vec![0u8; 64];
            let n = c.read(&mut req).unwrap();
            req.truncate(n);
            c.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(50));
            req
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let proxy = ProxyServer {
            id: 1,
            name: "p".into(),
            kind: crate::config::ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: addr.port(),
            username: None,
            password: None,
            timeout_secs: 5,
        };
        connect(&mut stream, &proxy, "2606:4700:4700::1111", 53).expect("connect through the proxy");
        let req = server.join().unwrap();
        assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x04], "VER CMD RSV ATYP");
        assert_eq!(req.len(), 4 + 16 + 2, "a v6 target is 16 bytes plus the port");
        let ip = &req[4..20];
        assert_eq!(&ip[..2], &[0x26, 0x06]);
        assert_eq!(&ip[14..16], &[0x11, 0x11]);
        assert_eq!(&req[20..], &[0x00, 0x35], "port in network order");
    }

    #[test]
    fn udp_frame_roundtrips_v6() {
        let dst: SocketAddr = "[2001:db8::5]:53".parse().unwrap();
        let framed = udp_frame(&dst, b"query");
        assert_eq!(framed[3], 0x04, "ATYP 4 for IPv6");
        assert_eq!(framed.len(), 3 + 1 + 16 + 2 + 5);
        let (back, payload) = parse_udp_frame(&framed).expect("parses back");
        assert_eq!(back, dst, "the v6 destination survives the framing");
        assert_eq!(payload, b"query");
    }

    #[test]
    fn parses_domain_target() {
        let (atyp, data) = parse_ip_or_domain("example.com");
        assert_eq!(atyp, 0x03);
        assert_eq!(data, b"example.com");
    }

    #[test]
    fn parses_ipv4_and_ipv6_targets() {
        let (atyp, data) = parse_ip_or_domain("127.0.0.1");
        assert_eq!(atyp, 0x01);
        assert_eq!(data, vec![127, 0, 0, 1]);
        let (atyp, data) = parse_ip_or_domain("::1");
        assert_eq!(atyp, 0x04);
        assert_eq!(data.len(), 16);
    }
}
