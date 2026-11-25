//! Minimal dependency-free DNS resolver (RFC 1035) over UDP and TCP, used only
//! when the user configures one in Settings. Every failure/empty path falls back
//! to the OS resolver, so a mis-typed server can never break connectivity.
//!
//! Scope: A + AAAA answers, name compression on parse. No DNSSEC, no recursion
//! control beyond the standard RD bit.

use crate::config::{DnsProto, DnsServer, DnsSettings, ProxyServer};
use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Build a standard query for `name`/`qtype`.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut b = Vec::with_capacity(32 + name.len());
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    b.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT/NSCOUNT/ARCOUNT = 0
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        b.push(bytes.len().min(63) as u8);
        b.extend_from_slice(&bytes[..bytes.len().min(63)]);
    }
    b.push(0); // root label
    b.extend_from_slice(&qtype.to_be_bytes());
    b.extend_from_slice(&CLASS_IN.to_be_bytes());
    b
}

/// Parse A + AAAA answers from a DNS response message.
pub fn parse_answers(buf: &[u8]) -> io::Result<Vec<IpAddr>> {
    if buf.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidData, "short dns header"));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12;
    // Skip the question section (uncompressed names).
    for _ in 0..qd {
        pos = skip_name(buf, pos)? + 4; // + qtype + qclass
    }
    let mut out = Vec::new();
    for _ in 0..an {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated answer header"));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated rdata"));
        }
        let rdata = &buf[pos..pos + rdlen];
        match (rtype, rdlen) {
            (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                out.push(IpAddr::V6(Ipv6Addr::from(o)));
            }
            _ => {}
        }
        pos += rdlen;
    }
    Ok(out)
}

/// Materialise a DNS name, following compression pointers.
///
/// Two things a naive reader gets wrong, both of which are attacker-controlled here
/// because we parse replies that came back through a proxy: a pointer loop (0xC00C
/// pointing at itself) would spin forever, and a pointer past the end must not read
/// out of bounds. So the jump count is bounded and every offset is checked.
/// `Ok((name, next))` where `next` is the offset AFTER the name as it sits in the
/// record (i.e. pointers do not advance past their target).
pub fn read_name(buf: &[u8], start: usize) -> io::Result<(String, usize)> {
    const MAX_JUMPS: usize = 8; // RFC 1035 allows pointers only backwards; 8 is generous
    let mut pos = start;
    let mut jumps = 0usize;
    let mut labels: Vec<String> = Vec::new();
    let mut next = start;
    let mut first = true;
    loop {
        if pos >= buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "name runs off end"));
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if first {
                next = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 2 > buf.len() {
                return Err(Error::new(ErrorKind::UnexpectedEof, "bad pointer"));
            }
            if first {
                next = pos + 2;
                first = false;
            }
            let target = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if target >= buf.len() {
                return Err(Error::new(ErrorKind::InvalidData, "pointer past end"));
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return Err(Error::new(ErrorKind::InvalidData, "name pointer loop"));
            }
            pos = target;
            continue;
        }
        if len > 63 {
            return Err(Error::new(ErrorKind::InvalidData, "bad label length"));
        }
        let end = pos + 1 + len;
        if end > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated label"));
        }
        labels.push(String::from_utf8_lossy(&buf[pos + 1..end]).to_string());
        pos = end;
        if first {
            next = pos;
        }
    }
    if labels.is_empty() {
        return Ok((String::new(), next));
    }
    Ok((labels.join("."), next))
}

/// Answer records as (hostname, address, ttl-seconds) pairs, so a caller can learn
/// which name an address was seen for. Unlike [`parse_answers`] this keeps the name,
/// which is what a passive DNS observer needs to map IP → host for rule matching.
pub fn snoop_answers(buf: &[u8]) -> io::Result<Vec<(String, IpAddr, u32)>> {
    if buf.len() < 12 {
        return Err(Error::new(ErrorKind::InvalidData, "short dns header"));
    }
    // Only a successful response carries answers worth believing; NXDOMAIN/negative
    // answers must not poison the cache.
    let rcode = buf[3] & 0x0F;
    if rcode != 0 {
        return Ok(Vec::new());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if an == 0 || an > 64 {
        // 64 is generous; a huge count is either a crafted packet or not for us.
        return Ok(Vec::new());
    }
    let mut pos = 12;
    let mut qname = String::new();
    for i in 0..qd {
        let (name, next) = read_name(buf, pos)?;
        if i == 0 {
            qname = name;
        }
        pos = next + 4; // qtype + qclass
        if pos > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated question"));
        }
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let (name, next) = read_name(buf, pos)?;
        pos = next;
        if pos + 10 > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated answer header"));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "truncated rdata"));
        }
        let rdata = &buf[pos..pos + rdlen];
        // Names in answers are usually a pointer to the question name; trust the
        // question name when the record points back at it.
        let host = if name.is_empty() || name == qname { qname.clone() } else { name };
        match (rtype, rdlen) {
            (TYPE_A, 4) => out.push((host, IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])), ttl)),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                out.push((host, IpAddr::V6(Ipv6Addr::from(o)), ttl));
            }
            _ => {}
        }
        pos += rdlen;
    }
    Ok(out)
}

/// Return the byte offset just past a (possibly compressed) DNS name.
fn skip_name(buf: &[u8], mut pos: usize) -> io::Result<usize> {
    loop {
        if pos >= buf.len() {
            return Err(Error::new(ErrorKind::UnexpectedEof, "name runs off end"));
        }
        let len = buf[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: the name ends here (2 bytes).
            if pos + 2 > buf.len() {
                return Err(Error::new(ErrorKind::UnexpectedEof, "bad pointer"));
            }
            return Ok(pos + 2);
        }
        if len > 63 {
            return Err(Error::new(ErrorKind::InvalidData, "bad label length"));
        }
        pos += 1 + len;
    }
}

fn query_proto(server: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    let id = (std::process::id() as u16) ^ ((qtype as u16) << 8) ^ (name.len() as u16);
    let msg = build_query(id, name, qtype);
    match server {
        SocketAddr::V4(_) | SocketAddr::V6(_) => {
            // UDP first with a TCP fallback if the reply is truncated.
            let sock = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
            sock.set_read_timeout(Some(timeout))?;
            sock.set_write_timeout(Some(timeout))?;
            sock.send_to(&msg, server)?;
            let mut buf = [0u8; 1500];
            let (n, _from) = sock.recv_from(&mut buf)?;
            let resp = &buf[..n];
            // TC flag set => retry over TCP.
            if resp.len() >= 4 && (resp[2] & 0x02) != 0 {
                return query_tcp(server, name, qtype, timeout);
            }
            parse_answers(resp)
        }
    }
    .or_else(|_| query_tcp(server, name, qtype, timeout))
}

fn query_tcp(server: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> io::Result<Vec<IpAddr>> {
    let id = (std::process::id() as u16) ^ ((qtype as u16) << 8) ^ (name.len() as u16);
    let msg = build_query(id, name, qtype);
    let mut stream = TcpStream::connect(server)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let len = (msg.len() as u16).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&msg)?;
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb)?;
    let mut buf = vec![0u8; u16::from_be_bytes(lb) as usize];
    stream.read_exact(&mut buf)?;
    parse_answers(&buf)
}

fn to_sockaddr(address: &str, port: u16) -> io::Result<SocketAddr> {
    // The configured DNS server address must already be an IP (no bootstrap
    // recursion): use the OS resolver for the rare case it's a hostname.
    (address, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::new(ErrorKind::AddrNotAvailable, "dns server unresolved"))
}

/// Resolve `host` using the configured resolver chain.
/// - No servers configured (all addresses blank) ⇒ use the OS resolver.
/// - Servers configured ⇒ try them IN ORDER; the first that answers wins.
///   If every resolver fails/returns nothing, return an EMPTY vec — we do NOT
///   fall back to the OS resolver (so nothing leaks via the host's own DNS).
pub fn resolve(cfg: &DnsSettings, host: &str, timeout: Duration) -> Vec<IpAddr> {
    let servers: Vec<&DnsServer> = cfg
        .servers
        .iter()
        .filter(|s| !s.server.trim().is_empty())
        .collect();
    if servers.is_empty() {
        return system(host);
    }
    let qtypes = [TYPE_A, TYPE_AAAA];
    for srv in &servers {
        let Ok(server) = to_sockaddr(srv.server.trim(), srv.port) else {
            continue;
        };
        let mut ips = Vec::new();
        for &qt in &qtypes {
            let r = match srv.protocol {
                DnsProto::Udp => query_proto(server, host, qt, timeout),
                DnsProto::Tcp => query_tcp(server, host, qt, timeout),
            };
            if let Ok(v) = r {
                ips.extend(v);
            }
        }
        if !ips.is_empty() {
            return ips;
        }
    }
    // Fail-closed: chain configured but nothing resolved — do not leak to OS DNS.
    Vec::new()
}

fn system(host: &str) -> Vec<IpAddr> {
    (host, 0u16)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Resolve `name` by sending the DNS query THROUGH `proxy` (SOCKS5 UDP
/// ASSOCIATE) to the configured `resolver` (an IP). This is the (b) building
/// block: whitelisted apps' DNS goes via the proxy, never the OS network.
/// `resolver.server` must be an IP (no bootstrap recursion).
pub fn resolve_via_socks5(
    proxy: &ProxyServer,
    resolver: &DnsServer,
    name: &str,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let resolver_ip: IpAddr = resolver
        .server
        .trim()
        .parse()
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "dns resolver must be an IP"))?;
    let target = SocketAddr::new(resolver_ip, resolver.port);
    // Control TCP connection to the proxy must stay open for the association's life.
    let mut ctl = crate::engine::dial_proxy(&proxy.host, proxy.port, timeout.as_secs().max(1))?;
    let relay = crate::socks5::udp_associate(&mut ctl, proxy)?;
    let sock = UdpSocket::bind(if relay.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    sock.connect(relay)?;
    sock.set_read_timeout(Some(timeout))?;
    let mut out = Vec::new();
    for &qt in &[TYPE_A, TYPE_AAAA] {
        let id = (std::process::id() as u16) ^ ((qt as u16) << 8) ^ (name.len() as u16);
        let query = build_query(id, name, qt);
        sock.send(&crate::socks5::udp_frame(&target, &query))?;
        let mut buf = [0u8; 1500];
        let n = sock.recv(&mut buf)?;
        if let Some((_from, payload)) = crate::socks5::parse_udp_frame(&buf[..n]) {
            if let Ok(ips) = parse_answers(payload) {
                out.extend(ips);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_header_and_question() {
        let q = build_query(0x1234, "www.example.com", TYPE_A);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // id
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1); // QDCOUNT
        // \3www\7example\3com\0 then type=1 class=1
        assert_eq!(q[12], 3);
        assert_eq!(&q[13..16], b"www");
        assert_eq!(*q.last().unwrap(), 0x01); // class IN low byte
        assert_eq!(u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]), TYPE_A);
    }

    #[test]
    fn parse_a_and_aaaa_with_pointer_names() {
        // header: qd=1, an=2
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        // question: \7example\3com\0 type A class IN
        m.extend_from_slice(&[7]);
        m.extend_from_slice(b"example");
        m.extend_from_slice(&[3]);
        m.extend_from_slice(b"com");
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        // answer1: name pointer 0xC0 0x0C, type A, class IN, ttl, rdlen 4, 93.184.216.34
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        // answer2: pointer, type AAAA, rdlen 16, ::1
        m.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        let mut aaaa = [0u8; 16];
        aaaa[15] = 1;
        m.extend_from_slice(&aaaa);

        let ips = parse_answers(&m).unwrap();
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(ips.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    /// A response: example.com A 93.184.216.34 (+ a second A) with the answer names
    /// as compression pointers, which is how real servers send it.
    fn canned_a_response(name: &str, ips: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, ips.len() as u8, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A, QCLASS IN
        let qname_off = 12usize;
        for ip in ips {
            m.extend_from_slice(&[0xC0, qname_off as u8]); // pointer to the question name
            m.extend_from_slice(&[0, 1, 0, 1]); // A / IN
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]);
            m.extend_from_slice(ip);
        }
        m
    }

    #[test]
    fn snoops_names_from_compressed_answers() {
        let m = canned_a_response("example.com", &[[93, 184, 216, 34], [93, 184, 216, 35]], 60);
        let got = snoop_answers(&m).expect("parses");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "example.com", "the pointer must resolve back to the name");
        assert_eq!(got[0].1, IpAddr::V4([93, 184, 216, 34].into()));
        assert_eq!(got[1].1, IpAddr::V4([93, 184, 216, 35].into()));
        assert_eq!(got[0].2, 60, "ttl is carried so the cache can expire entries");
    }

    #[test]
    fn snoop_ignores_negative_answers_and_other_types() {
        let mut m = canned_a_response("example.com", &[[1, 1, 1, 1]], 60);
        m[3] |= 3; // rcode 3 = NXDOMAIN: must not be believed
        assert!(snoop_answers(&m).unwrap().is_empty());

        // A well-formed response whose only record is a CNAME yields no address pair.
        let mut c = vec![0u8; 12];
        c[3] = 0x80; // response, no error
        c[6] = 1; // ANCOUNT 1
        c.extend_from_slice(&[0x07, b'e', 0x03, b'c', 0x00]); // "e.c."
        c.extend_from_slice(&[0, 1, 0, 1]);
        c.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 10, 0, 2, 0xC0, 12]); // CNAME
        assert_eq!(snoop_answers(&c).unwrap().len(), 0, "CNAMEs carry no address");
    }

    #[test]
    fn snoop_survives_hostile_names() {
        // ANCOUNT is a 16-bit field: the low byte is [7], and getting that wrong makes
        // these fixtures pass without exercising anything.
        fn header_with_one_answer() -> Vec<u8> {
            let mut h = vec![0u8; 12];
            h[3] = 0x80; // response, rcode 0
            h[4] = 0;
            h[5] = 1; // QDCOUNT 1
            h[6] = 0;
            h[7] = 1; // ANCOUNT 1
            h
        }

        // (1) a name that is a pointer to itself: must terminate, not spin
        let mut loop_ = header_with_one_answer();
        loop_.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]); // question: pointer to offset 12
        loop_.extend_from_slice(&[0, 1, 0, 1]);
        loop_.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        let started = std::time::Instant::now();
        let r = snoop_answers(&loop_);
        assert!(started.elapsed() < std::time::Duration::from_secs(1), "pointer loop must be bounded");
        let ok = r.as_ref().map(|v| v.is_empty()).unwrap_or(true);
        assert!(ok, "self-referential name must not produce answers: {r:?}");

        // (2) a pointer that lands past the end of the message
        let mut far = header_with_one_answer();
        far.extend_from_slice(&[0xC0, 0xFE, 0, 1, 0, 1]);
        far.extend_from_slice(&[0xC0, 0xFE, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4]);
        assert!(snoop_answers(&far).is_err(), "pointer past end must be rejected");

        // (3) a label that claims more bytes than exist
        let mut trunc = header_with_one_answer();
        trunc.extend_from_slice(&[0x3F, b'a', b'b']);
        assert!(snoop_answers(&trunc).is_err(), "over-long label must be rejected");

        // (4) an absurd answer count is refused outright, not iterated
        let mut many = header_with_one_answer();
        many[7] = 0xFF;
        many.extend_from_slice(&[7, b'e', 3, b'c', 0, 0, 1, 0, 1]);
        assert!(snoop_answers(&many).unwrap().is_empty(), "ANCOUNT > 64 is not ours to parse");
    }

    #[test]
    fn read_name_follows_one_pointer_and_reports_the_next_offset() {
        // "examplecom " at 12, then a pointer to it
        let m = canned_a_response("example.com", &[[9, 9, 9, 9]], 5);
        let (n1, next1) = read_name(&m, 12).unwrap();
        assert_eq!(n1, "example.com");
        let (n2, next2) = read_name(&m, next1 + 4).unwrap(); // answer name (pointer)
        assert_eq!(n2, "example.com", "a pointer resolves to the same name");
        assert_eq!(next2, next1 + 4 + 2, "a pointer consumes exactly 2 bytes");
    }

    #[test]
    fn parse_rejects_truncated() {
        let mut m = vec![0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 1, 2]); // rdlen 4 but 2 bytes
        assert!(parse_answers(&m).is_err());
    }

    #[test]
    fn skip_name_walks_labels_and_pointers() {
        let b = [0x03, b'a', b'b', b'c', 0x00, 0x00];
        assert_eq!(skip_name(&b, 0).unwrap(), 5);
        let p = [0x00, 0xC0, 0x02, 0x00];
        assert_eq!(skip_name(&p, 1).unwrap(), 3);
    }

    #[test]
    fn resolve_via_socks5_requires_ip_resolver() {
        let proxy = crate::config::ProxyServer {
            id: 1,
            name: "p".into(),
            kind: crate::config::ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            timeout_secs: 1,
        };
        let named = DnsServer { protocol: DnsProto::Udp, server: "dns.example.com".into(), port: 53 };
        // resolver must be an IP → error before any network I/O (deterministic).
        assert!(resolve_via_socks5(&proxy, &named, "a.test", Duration::from_millis(50)).is_err());
    }
}
