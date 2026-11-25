//! DNS observation ("snooping") end to end, driven through the engine's own relays.
//!
//! Why this matters for the goal: the WFP route has no `getaddrinfo` hook, so a
//! redirected connection only ever shows up as an IP address. Unless the engine knows
//! which hostname that IP came from — learned from the DNS answer it carried a moment
//! earlier — every `*.example.com` rule silently stops matching there. This test
//! proves that chain works, without a driver or a socket hook:
//!
//!   app → engine UDP relay → SOCKS5 (returns a real DNS answer) → observation table
//!   app → engine TCP relay (destination is a bare IP) → hostname rule matches → proxied
//!
//! If the observation did not happen, the TCP step would fall through to Direct, dial
//! 203.0.113.77 for real (TEST-NET-3, unreachable here) and the echo would never come
//! back — so a green test means the name was genuinely recovered.

#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use trans_proxier::config::{Chain, Config, DnsMode, ProxyKind, ProxyServer, Rule, RuleAction};
use trans_proxier::intercept::{self, Req, MAGIC};
use trans_proxier::monitor::Monitor;

/// "snooped.example.com" A 203.0.113.77, answer name as a compression pointer.
fn dns_answer_for(name: &str, ip: [u8; 4]) -> Vec<u8> {
    let mut m = vec![0u8; 12];
    m[2] = 0x81; // QR=1, RD=1
    m[3] = 0x80; // RA=1, RCODE=0
    m[0] = 0xAB;
    m[1] = 0xCD;
    // Header flags span two bytes: [2] = QR AA TC RD, [3] = RA Z AD CD with RCODE in
    // its LOW NIBBLE. A non-zero rcode is (correctly) ignored by the observer.
    m[5] = 1; // QDCOUNT
    m[7] = 1; // ANCOUNT
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&[0, 1, 0, 1]); // QTYPE A / QCLASS IN
    m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]); // pointer to the question name, A / IN
    m.extend_from_slice(&60u32.to_be_bytes());
    m.extend_from_slice(&[0, 4]);
    m.extend_from_slice(&ip);
    m
}

/// A SOCKS5 server that echoes CONNECT traffic and answers a UDP query for port 53
/// with `dns_answer()` — enough to carry the app's resolver traffic and no more.
fn dns_answer() -> Vec<u8> {
    dns_answer_for("snooped.example.com", [203, 0, 113, 77])
}

/// Returns the listen port and a stream of "host:port" strings the engine asked this
/// proxy to CONNECT to — so a test can assert on the NAME, which is the real claim.
fn spawn_socks5() -> (u16, std::sync::mpsc::Receiver<String>) {
    let (tx, rx) = std::sync::mpsc::channel();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || {
                let mut g = [0u8; 2];
                if c.read_exact(&mut g).is_err() {
                    return;
                }
                let mut meth = vec![0u8; g[1] as usize];
                if c.read_exact(&mut meth).is_err() || c.write_all(&[5, 0]).is_err() {
                    return;
                }
                let mut head = [0u8; 4];
                if c.read_exact(&mut head).is_err() {
                    return;
                }
                // Consume the WHOLE target: ATYP decides the address length, and a
                // fixed-size read leaves request bytes in the socket — which an echo
                // server then hands back as if the app had sent them.
                let mut target = String::new();
                let mut tport = 0u16;
                let read_target = match head[3] {
                    1 => {
                        let mut a = [0u8; 6];
                        c.read_exact(&mut a).map(|_| {
                            tport = u16::from_be_bytes([a[4], a[5]]);
                            target = format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
                        })
                    }
                    4 => {
                        let mut a = [0u8; 18];
                        c.read_exact(&mut a).map(|_| {
                            tport = u16::from_be_bytes([a[16], a[17]]);
                            target = "v6".to_string();
                        })
                    }
                    3 => {
                        let mut n = [0u8; 1];
                        c.read_exact(&mut n).and_then(|_| {
                            let mut d = vec![0u8; n[0] as usize + 2];
                            c.read_exact(&mut d).map(|_| {
                                let len = n[0] as usize;
                                tport = u16::from_be_bytes([d[len], d[len + 1]]);
                                target = String::from_utf8_lossy(&d[..len]).to_string();
                            })
                        })
                    }
                    other => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unsupported ATYP {other}"),
                    )),
                };
                if read_target.is_err() {
                    return;
                }
                if head[1] != 3 {
                    // CONNECT: report what the engine actually asked to reach
                    let _ = tx.send(format!("{target}:{tport}"));
                    // CONNECT: pretend success, then echo
                    if c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).is_err() {
                        return;
                    }
                    if tport == 53 {
                        // DNS over TCP is [2-byte length][message]: read the query and
                        // answer with one framed reply, so the engine's tap has
                        // something real to find a name in.
                        let mut lb = [0u8; 2];
                        if c.read_exact(&mut lb).is_err() {
                            return;
                        }
                        let mut q = vec![0u8; u16::from_be_bytes(lb) as usize];
                        if c.read_exact(&mut q).is_err() {
                            return;
                        }
                        let ans = dns_answer_for("snooped-tcp.example.com", [203, 0, 113, 99]);
                        let pb = (ans.len() as u16).to_be_bytes();
                        let _ = c.write_all(&pb);
                        let _ = c.write_all(&ans);
                        return;
                    }
                    let mut b = [0u8; 4096];
                    while let Ok(n) = c.read(&mut b) {
                        if n == 0 || c.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                    return;
                }
                // UDP ASSOCIATE: hand the client a relay endpoint and answer :53
                let us = UdpSocket::bind("127.0.0.1:0").unwrap();
                let up = us.local_addr().unwrap();
                let octets = match up { std::net::SocketAddr::V4(v) => v.ip().octets(), _ => [127, 0, 0, 1] };

                let pb = up.port().to_be_bytes();
                if c.write_all(&[5, 0, 0, 1, octets[0], octets[1], octets[2], octets[3], pb[0], pb[1]]).is_err() {
                    return;
                }
                let answer = dns_answer();
                let mut buf = [0u8; 4096];
                us.set_read_timeout(Some(Duration::from_secs(8))).ok();
                while let Ok((n, from)) = us.recv_from(&mut buf) {
                    // Use the same decoder the engine uses: the destination port sits
                    // at a fixed offset behind the ATYP-dependent address, and reading
                    // it from the END of the datagram silently picks up payload bytes.
                    let dport = match trans_proxier::socks5::parse_udp_frame(&buf[..n]) {
                        Some((dst, _)) => dst.port(),
                        None => continue,
                    };
                    let mut out = vec![0, 0, 0, 1];
                    out.extend_from_slice(&octets);
                    out.extend_from_slice(&pb);
                    out.extend_from_slice(if dport == 53 { &answer } else { &buf[..n] });
                    let _ = us.send_to(&out, from);
                    if dport == 53 {
                        break;
                    }
                }
            });
        }
    });
    (port, rx)
}

fn header(req: &Req) -> Vec<u8> {
    unsafe {
        std::slice::from_raw_parts(req as *const Req as *const u8, std::mem::size_of::<Req>()).to_vec()
    }
}

#[test]
fn a_proxied_dns_answer_lets_a_hostname_rule_match_a_later_ip_connect() {
    // Instance-suffixed names keep this engine off the same pipe as the hook tests.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("s{}", std::process::id())) };
    let (socks, dialed) = spawn_socks5();

    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.settings.dns_mode = DnsMode::Proxy;
    config.settings.dns.servers.clear(); // query whatever resolver the app chose
    config.proxies.push(ProxyServer {
        id: 1,
        name: "s5".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: socks,
        username: None,
        password: None,
        timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    // Exactly two rules, and NEITHER matches 203.0.113.77 by address: the later
    // connect can only be proxied if the engine knows its name.
    config.rules.push(Rule {
        id: 1,
        name: "resolver".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("8.8.8.8".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    config.rules.push(Rule {
        id: 2,
        name: "snooped-host".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("snooped.example.com".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());
    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    // ── 1. the app's resolver query rides our UDP tunnel ────────────────────────
    let relay = std::net::SocketAddr::from(([127, 0, 0, 1], servers.udp_port));
    let q = UdpSocket::bind("127.0.0.1:0").unwrap();
    q.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[8, 8, 8, 8]);
    let hdr = header(&Req {
        magic: MAGIC,
        pid: std::process::id(),
        family: 2,
        port_be: 53u16.to_be(),
        addr,
        proto: 17,
        _pad: [0; 3],
    });
    q.send_to(&hdr, relay).expect("header to the udp relay");
    q.send_to(&[0xAB, 0xCD, 0x01, 0x00, 0, 1], relay).expect("query to the udp relay");

    let mut ans = [0u8; 512];
    let (an, _) = q.recv_from(&mut ans).expect("the DNS answer must reach the app");
    assert!(an > 12, "expected a DNS response, got {an} bytes");

    // ── 2. the engine must have learned the name behind the address ─────────────
    let ip: std::net::IpAddr = "203.0.113.77".parse().unwrap();
    assert_eq!(
        servers.dns_pool.observed_name(ip).as_deref(),
        Some("snooped.example.com"),
        "carrying the answer must populate the observation table"
    );

    // ── 3. a connect that arrives as a bare IP matches the HOSTNAME rule ────────
    let tcp = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], servers.tcp_port))).expect("connect to the relay");
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut raddr = [0u8; 16];
    raddr[..4].copy_from_slice(&[203, 0, 113, 77]);
    let h2 = header(&Req {
        magic: MAGIC,
        pid: std::process::id(),
        family: 2,
        port_be: 80u16.to_be(),
        addr: raddr,
        proto: 6,
        _pad: [0; 3],
    });
    let payload = b"matched-by-hostname";
    tcp.write_all(&h2).unwrap();
    tcp.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    tcp.read_exact(&mut got).expect(
        "echo required: without the observation the rule would say Direct and dial \
         203.0.113.77 for real (unroutable), so nothing comes back",
    );
    assert_eq!(got, payload, "the tunnel must be a clean byte pipe");
    // The decisive form of the claim: what the engine ASKED the proxy for.
    assert_eq!(
        dialed
            .recv_timeout(Duration::from_secs(5))
            .expect("the proxy should have seen a CONNECT"),
        "snooped.example.com:80",
        "the SOCKS5 CONNECT must carry the hostname, not the IP it was dialled at"
    );
    let (lines, _) = monitor.since(0);
    assert!(
        lines.iter().any(|l| l.message.contains("snooped.example.com:80") && l.message.contains("隧道已建立")),
        "the tunnel must be logged against the hostname (there is no hook here, so the tunnel line is the decision), got:\n{}",
        lines.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn without_an_answer_the_same_connect_is_not_matched_by_the_hostname_rule() {
    // The negative control for the test above: same profile, no DNS traffic first, so
    // the IP has no name and the hostname rule must NOT fire.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("n{}", std::process::id())) };
    let (socks, _dialed) = spawn_socks5();
    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.proxies.push(ProxyServer {
        id: 1,
        name: "s5".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: socks,
        username: None,
        password: None,
        timeout_secs: 3,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 2,
        name: "snooped-host".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("snooped.example.com".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());
    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    let tcp = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], servers.tcp_port))).unwrap();
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut raddr = [0u8; 16];
    raddr[..4].copy_from_slice(&[203, 0, 113, 78]);
    let h = header(&Req {
        magic: MAGIC,
        pid: std::process::id(),
        family: 2,
        port_be: 80u16.to_be(),
        addr: raddr,
        proto: 6,
        _pad: [0; 3],
    });
    tcp.write_all(&h).unwrap();
    tcp.write_all(b"no-name-yet").unwrap();
    let mut got = [0u8; 11];
    assert!(tcp.read_exact(&mut got).is_err(), "an unnamed IP must not be tunnelled");
    let (lines, _) = monitor.since(0);
    assert!(
        !lines.iter().any(|l| l.message.contains("snooped.example.com")),
        "nothing should have matched the hostname rule"
    );
}

#[test]
fn dns_over_tcp_is_observed_too() {
    // Truncated answers, big responses and some resolvers' default all put DNS on TCP,
    // and the engine already tunnels port 53 there. Without this tap, a name learned
    // only over TCP would never reach the hostname rules.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("T{}", std::process::id())) };
    let (socks, _dialed) = spawn_socks5();
    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.proxies.push(ProxyServer {
        id: 1,
        name: "s5".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: socks,
        username: None,
        password: None,
        timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1,
        name: "any-53".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("*".into()),
        port: Some("53".into()),
        protocol: trans_proxier::config::RuleProtocol::Tcp,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());
    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    let mut c = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], servers.tcp_port))).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[8, 8, 8, 8]);
    let h = header(&Req {
        magic: MAGIC,
        pid: std::process::id(),
        family: 2,
        port_be: 53u16.to_be(),
        addr,
        proto: 6,
        _pad: [0; 3],
    });
    c.write_all(&h).unwrap();
    let query = vec![0x00, 0x02, 0xAB, 0xCD]; // a 2-byte framed "query" (contents unused)
    c.write_all(&query).unwrap();
    c.flush().unwrap();

    // the framed answer must arrive back at the app, untouched
    let mut lb = [0u8; 2];
    c.read_exact(&mut lb).expect("the length prefix must reach the app");
    let mut body = vec![0u8; u16::from_be_bytes(lb) as usize];
    c.read_exact(&mut body).expect("the DNS answer must reach the app, byte intact");
    assert!(body.len() > 12, "answer body too short: {}", body.len());
    assert_eq!(&body[0..2], &[0xAB, 0xCD], "the reply is the response to our query id");

    // and the engine must have learned the name from it. The tap deliberately runs
    // AFTER forwarding (the user's bytes must never wait on an observer), so give it
    // a moment rather than pretending the two are atomic.
    let ip: std::net::IpAddr = "203.0.113.99".parse().unwrap();
    let mut seen = None;
    for _ in 0..40 {
        if let Some(n) = servers.dns_pool.observed_name(ip) {
            seen = Some(n);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        seen.as_deref(),
        Some("snooped-tcp.example.com"),
        "a TCP-carried answer must populate the same observation table"
    );
    // so a hostname rule can now resolve the bare address
    assert_eq!(
        trans_proxier::dns::effective_host(&servers.dns_pool, "203.0.113.99"),
        "snooped-tcp.example.com"
    );
}

#[test]
fn a_non_dns_tcp_stream_is_forwarded_untouched_by_the_tap() {
    // The tap only engages on port 53; a normal tunnel must still be a pure byte pipe,
    // and a stream that is not DNS at all must not confuse it into buffering forever.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("u{}", std::process::id())) };
    let (socks, dialed) = spawn_socks5();
    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.proxies.push(ProxyServer {
        id: 1,
        name: "s5".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: socks,
        username: None,
        password: None,
        timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1,
        name: "catch-all".into(),
        enabled: true,
        priority: 1,
        app: None,
        host: Some("*".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());
    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    let mut c = TcpStream::connect(std::net::SocketAddr::from(([127, 0, 0, 1], servers.tcp_port))).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[93, 184, 216, 34]);
    let h = header(&Req {
        magic: MAGIC,
        pid: std::process::id(),
        family: 2,
        port_be: 443u16.to_be(),
        addr,
        proto: 6,
        _pad: [0; 3],
    });
    c.write_all(&h).unwrap();
    // far more than one tap buffer's worth, in one go, to prove nothing is swallowed
    let blob: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    c.write_all(&blob).unwrap();
    let mut got = vec![0u8; blob.len()];
    c.read_exact(&mut got).expect("the whole stream must echo back unchanged");
    assert_eq!(got, blob, "a non-DNS tunnel must be a transparent pipe");
    assert_eq!(dialed.recv_timeout(Duration::from_secs(3)).ok().as_deref(), Some("93.184.216.34:443"));
}
