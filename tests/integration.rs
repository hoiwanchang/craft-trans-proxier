use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use trans_proxier::config::{Chain, Config, ProxyKind, ProxyServer, Rule, RuleAction};
use trans_proxier::rules::Decision;
use trans_proxier::engine;

fn spawn_echo_target() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn_result in listener.incoming() {
            let Ok(mut conn) = conn_result else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let Ok(n) = conn.read(&mut buf) else { break };
                    if n == 0 {
                        break;
                    }
                    let _ = conn.write_all(&buf[..n]);
                }
            });
        }
    });
    port
}

fn spawn_fake_http_proxy(relay_to_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn_result in listener.incoming() {
            let Ok(mut conn) = conn_result else { continue };
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 4096];
                let Ok(n) = conn.read(&mut buf) else { return };
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                if !request.starts_with("CONNECT ") {
                    return;
                }
                let _ = conn.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
                let Ok(target) = TcpStream::connect(("127.0.0.1", relay_to_port)) else { return };
                let mut client_reader = conn.try_clone().unwrap();
                let mut client_writer = conn.try_clone().unwrap();
                let mut target_reader = target.try_clone().unwrap();
                let mut target_writer = target.try_clone().unwrap();
                let t1 = std::thread::spawn(move || {
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        let Ok(n) = client_reader.read(&mut buf) else { break };
                        if n == 0 { break; }
                        if target_writer.write_all(&buf[..n]).is_err() { break; }
                    }
                });
                let t2 = std::thread::spawn(move || {
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        let Ok(n) = target_reader.read(&mut buf) else { break };
                        if n == 0 { break; }
                        if client_writer.write_all(&buf[..n]).is_err() { break; }
                    }
                });
                let _ = t1.join();
                let _ = t2.join();
            });
        }
    });
    port
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof"));
        }
        filled += n;
    }
    Ok(())
}

fn mini_socks5_client(proxy_port: u16, host: &str, port: u16) -> Option<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).ok()?;
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut reply = [0u8; 2];
    read_exact(&mut stream, &mut reply).ok()?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return None;
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03];
    req.push(host.len() as u8);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).ok()?;
    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head).ok()?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return None;
    }
    let atyp = head[3];
    let addr_len = match atyp {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(&mut stream, &mut len).ok()?;
            len[0] as usize
        }
        _ => return None,
    };
    let mut addr = vec![0u8; addr_len];
    read_exact(&mut stream, &mut addr).ok()?;
    let mut port_bytes = [0u8; 2];
    read_exact(&mut stream, &mut port_bytes).ok()?;
    Some(stream)
}

fn test_config_with_chain(proxy1_port: u16, proxy2_port: u16) -> Config {
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1,
        name: "proxy1".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: proxy1_port,
        username: None,
        password: None,
        timeout_secs: 5,
    });
    config.proxies.push(ProxyServer {
        id: 2,
        name: "proxy2".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: proxy2_port,
        username: None,
        password: None,
        timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "test-chain".into(), proxies: vec![1, 2] });
    config.rules.push(Rule {
        id: 1,
        name: "match-all".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("example.com".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
    });
    config
}

#[test]
fn http_proxy_forwards_absolute_get_origin_form() {
    use std::sync::Arc;
    use trans_proxier::monitor::Monitor;

    let target_port = spawn_echo_target(); // echoes back whatever it receives
    let monitor = Arc::new(Monitor::new());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let m = monitor.clone();
    std::thread::spawn(move || {
        let _ = engine::serve_http(listener, Config::default(), None, m);
    });

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // absolute-form proxy GET; includes a hop-by-hop header that must be stripped
    let req = format!(
        "GET http://127.0.0.1:{}/hello HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        target_port
    );
    client.write_all(req.as_bytes()).unwrap();

    // read the echoed replay until the header block ends
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match client.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let got = String::from_utf8_lossy(&buf).to_string();
    assert!(got.starts_with("GET /hello HTTP/1.1"), "must replay origin-form, got: {got:?}");
    assert!(!got.contains("http://127.0.0.1"), "URI must NOT stay absolute, got: {got:?}");
    assert!(!got.to_ascii_lowercase().contains("proxy-connection"), "hop-by-hop header must be stripped");
    assert!(got.contains("Accept: */*"), "end-to-end headers forwarded");
    // the connection must have been counted by the monitor
    assert!(monitor.snapshot().2 >= 1, "HTTP proxy connection counted");
}

#[test]
fn chain_connects_through_two_proxies_via_http() {
    let target_port = spawn_echo_target();
    let p2_port = spawn_fake_http_proxy(target_port);
    let p1_port = spawn_fake_http_proxy(p2_port);
    let config = test_config_with_chain(p1_port, p2_port);

    let errors = config.validate();
    assert!(errors.is_empty(), "config should validate: {:?}", errors);

    let (mut stream, decision) = engine::connect_target(&config, None, "example.com", 443)
        .expect("chain connect should succeed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(b"hello-chain").unwrap();
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).expect("should read echo");
    assert_eq!(&buf[..n], b"hello-chain");
    assert!(matches!(decision, Decision::Proxy { chain: 1, .. }));
}

#[test]
fn exclusion_list_forces_direct_connection() {
    let target_port = spawn_echo_target();
    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.proxies.push(ProxyServer {
        id: 1,
        name: "will-not-be-used".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: 1,
        username: None,
        password: None,
        timeout_secs: 1,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1,
        name: "match".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("*".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
    });
    let (mut stream, _) = engine::connect_target(&config, None, "127.0.0.1", target_port)
        .expect("excluded host must connect directly");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(b"direct").unwrap();
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).expect("echo");
    assert_eq!(&buf[..n], b"direct");
}

#[test]
fn serve_routes_through_chain_end_to_end() {
    let target_port = spawn_echo_target();
    let p2_port = spawn_fake_http_proxy(target_port);
    let p1_port = spawn_fake_http_proxy(p2_port);
    let config = test_config_with_chain(p1_port, p2_port);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _ = engine::serve(listener, config, None);
    });

    let mut stream = mini_socks5_client(port, "example.com", 443)
        .expect("SOCKS5 handshake should succeed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(b"through-the-chain").unwrap();
    let mut buf = [0u8; 64];
    let mut total = 0;
    while total < b"through-the-chain".len() {
        let n = stream.read(&mut buf[total..]).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(&buf[..total], b"through-the-chain");
}

#[test]
fn checker_reports_ok_for_working_proxy() {
    let target_port = spawn_echo_target();
    let proxy_port = spawn_fake_http_proxy(target_port);
    let proxy = ProxyServer {
        id: 9,
        name: "fake".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: proxy_port,
        username: None,
        password: None,
        timeout_secs: 5,
    };
    let result = trans_proxier::check::check_proxy(&proxy, "example.com", 443, Duration::from_secs(5));
    assert!(result.ok, "check should pass: {}", result.message);
}

#[test]
fn checker_reports_failure_for_unreachable_proxy() {
    let proxy = ProxyServer {
        id: 9,
        name: "dead".into(),
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: 1,
        username: None,
        password: None,
        timeout_secs: 1,
    };
    let result = trans_proxier::check::check_proxy(&proxy, "example.com", 443, Duration::from_secs(2));
    assert!(!result.ok, "check should fail: {}", result.message);
}

#[test]
fn serve_counts_bytes_and_logs_to_monitor() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use trans_proxier::monitor::Monitor;

    let target_port = spawn_echo_target();
    let p2_port = spawn_fake_http_proxy(target_port);
    let p1_port = spawn_fake_http_proxy(p2_port);
    let config = test_config_with_chain(p1_port, p2_port);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let monitor = std::sync::Arc::new(Monitor::new());
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (l, c, s, m) = (listener, config, stop.clone(), monitor.clone());
    std::thread::spawn(move || {
        let _ = engine::serve_with_stop(l, c, None, s, m);
    });

    let mut stream = mini_socks5_client(port, "example.com", 443)
        .expect("SOCKS5 handshake should succeed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"counted-bytes-12345"; // 17 bytes each direction
    stream.write_all(payload).unwrap();
    let mut buf = [0u8; 64];
    let mut total = 0;
    while total < payload.len() {
        let n = stream.read(&mut buf[total..]).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(&buf[..total], payload);

    // Give the relay threads a moment to flush counters after the echo completes.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let (up, down, conns) = loop {
        let snap = monitor.snapshot();
        if snap.0 >= payload.len() as u64 && snap.1 >= payload.len() as u64 {
            break snap;
        }
        if std::time::Instant::now() >= deadline {
            break snap;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    stop.store(true, Ordering::SeqCst);

    assert!(conns >= 1, "connection should be counted, got {conns}");
    assert!(
        up >= payload.len() as u64,
        "upload bytes must be counted (>= {}), got {up}",
        payload.len()
    );
    assert!(
        down >= payload.len() as u64,
        "download bytes must be counted (>= {}), got {down}",
        payload.len()
    );

    // The monitor must have recorded the connection + routing decision for the log window.
    let (lines, _) = monitor.since(0);
    assert!(!lines.is_empty(), "monitor should have emitted log lines");
    assert!(
        lines.iter().any(|l| l.message.contains("example.com")),
        "a log line should mention the target host"
    );
}

#[test]
fn socks5_udp_associate_relays_datagrams() {
    use std::net::{SocketAddr, UdpSocket};
    use trans_proxier::socks5::udp_frame;

    // UDP echo target.
    let echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let echo_addr: SocketAddr = echo.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut b = [0u8; 2048];
        // Echo whatever arrives, forever (single datagram suffices for the test).
        loop {
            if let Ok((n, src)) = echo.recv_from(&mut b) {
                let _ = echo.send_to(&b[..n], src);
            }
        }
    });

    // SOCKS5 server (engine::serve) on an ephemeral TCP port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let _ = engine::serve(listener, Config::default(), None);
    });

    // Client: greeting + UDP ASSOCIATE (cmd=3, DST 0.0.0.0:0).
    let mut ctl = TcpStream::connect(("127.0.0.1", port)).unwrap();
    ctl.write_all(&[0x05, 0x01, 0x00]).unwrap(); // no-auth
    let mut g = [0u8; 2];
    ctl.read_exact(&mut g).unwrap();
    assert_eq!(g, [0x05, 0x00]);
    ctl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut rep = [0u8; 10];
    ctl.read_exact(&mut rep).unwrap();
    assert_eq!(&rep[0..3], &[0x05, 0x00, 0x00], "UDP ASSOCIATE must succeed");
    assert_eq!(rep[3], 0x01, "IPv4 relay bound addr");
    let relay_ip = [rep[4], rep[5], rep[6], rep[7]];
    let relay_port = u16::from_be_bytes([rep[8], rep[9]]);
    let relay: SocketAddr = (std::net::IpAddr::from(relay_ip), relay_port).into();

    // Send a framed datagram to the relay; expect the echo returned, re-framed.
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let payload = b"game-udp-payload";
    client.send_to(&udp_frame(&echo_addr, payload), relay).unwrap();
    let mut rb = [0u8; 2048];
    let (n, _src) = client.recv_from(&mut rb).unwrap();
    let (origin, got) = trans_proxier::socks5::parse_udp_frame(&rb[..n]).expect("valid framed reply");
    assert_eq!(origin, echo_addr, "reply should be attributed to the echo target");
    assert_eq!(got, payload, "UDP round-trip through the SOCKS5 UDP ASSOCIATE relay");
}

#[test]
fn disconnect_aborts_active_relay() {
    // A connected socket pair standing in for a proxified flow. relay_counted
    // blocks copying; after abort_flow the copy loops must return even though
    // the sockets are still open and idle — i.e. Disconnect really works.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (mut s, _) = listener.accept().unwrap();
    c.write_all(b"hi").unwrap();
    let mut tmp = [0u8; 4];
    let _ = s.read(&mut tmp);

    let monitor = std::sync::Arc::new(trans_proxier::monitor::Monitor::new());
    let flow = monitor.open_flow(
        "app.exe".into(),
        "1.2.3.4:80".into(),
        "TCP",
        "chain".into(),
        "#1".into(),
    );
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let m_thread = monitor.clone();
    let f_thread = flow.clone();
    std::thread::spawn(move || {
        // Both sockets stay open (no EOF), so only the abort flag can end this.
        let _ = engine::relay_counted(c, s, Some(&m_thread), Some(&f_thread));
        let _ = done_tx.send(());
    });

    std::thread::sleep(Duration::from_millis(200));
    assert!(monitor.abort_flow(flow.id), "flow id should exist");
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("relay must stop shortly after abort_flow (sockets still open, no EOF)");
}

#[test]
fn redundancy_fails_fast_for_a_down_proxy() {
    // fnd_13 "Recheck failed proxy each (sec.)": a failed first-hop proxy is
    // marked down and the NEXT attempt fails fast instead of re-waiting. Uses a
    // unique proxy id so it never collides with other tests' global redundancy
    // state.
    let mut config = Config::default();
    config.settings.redundancy_recheck_secs = 3600;
    config.proxies.push(ProxyServer {
        id: 4242, name: "dead".into(), kind: ProxyKind::Http, host: "127.0.0.1".into(),
        port: 1, username: None, password: None, timeout_secs: 1,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![4242] });

    // First attempt: a real connect failure (port 1 refused), which marks it down.
    let e1 = engine::connect_via_chain(&config, 1, "example.com", 80).unwrap_err();
    assert!(
        !e1.to_string().contains("marked down"),
        "first failure must be the real connect error, got {e1}"
    );
    // Second attempt: fail-fast because the proxy is known-down.
    let e2 = engine::connect_via_chain(&config, 1, "example.com", 80).unwrap_err();
    assert!(e2.to_string().contains("marked down"), "expected fail-fast, got {e2}");
    assert!(trans_proxier::redundancy::is_available(4242, 0), "recheck_secs=0 => always available");
    assert!(!trans_proxier::redundancy::is_available(4242, 3600), "still down within the window");
}

fn spawn_fake_socks4(relay_to_port: u16) -> u16 {
    use std::io::Read;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in listener.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let mut hdr = [0u8; 8];
                if c.read_exact(&mut hdr).is_err() {
                    return;
                }
                let mut byte = [0u8; 1];
                let mut eat_nul = |c: &mut TcpStream| -> bool {
                    loop {
                        match c.read(&mut byte) {
                            Ok(0) => return false,
                            Ok(_) => {
                                if byte[0] == 0 {
                                    return true;
                                }
                            }
                            Err(_) => return false,
                        }
                    }
                };
                if !eat_nul(&mut c) {
                    return; // userid terminator
                }
                if hdr[4..8] == [0, 0, 0, 3] && !eat_nul(&mut c) {
                    return; // SOCKS4a hostname terminator
                }
                // granted; then tunnel to the echo target.
                let _ = c.write_all(&[0x00, 0x5a, hdr[2], hdr[3], hdr[4], hdr[5], hdr[6], hdr[7]]);
                let Ok(t) = TcpStream::connect(("127.0.0.1", relay_to_port)) else { return };
                let mut cr = c.try_clone().unwrap();
                let mut cw = c;
                let mut tr = t.try_clone().unwrap();
                let mut tw = t;
                std::thread::spawn(move || {
                    let mut b = [0u8; 8192];
                    loop {
                        match cr.read(&mut b) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if tw.write_all(&b[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                let mut b = [0u8; 8192];
                loop {
                    match tr.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if cw.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

#[test]
fn chain_over_socks4a_end_to_end() {
    // A hostname target exercises the SOCKS4A remote-resolve path through the
    // full chain engine (rules -> connect_via_chain -> open_tunnel -> SOCKS4a).
    let target = spawn_echo_target();
    let s4 = spawn_fake_socks4(target);
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1, name: "s4".into(), kind: ProxyKind::Socks4, host: "127.0.0.1".into(),
        port: s4, username: None, password: None, timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1, name: "all".into(), enabled: true, priority: 1, app: None,
        host: Some("*".into()), port: None, protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
    });
    let (mut stream, _decision) = engine::connect_target(&config, None, "example.com", 443)
        .expect("SOCKS4a chain connect should succeed");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.write_all(b"hi-socks4").unwrap();
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).expect("echo back through socks4a");
    assert_eq!(&buf[..n], b"hi-socks4", "SOCKS4a end-to-end round-trip");
}

#[test]
fn checker_reports_ok_for_socks4_proxy() {
    // The Proxy Checker must handle SOCKS4 too (it previously said "not
    // implemented"), closing the check/serve inconsistency.
    let target = spawn_echo_target();
    let s4 = spawn_fake_socks4(target);
    let proxy = ProxyServer {
        id: 5, name: "s4".into(), kind: ProxyKind::Socks4, host: "127.0.0.1".into(),
        port: s4, username: None, password: None, timeout_secs: 5,
    };
    let result = trans_proxier::check::check_proxy(&proxy, "example.com", 80, Duration::from_secs(5));
    assert!(result.ok, "SOCKS4 proxy should check OK: {}", result.message);
}

#[test]
fn checker_reports_ok_for_a_working_chain() {
    let target = spawn_echo_target();
    let p2 = spawn_fake_http_proxy(target);
    let p1 = spawn_fake_http_proxy(p2);
    let mut config = Config::default();
    config.proxies.push(ProxyServer { id: 1, name: "hop1".into(), kind: ProxyKind::Http, host: "127.0.0.1".into(), port: p1, username: None, password: None, timeout_secs: 5 });
    config.proxies.push(ProxyServer { id: 2, name: "hop2".into(), kind: ProxyKind::Http, host: "127.0.0.1".into(), port: p2, username: None, password: None, timeout_secs: 5 });
    config.chains.push(Chain { id: 7, name: "two-hop".into(), proxies: vec![1, 2] });
    let r = trans_proxier::check::check_chain(&config, 7, "example.com", 443);
    assert!(r.ok, "two-hop chain should check OK: {}", r.message);
}

#[test]
fn checker_reports_failure_for_a_broken_chain() {
    // A chain whose egress points at a dead port must report FAIL, not ok.
    let mut config = Config::default();
    config.proxies.push(ProxyServer { id: 1, name: "dead".into(), kind: ProxyKind::Http, host: "127.0.0.1".into(), port: 1, username: None, password: None, timeout_secs: 1 });
    config.chains.push(Chain { id: 3, name: "broken".into(), proxies: vec![1] });
    let r = trans_proxier::check::check_chain(&config, 3, "example.com", 443);
    assert!(!r.ok, "dead chain should fail: {}", r.message);
    assert!(r.message.contains("FAIL") || !r.ok, "failure is surfaced: {}", r.message);
}

#[test]
fn engine_dials_an_ipv6_upstream_proxy() {
    // Regression guard: an upstream proxy configured with a bare IPv6 host must be
    // dialed correctly (parsed to an IPv6 socket address), not rejected as an
    // invalid address. Nothing listens on [::1]:9, so we expect a CONNECTION
    // REFUSED (a network-level rejection) rather than an address-parse/invalid
    // error — proving the IPv6 host literal was accepted by connect_via_chain.
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1, name: "v6".into(), kind: ProxyKind::Socks5,
        host: "::1".into(), port: 9, username: None, password: None, timeout_secs: 3,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    let err = engine::connect_via_chain(&config, 1, "example.com", 443)
        .expect_err("no listener on ::1:9");
    let msg = err.to_string();
    assert!(
        !msg.contains("Invalid argument") && !msg.contains("地址无效") && !msg.to_lowercase().contains("invalid address"),
        "IPv6 host must PARSE (got a network error, not an address error): {msg}"
    );
    assert!(
        msg.contains("refused") || msg.contains("拒绝") || msg.contains("Cannot start") || msg.contains("failed"),
        "expected a connection-level failure for the v6 dial: {msg}"
    );
}

#[test]
fn proxy_timeout_secs_is_enforced_not_hanging() {
    // fnd_13 "Timeout (s)" was a dead knob for the proxy CONNECT path: a bare
    // TcpStream::connect to an unreachable host blocks ~21s (OS default). The fix
    // (dial_proxy -> connect_timeout) must return within ~the configured timeout.
    // TEST-NET-2 (198.51.100.x) blackholes packets, so a real 21s hang is the
    // failure this guards against.
    let started = std::time::Instant::now();
    let r = trans_proxier::engine::dial_proxy("198.51.100.7", 9, 1);
    let elapsed = started.elapsed();
    assert!(r.is_err(), "unreachable proxy should fail");
    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "connect must respect timeout_secs=1, not the ~21s OS default (took {elapsed:?})"
    );
}

#[test]
fn stalling_proxy_handshake_times_out() {
    // fnd_43/45/46 completion: a proxy that ACCEPTS the TCP connection but then
    // stalls the SOCKS handshake (never replies) must fail within timeout_secs,
    // not hang forever on read_exact. This was the un-bounded handshake read.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // Accept and hold the connection open, sending nothing back.
        if let Ok((_c, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(30)); // keep it open, stall
        }
    });
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1, name: "stall".into(), kind: ProxyKind::Socks5, host: "127.0.0.1".into(),
        port, username: None, password: None, timeout_secs: 1,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    let started = std::time::Instant::now();
    let r = engine::connect_via_chain(&config, 1, "example.com", 443);
    let elapsed = started.elapsed();
    assert!(r.is_err(), "stalling proxy handshake must error, not hang");
    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "handshake must respect timeout_secs=1, not block forever (took {elapsed:?})"
    );
}

#[test]
fn http_proxy_connect_tunnel_counts_bytes() {
    use std::sync::Arc;
    use trans_proxier::monitor::Monitor;
    let target = spawn_echo_target();
    let _ = target; // connect_via_chain routes "example.com" — use a proxy that reaches echo
    // Route the tunnel through a fake HTTP proxy that connects to the echo target.
    let egress = spawn_fake_http_proxy(target);
    let monitor = Arc::new(Monitor::new());
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1, name: "eg".into(), kind: ProxyKind::Http, host: "127.0.0.1".into(),
        port: egress, username: None, password: None, timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1, name: "all".into(), enabled: true, priority: 1, app: None,
        host: Some("*".into()), port: None, protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let m = monitor.clone();
    std::thread::spawn(move || { let _ = engine::serve_http(listener, config, None, m); });

    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Issue a CONNECT, expect 200, then tunnel bytes that echo back.
    c.write_all(b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
    let mut resp = [0u8; 64];
    let n = c.read(&mut resp).unwrap();
    assert!(String::from_utf8_lossy(&resp[..n]).contains("200"), "CONNECT should be granted");
    let payload = b"tunnel-counted-payload";
    c.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    let dl = std::time::Instant::now() + Duration::from_secs(5);
    while filled < got.len() && std::time::Instant::now() < dl {
        match c.read(&mut got[filled..]) { Ok(0) => break, Ok(k) => filled += k, Err(_) => break }
    }
    assert_eq!(&got[..filled], payload, "tunnel echoes the payload");
    // The tunnel used relay_counted -> the monitor's up/down counters advanced.
    let (up, down, _conns) = monitor.snapshot();
    assert!(up >= payload.len() as u64, "uploaded bytes counted: got {up}");
    assert!(down >= payload.len() as u64, "downloaded bytes counted: got {down}");
}
