//! LIVE test of the WFP callout ingress — the engine half of the kernel-callout
//! contract (`src/wfp_ingress.rs`).
//!
//! The `.sys` cannot be built or loaded here, so THIS TEST IS THE DRIVER: it does
//! exactly the two things a callout would do — redirect a connect to a token port
//! and write the flow's `(token, FlowRecord)` to the ingress pipe — and then
//! asserts the original destination is recovered and proxied. Everything below the
//! simulated driver is the real engine, real loopback sockets and a real SOCKS5
//! handshake.
//!
//! No socket hook is installed (no tpdrv.dll), so nothing outside this process is
//! touched.

#![cfg(all(windows, target_arch = "x86_64"))]

use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use trans_proxier::config::{Chain, Config, ProxyKind, ProxyServer, Rule, RuleAction};
use trans_proxier::intercept;
use trans_proxier::monitor::Monitor;
use trans_proxier::wfp_classify::{FlowRecord, FLOW_RECORD_LEN, VERDICT_REDIRECT};
use trans_proxier::wfp_ingress;

unsafe extern "system" {
    fn CallNamedPipeW(
        name: *const u16,
        in_buf: *mut c_void,
        in_size: u32,
        out_buf: *mut c_void,
        out_size: u32,
        bytes_read: *mut u32,
        timeout: u32,
    ) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A minimal SOCKS5 egress: answer CONNECT, then echo. Enough to prove the
/// redirected connection was tunnelled to the recorded destination.
fn spawn_socks5_echo() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(|| {
                let mut s = s;
                let mut v = [0u8; 512];
                s.set_read_timeout(Some(Duration::from_secs(10))).ok();
                // greeting -> no-auth method
                if s.read_exact(&mut v[..2]).is_err() {
                    return;
                }
                let nmethods = v[1] as usize;
                let mut meth = vec![0u8; nmethods];
                if s.read_exact(&mut meth).is_err() {
                    return;
                }
                if s.write_all(&[5, 0]).is_err() {
                    return;
                }
                // CONNECT request: VER CMD RSV ATYP + address + port
                let mut head = [0u8; 4];
                if s.read_exact(&mut head).is_err() {
                    return;
                }
                let atyp_len = match head[3] {
                    1 => 6,
                    3 => s.read(&mut v[..1]).unwrap_or(1) as usize + 2, // domain len + port
                    4 => 18,
                    _ => return,
                };
                let mut rest = vec![0u8; atyp_len];
                if s.read_exact(&mut rest).is_err() {
                    return;
                }
                // success reply, then behave like an echo tunnel
                if s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).is_err() {
                    return;
                }
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// The driver's write: `[u16 token][u16 rsv][FlowRecord]`, one-byte ack back.
/// Returns None if no pipe instance answered at all.
fn driver_write(frame: &[u8]) -> Option<u8> {
    // The ingress accepts one connection per instance and re-creates it, so a
    // writer has to retry — exactly what a callout driver does at start-up too.
    let mut out = [0u8; 1];
    let mut got = 0u32;
    let mut buf = frame.to_vec();
    for _ in 0..60 {
        let ok = unsafe {
            CallNamedPipeW(
                wide(&intercept::wfp_pipe_name()).as_ptr(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                out.as_mut_ptr() as *mut c_void,
                1,
                &mut got,
                1000,
            )
        };
        if ok != 0 {
            assert_eq!(got, 1, "the ingress must ack with one byte");
            return Some(out[0]);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn driver_stages(token: u16, record: &FlowRecord) -> u8 {
    let mut frame = vec![0u8; 4 + FLOW_RECORD_LEN];
    frame[0..2].copy_from_slice(&token.to_le_bytes());
    frame[4..].copy_from_slice(&record.to_bytes());
    driver_write(&frame).expect("the ingress pipe must answer")
}

fn record_for(addr: &str, chain: u32) -> FlowRecord {
    let sa: SocketAddr = addr.parse().unwrap();
    let mut r = FlowRecord::default();
    match sa {
        SocketAddr::V4(v4) => {
            r.family = 2;
            r.addr[..4].copy_from_slice(&v4.ip().octets());
            r.port_be = v4.port().to_be();
        }
        SocketAddr::V6(v6) => {
            r.family = 23;
            r.addr = v6.ip().octets();
            r.port_be = v6.port().to_be();
        }
    }
    r.verdict = VERDICT_REDIRECT;
    r.chain = chain;
    r.proto = 6;
    r.pid = std::process::id();
    r
}

#[test]
fn a_redirected_flow_is_relayed_to_its_recorded_destination() {
    // Must be set before spawn_servers so the pipe name is this test's own.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("w{}", std::process::id())) };
    unsafe { std::env::set_var("TPROXIER_WFP_INGRESS", "1") };

    let socks = spawn_socks5_echo();
    let mut config = Config::default();
    config.proxies.push(ProxyServer {
        id: 1,
        name: "socks5".into(),
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
        name: "all".into(),
        enabled: true,
        priority: 10,
        app: None,
        host: Some("*".into()),
        port: None,
        protocol: trans_proxier::config::RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());
    let _servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    let tokens = wfp_ingress::token_ports();
    assert_eq!(tokens.len(), wfp_ingress::TOKEN_POOL, "the driver is handed a pool of token ports");

    // ── simulated callout, case 1: a staged flow reaches its ORIGINAL destination
    let token = tokens[0];
    let ack = driver_stages(token, &record_for("198.51.100.20:80", 1));
    assert_eq!(ack, 1, "a well-formed record must be accepted");
    let mut c = TcpStream::connect(("127.0.0.1", token)).expect("redirected connect accepted");
    c.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let payload = b"via-wfp-redirect";
    c.write_all(payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    if let Err(e) = c.read_exact(&mut got) {
        let (lines, _) = monitor.since(0);
        panic!(
            "echo back through the tunnel: {e}
--- engine log ---
{}",
            lines.iter().map(|l| format!("  [{}] {}", l.level, l.message)).collect::<Vec<_>>().join("
")
        );
    }
    assert_eq!(got, payload, "the redirected connection rode the SOCKS5 chain");
    let (lines, _) = monitor.since(0);
    assert!(
        lines.iter().any(|l| l.message.contains("198.51.100.20:80") && l.message.contains("隧道已建立")),
        "the engine must tunnel to the destination from the FLOW RECORD, not the token port, got:\n{}",
        lines.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("\n")
    );

    // ── case 2: nothing staged for this token → close, dial nothing. A redirect we
    //    cannot attribute must never guess a destination.
    let token2 = tokens[1];
    let mut c2 = TcpStream::connect(("127.0.0.1", token2)).expect("second token accepts");
    let mut sink = [0u8; 16];
    c2.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let n = c2.read(&mut sink).unwrap_or(0);
    assert_eq!(n, 0, "an unstaged token must be closed without egress");

    // ── case 3: a record the driver wrote with a bad magic is refused, so it can
    //    not be mistaken for a live flow.
    let mut junk = FlowRecord::default().to_bytes();
    junk[0] ^= 0xFF;
    let mut frame = vec![0u8; 4 + FLOW_RECORD_LEN];
    frame[0..2].copy_from_slice(&tokens[2].to_le_bytes());
    frame[4..].copy_from_slice(&junk);
    assert_eq!(driver_write(&frame), Some(0), "a corrupt record must be rejected");
    assert!(wfp_ingress::take(tokens[2]).is_none(), "and must not be staged");
}
