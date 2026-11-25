//! LIVE transparent-proxification test — Windows x64 only, and CRUCIALLY
//! in-process: it loads tpdrv.dll into the TEST process (whose DllMain installs
//! the ws2_32 socket hook there) and uses `intercept::spawn_servers` for the
//! engine. It does NOT call Engine::start, so NO global hook is placed and no
//! other user process is touched — safe to run.
//!
//! Verifies the full transparent data path for BOTH TCP and UDP against a local
//! fake SOCKS5 proxy (which supports CONNECT + UDP ASSOCIATE):
//!   app socket -> hook -> named-pipe decision (per-PID rule) -> relay ->
//!   SOCKS5 proxy -> echo target -> back to the app, with no proxy configured
//!   in the app.

#![cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))]
// ^ x86 (i686) is included deliberately: the hook is shipped in both bitnesses (a 32-bit
//   target gets the i686 tpdrv.dll through tphelper), and its install path differs —
//   `push imm32; ret` instead of the 14-byte RIP jump, and no RIP fixups. Until this gate
//   was widened, that entire 32-bit code path — including the short-branch widening added
//   for freeaddrinfo — had never executed a single round-trip. Run it with:
//     cargo test -p trans-proxier --no-default-features --target i686-pc-windows-msvc \
//         --test transparent_windows

use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use trans_proxier::config::{Chain, Config, DnsMode, ProxyKind, ProxyServer, Rule, RuleAction};
use trans_proxier::intercept;
use trans_proxier::monitor::Monitor;

unsafe extern "system" {
    fn CreateMutexW(sa: *const c_void, initial: i32, name: *const u16) -> *mut c_void;
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(m: *mut c_void, n: *const i8) -> *mut c_void;
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

#[repr(C)]
struct AiRes {
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
    addrlen: usize,
    canonname: *mut i8,
    addr: *mut c_void,
    next: *mut c_void,
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn getaddrinfo(node: *const i8, service: *const i8, hints: *const c_void, res: *mut *mut AiRes) -> i32;
    fn freeaddrinfo(res: *mut AiRes);
}

#[repr(C)]
struct WsaBuf {
    len: u32,
    buf: *mut i8,
}

#[repr(C)]
struct SockAddrInW {
    family: u16,
    port: u16, // network order
    addr: [u8; 4],
    zero: [u8; 8],
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn socket(af: i32, ty: i32, proto: i32) -> *mut c_void;
    fn bind(s: *mut c_void, name: *const SockAddrInW, len: i32) -> i32;
    fn closesocket(s: *mut c_void) -> i32;
    fn WSASendTo(
        s: *mut c_void, buffers: *const WsaBuf, count: u32, sent: *mut u32, flags: u32,
        to: *const SockAddrInW, tolen: i32, name: *mut c_void, overlapped: *mut c_void,
    ) -> i32;
    fn WSARecvFrom(
        s: *mut c_void, buffers: *mut WsaBuf, count: u32, received: *mut u32, flags: *mut u32,
        from: *mut SockAddrInW, fromlen: *mut i32, name: *mut c_void, overlapped: *mut c_void,
    ) -> i32;
    fn setsockopt(s: *mut c_void, level: i32, opt: i32, val: *const i8, len: i32) -> i32;
}
#[repr(C)]
struct SockAddrIn6W {
    family: u16,
    port: u16, // network order
    flow: u32,
    addr: [u8; 16],
    scope: u32,
}

#[repr(C)]
struct WsaOverlapped {
    internal: usize,
    internal_high: usize,
    off: u32,
    off_hi: u32,
    event: *mut c_void,
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSASocketW(af: i32, ty: i32, proto: i32, proto_info: *const c_void, g: u32, flags: u32) -> *mut c_void;
    fn connect(s: *mut c_void, name: *const c_void, len: i32) -> i32;
    fn WSASend(
        s: *mut c_void, buffers: *const WsaBuf, count: u32, sent: *mut u32, flags: u32,
        name: *mut c_void, overlapped: *mut c_void,
    ) -> i32;
    fn WSARecv(
        s: *mut c_void, buffers: *mut WsaBuf, count: u32, received: *mut u32, flags: *mut u32,
        name: *mut c_void, overlapped: *mut c_void,
    ) -> i32;
    fn WSAGetLastError() -> i32;
}

#[repr(C)]
struct FdSetWin {
    count: u32,
    fds: [*mut c_void; 64],
}

#[repr(C)]
struct WinTimeVal {
    sec: i32,
    usec: i32,
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn select(
        nfds: i32,
        read: *mut FdSetWin,
        write: *mut FdSetWin,
        except: *mut FdSetWin,
        tv: *mut WinTimeVal,
    ) -> i32;
    fn WSAEventSelect(s: *mut c_void, event: *mut c_void, network_events: i32) -> i32;
    fn WSAEnumNetworkEvents(s: *mut c_void, event: *mut c_void, events: *mut i32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(sa: *const c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn CreateIoCompletionPort(handle: *mut c_void, port: *mut c_void, key: usize, threads: u32) -> *mut c_void;
    fn GetQueuedCompletionStatus(port: *mut c_void, bytes: *mut u32, key: *mut usize, ov: *mut *mut c_void, ms: u32) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// A minimal SOCKS5 server that supports BOTH CONNECT (TCP) and UDP ASSOCIATE,
/// tunnelling to the requested destination. We point the engine's chain at it.
fn spawn_fake_socks5() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            std::thread::spawn(move || {
                let mut g = [0u8; 2];
                if c.read_exact(&mut g).is_err() { return; }
                let mut meth = vec![0u8; g[1] as usize];
                if c.read_exact(&mut meth).is_err() { return; }
                let _ = c.write_all(&[0x05, 0x00]); // no auth
                let mut head = [0u8; 4];
                if c.read_exact(&mut head).is_err() { return; }
                let cmd = head[1];
                // read DST.ADDR (we don't actually need it: we echo below)
                match head[3] {
                    0x01 => { let mut a=[0u8;6]; let _=c.read_exact(&mut a); }
                    0x03 => { let mut n=[0u8;1]; let _=c.read_exact(&mut n); let mut d=vec![0u8;n[0] as usize+2]; let _=c.read_exact(&mut d);}
                    0x04 => { let mut a=[0u8;18]; let _=c.read_exact(&mut a);}
                    _ => return,
                }
                if cmd == 0x01 {
                    // CONNECT: behave like an echo tunnel.
                    let _ = c.write_all(&[0x05,0x00,0x00,0x01,127,0,0,1,0,0]);
                    let mut b = [0u8; 4096];
                    loop { match c.read(&mut b){ Ok(0)|Err(_)=>break, Ok(n)=> if c.write_all(&b[..n]).is_err(){break} } }
                } else if cmd == 0x03 {
                    // UDP ASSOCIATE: bind a UDP relay, reply its addr, echo frames.
                    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
                    let a = udp.local_addr().unwrap();
                    let SocketAddr::V4(v4) = a else { return };
                    let mut rep = vec![0x05,0x00,0x00,0x01];
                    rep.extend_from_slice(&v4.ip().octets());
                    rep.extend_from_slice(&v4.port().to_be_bytes());
                    let _ = c.write_all(&rep);
                    let mut buf = vec![0u8; 65536];
                    udp.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    while let Ok((n, from)) = udp.recv_from(&mut buf) {
                        let _ = udp.send_to(&buf[..n], from); // echo the whole frame back
                    }
                }
            });
        }
    });
    port
}

#[test]
fn transparent_tcp_and_udp_proxification() {
    let fake = spawn_fake_socks5();

    // Engine config: proxy everything through the local SOCKS5; loopback direct
    // (so the engine's own hops to :fake don't loop). Whitelist OFF (rule covers).
    let mut config = Config::default();
    config.settings.proxy_exclusion_list = vec!["127.0.0.1".into()];
    config.settings.dns_mode = DnsMode::Proxy; // arm the DNS fake-IP producer for this test
    config.proxies.push(ProxyServer {
        id: 1, name: "fake-socks5".into(), kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(), port: fake, username: None, password: None, timeout_secs: 5,
    });
    config.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
    config.rules.push(Rule {
        id: 1, name: "all".into(), enabled: true, priority: 10,
        app: None, host: Some("*".into()), port: None, protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
    });
    // A higher-priority Block rule: connecting to this TEST-NET address must be
    // refused in-hook (no egress), proving the transparent engine enforces Block.
    config.rules.push(Rule {
        id: 2, name: "block".into(), enabled: true, priority: 20,
        app: None, host: Some("198.51.100.99".into()), port: None, protocol: trans_proxier::config::RuleProtocol::Both, action: RuleAction::Block,
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());

    // Isolate this test's engine + injected-hook namespace from any OTHER running
    // trans-proxier (which shares the default `tproxierPE` mutex/pipe) so the test
    // is deterministic even while the GUI app is live. Must be set BEFORE
    // spawn_servers + LoadLibrary so both the engine and the hook read it.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("t{}", std::process::id())) };
    // Arm the WFP route too, so the relay accept path runs its
    // SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT check on every hooked connection:
    // with no callout attached the query must fail cleanly and change nothing.
    unsafe { std::env::set_var("TPROXIER_WFP_INGRESS", "1") };

    // This suite owns an engine-shaped process of its own, so it must not be governed
    // by a live trans-proxier on the machine: run the whole test under its own instance
    // name, which scopes the mutex, the pipes and the control block together.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", "livetest") };
    // 1. engine mutex (hook liveness gate) BEFORE loading the driver.
    let _mutex = unsafe { CreateMutexW(std::ptr::null(), 0, wide(&intercept::engine_mutex_name()).as_ptr()) };
    // 2. servers (pipe + tcp relay + udp relay + DNS-allocation pipe), no global hook.
    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");
    // 3. install the socket hook in THIS process (DllMain path).
    let exe = std::env::current_exe().unwrap();
    let mut dll = exe.parent().unwrap().join("tpdrv.dll");
    if !dll.exists() { dll = exe.parent().unwrap().parent().unwrap().join("tpdrv.dll"); }
    assert!(dll.exists(), "build tpdrv.dll first");
    let hmod = unsafe { LoadLibraryW(wide(&dll.to_string_lossy()).as_ptr()) };
    assert!(!hmod.is_null(), "LoadLibrary(tpdrv.dll) failed");
    std::thread::sleep(Duration::from_millis(150));

    // --- TCP: connect to an "external" IP; the hook diverts it through SOCKS5 CONNECT ---
    let payload = b"transparent-tcp".to_vec();
    let mut s = TcpStream::connect(("198.51.100.7", 80)).expect("tcp connect (proxified)");
    s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    s.write_all(&payload).unwrap();
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).expect("tcp echo");
    assert_eq!(got, payload, "TCP round-trip through the transparent path");

    // --- REGRESSION: NON-BLOCKING connect (what browsers do). `connect_timeout`
    //     sets the socket non-blocking and gets WSAEWOULDBLOCK; the hook must still
    //     stamp the in-band Req header once the relay connect completes, else the
    //     relay misreads the app's first bytes (e.g. TLS) as a bad magic. ---
    let npayload = b"transparent-tcp-nonblocking".to_vec();
    let addr: SocketAddr = "198.51.100.8:80".parse().unwrap();
    let mut ns = TcpStream::connect_timeout(&addr, Duration::from_secs(6))
        .expect("non-blocking tcp connect (proxified)");
    ns.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    ns.write_all(&npayload).unwrap();
    let mut ngot = vec![0u8; npayload.len()];
    ns.read_exact(&mut ngot).expect("non-blocking tcp echo");
    assert_eq!(ngot, npayload, "TCP round-trip via a NON-BLOCKING (browser-style) connect");

    // --- UDP: connect a datagram socket to an "external" IP; hook tags proto=17,
    //     the engine tunnels it via SOCKS5 UDP ASSOCIATE to the fake proxy ---
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.connect(("203.0.113.9", 443)).expect("udp connect (proxified)");
    udp.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let uping = b"transparent-udp";
    udp.send(uping).unwrap();
    let mut ub = [0u8; 64];
    let mut un = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while un < uping.len() && std::time::Instant::now() < deadline {
        match udp.recv(&mut ub[un..]) { Ok(n) => un += n, Err(_) => break }
    }
    // dump the engine view of the UDP flow for diagnosis
    let (lines, _) = monitor.since(0);
    eprintln!("--- engine monitor ({} lines) ---", lines.len());
    for l in &lines {
        eprintln!("  [{}] {}", l.level, l.message);
    }
    assert_eq!(&ub[..un], uping, "UDP round-trip through the transparent SOCKS5 UDP ASSOCIATE path");

    // --- UNCONNECTED UDP: send_to/recv_from on a datagram socket that never
    //     calls connect(); the hook uses a per-(socket,dst) shadow socket. ---
    let ud2 = UdpSocket::bind("127.0.0.1:0").unwrap();
    ud2.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let u2ping = b"transparent-udp-unconn";
    ud2.send_to(u2ping, ("198.51.100.11", 53)).expect("send_to (proxified)");
    let mut ub2 = [0u8; 64];
    let mut un2 = 0usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(6);
    while un2 < u2ping.len() && std::time::Instant::now() < deadline {
        match ud2.recv(&mut ub2[un2..]) { Ok(n) => un2 += n, Err(_) => break }
    }
    let (lines, _) = monitor.since(0);
    for l in &lines {
        eprintln!("  [post-unconn] {}", l.message);
    }
    assert_eq!(&ub2[..un2], u2ping, "UNCONNECTED UDP round-trip via shadow-socket proxying");

    // --- UNCONNECTED IPv6 UDP: send_to to a v6 destination is proxied via the v4
    //     shadow socket; the v6 destination rides in the SOCKS5 UDP frame (ATYP
    //     0x04) and the egress proxy resolves it. Closes IPv6 UDP for send_to apps. ---
    let ud6 = UdpSocket::bind("[::1]:0").unwrap();
    ud6.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let dst6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)), 53);
    let p6 = b"v6-unconn-udp";
    ud6.send_to(p6, dst6).expect("v6 send_to (proxified)");
    let mut b6 = [0u8; 64];
    let mut n6 = 0usize;
    let dl6 = std::time::Instant::now() + Duration::from_secs(6);
    while n6 < p6.len() && std::time::Instant::now() < dl6 {
        match ud6.recv(&mut b6[n6..]) { Ok(k) => n6 += k, Err(_) => break }
    }
    assert_eq!(&b6[..n6], p6, "UNCONNECTED IPv6 UDP round-trip via shadow-socket proxying");

    // --- CONNECTED IPv6 UDP: connect() a v6 socket to a v6 target and use
    //     send()/recv(). The hook redirects the connect to the dual-stack relay
    //     ([::1]:port) and the v6 destination rides in the SOCKS5 UDP frame. ---
    let cu6 = UdpSocket::bind("[::1]:0").unwrap();
    let cdst6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 5)), 53);
    cu6.connect(cdst6).expect("connected v6 udp (proxified)");
    cu6.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    let cp6 = b"v6-connected-udp";
    cu6.send(cp6).expect("connected v6 udp send");
    let mut cb6 = [0u8; 64];
    let mut cn6 = 0usize;
    let dlc = std::time::Instant::now() + Duration::from_secs(6);
    while cn6 < cp6.len() && std::time::Instant::now() < dlc {
        match cu6.recv(&mut cb6[cn6..]) { Ok(k) => cn6 += k, Err(_) => break }
    }
    assert_eq!(&cb6[..cn6], cp6, "CONNECTED IPv6 UDP round-trip via dual-stack relay");

    // --- OVERLAPPED (event-completion) UNCONNECTED IPv6 UDP: the IOCP/overlapped
    //     style used by games. WSARecvFrom is posted FIRST, so it must report
    //     WSA_IO_PENDING and be completed out-of-line by the hook when the proxied
    //     echo lands — proving overlapped UDP no longer escapes the proxy. ---
    unsafe {
        let msg = b"v6-overlapped-udp";
        let dst6 = SockAddrIn6W {
            family: 23,
            port: 53u16.to_be(),
            flow: 0,
            addr: {
                let mut a = [0u8; 16];
                a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[15] = 0x77; // 2001:db8::77
                a
            },
            scope: 0,
        };
        // (a) event-based completion
        let sock = WSASocketW(23, 2, 17, std::ptr::null(), 0, 1 /*WSA_FLAG_OVERLAPPED*/);
        assert!(sock != (-1isize as *mut c_void), "WSASocketW(v6, overlapped) failed");
        let local6 = SockAddrIn6W { family: 23, port: 0, flow: 0, addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], scope: 0 };
        assert_eq!(bind(sock as *mut c_void, &local6 as *const SockAddrIn6W as *const SockAddrInW, std::mem::size_of::<SockAddrIn6W>() as i32), 0, "bind [::1]");
        let ev = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut ov = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: ev };
        let mut rbuf = [0u8; 64];
        let mut rwb = WsaBuf { len: rbuf.len() as u32, buf: rbuf.as_mut_ptr() as *mut i8 };
        let mut recvd = 0u32;
        let mut rflags = 0u32;
        let mut flen = std::mem::size_of::<SockAddrIn6W>() as i32;
        let mut from6: SockAddrIn6W = std::mem::zeroed();
        let rr = WSARecvFrom(
            sock, &mut rwb, 1, &mut recvd, &mut rflags,
            &mut from6 as *mut SockAddrIn6W as *mut SockAddrInW, &mut flen,
            std::ptr::null_mut(), &mut ov as *mut WsaOverlapped as *mut c_void,
        );
        assert_eq!(rr, -1, "an overlapped recv with an empty inbox must NOT complete inline");
        assert_eq!(WSAGetLastError(), 997, "must report WSA_IO_PENDING");
        // now send; the reply arrives on the shadow flow and completes `ov`
        let sb = WsaBuf { len: msg.len() as u32, buf: msg.as_ptr() as *const u8 as *mut i8 };
        let mut sent = 0u32;
        let ev_s = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut ov_s = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: ev_s };
        let sr = WSASendTo(
            sock, &sb, 1, &mut sent, 0, &dst6 as *const SockAddrIn6W as *const SockAddrInW,
            std::mem::size_of::<SockAddrIn6W>() as i32, std::ptr::null_mut(),
            &mut ov_s as *mut WsaOverlapped as *mut c_void,
        );
        assert_eq!(sr, 0, "overlapped WSASendTo (proxified) completes immediately");
        assert_eq!(WaitForSingleObject(ev_s, 1000), 0, "a completed send signals its event");
        assert_eq!(sent as usize, msg.len(), "WSASendTo reports the bytes forwarded");
        let wait = WaitForSingleObject(ev, 6000);
        assert_eq!(wait, 0 /*WAIT_OBJECT_0*/, "the pending recv must be signalled by the hook");
        assert_eq!(ov.internal, 0, "OVERLAPPED.Internal must report success");
        assert_eq!(ov.internal_high as usize, msg.len(), "OVERLAPPED.InternalHigh = bytes received");
        assert_eq!(recvd as usize, msg.len(), "*lpNumberOfBytesRecvd");
        assert_eq!(&rbuf[..recvd as usize], &msg[..], "OVERLAPPED IPv6 UDP round-trip through the proxy");
        assert_eq!(from6.family, 23, "the reply sockaddr keeps AF_INET6 for the app");
        closesocket(sock);
        CloseHandle(ev);
        CloseHandle(ev_s);

        // (b) IOCP completion: the app associates the socket with a completion
        //     port (seen through the hooked WSAIoctl), so the hook must post a
        //     queued status instead of only setting the event.
        let port = CreateIoCompletionPort(-1isize as *mut c_void, std::ptr::null_mut(), 0, 1);
        assert!(!port.is_null(), "CreateIoCompletionPort failed");
        let s2 = WSASocketW(23, 2, 17, std::ptr::null(), 0, 1);
        assert_eq!(bind(s2 as *mut c_void, &local6 as *const SockAddrIn6W as *const SockAddrInW, std::mem::size_of::<SockAddrIn6W>() as i32), 0, "bind [::1] (iocp sock)");
        // The normal way to drive a socket through an IOCP: hand the socket handle
        // to CreateIoCompletionPort (no WSAIoctl involved).
        let got = CreateIoCompletionPort(s2, port, 0xBEEF, 0);
        assert!(!got.is_null(), "associate completion port failed");
        let ev2 = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut ov2 = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: ev2 };
        let mut rb2 = [0u8; 64];
        let mut wb2 = WsaBuf { len: rb2.len() as u32, buf: rb2.as_mut_ptr() as *mut i8 };
        let mut rcv2 = 0u32;
        let mut fl2 = 0u32;
        let mut fn2 = std::mem::size_of::<SockAddrIn6W>() as i32;
        let mut fr2: SockAddrIn6W = std::mem::zeroed();
        let r2 = WSARecvFrom(
            s2, &mut wb2, 1, &mut rcv2, &mut fl2,
            &mut fr2 as *mut SockAddrIn6W as *mut SockAddrInW, &mut fn2,
            std::ptr::null_mut(), &mut ov2 as *mut WsaOverlapped as *mut c_void,
        );
        assert_eq!(r2, -1, "recv pends again (empty inbox)");
        let msg2 = b"v6-overlapped-iocp";
        let sb2 = WsaBuf { len: msg2.len() as u32, buf: msg2.as_ptr() as *const u8 as *mut i8 };
        let mut sent2 = 0u32;
        let ev_s2 = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut ov_s2 = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: ev_s2 };
        let sr2 = WSASendTo(
            s2, &sb2, 1, &mut sent2, 0, &dst6 as *const SockAddrIn6W as *const SockAddrInW,
            std::mem::size_of::<SockAddrIn6W>() as i32, std::ptr::null_mut(),
            &mut ov_s2 as *mut WsaOverlapped as *mut c_void,
        );
        assert_eq!(sr2, 0, "overlapped send on the IOCP socket completes inline");
        // Both the deferred recv AND the inline-completing send post to the port;
        // the order between them is not defined, so drain until ours shows up.
        let want = &mut ov2 as *mut WsaOverlapped as usize;
        let mut got_recv = false;
        let mut nbytes = 0u32;
        for _ in 0..2 {
            let mut key = 0usize;
            let mut pov: *mut c_void = std::ptr::null_mut();
            let gq = GetQueuedCompletionStatus(port, &mut nbytes, &mut key, &mut pov, 6000);
            assert_eq!(gq, 1, "GetQueuedCompletionStatus must yield the proxied datagram");
            assert_eq!(key, 0xBEEF, "completion key preserved through the hook");
            if pov as usize == want {
                got_recv = true;
                break;
            }
        }
        assert!(got_recv, "the deferred recv's OVERLAPPED must be the completion context");
        assert_eq!(nbytes as usize, msg2.len(), "completed byte count");
        assert_eq!(&rb2[..rcv2 as usize], &msg2[..], "IOCP-completed IPv6 UDP round-trip");
        closesocket(s2);
        CloseHandle(ev2);
        CloseHandle(ev_s2);
        CloseHandle(port);
    }

    // --- OVERLAPPED *CONNECTED* IPv6 UDP — the last combination in "connected +
    //     overlapped IPv6 UDP" to be asserted. It is a genuinely different path from
    //     the cases above: the hook only rewrites connect() to the [::1] relay, so the
    //     overlapped completions are produced by REAL Winsock on the app's own socket.
    //     If the hook had instead queued replies into its inbox, this would hang. ───
    unsafe {
        let cmsg = "v6-connected-overlapped";
        let cm = cmsg.as_bytes();
        let dst6 = SockAddrIn6W {
            family: 23,
            port: 443u16.to_be(),
            flow: 0,
            addr: {
                let mut a = [0u8; 16];
                a[0] = 0x20; a[1] = 0x01; a[2] = 0x0d; a[3] = 0xb8; a[15] = 0x99; // 2001:db8::99
                a
            },
            scope: 0,
        };

        // (a) event completion on a connected, overlapped v6 datagram socket
        let cs = WSASocketW(23, 2, 17, std::ptr::null(), 0, 1 /*WSA_FLAG_OVERLAPPED*/);
        assert!(cs != (-1isize as *mut c_void), "overlapped v6 dgram socket");
        let any6 = SockAddrIn6W { family: 23, port: 0, flow: 0, addr: [0; 16], scope: 0 };
        assert_eq!(
            bind(cs as *mut c_void, &any6 as *const SockAddrIn6W as *const SockAddrInW, std::mem::size_of::<SockAddrIn6W>() as i32),
            0,
            "bind [::] on the overlapped v6 socket"
        );
        let rc = connect(cs, &dst6 as *const SockAddrIn6W as *const c_void, std::mem::size_of::<SockAddrIn6W>() as i32);
        assert_eq!(rc, 0, "connect() to a v6 target (the hook diverts it to the [::1] relay)");

        let cev = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut cov = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: cev };
        let cbuf = WsaBuf { len: cm.len() as u32, buf: cm.as_ptr() as *const u8 as *mut i8 };
        let mut csent = 0u32;
        let sr = WSASend(cs, &cbuf, 1, &mut csent, 0, std::ptr::null_mut(), &mut cov as *mut WsaOverlapped as *mut c_void);
        assert_eq!(sr, 0, "overlapped WSASend on a connected v6 socket");
        // Per Winsock, an overlapped send that completes IN THE CALL returns 0 and
        // does not signal the event; only a pended one does. Accept both shapes.
        if csent == 0 {
            assert_eq!(WaitForSingleObject(cev, 6000), 0, "a pended WSASend must signal its event");
        }
        assert_eq!(csent as usize, cm.len(), "bytes reported sent");

        let mut crb = [0u8; 64];
        let mut crw = WsaBuf { len: crb.len() as u32, buf: crb.as_mut_ptr() as *mut i8 };
        let mut crcv = 0u32;
        let mut cfl = 0u32;
        let rev = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut rov = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: rev };
        let rr = WSARecv(cs, &mut crw, 1, &mut crcv, &mut cfl, std::ptr::null_mut(), &mut rov as *mut WsaOverlapped as *mut c_void);
        if rr != 0 {
            assert_eq!(WSAGetLastError(), 997, "a pending recv must report WSA_IO_PENDING");
            assert_eq!(WaitForSingleObject(rev, 6000), 0, "the relay's reply must complete the recv");
        }
        assert_eq!(rov.internal, 0, "recv OVERLAPPED.Internal reports success");
        assert_eq!(&crb[..crcv as usize], &cm[..], "CONNECTED + OVERLAPPED + IPv6 round-trip through the proxy");
        closesocket(cs);
        CloseHandle(cev);
        CloseHandle(rev);

        // (b) the same over an IOCP: completions for a connected socket come from
        //     AFD itself, so the relay path must work with a completion port too.
        let port = CreateIoCompletionPort(-1isize as *mut c_void, std::ptr::null_mut(), 0, 1);
        assert!(!port.is_null(), "CreateIoCompletionPort");
        let cs2 = WSASocketW(23, 2, 17, std::ptr::null(), 0, 1);
        assert_eq!(
            bind(cs2 as *mut c_void, &any6 as *const SockAddrIn6W as *const SockAddrInW, std::mem::size_of::<SockAddrIn6W>() as i32),
            0,
            "bind [::] (iocp variant)"
        );
        assert_eq!(CreateIoCompletionPort(cs2, port, 0x5EED, 0), port, "associate the connected v6 socket");
        assert_eq!(
            connect(cs2, &dst6 as *const SockAddrIn6W as *const c_void, std::mem::size_of::<SockAddrIn6W>() as i32),
            0,
            "connect (iocp variant)"
        );
        let i2 = b"v6-connected-overlapped-iocp";
        let sb2 = WsaBuf { len: i2.len() as u32, buf: i2.as_ptr() as *const u8 as *mut i8 };
        let mut s2n = 0u32;
        let e2 = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut o2 = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: e2 };
        let _ = WSASend(cs2, &sb2, 1, &mut s2n, 0, std::ptr::null_mut(), &mut o2 as *mut WsaOverlapped as *mut c_void);
        let mut r2b = [0u8; 64];
        let mut r2w = WsaBuf { len: r2b.len() as u32, buf: r2b.as_mut_ptr() as *mut i8 };
        let mut r2n = 0u32;
        let mut r2f = 0u32;
        let e3 = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        let mut o3 = WsaOverlapped { internal: 0, internal_high: 0, off: 0, off_hi: 0, event: e3 };
        let rrcv = WSARecv(cs2, &mut r2w, 1, &mut r2n, &mut r2f, std::ptr::null_mut(), &mut o3 as *mut WsaOverlapped as *mut c_void);
        // A reply that was already queued completes in the call, and per Winsock that
        // posts NO completion packet — so only drain the port when it actually pended.
        let want = &mut o3 as *mut WsaOverlapped as usize;
        let mut got = rrcv == 0;
        for _ in 0..4 {
            if got {
                break;
            }
            let mut nb = 0u32;
            let mut key = 0usize;
            let mut pov: *mut c_void = std::ptr::null_mut();
            if GetQueuedCompletionStatus(port, &mut nb, &mut key, &mut pov, 6000) == 0 {
                break;
            }
            assert_eq!(key, 0x5EED, "completion key survives the connected-socket path");
            if pov as usize == want {
                got = true;
                break;
            }
        }
        assert!(got, "the relayed reply must complete inline or through the port");
        assert_eq!(&r2b[..r2n as usize], &i2[..], "CONNECTED + OVERLAPPED + IPv6 + IOCP round-trip");
        closesocket(cs2);
        CloseHandle(e2);
        CloseHandle(e3);
        CloseHandle(port);
    }

    // --- SELECT-driven UDP: readiness has to come from the hook inbox. The app
    //     socket itself never receives anything (the reply lands on the shadow
    //     socket), so an unhooked select would block until its timeout. ---
    unsafe {
        let sock = socket(2, 2, 17);
        assert!(sock != (-1isize as *mut c_void), "socket() for select test");
        let local = SockAddrInW { family: 2, port: 0u16.to_be(), addr: [127, 0, 0, 1], zero: [0; 8] };
        bind(sock, &local, std::mem::size_of::<SockAddrInW>() as i32);
        let dst = SockAddrInW { family: 2, port: 53u16.to_be(), addr: [198, 51, 100, 41], zero: [0; 8] };
        let msg = b"select-driven-udp";
        let sb = WsaBuf { len: msg.len() as u32, buf: msg.as_ptr() as *const u8 as *mut i8 };
        let mut sent = 0u32;
        let r = WSASendTo(
            sock, &sb, 1, &mut sent, 0, &dst, std::mem::size_of::<SockAddrInW>() as i32,
            std::ptr::null_mut(), std::ptr::null_mut(),
        );
        assert_eq!(r, 0, "sendto before select (proxified)");

        let mut rfds = FdSetWin { count: 1, fds: [std::ptr::null_mut(); 64] };
        rfds.fds[0] = sock;
        let mut tv = WinTimeVal { sec: 6, usec: 0 };
        let none: *mut FdSetWin = std::ptr::null_mut();
        let ready = select(0, &mut rfds, none, none, &mut tv);
        assert_eq!(ready, 1, "select() must report the proxied socket readable");
        assert_eq!(rfds.count, 1, "the returned read-set names it");
        assert_eq!(rfds.fds[0], sock, "and it is our socket");

        // readable must mean readable: the datagram is really there
        let mut rb = [0u8; 64];
        let mut rwb = WsaBuf { len: rb.len() as u32, buf: rb.as_mut_ptr() as *mut i8 };
        let mut recvd = 0u32;
        let mut flags = 0u32;
        let mut flen = std::mem::size_of::<SockAddrInW>() as i32;
        let mut from: SockAddrInW = std::mem::zeroed();
        let rr = WSARecvFrom(
            sock, &mut rwb, 1, &mut recvd, &mut flags, &mut from, &mut flen,
            std::ptr::null_mut(), std::ptr::null_mut(),
        );
        assert_eq!(rr, 0, "recv after select()");
        assert_eq!(&rb[..recvd as usize], &msg[..], "SELECT-driven UDP round-trip");
        closesocket(sock);
    }

    // --- WSAEventSelect-driven UDP (the other common game loop): wait on an event,
    //     then WSAEnumNetworkEvents must report FD_READ from the hook queue. ---
    unsafe {
        const FD_READ: i32 = 0x0001;
        let sock = socket(2, 2, 17);
        let local = SockAddrInW { family: 2, port: 0u16.to_be(), addr: [127, 0, 0, 1], zero: [0; 8] };
        bind(sock, &local, std::mem::size_of::<SockAddrInW>() as i32);
        let ev = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
        assert_eq!(WSAEventSelect(sock, ev, FD_READ), 0, "WSAEventSelect(FD_READ)");
        let dst = SockAddrInW { family: 2, port: 53u16.to_be(), addr: [198, 51, 100, 42], zero: [0; 8] };
        let msg = b"event-select-udp";
        let sb = WsaBuf { len: msg.len() as u32, buf: msg.as_ptr() as *const u8 as *mut i8 };
        let mut sent = 0u32;
        assert_eq!(
            WSASendTo(sock, &sb, 1, &mut sent, 0, &dst, std::mem::size_of::<SockAddrInW>() as i32,
                      std::ptr::null_mut(), std::ptr::null_mut()),
            0,
            "sendto before waiting on the event"
        );
        assert_eq!(WaitForSingleObject(ev, 6000), 0, "the hook must signal the FD_READ event");
        let mut net = 0i32;
        assert_eq!(WSAEnumNetworkEvents(sock, ev, &mut net), 0, "WSAEnumNetworkEvents");
        assert_ne!(net & FD_READ, 0, "FD_READ must be reported for a queued reply, got {net:#x}");

        let mut rb = [0u8; 64];
        let mut rwb = WsaBuf { len: rb.len() as u32, buf: rb.as_mut_ptr() as *mut i8 };
        let mut recvd = 0u32;
        let mut flags = 0u32;
        let mut flen = std::mem::size_of::<SockAddrInW>() as i32;
        let mut from: SockAddrInW = std::mem::zeroed();
        let tv: u32 = 5000;
        setsockopt(sock, 0xffff, 0x1006, &tv as *const u32 as *const i8, 4);
        assert_eq!(
            WSARecvFrom(sock, &mut rwb, 1, &mut recvd, &mut flags, &mut from, &mut flen,
                        std::ptr::null_mut(), std::ptr::null_mut()),
            0,
            "recv after the event fired"
        );
        assert_eq!(&rb[..recvd as usize], &msg[..], "WSAEventSelect-driven UDP round-trip");
        closesocket(sock);
        CloseHandle(ev);
    }

    // --- WFP-route UDP. A driver would (1) stage a flow record naming the real
    //     destination and (2) let the redirected app send bare datagrams into a
    //     per-flow token socket. This test does both, so everything downstream of the
    //     kernel is exercised for real: relay framing, SOCKS5 UDP ASSOCIATE, and the
    //     reply path back to the app. ---
    {
        use trans_proxier::wfp_classify::{FlowRecord, VERDICT_REDIRECT};
        use trans_proxier::wfp_ingress;
        let ut = wfp_ingress::udp_token_ports();
        assert_eq!(ut.len(), wfp_ingress::UDP_TOKEN_POOL, "a UDP token per concurrent flow");
        let tok = ut[3];

        let mut rec = FlowRecord::default();
        rec.family = 2;
        rec.addr[..4].copy_from_slice(&[203, 0, 113, 77]);
        rec.port_be = 443u16.to_be();
        rec.proto = 17;
        rec.verdict = VERDICT_REDIRECT;
        rec.pid = std::process::id();
        rec.token_port = tok;
        let mut frame = vec![0u8; 4 + std::mem::size_of_val(&rec.to_bytes())];
        frame[0..2].copy_from_slice(&tok.to_le_bytes());
        frame[4..].copy_from_slice(&rec.to_bytes());
        let mut ack = [0u8; 1];
        let mut got = 0u32;
        let mut ok = 0;
        for _ in 0..60 {
            ok = unsafe {
                CallNamedPipeW(
                    wide(&intercept::wfp_pipe_name()).as_ptr(),
                    frame.as_mut_ptr() as *mut c_void,
                    frame.len() as u32,
                    ack.as_mut_ptr() as *mut c_void,
                    1,
                    &mut got,
                    1000,
                )
            };
            if ok != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_ne!(ok, 0, "ingress pipe must accept the staged UDP flow");
        assert_eq!(ack[0], 1, "UDP record accepted");

        let wg = b"via-wfp-udp-token";
        let app = UdpSocket::bind("127.0.0.1:0").unwrap();
        app.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        app.send_to(wg, ("127.0.0.1", tok)).expect("redirected datagram into the token");
        let mut back = [0u8; 64];
        let (bn, bfrom) = app
            .recv_from(&mut back)
            .expect("reply must come back through the token socket");
        assert_eq!(&back[..bn], &wg[..], "UDP round-trip over the WFP route");
        assert_eq!(bfrom.port(), tok, "the app only accepts replies from the port it was sent to");

        // ── THE SAME TOKEN, NOW A DIFFERENT FLOW ────────────────────────────────
        // The driver hands a UDP token back on flow delete, so a port that served one
        // flow will serve the next. A source pin that never resets would reject this
        // datagram as "a second source" — and after 16 flows UDP would be dead forever,
        // which is precisely the bug this scenario exists to catch.
        {
            use trans_proxier::wfp_classify::{FlowRecord as FR2, VERDICT_REDIRECT as VR2};
            let mut rec2 = FR2::default();
            rec2.family = 2;
            rec2.addr[..4].copy_from_slice(&[198, 51, 100, 66]);
            rec2.port_be = 5353u16.to_be();
            rec2.proto = 17;
            rec2.verdict = VR2;
            rec2.pid = std::process::id();
            rec2.token_port = tok;
            rec2.flow_id = 0xB00B_0001; // a different WFP flow on a recycled port
            let mut frame2 = vec![0u8; 4 + rec2.to_bytes().len()];
            frame2[0..2].copy_from_slice(&tok.to_le_bytes());
            frame2[4..].copy_from_slice(&rec2.to_bytes());
            let mut ack2 = [0u8; 1];
            let mut got2 = 0u32;
            let ok2 = unsafe {
                CallNamedPipeW(
                    wide(&intercept::wfp_pipe_name()).as_ptr(),
                    frame2.as_mut_ptr() as *mut c_void,
                    frame2.len() as u32,
                    ack2.as_mut_ptr() as *mut c_void,
                    1,
                    &mut got2,
                    1000,
                )
            };
            assert_ne!(ok2, 0, "the ingress pipe must accept the next flow on this token");

            let app2 = UdpSocket::bind("127.0.0.1:0").unwrap();
            app2.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
            assert_ne!(
                app2.local_addr().unwrap().port(),
                app.local_addr().unwrap().port(),
                "this scenario is only meaningful coming from a different source"
            );
            let wg2 = b"second-flow-same-token";
            app2.send_to(wg2, ("127.0.0.1", tok))
                .expect("datagram from the new flow into the recycled token");
            let mut back2 = [0u8; 64];
            let (bn2, _) = app2
                .recv_from(&mut back2)
                .expect("a rebound token must answer the NEW source, not the old one");
            assert_eq!(&back2[..bn2], &wg2[..], "the recycled token carries the new flow");
            let (l2, _) = monitor.since(0);
            assert!(
                !l2.iter().any(|l| l.message.contains("第二个源")),
                "a recycled token must not be logged as a second-source violation"
            );
            assert!(
                l2.iter().any(|l| l.message.contains("198.51.100.66:5353")),
                "the new flow's own destination must be what the relay dials"
            );
        }
        let (wl, _) = monitor.since(0);
        assert!(
            wl.iter().any(|l| l.message.contains("203.0.113.77:443") && l.message.contains("关联建立")),
            "the relay must open the associate for the RECORD's destination, got:\n{}",
            wl.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("\n")
        );
    }

    // --- (b) over TCP as well: the relay re-decides the route, and it must apply
    //     the same DNS policy the hook did. Without that, a resolver the rules send
    //     Direct gets dialled straight from this machine (the leak) instead of
    //     riding the chain, and the rewrite to the configured resolver never happens.
    {
        config.write().unwrap().rules.push(Rule {
            id: 4,
            name: "resolver-direct-tcp".into(),
            enabled: true,
            priority: 50,
            app: None,
            host: Some("198.51.100.79".into()),
            port: None,
            protocol: trans_proxier::config::RuleProtocol::Both,
            action: RuleAction::Direct,
        });
        let tq = b"dns-over-tcp-via-proxy";
        let mut tc = TcpStream::connect("198.51.100.79:53").expect("TCP DNS must be tunnelled, not dialled direct");
        tc.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        tc.write_all(tq).unwrap();
        let mut tg = vec![0u8; tq.len()];
        tc.read_exact(&mut tg)
            .expect("no echo => the connection went out through the OS path, not the chain");
        assert_eq!(tg, tq);
        let (dl, _) = monitor.since(0);
        assert!(
            dl.iter()
                .any(|l| l.message.contains("198.51.100.79:53") && l.message.contains("DNS")),
            "the tunnel must record that the query was dialled at the configured resolver, got:\n{}",
            dl.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("\n")
        );
        config.write().unwrap().rules.retain(|r| r.id != 4);
    }

    // --- BLOCK action: a connect to a host matched by a Block rule must be
    //     refused in-hook (WSAECONNREFUSED), with NO proxy egress. The engine log
    //     line "…→ 阻止" distinguishes a block from a proxied connection failure. ---
    let blocked = TcpStream::connect("198.51.100.99:80");
    assert!(blocked.is_err(), "blocked connect must fail, got {:?}", blocked.map(|_| "connected"));
    let (lines, _) = monitor.since(0);
    assert!(
        lines.iter().any(|l| l.message.contains("198.51.100.99:80") && l.message.contains("阻止")),
        "engine must log the block decision, got:\n{}",
        lines.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("\n")
    );

    // both flows must have been logged by the engine as proxified.
    //     resolve a name through the engine's DNS pipe to a synthetic IP, then
    //     connect() to it; the live hook decision must reverse-map that IP back to
    //     the HOSTNAME (so a *.example.com rule can fire). The decision log showing
    //     the hostname — which the raw 198.18.x IP could never produce — proves the
    //     whole chain works on the real in-process ws2_32 hook. ---
    let name = b"dns-test.example.com";
    let mut inbuf = [0u8; 256];
    inbuf[..4].copy_from_slice(&std::process::id().to_le_bytes()); // [pid][hostname]
    inbuf[4..4 + name.len()].copy_from_slice(name);
    let mut outbuf = [0u8; 4];
    let mut got = 0u32;
    let ok = unsafe {
        CallNamedPipeW(
            wide(&intercept::dns_pipe_name()).as_ptr(),
            inbuf.as_mut_ptr() as *mut c_void,
            256,
            outbuf.as_mut_ptr() as *mut c_void,
            4,
            &mut got,
            2000,
        )
    };
    assert_ne!(ok, 0, "CallNamedPipeW(DNS) failed");
    assert_eq!(got, 4, "DNS pipe must return a 4-byte fake IPv4");
    let fake_ip = std::net::Ipv4Addr::new(outbuf[0], outbuf[1], outbuf[2], outbuf[3]);
    assert_eq!(fake_ip.octets()[0], 198, "fake IP is from the 198.18/15 pool");
    assert_eq!(servers.dns_pool.resolve(fake_ip).as_deref(), Some("dns-test.example.com"));

    let vpayload = b"via-fake-ip".to_vec();
    let mut vs = TcpStream::connect((std::net::IpAddr::V4(fake_ip), 80)).expect("connect to fake IP (proxified)");
    vs.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    vs.write_all(&vpayload).unwrap();
    let mut vgot = vec![0u8; vpayload.len()];
    vs.read_exact(&mut vgot).expect("echo via fake IP");
    assert_eq!(vgot, vpayload, "round-trip to the fake IP reached the SOCKS5 chain");
    let (vlines, _) = monitor.since(0);
    assert!(
        vlines.iter().any(|l| l.message.contains("dns-test.example.com:80") && l.message.contains("代理")),
        "live decision must reverse-map the fake IP to its HOSTNAME, not log the raw 198.18.x"
    );

    // --- IPv6 transparent TCP: a whitelisted app's IPv6 connect() is NOW proxied
    //     (previously the IPv4-only hook let it bypass entirely = IPv6 leak).
    //     Connect to a TEST-NET v6 address; the hook redirects it to the engine
    //     (v4-mapped loopback) and the engine dials the v6 host via SOCKS5. ---
    let v6dst = std::net::SocketAddr::new(
        std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
        80,
    );
    let v6payload = b"ipv6-transparent".to_vec();
    let mut v6s = TcpStream::connect(v6dst).expect("IPv6 connect (proxified)");
    v6s.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    v6s.write_all(&v6payload).unwrap();
    let mut v6got = vec![0u8; v6payload.len()];
    v6s.read_exact(&mut v6got).expect("IPv6 echo through the proxy");
    assert_eq!(v6got, v6payload, "IPv6 TCP round-trip through the transparent proxy");
    let (v6lines, _) = monitor.since(0);
    assert!(
        v6lines.iter().any(|l| l.message.contains("2001:db8::1") && l.message.contains("代理")),
        "IPv6 destination must be logged as proxified (reverse of the v4-only leak)"
    );

    // --- the getaddrinfo / freeaddrinfo PAIR, asserted as an INVARIANT instead of one
    //     fixed outcome. The fake node is allocated by the hook, so handing it out is
    //     only safe while detour_freeaddrinfo is live to intercept the free. Which halves
    //     actually installed is readable (TpdrvHookStatus bits 13 and 14): on a host whose
    //     freeaddrinfo prologue Module Copy refuses to relocate, the hook MUST decline to
    //     virtualise DNS rather than let ws2_32 free a pointer it never allocated. ---
    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16, // network byte order
        addr: [u8; 4],
        zero: [u8; 8],
    }
    type HookStatus = unsafe extern "system" fn() -> u32;
    let hooks = unsafe {
        let p = GetProcAddress(hmod, c"TpdrvHookStatus".as_ptr() as *const i8);
        assert!(!p.is_null(), "tpdrv.dll must export TpdrvHookStatus (which detours are live)");
        std::mem::transmute::<*mut c_void, HookStatus>(p)()
    };
    let gai_hook = hooks & (1 << 13) != 0;
    let fai_hook = hooks & (1 << 14) != 0;
    println!("detour mask {hooks:#07x}: getaddrinfo={gai_hook} freeaddrinfo={fai_hook}");

    let node_c = std::ffi::CString::new("dns-hook.example.com").unwrap();
    let svc_c = std::ffi::CString::new("8080").unwrap();
    let mut gai_res: *mut AiRes = std::ptr::null_mut();
    let rc = unsafe { getaddrinfo(node_c.as_ptr(), svc_c.as_ptr(), std::ptr::null(), &mut gai_res) };
    let fake = rc == 0
        && !gai_res.is_null()
        && unsafe {
            let sa = &*((*gai_res).addr as *const SockAddrIn);
            sa.family == 2 && sa.addr[0] == 198 && u16::from_be(sa.port) == 8080
        };
    if fai_hook {
        assert!(
            fake,
            "both halves of the pair are live, so the name must return a 198.18/15 fake              IP with port 8080 preserved (rc={rc})"
        );
    } else {
        assert!(
            !fake,
            "freeaddrinfo is not detoured (mask {hooks:#07x}), so the hook must NOT hand              out a node it allocated: the real resolver answers instead"
        );
        assert!(gai_hook, "getaddrinfo is still hooked — the heap guard lives inside it");
    }
    // The widened prologue has to actually EXECUTE, not just install: an IP literal is
    // inert (never virtualised), so this goes through the trampoline we rebuilt for
    // freeaddrinfo — `test rcx,rcx` plus the widened `je` — into real Winsock, which
    // then frees a node it allocated itself. A bad relocation shows up here as a crash.
    let num_c = std::ffi::CString::new("203.0.113.9").unwrap();
    let mut nres: *mut AiRes = std::ptr::null_mut();
    let nrc = unsafe { getaddrinfo(num_c.as_ptr(), svc_c.as_ptr(), std::ptr::null(), &mut nres) };
    assert_eq!(nrc, 0, "a numeric node must still resolve (through the trampoline)");
    assert!(!nres.is_null(), "numeric resolution returned a node");
    let na = unsafe { &*((*nres).addr as *const SockAddrIn) };
    assert_eq!(na.addr[..4], [203, 0, 113, 9], "the numeric answer must pass through untouched");
    unsafe { freeaddrinfo(nres) };

    if !gai_res.is_null() {
        // Must not abort in either branch: with the pair live the detour recognises our
        // leaked node and skips the real free; without it the node is the system's own.
        unsafe { freeaddrinfo(gai_res) };
    }

    // --- WSA-style UNCONNECTED UDP: WSASendTo + WSARecvFrom (games that use the
    //     WSA* calls, not sendto/recv) must ALSO be proxied through the same
    //     shadow-socket/inbox machinery. ---
    unsafe {
        const AF_INET: i32 = 2;
        const SOCK_DGRAM: i32 = 2;
        const SOL_SOCKET: i32 = 0xffff;
        const SO_RCVTIMEO: i32 = 0x1006;
        let sock = socket(AF_INET, SOCK_DGRAM, 17);
        assert!(sock != (-1isize as *mut c_void), "socket() failed");
        let local = SockAddrInW { family: AF_INET as u16, port: 0u16.to_be(), addr: [127, 0, 0, 1], zero: [0; 8] };
        bind(sock, &local, std::mem::size_of::<SockAddrInW>() as i32);
        let tv: u32 = 5000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv as *const u32 as *const i8, 4);

        let dst = SockAddrInW { family: AF_INET as u16, port: 53u16.to_be(), addr: [198, 51, 100, 13], zero: [0; 8] };
        let msg = b"wsa-udp-ping";
        let sbuf = WsaBuf { len: msg.len() as u32, buf: msg.as_ptr() as *const u8 as *mut i8 };
        let mut sent = 0u32;
        let r = WSASendTo(sock, &sbuf, 1, &mut sent, 0, &dst, std::mem::size_of::<SockAddrInW>() as i32, std::ptr::null_mut(), std::ptr::null_mut());
        assert_eq!(r, 0, "WSASendTo (proxified) should succeed");
        assert_eq!(sent as usize, msg.len(), "WSASendTo reports bytes sent");

        let mut rbuf = [0u8; 64];
        let mut rwsa = WsaBuf { len: rbuf.len() as u32, buf: rbuf.as_mut_ptr() as *mut i8 };
        let mut recvd = 0u32;
        let mut flags = 0u32;
        let mut flen = std::mem::size_of::<SockAddrInW>() as i32;
        let mut from: SockAddrInW = std::mem::zeroed();
        let rr = WSARecvFrom(sock, &mut rwsa, 1, &mut recvd, &mut flags, &mut from, &mut flen, std::ptr::null_mut(), std::ptr::null_mut());
        closesocket(sock);
        assert_eq!(rr, 0, "WSARecvFrom should receive the proxied echo");
        assert_eq!(&rbuf[..recvd as usize], &msg[..], "WSASendTo/WSARecvFrom UDP round-trip through the SOCKS5 proxy");
    }

    // --- (b) the app's :53 goes through the PROXY: a resolver that the rules send
    //     Direct is still tunnelled when dns_mode=proxy, and is NOT tunnelled when
    //     dns_mode=local. The unroutable TEST-NET resolver answers nothing, so an
    //     echo back can only mean the query rode the SOCKS5 chain. ---
    {
        let resolver: SocketAddr = "198.51.100.77:53".parse().unwrap();
        config.write().unwrap().rules.push(Rule {
            id: 3,
            name: "resolver-direct".into(),
            enabled: true,
            priority: 50, // above the catch-all "*" rule (priority 10)
            app: None,
            host: Some("198.51.100.77".into()),
            port: None,
            protocol: trans_proxier::config::RuleProtocol::Both,
            action: RuleAction::Direct,
        });
        let q = b"who-is-198-51-100-77";
        let mut rb = [0u8; 64];

        // 1. dns_mode=local: the Direct rule stands, so nothing is proxied here.
        config.write().unwrap().settings.dns_mode = DnsMode::Local;
        let s_local = UdpSocket::bind("127.0.0.1:0").unwrap();
        s_local.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        // Off-network this send fails outright (no route to TEST-NET-2); either way
        // nothing may come back, which is what proves it was not tunnelled.
        let direct = s_local.send_to(q, resolver);
        assert!(
            s_local.recv(&mut rb).is_err(),
            "with dns_mode=local a Direct-routed resolver query must not be tunnelled (send: {direct:?})"
        );

        // 2. dns_mode=proxy: the same destination is pulled onto the chain, AND dialled
        //    at the CONFIGURED resolver rather than the app's — which is the whole point
        //    of the custom-resolver requirement, and is otherwise invisible on the wire.
        config.write().unwrap().settings.dns.servers = vec![trans_proxier::config::DnsServer {
            protocol: trans_proxier::config::DnsProto::Udp,
            server: "1.1.1.1".into(),
            port: 53,
        }];
        config.write().unwrap().settings.dns_mode = DnsMode::Proxy;
        let s_proxy = UdpSocket::bind("127.0.0.1:0").unwrap();
        s_proxy.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        s_proxy.send_to(q, resolver).expect("proxy-mode resolver query");
        let (n, _from) = s_proxy.recv_from(&mut rb).expect("resolver query must come back via the proxy");
        assert_eq!(&rb[..n], &q[..], "DNS query tunnelled through SOCKS5 and echoed back");
        let (dl, _) = monitor.since(0);
        assert!(
            dl.iter().any(|l| l.message.contains("DNS 解析器改写")
                && l.message.contains("198.51.100.77:53")
                && l.message.contains("1.1.1.1:53")),
            "the UDP query for the app's resolver must be RE-DIALLED at the configured resolver, and say so; got:
{}
{}",
            "see next line",
            dl.iter().rev().take(8).map(|l| l.message.clone()).collect::<Vec<_>>().join(" | ")
        );
        assert!(
            dl.iter().any(|l| l.message.contains("198.51.100.77:53") && l.message.contains("代理")),
            "the engine must log the resolver query as proxified, got:
{}",
            dl.iter().map(|l| l.message.clone()).collect::<Vec<_>>().join("
")
        );
        // leave the profile as the rest of the suite expects it
        config.write().unwrap().settings.dns_mode = DnsMode::Proxy;
        config.write().unwrap().settings.dns.servers.clear();
        config.write().unwrap().rules.retain(|r| r.id != 3);
    }

    // both flows must have been logged by the engine as proxified.
    let (lines, _) = monitor.since(0);
    assert!(lines.iter().any(|l| l.message.contains("(TCP)") && l.message.contains("代理")), "tcp interception logged");
    assert!(lines.iter().any(|l| l.message.contains("(UDP)") && l.message.contains("代理")), "udp interception logged");
}
