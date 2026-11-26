//! Non-blocking `connect()` must keep its completion semantics — the bug that makes
//! every Chromium-family app hang while Firefox works.
//!
//! The transparent hook cannot let the app connect to the real destination, so it
//! redirects the app's socket to the local relay instead. For a BLOCKING socket that is
//! invisible: connect returns once the loopback hop is up, and the in-band header that
//! tells the relay the original destination can be written immediately.
//!
//! For a NON-BLOCKING socket — which is what Chrome/Edge/Electron use, with IOCP or
//! WSAEventSelect — the contract is different: `connect()` must return
//! `SOCKET_ERROR / WSAEWOULDBLOCK`, and the application learns the connection completed
//! from an **FD_CONNECT** notification the kernel posts because *it* is the one that
//! started the connect. Our hook used to wait for the loopback connect itself
//! (`await_connect`) and return 0 to the caller. Two consequences: the app is told
//! synchronously "connected" while the kernel's completion is consumed by us, so IOCP
//! clients wait for an FD_CONNECT that never arrives; and they therefore never write,
//! which is exactly the "已连接 20s, 发送 0 B, ERR_TIMED_OUT" rows in the field report.
//!
//! This test asserts the contract itself, plus that the tunnel still works afterwards —
//! which requires the original destination to reach the relay WITHOUT the in-band header,
//! i.e. via the out-of-band registration keyed by the socket's local port.

#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use trans_proxier::config::{Chain, Config, DnsMode, ProxyKind, ProxyServer, Rule, RuleAction, RuleProtocol};
use trans_proxier::intercept;
use trans_proxier::monitor::Monitor;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const WSAEWOULDBLOCK: i32 = 10035;
const FD_CONNECT: i32 = 0x0010;
const WAIT_OBJECT_0: u32 = 0;
const INVALID_HANDLE_V: *mut c_void = -1isize as *mut c_void;

#[repr(C)]
struct SockAddrIn {
    sin_family: i16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct TimeVal {
    sec: i64,
    usec: i64,
}

#[repr(C)]
struct FdSet {
    count: u32,
    fds: [usize; 64],
}

unsafe extern "system" {
    fn WSAStartup(ver: u16, data: *mut c_void) -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> *mut c_void;
    fn connect(s: *mut c_void, name: *const SockAddrIn, len: i32) -> i32;
    fn ioctlsocket(s: *mut c_void, cmd: i32, arg: *mut u32) -> i32;
    fn closesocket(s: *mut c_void) -> i32;
    fn send(s: *mut c_void, buf: *const u8, len: i32, flags: i32) -> i32;
    fn getsockname(s: *mut c_void, name: *mut SockAddrIn, len: *mut i32) -> i32;
    fn WSAGetLastError() -> i32;
    fn WSAEventSelect(s: *mut c_void, ev: *mut c_void, events: i32) -> i32;
    fn CreateEventW(sa: *const c_void, manual: i32, initial: i32, name: *const u16) -> *mut c_void;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn select(nfds: i32, r: *mut FdSet, w: *mut FdSet, e: *mut FdSet, tv: *mut TimeVal) -> i32;
    fn CreateMutexW(sa: *const c_void, owner: i32, name: *const u16) -> *mut c_void;
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// A destination that is guaranteed never to answer, so any success we observe came from
/// the proxy path and not from the network.
fn target() -> SockAddrIn {
    SockAddrIn {
        sin_family: AF_INET as i16,
        sin_port: (443u16).to_be(),
        sin_addr: [198, 51, 100, 7],
        sin_zero: [0; 8],
    }
}

fn engine_up() -> (Arc<RwLock<Config>>, Arc<Monitor>, intercept::Servers, *mut c_void) {
    unsafe {
        let mut data = [0u16; 400];
        WSAStartup(0x0202, data.as_mut_ptr() as *mut c_void);
    }
    let fake = spawn_fake_socks5();
    let mut config = Config::default();
    config.settings.proxification_enabled = true;
    config.settings.app_whitelist_enabled = false;
    config.settings.ip_leak_prevention = false;
    config.settings.dns_mode = trans_proxier::config::DnsMode::Proxy;
    config.proxies.push(ProxyServer {
        id: 1,
        name: "fake-socks5".into(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: fake,
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
        protocol: RuleProtocol::Both,
        action: RuleAction::Proxy { chain: 1 },
    });
    let config = Arc::new(RwLock::new(config));
    let monitor = Arc::new(Monitor::new());

    // Own instance: a developer running the GUI must not gate (or be gated by) this test.
    unsafe { std::env::set_var("TPROXIER_INSTANCE", format!("nb{}", std::process::id())) };
    let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, wide(&intercept::engine_mutex_name()).as_ptr()) };
    assert!(mutex != std::ptr::null_mut() && mutex != INVALID_HANDLE_V, "engine mutex");

    let servers = intercept::spawn_servers(config.clone(), monitor.clone()).expect("spawn_servers");

    let exe = std::env::current_exe().unwrap();
    let mut dll = exe.parent().unwrap().join("tpdrv.dll");
    if !dll.exists() {
        dll = exe.parent().unwrap().parent().unwrap().join("tpdrv.dll");
    }
    assert!(dll.exists(), "build tpdrv.dll first: {}", dll.display());
    let hmod = unsafe { LoadLibraryW(wide(&dll.to_string_lossy()).as_ptr()) };
    assert!(!hmod.is_null(), "LoadLibrary(tpdrv.dll) failed");
    std::thread::sleep(Duration::from_millis(200));
    (config, monitor, servers, mutex)
}

/// A SOCKS5 server that answers CONNECT with a loopback tunnel and echoes, so we can
/// prove bytes actually went through the proxy.
fn spawn_fake_socks5() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut hello = [0u8; 3];
                if s.read_exact(&mut hello).is_err() {
                    return;
                }
                let _ = s.write_all(&[5, 0]); // VER, METHOD
                let mut head = [0u8; 5];
                if s.read_exact(&mut head[..4]).is_err() {
                    return;
                }
                let extra = match head[3] {
                    1 => 4,
                    3 => {
                        // ATYP 3: one length byte we have not read yet, then the name
                        // and the 2-byte port.
                        if s.read_exact(&mut head[4..5]).is_err() {
                            return;
                        }
                        head[4] as usize + 2
                    }
                    4 => 16,
                    _ => 4,
                };
                let mut rest = vec![0u8; extra];
                if s.read_exact(&mut rest).is_err() {
                    return;
                }
                // reply: ver, rep=0, rsv, atyp=1, 0.0.0.0:0
                let _ = s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// The contract, stated as the application sees it.
#[test]
fn nonblocking_connect_reports_in_progress_rather_than_done() {
    let (_cfg, _mon, _servers, _mutex) = engine_up();

    let s = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
    assert!(s != INVALID_HANDLE_V, "socket() failed: {}", unsafe { WSAGetLastError() });

    let mut one = 1u32;
    assert_eq!(unsafe { ioctlsocket(s, -2147195266 /* FIONBIO */, &mut one) }, 0, "FIONBIO");

    let t = target();
    let r = unsafe { connect(s, &t as *const SockAddrIn as *const SockAddrIn, std::mem::size_of::<SockAddrIn>() as i32) };
    let gle = unsafe { WSAGetLastError() };

    // This is the whole bug: the hook waited for the relay connect itself and returned 0,
    // consuming the completion the application is waiting for.
    assert_eq!(
        r, -1,
        "a non-blocking connect() must not be answered with 0 by the hook — the client \
         (Chromium: IOCP) waits for FD_CONNECT and would hang forever (got 0, gle={gle})"
    );
    assert_eq!(
        gle, WSAEWOULDBLOCK,
        "non-blocking connect() must still report WSAEWOULDBLOCK through the hook"
    );

    // ...and the completion must actually arrive.
    let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    assert!(ev != std::ptr::null_mut() && ev != INVALID_HANDLE_V, "CreateEvent");
    assert_eq!(unsafe { WSAEventSelect(s, ev, FD_CONNECT) }, 0, "WSAEventSelect");
    let wait = unsafe { WaitForSingleObject(ev, 4000) };
    unsafe {
        closesocket(s);
    }
    assert_eq!(
        wait, WAIT_OBJECT_0,
        "FD_CONNECT never arrived — the application would sit on a connected-but-never-\
         notified socket and send nothing (the observed 发送 0 B / ERR_TIMED_OUT)"
    );
}

/// The consequence that matters: the tunnel still carries the connection, so the original
/// destination reached the relay even though no in-band header could be written before the
/// application's own first bytes.
#[test]
fn nonblocking_tunnel_still_delivers_the_original_destination() {
    let (_cfg, mon, _servers, _mutex) = engine_up();

    let s = unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_TCP) };
    assert!(s != INVALID_HANDLE_V, "socket() failed");
    let mut one = 1u32;
    assert_eq!(unsafe { ioctlsocket(s, -2147195266, &mut one) }, 0);

    let t = target();
    let _ = unsafe { connect(s, &t as *const SockAddrIn, std::mem::size_of::<SockAddrIn>() as i32) };

    // wait for writability (loopback connect completes fast), then write as TLS would
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    let mut wrote = -1;
    while std::time::Instant::now() < deadline {
        let mut set = FdSet { count: 1, fds: [0usize; 64] };
        set.fds[0] = s as usize;
        let mut tv = TimeVal { sec: 0, usec: 200_000 };
        let ready = unsafe { select(0, std::ptr::null_mut(), &mut set, std::ptr::null_mut(), &mut tv) };
        if ready > 0 {
            let mut err = 0i32;
            let mut len = std::mem::size_of::<i32>() as i32;
            unsafe extern "system" {
                fn getsockopt(s: *mut c_void, level: i32, opt: i32, val: *mut i8, len: *mut i32) -> i32;
            }
            // SO_ERROR(0x1007) at SOL_SOCKET(0xffff): a failed connect surfaces here
            unsafe { getsockopt(s, 0x1007, 0x1007, &mut err as *mut i32 as *mut i8, &mut len) };
            if err != 0 {
                break; // genuinely failed; the assertion below will report it
            }
            let msg = b"hello-over-tunnel";
            wrote = unsafe { send(s, msg.as_ptr(), msg.len() as i32, 0) };
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        wrote == 17,
        "the client never got a writable socket (or the connect failed): sent {wrote} bytes"
    );
    unsafe { closesocket(s) };

    // the relay is echo, so if the path is intact the engine logged the proxied flow
    let mut seen = false;
    for _ in 0..40 {
        let (lines, _) = mon.since(0);
        if lines
            .iter()
            .any(|l| l.message.contains("198.51.100.7") && l.message.contains("隧道已建立"))
        {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        seen,
        "no tunnel was established for the non-blocking socket: without the in-band header \
         the relay must resolve the destination from the out-of-band registration"
    );
}
