//! Windows-only transparent-interception engine, SHARED by `tpinject` (CLI) and
//! the desktop GUI's 启动 button.
//!
//! Pieces:
//!  1. engine mutex (hook liveness gate),
//!  2. named-pipe decision server keyed by the OWNING process (real whitelist),
//!  3. a TCP relay (redirected app sockets → `engine::connect_target` → chain),
//!  4. a UDP relay (connected-UDP apps → SOCKS5 UDP ASSOCIATE through the
//!     chain's SOCKS5 egress — this is what proxies game traffic),
//!  5. global WH_GETMESSAGE hook install via the driver's InitFilter3.
//!
//! `spawn_servers` runs 2–4 WITHOUT the hook so the transparent data path can be
//! tested in-process (no system-wide injection); `Engine` adds 1+5 for real use.

use std::collections::HashMap;
use std::ffi::{c_void, OsStr};
use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::config::{Config, ProxyKind};
use crate::dns::{self, FakeIpPool};
use crate::engine;
use crate::monitor::Monitor;
use crate::rules::{decide_route, is_whitelisted, Decision};
use crate::socks5;

pub const MAGIC: u32 = 0x5052_5831; // "PRX1" — the wire handshake tpdrv and the engine share
/// Same 32-byte record, second intent: "this app socket's local port belongs to the
/// destination in this record". Sent AFTER the decision (binding earlier could trap a
/// socket that turns out to be direct on the loopback address), and BEFORE the connect,
/// so the mapping exists by the time the redirected connection is accepted.
pub const MAGIC_REG: u32 = 0x5052_5832; // "PRX2"
const ACTION_DIRECT: u32 = 0;
const ACTION_PROXY: u32 = 1;
const ACTION_BLOCK: u32 = 2;
const IPPROTO_UDP: u8 = 17;
const AF_INET6: u16 = 23; // Winsock AF_INET6
pub const PIPE_NAME: &str = r"\\.\pipe\tproxierPE";
/// Dedicated DNS-allocation pipe (separate name so it never collides with the
/// connect-decision pipe). A hostname (null-padded to DNS_NAME_MAX) goes in, the
/// 4 octets of a fake IP come out — the producer half of the fake-IP model
/// (fnd_10). An app-side `getaddrinfo` hook (consent-gated, in tpdrv) calls this;
/// the engine's connect decision reverse-maps the fake IP back to the name.
pub const PIPE_NAME_DNS: &str = r"\\.\pipe\tproxierDNS";
/// Ingress for a WFP callout driver: per-flow original destinations, delivered as
/// `wfp_classify::FlowRecord` bytes. See `crate::wfp_ingress`.
pub const PIPE_NAME_WFP: &str = r"\\.\pipe\tproxierWFP";
const DNS_NAME_MAX: usize = 256;
pub const ENGINE_MUTEX: &str = "tproxierPE";

/// Multi-instance isolation: set `TPROXIER_INSTANCE=<tag>` to give this engine +
/// its injected hook a private mutex/pipe namespace, so a test (or a second
/// engine) does not collide with an already-running one. Empty/unset ⇒ default.
fn instance_suffix() -> String {
    match std::env::var("TPROXIER_INSTANCE") {
        Ok(s) if !s.is_empty() => format!("_{s}"),
        _ => String::new(),
    }
}
pub fn pipe_name() -> String { format!("{PIPE_NAME}{}", instance_suffix()) }
pub fn dns_pipe_name() -> String { format!("{PIPE_NAME_DNS}{}", instance_suffix()) }
pub fn wfp_pipe_name() -> String { format!("{PIPE_NAME_WFP}{}", instance_suffix()) }
pub fn engine_mutex_name() -> String { format!("{ENGINE_MUTEX}{}", instance_suffix()) }


/// The family policy that applies to a flow going through `proxy_host`.
///
/// "auto" deliberately resolves to **no trimming**. The obvious heuristic — the proxy
/// is on loopback, therefore the egress is this machine, therefore a host with no ::/0
/// route cannot reach IPv6 origins — is wrong for a proxy chain: a local listener like
/// 127.0.0.1:7890 forwards to remote nodes that may well have IPv6 egress even when
/// this box has none, and the app's v6 socket is dialled by the PROXY (SOCKS5 ATYP 4
/// over a v4 loopback hop), not by us. Guessing here trades a small delay for
/// unreachable IPv6-only origins, so trimming is opt-in only: set
/// `egress_family = ipv4` / `ipv6` when you have confirmed the chain lacks that family.
pub fn effective_family_policy(cfg: &Config, _proxy_host: &str) -> crate::dns::FamilyPolicy {
    crate::dns::FamilyPolicy::parse(&cfg.settings.egress_family)
}

/// The control block tpdrv reads before it modifies anything. Same layout as the one
/// in `tpdrv/src/lib.rs`; `ctl_layout_agrees_with_the_driver` is what keeps them so.
#[repr(C)]
pub struct Ctl {
    pub teardown: u32,
    pub apps_len: u32,
    pub apps: [u16; 1024],
}

pub fn ctl_name() -> String { format!("Local\\TpDrvCtl{}", instance_suffix()) }

/// Who may be patched, as the string tpdrv compares against: ';' separated lowercased
/// image names, or `*` when the operator switched the program whitelist off.
///
/// An ENABLED-but-empty whitelist yields the empty string, which means nothing may be
/// patched - the fail-closed reading. "Whitelist on, no programs" is not the same
/// decision as "no whitelist", and treating them alike is how a session ends up with
/// every GUI process patched by accident.
pub fn ctl_apps(whitelist_enabled: bool, apps: &[String]) -> String {
    if !whitelist_enabled {
        return "*".to_string();
    }
    apps.iter()
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| !a.is_empty())
        .collect::<Vec<_>>()
        .join(";")
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Req {
    pub magic: u32,
    pub pid: u32,
    pub family: u16,
    pub port_be: u16,
    pub addr: [u8; 16],
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Build the in-band header the UDP relay expects, from a WFP flow record.
///
/// A redirected datagram carries no header — the application knows nothing about us
/// — so the ingress has to synthesise the one the hook would have sent. Reusing the
/// same framing means the already-verified SOCKS5 UDP relay serves WFP traffic too,
/// instead of a second data path that only a real driver could test.
pub fn req_from_flow(rec: &crate::wfp_classify::FlowRecord) -> Req {
    Req {
        magic: MAGIC,
        pid: rec.pid,
        family: rec.family,
        port_be: rec.port_be,
        addr: rec.addr,
        // a record that carries no protocol still arrived as a datagram
        proto: if rec.proto == 0 { IPPROTO_UDP } else { rec.proto },
        _pad: [0; 3],
    }
}

/// The app socket's own port, when the hook told us it (bytes 1..3 of the old
/// `_pad`, so the 32-byte ABI and its pinned offsets are unchanged). A non-blocking
/// client cannot be given the in-band destination header — the application may write
/// its own first bytes as soon as FD_CONNECT arrives, and whoever writes first wins —
/// so the hook binds first, reports the local port here, and the relay resolves the
/// destination from it when the redirected connection is accepted.
pub fn req_local_port(req: &Req) -> Option<u16> {
    let p = u16::from_be_bytes([req._pad[1], req._pad[2]]);
    (p != 0).then_some(p)
}

/// Out-of-band destination table: app local port → the request that made it. Bounded
/// and evicting, because a client that binds and then never connects would otherwise
/// grow it forever, and an unbounded table in a proxy is just a memory leak with extra
/// steps. Entries are consumed on use.
const PENDING_MAX: usize = 4096;

fn pending() -> &'static Mutex<std::collections::VecDeque<(u16, Req)>> {
    use std::sync::OnceLock;
    static T: OnceLock<Mutex<std::collections::VecDeque<(u16, Req)>>> = OnceLock::new();
    T.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

fn remember_pending(port: u16, req: Req) {
    let mut q = pending().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = q.iter_mut().find(|(p, _)| *p == port) {
        existing.1 = req;
        return;
    }
    if q.len() >= PENDING_MAX {
        q.pop_front();
    }
    q.push_back((port, req));
}

fn take_pending(port: u16) -> Option<Req> {
    let mut q = pending().lock().unwrap_or_else(|e| e.into_inner());
    let i = q.iter().position(|(p, _)| *p == port)?;
    q.remove(i).map(|(_, r)| r)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Resp {
    pub magic: u32,
    pub action: u32,
    pub relay_ip: [u8; 4],
    pub relay_port: u16,
    pub _pad: u16,
}

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type BOOL = i32;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as *mut c_void;

unsafe extern "system" {
    fn CreateMutexW(sa: *const c_void, initialOwner: BOOL, name: *const u16) -> HANDLE;
    fn CreateNamedPipeW(
        name: *const u16,
        openMode: u32,
        pipeMode: u32,
        maxInstances: u32,
        inBuf: u32,
        outBuf: u32,
        defaultTimeout: u32,
        sa: *const c_void,
    ) -> HANDLE;
    fn ConnectNamedPipe(h: HANDLE, overlapped: *mut c_void) -> BOOL;
    fn DisconnectNamedPipe(h: HANDLE) -> BOOL;
    fn ReadFile(h: HANDLE, buf: *mut u8, n: u32, read: *mut u32, ov: *mut c_void) -> BOOL;
    fn WriteFile(h: HANDLE, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> BOOL;
    fn CloseHandle(h: HANDLE) -> BOOL;
    fn OpenProcess(access: u32, inherit: BOOL, pid: u32) -> HANDLE;
    fn QueryFullProcessImageNameW(h: HANDLE, flags: u32, name: *mut u16, size: *mut u32) -> BOOL;
    fn LoadLibraryW(name: *const u16) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const i8) -> *const c_void;
    fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> BOOL;
    fn GetLastError() -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// PID -> image basename (what app rules + the whitelist match).
pub fn image_basename(pid: u32) -> Option<String> {
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..size as usize]);
        path.rsplit(['\\', '/']).next().map(|s| s.to_string())
    }
}

/// Sorted, de-duplicated basenames of currently-running processes — feeds the
/// "选择程序" picker in the Rules editor so users don't hand-type exe names.
#[cfg(windows)]
pub fn running_app_names() -> Vec<String> {
    use std::collections::BTreeSet;
    #[repr(C)]
    struct PE32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_pid: u32,
        th32_heap: usize,
        th32_module: u32,
        cnt_threads: u32,
        th32_ppid: u32,
        pc_pri: i32,
        dw_flags: u32,
        sz_exe: [u16; 260],
    }
    unsafe extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
        fn Process32FirstW(h: HANDLE, e: *mut PE32W) -> BOOL;
        fn Process32NextW(h: HANDLE, e: *mut PE32W) -> BOOL;
    }
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    let mut set: BTreeSet<String> = BTreeSet::new();
    unsafe {
        let hs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if !hs.is_null() && hs as isize != -1 {
            let mut e: PE32W = std::mem::zeroed();
            e.dw_size = std::mem::size_of::<PE32W>() as u32;
            if Process32FirstW(hs, &mut e) != 0 {
                loop {
                    let n = e.sz_exe.iter().position(|&c| c == 0).unwrap_or(e.sz_exe.len());
                    let s = String::from_utf16_lossy(&e.sz_exe[..n]).trim().to_string();
                    if !s.is_empty() {
                        set.insert(s);
                    }
                    if Process32NextW(hs, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(hs);
        }
    }
    set.into_iter().collect()
}

#[cfg(not(windows))]
pub fn running_app_names() -> Vec<String> {
    Vec::new()
}

/// Coarse grouping for the app picker: "程序" (a normal user .exe),
/// "服务" (known Windows service / background host), "未知" (no .exe name,
/// e.g. kernel pseudo-processes). Pure + platform-independent (unit-testable).
pub fn app_category(name: &str) -> &'static str {
    const SERVICES: &[&str] = &[
        "svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "winlogon.exe",
        "csrss.exe", "smss.exe", "dwm.exe", "conhost.exe", "taskhostw.exe",
        "dllhost.exe", "runtimebroker.exe", "searchindexer.exe", "spoolsv.exe",
        "audiodg.exe", "sihost.exe", "ctfmon.exe", "fontdrvhost.exe",
        "wmiprvse.exe", "wslservice.exe", "dockerservice.exe", "codexcollector.exe",
    ];
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return "未知";
    }
    if SERVICES.contains(&lower.as_str()) || lower.ends_with("svc.exe") {
        return "服务";
    }
    if lower.ends_with(".exe") {
        return "程序";
    }
    "未知"
}

fn target_of(req: &Req) -> (String, u16) {
    let port = u16::from_be(req.port_be);
    let host = if req.family == AF_INET6 {
        // Render IPv4-mapped (::ffff:a.b.c.d) as dotted-quad so the loopback
        // relay endpoint (::ffff:127.0.0.1) still matches the "127.0.0.1"
        // exclusion — otherwise the app's connect() to the relay would be
        // re-intercepted forever.
        if req.addr[..10] == [0; 10] && req.addr[10..12] == [0xff, 0xff] {
            format!("{}.{}.{}.{}", req.addr[12], req.addr[13], req.addr[14], req.addr[15])
        } else {
            std::net::Ipv6Addr::from(req.addr).to_string()
        }
    } else {
        format!("{}.{}.{}.{}", req.addr[0], req.addr[1], req.addr[2], req.addr[3])
    };
    (host, port)
}

/// The host used for DECISIONS: a fake IP handed back to a fake-IP pool becomes
/// its real hostname, so hostname-based rules match an IP-only hook (fnd_10).
fn decision_host(req: &Req, pool: &FakeIpPool) -> (String, u16) {
    let (ip, port) = target_of(req);
    (dns::effective_host(pool, &ip), port)
}

/// Per-connection decision. UDP flows additionally require the chain egress to be
/// SOCKS5 (HTTP CONNECT cannot carry UDP — fnd_10); otherwise we leave UDP direct.
fn decide_for(req: &Req, config: &Config, tcp_port: u16, tcp_port_v6: u16, udp_port: u16, udp_port_v6: u16, pool: &FakeIpPool) -> Resp {
    // Record the destination against the app socket's own port FIRST: a non-blocking
    // client may write before any header could be sent, and the redirected connection
    // arriving on the relay is then resolved by its peer port instead.
    if let Some(lp) = req_local_port(req) {
        remember_pending(lp, *req);
    }
    let (host, port) = decision_host(req, pool);
    let app = image_basename(req.pid);
    match decide_route(config, app.as_deref(), &host, port, req.proto) {
        Decision::Proxy { chain, .. } => {
            if req.proto == IPPROTO_UDP {
                // "Block Traffic to All UDP Ports if Matched the Rule" (fnd_10):
                // when armed, a matched app's UDP is BLOCKED outright (refused in the
                // hook), not leaked direct — that is what "block" means.
                if config.settings.block_udp_if_matched {
                    return Resp { magic: MAGIC, action: ACTION_BLOCK, ..Default::default() };
                }
                let egress_is_socks5 = config
                    .chain_by_id(chain)
                    .and_then(|c| c.proxies.last())
                    .and_then(|id| config.proxy_available(*id))
                    .map(|p| p.kind == ProxyKind::Socks5)
                    .unwrap_or(false);
                if !egress_is_socks5 {
                    // The matched rule's egress cannot tunnel UDP (HTTP CONNECT /
                    // SOCKS4). Sending it direct would LEAK a whitelisted app's
                    // real IP; with IP-leak prevention on, block it instead.
                    let action = if config.settings.ip_leak_prevention {
                        ACTION_BLOCK
                    } else {
                        ACTION_DIRECT
                    };
                    return Resp { magic: MAGIC, action, ..Default::default() };
                }
                // Connected IPv6 UDP dials the [::1] relay (the hook's family6
                // branch uses ::1:relay_port); everything else uses the v4 relay.
                let connected_v6 = req.family == AF_INET6 && req._pad[0] == 1;
                if connected_v6 {
                    if udp_port_v6 == 0 {
                        return Resp { magic: MAGIC, action: ACTION_DIRECT, ..Default::default() };
                    }
                    Resp { magic: MAGIC, action: ACTION_PROXY, relay_ip: [0, 0, 0, 0], relay_port: udp_port_v6, _pad: 0 }
                } else {
                    Resp { magic: MAGIC, action: ACTION_PROXY, relay_ip: [127, 0, 0, 1], relay_port: udp_port, _pad: 0 }
                }
            } else {
                // IPv6 connects redirect to the engine's [::1] relay; IPv4 to 127.0.0.1.
                if req.family == AF_INET6 {
                    if tcp_port_v6 == 0 {
                        // No IPv6 relay available -> leave v6 direct rather than fail.
                        return Resp { magic: MAGIC, action: ACTION_DIRECT, ..Default::default() };
                    }
                    Resp { magic: MAGIC, action: ACTION_PROXY, relay_ip: [0, 0, 0, 0], relay_port: tcp_port_v6, _pad: 0 }
                } else {
                    Resp { magic: MAGIC, action: ACTION_PROXY, relay_ip: [127, 0, 0, 1], relay_port: tcp_port, _pad: 0 }
                }
            }
        }
        Decision::Direct { .. } => Resp { magic: MAGIC, action: ACTION_DIRECT, ..Default::default() },
        Decision::Block { .. } => Resp { magic: MAGIC, action: ACTION_BLOCK, ..Default::default() },
    }
}

fn serve_pipe_one(pipe: HANDLE, config: &Config, tcp_port: u16, tcp_port_v6: u16, udp_port: u16, udp_port_v6: u16, monitor: &Monitor, pool: &FakeIpPool) {
    unsafe {
        let mut req = Req::default();
        let mut read = 0u32;
        let ok = ReadFile(
            pipe,
            &mut req as *mut Req as *mut u8,
            std::mem::size_of::<Req>() as u32,
            &mut read,
            std::ptr::null_mut(),
        );
        if ok == 0 || read as usize != std::mem::size_of::<Req>() {
            return;
        }
        if req.magic == MAGIC_REG {
            // Registration only. Answer with a normal (unused) verdict so the hook's
            // existing reply validation passes and no second protocol fork is needed.
            if let Some(lp) = req_local_port(&req) {
                remember_pending(lp, req);
            }
            let resp = Resp { magic: MAGIC, action: 0, ..Default::default() };
            let b = {
                std::slice::from_raw_parts(&resp as *const Resp as *const u8, std::mem::size_of::<Resp>())
            };
            let mut put = 0u32;
            WriteFile(pipe, b.as_ptr(), b.len() as u32, &mut put, std::ptr::null_mut());
            return;
        }
        if req.magic != MAGIC {
            return;
        }
        let resp = decide_for(&req, config, tcp_port, tcp_port_v6, udp_port, udp_port_v6, pool);
        let (host, port) = decision_host(&req, pool);
        let app = image_basename(req.pid).unwrap_or_else(|| format!("pid:{}", req.pid));
        monitor.log(
            "info",
            format!(
                "拦截 {app} → {host}:{port} {}→ {}",
                if req.proto == IPPROTO_UDP { "(UDP)" } else { "(TCP)" },
                if resp.action == ACTION_PROXY {
                    "代理"
                } else if resp.action == ACTION_BLOCK {
                    "阻止"
                } else {
                    "直连"
                },
            ),
        );
        let mut written = 0u32;
        WriteFile(
            pipe,
            &resp as *const Resp as *const u8,
            std::mem::size_of::<Resp>() as u32,
            &mut written,
            std::ptr::null_mut(),
        );
    }
}

fn pipe_server(
    config: Arc<RwLock<Config>>,
    tcp_port: u16,
    tcp_port_v6: u16,
    udp_port: u16,
    udp_port_v6: u16,
    monitor: Arc<Monitor>,
    pool: Arc<FakeIpPool>,
    active_pipe: Arc<AtomicIsize>,
    stop: Arc<AtomicBool>,
) {
    let name = wide(&pipe_name());
    while !stop.load(Ordering::SeqCst) {
        let pipe = unsafe {
            CreateNamedPipeW(name.as_ptr(), 0x0003, 0x0004 | 0x0002, 255, 512, 512, 0, std::ptr::null())
        };
        if pipe == INVALID_HANDLE_VALUE {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        active_pipe.store(pipe as isize, Ordering::SeqCst);
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } != 0;
        active_pipe.store(0, Ordering::SeqCst);
        if connected {
            let cfg = config.clone();
            let mon = monitor.clone();
            let pool = pool.clone();
            let raw = pipe as isize;
            std::thread::spawn(move || {
                let pipe = raw as HANDLE;
                let c = cfg.read().unwrap().clone();
                serve_pipe_one(pipe, &c, tcp_port, tcp_port_v6, udp_port, udp_port_v6, &mon, &pool);
                unsafe {
                    DisconnectNamedPipe(pipe);
                    CloseHandle(pipe);
                }
            });
        } else {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
        }
    }
}

fn dns_pipe_server(
    config: Arc<RwLock<Config>>,
    pool: Arc<FakeIpPool>,
    monitor: Arc<Monitor>,
    active: Arc<AtomicIsize>,
    stop: Arc<AtomicBool>,
) {
    let name = wide(&dns_pipe_name());
    while !stop.load(Ordering::SeqCst) {
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                0x0003, // PIPE_ACCESS_DUPLEX
                0x0004 | 0x0002, // MESSAGE mode in+out
                255,
                DNS_NAME_MAX as u32,
                4,
                0,
                std::ptr::null(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        active.store(pipe as isize, Ordering::SeqCst);
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } != 0;
        active.store(0, Ordering::SeqCst);
        if connected {
            let cfg = config.clone();
            let pool = pool.clone();
            let mon = monitor.clone();
            let raw = pipe as isize;
            std::thread::spawn(move || {
                let pipe = raw as HANDLE;
                // Request: [pid: u32 LE][hostname: null-padded utf8].
                // Reply:   [fake IPv4 octets] — 0.0.0.0 means "not virtualised,
                // the caller must resolve for real" (dns_mode=local / non-whitelisted).
                let mut buf = [0u8; DNS_NAME_MAX];
                let mut read = 0u32;
                let ok = unsafe {
                    ReadFile(pipe, buf.as_mut_ptr(), DNS_NAME_MAX as u32, &mut read, std::ptr::null_mut())
                };
                let reply = if ok != 0 && read > 4 {
                    let pid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let body = &buf[4..read as usize];
                    let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
                    let host = String::from_utf8_lossy(&body[..end]).to_ascii_lowercase();
                    let c = cfg.read().unwrap().clone();
                    let app = image_basename(pid);
                    let virt = dns::should_virtualize(
                        c.settings.dns_mode == crate::config::DnsMode::Proxy,
                        c.settings.app_whitelist_enabled,
                        is_whitelisted(&c, app.as_deref()),
                    );
                    if !host.is_empty() && virt {
                        let ip = pool.allocate(&host);
                        mon.log("info", format!("DNS-UDP fake IP: {host} = {ip}"));
                        ip.octets()
                    } else {
                        [0, 0, 0, 0]
                    }
                } else {
                    [0, 0, 0, 0]
                };
                let mut written = 0u32;
                unsafe {
                    WriteFile(pipe, reply.as_ptr(), 4, &mut written, std::ptr::null_mut());
                    DisconnectNamedPipe(pipe);
                    CloseHandle(pipe);
                }
            });
        } else {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
        }
    }
}

/// Turn an already-accepted local connection into a proxied tunnel to
/// `host:port`. Shared by the hook relay (which learns the target from the in-band
/// `Req` header) and the WFP callout ingress (which learns it from a `FlowRecord`),
/// so both front-ends get the same routing, logging and accounting.
pub(crate) fn relay_established(
    client: std::net::TcpStream,
    host: &str,
    port: u16,
    app: Option<String>,
    pid: Option<u32>,
    config: Arc<RwLock<Config>>,
    monitor: Arc<Monitor>,
    redirect_records: Option<&[u8]>,
    pool: Arc<FakeIpPool>,
) {
    let cfg = config.read().unwrap().clone();
    // (b) applies to BOTH transports: a DNS query is dialled to the configured
    // resolver even though the rules matched the resolver the app was told to use.
    let (dial_host, dial_port) = dns_dial_target(&cfg, host, port);
    match engine::connect_target_dialing(&cfg, app.as_deref(), host, port, &dial_host, dial_port) {
        Ok((upstream, decision)) => {
            // WFP road-map step 8: hand the redirect records to the outbound socket
            // so the stack relates this proxied connection back to the original one
            // (and no callout - ours or another product's - re-redirects it).
            if let Some(recs) = redirect_records {
                if !crate::wfp_ingress::apply_records(&upstream, recs) {
                    monitor.log("warn", "WFP: 无法在出口套接字上设置重定向记录".to_string());
                }
            }
            let rewrote = if dial_host != host || dial_port != port {
                format!(" (DNS → {dial_host}:{dial_port})")
            } else {
                String::new()
            };
            monitor.log(
                "info",
                format!(
                    "中继: 隧道已建立 → {host}:{port} via {}{rewrote}",
                    engine::server_label(&cfg, &decision)
                ),
            );
            let flow = monitor.open_flow(
                app.clone().unwrap_or_else(|| format!("pid:{}", pid.unwrap_or(0))),
                format!("{host}:{port}"),
                "TCP",
                engine::server_label(&cfg, &decision),
                engine::rule_label(&decision),
            );
            // A DNS conversation over TCP (truncated answers, large zones, some
            // resolvers always-TCP) is framed as [2-byte length][message]; observe the
            // answers without ever holding up the byte pipe.
            let dns_port = port == 53 || cfg.settings.dns.servers.iter().any(|s| s.port == port);
            if dns_port {
                let acc: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
                let p2 = pool.clone();
                let tap = |chunk: &[u8]| {
                    let mut buf = acc.lock().unwrap_or_else(|e| e.into_inner());
                    buf.extend_from_slice(chunk);
                    // A conversation that never forms a valid frame is not DNS; stop
                    // buffering rather than growing without bound.
                    if buf.len() > 66 * 1024 {
                        buf.clear();
                        return;
                    }
                    loop {
                        if buf.len() < 2 {
                            return;
                        }
                        let total = 2 + u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        if buf.len() < total {
                            return;
                        }
                        p2.observe_dns_response(&buf[2..total]);
                        buf.drain(..total);
                    }
                };
                let _ = engine::relay_counted_tap(client, upstream, Some(&monitor), Some(&flow), Some(&tap));
            } else {
                let _ = engine::relay_counted(client, upstream, Some(&monitor), Some(&flow));
            }
            monitor.close_flow(flow.id);
        }
        Err(e) => monitor.log("warn", format!("中继 {host}:{port} 失败: {e}")),
    }
}

/// Resolve a pid to an image name once (the same process asks many times per second).
fn app_of(cache: &Arc<Mutex<HashMap<u32, Option<String>>>>, pid: u32) -> Option<String> {
    let mut m = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(a) = m.get(&pid) {
        return a.clone();
    }
    let a = image_basename(pid);
    m.insert(pid, a.clone());
    a
}

fn relay_server(listener: TcpListener, config: Arc<RwLock<Config>>, monitor: Arc<Monitor>, pool: Arc<FakeIpPool>, stop: Arc<AtomicBool>) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    let appcache = Arc::new(Mutex::new(HashMap::<u32, Option<String>>::new()));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut client, _)) => {
                let _ = client.set_nonblocking(false);
                let config = config.clone();
                let monitor = monitor.clone();
                let appcache = appcache.clone();
                let pool = pool.clone();
                std::thread::spawn(move || {
                    // A WFP-redirected connection carries NO in-band header: the app's
                    // own bytes start immediately, and the original destination comes
                    // from the redirect context the callout attached to this socket.
                    if crate::wfp_ingress::enabled() {
                        let (ctx, recs) = crate::wfp_ingress::query_redirect(&client);
                        if let Some(r) = ctx {
                            if let Some(remote) = r.remote() {
                                let host = dns::effective_host(&pool, &remote.ip().to_string());
                                let app = image_basename(r.pid);
                                relay_established(
                                    client,
                                    &host,
                                    remote.port(),
                                    app,
                                    Some(r.pid),
                                    config,
                                    monitor,
                                    recs.as_deref(),
                                    pool.clone(),
                                );
                                return;
                            }
                        }
                    }
                    // Out-of-band first: the hook binds before it connects precisely so
                    // we can identify the flow without any in-band bytes.
                    let by_port = client
                        .peer_addr()
                        .ok()
                        .and_then(|a| take_pending(a.port()))
                        .map(|req| {
                            let (host, port) = decision_host(&req, &pool);
                            (req, host, port)
                        });
                    if let Some((req, host, port)) = by_port {
                        let app = app_of(&appcache, req.pid);
                        relay_established(client, &host, port, app, Some(req.pid), config, monitor, None, pool.clone());
                        return;
                    }
                    let mut hdr = [0u8; std::mem::size_of::<Req>()];
                    if let Err(e) = client.read_exact(&mut hdr) {
                        monitor.log("warn", format!("中继: 读取钩子请求头失败（连接被提前关闭？）: {e}"));
                        return;
                    }
                    let req: Req = unsafe { std::ptr::read_unaligned(hdr.as_ptr() as *const Req) };
                    if req.magic != MAGIC {
                        monitor.log("warn", format!("中继: 请求头 magic 不匹配 (0x{:x})，钩子/引擎版本可能不一致", req.magic));
                        return;
                    }
                    let (host, port) = decision_host(&req, &pool);
                    let app = app_of(&appcache, req.pid);
                    relay_established(client, &host, port, app, Some(req.pid), config, monitor, None, pool.clone());
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The resolver a DNS query is actually dialled at. With `dns_mode` delegating
/// resolution, a query on port 53 goes to the FIRST configured resolver that is an
/// IP literal — the proxy reaches it, so the app never touches the OS resolver, and
/// the reply still gets back to the app (which matches on the DNS query id).
///
/// Skipped, keeping the original destination, when: the destination is a loopback
/// stub resolver (dnscrypt/systemd-resolved/dnscw: the stub's OWN upstream is what
/// should be proxied — rewriting the local hop would dial a public resolver
/// unproxied); no resolver is configured; or the configured resolver is a hostname,
/// which would recurse into the resolver we are trying to reach.
pub(crate) fn dns_effective_target(
    dns: &crate::config::DnsSettings,
    dst_ip: std::net::IpAddr,
    port: u16,
) -> (std::net::IpAddr, u16) {
    if port == 53 && !dst_ip.is_loopback() {
        if let Some(s) = dns.servers.iter().find(|s| !s.server.trim().is_empty()) {
            if let Ok(ip) = s.server.trim().parse::<std::net::IpAddr>() {
                return (ip, s.port);
            }
        }
    }
    (dst_ip, port)
}

/// The address a TCP connection to `host:port` should actually be dialled at, after
/// the resolver policy — so DNS over TCP behaves like DNS over UDP instead of being
/// tunnelled to whatever resolver the app was configured with. Only an IP-literal
/// destination qualifies: a hostname on port 53 is an application endpoint.
pub(crate) fn dns_dial_target(config: &Config, host: &str, port: u16) -> (String, u16) {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let (d_ip, d_port) = dns_effective_target(&config.settings.dns, ip, port);
        if d_ip != ip || d_port != port {
            return (d_ip.to_string(), d_port);
        }
    }
    (host.to_string(), port)
}

/// UDP relay. The app's connected UDP socket was redirected here; its FIRST
/// datagram is a 32-byte Req header (magic) naming the true target. We open a
/// SOCKS5 UDP ASSOCIATE to the chain's egress and tunnel each subsequent
/// datagram through it; replies are unwrapped and sent back to the app socket.

fn udp_relay(relay: Arc<UdpSocket>, config: Arc<RwLock<Config>>, monitor: Arc<Monitor>, pool: Arc<FakeIpPool>, stop: Arc<AtomicBool>) {
    let _ = relay.set_read_timeout(Some(Duration::from_millis(80)));
    // app src -> (true target, upstream assoc socket, assoc relay ep, conn row,
    //             shared abort flag, last-activity)
    type Flow = (
        SocketAddr,
        Arc<UdpSocket>,
        SocketAddr,
        Arc<crate::monitor::ConnInfo>,
        Arc<AtomicBool>,
        std::time::Instant,
        // qtype this flow's resolver traffic must not see an answer for, decided when
        // the flow was opened (that is the only moment the egress proxy is known).
        Option<u16>,
    );
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let idle_limit = Duration::from_secs(120);
    let mut last_sweep = std::time::Instant::now();
    while !stop.load(Ordering::SeqCst) {
        // Periodically reap idle flows so a long-lived engine does not accumulate
        // one dead associate socket + reader thread per churned UDP "connection"
        // (games open/close UDP constantly). Removing the map entry drops our last
        // Arc<UdpSocket> ref -> the assoc socket closes -> the reader's recv errors
        // -> the reader thread exits; `flag` also lets it stop within its 500ms poll.
        if last_sweep.elapsed() >= Duration::from_secs(10) {
            last_sweep = std::time::Instant::now();
            let stale: Vec<SocketAddr> = flows
                .iter()
                .filter(|(_, f)| f.5.elapsed() >= idle_limit)
                .map(|(k, _)| *k)
                .collect();
            for k in stale {
                if let Some(f) = flows.get(&k) {
                    f.4.store(true, Ordering::SeqCst);
                }
                flows.remove(&k);
            }
        }
        let (n, src) = match relay.recv_from(&mut buf) {
            Ok(v) => v,
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        };
        let data = &buf[..n];

        // Is THIS datagram a flow declaration? It has to be answered before the existing
        // flow is consulted: the WFP route keeps one socket per token port, so when the
        // driver recycles that token the next application's very first packet arrives from
        // the SAME source address as the previous flow's payload. Treating it as payload
        // would tunnel app B's datagrams to app A's destination — a misrouting, not a
        // mere malfunction. (Found by the recycled-token scenario in
        // tests/transparent_windows.rs, which failed exactly this way.)
        let declares_flow = n >= std::mem::size_of::<Req>() && {
            let r: Req = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Req) };
            r.magic == MAGIC && r.proto == IPPROTO_UDP
        };
        if let Some(f) = flows.get_mut(&src) {
            if f.4.load(Ordering::SeqCst) {
                // being reaped; ignore stragglers
            } else if !declares_flow {
                // Address-family trimming. On a chain with no IPv6 egress a AAAA answer is
                // a destination the app cannot reach, and the app only finds out after a
                // failed connect — which is what "some sites are slow since I enabled the
                // transparent engine" means. Answering the query with a valid empty answer
                // makes it fall back to IPv4 immediately, and it is strictly local: the
                // upstream resolver never sees a suppressed query, and nothing else is
                // rewritten. Anything that is not a well-formed single-question query is
                // forwarded untouched.
                if let Some(sup) = f.6 {
                    if crate::dns::query_qtype(data) == Some(sup) {
                        if let Some(ans) = crate::dns::empty_answer_for(data) {
                            let _ = relay.send_to(&ans, src);
                            monitor.log(
                                "info",
                                format!(
                                    "DNS 族裁剪: 就地空答案回给应用（此链路无 {} 出口），应用将改用另一族",
                                    if sup == 28 { "IPv6" } else { "IPv4" },
                                ),
                            );
                            continue;
                        }
                    }
                }
                let framed = socks5::udp_frame(&f.0, data);
                let _ = f.1.send_to(&framed, f.2);
                f.3.sent.fetch_add(n as u64, Ordering::Relaxed);
                f.5 = std::time::Instant::now();
                continue;
            } else {
                // retire the previous flow on this source before the replacement is
                // inserted: signalling abort closes its associate socket, which ends its
                // reader thread. Replies already in flight are not attributable to the
                // old app any more, which is the residual (documented) race of reusing a
                // token port rather than a bug in the routing of new packets.
                f.4.store(true, Ordering::SeqCst);
            }
        }
        // new flow: first datagram must be the Req header
        if !declares_flow {
            continue;
        }
        let req: Req = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Req) };
        let (host, port) = decision_host(&req, &pool);
        let app = image_basename(req.pid);
        let cfg = config.read().unwrap().clone();
        let decision = decide_route(&cfg, app.as_deref(), &host, port, req.proto);
        let chain_egress = match &decision {
            Decision::Proxy { chain, .. } => config_chain_socks5(&cfg, *chain),
            Decision::Direct { .. } => None,
            Decision::Block { .. } => None,
        };
        let Some(proxy) = chain_egress else {
            monitor.log("warn", format!("UDP {host}:{port} 无 SOCKS5 出口，丢弃（需 SOCKS5 出口代理）"));
            continue;
        };
        match open_udp_associate(&proxy.host, proxy.port, proxy.username.as_deref(), proxy.password.as_deref(), proxy.timeout_secs) {
            Ok((assoc, assoc_relay)) => {
                let assoc = Arc::new(assoc);
                // Build the true destination from the header. IPv6 datagrams ride
                // inside the SOCKS5 UDP frame (ATYP 0x04) to the IPv4 egress proxy,
                // which does the remote v6 resolution — so the associate socket stays v4.
                let dst_ip = if req.family == AF_INET6 {
                    IpAddr::from(req.addr)
                } else {
                    IpAddr::from([req.addr[0], req.addr[1], req.addr[2], req.addr[3]])
                };
                let target: SocketAddr = dns_effective_target(&cfg.settings.dns, dst_ip, port).into();
                if target.ip() != dst_ip || target.port() != port {
                    // The user asked for their queries to be dialled at THEIR resolvers,
                    // not the OS's. That rewrite is invisible in a packet capture (the
                    // frame just carries a different address), so it is said out loud
                    // here: without this line a mis-set resolver list looks identical to
                    // working DNS-over-proxy.
                    monitor.log(
                        "info",
                        format!("DNS 解析器改写: {host}:{port} → {target} (经代理)"),
                    );
                }
                let flow = monitor.open_flow(
                    app.unwrap_or_else(|| format!("pid:{}", req.pid)),
                    format!("{host}:{port}"),
                    "UDP",
                    format!("{}:{}", proxy.host, proxy.port),
                    // the TCP path labels this with the rule that actually decided it;
                    // UDP used a literal "rule", which read as "my rules are not being
                    // saved" when they were — the display was the bug, not the profile.
                    engine::rule_label(&decision),
                );
                let flag = Arc::new(AtomicBool::new(false));
                // Decided ONCE, here, where the proxy this flow actually uses is known:
                // re-deriving it per datagram would need another config read and could pick a
                // different chain than the one the flow was opened on.
                let fam_suppress = if port == 53 {
                    effective_family_policy(&cfg, &proxy.host).suppressed_qtype()
                } else {
                    None
                };
                flows.insert(
                    src,
                    (
                        target,
                        assoc.clone(),
                        assoc_relay,
                        flow.clone(),
                        flag.clone(),
                        std::time::Instant::now(),
                        fam_suppress,
                    ),
                );
                // Passive DNS observation: when this flow carries resolver traffic, the
                // replies name the addresses the app is about to connect to — which is
                // how a hostname rule can match a connect that arrives as a bare IP
                // (the normal case for the WFP route, where no getaddrinfo hook exists).
                let snoop_dns = port == 53
                    || cfg.settings.dns.servers.iter().any(|s| s.port == port);
                // reader thread: upstream replies -> unwrap -> back to app `src`
                let app_src = src;
                let relay_out = relay.clone();
                let mon = monitor.clone();
                let pool = pool.clone();
                std::thread::spawn(move || {
                    let mut b = vec![0u8; 64 * 1024];
                    let _ = assoc.set_read_timeout(Some(Duration::from_millis(500)));
                    loop {
                        if flag.load(Ordering::SeqCst) {
                            break; // reaped as idle
                        }
                        match assoc.recv_from(&mut b) {
                            Ok((m, _from)) => {
                                if let Some((_origin, payload)) = socks5::parse_udp_frame(&b[..m]) {
                                    if snoop_dns {
                                        pool.observe_dns_response(payload);
                                    }
                                    let _ = relay_out.send_to(payload, app_src);
                                    flow.recv.fetch_add(m as u64, Ordering::Relaxed);
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                // keep waiting (bounded by the abort flag above)
                            }
                            Err(_) => break, // socket closed (reaped) or hard error
                        }
                    }
                    // association torn down → mark the Connection-List row closed
                    mon.close_flow(flow.id);
                });
                monitor.log("info", format!("UDP 关联建立：{host}:{port} via {}:{}", proxy.host, proxy.port));
            }
            Err(e) => monitor.log("warn", format!("UDP 关联失败 {host}:{port}: {e}")),
        }
    }
}

fn config_chain_socks5(cfg: &Config, chain: u32) -> Option<crate::config::ProxyServer> {
    let last = cfg.chain_by_id(chain)?.proxies.last().copied()?;
    let p = cfg.proxy_available(last)?;
    if p.kind == ProxyKind::Socks5 {
        Some(p.clone())
    } else {
        None
    }
}

/// Dial an upstream SOCKS5 proxy and negotiate UDP ASSOCIATE; returns the local
/// socket to send framed datagrams on + the proxy's relay endpoint.
fn open_udp_associate(host: &str, port: u16, user: Option<&str>, pass: Option<&str>, timeout_secs: u64) -> std::io::Result<(UdpSocket, SocketAddr)> {
    let proxy = crate::config::ProxyServer {
        id: 0,
        name: "udp-egress".into(),
        kind: ProxyKind::Socks5,
        host: host.into(),
        port,
        username: user.map(Into::into),
        password: pass.map(Into::into),
        timeout_secs,
    };
    // Bounded + IPv6-capable dial (engine::dial_proxy), NOT a bare blocking
    // connect — an unreachable SOCKS5 egress would otherwise hang ~21s per UDP
    // flow, and an IPv6 proxy host needs the address-family handling.
    let mut ctl = engine::dial_proxy(host, port, timeout_secs)?;
    // Bound the ASSOCIATE handshake too (a stalling proxy shouldn't hang forever).
    let ht = Duration::from_secs(timeout_secs.max(1));
    let _ = ctl.set_read_timeout(Some(ht));
    let _ = ctl.set_write_timeout(Some(ht));
    let relay = socks5::udp_associate(&mut ctl, &proxy)?;
    let data = UdpSocket::bind("0.0.0.0:0")?;
    // Leak the control connection for the lifetime of the process-scope flow.
    std::mem::forget(ctl);
    Ok((data, relay))
}

/// The proxy/relay/decision servers WITHOUT installing the system-wide hook.
pub struct Servers {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub udp_port_v6: u16,
    /// The fake-IP pool the decision path reverse-maps through (shared so a DNS
    /// producer can later populate it — fnd_10).
    pub dns_pool: Arc<FakeIpPool>,
    stop: Arc<AtomicBool>,
    active_pipe: Arc<AtomicIsize>,
    active_dns: Arc<AtomicIsize>,
}

impl Servers {
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Both accept loops are parked inside `ConnectNamedPipe`, so nudge each one to
        // finish that call. Without this the loops never observe `stop`, and closing
        // their handles instead would block until a client arrived - which is the hang
        // that kept trans-proxier resident after its window was closed.
        interrupt_pipe_wait(&pipe_name());
        interrupt_pipe_wait(&dns_pipe_name());
        // One turn of the loops is enough (they re-test `stop` right after the
        // transaction). Bounded, because a stalled handler must never be able to make
        // process exit depend on it.
        let deadline = std::time::Instant::now() + Duration::from_millis(400);
        while std::time::Instant::now() < deadline {
            if self.pending_pipes() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Pipe instances currently mid-accept. Used to know the loops actually drained.
    pub fn pending_pipes(&self) -> usize {
        [&self.active_pipe, &self.active_dns]
            .iter()
            .filter(|h| h.load(Ordering::SeqCst) != 0)
            .count()
    }
}

/// Wake a thread parked in a synchronous `ConnectNamedPipe` without touching its
/// handle.
///
/// `CloseHandle` from another thread does NOT cancel a pending operation: it waits for
/// it to complete, and completing it needs a client. That is why stopping the engine
/// used to hang forever inside `Engine::drop` (and, had a client arrived, the handler
/// thread would then have worked on a handle somebody else closed). Connecting to the
/// pipe ourselves ends the wait on the loop's own terms: `serve_pipe_one` reads nothing
/// usable, returns immediately, the loop re-tests the stop flag and exits.
fn interrupt_pipe_wait(name: &str) {
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16, access: u32, share: u32, sa: *const c_void,
            disp: u32, flags: u32, template: *mut c_void,
        ) -> *mut c_void;
    }
    const GENERIC_READ_WRITE: u32 = 0x8000_0000 | 0x4000_0000; // GENERIC_READ | GENERIC_WRITE
    const OPEN_EXISTING: u32 = 3;
    let w = wide(name);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            GENERIC_READ_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if h != INVALID_HANDLE_VALUE && !h.is_null() {
        unsafe { CloseHandle(h) };
    }
}

/// Start the decision pipe + TCP relay + UDP relay (loopback). Testable without
/// touching other processes.
pub fn spawn_servers(config: Arc<RwLock<Config>>, monitor: Arc<Monitor>) -> std::io::Result<Servers> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let tcp_port = listener.local_addr()?.port();
    // Best-effort IPv6 relay: a dedicated [::1] listener so AF_INET6 (V6ONLY) app
    // sockets can reach it. If IPv6 loopback is unavailable, tcp_port_v6=0 and v6
    // connects fall back to direct (never an error).
    let listener_v6 = TcpListener::bind("[::1]:0").ok();
    let tcp_port_v6 = listener_v6.as_ref().and_then(|l| l.local_addr().ok()).map(|a| a.port()).unwrap_or(0);
    // v4 UDP relay (serves v4 clients + unconnected v6 via v4 shadow sockets).
    let udp = UdpSocket::bind("127.0.0.1:0")?;
    let udp_port = udp.local_addr()?.port();
    let udp = Arc::new(udp);
    udp.set_nonblocking(true)?;
    // Separate IPv6 UDP relay so CONNECTED v6 (V6ONLY) app sockets can dial
    // [::1]. If IPv6 loopback is unavailable, udp_port_v6=0 and connected v6 UDP
    // falls back to direct.
    let udp_v6 = UdpSocket::bind("[::1]:0").ok().map(|s| {
        let _ = s.set_nonblocking(true);
        s
    });
    let udp_port_v6 = udp_v6.as_ref().and_then(|s| s.local_addr().ok()).map(|a| a.port()).unwrap_or(0);
    let udp_v6 = udp_v6.map(Arc::new);

    let stop = Arc::new(AtomicBool::new(false));
    let active_pipe = Arc::new(AtomicIsize::new(0));
    let active_dns = Arc::new(AtomicIsize::new(0));
    let dns_pool = Arc::new(FakeIpPool::new());

    {
        let (c, m, ap, s, dp) = (config.clone(), monitor.clone(), active_pipe.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || pipe_server(c, tcp_port, tcp_port_v6, udp_port, udp_port_v6, m, dp, ap, s));
    }
    {
        let (c, m, s, dp) = (config.clone(), monitor.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || relay_server(listener, c, m, dp, s));
    }
    if let Some(l6) = listener_v6 {
        let (c, m, s, dp) = (config.clone(), monitor.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || relay_server(l6, c, m, dp, s));
    }
    {
        let (c, m, s, dp) = (config.clone(), monitor.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || udp_relay(udp, c, m, dp, s));
    }
    if let Some(u6) = udp_v6 {
        let (c, m, s, dp) = (config.clone(), monitor.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || udp_relay(u6, c, m, dp, s));
    }
    {
        let (c, m, ad, s, dp) = (config.clone(), monitor.clone(), active_dns.clone(), stop.clone(), dns_pool.clone());
        std::thread::spawn(move || dns_pipe_server(c, dp, m, ad, s));
    }
    // Only armed when a WFP callout driver is expected (see `wfp_ingress`); with it
    // off the engine behaves exactly as a build without the module.
    if crate::wfp_ingress::enabled() {
        crate::wfp_ingress::spawn(config.clone(), monitor.clone(), dns_pool.clone(), stop.clone(), udp_port)?;
    }
    Ok(Servers { tcp_port, udp_port, udp_port_v6, dns_pool, stop, active_pipe, active_dns })
}

pub struct Engine {
    servers: Servers,
    mutex: isize,
    #[allow(dead_code)] // kept for diagnostics; teardown uses the DLL's KillFilter
    hhook: isize,
    driver_module: isize,
    /// Control block: the mapping handle and its writable view (the view is how the
    /// teardown counter reaches processes we hold no handle to).
    ctl: isize,
    ctl_view: usize,
    /// Targeted per-pid injection, the default. `None` only when the operator
    /// explicitly asks for the legacy global message hook.
    watcher: Option<crate::inject::Watcher>,
}

type InitFilter3Fn = extern "system" fn(HMODULE) -> *mut c_void;
type KillFilterFn = extern "system" fn();

impl Engine {
    pub fn start(config: Arc<RwLock<Config>>, monitor: Arc<Monitor>, driver_path: &str) -> Result<Engine, String> {
        // Mark THIS process as the engine so the driver we load does not redirect
        // our own sockets (prevents a relay loop).
        unsafe {
            SetEnvironmentVariableW(wide("TPROX_ENGINE").as_ptr(), wide("1").as_ptr());
        }
        let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, wide(&engine_mutex_name()).as_ptr()) };
        if mutex.is_null() || mutex == INVALID_HANDLE_VALUE {
            return Err("cannot create engine mutex".into());
        }
        if unsafe { GetLastError() } == 183 {
            unsafe { CloseHandle(mutex) };
            return Err("另一个透明引擎实例已在运行（mutex 已存在）".into());
        }

        // Publish the control block BEFORE the hook exists: a process mapped in later
        // must never have to guess whether it may be patched.
        let apps = {
            let c = config.read().map_err(|e| format!("config: {e}"))?;
            ctl_apps(c.settings.app_whitelist_enabled, &c.settings.app_whitelist)
        };
        let (ctl, ctl_view) = match publish_ctl(&apps) {
            Ok(v) => v,
            Err(e) => {
                unsafe { CloseHandle(mutex) };
                return Err(e);
            }
        };

        // Injection happens in ANOTHER process, so a relative name like `tpdrv.dll`
        // would resolve against that app's working directory and fail. Resolve once.
        let dll_abs = std::path::Path::new(driver_path)
            .canonicalize()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| driver_path.to_string());
        let cfg_watch = config.clone();

        let servers = spawn_servers(config, monitor.clone()).map_err(|e| format!("spawn servers: {e}"))?;

        // Two install strategies, and the default is the narrow one.
        //
        // The legacy path (SetWindowsHookExW, dwThreadId=0) makes Windows map the DLL
        // into every message-pumping process: measured on a real desktop, 99 processes
        // carried it to serve a whitelist of a handful, and once several builds were
        // live the same ws2_32 function sat inline-detoured five deep in 65 of them -
        // that is what crashed nearly everything. Targeted injection only reaches the
        // programs the profile names, and it undoes itself on stop.
        let legacy = std::env::var_os("TPROXIER_GLOBAL_HOOK").is_some();
        let mut hhook = 0isize;
        let mut driver_module = 0isize;
        let mut watcher: Option<crate::inject::Watcher> = None;
        if !legacy && cfg_watch.read().map(|c| !c.settings.app_whitelist_enabled).unwrap_or(true) {
            release_ctl(ctl, ctl_view);
            servers.shutdown();
            unsafe { CloseHandle(mutex) };
            return Err("定向注入需要开启程序白名单：名单为空就等于不代理任何流量，而不注入全局钩子时也没有别的办法确定范围".into());
        }
        if legacy {
            let hmod = unsafe { LoadLibraryW(wide(driver_path).as_ptr()) };
            if hmod.is_null() {
                release_ctl(ctl, ctl_view);
                servers.shutdown();
                unsafe { CloseHandle(mutex) };
                return Err(format!("无法加载驱动 DLL: {driver_path}"));
            }
            let proc = unsafe { GetProcAddress(hmod, c"InitFilter3".as_ptr() as *const i8) };
            if proc.is_null() {
                release_ctl(ctl, ctl_view);
                servers.shutdown();
                unsafe { CloseHandle(mutex) };
                return Err("驱动 DLL 缺少 InitFilter3 导出".into());
            }
            let init: InitFilter3Fn = unsafe { std::mem::transmute(proc) };
            hhook = init(hmod) as isize;
            if hhook == 0 {
                release_ctl(ctl, ctl_view);
                let gle = unsafe { GetLastError() };
                servers.shutdown();
                unsafe { CloseHandle(mutex) };
                return Err(format!("装全局钩子失败 (GetLastError={gle})：183 表示另一个 tpdrv 已持有钩子，本版本拒绝叠加"));
            }
            driver_module = hmod as isize;
        } else {
            watcher = Some(crate::inject::Watcher::spawn(dll_abs, cfg_watch));
        }

        monitor.log(
            "info",
            if legacy {
                format!("透明引擎已启动（全局钩子模式，TCP中继 :{}，UDP :{}，hook=0x{hhook:x}）", servers.tcp_port, servers.udp_port)
            } else {
                format!("透明引擎已启动（定向注入：只进白名单程序，TCP中继 :{}，UDP :{}）", servers.tcp_port, servers.udp_port)
            },
        );
        Ok(Engine {
            servers,
            mutex: mutex as isize,
            hhook,
            driver_module,
            ctl: ctl as isize,
            ctl_view,
            watcher,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Walk into each process we injected and take our patches off, while the
        // engine is still fully alive: the remote routine answers over our pipe, and
        // the relays it may still be talking to vanish once the servers shut down.
        if let Some(w) = self.watcher.as_mut() {
            w.shutdown();
        }
        // Ask every hooked process to put ws2_32 back BEFORE the hook is removed: the
        // message-hook thunk is the only code of ours still running inside those
        // processes, and unhooting first would leave them patched until they restart.
        // They poll the counter at most once a second, hence the brief wait.
        if self.ctl_view != 0 {
            bump_teardown(self.ctl_view);
            // The 1.5 s wait exists only for the legacy global-hook path, where a
            // broadcast is the sole way to reach the patched processes. In targeted mode
            // we already walked into each process and restored it above, so sleeping here
            // just kept the process resident after the window closed.
            if self.driver_module != 0 {
                std::thread::sleep(Duration::from_millis(1500));
            }
        }
        // Kill the engine mutex next: hooked apps gate on it (engine_alive) and
        // fall back to direct the instant it is gone, without touching the pipe.
        if self.mutex != 0 && self.mutex != -1 {
            unsafe {
                CloseHandle(self.mutex as HANDLE);
            }
            self.mutex = 0;
        }
        self.servers.shutdown();
        // Last, and potentially slow: unhooking a global message hook blocks until
        // every loading process acknowledges removal. Callers run this drop on a
        // dedicated thread (see gui::serve_stop) so a stall can never freeze the UI.
        if self.driver_module != 0 {
            let kill = unsafe { GetProcAddress(self.driver_module as HMODULE, c"KillFilter".as_ptr() as *const i8) };
            if !kill.is_null() {
                let f: KillFilterFn = unsafe { std::mem::transmute(kill) };
                f();
            }
            // Release THIS process's (the engine's) reference so the file handle the
            // engine holds on tpdrv.dll is freed on Stop. The module is only unpinned
            // in the engine (DllMain pins just the hook-hosting processes), so this
            // FreeLibrary drops the engine's last ref and unmaps it here. Injected
            // foreign apps keep their own pinned copy until they exit — unloading a
            // DLL another process may still be executing is not safe to force.
            unsafe {
                unsafe extern "system" {
                    fn FreeLibrary(hlibmodule: HMODULE) -> BOOL;
                }
                FreeLibrary(self.driver_module as HMODULE);
            }
            self.driver_module = 0;
        }
        // The control block goes last and unconditionally: in targeted mode no driver
        // module is loaded here at all, so putting this inside the driver_module branch
        // would mean every engine start leaked two handles and left the name reserved —
        // the next start would then read a stale whitelist instead of writing its own.
        release_ctl(self.ctl as *mut c_void, self.ctl_view);
        self.ctl = 0;
        self.ctl_view = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_v4(ip: [u8; 4], port: u16) -> Req {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&ip);
        Req { magic: MAGIC, pid: 1, family: 2, port_be: port.to_be(), addr: a, proto: 6, _pad: [0; 3] }
    }
    fn req_v6(addr: [u8; 16], port: u16) -> Req {
        Req { magic: MAGIC, pid: 1, family: AF_INET6, port_be: port.to_be(), addr, proto: 6, _pad: [0; 3] }
    }

    #[test]
    fn target_of_ipv4() {
        assert_eq!(target_of(&req_v4([93, 184, 216, 34], 443)), ("93.184.216.34".to_string(), 443));
    }

    #[test]
    fn target_of_ipv6_global() {
        // 2001:db8::1
        let mut addr = [0u8; 16];
        addr[0] = 0x20; addr[1] = 0x01; addr[2] = 0x0d; addr[3] = 0xb8; addr[15] = 0x01;
        let (host, port) = target_of(&req_v6(addr, 8080));
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn target_of_ipv4_mapped_renders_as_v4_for_exclusion() {
        // ::ffff:127.0.0.1 -> MUST render "127.0.0.1" so the relay hop matches the
        // loopback exclusion (prevents an app re-connecting to the relay forever).
        let mut addr = [0u8; 16];
        addr[10] = 0xff; addr[11] = 0xff; addr[12] = 127; addr[15] = 1;
        assert_eq!(target_of(&req_v6(addr, 9050)).0, "127.0.0.1");
    }

    #[test]
    fn target_of_ipv6_loopback() {
        let mut addr = [0u8; 16];
        addr[15] = 1; // ::1
        assert_eq!(target_of(&req_v6(addr, 443)).0, "::1");
    }
}

#[cfg(test)]
mod udp_block_tests {
    use super::*;
    use crate::config::{Chain, ProxyServer, Rule, RuleAction, RuleProtocol};

    fn cfg(kind: ProxyKind, block_udp: bool, ip_leak: bool) -> Config {
        let mut c = Config::default();
        c.settings.block_udp_if_matched = block_udp;
        c.settings.ip_leak_prevention = ip_leak;
        c.proxies.push(ProxyServer {
            id: 1, name: "p".into(), kind, host: "127.0.0.1".into(),
            port: 1080, username: None, password: None, timeout_secs: 5,
        });
        c.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
        c.rules.push(Rule {
            id: 1, name: "all".into(), enabled: true, priority: 10,
            app: None, host: Some("*".into()), port: None,
            protocol: RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        });
        c
    }

    fn udp_req() -> Req {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[93, 184, 216, 34]); // not loopback, not fake-ip
        Req { magic: MAGIC, pid: 1, family: 2, port_be: 53u16.to_be(), addr: a, proto: IPPROTO_UDP, _pad: [0; 3] }
    }

    fn act(c: &Config) -> u32 {
        decide_for(&udp_req(), c, 1000, 1001, 1002, 1003, &FakeIpPool::new()).action
    }

    #[test]
    fn block_udp_if_matched_now_blocks() {
        assert_eq!(act(&cfg(ProxyKind::Socks5, true, false)), ACTION_BLOCK);
    }

    #[test]
    fn non_socks5_egress_blocks_when_ip_leak_prevention_on() {
        assert_eq!(act(&cfg(ProxyKind::Http, false, true)), ACTION_BLOCK);
    }

    #[test]
    fn non_socks5_egress_goes_direct_when_prevention_off_inverse() {
        assert_eq!(act(&cfg(ProxyKind::Socks4, false, false)), ACTION_DIRECT);
    }

    #[test]
    fn socks5_egress_still_proxies_inverse() {
        assert_eq!(act(&cfg(ProxyKind::Socks5, false, true)), ACTION_PROXY);
    }
}

#[cfg(test)]
mod disabled_proxy_tests {
    use super::*;
    use crate::config::{Chain, ProxyServer, Rule, RuleAction, RuleProtocol};

    fn cfg(kind: ProxyKind) -> Config {
        let mut c = Config::default();
        c.settings.ip_leak_prevention = true;
        c.proxies.push(ProxyServer {
            id: 1, name: "p".into(), kind, host: "127.0.0.1".into(),
            port: 1080, username: None, password: None, timeout_secs: 5,
        });
        c.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
        c.rules.push(Rule {
            id: 1, name: "all".into(), enabled: true, priority: 10,
            app: None, host: Some("*".into()), port: None,
            protocol: RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        });
        c
    }
    fn udp_req() -> Req {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[93, 184, 216, 34]);
        Req { magic: MAGIC, pid: 1, family: 2, port_be: 53u16.to_be(), addr: a, proto: IPPROTO_UDP, _pad: [0; 3] }
    }

    #[test]
    fn proxy_available_skips_disabled_but_proxy_by_id_still_lists() {
        let mut c = cfg(ProxyKind::Socks5);
        assert!(c.proxy_available(1).is_some(), "enabled by default");
        assert!(c.proxy_by_id(1).is_some());
        c.settings.disabled_proxies = vec![1];
        assert!(c.proxy_available(1).is_none(), "deactivated -> unavailable");
        assert!(c.proxy_by_id(1).is_some(), "still listed for the editor");
    }

    #[test]
    fn disabled_socks5_egress_blocks_udp_under_leak_prevention() {
        let mut c = cfg(ProxyKind::Socks5);
        assert_eq!(decide_for(&udp_req(), &c, 1000, 1001, 1002, 1003, &FakeIpPool::new()).action, ACTION_PROXY);
        c.settings.disabled_proxies = vec![1];
        // egress now unavailable -> not SOCKS5 -> blocked (prevention on), never leaked
        assert_eq!(decide_for(&udp_req(), &c, 1000, 1001, 1002, 1003, &FakeIpPool::new()).action, ACTION_BLOCK);
    }
}

#[cfg(all(test, windows))]
mod running_apps_tests {
    use super::*;
    #[test]
    fn running_app_names_sorted_and_unique() {
        let v = running_app_names();
        // BTreeSet-backed: strictly increasing => sorted AND de-duplicated.
        for w in v.windows(2) {
            assert!(w[0] < w[1], "must be sorted & unique, got {:?} vs {:?}", w[0], w[1]);
        }
    }
}

#[cfg(test)]
mod app_category_tests {
    use super::app_category;
    #[test]
    fn groups_apps_services_unknown() {
        assert_eq!(app_category("firefox.exe"), "程序");
        assert_eq!(app_category("chrome.exe"), "程序");
        assert_eq!(app_category("svchost.exe"), "服务");
        assert_eq!(app_category("SomeThingSvc.exe"), "服务");
        assert_eq!(app_category("Memory Compression"), "未知");
        assert_eq!(app_category("System"), "未知");
        assert_eq!(app_category("   "), "未知");
    }
}

#[cfg(test)]
mod dns_redirect_tests {
    use super::{decision_host, dns_dial_target, dns_effective_target, req_from_flow, MAGIC, Req};

    #[test]
    fn tcp_dns_dial_target_follows_the_resolver_policy() {
        let d = DnsSettings {
            servers: vec![DnsServer {
                protocol: DnsProto::Udp,
                server: "1.1.1.1".into(),
                port: 53,
            }],
        };
        let mut c = crate::config::Config::default();
        c.settings.dns = d.clone();
        // an IP resolver on :53 is redirected to the configured one
        assert_eq!(dns_dial_target(&c, "192.168.1.1", 53), ("1.1.1.1".to_string(), 53));
        // a hostname on :53 is an app endpoint, not a resolver
        assert_eq!(dns_dial_target(&c, "dns.example.com", 53), ("dns.example.com".to_string(), 53));
        // loopback stub and non-DNS ports are untouched
        assert_eq!(dns_dial_target(&c, "127.0.0.53", 53), ("127.0.0.53".to_string(), 53));
        assert_eq!(dns_dial_target(&c, "93.184.216.34", 443), ("93.184.216.34".to_string(), 443));
        // IPv6 literal survives the round trip
        assert_eq!(dns_dial_target(&c, "2001:db8::1", 53), ("1.1.1.1".to_string(), 53));
    }

    /// The WFP ingress rebuilds the hook's in-band header from a flow record
    /// (`req_from_flow`) so one relay serves both front-ends. If the two encodings
    /// ever disagree about port byte order or address packing, the WFP route and the
    /// hook route would proxy DIFFERENT destinations for the same app — silently. This
    /// pins them to the same bytes.
    #[test]
    fn a_wfp_record_reproduces_the_hook_header_byte_for_byte() {
        use crate::wfp_classify::{FlowRecord, VERDICT_REDIRECT};

        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[15] = 0x05;

        for (family, addr, port) in [(2u16, {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&[198, 51, 100, 77]);
            a
        }, 53u16), (23, v6, 443u16)] {
            // exactly what tpdrv stores in Req.port_be: the raw sin_port octets read
            // as a native u16, i.e. host.to_be()
            let req = Req {
                magic: MAGIC,
                pid: 4242,
                family,
                port_be: port.to_be(),
                addr,
                proto: 17,
                _pad: [0; 3],
            };
            let rec = FlowRecord {
                family: req.family,
                port_be: req.port_be,
                addr: req.addr,
                pid: req.pid,
                chain: 0,
                verdict: VERDICT_REDIRECT,
                proto: req.proto,
                flow_id: 0,
                local_addr: [0; 16],
                local_port_be: 0,
                token_port: 12000,
            };
            let rebuilt = req_from_flow(&rec);

            let as_bytes = |r: &Req| -> [u8; std::mem::size_of::<Req>()] {
                unsafe { std::ptr::read_unaligned(r as *const Req as *const [u8; std::mem::size_of::<Req>()]) }
            };
            assert_eq!(
                as_bytes(&rebuilt),
                as_bytes(&req),
                "family {family}: the two wire formats must agree byte for byte"
            );
            // and both must name the same destination the relay will dial
            let pool = crate::dns::FakeIpPool::new();
            let (host, p1) = decision_host(&rebuilt, &pool);
            let (_, p2) = decision_host(&req, &pool);
            assert_eq!(p1, port, "port survives the record round trip (family {family})");
            assert_eq!(p2, port);
            assert_eq!(host, rec.remote().unwrap().ip().to_string());
        }
    }

    #[test]
    fn an_ipv6_configured_resolver_is_dialled_as_an_ipv6_target() {
        // Item (b) must hold for a v6 resolver too: the rewrite yields the v6 literal
        // and the SOCKS5 layer then frames it as ATYP 0x04 (asserted in socks5 tests).
        let mut c = crate::config::Config::default();
        c.settings.dns.servers = vec![DnsServer {
            protocol: DnsProto::Udp,
            server: "2606:4700:4700::1111".into(),
            port: 53,
        }];
        assert_eq!(
            dns_dial_target(&c, "192.168.1.1", 53),
            ("2606:4700:4700::1111".to_string(), 53)
        );
        // and a v6 app resolver is rewritten the same way
        assert_eq!(
            dns_dial_target(&c, "fd00::53", 53),
            ("2606:4700:4700::1111".to_string(), 53)
        );
        // an empty resolver list leaves the destination alone — but the query is
        // still proxied, so there is no path back to the OS resolver.
        let mut empty = crate::config::Config::default();
        empty.settings.dns.servers.clear();
        assert_eq!(dns_dial_target(&empty, "192.168.1.1", 53), ("192.168.1.1".to_string(), 53));
    }

    #[test]
    fn a_direct_verdict_still_dials_the_configured_resolver() {
        // The rule says Direct for the app's resolver, but the DNS policy pulls it
        // onto the chain; the dial target must still be OUR resolver, not the app's.
        let mut c = crate::config::Config::default();
        c.settings.dns.servers = vec![DnsServer {
            protocol: DnsProto::Udp,
            server: "10.0.0.2".into(),
            port: 5353,
        }];
        assert_eq!(dns_dial_target(&c, "192.168.1.1", 53), ("10.0.0.2".to_string(), 5353));
    }
    use crate::config::{DnsProto, DnsServer, DnsSettings};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn port53_redirects_to_first_ip_resolver() {
        let d = DnsSettings::default(); // 1.1.1.1, 8.8.8.8
        assert_eq!(dns_effective_target(&d, ip("192.168.1.1"), 53), (ip("1.1.1.1"), 53));
    }

    #[test]
    fn non_dns_port_untouched() {
        let d = DnsSettings::default();
        assert_eq!(dns_effective_target(&d, ip("8.8.4.4"), 443), (ip("8.8.4.4"), 443));
    }

    #[test]
    fn empty_resolver_list_leaves_target() {
        let d = DnsSettings { servers: vec![] };
        assert_eq!(dns_effective_target(&d, ip("127.0.0.53"), 53), (ip("127.0.0.53"), 53));
    }

    #[test]
    fn hostname_resolver_not_used_to_avoid_bootstrap_recursion() {
        let d = DnsSettings {
            servers: vec![DnsServer { protocol: DnsProto::Udp, server: "dns.example".into(), port: 53 }],
        };
        assert_eq!(dns_effective_target(&d, ip("1.2.3.4"), 53), (ip("1.2.3.4"), 53));
    }

    #[test]
    fn custom_port_honored() {
        let d = DnsSettings {
            servers: vec![DnsServer { protocol: DnsProto::Udp, server: "10.0.0.2".into(), port: 5353 }],
        };
        assert_eq!(dns_effective_target(&d, ip("1.1.1.1"), 53), (ip("10.0.0.2"), 5353));
    }
}

unsafe extern "system" {
    fn CreateFileMappingW(
        sec: *mut c_void, sa: *const c_void, protect: u32, max_hi: u32, max_lo: u32,
        name: *const u16,
    ) -> *mut c_void;
    fn MapViewOfFile(
        h: *mut c_void, access: u32, off_hi: u32, off_lo: u32, bytes: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(v: *const c_void) -> i32;
}

const CTL_PAGE_RW: u32 = 0x04;
const CTL_FILE_MAP_ALL: u32 = 0x000F_001F;

/// Create the control block and write `apps` into it. Returns (handle, view).
fn publish_ctl(apps: &str) -> Result<(*mut c_void, usize), String> {
    let name = wide(&ctl_name());
    let h = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            CTL_PAGE_RW,
            0,
            std::mem::size_of::<Ctl>() as u32,
            name.as_ptr(),
        )
    };
    if h.is_null() {
        return Err("cannot create the tpdrv control block".to_string());
    }
    let v = unsafe { MapViewOfFile(h, CTL_FILE_MAP_ALL, 0, 0, std::mem::size_of::<Ctl>()) };
    if v.is_null() {
        unsafe { CloseHandle(h) };
        return Err("cannot map the tpdrv control block".to_string());
    }
    write_ctl_apps(v as *mut Ctl, apps);
    Ok((h, v as usize))
}

fn write_ctl_apps(ctl: *mut Ctl, apps: &str) {
    unsafe {
        let c = &mut *ctl;
        let cap = c.apps.len();
        let mut n = 0usize;
        for u in apps.encode_utf16().take(cap) {
            c.apps[n] = u;
            n += 1;
        }
        if n < cap {
            c.apps[n] = 0;
        }
        c.apps_len = n as u32;
    }
}

/// The one signal that reaches processes we hold no handle to. `max(1)` keeps zero
/// meaning "never bumped", which is what tpdrv compares its initial view against.
fn bump_teardown(view: usize) {
    unsafe {
        let c = &mut *(view as *mut Ctl);
        c.teardown = c.teardown.wrapping_add(1).max(1);
    }
}

fn release_ctl(handle: *mut c_void, view: usize) {
    if view != 0 {
        unsafe { UnmapViewOfFile(view as *const c_void) };
    }
    if !handle.is_null() {
        unsafe { CloseHandle(handle) };
    }
}

#[cfg(test)]
mod ctl_tests {
    use super::{ctl_apps, Ctl};

    #[test]
    fn the_control_block_is_the_shape_tpdrv_reads() {
        // A silent layout drift here would make the driver read a garbage app list and
        // patch nothing (or everything), so pin the size the way the flow record is.
        assert_eq!(std::mem::size_of::<Ctl>(), 2056);
        assert_eq!(std::mem::offset_of!(Ctl, apps_len), 4);
        assert_eq!(std::mem::offset_of!(Ctl, apps), 8);
    }

    #[test]
    fn an_enabled_but_empty_whitelist_patches_nothing() {
        // The distinction that matters after 92 apps got injected: a whitelist that is
        // switched on but empty must not collapse into "no whitelist", because
        // the driver reads the empty string as "patch nothing" and the star as
        // "patch whatever pumps messages".
        assert_eq!(ctl_apps(true, &[]), "");
        assert_eq!(ctl_apps(false, &[]), "*");
        // a list is lowercased and trimmed on the way in; blank entries disappear
        let mixed = vec!["Firefox.EXE".to_string(), "   ".to_string(), "chrome.exe".into()];
        assert_eq!(ctl_apps(true, &mixed), "firefox.exe;chrome.exe");
        // and turning the whitelist off ignores the list entirely
        assert_eq!(ctl_apps(false, &mixed), "*");
    }
}

#[cfg(test)]
mod req_abi_probe {
    use super::Req;

    /// The byte layout tpdrv writes and this side reads. Pinned rather than derived
    /// from the type, because the one bug this guards against is invisible in every
    /// other way: if `#[repr(C)]` ever moves onto the wrong struct, both sides still
    /// compile, `size_of` still agrees, and every decision silently comes back wrong
    /// - which is exactly how a proxified connect ended up timing out.
    #[test]
    fn the_pipe_record_layout_is_pinned() {
        assert_eq!(std::mem::size_of::<Req>(), 32);
        assert_eq!(std::mem::offset_of!(Req, magic), 0);
        assert_eq!(std::mem::offset_of!(Req, pid), 4);
        assert_eq!(std::mem::offset_of!(Req, family), 8);
        assert_eq!(std::mem::offset_of!(Req, port_be), 10);
        assert_eq!(std::mem::offset_of!(Req, addr), 12);
        assert_eq!(std::mem::offset_of!(Req, proto), 28);
        assert_eq!(std::mem::offset_of!(Req, _pad), 29);
    }

    /// And the control block's, against the driver's copy of the same layout.
    #[test]
    fn the_control_block_layout_is_pinned() {
        assert_eq!(std::mem::size_of::<super::Ctl>(), 2056);
        assert_eq!(std::mem::offset_of!(super::Ctl, teardown), 0);
        assert_eq!(std::mem::offset_of!(super::Ctl, apps_len), 4);
        assert_eq!(std::mem::offset_of!(super::Ctl, apps), 8);
    }
}

#[cfg(test)]
mod family_wiring_tests {
    use super::*;

    fn cfg_with(v: &str) -> Config {
        let mut c = Config::default();
        c.settings.egress_family = v.to_string();
        c
    }

    #[test]
    fn an_explicit_policy_wins_over_the_probe() {
        // The operator saying "ipv4" must be honoured even on a machine that does have
        // IPv6, and "dual" must disable trimming even on one that does not: the auto
        // probe must never override an explicit choice.
        assert_eq!(
            effective_family_policy(&cfg_with("ipv4"), "127.0.0.1").suppressed_qtype(),
            Some(28)
        );
        assert_eq!(
            effective_family_policy(&cfg_with("dual"), "127.0.0.1").suppressed_qtype(),
            None
        );
        assert_eq!(
            effective_family_policy(&cfg_with("ipv6"), "127.0.0.1").suppressed_qtype(),
            Some(1)
        );
    }

    #[test]
    fn auto_never_suppresses_even_without_local_v6() {
        // The whole point: this machine may have no IPv6 route while the proxy's egress
        // does. Trimming on the local routing table would make IPv6-only origins
        // unreachable, which is worse than the delay it saves.
        let c = cfg_with("auto");
        assert_eq!(effective_family_policy(&c, "127.0.0.1").suppressed_qtype(), None);
        assert_eq!(effective_family_policy(&c, "203.0.113.9").suppressed_qtype(), None);
        // and the explicit opt-in still works, in both directions
        assert_eq!(
            effective_family_policy(&cfg_with("ipv4"), "127.0.0.1").suppressed_qtype(),
            Some(28),
            "an operator who HAS confirmed no v6 egress can still trim AAAA"
        );
        assert_eq!(
            effective_family_policy(&cfg_with("ipv6"), "127.0.0.1").suppressed_qtype(),
            Some(1)
        );
    }

    #[test]
    fn the_profile_key_round_trips() {
        let mut c = Config::default();
        assert_eq!(c.settings.egress_family, "dual", "default must trim nothing");
        c.settings.egress_family = "ipv4".into();
        let text = c.serialize();
        let back = Config::parse(&text).expect("the profile we wrote must parse");
        assert_eq!(back.settings.egress_family, "ipv4");
    }
}
