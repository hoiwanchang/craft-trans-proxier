//! WFP callout ingress — the ENGINE half of the kernel-callout contract.
//!
//! A WFP redirect cannot carry the original destination inside the connection
//! (`FWPM_ACTION0` and `FWPS_CLASSIFY_OUT0` have no endpoint field — asserted by
//! tests in `crate::wfp`), so the driver and the engine correlate out of band:
//!
//! 1. at start-up the engine binds a pool of loopback **token listeners** and hands
//!    their port numbers to the driver (the driver picks one per redirected flow);
//! 2. the callout redirects that flow's connect to `127.0.0.1:<token>` and writes
//!    `(token, FlowRecord)` to the [`crate::intercept::wfp_pipe_name`] pipe —
//!    `FlowRecord` names the ORIGINAL destination the classify context saw;
//! 3. when the redirected connect is accepted on the token port, the record is
//!    looked up and the connection is relayed through the proxy exactly like a
//!    hook-originated one ([`crate::intercept::relay_established`]).
//!
//! Nothing here runs the target's code or touches WFP: it is a loopback listener
//! plus a named pipe, and it is OFF unless `TPROXIER_WFP_INGRESS=1`, so a build
//! without a matching driver behaves exactly as before. A test can — and does —
//! stand in for the driver by writing the same frame.
//!
//! Token ports are the fallback for a driver that cannot populate the redirect
//! context. The PRIMARY path is [`query_redirect`], which reads what the callout
//! attached to the accepted socket using WFP's own proxy-side API — the mechanism
//! `docs/WFP_ROADMAP.md` step 7 describes, and the reason no side channel is needed.
//!
//! The remaining piece is the driver itself (`docs/WFP_ROADMAP.md`, Option B): it
//! needs the WDK for `fwpsk.h`, signing, and a host where breaking networking is
//! recoverable.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::dns::FakeIpPool;
use crate::intercept::{self, image_basename};
use crate::monitor::Monitor;
use crate::wfp_classify::{FlowRecord, FLOW_RECORD_LEN, VERDICT_REDIRECT};

/// How many token ports to pre-bind. A redirected flow holds one token only for as
/// long as its connection is being established, so this bounds concurrent
/// redirects rather than total connections; the driver waits for a free one.
pub const TOKEN_POOL: usize = 16;

/// Separate pool for redirected UDP flows. A token is one socket, and a datagram
/// flow needs its own: the app only accepts replies from the port it was redirected
/// to, so sharing one listener between apps would deliver one program's traffic into
/// another's tunnel. The driver takes one per flow and returns it in its flow-delete
/// callback, which is why that callback is not a no-op in a UDP-capable build.
pub const UDP_TOKEN_POOL: usize = 16;

/// Off-the-wire request a callout driver writes: `[u16 token][u16 reserved]
/// [FlowRecord bytes]`. Fixed size so a short or stale write can never be parsed
/// as a live flow.
pub const REQUEST_LEN: usize = 4 + FLOW_RECORD_LEN;
/// Records older than this are dropped: a driver that redirected a flow but whose
/// connection never arrived (RST, process killed) must not leave a destination
/// parked forever, and a *reused* token must not resurrect an old target.
const RECORD_TTL: Duration = Duration::from_secs(10);

static RECORDS: OnceLock<Mutex<HashMap<u16, (FlowRecord, Instant)>>> = OnceLock::new();
static TOKENS: OnceLock<Mutex<Vec<u16>>> = OnceLock::new();
static UDP_TOKENS: OnceLock<Mutex<Vec<u16>>> = OnceLock::new();

fn records() -> &'static Mutex<HashMap<u16, (FlowRecord, Instant)>> {
    RECORDS.get_or_init(|| Mutex::new(HashMap::new()))
}
fn tokens() -> &'static Mutex<Vec<u16>> {
    TOKENS.get_or_init(|| Mutex::new(Vec::new()))
}
fn udp_tokens() -> &'static Mutex<Vec<u16>> {
    UDP_TOKENS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Set by the environment; the engine is otherwise identical to a build without
/// this module.
static RUNTIME_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("TPROXIER_WFP_INGRESS").is_some()) || RUNTIME_ON.load(Ordering::SeqCst)
}

/// Latch the ingress path on from inside the process, for callers that cannot set an
/// environment variable before the engine starts — the GUI decides this when the operator
/// ticks a box, by which time `enabled()` may already have been read (the `OnceLock`
/// above is write-once by design, so the environment cannot be the only door).
/// One-way on purpose: turning the route off means tearing the [`Route`] down, not
/// silently flipping a flag under a running driver.
pub fn enable_at_runtime() {
    RUNTIME_ON.store(true, Ordering::SeqCst);
}

/// The TCP token ports the driver may redirect a stream flow to (empty until spawn).
pub fn token_ports() -> Vec<u16> {
    tokens().lock().map(|t| t.clone()).unwrap_or_default()
}

/// The UDP token ports the driver may redirect a datagram flow to — one per
/// concurrent flow, handed back when its flow-delete callback runs.
pub fn udp_token_ports() -> Vec<u16> {
    udp_tokens().lock().map(|t| t.clone()).unwrap_or_default()
}

/// Record a flow's original destination for `token` (the driver's side of the
/// protocol; public so a test — or an out-of-process supervisor — can drive it).
pub fn stage(token: u16, record: &FlowRecord) {
    if let Ok(mut m) = records().lock() {
        m.insert(token, (*record, Instant::now()));
    }
}

/// Take the record staged for `token`, if it is still fresh.
pub fn take(token: u16) -> Option<FlowRecord> {
    let mut m = records().lock().ok()?;
    let (rec, at) = m.remove(&token)?;
    (at.elapsed() < RECORD_TTL).then_some(rec)
}

/// ─── WFP's OWN proxy-side correlation API ──────────────────────────────────
///
/// `docs/WFP_ROADMAP.md` step 7 is a user-mode call: a service that accepts a
/// WFP-redirected connection asks that socket for the redirect CONTEXT (the opaque
/// bytes the callout stored in `FWPS_CONNECT_REQUEST0.localRedirectContext`) and
/// the redirect RECORDS, then sets the records on its own outbound socket so the
/// stack can correlate the two halves and no callout re-redirects them. We define
/// our driver to put a [`FlowRecord`] in that context, so the original destination
/// arrives with the connection — no side channel, no port tokens, no race.
///
/// opcodes: `shared/mstcpip.h:560-562`, `_WSAIOW(IOC_VENDOR, n)` where
/// `IOC_IN = 0x80000000` and `IOC_VENDOR = 0x18000000` (`shared/ws2def.h:385,397,680`).
pub const SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS: u32 = 0x9800_00DC; // _WSAIOW(IOC_VENDOR,220)
pub const SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT: u32 = 0x9800_00DD; // _WSAIOW(IOC_VENDOR,221)
pub const SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS: u32 = 0x9800_00DE; // _WSAIOW(IOC_VENDOR,222)

/// Largest redirect context we accept from the stack. The contract is 72 bytes, so
/// this only bounds the buffer a (possibly buggy) driver could hand back.
const CONTEXT_MAX: usize = 4096;
const RECORDS_MAX: usize = 8192;

/// The `(context, records)` WFP attached to an accepted, redirected socket.
/// `None` means this socket was not WFP-redirected — the overwhelmingly common
/// case, and the reason the hook path stays byte-identical.
pub fn query_redirect(sock: &std::net::TcpStream) -> (Option<FlowRecord>, Option<Vec<u8>>) {
    use std::os::windows::io::AsRawSocket;
    let raw = sock.as_raw_socket() as usize;
    let ctx = wfp_ioctl_get(raw, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, CONTEXT_MAX)
        .and_then(|b| FlowRecord::from_bytes(&b));
    let recs = wfp_ioctl_get(raw, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, RECORDS_MAX);
    (ctx, recs)
}

/// Set the redirect records on the proxy's own outbound socket (roadmap step 8).
pub fn apply_records(sock: &std::net::TcpStream, records: &[u8]) -> bool {
    use std::os::windows::io::AsRawSocket;
    wfp_ioctl_set(sock.as_raw_socket() as usize, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, records)
}

/// `WSAIoctl` with an output buffer only (the query forms take no input).
fn wfp_ioctl_get(sock: usize, code: u32, out_max: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; out_max];
    let mut returned = 0u32;
    let rc = unsafe {
        WSAIoctl(
            sock as *mut c_void,
            code,
            std::ptr::null(),
            0,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 {
        return None; // not redirected (or the platform lacks the API)
    }
    let n = (returned as usize).min(buf.len());
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    Some(buf)
}

fn wfp_ioctl_set(sock: usize, code: u32, in_buf: &[u8]) -> bool {
    if in_buf.is_empty() {
        return false;
    }
    let mut returned = 0u32;
    let rc = unsafe {
        WSAIoctl(
            sock as *mut c_void,
            code,
            in_buf.as_ptr() as *const c_void,
            in_buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    rc == 0
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAIoctl(
        sock: *mut c_void,
        code: u32,
        in_buf: *const c_void,
        in_len: u32,
        out_buf: *mut c_void,
        out_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        completion: *mut c_void,
    ) -> i32;
}

/// ─── the driver's control device ──────────────────────────────────────────
///
/// The callout cannot ask us anything while it is classifying (DISPATCH_LEVEL), so
/// the service pushes what it needs — its pid and the token listeners — up front.
/// Layout and codes mirror `driver_wfp/tpdrv_wfp.h`; the tests below pin them the
/// same way that file's `C_ASSERT`s pin the record layout, so the two halves cannot
/// drift apart silently.
pub const DEVICE_PATH: &str = r"\\.\TpDrvWfp";

/// `CTL_CODE(DeviceType, Function, Method, Access)` with DeviceType 0x8000,
/// METHOD_BUFFERED (0); SET_CONFIG asks for read|write access (3), GET_STATUS any (0).
pub const IOCTL_TPDRV_SET_CONFIG: u32 = (0x8000 << 16) | (3 << 14) | (0x800 << 2) | 0;
pub const IOCTL_TPDRV_GET_STATUS: u32 = (0x8000 << 16) | (0 << 14) | (0x801 << 2) | 0;
/// A redirected DATAGRAM has no accepted socket to ask for its redirect context, so the
/// driver keeps the token → flow mapping and answers this instead. The other half of the
/// contract is task #6: the driver releases the token in its flow-delete callback, or the
/// pool leaks and UDP redirection silently stops working.
pub const IOCTL_TPDRV_QUERY_FLOW: u32 = (0x8000 << 16) | (0 << 14) | (0x802 << 2) | 0;

/// `TPDRV_CONFIG` — field order and sizes must match the header exactly, including
/// the separate UDP pool: a datagram flow takes a token of its own.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverConfig {
    pub proxy_pid: u32,
    pub enabled: u32,
    pub token_count: u32,
    pub udp_token_count: u32,
    pub tokens: [u16; 64],
    pub udp_tokens: [u16; 64],
}

/// `TPDRV_STATUS`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DriverStatus {
    pub enabled: u32,
    pub proxy_pid: u32,
    pub token_count: u32,
    pub udp_token_count: u32,
    pub udp_active_flows: u32,
    pub callouts_registered: u32,
    pub redirect_handle_valid: u32,
    /// Datagrams the callout left direct because the engine indicated no flow handle, so
    /// a redirected token could never be returned by `flowDeleteFn`. Refusing is the safe
    /// choice (a leak is worse than an unproxied packet) but it is invisible in the wire
    /// path, so the driver counts it and `wfp --verify` reports it.
    pub udp_untrackable: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16, access: u32, share: u32, sa: *const c_void, disp: u32,
        flags: u32, template: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        device: *mut c_void, code: u32, in_buf: *const c_void, in_len: u32,
        out_buf: *mut c_void, out_len: u32, returned: *mut u32, overlapped: *mut c_void,
    ) -> i32;
}

const GENERIC_READ_WRITE: u32 = 0xC000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE_WIN: *mut c_void = -1isize as *mut c_void;

/// Hand the driver our pid and the token pool, and switch redirection on (or off).
/// `Err` when the driver is not installed — the expected state, and the reason the
/// hook path stays the default.
pub fn configure_driver(enabled: bool) -> std::io::Result<DriverStatus> {
    let dev = open_device()?;
    let r = push_config(dev, enabled).and_then(|()| status_on(dev));
    unsafe { CloseHandle(dev) };
    r
}

/// Does the driver's view of itself differ from what this process is serving?
///
/// Pure, so the failure mode is testable without a kernel: a callout driver that is
/// stopped and started again comes back **inert** (`DriverEntry` configures nothing
/// until the service pushes), and until it is pushed again every filtered connect is
/// permitted untouched — proxification silently stops while the filters are still
/// installed and `netsh wfp show state` still lists them. So "any" disagreement
/// re-pushes; agreement is the only reason not to.
pub fn needs_reconfigure(
    st: &DriverStatus,
    proxy_pid: u32,
    want_enabled: bool,
    token_count: usize,
    udp_token_count: usize,
) -> bool {
    st.enabled != u32::from(want_enabled)
        || st.proxy_pid != proxy_pid
        || st.token_count != (token_count.min(64) as u32)
        || st.udp_token_count != (udp_token_count.min(64) as u32)
}

/// Read the driver, and re-arm it only if it drifted from us. Returns the state AFTER
/// any re-push. This is what a long-running supervisor polls; `configure_driver` is the
/// unconditional version used when the route is first brought up.
pub fn ensure_armed() -> std::io::Result<DriverStatus> {
    let st = status()?;
    let ports = token_ports();
    let udp = udp_token_ports();
    if !needs_reconfigure(&st, std::process::id(), true, ports.len(), udp.len()) {
        return Ok(st);
    }
    configure_driver(true)
}

/// Ask the driver what it is configured with, WITHOUT changing anything. This is
/// what `trans-proxier wfp --verify` polls, so a diagnostic run cannot alter the
/// state it is trying to describe.
pub fn status() -> std::io::Result<DriverStatus> {
    let dev = open_device()?;
    let r = status_on(dev);
    unsafe { CloseHandle(dev) };
    r
}

fn status_on(dev: *mut c_void) -> std::io::Result<DriverStatus> {
    let mut st = DriverStatus::default();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dev,
            IOCTL_TPDRV_GET_STATUS,
            std::ptr::null(),
            0,
            &mut st as *mut DriverStatus as *mut c_void,
            std::mem::size_of::<DriverStatus>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A .sys older than this build answers with FEWER bytes, and because the buffer
    // starts zeroed, every field it did not write reads as 0 - including
    // udp_untrackable, whose 0 is exactly the value that PASSES the gate. A short
    // reply is therefore refused, not reported as a measured zero.
    if returned as usize != std::mem::size_of::<DriverStatus>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "driver wrote {returned} status bytes, this build reads {} - the loaded .sys and this service disagree on the ABI",
                std::mem::size_of::<DriverStatus>(),
            ),
        ));
    }
    Ok(st)
}

/// Send our pid + token pools to the driver. Split from `configure_driver` so the
/// read-only status path cannot accidentally reconfigure the driver it is describing.
fn push_config(dev: *mut c_void, enabled: bool) -> std::io::Result<()> {
    let ports = token_ports();
    let uports = udp_token_ports();
    let mut cfg = DriverConfig {
        proxy_pid: std::process::id(),
        enabled: u32::from(enabled),
        token_count: ports.len().min(64) as u32,
        udp_token_count: uports.len().min(64) as u32,
        tokens: [0; 64],
        udp_tokens: [0; 64],
    };
    cfg.tokens[..cfg.token_count as usize].copy_from_slice(&ports[..cfg.token_count as usize]);
    cfg.udp_tokens[..cfg.udp_token_count as usize].copy_from_slice(&uports[..cfg.udp_token_count as usize]);
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dev,
            IOCTL_TPDRV_SET_CONFIG,
            &cfg as *const DriverConfig as *const c_void,
            std::mem::size_of::<DriverConfig>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// True when the callout driver is loaded: opening its control device is the whole
/// probe, so this never changes driver state.
pub fn driver_present() -> bool {
    match open_device() {
        Ok(dev) => {
            unsafe { CloseHandle(dev) };
            true
        }
        Err(_) => false,
    }
}

fn open_device() -> std::io::Result<*mut c_void> {
    let path: Vec<u16> = DEVICE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
    let dev = unsafe {
        CreateFileW(path.as_ptr(), GENERIC_READ_WRITE, 0, std::ptr::null(), OPEN_EXISTING, 0, std::ptr::null_mut())
    };
    if dev == INVALID_HANDLE_WIN || dev.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(dev)
}

/// Start the token listeners (TCP — see [`flow_rejection`]) and the driver's ingress pipe.
pub fn spawn(
    config: Arc<std::sync::RwLock<Config>>,
    monitor: Arc<Monitor>,
    pool: Arc<FakeIpPool>,
    stop: Arc<AtomicBool>,
    udp_relay_port: u16,
) -> std::io::Result<()> {
    for _ in 0..TOKEN_POOL {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if let Ok(mut t) = tokens().lock() {
            t.push(port);
        }
        let (c, m, p, s) = (config.clone(), monitor.clone(), pool.clone(), stop.clone());
        std::thread::spawn(move || accept_loop(listener, port, c, m, p, s));
    }
    let relay = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        udp_relay_port,
    );
    for _ in 0..UDP_TOKEN_POOL {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let port = sock.local_addr()?.port();
        if let Ok(mut t) = udp_tokens().lock() {
            t.push(port);
        }
        let (c, m, p2, s2) = (config.clone(), monitor.clone(), pool.clone(), stop.clone());
        std::thread::spawn(move || udp_token_loop(sock, port, relay, c, m, p2, s2));
    }
    monitor.log(
        "info",
        format!(
            "WFP ingress: {TOKEN_POOL} TCP + {UDP_TOKEN_POOL} UDP 令牌端口，管道 {}",
            intercept::wfp_pipe_name()
        ),
    );
    let (m, s) = (monitor, stop);
    std::thread::spawn(move || pipe_server(m, s));
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

type HANDLE = *mut c_void;
const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        name: *const u16, open_mode: u32, pipe_mode: u32, max_instances: u32,
        out_buf: u32, in_buf: u32, default_timeout: u32, sa: *const c_void,
    ) -> HANDLE;
    fn ConnectNamedPipe(pipe: HANDLE, overlapped: *mut c_void) -> i32;
    fn DisconnectNamedPipe(pipe: HANDLE) -> i32;
    fn ReadFile(pipe: HANDLE, buf: *mut u8, len: u32, read: *mut u32, ov: *mut c_void) -> i32;
    fn WriteFile(pipe: HANDLE, buf: *const u8, len: u32, written: *mut u32, ov: *mut c_void) -> i32;
    fn CloseHandle(h: HANDLE) -> i32;
}

/// Find the flow that arrived on `token`: the pipe-staged record first (works with any
/// driver and is what the live test drives), then the driver's own flow table.
fn flow_for_token(token: u16) -> Option<FlowRecord> {
    if let Some(rec) = take(token) {
        return Some(rec);
    }
    let dev = open_device().ok()?;
    let mut out = FlowRecord::default().to_bytes();
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dev,
            IOCTL_TPDRV_QUERY_FLOW,
            &token as *const u16 as *const c_void,
            std::mem::size_of::<u16>() as u32,
            out.as_mut_ptr() as *mut c_void,
            out.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(dev) };
    if ok == 0 {
        return None;
    }
    FlowRecord::from_bytes(&out)
}

/// Serve one redirected UDP flow from its own token socket.
///
/// The app sends bare datagrams (it believes it is talking to the real destination),
/// so the first one is prefixed with a synthesised `Req` header naming the original
/// target; after that the already-verified UDP relay does the SOCKS5 ASSOCIATE work.
/// Replies come back from the relay and are forwarded to the peer the flow was
/// learned from — which is precisely why a token cannot be shared between apps.
/// What a datagram arriving on a per-flow UDP token should do to the source pin.
///
/// The pin exists because a token is the ONLY thing binding a redirected datagram to a
/// flow on the UDP path — there is no `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` for a
/// datagram socket — so a second source must not be able to ride along in someone else's
/// tunnel. But the driver RECYCLES tokens (its flow-delete callback releases the port for
/// the next flow), so a pin that never resets would reject every later flow that lands on
/// a reused port: the first 16 UDP flows work and then UDP silently stops. Hence the
/// difference between "a different source, same flow" (refuse) and "a different source
/// because this is now a different flow" (rebind).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinAction {
    /// the pinned source, or a reply: forward as today
    Keep,
    /// the token now describes a different flow: adopt this source
    Rebind,
    /// cannot be attributed — drop, never guess a destination
    Refuse,
}

pub(crate) fn udp_pin_action(
    pinned: Option<(u64, std::net::SocketAddr)>,
    fresh: Option<(u64, std::net::SocketAddr)>,
    same_source: bool,
) -> PinAction {
    if same_source && pinned.is_some() {
        return PinAction::Keep;
    }
    match (pinned, fresh) {
        // nothing to attribute the packet to: refusing is the only safe answer, and it
        // is what the driver-less (staged-record) path always did
        (_, None) => PinAction::Refuse,
        (None, Some(_)) => PinAction::Rebind,
        (Some(a), Some(b)) if a != b => PinAction::Rebind,
        (Some(_), Some(_)) => PinAction::Refuse,
    }
}

fn udp_token_loop(
    sock: std::net::UdpSocket,
    port: u16,
    relay: std::net::SocketAddr,
    _config: Arc<std::sync::RwLock<Config>>,
    monitor: Arc<Monitor>,
    _pool: Arc<FakeIpPool>,
    stop: Arc<AtomicBool>,
) {
    let _ = sock.set_read_timeout(Some(Duration::from_millis(150)));
    let mut buf = vec![0u8; 64 * 1024];
    let mut app: Option<std::net::SocketAddr> = None;
    // (WFP flow id, original destination) of whoever `app` was pinned to
    let mut pinned: Option<(u64, std::net::SocketAddr)> = None;
    while !stop.load(Ordering::SeqCst) {
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => return,
        };
        if n == 0 {
            continue;
        }
        if from == relay {
            match app {
                Some(a) => {
                    let _ = sock.send_to(&buf[..n], a);
                }
                None => monitor.log("warn", format!("WFP UDP 令牌 {port} 收到无主应答，已丢弃")),
            }
            continue;
        }
        if app == Some(from) {
            // a later datagram on the established flow: payload only
            if let Err(e) = sock.send_to(&buf[..n], relay) {
                monitor.log("warn", format!("WFP UDP 令牌 {port} 转发失败: {e}"));
            }
            continue;
        }
        // The record is fetched ONCE per datagram: `flow_for_token` consumes a staged
        // record, so resolving it twice would make the second look unanswered (a bug the
        // recycled-token scenario in tests/transparent_windows.rs caught immediately).
        let rec = match flow_for_token(port) {
            Some(r) => r,
            None => {
                monitor.log("warn", format!("WFP UDP 令牌 {port} 无流记录，已拒绝（不猜测目的地）"));
                continue;
            }
        };
        // A different source than the pinned one is either the driver breaking its
        // contract or the token having been recycled to a new flow — the record says
        // which, so consult it instead of refusing the port forever.
        if app.is_some() && app != Some(from) {
            let fresh = rec.remote().map(|d| (rec.flow_id, d));
            let rejected = flow_rejection(&rec).is_some();
            match (udp_pin_action(pinned, fresh, false), rejected) {
                (PinAction::Rebind, false) => {
                    monitor.log(
                        "info",
                        format!(
                            "WFP UDP 令牌 {port} 已回收给新流（目的地 {}），改绑新源 {from}",
                            fresh.map(|(_, d)| d.to_string()).unwrap_or_default()
                        ),
                    );
                    app = None;
                    pinned = None;
                }
                _ => {
                    // second source on the SAME flow, or nothing safe to attribute it to
                    monitor.log("warn", format!("WFP UDP 令牌 {port} 出现第二个源 {from}，已拒绝"));
                    continue;
                }
            }
        }
        if let Some(why) = flow_rejection(&rec) {
            monitor.log("warn", format!("WFP UDP 流记录被拒绝: {why}"));
            continue;
        }
        let req = intercept::req_from_flow(&rec);
        let hdr: &[u8] = unsafe {
            std::slice::from_raw_parts(
                &req as *const intercept::Req as *const u8,
                std::mem::size_of::<intercept::Req>(),
            )
        };
        match sock.send_to(hdr, relay).and_then(|_| sock.send_to(&buf[..n], relay)) {
            Ok(_) => {
                app = Some(from);
                // remember WHICH flow this pin belongs to, so a recycled token can be
                // told apart from a second source riding on a live one
                pinned = rec.remote().map(|d| (rec.flow_id, d));
                let dst = rec.remote().map(|r| r.to_string()).unwrap_or_default();
                monitor.log("info", format!("WFP UDP 令牌 {port} → {dst} (app {from})"));
            }
            Err(e) => monitor.log("warn", format!("WFP UDP 令牌 {port} 头部/数据发送失败: {e}")),
        }
    }
}

/// Accept on one token port until the engine stops. Each accepted connection
/// consumes the record staged for this port; with none (or a stale one) the
/// connection is closed WITHOUT dialling anything — an unknown flow is never
/// guessed at.
fn accept_loop(
    listener: TcpListener,
    token: u16,
    config: Arc<std::sync::RwLock<Config>>,
    monitor: Arc<Monitor>,
    pool: Arc<FakeIpPool>,
    stop: Arc<AtomicBool>,
) {
    let _ = listener.set_nonblocking(true);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, _)) => {
                let (c, m, p) = (config.clone(), monitor.clone(), pool.clone());
                std::thread::spawn(move || match take(token) {
                    Some(rec) => forward(client, rec, c, m, p),
                    None => {
                        m.log("warn", format!("WFP 令牌 {token} 无对应流记录，已关闭（不猜测目的地）"));
                        drop(client);
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return,
        }
    }
}

/// Why a staged flow cannot be served by this ingress, if it cannot. Split out of
/// [`forward`] so the behaviour is testable without a socket, and so an unsupported
/// case is REFUSED with a reason instead of silently relayed to the wrong place.
pub(crate) fn flow_rejection(rec: &FlowRecord) -> Option<&'static str> {
    if rec.verdict != VERDICT_REDIRECT {
        return Some("非重定向判决（non-redirect verdict）");
    }
    if rec.remote().is_none() {
        return Some("未知地址族（unknown address family）");
    }
    // UDP is served from its own per-flow token socket (see udp_token_loop), so a
    // datagram record is as valid here as a stream one.
    None
}

/// Relay a redirected connection to the destination its `FlowRecord` names, with
/// the fake-IP pool consulted so hostname rules still fire.
fn forward(
    client: TcpStream,
    rec: FlowRecord,
    config: Arc<std::sync::RwLock<Config>>,
    monitor: Arc<Monitor>,
    pool: Arc<FakeIpPool>,
) {
    if let Some(why) = flow_rejection(&rec) {
        monitor.log("warn", format!("WFP 流记录被拒绝: {why}（pid={}, proto={}）", rec.pid, rec.proto));
        return;
    }
    let remote = rec.remote().expect("flow_rejection checked the family");
    let host = dns_host_for(&pool, remote.ip());
    let app = image_basename(rec.pid);
    intercept::relay_established(client, &host, remote.port(), app, Some(rec.pid), config, monitor, None, pool.clone());
}

/// Reverse-map a fake IP back to its hostname so `*.example.com` rules can fire on
/// a WFP-redirected flow exactly as they do on a hooked one.
fn dns_host_for(pool: &FakeIpPool, ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => crate::dns::effective_host(pool, &v4.to_string()),
        other => other.to_string(),
    }
}

/// The driver's ingress pipe: fixed-size requests, one-byte acknowledgement.
fn pipe_server(monitor: Arc<Monitor>, stop: Arc<AtomicBool>) {
    let name = wide(&intercept::wfp_pipe_name());
    while !stop.load(Ordering::SeqCst) {
        let pipe = unsafe {
            CreateNamedPipeW(name.as_ptr(), 0x0003, 0x0004 | 0x0002, 8, 512, 512, 0, std::ptr::null())
        };
        if pipe == INVALID_HANDLE_VALUE {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } != 0;
        if !connected {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
            continue;
        }
        let m = monitor.clone();
        let raw = pipe as isize;
        std::thread::spawn(move || {
            let pipe = raw as HANDLE;
            let mut buf = [0u8; REQUEST_LEN];
            let mut got = 0u32;
            let ok = unsafe {
                ReadFile(pipe, buf.as_mut_ptr(), REQUEST_LEN as u32, &mut got, std::ptr::null_mut())
            };
            let ack: [u8; 1] = if ok != 0 && got as usize == REQUEST_LEN {
                match FlowRecord::from_bytes(&buf[4..]) {
                    Some(rec) => {
                        stage(u16::from_le_bytes([buf[0], buf[1]]), &rec);
                        [1]
                    }
                    // bad magic: refuse to remember a destination we cannot trust
                    None => [0],
                }
            } else {
                [0]
            };
            let mut written = 0u32;
            unsafe {
                WriteFile(pipe, ack.as_ptr(), 1, &mut written, std::ptr::null_mut());
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
            if ack[0] == 0 {
                m.log("warn", "WFP 管道写入的流记录长度或魔数无效，已忽略".to_string());
            }
        });
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_driver_that_agrees_with_us_is_left_alone() {
        let ports = vec![12000, 12001];
        let udp = vec![13000];
        let st = DriverStatus {
            enabled: 1,
            proxy_pid: 4242,
            token_count: 2,
            udp_token_count: 1,
            ..Default::default()
        };
        assert!(!needs_reconfigure(&st, 4242, true, ports.len(), udp.len()));
    }

    #[test]
    fn any_disagreement_repushes_including_a_foreign_owner() {
        let base = DriverStatus { enabled: 1, proxy_pid: 4242, token_count: 2, udp_token_count: 1, ..Default::default() };
        // restarted driver: back to inert, so proxification has silently stopped
        assert!(needs_reconfigure(&DriverStatus { enabled: 0, ..base }, 4242, true, 2, 1));
        // someone else's engine owns the pool now
        assert!(needs_reconfigure(&DriverStatus { proxy_pid: 9999, ..base }, 4242, true, 2, 1));
        // our listeners changed size since the last push
        assert!(needs_reconfigure(&DriverStatus { token_count: 16, ..base }, 4242, true, 2, 1));
        assert!(needs_reconfigure(&DriverStatus { udp_token_count: 4, ..base }, 4242, true, 2, 1));
        // pausing the route is a decision too: enabled=0 must be pushed, not skipped
        assert!(needs_reconfigure(&base, 4242, false, 2, 1));
    }

    #[test]
    fn the_pool_is_truncated_the_same_way_on_both_sides() {
        // push_config sends at most 64 ports; the comparison must use the same bound,
        // or a large pool would re-push every poll forever.
        let st = DriverStatus { enabled: 1, proxy_pid: 7, token_count: 64, udp_token_count: 64, ..Default::default() };
        assert!(!needs_reconfigure(&st, 7, true, 96, 96));
        assert!(needs_reconfigure(&st, 7, true, 63, 64));
    }

    #[test]
    fn redirect_ioctls_are_the_mstcpip_opcodes() {
        // _WSAIOW(IOC_VENDOR, n) = IOC_IN | IOC_VENDOR | n, per ws2def.h.
        let ioc_in: u32 = 0x8000_0000;
        let ioc_vendor: u32 = 0x1800_0000;
        let w = |n: u32| ioc_in | ioc_vendor | n;
        assert_eq!(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, w(220));
        assert_eq!(SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, w(221));
        assert_eq!(SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, w(222));
    }

    #[test]
    fn a_plain_socket_reports_no_redirect() {
        // The engine asks every accepted connection; without a WFP callout the query
        // must fail cleanly (None) rather than block or panic, so the hook path and a
        // driver-less build are unaffected.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        let (ctx, recs) = query_redirect(&b);
        assert!(ctx.is_none(), "no callout attached a redirect context");
        assert!(recs.is_none(), "no redirect records on a plain connection");
        drop(a);
    }

    /// The C header's `#define NAME value`, or None.
    fn c_define(src: &str, name: &str) -> Option<u64> {
        for line in src.lines() {
            let l = line.trim();
            if let Some(rest) = l.strip_prefix(&format!("#define {name}")) {
                let tok = rest.split_whitespace().next()?;
                let t = tok.trim_end_matches('u').trim_end_matches('U');
                return if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    t.parse::<u64>().ok()
                };
            }
        }
        None
    }

    #[test]
    fn shared_scalars_agree_between_the_driver_and_the_service() {
        const HDR: &str = include_str!("../driver_wfp/tpdrv_wfp.h");
        assert_eq!(c_define(HDR, "TP_FLOW_RECORD_MAGIC"), Some(crate::wfp_classify::FLOW_RECORD_MAGIC as u64));
        
        assert_eq!(
            c_define(HDR, "TP_VERDICT_PERMIT"),
            Some(crate::wfp_classify::VERDICT_PERMIT as u64)
        );
        assert_eq!(
            c_define(HDR, "TP_VERDICT_REDIRECT"),
            Some(crate::wfp_classify::VERDICT_REDIRECT as u64)
        );
        assert_eq!(
            c_define(HDR, "TP_VERDICT_BLOCK"),
            Some(crate::wfp_classify::VERDICT_BLOCK as u64)
        );
        // the driver's pool size must be at least what the service pushes
        assert_eq!(c_define(HDR, "TPDRV_MAX_TOKENS"), Some(64));
        assert!(TOKEN_POOL <= 64 && UDP_TOKEN_POOL <= 64);

        // CTL_CODE(DeviceType<<16 | Access<<14 | Function<<2 | Method)
        let ctl = |dev: u32, access: u32, fun: u32, method: u32| -> u32 {
            (dev << 16) | (access << 14) | (fun << 2) | method
        };
        assert_eq!(IOCTL_TPDRV_SET_CONFIG, ctl(0x8000, 3, 0x800, 0));
        assert_eq!(IOCTL_TPDRV_GET_STATUS, ctl(0x8000, 0, 0x801, 0));
        assert_eq!(IOCTL_TPDRV_QUERY_FLOW, ctl(0x8000, 0, 0x802, 0));
        for (code, name) in [
            (IOCTL_TPDRV_SET_CONFIG, "IOCTL_TPDRV_SET_CONFIG"),
            (IOCTL_TPDRV_GET_STATUS, "IOCTL_TPDRV_GET_STATUS"),
            (IOCTL_TPDRV_QUERY_FLOW, "IOCTL_TPDRV_QUERY_FLOW"),
        ] {
            let line = HDR.lines().find(|l| l.contains(&format!("#define {name}"))).unwrap_or_else(|| panic!("{name} vanished from the C header"));
            // device type + function code must match what we compute here
            assert!(line.contains("FILE_DEVICE_TPDRV"), "{line}");
            let fun = line.split(", ").nth(1).and_then(|s| s.trim_start().strip_prefix("0x")).and_then(|s| s.split(',').next()).and_then(|s| u32::from_str_radix(s.trim(), 16).ok());
            assert_eq!(fun, Some((code >> 2) & 0xFFF), "{name}: C function code vs Rust");
        }
        assert_eq!(c_define(HDR, "FILE_DEVICE_TPDRV"), Some(0x8000));
    }

    #[test]
    fn driver_config_layout_matches_the_c_header() {
        // TPDRV_CONFIG: 4 ULONGs then two UINT16[64] pools.
        assert_eq!(std::mem::size_of::<DriverConfig>(), 16 + 128 + 128);
        assert_eq!(std::mem::offset_of!(DriverConfig, tokens), 16);
        assert_eq!(std::mem::offset_of!(DriverConfig, udp_tokens), 144);
        assert_eq!(std::mem::size_of::<DriverStatus>(), 32);
        // CTL_CODE(DeviceType<<16 | Access<<14 | Function<<2 | Method)
        assert_eq!(IOCTL_TPDRV_SET_CONFIG, 0x8000_E000);
        assert_eq!(IOCTL_TPDRV_GET_STATUS, 0x8000_2004);
    }

    /// The pin must survive a normal flow, refuse an unattributable packet, and — the
    /// bug this exists for — let a RECYCLED token start a new flow instead of rejecting
    /// every later app on that port forever.
    #[test]
    fn a_recycled_udp_token_rebinds_but_a_second_source_on_one_flow_does_not() {
        use std::net::SocketAddr;
        let d1: SocketAddr = "203.0.113.9:53".parse().unwrap();
        let d2: SocketAddr = "198.51.100.7:443".parse().unwrap();

        // first packet of a flow: nothing pinned yet, and there is a record → establish
        assert_eq!(udp_pin_action(None, Some((1, d1)), false), PinAction::Rebind);
        // the same source again: forward, do not re-resolve
        assert_eq!(udp_pin_action(Some((1, d1)), None, true), PinAction::Keep);
        // token recycled by flow-delete: same port, different flow → rebind (this was
        // the permanent rejection)
        assert_eq!(
            udp_pin_action(Some((1, d1)), Some((2, d2)), false),
            PinAction::Rebind,
            "a reused token must be able to start the next flow"
        );
        // different flow id but the SAME destination still counts as a new flow
        assert_eq!(udp_pin_action(Some((1, d1)), Some((7, d1)), false), PinAction::Rebind);
        // same flow id AND same destination from another socket: contract violation
        assert_eq!(udp_pin_action(Some((1, d1)), Some((1, d1)), false), PinAction::Refuse);
        // nothing to attribute it to: refuse rather than guess (unchanged behaviour)
        assert_eq!(udp_pin_action(Some((1, d1)), None, false), PinAction::Refuse);
        assert_eq!(udp_pin_action(None, None, false), PinAction::Refuse);
    }

    #[test]
    fn a_machine_without_the_driver_reports_the_usual_error() {
        // This host has no WFP callout installed, so the control device must simply
        // be absent: the engine keeps running on the hook path.
        let r = configure_driver(true);
        assert!(r.is_err(), "unexpected: a TpDrvWfp device exists here");
        assert!(!driver_present());
    }

    #[test]
    fn applying_records_without_a_redirect_fails_without_side_effects() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let a = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (b, _) = l.accept().unwrap();
        assert!(!apply_records(&b, &[1, 2, 3]), "setting records on an unredirected socket must fail");
        drop(a);
    }
    use super::*;
    use crate::wfp_classify::VERDICT_PERMIT;

    fn rec(port: u16) -> FlowRecord {
        FlowRecord {
            family: 2,
            port_be: port.to_be(),
            addr: [198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pid: 1,
            chain: 3,
            verdict: VERDICT_REDIRECT,
            proto: 6,
            flow_id: 9,
            local_addr: [0; 16],
            local_port_be: 0,
            token_port: 12000,
        }
    }

    #[test]
    fn flow_lookup_uses_the_staged_record_and_never_invents_one() {
        // staged → returned; and consumed, so a second lookup on the same token cannot
        // hand the same destination to a different flow.
        stage(15001, &rec(53));
        let first = flow_for_token(15001).expect("the staged record is found");
        assert_eq!(first.remote().map(|r| r.port()), Some(53));
        // nothing staged and (on this host) no driver ⇒ None, never a guess
        assert!(flow_for_token(15002).is_none(), "an unknown token gets no destination");
    }

    #[test]
    fn unsupported_flows_are_refused_with_a_reason() {
        let tcp = rec(443);
        assert_eq!(flow_rejection(&tcp), None, "a normal TCP redirect is servable");

        let mut udp = rec(53);
        udp.proto = 17;
        assert_eq!(flow_rejection(&udp), None, "UDP rides its own per-flow token now");

        let mut permit = rec(443);
        permit.verdict = crate::wfp_classify::VERDICT_PERMIT;
        assert!(flow_rejection(&permit).is_some());

        let mut bogus = rec(443);
        bogus.family = 99;
        assert_eq!(flow_rejection(&bogus), Some("未知地址族（unknown address family）"));
    }

    #[test]
    fn a_staged_record_is_taken_once_and_a_stale_one_is_dropped() {
        // Unique tokens per assertion: RECORDS is process-wide shared state.
        stage(4001, &rec(443));
        let got = take(4001).expect("record survives");
        assert_eq!(got.remote(), Some("198.51.100.20:443".parse().unwrap()));
        assert!(take(4001).is_none(), "one record per redirect: a token is not reusable while staged");

        stage(4002, &rec(443));
        if let Ok(mut m) = records().lock() {
            m.get_mut(&4002).unwrap().1 = Instant::now() - RECORD_TTL - Duration::from_secs(1);
        }
        assert!(take(4002).is_none(), "an abandoned flow must not linger past its TTL");
    }

    #[test]
    fn request_frame_is_token_plus_record() {
        assert_eq!(REQUEST_LEN, 4 + FLOW_RECORD_LEN);
        let r = rec(53);
        let mut frame = [0u8; REQUEST_LEN];
        frame[0..2].copy_from_slice(&9999u16.to_le_bytes());
        frame[4..].copy_from_slice(&r.to_bytes());
        let token = u16::from_le_bytes([frame[0], frame[1]]);
        let back = FlowRecord::from_bytes(&frame[4..]).expect("parses");
        assert_eq!(token, 9999);
        assert_eq!(back.verdict, VERDICT_REDIRECT);
        // A record staged from a PERMIT verdict is still readable here: the caller
        // decides what to do with it, the ingress only transports it.
        assert_eq!(VERDICT_PERMIT, 0);
    }

    #[test]
    fn fake_ips_reverse_map_but_real_ones_pass_through() {
        let pool = FakeIpPool::new();
        let fake = pool.allocate("svc.example.com");
        assert_eq!(dns_host_for(&pool, fake.into()), "svc.example.com");
        assert_eq!(dns_host_for(&pool, "198.51.100.30".parse().unwrap()), "198.51.100.30");
        assert_eq!(dns_host_for(&pool, "2001:db8::1".parse().unwrap()), "2001:db8::1");
    }
}
