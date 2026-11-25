//! `tpdrv` — clean-room reconstruction of the original PE's injected socket
//! interception DLL (`PrxDrvPE64.dll` / `PrxDrvPE.dll`).
//!
//! Evidence for the architecture (see craft-anything findings fnd_6/7/8):
//!  * fnd_6 — the sole export `InitFilter3` is exactly
//!    `SetWindowsHookExW(WH_GETMESSAGE, carrier, hMod=self, dwThreadId=0)`: a
//!    *global* message hook whose carrier proc only calls `CallNextHookEx`, so
//!    its only job is to make the OS map this DLL into every message-pumping
//!    process. Injection is a Windows message hook, NOT a remote thread.
//!  * fnd_7 — on attach, the DLL stays inert unless the engine's named mutex is
//!    present (`OpenMutexW` gate), then installs inline hooks on the ws2_32
//!    socket connect path using the "Module Copy" technique (disasm + relocate).
//!  * fnd_8 — each intercepted connect is decided by the engine over the named
//!    pipe `\\.\pipe\enginePE` via `CallNamedPipeW`, keyed by
//!    `GetCurrentProcessId()`; the app's socket is then transparently redirected
//!    to the engine's local relay. The app never configures a proxy.
//!
//! This is a faithful SKELETON of that pipeline. It cannot be run/validated in a
//! non-Windows CI: the inline-hook installation here uses a fixed-length 14-byte
//! jmp trampoline as a stand-in for the full "Module Copy" length-decoder — a
//! production build must decode instruction boundaries (e.g. `zydis`) before
//! overwriting, which is precisely why the original prints its "cannot decode
//! instructions / switch to Module Copy" error. See `install_jmp`.
#![allow(non_snake_case, non_camel_case_types)]
// Hand-written process-wide inline hooking: the detour/trampoline and the raw
// Win32 FFI legitimately sit in unsafe contexts and some scaffold consts/fns are
// kept for the cross-arch (i686) build and future WSAConnect/DNS hooks.
#![allow(unused_unsafe, dead_code, unsafe_op_in_unsafe_fn)]

#[cfg(not(windows))]
compile_error!("tpdrv builds only for a *-pc-windows-* target");

use std::ffi::{c_void, OsStr};
use std::sync::atomic::{AtomicUsize, Ordering};

mod decode;

// ---------------------------------------------------------------------------
// Minimal Win32 / WinSock FFI (self-contained, matching the tiny import set of
// the original DLL: kernel32, user32, ws2_32).
// ---------------------------------------------------------------------------
type BOOL = i32;
type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type HHOOK = *mut c_void;
type WPARAM = usize;
type LPARAM = isize;
type LRESULT = isize;
type SOCKET = usize; // UINT_PTR
const TRUE: BOOL = 1;
const INVALID_SOCKET: SOCKET = usize::MAX;

const WH_GETMESSAGE: i32 = 3;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const SOL_SOCKET: i32 = 0xffff;
const SO_TYPE: i32 = 0x1008; // Winsock (NOT the BSD 0x1001, which is SO_DEBUG here)
const SOCK_DGRAM: i32 = 2;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[repr(C)]
#[derive(Clone, Copy)]
struct SOCKADDR {
    sa_family: u16,
    sa_data: [i8; 14],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[repr(C)]
struct SOCKADDR_IN {
    sin_family: u16,
    sin_port: u16, // network byte order
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct SOCKADDR_IN6 {
    sin6_family: u16,
    sin6_port: u16, // network byte order
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[link(name = "user32")]
#[link(name = "ws2_32")]
unsafe extern "system" {
    fn SetWindowsHookExW(idHook: i32, lpfn: HOOKPROC, hmod: HMODULE, idThread: u32) -> HHOOK;
    fn CallNextHookEx(hhk: HHOOK, nCode: i32, wParam: WPARAM, lParam: LPARAM) -> LRESULT;
    fn GetCurrentProcessId() -> u32;
    fn CallNamedPipeW(
        lpName: *const u16,
        lpInBuffer: *const c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut c_void,
        nOutBufferSize: u32,
        lpBytesRead: *mut u32,
        nTimeOut: u32,
    ) -> BOOL;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> BOOL;
    fn send(s: SOCKET, buf: *const i8, len: i32, flags: i32) -> i32;
    fn sendto(s: SOCKET, buf: *const i8, len: i32, flags: i32, to: *const SOCKADDR, tolen: i32) -> i32;
    fn recvfrom(s: SOCKET, buf: *mut i8, len: i32, flags: i32, from: *mut SOCKADDR, fromlen: *mut i32) -> i32;
    fn recv(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32;
    fn socket(af: i32, ty: i32, proto: i32) -> SOCKET;
    fn connect_sock(s: SOCKET, name: *const SOCKADDR, len: i32) -> i32;
    fn closesocket(s: SOCKET) -> i32;
}

// Winsock `connect` is declared separately (name collides with Rust keyword
// context); expose the raw import for the UDP shadow-socket path.
#[link(name = "ws2_32")]
unsafe extern "system" {
    #[link_name = "connect"]
    fn ws2_connect(s: SOCKET, name: *const SOCKADDR, len: i32) -> i32;
}

// `HOOKPROC` is a function pointer; declare it as a plain fn type.
type HOOKPROC = Option<extern "system" fn(i32, WPARAM, LPARAM) -> LRESULT>;

// ---------------------------------------------------------------------------
// Wire protocol with the engine (`tpinject`). Kept in sync by hand with
// `tpinject::proto` — both sides document the same fixed little-endian layout.
// ---------------------------------------------------------------------------
const MAGIC: u32 = 0x5052_5831; // "PRX1"

/// Control request the injected hook sends to the engine over the named pipe:
/// "I am `pid`, about to connect to `target`; proxy me or leave me alone?"
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Req {
    magic: u32,
    pid: u32,
    family: u16,
    port_be: u16, // target port, network order as the app used it
    addr: [u8; 16], // IPv4 in [0..4]
    proto: u8,
    _pad: [u8; 3],
}

/// Engine's decision.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Resp {
    magic: u32,
    action: u32, // 0 = direct, 1 = proxy
    relay_ip: [u8; 4], // local relay to dial when proxying
    relay_port: u16, // host order
    _pad: u16,
}

const ACTION_PROXY: u32 = 1;
const ACTION_BLOCK: u32 = 2;

/// Fail the current socket op as if the peer refused the connection
/// (WSAECONNREFUSED = 10061) — how a matched "Block" rule is enforced in-hook.
fn refuse_connection() {
    unsafe {
        unsafe extern "system" {
            fn WSASetLastError(e: i32);
        }
        WSASetLastError(10061);
    }
}

// Named objects (our own names, distinct from the original's `enginePE`).
const PIPE_NAME: &str = r"\\.\pipe\tproxierPE";
const PIPE_NAME_DNS: &str = r"\\.\pipe\tproxierDNS";
const ENGINE_MUTEX: &str = "tproxierPE";

/// Multi-instance isolation (see `TPROXIER_INSTANCE`); the injected hook reads
/// the SAME env as the engine so both use a matching private namespace.
fn instance_suffix() -> String {
    match std::env::var("TPROXIER_INSTANCE") {
        Ok(s) if !s.is_empty() => format!("_{s}"),
        _ => String::new(),
    }
}
fn engine_mutex() -> String { format!("{ENGINE_MUTEX}{}", instance_suffix()) }

// ---------------------------------------------------------------------------
// Global hook state.
// ---------------------------------------------------------------------------
static HHOOK_HANDLE: AtomicUsize = AtomicUsize::new(0);
// Original `connect` entry points, reached through the trampoline we build in
// `install_jmp`. Stored as usize to keep it Sync without unsafe globals.
static ORIG_CONNECT: AtomicUsize = AtomicUsize::new(0);
// Same, for `WSAConnect` (used by many modern apps instead of `connect`).
static ORIG_WSACONNECT: AtomicUsize = AtomicUsize::new(0);
static HOOK_INSTALLED: AtomicUsize = AtomicUsize::new(0);

// Address of the real ws2_32 `connect` we hooked, so we know where to jump back.
static REAL_CONNECT_ADDR: AtomicUsize = AtomicUsize::new(0);
// Trampolines for the unconnected-UDP path.
static ORIG_SENDTO: AtomicUsize = AtomicUsize::new(0);
static ORIG_RECVFROM: AtomicUsize = AtomicUsize::new(0);
static ORIG_RECV: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSASENDTO: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSARECVFROM: AtomicUsize = AtomicUsize::new(0);
// Overlapped UDP needs to see IOCP association (WSAIoctl) and socket teardown
// (closesocket) — a pending completion must never touch a freed buffer.
static ORIG_WSAIOCTL: AtomicUsize = AtomicUsize::new(0);
static ORIG_CLOSESOCKET: AtomicUsize = AtomicUsize::new(0);
static ORIG_CREATEIOCPORT: AtomicUsize = AtomicUsize::new(0);
static ORIG_SELECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSAEVENTSELECT: AtomicUsize = AtomicUsize::new(0);
static ORIG_WSAENUMNETWORK: AtomicUsize = AtomicUsize::new(0);

// DNS fake-IP path: getaddrinfo is hooked to hand a whitelisted app a synthetic
// address (so the app then connect()s to it and we map it back to the hostname
// for rules). We LEAK the fake `addrinfo` node we return, and hook freeaddrinfo
// so freeing one of OUR nodes is a no-op — calling the real freeaddrinfo on
// memory we did not allocate from the Winsock heap would corrupt the heap.
static ORIG_GETADDRINFO: AtomicUsize = AtomicUsize::new(0);
static ORIG_FREEADDRINFO: AtomicUsize = AtomicUsize::new(0);
static FAKE_AI_HEADS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<usize>>> = std::sync::OnceLock::new();
fn fake_heads() -> &'static std::sync::Mutex<std::collections::HashSet<usize>> {
    FAKE_AI_HEADS.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// Winsock `ADDRINFOA` (the struct getaddrinfo/freeaddrinfo operate on). Field
/// order/sizes match the platform; `ai_addrlen` is a size_t.
#[repr(C)]
struct AddrInfoA {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: usize,
    ai_canonname: *mut i8,
    ai_addr: *mut SOCKADDR,
    ai_next: *mut AddrInfoA,
}
type GetAddrInfoFn = unsafe extern "system" fn(*const i8, *const i8, *const AddrInfoA, *mut *mut AddrInfoA) -> i32;
type FreeAddrInfoFn = unsafe extern "system" fn(*mut AddrInfoA);


// --- unconnected UDP proxy state (per-process) -----------------------------
// For a socket `s` used with sendto(to), we open a SHADOW connected socket to
// the engine's UDP relay and forward there; replies are read back into an inbox
// that our recvfrom(s) drains. The engine sees each shadow socket's stable
// source address, so its per-flow model is unchanged.
type DstKey = (u16, [u8; 16], u16); // (family, ip bytes, port_be) — IPv4 + IPv6
struct UdpState {
    // (app socket, dst) -> shadow socket connected to the engine relay
    flows: std::collections::HashMap<(SOCKET, DstKey), SOCKET>,
    // app socket -> queued replies (raw sockaddr bytes of the peer, data)
    inbox: std::collections::HashMap<SOCKET, std::sync::Mutex<std::collections::VecDeque<(Vec<u8>, Vec<u8>)>>>,
    // app sockets that have at least one proxied flow (recvfrom must read inbox)
    proxied: std::collections::HashSet<SOCKET>,
    // app socket -> (IOCP handle, completion key) recorded from
    // WSAIoctl(IOCTL_ASSOCIATE_COMPLETION_PORT), so an overlapped completion can
    // be delivered the way the app actually waits for it.
    iocp: std::collections::HashMap<SOCKET, (usize, usize)>,
    // (app socket, OVERLAPPED*) -> alive flag; cleared by closesocket so a
    // deferred completer never writes into a buffer the app has released.
    pending: std::collections::HashMap<(SOCKET, usize), std::sync::Arc<std::sync::atomic::AtomicBool>>,
    // shadow sockets whose app socket closed; retired by their own reader thread
    dead_flows: std::collections::HashSet<SOCKET>,
    // socket whose REAL side is currently being drained by one completer thread,
    // so two pending recvs can't steal each other's datagram
    recv_turn: std::collections::HashSet<SOCKET>,
    // proxied socket -> manual-reset event that is SIGNALED while its inbox holds
    // a datagram. A proxied reply lands in the queue, never on the app socket, so
    // select()/WSAEventSelect() readiness has to be answered from here.
    ready: std::collections::HashMap<SOCKET, RawHandle>,
    // socket -> the event the app registered with WSAEventSelect(FD_READ)
    wsa_events: std::collections::HashMap<SOCKET, RawHandle>,
}
static UDP_STATE: std::sync::OnceLock<std::sync::Mutex<UdpState>> = std::sync::OnceLock::new();
fn udp() -> &'static std::sync::Mutex<UdpState> {
    UDP_STATE.get_or_init(|| std::sync::Mutex::new(UdpState {
        flows: std::collections::HashMap::new(),
        inbox: std::collections::HashMap::new(),
        proxied: std::collections::HashSet::new(),
        iocp: std::collections::HashMap::new(),
        pending: std::collections::HashMap::new(),
        dead_flows: std::collections::HashSet::new(),
        recv_turn: std::collections::HashSet::new(),
        ready: std::collections::HashMap::new(),
        wsa_events: std::collections::HashMap::new(),
    }))
}

const AF_INET_C: i32 = 2;
const SOCK_DGRAM_C: i32 = 2;

/// One-owner gate for the global message hook.
///
/// Five builds of this DLL ended up hooked into the same session at once, and every
/// whitelisted process then carried five stacked inline detours over the same
/// ws2_32 functions - which is what made almost everything crash. Windows does not
/// refuse the second SetWindowsHookExW, so ownership has to be claimed explicitly:
/// a named mutex held for the life of the process that installed the hook. It dies
/// with that process, so a killed engine cannot leave the slot stuck either.
static OWNER_MUTEX: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn claim_hook_ownership() -> bool {
    unsafe extern "system" {
        fn CreateMutexW(sa: *const c_void, initial: i32, name: *const u16) -> *mut c_void;
        fn GetLastError() -> u32;
    }
    const ERROR_ALREADY_EXISTS: u32 = 183;
    let wide: Vec<u16> = "Local\\TpDrvHookOwner".encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = CreateMutexW(std::ptr::null(), 0, wide.as_ptr());
        if h.is_null() {
            return false;
        }
        if GetLastError() == ERROR_ALREADY_EXISTS {
            // someone else owns the hook; do NOT keep our handle open or the slot
            // would be held by a process that never hooked anything
            unsafe extern "system" { fn CloseHandle(h: *mut c_void) -> i32; }
            CloseHandle(h);
            return false;
        }
        OWNER_MUTEX.store(h as usize, Ordering::SeqCst);
        true
    }
}

fn release_hook_ownership() {
    unsafe extern "system" { fn CloseHandle(h: *mut c_void) -> i32; }
    let h = OWNER_MUTEX.swap(0, Ordering::SeqCst);
    if h != 0 {
        unsafe { CloseHandle(h as *mut c_void) };
    }
}

// ---------------------------------------------------------------------------
// The exported installer. Mirrors `InitFilter3` byte-for-byte in intent:
//   SetWindowsHookExW(WH_GETMESSAGE, carrier_proc, hModuleOfThisDll, 0)
// `dwThreadId = 0` makes it a global hook so Windows maps this DLL into every
// process that pumps messages.
// ---------------------------------------------------------------------------
#[unsafe(no_mangle)]
pub extern "system" fn InitFilter3(hmod: HMODULE) -> HHOOK {
    unsafe {
        if !claim_hook_ownership() {
            // A global hook is already installed - by this build or another one.
            // Stacking a second would leave every target process with two inline
            // detours over the same function, so refuse and let the caller report.
            return std::ptr::null_mut();
        }
        let hhk = SetWindowsHookExW(WH_GETMESSAGE, Some(carrier_proc), hmod, 0);
        if (hhk as usize) == 0 {
        }
        HHOOK_HANDLE.store(hhk as usize, Ordering::SeqCst);
        hhk
    }
}

/// Remove the global message hook this DLL installed (called by the engine on
/// Stop). Does not un-socket-hook already-injected processes — those fall back
/// to DIRECT once the engine mutex/pipe is gone (see detour/ask_engine).
#[unsafe(no_mangle)]
pub extern "system" fn KillFilter() {
    unsafe extern "system" {
        fn UnhookWindowsHookEx(hhk: HHOOK) -> BOOL;
    }
    // Free the ownership slot with the hook: an engine that stops must let the
    // next one start, and a slot left held would look like a live route.
    release_hook_ownership();
    let hhk = HHOOK_HANDLE.swap(0, Ordering::SeqCst);
    if hhk != 0 {
        unsafe {
            UnhookWindowsHookEx(hhk as HHOOK);
        }
    }
}

/// The global message-hook procedure. Like the original it does nothing but
/// chain to the next hook — its sole reason to exist is to make the OS load
/// this DLL into target processes. All real work happens in `dll_attach`.
extern "system" fn carrier_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // The only code of ours still running inside an already-injected process once
        // the engine is gone, so it is also how the patch comes back off: the engine
        // bumps the teardown counter and every hooked process restores its own prologues.
        ctl_check_teardown();
    unsafe { CallNextHookEx(HHOOK_HANDLE.load(Ordering::SeqCst) as HHOOK, code, wparam, lparam) }
}

// ---------------------------------------------------------------------------
// DllMain — on process attach, gate on the engine being alive, then install the
// socket hooks (this mirrors sub_18000396e: OpenMutexW gate -> installer).
// ---------------------------------------------------------------------------
const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        ctl_attach();
        // Only a process that will actually host inline ws2_32 detours needs the
        // module pinned. The engine loads the DLL only to call InitFilter3/KillFilter
        // and installs no socket hooks here, so it must NOT be pinned — that lets the
        // engine FreeLibrary its own copy on Stop (releasing the file handle it holds).
        if engine_alive() && !am_engine() && patch_allowed_here() {
            // Pin the module so the OS never unloads it while our hooks are live:
            // bump the load count by re-loading the same image and leaking the ref.
            unsafe extern "system" {
                fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> HMODULE;
                fn GetModuleFileNameW(module: HMODULE, buf: *mut u16, size: u32) -> u32;
            }
            let mut path = [0u16; 1024];
            let n = unsafe { GetModuleFileNameW(hinst, path.as_mut_ptr(), path.len() as u32) };
            if n > 0 {
                unsafe {
                    LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), 0x00000800); // LOAD_LIBRARY_AS_DATAFILE — pins it
                }
            }
            install_socket_hooks();
        }
    }
    TRUE
}

/// The engine (`tpinject`) and the installer (`tphelper`) load this DLL to install
/// the *global message hook*, but must NOT have their OWN sockets redirected —
/// otherwise the engine's outbound connection to the upstream proxy would loop
/// back into its own relay. They set `TPROX_ENGINE=1` in their own process, which
/// a target application (mapped in via the message hook) will not have.
fn am_engine() -> bool {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn GetEnvironmentVariableW(name: *const u16, buf: *mut u16, size: u32) -> u32;
    }
    let name: Vec<u16> = OsStr::new("TPROX_ENGINE").encode_wide().chain(std::iter::once(0)).collect();
    let mut buf = [0u16; 8];
    let n = unsafe { GetEnvironmentVariableW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    n > 0
}

/// OpenMutexW gate: if the engine's named mutex is absent we stay inert (a stray
/// injected DLL must not hijack sockets when the original is not running).
fn engine_alive() -> bool {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn OpenMutexW(desiredAccess: u32, inheritOwner: BOOL, name: *const u16) -> HANDLE;
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let wide: Vec<u16> = OsStr::new(&engine_mutex()).encode_wide().chain(std::iter::once(0)).collect();
    unsafe {
        let h = OpenMutexW(SYNCHRONIZE, 0, wide.as_ptr());
        if h.is_null() {
            false
        } else {
            unsafe extern "system" {
                fn CloseHandle(h: HANDLE) -> BOOL;
            }
            CloseHandle(h);
            true
        }
    }
}

/// Resolve the target socket functions in ws2_32 and place a jmp trampoline over
/// each. Hooks BOTH `connect` and `WSAConnect` so apps that use either are covered.
fn install_socket_hooks() {
    unsafe extern "system" {
        fn LoadLibraryA(name: *const i8) -> HMODULE;
        fn GetProcAddress(module: HMODULE, name: *const i8) -> *const c_void;
    }
    let ws2 = unsafe { LoadLibraryA(c"ws2_32.dll".as_ptr() as *const i8) };
    if ws2.is_null() {
        return;
    }
    unsafe {
        let conn = GetProcAddress(ws2, c"connect".as_ptr() as *const i8);
        if !conn.is_null() {
            REAL_CONNECT_ADDR.store(conn as usize, Ordering::SeqCst);
            let tramp = install_jmp(conn as usize, detour_connect as *const c_void, "connect");
            if tramp != 0 {
                ORIG_CONNECT.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        let wsa = GetProcAddress(ws2, c"WSAConnect".as_ptr() as *const i8);
        if !wsa.is_null() {
            // install_jmp decodes whole prologue instructions (Module Copy) and
            // refuses to split/relocate them; detour_wsaconnect shares the logic.
            let tramp = install_jmp(wsa as usize, detour_wsaconnect as *const c_void, "WSAConnect");
            if tramp != 0 {
                ORIG_WSACONNECT.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        // Unconnected UDP: sendto/recvfrom (games that don't connect() their UDP).
        let sto = GetProcAddress(ws2, c"sendto".as_ptr() as *const i8);
        if !sto.is_null() {
            let tramp = install_jmp(sto as usize, detour_sendto as *const c_void, "sendto");
            if tramp != 0 {
                ORIG_SENDTO.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        let rfo = GetProcAddress(ws2, c"recvfrom".as_ptr() as *const i8);
        if !rfo.is_null() {
            let tramp = install_jmp(rfo as usize, detour_recvfrom as *const c_void, "recvfrom");
            if tramp != 0 {
                ORIG_RECVFROM.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        // std::net UdpSocket::recv calls Winsock `recv` (not recvfrom); a game
        // that reads with recv() must also drain the proxied inbox.
        let rcv = GetProcAddress(ws2, c"recv".as_ptr() as *const i8);
        if !rcv.is_null() {
            let tramp = install_jmp(rcv as usize, detour_recv as *const c_void, "recv");
            if tramp != 0 {
                ORIG_RECV.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        // DNS fake-IP: getaddrinfo + freeaddrinfo as a PAIR (freeaddrinfo must
        // know our leaked nodes or it would free from the wrong heap).
        let gai = GetProcAddress(ws2, c"getaddrinfo".as_ptr() as *const i8);
        if !gai.is_null() {
            let tramp = install_jmp(gai as usize, detour_getaddrinfo as *const c_void, "getaddrinfo");
            if tramp != 0 {
                ORIG_GETADDRINFO.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        let fai = GetProcAddress(ws2, c"freeaddrinfo".as_ptr() as *const i8);
        if !fai.is_null() && ORIG_GETADDRINFO.load(Ordering::SeqCst) != 0 {
            let tramp = install_jmp(fai as usize, detour_freeaddrinfo as *const c_void, "freeaddrinfo");
            if tramp != 0 {
                ORIG_FREEADDRINFO.store(tramp, Ordering::SeqCst);
            }
        }
        // WSA-style unconnected UDP: games/sockets often use WSASendTo/WSARecvFrom
        // instead of sendto/recvfrom; without these the same app's UDP escapes the
        // proxy. Reuses the shadow-socket (send) / inbox (recv) machinery.
        let wsto = GetProcAddress(ws2, c"WSASendTo".as_ptr() as *const i8);
        if !wsto.is_null() {
            let tramp = install_jmp(wsto as usize, detour_wsasendto as *const c_void, "WSASendTo");
            if tramp != 0 {
                ORIG_WSASENDTO.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        let wrfo = GetProcAddress(ws2, c"WSARecvFrom".as_ptr() as *const i8);
        if !wrfo.is_null() {
            let tramp = install_jmp(wrfo as usize, detour_wsarecvfrom as *const c_void, "WSARecvFrom");
            if tramp != 0 {
                ORIG_WSARECVFROM.store(tramp, Ordering::SeqCst);
                HOOK_INSTALLED.store(1, Ordering::SeqCst);
            }
        }
        // Overlapped UDP needs the IOCP association (to post the completion where
        // the app polls) and socket teardown (to abort pending completions).
        let wiop = GetProcAddress(ws2, c"WSAIoctl".as_ptr() as *const i8);
        if !wiop.is_null() {
            let tramp = install_jmp(wiop as usize, detour_wsaioclt as *const c_void, "WSAIoctl");
            if tramp != 0 {
                ORIG_WSAIOCTL.store(tramp, Ordering::SeqCst);
            }
        }
        // select()/WSAEventSelect()/WSAEnumNetworkEvents(): readiness for a socket
        // whose replies live in the hook inbox.
        let wsel = GetProcAddress(ws2, c"WSAEventSelect".as_ptr() as *const i8);
        if !wsel.is_null() {
            let tramp = install_jmp(wsel as usize, detour_wsaeventselect as *const c_void, "WSAEventSelect");
            if tramp != 0 {
                ORIG_WSAEVENTSELECT.store(tramp, Ordering::SeqCst);
            }
        }
        let wenu = GetProcAddress(ws2, c"WSAEnumNetworkEvents".as_ptr() as *const i8);
        if !wenu.is_null() {
            let tramp = install_jmp(wenu as usize, detour_wsaenumnetworkevents as *const c_void, "WSAEnumNetworkEvents");
            if tramp != 0 {
                ORIG_WSAENUMNETWORK.store(tramp, Ordering::SeqCst);
            }
        }
        let wsel2 = GetProcAddress(ws2, c"select".as_ptr() as *const i8);
        if !wsel2.is_null() {
            let tramp = install_jmp(wsel2 as usize, detour_select as *const c_void, "select");
            if tramp != 0 {
                ORIG_SELECT.store(tramp, Ordering::SeqCst);
            }
        }
        let k32 = LoadLibraryA(c"kernel32.dll".as_ptr() as *const i8);
        let ciop = GetProcAddress(k32, c"CreateIoCompletionPort".as_ptr() as *const i8);
        if !ciop.is_null() {
            let tramp = install_jmp(ciop as usize, detour_createiocport as *const c_void, "CreateIoCompletionPort");
            if tramp != 0 {
                ORIG_CREATEIOCPORT.store(tramp, Ordering::SeqCst);
            }
        }
        let cso = GetProcAddress(ws2, c"closesocket".as_ptr() as *const i8);
        if !cso.is_null() {
            let tramp = install_jmp(cso as usize, detour_closesocket as *const c_void, "closesocket");
            if tramp != 0 {
                ORIG_CLOSESOCKET.store(tramp, Ordering::SeqCst);
            }
        }
    }
}

/// Prologue bytes an unconditional absolute jump needs on this architecture.
#[cfg(target_arch = "x86_64")]
const PATCH_LEN: usize = 14; // FF 25 00000000 <addr:u64>  (jmp [rip+0])
#[cfg(target_arch = "x86")]
const PATCH_LEN: usize = 6; // 68 <addr:u32> C3           (push imm32 ; ret)

/// Prologue bytes a near unconditional jump needs: `E9 rel32`, the same length on both
/// architectures. Cheaper than PATCH_LEN, and often the difference between hooking an
/// export and refusing it.
const REL_PATCH_LEN: usize = 5;

/// Emit a position-independent absolute jump to `dest` into `at` (PATCH_LEN bytes).
unsafe fn write_abs_jmp(at: *mut u8, dest: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        core::ptr::write(at as *mut u16, 0x25FF);
        core::ptr::write(at.add(2) as *mut u32, 0);
        core::ptr::write(at.add(6) as *mut u64, dest as u64);
    }
    #[cfg(target_arch = "x86")]
    {
        core::ptr::write(at, 0x68); // push imm32
        core::ptr::write(at.add(1) as *mut u32, dest as u32);
        core::ptr::write(at.add(5), 0xC3); // ret
    }
}

/// Emit `jmp rel32` to `dest` at `at` (REL_PATCH_LEN bytes). The caller has already
/// proved the displacement fits an i32.
unsafe fn write_rel_jmp(at: *mut u8, dest: usize) {
    let rel = (dest as isize) - (at as isize + REL_PATCH_LEN as isize);
    core::ptr::write(at, 0xE9);
    core::ptr::write(at.add(1) as *mut i32, rel as i32);
}

/// Install an absolute-jmp detour at `target` pointing to `detour`, returning the
/// address of a freshly built executable trampoline (displaced whole
/// instructions + a jump back), or 0 on any problem — in which case the target
/// is left UNMODIFIED. This is the "Module Copy" idea (fnd_7): the prologue is
/// decoded instruction-by-instruction so we never split an instruction, and
/// near-relative branches we cannot relocate cause a safe refusal instead.
/// Trace hook installation to the process' stderr — the live test runs with
/// --nocapture, so a refused detour becomes visible instead of silently leaving
/// an API un-hooked.
unsafe fn hook_dbg(msg: &str) {
    if std::env::var("TPROXIER_HOOK_DEBUG").is_err() {
        return;
    }
    unsafe extern "system" {
        fn GetStdHandle(which: i32) -> *mut c_void;
        fn WriteFile(h: *mut c_void, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> i32;
    }
    let h = GetStdHandle(-12); // STD_ERROR_HANDLE
    if h.is_null() || h == (-1isize as *mut c_void) {
        return;
    }
    let mut written = 0u32;
    WriteFile(h, msg.as_ptr(), msg.len() as u32, &mut written, std::ptr::null_mut());
}

/// Reserve an executable trampoline page. When the displaced prologue carries a
/// RIP-relative operand, the copy must land within ±2 GiB of `target` or the
/// correction cannot be expressed in its disp32 — so scan nearby first instead of
/// taking whatever address the allocator offers (which is often 10+ GiB away).
unsafe fn alloc_trampoline_near(target: usize, size: usize, need_near: bool) -> *mut c_void {
    unsafe extern "system" {
        fn VirtualAlloc(addr: *const c_void, size: usize, alloc_type: u32, protect: u32) -> *mut c_void;
    }
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    let commit = |hint: usize| -> *mut c_void {
        VirtualAlloc(hint as *const c_void, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    let in_range = |p: *mut c_void| -> bool {
        let d = p as isize - target as isize;
        d > i32::MIN as isize && d < i32::MAX as isize
    };
    if !need_near {
        return commit(0);
    }
    // Loader gaps next to each module make a hit within a few steps likely.
    for step in 1..512usize {
        let delta = step * 0x10000;
        if target > delta {
            let p = commit((target - delta) & !0xFFFF);
            if !p.is_null() && in_range(p) {
                return p;
            }
        }
        let p = commit((target + delta) & !0xFFFF);
        if !p.is_null() && in_range(p) {
            return p;
        }
    }
    let p = commit(0);
    if !p.is_null() && in_range(p) {
        p
    } else {
        std::ptr::null_mut()
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Patch ledger, the control block, and the removal path
//
// Until now this DLL patched ws2_32 in every process the global message hook
// mapped it into (the only gate was "engine alive") and never saved the bytes it
// destroyed - so the only way back for a patched app was to restart it. That is
// how an operator ended up with 92 injected apps, 65 of them carrying five copies
// at once. Three pieces make the modification both narrow and reversible:
//   * a ledger of (target, length, original bytes), filled in by install_jmp;
//   * a control block the engine owns, naming the executables we may touch and
//     counting teardown requests;
//   * carrier_proc as the removal channel, because it is the only code of ours
//     that still runs inside an already-injected process.
// ══════════════════════════════════════════════════════════════════════════

/// Largest window install_jmp ever displaces (a decoded instruction boundary can
/// exceed the 14-byte patch), which is also why `orig` is sized from it.
const ORIG_MAX: usize = 64;
const LEDGER_MAX: usize = 32;

#[derive(Clone, Copy)]
struct Patched {
    target: usize,
    len: usize,
    orig: [u8; ORIG_MAX],
    name: &'static str,
}

static LEDGER: std::sync::Mutex<[Option<Patched>; LEDGER_MAX]> =
    std::sync::Mutex::new([None; LEDGER_MAX]);

/// `Local\TpDrvCtl`. The engine creates it before it hooks anything, so a mapped copy
/// sees either a complete list or no block at all - never a half-written one.
#[repr(C)]
struct Ctl {
    /// Bumped by the engine when every injected process should restore ws2_32.
    teardown: u32,
    /// Used length of `apps`: a ';' separated list of lowercased exe names, or the
    /// single character `*` when the operator deliberately turned the program
    /// whitelist off.
    apps_len: u32,
    apps: [u16; 1024],
}

/// Named per engine instance, exactly like the pipes and the engine mutex. A single
/// session-wide name let one engine's whitelist silently disable patching in every
/// other process that loaded this DLL - including a test that has its own engine.
fn ctl_name() -> String { format!("Local\\TpDrvCtl{}", instance_suffix()) }

static CTL_VIEW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static SEEN_TEARDOWN: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LAST_CTL_CHECK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn record_patch(target: usize, len: usize, name: &'static str) {
    if len > ORIG_MAX {
        return;
    }
    let mut p = [0u8; ORIG_MAX];
    unsafe {
        core::ptr::copy_nonoverlapping(target as *const u8, p.as_mut_ptr(), len);
    }
    if let Ok(mut g) = LEDGER.lock() {
        for slot in g.iter_mut() {
            if slot.is_none() {
                *slot = Some(Patched {
                    target,
                    len,
                    orig: p,
                    name,
                });
                return;
            }
        }
    }
}

/// Write every prologue this copy overwrote back, exactly. Trampolines are deliberately
/// leaked: freeing pages that another thread may still be about to return into is a
/// worse trade than a few pages held for the life of the process.
fn restore_all() -> usize {
    unsafe extern "system" {
        fn VirtualProtect(addr: *mut c_void, size: usize, protect: u32, old: *mut u32) -> i32;
        fn FlushInstructionCache(h: *mut c_void, addr: *const c_void, size: usize) -> i32;
        fn GetCurrentProcess() -> *mut c_void;
    }
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    let mut todo: [Option<Patched>; LEDGER_MAX] = [None; LEDGER_MAX];
    if let Ok(mut g) = LEDGER.lock() {
        std::mem::swap(&mut *g, &mut todo);
    }
    let mut done = 0usize;
    for e in todo.iter_mut() {
        let Some(p) = e else { continue };
        let mut old = 0u32;
        if unsafe { VirtualProtect(p.target as *mut c_void, p.len, PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
            continue;
        }
        unsafe {
            core::ptr::copy_nonoverlapping(p.orig.as_ptr(), p.target as *mut u8, p.len);
            let mut tmp = 0u32;
            VirtualProtect(p.target as *mut c_void, p.len, old, &mut tmp);
            FlushInstructionCache(GetCurrentProcess(), p.target as *const c_void, p.len);
        }
        unsafe { hook_dbg(&format!("tpdrv: restored {} prologue\n", p.name)); }
        done += 1;
    }
    done
}

/// Explicit removal entry point. The engine normally bumps the teardown counter
/// instead, because it has no handle on the processes the hook already mapped.
/// Returns how many patches came off.
#[unsafe(no_mangle)]
pub extern "system" fn TpdrvRemove() -> u32 {
    restore_all() as u32
}

/// How many prologues this copy still has overwritten - so a test can prove removal
/// actually happened rather than trusting that a call was made.
#[unsafe(no_mangle)]
pub extern "system" fn TpdrvPatchedCount() -> u32 {
    LEDGER
        .lock()
        .map(|g| g.iter().filter(|s| s.is_some()).count() as u32)
        .unwrap_or(0)
}

fn ctl_attach() {
    unsafe extern "system" {
        fn OpenFileMappingW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
        fn MapViewOfFile(h: *mut c_void, access: u32, off_hi: u32, off_lo: u32, bytes: usize) -> *mut c_void;
    }
    const FILE_MAP_READ: u32 = 4;
    let name = ctl_name();
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let h = OpenFileMappingW(FILE_MAP_READ, 0, wide.as_ptr());
        if h.is_null() {
            return; // no control block: an older engine, so behave as before
        }
        let v = MapViewOfFile(h, FILE_MAP_READ, 0, 0, std::mem::size_of::<Ctl>());
        if !v.is_null() {
            CTL_VIEW.store(v as usize, Ordering::SeqCst);
        }
    }
}

/// (teardown counter, app list). A `None` list means there is no control block.
fn ctl_read() -> (u32, Option<String>) {
    let v = CTL_VIEW.load(Ordering::SeqCst);
    if v == 0 {
        return (0, None);
    }
    let c = unsafe { &*(v as *const Ctl) };
    let n = (c.apps_len as usize).min(c.apps.len());
    (c.teardown, Some(String::from_utf16_lossy(&c.apps[..n])))
}

fn own_exe_name() -> String {
    unsafe extern "system" {
        fn GetModuleFileNameW(m: *mut c_void, buf: *mut u16, size: u32) -> u32;
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 {
        return String::new();
    }
    let full = String::from_utf16_lossy(&buf[..n as usize]);
    let seps = ['\\', '/'];
    full.split(seps.as_slice())
        .next_back()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Whether ws2_32 may be modified in this process at all.
///
/// With a control block present the default is NO: a process the engine did not name
/// is left byte for byte untouched. That is the point - the price of an injected
/// detour is the host's stability, and "patch everything" spent it on ~90 processes
/// that were never meant to be proxied.
/// The comparison alone, so its semantics are testable without a control block or a
/// second process. `*` is the operator's own "no scope" decision; every other entry
/// must name this image exactly, or as the file part of a full path.
fn name_in_list(list: &str, me: &str) -> bool {
    let list = list.trim().to_ascii_lowercase();
    if list == "*" {
        return true;
    }
    if me.is_empty() {
        return false;
    }
    // An entry is either a bare image name or a full path; matching the path form has
    // to include the separator, or "notfirefox.exe" would satisfy "...firefox.exe".
    let path_suffix = format!("\\{me}");
    list.split(';').any(|a| {
        let t = a.trim();
        !t.is_empty() && (t == me || t.ends_with(path_suffix.as_str()))
    })
}

fn patch_allowed_here() -> bool {
    let (_, apps) = ctl_read();
    match apps {
        // no control block: an older engine, so behave as before
        None => true,
        Some(list) => name_in_list(&list, &own_exe_name()),
    }
}

/// The message-hook thunk runs for every retrieved message in the host process, so the
/// control block is read at most once a second: the cheapest thing that still notices
/// a stop promptly.
const CTL_POLL_MS: u64 = 1000;

fn ctl_check_teardown() {
    unsafe extern "system" {
        fn GetTickCount64() -> u64;
    }
    let now = unsafe { GetTickCount64() };
    let last = LAST_CTL_CHECK.load(Ordering::Relaxed);
    if now.saturating_sub(last) < CTL_POLL_MS {
        return;
    }
    LAST_CTL_CHECK.store(now, Ordering::Relaxed);
    let (teardown, _) = ctl_read();
    let seen = SEEN_TEARDOWN.load(Ordering::Relaxed);
    if teardown != seen {
        SEEN_TEARDOWN.store(teardown, Ordering::Relaxed);
        if teardown > 0 {
            restore_all();
        }
    }
}

#[cfg(test)]
mod ctl_tests {
    use super::*;

    unsafe fn fill(page: *mut c_void, bytes: &[u8]) {
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), page as *mut u8, bytes.len()) };
    }

    #[test]
    fn the_ledger_round_trips_a_prologue_and_removal_empties_it() {
        // A private executable page stands in for a function prologue, so this proves
        // record/restore byte for byte without patching a real system DLL.
        unsafe extern "system" {
            fn VirtualAlloc(addr: *const c_void, size: usize, alloc: u32, protect: u32) -> *mut c_void;
            fn VirtualFree(addr: *const c_void, size: usize, free: u32) -> i32;
        }
        const MEM_COMMIT_RESERVE: u32 = 0x3000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const MEM_RELEASE: u32 = 0x8000;
        let page =
            unsafe { VirtualAlloc(std::ptr::null_mut(), 4096, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE) };
        assert!(!page.is_null(), "no executable page to test against");
        let orig: [u8; 8] = [0x48, 0x89, 0x5c, 0x24, 0x10, 0x57, 0x48, 0x83];
        unsafe { fill(page, &orig) };

        record_patch(page as usize, 8, "test-prologue");
        assert_eq!(TpdrvPatchedCount(), 1, "the ledger must record what was patched");

        // scribble a jmp patch over it the way install_jmp does, then take it off
        unsafe {
            core::ptr::write(page as *mut u8, 0xE9);
            core::ptr::write(page.add(5) as *mut u8, 0xCC);
        }
        assert_eq!(restore_all(), 1, "restore must report the one entry");
        let after = unsafe { std::slice::from_raw_parts(page as *const u8, 8) };
        assert_eq!(after, &orig, "the prologue must come back byte for byte");
        assert_eq!(TpdrvPatchedCount(), 0, "the ledger must be empty after removal");

        // inverse of every rule: removing twice must be a no-op, not a second write
        assert_eq!(restore_all(), 0, "a second removal must restore nothing");
        unsafe {
            VirtualFree(page, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn our_own_image_name_resolves() {
        // patch_allowed_here is only as good as this: without a name nothing can match,
        // and an empty name must therefore mean "refuse", never "allow".
        let me = own_exe_name();
        assert!(me.ends_with(".exe"), "unexpected exe name {me:?}");
        assert!(!me.contains('\\'), "should be the file name only: {me:?}");
        assert!(!name_in_list("firefox.exe", ""), "an unknown image must not be allowed");
    }

    #[test]
    fn only_named_images_may_be_patched() {
        assert!(name_in_list("firefox.exe;chrome.exe", "firefox.exe"));
        assert!(!name_in_list("chrome.exe", "firefox.exe"), "unlisted stays untouched");
        // the engine may publish full paths instead of bare names
        assert!(name_in_list("c:\\program files\\mozilla firefox\\firefox.exe", "firefox.exe"));
        assert!(
            !name_in_list("c:\\tools\\notfirefox.exe", "firefox.exe"),
            "a path must match on a whole component, not a suffix"
        );
        // the operator's explicit "no scope" is honoured, and only when spelled exactly
        assert!(name_in_list("*", "anything.exe"));
        assert!(
            !name_in_list("", "anything.exe"),
            "an empty list means nothing is whitelisted, not everything"
        );
        // case: the engine lowercases, but a hand-written entry should still work
        assert!(name_in_list("Firefox.exe", "firefox.exe"));
    }
}

unsafe fn install_jmp(target: usize, detour: *const c_void, name: &'static str) -> usize {

    // 1. Decode whole instructions from the prologue until they can fit PATCH_LEN.
    //    Returns 0 (leaving the target untouched) if anything is undecodable or a
    //    near-relative branch would have to be relocated.
    let window = core::slice::from_raw_parts(target as *const u8, 64);
    // Three ways in, cheapest refusal last. `freeaddrinfo` is the concrete case: its
    // prologue is `48 85 c9` (test rcx,rcx) + `74 56` (je +0x56), so a near-relative
    // branch sits inside the first FIVE bytes — neither the 14-byte absolute patch nor
    // the 5-byte relative one can be stolen verbatim. Widening that `je` to
    // `0F 84 disp32` on the way into the trampoline is what makes the export hookable,
    // and with it the freeaddrinfo half of the getaddrinfo pair (see detour_getaddrinfo).
    let room = (detour as isize) - (target as isize + REL_PATCH_LEN as isize);
    let rel_reachable = room >= i32::MIN as isize && room <= i32::MAX as isize;
    let (off, fixups, patch_len, widen) = match decode::displace(window, PATCH_LEN) {
        Some((o, f)) => (o, f, PATCH_LEN, Vec::new()),
        // A window needing BOTH widening and RIP correction is refused rather than
        // handled: the offset bookkeeping for that combination is not worth the risk
        // when the prologues that matter have one or the other.
        None => match decode::displace_widenable(window, PATCH_LEN) {
            Some((o, f, b)) if f.is_empty() => (o, f, PATCH_LEN, b),
            _ => match decode::displace(window, REL_PATCH_LEN) {
                Some((o, f)) if rel_reachable => (o, f, REL_PATCH_LEN, Vec::new()),
                _ => {
                    hook_dbg(&format!(
                        "install_jmp({name}@{target:#x}): decode refused (a prologue we would \
                         have to split or relocate, and no 5-byte jmp reaches)\n"
                    ));
                    return 0;
                }
            },
        },
    };

    // 2. Reserve+commit an executable RWX page for the trampoline. A displaced
    //    `[rip+disp32]` only survives the move when the copy stays within ±2 GiB
    //    of the original, so demand a nearby page whenever the prologue has one.
    //    The trampoline's own return jump is always the ABSOLUTE form, so it is sized
    //    from PATCH_LEN even when the detour we install is the 5-byte relative one;
    //    each widened branch costs 4 extra bytes (rel8 → rel32).
    //
    //    Proximity is demanded for a widened branch too, and not just for RIP operands:
    //    a rel32 can only span ±2 GiB, so on a far page the re-encoded `jcc` cannot
    //    address its own original target and the install has to decline (this is what
    //    silently un-hooked freeaddrinfo the first time — the trace line above the
    //    fallible step made it look like it had succeeded).
    let need_bytes = off + 4 * widen.len() + PATCH_LEN + 8;
    let must_be_near = !fixups.is_empty() || !widen.is_empty();
    let tramp = alloc_trampoline_near(target, need_bytes, must_be_near) as *mut u8;
    if tramp.is_null() {
        hook_dbg(&format!("install_jmp({name}@{target:#x}): no trampoline, rip={}
", fixups.len()));
        return 0;
    }
    hook_dbg(&format!("install_jmp({name}@{target:#x}): off={off} patch={patch_len} rip={} tramp={tramp:#p}
", fixups.len()));

    // 3. Trampoline = the `off` displaced bytes, then jmp back to target+off. Stolen
    //    short branches are re-encoded as their rel32 form on the way in, because a
    //    2-byte displacement cannot address the original target from another page.
    if widen.is_empty() {
        core::ptr::copy_nonoverlapping(target as *const u8, tramp, off);
        #[cfg(target_arch = "x86_64")]
        {
            // next-IP shifts by exactly (target - tramp), so every RIP-relative
            // displacement is corrected by the same amount.
            let delta = target as isize - tramp as isize;
            if !fixups.is_empty() && (delta > i32::MAX as isize || delta < i32::MIN as isize) {
                return 0; // too far to re-encode a disp32: decline, don't corrupt memory
            }
            for f in &fixups {
                let at = tramp.add(f.disp_at) as *mut i32;
                let old = core::ptr::read_unaligned(at);
                core::ptr::write_unaligned(at, old.wrapping_add(delta as i32));
            }
        }
        write_abs_jmp(tramp.add(off), target + off);
    } else {
        let mut read = 0usize;
        let mut w = 0usize;
        for b in &widen {
            core::ptr::copy_nonoverlapping((target + read) as *const u8, tramp.add(w), b.at - read);
            w += b.at - read;
            // where this branch really goes, and the wider encoding that gets there
            let abs = (target + b.insn_end) as isize + b.rel as isize;
            let at = tramp.add(w);
            let width = if b.unconditional { 5 } else { 6 };
            if b.unconditional {
                core::ptr::write(at, 0xE9); // jmp rel32
            } else {
                core::ptr::write(at, 0x0F); // jcc rel32
                core::ptr::write(at.add(1), 0x80 + b.cc);
            }
            let rel = abs - (at as isize + width as isize);
            if rel > i32::MAX as isize || rel < i32::MIN as isize {
                hook_dbg(&format!(
                    "install_jmp({name}@{target:#x}): widened branch cannot reach from \
                     {tramp:#p} — declining, never truncating a displacement\n"
                ));
                return 0; // widened form still cannot reach: decline, never truncate
            }
            core::ptr::write(at.add(width - 4) as *mut i32, rel as i32);
            w += width;
            read = b.insn_end;
        }
        core::ptr::copy_nonoverlapping((target + read) as *const u8, tramp.add(w), off - read);
        w += off - read;
        write_abs_jmp(tramp.add(w), target + off);
    }

    // Keep the bytes we are about to destroy. Without this the only way to give a
    // patched process its original code back is to restart it - which is exactly what
    // left 92 apps needing a relaunch.
    record_patch(target, off, name);

    // 4. Overwrite the target's first patch_len bytes with jmp-to-detour; pad the
    //    remaining displaced bytes (off-patch_len) with INT3 so stray exec traps.
    let mut old = 0u32;
    if VirtualProtect(target as *mut c_void, off, PAGE_EXECUTE_READWRITE, &mut old) != TRUE {
        return 0;
    }
    if patch_len == REL_PATCH_LEN {
        write_rel_jmp(target as *mut u8, detour as usize);
    } else {
        write_abs_jmp(target as *mut u8, detour as usize);
    }
    for k in patch_len..off {
        core::ptr::write((target + k) as *mut u8, 0xCC);
    }
    let mut tmp = 0u32;
    VirtualProtect(target as *mut c_void, off, old, &mut tmp);

    tramp as usize
}

// ---------------------------------------------------------------------------
// The `connect` / `WSAConnect` detours.
// ---------------------------------------------------------------------------
type ConnectFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, i32) -> i32;

#[repr(C)]
struct WSABUF {
    len: u32,
    buf: *mut i8,
}
type WsaConnectFn = unsafe extern "system" fn(
    SOCKET,
    *const SOCKADDR,
    i32,
    *const WSABUF,
    *mut WSABUF,
    *const c_void,
    *const c_void,
) -> i32;

/// (getsockopt result, SO_TYPE value) for diagnostics + datagram detection.
unsafe fn sock_type(s: SOCKET) -> (i32, i32) {
    unsafe extern "system" {
        fn getsockopt(
            s: SOCKET,
            level: i32,
            optname: i32,
            optval: *mut i8,
            optlen: *mut i32,
        ) -> i32;
    }
    let mut ty: i32 = 0;
    let mut len = 4i32;
    let r = getsockopt(s, SOL_SOCKET, SO_TYPE, &mut ty as *mut i32 as *mut i8, &mut len);
    (r, ty)
}

/// Shared decision used by both detours. On a PROXY verdict the socket `s` is
/// connected to the engine relay via `dial` and the target header is stamped;
/// returns Some(result) to be handed back to the app. Returns None when the
/// connection is not proxified (non-IPv4, engine says direct, or engine absent),
/// so the caller invokes the pristine function unchanged.
unsafe fn intercept_impl<D: FnMut(*const SOCKADDR, i32) -> i32>(
    s: SOCKET,
    name: *const SOCKADDR,
    len: i32,
    mut dial: D,
) -> Option<i32> {
    if name.is_null() {
        return None;
    }
    let family = unsafe { (*(name as *const SOCKADDR)).sa_family };
    if family != AF_INET && family != AF_INET6 {
        return None; // IPv4 + IPv6 handled; other families pass through
    }
    let (port_be, addr): (u16, [u8; 16]) = if family == AF_INET {
        if len < std::mem::size_of::<SOCKADDR_IN>() as i32 {
            return None;
        }
        let sin = &*(name as *const SOCKADDR_IN);
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&sin.sin_addr);
        (sin.sin_port, a)
    } else {
        if len < std::mem::size_of::<SOCKADDR_IN6>() as i32 {
            return None;
        }
        let sin6 = &*(name as *const SOCKADDR_IN6);
        (sin6.sin6_port, sin6.sin6_addr)
    };
    // Connected UDP (games) goes through connect() too; detect the socket type so
    // we tag proto 17 and the engine hands back its UDP relay endpoint.
    let (gs_r, gs_ty) = sock_type(s);
    let _ = (gs_r, gs_ty);
    let proto = if gs_r == 0 && gs_ty == SOCK_DGRAM { IPPROTO_UDP } else { IPPROTO_TCP };
    // Connected IPv6 UDP is proxied like IPv4: the engine's UDP relay is dual-stack
    // ([::] with V6ONLY off), and the `family == AF_INET6` connect branch below
    // dials it via [::1]:relay_port. (It used to bail to direct because the relay
    // was IPv4-only and a V6ONLY socket cannot connect to a v4-mapped peer.)
    let req = Req {
        magic: MAGIC,
        pid: GetCurrentProcessId(),
        family,
        port_be,
        addr,
        proto,
        // _pad[0]=1 marks this as a CONNECT() flow, so the engine routes
        // connected IPv6 UDP to the [::1] relay (vs the v4 shadow for sendto).
        _pad: [1, 0, 0],
    };
    match ask_engine(req) {
        Some(resp) if resp.action == ACTION_PROXY => {
            // The engine runs a dedicated IPv6-loopback relay on [::1] for v6
            // clients (std's AF_INET6 sockets are V6ONLY, so a v4-mapped address
            // would fail WSAEADDRNOTAVAIL). v4 clients use the 127.0.0.1 relay.
            let r = if family == AF_INET6 {
                let mut a6 = [0u8; 16];
                a6[15] = 1; // ::1
                let relay6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: resp.relay_port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: a6,
                    sin6_scope_id: 0,
                };
                dial(
                    &relay6 as *const SOCKADDR_IN6 as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN6>() as i32,
                )
            } else {
                let relay = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: resp.relay_port.to_be(),
                    sin_addr: resp.relay_ip,
                    sin_zero: [0; 8],
                };
                dial(
                    &relay as *const SOCKADDR_IN as *const SOCKADDR,
                    std::mem::size_of::<SOCKADDR_IN>() as i32,
                )
            };
            // A non-blocking client (browsers call connect() on a non-blocking
            // socket) gets WSAEWOULDBLOCK: the relay connect is still in progress,
            // so the socket is NOT connected yet. Sending the in-band Req header now
            // would fail and the app's first bytes (e.g. a TLS ClientHello) would hit
            // the relay with no header → the relay misreads them as a bad magic. Wait
            // for the connect to finish, THEN stamp the header.
            let mut rr = r;
            if rr == -1 {
                unsafe extern "system" {
                    fn WSAGetLastError() -> i32;
                }
                if WSAGetLastError() == 10035 /* WSAEWOULDBLOCK */ {
                    rr = await_connect(s, 5000);
                }
            }
            if rr != -1 {
                send_header(s, req);
            }
            Some(rr)
        }
        Some(resp) if resp.action == ACTION_BLOCK => {
            // Block rule: refuse the connection (WSAECONNREFUSED) so nothing leaks
            // direct and nothing is proxified — mirrors the original's "Block" action.
            refuse_connection();
            Some(-1)
        }
        _ => None,
    }
}

extern "system" fn detour_connect(s: SOCKET, name: *const SOCKADDR, len: i32) -> i32 {
    unsafe {
        match intercept(s, name, len, |n, l| call_real_connect(s, n, l)) {
            Some(r) => r,
            None => call_real_connect(s, name, len),
        }
    }
}

extern "system" fn detour_wsaconnect(
    s: SOCKET,
    name: *const SOCKADDR,
    len: i32,
    caller: *const WSABUF,
    callee: *mut WSABUF,
    gq: *const c_void,
    sq: *const c_void,
) -> i32 {
    unsafe {
        match intercept(s, name, len, |n, l| {
            call_real_wsaconnect(s, n, l, caller, callee, gq, sq)
        }) {
            Some(r) => r,
            None => call_real_wsaconnect(s, name, len, caller, callee, gq, sq),
        }
    }
}

/// Call the pristine `connect` through the trampoline built by `install_jmp`.
unsafe fn call_real_connect(s: SOCKET, name: *const SOCKADDR, len: i32) -> i32 {
    let addr = ORIG_CONNECT.load(Ordering::SeqCst);
    if addr != 0 {
        let f: ConnectFn = std::mem::transmute(addr);
        f(s, name, len)
    } else {
        -1
    }
}

/// Call the pristine `WSAConnect` through its trampoline.
unsafe fn call_real_wsaconnect(
    s: SOCKET,
    name: *const SOCKADDR,
    len: i32,
    caller: *const WSABUF,
    callee: *mut WSABUF,
    gq: *const c_void,
    sq: *const c_void,
) -> i32 {
    let addr = ORIG_WSACONNECT.load(Ordering::SeqCst);
    if addr != 0 {
        let f: WsaConnectFn = std::mem::transmute(addr);
        f(s, name, len, caller, callee, gq, sq)
    } else {
        -1
    }
}

type SendToFn = unsafe extern "system" fn(SOCKET, *const i8, i32, i32, *const SOCKADDR, i32) -> i32;
type RecvFromFn = unsafe extern "system" fn(SOCKET, *mut i8, i32, i32, *mut SOCKADDR, *mut i32) -> i32;
type RecvFn = unsafe extern "system" fn(SOCKET, *mut i8, i32, i32) -> i32;
unsafe fn call_real_sendto(s: SOCKET, b: *const i8, l: i32, f: i32, to: *const SOCKADDR, tl: i32) -> i32 {
    let a = ORIG_SENDTO.load(Ordering::SeqCst);
    if a != 0 { let g: SendToFn = std::mem::transmute(a); g(s, b, l, f, to, tl) } else { -1 }
}
unsafe fn call_real_recvfrom(s: SOCKET, b: *mut i8, l: i32, f: i32, from: *mut SOCKADDR, fl: *mut i32) -> i32 {
    let a = ORIG_RECVFROM.load(Ordering::SeqCst);
    if a != 0 { let g: RecvFromFn = std::mem::transmute(a); g(s, b, l, f, from, fl) } else { -1 }
}
unsafe fn call_real_recv(s: SOCKET, b: *mut i8, l: i32, f: i32) -> i32 {
    let a = ORIG_RECV.load(Ordering::SeqCst);
    if a != 0 { let g: RecvFn = std::mem::transmute(a); g(s, b, l, f) } else { -1 }
}

/// Proxify an UNCONNECTED datagram `sendto` (IPv4 or IPv6 destination) by
/// forwarding through a per-(socket,dst) **IPv4 shadow socket** connected to the
/// engine's UDP relay — the real (v4 or v6) destination travels in the Req header
/// and the SOCKS5 UDP frame, so no IPv6 socket is needed here. Returns Some(ret)
/// when handled, None when the caller should use the pristine sendto (non-UDP,
/// loopback, non-IP family, engine says direct, or absent).
unsafe fn udp_send_impl(s: SOCKET, buf: *const i8, len: i32, flags: i32, to: *const SOCKADDR, tolen: i32) -> Option<i32> {
    if to.is_null() { return None; }
    let family = (*(to as *const SOCKADDR)).sa_family;
    if family != AF_INET && family != AF_INET6 { return None; }
    let (r, ty) = sock_type(s);
    if r != 0 || ty != SOCK_DGRAM { return None; }
    // Normalise the destination to 16 bytes + capture the peer sockaddr for replies.
    let (addr, port_be): ([u8; 16], u16) = if family == AF_INET {
        if tolen < std::mem::size_of::<SOCKADDR_IN>() as i32 { return None; }
        let sin = &*(to as *const SOCKADDR_IN);
        if sin.sin_addr[0] == 127 { return None; } // loopback stays direct
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&sin.sin_addr);
        (a, sin.sin_port)
    } else {
        if tolen < std::mem::size_of::<SOCKADDR_IN6>() as i32 { return None; }
        let sin6 = &*(to as *const SOCKADDR_IN6);
        // ::1 (loopback) stays direct.
        let is_loopback = sin6.sin6_addr[..15].iter().all(|&b| b == 0) && sin6.sin6_addr[15] == 1;
        if is_loopback { return None; }
        (sin6.sin6_addr, sin6.sin6_port)
    };
    let dst: DstKey = (family, addr, port_be);
    // Reconstruct the peer sockaddr (v4 or v6) so the app's recvfrom sees the
    // right family + length on replies.
    let reply_addr: Vec<u8> = if family == AF_INET {
        let sa = SOCKADDR_IN { sin_family: AF_INET, sin_port: port_be, sin_addr: [addr[0], addr[1], addr[2], addr[3]], sin_zero: [0; 8] };
        unsafe { std::slice::from_raw_parts(&sa as *const SOCKADDR_IN as *const u8, std::mem::size_of::<SOCKADDR_IN>()).to_vec() }
    } else {
        let sa6 = SOCKADDR_IN6 { sin6_family: AF_INET6, sin6_port: port_be, sin6_flowinfo: 0, sin6_addr: addr, sin6_scope_id: 0 };
        unsafe { std::slice::from_raw_parts(&sa6 as *const SOCKADDR_IN6 as *const u8, std::mem::size_of::<SOCKADDR_IN6>()).to_vec() }
    };

    // Ensure a shadow flow exists for (s,dst).
    let shadow = {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        if let Some(&sh) = st.flows.get(&(s, dst)) {
            sh
        } else {
            let req = Req {
                magic: MAGIC,
                pid: GetCurrentProcessId(),
                family,
                port_be,
                addr,
                proto: IPPROTO_UDP,
                _pad: [0; 3],
            };
            match ask_engine(req) {
                Some(resp) if resp.action == ACTION_PROXY => {
                    let sh = socket(AF_INET_C, SOCK_DGRAM_C, 17);
                    if sh == INVALID_SOCKET { return None; }
                    let relay = SOCKADDR_IN {
                        sin_family: AF_INET,
                        sin_port: resp.relay_port.to_be(),
                        sin_addr: resp.relay_ip,
                        sin_zero: [0; 8],
                    };
                    ws2_connect(sh, &relay as *const SOCKADDR_IN as *const SOCKADDR, std::mem::size_of::<SOCKADDR_IN>() as i32);
                    // 2s recv timeout so the reader can wake + (later) notice close.
                    unsafe extern "system" { fn setsockopt(s: SOCKET, level: i32, opt: i32, val: *const i8, len: i32) -> i32; }
                    const SOL: i32 = 0xffff;
                    const SO_RCVTIMEO: i32 = 0x1006;
                    let tv: [u32; 2] = [2, 0];
                    setsockopt(sh, SOL, SO_RCVTIMEO, tv.as_ptr() as *const i8, 8);
                    send_header(sh, req);
                    st.flows.insert((s, dst), sh);
                    st.proxied.insert(s);
                    st.inbox.entry(s).or_insert_with(|| std::sync::Mutex::new(std::collections::VecDeque::new()));
                    // Reader thread: shadow replies -> app inbox (source = real peer
                    // sockaddr, reconstructed with the correct family/length above).
                    let s_id = s;
                    std::thread::spawn(move || {
                        let mut b = vec![0u8; 65536];
                        loop {
                            // closesocket(app) parked this shadow socket: retire it
                            // here, between polls, so no one else can read it.
                            let dead = match udp().lock() {
                                Ok(st) => st.dead_flows.contains(&sh),
                                Err(p) => p.into_inner().dead_flows.contains(&sh),
                            };
                            if dead {
                                if let Ok(mut st) = udp().lock() {
                                    st.dead_flows.remove(&sh);
                                }
                                let _ = call_real_closesocket(sh);
                                break;
                            }
                            let n = unsafe {
                                call_real_recvfrom(sh, b.as_mut_ptr() as *mut i8, b.len() as i32, 0, std::ptr::null_mut(), std::ptr::null_mut())
                            };
                            if n < 0 {
                                // Read the Winsock error (not kernel GetLastError).
                                let wsa = unsafe {
                                    unsafe extern "system" { fn WSAGetLastError() -> i32; }
                                    WSAGetLastError()
                                };
                                // WSAEWOULDBLOCK(10035)/WSAETIMEDOUT(10060): no data yet, keep waiting.
                                if wsa == 10035 || wsa == 10060 { continue; }
                                break; // socket closed / hard error
                            }
                            if n == 0 { break; }
                            if let Ok(st) = udp().lock() {
                                if let Some(q) = st.inbox.get(&s_id) {
                                    let mut q = q.lock().unwrap_or_else(|e| e.into_inner());
                                    q.push_back((reply_addr.clone(), b[..n as usize].to_vec()));
                                }
                            }
                            sync_ready(s_id);
                        }
                    });
                    sh
                }
                Some(resp) if resp.action == ACTION_BLOCK => {
                    refuse_connection();
                    return Some(-1);
                }
                _ => return None, // direct: let the app's own sendto run
            }
        }
    };
    // Forward the app's payload through the shadow socket (connected to relay).
    let n = send(shadow, buf, len, flags);
    Some(n)
}

/// Read the app socket's Winsock SO_RCVTIMEO (a DWORD of milliseconds on Windows;
/// 0 == no timeout). Lets a proxied recv()/recvfrom() still time out like a real
/// socket instead of blocking forever when the proxy never replies.
unsafe fn sock_rcvtimeo(s: SOCKET) -> Option<std::time::Duration> {
    unsafe extern "system" {
        fn getsockopt(s: SOCKET, level: i32, opt: i32, val: *mut i8, len: *mut i32) -> i32;
    }
    const SO_RCVTIMEO_MS: i32 = 0x1006;
    let mut ms: u32 = 0;
    let mut len = 4i32;
    let r = getsockopt(s, SOL_SOCKET, SO_RCVTIMEO_MS, &mut ms as *mut u32 as *mut i8, &mut len);
    if r == 0 && ms > 0 {
        Some(std::time::Duration::from_millis(ms as u64))
    } else {
        None
    }
}

/// Drain the app socket's reply inbox for `recvfrom`/`recv`. Returns Some(ret) if
/// `s` is a proxied UDP socket, None if it should use the pristine receive.
/// `s` is a proxied UDP socket, None if it should use the pristine receive.
/// `nowait` takes at most one already-queued datagram and reports an empty inbox
/// as the -2 sentinel — used by the overlapped (WSARecvFrom) path.
unsafe fn udp_recv_impl(s: SOCKET, buf: *mut i8, len: i32, from: *mut SOCKADDR, fromlen: *mut i32, nowait: bool) -> Option<i32> {
    let is_proxied = {
        let st = udp().lock().ok()?;
        st.proxied.contains(&s)
    };
    if !is_proxied {
        return None;
    }
    // Block until an item arrives, honouring the socket's receive timeout so a
    // proxied socket can't hang the host thread forever.
    let timeout = sock_rcvtimeo(s);
    let start = std::time::Instant::now();
    loop {
        let item = {
            let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
            match st.inbox.get_mut(&s) {
                Some(q) => { let mut q = q.lock().unwrap_or_else(|e| e.into_inner()); q.pop_front() }
                None => None,
            }
        };
        if let Some((peer, data)) = item {
            let n = data.len().min(len as usize);
            std::ptr::copy_nonoverlapping(data.as_ptr() as *const i8, buf, n);
            if !from.is_null() && !fromlen.is_null() {
                // Copy the peer sockaddr (v4 16B or v6 28B) up to the caller's
                // buffer, then report its true length.
                let copy_len = (*fromlen as usize).min(peer.len());
                std::ptr::copy_nonoverlapping(peer.as_ptr(), from as *mut SOCKADDR as *mut u8, copy_len);
                *fromlen = peer.len() as i32;
            }
            sync_ready(s);
            return Some(n as i32);
        }
        if nowait {
            return Some(-2); // proxied socket, but nothing queued yet
        }
        if let Some(dur) = timeout {
            if start.elapsed() >= dur {
                unsafe extern "system" { fn WSASetLastError(e: i32); }
                WSASetLastError(10060); // WSAETIMEDOUT
                return Some(-1);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

unsafe extern "system" fn detour_sendto(s: SOCKET, buf: *const i8, len: i32, flags: i32, to: *const SOCKADDR, tolen: i32) -> i32 {
    match udp_send(s, buf, len, flags, to, tolen) {
        Some(r) => r,
        None => call_real_sendto(s, buf, len, flags, to, tolen),
    }
}

unsafe extern "system" fn detour_recvfrom(s: SOCKET, buf: *mut i8, len: i32, flags: i32, from: *mut SOCKADDR, fromlen: *mut i32) -> i32 {
    match udp_recv(s, buf, len, from, fromlen, false) {
        Some(r) => r,
        None => call_real_recvfrom(s, buf, len, flags, from, fromlen),
    }
}

unsafe extern "system" fn detour_recv(s: SOCKET, buf: *mut i8, len: i32, flags: i32) -> i32 {
    // recv() carries no source address; reuse the inbox drain with from=null.
    match udp_recv(s, buf, len, std::ptr::null_mut(), std::ptr::null_mut(), false) {
        Some(r) => r,
        None => call_real_recv(s, buf, len, flags),
    }
}

// --- WSA-style unconnected UDP (games that use WSASendTo/WSARecvFrom) --------
type WsaSendToFn = unsafe extern "system" fn(
    SOCKET, *const WSABUF, u32, *mut u32, u32, *const SOCKADDR, i32, *mut c_void, *mut c_void,
) -> i32;
type WsaRecvFromFn = unsafe extern "system" fn(
    SOCKET, *mut WSABUF, u32, *mut u32, *mut u32, *mut SOCKADDR, *mut i32, *mut c_void, *mut c_void,
) -> i32;

unsafe fn call_real_wsasendto(
    s: SOCKET, b: *const WSABUF, c: u32, sent: *mut u32, f: u32, to: *const SOCKADDR, tl: i32, name: *mut c_void, ov: *mut c_void,
) -> i32 {
    let a = ORIG_WSASENDTO.load(Ordering::SeqCst);
    if a != 0 {
        let g: WsaSendToFn = std::mem::transmute(a);
        g(s, b, c, sent, f, to, tl, name, ov)
    } else {
        -1
    }
}
unsafe fn call_real_wsarecvfrom(
    s: SOCKET, b: *mut WSABUF, c: u32, recvd: *mut u32, f: *mut u32, from: *mut SOCKADDR, fl: *mut i32, name: *mut c_void, ov: *mut c_void,
) -> i32 {
    let a = ORIG_WSARECVFROM.load(Ordering::SeqCst);
    if a != 0 {
        let g: WsaRecvFromFn = std::mem::transmute(a);
        g(s, b, c, recvd, f, from, fl, name, ov)
    } else {
        -1
    }
}

// --- overlapped (WSAOVERLAPPED) UDP ----------------------------------------
//
// A game that drives UDP through IOCP never blocks in recv(), so the synchronous
// inbox drain above never runs for it. Winsock lets an overlapped operation
// complete *immediately* from the call itself, which is what we use when a
// datagram is already queued; otherwise the call returns WSA_IO_PENDING and a
// helper thread finishes it. Completion is delivered the way the app actually
// waits: a queued completion packet when we saw WSAIoctl associate the socket
// with an IOCP, else the OVERLAPPED hEvent.
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut c_void,
}

// Bundles the caller's buffers so a deferred completion can carry them to the
// completer thread. Valid for as long as the I/O is pending (Winsock contract).
struct OvRecv {
    sock: SOCKET,
    ov: *mut c_void,
    buf: *mut i8,
    len: i32,
    received: *mut u32,
    flags: *mut u32,
    from: *mut SOCKADDR,
    fromlen: *mut i32,
}
unsafe impl Send for OvRecv {}

const WSA_IO_PENDING: i32 = 997;
const WSA_ETIMEOUT: usize = 10060; // WSAETIMEDOUT (no datagram within SO_RCVTIMEO)
const WSA_EABORTED: usize = 10053; // WSAECONNABORTED (send failed / socket gone)
// WSAIoctl opcode that binds a socket to an I/O completion port. Observed on this
// host (2026-11-25) to be the only _WSAIOW(IOC_WS2,n) in 0..0x40 that accepts a
// {CompletionPort, Key} input buffer.
const IOCTL_ASSOCIATE_COMPLETION_PORT: u32 = 0x8800_0009;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetEvent(hEvent: *mut c_void) -> i32;
    fn PostQueuedCompletionStatus(port: *mut c_void, bytes: u32, key: usize, ov: *mut c_void) -> i32;
}

/// Wake whoever waits on `ov`: a queued completion packet when the socket is
/// IOCP-associated, else the OVERLAPPED's hEvent. Takes NO locks — callers that
/// hold the UDP state must resolve `iocp` before calling this.
unsafe fn signal_ov(ov: *mut c_void, bytes: u32, err: usize, iocp: Option<(usize, usize)>) {
    if ov.is_null() {
        return;
    }
    let o = &mut *(ov as *mut Overlapped);
    o.internal = err;
    o.internal_high = bytes as usize;
    if let Some((p, key)) = iocp {
        if p != 0 {
            let _ = PostQueuedCompletionStatus(p as *mut c_void, bytes, key, ov);
        }
    }
    // Also release an event waiter: which of the two an app uses is its business,
    // and signalling an unused hEvent is harmless.
    if !o.event.is_null() {
        let _ = SetEvent(o.event);
    }
}

/// Complete an OVERLAPPED for a socket the caller does NOT hold the lock for.
unsafe fn complete_ov(s: SOCKET, ov: *mut c_void, bytes: u32, err: usize) {
    let iocp = udp().lock().ok().and_then(|st| st.iocp.get(&s).copied());
    signal_ov(ov, bytes, err, iocp);
}

/// Copy one datagram (+ its peer sockaddr) into the app's buffers. The caller has
/// already retired the `pending` entry and holds no lock.
unsafe fn deliver_ov(r: &OvRecv, data: &[u8], peer: &[u8]) {
    let n = data.len().min(r.len.max(0) as usize);
    std::ptr::copy_nonoverlapping(data.as_ptr() as *const i8, r.buf, n);
    if !r.received.is_null() {
        *r.received = n as u32;
    }
    if !r.flags.is_null() {
        *r.flags = 0;
    }
    if !r.from.is_null() && !r.fromlen.is_null() && !peer.is_empty() {
        let copy_len = (*r.fromlen as usize).min(peer.len());
        std::ptr::copy_nonoverlapping(peer.as_ptr(), r.from as *mut SOCKADDR as *mut u8, copy_len);
        *r.fromlen = peer.len() as i32;
    }
}

/// Pop this socket's pending entry (returning the info needed to signal it) once
/// a datagram is in hand.
unsafe fn retire_pending(r: &OvRecv, data: &[u8], peer: &[u8]) -> bool {
    let iocp = {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        match st.pending.remove(&(r.sock, r.ov as usize)) {
            Some(_) => st.iocp.get(&r.sock).copied(),
            None => return true, // cancelled meanwhile: leave the buffers alone
        }
    };
    sync_ready(r.sock);
    deliver_ov(r, data, peer);
    signal_ov(r.ov, data.len() as u32, 0, iocp);
    true
}

/// Take one queued datagram for a pending overlapped receive. When the socket has
/// become proxied the reply comes from the inbox; while it is still direct (the
/// app may post its recv *before* its first send) a readable datagram is drained
/// from the real socket instead, so the takeover never loses traffic.
unsafe fn finish_pending_ov(r: &OvRecv) -> bool {
    let (queued, proxied, iocp, cancelled) = {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        let key = (r.sock, r.ov as usize);
        if st.pending.get(&key).map(|a| a.load(Ordering::SeqCst)) != Some(true) {
            (None, false, None, true)
        } else {
            let proxied = st.proxied.contains(&r.sock);
            let queued = if proxied {
                st.inbox.get_mut(&r.sock).and_then(|q| {
                    let mut q = q.lock().unwrap_or_else(|e| e.into_inner());
                    q.pop_front()
                })
            } else {
                None
            };
            let iocp = st.iocp.get(&r.sock).copied();
            (queued, proxied, iocp, false)
        }
    };
    if cancelled {
        return true;
    }
    if let Some((peer, data)) = queued {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        st.pending.remove(&(r.sock, r.ov as usize));
        drop(st);
        sync_ready(r.sock);
        deliver_ov(r, &data, &peer);
        signal_ov(r.ov, data.len() as u32, 0, iocp);
        return true;
    }
    if proxied {
        return false; // the proxy simply hasn't answered yet
    }
    // Direct socket: drain it ourselves if one datagram is already readable.
    let mine = {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        st.recv_turn.insert(r.sock)
    };
    if !mine {
        return false; // another completer owns the real side right now
    }
    let got = drain_real_once(r.sock);
    if let Ok(mut st) = udp().lock() {
        st.recv_turn.remove(&r.sock);
    }
    match got {
        Some((data, peer)) => retire_pending(r, &data, &peer),
        None => false,
    }
}

/// select(0) + one recvfrom on the app's own socket: a datagram the app would
/// have received without us. Returns (payload, peer sockaddr bytes).
unsafe fn drain_real_once(s: SOCKET) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut set = FdSetWin { count: 1, fds: [0; 64] };
    set.fds[0] = s;
    let mut tv = TimeVal { sec: 0, usec: 0 };
    let none: *mut FdSetWin = std::ptr::null_mut();
    if call_real_select(0, &mut set, none, none, &mut tv) <= 0 {
        return None;
    }
    let mut buf = vec![0u8; 65536];
    let mut peer = [0u8; 128];
    let mut plen = peer.len() as i32;
    let n = call_real_recvfrom(
        s, buf.as_mut_ptr() as *mut i8, buf.len() as i32, 0,
        peer.as_mut_ptr() as *mut SOCKADDR, &mut plen,
    );
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    let plen = (plen.max(0) as usize).min(peer.len());
    Some((buf, peer[..plen].to_vec()))
}

/// Wait for a reply and complete the app's OVERLAPPED out-of-line.
fn spawn_ov_completer(r: OvRecv, timeout: Option<std::time::Duration>) {
    std::thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            let done = unsafe { finish_pending_ov(&r) };
            if done {
                return;
            }
            if let Some(dur) = timeout {
                if start.elapsed() >= dur {
                    let aborted = {
                        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
                        st.pending.remove(&(r.sock, r.ov as usize)).map(|_| st.iocp.get(&r.sock).copied())
                    };
                    if let Some(iocp) = aborted {
                        unsafe { signal_ov(r.ov, 0, WSA_ETIMEOUT, iocp) };
                    }
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    });
}

/// WSASendTo. Proxied unconnected UDP is forwarded through the shadow socket;
/// with an OVERLAPPED the same call also reports completion immediately, because
/// a loopback UDP send cannot realistically block.
unsafe extern "system" fn detour_wsasendto(
    s: SOCKET, buffers: *const WSABUF, count: u32, sent: *mut u32, flags: u32,
    to: *const SOCKADDR, tolen: i32, name: *mut c_void, overlapped: *mut c_void,
) -> i32 {
    if count < 1 || buffers.is_null() {
        return call_real_wsasendto(s, buffers, count, sent, flags, to, tolen, name, overlapped);
    }
    let b = &*buffers;
    match udp_send(s, b.buf, b.len as i32, flags as i32, to, tolen) {
        Some(n) => {
            let bytes = if n > 0 { n as u32 } else { 0 };
            if !sent.is_null() {
                *sent = bytes;
            }
            if !overlapped.is_null() {
                if n < 0 {
                    complete_ov(s, overlapped, 0, WSA_EABORTED);
                    wsa_set_last_error(10053);
                } else {
                    complete_ov(s, overlapped, bytes, 0);
                }
            }
            if n < 0 { -1 } else { 0 } // WSASendTo: 0 == success
        }
        None => call_real_wsasendto(s, buffers, count, sent, flags, to, tolen, name, overlapped),
    }
}

fn wsa_set_last_error(e: i32) {
    unsafe extern "system" { fn WSASetLastError(code: i32); }
    unsafe { WSASetLastError(e) }
}

/// WSARecvFrom. Synchronous callers drain the inbox (blocking); overlapped
/// callers get an immediate completion when a datagram is already queued and a
/// WSA_IO_PENDING + deferred completion otherwise.
unsafe extern "system" fn detour_wsarecvfrom(
    s: SOCKET, buffers: *mut WSABUF, count: u32, received: *mut u32, flags: *mut u32,
    from: *mut SOCKADDR, fromlen: *mut i32, name: *mut c_void, overlapped: *mut c_void,
) -> i32 {
    if count < 1 || buffers.is_null() {
        return call_real_wsarecvfrom(s, buffers, count, received, flags, from, fromlen, name, overlapped);
    }
    let b = &mut *buffers;
    if overlapped.is_null() {
        match udp_recv(s, b.buf, b.len as i32, from, fromlen, false) {
            Some(n) => {
                if !received.is_null() {
                    *received = if n > 0 { n as u32 } else { 0 };
                }
                if n < 0 { -1 } else { 0 }
            }
            None => call_real_wsarecvfrom(s, buffers, count, received, flags, from, fromlen, name, overlapped),
        }
    } else {
        // Overlapped. A datagram already sitting in the proxied inbox completes
        // right here, in the call.
        match udp_recv(s, b.buf, b.len as i32, from, fromlen, true) {
            Some(-2) | None => {}
            Some(n) => {
                if !received.is_null() {
                    *received = if n > 0 { n as u32 } else { 0 };
                }
                if !flags.is_null() {
                    *flags = 0;
                }
                complete_ov(s, overlapped, n.max(0) as u32, 0);
                return 0;
            }
        }
        // Otherwise take over the request only for a datagram socket; a stream
        // socket (or anything we cannot classify) keeps pristine Winsock.
        let proxied = udp().lock().ok().map(|st| st.proxied.contains(&s)).unwrap_or(false);
        let (qr, ty) = sock_type(s);
        let dgram = qr == 0 && ty == SOCK_DGRAM;
        if !proxied {
            if !dgram {
                return call_real_wsarecvfrom(s, buffers, count, received, flags, from, fromlen, name, overlapped);
            }
            // Direct for now: serve an already-readable datagram from the real
            // socket so the takeover is invisible to a recv-posted-before-send app.
            if let Some((data, peer)) = drain_real_once(s) {
                let r = OvRecv {
                    sock: s, ov: overlapped, buf: b.buf, len: b.len as i32, received, flags, from, fromlen,
                };
                deliver_ov(&r, &data, &peer);
                complete_ov(s, overlapped, data.len() as u32, 0);
                return 0;
            }
        }
        let r = OvRecv {
            sock: s, ov: overlapped, buf: b.buf, len: b.len as i32, received, flags, from, fromlen,
        };
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        {
            let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
            // Bound the takeover: never let a leaking app pile up unbounded threads.
            if st.pending.len() > 256 {
                drop(st);
                return call_real_wsarecvfrom(s, buffers, count, received, flags, from, fromlen, name, overlapped);
            }
            st.pending.insert((s, overlapped as usize), alive);
        }
        spawn_ov_completer(r, sock_rcvtimeo(s));
        wsa_set_last_error(WSA_IO_PENDING);
        -1
    }
}

/// WSAIoctl: remember an IOCP association so overlapped completions land where
/// the app polls. (Only the ws2_32 export is hooked; a service provider called
/// through its SPI table directly is not observed.)
type WsaIoctlFn = unsafe extern "system" fn(
    SOCKET, u32, *const c_void, u32, *mut c_void, u32, *mut u32, *mut c_void, *mut c_void,
) -> i32;
unsafe fn call_real_wsaioctl(
    s: SOCKET, code: u32, inb: *const c_void, inn: u32, outb: *mut c_void, outn: u32,
    ret: *mut u32, ov: *mut c_void, comp: *mut c_void,
) -> i32 {
    let a = ORIG_WSAIOCTL.load(Ordering::SeqCst);
    if a != 0 {
        let g: WsaIoctlFn = std::mem::transmute(a);
        g(s, code, inb, inn, outb, outn, ret, ov, comp)
    } else {
        -1
    }
}

unsafe extern "system" fn detour_wsaioclt(
    s: SOCKET, code: u32, inb: *const c_void, inn: u32, outb: *mut c_void, outn: u32,
    ret: *mut u32, ov: *mut c_void, comp: *mut c_void,
) -> i32 {
    let r = call_real_wsaioctl(s, code, inb, inn, outb, outn, ret, ov, comp);
    if r == 0 && code == IOCTL_ASSOCIATE_COMPLETION_PORT && inn as usize >= 2 * std::mem::size_of::<usize>() && !inb.is_null() {
        let pair = &*(inb as *const [usize; 2]);
        if let Ok(mut st) = udp().lock() {
            st.iocp.insert(s, (pair[0], pair[1]));
        }
    }
    r
}

/// CreateIoCompletionPort is how an app binds a socket to an IOCP without ever
/// calling WSAIoctl, so the association has to be observed here too.
type CreateIoCompletionPortFn =
    unsafe extern "system" fn(*mut c_void, *mut c_void, usize, u32) -> *mut c_void;
unsafe extern "system" fn detour_createiocport(
    sock: *mut c_void, port: *mut c_void, key: usize, threads: u32,
) -> *mut c_void {
    let a = ORIG_CREATEIOCPORT.load(Ordering::SeqCst);
    let r = if a != 0 {
        let g: CreateIoCompletionPortFn = std::mem::transmute(a);
        g(sock, port, key, threads)
    } else {
        std::ptr::null_mut()
    };
    if !r.is_null() && !port.is_null() {
        // Record only genuine sockets: a pipe/file handle must not leave an entry
        // that a later socket handle could collide with.
        let (qr, ty) = sock_type(sock as SOCKET);
        if qr == 0 && ty == SOCK_DGRAM {
            if let Ok(mut st) = udp().lock() {
                st.iocp.insert(sock as SOCKET, (r as usize, key));
            }
        }
    }
    r
}

/// closesocket: drop per-socket UDP state and abort any pending overlapped
/// receive so its completer stops referencing the caller's buffers.
unsafe extern "system" fn detour_closesocket(s: SOCKET) -> i32 {
    {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        st.iocp.remove(&s);
        st.proxied.remove(&s);
        st.inbox.remove(&s);
        st.wsa_events.remove(&s);
        if let Some(h) = st.ready.remove(&s) {
            if !h.0.is_null() {
                CloseHandleR(h.0);
            }
        }
        let keys: Vec<(SOCKET, usize)> = st.pending.keys().filter(|(ps, _)| *ps == s).copied().collect();
        let mut alive = Vec::with_capacity(keys.len());
        for k in keys {
            if let Some(a) = st.pending.remove(&k) {
                a.store(false, Ordering::SeqCst);
                alive.push(a);
            }
        }
        let flows: Vec<SOCKET> = st.flows.keys().filter(|(fs, _)| *fs == s).map(|&(_, d)| st.flows[&(s, d)]).collect();
        // Never close a shadow socket from here: its reader thread may be blocked
        // in recvfrom() on it, and Winsock recycles the handle value — the reader
        // could wake up reading someone else's socket. Park it and let the reader
        // retire it between polls.
        for sh in flows {
            st.dead_flows.insert(sh);
        }
        for k in st.flows.keys().filter(|(fs, _)| *fs == s).copied().collect::<Vec<_>>() {
            st.flows.remove(&k);
        }
        alive
    };
    call_real_closesocket(s)
}

type CloseSocketFn = unsafe extern "system" fn(SOCKET) -> i32;
unsafe fn call_real_closesocket(s: SOCKET) -> i32 {
    let a = ORIG_CLOSESOCKET.load(Ordering::SeqCst);
    if a != 0 {
        let g: CloseSocketFn = std::mem::transmute(a);
        g(s)
    } else {
        -1
    }
}


// --- readiness for select() / WSAEventSelect() ------------------------------
//
// A proxied datagram is queued in the hook inbox; the app own socket never
// becomes readable, so select() and WSAEventSelect() must be answered from the
// queue instead of from Winsock. Note the Windows layouts: fd_set is a count plus
// an inline array, and timeval is two 32-bit LONGs (not the 64-bit pair Linux
// uses - reading it wrong silently turns a timeout into garbage).
#[repr(C)]
pub struct FdSetWin {
    pub count: u32,
    pub fds: [SOCKET; 64],
}

#[repr(C)]
pub struct TimeVal {
    pub sec: i32,
    pub usec: i32,
}

/// A HANDLE stored in the shared state maps.
#[derive(Clone, Copy)]
pub struct RawHandle(pub *mut c_void);
unsafe impl Send for RawHandle {}
unsafe impl Sync for RawHandle {}

const FD_READ_WIN: i32 = 0x0001;
const WAIT_TIMEOUT_WIN: u32 = 0x0000_0102;
const INFINITE_WIN: u32 = 0xFFFF_FFFF;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateEventW(sa: *const c_void, manual_reset: i32, initial: i32, name: *const u16) -> *mut c_void;
    fn ResetEvent(h: *mut c_void) -> i32;
    #[link_name = "CloseHandle"]
    fn CloseHandleR(h: *mut c_void) -> i32;
    fn WaitForMultipleObjects(n: u32, handles: *const *mut c_void, wait_all: i32, ms: u32) -> u32;
}

/// Level-triggered readiness: the event is signalled exactly while the inbox holds
/// a datagram. Call after every push and every pop.
unsafe fn sync_ready(s: SOCKET) {
    let st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    let queued = match st.inbox.get(&s) {
        Some(q) => !q.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        None => return,
    };
    if let Some(h) = st.ready.get(&s) {
        if queued {
            SetEvent(h.0);
        } else {
            ResetEvent(h.0);
        }
    }
    if queued {
        if let Some(h) = st.wsa_events.get(&s) {
            SetEvent(h.0);
        }
    }
}

/// The hook readiness event for `s`, created on first use (manual reset, clear).
unsafe fn ready_event(s: SOCKET) -> *mut c_void {
    let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    if let Some(h) = st.ready.get(&s) {
        return h.0;
    }
    let h = CreateEventW(std::ptr::null(), 1, 0, std::ptr::null());
    st.ready.insert(s, RawHandle(h));
    h
}

/// True when a reply is queued for `s`.
fn inbox_has_data(s: SOCKET) -> bool {
    let st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
    match st.inbox.get(&s) {
        Some(q) => !q.lock().unwrap_or_else(|e| e.into_inner()).is_empty(),
        None => false,
    }
}

/// Call the pristine Winsock select through the trampoline: the export itself is
/// patched, so calling it directly would recurse forever.
type SelectFn = unsafe extern "system" fn(
    i32, *mut FdSetWin, *mut FdSetWin, *mut FdSetWin, *mut TimeVal,
) -> i32;
unsafe fn call_real_select(
    nfds: i32, read: *mut FdSetWin, write: *mut FdSetWin, except: *mut FdSetWin, tv: *mut TimeVal,
) -> i32 {
    let a = ORIG_SELECT.load(Ordering::SeqCst);
    if a != 0 {
        let g: SelectFn = std::mem::transmute(a);
        g(nfds, read, write, except, tv)
    } else {
        -1
    }
}

/// How long a hooked select() sleeps between checks when nothing is ready yet.
const SELECT_POLL_MS: u64 = 20;

// ── select() rewriting, in place and in bounds ──────────────────────────────────
//
// The previous version declared fd_set as a 64-entry array and then
//
//     let list = all.fds[..all.count].to_vec();   // panics when count > 64
//     …
//     *read = out;                                // writes 4 + 64*8 bytes
//
// Windows declares fd_set as `{ u_int fd_count; SOCKET fd_array[1]; }` with the
// caller's allocation holding exactly `fd_count` entries (up to FD_SETSIZE 1024). So
// for the common case of a browser selecting on more than 64 sockets the slice
// panicked - inside `extern "system"`, which cannot unwind, i.e. the host died
// (observed: Firefox 161, UptimeTS 7.0, fastfail at tpdrv.dll, frames in
// core::panicking above lib.rs:2184). And for the *other* common case - fewer than 64
// sockets - `*read = out` wrote 516 bytes over a buffer sized for e.g. 5 entries,
// corrupting the caller's memory. Both are fixed by treating the caller's set as a
// header plus a variable trailer, and by only ever shrinking or refilling within the
// count the caller itself declared.

/// Windows' FD_SETSIZE: the largest a caller's fd_set trailer can legitimately be.
const FD_SETSIZE_WIN: usize = 1024;

/// Read the sockets a caller actually put in its set. The array in `FdSetWin` is a
/// placeholder, not the allocation's size, so this goes through the raw trailer and
/// clamps to FD_SETSIZE rather than trusting `count` blindly.
unsafe fn fds_get(set: *const FdSetWin) -> Vec<SOCKET> {
    if set.is_null() {
        return Vec::new();
    }
    let declared = unsafe { (*set).count } as usize;
    let n = declared.min(FD_SETSIZE_WIN);
    if n == 0 {
        return Vec::new();
    }
    let base = unsafe { std::ptr::addr_of!((*set).fds) } as *const SOCKET;
    unsafe { std::slice::from_raw_parts(base, n).to_vec() }
}

/// Refill a caller's set with `keep`, in place. `capacity` is the count the caller
/// originally declared, i.e. how many entries its allocation can actually hold, and
/// `keep` is truncated to it: an fd_set may only ever shrink or stay the same size.
///
/// Returns how many entries were written. Never writes past `capacity`, which is the
/// property that `*read = out` violated.
unsafe fn fds_put(set: *mut FdSetWin, keep: &[SOCKET], capacity: usize) -> usize {
    if set.is_null() || capacity == 0 {
        unsafe {
            if !set.is_null() {
                (*set).count = 0;
            }
        }
        return 0;
    }
    let n = keep.len().min(capacity);
    let base = unsafe { std::ptr::addr_of_mut!((*set).fds) } as *mut SOCKET;
    for i in 0..n {
        unsafe { std::ptr::write(base.add(i), keep[i]) };
    }
    unsafe { (*set).count = n as u32 };
    n
}

/// `select()` counts what is left in the three sets, and Windows filters them in
/// place, so the survivor counts are the return value. That is also why the hook must
/// not invent its own set object: it participates in the caller's.
unsafe fn fd_set_total(read: *const FdSetWin, write: *const FdSetWin, except: *const FdSetWin) -> usize {
    unsafe {
        fds_get(read).len() + fds_get(write).len() + fds_get(except).len()
    }
}


unsafe extern "system" fn detour_select(
    nfds: i32,
    read: *mut FdSetWin,
    write: *mut FdSetWin,
    except: *mut FdSetWin,
    tv: *mut TimeVal,
) -> i32 {
    // Everything here participates in the CALLER's fd_sets: a count plus a variable
    // trailer, so the hook may only shrink or refill within the count the caller
    // declared. The previous version sliced a fixed 64-entry array (panicking above 64
    // sockets, which is routine for a browser) and then assigned a whole 64-entry
    // struct back over a buffer sized for far fewer.
    let capacity = unsafe { if read.is_null() { 0usize } else { (*read).count as usize } };
    if capacity == 0 {
        return call_real_select(nfds, read, write, except, tv);
    }
    let list = match fenced("select", || unsafe { fds_get(read) }) {
        Some(v) => v,
        None => return call_real_select(nfds, read, write, except, tv),
    };
    let ours: Vec<SOCKET> = {
        let st = match udp().lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        list.iter().copied().filter(|s| st.proxied.contains(s)).collect()
    };
    if ours.is_empty() {
        return call_real_select(nfds, read, write, except, tv);
    }
    let foreign: Vec<SOCKET> = list.iter().copied().filter(|s| !ours.contains(s)).collect();
    // `tv == NULL` waits forever; otherwise the caller's own interval, converted once.
    let deadline: Option<std::time::Instant> = match unsafe { tv.as_ref() } {
        None => None,
        Some(t) => {
            let ms = (t.sec.max(0) as u64)
                .saturating_mul(1000)
                .saturating_add(t.usec.max(0) as u64 / 1000);
            Some(std::time::Instant::now() + std::time::Duration::from_millis(ms))
        }
    };
    let mut zero = TimeVal { sec: 0, usec: 0 };
    loop {
        // Our proxied sockets never become readable through the real select - the reply
        // is already sitting in our queue - so ask about them ourselves and let the real
        // select answer for everything the hook does not own.
        let ready_ours: Vec<SOCKET> = ours.iter().copied().filter(|s| inbox_has_data(*s)).collect();
        unsafe { fds_put(read, &foreign, capacity) };
        call_real_select(0, read, write, except, &mut zero);
        let ready_foreign = unsafe { fds_get(read) };
        let mut keep = ready_foreign;
        for s in ready_ours {
            if keep.len() < capacity {
                keep.push(s);
            }
        }
        unsafe { fds_put(read, &keep, capacity) };
        let total = unsafe { fd_set_total(read, write, except) };
        if total > 0 {
            return total as i32;
        }
        if deadline.is_some() && std::time::Instant::now() >= deadline.unwrap() {
            unsafe { fds_put(read, &[], capacity) };
            return 0;
        }
        // Bounded sleep: also lets a queue drained by another thread be noticed instead
        // of parking the caller forever on an infinite select.
        std::thread::sleep(std::time::Duration::from_millis(SELECT_POLL_MS));
    }
}


type WsaEventSelectFn = unsafe extern "system" fn(SOCKET, *mut c_void, i32) -> i32;

/// WSAEventSelect: keep the app event so a queued reply can release it. The real
/// call still runs; for FD_READ the socket would never signal on its own anyway.
unsafe extern "system" fn detour_wsaeventselect(s: SOCKET, ev: *mut c_void, events: i32) -> i32 {
    let a = ORIG_WSAEVENTSELECT.load(Ordering::SeqCst);
    let r = if a != 0 {
        let g: WsaEventSelectFn = std::mem::transmute(a);
        g(s, ev, events)
    } else {
        -1
    };
    if r == 0 && events & FD_READ_WIN != 0 && !ev.is_null() {
        let mut st = match udp().lock() { Ok(g) => g, Err(p) => p.into_inner() };
        st.wsa_events.insert(s, RawHandle(ev));
        let queued = st
            .inbox
            .get(&s)
            .map(|q| !q.lock().unwrap_or_else(|e| e.into_inner()).is_empty())
            .unwrap_or(false);
        if queued {
            SetEvent(ev);
        }
    }
    r
}

type WsaEnumNetFn = unsafe extern "system" fn(SOCKET, *mut c_void, *mut i32) -> i32;

/// WSAEnumNetworkEvents: report FD_READ from the hook queue. Level-triggered, so
/// it clears itself once the app has drained the inbox.
unsafe extern "system" fn detour_wsaenumnetworkevents(
    s: SOCKET,
    ev: *mut c_void,
    events: *mut i32,
) -> i32 {
    let a = ORIG_WSAENUMNETWORK.load(Ordering::SeqCst);
    let r = if a != 0 {
        let g: WsaEnumNetFn = std::mem::transmute(a);
        g(s, ev, events)
    } else {
        -1
    };
    if !events.is_null() && inbox_has_data(s) {
        *events |= FD_READ_WIN;
    }
    r
}

/// Query the engine's DNS-allocation pipe for a fake IPv4 for `node`.
/// Returns None when the engine is off / declines (dns_mode=local, app not
/// proxified) so the caller falls back to the real resolver.
fn ask_dns_pipe(node: &str) -> Option<[u8; 4]> {
    use std::os::windows::ffi::OsStrExt;
    if !engine_alive() {
        return None;
    }
    let pid = unsafe { GetCurrentProcessId() };
    let nb = node.as_bytes();
    if nb.is_empty() || nb.len() > 251 {
        return None;
    }
    let mut req = [0u8; 256];
    req[..4].copy_from_slice(&pid.to_le_bytes());
    req[4..4 + nb.len()].copy_from_slice(nb);
    let wide: Vec<u16> = OsStr::new(&format!("{PIPE_NAME_DNS}{}", instance_suffix())).encode_wide().chain(std::iter::once(0)).collect();
    let mut octets = [0u8; 4];
    let mut read = 0u32;
    let ok = unsafe {
        CallNamedPipeW(
            wide.as_ptr(),
            req.as_ptr() as *const c_void,
            256,
            octets.as_mut_ptr() as *mut c_void,
            4,
            &mut read,
            2000,
        )
    };
    if ok == TRUE && read == 4 && octets != [0, 0, 0, 0] {
        Some(octets)
    } else {
        None
    }
}

fn service_to_port_be(service: *const i8) -> u16 {
    if service.is_null() {
        return 0;
    }
    let s = unsafe { std::ffi::CStr::from_ptr(service) }.to_string_lossy();
    match s.trim().parse::<u16>() {
        Ok(p) => p.to_be(),
        Err(_) => 0,
    }
}

unsafe fn call_real_getaddrinfo(
    node: *const i8,
    service: *const i8,
    hints: *const AddrInfoA,
    res: *mut *mut AddrInfoA,
) -> i32 {
    let a = ORIG_GETADDRINFO.load(Ordering::SeqCst);
    if a != 0 {
        let f: GetAddrInfoFn = std::mem::transmute(a);
        f(node, service, hints, res)
    } else {
        10109 // WSASYSNOTREADY-ish; never reached (hook implies trampoline set)
    }
}

unsafe fn call_real_freeaddrinfo(ptr: *mut AddrInfoA) {
    let a = ORIG_FREEADDRINFO.load(Ordering::SeqCst);
    if a != 0 {
        let f: FreeAddrInfoFn = std::mem::transmute(a);
        f(ptr)
    }
}

extern "system" fn detour_getaddrinfo(
    node: *const i8,
    service: *const i8,
    hints: *const AddrInfoA,
    res: *mut *mut AddrInfoA,
) -> i32 {
    unsafe {
        // Inert unless the engine is up + we are not the engine; and never for a
        // numeric host (nothing to map back).
        if node.is_null() || am_engine() || !engine_alive() || res.is_null() {
            return call_real_getaddrinfo(node, service, hints, res);
        }
        let nstr = std::ffi::CStr::from_ptr(node).to_string_lossy().into_owned();
        if nstr.parse::<std::net::Ipv4Addr>().is_ok() || nstr.parse::<std::net::Ipv6Addr>().is_ok() {
            return call_real_getaddrinfo(node, service, hints, res);
        }
        // The fake node is OURS (Box::leak below), so it is only safe to hand out
        // while detour_freeaddrinfo is in place to intercept the free. Where that
        // detour could not be installed — this host's freeaddrinfo prologue is one
        // Module Copy refuses to relocate — handing it out would let ws2_32 free a
        // pointer it never allocated. Resolve for real instead: DNS-based rules just
        // behave as they do with the feature off, which beats a corrupted heap.
        if ORIG_FREEADDRINFO.load(Ordering::SeqCst) == 0 {
            hook_dbg("getaddrinfo: freeaddrinfo detour absent, so the pair stays off
");
            return call_real_getaddrinfo(node, service, hints, res);
        }
        let oct = match ask_dns_pipe(&nstr) {
            Some(o) => o,
            None => return call_real_getaddrinfo(node, service, hints, res),
        };
        // Build a single fake IPv4 node, leaked; freeaddrinfo no-ops on it (it is
        // in FAKE_AI_HEADS). Per-call allocation is intentional: sharing one cached
        // node across concurrent getaddrinfo callers corrupted the heap (a cached
        // pointer freed by one user while another still held it), so we keep each
        // lookup's node distinct. Bounded by the number of lookups in practice.
        let (st, pr, fam) = if hints.is_null() {
            (0, 0, AF_INET as i32)
        } else {
            let h = &*hints;
            (h.ai_socktype, h.ai_protocol, if h.ai_family == 0 { AF_INET as i32 } else { h.ai_family })
        };
        let sin = Box::leak(Box::new(SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: service_to_port_be(service),
            sin_addr: oct,
            sin_zero: [0; 8],
        }));
        let node_ref: *mut AddrInfoA = Box::leak(Box::new(AddrInfoA {
            ai_flags: 0,
            ai_family: fam,
            ai_socktype: st,
            ai_protocol: pr,
            ai_addrlen: std::mem::size_of::<SOCKADDR_IN>(),
            ai_canonname: std::ptr::null_mut(),
            ai_addr: sin as *const SOCKADDR_IN as *mut SOCKADDR,
            ai_next: std::ptr::null_mut(),
        }));
        if let Ok(mut g) = fake_heads().lock() {
            g.insert(node_ref as usize);
        }
        *res = node_ref;
        0
    }
}

/// Which detours are live in this process, as a bitmask — `0` for a bit means that API
/// is untouched, which is how a caller distinguishes "feature off" from "feature
/// refused". The bits are the order `install_hooks` patches them in:
///
/// 0 connect · 1 WSAConnect · 2 sendto · 3 recvfrom · 4 recv · 5 WSASendTo ·
/// 6 WSARecvFrom · 7 WSAIoctl · 8 closesocket · 9 CreateIoCompletionPort · 10 select ·
/// 11 WSAEventSelect · 12 WSAEnumNetworkEvents · 13 getaddrinfo · 14 freeaddrinfo
///
/// This is deliberately an export and not a return value of `InitFilter3`: the hook can
/// be installed by the broker in a foreign process, where the only way back to the
/// engine is a query. Bits 13/14 are the pair the DNS fake-IP path depends on.
#[unsafe(no_mangle)]
pub extern "system" fn TpdrvHookStatus() -> u32 {
    let live = [
        &ORIG_CONNECT,
        &ORIG_WSACONNECT,
        &ORIG_SENDTO,
        &ORIG_RECVFROM,
        &ORIG_RECV,
        &ORIG_WSASENDTO,
        &ORIG_WSARECVFROM,
        &ORIG_WSAIOCTL,
        &ORIG_CLOSESOCKET,
        &ORIG_CREATEIOCPORT,
        &ORIG_SELECT,
        &ORIG_WSAEVENTSELECT,
        &ORIG_WSAENUMNETWORK,
        &ORIG_GETADDRINFO,
        &ORIG_FREEADDRINFO,
    ];
    let mut mask = 0u32;
    for (bit, slot) in live.iter().enumerate() {
        if slot.load(Ordering::SeqCst) != 0 {
            mask |= 1 << bit;
        }
    }
    mask
}

extern "system" fn detour_freeaddrinfo(ptr: *mut AddrInfoA) {
    unsafe {
        if !ptr.is_null() {
            if let Ok(mut g) = fake_heads().lock() {
                if g.remove(&(ptr as usize)) {
                    return; // our leaked fake node — do NOT free (wrong heap)
                }
            }
        }
        call_real_freeaddrinfo(ptr);
    }
}

/// Drive a pending non-blocking `connect()` to completion by polling
/// `SO_ERROR`, returning 0 once connected, or -1 on failure/timeout (with the
/// Winsock error left set). Used so the in-band Req header is only written once
/// the socket is genuinely connected.
fn await_connect(s: SOCKET, timeout_ms: u32) -> i32 {
    unsafe extern "system" {
        fn getsockopt(s: SOCKET, level: i32, opt: i32, val: *mut i8, len: *mut i32) -> i32;
        fn Sleep(d: u32);
        fn GetTickCount64() -> u64;
        fn WSASetLastError(e: i32);
    }
    const SOL_SOCKET: i32 = 0xffff;
    const SO_ERROR: i32 = 0x1007;
    const WSAEALREADY: i32 = 10056; // still connecting
    const WSAEINPROGRESS: i32 = 10037; // still connecting
    const WSAETIMEDOUT: i32 = 10060;
    let deadline = unsafe { GetTickCount64() } + timeout_ms as u64;
    loop {
        let mut err = 0i32;
        let mut len = 4i32;
        unsafe { getsockopt(s, SOL_SOCKET, SO_ERROR, &mut err as *mut i32 as *mut i8, &mut len) };
        if err == 0 {
            return 0;
        }
        if err != WSAEALREADY && err != WSAEINPROGRESS {
            unsafe { WSASetLastError(err) }; // real connect failure
            return -1;
        }
        if unsafe { GetTickCount64() } >= deadline {
            unsafe { WSASetLastError(WSAETIMEDOUT) };
            return -1;
        }
        unsafe { Sleep(2) };
    }
}

fn send_header(s: SOCKET, req: Req) {
    let bytes = unsafe {
        std::slice::from_raw_parts(&req as *const Req as *const i8, std::mem::size_of::<Req>())
    };
    unsafe {
        send(s, bytes.as_ptr(), bytes.len() as i32, 0);
    }
}

/// One-shot control query over the named pipe (mirrors CallNamedPipeW usage).
/// Fast-fails when the engine mutex is absent (engine not running) so an inert
/// injected copy never adds latency to the host app's sockets; retries briefly
/// only for a busy/transitioning pipe while the engine IS up.
fn ask_engine(req: Req) -> Option<Resp> {
    use std::os::windows::ffi::OsStrExt;
    // Cheap liveness gate: if the engine mutex is gone, do NOT touch the pipe.
    if !engine_alive() {
        return None;
    }
    const ERROR_PIPE_BUSY: u32 = 231;
    const ERROR_MORE_DATA: u32 = 234;
    const ERROR_BROKEN_PIPE: u32 = 109;
    let wide: Vec<u16> = OsStr::new(&format!("{PIPE_NAME}{}", instance_suffix())).encode_wide().chain(std::iter::once(0)).collect();
    for _attempt in 0..10 {
        let mut resp = Resp::default();
        let mut read = 0u32;
        let ok = unsafe {
            CallNamedPipeW(
                wide.as_ptr(),
                &req as *const Req as *const c_void,
                std::mem::size_of::<Req>() as u32,
                &mut resp as *mut Resp as *mut c_void,
                std::mem::size_of::<Resp>() as u32,
                &mut read,
                2000,
            )
        };
        if ok == TRUE && read as usize == std::mem::size_of::<Resp>() && resp.magic == MAGIC {
            return Some(resp);
        }
        let gle = unsafe {
            unsafe extern "system" {
                fn GetLastError() -> u32;
            }
            GetLastError()
        };
        // Retry only transient pipe conditions; anything else -> fall back to direct.
        if gle != ERROR_PIPE_BUSY && gle != ERROR_MORE_DATA && gle != ERROR_BROKEN_PIPE {
            return None;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    None
}

// ══════════════════════════════════════════════════════════════════════════
// Panic fence
//
// A panic escaping one of these hooks takes down whatever process we happen to be
// injected into. The detours are `extern "system"` (they cannot unwind) and are
// called from the host's own C code, so the runtime converts our panic into the
// HOST app's abort - observed as a Firefox 161 crash with nss3 below tpdrv and
// core::panicking above it, typed EXCEPTION_STACK_BUFFER_OVERRUN /
// FAST_FAIL_FATAL_APP_EXIT. The DLL previously contained no catch_unwind at all.
//
// Fencing the three shared helpers rather than all 16 detours is deliberate: each
// one already returns Option<T> where None means "not intercepted", and every
// caller responds to None by calling the real ws2_32 function. So the worst case
// after this fence is that ONE socket goes direct and the host keeps running -
// and the log line says which helper was panicking.
// ══════════════════════════════════════════════════════════════════════════

fn fenced<T>(site: &'static str, f: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(p) => {
            report_panic(site, &*p);
            None
        }
    }
}

/// Logged once per site, then silence: a hot path must not spam the disk, but
// "we swallowed a panic in recvfrom" must be findable by whoever reads the
/// crash report. Written to be panic-free itself, since it runs in the error path.
fn report_panic(site: &'static str, payload: &(dyn std::any::Any + Send)) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<Vec<&'static str>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    {
        let mut g = seen.lock().unwrap_or_else(|e| e.into_inner());
        if g.iter().any(|s| *s == site) {
            return;
        }
        g.push(site);
    }
    let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload was not a string".to_string()
    };
    use std::io::Write;
    let base = std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join("trans-proxier");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("tpdrv-hook.log"))
    {
        let _ = writeln!(
            f,
            "{} tpdrv swallowed a panic in the {} helper: {}",
            std::process::id(),
            site,
            msg,
        );
    }
}

unsafe fn intercept<D: FnMut(*const SOCKADDR, i32) -> i32>(
    s: SOCKET,
    name: *const SOCKADDR,
    len: i32,
    mut dial: D,
) -> Option<i32> {
    fenced("connect-intercept", || intercept_impl(s, name, len, &mut dial)).unwrap_or_default()
}

unsafe fn udp_send(s: SOCKET, buf: *const i8, len: i32, flags: i32, to: *const SOCKADDR, tolen: i32) -> Option<i32> {
    fenced("sendto", || udp_send_impl(s, buf, len, flags, to, tolen)).unwrap_or_default()
}

unsafe fn udp_recv(s: SOCKET, buf: *mut i8, len: i32, from: *mut SOCKADDR, fromlen: *mut i32, nowait: bool) -> Option<i32> {
    fenced("recvfrom", || udp_recv_impl(s, buf, len, from, fromlen, nowait)).unwrap_or_default()
}

#[cfg(test)]
mod fence_tests {
    use super::fenced;

    /// Mirrors exactly how the three helpers are wrapped: the fence's outer None is
    /// collapsed by `unwrap_or_default`, so both a swallowed panic and a helper that
    /// declined land as None - which every detour caller answers by calling the real
    /// ws2_32 function. That is the property the Firefox crash needs.
    fn wrapped(boom: bool) -> Option<i32> {
        fenced("unit-test-site", || {
            if boom {
                panic!("forced panic inside a hook helper")
            }
            Some(7)
        })
        .unwrap_or_default()
    }

    #[test]
    fn a_panic_inside_a_hook_degrades_to_direct_instead_of_killing_the_host() {
        // If catch_unwind stopped fencing anything, this test process would abort
        // exactly like Firefox did, and the failure would show as a crash rather than
        // an assertion - which is the point of asserting on the value.
        assert_eq!(wrapped(true), None, "a panicking helper must mean not-intercepted");
        // inverse: a healthy helper keeps its result, so the fence cannot be quietly
        // swallowing successes and turning everything into direct traffic
        assert_eq!(wrapped(false), Some(7), "the fence must not eat real interceptions");
    }
}

#[cfg(test)]
mod owner_tests {
    use super::{claim_hook_ownership, release_hook_ownership};

    #[test]
    fn a_second_owner_is_refused_and_the_slot_frees_again() {
        // The exact situation that produced five stacked hooks: two installs, no
        // refusal. Ownership must be exclusive while held and recoverable after.
        // The slot is a SESSION-GLOBAL object, so a live engine on this machine owns it
        // legitimately and that is not a failure of this logic. Skip with a message
        // rather than asserting on state this test does not control - a test that only
        // passes when nothing else is running is worse than no test, because it fails
        // on exactly the machines that matter.
        if !claim_hook_ownership() {
            eprintln!(
                "skip: another process already holds the hook-ownership slot",
            );
            return;
        }
        assert!(!claim_hook_ownership(), "a second install must be refused");
        release_hook_ownership();
        assert!(claim_hook_ownership(), "the slot must be claimable again");
        release_hook_ownership();
    }
}

#[cfg(test)]
#[allow(unsafe_op_in_unsafe_fn)]
mod select_abi_tests {
    use super::{fds_get, fds_put, FdSetWin, SOCKET};

    /// Build an fd_set the way Windows actually allocates one: a count and a trailer
    /// of exactly `cap` sockets, plus a guard word right after it. The old code read a
    /// fixed 64-entry array out of this (panicking past 64) and wrote one back (walking
    /// over the end of the caller's buffer). Both are asserted against here.
    fn make_set(cap: usize, values: &[SOCKET]) -> (Vec<u8>, usize) {
        let bytes = 8 + 8 * cap + 8;
        let mut buf = vec![0u8; bytes];
        buf[..4].copy_from_slice(&(values.len() as u32).to_ne_bytes());
        for (i, v) in values.iter().enumerate() {
            buf[8 + 8 * i..8 + 8 * i + 8].copy_from_slice(&(*v as u64).to_ne_bytes());
        }
        let guard_at = 8 + 8 * cap;
        buf[guard_at..guard_at + 8].copy_from_slice(&0xDEAD_BEEF_DEAD_BEEFu64.to_ne_bytes());
        let ptr = buf.as_mut_ptr() as usize;
        (buf, ptr)
    }

    fn guards_intact(buf: &[u8], cap: usize) -> bool {
        let at = 8 + 8 * cap;
        u64::from_ne_bytes(buf[at..at + 8].try_into().unwrap()) == 0xDEAD_BEEF_DEAD_BEEF
    }

    #[test]
    fn reading_a_set_larger_than_the_placeholder_array_does_not_panic() {
        let vals: Vec<SOCKET> = (1..=100).collect();
        let (_buf, p) = make_set(100, &vals);
        let got = unsafe { fds_get(p as *const FdSetWin) };
        assert_eq!(got.len(), 100, "a 100-socket select() is ordinary");
        assert_eq!(got[99], 100);
    }

    #[test]
    fn refilling_never_writes_past_the_callers_count() {
        // The caller asked for room for 5 sockets. Shrinking to 2 and staying at 5 are
        // both legal; asking for more must be truncated, not written.
        let vals: Vec<SOCKET> = (1..=5).collect();
        let (mut buf, p) = make_set(5, &vals);
        let n = unsafe { fds_put(p as *mut FdSetWin, &[7, 8], 5) };
        assert_eq!(n, 2);
        assert!(guards_intact(&buf, 5), "trailer must stay inside the allocation");
        let over: Vec<SOCKET> = (1..=50).collect();
        let n = unsafe { fds_put(p as *mut FdSetWin, &over, 5) };
        assert_eq!(n, 5, "clamped to the declared capacity");
        assert!(guards_intact(&buf, 5), "clamping must actually clamp");
        assert_eq!(unsafe { fds_get(p as *const FdSetWin) }.len(), 5);
    }

}
