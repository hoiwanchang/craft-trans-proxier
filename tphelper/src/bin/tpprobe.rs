//! `tpprobe` — a minimal GUI(message-pumping) helper process used to prove the
//! transparent hook is injected CROSS-PROCESS (the in-process self-test cannot
//! show this). It pumps messages so Windows maps tpdrv.dll into it (via the
//! global WH_GETMESSAGE hook the engine installed), waits, then connects a
//! socket to an "external" address and round-trips a payload through whatever
//! proxy the engine chose — all WITHOUT this program configuring any proxy.
//!
//!   tpprobe <ipv4> <port> [payload]
//!
//! Prints `RESULT=OK <bytes>` on success (exit 0) or `RESULT=FAIL:<err>` (exit 1).
#![allow(non_snake_case)]

#[cfg(not(windows))]
fn main() {
    eprintln!("tpprobe is Windows-only");
    std::process::exit(2);
}

#[cfg(windows)]
fn main() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    let argv: Vec<String> = std::env::args().collect();
    let ip = argv.get(1).cloned().unwrap_or_else(|| "198.51.100.7".into());
    let port: u16 = argv.get(2).and_then(|s| s.parse().ok()).unwrap_or(80);
    let payload = argv.get(3).cloned().unwrap_or_else(|| "TPPROBE-PING".into());

    // Pump messages for ~1.5s so the global WH_GETMESSAGE hook (installed by the
    // engine) forces Windows to load tpdrv.dll into THIS process, whose DllMain
    // then inline-hooks ws2_32!connect here.
    pump_messages(Duration::from_millis(1500));

    // Did the injection actually happen?
    println!("{}", tpdrv_loaded());
    println!("{}", diag());
    println!("{}", pipe_selftest());

    let addr = format!("{ip}:{port}");
    match TcpStream::connect(&addr) {
        Ok(mut s) => {
            s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(8))).unwrap();
            if s.write_all(payload.as_bytes()).is_err() {
                println!("RESULT=FAIL:write");
                std::process::exit(1);
            }
            let mut got = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(8);
            let mut buf = [0u8; 256];
            while got.len() < payload.len() && Instant::now() < deadline {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            if got == payload.as_bytes() {
                println!("RESULT=OK {}", got.len());
                std::process::exit(0);
            } else {
                println!("RESULT=FAIL:mismatch got={:?}", String::from_utf8_lossy(&got));
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("RESULT=FAIL:connect {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn tpdrv_loaded() -> String {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut core::ffi::c_void;
    }
    let w: Vec<u16> = OsStr::new("tpdrv.dll").encode_wide().chain(std::iter::once(0)).collect();
    let h = unsafe { GetModuleHandleW(w.as_ptr()) };
    if h.is_null() {
        "INJECTED=0".to_string()
    } else {
        "INJECTED=1".to_string()
    }
}

#[cfg(windows)]
fn diag() -> String {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn OpenMutexW(access: u32, inherit: i32, name: *const u16) -> *mut c_void;
        fn LoadLibraryA(name: *const i8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const i8) -> *const c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
    }
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let mut out = String::new();
    // engine mutex visible?
    let mname: Vec<u16> = OsStr::new("tproxierPE").encode_wide().chain(std::iter::once(0)).collect();
    let h = unsafe { OpenMutexW(SYNCHRONIZE, 0, mname.as_ptr()) };
    out.push_str(if h.is_null() { "MUTEX_SEEN=0 " } else { "MUTEX_SEEN=1 " });
    if !h.is_null() {
        unsafe { CloseHandle(h) };
    }
    // is ws2_32!connect patched (starts with FF 25)?
    let ws2 = unsafe { LoadLibraryA(c"ws2_32.dll".as_ptr() as *const i8) };
    let c = unsafe { GetProcAddress(ws2, c"connect".as_ptr() as *const i8) };
    if c.is_null() {
        out.push_str("CONNECT_PATCHED=?");
    } else {
        let b0 = unsafe { *(c as *const u8) };
        let b1 = unsafe { *(c as *const u8).add(1) };
        out.push_str(if b0 == 0xFF && b1 == 0x25 { "CONNECT_PATCHED=1" } else { "CONNECT_PATCHED=0" });
    }
    out
}

#[cfg(windows)]
fn pipe_selftest() -> String {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn CallNamedPipeW(name: *const u16, inbuf: *const c_void, inlen: u32, outbuf: *mut c_void, outlen: u32, read: *mut u32, timeout: u32) -> i32;
        fn GetLastError() -> u32;
    }
    // Build a Req exactly as tpdrv's detour would: magic, pid, family, port_be, addr.
    let mut req = [0u8; 32];
    req[0..4].copy_from_slice(&0x5052_5831u32.to_le_bytes()); // "PRX1"
    // pid at 4..8
    let mut out = [0u8; 16];
    let mut read = 0u32;
    let name: Vec<u16> = OsStr::new(r"\\.\pipe\tproxierPE").encode_wide().chain(std::iter::once(0)).collect();
    let ok = unsafe { CallNamedPipeW(name.as_ptr(), req.as_ptr() as *const c_void, req.len() as u32, out.as_mut_ptr() as *mut c_void, out.len() as u32, &mut read, 3000) };
    if ok == 0 {
        format!("PIPE_SELFTEST=FAIL gle={} read={}", unsafe { GetLastError() }, read)
    } else {
        format!("PIPE_SELFTEST=OK read={read} action={} relay_port={}", u32::from_le_bytes([out[4],out[5],out[6],out[7]]), u16::from_le_bytes([out[12],out[13]]))
    }
}

#[cfg(windows)]
fn pump_messages(dur: std::time::Duration) {
    use std::ffi::c_void;
    use std::time::Instant;
    type BOOL = i32;
    const WM_USER: u32 = 0x0400;
    const PM_REMOVE: u32 = 0x0001;

    unsafe extern "system" {
        fn GetCurrentThreadId() -> u32;
    }
    #[link(name = "user32")]
    unsafe extern "system" {
        fn PostThreadMessageW(id: u32, msg: u32, wp: usize, lp: isize) -> BOOL;
        fn PeekMessageW(msg: *mut c_void, hwnd: *mut c_void, fltMin: u32, fltMax: u32, remove: u32) -> BOOL;
    }

    let tid = unsafe { GetCurrentThreadId() };
    let start = Instant::now();
    // A stack buffer acting as the MSG struct (we never inspect fields).
    let mut msg = [0u8; 64];
    while start.elapsed() < dur {
        unsafe {
            PostThreadMessageW(tid, WM_USER, 0, 0);
            // Drain whatever is queued — each retrieval invokes the message hook.
            for _ in 0..8 {
                if PeekMessageW(msg.as_mut_ptr() as *mut c_void, std::ptr::null_mut(), 0, 0, PM_REMOVE) == 0 {
                    break;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}
