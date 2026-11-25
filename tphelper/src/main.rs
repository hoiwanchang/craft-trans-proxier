//! `tphelper` — clean-room reconstruction of the original PE's `Helper64.exe`.
//!
//! Why it exists (finding fnd_6): the main engine (`the original.exe`) is 32-bit,
//! and a 32-bit process cannot install a hook DLL that will be mapped into a
//! 64-bit target. the original therefore spawns a bitness-matched helper. This
//! helper simply: loads the hook DLL, resolves `InitFilter3`, calls it (which
//! installs the global WH_GETMESSAGE hook), signals readiness, and waits.
//!
//! "This module is a part of the original Portable Edition. You cannot run it
//! directly." — we mirror that guard: it needs the driver path passed in.
#![allow(non_snake_case)]

#[cfg(not(windows))]
compile_error!("tphelper builds only for a *-pc-windows-* target");

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::process::exit;

type HANDLE = *mut c_void;
type HMODULE = *mut c_void;
type HHOOK = *mut c_void;
type BOOL = i32;
const TRUE: BOOL = 1;

unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> HMODULE;
    fn GetProcAddress(module: HMODULE, name: *const i8) -> *const c_void;
    fn FreeLibrary(module: HMODULE) -> BOOL;
    fn GetStdHandle(n: u32) -> HANDLE;
    fn WriteFile(h: HANDLE, buf: *const u8, n: u32, written: *mut u32, ov: *mut c_void) -> BOOL;
    fn CreateEventW(
        sa: *const c_void,
        manual_reset: BOOL,
        initial: BOOL,
        name: *const u16,
    ) -> HANDLE;
    fn SetEvent(h: HANDLE) -> BOOL;
    fn WaitForSingleObject(h: HANDLE, ms: u32) -> u32;
    fn CloseHandle(h: HANDLE) -> BOOL;
}

type InitFilter3Fn = extern "system" fn(HMODULE) -> HHOOK;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn eprint(s: &str) {
    let mut w = 0u32;
    let bytes = s.as_bytes();
    unsafe {
        WriteFile(GetStdHandle((-12i32) as u32), bytes.as_ptr(), bytes.len() as u32, &mut w, std::ptr::null_mut());
    }
}

fn main() {
    // The driver (hook DLL) path is required. Mirrors "You cannot run it
    // directly." — it is spawned by the engine with the path in argv[1].
    let driver = std::env::args().nth(1).unwrap_or_else(|| {
        eprint("tphelper: usage: tphelper <path-to-hook-dll> [session]\n");
        exit(2);
    });
    let session = std::env::args().nth(2).unwrap_or_default();

    // We are an installer, not a proxified target: mark this process as the
    // engine so the loaded DLL installs the global message hook (via InitFilter3)
    // but does NOT redirect this host's own sockets.
    unsafe extern "system" {
        fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> i32;
    }
    unsafe {
        SetEnvironmentVariableW(wide("TPROX_ENGINE").as_ptr(), wide("1").as_ptr());
    }

    let hmod = unsafe { LoadLibraryW(wide(&driver).as_ptr()) };
    if hmod.is_null() {
        eprint(&format!("tphelper: cannot load {driver}\n"));
        exit(3);
    }
    let proc = unsafe { GetProcAddress(hmod, c"InitFilter3".as_ptr() as *const i8) };
    if proc.is_null() {
        eprint("tphelper: InitFilter3 not found in hook DLL.\n");
        unsafe {
            FreeLibrary(hmod);
        }
        exit(4);
    }

    // Installing the global hook. dwThreadId=0 => every message-pumping process
    // gets the DLL mapped in, and its DllMain does the real socket hooking.
    let init: InitFilter3Fn = unsafe { std::mem::transmute(proc) };
    let _hhk = init(hmod);

    // Tell the engine we are up (matches the originalHelper64Ready%u).
    let ready_name = format!("tproxierHelperReady{session}");
    let ready = unsafe { CreateEventW(std::ptr::null(), TRUE, 0, wide(&ready_name).as_ptr()) };
    if ready != std::ptr::null_mut() {
        unsafe {
            SetEvent(ready);
        }
    }

    // Block until the engine signals it is tearing down (or forever if no name
    // given). The process must stay alive: a global hook is removed when its
    // installing module unloads, so the host must outlive proxification.
    if !session.is_empty() {
        let wait_name = format!("tproxierHelperWait{session}");
        let wait = unsafe { CreateEventW(std::ptr::null(), TRUE, 0, wide(&wait_name).as_ptr()) };
        if wait != std::ptr::null_mut() {
            // INFINITE
            unsafe {
                WaitForSingleObject(wait, 0xFFFF_FFFF);
                CloseHandle(wait);
            }
        }
    } else {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }

    unsafe {
        if !ready.is_null() {
            CloseHandle(ready);
        }
        FreeLibrary(hmod);
    }
}
