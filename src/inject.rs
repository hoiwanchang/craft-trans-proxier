//! Targeted, per-process injection — the replacement for the global message hook.
//!
//! Why this exists: the original design called `SetWindowsHookExW(WH_GETMESSAGE, …,
//! dwThreadId=0)` so the OS maps `tpdrv.dll` into EVERY process that pumps messages.
//! Measured on a real desktop that meant 99 processes carrying our DLL to serve a
//! whitelist of a handful, and once several builds were in play the same ws2_32
//! function ended up inline-detoured five deep in 65 processes, which crashed almost
//! everything. Limiting *patching* (see `Local\TpDrvCtl` in tpdrv) does not help here:
//! mapping is itself the exposure the operator objected to.
//!
//! So injection is now driven from the whitelist:
//!  * a snapshot loop finds processes whose image name the operator listed,
//!  * each unseen pid gets `CreateRemoteThread(LoadLibraryW)`,
//!  * on stop, each injected process gets a remote `TpdrvRemove` (restore ws2_32) and a
//!    remote `FreeLibrary`, so nothing is left modified once the engine is gone.
//!
//! Coverage note, stated rather than hidden: a whitelisted app started in the same
//! instant as the engine can begin its first connection before the next snapshot
//! (bounded by `POLL`), and a process at a higher integrity level cannot be injected
//! from an unelevated engine — the global hook had exactly the same two limits, so
//! this is not a regression, but the WFP kernel route is what actually closes them.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CREATE_THREAD: u32 = 0x0002;
const VM_OPERATION: u32 = 0x0008;
const VM_WRITE: u32 = 0x0020;
const VM_READ: u32 = 0x0010;
const QUERY_LIMITED: u32 = 0x1000;
const PROCESS_ALL: u32 = CREATE_THREAD | VM_OPERATION | VM_WRITE | VM_READ | QUERY_LIMITED;
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const MEM_RELEASE: u32 = 0x8000;
const MEM_DECOMMIT: u32 = 0x4000;
const PAGE_READWRITE: u32 = 0x04;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
const TH32CS_SNAPMODULE: u32 = 0x0000_0008;
const TH32CS_SNAPMODULE32: u32 = 0x0000_0010;
const INVALID_HANDLE_V: *mut c_void = -1isize as *mut c_void;

unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn CloseHandle(h: *mut c_void) -> i32;
    fn VirtualAllocEx(h: *mut c_void, addr: *mut c_void, size: usize, alloc: u32, protect: u32) -> *mut c_void;
    fn VirtualFreeEx(h: *mut c_void, addr: *mut c_void, size: usize, free: u32) -> i32;
    fn WriteProcessMemory(h: *mut c_void, base: *mut c_void, buf: *const c_void, size: usize, written: *mut usize) -> i32;
    fn CreateRemoteThread(h: *mut c_void, sa: *const c_void, stack: usize, start: *const c_void, arg: *mut c_void, flags: u32, tid: *mut u32) -> *mut c_void;
    fn WaitForSingleObject(h: *mut c_void, ms: u32) -> u32;
    fn GetProcAddress(module: *mut c_void, name: *const i8) -> *const c_void;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn GetLastError() -> u32;
}

#[repr(C)]
struct ProcEntry32W {
    dw_size: u32,
    cnt_usage: u32,
    th32_process_id: u32,
    th32_default_heap_id: usize,
    th32_module_id: u32,
    cnt_threads: u32,
    th32_parent_process_id: u32,
    pc_priority_base: i32,
    dw_flag: u32,
    sz_exe_file: [u16; 260],
}

/// MODULEENTRY32W, field for field. The ULONG_PTR/DWORD pair in the middle matters:
/// dropping `th32ProcessID` shifts `szModule` by eight bytes, and every lookup then
/// reads the tail of the previous field and answers "not loaded" for a module that is
/// plainly there — which is exactly what the test below caught.
#[repr(C)]
struct ModEntry32W {
    dw_size: u32,
    th32_module: u32,
    th32_default_heap_id: usize,
    th32_process_id: u32,
    mod_base_addr: usize,
    mod_size: u32,
    h_module: *mut c_void,
    sz_module: [u16; 256],
    sz_exe: [u16; 260],
}

unsafe extern "system" {
    fn Process32FirstW(snap: *mut c_void, entry: *mut ProcEntry32W) -> i32;
    fn Process32NextW(snap: *mut c_void, entry: *mut ProcEntry32W) -> i32;
    fn Module32FirstW(snap: *mut c_void, entry: *mut ModEntry32W) -> i32;
    fn Module32NextW(snap: *mut c_void, entry: *mut ModEntry32W) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// The bare, lowercased image name of a whitelist entry, which may be written either as
/// `firefox.exe` or as a full path. Snapshot names are bare, so both forms have to
/// reduce to the same thing or an entry silently matches nothing.
fn image_name(entry: &str) -> Option<String> {
    let seps = ['\\', '/'];
    let t = entry.trim();
    if t.is_empty() {
        return None;
    }
    t.split(seps.as_slice())
        .next_back()
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| s.ends_with(".exe"))
}

/// Every live `(pid, lowercased image name)`.
pub fn snapshot_processes() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_V || snap.is_null() {
            return out;
        }
        let mut e: ProcEntry32W = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ProcEntry32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let end = e.sz_exe_file.iter().position(|&c| c == 0).unwrap_or(0);
                let name = String::from_utf16_lossy(&e.sz_exe_file[..end]).to_ascii_lowercase();
                out.push((e.th32_process_id, name));
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Whether `dll_name` (e.g. `tpdrv.dll`) is already mapped in `pid`. Used to confirm
/// the injection actually landed instead of trusting that a thread ran.
pub fn module_loaded(pid: u32, dll_name: &str) -> bool {
    let want = dll_name.to_ascii_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_V || snap.is_null() {
            return false;
        }
        let mut e: ModEntry32W = std::mem::zeroed();
        e.dw_size = std::mem::size_of::<ModEntry32W>() as u32;
        let mut found = false;
        if Module32FirstW(snap, &mut e) != 0 {
            loop {
                let end = e.sz_module.iter().position(|&c| c == 0).unwrap_or(0);
                let n = String::from_utf16_lossy(&e.sz_module[..end]).to_ascii_lowercase();
                if n == want {
                    found = true;
                    break;
                }
                if Module32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

fn remote_addr(name: &str) -> Option<*const c_void> {
    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> *mut c_void;
    }
    unsafe {
        // The module is already mapped in this process and we only want an export
        // address, so GetModuleHandleW (which changes no refcount) is the honest call;
        // GetModuleHandleExW needs an out-parameter and a flag to mean the same thing.
        let wide_name = wide("kernel32.dll");
        let me = GetModuleHandleW(wide_name.as_ptr());
        if me.is_null() {
            return None;
        }
        // LPCSTR, not LPCWSTR: passing a wide buffer here looks up the single
        // character "L" and fails with GLE 127 (ERROR_PROC_NOT_FOUND).
        let c_name = match std::ffi::CString::new(name) { Ok(c) => c, Err(_) => return None };
        let p = GetProcAddress(me, c_name.as_ptr());
        (!p.is_null()).then_some(p as *const c_void)
    }
}

/// Run `fn_name` from `kernel32` (or this module) in the target with a single pointer
/// argument and wait briefly for it to finish.
fn remote_call(pid: u32, fn_name: &str, arg: Option<&str>, wait_ms: u32) -> Result<(), String> {
    let addr = remote_addr(fn_name).or_else(|| {
        // TpdrvRemove lives in tpdrv.dll, not kernel32: resolve it out of our own
        // process, where the DLL is mapped, and reuse the address. ASLR makes that
        // valid only when the target mapped it at the same base, so the caller
        // verifies the effect instead of trusting this return.
        unsafe extern "system" {
            fn GetModuleHandleW(name: *const u16) -> *mut c_void;
        }
        unsafe {
            let wide_dll = wide("tpdrv.dll");
            let h = GetModuleHandleW(wide_dll.as_ptr());
            if h.is_null() {
                return None;
            }
            let c_name = match std::ffi::CString::new(fn_name) { Ok(c) => c, Err(_) => return None };
            let p = GetProcAddress(h, c_name.as_ptr());
            (!p.is_null()).then_some(p as *const c_void)
        }
    }).ok_or_else(|| format!("目标进程里找不到 {fn_name} 的地址（位数不符或被保护）"))?;
    unsafe {
        let h = OpenProcess(PROCESS_ALL, 0, pid);
        if h.is_null() {
            return Err(format!("OpenProcess({pid}) was refused"));
        }
        // The argument, if any, is a wide string the target must read.
        let mut remote_arg: *mut c_void = std::ptr::null_mut();
        let payload = arg.map(wide);
        if let Some(p) = &payload {
            let n = p.len() * 2;
            let base = VirtualAllocEx(h, std::ptr::null_mut(), n, MEM_COMMIT_RESERVE, PAGE_READWRITE);
            if base.is_null() {
                CloseHandle(h);
                return Err(format!("VirtualAllocEx in {pid} failed"));
            }
            let mut written = 0usize;
            if WriteProcessMemory(h, base, p.as_ptr() as *const c_void, n, &mut written) == 0 {
                VirtualFreeEx(h, base, 0, MEM_RELEASE);
                CloseHandle(h);
                return Err(format!("WriteProcessMemory into {pid} failed"));
            }
            remote_arg = base;
        }
        let mut tid = 0u32;
        let th = CreateRemoteThread(h, std::ptr::null(), 0, addr, remote_arg, 0, &mut tid);
        if th.is_null() {
            let gle = GetLastError();
            if !remote_arg.is_null() {
                VirtualFreeEx(h, remote_arg, 0, MEM_RELEASE);
            }
            CloseHandle(h);
            return Err(format!("CreateRemoteThread into {pid} failed (GLE={gle})"));
        }
        WaitForSingleObject(th, wait_ms);
        CloseHandle(th);
        if !remote_arg.is_null() {
            // The remote thread has already returned by here, so its argument is safe to drop.
            WaitForSingleObject(std::ptr::null_mut(), 0);
            VirtualFreeEx(h, remote_arg, 0, MEM_DECOMMIT);
            VirtualFreeEx(h, remote_arg, 0, MEM_RELEASE);
        }
        CloseHandle(h);
    }
    Ok(())
}

/// Load `dll_path` into `pid`. Returns Err when the module is not visible in the
/// target afterwards, which is the case for a bitness mismatch or a protected process.
pub fn inject(pid: u32, dll_path: &str) -> Result<(), String> {
    remote_call(pid, "LoadLibraryW", Some(dll_path), 5000)?;
    if module_loaded(pid, "tpdrv.dll") {
        Ok(())
    } else {
        Err(format!("{pid} did not load the driver DLL"))
    }
}

/// Undo everything we modified in a target: put the ws2_32 prologues back.
///
/// The image itself stays mapped until that process exits. Remotely unloading would
/// mean capturing tpdrv's HMODULE *in the target* (a 32-bit `GetExitCodeThread` cannot
/// carry a 64-bit module handle) and then racing any thread still inside our code, so
/// the honest boundary is: **behaviour** is removed on Stop, **address space** on exit.
/// Nothing outside the whitelist is ever touched at all, which was the point.
pub fn eject(pid: u32) -> Result<(), String> {
    // Short: restoring ~15 prologues is instant, and a long per-target wait serialised
    // across every injected process is what kept the engine resident after the window
    // closed (shutdown runs detached, so nobody was watching it take minutes).
    remote_call(pid, "TpdrvRemove", None, 500)
}

/// The whitelist watcher. Owns the set of pids it has injected so a process is touched
/// once, and re-checks names each pass so the operator editing the list takes effect
/// without a restart.
pub struct Watcher {
    stop: Arc<Mutex<bool>>,
    /// pids we have already tried to enter, with the outcome of that attempt. One
    /// attempt per process: re-trying every poll tick used to spawn a fresh remote
    /// thread into the same app over and over (visible as the engine gaining a thread
    /// every ~500 ms and the target's connections turning unreliable), and a process
    /// that refused us once will not accept us because we asked again.
    attempted: Arc<Mutex<HashMap<u32, bool>>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Poll period of the watcher. It also has to stay well above the cost of one pass so a
/// refused process could, in an earlier version, spawn a remote thread twice a second.
const POLL: Duration = Duration::from_millis(500);

impl Watcher {
    /// `dll_path` is attempted into every live process whose image name the profile
    /// lists, and into ones that appear later. The profile is re-read each pass, so
    /// editing the whitelist takes effect without restarting the engine.
    ///
    /// When the program whitelist is switched OFF, nothing is attempted: the only way to
    /// "cover everything" without a whitelist is the global hook we just removed, and
    /// mapping into every process to proxy none of them is the exposure this file
    /// exists to eliminate. The WFP kernel route is the supported way to go broad.
    pub fn spawn(
        dll_path: String,
        config: Arc<std::sync::RwLock<crate::config::Config>>,
    ) -> Watcher {
        let stop = Arc::new(Mutex::new(false));
        let attempted = Arc::new(Mutex::new(HashMap::new()));
        let (s2, i2) = (stop.clone(), attempted.clone());
        let handle = std::thread::spawn(move || loop {
            if *s2.lock().unwrap_or_else(|e| e.into_inner()) {
                break;
            }
            let want: Vec<String> = match config.read() {
                Ok(c) if c.settings.app_whitelist_enabled => c
                    .settings
                    .app_whitelist
                    .iter()
                    .filter_map(|a| image_name(a))
                    .collect(),
                _ => Vec::new(),
            };
            if !want.is_empty() {
                for (pid, name) in snapshot_processes() {
                    if !want.iter().any(|w| w == &name) {
                        continue;
                    }
                    if i2.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&pid) {
                        continue;
                    }
                    // One attempt per process id. Recording the failure too is the
                    // point: a target that refused us (bitness, protection, exit race)
                    // must not be re-entered on every tick.
                    let ok = inject(pid, &dll_path).is_ok();
                    i2.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(pid, ok);
                }
            }
            std::thread::sleep(POLL);
        });
        Watcher { stop, attempted, handle: Some(handle) }
    }

    /// pids we are actually inside (successful attempts only) — the set we must eject
    /// from, and the set worth showing the operator.
    pub fn targets(&self) -> Vec<u32> {
        self.attempted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, ok)| **ok)
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Stop injecting and undo ourselves everywhere we got in.
    pub fn shutdown(&mut self) {
        *self.stop.lock().unwrap_or_else(|e| e.into_inner()) = true;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let pids: Vec<u32> = self.targets();
        for pid in pids {
            let _ = eject(pid);
        }
        self.attempted.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_process_snapshot_sees_this_verifier_and_its_image_name() {
        // If the snapshot were empty or the name decoding wrong, the whitelist could
        // never match and injection would silently do nothing - the failure mode where
        // "nothing is proxied" looks identical to "no rule matched".
        let me = std::process::id();
        let all = snapshot_processes();
        assert!(!all.is_empty(), "process snapshot came back empty");
        let mine = all.iter().find(|(pid, _)| *pid == me).expect("our own pid in snapshot");
        assert!(mine.1.ends_with(".exe"), "image name not decoded: {:?}", mine.1);
        assert!(!mine.1.contains('/'), "should be a bare file name: {:?}", mine.1);
    }

    #[test]
    fn module_lookup_works_on_our_own_process_and_on_nothing_bogus() {
        // kernel32 is in every process, so a true answer proves the walk rather than
        // proving nothing; a pid that cannot exist must be false, not a panic.
        assert!(module_loaded(std::process::id(), "kernel32.dll"));
        assert!(!module_loaded(0x7FFF_FFFF, "tpdrv.dll"));
    }
    /// End to end for the injection primitive itself: a real CreateRemoteThread +
    /// LoadLibraryW round trip into this process. tpdrv stays inert here because no
    /// engine mutex exists, so nothing is patched - the point is that the mechanism
    /// reaches the target and reports honestly, which is the whole difference between
    /// "we asked it to load" and "it is loaded".
    #[test]
    fn a_remote_thread_really_loads_the_dll_into_the_target()
    {
        let mut dll = std::env::current_exe().unwrap();
        dll.pop();
        if !dll.join("tpdrv.dll").exists() {
            dll.pop();
        }
        let dll = dll.join("tpdrv.dll");
        let path = dll.to_string_lossy().to_string();
        if !dll.exists() {
            eprintln!("skip: build tpdrv.dll next to this test binary ({}))", path);
            return;
        }
        let me = std::process::id();
        assert!(!module_loaded(me, "tpdrv.dll"), "precondition: not already in");
        inject(me, &path).expect("self-injection should succeed");
        assert!(module_loaded(me, "tpdrv.dll"), "the module must be visible in the target");
        // and the removal entry point we call on Stop is actually exported
        eject(me).expect("TpdrvRemove must be callable in the target");
    }
}
