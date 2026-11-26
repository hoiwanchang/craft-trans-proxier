//! Run-at-logon registration for the desktop app.
//!
//! Scope, stated plainly: this is the **user** logon path (`HKCU\...\Run`), which starts
//! after someone signs in and runs in that person's session. It deliberately does NOT
//! pretend to be a service: the engine's IPC is session-local today (`\\.\pipe\tproxierPE`
//! with no `Global\` prefix, a session-scoped mutex, and `Local\TpDrvCtl`), so the same
//! binary launched in session 0 would publish objects no injected application can see —
//! it would appear to run while proxifying nothing. Making that case work is a separate
//! change (Global names + an SDDL that lets the interactive user connect, plus turning the
//! tray into a client of the service), not a flag here.
//!
//! Writing to the registry is an action on the operator's machine, so nothing in this
//! module runs implicitly: it is reached only from `autostart install` / the 选项 checkbox.

#![cfg(windows)]

use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = "trans-proxier";

unsafe extern "system" {
    fn RegOpenKeyExW(hkey: *mut c_void, sub: *const u16, options: u32, access: u32, out: *mut *mut c_void) -> i32;
    fn RegSetValueExW(hkey: *mut c_void, name: *const u16, reserved: u32, kind: u32, data: *const u8, len: u32) -> i32;
    fn RegDeleteValueW(hkey: *mut c_void, name: *const u16) -> i32;
    fn RegCloseKey(hkey: *mut c_void) -> i32;
    fn RegQueryValueExW(hkey: *mut c_void, name: *const u16, reserved: *mut u32, kind: *mut u32, data: *mut u8, len: *mut u32) -> i32;
}

const HKEY_CURRENT_USER: *mut c_void = 0x8000_0001 as *mut c_void;
const KEY_WRITE: u32 = 0x20006;
const KEY_READ: u32 = 0x20019;
const REG_SZ: u32 = 1;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;

fn w(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// The command line stored in the Run key.
///
/// Quoting matters and is easy to get wrong: the install path contains spaces on most
/// machines (`C:\Program Files\...`), and an unquoted value is parsed by the shell as
/// "run `C:\Program` with argument `Files\...`" — a silent failure at logon, the worst
/// possible time to discover it. Existing quoting is preserved rather than doubled.
pub fn run_command(exe: &str) -> String {
    let trimmed = exe.trim();
    if trimmed.starts_with('"') {
        format!("{trimmed} --minimised")
    } else {
        format!("\"{trimmed}\" --minimised")
    }
}

fn open_run(access: u32) -> Option<*mut c_void> {
    unsafe {
        let mut h = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CURRENT_USER, w(RUN_KEY).as_ptr(), 0, access, &mut h) == ERROR_SUCCESS {
            Some(h)
        } else {
            None
        }
    }
}

/// Register the app to start at logon. Idempotent.
pub fn install(exe: &str) -> Result<String, String> {
    let cmd = run_command(exe);
    let h = open_run(KEY_WRITE).ok_or_else(|| format!("cannot open HKCU\\{RUN_KEY}"))?;
    let val = w(cmd.as_str());
    let bytes = unsafe { std::slice::from_raw_parts(val.as_ptr() as *const u8, (val.len() * 2) - 2) };
    let r = unsafe {
        RegSetValueExW(
            h,
            w(VALUE_NAME).as_ptr(),
            0,
            REG_SZ,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    unsafe { RegCloseKey(h) };
    if r != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW failed ({r})"));
    }
    Ok(cmd)
}

/// Remove the logon entry. Absent is success — the point is the end state.
pub fn remove() -> Result<(), String> {
    let Some(h) = open_run(KEY_WRITE) else { return Ok(()) };
    let r = unsafe { RegDeleteValueW(h, w(VALUE_NAME).as_ptr()) };
    unsafe { RegCloseKey(h) };
    match r {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        other => Err(format!("RegDeleteValueW failed ({other})")),
    }
}

/// What (if anything) is registered right now.
pub fn status() -> Result<Option<String>, String> {
    let Some(h) = open_run(KEY_READ) else { return Ok(None) };
    let mut kind = 0u32;
    let mut len = 0u32;
    let name = w(VALUE_NAME);
    let probe = unsafe {
        RegQueryValueExW(h, name.as_ptr(), std::ptr::null_mut(), &mut kind, std::ptr::null_mut(), &mut len)
    };
    if probe != ERROR_SUCCESS || len == 0 || kind != REG_SZ {
        unsafe { RegCloseKey(h) };
        return Ok(None);
    }
    let mut buf = vec![0u8; len as usize];
    let mut len2 = len;
    let got = unsafe { RegQueryValueExW(h, name.as_ptr(), std::ptr::null_mut(), &mut kind, buf.as_mut_ptr(), &mut len2) };
    unsafe { RegCloseKey(h) };
    if got != ERROR_SUCCESS {
        return Ok(None);
    }
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let s = String::from_utf16_lossy(&units);
    Ok(Some(s.trim_end_matches('\0').to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_spaces_is_quoted_because_the_shell_splits_on_them() {
        let got = run_command(r"C:\Program Files\trans-proxier\trans-proxier.exe");
        assert!(
            got.starts_with('"') && got.contains(r"Program Files") && got.ends_with("--minimised"),
            "unquoted Run values are truncated at the first space at logon: {got}"
        );
        // and a pre-quoted value must not gain a second pair
        assert_eq!(run_command("\"D:\\a b\\x.exe\""), "\"D:\\a b\\x.exe\" --minimised");
    }

    #[test]
    fn the_value_name_is_stable_and_scoped_to_us() {
        // A renamed value would leave the old entry behind at logon forever, so the key
        // name is part of the contract, not an implementation detail.
        assert_eq!(VALUE_NAME, "trans-proxier");
        assert_eq!(RUN_KEY, r"Software\Microsoft\Windows\CurrentVersion\Run");
    }

    /// Read-only: proves we can ask the registry without touching it. Never writes here —
    /// a unit test must not modify the machine it runs on.
    #[test]
    fn status_reads_without_side_effects_and_never_panics() {
        let s = status().expect("reading HKCU Run must not error out right here");
        if let Some(v) = &s {
            assert!(v.contains(".exe"), "unexpected Run value shape: {v}");
        }
    }
}
