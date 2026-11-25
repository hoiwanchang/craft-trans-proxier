use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[allow(non_snake_case)]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> isize;
    fn FreeLibrary(h: isize) -> i32;
    fn GetLastError() -> u32;
}

// thiscall: this(out) in ECX, then stack args: key=[ebp+8] len=[ebp+0x18] limit=[ebp+0x1c] err=[ebp+0x20]
type FnKey = extern "this" fn(
    out: *mut u32,
    key: *const u16, a1: u32, a2: u32, a3: u32, len: u32, limit: u32, err: u32,
) -> u32;

fn load_image(path: &str) -> isize {
    let w: Vec<u16> = OsStr::new(path).encode_wide().into_iter().chain(Some(0)).collect();
    unsafe { LoadLibraryW(w.as_ptr()) }
}

unsafe fn decode(base: isize, key: &str) -> u32 {
    let f: FnKey = std::mem::transmute((base as usize) + 0x402430);
    let mut kb: Vec<u16> = key.encode_utf16().collect();
    kb.push(0);
    let mut out = [0u32; 16];
    let r = f(out.as_mut_ptr(), kb.as_ptr(), 0, 0, 0, 29, 8, 0);
    let r = r; // AL
    // print out fields
    let mut s = String::new();
    for v in out.iter() { s.push_str(&format!("{:08x}", v)); }
    eprintln!("  out = {}", s);
    r
}

fn main() {
    let path = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe";
    let h = unsafe { load_image(path) };
    println!("handle={:#x}", h);
    if h == 0 { println!("load failed err={}", unsafe { GetLastError() }); return; }
    for k in [
        "00000-00000-00000-00000-00000",
        "11111-11111-11111-11111-11111",
        "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
        "99999-99999-99999-99999-99999",
    ] {
        let r = unsafe { decode(h, k) };
        println!("key={} -> {}", k, r);
    }
    unsafe { FreeLibrary(h); }
}
