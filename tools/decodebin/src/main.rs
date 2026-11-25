use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

#[allow(non_snake_case)]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> isize;
    fn FreeLibrary(h: isize) -> i32;
    fn GetLastError() -> u32;
}

// sub_402430 : thiscall (this in ECX = out buffer), self-cleaning `ret 0x1c`.
type FnDecode = extern "thiscall" fn(
    out: *mut u32, key: *const u16, a1: u32, a2: u32, a3: u32,
    len: u32, limit: u32, err: *mut u8,
) -> u32;

const PE: &str = r"D:\Kane\WorkSpaces\tools\crafts\craft-trans-proxier\original\Proxifier PE\Proxifier.exe";
// sub_402430 has VA 0x402430; preferred base is 0x00400000, so RVA = 0x402430 - 0x400000.
const SUB_OFF: usize = 0x402430 - 0x400000;

fn load_base() -> Option<usize> {
    let w: Vec<u16> = OsStr::new(PE).encode_wide().into_iter().chain(Some(0)).collect();
    let h = unsafe { LoadLibraryW(w.as_ptr()) };
    if h == 0 {
        eprintln!("load failed err={}", unsafe { GetLastError() });
        None
    } else {
        Some(h as usize)
    }
}

fn decode(base: usize, key: &str, out: &mut [u32; 16], err: &mut [u8; 256]) -> u32 {
    let f: FnDecode = unsafe { std::mem::transmute((base + SUB_OFF) as *const u8) };
    let kb: Vec<u16> = key.encode_utf16().collect();
    err.iter_mut().for_each(|b| *b = 0);
    let r = unsafe { f(out.as_mut_ptr(), kb.as_ptr(), 0, 0, 0, kb.len() as u32, 8, err.as_mut_ptr()) };
    r
}

fn dump_key(key: &str, base: usize) {
    let mut out = [0u32; 16];
    let mut err = [0u8; 256];
    let r = decode(base, key, &mut out, &mut err);
    let mut w: Vec<u16> = (0..err.len() / 2)
        .map(|i| u16::from_le_bytes([err[2 * i], err[2 * i + 1]]))
        .collect();
    w.truncate(w.iter().position(|&x| x == 0).unwrap_or(w.len()));
    let estr = String::from_utf16_lossy(&w);
    let fields: Vec<String> = (0..8).map(|i| format!("{:08x}", out[i])).collect();
    println!("key={} AL={} out=[{}] err=\"{}\"", key, r, fields.join(" "), estr);
}

fn main() {
    let base = match load_base() { Some(b) => b, None => return };
    println!("base={:#x}", base);
    println!("--- built-in keys ---");
    for k in [
        "00000-00000-00000-00000-00000",
        "11111-11111-11111-11111-11111",
        "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA",
        "99999-99999-99999-99999-99999",
        "12345-67890-12345-67890-12345",
    ] {
        dump_key(k, base);
    }
    if let Ok(data) = std::fs::read_to_string("keys.txt") {
        println!("--- keys.txt ---");
        for line in data.lines() {
            let k = line.trim();
            if k.is_empty() { continue; }
            dump_key(k, base);
        }
    }
    unsafe { FreeLibrary(base as isize); }
}
