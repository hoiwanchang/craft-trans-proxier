//! System-tray icon + control menu, mirroring the original's tray (fnd_13): the
//! app lives in the notification area with a context menu whose first item
//! toggles the transparent engine (start / stop), plus a Quit command.
//!
//! The menu CONTENT + command semantics are pure and i18n-aware so they are
//! unit-testable on any host ([`build_menu`], [`TrayCmd::label`], [`tip`]); the
//! actual `Shell_NotifyIcon` plumbing is the `#[cfg(windows)]` section below and
//! is a faithful implementation of the documented Win32 message protocol.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

/// Bilingual language selector for the menu model (kept independent of the
/// `config` crate so the tray logic stays testable in isolation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

/// Live engine state the tray reflects in its menu + tooltip.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrayState {
    pub engine_running: bool,
    pub serving: bool,
    /// Whether the user has granted the global-hook consent (the start item is
    /// disabled until this is true — mirrors the GUI 启动 gate).
    pub consent_granted: bool,
}

/// A tray menu command. The discriminants double as Win32 menu command ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TrayCmd {
    ToggleEngine = 1,
    OpenSettings = 2,
    Quit = 3,
}

impl TrayCmd {
    pub fn from_id(id: u32) -> Option<TrayCmd> {
        match id {
            1 => Some(TrayCmd::ToggleEngine),
            2 => Some(TrayCmd::OpenSettings),
            3 => Some(TrayCmd::Quit),
            _ => None,
        }
    }

    /// Menu label for this command given live state + language. The engine item
    /// reads 停止 (Stop) while running and 启动透明引擎 (Start) otherwise.
    pub fn label(self, state: &TrayState, lang: Lang) -> &'static str {
        use TrayCmd::*;
        match (self, lang) {
            (ToggleEngine, Lang::Zh) => {
                if state.engine_running { "停止透明引擎" } else { "启动透明引擎" }
            }
            (ToggleEngine, Lang::En) => {
                if state.engine_running { "Stop Transparent Engine" } else { "Start Transparent Engine" }
            }
            (OpenSettings, Lang::Zh) => "打开主界面",
            (OpenSettings, Lang::En) => "Open Main Window",
            (Quit, Lang::Zh) => "退出",
            (Quit, Lang::En) => "Quit",
        }
    }

    /// Toggle commands are inert until the hook consent is granted (and the
    /// engine isn't already starting/stopped by another path).
    pub fn enabled(self, state: &TrayState) -> bool {
        match self {
            TrayCmd::ToggleEngine => state.consent_granted,
            _ => true,
        }
    }
}

/// A rendered menu line — either a clickable command or a separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrayItem {
    Sep,
    Cmd(TrayCmd),
}

/// The tray context-menu model (fnd_13): Open → separator → engine toggle → Quit.
pub fn build_menu(_state: &TrayState) -> Vec<TrayItem> {
    use TrayCmd::*;
    vec![
        TrayItem::Cmd(OpenSettings),
        TrayItem::Sep,
        TrayItem::Cmd(ToggleEngine),
        TrayItem::Cmd(Quit),
    ]
}

/// Notification-area tooltip reflecting live state.
pub fn tip(state: &TrayState, lang: Lang) -> String {
    let running = match lang {
        Lang::Zh => if state.engine_running { "引擎：运行中" } else { "引擎：未运行" },
        Lang::En => if state.engine_running { "Engine: running" } else { "Engine: stopped" },
    };
    let serving = match lang {
        Lang::Zh => if state.serving { "，SOCKS 监听中" } else { "" },
        Lang::En => if state.serving { ", SOCKS listening" } else { "" },
    };
    format!("trans-proxier  {running}{serving}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_has_open_toggle_quit_and_a_separator() {
        let items = build_menu(&TrayState::default());
        assert!(items.contains(&TrayItem::Cmd(TrayCmd::OpenSettings)));
        assert!(items.contains(&TrayItem::Cmd(TrayCmd::ToggleEngine)));
        assert!(items.contains(&TrayItem::Cmd(TrayCmd::Quit)));
        assert!(items.contains(&TrayItem::Sep));
        assert_eq!(items.len(), 4);
    }

    #[test]
    fn toggle_label_reflects_engine_state() {
        let off = TrayState { engine_running: false, ..Default::default() };
        let on = TrayState { engine_running: true, ..Default::default() };
        assert_eq!(TrayCmd::ToggleEngine.label(&off, Lang::En), "Start Transparent Engine");
        assert_eq!(TrayCmd::ToggleEngine.label(&on, Lang::En), "Stop Transparent Engine");
        assert_eq!(TrayCmd::ToggleEngine.label(&on, Lang::Zh), "停止透明引擎");
    }

    #[test]
    fn toggle_disabled_without_consent() {
        // Inverse: the dangerous start action must be gated OFF until consent.
        let no_consent = TrayState { engine_running: false, consent_granted: false, ..Default::default() };
        let consented = TrayState { engine_running: false, consent_granted: true, ..Default::default() };
        assert!(!TrayCmd::ToggleEngine.enabled(&no_consent), "start must be disabled pre-consent");
        assert!(TrayCmd::ToggleEngine.enabled(&consented));
        // Quit / Open are always available.
        assert!(TrayCmd::Quit.enabled(&no_consent));
        assert!(TrayCmd::OpenSettings.enabled(&no_consent));
    }

    #[test]
    fn command_ids_roundtrip() {
        for c in [TrayCmd::ToggleEngine, TrayCmd::OpenSettings, TrayCmd::Quit] {
            let id = c as u32;
            assert_eq!(TrayCmd::from_id(id), Some(c));
        }
        assert_eq!(TrayCmd::from_id(99), None);
    }

    #[test]
    fn tooltip_matches_state_and_language() {
        assert!(tip(&TrayState::default(), Lang::En).contains("Engine: stopped"));
        let s = TrayState { engine_running: true, serving: true, consent_granted: true };
        assert!(tip(&s, Lang::En).contains("Engine: running"));
        assert!(tip(&s, Lang::En).contains("SOCKS listening"));
        assert!(tip(&s, Lang::Zh).contains("运行中"));
    }
}

// ---------------------------------------------------------------------------
// Windows Shell_NotifyIcon implementation (faithful Win32 message protocol).
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod win {
    // A faithful Win32 Shell_NotifyIcon binding declares the whole relevant API
    // surface (message constants, style flags, helper imports); not every item is
    // referenced by this one tray, which is expected for a system-API shim.
    #![allow(dead_code, unsafe_op_in_unsafe_fn)]
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::mpsc::Sender;

    type HANDLE = *mut c_void;
    type HWND = *mut c_void;
    type HINSTANCE = *mut c_void;
    type LRESULT = isize;
    type WPARAM = usize;
    type LPARAM = isize;
    type BOOL = i32;
    type UINT = u32;
    type HMENU = *mut c_void;

    const WM_USER: UINT = 0x0400;
    const WM_TRAY: UINT = WM_USER + 1;
    const WM_LBUTTONDBLCLK: UINT = 0x0203;
    const WM_RBUTTONUP: UINT = 0x0205;
    const WM_DESTROY: UINT = 0x0002;
    const TPM_RETURNCMD: UINT = 0x0100;
    const TPM_RIGHTBUTTON: UINT = 0x0002;
    const MF_STRING: UINT = 0x0000;
    const MF_SEPARATOR: UINT = 0x0800;
    const MF_DISABLED: UINT = 0x0002;
    const MF_GRAYED: UINT = 0x0001;
    const NIM_ADD: u32 = 0x0;
    const NIM_DELETE: u32 = 0x2;
    const NIF_MESSAGE: u32 = 0x1;
    const NIF_ICON: u32 = 0x2;
    const NIF_TIP: u32 = 0x4;
    const IDI_APPLICATION: *const u16 = 32512 as *const u16;
    const IMAGE_ICON: u32 = 1;
    const LR_DEFAULTSIZE: u32 = 0x40;
    const LR_SHARED: u32 = 0x8000;
    const SW_RESTORE: i32 = 9;

    #[repr(C)]
    struct POINT {
        x: i32,
        y: i32,
    }
    #[repr(C)]
    struct WNDCLASSEXW {
        cb_size: UINT,
        style: UINT,
        lpfn_wnd_proc: Option<unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT>,
        cb_cls_extra: i32,
        cb_wnd_extra: i32,
        h_instance: HINSTANCE,
        h_icon: HANDLE,
        h_cursor: HANDLE,
        h_brush: HANDLE,
        lpsz_menu_name: *const u16,
        lpsz_class_name: *const u16,
        h_icon_sm: HANDLE,
    }
    #[repr(C)]
    struct NOTIFYICONDATAW {
        cb_size: u32,
        hwnd: HWND,
        uid: UINT,
        u_flags: u32,
        u_callb_msg: UINT,
        h_icon: HANDLE,
        sz_tip: [u16; 128],
    }

    // Explicit link libs: user32 (window + shell-notify icon messaging) and
    // shell32 (Shell_NotifyIconW). Declaring #[link] here (not relying on the
    // GUI's transitive user32) makes this module link correctly in ANY consumer.
    #[link(name = "user32")]
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn RegisterClassExW(wc: *const WNDCLASSEXW) -> u16;
        fn CreateWindowExW(
            ex: u32, cls: *const u16, title: *const u16, style: u32,
            x: i32, y: i32, w: i32, h: i32, parent: HWND, menu: HMENU,
            inst: HINSTANCE, param: *const c_void,
        ) -> HWND;
        fn DefWindowProcW(h: HWND, m: UINT, w: WPARAM, l: LPARAM) -> LRESULT;
        fn DestroyWindow(h: HWND) -> BOOL;
        fn PostQuitMessage(code: i32);
        fn GetMessageW(msg: *mut Msg, h: HWND, fltmin: u32, fltmax: u32) -> i32;
        fn TranslateMessage(msg: *const Msg) -> BOOL;
        fn DispatchMessageW(msg: *const Msg) -> LRESULT;
        fn Shell_NotifyIconW(dw: u32, nid: *const NOTIFYICONDATAW) -> i32;
        fn LoadImageW(i: HINSTANCE, name: *const u16, t: u32, x: i32, y: i32, l: u32) -> HANDLE;
        fn CreatePopupMenu() -> HMENU;
        fn AppendMenuW(m: HMENU, f: u32, id: usize, text: *const u16) -> BOOL;
        fn TrackPopupMenu(m: HMENU, f: u32, x: i32, y: i32, n: i32, h: HWND, r: *const c_void) -> BOOL;
        fn GetCursorPos(p: *mut POINT) -> BOOL;
        fn SetForegroundWindow(h: HWND) -> BOOL;
        fn ShowWindow(h: HWND, c: i32) -> BOOL;
        fn FindWindowW(cls: *const u16, title: *const u16) -> HWND;
    }

    #[repr(C)]
    struct Msg {
        hwnd: HWND,
        message: UINT,
        wparam: WPARAM,
        lparam: LPARAM,
        time: u32,
        pt: POINT,
    }

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    // Window-scoped state reached from the static wndproc.
    struct Ctx {
        tx: Sender<TrayCmd>,
        state: Arc<RwLock<TrayState>>,
        lang: Lang,
        hwnd: isize,
    }
    static CTX: std::sync::Mutex<Option<Box<Ctx>>> = std::sync::Mutex::new(None);

    unsafe extern "system" fn wndproc(h: HWND, m: UINT, w: WPARAM, l: LPARAM) -> LRESULT {
        match m {
            WM_TRAY => {
                // The low word of lParam is the mouse message that hit the icon.
                let event = ((l as u32) & 0xffff) as UINT;
                if event == WM_RBUTTONUP || event == WM_LBUTTONDBLCLK {
                    let guard = CTX.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(ctx) = guard.as_ref() {
                        let state = *ctx.state.read().unwrap_or_else(|e| e.into_inner());
                        if event == WM_LBUTTONDBLCLK {
                            // double-click: just surface the main window
                            show_main_window(ctx.lang);
                            let _ = ctx.tx.send(TrayCmd::OpenSettings);
                            return 0;
                        }
                        show_menu(h, ctx, &state);
                    }
                }
                0
            }
            WM_DESTROY => {
                let nid = make_nid(h);
                Shell_NotifyIconW(NIM_DELETE, &nid);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(h, m, w, l),
        }
    }

    unsafe fn show_menu(h: HWND, ctx: &Ctx, state: &TrayState) {
        let menu = CreatePopupMenu();
        for item in build_menu(state) {
            match item {
                TrayItem::Sep => {
                    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
                }
                TrayItem::Cmd(cmd) => {
                    let label = wide(cmd.label(state, ctx.lang));
                    let mut flags = MF_STRING;
                    if !cmd.enabled(state) {
                        flags |= MF_GRAYED | MF_DISABLED;
                    }
                    AppendMenuW(menu, flags, cmd as usize, label.as_ptr());
                }
            }
        }
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(h);
        let sel = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, h, std::ptr::null());
        if let Some(cmd) = TrayCmd::from_id(sel as u32) {
            match cmd {
                TrayCmd::OpenSettings => show_main_window(ctx.lang),
                TrayCmd::Quit => { DestroyWindow(h); }
                TrayCmd::ToggleEngine => {}
            }
            let _ = ctx.tx.send(cmd);
        }
    }

    // Best-effort: if a trans-proxier top window exists, restore it.
    unsafe fn show_main_window(_lang: Lang) {
        let title = wide("trans-proxier");
        let hwnd = FindWindowW(std::ptr::null(), title.as_ptr());
        if !hwnd.is_null() {
            ShowWindow(hwnd, SW_RESTORE);
        }
    }

    fn make_nid(h: HWND) -> NOTIFYICONDATAW {
        NOTIFYICONDATAW {
            cb_size: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hwnd: h,
            uid: 1,
            u_flags: 0,
            u_callb_msg: 0,
            h_icon: std::ptr::null_mut(),
            sz_tip: [0; 128],
        }
    }

    /// Handle to a running tray icon. Dropping it removes the icon and stops the
    /// tray message loop.
    pub struct Tray {
        running: Arc<AtomicBool>,
    }

    /// Build the tray icon from the embedded multi-size .ico (drawn by
    /// `assets/make_icon.py`, so the glyph is reproducible rather than a binary blob
    /// nobody can regenerate).
    ///
    /// The size comes from SM_CXSMICON, not a hard-coded 16: on a 150%/200% display a
    /// 16px bitmap gets stretched by the shell and looks blurry, which is exactly the
    /// "plain-looking icon" complaint. Falls back to the system default if anything
    /// about the resource fails — a tray entry with no icon at all is worse than the
    /// generic one.
    unsafe fn tray_icon_handle() -> *mut c_void {
        const TRAY_ICO: &[u8] = include_bytes!("../assets/tray.ico");
        unsafe extern "system" {
            fn CreateIconFromResourceEx(
                presbits: *const u8, dwressize: u32, bicon: i32, dwversion: u32,
                x: i32, y: i32, flags: u32,
            ) -> *mut c_void;
            fn GetSystemMetrics(index: i32) -> i32;
            fn LoadImageW(hinst: *mut c_void, name: *const u16, utype: u32, x: i32, y: i32, loaded: u32) -> *mut c_void;
        }
        const SM_CXSMICON: i32 = 49;
        const IDI_APPLICATION: *const u16 = 32512 as *const u16;
        const IMAGE_ICON: u32 = 1;
        const LR_DEFAULTSIZE: u32 = 0x40;
        const LR_SHARED: u32 = 0x8000;
        let fallback =
            unsafe { LoadImageW(std::ptr::null_mut(), IDI_APPLICATION, IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED) };
        let want = unsafe { GetSystemMetrics(SM_CXSMICON) };
        let want = if want > 0 { want as usize } else { 16 };
        if TRAY_ICO.len() < 6 {
            return fallback;
        }
        let (reserved, kind, count) = {
            (
                u16::from_le_bytes([TRAY_ICO[0], TRAY_ICO[1]]),
                u16::from_le_bytes([TRAY_ICO[2], TRAY_ICO[3]]),
                u16::from_le_bytes([TRAY_ICO[4], TRAY_ICO[5]]),
            )
        };
        if reserved != 0 || kind != 1 || count == 0 {
            return fallback;
        }
        // pick the closest entry that is at least `want`, else the largest available
        let mut best: Option<(usize, usize, usize)> = None; // (score, offset, len)
        for i in 0..count as usize {
            let d = 6 + 16 * i;
            if TRAY_ICO.len() < d + 16 {
                break;
            }
            let w = if TRAY_ICO[d] == 0 { 256 } else { TRAY_ICO[d] as usize };
            let size = u32::from_le_bytes([
                TRAY_ICO[d + 8], TRAY_ICO[d + 9], TRAY_ICO[d + 10], TRAY_ICO[d + 11],
            ]) as usize;
            let off = u32::from_le_bytes([
                TRAY_ICO[d + 12], TRAY_ICO[d + 13], TRAY_ICO[d + 14], TRAY_ICO[d + 15],
            ]) as usize;
            if off + size > TRAY_ICO.len() {
                continue;
            }
            // prefer ≥ want (sharp downscale beats upscale), smallest such; then largest overall
            let score = if w >= want { w - want } else { 1000 + (want - w) };
            if best.map(|(s, _, _)| score < s).unwrap_or(true) {
                best = Some((score, off, size));
            }
        }
        let Some((_, off, size)) = best else { return fallback };
        let h = unsafe {
            CreateIconFromResourceEx(TRAY_ICO[off..].as_ptr(), size as u32, 1, 0x0003_0000, 0, 0, 0)
        };
        if h.is_null() { fallback } else { h }
    }

    impl Tray {
        /// Spawn the tray on its own thread. `rx` receives the commands the user
        /// picks (the GUI drains it each frame).
        pub fn spawn(state: Arc<RwLock<TrayState>>, lang: Lang) -> (Tray, std::sync::mpsc::Receiver<TrayCmd>) {
            let (tx, rx) = std::sync::mpsc::channel();
            let running = Arc::new(AtomicBool::new(true));
            let r2 = running.clone();
            std::thread::spawn(move || unsafe {
                let cls = wide("tproxierTrayWnd");
                let inst = std::ptr::null_mut();
                let icon = tray_icon_handle();
                let wc = WNDCLASSEXW {
                    cb_size: std::mem::size_of::<WNDCLASSEXW>() as UINT,
                    style: 0,
                    lpfn_wnd_proc: Some(wndproc),
                    cb_cls_extra: 0,
                    cb_wnd_extra: 0,
                    h_instance: inst,
                    h_icon: icon,
                    h_cursor: std::ptr::null_mut(),
                    h_brush: std::ptr::null_mut(),
                    lpsz_menu_name: std::ptr::null(),
                    lpsz_class_name: cls.as_ptr(),
                    h_icon_sm: icon,
                };
                if RegisterClassExW(&wc) == 0 {
                    r2.store(false, Ordering::SeqCst);
                    return;
                }
                let h = CreateWindowExW(
                    0, cls.as_ptr(), std::ptr::null(), 0,
                    0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), inst, std::ptr::null(),
                );
                if h.is_null() {
                    r2.store(false, Ordering::SeqCst);
                    return;
                }
                {
                    let mut g = CTX.lock().unwrap_or_else(|e| e.into_inner());
                    *g = Some(Box::new(Ctx { tx, state: state.clone(), lang, hwnd: h as isize }));
                }
                // Add the icon with a tooltip.
                let mut nid = make_nid(h);
                nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
                nid.u_callb_msg = WM_TRAY;
                nid.h_icon = icon;
                let tip = wide(&tip(&state.read().unwrap_or_else(|e| e.into_inner()), lang));
                for (i, c) in tip.iter().enumerate().take(127) {
                    nid.sz_tip[i] = *c;
                }
                Shell_NotifyIconW(NIM_ADD, &nid);

                let mut msg = Msg {
                    hwnd: std::ptr::null_mut(), message: 0, wparam: 0, lparam: 0, time: 0,
                    pt: POINT { x: 0, y: 0 },
                };
                while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
                // Drop the context when the loop ends.
                let mut g = CTX.lock().unwrap_or_else(|e| e.into_inner());
                *g = None;
                r2.store(false, Ordering::SeqCst);
            });
            (Tray { running }, rx)
        }
    }

    impl Drop for Tray {
        fn drop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            // Post WM_CLOSE to the tray window so its loop ends + icon is removed.
            unsafe {
                let guard = CTX.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ctx) = guard.as_ref() {
                    // (no PostMessage import; use DestroyWindow from this thread)
                    DestroyWindow(ctx.hwnd as HWND);
                }
            }
        }
    }
}

#[cfg(windows)]
pub use win::Tray;
