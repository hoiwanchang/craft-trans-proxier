use crate::check;
use crate::config::{
    Chain, Config, DnsMode, DnsProto, DnsServer, Language, ProxyKind, ProxyServer, Rule, RuleAction, RuleProtocol,
};
use crate::engine;
use crate::monitor::{LogLine, Monitor};
use crate::profiles::ProfileStore;
use crate::rules::{Decision, decide};
use eframe::egui;
use eframe::App;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckKind {
    Proxy,
    Chain,
}

/// Central-area view, matching the original's "Connection List" vs "Log" toggle.
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Connections,
    Log,
    Servers,
    Chains,
    Rules,
    Options,
    Check,
    Route,
    Profiles,
    Appearance,
}

/// Which field the running-app picker edits: one rule's `app`, or the global
/// app-whitelist. Reuses one picker for every whitelist input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PickerMode {
    Rule(usize),
    Whitelist,
    FixedApp,
}

/// Which comma-list a generic list-editor modal edits.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListTarget {
    Exclusion,
    Inclusion,
}

/// Every main-window tab: (view, stable config key, 中文 label, English label).
/// `hidden_tabs` stores the stable keys to hide.
fn all_tabs() -> [(View, &'static str, &'static str, &'static str); 10] {
    [
        (View::Connections, "connections", "连接", "Connections"),
        (View::Servers, "servers", "代理服务器", "Servers"),
        (View::Chains, "chains", "代理链", "Chains"),
        (View::Rules, "rules", "规则", "Rules"),
        (View::Profiles, "profiles", "配置文件", "Profiles"),
        (View::Options, "options", "选项", "Options"),
        (View::Check, "check", "连接检测", "Check"),
        (View::Route, "route", "路由测试", "Route"),
        (View::Appearance, "appearance", "外观", "Appearance"),
        (View::Log, "log", "日志", "Log"),
    ]
}

/// One-time visual polish: a clean dark theme + generous spacing so controls stop
/// looking cramped (the earlier default style packed everything edge-to-edge).
fn apply_theme(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.panel_fill = egui::Color32::from_rgb(24, 26, 31);
    v.window_fill = egui::Color32::from_rgb(30, 32, 38);
    v.faint_bg_color = egui::Color32::from_rgb(38, 40, 47);
    v.extreme_bg_color = egui::Color32::from_rgb(17, 18, 22);
    v.hyperlink_color = egui::Color32::from_rgb(90, 170, 250);
    v.selection.bg_fill = egui::Color32::from_rgb(40, 90, 150);
    v.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(150, 200, 255));
    ctx.set_visuals(v);
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(12.0, 8.0);
        s.spacing.button_padding = egui::vec2(13.0, 7.0);
        s.spacing.window_margin = egui::Margin::from(12.0);
        s.spacing.menu_margin = egui::Margin::from(10.0);
        // Any TextEdit without an explicit width gets a usable size (fixes the
        // "host/port inputs are tiny" complaint app-wide).
        s.spacing.text_edit_width = 240.0;
        s.spacing.slider_width = 200.0;
        s.spacing.icon_width = 18.0;
    });
}

/// Scale the egui text styles to `pct`% of the 14pt base. Applied every frame so
/// the font-size slider in 常规设置 previews live; persists via `ui_scale_pct`.
fn apply_ui_scale(ctx: &egui::Context, pct: u32) {
    let pct = pct.clamp(50, 300);
    let base = 14.0 * (pct as f32 / 100.0);
    ctx.global_style_mut(|style| {
        // Skip when already at the target so we don't fight the theme each frame.
        let cur = style.text_styles.get(&egui::TextStyle::Body).map(|id| id.size);
        if cur == Some(base) {
            return;
        }
        use egui::TextStyle::*;
        style.text_styles.insert(Small, egui::FontId::proportional((base - 2.0).max(6.0)));
        style.text_styles.insert(Body, egui::FontId::proportional(base));
        style.text_styles.insert(Button, egui::FontId::proportional(base));
        style.text_styles.insert(Heading, egui::FontId::proportional(base + 6.0));
        style.text_styles.insert(Monospace, egui::FontId::monospace(base));
    });
}

/// Handle for the TRANSPARENT-interception engine (the primary feature): it
/// installs the hook + pipe decision server + relay so whitelisted programs are
/// proxified with no proxy setting in them. Started independently of the manual
/// SOCKS5 server below.
/// GUI state for the WFP kernel-redirect route. Kept in one place because its parts
/// are only meaningful together: ticking it on without the engine's token listeners
/// cannot work, and leaving the route armed after the engine stops would redirect into
/// closed ports.
#[derive(Default)]
struct WfpUi {
    enabled: bool,
    consent: bool,
    note: String,
    /// Held for the lifetime of the route: dropping it disarms the driver and withdraws
    /// the filters (they live in this process's dynamic BFE session).
    #[cfg(windows)]
    route: Option<crate::wfp_route::Route>,
}

struct ServeHandle {
    cfg_shared: Arc<RwLock<Config>>,
    /// Held only so that dropping the handle stops the engine (removes the hook,
    /// closes the mutex/pipe); we never call into it directly.
    #[cfg(windows)]
    #[allow(dead_code)]
    engine: Option<crate::intercept::Engine>,
}

/// Handle for the OPTIONAL manual SOCKS5 listener (for apps you deliberately
/// point at 127.0.0.1:<port>); many users never start this.
struct SocksHandle {
    port: u16,
    stop: Arc<AtomicBool>,
}

fn tr(lang: Language, zh: &'static str, en: &'static str) -> &'static str {
    match lang {
        Language::Zh => zh,
        Language::En => en,
    }
}

fn translate_reason(reason: &str, lang: Language) -> &'static str {
    match (reason, lang) {
        ("not in app whitelist", Language::Zh) => "不在程序白名单中",
        ("not in app whitelist", Language::En) => "Not in app whitelist",
        ("Exclusion List match", Language::Zh) => "排除列表命中",
        ("Exclusion List match", Language::En) => "Exclusion list match",
        ("Inclusion List match (no match)", Language::Zh) => "包含列表未命中",
        ("Inclusion List match (no match)", Language::En) => "Not in inclusion list",
        ("matched direct rule", Language::Zh) => "匹配直连规则",
        ("matched direct rule", Language::En) => "Matched direct rule",
        ("no rule matched", Language::Zh) => "无匹配规则",
        ("no rule matched", Language::En) => "No rule matched",
        _ => "?",
    }
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn join_list(list: &[String]) -> String {
    list.join(", ")
}

fn fmt_rate(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{bps:.0} B/s")
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{:.2} MB/s", bps / (1024.0 * 1024.0))
    }
}

fn fmt_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let n = n as f64;
    if n < K {
        format!("{n:.0} B")
    } else if n < K * K {
        format!("{:.1} KB", n / K)
    } else if n < K * K * K {
        format!("{:.2} MB", n / (K * K))
    } else {
        format!("{:.2} GB", n / (K * K * K))
    }
}

fn check_lines_from(lang: Language, result: &check::CheckResult) -> Vec<String> {
    let mark = if result.ok {
        tr(lang, "通过", "PASS")
    } else {
        tr(lang, "失败", "FAIL")
    };
    vec![
        format!(
            "[{}] {} → {}:{}",
            mark, result.proxy_name, result.host, result.port
        ),
        format!("      {}", result.message),
    ]
}

pub fn run(config_path: PathBuf) -> u8 {
    // wgpu's default backends-ALL enumeration segfaults on some virtual displays;
    // each backend individually is fine. Honour an explicit WGPU_BACKEND if set.
    if std::env::var_os("WGPU_BACKEND").is_none() {
        // SAFETY: single-threaded here, before run_native spawns any threads.
        unsafe { std::env::set_var("WGPU_BACKEND", "dx12") };
    }
    let path = resolve_config_path(config_path);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("trans-proxier")
            .with_inner_size([1080.0, 720.0])
            .with_maximized(true)
            .with_resizable(true),
        ..Default::default()
    };
    match eframe::run_native(
        "trans-proxier",
        options,
        Box::new(move |cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(GuiApp::new(path)))
        }),
    ) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

fn resolve_config_path(path: PathBuf) -> PathBuf {
    if path.exists() {
        return path;
    }
    if !path.is_absolute() {
        if let Ok(exe) = std::env::current_exe() {
            let candidate = exe.with_file_name(&path);
            if candidate.exists() {
                return candidate;
            }
        }
    }
    path
}

/// The hook driver DLL lives next to the GUI exe (target/debug/tpdrv.dll).
fn default_driver_path() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("tpdrv.dll").to_string_lossy().into_owned();
        }
    }
    "tpdrv.dll".to_string()
}

const LOG_VIEW_CAP: usize = 1500;

struct GuiApp {
    path: PathBuf,
    config: Config,
    saved: Config,
    can_save: bool,
    banner: Option<String>,
    status: String,
    exclusion_text: String,
    inclusion_text: String,
    whitelist_text: String,
    route_host: String,
    route_port: u16,
    route_app: String,
    route_lines: Vec<String>,
    check_kind: CheckKind,
    check_id: u32,
    check_host: String,
    check_port: u16,
    check_lines: Vec<String>,
    checking: bool,
    check_rx: Option<mpsc::Receiver<Vec<String>>>,
    serve_port: u16,
    http_port: u16,
    socks_ip: String,
    http_ip: String,
    serve_app: String,
    driver_path: String,
    hook_consent: bool,
    serve: Option<ServeHandle>,
    wfp: WfpUi,
    socks: Option<SocksHandle>,
    http_proxy: Option<SocksHandle>,
    // Running-apps picker for a rule's "程序" field: modal with search + checkboxes.
    dlg_app_picker: bool,
    app_picker_mode: PickerMode,
    app_picker_query: String,
    app_list: Vec<String>,
    rules_io_path: String,
    // Generic string-list editor modal (exclusion / inclusion / dns-no-resolve).
    dlg_list_editor: bool,
    list_editor_target: ListTarget,
    list_editor_items: Vec<String>,
    last_window_title: String,
    // Set by the 选项 "切换配置文件" dropdown; applied centrally in update() after
    // show_central so it isn't clobbered by the settings writeback.
    pending_switch: Option<String>,
    // System-tray control menu (fnd_13). Windows-only; spawned when
    // `settings.start_in_tray` is on. The TrayState is shared so the menu/tooltip
    // reflect live engine state; commands come back over the receiver.
    #[cfg(windows)]
    tray_state: Arc<RwLock<crate::tray::TrayState>>,
    #[cfg(windows)]
    tray_rx: Option<std::sync::mpsc::Receiver<crate::tray::TrayCmd>>,
    #[cfg(windows)]
    _tray: Option<crate::tray::Tray>,
    // Original-style shell state (fnd_13): central view + modal editor dialogs.
    view: View,
    dlg_settings: bool,
    dlg_servers: bool,
    dlg_chains: bool,
    dlg_rules: bool,
    dlg_route: bool,
    dlg_check: bool,
    dlg_options: bool,
    dlg_about: bool,
    dlg_profiles: bool,
    selected_conn: Option<u64>,
    conn_filter: String,
    /// The live log is a projection of `log_all` through this filter; keeping both
    /// means changing the filter re-narrows the history instead of only future lines.
    log_filter: crate::monitor::LogFilter,
    log_filter_applied: crate::monitor::LogFilter,
    log_all: VecDeque<LogLine>,
    update_checked: bool,
    profile_store: ProfileStore,
    profile_name: String,
    profile_password: String,
    profile_encrypt: bool,
    profile_file: String,
    selected_profile: Option<String>,
    monitor: Arc<Monitor>,
    log_cursor: u64,
    log_view: VecDeque<LogLine>,
    prev_sample: Option<(Instant, u64, u64)>,
    rate_up: f64,
    rate_down: f64,
    total_up: u64,
    total_down: u64,
    conns: u64,
}

impl GuiApp {
    fn new(path: PathBuf) -> Self {
        let (config, can_save, banner) = match Config::load(&path) {
            Ok(c) => (c, true, None),
            Err(e) => {
                if path.exists() {
                    (Config::default(), false, Some(e))
                } else {
                    (Config::default(), true, None)
                }
            }
        };
        let mut exclusion_text = join_list(&config.settings.proxy_exclusion_list);
        let mut inclusion_text = join_list(&config.settings.proxy_inclusion_list);
        let mut whitelist_text = join_list(&config.settings.app_whitelist);
        let mut hook_consent = config.settings.hook_consent;
        let mut config = config;
        let monitor = Arc::new(Monitor::new());
        monitor.log("info", format!("已加载配置：{}", path.display()));
        let profiles_dir = path.parent().unwrap_or(Path::new(".")).join("profiles");
        let profile_store = ProfileStore::new(&profiles_dir).unwrap_or_else(|_| {
            ProfileStore::new(std::env::temp_dir().join("trans-proxier-profiles"))
                .expect("temp profiles dir")
        });
        // Auto-load the last-used profile at startup (if remembered, present, and
        // not password-protected; encrypted ones prompt for manual load).
        let mut selected_profile = None;
        let ap = config.settings.active_profile.clone();
        if !ap.is_empty() && profile_store.exists(&ap) {
            match profile_store.load_with(&ap, None) {
                Ok(mut c) => {
                    c.settings.active_profile = ap.clone();
                    exclusion_text = join_list(&c.settings.proxy_exclusion_list);
                    inclusion_text = join_list(&c.settings.proxy_inclusion_list);
                    whitelist_text = join_list(&c.settings.app_whitelist);
                    hook_consent = c.settings.hook_consent;
                    config = c;
                    selected_profile = Some(ap.clone());
                    monitor.log("info", format!("已自动加载上次配置文件 \"{ap}\""));
                }
                Err(e) => monitor.log(
                    "warn",
                    format!("自动加载配置 {ap} 失败（可能需密码，请在『配置文件』页手动加载）：{e}"),
                ),
            }
        }
        GuiApp {
            path,
            saved: config.clone(),
            config,
            can_save,
            banner,
            status: String::new(),
            view: View::Connections,
            dlg_settings: false,
            dlg_servers: false,
            dlg_chains: false,
            dlg_rules: false,
            dlg_route: false,
            dlg_check: false,
            dlg_options: false,
            dlg_about: false,
            dlg_profiles: false,
            selected_conn: None,
            conn_filter: String::new(),
            log_filter: crate::monitor::LogFilter::default(),
            log_filter_applied: crate::monitor::LogFilter::default(),
            log_all: VecDeque::new(),
            update_checked: false,
            profile_store,
            profile_name: String::new(),
            profile_password: String::new(),
            profile_encrypt: false,
            profile_file: String::new(),
            selected_profile,
            exclusion_text,
            inclusion_text,
            whitelist_text,
            route_host: "example.com".into(),
            route_port: 443,
            route_app: String::new(),
            route_lines: Vec::new(),
            check_kind: CheckKind::Proxy,
            check_id: 1,
            check_host: "example.com".into(),
            check_port: 443,
            check_lines: Vec::new(),
            checking: false,
            check_rx: None,
            serve_port: 1080,
            http_port: 8888,
            socks_ip: "127.0.0.1".into(),
            http_ip: "127.0.0.1".into(),
            serve_app: String::new(),
            driver_path: default_driver_path(),
            hook_consent,
            serve: None,
            wfp: WfpUi::default(),
            socks: None,
            http_proxy: None,
            dlg_app_picker: false,
            app_picker_mode: PickerMode::Rule(0),
            app_picker_query: String::new(),
            app_list: Vec::new(),
            rules_io_path: String::new(),
            dlg_list_editor: false,
            list_editor_target: ListTarget::Exclusion,
            list_editor_items: Vec::new(),
            last_window_title: "trans-proxier".to_string(),
            pending_switch: None,
            #[cfg(windows)]
            tray_state: Arc::new(RwLock::new(crate::tray::TrayState::default())),
            #[cfg(windows)]
            tray_rx: None,
            #[cfg(windows)]
            _tray: None,
            monitor,
            log_cursor: 0,
            log_view: VecDeque::new(),
            prev_sample: None,
            rate_up: 0.0,
            rate_down: 0.0,
            total_up: 0,
            total_down: 0,
            conns: 0,
        }
    }

    fn t(&self, zh: &'static str, en: &'static str) -> &'static str {
        tr(self.config.settings.language, zh, en)
    }

    fn log(&self, level: &'static str, msg: impl Into<String>) {
        self.monitor.log(level, msg);
    }

    fn save(&mut self) {
        if !self.can_save {
            self.banner = Some(self.t("原配置无法解析，拒绝覆盖。请先修复或删除该文件。", "The existing config could not be parsed; refusing to overwrite it. Fix or delete the file first.").to_string());
            return;
        }
        let errors = self.config.validate();
        if !errors.is_empty() {
            self.banner = Some(format!(
                "{} ({}) {}",
                self.t("配置无效，未保存：", "Config invalid, not saved:"),
                errors.len(),
                errors[0].message
            ));
            self.log("warn", format!("保存失败：配置有 {} 个错误", errors.len()));
            return;
        }
        match self.config.write(&self.path) {
            Ok(()) => {
                self.saved = self.config.clone();
                self.banner = None;
                self.status = self.t("已保存。", "Saved.").to_string();
                self.log("info", format!("已保存到 {}", self.path.display()));
            }
            Err(e) => {
                self.banner = Some(format!("{} {}", self.t("保存失败：", "Save failed:"), e));
                self.log("warn", format!("写入失败：{e}"));
            }
        }
    }

    fn reload(&mut self) {
        match Config::load(&self.path) {
            Ok(c) => {
                self.exclusion_text = join_list(&c.settings.proxy_exclusion_list);
                self.inclusion_text = join_list(&c.settings.proxy_inclusion_list);
                self.whitelist_text = join_list(&c.settings.app_whitelist);
                self.saved = c.clone();
                self.config = c;
                self.can_save = true;
                self.banner = None;
                self.status = self.t("已重新加载。", "Reloaded.").to_string();
                self.log("info", "已重新加载配置。");
            }
            Err(e) => {
                self.can_save = false;
                self.banner = Some(format!("{} {}", self.t("重新加载失败：", "Reload failed:"), e));
                self.log("warn", format!("重新加载失败：{e}"));
            }
        }
    }

    fn compute_route(&mut self) {
        let host = self.route_host.trim().to_string();
        if host.is_empty() {
            self.route_lines = vec![self.t("未填写主机。", "No host entered.").to_string()];
            return;
        }
        let app = if self.route_app.trim().is_empty() {
            None
        } else {
            Some(self.route_app.trim().to_string())
        };
        let port = self.route_port;
        let decision = decide(&self.config, app.as_deref(), &host, port);
        let lang = self.config.settings.language;
        let mut lines = Vec::new();
        match &decision {
            Decision::Proxy { chain, rule } => {
                lines.push(format!(
                    "{} #{chain} ({} #{rule})",
                    tr(lang, "经由代理链", "via chain"),
                    tr(lang, "规则", "rule")
                ));
                match self.config.chain_by_id(*chain) {
                    Some(c) => {
                        for (i, pid) in c.proxies.iter().enumerate() {
                            match self.config.proxy_by_id(*pid) {
                                Some(p) => lines.push(format!(
                                    "  {} {}: {} [{}] {}:{}",
                                    tr(lang, "跳", "hop"),
                                    i + 1,
                                    p.name,
                                    p.kind.as_str(),
                                    p.host,
                                    p.port
                                )),
                                None => lines.push(format!(
                                    "  {} {}: MISSING proxy #{pid}",
                                    tr(lang, "跳", "hop"),
                                    i + 1
                                )),
                            }
                        }
                    }
                    None => lines.push(format!(
                        "  {} #{chain} {}",
                        tr(lang, "代理链", "chain"),
                        tr(lang, "不存在", "not found")
                    )),
                }
            }
            Decision::Direct { rule, reason } => {
                let rule_part = rule
                    .map(|r| format!(", {} #{r}", tr(lang, "规则", "rule")))
                    .unwrap_or_default();
                lines.push(format!(
                    "{} ({}{rule_part})",
                    tr(lang, "直连", "direct"),
                    translate_reason(reason, lang)
                ));
            }
            Decision::Block { rule } => {
                lines.push(format!(
                    "{} ({} #{rule})",
                    tr(lang, "已阻止", "blocked"),
                    tr(lang, "规则", "rule")
                ));
            }
        }
        self.route_lines = lines;
    }

    fn start_check(&mut self) {
        let host = self.check_host.trim().to_string();
        if host.is_empty() {
            self.banner = Some(self.t("请填写检测目标主机。", "Enter a target host.").to_string());
            return;
        }
        let port = self.check_port;
        let kind = self.check_kind;
        let id = self.check_id;
        let config = self.config.clone();
        let monitor = self.monitor.clone();
        let (tx, rx) = mpsc::channel::<Vec<String>>();
        self.check_rx = Some(rx);
        self.checking = true;
        self.check_lines = Vec::new();
        self.banner = None;
        self.log("info", format!("开始检测：{host}:{port}"));
        std::thread::spawn(move || {
            let lang = config.settings.language;
            let lines: Vec<String> = match kind {
                CheckKind::Proxy => match config.proxy_by_id(id) {
                    Some(p) => {
                        let p = p.clone();
                        let timeout = Duration::from_secs(p.timeout_secs.max(1));
                        let result = check::check_proxy(&p, &host, port, timeout);
                        monitor.log(
                            if result.ok { "info" } else { "warn" },
                            format!("检测 {}：{}", p.name, result.message),
                        );
                        check_lines_from(lang, &result)
                    }
                    None => vec![format!(
                        "{} #{id} {}",
                        tr(lang, "代理", "proxy"),
                        tr(lang, "不存在", "not found")
                    )],
                },
                CheckKind::Chain => match config.chain_by_id(id) {
                    Some(_) => {
                        let result = check::check_chain(&config, id, &host, port);
                        monitor.log(
                            if result.ok { "info" } else { "warn" },
                            format!("链检测 #{id}：{}", result.message),
                        );
                        check_lines_from(lang, &result)
                    }
                    None => vec![format!(
                        "{} #{id} {}",
                        tr(lang, "代理链", "chain"),
                        tr(lang, "不存在", "not found")
                    )],
                },
            };
            let _ = tx.send(lines);
        });
    }

    fn poll_check(&mut self) {
        if self.check_rx.is_none() {
            return;
        }
        let mut lines: Option<Vec<String>> = None;
        let mut disconnected = false;
        {
            let rx = self.check_rx.as_ref().unwrap();
            match rx.try_recv() {
                Ok(l) => lines = Some(l),
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => disconnected = true,
            }
        }
        if let Some(l) = lines {
            self.check_lines = l;
        }
        self.checking = false;
        self.check_rx = None;
        if disconnected {
            self.banner = Some(
                self.t("检测线程异常退出。", "The check thread ended unexpectedly.")
                    .to_string(),
            );
        }
    }

    fn poll_monitor(&mut self) {
        // Feed the running engine the current UI config so whitelist/rule edits
        // take effect for new connections without a restart.
        if let Some(h) = &self.serve {
            if let Ok(mut w) = h.cfg_shared.write() {
                *w = self.config.clone();
            }
        }
        let running = self.serve.is_some() || self.socks.is_some() || self.http_proxy.is_some();
        if running {
            let (up, down, _) = self.monitor.snapshot();
            let now = Instant::now();
            if let Some((t, pu, pd)) = self.prev_sample {
                let dt = now.duration_since(t).as_secs_f64();
                if dt > 0.0 {
                    let ru = up.saturating_sub(pu) as f64 / dt;
                    let rd = down.saturating_sub(pd) as f64 / dt;
                    self.rate_up = self.rate_up * 0.5 + ru * 0.5;
                    self.rate_down = self.rate_down * 0.5 + rd * 0.5;
                }
            }
            self.prev_sample = Some((now, up, down));
            self.total_up = up;
            self.total_down = down;
            self.conns = self.monitor.active_count();
        } else {
            self.rate_up = 0.0;
            self.rate_down = 0.0;
            self.prev_sample = None;
        }
        let (fresh, cursor) = self.monitor.since(self.log_cursor);
        self.log_cursor = cursor;
        let arrived = !fresh.is_empty();
        if arrived {
            for l in fresh {
                self.log_all.push_back(l);
            }
            while self.log_all.len() > LOG_VIEW_CAP {
                self.log_all.pop_front();
            }
        }
        if arrived || self.log_filter != self.log_filter_applied {
            let f = self.log_filter.clone();
            self.log_view = self
                .log_all
                .iter()
                .filter(|l| crate::monitor::log_filter_matches(&l.message, &f))
                .cloned()
                .collect();
            self.log_filter_applied = f;
        }
    }

    fn serve_start(&mut self) {
        let errors = self.config.validate();
        if !errors.is_empty() {
            self.banner = Some(format!(
                "{} {}",
                self.t("配置无效，无法启动透明引擎：", "Config invalid, cannot start engine:"),
                errors[0].message
            ));
            return;
        }
        // Safety gate: a global message hook loads into EVERY message-pumping app
        // in the session. Require an explicit consent checkbox first.
        if !self.hook_consent {
            self.banner = Some(
                self.t(
                    "请先勾选「同意安装全局钩子」——它会加载进本会话所有前台程序。",
                    "Tick “I consent to install a global hook” first — it loads into every foreground app in this session.",
                )
                .to_string(),
            );
            return;
        }
        self.monitor.reset_counters();
        self.prev_sample = None;
        self.rate_up = 0.0;
        self.rate_down = 0.0;
        self.total_up = 0;
        self.total_down = 0;
        self.conns = 0;

        // The transparent engine needs NO SOCKS5 port: it hooks the whitelisted
        // programs directly. It reads config live via cfg_shared.
        let cfg_shared = Arc::new(RwLock::new(self.config.clone()));
        #[cfg(windows)]
        {
            // Decided BEFORE the engine exists: spawn_servers binds the TCP/UDP token
            // ports only when the ingress path is already latched on, and the driver
            // cannot be handed a pool that does not exist yet.
            let wfp_prepared = if self.wfp.enabled {
                match crate::wfp_route::prepare(&self.config, self.wfp.consent) {
                    Ok(()) => true,
                    Err(e) => {
                        self.wfp.note = e.clone();
                        self.log("warn", format!("WFP 重定向未启用：{e}"));
                        false
                    }
                }
            } else {
                false
            };
            let driver = self.driver_path.clone();
            match crate::intercept::Engine::start(cfg_shared.clone(), self.monitor.clone(), &driver) {
                Ok(e) => {
                    self.serve = Some(ServeHandle {
                        cfg_shared,
                        engine: Some(e),
                    });
                    self.banner = None;
                    self.status = self.t("透明拦截已启用", "Transparent interception ON").to_string();
                    self.log("info", "透明拦截引擎已启动：白名单内程序的全流量将自动走代理");
                    if wfp_prepared {
                        match crate::wfp_route::commit(&self.config, &self.monitor) {
                            Ok(r) => {
                                self.wfp.note = format!("WFP: {} filters", r.installed());
                                self.wfp.route = Some(r);
                            }
                            Err(e) => {
                                self.wfp.note = e.clone();
                                self.log("warn", format!("WFP 过滤器安装失败：{e}"));
                            }
                        }
                    }
                }
                Err(err) => {
                    self.log("warn", format!("透明引擎启动失败：{err}"));
                    self.banner = Some(format!(
                        "{} {err}",
                        self.t("透明引擎启动失败（先 `cargo build -p tpdrv`）：", "Transparent engine failed to start (run `cargo build -p tpdrv` first):")
                    ));
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = cfg_shared;
            self.banner = Some(
                self.t("透明拦截仅支持 Windows。", "Transparent interception is Windows-only.")
                    .to_string(),
            );
        }
    }

    fn serve_stop(&mut self) {
        // First the WFP route: its Drop disarms the driver while our token ports are
        // still open, so no in-flight whitelisted connect is pointed at a dead port.
        #[cfg(windows)]
        if self.wfp.route.take().is_some() {
            self.wfp.note = String::new();
            self.log("info", "WFP 内核重定向已停用（驱动 enabled=0，本进程动态会话中的过滤器一并撤回）");
        }
        if let Some(h) = self.serve.take() {
            // Dropping the Engine removes the hook + closes the mutex/pipe; hooked
            // apps then see no engine and fall back to direct connections.
            self.log("info", "透明引擎已停止（已注入的程序在重启前仍会直连）");
            self.status = self.t("已停止。", "Stopped.").to_string();
            self.banner = None;
            // `Engine::drop` calls UnhookWindowsHookEx on a GLOBAL message hook,
            // which blocks until every process that loaded the DLL acknowledges the
            // removal (browsers can stall this for seconds or indefinitely). Running
            // it here would freeze the egui window. Hand the teardown to a detached
            // worker; the UI thread is already unblocked and interception is already
            // inert (mutex/pipe closed at the top of drop).
            std::thread::spawn(move || drop(h));
        }
    }

    /// Optional manual SOCKS5 listener (only for apps you point at it yourself).
    fn socks_start(&mut self) {
        let port = self.serve_port;
        let ip = if self.socks_ip.trim().is_empty() { "127.0.0.1".to_string() } else { self.socks_ip.trim().to_string() };
        let addr = format!("{ip}:{port}");
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                self.banner = Some(format!("{} {addr}: {e}", self.t("无法监听", "Cannot bind")));
                return;
            }
        };
        let app = if self.serve_app.trim().is_empty() {
            None
        } else {
            Some(self.serve_app.trim().to_string())
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let config = self.config.clone();
        let monitor = self.monitor.clone();
        monitor.log("info", format!("手动 SOCKS5 已启动，监听 {addr}"));
        std::thread::spawn(move || {
            let _ = engine::serve_with_stop(listener, config, app, stop2, monitor);
        });
        self.socks = Some(SocksHandle { port, stop });
        self.banner = None;
    }

    fn socks_stop(&mut self) {
        if let Some(h) = self.socks.take() {
            h.stop.store(true, Ordering::SeqCst);
            self.log("info", format!("手动 SOCKS5 已停止（端口 {}）", h.port));
        }
    }

    /// Optional manual HTTP proxy listener (apps you point at it as an HTTP
    /// proxy — fnd_10 "HTTP proxy servers support"). Handles CONNECT + absolute
    /// GET, routed through the same engine as everything else.
    fn http_start(&mut self) {
        let port = self.http_port;
        let ip = if self.http_ip.trim().is_empty() { "127.0.0.1".to_string() } else { self.http_ip.trim().to_string() };
        let addr = format!("{ip}:{port}");
        let listener = match std::net::TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                self.banner = Some(format!("{} {addr}: {e}", self.t("无法监听", "Cannot bind")));
                return;
            }
        };
        let app = if self.serve_app.trim().is_empty() {
            None
        } else {
            Some(self.serve_app.trim().to_string())
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = Arc::clone(&stop);
        let config = self.config.clone();
        let monitor = self.monitor.clone();
        monitor.log("info", format!("HTTP 代理已启动，监听 {addr}"));
        std::thread::spawn(move || {
            let _ = engine::serve_http_with_stop(listener, config, app, monitor, stop2);
        });
        self.http_proxy = Some(SocksHandle { port, stop });
        self.banner = None;
    }

    fn http_stop(&mut self) {
        if let Some(h) = self.http_proxy.take() {
            h.stop.store(true, Ordering::SeqCst);
            self.log("info", format!("HTTP 代理已停止（端口 {}）", h.port));
        }
    }

    fn show_toolbar(&mut self, ui: &mut egui::Ui) {
        let path_display = self.path.display().to_string();
        let dirty = self.config != self.saved;
        let can_save = self.can_save;
        let banner = self.banner.clone();
        let status = self.status.clone();
        let lang = self.config.settings.language;
        let mut lang_local = lang;
        let mut do_save = false;
        let mut do_reload = false;
        let trans_on = self.serve.is_some();
        let mut consent_local = self.hook_consent;
        let mut do_t_start = false;
        let mut do_t_stop = false;
        let prox_on = self.config.settings.proxification_enabled;
        let mut do_proxy_toggle = false;
        let green = egui::Color32::from_rgb(34, 120, 54);
        let red = egui::Color32::from_rgb(150, 46, 40);
        let prox_on_lbl = self.t("全局代理: 开", "Proxying: ON").to_string();
        let prox_off_lbl = self.t("全局代理: 关", "Proxying: OFF").to_string();
        let consent_short = self.t("同意全局钩子", "Consent hook");
        let t_start = self.t("▶ 启动", "▶ Start").to_string();
        let t_stop = self.t("■ 停止", "■ Stop").to_string();
        let save_label = self.t("保存", "Save");
        let reload_label = self.t("重新加载", "Reload");
        let lang_label = self.t("语言", "Language");
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("trans-proxier");
                ui.separator();
                ui.monospace(path_display.as_str());
                if dirty {
                    ui.colored_label(egui::Color32::from_rgb(240, 200, 90), "●");
                }
                ui.separator();
                ui.checkbox(&mut consent_local, consent_short);
                if trans_on {
                    let b = ui.add(egui::Button::new(egui::RichText::new(t_stop.as_str()).color(egui::Color32::WHITE)).fill(red));
                    if b.clicked() {
                        do_t_stop = true;
                    }
                } else {
                    let sb = if consent_local {
                        ui.add(egui::Button::new(egui::RichText::new(t_start.as_str()).color(egui::Color32::WHITE)).fill(green))
                    } else {
                        ui.add_enabled(false, egui::Button::new(t_start.as_str()))
                    };
                    if sb.clicked() {
                        do_t_start = true;
                    }
                }
                // Global proxification master switch (same as 选项 → 启用代理).
                let prox_lbl = if prox_on { prox_on_lbl.as_str() } else { prox_off_lbl.as_str() };
                let pb = ui.add(
                    egui::Button::new(egui::RichText::new(prox_lbl).color(egui::Color32::WHITE))
                        .fill(if prox_on { green } else { red }),
                );
                if pb.clicked() {
                    do_proxy_toggle = true;
                }
                ui.separator();
                let save_btn = if can_save {
                    ui.add(egui::Button::new(save_label))
                } else {
                    ui.add_enabled(false, egui::Button::new(save_label))
                };
                if save_btn.clicked() {
                    do_save = true;
                }
                if ui.button(reload_label).clicked() {
                    do_reload = true;
                }
                ui.separator();
                ui.label(lang_label);
                egui::ComboBox::new("lang-combo", "")
                    .selected_text(lang_local.label())
                    .width(110.0)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut lang_local, Language::Zh, "中文");
                        ui.selectable_value(&mut lang_local, Language::En, "English");
                    });
            });
            if let Some(b) = &banner {
                ui.colored_label(egui::Color32::from_rgb(235, 110, 90), b.as_str());
            } else if !status.is_empty() {
                ui.label(status.as_str());
            }
            ui.add_space(2.0);
        });
        if do_save {
            self.save();
        }
        if do_reload {
            self.reload();
        }
        if lang_local != lang {
            self.config.settings.language = lang_local;
        }
        self.hook_consent = consent_local;
        if do_proxy_toggle {
            self.config.settings.proxification_enabled = !self.config.settings.proxification_enabled;
            let on = self.config.settings.proxification_enabled;
            let msg = if on {
                self.t("全局代理已启用", "Global proxying enabled")
            } else {
                self.t("全局代理已关闭（全部直连）", "Global proxying OFF (everything direct)")
            };
            self.log("info", msg);
        }
        if do_t_start {
            self.serve_start();
        }
        if do_t_stop {
            self.serve_stop();
        }
    }

    fn show_menubar(&mut self, ui: &mut egui::Ui) {
        let mut view = self.view;
        let mut d_about = false;
        let mut d_profiles = false;
        let mut do_new = false;
        let mut do_update = false;
        let (mut do_save, mut do_reload) = (false, false);

        let t = |zh: &'static str, en: &'static str| tr(self.config.settings.language, zh, en);
        // fnd_13 keyboard accelerators: Ctrl+N new profile, Ctrl+M manage,
        // Ctrl+O import, Ctrl+S save.
        let (acc_new, acc_manage, acc_import, acc_save) = ui.input(|i| {
            let cmd = i.modifiers.command;
            (
                cmd && i.key_pressed(egui::Key::N),
                cmd && i.key_pressed(egui::Key::M),
                cmd && i.key_pressed(egui::Key::O),
                cmd && i.key_pressed(egui::Key::S),
            )
        });
        if acc_new {
            do_new = true;
            d_profiles = true;
        }
        if acc_manage || acc_import {
            d_profiles = true;
        }
        if acc_save {
            do_save = true;
        }
        egui::Panel::top("menubar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.menu_button(t("文件", "File"), |ui| {
                    if ui.button(t("新建配置文件\tCtrl+N", "New Profile\tCtrl+N")).clicked() { do_new = true; ui.close(); }
                    if ui.button(t("管理配置文件…\tCtrl+M", "Manage Profiles…\tCtrl+M")).clicked() { d_profiles = true; ui.close(); }
                    if ui.button(t("导入配置文件…\tCtrl+O", "Import Profile…\tCtrl+O")).clicked() { d_profiles = true; ui.close(); }
                    if ui.button(t("另存为配置文件…", "Save Profile As…")).clicked() { d_profiles = true; ui.close(); }
                    ui.separator();
                    if ui.button(t("保存配置\tCtrl+S", "Save\tCtrl+S")).clicked() { do_save = true; ui.close(); }
                    if ui.button(t("重新加载", "Reload")).clicked() { do_reload = true; ui.close(); }
                    ui.separator();
                    if ui.button(t("退出", "Exit")).clicked() { ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close); ui.close(); }
                });
                ui.menu_button(t("选项", "Options"), |ui| {
                    if ui.button(t("代理服务器", "Proxy Servers")).clicked() { view = View::Servers; ui.close(); }
                    if ui.button(t("代理链", "Proxy Chains")).clicked() { view = View::Chains; ui.close(); }
                    if ui.button(t("代理规则", "Proxification Rules")).clicked() { view = View::Rules; ui.close(); }
                    ui.separator();
                    if ui.button(t("选项（含常规设置）", "Options (settings)")).clicked() { view = View::Options; ui.close(); }
                    if ui.button(t("外观", "Appearance")).clicked() { view = View::Appearance; ui.close(); }
                    ui.separator();
                    if ui.button(t("连接检测", "Proxy Checker")).clicked() { view = View::Check; ui.close(); }
                    if ui.button(t("路由测试", "Route test")).clicked() { view = View::Route; ui.close(); }
                });
                ui.menu_button(t("视图", "View"), |ui| {
                    // Only the tabs not already reachable from the Options menu.
                    for (v, zh, en) in [
                        (View::Connections, "连接", "Connections"),
                        (View::Profiles, "配置文件", "Profiles"),
                        (View::Log, "日志", "Log"),
                    ] {
                        if ui.selectable_label(view == v, t(zh, en)).clicked() {
                            view = v;
                            ui.close();
                        }
                    }
                });
                ui.menu_button(t("帮助", "Help"), |ui| {
                    if ui.button(t("检查更新…", "Check for Updates…")).clicked() { do_update = true; ui.close(); }
                    if ui.button(t("关于本软件…", "About…")).clicked() { d_about = true; ui.close(); }
                });
            });
        });

        self.view = view;
        self.dlg_about |= d_about;
        if do_update {
            self.check_for_updates(true);
        }
        self.dlg_profiles |= d_profiles;
        if do_new {
            self.config = Config::default();
            self.profile_name = String::new();
            self.exclusion_text = join_list(&self.config.settings.proxy_exclusion_list);
            self.inclusion_text = join_list(&self.config.settings.proxy_inclusion_list);
            self.whitelist_text = join_list(&self.config.settings.app_whitelist);
        }
        if do_save {
            self.save();
        }
        if do_reload {
            self.reload();
        }
    }

    fn show_validation(&mut self, ui: &mut egui::Ui) {
        let errors = self.config.validate();
        if errors.is_empty() {
            return;
        }
        let title = self.t("配置无效", "Invalid config").to_string();
        egui::Panel::top("validation").show(ui, |ui| {
            ui.colored_label(
                egui::Color32::from_rgb(235, 120, 90),
                format!("{} ({})", title, errors.len()),
            );
            for e in &errors {
                ui.monospace(e.message.as_str());
            }
            ui.add_space(2.0);
        });
    }

    fn show_statusbar(&mut self, ui: &mut egui::Ui) {
        let trans = self.serve.is_some();
        let socks = self.socks.is_some();
        let enabled = trans || socks;
        let port = self.serve_port;
        let status_text = if trans {
            self.t("透明拦截已启用", "Transparent interception enabled").to_string()
        } else if socks {
            format!("SOCKS5 127.0.0.1:{port}")
        } else {
            self.t("未启用", "Disabled").to_string()
        };
        let up_rate = fmt_rate(self.rate_up);
        let down_rate = fmt_rate(self.rate_down);
        let total_up = fmt_bytes(self.total_up);
        let total_down = fmt_bytes(self.total_down);
        let conns = self.conns;
        let up_lbl = self.t("上传", "Up");
        let down_lbl = self.t("下载", "Down");
        let conn_lbl = self.t("连接", "Conns");
        egui::Panel::bottom("statusbar")
            .exact_size(30.0)
            .resizable(false)
            .frame(
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(22, 26, 32))
                    .inner_margin(egui::Margin::symmetric(12, 6)),
            )
            .show(ui, |ui| {
            ui.horizontal(|ui| {
                let dot = if enabled {
                    egui::Color32::from_rgb(100, 220, 120)
                } else {
                    egui::Color32::from_rgb(150, 150, 150)
                };
                ui.colored_label(dot, "●");
                ui.label(status_text.as_str());
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(120, 180, 240), format!("↑ {up_lbl} {up_rate}"));
                ui.label(format!("({total_up})"));
                ui.separator();
                ui.colored_label(egui::Color32::from_rgb(150, 220, 150), format!("↓ {down_lbl} {down_rate}"));
                ui.label(format!("({total_down})"));
                ui.separator();
                ui.label(format!("{conn_lbl}: {conns}"));
            });
        });
    }

    fn show_central(&mut self, ui: &mut egui::Ui) {
        let view = self.view;
        egui::CentralPanel::default_margins().show(ui, |ui| match view {
            View::Connections => self.show_conn_list(ui),
            View::Log => {
                egui::ScrollArea::vertical().show(ui, |ui| self.show_log_body(ui));
            }
            // Config editors, formerly popup dialogs, now inline tabs.
            other => {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match other {
                    View::Servers => self.show_proxies(ui),
                    View::Chains => self.show_chains(ui),
                    View::Rules => self.show_rules(ui),
                    View::Options => self.show_options(ui),
                    View::Check => self.show_check(ui),
                    View::Route => self.show_route(ui),
                    View::Profiles => self.show_profiles(ui),
                    View::Appearance => self.show_appearance(ui),
                    _ => {}
                });
            }
        });
    }

    /// One-click tab bar for the main views (connection list, log) and every
    /// config editor that used to live under the "配置文件/Profile" popup menu.
    fn show_tabbar(&mut self, ui: &mut egui::Ui) {
        let mut view = self.view;
        let lang = self.config.settings.language;
        let hidden = self.config.settings.hidden_tabs.clone();
        egui::Panel::top("tabbar").show(ui, |ui| {
            ui.horizontal(|ui| {
                for (v, key, zh, en) in all_tabs() {
                    let is_hidden = hidden.iter().any(|h| h.eq_ignore_ascii_case(key));
                    // Always keep the active tab visible so a hidden-current state
                    // is never a dead end.
                    if is_hidden && view != v {
                        continue;
                    }
                    if ui.selectable_label(view == v, tr(lang, zh, en)).clicked() {
                        view = v;
                    }
                }
            });
        });
        self.view = view;
    }

    /// The live proxified-connection table, mirroring the original's main list
    /// (fnd_13): Application | Remote host | Server | Rule | Proto | Created |
    /// Sent | Received, with Disconnect/Delete for the selected row.
    fn show_conn_list(&mut self, ui: &mut egui::Ui) {
        let mut do_disconnect = false;
        let mut do_delete = false;
        let mut do_abort_app: Option<String> = None;
        let mut pending_rule: Option<(String, String, String)> = None;
        let mut pending_block: Option<(String, String, String)> = None;
        let n_active = self.conns;
        let d_txt = self.t("断开", "Disconnect");
        let del_txt = self.t("删除", "Delete");
        let app_d_txt = self.t("断开该程序全部", "Disconnect all for app");
        let rule_txt = self.t("＋规则", "＋Rule");
        let block_txt = self.t("＋屏蔽", "＋Block");
        let filt_hint = self.t("过滤…", "Filter…");
        let act_txt = self.t("活动连接", "Active").to_string();
        ui.horizontal(|ui| {
            if ui.button(d_txt).clicked() {
                do_disconnect = true;
            }
            if ui.button(del_txt).clicked() {
                do_delete = true;
            }
            ui.add(egui::TextEdit::singleline(&mut self.conn_filter).hint_text(filt_hint).desired_width(180.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(format!("{act_txt}: {n_active}"));
            });
        });
        ui.separator();
        if do_disconnect {
            if let Some(id) = self.selected_conn {
                // Signal the relay copy loops to stop, then mark the row closed.
                self.monitor.abort_flow(id);
            }
        }
        if let Some(app) = &do_abort_app {
            let n = self.monitor.abort_app(app);
            self.log("info", format!("已断开 {app} 的全部连接（{n} 条）"));
        }
        if do_delete {
            // fnd_13 "&Delete": remove the selected connection's ROW from the
            // list (not just deselect). A running relay keeps its own handle.
            if let Some(id) = self.selected_conn {
                self.monitor.remove_flow(id);
            }
            self.selected_conn = None;
        }

        let cols: [&str; 11] = [
            self.t("程序", "Application"),
            self.t("远程主机", "Remote host"),
            self.t("服务器", "Server"),
            self.t("规则", "Rule"),
            self.t("协议", "Proto"),
            self.t("已连接", "Created"),
            self.t("发送", "Sent"),
            self.t("接收", "Received"),
            "",
            "",
            "",
        ];
        let filt = self.conn_filter.clone();
        let all = self.monitor.active_rows();
        let rows: Vec<_> = all
            .into_iter()
            .filter(|r| crate::monitor::conn_filter_matches(r, &filt))
            .collect();
        let mut sel = self.selected_conn;
        let empty = self.t("（无连接）", "(no connections)").to_string();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("conn_grid").striped(true).min_col_width(8.0).show(ui, |ui| {
                    for c in &cols {
                        ui.strong(*c);
                    }
                    ui.end_row();
                    if rows.is_empty() {
                        ui.label(empty.as_str());
                        ui.end_row();
                    }
                    for r in &rows {
                        let dot = if r.active { "●" } else { "○" };
                        let label = format!("{dot} {}", r.app);
                        if ui.selectable_label(sel == Some(r.id), label.as_str()).clicked() {
                            sel = Some(r.id);
                        }
                        ui.label(r.remote.as_str());
                        ui.label(r.server.as_str());
                        ui.label(r.rule.as_str());
                        ui.label(r.proto);
                        ui.label(format!("{}s", r.elapsed_secs));
                        ui.label(fmt_bytes(r.sent));
                        ui.label(fmt_bytes(r.recv));
                        if ui.button(app_d_txt).clicked() {
                            do_abort_app = Some(r.app.clone());
                        }
                        if ui.button(rule_txt).clicked() {
                            pending_rule = Some((r.app.clone(), r.remote.clone(), r.proto.to_string()));
                        }
                        if ui.button(block_txt).clicked() {
                            pending_block = Some((r.app.clone(), r.remote.clone(), r.proto.to_string()));
                        }
                        ui.end_row();
                    }
                });
            });
        self.selected_conn = sel;
        if let Some((app, remote, proto)) = pending_rule {
            let id = self.config.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            let chain = self.config.chains.first().map(|c| c.id).unwrap_or(0);
            let rule = crate::rules::rule_from_conn(&app, &remote, &proto, chain, id);
            self.log("info", format!("已为连接新建规则：{}", rule.name));
            self.config.rules.push(rule);
        }
        if let Some((app, remote, proto)) = pending_block {
            let id = self.config.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            let rule = crate::rules::block_rule_from_conn(&app, &remote, &proto, id);
            self.log("info", format!("已为连接新建屏蔽规则：{}", rule.name));
            self.config.rules.push(rule);
        }
    }

    /// Options dialog (fnd_13): DNS settings, HTTP-proxy support, engine hook
    /// type, redundancy recheck, update check.
    fn show_options(&mut self, ui: &mut egui::Ui) {
        // Merged 选项 (was 常规设置 + 选项, de-duplicated). Fully expanded, with
        // second-level headings per section. Controls bind to locals, written back once.
        ui.heading(self.t("选项", "Options"));

        let mut name = self.config.settings.name.clone();
        let mut start_tray = self.config.settings.start_in_tray;
        let mut exclusion = self.exclusion_text.clone();
        let mut inclusion = self.inclusion_text.clone();
        let mut whitelist_enabled = self.config.settings.app_whitelist_enabled;
        let mut whitelist = self.whitelist_text.clone();
        let mut mode = self.config.settings.dns_mode;
        let mut block_udp = self.config.settings.block_udp_if_matched;
        let mut prox = self.config.settings.proxification_enabled;
        let mut leak = self.config.settings.ip_leak_prevention;
        let mut leak_chain = self.config.settings.ip_leak_default_chain;
        let mut rc = self.config.settings.redundancy_recheck_secs;
        let mut chk = self.config.settings.check_updates;

        let chain_opts: Vec<(u32, String)> = self
            .config
            .chains
            .iter()
            .map(|c| (c.id, format!("#{} — {}", c.id, c.name)))
            .collect();
        let off_label: String = self.t("关闭 (未命中即直连)", "Off (direct when unmatched)").to_string();
        let leak_selected = if leak_chain == 0 {
            off_label.clone()
        } else {
            chain_opts
                .iter()
                .find(|(id, _)| *id == leak_chain)
                .map(|(_, n)| n.clone())
                .unwrap_or_else(|| format!("#{leak_chain}"))
        };

        let lang = self.config.settings.language;
        let sub = |ui: &mut egui::Ui, zh: &'static str, en: &'static str| {
            ui.add_space(10.0);
            ui.strong(tr(lang, zh, en));
        };

        sub(ui, "配置文件", "Profile");
        ui.label(
            egui::RichText::new(tr(
                lang,
                "当前配置文件名 — 用于 另存为 / 导入 / 导出，并显示在窗口标题",
                "Current profile name — used by Save-As / Import / Export, shown in the window title",
            ))
            .weak(),
        );
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut name).id_salt("opt-name").desired_width(320.0).min_size(egui::vec2(320.0, 0.0)));
        });
        let saved_profiles = self.profile_store.list();
        if saved_profiles.is_empty() {
            ui.label(egui::RichText::new(tr(lang, "（暂无已保存的配置，可在「配置文件」页另存）", "(no saved profiles yet — use Save-As on the Profiles tab)")).weak());
        } else {
            let cur_profile = self
                .selected_profile
                .clone()
                .unwrap_or_else(|| self.config.settings.name.clone());
            let mut chosen = cur_profile.clone();
            ui.horizontal(|ui| {
                ui.label(tr(lang, "切换配置文件", "Switch profile"));
                egui::ComboBox::new("profile-switch", "")
                    .selected_text(cur_profile.as_str())
                    .width(240.0)
                    .show_ui(ui, |ui| {
                        for p in &saved_profiles {
                            ui.selectable_value(&mut chosen, p.clone(), p.as_str());
                        }
                    });
            });
            if chosen != cur_profile {
                self.pending_switch = Some(chosen);
            }
        }
        ui.checkbox(&mut start_tray, tr(lang, "最小化到系统托盘（可经托盘菜单启停引擎/退出）", "Minimise to tray (start/stop engine + Quit via tray)"));

        sub(ui, "代理范围", "Proxy scope");
        let edit_hint = self.t("编辑列表", "Edit list");
        ui.horizontal(|ui| {
            ui.label(tr(lang, "代理排除列表", "Exclusion list"));
            ui.add(egui::TextEdit::singleline(&mut exclusion).id_salt("opt-exclusion").desired_width(360.0));
            if ui.button("…").on_hover_text(edit_hint).clicked() {
                self.list_editor_target = ListTarget::Exclusion;
                self.list_editor_items = split_list(&exclusion);
                self.dlg_list_editor = true;
            }
        });
        ui.horizontal(|ui| {
            ui.label(tr(lang, "代理包含列表", "Inclusion list"));
            ui.add(egui::TextEdit::singleline(&mut inclusion).id_salt("opt-inclusion").desired_width(360.0));
            if ui.button("…").on_hover_text(edit_hint).clicked() {
                self.list_editor_target = ListTarget::Inclusion;
                self.list_editor_items = split_list(&inclusion);
                self.dlg_list_editor = true;
            }
        });

        sub(ui, "程序白名单", "App whitelist");
        ui.checkbox(&mut whitelist_enabled, tr(lang, "启用程序白名单（仅白名单内程序走代理）", "Enable app whitelist (only listed apps are proxified)"));
        ui.horizontal(|ui| {
            ui.label(tr(lang, "程序白名单（逗号分隔）", "App whitelist (comma-separated)"));
            ui.add(egui::TextEdit::singleline(&mut whitelist).id_salt("opt-whitelist").desired_width(360.0));
            if ui.button("…").on_hover_text(tr(lang, "从运行中的程序选择", "Pick from running apps")).clicked() {
                self.whitelist_text = whitelist.clone();
                self.app_picker_mode = PickerMode::Whitelist;
                self.app_picker_query.clear();
                self.dlg_app_picker = true;
            }
        });

        sub(ui, "DNS", "DNS");
        ui.radio_value(&mut mode, DnsMode::Auto, tr(lang, "自动检测 DNS 设置", "Detect DNS settings automatically"));
        ui.radio_value(&mut mode, DnsMode::Proxy, tr(lang, "通过代理解析主机名", "Resolve hostnames through proxy"))
            .on_hover_text(tr(
                lang,
                "应用发往 :53 的 DNS 查询也走代理链路；没有可承载的链路时直接阻止，绝不回落到系统 DNS",
                "The app's own :53 queries ride the proxy chain too; blocked when no chain can carry them — never the OS resolver",
            ));
        ui.radio_value(&mut mode, DnsMode::Local, tr(lang, "不解析（系统 DNS）", "Do not resolve (System DNS)"));
        ui.checkbox(&mut block_udp, tr(lang, "命中规则时阻止所有 UDP 端口", "Block all UDP ports when a rule matches"));

        ui.add_space(6.0);
        ui.strong(tr(
            lang,
            "自定义解析器（按顺序尝试；列表留空 = 跟随系统；全部失败则不解析）",
            "Custom resolvers (tried in order; empty = system; all-fail = no resolve)",
        ));
        let mut dns_servers = self.config.settings.dns.servers.clone();
        let mut dns_del: Option<usize> = None;
        let mut dns_up: Option<usize> = None;
        let mut dns_dn: Option<usize> = None;
        egui::Grid::new("dns-resolver")
            .num_columns(6)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                for (idx, s) in dns_servers.iter_mut().enumerate() {
                    egui::ComboBox::new(("dns-proto", idx), "")
                        .selected_text(s.protocol.as_str())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut s.protocol, DnsProto::Udp, "udp");
                            ui.selectable_value(&mut s.protocol, DnsProto::Tcp, "tcp");
                        });
                    ui.add(
                        egui::TextEdit::singleline(&mut s.server)
                            .desired_width(200.0)
                            .min_size(egui::vec2(200.0, 0.0))
                            .hint_text("1.1.1.1"),
                    );
                    ui.add(egui::DragValue::new(&mut s.port).range(1..=u16::MAX));
                    if ui.button("🗑").clicked() {
                        dns_del = Some(idx);
                    }
                    if ui.button("↑").clicked() {
                        dns_up = Some(idx);
                    }
                    if ui.button("↓").clicked() {
                        dns_dn = Some(idx);
                    }
                    ui.end_row();
                }
            });
        if let Some(i) = dns_up {
            if i > 0 {
                dns_servers.swap(i, i - 1);
            }
        }
        if let Some(i) = dns_dn {
            if i + 1 < dns_servers.len() {
                dns_servers.swap(i, i + 1);
            }
        }
        if let Some(i) = dns_del {
            dns_servers.remove(i);
        }
        ui.horizontal(|ui| {
            if ui.button(tr(lang, "＋ 添加解析器", "＋ Add resolver")).clicked() {
                dns_servers.push(DnsServer::default());
            }
            if dns_servers.is_empty() {
                ui.label(egui::RichText::new(tr(lang, "（空 = 使用系统 DNS）", "(empty = OS resolver)")).weak());
            }
        });
        self.config.settings.dns.servers = dns_servers;

        sub(ui, "代理行为", "Proxy behaviour");
        ui.checkbox(&mut prox, tr(lang, "启用代理（取消=全局暂停，全部直连）", "Proxification enabled (uncheck = pause, everything direct)"));
        ui.checkbox(&mut leak, tr(lang, "IP 泄漏防护", "IP leak prevention"));
        ui.horizontal(|ui| {
            ui.label(tr(lang, "兜底代理链", "Fallback chain"));
            egui::ComboBox::new("opt-leak-chain", "")
                .selected_text(leak_selected.as_str())
                .width(220.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut leak_chain, 0u32, off_label.as_str());
                    for (id, label) in &chain_opts {
                        ui.selectable_value(&mut leak_chain, *id, label.as_str());
                    }
                });
        });
        ui.horizontal(|ui| {
            ui.label(tr(lang, "重测失败代理间隔（秒）", "Recheck failed proxy each (sec.)"));
            ui.add(egui::DragValue::new(&mut rc).range(5..=3600));
        });

        sub(ui, "更新", "Updates");
        ui.checkbox(&mut chk, tr(lang, "启动时检查产品更新", "Check for Product Updates on Startup"));

        // Write everything back once.
        self.config.settings.name = name.trim().to_string();
        self.config.settings.start_in_tray = start_tray;
        self.exclusion_text = exclusion;
        self.inclusion_text = inclusion;
        self.config.settings.proxy_exclusion_list = split_list(&self.exclusion_text);
        self.config.settings.proxy_inclusion_list = split_list(&self.inclusion_text);
        self.config.settings.app_whitelist_enabled = whitelist_enabled;
        self.whitelist_text = whitelist;
        self.config.settings.app_whitelist = split_list(&self.whitelist_text);
        self.config.settings.dns_mode = mode;
        self.config.settings.block_udp_if_matched = block_udp;
        self.config.settings.proxification_enabled = prox;
        self.config.settings.ip_leak_prevention = leak;
        self.config.settings.ip_leak_default_chain = leak_chain;
        self.config.settings.redundancy_recheck_secs = rc;
        self.config.settings.check_updates = chk;

        ui.add_space(6.0);
        self.show_serve_controls(ui);
    }

    fn show_about(&mut self, ui: &mut egui::Ui) {
        ui.heading("trans-proxier");
        ui.label(self.t(
            "开源净室复刻（Rust）——仅复刻行为，不含原版代码。",
            "An open-source clean-room recreation in Rust — behaviour only, no original code.",
        ));
        ui.label("TCP + connected-UDP transparent proxification; SOCKS5 / HTTP-CONNECT chaining.");
        ui.label("UI layout and command names reconstructed from the original (fnd_13).");
    }

    /// Render the floating editor dialogs, each toggled from the menu bar.
    fn show_dialogs(&mut self, ctx: &egui::Context) {
        // Each block uses a LOCAL `open` (copied from the flag), so the window's
        // `&mut open` and the `self.show_*` body borrow disjoint things.
        {
            let mut open = self.dlg_settings;
            if open {
                let title = self.t("常规设置", "General / Settings");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_settings(ui));
                self.dlg_settings = open;
            }
        }
        {
            let mut open = self.dlg_servers;
            if open {
                let title = self.t("代理服务器", "Proxy Servers");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_proxies(ui));
                self.dlg_servers = open;
            }
        }
        {
            let mut open = self.dlg_chains;
            if open {
                let title = self.t("代理链", "Proxy Chains");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_chains(ui));
                self.dlg_chains = open;
            }
        }
        {
            let mut open = self.dlg_rules;
            if open {
                let title = self.t("代理规则", "Proxification Rules");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_rules(ui));
                self.dlg_rules = open;
            }
        }
        {
            let mut open = self.dlg_route;
            if open {
                let title = self.t("路由测试", "Route test");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_route(ui));
                self.dlg_route = open;
            }
        }
        {
            let mut open = self.dlg_check;
            if open {
                let title = self.t("连通检测", "Proxy Checker");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_check(ui));
                self.dlg_check = open;
            }
        }
        {
            let mut open = self.dlg_options;
            if open {
                let title = self.t("选项", "Options");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_options(ui));
                self.dlg_options = open;
            }
        }
        {
            let mut open = self.dlg_about;
            if open {
                let title = self.t("关于本软件", "About");
                egui::Window::new(title).open(&mut open).show(ctx, |ui| self.show_about(ui));
                self.dlg_about = open;
            }
        }
        {
            let mut open = self.dlg_profiles;
            if open {
                let title = self.t("管理配置文件", "Manage Profiles");
                egui::Window::new(title).open(&mut open).default_width(460.0).show(ctx, |ui| self.show_profiles(ui));
                self.dlg_profiles = open;
            }
        }
        {
            let mut open = self.dlg_app_picker;
            if open {
                let title = self.t("选择程序（可搜索/多选）", "Pick apps (search / multi-select)");
                egui::Window::new(title)
                    .open(&mut open)
                    .default_width(360.0)
                    .default_height(440.0)
                    .show(ctx, |ui| self.show_app_picker(ui));
                self.dlg_app_picker = open;
            }
        }
        {
            let mut open = self.dlg_list_editor;
            if open {
                let title = self.t("编辑列表", "Edit list");
                egui::Window::new(title)
                    .open(&mut open)
                    .default_width(420.0)
                    .show(ctx, |ui| self.show_list_editor(ui));
                self.dlg_list_editor = open;
            }
        }
    }

    /// Generic editable string-list modal: a text row per item with a trash
    /// button, ＋ 添加, and 保存 that writes back to the target comma-list.
    fn show_list_editor(&mut self, ui: &mut egui::Ui) {
        let target = self.list_editor_target;
        let add_lbl = self.t("＋ 添加", "＋ Add").to_string();
        let save_lbl = self.t("保存", "Save").to_string();
        let cancel_lbl = self.t("取消", "Cancel").to_string();
        let mut remove: Vec<usize> = Vec::new();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(320.0)
            .show(ui, |ui| {
                for (idx, it) in self.list_editor_items.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(it)
                                .id_salt(("le-item", idx))
                                .desired_width(320.0)
                                .min_size(egui::vec2(320.0, 0.0)),
                        );
                        if ui.button("🗑").clicked() {
                            remove.push(idx);
                        }
                    });
                }
            });
        for i in remove.iter().rev() {
            self.list_editor_items.remove(*i);
        }
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button(add_lbl.as_str()).clicked() {
                self.list_editor_items.push(String::new());
            }
            if ui.button(save_lbl.as_str()).clicked() {
                let joined = self
                    .list_editor_items
                    .iter()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(",");
                match target {
                    ListTarget::Exclusion => {
                        self.exclusion_text = joined.clone();
                        self.config.settings.proxy_exclusion_list = split_list(&joined);
                    }
                    ListTarget::Inclusion => {
                        self.inclusion_text = joined.clone();
                        self.config.settings.proxy_inclusion_list = split_list(&joined);
                    }
                }
                self.dlg_list_editor = false;
            }
            if ui.button(cancel_lbl.as_str()).clicked() {
                self.dlg_list_editor = false;
            }
        });
    }

    /// Searchable, case-insensitive, multi-select list of running processes,
    /// grouped by category (程序/服务/未知). Reused for a rule's `app` field AND the
    /// global app whitelist; the checked set is written back as a comma list.
    fn show_app_picker(&mut self, ui: &mut egui::Ui) {
        let mode = self.app_picker_mode;
        if let PickerMode::Rule(i) = mode {
            if self.config.rules.get(i).is_none() {
                self.dlg_app_picker = false;
                return;
            }
        }
        if ui.button(self.t("刷新运行列表", "Refresh running apps")).clicked() {
            self.app_list = crate::intercept::running_app_names();
        }

        // Current tokens by target.
        let cur: String = match mode {
            PickerMode::Rule(i) => self.config.rules[i].app.clone().unwrap_or_default(),
            PickerMode::Whitelist => self.whitelist_text.clone(),
            PickerMode::FixedApp => self.serve_app.clone(),
        };
        let mut tokens: Vec<String> =
            crate::rules::pattern_list(&cur).into_iter().map(|s| s.to_string()).collect();
        let mut sel_lower: std::collections::HashSet<String> =
            tokens.iter().map(|t| t.to_ascii_lowercase()).collect();

        // Candidates = running apps ∪ tokens already set (typed/non-running names stay
        // visible + checked). Dedup case-insensitively, then group by category.
        let mut by_lower: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for n in self.app_list.iter().chain(tokens.iter()) {
            by_lower.entry(n.to_ascii_lowercase()).or_insert_with(|| n.clone());
        }
        let mut candidates: Vec<String> = by_lower.into_values().collect();
        candidates.sort_by_key(|a| a.to_ascii_lowercase());
        let mut grouped: std::collections::BTreeMap<&'static str, Vec<String>> =
            Default::default();
        for n in candidates {
            grouped
                .entry(crate::intercept::app_category(&n))
                .or_default()
                .push(n);
        }

        let search_lbl = self.t("搜索", "Search").to_string();
        let hint = self.t("不区分大小写", "case-insensitive").to_string();
        let clear_lbl = self.t("清除", "Clear").to_string();
        let n_cand = tokens.len();
        let query = &mut self.app_picker_query;
        ui.horizontal(|ui| {
            ui.label(search_lbl.as_str());
            ui.add(
                egui::TextEdit::singleline(query)
                    .hint_text(hint.as_str())
                    .desired_width(220.0),
            );
            if !query.is_empty() && ui.button(clear_lbl.as_str()).clicked() {
                query.clear();
            }
            let _ = n_cand;
        });
        let q = self.app_picker_query.trim().to_ascii_lowercase();
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for cat in ["程序", "服务", "未知"] {
                    let Some(items) = grouped.get(cat) else { continue };
                    let visible: Vec<&String> = items
                        .iter()
                        .filter(|n| q.is_empty() || n.to_ascii_lowercase().contains(&q))
                        .collect();
                    if visible.is_empty() {
                        continue;
                    }
                    ui.add_space(4.0);
                    ui.strong(cat);
                    for name in visible {
                        let lower = name.to_ascii_lowercase();
                        let mut on = sel_lower.contains(&lower);
                        if ui.checkbox(&mut on, name.as_str()).changed() {
                            if on {
                                sel_lower.insert(lower.clone());
                                tokens.push(name.clone());
                            } else {
                                sel_lower.remove(&lower);
                                tokens.retain(|t| t.to_ascii_lowercase() != lower);
                            }
                            let joined =
                                if tokens.is_empty() { None } else { Some(tokens.join(",")) };
                            match mode {
                                PickerMode::Rule(i) => {
                                    if let Some(r) = self.config.rules.get_mut(i) {
                                        r.app = joined;
                                    }
                                }
                                PickerMode::Whitelist => {
                                    self.whitelist_text = joined.unwrap_or_default();
                                    self.config.settings.app_whitelist = tokens.clone();
                                }
                                PickerMode::FixedApp => {
                                    self.serve_app = joined.unwrap_or_default();
                                }
                            }
                        }
                    }
                }
            });
        if ui.button(self.t("完成", "Done")).clicked() {
            self.dlg_app_picker = false;
        }
    }

    /// Profiles dialog (fnd_13): New/Save As/Load/Delete + Import/Export paths.
    /// Load a saved profile and make it the active config (name/title follow).
    fn apply_profile_load(&mut self, n: &str) {
        let pw = self.profile_password.clone();
        match self.profile_store.load_with(n, Some(&pw)) {
            Ok(mut c) => {
                c.settings.name = n.to_string();
                self.exclusion_text = join_list(&c.settings.proxy_exclusion_list);
                self.inclusion_text = join_list(&c.settings.proxy_inclusion_list);
                self.whitelist_text = join_list(&c.settings.app_whitelist);
                self.config = c;
                self.config.settings.active_profile = n.to_string();
                self.saved = self.config.clone();
                self.selected_profile = Some(n.to_string());
                self.profile_name = n.to_string();
                self.log("info", format!("已切换/加载配置 \"{n}\""));
                self.status = format!("Profile: {n}");
            }
            Err(e) => self.log("warn", format!("加载配置 {n} 失败：{e}")),
        }
    }

    fn show_profiles(&mut self, ui: &mut egui::Ui) {
        ui.label(format!(
            "{}: {}",
            self.t("配置目录", "Profiles folder"),
            self.profile_store.dir().display()
        ));
        let mut name = self.profile_name.clone();
        ui.horizontal(|ui| {
            ui.label(self.t("名称", "Name"));
            ui.add(egui::TextEdit::singleline(&mut name).desired_width(200.0).hint_text("work"));
        });
        self.profile_name = name.clone();

        let names = self.profile_store.list();
        let mut load: Option<String> = None;
        let mut del: Option<String> = None;
        ui.group(|ui| {
            ui.strong(self.t("已保存的配置", "Saved profiles"));
            if names.is_empty() {
                ui.label(self.t("（无）", "(none)"));
            }
            for n in &names {
                ui.horizontal(|ui| {
                    let enc = self.profile_store.is_encrypted(n);
                    let label = if enc { format!("🔒 {n}") } else { n.clone() };
                    if ui.selectable_label(self.selected_profile.as_deref() == Some(n.as_str()), &label).clicked() {
                        self.selected_profile = Some(n.clone());
                    }
                    if ui.button(self.t("加载", "Load")).clicked() { load = Some(n.clone()); }
                    if ui.button(self.t("删除", "Delete")).clicked() { del = Some(n.clone()); }
                });
            }
        });

        if let Some(n) = load.as_deref() {
            self.apply_profile_load(n);
        }
        if let Some(n) = &del {
            match self.profile_store.delete(n) {
                Ok(()) => self.log("info", format!("已删除配置 \"{n}\"")),
                Err(e) => self.log("warn", e),
            }
            if self.selected_profile.as_deref() == Some(n.as_str()) {
                self.selected_profile = None;
            }
        }

        ui.horizontal(|ui| {
            let pw_label = self.t("主密码", "Master password");
            let pw_hint = self.t("加载加密配置/加密保存时填写", "to load/save an encrypted profile");
            let enc_label = self.t("加密保存", "Encrypt on save");
            ui.label(pw_label);
            ui.add(
                egui::TextEdit::singleline(&mut self.profile_password)
                    .password(true)
                    .desired_width(200.0)
                    .hint_text(pw_hint),
            );
            ui.checkbox(&mut self.profile_encrypt, enc_label);
        });

        ui.horizontal(|ui| {
            let saveas_txt = self.t("另存当前配置为…", "Save current as…");
            if ui.button(saveas_txt).clicked() && !name.trim().is_empty() {
                let pw = self.profile_password.clone();
                let res = if self.profile_encrypt && !pw.is_empty() {
                    self.profile_store.save_password(&name, &self.config, &pw)
                } else {
                    self.profile_store.save(&name, &self.config)
                };
                match res {
                    Ok(()) => {
                        let kind = if self.profile_encrypt && !pw.is_empty() { self.t("（已加密）", " (encrypted)") } else { "" };
                        self.log("info", format!("已保存配置 \"{name}\"{kind}"));
                    }
                    Err(e) => self.log("warn", e),
                }
            }
            let newsave_txt = self.t("新建默认配置", "New profile");
            if ui.button(newsave_txt).clicked() && !name.trim().is_empty() && !self.profile_store.exists(&name) {
                match self.profile_store.save(&name, &Config::default()) {
                    Ok(()) => self.log("info", format!("已新建配置 \"{name}\"")),
                    Err(e) => self.log("warn", e),
                }
            }
        });

        // fnd_13: Import Profile… / Export Profile… (path text entry; the OS
        // native picker needs a file-dialog crate, so a typed path is used).
        ui.horizontal(|ui| {
            let file_label = self.t("文件路径", "File path");
            let imp_txt = self.t("导入…", "Import…");
            let exp_txt = self.t("导出…", "Export…");
            ui.label(file_label);
            ui.add(
                egui::TextEdit::singleline(&mut self.profile_file)
                    .id_salt("profile-file")
                    .desired_width(240.0)
                    .hint_text(r"C:\path\profile.ini"),
            );
            let file = self.profile_file.clone();
            let pw = self.profile_password.clone();
            // Import into the store under the typed name (or "imported").
            if ui.button(imp_txt).clicked() && !file.trim().is_empty() {
                let target = if name.trim().is_empty() { "imported".to_string() } else { name.clone() };
                match self.profile_store.import_with(Path::new(file.trim()), &target, Some(&pw)) {
                    Ok(()) => {
                        self.log("info", format!("已导入 \"{target}\" 自 {file}"));
                        self.selected_profile = Some(target);
                    }
                    Err(e) => self.log("warn", e),
                }
            }
            // Export the selected profile to the file.
            let sel = self.selected_profile.clone();
            if ui.button(exp_txt).clicked() && !file.trim().is_empty() {
                match sel {
                    Some(s) => match self.profile_store.export(&s, Path::new(file.trim())) {
                        Ok(()) => self.log("info", format!("已导出 \"{s}\" 到 {file}")),
                        Err(e) => self.log("warn", e),
                    },
                    None => self.log("warn", self.t("请先在列表中选择一个配置", "Select a profile first").to_string()),
                }
            }
        });
    }

    fn show_settings(&mut self, ui: &mut egui::Ui) {
        // Merged into 选项 (View::Options); thin alias so older callers/menu still work.
        self.show_options(ui);
    }

    /// 外观 / Appearance — UI font size and which tabs are shown (persisted to config).
    fn show_appearance(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.t("外观", "Appearance"));
        let mut pct = self.config.settings.ui_scale_pct as i32;
        ui.horizontal(|ui| {
            ui.label(self.t("字体大小", "Font size"));
            ui.add(egui::Slider::new(&mut pct, 50..=300).suffix("%"));
            if ui.button(self.t("重置", "Reset")).clicked() {
                pct = 100;
            }
        });
        self.config.settings.ui_scale_pct = (pct as u32).clamp(50, 300);

        ui.add_space(6.0);
        ui.label(self.t("显示的标签页", "Visible tabs"));
        let lang = self.config.settings.language;
        egui::Grid::new("tab-visibility")
            .num_columns(3)
            .spacing([12.0, 4.0])
            .show(ui, |ui| {
                for (i, tab) in all_tabs().iter().enumerate() {
                    let &(_, key, zh, en) = tab;
                    let mut shown =
                        !self.config.settings.hidden_tabs.iter().any(|h| h.eq_ignore_ascii_case(key));
                    if ui.checkbox(&mut shown, tr(lang, zh, en)).changed() {
                        if shown {
                            self.config.settings.hidden_tabs.retain(|h| !h.eq_ignore_ascii_case(key));
                        } else if !self.config.settings.hidden_tabs.iter().any(|h| h.eq_ignore_ascii_case(key)) {
                            self.config.settings.hidden_tabs.push(key.to_string());
                        }
                    }
                    if i % 3 == 2 {
                        ui.end_row();
                    }
                }
            });
    }

    fn show_proxies(&mut self, ui: &mut egui::Ui) {
        let heading = format!(
            "{} ({})",
            self.t("代理服务器", "Proxy servers"),
            self.config.proxies.len()
        );
        ui.heading(heading);
        let name_label = self.t("名称", "Name");
        let kind_label = self.t("类型", "Type");
        let host_label = self.t("主机", "Host");
        let port_label = self.t("端口", "Port");
        let timeout_label = self.t("超时(秒)", "Timeout (s)");
        let user_label = self.t("用户", "User");
        let pass_label = self.t("密码", "Password");
        let add_label = self.t("添加代理", "Add proxy");

        let snapshot: Vec<(usize, ProxyServer)> = self
            .config
            .proxies
            .iter()
            .enumerate()
            .map(|(i, p)| (i, p.clone()))
            .collect();
        let mut remove_idx: Option<usize> = None;

        for (i, p) in snapshot {
            let pid = p.id;
            let mut name = p.name.clone();
            let mut kind = p.kind;
            let mut host = p.host.clone();
            let mut port = p.port;
            let mut timeout = p.timeout_secs;
            let mut username = p.username.clone().unwrap_or_default();
            let mut password = p.password.clone().unwrap_or_default();
            let mut remove = false;
            let mut enabled = !self.config.settings.disabled_proxies.contains(&pid);

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.monospace(format!("#{pid}"));
                    ui.checkbox(&mut enabled, self.t("启用", "On"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("🗑").clicked() {
                            remove = true;
                        }
                    });
                });
                ui.separator();
                egui::Grid::new(("px-grid", i))
                    .num_columns(4)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(name_label);
                        ui.add(egui::TextEdit::singleline(&mut name).id_salt(("px-name", i)).desired_width(240.0).min_size(egui::vec2(240.0, 0.0)));
                        ui.label(kind_label);
                        egui::ComboBox::new(("px-kind", i), "")
                            .selected_text(kind.as_str())
                            .width(130.0)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut kind, ProxyKind::Http, "http");
                                ui.selectable_value(&mut kind, ProxyKind::Https, "https");
                                ui.selectable_value(&mut kind, ProxyKind::Socks4, "socks4");
                                ui.selectable_value(&mut kind, ProxyKind::Socks5, "socks5");
                            });
                        ui.end_row();

                        ui.label(host_label);
                        ui.add(egui::TextEdit::singleline(&mut host).id_salt(("px-host", i)).desired_width(240.0).min_size(egui::vec2(240.0, 0.0)));
                        ui.label(port_label);
                        ui.add(egui::DragValue::new(&mut port).range(1..=u16::MAX).speed(1.0));
                        ui.end_row();

                        ui.label(user_label);
                        ui.add(egui::TextEdit::singleline(&mut username).id_salt(("px-user", i)).desired_width(240.0).min_size(egui::vec2(240.0, 0.0)));
                        ui.label(timeout_label);
                        ui.add(egui::DragValue::new(&mut timeout).range(1..=u64::MAX).speed(1.0));
                        ui.end_row();

                        ui.label(pass_label);
                        ui.add(egui::TextEdit::singleline(&mut password).password(true).id_salt(("px-pass", i)).desired_width(240.0).min_size(egui::vec2(240.0, 0.0)));
                        ui.end_row();
                    });
            });

            let p = &mut self.config.proxies[i];
            p.name = name.trim().to_string();
            p.kind = kind;
            p.host = host.trim().to_string();
            p.port = port;
            p.timeout_secs = timeout;
            p.username = if username.trim().is_empty() {
                None
            } else {
                Some(username.trim().to_string())
            };
            p.password = if password.trim().is_empty() {
                None
            } else {
                Some(password.trim().to_string())
            };
            if enabled {
                self.config.settings.disabled_proxies.retain(|x| *x != pid);
            } else if !self.config.settings.disabled_proxies.contains(&pid) {
                self.config.settings.disabled_proxies.push(pid);
            }
            if remove {
                remove_idx = Some(i);
            }
        }

        if let Some(i) = remove_idx {
            self.config.proxies.remove(i);
        }
        if ui.button(add_label).clicked() {
            let id = self.config.proxies.iter().map(|p| p.id).max().unwrap_or(0) + 1;
            self.config.proxies.push(ProxyServer {
                id,
                name: format!("proxy-{id}"),
                kind: ProxyKind::Http,
                host: "127.0.0.1".into(),
                port: 8080,
                username: None,
                password: None,
                timeout_secs: 10,
            });
        }
    }

    fn show_chains(&mut self, ui: &mut egui::Ui) {
        let heading = format!(
            "{} ({})",
            self.t("代理链", "Chains"),
            self.config.chains.len()
        );
        ui.heading(heading);
        let name_label = self.t("名称", "Name");
        let ids_label = self.t("代理ID", "Proxy IDs");
        let add_slot_label = self.t("加一跳", "+ hop");
        let add_label = self.t("添加代理链", "Add chain");

        let snapshot: Vec<(usize, Chain)> = self
            .config
            .chains
            .iter()
            .enumerate()
            .map(|(i, c)| (i, c.clone()))
            .collect();
        let mut remove_idx: Option<usize> = None;

        for (i, c) in snapshot {
            let cid = c.id;
            let mut name = c.name.clone();
            let mut slots = c.proxies.clone();
            let mut remove = false;
            let mut remove_slot: Option<usize> = None;
            let mut add_slot = false;

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.monospace(format!("#{cid}"));
                    ui.label(name_label);
                    ui.add(egui::TextEdit::singleline(&mut name).id_salt(("ch-name", i)).desired_width(220.0));
                    if ui.button("🗑").clicked() {
                        remove = true;
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(ids_label);
                    let mut j = 0;
                    while j < slots.len() {
                        ui.add(egui::DragValue::new(&mut slots[j]).range(1..=u32::MAX).speed(1.0));
                        if ui.button("🗑").clicked() {
                            remove_slot = Some(j);
                        }
                        j += 1;
                    }
                    if ui.button(add_slot_label).clicked() {
                        add_slot = true;
                    }
                });
            });

            if let Some(j) = remove_slot {
                slots.remove(j);
            }
            if add_slot {
                let id = self.config.proxies.iter().map(|p| p.id).max().unwrap_or(0);
                slots.push(id);
            }
            let c = &mut self.config.chains[i];
            c.name = name.trim().to_string();
            c.proxies = slots;
            if remove {
                remove_idx = Some(i);
            }
        }

        if let Some(i) = remove_idx {
            self.config.chains.remove(i);
        }
        if ui.button(add_label).clicked() {
            let id = self.config.chains.iter().map(|c| c.id).max().unwrap_or(0) + 1;
            self.config.chains.push(Chain {
                id,
                name: format!("chain-{id}"),
                proxies: Vec::new(),
            });
        }
    }

    fn show_rules(&mut self, ui: &mut egui::Ui) {
        let heading = format!(
            "{} ({})",
            self.t("规则", "Rules"),
            self.config.rules.len()
        );
        ui.heading(heading);
        let file_lbl = self.t("规则文件", "Rules file");
        let exp_lbl = self.t("导出规则", "Export").to_string();
        let imp_lbl = self.t("导入规则(覆盖)", "Import (replace)").to_string();
        let mut do_export = false;
        let mut do_import = false;
        {
            let path = &mut self.rules_io_path;
            ui.horizontal(|ui| {
                ui.label(file_lbl);
                ui.add(egui::TextEdit::singleline(path).id_salt("rules-io-path").desired_width(320.0).min_size(egui::vec2(320.0, 0.0)).hint_text("rules.ini"));
                if ui.button(exp_lbl.as_str()).clicked() {
                    do_export = true;
                }
                if ui.button(imp_lbl.as_str()).clicked() {
                    do_import = true;
                }
            });
        }
        if do_export {
            match std::fs::write(&self.rules_io_path, Config::serialize_rules(&self.config.rules)) {
                Ok(_) => self.log("info", format!("已导出规则到 {}", self.rules_io_path)),
                Err(e) => self.log("warn", format!("导出规则失败: {e}")),
            }
        }
        if do_import {
            match std::fs::read_to_string(&self.rules_io_path)
                .map_err(|e| e.to_string())
                .and_then(|t| Config::parse_rules(&t))
            {
                Ok(rules) => {
                    let n = rules.len();
                    self.config.rules = rules;
                    self.log("info", format!("已导入 {n} 条规则（覆盖）"));
                }
                Err(e) => self.log("warn", format!("导入规则失败: {e}")),
            }
        }
        ui.separator();
        let enabled_label = self.t("启用", "Enabled");
        let name_label = self.t("名称", "Name");
        let priority_label = self.t("优先级", "Priority");
        let app_label = self.t("程序", "App");
        let host_label = self.t("主机", "Host");
        let port_label = self.t("端口", "Port");
        let action_label = self.t("动作", "Action");
        let proxy_label = self.t("代理", "Proxy");
        let direct_label = self.t("直连", "Direct");
        let block_label = self.t("阻止", "Block");
        let chain_label = self.t("链", "Chain");
        let add_label = self.t("添加规则", "Add rule");

        let snapshot: Vec<(usize, Rule)> = self
            .config
            .rules
            .iter()
            .enumerate()
            .map(|(i, r)| (i, r.clone()))
            .collect();
        let chains: Vec<Chain> = self.config.chains.clone();
        let mut remove_idx: Option<usize> = None;

        for (i, r) in snapshot {
            let rid = r.id;
            let mut name = r.name.clone();
            let mut enabled = r.enabled;
            let mut priority = r.priority;
            let mut app = r.app.clone().unwrap_or_default();
            let mut host = r.host.clone().unwrap_or_default();
            let mut port = r.port.clone().unwrap_or_default();
            let mut proto = r.protocol;
            #[derive(PartialEq)]
            enum Kind {
                Proxy,
                Direct,
                Block,
            }
            let mut kind = match r.action {
                RuleAction::Proxy { .. } => Kind::Proxy,
                RuleAction::Direct => Kind::Direct,
                RuleAction::Block => Kind::Block,
            };
            let mut chain = match r.action {
                RuleAction::Proxy { chain } => chain,
                _ => chains.first().map(|c| c.id).unwrap_or(0),
            };
            let chain_sel = chains
                .iter()
                .find(|c| c.id == chain)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("#{chain}"));
            let mut remove = false;

            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.monospace(format!("#{rid}"));
                    ui.checkbox(&mut enabled, enabled_label);
                    ui.label(name_label);
                    ui.add(egui::TextEdit::singleline(&mut name).id_salt(("r-name", i)).desired_width(140.0));
                    ui.label(priority_label);
                    ui.add(egui::DragValue::new(&mut priority).range(i32::MIN..=i32::MAX).speed(1.0));
                    if ui.button("🗑").clicked() {
                        remove = true;
                    }
                });
                egui::Grid::new(("r-fields", i))
                    .num_columns(4)
                    .spacing([10.0, 6.0])
                    .show(ui, |ui| {
                        ui.label(app_label);
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut app).id_salt(("r-app", i)).desired_width(220.0).min_size(egui::vec2(220.0, 0.0)).hint_text(self.t("多个用逗号分隔", "comma-separated")));
                            if ui
                                .button("…")
                                .on_hover_text(self.t("从运行中的程序选择", "Pick from running apps"))
                                .clicked()
                            {
                                if self.app_list.is_empty() {
                                    self.app_list = crate::intercept::running_app_names();
                                }
                                self.app_picker_mode = PickerMode::Rule(i);
                                self.app_picker_query.clear();
                                self.dlg_app_picker = true;
                            }
                        });
                        ui.label(host_label);
                        ui.add(egui::TextEdit::singleline(&mut host).id_salt(("r-host", i)).desired_width(240.0).min_size(egui::vec2(240.0, 0.0)).hint_text(self.t("多个用逗号分隔", "comma-separated")));
                        ui.end_row();

                        ui.label(port_label);
                        ui.add(egui::TextEdit::singleline(&mut port).id_salt(("r-port", i)).desired_width(220.0).min_size(egui::vec2(220.0, 0.0)).hint_text(self.t("80,443,8000-8100", "80,443,8000-8100")));
                        ui.label(self.t("协议", "Proto"));
                        let proto_sel = match proto {
                            RuleProtocol::Tcp => self.t("TCP", "TCP"),
                            RuleProtocol::Udp => self.t("UDP", "UDP"),
                            RuleProtocol::Both => self.t("TCP 和 UDP", "TCP and UDP"),
                        };
                        egui::ComboBox::new(("r-proto", i), "")
                            .selected_text(proto_sel)
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut proto, RuleProtocol::Both, self.t("TCP 和 UDP", "TCP and UDP"));
                                ui.selectable_value(&mut proto, RuleProtocol::Tcp, "TCP");
                                ui.selectable_value(&mut proto, RuleProtocol::Udp, "UDP");
                            });
                        ui.end_row();
                    });
                ui.horizontal(|ui| {
                    ui.label(action_label);
                    if ui.selectable_label(kind == Kind::Proxy, proxy_label).clicked() {
                        kind = Kind::Proxy;
                    }
                    if ui.selectable_label(kind == Kind::Direct, direct_label).clicked() {
                        kind = Kind::Direct;
                    }
                    if ui.selectable_label(kind == Kind::Block, block_label).clicked() {
                        kind = Kind::Block;
                    }
                    if kind == Kind::Proxy {
                        ui.label(chain_label);
                        egui::ComboBox::new(("r-chain", i), "")
                            .selected_text(chain_sel.as_str())
                            .width(180.0)
                            .show_ui(ui, |ui| {
                                for c in &chains {
                                    ui.selectable_value(&mut chain, c.id, c.name.as_str());
                                }
                            });
                    }
                });
            });

            let r = &mut self.config.rules[i];
            r.name = name.trim().to_string();
            r.enabled = enabled;
            r.priority = priority;
            r.app = if app.trim().is_empty() {
                None
            } else {
                Some(app.trim().to_string())
            };
            r.host = if host.trim().is_empty() {
                None
            } else {
                Some(host.trim().to_string())
            };
            r.port = {
                let toks: Vec<&str> = port
                    .split([',', ';', ' ', '\t'])
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if toks.is_empty() {
                    None
                } else {
                    Some(toks.join(","))
                }
            };
            r.protocol = proto;
            r.action = match kind {
                Kind::Proxy => RuleAction::Proxy { chain },
                Kind::Direct => RuleAction::Direct,
                Kind::Block => RuleAction::Block,
            };
            if remove {
                remove_idx = Some(i);
            }
        }

        if let Some(i) = remove_idx {
            self.config.rules.remove(i);
        }
        if ui.button(add_label).clicked() {
            let id = self.config.rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
            self.config.rules.push(Rule {
                id,
                name: format!("rule-{id}"),
                enabled: true,
                priority: 10,
                app: None,
                host: Some("*".into()),
                port: None,
                protocol: RuleProtocol::Both,
                action: RuleAction::Proxy {
                    chain: self.config.chains.first().map(|c| c.id).unwrap_or(0),
                },
            });
        }
    }

    fn show_route(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.t("路由测试", "Route test"));
        let host_label = self.t("主机", "Host");
        let port_label = self.t("端口", "Port");
        let app_label = self.t("程序", "App");
        let go_label = self.t("计算", "Compute");

        let mut host = self.route_host.clone();
        let mut port = self.route_port;
        let mut app = self.route_app.clone();
        let mut compute = false;

        ui.horizontal(|ui| {
            ui.label(host_label);
            ui.add(egui::TextEdit::singleline(&mut host).id_salt("route-host").desired_width(220.0));
            ui.label(port_label);
            ui.add(egui::DragValue::new(&mut port).range(1..=u16::MAX).speed(1.0));
            ui.label(app_label);
            ui.add(egui::TextEdit::singleline(&mut app).id_salt("route-app").desired_width(220.0).min_size(egui::vec2(220.0, 0.0)));
            if ui.button(go_label).clicked() {
                compute = true;
            }
        });
        self.route_host = host;
        self.route_port = port;
        self.route_app = app;
        if compute {
            self.compute_route();
        }
        if self.route_lines.is_empty() {
            ui.label(self.t("点击「计算」查看规则引擎对一条连接会做什么。", "Press Compute to see what the rule engine would do for a connection."));
        } else {
            for line in &self.route_lines {
                ui.monospace(line.as_str());
            }
        }
    }

    fn show_check(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.t("连通性检测", "Connectivity check"));
        let kind_label = self.t("类型", "Kind");
        let proxy_label = self.t("代理", "Proxy");
        let chain_label = self.t("代理链", "Chain");
        let id_label = self.t("ID", "ID");
        let host_label = self.t("目标主机", "Target host");
        let port_label = self.t("目标端口", "Target port");
        let check_label = self.t("检测", "Check");
        let checking_label = self.t("检测中…", "Checking…");

        let mut kind = self.check_kind;
        let mut id = self.check_id;
        let mut host = self.check_host.clone();
        let mut port = self.check_port;
        let checking = self.checking;
        let mut go = false;

        ui.horizontal(|ui| {
            ui.label(kind_label);
            if ui.selectable_label(kind == CheckKind::Proxy, proxy_label).clicked() {
                kind = CheckKind::Proxy;
            }
            if ui.selectable_label(kind == CheckKind::Chain, chain_label).clicked() {
                kind = CheckKind::Chain;
            }
            ui.label(id_label);
            ui.add(egui::DragValue::new(&mut id).range(1..=u32::MAX).speed(1.0));
            ui.label(host_label);
            ui.add(egui::TextEdit::singleline(&mut host).id_salt("check-host").desired_width(180.0));
            ui.label(port_label);
            ui.add(egui::DragValue::new(&mut port).range(1..=u16::MAX).speed(1.0));
            if checking {
                ui.label(checking_label);
            } else if ui.button(check_label).clicked() {
                go = true;
            }
        });
        self.check_kind = kind;
        self.check_id = id;
        self.check_host = host;
        self.check_port = port;
        if go {
            self.start_check();
        }
        for line in &self.check_lines {
            ui.monospace(line.as_str());
        }
    }

    fn show_serve_controls(&mut self, ui: &mut egui::Ui) {
        ui.heading(self.t("透明代理引擎", "Transparent proxy engine"));
        ui.label(self.t(
            "启动后安装钩子：白名单内程序的 TCP+UDP 全流量被自动劫持走代理，无需在程序里配置任何代理。",
            "Installs the hook: all TCP+UDP traffic of whitelisted programs is proxified automatically — no proxy setting in the app.",
        ));
        let drv_label = self.t("钩子驱动", "Hook driver");
        let start_label = self.t("启动", "Start");
        let stop_label = self.t("停止", "Stop");

        let consent_label = self.t(
            "同意安装全局钩子（会加载进本会话所有前台程序）",
            "I consent to install a global hook (loads into every foreground app)",
        );
        let mut consent = self.hook_consent;
        ui.horizontal(|ui| {
            ui.checkbox(&mut consent, consent_label);
        });
        self.hook_consent = consent;

        let trans_on = self.serve.is_some();
        let mut drv = self.driver_path.clone();
        let mut do_t_start = false;
        let mut do_t_stop = false;
        ui.horizontal(|ui| {
            if trans_on {
                if ui.button(stop_label).clicked() {
                    do_t_stop = true;
                }
            } else if ui.button(start_label).clicked() {
                do_t_start = true;
            }
            ui.label(drv_label);
            ui.add(egui::TextEdit::singleline(&mut drv).id_salt("serve-driver").desired_width(320.0));
        });
        self.driver_path = drv;
        if do_t_start {
            self.serve_start();
        }
        if do_t_stop {
            self.serve_stop();
        }
        if trans_on {
            ui.colored_label(
                egui::Color32::from_rgb(100, 220, 120),
                self.t("● 透明拦截运行中（钩子已装入其它进程）", "● Transparent interception running (hook injected)"),
            );
        }

        // ── WFP kernel redirect: the route that also covers services and processes
        //    with no message pump. Needs tpdrv_wfp.sys loaded, and (to install
        //    filters) an elevated process — both are reported, never assumed.
        #[cfg(windows)]
        {
            let l_cons = self.t(
                "同意 WFP 内核重定向（在内核改写连接目标）",
                "I consent to WFP kernel redirect (the connect target is rewritten in the kernel)",
            )
            .to_string();
            let l_en = self.t(
                "启用 WFP 内核重定向（需已加载 tpdrv_wfp.sys；安装过滤器需管理员）",
                "Enable WFP kernel redirect (needs tpdrv_wfp.sys loaded; filters need Administrator)",
            )
            .to_string();
            let mut wcons = self.wfp.consent;
            let mut wen = self.wfp.enabled;
            ui.horizontal(|ui| {
                ui.checkbox(&mut wcons, &l_cons);
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut wen, &l_en);
            });
            self.wfp.consent = wcons;
            if self.wfp.enabled && !wen {
                // switching off while armed
                if self.wfp.route.take().is_some() {
                    self.log("info", "WFP 内核重定向已停用（用户取消勾选）");
                }
                self.wfp.note = String::new();
            } else if !self.wfp.enabled && wen {
                // switching on while already running: honest about what it takes
                self.wfp.note = if self.serve.is_some() {
                    self.t(
                        "令牌端口随引擎而生：请先停止再启动透明引擎以启用 WFP 重定向",
                        "Token ports are bound when the engine starts: stop and start the engine to arm WFP",
                    )
                    .to_string()
                } else {
                    String::new()
                };
            }
            self.wfp.enabled = wen;
            if !self.wfp.note.is_empty() {
                ui.label(&self.wfp.note);
            }
            if self.wfp.route.is_some() {
                ui.colored_label(
                    egui::Color32::from_rgb(100, 220, 120),
                    self.t("● WFP 内核重定向运行中", "● WFP kernel redirect armed"),
                );
            }
        }

        ui.add_space(6.0);
        ui.separator();
        ui.label(self.t(
            "可选 · 手动本地代理（把程序指到这里填的 监听IP:端口，一般用上面的透明拦截即可）",
            "Optional · manual local proxy (point apps at the Listen-IP:Port below; the transparent engine above is usually enough)",
        ));
        let port_label = self.t("端口", "Port");
        let ip_label = self.t("监听 IP", "Listen IP");
        let app_label = self.t("固定程序名", "Fixed app name");
        let socks_on = self.socks.is_some();
        let http_on = self.http_proxy.is_some();
        let mut port = self.serve_port;
        let mut sip = self.socks_ip.clone();
        let mut hport = self.http_port;
        let mut hip = self.http_ip.clone();
        let mut app = self.serve_app.clone();
        let mut do_s_start = false;
        let mut do_s_stop = false;
        let mut do_h_start = false;
        let mut do_h_stop = false;
        let mut open_app_picker = false;

        ui.label(self.t("SOCKS5 代理", "SOCKS5 proxy"));
        ui.horizontal(|ui| {
            ui.label(ip_label);
            ui.add(egui::TextEdit::singleline(&mut sip).id_salt("socks-ip").desired_width(150.0).min_size(egui::vec2(150.0, 0.0)).hint_text("127.0.0.1"));
            ui.label(port_label);
            ui.add(egui::DragValue::new(&mut port).range(1..=u16::MAX).speed(1.0));
        });
        ui.horizontal(|ui| {
            if socks_on {
                if ui.button(stop_label).clicked() {
                    do_s_stop = true;
                }
                ui.colored_label(egui::Color32::from_rgb(150, 190, 230), format!("● SOCKS5 {sip}:{port}"));
            } else if ui.button(start_label).clicked() {
                do_s_start = true;
            }
        });
        ui.separator();

        ui.label(self.t("HTTP 代理", "HTTP proxy"));
        ui.horizontal(|ui| {
            ui.label(ip_label);
            ui.add(egui::TextEdit::singleline(&mut hip).id_salt("http-ip").desired_width(150.0).min_size(egui::vec2(150.0, 0.0)).hint_text("127.0.0.1"));
            ui.label(port_label);
            ui.add(egui::DragValue::new(&mut hport).range(1..=u16::MAX).speed(1.0));
        });
        ui.horizontal(|ui| {
            if http_on {
                if ui.button(stop_label).clicked() {
                    do_h_stop = true;
                }
                ui.colored_label(egui::Color32::from_rgb(150, 210, 170), format!("● HTTP {hip}:{hport}"));
            } else if ui.button(start_label).clicked() {
                do_h_start = true;
            }
        });
        ui.separator();

        ui.horizontal(|ui| {
            ui.label(app_label);
            ui.add(
                egui::TextEdit::singleline(&mut app)
                    .id_salt("serve-app")
                    .desired_width(220.0)
                    .min_size(egui::vec2(220.0, 0.0))
                    .hint_text(self.t("留空 = 匹配全部", "empty = match all")),
            );
            if ui.button("…").on_hover_text(self.t("从运行中的程序选择", "Pick from running apps")).clicked() {
                open_app_picker = true;
            }
        });

        self.serve_port = port;
        self.socks_ip = sip;
        self.http_port = hport;
        self.http_ip = hip;
        self.serve_app = app.clone();
        if open_app_picker {
            self.app_picker_mode = PickerMode::FixedApp;
            self.app_picker_query.clear();
            self.dlg_app_picker = true;
        }
        if do_s_start {
            self.socks_start();
        }
        if do_s_stop {
            self.socks_stop();
        }
        if do_h_start {
            self.http_start();
        }
        if do_h_stop {
            self.http_stop();
        }
    }

    fn show_log_body(&mut self, ui: &mut egui::Ui) {
        let heading = self.t("实时日志", "Live log");
        let clear_label = self.t("清空", "Clear");
        let empty_label = self.t("暂无日志。", "No log entries.");
        let mut do_clear = false;
        ui.horizontal(|ui| {
            ui.heading(heading);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(clear_label).clicked() {
                    do_clear = true;
                }
            });
        });
        if do_clear {
            self.log_view.clear();
            self.log_all.clear();
        }
        // Filter row. `显示直连` is OFF by default, which is what makes the panel
        // readable: almost every line the engine writes is a bypassed loopback or
        // name-resolution flow, and the operator is looking for what went through a
        // proxy. Non-flow lines (startup, WFP notes, warnings) are never filtered
        // out - see log_filter_matches.
        let proto_all = self.t("全部", "All");
        let lbl_proto = self.t("协议", "Proto");
        let hint_dest = self.t("目的 IP / 主机", "dest ip / host");
        let hint_port = self.t("端口", "port");
        let lbl_direct = self.t("显示直连", "Show direct");
        {
            let mut f = self.log_filter.clone();
            ui.horizontal(|ui| {
                ui.label(lbl_proto);
                let mut pick: u8 = match f.proto.as_str() {
                    "TCP" => 1,
                    "UDP" => 2,
                    _ => 0,
                };
                egui::ComboBox::from_id_salt("log-proto-filter")
                    .selected_text(match pick {
                        1 => "TCP",
                        2 => "UDP",
_ => proto_all,
                    })
                    .show_ui(ui, |ui| {
ui.selectable_value(&mut pick, 0, proto_all);
                        ui.selectable_value(&mut pick, 1, "TCP");
                        ui.selectable_value(&mut pick, 2, "UDP");
                    });
f.proto = match pick { 1 => "TCP", 2 => "UDP", _ => "" }.to_string();
                ui.add(
                    egui::TextEdit::singleline(&mut f.dest)
                        .hint_text(hint_dest)
                        .desired_width(130.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut f.port)
                        .hint_text(hint_port)
                        .desired_width(56.0),
                );
                ui.checkbox(&mut f.show_direct, lbl_direct);
            });
            self.log_filter = f;
        }

        if self.log_view.is_empty() {
            let filtered_out = !self.log_all.is_empty();
            ui.label(if filtered_out {
                self.t("没有符合过滤条件的日志", "No entries match the filter.")
            } else {
                empty_label
            });
            return;
        }
        // Virtualized: lay out only the rows in view, not all up-to-1500 lines
        // every frame — this is what stopped the UI getting sluggish over time.
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
        let total = self.log_view.len();
        egui::ScrollArea::vertical()
            .id_salt("log-scroll")
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show_rows(ui, row_h, total, |ui, visible| {
                for idx in visible {
                    if let Some(line) = self.log_view.get(idx) {
                        let color = match line.level {
                            "warn" => egui::Color32::from_rgb(235, 160, 90),
                            "error" => egui::Color32::from_rgb(235, 110, 90),
                            _ => egui::Color32::from_rgb(190, 200, 210),
                        };
                        ui.add(
                            egui::Label::new(egui::RichText::new(format!(
                                "{} [{}] {}",
                                line.time, line.level, line.message
                            ))
                            .color(color))
                            .selectable(true),
                        );
                    }
                }
            });
    }
}

impl GuiApp {
    /// Reflect live engine state into the tray, spawn the tray when enabled, and
    /// drain user-picked commands. No-op on non-Windows (no tray).
    #[cfg(windows)]
    fn handle_tray(&mut self, ctx: &egui::Context) {
        use crate::tray::{self, TrayCmd, TrayState};
        if let Ok(mut st) = self.tray_state.write() {
            *st = TrayState {
                engine_running: self.serve.is_some(),
                serving: self.socks.is_some() || self.http_proxy.is_some(),
                consent_granted: self.hook_consent,
            };
        }
        if self.config.settings.start_in_tray && self.tray_rx.is_none() {
            let lang = if matches!(self.config.settings.language, crate::config::Language::Zh) {
                tray::Lang::Zh
            } else {
                tray::Lang::En
            };
            let (tray, rx) = tray::Tray::spawn(self.tray_state.clone(), lang);
            self._tray = Some(tray);
            self.tray_rx = Some(rx);
        }
        if let Some(rx) = self.tray_rx.take() {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    TrayCmd::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    TrayCmd::OpenSettings => ctx.request_repaint(),
                    TrayCmd::ToggleEngine => {
                        if self.serve.is_some() {
                            self.serve_stop();
                        } else {
                            self.serve_start();
                        }
                    }
                }
            }
            self.tray_rx = Some(rx);
        }
    }

    #[cfg(not(windows))]
    fn handle_tray(&mut self, _ctx: &egui::Context) {}

    /// fnd_13 "Check for Product Updates on Startup". Pure decision via
    /// [`crate::update`]; the fetch is intentionally not performed (no update
    /// server exists for a clean-room build), so `latest` is None and the honest
    /// result is "not configured" unless a source is wired in later.
    fn check_for_updates(&mut self, manual: bool) {
        use crate::config::Language;
        let cur = env!("CARGO_PKG_VERSION");
        let outcome = crate::update::check(cur, self.config.settings.check_updates, None);
        let zh = matches!(self.config.settings.language, Language::Zh);
        let msg = match &outcome {
            crate::update::UpdateOutcome::Available { latest } => {
                if zh { format!("发现新版本 {latest}") } else { format!("New version {latest} available") }
            }
            crate::update::UpdateOutcome::UpToDate => {
                if zh { "已是最新版本。".to_string() } else { "Already up to date.".to_string() }
            }
            crate::update::UpdateOutcome::Disabled => {
                if zh { "更新检查已关闭或未配置更新源。".to_string() }
                else { "Update check disabled or no update source configured.".to_string() }
            }
        };
        let prefix = if manual { "检查更新：" } else { "" };
        self.log("info", format!("{prefix}{msg}"));
        if manual {
            self.status = msg;
        }
    }
}

impl App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_check();
        self.poll_monitor();
        let ctx = ui.ctx();
        apply_ui_scale(ctx, self.config.settings.ui_scale_pct);
        let want_title = format!("trans-proxier — {}", self.config.settings.name);
        if want_title != self.last_window_title {
            self.last_window_title = want_title.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(want_title));
        }
        // Persist the "同意全局钩子" consent into the config (saved with the profile).
        self.config.settings.hook_consent = self.hook_consent;
        self.handle_tray(ctx);
        // fnd_13 startup update check (honours Settings.check_updates; runs once).
        if self.config.settings.check_updates && !self.update_checked {
            self.update_checked = true;
            self.check_for_updates(false);
        }
        self.show_toolbar(ui);
        self.show_menubar(ui);
        self.show_tabbar(ui);
        self.show_validation(ui);
        self.show_statusbar(ui);
        self.show_central(ui);

        // Apply a profile switch requested from 选项 (after the settings writeback
        // so the loaded profile isn't overwritten by the previous frame's locals).
        if let Some(n) = self.pending_switch.take() {
            self.apply_profile_load(&n);
        }

        // Modal-style editor dialogs (the original opens these from the menus).
        let ctx = ui.ctx();
        self.show_dialogs(ctx);

        // Keep the status bar rates + live connection list ticking.
        ctx.request_repaint_after(Duration::from_millis(400));
    }

    fn on_exit(&mut self) {
        self.serve_stop();
        self.socks_stop();
        self.http_stop();
    }
}
