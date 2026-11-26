use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Local,
    Proxy,
    Auto,
}
impl DnsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsMode::Local => "local",
            DnsMode::Proxy => "proxy",
            DnsMode::Auto => "auto",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "local" => Some(DnsMode::Local),
            "proxy" => Some(DnsMode::Proxy),
            "auto" => Some(DnsMode::Auto),
            _ => None,
        }
    }
}

/// Transport for the optional custom DNS resolver (DoH deferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsProto {
    #[default]
    Udp,
    Tcp,
}
impl DnsProto {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsProto::Udp => "udp",
            DnsProto::Tcp => "tcp",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(DnsProto::Udp),
            "tcp" => Some(DnsProto::Tcp),
            _ => None,
        }
    }
}

/// One DNS resolver entry: its own transport, address, and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServer {
    pub protocol: DnsProto,
    pub server: String,
    pub port: u16,
}

impl Default for DnsServer {
    fn default() -> Self {
        DnsServer { protocol: DnsProto::Udp, server: String::new(), port: 53 }
    }
}

/// Optional user-configured DNS resolver CHAIN, tried in order (first answer
/// wins). Defaults to Cloudflare + Google over UDP:53. When the chain is
/// non-empty and ALL resolvers fail, resolution fails (no OS leak); see
/// `net_dns::resolve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSettings {
    pub servers: Vec<DnsServer>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        DnsSettings {
            servers: vec![
                DnsServer { protocol: DnsProto::Udp, server: "1.1.1.1".into(), port: 53 },
                DnsServer { protocol: DnsProto::Udp, server: "8.8.8.8".into(), port: 53 },
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Https,
    Socks4,
    Socks5,
}
impl ProxyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Https => "https",
            ProxyKind::Socks4 => "socks4",
            ProxyKind::Socks5 => "socks5",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "http" | "http-proxy" => Some(ProxyKind::Http),
            "https" => Some(ProxyKind::Https),
            "socks4" => Some(ProxyKind::Socks4),
            "socks5" => Some(ProxyKind::Socks5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyServer {
    pub id: u32,
    pub name: String,
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub id: u32,
    pub name: String,
    pub proxies: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Proxy { chain: u32 },
    Direct,
    /// Hard-block the connection at the engine (the original's "Block"): the app's
    /// socket is refused, so nothing leaks direct and nothing is proxified.
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleProtocol {
    Tcp,
    Udp,
    #[default]
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub app: Option<String>,
    pub host: Option<String>,
    /// Port spec: exact, comma/whitespace-separated list, `a-b` range, or `*`.
    /// None / empty means unconstrained.
    pub port: Option<String>,
    pub protocol: RuleProtocol,
    pub action: RuleAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Zh,
    En,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::Zh => "zh",
            Language::En => "en",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "zh" | "zh-cn" | "zh_cn" | "chinese" => Some(Language::Zh),
            "en" | "en-us" | "en_us" | "english" => Some(Language::En),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Language::Zh => "中文",
            Language::En => "English",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub language: Language,
    pub app_whitelist_enabled: bool,
    pub app_whitelist: Vec<String>,
    pub name: String,
    pub dns_mode: DnsMode,
    pub ip_leak_prevention: bool,
    pub proxy_exclusion_list: Vec<String>,
    pub proxy_inclusion_list: Vec<String>,
    // Proxy-server ids the user deactivated (the original: toggle a server off
    // without deleting it). Chains/egress treat these as unavailable.
    pub disabled_proxies: Vec<u32>,
    // Options-dialog settings persisted under the original's observed key names.
    pub check_updates: bool,               // UpdateCheck
    pub redundancy_recheck_secs: u64,      // RedundancyRecheckTime
    pub block_udp_if_matched: bool,        // Block Traffic to All UDP Ports if Matched the Rule
    pub dns_no_resolve: Vec<String>,       // "Do NOT resolve the following" name list
    // IP-leak prevention (fnd_10): when `ip_leak_prevention` is on and this is a
    // non-zero chain id, a WHITELISTED app whose connection matches NO rule is
    // sent through this chain instead of leaking a direct connection. 0 = off.
    pub ip_leak_default_chain: u32,
    // Start minimised to the notification-area (system tray) icon (fnd_13 tray).
    pub start_in_tray: bool,
    /// Start the transparent engine by itself once the app is up. The logon entry
    /// (`autostart install`) is only half of "starts automatically": without this the
    /// program sits in the tray doing nothing until a human presses 启动.
    pub start_engine_on_launch: bool,
    /// Which address family the PROXY chain can reach, hence which DNS answers we may
    /// withhold from apps: "ipv4" drops AAAA, "ipv6" drops A, "dual"
    /// (the default) drops nothing.
    ///
    /// Deliberately opt-in. The local routing table is NOT evidence: a proxy listening
    /// on 127.0.0.1 forwards to remote nodes whose egress we cannot see, and an app
    /// socket dialled to an IPv6 literal is connected by the PROXY (SOCKS5 ATYP 4 over
    /// a v4 loopback hop). Trimming on a guess would turn IPv6-only origins into
    /// "unreachable", which costs more than the failed attempt it saves.
    pub egress_family: String,
    // Global proxification switch (the original's "Pause / No Proxification"): when
    // false every connection bypasses the proxy and goes direct, regardless of rules.
    pub proxification_enabled: bool,
    // Remembered "I consent to install a global hook" (user asked it persist across
    // restarts). Safety gate: engine still refuses to start until it is ticked.
    pub hook_consent: bool,
    // Optional custom DNS resolver (UDP/TCP); empty server ⇒ OS resolver.
    pub dns: DnsSettings,
    // Name of the profile that was last switched to; auto-loaded at startup.
    pub active_profile: String,
    // UI font size as a percentage of the 14pt base (integer to keep Settings: Eq).
    pub ui_scale_pct: u32,
    // Tab keys the user hid (e.g. ["check","route"]); empty shows all tabs.
    pub hidden_tabs: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            language: Language::Zh,
            app_whitelist_enabled: false,
            app_whitelist: Vec::new(),
            name: "Default Profile".into(),
            dns_mode: DnsMode::Local,
            ip_leak_prevention: true,
            proxy_exclusion_list: vec!["localhost".into(), "127.0.0.1".into(), "::1".into()],
            proxy_inclusion_list: Vec::new(),
            disabled_proxies: Vec::new(),
            check_updates: true,
            redundancy_recheck_secs: 60,
            block_udp_if_matched: false,
            dns_no_resolve: vec!["localhost".into()],
            ip_leak_default_chain: 0,
            start_in_tray: false,
            start_engine_on_launch: false,
            egress_family: "dual".to_string(),
            proxification_enabled: true,
            hook_consent: false,
            dns: DnsSettings::default(),
            active_profile: String::new(),
            ui_scale_pct: 100,
            hidden_tabs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub settings: Settings,
    pub proxies: Vec<ProxyServer>,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub message: String,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ConfigError {}

fn get_section_header(s: &str) -> Option<(&str, &str)> {
    let trimmed = s.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return None;
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let dot = inner.find('.');
    match dot {
        None => Some((inner, "")),
        Some(i) => Some((&inner[..i], &inner[i + 1..])),
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn parse_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().trim_matches('"').to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn unquote(s: &str) -> &str {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        &t[1..t.len() - 1]
    } else {
        t
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot load profile from {}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg = Config::default();
        // DNS resolvers are file-owned: a config without `[dns.N]` means "none
        // configured" (→ prompt), not the fresh-default seed. `Config::default()`
        // (new profile) still seeds 1.1.1.1 / 8.8.8.8.
        cfg.settings.dns.servers.clear();
        let mut section: Option<(String, String)> = None; // (kind, id)
        // Legacy flat keys (pre-[dns.N]) collected here and migrated after parsing.
        let mut legacy_primary = DnsServer::default();
        let mut legacy_backup = DnsServer::default();

        for (lineno, raw_line) in text.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') {
                let (kind, id) = get_section_header(line)
                    .ok_or_else(|| format!("line {}: invalid section header '{line}'", lineno + 1))?;
                section = Some((kind.to_string(), id.to_string()));
                continue;
            }
            let (kind, id) = section
                .clone()
                .ok_or_else(|| format!("line {}: key/value outside of any section", lineno + 1))?;
            let eq = line
                .find('=')
                .ok_or_else(|| format!("line {}: expected 'key = value', got '{line}'", lineno + 1))?;
            let key = line[..eq].trim().to_ascii_lowercase();
            let value = line[eq + 1..].trim().to_string();

            match kind.as_str() {
                "settings" => {
                    match key.as_str() {
                        "name" => cfg.settings.name = unquote(&value).to_string(),
                        "active_profile" => cfg.settings.active_profile = unquote(&value).to_string(),
                        "dns_mode" => {
                            cfg.settings.dns_mode = DnsMode::parse(unquote(&value))
                                .ok_or_else(|| format!("line {}: unknown dns_mode '{value}'", lineno + 1))?;
                        }
                        // Legacy flat DNS keys → migrate into the resolver list below.
                        "dns_protocol" => {
                            if let Some(p) = DnsProto::parse(unquote(&value)) {
                                legacy_primary.protocol = p;
                            }
                        }
                        "dns_server" => legacy_primary.server = unquote(&value).trim().to_string(),
                        "dns_port" => legacy_primary.port = unquote(&value).parse().unwrap_or(53),
                        "dns_fallback_protocol" => {
                            if let Some(p) = DnsProto::parse(unquote(&value)) {
                                legacy_backup.protocol = p;
                            }
                        }
                        "dns_fallback_server" => legacy_backup.server = unquote(&value).trim().to_string(),
                        "dns_fallback_port" => legacy_backup.port = unquote(&value).parse().unwrap_or(53),
                        "ip_leak_prevention" => {
                            cfg.settings.ip_leak_prevention = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "proxy_exclusion_list" => {
                            cfg.settings.proxy_exclusion_list = parse_list(&value);
                        }
                        "proxy_inclusion_list" => {
                            cfg.settings.proxy_inclusion_list = parse_list(&value);
                        }
                        "disabled_proxies" => {
                            let mut ids = Vec::new();
                            for t in parse_list(&value) {
                                ids.push(
                                    t.trim()
                                        .parse::<u32>()
                                        .map_err(|_| format!("line {}: invalid proxy id '{t}'", lineno + 1))?,
                                );
                            }
                            cfg.settings.disabled_proxies = ids;
                        }
                        "language" => {
                            cfg.settings.language = Language::parse(unquote(&value))
                                .ok_or_else(|| format!("line {}: unknown language '{value}'", lineno + 1))?;
                        }
                        "app_whitelist_enabled" => {
                            cfg.settings.app_whitelist_enabled = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "app_whitelist" => {
                            cfg.settings.app_whitelist = parse_list(&value);
                        }
                        "updatecheck" | "check_updates" => {
                            cfg.settings.check_updates = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "redundancyrechecktime" | "redundancy_recheck_secs" => {
                            cfg.settings.redundancy_recheck_secs = unquote(&value).parse::<u64>()
                                .map_err(|_| format!("line {}: invalid number '{value}'", lineno + 1))?;
                        }
                        "blockudp" | "block_udp" | "block_udp_if_matched" => {
                            cfg.settings.block_udp_if_matched = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "dns_no_resolve" => {
                            cfg.settings.dns_no_resolve = parse_list(&value);
                        }
                        "ip_leak_default_chain" => {
                            cfg.settings.ip_leak_default_chain = unquote(&value).parse::<u32>()
                                .map_err(|_| format!("line {}: invalid number '{value}'", lineno + 1))?;
                        }
                        "egress_family" => {
                            // deliberately lenient: an unknown word means "auto", never a
                            // rejected profile — a typo in a settings file must not make the app
                            // unreadable
                            cfg.settings.egress_family = unquote(&value).trim().to_ascii_lowercase();
                        }
                        "start_engine_on_launch" => {
                            cfg.settings.start_engine_on_launch = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "start_in_tray" => {
                            cfg.settings.start_in_tray = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "proxification_enabled" | "proxy_enabled" => {
                            cfg.settings.proxification_enabled = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "hook_consent" => {
                            cfg.settings.hook_consent = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "paused" => {
                            cfg.settings.proxification_enabled = !parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "ui_scale_pct" | "ui_scale" => {
                            let pct = unquote(&value).parse::<u32>()
                                .map_err(|_| format!("line {}: invalid ui scale '{value}'", lineno + 1))?;
                            cfg.settings.ui_scale_pct = pct.clamp(50, 300);
                        }
                        "hidden_tabs" => {
                            cfg.settings.hidden_tabs = parse_list(&value);
                        }
                        _ => {
                            return Err(format!("line {}: unknown settings key '{key}'", lineno + 1));
                        }
                    }
                }
                "proxy" => {
                    let target = ensure_proxy(&mut cfg, &id, lineno)?;
                    match key.as_str() {
                        "name" => target.name = unquote(&value).to_string(),
                        "type" => {
                            target.kind = ProxyKind::parse(unquote(&value))
                                .ok_or_else(|| format!("line {}: unknown proxy type '{value}'", lineno + 1))?;
                        }
                        "host" => target.host = unquote(&value).to_string(),
                        "port" => {
                            target.port = unquote(&value)
                                .parse::<u16>()
                                .map_err(|_| format!("line {}: invalid port '{value}'", lineno + 1))?;
                        }
                        "username" => target.username = some_or_none(&value),
                        "password" => target.password = some_or_none(&value),
                        "timeout" => {
                            target.timeout_secs = unquote(&value)
                                .parse::<u64>()
                                .map_err(|_| format!("line {}: invalid timeout '{value}'", lineno + 1))?;
                        }
                        _ => return Err(format!("line {}: unknown proxy key '{key}'", lineno + 1)),
                    }
                }
                "dns" => {
                    let target = ensure_dns(&mut cfg, &id, lineno)?;
                    match key.as_str() {
                        "protocol" => {
                            target.protocol = DnsProto::parse(unquote(&value))
                                .ok_or_else(|| format!("line {}: unknown dns protocol '{value}' (udp|tcp)", lineno + 1))?;
                        }
                        "server" => target.server = unquote(&value).trim().to_string(),
                        "port" => {
                            target.port = unquote(&value).parse::<u16>()
                                .map_err(|_| format!("line {}: invalid dns port '{value}'", lineno + 1))?;
                        }
                        _ => return Err(format!("line {}: unknown dns key '{key}'", lineno + 1)),
                    }
                }
                "chain" => {
                    let target = ensure_chain(&mut cfg, &id, lineno)?;
                    match key.as_str() {
                        "name" => target.name = unquote(&value).to_string(),
                        "proxies" => {
                            let mut ids = Vec::new();
                            for part in parse_list(&value) {
                                ids.push(
                                    part.parse::<u32>()
                                        .map_err(|_| format!("line {}: invalid chain id '{part}'", lineno + 1))?,
                                );
                            }
                            target.proxies = ids;
                        }
                        _ => return Err(format!("line {}: unknown chain key '{key}'", lineno + 1)),
                    }
                }
                "rule" => {
                    let target = ensure_rule(&mut cfg, &id, lineno)?;
                    match key.as_str() {
                        "name" => target.name = unquote(&value).to_string(),
                        "enabled" => {
                            target.enabled = parse_bool(unquote(&value))
                                .ok_or_else(|| format!("line {}: invalid boolean '{value}'", lineno + 1))?;
                        }
                        "priority" => {
                            target.priority = unquote(&value)
                                .parse::<i32>()
                                .map_err(|_| format!("line {}: invalid priority '{value}'", lineno + 1))?;
                        }
                        "app" => target.app = some_or_none(&value),
                        "host" => target.host = some_or_none(&value),
                        "port" => {
                            let raw = unquote(&value).trim().to_string();
                            let toks: Vec<&str> = raw
                                .split([',', ';', ' ', '\t'])
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .collect();
                            for t in &toks {
                                let ok = *t == "*"
                                    || *t == "any"
                                    || t.parse::<u16>().is_ok()
                                    || t.split_once('-')
                                        .map_or(false, |(a, b)| a.trim().parse::<u16>().is_ok() && b.trim().parse::<u16>().is_ok());
                                if !ok {
                                    return Err(format!("line {}: invalid port spec '{t}'", lineno + 1));
                                }
                            }
                            target.port = if toks.is_empty() { None } else { Some(toks.join(",")) };
                        }
                        "protocol" => {
                            let v = unquote(&value).to_ascii_lowercase();
                            target.protocol = match v.as_str() {
                                "tcp" => RuleProtocol::Tcp,
                                "udp" => RuleProtocol::Udp,
                                "both" | "tcp+udp" | "tcp and udp" => RuleProtocol::Both,
                                _ => {
                                    return Err(format!("line {}: unknown protocol '{value}'", lineno + 1));
                                }
                            };
                        }
                        "action" => {
                            let v = unquote(&value).to_ascii_lowercase();
                            match v.as_str() {
                                "direct" => target.action = RuleAction::Direct,
                                "proxy" => target.action = RuleAction::Proxy { chain: 0 }, // chain filled in below
                                "block" | "deny" => target.action = RuleAction::Block,
                                _ => return Err(format!("line {}: unknown action '{value}'", lineno + 1)),
                            }
                        }
                        "chain" => match &mut target.action {
                            RuleAction::Proxy { chain } => {
                                *chain = unquote(&value).parse::<u32>().map_err(|_| {
                                    format!("line {}: invalid chain id '{value}'", lineno + 1)
                                })?;
                            }
                            RuleAction::Direct | RuleAction::Block => {
                                return Err(format!(
                                    "line {}: 'chain' key requires action=proxy",
                                    lineno + 1
                                ));
                            }
                        },
                        _ => return Err(format!("line {}: unknown rule key '{key}'", lineno + 1)),
                    }
                }
                other => {
                    return Err(format!("line {}: unknown section '[{}]'", lineno + 1, other));
                }
            }
        }
        // Migrate legacy flat DNS entries into the ordered list if present and no
        // [dns.N] sections were supplied.
        if cfg.settings.dns.servers.is_empty() {
            if !legacy_primary.server.is_empty() {
                cfg.settings.dns.servers.push(legacy_primary);
            }
            if !legacy_backup.server.is_empty() {
                cfg.settings.dns.servers.push(legacy_backup);
            }
        }
        Ok(cfg)
    }

    pub fn validate(&self) -> Vec<ConfigError> {
        let mut errors = Vec::new();
        // IP-leak safety chain must actually exist when the feature is armed.
        if self.settings.ip_leak_prevention && self.settings.ip_leak_default_chain != 0
            && !self.chains.iter().any(|c| c.id == self.settings.ip_leak_default_chain)
        {
            errors.push(ConfigError {
                message: format!(
                    "IP-leak prevention safety chain (id = {}) does not exist",
                    self.settings.ip_leak_default_chain
                ),
            });
        }
        // Prompt to configure DNS when the chain is empty (default seeds 1.1.1.1 +
        // 8.8.8.8, so this only fires if the user clears every entry).
        if self.settings.dns.servers.iter().all(|s| s.server.trim().is_empty()) {
            errors.push(ConfigError {
                message: "未配置 DNS 解析器：请在 选项→DNS 添加（建议 1.1.1.1 / 8.8.8.8 UDP:53）".to_string(),
            });
        }
        let mut proxy_ids: Vec<u32> = Vec::new();
        for p in &self.proxies {
            if proxy_ids.contains(&p.id) {
                errors.push(ConfigError {
                    message: format!("Duplicated IDs found. Two or more proxy servers have id = {}", p.id),
                });
            }
            proxy_ids.push(p.id);
        }
        let mut chain_ids: Vec<u32> = Vec::new();
        for c in &self.chains {
            if chain_ids.contains(&c.id) {
                errors.push(ConfigError {
                    message: format!("Duplicated IDs found. Two or more proxy chains have id = {}", c.id),
                });
            }
            chain_ids.push(c.id);

            let has_proxy = |id: u32| self.proxies.iter().any(|p| p.id == id);
            for &pid in &c.proxies {
                if !has_proxy(pid) {
                    errors.push(ConfigError {
                        message: format!("Chain \"{}\" refers to nonexistent proxy (id = {})", c.name, pid),
                    });
                }
            }
            // NOTE: we deliberately do NOT replicate the original's own
            // "HTTP proxy server must be the last one in the chain." rule
            // (fnd_10). That restriction is a limit of the original's TCP-only
            // chaining; our engine tunnels any protocol through any hop, so
            // chains like [http, http] work (verified by an integration test)
            // and enforcing HTTP-last would be a capability REGRESSION, not
            // fidelity. UDP is validated at connect time against the chain's
            // egress (must be SOCKS5 for UDP), so game traffic still works.
        }
        for p in &self.proxies {
            if p.host.is_empty() {
                errors.push(ConfigError {
                    message: format!("Proxy \"{}\" (id = {}) has no host", p.name, p.id),
                });
            }
        }
        for r in &self.rules {
            match &r.action {
                RuleAction::Proxy { chain } => {
                    let c = self.chains.iter().find(|c| c.id == *chain);
                    if c.is_none() {
                        errors.push(ConfigError {
                            message: format!(
                                "Rule \"{}\" refers to nonexistent proxy chain (id = {})",
                                r.name, chain
                            ),
                        });
                    } else if c.unwrap().proxies.is_empty() {
                        errors.push(ConfigError {
                            message: format!("Chain \"{}\" is empty", c.unwrap().name),
                        });
                    }
                }
                RuleAction::Direct | RuleAction::Block => {}
            }
            if r.name.is_empty() {
                errors.push(ConfigError {
                    message: format!("Rule (id = {}) has no name", r.id),
                });
            }
        }
        errors
    }

    pub fn chain_by_id(&self, id: u32) -> Option<&Chain> {
        self.chains.iter().find(|c| c.id == id)
    }

    pub fn proxy_by_id(&self, id: u32) -> Option<&ProxyServer> {
        self.proxies.iter().find(|p| p.id == id)
    }

    /// A proxy is AVAILABLE only if it exists and is not deactivated
    /// (`settings.disabled_proxies`). Chains/egress use this so a switched-off
    /// server is skipped, but listing/UI still reaches it via `proxy_by_id`.
    pub fn proxy_available(&self, id: u32) -> Option<&ProxyServer> {
        if self.settings.disabled_proxies.contains(&id) {
            None
        } else {
            self.proxy_by_id(id)
        }
    }
}

fn some_or_none(value: &str) -> Option<String> {
    let v = unquote(value).trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

fn ensure_proxy<'a>(cfg: &'a mut Config, id: &str, lineno: usize) -> Result<&'a mut ProxyServer, String> {
    let pid = id
        .parse::<u32>()
        .map_err(|_| format!("line {}: invalid proxy id '{id}'", lineno + 1))?;
    if !cfg.proxies.iter().any(|p| p.id == pid) {
        cfg.proxies.push(ProxyServer {
            id: pid,
            name: format!("proxy-{}", pid),
            kind: ProxyKind::Http,
            host: String::new(),
            port: 0,
            username: None,
            password: None,
            timeout_secs: 10,
        });
    }
    let pos = cfg.proxies.iter().position(|p| p.id == pid).unwrap();
    Ok(&mut cfg.proxies[pos])
}

fn ensure_chain<'a>(cfg: &'a mut Config, id: &str, lineno: usize) -> Result<&'a mut Chain, String> {
    let cid = id
        .parse::<u32>()
        .map_err(|_| format!("line {}: invalid chain id '{id}'", lineno + 1))?;
    if !cfg.chains.iter().any(|c| c.id == cid) {
        cfg.chains.push(Chain { id: cid, name: format!("chain-{}", cid), proxies: Vec::new() });
    }
    let pos = cfg.chains.iter().position(|c| c.id == cid).unwrap();
    Ok(&mut cfg.chains[pos])
}

fn ensure_dns<'a>(cfg: &'a mut Config, id: &str, lineno: usize) -> Result<&'a mut DnsServer, String> {
    let did = id
        .parse::<u32>()
        .map_err(|_| format!("line {}: invalid dns id '{id}'", lineno + 1))? as usize;
    if did == 0 {
        return Err(format!("line {}: dns id must be >= 1", lineno + 1));
    }
    while cfg.settings.dns.servers.len() < did {
        cfg.settings.dns.servers.push(DnsServer::default());
    }
    Ok(&mut cfg.settings.dns.servers[did - 1])
}

fn ensure_rule<'a>(cfg: &'a mut Config, id: &str, lineno: usize) -> Result<&'a mut Rule, String> {
    let rid = id
        .parse::<u32>()
        .map_err(|_| format!("line {}: invalid rule id '{id}'", lineno + 1))?;
    if !cfg.rules.iter().any(|r| r.id == rid) {
        cfg.rules.push(Rule {
            id: rid,
            name: format!("rule-{}", rid),
            enabled: true,
            priority: 0,
            app: None,
            host: None,
            port: None,
            protocol: RuleProtocol::default(),
            action: RuleAction::Direct,
        });
    }
    let pos = cfg.rules.iter().position(|r| r.id == rid).unwrap();
    Ok(&mut cfg.rules[pos])
}

impl Config {
    pub fn write(&self, path: &Path) -> Result<(), String> {
        let text = self.serialize();
        std::fs::write(path, text).map_err(|e| format!("Cannot write profile to {}: {e}", path.display()))
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        out.push_str("# Settings.ini — trans-proxier config (clean room)\n");
        out.push_str("[settings]\n");
        out.push_str(&format!("name = \"{}\"\n", self.settings.name));
        if !self.settings.active_profile.is_empty() {
            out.push_str(&format!("active_profile = \"{}\"\n", self.settings.active_profile));
        }
        out.push_str(&format!("dns_mode = {}\n", self.settings.dns_mode.as_str()));
        out.push_str(&format!("ip_leak_prevention = {}\n", self.settings.ip_leak_prevention));
        out.push_str(&format!("ip_leak_default_chain = {}\n", self.settings.ip_leak_default_chain));
        out.push_str(&format!("start_in_tray = {}\n", self.settings.start_in_tray));
        out.push_str(&format!("start_engine_on_launch = {}\n", self.settings.start_engine_on_launch));
        out.push_str(&format!("egress_family = \"{}\"\n", self.settings.egress_family));
        out.push_str(&format!(
            "proxification_enabled = {}\n",
            self.settings.proxification_enabled
        ));
        if self.settings.hook_consent {
            out.push_str("hook_consent = true\n");
        }
        out.push_str(&format!("ui_scale_pct = {}\n", self.settings.ui_scale_pct));
        if !self.settings.hidden_tabs.is_empty() {
            out.push_str(&format!("hidden_tabs = {}\n", self.settings.hidden_tabs.join(",")));
        }
        out.push_str(&format!(
            "proxy_exclusion_list = {}\n",
            self.settings.proxy_exclusion_list.join(",")
        ));
        out.push_str(&format!(
            "proxy_inclusion_list = {}\n",
            self.settings.proxy_inclusion_list.join(",")
        ));
        if !self.settings.disabled_proxies.is_empty() {
            out.push_str(&format!(
                "disabled_proxies = {}\n",
                self.settings.disabled_proxies
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        out.push_str(&format!("language = {}\n", self.settings.language.as_str()));
        out.push_str(&format!("app_whitelist_enabled = {}\n", self.settings.app_whitelist_enabled));
        out.push_str(&format!("app_whitelist = {}\n", self.settings.app_whitelist.join(",")));
        out.push_str(&format!("updatecheck = {}\n", self.settings.check_updates));
        out.push_str(&format!("redundancy_recheck_secs = {}\n", self.settings.redundancy_recheck_secs));
        out.push_str(&format!("block_udp = {}\n", self.settings.block_udp_if_matched));
        out.push_str(&format!("dns_no_resolve = {}\n", self.settings.dns_no_resolve.join(",")));
        for p in &self.proxies {
            out.push_str(&format!("\n[proxy.{}]\n", p.id));
            out.push_str(&format!("name = \"{}\"\n", p.name));
            out.push_str(&format!("type = {}\n", p.kind.as_str()));
            out.push_str(&format!("host = \"{}\"\n", p.host));
            out.push_str(&format!("port = {}\n", p.port));
            if let Some(u) = &p.username {
                out.push_str(&format!("username = \"{}\"\n", u));
            }
            if let Some(pw) = &p.password {
                out.push_str(&format!("password = \"{}\"\n", pw));
            }
            out.push_str(&format!("timeout = {}\n", p.timeout_secs));
        }
        for c in &self.chains {
            out.push_str(&format!("\n[chain.{}]\n", c.id));
            out.push_str(&format!("name = \"{}\"\n", c.name));
            out.push_str(&format!(
                "proxies = {}\n",
                c.proxies.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")
            ));
        }
        for (i, d) in self.settings.dns.servers.iter().enumerate() {
            if d.server.trim().is_empty() {
                continue;
            }
            out.push_str(&format!("\n[dns.{}]\n", i + 1));
            out.push_str(&format!("protocol = {}\n", d.protocol.as_str()));
            out.push_str(&format!("server = \"{}\"\n", d.server.trim()));
            out.push_str(&format!("port = {}\n", d.port));
        }
        for r in &self.rules {
            out.push_str(&format!("\n[rule.{}]\n", r.id));
            out.push_str(&format!("name = \"{}\"\n", r.name));
            out.push_str(&format!("enabled = {}\n", r.enabled));
            out.push_str(&format!("priority = {}\n", r.priority));
            if let Some(app) = &r.app {
                out.push_str(&format!("app = \"{}\"\n", app));
            }
            if let Some(h) = &r.host {
                out.push_str(&format!("host = \"{}\"\n", h));
            }
            if let Some(port) = &r.port {
                out.push_str(&format!("port = \"{port}\"\n"));
            }
            if r.protocol != RuleProtocol::Both {
                out.push_str(&format!(
                    "protocol = {}\n",
                    match r.protocol {
                        RuleProtocol::Tcp => "tcp",
                        RuleProtocol::Udp => "udp",
                        RuleProtocol::Both => "both",
                    }
                ));
            }
            match &r.action {
                RuleAction::Proxy { chain } => {
                    out.push_str("action = proxy\n");
                    out.push_str(&format!("chain = {}\n", chain));
                }
                RuleAction::Direct => {
                    out.push_str("action = direct\n");
                }
                RuleAction::Block => {
                    out.push_str("action = block\n");
                }
            }
        }
        out
    }

    /// Emit only the `[rule.N]` blocks — for exporting / sharing a ruleset.
    pub fn serialize_rules(rules: &[Rule]) -> String {
        let mut out = String::new();
        for r in rules {
            out.push_str(&format!("\n[rule.{}]\n", r.id));
            out.push_str(&format!("name = \"{}\"\n", r.name));
            out.push_str(&format!("enabled = {}\n", r.enabled));
            out.push_str(&format!("priority = {}\n", r.priority));
            if let Some(app) = &r.app {
                out.push_str(&format!("app = \"{app}\"\n"));
            }
            if let Some(h) = &r.host {
                out.push_str(&format!("host = \"{h}\"\n"));
            }
            if let Some(port) = &r.port {
                out.push_str(&format!("port = \"{port}\"\n"));
            }
            if r.protocol != RuleProtocol::Both {
                out.push_str(&format!(
                    "protocol = {}\n",
                    match r.protocol {
                        RuleProtocol::Tcp => "tcp",
                        RuleProtocol::Udp => "udp",
                        RuleProtocol::Both => "both",
                    }
                ));
            }
            match &r.action {
                RuleAction::Proxy { chain } => {
                    out.push_str("action = proxy\n");
                    out.push_str(&format!("chain = {chain}\n"));
                }
                RuleAction::Direct => out.push_str("action = direct\n"),
                RuleAction::Block => out.push_str("action = block\n"),
            }
        }
        out
    }

    /// Parse `[rule.N]` blocks from a rules file into a rule list.
    pub fn parse_rules(text: &str) -> Result<Vec<Rule>, String> {
        let cfg = Config::parse(&format!("[settings]\n{text}"))?;
        Ok(cfg.rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_serializes_roundtrip() {
        let text = "[settings]\nname = \"Default Profile\"\ndns_mode = local\nip_leak_prevention = true\nproxy_exclusion_list = localhost,127.0.0.1\nproxy_inclusion_list =\n\n[proxy.1]\nname = \"Work\"\ntype = http\nhost = 127.0.0.1\nport = 8080\n\n[chain.1]\nname = \"Chain\"\nproxies = 1\n\n[rule.1]\nname = \"app\"\nenabled = true\npriority = 10\nhost = \"*.example.com\"\nport = 443\naction = proxy\nchain = 1\n";
        let cfg = Config::parse(text).unwrap();
        let out = cfg.serialize();
        let cfg2 = Config::parse(&out).unwrap();
        assert_eq!(cfg, cfg2);
    }

    #[test]
    fn parses_rule_protocol_and_roundtrips() {
        let base = "[rule.1]\nname = \"t\"\nenabled = true\npriority = 1\nhost = \"*\"\naction = proxy\nchain = 1\n";
        // Omitted protocol -> Both, and not emitted on serialize (clean profiles).
        let both = Config::parse(base).unwrap();
        assert_eq!(both.rules[0].protocol, RuleProtocol::Both);
        assert!(!both.serialize().contains("\nprotocol ="), "Both must not emit a rule protocol line");
        // Explicit tcp / udp parse and survive a serialize -> parse round-trip.
        for (val, want) in [("tcp", RuleProtocol::Tcp), ("udp", RuleProtocol::Udp)] {
            let text = format!("{base}protocol = {val}\n");
            let cfg = Config::parse(&text).unwrap();
            assert_eq!(cfg.rules[0].protocol, want, "{val} must parse");
            let back = Config::parse(&cfg.serialize()).unwrap();
            assert_eq!(back.rules[0].protocol, want, "{val} must round-trip");
        }
        assert!(Config::parse(&format!("{base}protocol = carrier-pigeon\n")).is_err());
    }

    #[test]
    fn parses_and_serializes_block_action() {
        let text = "[rule.1]\nname = \"b\"\nenabled = true\npriority = 1\nhost = \"*.ads.test\"\naction = block\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.rules[0].action, RuleAction::Block);
        let out = cfg.serialize();
        assert!(out.contains("action = block\n"), "block must serialize: {out}");
        // block needs no chain; a stray chain key on a block rule is rejected.
        let bad = text.replace("action = block\n", "action = block\nchain = 1\n");
        assert!(Config::parse(&bad).is_err());
        assert_eq!(Config::parse(&out).unwrap(), cfg);
    }

    #[test]
    fn proxification_pause_roundtrips_and_inverse_key() {
        // proxification_enabled = false survives a round-trip.
        let text = "[settings]\nname = \"p\"\nproxification_enabled = false\n";
        let cfg = Config::parse(text).unwrap();
        assert!(!cfg.settings.proxification_enabled);
        let out = cfg.serialize();
        assert!(out.contains("proxification_enabled = false"), "{out}");
        assert_eq!(Config::parse(&out).unwrap(), cfg);
        // The `paused = true` inverse key means the same thing.
        let via_paused = Config::parse("[settings]\npaused = true\n").unwrap();
        assert!(!via_paused.settings.proxification_enabled);
        assert!(Config::default().settings.proxification_enabled, "default must be enabled");
    }

    #[test]
    fn parses_and_serializes_port_specs() {
        let base = "[rule.1]\nname = \"p\"\nenabled = true\npriority = 1\nhost = \"*\"\n";
        // list + range normalises to comma-joined and round-trips.
        let cfg = Config::parse(&format!("{base}port = 80 443, 8000-8100\naction = direct\n")).unwrap();
        assert_eq!(cfg.rules[0].port.as_deref(), Some("80,443,8000-8100"));
        assert_eq!(Config::parse(&cfg.serialize()).unwrap(), cfg);
        // star = any; empty = None.
        assert_eq!(Config::parse(&format!("{base}port = *\naction = direct\n")).unwrap().rules[0].port.as_deref(), Some("*"));
        assert_eq!(Config::parse(&format!("{base}port =\naction = direct\n")).unwrap().rules[0].port, None);
        // invalid token is rejected.
        assert!(Config::parse(&format!("{base}port = http\naction = direct\n")).is_err());
        assert!(Config::parse(&format!("{base}port = 99999\naction = direct\n")).is_err());
    }

    #[test]
    fn disabled_proxies_roundtrip_and_validation() {
        let c = Config::parse("[settings]\ndisabled_proxies = 2,5\n").unwrap();
        assert_eq!(c.settings.disabled_proxies, vec![2, 5]);
        let out = c.serialize();
        assert!(out.contains("disabled_proxies = 2,5"), "{out}");
        assert_eq!(Config::parse(&out).unwrap(), c);
        // empty list is not emitted; a non-numeric id is rejected.
        assert!(!Config::default().serialize().contains("disabled_proxies"));
        assert!(Config::parse("[settings]\ndisabled_proxies = x\n").is_err());
    }

    #[test]
    fn dns_resolver_chain_roundtrip() {
        let c = Config::parse(
            "[settings]\n[dns.1]\nprotocol = udp\nserver = \"1.1.1.1\"\nport = 53\n[dns.2]\nprotocol = tcp\nserver = \"192.0.2.10\"\nport = 5353\n",
        )
        .unwrap();
        assert_eq!(c.settings.dns.servers.len(), 2, "ordered chain parsed");
        assert_eq!(c.settings.dns.servers[0].protocol, DnsProto::Udp);
        assert_eq!(c.settings.dns.servers[0].server, "1.1.1.1");
        assert_eq!(c.settings.dns.servers[1].protocol, DnsProto::Tcp);
        assert_eq!(c.settings.dns.servers[1].port, 5353);
        let out = c.serialize();
        assert!(out.contains("[dns.1]") && out.contains("[dns.2]"), "{out}");
        assert_eq!(Config::parse(&out).unwrap(), c, "chain round-trips in order");
        // default (fresh / New profile) seeds 1.1.1.1 + 8.8.8.8.
        let d = Config::default();
        assert_eq!(d.settings.dns.servers.len(), 2, "default seeds two resolvers");
        assert_eq!(d.settings.dns.servers[0].server, "1.1.1.1");
        assert_eq!(d.settings.dns.servers[1].server, "8.8.8.8");
        // a config file with NO [dns.N] ⇒ empty chain (file owns it → prompt).
        let none = Config::parse("[settings]\nname = \"x\"\n").unwrap();
        assert!(none.settings.dns.servers.is_empty());
        assert!(!none.serialize().contains("[dns."));
        // invalid transport rejected.
        assert!(Config::parse("[dns.1]\nprotocol = pigeon\nserver = \"1.1.1.1\"\n").is_err());
    }

    #[test]
    fn legacy_flat_dns_keys_migrate() {
        let c = Config::parse(
            "[settings]\ndns_protocol = tcp\ndns_server = 10.0.0.2\ndns_port = 5353\ndns_fallback_server = 10.0.0.3\ndns_fallback_port = 53\n",
        )
        .unwrap();
        assert_eq!(c.settings.dns.servers.len(), 2, "legacy keys must not error, they migrate");
        assert_eq!(
            c.settings.dns.servers[0],
            DnsServer { protocol: DnsProto::Tcp, server: "10.0.0.2".into(), port: 5353 }
        );
        assert_eq!(c.settings.dns.servers[1].server, "10.0.0.3");
        // and it re-saves as [dns.N], not the old flat keys.
        let out = c.serialize();
        assert!(out.contains("[dns.1]") && !out.contains("dns_protocol"));
    }

    #[test]
    fn hook_consent_persists_roundtrip() {
        let c = Config::parse("[settings]\nhook_consent = true\n").unwrap();
        assert!(c.settings.hook_consent);
        let out = c.serialize();
        assert!(out.contains("hook_consent = true"), "{out}");
        assert_eq!(Config::parse(&out).unwrap(), c);
        // default (false) is not emitted, so existing configs stay clean.
        assert!(!Config::default().serialize().contains("hook_consent"));
    }

    #[test]
    fn rules_export_import_roundtrip() {
        let rules = vec![
            Rule { id: 1, name: "a".into(), enabled: true, priority: 10, app: Some("chrome.exe".into()), host: Some("*.example.com".into()), port: Some("443".into()), protocol: RuleProtocol::Tcp, action: RuleAction::Proxy { chain: 1 } },
            Rule { id: 2, name: "b".into(), enabled: false, priority: 5, app: None, host: None, port: None, protocol: RuleProtocol::Both, action: RuleAction::Block },
        ];
        let text = Config::serialize_rules(&rules);
        let back = Config::parse_rules(&text).unwrap();
        assert_eq!(back, rules, "rules must survive an export/import round-trip");
    }

    #[test]
    fn the_unattended_launch_flags_round_trip() {
        // Both are needed for "starts by itself at logon": one puts the app in the Run
        // key, the other actually turns the engine on. A profile that loses either on
        // save would silently downgrade to "app opens, does nothing".
        let mut c = Config::default();
        assert!(!c.settings.start_in_tray && !c.settings.start_engine_on_launch, "defaults stay manual");
        c.settings.start_in_tray = true;
        c.settings.start_engine_on_launch = true;
        let text = c.serialize();
        let back = Config::parse(&text).expect("our own profile must parse");
        assert!(back.settings.start_in_tray, "start_in_tray survived");
        assert!(back.settings.start_engine_on_launch, "start_engine_on_launch survived");
    }

    #[test]
    fn ui_scale_and_hidden_tabs_roundtrip() {
        // default scale 100, no hidden tabs, not emitted.
        let d = Config::default();
        assert_eq!(d.settings.ui_scale_pct, 100);
        assert!(!d.serialize().contains("hidden_tabs"), "empty hidden_tabs is not emitted");
        // parse + clamp + round-trip.
        let c = Config::parse("[settings]\nui_scale_pct = 250\nhidden_tabs = check,route\n").unwrap();
        assert_eq!(c.settings.ui_scale_pct, 250);
        assert_eq!(c.settings.hidden_tabs, vec!["check".to_string(), "route".to_string()]);
        let out = c.serialize();
        assert!(out.contains("ui_scale_pct = 250") && out.contains("hidden_tabs = check,route"), "{out}");
        assert_eq!(Config::parse(&out).unwrap(), c);
        // clamped to [50,300]; non-numeric rejected.
        assert_eq!(Config::parse("[settings]\nui_scale_pct = 999\n").unwrap().settings.ui_scale_pct, 300);
        assert!(Config::parse("[settings]\nui_scale_pct = big\n").is_err());
    }

    #[test]
    fn validates_empty_config() {
        let cfg = Config::default();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn rejects_chains_referencing_missing_proxies() {
        let text = "[chain.1]\nname = \"broken\"\nproxies = 9\n";
        let cfg = Config::parse(text).unwrap();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.message.contains("nonexistent proxy")));
    }

    #[test]
    fn rejects_duplicate_proxy_ids() {
        let mut cfg = Config::default();
        cfg.proxies.push(ProxyServer {
            id: 1,
            name: "a".into(),
            kind: ProxyKind::Http,
            host: "h".into(),
            port: 80,
            username: None,
            password: None,
            timeout_secs: 5,
        });
        cfg.proxies.push(ProxyServer {
            id: 1,
            name: "b".into(),
            kind: ProxyKind::Http,
            host: "h".into(),
            port: 81,
            username: None,
            password: None,
            timeout_secs: 5,
        });
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.message.contains("Duplicated IDs")));
    }

    #[test]
    fn rejects_rule_referencing_missing_chain() {
        let text = "[rule.1]\nname = \"broken\"\naction = proxy\nchain = 99\n";
        let cfg = Config::parse(text).unwrap();
        let errors = cfg.validate();
        assert!(errors.iter().any(|e| e.message.contains("nonexistent proxy chain")));
    }

    #[test]
    fn parses_settings_and_proxies() {
        let text = "[settings]\nname = \"Work\"\ndns_mode = proxy\nip_leak_prevention = false\nproxy_exclusion_list = a.com\n\n[proxy.2]\nname = \"Edge\"\ntype = socks5\nhost = 1.2.3.4\nport = 1080\nusername = \"u\"\npassword = \"p\"\n";
        let cfg = Config::parse(text).unwrap();
        assert_eq!(cfg.settings.name, "Work");
        assert_eq!(cfg.settings.dns_mode, DnsMode::Proxy);
        assert!(!cfg.settings.ip_leak_prevention);
        assert_eq!(cfg.settings.proxy_exclusion_list, vec!["a.com".to_string()]);
        assert_eq!(cfg.proxies.len(), 1);
        assert_eq!(cfg.proxies[0].kind, ProxyKind::Socks5);
        assert_eq!(cfg.proxies[0].username.as_deref(), Some("u"));
    }
}
