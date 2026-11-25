use crate::config::{Config, DnsMode, ProxyKind, Rule, RuleAction, RuleProtocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Proxy { chain: u32, rule: u32 },
    Direct { rule: Option<u32>, reason: &'static str },
    /// A matching Block rule: the connection must be refused, neither proxied
    /// nor leaked direct.
    Block { rule: u32 },
}

fn glob_match(pattern: &str, value: &str) -> bool {
    fn rec(p: &[char], v: &[char], i: usize, j: usize) -> bool {
        if i == p.len() {
            return j == v.len();
        }
        if p[i] == '*' {
            for k in j..=v.len() {
                if rec(p, v, i + 1, k) {
                    return true;
                }
            }
            return false;
        }
        if j == v.len() {
            return false;
        }
        if p[i] == v[j] {
            return rec(p, v, i + 1, j + 1);
        }
        false
    }
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let v: Vec<char> = value.to_ascii_lowercase().chars().collect();
    rec(&p, &v, 0, 0)
}

fn app_basename(path: &str) -> &str {
    let trimmed = path.trim_end_matches('"');
    if let Some(pos) = trimmed.rfind(['\\', '/']) {
        &trimmed[pos + 1..]
    } else {
        trimmed
    }
}

fn app_in_list(list: &[String], app: &str) -> bool {
    let base = app_basename(app).to_ascii_lowercase();
    let full = app.to_ascii_lowercase();
    for entry in list {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() {
            continue;
        }
        if glob_match(&e, &base) || glob_match(&e, &full) {
            return true;
        }
    }
    false
}

fn host_in_list(list: &[String], host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    for entry in list {
        let e = entry.trim().to_ascii_lowercase();
        if e.is_empty() {
            continue;
        }
        if glob_match(&e, &h) {
            return true;
        }
    }
    false
}

/// Does the rule's protocol filter admit a connection of `proto`?
/// `proto` uses Winsock numbers: 6 = TCP, 17 = UDP; 0 = unknown/any and is
/// always allowed so protocol-agnostic callers behave as before.
fn proto_allows(rule: &Rule, proto: u8) -> bool {
    match rule.protocol {
        RuleProtocol::Both => true,
        RuleProtocol::Tcp => proto == 0 || proto == 6,
        RuleProtocol::Udp => proto == 0 || proto == 17,
    }
}

/// Split a rule's host/app field into glob patterns. the original lets one rule
/// list several servers / programs; in the flat config they are separated by
/// commas, semicolons or whitespace. Empty fields yield no patterns.
pub(crate) fn pattern_list(field: &str) -> Vec<&str> {
    field
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Does the connection `port` satisfy a rule's port spec? the original lets a rule
/// list ports and ranges (`80, 443, 8000-8100`); `*` matches any port. A spec
/// with no usable entries is unconstrained (matches all).
pub(crate) fn port_matches(spec: &str, port: u16) -> bool {
    let mut any = false;
    for part in spec
        .split([',', ';', ' ', '\t', '\r', '\n'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        any = true;
        if part == "*" || part == "any" {
            return true;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(a), Ok(b)) = (lo.trim().parse::<u32>(), hi.trim().parse::<u32>()) {
                if (a.min(b)..=a.max(b)).contains(&(port as u32)) {
                    return true;
                }
            }
        } else if let Ok(exact) = part.parse::<u32>() {
            if exact == port as u32 {
                return true;
            }
        }
    }
    !any
}

fn rule_matches(rule: &Rule, app: Option<&str>, host: &str, port: u16, proto: u8) -> bool {
    if !proto_allows(rule, proto) {
        return false;
    }
    if let Some(r_app) = &rule.app {
        let pats = pattern_list(r_app);
        if !pats.is_empty() {
            let Some(a) = app else { return false };
            let base = app_basename(a);
            if !pats.iter().any(|p| glob_match(p, base) || glob_match(p, a)) {
                return false;
            }
        }
    }
    if let Some(r_host) = &rule.host {
        let pats = pattern_list(r_host);
        if !pats.is_empty() && !pats.iter().any(|p| glob_match(p, host)) {
            return false;
        }
    }
    if let Some(r_port) = &rule.port {
        if !port_matches(r_port, port) {
            return false;
        }
    }
    true
}

/// Does `app` pass the whitelist gate? True when the whitelist is disabled (so
/// every app is "proxified") or the app matches the configured list.
pub fn is_whitelisted(config: &Config, app: Option<&str>) -> bool {
    if !config.settings.app_whitelist_enabled {
        return true;
    }
    app.map(|a| app_in_list(&config.settings.app_whitelist, a)).unwrap_or(false)
}

/// Is `host`:`port` a DNS query the app sent to a resolver? Port 53 always is; so
/// is any port a resolver is configured on. Queries to a loopback stub resolver
/// are excluded — that stub is itself proxied on its own egress, and forcing the
/// local hop would break name resolution entirely.
fn is_dns_query(config: &Config, host: &str, port: u16) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() {
            return false;
        }
    }
    port == 53 || config.settings.dns.servers.iter().any(|s| s.port == port)
}

/// First chain that can carry DNS for `proto`, preferring the chain the profile's
/// own proxy rules already point at. UDP needs a SOCKS5 egress (the only one with
/// a UDP associate); TCP is carried by any proxy kind.
fn dns_egress_chain(config: &Config, proto: u8) -> Option<u32> {
    let capable = |id: u32| -> bool {
        config
            .chain_by_id(id)
            .and_then(|c| c.proxies.last())
            .and_then(|pid| config.proxy_available(*pid))
            .map(|p| proto != 17 || p.kind == ProxyKind::Socks5)
            .unwrap_or(false)
    };
    let mut ranked: Vec<u32> = config
        .rules
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| match &r.action {
            RuleAction::Proxy { chain } => Some(*chain),
            _ => None,
        })
        .collect();
    for c in &config.chains {
        if !ranked.contains(&c.id) {
            ranked.push(c.id);
        }
    }
    ranked.into_iter().find(|id| capable(*id))
}

/// The routing decision as the DATA PATH will apply it: the rule result, plus the
/// "resolve hostnames through the proxy" policy. With `dns_mode = proxy` an app's
/// resolver query may never take the OS path, so a Direct verdict for a DNS query
/// is re-routed onto a capable chain — and blocked (fail closed) when no chain can
/// carry it. An explicit Block rule stays a block: that is the user's intent, and
/// it leaks nothing.
///
/// The `rule` id of a re-routed decision is 0: "engine policy", not a profile rule.
pub fn decide_route(config: &Config, app: Option<&str>, host: &str, port: u16, proto: u8) -> Decision {
    let d = decide_proto(config, app, host, port, proto);
    if !matches!(d, Decision::Direct { .. }) {
        return d;
    }
    if config.settings.dns_mode != DnsMode::Proxy || !is_dns_query(config, host, port) {
        return d;
    }
    match dns_egress_chain(config, proto) {
        Some(chain) => Decision::Proxy { chain, rule: 0 },
        None => Decision::Block { rule: 0 },
    }
}

pub fn decide(config: &Config, app: Option<&str>, host: &str, port: u16) -> Decision {
    decide_proto(config, app, host, port, 0)
}

/// Protocol-aware decision. `proto` is the Winsock protocol of the connection
/// (6 = TCP, 17 = UDP) so a rule restricted to the other transport is skipped.
pub fn decide_proto(
    config: &Config,
    app: Option<&str>,
    host: &str,
    port: u16,
    proto: u8,
) -> Decision {
    let h = host.to_ascii_lowercase();

    // Global proxification switch off (the original's "Pause"): nothing is proxied.
    if !config.settings.proxification_enabled {
        return Decision::Direct { rule: None, reason: "proxification paused" };
    }

    if config.settings.app_whitelist_enabled {
        let whitelist_match = app
            .map(|a| app_in_list(&config.settings.app_whitelist, a))
            .unwrap_or(false);
        if !whitelist_match {
            return Decision::Direct {
                rule: None,
                reason: "not in app whitelist",
            };
        }
    }
    // IP-leak prevention (fnd_10): a whitelisted app whose connection matches no
    // rule must NOT silently leak direct — it falls through to a safety chain.
    let whitelisted_app = config.settings.app_whitelist_enabled && app.is_some();

    // "Do NOT resolve the following" (fnd_10 / fnd_13): these names are never sent
    // through the proxified-DNS / DNS-then-proxy path, so they connect directly.
    if host_in_list(&config.settings.dns_no_resolve, &h) {
        return Decision::Direct {
            rule: None,
            reason: "DNS (Do not resolve)",
        };
    }

    if host_in_list(&config.settings.proxy_exclusion_list, &h) {
        return Decision::Direct {
            rule: None,
            reason: "Exclusion List match",
        };
    }
    if !config.settings.proxy_inclusion_list.is_empty()
        && !host_in_list(&config.settings.proxy_inclusion_list, &h)
    {
        return Decision::Direct {
            rule: None,
            reason: "Inclusion List match (no match)",
        };
    }

    let mut rules: Vec<&Rule> = config.rules.iter().filter(|r| r.enabled).collect();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in rules {
        if rule_matches(rule, app, &h, port, proto) {
            match &rule.action {
                RuleAction::Proxy { chain } => {
                    return Decision::Proxy { chain: *chain, rule: rule.id };
                }
                RuleAction::Direct => {
                    return Decision::Direct { rule: Some(rule.id), reason: "matched direct rule" };
                }
                RuleAction::Block => {
                    return Decision::Block { rule: rule.id };
                }
            }
        }
    }

    if whitelisted_app && config.settings.ip_leak_prevention && config.settings.ip_leak_default_chain != 0 {
        return Decision::Proxy {
            chain: config.settings.ip_leak_default_chain,
            rule: 0,
        };
    }

    Decision::Direct { rule: None, reason: "no rule matched" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Settings};

    fn cfg_with_rule(rule: Rule) -> Config {
        let mut cfg = Config {
            settings: Settings {
                proxy_exclusion_list: vec!["localhost".into()],
                proxy_inclusion_list: Vec::new(),
                ..Settings::default()
            },
            ..Config::default()
        };
        cfg.rules.push(rule);
        cfg
    }

    fn rule(name: &str, host: Option<&str>, action: RuleAction) -> Rule {
        Rule {
            id: 1,
            name: name.into(),
            enabled: true,
            priority: 0,
            app: None,
            host: host.map(|s| s.to_string()),
            port: None,
            protocol: RuleProtocol::Both,
            action,
        }
    }

    /// A profile with one chain (#7) whose egress is `kind`, and no rules at all
    /// (so every connection is Direct by default) — the shape the DNS policy has
    /// to override.
    fn dns_profile(kind: ProxyKind, mode: crate::config::DnsMode) -> Config {
        let mut cfg = Config::default();
        cfg.settings.dns_mode = mode;
        cfg.proxies.push(crate::config::ProxyServer {
            id: 7,
            name: "egress".into(),
            kind,
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            timeout_secs: 5,
        });
        cfg.chains.push(crate::config::Chain {
            id: 7,
            name: "c".into(),
            proxies: vec![7],
        });
        cfg
    }

    #[test]
    fn dns_proxy_mode_reroutes_app_queries_to_the_chain() {
        use crate::config::ProxyKind::*;
        let cfg = dns_profile(Socks5, crate::config::DnsMode::Proxy);
        // Nothing matched, so the raw verdict is Direct for the resolver and for
        // ordinary traffic; only the DNS query is pulled onto the chain.
        assert!(matches!(decide_proto(&cfg, None, "192.168.1.1", 53, 17), Decision::Direct { .. }));
        assert!(matches!(
            decide_route(&cfg, None, "192.168.1.1", 53, 17),
            Decision::Proxy { chain: 7, rule: 0 }
        ));
        // DNS over TCP, too: the RAW rule verdict is Direct, so an engine that
        // re-decides with decide_proto (as the TCP relay used to) would dial the
        // app's resolver straight out of the machine.
        assert!(matches!(decide_proto(&cfg, None, "192.168.1.1", 53, 6), Decision::Direct { .. }));
        assert!(matches!(
            decide_route(&cfg, None, "192.168.1.1", 53, 6),
            Decision::Proxy { chain: 7, rule: 0 }
        ));
        assert!(matches!(decide_route(&cfg, None, "93.184.216.34", 443, 6), Decision::Direct { .. }));
    }

    #[test]
    fn dns_proxy_mode_fails_closed_without_a_capable_egress() {
        use crate::config::ProxyKind::*;
        // An HTTP CONNECT egress carries no UDP: a DNS-over-UDP query must be blocked
        // rather than leaked to the OS resolver, while DNS-over-TCP still goes out.
        let cfg = dns_profile(Http, crate::config::DnsMode::Proxy);
        assert!(matches!(decide_route(&cfg, None, "192.168.1.1", 53, 17), Decision::Block { .. }));
        // DNS over TCP, too: the RAW rule verdict is Direct, so an engine that
        // re-decides with decide_proto (as the TCP relay used to) would dial the
        // app's resolver straight out of the machine.
        assert!(matches!(decide_proto(&cfg, None, "192.168.1.1", 53, 6), Decision::Direct { .. }));
        assert!(matches!(
            decide_route(&cfg, None, "192.168.1.1", 53, 6),
            Decision::Proxy { chain: 7, rule: 0 }
        ));
    }

    #[test]
    fn dns_proxy_mode_keeps_explicit_blocks_and_local_mode_untouched() {
        use crate::config::{DnsMode, ProxyKind};
        let mut cfg = dns_profile(ProxyKind::Socks5, DnsMode::Proxy);
        cfg.rules.push(rule("no-dns", Some("192.168.1.1"), RuleAction::Block));
        assert!(matches!(decide_route(&cfg, None, "192.168.1.1", 53, 17), Decision::Block { rule: 1 }));

        let local = dns_profile(ProxyKind::Socks5, DnsMode::Local);
        assert!(matches!(decide_route(&local, None, "192.168.1.1", 53, 17), Decision::Direct { .. }));
    }

    #[test]
    fn dns_proxy_mode_skips_loopback_stub_and_custom_port() {
        use crate::config::{DnsMode, DnsServer, DnsProto, ProxyKind};
        let cfg = dns_profile(ProxyKind::Socks5, DnsMode::Proxy);
        // A local stub resolver (systemd-resolved / dnscrypt-proxy) stays direct —
        // its own upstream is what gets proxied.
        assert!(matches!(decide_route(&cfg, None, "127.0.0.53", 53, 17), Decision::Direct { .. }));

        // A resolver configured on a non-standard port is still a DNS query.
        let mut cfg2 = dns_profile(ProxyKind::Socks5, DnsMode::Proxy);
        cfg2.settings.dns.servers = vec![DnsServer {
            protocol: DnsProto::Udp,
            server: "10.1.1.1".into(),
            port: 5353,
        }];
        assert!(matches!(
            decide_route(&cfg2, None, "10.9.9.9", 5353, 17),
            Decision::Proxy { chain: 7, rule: 0 }
        ));
        assert!(matches!(decide_route(&cfg2, None, "10.9.9.9", 5354, 17), Decision::Direct { .. }));
    }

    #[test]
    fn glob_matches_subdomain_style() {
        assert!(glob_match("*.example.com", "a.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(!glob_match("*.example.com", "evil.com"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "exact2"));
    }

    #[test]
    fn exclusion_list_forces_direct() {
        let r = rule("r", Some("*"), RuleAction::Proxy { chain: 1 });
        let cfg = cfg_with_rule(r);
        let d = decide(&cfg, None, "localhost", 443);
        assert!(matches!(d, Decision::Direct { rule: None, .. }));
    }

    #[test]
    fn inclusion_list_requires_match() {
        let r = rule("r", Some("*"), RuleAction::Proxy { chain: 1 });
        let mut cfg = cfg_with_rule(r);
        cfg.settings.proxy_inclusion_list = vec!["allowed.com".into()];
        let blocked = decide(&cfg, None, "evil.com", 443);
        assert!(matches!(blocked, Decision::Direct { reason: "Inclusion List match (no match)", .. }));
        let allowed = decide(&cfg, None, "allowed.com", 443);
        assert!(matches!(allowed, Decision::Proxy { chain: 1, .. }));
    }

    #[test]
    fn priority_wins_over_order() {
        let mut cfg = Config::default();
        cfg.rules.push(Rule {
            id: 1,
            name: "low".into(),
            enabled: true,
            priority: 1,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 10 },
        });
        cfg.rules.push(Rule {
            id: 2,
            name: "high".into(),
            enabled: true,
            priority: 99,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 20 },
        });
        let d = decide(&cfg, None, "any.example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 20, rule: 2 }));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let mut cfg = Config::default();
        cfg.rules.push(Rule {
            id: 1,
            name: "off".into(),
            enabled: false,
            priority: 999,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 5 },
        });
        let d = decide(&cfg, None, "any.example.com", 443);
        assert!(matches!(d, Decision::Direct { rule: None, .. }));
    }

    #[test]
    fn app_match_by_basename() {
        let r = Rule {
            id: 1,
            name: "browser".into(),
            enabled: true,
            priority: 0,
            app: Some("chrome.exe".into()),
            host: None,
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 3 },
        };
        let cfg = cfg_with_rule(r);
        let d = decide(&cfg, Some("C:\\Program Files\\chrome.exe"), "any.example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 3, .. }));
    }

    #[test]
    fn port_match() {
        let r = Rule {
            id: 1,
            name: "p443".into(),
            enabled: true,
            priority: 0,
            app: None,
            host: Some("*".into()),
            port: Some("443".into()),
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        };
        let cfg = cfg_with_rule(r);
        let d1 = decide(&cfg, None, "any.example.com", 443);
        assert!(matches!(d1, Decision::Proxy { chain: 1, .. }));
        let d2 = decide(&cfg, None, "any.example.com", 8080);
        assert!(matches!(d2, Decision::Direct { .. }));
    }

    fn proto_rule(protocol: crate::config::RuleProtocol) -> Config {
        cfg_with_rule(Rule {
            id: 1,
            name: "proto".into(),
            enabled: true,
            priority: 0,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol,
            action: RuleAction::Proxy { chain: 1 },
        })
    }

    #[test]
    fn tcp_only_rule_matches_tcp_not_udp() {
        let cfg = proto_rule(crate::config::RuleProtocol::Tcp);
        // proto 6 = TCP matches; 17 = UDP is skipped -> direct.
        assert!(matches!(decide_proto(&cfg, None, "e.com", 443, 6), Decision::Proxy { .. }));
        assert!(matches!(decide_proto(&cfg, None, "e.com", 443, 17), Decision::Direct { .. }));
    }

    #[test]
    fn udp_only_rule_matches_udp_not_tcp() {
        let cfg = proto_rule(crate::config::RuleProtocol::Udp);
        assert!(matches!(decide_proto(&cfg, None, "e.com", 53, 17), Decision::Proxy { .. }));
        assert!(matches!(decide_proto(&cfg, None, "e.com", 53, 6), Decision::Direct { .. }));
    }

    #[test]
    fn both_rule_and_unknown_proto_match_any() {
        let cfg = proto_rule(crate::config::RuleProtocol::Both);
        assert!(matches!(decide_proto(&cfg, None, "e.com", 443, 6), Decision::Proxy { .. }));
        assert!(matches!(decide_proto(&cfg, None, "e.com", 443, 17), Decision::Proxy { .. }));
        // A tcp-only rule still matches when proto is unknown (0) — protocol-agnostic
        // callers (decide) keep their pre-feature behaviour.
        let tcp_only = proto_rule(crate::config::RuleProtocol::Tcp);
        assert!(matches!(decide(&tcp_only, None, "e.com", 443), Decision::Proxy { .. }));
    }
}

#[cfg(test)]
mod whitelist_tests {
    use super::*;

    fn wl_config() -> Config {
        let mut cfg = Config::default();
        cfg.settings.app_whitelist_enabled = true;
        cfg.settings.app_whitelist = vec!["chrome.exe".into()];
        cfg.rules.push(Rule {
            id: 1,
            name: "proxy-all".into(),
            enabled: true,
            priority: 10,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        });
        cfg
    }

    #[test]
    fn whitelist_allows_listed_app() {
        let cfg = wl_config();
        let d = decide(&cfg, Some(r"C:\Apps\chrome.exe"), "example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 1, .. }));
    }

    #[test]
    fn whitelist_blocks_unlisted_app() {
        let cfg = wl_config();
        let d = decide(&cfg, Some(r"C:\Apps\notes.exe"), "example.com", 443);
        assert!(matches!(d, Decision::Direct { reason: "not in app whitelist", .. }));
    }

    #[test]
    fn whitelist_blocks_unknown_app() {
        let cfg = wl_config();
        let d = decide(&cfg, None, "example.com", 443);
        assert!(matches!(d, Decision::Direct { reason: "not in app whitelist", .. }));
    }

    #[test]
    fn whitelist_disabled_matches_rules_normally() {
        let mut cfg = Config::default();
        cfg.settings.app_whitelist_enabled = false;
        cfg.settings.app_whitelist = vec!["chrome.exe".into()];
        cfg.rules.push(Rule {
            id: 1,
            name: "proxy-all".into(),
            enabled: true,
            priority: 10,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        });
        let d = decide(&cfg, Some(r"C:\Apps\notes.exe"), "example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 1, .. }));
    }
}

#[cfg(test)]
mod dns_no_resolve_tests {
    use super::*;
    use crate::config::{Chain, ProxyKind, ProxyServer};

    fn cfg() -> Config {
        let mut c = Config::default();
        c.settings.dns_no_resolve = vec!["*.lan".into(), "printer.local".into()];
        c.proxies.push(ProxyServer {
            id: 7, name: "p".into(), kind: ProxyKind::Socks5, host: "1.1.1.1".into(),
            port: 1080, username: None, password: None, timeout_secs: 5,
        });
        c.chains.push(Chain { id: 7, name: "c".into(), proxies: vec![7] });
        // A catch-all proxy rule that would otherwise route EVERYTHING.
        c.rules.push(Rule {
            id: 1, name: "all".into(), enabled: true, priority: 5,
            app: None, host: Some("*".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 7 },
        });
        c
    }

    #[test]
    fn listed_host_is_not_resolved_or_proxied() {
        let c = cfg();
        let d = decide(&c, None, "printer.lan", 443);
        assert!(matches!(d, Decision::Direct { reason: "DNS (Do not resolve)", .. }), "got {d:?}");
        let d2 = decide(&c, None, "Printer.LOCAL", 53);
        assert!(matches!(d2, Decision::Direct { reason: "DNS (Do not resolve)", .. }), "case-insensitive, got {d2:?}");
    }

    #[test]
    fn inverse_unlisted_host_still_proxies() {
        // Proves the no-resolve gate is specific and does not disable proxying.
        let c = cfg();
        let d = decide(&c, None, "example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 7, .. }), "got {d:?}");
    }

    #[test]
    fn default_localhost_is_in_no_resolve() {
        let c = Config::default();
        let d = decide(&c, None, "localhost", 443);
        assert!(matches!(d, Decision::Direct { reason: "DNS (Do not resolve)", .. }), "got {d:?}");
    }
}

#[cfg(test)]
mod ip_leak_tests {
    use super::*;
    use crate::config::{Chain, ProxyKind, ProxyServer};

    // Whitelisted app, NO rule matches the host, default safety chain set.
    fn leak_cfg(prevention: bool, default_chain: u32) -> Config {
        let mut cfg = Config::default();
        cfg.settings.app_whitelist_enabled = true;
        cfg.settings.app_whitelist = vec!["game.exe".into()];
        cfg.settings.ip_leak_prevention = prevention;
        cfg.settings.ip_leak_default_chain = default_chain;
        cfg.settings.proxy_exclusion_list = vec!["localhost".into()];
        cfg.proxies.push(ProxyServer {
            id: 7, name: "p".into(), kind: ProxyKind::Socks5, host: "127.0.0.1".into(),
            port: 1080, username: None, password: None, timeout_secs: 5,
        });
        cfg.chains.push(Chain { id: 7, name: "safety".into(), proxies: vec![7] });
        // A rule that matches ONLY tracked.example.com — other hosts match nothing.
        cfg.rules.push(Rule {
            id: 1, name: "tracked".into(), enabled: true, priority: 10,
            app: None, host: Some("tracked.example.com".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 7 },
        });
        cfg
    }

    #[test]
    fn whitelisted_app_with_no_rule_match_uses_safety_chain() {
        let cfg = leak_cfg(true, 7);
        let d = decide(&cfg, Some(r"C:\Games\game.exe"), "untracked.net", 443);
        assert!(matches!(d, Decision::Proxy { chain: 7, .. }), "leak prevention must proxy, got {d:?}");
    }

    #[test]
    fn inverse_disabled_leaks_direct() {
        // With prevention OFF the same flow must go DIRECT (proves the gate drives it).
        let cfg = leak_cfg(false, 7);
        let d = decide(&cfg, Some(r"C:\Games\game.exe"), "untracked.net", 443);
        assert!(matches!(d, Decision::Direct { reason: "no rule matched", .. }), "got {d:?}");
    }

    #[test]
    fn inverse_chain_zero_never_forces_proxy() {
        let cfg = leak_cfg(true, 0);
        let d = decide(&cfg, Some(r"C:\Games\game.exe"), "untracked.net", 443);
        assert!(matches!(d, Decision::Direct { .. }), "chain 0 must not proxy, got {d:?}");
    }

    #[test]
    fn non_whitelisted_app_stays_direct_not_leak_proxy() {
        let cfg = leak_cfg(true, 7);
        let d = decide(&cfg, Some(r"C:\Apps\notes.exe"), "untracked.net", 443);
        assert!(matches!(d, Decision::Direct { reason: "not in app whitelist", .. }), "got {d:?}");
    }

    #[test]
    fn explicit_direct_rule_is_not_overridden() {
        let mut cfg = leak_cfg(true, 7);
        cfg.rules.push(Rule {
            id: 2, name: "force-direct".into(), enabled: true, priority: 100,
            app: None, host: Some("lan.local".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Direct,
        });
        // Host matches an explicit Direct rule (higher priority), so it stays Direct.
        let d = decide(&cfg, Some(r"C:\Games\game.exe"), "lan.local", 443);
        assert!(matches!(d, Decision::Direct { rule: Some(2), .. }), "explicit direct must win, got {d:?}");
    }

    #[test]
    fn exclusion_list_forces_direct_even_with_prevention() {
        let mut cfg = leak_cfg(true, 7);
        // Use a host that is ONLY in the exclusion list (not the default
        // dns_no_resolve ["localhost"]), so this exercises the exclusion reason.
        cfg.settings.proxy_exclusion_list = vec!["10.0.0.5".into()];
        let d = decide(&cfg, Some(r"C:\Games\game.exe"), "10.0.0.5", 443);
        assert!(matches!(d, Decision::Direct { reason: "Exclusion List match", .. }), "exclusion must win, got {d:?}");
    }
}

#[cfg(test)]
mod block_tests {
    use super::*;
    use crate::config::{Rule, RuleAction, RuleProtocol, Settings};

    fn cfg_with_block_rule() -> Config {
        let mut cfg = Config {
            settings: Settings {
                proxy_exclusion_list: vec!["localhost".into()],
                ..Settings::default()
            },
            ..Config::default()
        };
        // A high-priority Block rule for *.blocked.test, plus a catch-all proxy.
        cfg.rules.push(Rule {
            id: 1,
            name: "block".into(),
            enabled: true,
            priority: 100,
            app: None,
            host: Some("*.blocked.test".into()),
            port: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Block,
        });
        cfg.rules.push(Rule {
            id: 2,
            name: "proxy-all".into(),
            enabled: true,
            priority: 1,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Proxy { chain: 1 },
        });
        cfg
    }

    #[test]
    fn block_rule_wins_over_catchall_proxy() {
        let cfg = cfg_with_block_rule();
        let d = decide(&cfg, None, "x.blocked.test", 443);
        assert!(matches!(d, Decision::Block { rule: 1 }), "must block, got {d:?}");
    }

    #[test]
    fn non_matching_host_still_proxies_inverse() {
        // Proves the block rule is host-scoped and does not disable proxying.
        let cfg = cfg_with_block_rule();
        let d = decide(&cfg, None, "allowed.example.com", 443);
        assert!(matches!(d, Decision::Proxy { chain: 1, rule: 2 }), "got {d:?}");
    }

    #[test]
    fn block_is_transport_agnostic() {
        // A Both block rule blocks TCP(6) and UDP(17) alike.
        let cfg = cfg_with_block_rule();
        assert!(matches!(decide_proto(&cfg, None, "x.blocked.test", 443, 6), Decision::Block { .. }));
        assert!(matches!(decide_proto(&cfg, None, "x.blocked.test", 53, 17), Decision::Block { .. }));
    }

    #[test]
    fn udp_only_block_rule_does_not_block_tcp() {
        let mut cfg = Config::default();
        cfg.settings.proxy_exclusion_list = vec!["localhost".into()];
        cfg.rules.push(Rule {
            id: 1,
            name: "block-udp".into(),
            enabled: true,
            priority: 100,
            app: None,
            host: Some("*.blocked.test".into()),
            port: None,
            protocol: RuleProtocol::Udp,
            action: RuleAction::Block,
        });
        // UDP blocked, TCP not matched -> falls through to no-rule Direct.
        assert!(matches!(decide_proto(&cfg, None, "x.blocked.test", 53, 17), Decision::Block { .. }));
        assert!(matches!(decide_proto(&cfg, None, "x.blocked.test", 443, 6), Decision::Direct { .. }));
    }

    #[test]
    fn block_beats_ip_leak_fallback() {
        // Even with IP-leak prevention armed, an explicit Block rule must win
        // (not silently route the connection through the safety chain).
        let mut cfg = cfg_with_block_rule();
        cfg.settings.app_whitelist_enabled = true;
        cfg.settings.app_whitelist = vec!["game.exe".into()];
        cfg.settings.ip_leak_prevention = true;
        cfg.settings.ip_leak_default_chain = 1;
        let d = decide(&cfg, Some(r"C:\g\game.exe"), "x.blocked.test", 443);
        assert!(matches!(d, Decision::Block { rule: 1 }), "explicit block must win, got {d:?}");
    }
}

#[cfg(test)]
mod list_tests {
    use super::*;
    use crate::config::{Config, Rule, RuleAction, RuleProtocol, Settings};

    fn cfg_multi() -> Config {
        let mut cfg = Config {
            settings: Settings {
                proxy_exclusion_list: vec!["localhost".into()],
                ..Settings::default()
            },
            ..Config::default()
        };
        cfg.rules.push(Rule {
            id: 1,
            name: "multi".into(),
            enabled: true,
            priority: 10,
            app: Some("chrome.exe; firefox.exe".into()),
            host: Some("*.example.com, *.test.internal, cdn.foo.com".into()),
            port: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Proxy { chain: 7 },
        });
        cfg
    }

    #[test]
    fn any_listed_host_matches() {
        let cfg = cfg_multi();
        for h in ["a.example.com", "x.test.internal", "cdn.foo.com"] {
            let d = decide(&cfg, Some(r"C:\Apps\chrome.exe"), h, 443);
            assert!(matches!(d, Decision::Proxy { chain: 7, .. }), "{h} should match, got {d:?}");
        }
    }

    #[test]
    fn unlisted_host_inverse() {
        let cfg = cfg_multi();
        let d = decide(&cfg, Some(r"C:\Apps\chrome.exe"), "evil.org", 443);
        assert!(matches!(d, Decision::Direct { .. }), "unlisted host must not match, got {d:?}");
    }

    #[test]
    fn any_listed_app_matches_others_inverse() {
        let cfg = cfg_multi();
        assert!(matches!(
            decide(&cfg, Some(r"C:\Apps\firefox.exe"), "a.example.com", 443),
            Decision::Proxy { .. }
        ));
        // A program NOT in the app list fails the rule (no other rule -> direct).
        assert!(matches!(
            decide(&cfg, Some(r"C:\Apps\edge.exe"), "a.example.com", 443),
            Decision::Direct { .. }
        ));
    }

    #[test]
    fn semicolon_and_whitespace_separators_both_work() {
        let mut cfg = cfg_multi();
        cfg.rules[0].host = Some("*.a.com;*.b.com\n\t*.c.com".into());
        for h in ["x.a.com", "y.b.com", "z.c.com"] {
            let d = decide(&cfg, Some("chrome.exe"), h, 443);
            assert!(matches!(d, Decision::Proxy { .. }), "{h} should match, got {d:?}");
        }
    }
}

#[cfg(test)]
mod proxification_pause_tests {
    use super::*;
    use crate::config::{Config, Rule, RuleAction, RuleProtocol};

    fn cfg_catchall() -> Config {
        let mut cfg = Config::default();
        cfg.rules.push(Rule {
            id: 1, name: "all".into(), enabled: true, priority: 10,
            app: None, host: Some("*".into()), port: None,
            protocol: RuleProtocol::Both, action: RuleAction::Proxy { chain: 7 },
        });
        cfg
    }

    #[test]
    fn enabled_by_default_proxies() {
        let cfg = cfg_catchall();
        assert!(cfg.settings.proxification_enabled, "default must be enabled");
        assert!(matches!(decide(&cfg, None, "example.com", 443), Decision::Proxy { chain: 7, .. }));
    }

    #[test]
    fn paused_forces_direct_for_everything_inverse() {
        let mut cfg = cfg_catchall();
        cfg.settings.proxification_enabled = false;
        // Catch-all proxy rule must NOT fire while paused.
        let d = decide(&cfg, None, "example.com", 443);
        assert!(matches!(d, Decision::Direct { reason: "proxification paused", .. }), "got {d:?}");
    }

    #[test]
    fn pause_gate_precedes_block_and_ip_leak() {
        // Even an explicit Block rule and armed IP-leak fallback are bypassed
        // when proxification is paused — pause means "leave the stack alone".
        let mut cfg = cfg_catchall();
        cfg.rules.push(Rule {
            id: 2, name: "block".into(), enabled: true, priority: 100,
            app: None, host: Some("ads.test".into()), port: None,
            protocol: RuleProtocol::Both, action: RuleAction::Block,
        });
        cfg.settings.app_whitelist_enabled = true;
        cfg.settings.app_whitelist = vec!["game.exe".into()];
        cfg.settings.ip_leak_prevention = true;
        cfg.settings.ip_leak_default_chain = 7;
        cfg.settings.proxification_enabled = false;
        assert!(matches!(decide(&cfg, Some("game.exe"), "ads.test", 443), Decision::Direct { .. }));
        assert!(matches!(decide(&cfg, Some("game.exe"), "untracked.net", 443), Decision::Direct { .. }));
    }
}

#[cfg(test)]
mod port_spec_tests {
    use super::*;
    use crate::config::{Config, Rule, RuleAction, RuleProtocol};

    #[test]
    fn matcher_exact_list_range_star() {
        assert!(port_matches("443", 443));
        assert!(!port_matches("443", 80));
        assert!(port_matches("80,443,8080", 443));
        assert!(port_matches("8000-8100", 8050));
        assert!(!port_matches("8000-8100", 8101));
        assert!(port_matches("8000-8100", 8000));
        assert!(port_matches("8100-8000", 8050), "reversed range still works");
        assert!(port_matches("*", 65535));
        assert!(port_matches("443, 8000-8100", 8100), "mixed list+range w/ spaces");
        // empty/whitespace spec is unconstrained
        assert!(port_matches("", 1));
        assert!(port_matches("  ,  ", 9999));
    }

    #[test]
    fn decision_uses_port_range() {
        let mut cfg = Config::default();
        cfg.settings.proxy_exclusion_list = vec!["localhost".into()];
        cfg.rules.push(Rule {
            id: 1, name: "web".into(), enabled: true, priority: 10,
            app: None, host: Some("*".into()), port: Some("80,443,8000-8100".into()),
            protocol: RuleProtocol::Both, action: RuleAction::Proxy { chain: 5 },
        });
        for p in [80u16, 443, 8050] {
            assert!(matches!(decide(&cfg, None, "example.com", p), Decision::Proxy { chain: 5, .. }), "{p} should proxy");
        }
        // Outside the spec -> no rule matched -> direct (inverse proof the range binds).
        assert!(matches!(decide(&cfg, None, "example.com", 9999), Decision::Direct { .. }));
    }
}

/// Split a `host:port` remote string (IPv6-aware: `[::1]:443`) into `(host,
/// Option<port-spec>)`. A bare host with no port yields `None`.
pub fn split_host_port(remote: &str) -> (String, Option<String>) {
    let r = remote.trim();
    if let Some(rest) = r.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            let host = format!("[{}]", &rest[..close]);
            let after = rest[close + 1..].trim_start_matches(':');
            let port = if after.parse::<u16>().is_ok() { Some(after.to_string()) } else { None };
            return (host, port);
        }
    }
    match r.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.parse::<u16>().is_ok() => {
            (h.to_string(), Some(p.to_string()))
        }
        _ => (r.to_string(), None),
    }
}

/// Build a Proxification rule from a live connection row — the original's
/// per-connection "add rule for this application/server" convenience. The new
/// rule proxies the app to that exact host (and port, if the peer was numeric)
/// using `chain`; a higher priority lets it win over a catch-all rule.
pub fn rule_from_conn(app: &str, remote: &str, proto: &str, chain: u32, id: u32) -> Rule {
    let app_base = app_basename(app).to_string();
    let (host, port) = split_host_port(remote);
    let protocol = if proto.eq_ignore_ascii_case("udp") {
        RuleProtocol::Udp
    } else if proto.eq_ignore_ascii_case("tcp") {
        RuleProtocol::Tcp
    } else {
        RuleProtocol::Both
    };
    Rule {
        id,
        name: format!("auto:{app_base}→{host}"),
        enabled: true,
        priority: 100,
        app: if app_base.is_empty() { None } else { Some(app_base) },
        host: if host.is_empty() { None } else { Some(host) },
        port,
        protocol,
        action: RuleAction::Proxy { chain },
    }
}

#[cfg(test)]
mod rule_from_conn_tests {
    use super::*;
    use crate::config::{Config, RuleAction, RuleProtocol};

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("example.com:443"), ("example.com".into(), Some("443".into())));
        assert_eq!(split_host_port("198.51.100.7:80"), ("198.51.100.7".into(), Some("80".into())));
        assert_eq!(split_host_port("[2001:db8::1]:53"), ("[2001:db8::1]".into(), Some("53".into())));
        assert_eq!(split_host_port("example.com"), ("example.com".into(), None));
        // non-numeric "port" stays part of the host, not a bogus port
        assert_eq!(split_host_port("https://x"), ("https://x".into(), None));
    }

    #[test]
    fn builds_proxy_rule_from_tcp_conn() {
        let r = rule_from_conn(r"C:\Program Files\Google\Chrome\chrome.exe", "cdn.example.com:443", "TCP", 7, 42);
        assert_eq!(r.app.as_deref(), Some("chrome.exe"));
        assert_eq!(r.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(r.port.as_deref(), Some("443"));
        assert_eq!(r.protocol, RuleProtocol::Tcp);
        assert!(matches!(r.action, RuleAction::Proxy { chain: 7 }));
        assert_eq!(r.id, 42);
        assert!(r.enabled && r.priority == 100);
    }

    #[test]
    fn udp_and_ipv6_conn() {
        let r = rule_from_conn("game.exe", "[2001:db8::1]:3074", "UDP", 3, 9);
        assert_eq!(r.protocol, RuleProtocol::Udp);
        assert_eq!(r.host.as_deref(), Some("[2001:db8::1]"));
        assert_eq!(r.port.as_deref(), Some("3074"));
    }

    #[test]
    fn generated_rule_immediately_decides_proxy_inverse() {
        // The generated rule must actually match the same flow it was made from,
        // and must NOT match a different app/host (inverse proof).
        let mut cfg = Config::default();
        cfg.settings.proxy_exclusion_list = vec!["localhost".into()];
        let r = rule_from_conn(r"C:\a\chrome.exe", "cdn.example.com:443", "TCP", 7, 1);
        cfg.rules.push(r);
        let hit = decide_proto(&cfg, Some(r"C:\a\chrome.exe"), "cdn.example.com", 443, 6);
        assert!(matches!(hit, Decision::Proxy { chain: 7, rule: 1 }), "got {hit:?}");
        // different app -> rule's app filter fails -> direct
        let miss = decide_proto(&cfg, Some(r"C:\a\edge.exe"), "cdn.example.com", 443, 6);
        assert!(matches!(miss, Decision::Direct { .. }), "got {miss:?}");
    }
}

/// Like [`rule_from_conn`] but the generated rule BLOCKS the flow (admin
/// "blacklist this host from the connection list"). Reuses the same parsing so
/// app/host/port/proto are derived identically.
pub fn block_rule_from_conn(app: &str, remote: &str, proto: &str, id: u32) -> Rule {
    let mut r = rule_from_conn(app, remote, proto, 0, id);
    r.action = RuleAction::Block;
    r.name = r.name.replacen("auto:", "block:", 1);
    r
}

#[cfg(test)]
mod block_rule_from_conn_tests {
    use super::*;
    use crate::config::{Config, RuleAction, RuleProtocol};

    #[test]
    fn builds_block_rule() {
        let r = block_rule_from_conn(r"C:\a\spy.exe", "tracker.example.com:443", "TCP", 8);
        assert!(matches!(r.action, RuleAction::Block));
        assert_eq!(r.app.as_deref(), Some("spy.exe"));
        assert_eq!(r.host.as_deref(), Some("tracker.example.com"));
        assert_eq!(r.port.as_deref(), Some("443"));
        assert_eq!(r.protocol, RuleProtocol::Tcp);
        assert!(r.name.starts_with("block:"), "name marks it a block: {}", r.name);
    }

    #[test]
    fn generated_block_rule_actually_blocks_inverse() {
        let mut cfg = Config::default();
        cfg.settings.proxy_exclusion_list = vec!["localhost".into()];
        // A catch-all proxy first; the generated block rule has higher priority.
        cfg.rules.push(Rule { id: 1, name: "all".into(), enabled: true, priority: 10, app: None, host: Some("*".into()), port: None, protocol: RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 } });
        cfg.rules.push(block_rule_from_conn("spy.exe", "tracker.example.com:443", "TCP", 2));
        assert!(matches!(decide(&cfg, Some("spy.exe"), "tracker.example.com", 443), Decision::Block { rule: 2 }));
        // A different host still proxies (inverse: block is host-scoped).
        assert!(matches!(decide(&cfg, Some("spy.exe"), "good.example.com", 443), Decision::Proxy { .. }));
    }
}
