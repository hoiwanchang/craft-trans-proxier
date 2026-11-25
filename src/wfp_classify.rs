//! WFP callout decision core — the pure logic a Windows Filtering Platform
//! callout needs at `ALE_CONNECT_REDIRECT_V4/V6` (and the datagram layers).
//!
//! Why this exists separately from [`crate::rules`]: a WFP classify callback
//! runs inside the BFE and is handed only the connecting **process id** in the
//! ALE metadata — it cannot call `QueryFullProcessImageNameW` cheaply on the
//! classify path. So instead of an image *path* (what `rules::decide` matches on
//! for the driverless hook), the callout resolves the app once (out of band) to
//! a boolean "is this process in the proxified whitelist?" and the per-
//! connection decision here is made from `(whitelist result, host, port)`.
//!
//! The verdict semantics deliberately MIRROR `rules::decide` (so the two engines
//! agree), but without the path dependency:
//!   * not whitelisted (gate on)  -> Permit (direct, untouched)
//!   * "do not resolve" name list -> Permit
//!   * proxy exclusion list match  -> Permit
//!   * inclusion list non-match     -> Permit
//!   * highest-priority matching rule -> Permit or Redirect(chain)
//!   * no rule + IP-leak prevention  -> Redirect(safety chain)
//!   * otherwise                     -> Permit
//!
//! This is the verified decision seam; the WFP FFI plumbing (the callout DLL +
//! `FwpmCalloutAdd0`) is the administrator-install step described in
//! `docs/WFP_ROADMAP.md` (Option A) and is intentionally NOT claimed done here.

use crate::config::{Config, RuleAction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WfpVerdict {
    /// Leave the connection to go direct (WFP `FWP_ACTION_PERMIT`).
    Permit,
    /// Redirect this flow to the local engine on `chain` (WFP callout → redirect).
    Redirect { chain: u32 },
    /// Block the connection outright (WFP `FWP_ACTION_BLOCK`).
    Block,
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

fn host_in_list(list: &[String], host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    list.iter()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .any(|e| glob_match(&e, &h))
}

/// Decide what a WFP callout should do for a connection from `pid`.
/// `app_whitelisted` is the out-of-band answer to "is this process in the
/// proxified app list?" — already folding in whether the gate is enabled
/// (callers pass `true` when the whitelist is disabled, i.e. everything matches,
/// mirroring `rules::is_whitelisted`).
pub fn classify(config: &Config, app_whitelisted: bool, host: &str, port: u16) -> WfpVerdict {
    let h = host.to_ascii_lowercase();
    // Proxification paused globally -> never redirect (all traffic direct).
    if !config.settings.proxification_enabled {
        return WfpVerdict::Permit;
    }

    // Whitelist gate: a process we don't proxify goes straight through.
    if config.settings.app_whitelist_enabled && !app_whitelisted {
        return WfpVerdict::Permit;
    }
    // DNS "do not resolve" list always connects directly.
    if host_in_list(&config.settings.dns_no_resolve, &h) {
        return WfpVerdict::Permit;
    }
    if host_in_list(&config.settings.proxy_exclusion_list, &h) {
        return WfpVerdict::Permit;
    }
    if !config.settings.proxy_inclusion_list.is_empty()
        && !host_in_list(&config.settings.proxy_inclusion_list, &h)
    {
        return WfpVerdict::Permit;
    }

    let mut rules: Vec<&_> = config.rules.iter().filter(|r| r.enabled).collect();
    rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    for rule in rules {
        if let Some(rule_host) = &rule.host {
            let pats = crate::rules::pattern_list(rule_host);
            if !pats.is_empty() && !pats.iter().any(|p| glob_match(p, &h)) {
                continue;
            }
        }
        if let Some(rule_port) = &rule.port {
            if !crate::rules::port_matches(rule_port, port) {
                continue;
            }
        }
        // WFP callouts classify per-connection and can't cheaply match app paths,
        // so app-scoped rules are not evaluated here (the driverless hook covers
        // those). A rule with an app filter is skipped by the callout path.
        if rule.app.is_some() {
            continue;
        }
        match &rule.action {
            RuleAction::Proxy { chain } => return WfpVerdict::Redirect { chain: *chain },
            RuleAction::Direct => return WfpVerdict::Permit,
            RuleAction::Block => return WfpVerdict::Block,
        }
    }

    // IP-leak prevention: a whitelisted process with no matching rule still must
    // not leak direct (mirrors rules::decide's guarded fall-through).
    if config.settings.app_whitelist_enabled
        && app_whitelisted
        && config.settings.ip_leak_prevention
        && config.settings.ip_leak_default_chain != 0
    {
        return WfpVerdict::Redirect { chain: config.settings.ip_leak_default_chain };
    }

    WfpVerdict::Permit
}

/// ─── kernel ↔ engine flow contract ───────────────────────────────────────────
///
/// A WFP redirect delivers the ORIGINAL destination nowhere by itself: neither a
/// filter nor `FWPS_CLASSIFY_OUT0` has a field for it (both are asserted by tests
/// in `crate::wfp`). So the callout driver has to record what it redirected, keyed
/// by the ALE flow, and the engine has to recover it when the redirected socket is
/// accepted. [`FlowRecord`] is that record.
///
/// It is byte-serialised (never `transmute`d) so the kernel side can `RtlCopyMemory`
/// a `[u8; FLOW_RECORD_LEN]` across the boundary without either side depending on
/// the other's layout, and so a slot that was never filled is detectable: parsing
/// rejects anything without [`FLOW_RECORD_MAGIC`]. Integers are little-endian,
/// which is also native for every Windows kernel architecture this targets.
pub const FLOW_RECORD_LEN: usize = 72;
pub const FLOW_RECORD_MAGIC: u32 = 0x5052_5846; // "PRXF" — proxier flow

/// Verdict tags, mirroring [`WfpVerdict`] as a single byte.
pub const VERDICT_PERMIT: u8 = 0;
pub const VERDICT_REDIRECT: u8 = 1;
pub const VERDICT_BLOCK: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowRecord {
    /// Address family as Winsock defines it: AF_INET = 2, AF_INET6 = 23.
    pub family: u16,
    /// Original remote port in wire form: the u16 as stored in a SOCKADDR, i.e.
    /// `host_port.to_be()`. Serialised as those exact octets, byte-identical to what
    /// the C driver writes from `sin_port`/`sin6_port`. Use [`Self::remote`] to get a
    /// usable port number.
    pub port_be: u16,
    /// Original remote address: 4 bytes for AF_INET (rest zero), 16 for AF_INET6.
    pub addr: [u8; 16],
    /// Connecting process id, from the ALE metadata.
    pub pid: u32,
    /// Chain the flow was redirected onto; 0 when the verdict is not Redirect.
    pub chain: u32,
    /// One of the `VERDICT_*` constants.
    pub verdict: u8,
    /// IP protocol: 6 (TCP) or 17 (UDP).
    pub proto: u8,
    /// WFP flow identifier — the key the driver and the engine agree on.
    pub flow_id: u64,
    /// The socket's local endpoint at classify time: after a redirect the engine
    /// sees a loopback peer, so the original 4-tuple is recovered from these.
    pub local_addr: [u8; 16],
    pub local_port_be: u16,
    /// Which engine token port the flow was redirected to, so a proxy holding
    /// several listeners can confirm the record belongs to this connection.
    pub token_port: u16,
}

impl Default for FlowRecord {
    fn default() -> FlowRecord {
        FlowRecord {
            family: 0,
            port_be: 0,
            addr: [0; 16],
            pid: 0,
            chain: 0,
            verdict: VERDICT_PERMIT,
            proto: 0,
            flow_id: 0,
            local_addr: [0; 16],
            local_port_be: 0,
            token_port: 0,
        }
    }
}

impl FlowRecord {
    pub fn to_bytes(&self) -> [u8; FLOW_RECORD_LEN] {
        let mut b = [0u8; FLOW_RECORD_LEN];
        b[0..4].copy_from_slice(&FLOW_RECORD_MAGIC.to_le_bytes());
        b[4..6].copy_from_slice(&self.family.to_le_bytes());
        // `port_be` already holds the port AS IT APPEARS ON THE WIRE (a u16 whose
        // numeric value is the byte-swapped port — the same representation a
        // SOCKADDR's sin_port has in memory), so writing it little-endian reproduces
        // the wire octets. to_be_bytes here would double-swap and send 443 as 47873.
        b[6..8].copy_from_slice(&self.port_be.to_le_bytes());
        b[8..24].copy_from_slice(&self.addr);
        b[24..28].copy_from_slice(&self.pid.to_le_bytes());
        b[28..32].copy_from_slice(&self.chain.to_le_bytes());
        b[32] = self.verdict;
        b[33] = self.proto;
        b[34..36].copy_from_slice(&self.token_port.to_le_bytes());
        b[40..48].copy_from_slice(&self.flow_id.to_le_bytes());
        b[48..64].copy_from_slice(&self.local_addr);
        b[64..66].copy_from_slice(&self.local_port_be.to_le_bytes()); // same reasoning
        b
    }

    /// `None` unless the buffer carries our magic, so an uninitialised or stale
    /// slot can never be mistaken for a flow.
    pub fn from_bytes(b: &[u8]) -> Option<FlowRecord> {
        if b.len() < FLOW_RECORD_LEN || u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != FLOW_RECORD_MAGIC {
            return None;
        }
        Some(FlowRecord {
            family: u16::from_le_bytes([b[4], b[5]]),
            port_be: u16::from_le_bytes([b[6], b[7]]),
            addr: b[8..24].try_into().ok()?,
            pid: u32::from_le_bytes([b[24], b[25], b[26], b[27]]),
            chain: u32::from_le_bytes([b[28], b[29], b[30], b[31]]),
            verdict: b[32],
            proto: b[33],
            token_port: u16::from_le_bytes([b[34], b[35]]),
            flow_id: u64::from_le_bytes(b[40..48].try_into().ok()?),
            local_addr: b[48..64].try_into().ok()?,
            local_port_be: u16::from_le_bytes([b[64], b[65]]),
        })
    }

    pub fn remote(&self) -> Option<std::net::SocketAddr> {
        let port = self.port_be.swap_bytes();
        match self.family {
            2 => {
                let a: [u8; 4] = self.addr[..4].try_into().ok()?;
                Some(std::net::SocketAddr::new(std::net::IpAddr::V4(a.into()), port))
            }
            23 => Some(std::net::SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(self.addr)),
                port,
            )),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
const C_DRIVER: &str = include_str!("../driver_wfp/tpdrv_wfp.c");

/// Every `C_ASSERT(<offset-of>(TP_FLOW_RECORD, NAME) == N);` in the driver source.
///
/// Both spellings are accepted on purpose: `offsetof` needs <stddef.h>, while a kernel
/// translation unit idiomatically uses the WDK's `FIELD_OFFSET` — which is what the real
/// fwpsk.h-driven build forced us to switch to. Matching either means a change of
/// spelling on one side cannot quietly turn this cross-check into a test of nothing.
fn c_record_offsets(src: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim();
        let rest = match line
            .strip_prefix("C_ASSERT(offsetof(TP_FLOW_RECORD,")
            .or_else(|| line.strip_prefix("C_ASSERT(FIELD_OFFSET(TP_FLOW_RECORD,"))
        {
            Some(r) => r,
            None => continue,
        };
        let (name, tail) = match rest.split_once(')') {
            Some(v) => v,
            None => continue,
        };
        let n = match tail
            .split("==")
            .nth(1)
            .and_then(|v| v.trim().trim_end_matches([')', ';', ' ']).trim().parse::<usize>().ok())
        {
            Some(n) => n,
            None => continue,
        };
        out.push((name.trim().to_string(), n));
    }
    out
}

    use super::*;
    use crate::config::{Chain, ProxyKind, ProxyServer, Rule};

    fn cfg() -> Config {
        let mut c = Config::default();
        c.settings.proxy_exclusion_list = vec!["localhost".into(), "127.0.0.1".into()];
        c.proxies.push(ProxyServer {
            id: 9, name: "p".into(), kind: ProxyKind::Socks5, host: "1.1.1.1".into(),
            port: 1080, username: None, password: None, timeout_secs: 5,
        });
        c.chains.push(Chain { id: 9, name: "c".into(), proxies: vec![9] });
        c.rules.push(Rule {
            id: 1, name: "tracked".into(), enabled: true, priority: 5,
            app: None, host: Some("*.example.com".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 9 },
        });
        c
    }

    #[test]
    fn whitelist_gate_off_lets_non_whitelisted_through() {
        let mut c = cfg();
        c.settings.app_whitelist_enabled = true;
        // not whitelisted -> Permit even though the host matches *.example.com
        assert_eq!(classify(&c, false, "a.example.com", 443), WfpVerdict::Permit);
        // whitelisted -> Redirect
        assert_eq!(classify(&c, true, "a.example.com", 443), WfpVerdict::Redirect { chain: 9 });
    }

    #[test]
    fn whitelist_disabled_matches_everything() {
        let c = cfg(); // app_whitelist_enabled default false
        assert_eq!(classify(&c, false, "a.example.com", 443), WfpVerdict::Redirect { chain: 9 });
    }

    #[test]
    fn hostname_rule_matches_case_insensitive() {
        assert_eq!(classify(&cfg(), true, "CDN.EXAMPLE.COM", 443), WfpVerdict::Redirect { chain: 9 });
    }

    #[test]
    fn no_match_defaults_to_permit() {
        // untracked host, prevention off (default) -> Permit (direct)
        assert_eq!(classify(&cfg(), true, "untracked.net", 443), WfpVerdict::Permit);
    }

    #[test]
    fn exclusion_and_dns_noresolve_force_permit() {
        assert_eq!(classify(&cfg(), true, "localhost", 443), WfpVerdict::Permit);
        // "api.example.com" matches the host rule but is also in dns_no_resolve default? no.
        let mut c = cfg();
        c.settings.dns_no_resolve = vec!["api.example.com".into()];
        assert_eq!(classify(&c, true, "api.example.com", 443), WfpVerdict::Permit, "do-not-resolve beats the proxy rule");
    }

    #[test]
    fn ip_leak_prevention_redirects_unmatched_whitelisted() {
        let mut c = cfg();
        c.settings.app_whitelist_enabled = true;
        c.settings.ip_leak_prevention = true;
        c.settings.ip_leak_default_chain = 9;
        // untracked host, whitelisted app, prevention on -> Redirect safety chain
        assert_eq!(classify(&c, true, "untracked.net", 443), WfpVerdict::Redirect { chain: 9 });
        // inverse: prevention off -> Permit
        c.settings.ip_leak_prevention = false;
        assert_eq!(classify(&c, true, "untracked.net", 443), WfpVerdict::Permit);
    }

    #[test]
    fn explicit_direct_rule_wins() {
        let mut c = cfg();
        c.rules.push(Rule {
            id: 2, name: "lan".into(), enabled: true, priority: 50,
            app: None, host: Some("lan.host".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Direct,
        });
        // higher-priority Direct rule overrides the catch semantics
        assert_eq!(classify(&c, true, "lan.host", 443), WfpVerdict::Permit);
    }

    #[test]
    fn app_scoped_rules_are_skipped_by_callout() {
        let mut c = cfg();
        c.rules.push(Rule {
            id: 3, name: "chrome-only".into(), enabled: true, priority: 100,
            app: Some("chrome.exe".into()), host: Some("*.example.com".into()), port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 9 },
        });
        // A callout can't match app paths, so app-scoped rules are ignored; the
        // unscoped id:1 rule (lower priority) still applies here.
        assert_eq!(classify(&c, true, "a.example.com", 443), WfpVerdict::Redirect { chain: 9 });
    }

    #[test]
    fn port_scoped_rule() {
        let mut c = cfg();
        c.rules.push(Rule {
            id: 4, name: "only8080".into(), enabled: true, priority: 100,
            app: None, host: Some("*".into()), port: Some("8080".into()),
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 9 },
        });
        // id:1 (*.example.com) doesn't match example.org; id:4 matches only on 8080.
        assert_eq!(classify(&c, true, "example.org", 8080), WfpVerdict::Redirect { chain: 9 });
        assert_eq!(classify(&c, true, "example.org", 443), WfpVerdict::Permit);
    }

    // The WFP callout verdict must AGREE with the already-verified driverless
    // rules::decide on app-less configs (the driverless path passes app=None so
    // app-scoped rules are skipped there too) — otherwise the two engines would
    // route the same connection differently.
    #[test]
    fn agrees_with_rules_decide() {
        use crate::rules::{decide, Decision};
        let mut c = cfg();
        c.settings.app_whitelist_enabled = true;
        c.settings.ip_leak_prevention = true;
        c.settings.ip_leak_default_chain = 9;
        // no app-scoped rules (callout skips them; keep them aligned):
        c.rules.retain(|r| r.app.is_none());

        // whitelist DISABLED path (app_whitelisted=true) must equal decide(app=None)
        // for every probe host: but with whitelist ENABLED, decide(app=None) treats
        // unknown app as "not in whitelist" => Direct, while classify uses the passed
        // bool. Compare only the whitelist-disabled configuration to avoid that
        // intentional difference.
        let mut c2 = c.clone();
        c2.settings.app_whitelist_enabled = false;
        let hosts = ["a.example.com", "untracked.net", "localhost", "example.org"];
        for h in hosts {
            for port in [80u16, 443, 8080] {
                let cls = classify(&c2, true, h, port);
                let dec = decide(&c2, None, h, port);
                let same = match (&cls, &dec) {
                    (WfpVerdict::Redirect { chain: a }, Decision::Proxy { chain: b, .. }) => a == b,
                    (WfpVerdict::Permit, Decision::Direct { .. }) => true,
                    (WfpVerdict::Block, Decision::Block { .. }) => true,
                    _ => false,
                };
                assert!(same, "divergence for {h}:{port}: classify={cls:?} decide={dec:?}");
            }
        }
    }

    #[test]
    fn proxification_pause_never_redirects() {
        let mut c = cfg();
        c.settings.proxification_enabled = false;
        // The redirect rule (id:1 *.example.com -> chain 9) must not fire when paused.
        assert_eq!(classify(&c, true, "a.example.com", 443), WfpVerdict::Permit);
    }
    /// The C driver asserts a byte layout with C_ASSERT; the Rust side produces that
    /// layout in to_bytes/from_bytes. Compare THE BYTES, not offset_of: this struct is
    /// deliberately not `repr(C)` (nothing transmutes it), so field order in memory is
    /// the compiler's business — the wire layout is what both sides must agree on.
    #[test]
    fn the_c_driver_and_rust_agree_on_every_record_offset() {
        // Distinct value per field, so a byte range identifies the field unambiguously.
        let mut r = FlowRecord::default();
        r.family = 0xAABB;                 // 4
        r.port_be = 443u16.to_be();         // 6: the wire octets must be 01 BB
        r.addr = [0xE1; 16];                // 8..24
        r.pid = 0x11223344;                 // 24
        r.chain = 0x55667788;               // 28
        r.verdict = 0x9A;                   // 32
        r.proto = 0x9B;                     // 33
        r.token_port = 0x9C9D;              // 34
        r.flow_id = 0x0F0E0D0C0B0A0908;     // 40
        r.local_addr = [0xF2; 16];          // 48..64
        r.local_port_be = 80u16.to_be();    // 64: 00 50 on the wire
        let b = r.to_bytes();
        assert_eq!(b.len(), FLOW_RECORD_LEN);
        assert_eq!(&b[0..4], &FLOW_RECORD_MAGIC.to_le_bytes(), "magic at 0");
        assert_eq!(&b[4..6], &0xAABBu16.to_le_bytes(), "family");
        // 443 on the wire is 0x01 0xBB. This is the octet order a SOCKADDR carries in
        // memory and therefore what the C driver writes; a to_be_bytes() here would put
        // 0xBB 0x01 and every redirected flow would dial port 47873.
        assert_eq!(&b[6..8], &[0x01, 0xBB], "port octets match the C driver's sin_port");
        assert_eq!(&b[8..24], &[0xE1; 16], "addr");
        assert_eq!(&b[24..28], &0x11223344u32.to_le_bytes(), "pid");
        assert_eq!(&b[28..32], &0x55667788u32.to_le_bytes(), "chain");
        assert_eq!(b[32], 0x9A, "verdict");
        assert_eq!(b[33], 0x9B, "proto");
        assert_eq!(&b[34..36], &0x9C9Du16.to_le_bytes(), "tokenPort");
        assert_eq!(&b[40..48], &0x0F0E0D0C0B0A0908u64.to_le_bytes(), "flowId");
        assert_eq!(&b[48..64], &[0xF2; 16], "localAddr");
        assert_eq!(&b[64..66], &[0x00, 0x50], "local port octets too");

        // every offset the C source asserts must appear in this list, in agreement
        let asserted = c_record_offsets(C_DRIVER);
        let expect: &[(&str, usize)] = &[
            ("family", 4), ("portBe", 6), ("addr", 8), ("pid", 24), ("chain", 28),
            ("verdict", 32), ("proto", 33), ("tokenPort", 34), ("flowId", 40),
            ("localAddr", 48), ("localPortBe", 64),
        ];
        assert!(
            asserted.len() >= expect.len(),
            "the driver source lost layout assertions (found {})",
            asserted.len()
        );
        for (name, off) in expect {
            let found = asserted.iter().find(|(n, _)| n == name);
            match found {
                Some((_, c_off)) => assert_eq!(c_off, off, "field {name}: C says {c_off}, Rust writes byte {off}"),
                None => panic!("no C_ASSERT for {name} — add one or the two sides can drift"),
            }
        }
        assert!(C_DRIVER.contains("C_ASSERT(sizeof(TP_FLOW_RECORD) == 72)"), "the C side must pin the total size too");
        // and the round-trip reads back exactly what we wrote
        assert_eq!(FlowRecord::from_bytes(&b), Some(r));
    }

    /// One golden 72-byte buffer, asserted identically here and in
    /// driver_wfp/test_record.c. If either side changes its encoding, one of the two
    /// fails — which is the only defence against the service reading a destination port
    /// or address that the driver never wrote.
        ///
    /// The 72 bytes the DRIVER'S OWN classify callback produced, captured by running
    /// `driver_wfp/test_classify.c` on 2026-11-25 (that file asserts the same buffer
    /// byte for byte). Bytes 34..36 — the token port — are zeroed on both sides because
    /// they depend on where the round-robin pool happened to be.
    ///
    /// This is the cross-language contract as an execution result rather than two
    /// readings of the same idea: whatever the kernel stashes in
    /// `localRedirectContext`, `from_bytes` here must turn into the right destination,
    /// pid and protocol. If the C layout changes, one of the two tests fails.
    const C_CLASSIFY_RECORD_V4: [u8; 72] = [
            0x46, 0x58, 0x52, 0x50, 0x02, 0x00, 0x01, 0xbb, 0x5d, 0xb8, 0xd8, 0x22,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x0f, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xc8, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// The IPv6 sibling of the v4 vector above: the classify path's own bytes for a
    /// 2001:db8::5:443 flow from pid 3579 on a socket whose local end was ::1:51333.
    /// Family, the placement of a 16-byte address, and both wire-order ports must agree
    /// with the C, or every IPv6 app would be dialled at the wrong place.
    const C_CLASSIFY_RECORD_V6: [u8; 72] = [
            0x46, 0x58, 0x52, 0x50, 0x17, 0x00, 0x01, 0xbb, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
            0xfb, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0xc8, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn the_v6_record_the_driver_produced_decodes_to_the_right_destination() {
        let r = FlowRecord::from_bytes(&C_CLASSIFY_RECORD_V6).expect("the driver's v6 bytes must decode");
        assert_eq!(r.family, 23, "AF_INET6 as Winsock numbers it");
        assert_eq!(&r.addr[..4], &[0x20, 0x01, 0x0d, 0xb8], "2001:db8:: starts here");
        assert_eq!(r.addr[15], 0x05, "...and the interface id sits at the END of 16 bytes");
        assert_eq!(&r.addr[4..15], &[0u8; 11], "the compression zeros stay zero");
        assert_eq!(r.port_be, 443u16.to_be());
        assert_eq!(r.pid, 3579);
        assert_eq!(r.proto, 6);
        assert_eq!(r.verdict, VERDICT_REDIRECT);
        assert_eq!(r.local_addr[15], 1, "the original local endpoint was ::1");
        assert_eq!(r.local_port_be, 51333u16.to_be(), "v6 local port in wire order too");
        assert_eq!(
            r.remote(),
            Some("[2001:db8::5]:443".parse().unwrap()),
            "this is the destination the engine must dial through the proxy"
        );
    }

    #[test]
    fn the_record_the_driver_actually_produced_decodes_correctly() {
        let r = FlowRecord::from_bytes(&C_CLASSIFY_RECORD_V4).expect("the driver's bytes must decode");
        assert_eq!(r.family, 2, "AF_INET");
        assert_eq!(r.port_be, 443u16.to_be(), "the ORIGINAL port stays in wire order");
        assert_eq!(&r.addr[..4], &[93, 184, 216, 34], "the ORIGINAL address, 93.184.216.34");
        assert_eq!(&r.addr[4..], &[0u8; 12], "v4 leaves the rest of the 16 bytes zero");
        assert_eq!(r.pid, 9999, "the connecting process, from the ALE metadata");
        assert_eq!(r.verdict, VERDICT_REDIRECT);
        assert_eq!(r.proto, 6);
        assert_eq!(r.chain, 0, "left to the service to choose");
        assert_eq!(r.flow_id, 0, "the builder does not fill it, and that is deliberate");
        assert_eq!(&r.local_addr[..4], &[192, 168, 1, 5], "the original local endpoint");
        assert_eq!(r.local_port_be, 51234u16.to_be());
        assert_eq!(r.remote(), Some("93.184.216.34:443".parse().unwrap()),
                   "which is what the engine dials through the proxy");
    }


#[test]
    fn record_matches_the_shared_golden_bytes() {
        let mut r = FlowRecord::default();
        r.family = 2;
        r.port_be = 443u16.to_be();
        r.addr = [198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        r.pid = 4242;
        r.chain = 7;
        r.verdict = VERDICT_REDIRECT;
        r.proto = 6;
        r.token_port = 12000;
        r.flow_id = 0xDEAD_BEEF_0000_0001;
        r.local_addr = [192, 168, 1, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        r.local_port_be = 80u16.to_be();
        #[rustfmt::skip]
        // 4242 = 0x1092 → 92 10; 12000 = 0x2EE0 → E0 2E; 443 → 01 BB; 80 → 00 50
        const GOLDEN: [u8; 72] = [
            0x46, 0x58, 0x52, 0x50,  0x02, 0x00, 0x01, 0xBB,
            0xC6, 0x33, 0x64, 0x14,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            0x92, 0x10, 0x00, 0x00,  0x07, 0x00, 0x00, 0x00,
            0x01, 0x06, 0xE0, 0x2E,  0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00,  0xEF, 0xBE, 0xAD, 0xDE,
            0xC0, 0xA8, 0x01, 0x05,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            0x00, 0x50, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(r.to_bytes(), GOLDEN, "wire format drifted from the shared golden buffer");
        assert_eq!(FlowRecord::from_bytes(&GOLDEN), Some(r), "and must decode back identically");
    }

    #[test]
    fn flow_record_round_trips_and_rejects_garbage() {
        let r = FlowRecord {
            family: 23,
            port_be: 443u16.to_be(),
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5],
            pid: 4321,
            chain: 9,
            verdict: VERDICT_REDIRECT,
            proto: 17,
            flow_id: 0xDEAD_BEEF_0000_0001,
            local_addr: [0u8; 16],
            local_port_be: 80u16.to_be(),
            token_port: 0,
        };
        let bytes = r.to_bytes();
        assert_eq!(bytes.len(), FLOW_RECORD_LEN);
        assert_eq!(FlowRecord::from_bytes(&bytes), Some(r));
        assert_eq!(
            r.remote(),
            Some("[2001:db8::5]:443".parse().unwrap()),
            "the original destination must be recoverable from the record"
        );
        // A zeroed slot (never written by the driver) and a short buffer are both
        // rejected rather than read as a flow to 0.0.0.0:0.
        assert_eq!(FlowRecord::from_bytes(&[0u8; FLOW_RECORD_LEN]), None);
        assert_eq!(FlowRecord::from_bytes(&bytes[..71]), None);
        let mut v4 = r;
        v4.family = 2;
        v4.addr = [198, 51, 100, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(v4.remote(), Some("198.51.100.7:443".parse().unwrap()));
        v4.family = 99;
        assert_eq!(v4.remote(), None);
    }

    #[test]
    fn flow_record_bytes_are_pinned_so_the_driver_can_memcpy() {
        // Field offsets are part of the kernel ABI: a reordering must break here.
        let mut r = FlowRecord::default();
        r.verdict = VERDICT_BLOCK;
        r.proto = 6;
        let b = r.to_bytes();
        assert_eq!(&b[0..4], &FLOW_RECORD_MAGIC.to_le_bytes());
        assert_eq!(b[32], VERDICT_BLOCK);
        assert_eq!(b[33], 6);
        assert_eq!(&b[36..40], &[0; 4], "padding stays zero so the record is comparable");
    }
}
