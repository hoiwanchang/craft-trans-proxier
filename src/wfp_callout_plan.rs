//! Reference model of what a WFP redirect callout must DECIDE and WRITE.
//!
//! Why this lives in the user-mode crate instead of only inside the driver: the
//! dangerous part of a callout is not the kernel plumbing, it is the byte-level
//! output — the sockaddr written into `FWPS_CONNECT_REQUEST0.remoteAddressAndPort`
//! (network-order port, correct address family, correct length) and the
//! `localRedirectContext` the proxy later reads back. A mistake there is silent:
//! the connection goes somewhere wrong, or WFP rejects the redirect and traffic
//! black-holes. So the decision and the encoding are written and TESTED here,
//! against the documented field layouts, and `driver_wfp/tpdrv_wfp.c` implements
//! exactly this plan in C (where the WDK's own `fwpsk.h` type-checks the plumbing).
//!
//! Field indices: `Windows Kits/10/Include/10.0.26100.0/um/fwpsu.h`, enums
//! `FWPS_FIELDS_ALE_CONNECT_REDIRECT_V4` / `_V6` (identical numbering).
//! Struct/field semantics: `FWPS_CONNECT_REQUEST0` (fwpsk.h DDI) and
//! "Using Bind or Connect Redirection".

use crate::config::Config;
use crate::wfp_classify::{self, WfpVerdict};

/// Index into `FWPS_INCOMING_VALUES0.incomingValue[]` for the ALE redirect layers.
/// The V4 and V6 enums number these identically (fwpsu.h).
pub mod field {
    pub const ALE_APP_ID: usize = 0;
    pub const ALE_USER_ID: usize = 1;
    pub const IP_LOCAL_ADDRESS: usize = 2;
    pub const IP_LOCAL_ADDRESS_TYPE: usize = 3;
    pub const IP_LOCAL_PORT: usize = 4;
    pub const IP_PROTOCOL: usize = 5;
    pub const IP_REMOTE_ADDRESS: usize = 6;
    pub const IP_DESTINATION_ADDRESS_TYPE: usize = 7;
    pub const IP_REMOTE_PORT: usize = 8;
    pub const FLAGS: usize = 9;
}

/// AF_INET / AF_INET6 as Winsock defines them.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;
/// `sizeof(SOCKADDR_IN)` / `sizeof(SOCKADDR_IN6)`, the lengths the driver writes.
pub const SOCKADDR_IN_LEN: usize = 16;
pub const SOCKADDR_IN6_LEN: usize = 28;

/// What the classify callback saw, already dereferenced (no pointers here so the
/// logic can be tested on the host).
/// The only two transports this engine can carry: SOCKS5/HTTP CONNECT are stream, and
/// the UDP path is a SOCKS5 UDP ASSOCIATE.
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowFacts {
    pub pid: u32,
    /// Address family of the ORIGINAL remote endpoint.
    pub family: u16,
    /// Original remote address: 4 bytes for AF_INET (rest zero), 16 for AF_INET6.
    pub remote: [u8; 16],
    /// Original remote port, network byte order, as it arrived.
    pub remote_port_be: u16,
    /// The socket's local address/port at classify time.
    pub local: [u8; 16],
    pub local_port_be: u16,
    /// IPPROTO_TCP / IPPROTO_UDP.
    pub proto: u8,
    /// `FwpsQueryConnectionRedirectState0` said we redirected this flow already, or
    /// that we are the local redirect target. Without this check the callout
    /// redirects its own proxy connection forever.
    pub redirected_by_self: bool,
    /// Another callout already redirected the flow.
    pub redirected_by_other: bool,
    /// The app is connecting to a loopback address (its own local proxy / stub
    /// resolver). Microsoft: "If the connection is to a local proxy, your callout
    /// driver shouldn't attempt to redirect it."
    pub remote_is_loopback: bool,
    /// Whether the engine still allows this callout to change the action
    /// (`classifyOut->rights & FWPS_RIGHT_ACTION_WRITE`). An earlier callout may have
    /// taken that right away, and redirecting anyway is how filter products stop
    /// coexisting. Modelled explicitly because the driver checks it first.
    pub may_modify_action: bool,
    /// Outgoing interface LUID, copied verbatim into the redirect request.
    pub interface_luid: [u8; 8],
}

/// The instruction set the driver executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// Leave the connection alone (returns FWP_ACTION_PERMIT).
    Permit,
    /// Refuse it (returns FWP_ACTION_BLOCK).
    Block,
    Redirect {
        /// The engine's loopback listener this flow is sent to; also the key the
        /// proxy uses to find the flow again.
        token_port: u16,
        /// Bytes for `remoteAddressAndPort`, including the 2-byte family and the
        /// network-order port — the part that must not be improvised.
        sockaddr: Vec<u8>,
        /// Bytes for `localRedirectContext` (a FlowRecord): WFP owns and frees this
        /// buffer when the flow dies, so the driver must hand it freshly allocated
        /// memory of exactly this size.
        context: Vec<u8>,
    },
}

/// The redirect target for a token port: loopback in the SAME family as the
/// original destination (an IPv6 flow must not be pointed at a v4 sockaddr).
pub fn sockaddr_loopback(family: u16, token_port: u16) -> Vec<u8> {
    let port = token_port.to_be_bytes();
    match family {
        AF_INET6 => {
            let mut b = Vec::with_capacity(SOCKADDR_IN6_LEN);
            b.extend_from_slice(&AF_INET6.to_le_bytes());
            b.extend_from_slice(&port);
            b.extend_from_slice(&0u32.to_le_bytes()); // sin6_flowinfo
            b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // ::1
            b.extend_from_slice(&0u32.to_le_bytes()); // sin6_scope_id
            b
        }
        _ => {
            let mut b = Vec::with_capacity(SOCKADDR_IN_LEN);
            b.extend_from_slice(&AF_INET.to_le_bytes());
            b.extend_from_slice(&port);
            b.extend_from_slice(&[127, 0, 0, 1]);
            b.extend_from_slice(&[0u8; 8]); // sin_zero
            b
        }
    }
}

/// Decide what to do with one connect. `tokens` is the free-token pool the user
/// service handed the driver; `chain` is what the profile says for this flow.
pub fn plan(
    config: &Config,
    app_whitelisted: bool,
    host: &str,
    facts: &FlowFacts,
    tokens: &[u16],
) -> Call {
    // No right to modify the action ⇒ nothing we return would be honoured; leave the
    // flow exactly as the previous callouts decided (matches WFPSampler's guard).
    if !facts.may_modify_action {
        return Call::Permit;
    }
    // Anti-loop comes next: it is a correctness requirement, not a policy choice.
    // Re-redirecting our own proxy egress either loops forever or black-holes it.
    if facts.redirected_by_self || facts.remote_is_loopback {
        return Call::Permit;
    }
    // Only transports we can actually deliver. The ALE field is indicated as
    // FWP_UINT8; anything else — ICMP, GRE, or a field we could not read — has no
    // egress in SOCKS4/5 or HTTP CONNECT, and redirecting it would hand the app's
    // packets to a TCP or UDP token listener, i.e. corrupt a flow that was working.
    // Permitting it is also what the driverless hook does for these protocols.
    if facts.proto != IPPROTO_TCP && facts.proto != IPPROTO_UDP {
        return Call::Permit;
    }
    if let Some(t) = tokens.first() {
        // A redirect also has to be *useful*: if the profile would not have
        // proxied this flow anyway, leave it alone rather than hairpin it.
        match wfp_classify::classify(config, app_whitelisted, host, u16::from_be(facts.remote_port_be)) {
            WfpVerdict::Redirect { .. } | WfpVerdict::Block => {}
            WfpVerdict::Permit => return Call::Permit,
        }
        let context = context_for(facts, *t).to_bytes().to_vec();
        return Call::Redirect {
            token_port: *t,
            sockaddr: sockaddr_loopback(facts.family, *t),
            context,
        };
    }
    // No token available: we cannot carry the original destination anywhere, so
    // permit rather than block — a busy pool must not become an outage. (The
    // alternative, dropping, is what a mis-tuned pool would do to the machine.)
    Call::Permit
}

/// The `localRedirectContext` payload: the FlowRecord the proxy will read back via
/// `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`.
fn context_for(facts: &FlowFacts, token_port: u16) -> wfp_classify::FlowRecord {
    wfp_classify::FlowRecord {
        family: facts.family,
        port_be: facts.remote_port_be,
        addr: facts.remote,
        pid: facts.pid,
        // The chain is chosen by the proxy from the profile; the driver only needs
        // to route the flow, so it records what the classify pass decided if known.
        chain: 0,
        verdict: wfp_classify::VERDICT_REDIRECT,
        proto: facts.proto,
        flow_id: 0,
        local_addr: facts.local,
        local_port_be: facts.local_port_be,
        token_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Chain, ProxyKind, ProxyServer, Rule, RuleAction, RuleProtocol, Settings};

    fn cfg_proxy_all() -> Config {
        let mut c = Config {
            settings: Settings { dns_mode: crate::config::DnsMode::Proxy, ..Settings::default() },
            ..Config::default()
        };
        c.proxies.push(ProxyServer {
            id: 1,
            name: "s".into(),
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            timeout_secs: 3,
        });
        c.chains.push(Chain { id: 1, name: "c".into(), proxies: vec![1] });
        c.rules.push(Rule {
            id: 1,
            name: "all".into(),
            enabled: true,
            priority: 1,
            app: None,
            host: Some("*".into()),
            port: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Proxy { chain: 1 },
        });
        c
    }

    fn facts(family: u16, port: u16) -> FlowFacts {
        let mut remote = [0u8; 16];
        if family == AF_INET {
            remote[..4].copy_from_slice(&[93, 184, 216, 34]);
        } else {
            remote = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        }
        FlowFacts {
            pid: 4242,
            family,
            remote,
            remote_port_be: port.to_be(),
            local: [0u8; 16],
            local_port_be: 0,
            proto: 6,
            redirected_by_self: false,
            redirected_by_other: false,
            remote_is_loopback: false,
            may_modify_action: true,
            interface_luid: [0; 8],
        }
    }

    #[test]
    fn ipv4_redirect_sockaddr_is_loopback_with_network_order_port() {
        // 10808 = 0x2A38; the port goes on the wire big-endian, the family little.
        let sa = sockaddr_loopback(AF_INET, 10808);
        assert_eq!(sa.len(), SOCKADDR_IN_LEN);
        assert_eq!(&sa[..2], &[0x02, 0x00]);
        assert_eq!(&sa[2..4], &[0x2A, 0x38]);
        assert_eq!(&sa[4..8], &[127, 0, 0, 1]);
        assert_eq!(&sa[8..], &[0u8; 8]);
    }

    #[test]
    fn ipv6_redirect_sockaddr_keeps_the_address_family() {
        // A v6 flow redirected with a 16-byte v4 sockaddr is silently wrong: the
        // stack reads the family first.
        let sa = sockaddr_loopback(AF_INET6, 443);
        assert_eq!(sa.len(), SOCKADDR_IN6_LEN);
        assert_eq!(&sa[..2], &[0x17, 0x00]);
        assert_eq!(&sa[2..4], &[0x01, 0xBB]);
        assert_eq!(&sa[4..8], &[0, 0, 0, 0], "sin6_flowinfo");
        assert_eq!(sa[23], 1, "::1 in the last byte");
        assert_eq!(&sa[24..], &[0, 0, 0, 0], "sin6_scope_id");
    }

    #[test]
    fn anti_loop_beats_everything_else() {
        let c = cfg_proxy_all();
        let mut f = facts(AF_INET, 443);
        f.redirected_by_self = true;
        assert_eq!(plan(&c, true, "93.184.216.34", &f, &[10808]), Call::Permit);
        let mut g = facts(AF_INET, 443);
        g.remote_is_loopback = true;
        assert_eq!(plan(&c, true, "127.0.0.1", &g, &[10808]), Call::Permit);
    }

    #[test]
    fn a_flow_the_profile_would_not_proxy_is_left_alone() {
        // Same token available, but the rule says this host goes direct.
        let mut c = cfg_proxy_all();
        c.rules.push(Rule {
            id: 2,
            name: "direct-cdn".into(),
            enabled: true,
            priority: 99,
            app: None,
            host: Some("cdn.example".into()),
            port: None,
            protocol: RuleProtocol::Both,
            action: RuleAction::Direct,
        });
        c.settings.dns_mode = crate::config::DnsMode::Local; // so no DNS-policy override
        assert_eq!(plan(&c, true, "cdn.example", &facts(AF_INET, 443), &[10808]), Call::Permit);
    }

    #[test]
    fn redirect_carries_the_original_destination_and_the_token() {
        let c = cfg_proxy_all();
        let f = facts(AF_INET6, 8443);
        let call = plan(&c, true, "2001:db8::1", &f, &[12000, 12001]);
        let Call::Redirect { token_port, sockaddr, context } = call else {
            panic!("expected a redirect, got {call:?}");
        };
        assert_eq!(token_port, 12000, "first free token wins");
        assert_eq!(sockaddr, sockaddr_loopback(AF_INET6, 12000));
        assert_eq!(context.len(), wfp_classify::FLOW_RECORD_LEN);
        let back = wfp_classify::FlowRecord::from_bytes(&context).expect("parses");
        assert_eq!(
            back.remote(),
            Some("[2001:db8::1]:8443".parse().unwrap()),
            "the proxy must recover the ORIGINAL destination from the context"
        );
        assert_eq!(back.pid, 4242);
        assert_eq!(back.token_port, 12000);
        assert_eq!(back.proto, 6);
    }

    #[test]
    fn without_the_write_right_the_callout_defers_to_earlier_decisions() {
        let c = cfg_proxy_all();
        let mut f = facts(AF_INET, 443);
        f.may_modify_action = false;
        assert_eq!(
            plan(&c, true, "93.184.216.34", &f, &[10808]),
            Call::Permit,
            "a callout that cannot modify the action must not pretend to redirect"
        );
    }

    #[test]
    fn an_exhausted_token_pool_permits_rather_than_blackholing() {
        let c = cfg_proxy_all();
        assert_eq!(plan(&c, true, "93.184.216.34", &facts(AF_INET, 443), &[]), Call::Permit);
    }


    /// The driver indexes `incomingValue[]` with `field::IP_PROTOCOL`, so that number is
    /// only safe while it matches the platform's own enum. Re-derive it from the
    /// installed `um/fwpsu.h` when this host has one: a header that reorders these
    /// fields must break a test rather than silently redirect on the wrong value. (The
    /// WDK's `km` set does not ship it; the SDK's `um` copy is the same declaration the
    /// DDI pages describe.)
    #[test]
    fn the_installed_header_still_numbers_ip_protocol_at_our_index() {
        const CANDIDATES: [&str; 2] = [
            r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\fwpsu.h",
            r"C:\Program Files\Windows Kits\10\Include\10.0.26100.0\um\fwpsu.h",
        ];
        let path = match CANDIDATES.iter().find(|p| std::path::Path::new(p).exists()) {
            Some(p) => *p,
            None => {
                eprintln!("skipped: no fwpsu.h here, so field::{n} is unverified on this host",
                          n = "IP_PROTOCOL");
                return;
            }
        };
        let raw = std::fs::read(path).expect("read fwpsu.h");
        let text = if raw.starts_with(&[0xFF, 0xFE]) || raw.get(1) == Some(&0) {
            let units: Vec<u16> = raw[if raw.starts_with(&[0xFF, 0xFE]) { 2 } else { 0 }..]
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&raw).into_owned()
        };

        for enum_name in ["_V4", "_V6"] {
            let head = format!("FWPS_FIELDS_ALE_CONNECT_REDIRECT{enum_name}");
            let start = text.find(&head).unwrap_or_else(|| panic!("{head} absent from {path}"));
            let mut index = 0usize;
            let mut found: Option<usize> = None;
            for line in text[start..].lines().skip(1) {
                let t = line.trim();
                if t.starts_with('}') {
                    break; // end of the enum without seeing the field
                }
                let Some(name) = t.split([' ', ',', '=', '\t']).find(|w| w.starts_with("FWPS_FIELD_"))
                else { continue };
                if name.ends_with("_IP_PROTOCOL") {
                    found = Some(index);
                    break;
                }
                // honour an explicit `= N` as well as implicit numbering
                match t.split_once('=') {
                    Some((_, rhs)) => {
                        if let Ok(n) = rhs.trim().trim_end_matches(',').trim().parse::<usize>() {
                            index = n;
                            continue;
                        }
                        index += 1;
                        continue;
                    }
                    None => index += 1,
                }
            }
            assert_eq!(found, Some(field::IP_PROTOCOL), "{head}: IP_PROTOCOL is no longer where the driver indexes it");
        }
    }

    #[test]
    fn icmp_is_permitted_rather_than_handed_to_a_tcp_listener() {
        // The profile says proxy; the transport says we cannot carry it. The transport
        // wins, because the alternative is delivering ICMP echo packets to a socket that
        // will read them as a proxifier handshake and corrupt a flow that was working.
        let c = cfg_proxy_all();
        let tcp = facts(AF_INET, 443);
        assert_eq!(tcp.proto, IPPROTO_TCP, "the helper builds a TCP flow");
        assert!(matches!(plan(&c, true, "198.51.100.7", &tcp, &[12000]), Call::Redirect { .. }),
                "TCP must still redirect, or this test proves nothing");

        let mut udp = facts(AF_INET, 53);
        udp.proto = IPPROTO_UDP;
        assert!(matches!(plan(&c, true, "198.51.100.7", &udp, &[12000]), Call::Redirect { .. }),
                "UDP must still redirect too");

        // 1 = ICMP, 47 = GRE, 50/58 = ESP/AHv6, 0 and 0xFF = unreadable/empty field
        for proto in [1u8, 47, 50, 58, 0, 0xFF] {
            let mut other = facts(AF_INET, 443);
            other.proto = proto;
            assert!(matches!(plan(&c, true, "198.51.100.7", &other, &[12000]), Call::Permit),
                    "proto {proto} must be left to the rest of the stack");
        }
    }

}
