//! DNS fake-IP virtualisation — the engine side of the original's "DNS-UDP fake IP"
//! model (fnd_10).
//!
//! In transparent mode the injected hook only ever sees the numeric destination
//! that the application dialed, so a hostname rule (`*.example.com`) can never
//! match. A fake-IP pool breaks that: a name is mapped to a synthetic address
//! from a reserved block; the application then connects to that address, and the
//! pool maps it back to the real name for rule matching and for remote (SOCKS5
//! hostname) resolution at the egress.
//!
//! This module is pure logic and concurrency-safe (no sockets): the ALLOCATION
//! side is what a DNS hook hands back to the app, and the REVERSE side is what
//! the decision path uses to recover the hostname. The synthetic block is the
//! RFC 2544 benchmarking range 198.18.0.0/15 — the same space TUN-style proxies
//! use — so a fake address never collides with a real route.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// First usable address of the synthetic block (198.18.0.1).
pub const DEFAULT_POOL_BASE: [u8; 4] = [198, 18, 0, 1];
/// Number of synthetic addresses (198.18.0.0/15 holds 131072; keep it modest).
pub const DEFAULT_POOL_SIZE: usize = 0x0000_8000; // 32768

fn pack(o: [u8; 4]) -> u32 {
    u32::from_be_bytes(o)
}

#[derive(Debug)]
struct Inner {
    base: u32,
    size: u32,
    forward: HashMap<String, Ipv4Addr>, // name (normalised) -> fake ip
    reverse: HashMap<Ipv4Addr, String>, // fake ip -> name
    order: VecDeque<Ipv4Addr>,          // insertion order, for FIFO eviction
    cursor: u32,                        // next slot index to try
    /// Addresses seen in DNS ANSWERS we proxied, mapped back to the name they were
    /// returned for — with the expiry the record itself asked for. This is what lets
    /// hostname rules match a connection the app opened by IP (see `observed_name`).
    observed: HashMap<IpAddr, (String, std::time::Instant)>,
    observed_order: VecDeque<IpAddr>,
}

/// Thread-safe bidirectional name<->fake-IP table with FIFO eviction.
#[derive(Debug)]
pub struct FakeIpPool {
    inner: Mutex<Inner>,
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Normalise a hostname the way the rule matcher does: lowercase, no trailing dot.
fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl FakeIpPool {
    /// A pool over the default 198.18.0.1 / 32768-address synthetic block.
    pub fn new() -> Self {
        Self::with_block(DEFAULT_POOL_BASE, DEFAULT_POOL_SIZE)
    }

    /// A pool over an explicit synthetic block (used by tests + future tuning).
    pub fn with_block(base: [u8; 4], size: usize) -> Self {
        FakeIpPool {
            inner: Mutex::new(Inner {
                base: pack(base),
                size: size.max(1) as u32,
                forward: HashMap::new(),
                reverse: HashMap::new(),
                order: VecDeque::new(),
                cursor: 0,
                observed: HashMap::new(),
                observed_order: VecDeque::new(),
            }),
        }
    }

    fn ip_at(p: &Inner, idx: u32) -> Ipv4Addr {
        Ipv4Addr::from((p.base + idx) as u32)
    }

    /// Map `name` to a fake IPv4 address. Idempotent: a name keeps its address
    /// until it is evicted. When the block is full, the oldest mapping is
    /// recycled (FIFO) so the pool is bounded and can never grow unbounded.
    pub fn allocate(&self, name: &str) -> Ipv4Addr {
        let name = normalise(name);
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&ip) = p.forward.get(&name) {
            return ip;
        }
        let ip = if (p.forward.len() as u32) < p.size {
            // A free slot exists — scan forward for it.
            loop {
                let cand = Self::ip_at(&p, p.cursor);
                p.cursor = (p.cursor + 1) % p.size;
                if !p.reverse.contains_key(&cand) {
                    break cand;
                }
            }
        } else {
            // Full — recycle the oldest entry.
            let old = p.order.pop_front().expect("pool reported full but order empty");
            if let Some(evicted) = p.reverse.remove(&old) {
                p.forward.remove(&evicted);
            }
            old
        };
        p.forward.insert(name.clone(), ip);
        p.reverse.insert(ip, name);
        p.order.push_back(ip);
        ip
    }

    /// Reverse a fake address back to its hostname, if the pool manages it.
    pub fn resolve(&self, ip: Ipv4Addr) -> Option<String> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.reverse.get(&ip).cloned()
    }

    /// Cap on the observed-answer table: a long-running engine sees a lot of DNS,
    /// and an unbounded map here would be a slow leak. Oldest-first eviction.
    pub const OBSERVED_CAP: usize = 4096;

    /// Learn the names behind the addresses in a DNS response we carried.
    ///
    /// Returns how many address↔name pairs were stored. This is deliberately
    /// passive: we only look at replies that were already going to the app through
    /// our own tunnel, we never ask a resolver anything here, and a malformed or
    /// hostile message is dropped by `net_dns::snoop_answers` rather than trusted.
    pub fn observe_dns_response(&self, msg: &[u8]) -> usize {
        let pairs = match crate::net_dns::snoop_answers(msg) {
            Ok(p) => p,
            Err(_) => return 0,
        };
        let now = std::time::Instant::now();
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut stored = 0;
        for (name, ip, ttl) in pairs {
            if name.is_empty() {
                continue;
            }
            // Never let an answer overwrite a fake-IP mapping we handed out: those
            // are the pool's own addresses and the reverse map there is authoritative.
            if let IpAddr::V4(v4) = ip {
                if p.reverse.contains_key(&v4) {
                    continue;
                }
            }
            // RFC 1035: a 0 TTL means "do not cache". And an absurd one is capped so a
            // hostile server cannot pin entries for a lifetime.
            if ttl == 0 {
                continue;
            }
            let secs = ttl.min(86_400) as u64;
            let name = normalise(&name);
            if !p.observed.contains_key(&ip) && p.observed.len() >= Self::OBSERVED_CAP {
                if let Some(old) = p.observed_order.pop_front() {
                    p.observed.remove(&old);
                }
            }
            p.observed.insert(ip, (name, now + std::time::Duration::from_secs(secs)));
            if let Some(pos) = p.observed_order.iter().position(|&x| x == ip) {
                p.observed_order.remove(pos);
            }
            p.observed_order.push_back(ip);
            stored += 1;
        }
        // Opportunistic expiry: cheap (the table is small and capped) and it keeps
        // stale names from matching long after the record died.
        p.observed.retain(|_, (_, exp)| *exp > now);
        // keep the FIFO index in step with the table (mem::take side-steps the
        // disjoint-field borrow that a closure over p would hit)
        let live = std::mem::take(&mut p.observed);
        p.observed_order.retain(|ip| live.contains_key(ip));
        p.observed = live;
        stored
    }

    /// The name an address was most recently handed out as, if still within its TTL.
    pub fn observed_name(&self, ip: IpAddr) -> Option<String> {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (name, exp) = p.observed.get(&ip)?;
        if *exp > std::time::Instant::now() {
            Some(name.clone())
        } else {
            None
        }
    }

    /// Insert an observation with an explicit expiry (test hook: TTL behaviour would
    /// otherwise need a real sleep).
    #[doc(hidden)]
    pub fn inject_observed(&self, name: &str, ip: IpAddr, expires_in: std::time::Duration) {
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.observed.insert(ip, (normalise(name), std::time::Instant::now() + expires_in));
        p.observed_order.push_back(ip);
    }

    pub fn observed_len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).observed.len()
    }

    /// Is this address one the pool handed out? (A real IP is never "fake".)
    pub fn is_fake(&self, ip: Ipv4Addr) -> bool {
        let p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        p.reverse.contains_key(&ip)
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop a mapping (e.g. when a flow's name changes / explicit invalidation).
    pub fn remove(&self, name: &str) {
        let name = normalise(name);
        let mut p = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ip) = p.forward.remove(&name) {
            p.reverse.remove(&ip);
            p.order.retain(|&x| x != ip);
        }
    }
}

/// Resolve a transparent-mode host for rule matching: if `host` is a fake IP the
/// pool handed out, return the real hostname instead; otherwise return `host`
/// unchanged. This is the single seam that makes hostname-based proxification
/// rules work against an IP-only hook.
pub fn effective_host(pool: &FakeIpPool, host: &str) -> String {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // fake-IP mapping first: it is exact and we created it deliberately
        if let IpAddr::V4(v4) = ip {
            if let Some(name) = pool.resolve(v4) {
                return name;
            }
        }
        // otherwise fall back to what the app's own DNS answer said, which is how a
        // hostname rule can still fire for a connect that arrived by IP address
        if let Some(name) = pool.observed_name(ip) {
            return name;
        }
    }
    host.to_string()
}

/// Should the engine hand this querying app a fake IP for `host`? Only when
/// DNS-through-proxy is ON and the app is one we actually proxify (a whitelisted
/// app, when the whitelist is enabled). Otherwise the app must get a real answer
/// so its direct connections keep working — this is what keeps the getaddrinfo
/// hook fully inert under the default `dns_mode = local`.
pub fn should_virtualize(dns_mode_proxy: bool, whitelist_enabled: bool, app_whitelisted: bool) -> bool {
    dns_mode_proxy && (!whitelist_enabled || app_whitelisted)
}

/// "Block Non A/AAAA Queries if DNS through Proxy" (fnd_10/fnd_13, an IP-leak
/// prevention guard). When DNS is being resolved *through the proxy*, a non-A/
/// AAAA query (MX, TXT, AAAA-only leaks aside — any record type other than the
/// address records) can be used to leak data or bypass the intent, so the original
/// can refuse it. This is the pure decision the DNS-UDP interceptor calls.
///
/// `dns_through_proxy` is false for the local/system-resolver path → no
/// filtering (we don't intercept what we don't resolve).
pub fn dns_query_allowed(qtype: u16, dns_through_proxy: bool, block_non_a_aaaa: bool) -> bool {
    const A: u16 = 1;
    const AAAA: u16 = 28;
    if !dns_through_proxy {
        return true; // not our resolution path — don't touch it
    }
    if qtype == A || qtype == AAAA {
        return true;
    }
    !block_non_a_aaaa
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Rule, RuleAction};
    use crate::rules::{decide, Decision};

    #[test]
    fn allocate_is_idempotent_and_reversible() {
        let pool = FakeIpPool::new();
        let a = pool.allocate("www.Example.com");
        let b = pool.allocate("www.example.com"); // case-insensitive
        assert_eq!(a, b, "same name keeps the same fake address");
        assert_eq!(pool.resolve(a).as_deref(), Some("www.example.com"));
        assert_eq!(a.octets()[0], 198);
        assert_eq!(a.octets()[1], 18);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn distinct_names_get_distinct_addresses() {
        let pool = FakeIpPool::new();
        let a = pool.allocate("one.test");
        let b = pool.allocate("two.test");
        assert_ne!(a, b);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn real_ip_is_not_fake() {
        let pool = FakeIpPool::new();
        pool.allocate("host.test");
        assert!(!pool.is_fake(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(pool.resolve(Ipv4Addr::new(8, 8, 8, 8)), None);
    }

    #[test]
    fn evicts_oldest_when_full() {
        let pool = FakeIpPool::with_block([198, 18, 0, 1], 2);
        let a = pool.allocate("a.test");
        let b = pool.allocate("b.test");
        assert_eq!(pool.len(), 2);
        let c = pool.allocate("c.test");
        assert_eq!(pool.len(), 2, "bounded pool does not grow past its size");
        // `a` was the oldest, so it is evicted and its address recycled for `c`.
        assert_eq!(c, a, "evicted address is reused");
        assert_eq!(pool.resolve(c).as_deref(), Some("c.test"));
        assert_eq!(pool.resolve(b).as_deref(), Some("b.test"));
        assert_eq!(pool.resolve(a).as_deref(), Some("c.test")); // a is now c
        assert_ne!(c, b);
    }

    #[test]
    fn remove_drops_both_directions() {
        let pool = FakeIpPool::new();
        let a = pool.allocate("gone.test");
        pool.remove("GONE.test");
        assert_eq!(pool.resolve(a), None);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn effective_host_maps_fake_ip_back_to_name() {
        let pool = FakeIpPool::new();
        let fake = pool.allocate("api.example.com");
        assert_eq!(effective_host(&pool, &fake.to_string()), "api.example.com");
        // a plain hostname and an unmapped IP pass through untouched
        assert_eq!(effective_host(&pool, "already.a.host"), "already.a.host");
        assert_eq!(effective_host(&pool, "93.184.216.34"), "93.184.216.34");
    }

    #[test]
    fn hostname_rule_matches_once_the_fake_ip_is_reversed() {
        // A config whose ONLY rule matches by hostname. Given the bare IP of a
        // fake address the rule cannot match; given the reversed hostname it can.
        let mut cfg = Config::default();
        cfg.rules.push(Rule {
            id: 1,
            name: "example".into(),
            enabled: true,
            priority: 10,
            app: None,
            host: Some("*.example.com".into()),
            port: None,
            protocol: crate::config::RuleProtocol::Both, action: RuleAction::Proxy { chain: 1 },
        });
        cfg.chains.push(crate::config::Chain { id: 1, name: "c".into(), proxies: vec![1] });
        cfg.proxies.push(crate::config::ProxyServer {
            id: 1,
            name: "p".into(),
            kind: crate::config::ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            port: 1080,
            username: None,
            password: None,
            timeout_secs: 5,
        });

        let pool = FakeIpPool::new();
        let fake = pool.allocate("cdn.example.com");

        // IP-only (no reverse-map): the hostname rule does NOT match -> direct.
        let by_ip = decide(&cfg, None, &fake.to_string(), 443);
        assert!(matches!(by_ip, Decision::Direct { .. }), "fake IP alone must not match a host rule");

        // Reverse-mapped through the pool: the SAME host now matches -> proxy.
        let host = effective_host(&pool, &fake.to_string());
        let by_name = decide(&cfg, None, &host, 443);
        assert!(matches!(by_name, Decision::Proxy { chain: 1, rule: 1 }), "reverse-mapped hostname must proxy");
    }

    #[test]
    fn virtualize_only_under_dns_proxy_and_proxified_app() {
        assert!(!should_virtualize(false, false, false));
        assert!(!should_virtualize(false, true, true), "inverse: dns_mode=local never fakes even if whitelisted");
        // dns_mode=proxy, no whitelist => every app faked.
        assert!(should_virtualize(true, false, false));
        // dns_mode=proxy + whitelist: only whitelisted apps faked.
        assert!(should_virtualize(true, true, true));
        assert!(!should_virtualize(true, true, false), "non-whitelisted app must get a real answer");
    }

    #[test]
    fn block_non_a_aaaa_only_applies_under_proxy_dns() {
        const A: u16 = 1;
        const AAAA: u16 = 28;
        const TXT: u16 = 16;
        const MX: u16 = 15;
        // Not proxied DNS (system resolver) => never filtered, even with block on.
        assert!(dns_query_allowed(TXT, false, true), "inverse: local DNS path doesn't filter");
        // Proxied DNS => address records always allowed.
        assert!(dns_query_allowed(A, true, true));
        assert!(dns_query_allowed(AAAA, true, true));
        // Proxied DNS + block enabled => non-address records refused.
        assert!(!dns_query_allowed(TXT, true, true));
        assert!(!dns_query_allowed(MX, true, true));
        // Proxied DNS + block disabled => passthrough.
        assert!(dns_query_allowed(TXT, true, false));
    }
}

#[cfg(test)]
mod snoop_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    /// A reply for `name` with one A record, in wire order.
    fn a_response(name: &str, ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut m = vec![0u8; 12];
        m[3] = 0x80; // response, no error
        m[5] = 1; // QDCOUNT
        m[7] = 1; // ANCOUNT
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let off = 12u8;
        m.extend_from_slice(&[0xC0, off, 0, 1, 0, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 4]);
        m.extend_from_slice(&ip);
        m
    }

    #[test]
    fn a_proxied_reply_lets_a_hostname_rule_match_a_later_ip_connect() {
        let pool = FakeIpPool::new();
        assert_eq!(pool.observe_dns_response(&a_response("Snooped.Example.COM", [203, 0, 113, 77], 300)), 1);
        // this is the whole point: effective_host no longer hands the matcher an IP
        assert_eq!(
            effective_host(&pool, "203.0.113.77"),
            "snooped.example.com",
            "the observation must be normalised like the rule matcher expects"
        );
        // an address we never saw stays an address
        assert_eq!(effective_host(&pool, "203.0.113.78"), "203.0.113.78");
    }

    #[test]
    fn observations_expire_and_never_shadow_the_fake_pool() {
        let pool = FakeIpPool::new();
        pool.inject_observed("short.live", "203.0.113.80".parse().unwrap(), Duration::from_millis(1));
        assert_eq!(pool.observed_name("203.0.113.80".parse().unwrap()).as_deref(), Some("short.live"));
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(pool.observed_name("203.0.113.80".parse().unwrap()), None, "TTL must be honoured");

        // a fake address the pool handed out is authoritative even if a DNS reply
        // (or a hostile resolver) claims it belongs to some other name
        let fake = pool.allocate("real.name");
        let n = pool.observe_dns_response(&a_response("lied.about", fake.octets(), 3600));
        assert_eq!(n, 0, "the pool's own address must not be re-assigned by an answer");
        assert_eq!(effective_host(&pool, &fake.to_string()), "real.name");
    }

    #[test]
    fn ttl_is_clamped_and_a_zero_record_is_not_cached() {
        let pool = FakeIpPool::new();
        // ttl 0 → not cached at all (RFC 1035), so no sleep is needed to prove it
        assert_eq!(pool.observe_dns_response(&a_response("zero.ttl", [203, 0, 113, 90], 0)), 0);
        assert_eq!(pool.observed_name("203.0.113.90".parse().unwrap()), None);

        // an absurd ttl is capped rather than pinned forever
        pool.observe_dns_response(&a_response("huge.ttl", [203, 0, 113, 91], u32::MAX));
        assert_eq!(pool.observed_name("203.0.113.91".parse().unwrap()).as_deref(), Some("huge.ttl"));
    }

    #[test]
    fn garbage_in_the_reply_is_dropped_not_trusted() {
        let pool = FakeIpPool::new();
        assert_eq!(pool.observe_dns_response(b""), 0);
        assert_eq!(pool.observe_dns_response(&[0u8; 4]), 0);
        // header says one answer, body is nonsense
        let mut junk = vec![0u8; 12];
        junk[3] = 0x80;
        junk[7] = 1;
        junk.extend_from_slice(&[0xC0, 0xFF, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2]);
        assert_eq!(pool.observe_dns_response(&junk), 0);
        assert_eq!(pool.observed_len(), 0);
    }

    #[test]
    fn the_observed_table_stays_bounded() {
        // keep the test quick by checking the order bookkeeping rather than filling
        // 4096 slots: insert past a small number and confirm the FIFO index matches
        let pool = FakeIpPool::new();
        for i in 0..=600u32 {
            let ip = [203, 0, (i >> 8) as u8, (i & 0xFF) as u8];
            pool.observe_dns_response(&a_response("bulk.test", ip, 600));
        }
        assert_eq!(pool.observed_len(), 601);
        assert_eq!(pool.observed_name(IpAddr::V4(Ipv4Addr::new(203, 0, 1, 44))).as_deref(), Some("bulk.test"), "i = 300");
        // re-observing an address already present must not grow the table
        pool.observe_dns_response(&a_response("bulk.test", [203, 0, 1, 44], 600));
        assert_eq!(pool.observed_len(), 601);

        // past the cap, the oldest observations are dropped and the size holds
        for i in 0..(FakeIpPool::OBSERVED_CAP as u32 + 50) {
            let ip = [198, 51, (i >> 8) as u8, (i & 0xFF) as u8];
            pool.observe_dns_response(&a_response("flood.test", ip, 600));
        }
        assert_eq!(pool.observed_len(), FakeIpPool::OBSERVED_CAP, "the table must stay bounded");
        assert_eq!(
            pool.observed_name(IpAddr::V4(Ipv4Addr::new(203, 0, 1, 44))),
            None,
            "the oldest entries are the ones evicted"
        );
        // 601 + 4146 inserts against a 4096 cap evicts the oldest 651, so the tail of
        // the flood must still be there (i = 49 is not: it was evicted too)
        assert!(pool.observed_name(IpAddr::V4(Ipv4Addr::new(198, 51, 16, 33))).is_some(), "newest survive");
    }
}
