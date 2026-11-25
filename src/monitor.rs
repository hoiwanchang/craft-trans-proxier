use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A live/recent proxified connection, matching the original Connection List
/// columns (Application / Remote host / Server / Rule / Sent / Received /
/// Created-Elapsed) — fnd_13.
pub struct ConnInfo {
    pub id: u64,
    pub app: String,
    pub remote: String,
    pub proto: &'static str,
    pub server: String,
    pub rule: String,
    pub created: Instant,
    pub sent: AtomicU64,
    pub recv: AtomicU64,
    pub active: AtomicBool,
    /// Set by the UI's Disconnect to make the relay copy loops stop.
    pub abort: AtomicBool,
}

/// Immutable snapshot for UI rendering.
#[derive(Clone, Debug)]
pub struct ConnRow {
    pub id: u64,
    pub app: String,
    pub remote: String,
    pub proto: &'static str,
    pub server: String,
    pub rule: String,
    pub elapsed_secs: u64,
    pub sent: u64,
    pub recv: u64,
    pub active: bool,
}

const FLOW_CAP: usize = 512;

/// Process basename of an image path (used to match the Application column).
fn app_basename(p: &str) -> String {
    let t = p.trim_end_matches('"');
    match t.rfind(['\\', '/']) {
        Some(i) => t[i + 1..].to_string(),
        None => t.to_string(),
    }
}

/// Case-insensitive substring filter across the shown columns — backs the
/// Connection List "filter" box (fnd_13). An empty/whitespace query matches all.
pub fn conn_filter_matches(row: &ConnRow, query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }
    row.app.to_ascii_lowercase().contains(&q)
        || row.remote.to_ascii_lowercase().contains(&q)
        || row.server.to_ascii_lowercase().contains(&q)
        || row.rule.to_ascii_lowercase().contains(&q)
        || row.proto.to_ascii_lowercase().contains(&q)
}

#[derive(Clone, Debug)]
pub struct LogLine {
    pub time: String,
    pub level: &'static str,
    pub message: String,
}

#[derive(Clone, Debug)]
struct Slot {
    seq: u64,
    line: LogLine,
}

#[derive(Default)]
struct LogState {
    next: u64,
    q: VecDeque<Slot>,
}

const LOG_CAP: usize = 2000;

pub struct Monitor {
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    connections: AtomicU64,
    log: Mutex<LogState>,
    flows: Mutex<Vec<Arc<ConnInfo>>>,
    flow_seq: AtomicU64,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        Monitor {
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            connections: AtomicU64::new(0),
            log: Mutex::new(LogState::default()),
            flows: Mutex::new(Vec::new()),
            flow_seq: AtomicU64::new(1),
        }
    }

    /// Register a new proxified connection and return its handle.
    pub fn open_flow(
        &self,
        app: String,
        remote: String,
        proto: &'static str,
        server: String,
        rule: String,
    ) -> Arc<ConnInfo> {
        let info = Arc::new(ConnInfo {
            id: self.flow_seq.fetch_add(1, Ordering::Relaxed),
            app,
            remote,
            proto,
            server,
            rule,
            created: Instant::now(),
            sent: AtomicU64::new(0),
            recv: AtomicU64::new(0),
            active: AtomicBool::new(true),
            abort: AtomicBool::new(false),
        });
        let mut f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        f.push(Arc::clone(&info));
        // Prune closed flows beyond the cap (keep the most recent).
        if f.len() > FLOW_CAP {
            if let Some(pos) = f.iter().position(|x| !x.active.load(Ordering::Relaxed)) {
                f.remove(pos);
            }
            if f.len() > FLOW_CAP {
                f.remove(0);
            }
        }
        info
    }

    /// Snapshot of the current connections for the UI.
    pub fn flow_rows(&self) -> Vec<ConnRow> {
        let f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        f.iter()
            .map(|c| ConnRow {
                id: c.id,
                app: c.app.clone(),
                remote: c.remote.clone(),
                proto: c.proto,
                server: c.server.clone(),
                rule: c.rule.clone(),
                elapsed_secs: c.created.elapsed().as_secs(),
                sent: c.sent.load(Ordering::Relaxed),
                recv: c.recv.load(Ordering::Relaxed),
                active: c.active.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Only LIVE flows — used by the connection list so it neither clones nor
    /// renders the (potentially hundreds of) closed rows every frame.
    pub fn active_rows(&self) -> Vec<ConnRow> {
        let f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        f.iter()
            .filter(|c| c.active.load(Ordering::Relaxed))
            .map(|c| ConnRow {
                id: c.id,
                app: c.app.clone(),
                remote: c.remote.clone(),
                proto: c.proto,
                server: c.server.clone(),
                rule: c.rule.clone(),
                elapsed_secs: c.created.elapsed().as_secs(),
                sent: c.sent.load(Ordering::Relaxed),
                recv: c.recv.load(Ordering::Relaxed),
                active: true,
            })
            .collect()
    }

    pub fn close_flow(&self, id: u64) -> bool {
        let f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = f.iter().find(|c| c.id == id) {
            c.active.store(false, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Remove a connection row from the list entirely (fnd_13 "&Delete"). The
    /// running relay (if any) keeps its own `Arc<ConnInfo>` and finishes
    /// normally; this only drops the UI row. Returns true if a row was removed.
    pub fn remove_flow(&self, id: u64) -> bool {
        let before: usize;
        let after: usize;
        {
            let mut f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
            before = f.len();
            f.retain(|c| c.id != id);
            after = f.len();
        }
        after < before
    }

    /// Signal a connection to stop (UI Disconnect): sets the abort flag the
    /// relay copy loops check, then marks it closed.
    pub fn abort_flow(&self, id: u64) -> bool {
        let f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = f.iter().find(|c| c.id == id) {
            c.abort.store(true, Ordering::SeqCst);
            c.active.store(false, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Disconnect every *active* connection belonging to `app` (case-insensitive
    /// match on the process basename, the value shown in the Application
    /// column). Returns how many were aborted. the original's per-app "Disconnect".
    pub fn abort_app(&self, app: &str) -> usize {
        let needle = app_basename(app).to_ascii_lowercase();
        let f = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let mut n = 0;
        for c in f.iter() {
            if c.active.load(Ordering::Relaxed) && app_basename(&c.app).eq_ignore_ascii_case(&needle) {
                c.abort.store(true, Ordering::SeqCst);
                c.active.store(false, Ordering::Relaxed);
                n += 1;
            }
        }
        n
    }

    pub fn add_up(&self, n: u64) {
        self.uploaded.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: u64) {
        self.downloaded.fetch_add(n, Ordering::Relaxed);
    }
    pub fn add_connection(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Zero the byte/connection counters (used when a new serve session starts).
    /// The log ring is intentionally left intact so history is preserved.
    pub fn reset_counters(&self) {
        self.uploaded.store(0, Ordering::Relaxed);
        self.downloaded.store(0, Ordering::Relaxed);
        self.connections.store(0, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.uploaded.load(Ordering::Relaxed),
            self.downloaded.load(Ordering::Relaxed),
            self.connections.load(Ordering::Relaxed),
        )
    }

    /// Number of currently-live (not-yet-closed) flows. This is what the status
    /// bar's "连接" should show — `snapshot().2` is a cumulative accept counter
    /// that only the manual servers bump and never decrements.
    pub fn active_count(&self) -> u64 {
        self.flows
            .lock()
            .map(|f| f.iter().filter(|c| c.active.load(Ordering::Relaxed)).count() as u64)
            .unwrap_or(0)
    }

    pub fn log(&self, level: &'static str, message: impl Into<String>) {
        let mut st = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let seq = st.next;
        st.next += 1;
        if st.q.len() >= LOG_CAP {
            st.q.pop_front();
        }
        st.q.push_back(Slot {
            seq,
            line: LogLine {
                time: utc_hms(),
                level,
                message: message.into(),
            },
        });
    }

    /// Returns every line with a sequence number greater than `cursor`, plus the
    /// new cursor. A slow reader may miss lines evicted by the ring cap.
    pub fn since(&self, cursor: u64) -> (Vec<LogLine>, u64) {
        let st = self.log.lock().unwrap_or_else(|e| e.into_inner());
        let out: Vec<LogLine> = st
            .q
            .iter()
            .filter(|s| s.seq >= cursor)
            .map(|s| s.line.clone())
            .collect();
        let new_cursor = st.q.back().map(|s| s.seq + 1).unwrap_or(cursor);
        (out, new_cursor)
    }
}

fn utc_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 86400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate() {
        let m = Monitor::new();
        m.add_up(10);
        m.add_up(5);
        m.add_down(7);
        m.add_connection();
        assert_eq!(m.snapshot(), (15, 7, 1));
    }

    #[test]
    fn log_since_advances_cursor_without_replay() {
        let m = Monitor::new();
        m.log("info", "one");
        m.log("warn", "two");
        let (a, c1) = m.since(0);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].message, "one");
        let (b, _) = m.since(c1);
        assert!(b.is_empty(), "already-seen lines must not replay");
        m.log("info", "three");
        let (c, _) = m.since(c1);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].message, "three");
    }

    #[test]
    fn ring_cap_evicts_oldest() {
        let m = Monitor::new();
        for i in 0..(LOG_CAP + 50) {
            m.log("info", format!("m{i}"));
        }
        let (lines, cur) = m.since(0);
        assert_eq!(lines.len(), LOG_CAP);
        assert_eq!(lines.last().unwrap().message, format!("m{}", LOG_CAP + 49));
        assert_eq!(cur, (LOG_CAP + 50) as u64);
    }

    #[test]
    fn flow_registry_tracks_connections() {
        let m = Monitor::new();
        let c1 = m.open_flow("chrome.exe".into(), "93.1.2.3:443".into(), "TCP", "socks5:1080".into(), "browser".into());
        let c2 = m.open_flow("game.exe".into(), "203.0.113.9:3478".into(), "UDP", "chain #1".into(), "games".into());
        c1.sent.fetch_add(100, Ordering::Relaxed);
        c1.recv.fetch_add(250, Ordering::Relaxed);
        let rows = m.flow_rows();
        assert_eq!(rows.len(), 2);
        let r1 = rows.iter().find(|r| r.id == c1.id).unwrap();
        assert_eq!((r1.sent, r1.recv), (100, 250));
        assert!(r1.active);
        assert_eq!(r1.app, "chrome.exe");
        // close one, verify the other is still active and close returns false for unknown id.
        assert!(m.close_flow(c1.id));
        assert!(!m.close_flow(999999));
        let rows = m.flow_rows();
        assert!(!rows.iter().find(|r| r.id == c1.id).unwrap().active);
        assert!(rows.iter().find(|r| r.id == c2.id).unwrap().active);
    }

    #[test]
    fn active_count_is_live_flows_not_cumulative() {
        let m = Monitor::new();
        let a = m.open_flow("a.exe".into(), "h:1".into(), "TCP", "s".into(), "r".into());
        let b = m.open_flow("b.exe".into(), "h:2".into(), "TCP", "s".into(), "r".into());
        assert_eq!(m.active_count(), 2, "two live flows");
        m.close_flow(b.id);
        assert_eq!(m.active_count(), 1, "closing one drops the live count");
        m.close_flow(a.id);
        assert_eq!(m.active_count(), 0, "idle after all closed");
        // The cumulative accept counter is a different metric and must not be what
        // the live count reports: adding a connection keeps snapshot().2 monotonic.
        m.add_connection();
        assert_eq!(m.active_count(), 0, "add_connection is NOT an active flow");
    }

    #[test]
    fn flow_cap_bounds_list() {
        let m = Monitor::new();
        for i in 0..(FLOW_CAP + 40) {
            let c = m.open_flow(format!("a{i}.exe"), "1.2.3.4:80".into(), "TCP", "d".into(), "r".into());
            // close every third so pruning has room
            if i % 3 == 0 {
                c.active.store(false, Ordering::Relaxed);
            }
        }
        assert!(m.flow_rows().len() <= FLOW_CAP);
    }

    #[test]
    fn remove_flow_drops_the_row() {
        let m = Monitor::new();
        let a = m.open_flow("a.exe".into(), "1.1.1.1:443".into(), "TCP", "d".into(), "r".into());
        let b = m.open_flow("b.exe".into(), "2.2.2.2:443".into(), "TCP", "d".into(), "r".into());
        assert_eq!(m.flow_rows().len(), 2);
        // Removing an ACTIVE flow drops its row; the other stays.
        assert!(m.remove_flow(a.id), "remove an existing row");
        let rows = m.flow_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, b.id);
        // Removing again (or an unknown id) is false, not a panic.
        assert!(!m.remove_flow(a.id));
        assert!(!m.remove_flow(999999));
    }

    #[test]
    fn abort_app_disconnects_only_that_apps_active_flows() {
        let m = Monitor::new();
        // two connections for game.exe (one active, one already closed) + one for chrome.exe
        let g1 = m.open_flow("game.exe".into(), "1.1.1.1:443".into(), "UDP", "c".into(), "r".into());
        let g2 = m.open_flow("game.exe".into(), "2.2.2.2:443".into(), "UDP", "c".into(), "r".into());
        let c1 = m.open_flow("chrome.exe".into(), "3.3.3.3:443".into(), "TCP", "c".into(), "r".into());
        m.close_flow(g2.id); // g2 inactive already
        assert!(g1.active.load(Ordering::Relaxed) && c1.active.load(Ordering::Relaxed));

        // basename match (full path arg) + only the ACTIVE one is counted
        let n = m.abort_app(r"C:\Games\game.exe");
        assert_eq!(n, 1, "only game.exe's active flow should abort");
        assert!(g1.abort.load(Ordering::SeqCst), "active flow flagged for abort");
        assert!(!g1.active.load(Ordering::Relaxed));
        // the unrelated app is untouched
        assert!(c1.active.load(Ordering::Relaxed) && !c1.abort.load(Ordering::SeqCst));
        // aborting an app with nothing active aborts 0
        assert_eq!(m.abort_app("game.exe"), 0);
    }

    #[test]
    fn conn_filter_matches_case_insensitive_substring() {
        let row = ConnRow {
            id: 1,
            app: "Game.exe".into(),
            remote: "api.example.com:443".into(),
            proto: "TCP",
            server: "chain #1 (socks)".into(),
            rule: "#1".into(),
            elapsed_secs: 2,
            sent: 0,
            recv: 0,
            active: true,
        };
        assert!(conn_filter_matches(&row, ""));
        assert!(conn_filter_matches(&row, "   "));
        assert!(conn_filter_matches(&row, "game"), "matches app, case-insensitive");
        assert!(conn_filter_matches(&row, "EXAMPLE.COM"), "matches remote");
        assert!(conn_filter_matches(&row, "socks"), "matches server");
        assert!(conn_filter_matches(&row, "tcp"), "matches proto");
        assert!(!conn_filter_matches(&row, "zzz-not-there"));
    }
}

/// Live-log filter. Kept as plain data so the GUI can hold one and the predicate
/// stays testable without a UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogFilter {
    /// 协议 filter: empty = both.
    pub proto: String,
    /// substring of the destination host or address (case-insensitive)
    pub dest: String,
    /// exact destination port, empty = any
    pub port: String,
    /// show flows that bypassed the proxy. Off by default: the operator wants the
    /// proxied traffic, and the direct rows are the noise.
    pub show_direct: bool,
}

impl Default for LogFilter {
    fn default() -> Self {
        LogFilter {
            proto: String::new(),
            dest: String::new(),
            port: String::new(),
            show_direct: false,
        }
    }
}

impl LogFilter {
    pub fn is_active(&self) -> bool {
        !self.proto.is_empty() || !self.dest.is_empty() || !self.port.is_empty() || !self.show_direct
    }
}

/// Extract `host:port` + protocol from a flow line, if it has one.
///
/// The engine writes interceptions as `... -> <host>:<port> (TCP)` / `(UDP)`, so
/// that shape is what is parsed; anything else is simply an unlocated line.
fn flow_target(msg: &str) -> (Option<String>, Option<u16>, Option<String>) {
    let up = msg.to_ascii_uppercase();
    let proto = if up.contains("(TCP)") {
        Some("TCP".to_string())
    } else if up.contains("(UDP)") {
        Some("UDP".to_string())
    } else {
        None
    };
    // last host:port-looking token in the line
    let mut host = None;
    let mut port = None;
    for tok in msg.split(|c: char| c == ' ' || c == ',' || c == '(' || c == ')' || c == '=') {
        let t = tok.trim();
        if let Some(i) = t.rfind(":") {
            let (h, p) = (&t[..i], &t[i + 1..]);
            if let Ok(n) = p.parse::<u16>() {
                if !h.is_empty() {
                    host = Some(h.to_ascii_lowercase());
                    port = Some(n);
                }
            }
        }
    }
    (host, port, proto)
}

/// Whether one log line survives `f`. See the module note: only lines that
/// positively contradict the filter are hidden.
pub fn log_filter_matches(msg: &str, f: &LogFilter) -> bool {
    let direct = msg.contains("直连");
    let proxied = msg.contains("代理");
    // a direct FLOW row is the thing the default view drops - and only a flow row,
    // so `WFP ... 直连` prose without a target stays visible
    let (host, port, proto) = flow_target(msg);
    let is_flow = host.is_some() || port.is_some() || proto.is_some();
    if direct && !proxied && !f.show_direct && is_flow {
        return false;
    }
    if !f.proto.is_empty() {
        match &proto {
            // lines that name no protocol are kept: they are not TCP and not UDP,
            // they are something else entirely, and hiding them would hide the
            // warning that explains why the filtered ones are missing
            Some(p) if p.to_ascii_uppercase() != f.proto.to_ascii_uppercase() => return false,
            _ => {}
        }
    }
    if !f.port.is_empty() {
        let want: u16 = match f.port.trim().parse() {
            Ok(n) => n,
            Err(_) => return true, // not a number yet - treat as "still typing", no filter
        };
        if let Some(p) = port {
            if p != want {
                return false;
            }
        }
    }
    if !f.dest.is_empty() {
        let q = f.dest.trim().to_ascii_lowercase();
        let hit = host.as_deref().map(|h| h.contains(&q)).unwrap_or(false)
            || msg.to_ascii_lowercase().contains(&q);
        if !hit {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod log_filter_tests {
    use super::{log_filter_matches, LogFilter};

    const PROXIED: &str = " 拦截 firefox.exe → 1.2.3.4:443 (TCP)→ 代理";
    const DIRECT: &str = " 拦截 firefox.exe → 127.0.0.1:53167 (TCP)→ 直连";
    const UDPPROXY: &str = " 拦截 app.exe → 203.0.113.9:443 (UDP)→ 代理";
    const NOISE: &str = "WFP 内核重定向已启用: 4 个过滤器";

    #[test]
    fn default_view_hides_direct_flows_and_keeps_proxied_ones() {
        let f = LogFilter::default();
        assert!(!f.show_direct, "the default is proxy-only");
        assert!(log_filter_matches(PROXIED, &f), "proxied stays");
        assert!(!log_filter_matches(DIRECT, &f), "direct goes");
        // and non-flow lines are never hidden by the direct rule
        assert!(log_filter_matches(NOISE, &f), "engine/WFP notes stay visible");
        let all = LogFilter { show_direct: true, ..Default::default() };
        assert!(log_filter_matches(DIRECT, &all), "the checkbox brings them back");
    }

    #[test]
    fn protocol_port_and_destination_narrow_the_view() {
        let udp = LogFilter { proto: "UDP".into(), show_direct: true, ..Default::default() };
        assert!(log_filter_matches(UDPPROXY, &udp));
        assert!(!log_filter_matches(PROXIED, &udp), "a TCP row is not UDP");
        assert!(log_filter_matches(NOISE, &udp), "a line with no protocol is not contradicted");

        let p443 = LogFilter { port: "443".into(), ..Default::default() };
        assert!(log_filter_matches(PROXIED, &p443));
        let dns = LogFilter { port: "53".into(), show_direct: true, ..Default::default() };
        assert!(!log_filter_matches(PROXIED, &dns), "443 is not 53");
        assert!(!log_filter_matches(DIRECT, &dns), "53167 is not port 53");

        let ip = LogFilter { dest: "203.0.113".into(), ..Default::default() };
        assert!(log_filter_matches(UDPPROXY, &ip));
        assert!(!log_filter_matches(PROXIED, &ip), "1.2.3.4 is not that net");

        // a non-numeric port box means "still typing": filtering on it would blank
        // the log, which is never the intent of a filter
        let typing = LogFilter { port: "4a".into(), show_direct: true, ..Default::default() };
        assert!(log_filter_matches(PROXIED, &typing), "unparseable port must not hide rows");
    }
}
