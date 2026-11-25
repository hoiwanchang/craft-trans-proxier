use crate::config::{Config, ProxyKind, ProxyServer};
use crate::http_connect;
use crate::monitor::Monitor;
use crate::rules::{self, Decision};
use crate::socks5;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::Ordering;

#[derive(Debug)]
pub struct RouteError(pub String);

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RouteError {}

fn err(msg: impl Into<String>) -> RouteError {
    RouteError(msg.into())
}

/// Dial a proxy's first hop within `timeout_secs`, enforcing the per-proxy
/// `timeout` setting (fnd_13 "Timeout"). A bare `TcpStream::connect` would block
/// on the OS default (~21s) against an unreachable proxy; `connect_timeout`
/// bounds it. Numeric hosts skip DNS; hostnames resolve then connect each
/// candidate with the timeout.
pub fn dial_proxy(host: &str, port: u16, timeout_secs: u64) -> Result<TcpStream, Error> {
    let dur = std::time::Duration::from_secs(timeout_secs.max(1));
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()?
        .collect();
    let mut last = Error::new(ErrorKind::AddrNotAvailable, "proxy host resolved to no addresses");
    for a in addrs {
        match TcpStream::connect_timeout(&a, dur) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

pub fn connect_via_chain(
    config: &Config,
    chain_id: u32,
    host: &str,
    port: u16,
) -> Result<TcpStream, RouteError> {
    let chain = config
        .chain_by_id(chain_id)
        .ok_or_else(|| err(format!("Chain \"{chain_id}\" refers to nonexistent proxy chain")))?;
    if chain.proxies.is_empty() {
        return Err(err(format!("Chain \"{}\" is empty", chain.name)));
    }
    let proxies: Vec<&ProxyServer> = chain
        .proxies
        .iter()
        .map(|id| {
            config
                .proxy_available(*id)
                .ok_or_else(|| err(format!("Chain \"{}\" refers to an unavailable proxy (missing or disabled, id = {})", chain.name, id)))
        })
        .collect::<Result<Vec<&ProxyServer>, RouteError>>()?;
    let recheck = config.settings.redundancy_recheck_secs;
    if !crate::redundancy::is_available(proxies[0].id, recheck) {
        return Err(err(format!(
            "Proxy \"{}\" is marked down; failing fast until recheck ({}s)",
            proxies[0].name, recheck
        )));
    }
    let mut stream = match dial_proxy(&proxies[0].host, proxies[0].port, proxies[0].timeout_secs) {
        Ok(s) => {
            crate::redundancy::note_success(proxies[0].id);
            s
        }
        Err(e) => {
            // The first hop is the only real network dial; mark it down so the
            // next attempt fails fast instead of waiting the timeout again.
            crate::redundancy::note_failure(proxies[0].id);
            return Err(err(format!("Cannot start connection to proxy chain: {e}")));
        }
    };
    for (i, proxy) in proxies.iter().enumerate() {
        let is_last = i == proxies.len() - 1;
        // Honour this proxy's timeout on the HANDSHAKE too (not just the dial): a
        // proxy that accepts TCP then stalls the SOCKS/HTTP reply would otherwise
        // block read_exact forever. Applied per-hop so each proxy's own timeout governs.
        let ht = std::time::Duration::from_secs(proxy.timeout_secs.max(1));
        let _ = stream.set_read_timeout(Some(ht));
        let _ = stream.set_write_timeout(Some(ht));
        let (next_host, next_port) = if is_last {
            (host, port)
        } else {
            let next = proxies[i + 1];
            (next.host.as_str(), next.port)
        };
        open_tunnel(&mut stream, proxy, next_host, next_port)
            .map_err(|e| err(format!("Chain failure at proxy \"{}\" (id = {}): {e}", proxy.name, proxy.id)))?;
    }
    Ok(stream)
}

fn open_tunnel(
    stream: &mut TcpStream,
    proxy: &ProxyServer,
    host: &str,
    port: u16,
) -> Result<(), Error> {
    match proxy.kind {
        ProxyKind::Http | ProxyKind::Https => http_connect::connect(stream, proxy, host, port),
        ProxyKind::Socks5 => socks5::connect(stream, proxy, host, port),
        ProxyKind::Socks4 => {
            // Enable the 4A extension so hostname targets are resolved by the
            // remote proxy (numeric IPs use the plain SOCKS4 path unchanged).
            crate::socks4::connect(stream, proxy, host, port, true)
        }
    }
}

pub fn connect_direct(host: &str, port: u16) -> Result<TcpStream, Error> {
    TcpStream::connect((host, port))
}

pub fn connect_target(
    config: &Config,
    app: Option<&str>,
    host: &str,
    port: u16,
) -> Result<(TcpStream, Decision), RouteError> {
    connect_target_dialing(config, app, host, port, host, port)
}

/// Like [`connect_target`] but allows the address that is DIALLED to differ from
/// the one the rules were evaluated against — the DNS path needs this: the profile
/// matched the resolver the app was configured to use, while the query itself goes
/// to the resolver the operator configured.
///
/// The decision uses `rules::decide_route`, i.e. the same policy-aware entry point
/// as the transparent hook, so a connection the hook pulled onto a chain because of
/// the DNS policy can never be re-decided to Direct here and leak out unproxied.
pub fn connect_target_dialing(
    config: &Config,
    app: Option<&str>,
    decide_host: &str,
    decide_port: u16,
    dial_host: &str,
    dial_port: u16,
) -> Result<(TcpStream, Decision), RouteError> {
    let decision = rules::decide_route(config, app, decide_host, decide_port, 6);
    match decision {
        Decision::Proxy { chain, .. } => {
            let stream = connect_via_chain(config, chain, dial_host, dial_port)?;
            Ok((stream, decision))
        }
        Decision::Direct { .. } => {
            let stream = connect_direct(dial_host, dial_port).map_err(|e| {
                err(format!(
                    "Direct connection to {dial_host}:{dial_port} failed: {e}"
                ))
            })?;
            Ok((stream, decision))
        }
        Decision::Block { rule } => Err(err(format!(
            "Connection to {decide_host}:{decide_port} blocked by rule #{rule}"
        ))),
    }
}

fn copy_stream(
    from: &mut TcpStream,
    to: &mut TcpStream,
    count: &dyn Fn(u64),
    abort: Option<&std::sync::atomic::AtomicBool>,
    tap: Option<&(dyn Fn(&[u8]) + Send + Sync)>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    // Short read timeout so an idle direction still polls the abort flag.
    let _ = from.set_read_timeout(Some(std::time::Duration::from_millis(250)));
    loop {
        if let Some(a) = abort {
            if a.load(Ordering::SeqCst) {
                return Ok(());
            }
        }
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                count(n as u64);
                // Forward FIRST: an observer must never delay or alter a byte of the
                // user's traffic, and a bug in the tap cannot be allowed to hang it.
                to.write_all(&buf[..n])?;
                if let Some(t) = tap {
                    t(&buf[..n]);
                }
            }
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    Ok(())
}

pub fn relay(client: TcpStream, server: TcpStream) -> std::io::Result<()> {
    relay_counted(client, server, None, None)
}

/// Relay bytes between a SOCKS5 client and its upstream. When a `Monitor` is
/// supplied, client→upstream counts as upload and upstream→client as download;
/// an optional `flow` gets the same per-connection byte counts (Connection List).
pub fn relay_counted(
    client: TcpStream,
    server: TcpStream,
    monitor: Option<&Monitor>,
    flow: Option<&crate::monitor::ConnInfo>,
) -> std::io::Result<()> {
    relay_counted_tap(client, server, monitor, flow, None)
}

/// As [`relay_counted`], with an observer on the DOWNLOAD direction: every chunk of
/// bytes heading back to the client is also handed to `download_tap`, after it has
/// been forwarded. Used to learn names from DNS answers the engine is carrying
/// (`crate::dns::FakeIpPool::observe_dns_response`), which is how a hostname rule can
/// match a connection that only ever appears as an IP address.
pub fn relay_counted_tap(
    client: TcpStream,
    server: TcpStream,
    monitor: Option<&Monitor>,
    flow: Option<&crate::monitor::ConnInfo>,
    download_tap: Option<&(dyn Fn(&[u8]) + Send + Sync)>,
) -> std::io::Result<()> {
    let mut server_side = server.try_clone()?;
    let mut client_side_reader = client.try_clone()?;
    let mut client_side_writer = client.try_clone()?;
    let mut server_side_writer = server.try_clone()?;

    let up = |n: u64| {
        if let Some(m) = monitor {
            m.add_up(n);
        }
        if let Some(f) = flow {
            f.sent.fetch_add(n, Ordering::Relaxed);
        }
    };
    let down = |n: u64| {
        if let Some(m) = monitor {
            m.add_down(n);
        }
        if let Some(f) = flow {
            f.recv.fetch_add(n, Ordering::Relaxed);
        }
    };
    let up_ref = &up;
    let down_ref = &down;
    let abort = flow.map(|f| &f.abort);

    std::thread::scope(|s| {
        // client -> upstream (upload)
        s.spawn(move || {
            let _ = copy_stream(&mut client_side_reader, &mut server_side_writer, up_ref, abort, None);
        });
        // upstream -> client (download)
        s.spawn(move || {
            let _ = copy_stream(&mut server_side, &mut client_side_writer, down_ref, abort, download_tap);
        });
    });
    Ok(())
}

pub fn serve(listener: TcpListener, config: Config, app: Option<String>) -> std::io::Result<()> {
    serve_monitored(listener, config, app, None)
}

/// Serve inbound **HTTP proxy** requests (fnd_10 "HTTP proxy servers support"):
/// both `CONNECT host:port` tunnels and absolute-form `GET http://host/…` that
/// are routed through the same rule/chain engine as SOCKS5. Each request's
/// upstream connection is decided by `rules::decide` for `app`+host.
pub fn serve_http(
    listener: TcpListener,
    config: Config,
    app: Option<String>,
    monitor: std::sync::Arc<Monitor>,
) -> std::io::Result<()> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    serve_http_with_stop(listener, config, app, monitor, stop)
}

pub fn serve_http_with_stop(
    listener: TcpListener,
    config: Config,
    app: Option<String>,
    monitor: std::sync::Arc<Monitor>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::io::Result<()> {
    use std::sync::Arc;
    listener.set_nonblocking(true)?;
    let config = Arc::new(config);
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((mut client, _addr)) => {
                let _ = client.set_nonblocking(false);
                let cfg = config.clone();
                let app = app.clone();
                let mon = monitor.clone();
                std::thread::spawn(move || {
                    let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                    let cfg_ref = (*cfg).clone();
                    let connect = |host: &str, port: u16| -> std::io::Result<TcpStream> {
                        mon.add_connection();
                        mon.log("info", format!("HTTP 代理 {peer} → {host}:{port}"));
                        connect_target(&cfg_ref, app.as_deref(), host, port)
                            .map(|(s, _)| s)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()))
                    };
                    let tunnel = {
                        let mon = mon.clone();
                        move |a: TcpStream, b: TcpStream| relay_counted(a, b, Some(&mon), None)
                    };
                    let _ = crate::http_proxy::handle(&mut client, connect, tunnel);
                });
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    Ok(())
}

fn serve_monitored(
    listener: TcpListener,
    config: Config,
    app: Option<String>,
    monitor: Option<std::sync::Arc<Monitor>>,
) -> std::io::Result<()> {
    for incoming in listener.incoming() {
        let Ok(client) = incoming else { continue };
        let config = config.clone();
        let app = app.clone();
        let monitor = monitor.clone();
        std::thread::spawn(move || {
            let _ = serve_one(client, &config, app.as_deref(), monitor.as_deref());
        });
    }
    Ok(())
}

pub fn serve_with_stop(
    listener: TcpListener,
    config: Config,
    app: Option<String>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    monitor: std::sync::Arc<Monitor>,
) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;
    listener.set_nonblocking(true)?;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match listener.accept() {
            Ok((client, _addr)) => {
                // The listener is nonblocking for the accept loop; the relay and
                // SOCKS5 handshake below use blocking reads, so undo the flag.
                let _ = client.set_nonblocking(false);
                let config = config.clone();
                let app = app.clone();
                let monitor = monitor.clone();
                std::thread::spawn(move || {
                    let _ = serve_one(client, &config, app.as_deref(), Some(&monitor));
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    Ok(())
}

fn serve_one(
    mut client: TcpStream,
    config: &Config,
    app: Option<&str>,
    monitor: Option<&Monitor>,
) -> Result<(), String> {
    let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let target = read_socks5_request(&mut client).map_err(|e| e.to_string())?;
    if let Some(m) = monitor {
        m.add_connection();
        m.log(
            "info",
            format!("连接 {peer} → {}:{}（{}）", target.host, target.port, app.unwrap_or("未知应用")),
        );
    }
    if target.cmd == 0x03 {
        // SOCKS5 UDP ASSOCIATE — the path that lets whitelisted games' UDP be
        // proxied. (HTTP CONNECT could never carry this: fnd_10.)
        return serve_udp_associate(client, monitor).map_err(|e| e.to_string());
    }
    let result = connect_target(config, app, &target.host, target.port);
    match result {
        Ok((target_side, decision)) => {
            write_socks5_reply(&mut client, 0x00).map_err(|e| e.to_string())?;
            if let Some(m) = monitor {
                m.log("info", format!("  → {}", describe_decision(config, &decision)));
            }
            // Record a Connection-List row for this proxified flow (fnd_13).
            let flow = monitor.map(|m| {
                m.open_flow(
                    app.unwrap_or("unknown").to_string(),
                    format!("{}:{}", target.host, target.port),
                    "TCP",
                    server_label(config, &decision),
                    rule_label(&decision),
                )
            });
            relay_counted(client, target_side, monitor, flow.as_deref())
                .map_err(|e| e.to_string())?;
            if let (Some(m), Some(f)) = (monitor, &flow) {
                m.close_flow(f.id);
            }
            Ok(())
        }
        Err(e) => {
            let _ = write_socks5_reply(&mut client, 0x05);
            if let Some(m) = monitor {
                m.log("warn", format!("  → 失败: {e}"));
            }
            Err(e.to_string())
        }
    }
}

/// Server column for the Connection List: chain id + egress, or "direct".
pub(crate) fn server_label(config: &Config, decision: &Decision) -> String {
    match decision {
        Decision::Direct { .. } => "direct".into(),
        Decision::Block { .. } => "blocked".into(),
        Decision::Proxy { chain, .. } => {
            let name = config
                .chain_by_id(*chain)
                .and_then(|c| c.proxies.last())
                .and_then(|id| config.proxy_by_id(*id))
                .map(|p| p.name.clone())
                .unwrap_or_else(|| format!("#{chain}"));
            format!("chain #{chain} ({name})")
        }
    }
}

pub(crate) fn rule_label(decision: &Decision) -> String {
    match decision {
        Decision::Proxy { rule, .. } => format!("#{rule}"),
        Decision::Block { rule } => format!("#{rule}"),
        Decision::Direct { rule, .. } => rule.map(|r| format!("#{r}")).unwrap_or_else(|| "-".into()),
    }
}

/// SOCKS5 UDP ASSOCIATE (RFC 1928 §4/§7): open a relay UDP socket, tell the
/// client where to send framed datagrams, then shuttle them to/from the real
/// destination, adding/stripping the per-datagram header. The TCP control socket
/// staying open is the session lifetime (closing it tears the association down).
fn serve_udp_associate(mut control: TcpStream, monitor: Option<&Monitor>) -> std::io::Result<()> {
    use std::net::{SocketAddr, UdpSocket};
    // Bind the relay on loopback, matching where the client connects.
    let relay = UdpSocket::bind("127.0.0.1:0")?;
    let bnd = relay.local_addr()?;
    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
    let ip = match bnd {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(_) => [127, 0, 0, 1],
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&ip);
    reply.extend_from_slice(&bnd.port().to_be_bytes());
    control.write_all(&reply)?;
    if let Some(m) = monitor {
        m.log("info", format!("  → UDP 关联已建立，中继 {}", bnd));
    }
    relay.set_read_timeout(Some(std::time::Duration::from_millis(50)))?;
    control.set_nonblocking(true)?;

    let mut client_addr: Option<SocketAddr> = None;
    let mut buf = vec![0u8; 64 * 1024];
    let idle_limit = std::time::Duration::from_secs(120);
    let mut last_activity = std::time::Instant::now();
    loop {
        match relay.recv_from(&mut buf) {
            Ok((n, src)) => {
                last_activity = std::time::Instant::now();
                let framed = &buf[..n];
                match client_addr {
                    None => {
                        // first datagram from the client carries its address + target
                        if let Some((dst, payload)) = crate::socks5::parse_udp_frame(framed) {
                            client_addr = Some(src);
                            let _ = relay.send_to(payload, dst);
                        }
                    }
                    Some(caddr) if src == caddr => {
                        if let Some((dst, payload)) = crate::socks5::parse_udp_frame(framed) {
                            let _ = relay.send_to(payload, dst);
                        }
                    }
                    Some(caddr) => {
                        // a response from an upstream target → frame + back to client
                        let out = crate::socks5::udp_frame(&src, framed);
                        let _ = relay.send_to(&out, caddr);
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(_) => break,
        }
        // control socket EOF/closed ⇒ end of association
        let mut probe = [0u8; 1];
        match control.read(&mut probe) {
            Ok(0) => break,
            Err(ref e) if e.kind() != ErrorKind::WouldBlock => break,
            _ => {}
        }
        if last_activity.elapsed() > idle_limit {
            break;
        }
    }
    Ok(())
}

fn describe_decision(config: &Config, decision: &Decision) -> String {
    match decision {
        Decision::Direct { reason, rule } => format!(
            "直连（{reason}{}）",
            rule.map(|r| format!(", 规则 #{r}")).unwrap_or_default()
        ),
        Decision::Proxy { chain, rule } => {
            let hops = config
                .chain_by_id(*chain)
                .map(|c| c.proxies.len())
                .unwrap_or(0);
            format!("经由代理链 #{chain}（{hops} 跳，规则 #{rule}）")
        }
        Decision::Block { rule } => format!("已阻止（规则 #{rule}）"),
    }
}

fn write_socks5_reply(client: &mut TcpStream, code: u8) -> Result<(), std::io::Error> {
    // success: no address required beyond 127.0.0.1:0; failure: same shape with code set
    let reply_ip = [127u8, 0, 0, 1];
    client.write_all(&[0x05, code, 0x00, 0x01])?;
    client.write_all(&reply_ip)?;
    client.write_all(&0u16.to_be_bytes())?;
    Ok(())
}

fn read_socks5_request(client: &mut TcpStream) -> Result<Socks5Target, std::io::Error> {
    let mut greeting = [0u8; 2];
    read_exact(client, &mut greeting)?;
    if greeting[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "not a SOCKS5 request"));
    }
    let nmethods = greeting[1] as usize;
    let mut methods = vec![0u8; nmethods];
    read_exact(client, &mut methods)?;
    // no-auth only in this build
    client.write_all(&[0x05, 0x00])?;

    let mut head = [0u8; 4];
    read_exact(client, &mut head)?;
    if head[0] != 0x05 || (head[1] != 0x01 && head[1] != 0x03) {
        return Err(Error::new(ErrorKind::InvalidData, "not a SOCKS5 CONNECT/UDP request"));
    }
    let cmd = head[1];
    let atyp = head[3];
    let host = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            read_exact(client, &mut addr)?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        0x04 => {
            let mut addr = [0u8; 16];
            read_exact(client, &mut addr)?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            read_exact(client, &mut len)?;
            if len[0] == 0 {
                return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 host length"));
            }
            let mut buf = vec![0u8; len[0] as usize];
            read_exact(client, &mut buf)?;
            String::from_utf8_lossy(&buf).to_string()
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS5 ATYP")),
    };
    let mut port_bytes = [0u8; 2];
    read_exact(client, &mut port_bytes)?;
    Ok(Socks5Target {
        host,
        port: u16::from_be_bytes(port_bytes),
        cmd,
    })
}

struct Socks5Target {
    host: String,
    port: u16,
    cmd: u8, // 0x01 CONNECT, 0x03 UDP ASSOCIATE
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), std::io::Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "unexpected EOF"));
        }
        filled += n;
    }
    Ok(())
}
