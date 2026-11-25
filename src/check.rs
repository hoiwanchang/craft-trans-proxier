use crate::config::{Config, ProxyKind, ProxyServer};
use crate::http_connect;
use crate::socks4;
use crate::socks5;
use std::io::Error;
use std::net::TcpStream;

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub proxy_id: u32,
    pub proxy_name: String,
    pub host: String,
    pub port: u16,
    pub ok: bool,
    pub message: String,
}

pub fn check_proxy(
    proxy: &ProxyServer,
    host: &str,
    port: u16,
    timeout: std::time::Duration,
) -> CheckResult {
    let started = std::time::Instant::now();
    let result = do_check(proxy, host, port, timeout);
    let elapsed = started.elapsed();
    match result {
        Ok(()) => CheckResult {
            proxy_id: proxy.id,
            proxy_name: proxy.name.clone(),
            host: host.into(),
            port,
            ok: true,
            message: format!("OK (tunneled through \"{}\" in {:?})", proxy.name, elapsed),
        },
        Err(e) => CheckResult {
            proxy_id: proxy.id,
            proxy_name: proxy.name.clone(),
            host: host.into(),
            port,
            ok: false,
            message: format!("FAIL: {e} (after {elapsed:?})"),
        },
    }
}

fn do_check(proxy: &ProxyServer, host: &str, port: u16, timeout: std::time::Duration) -> Result<(), Error> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    match proxy.kind {
        ProxyKind::Http | ProxyKind::Https => http_connect::connect(&mut stream, proxy, host, port),
        ProxyKind::Socks5 => socks5::connect(&mut stream, proxy, host, port),
        ProxyKind::Socks4 => socks4::connect(&mut stream, proxy, host, port, true),
    }
}

pub fn check_chain(
    config: &Config,
    chain_id: u32,
    host: &str,
    port: u16,
) -> CheckResult {
    let started = std::time::Instant::now();
    let result = crate::engine::connect_via_chain(config, chain_id, host, port);
    let elapsed = started.elapsed();
    let chain = config.chain_by_id(chain_id);
    let name = chain.map(|c| c.name.clone()).unwrap_or_else(|| format!("chain-{chain_id}"));
    let name_clone = name.clone();
    match result {
        Ok(_stream) => CheckResult {
            proxy_id: chain_id,
            proxy_name: name,
            host: host.into(),
            port,
            ok: true,
            message: format!("OK (chain \"{}\" connected in {:?})", name_clone, elapsed),
        },
        Err(e) => CheckResult {
            proxy_id: chain_id,
            proxy_name: name,
            host: host.into(),
            port,
            ok: false,
            message: format!("FAIL: {e} (after {elapsed:?})"),
        },
    }
}
