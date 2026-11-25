//! SOCKS4 / SOCKS4a client — the engine previously returned "not implemented"
//! for `ProxyKind::Socks4` even though the config parses it and fnd_13 lists
//! "Use SOCKS 4A extension (remote hostname resolving feature)".
//!
//! Protocol (very little): the client sends a fixed request; the server replies
//! with an 8-byte grant/deny. SOCKS4 carries only a numeric IPv4 DSTIP; SOCKS4a
//! extends it so a *client* that cannot resolve can hand the proxy a hostname by
//! sending DSTIP = 0.0.x.x (x≠0, the "3" here marks 4a) followed by the
//! NUL-terminated hostname after the (also NUL-terminated) USERID.
//!
//! Request layout (both):
//!   VN=4 | CD=1(connect) | DSTPORT(2, BE) | DSTIP(4) | USERID(0-terminated) [| HOST(0-terminated, 4a only)]
//! Reply: VN1(=0) | CD | DSTPORT(2) | DSTIP(4), where CD 90 = granted, 91 = rejected
//! (91.. other codes = various failures; the user id is ASCII only in classic SOCKS4).

use crate::config::ProxyServer;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpStream};

const SOCKS4_VERSION: u8 = 0x04;
const SOCKS4_CMD_CONNECT: u8 = 0x01;
const REPLY_REQUEST_GRANTED: u8 = 0x5a; // 90
const REPLY_REJECTED: u8 = 0x5b; // 91
const REPLY_REJECTED_IDENTD: u8 = 0x5d; // 93
const REPLY_USERID_NOT_IDENTD: u8 = 0x5f; // 95

fn user_id(proxy: &ProxyServer) -> Vec<u8> {
    proxy.username.clone().unwrap_or_default().into_bytes()
}

/// Build a SOCKS4 CONNECT request for a numeric IPv4 destination.
/// `use_4a` + a hostname produces the 4a form (DSTIP 0.0.0.3 + NUL hostname).
/// Returns the request bytes, or an error if plain SOCKS4 was asked to carry a
/// hostname (classic SOCKS4 has no hostname field — the caller must resolve or
/// enable 4a).
pub fn build_request(host: &str, port: u16, userid: &[u8], use_4a: bool) -> Result<Vec<u8>, Error> {
    if userid.iter().any(|&b| b == 0) {
        return Err(Error::new(ErrorKind::InvalidInput, "SOCKS4 user id must not contain NUL"));
    }
    if userid.len() > 255 {
        return Err(Error::new(ErrorKind::InvalidInput, "SOCKS4 user id too long"));
    }
    let mut out = Vec::new();
    out.push(SOCKS4_VERSION);
    out.push(SOCKS4_CMD_CONNECT);
    out.extend_from_slice(&port.to_be_bytes());
    match host.parse::<Ipv4Addr>() {
        Ok(ip) => out.extend_from_slice(&ip.octets()),
        Err(_) => {
            if use_4a {
                out.extend_from_slice(&[0, 0, 0, 3]); // 4a sentinel
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    format!("SOCKS4 cannot connect to hostname \"{host}\" (needs SOCKS4A)"),
                ));
            }
        }
    }
    out.extend_from_slice(userid);
    out.push(0);
    // 4a appends the NUL-terminated hostname when DSTIP was the 0.0.0.x sentinel.
    if host.parse::<Ipv4Addr>().is_err() && use_4a {
        if host.as_bytes().contains(&0) {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid hostname"));
        }
        out.extend_from_slice(host.as_bytes());
        out.push(0);
    }
    Ok(out)
}

/// Map a SOCKS4 reply status code to a result.
pub fn parse_reply(cd: u8) -> Result<(), Error> {
    match cd {
        REPLY_REQUEST_GRANTED => Ok(()),
        REPLY_REJECTED => Err(Error::new(ErrorKind::ConnectionRefused, "SOCKS4 connection rejected")),
        REPLY_REJECTED_IDENTD => Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS4 rejected: client identd refused connection",
        )),
        REPLY_USERID_NOT_IDENTD => Err(Error::new(
            ErrorKind::PermissionDenied,
            "SOCKS4 rejected: server could not verify user id via identd",
        )),
        other => Err(Error::new(
            ErrorKind::PermissionDenied,
            format!("SOCKS4 rejected (code 0x{other:02x})"),
        )),
    }
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), Error> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream.read(&mut buf[filled..])?;
        if n == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "SOCKS4 reply truncated"));
        }
        filled += n;
    }
    Ok(())
}

/// Perform the SOCKS4/4a CONNECT handshake on an already-connected stream.
/// `use_4a` enables the hostname extension; otherwise numeric IPs only.
pub fn connect(
    stream: &mut TcpStream,
    proxy: &ProxyServer,
    host: &str,
    port: u16,
    use_4a: bool,
) -> Result<(), Error> {
    let req = build_request(host, port, &user_id(proxy), use_4a)?;
    stream.write_all(&req)?;
    // Reply VN(1) CD(1) DSTPORT(2) DSTIP(4) = 8 bytes.
    let mut reply = [0u8; 8];
    read_exact(stream, &mut reply)?;
    if reply[0] != 0x00 {
        return Err(Error::new(ErrorKind::InvalidData, "invalid SOCKS4 reply version (expected 0)"));
    }
    parse_reply(reply[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_ipv4_layout() {
        let r = build_request("93.184.216.34", 80, b"bob", false).unwrap();
        assert_eq!(r[0], 4); // VN
        assert_eq!(r[1], 1); // CONNECT
        assert_eq!(&r[2..4], &80u16.to_be_bytes());
        assert_eq!(&r[4..8], &[93, 184, 216, 34]);
        assert_eq!(&r[8..12], b"bob\0"); // userid + NUL
        assert_eq!(r.len(), 12); // no hostname for a numeric IP
    }

    #[test]
    fn socks4a_encodes_hostname() {
        let r = build_request("example.com", 443, b"", true).unwrap();
        assert_eq!(&r[2..4], &443u16.to_be_bytes());
        assert_eq!(&r[4..8], &[0, 0, 0, 3], "4a sentinel");
        // userid is empty -> just the NUL, then hostname + NUL
        assert_eq!(&r[8..], b"\0example.com\0".as_slice());
    }

    #[test]
    fn plain_socks4_rejects_hostname() {
        let e = build_request("example.com", 80, b"", false).unwrap_err();
        assert!(e.to_string().contains("SOCKS4A"), "should tell the user to use 4A: {e}");
    }

    #[test]
    fn rejects_nul_in_userid() {
        assert!(build_request("1.2.3.4", 80, b"a\0b", false).is_err());
    }

    #[test]
    fn reply_codes_map() {
        assert!(parse_reply(0x5a).is_ok());
        assert!(parse_reply(0x5b).is_err());
        assert!(parse_reply(0x5d).is_err());
        assert!(parse_reply(0x5f).is_err());
        assert!(parse_reply(0x00).is_err());
    }
}
