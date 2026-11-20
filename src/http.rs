//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use crate::conf::{Config, Level, Server};
use crate::vars::{Request, Sent, Template};

pub const NAME: &str = concat!("twinx/", env!("CARGO_PKG_VERSION"));

const REASONS: &[(u16, &str)] = &[
    (200, "OK"), (201, "Created"), (202, "Accepted"), (204, "No Content"), (206, "Partial Content"),
    (301, "Moved Permanently"), (302, "Moved Temporarily"), (303, "See Other"), (304, "Not Modified"),
    (307, "Temporary Redirect"), (308, "Permanent Redirect"), (400, "Bad Request"), (401, "Unauthorized"),
    (403, "Forbidden"), (404, "Not Found"), (405, "Not Allowed"), (406, "Not Acceptable"),
    (408, "Request Time-out"), (409, "Conflict"), (410, "Gone"), (411, "Length Required"),
    (412, "Precondition Failed"), (413, "Request Entity Too Large"), (414, "Request-URI Too Large"),
    (415, "Unsupported Media Type"), (416, "Requested Range Not Satisfiable"), (429, "Too Many Requests"),
    (500, "Internal Server Error"), (501, "Not Implemented"), (502, "Bad Gateway"),
    (503, "Service Temporarily Unavailable"), (504, "Gateway Time-out"), (505, "HTTP Version Not Supported"),
];

/// Binds every address the servers listen on and accepts connections on each in a thread.
pub fn listen(config: Arc<Config>) -> Result<(), String> {
    let mut addrs: Vec<SocketAddr> = config.servers.iter().flat_map(|s| s.listen.clone()).collect();
    addrs.dedup();
    for addr in addrs {
        let listener = TcpListener::bind(addr).map_err(|e| format!("bind() to {addr} failed ({e})"))?;
        let config = config.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let config = config.clone();
                thread::spawn(move || connection(&config, stream, addr));
            }
        });
    }
    Ok(())
}

/// The end of the request head (after the empty line), if it has arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buf.windows(3).position(|w| w == b"\n\r\n").map(|i| i + 3);
    lf.into_iter().chain(crlf).min()
}

fn connection(config: &Config, mut stream: TcpStream, local: SocketAddr) {
    let peer = stream.peer_addr().unwrap_or(local);
    let server = config.servers.iter().find(|s| s.listen.contains(&local)).unwrap_or(&config.servers[0]);
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    loop {
        let (pipelined, started) = (!buf.is_empty(), Instant::now());
        let end = loop {
            if let Some(end) = head_end(&buf) { break end; }
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 { return; }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head: Vec<u8> = buf.drain(..end).collect();
        let request = Request {
            method: String::new(),
            uri: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: server.names.first().cloned().unwrap_or_default(),
            peer,
            started,
            pipelined,
            length: head.len(),
        };
        if !exchange(server, &mut stream, request, &head) { return; }
    }
}

/// Answers one request; true when the connection stays open for the next one.
fn exchange(server: &Server, stream: &mut TcpStream, mut r: Request, head: &[u8]) -> bool {
    let parsed = parse(&mut r, head);
    let keepalive = parsed.is_ok() && keepalive(&r);
    let level = location(server, &r.uri);
    let (code, text) = level.ret.clone().unwrap_or((404, Template::default()));
    let (status, body) = match parsed {
        Err(status) => (status, None),
        Ok(()) => (code, (!text.0.is_empty() || code < 400).then(|| text.render(&r, &Sent::default()))),
    };
    let ctype = if body.is_some() { "text/plain" } else { "text/html" };
    let body = body.unwrap_or_else(|| page(status));
    let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
    let connection = if keepalive { "keep-alive" } else { "close" };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nServer: {NAME}\r\nDate: {date}\r\nContent-Type: {ctype}\r\n\
         Content-Length: {}\r\nConnection: {connection}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    let body_len = if r.method == "HEAD" { 0 } else { body.len() };
    out.extend_from_slice(&body.as_bytes()[..body_len]);
    let written = stream.write_all(&out).is_ok();
    let sent = Sent { status, bytes: out.len(), body: body_len };
    for log in &level.access_log {
        let line = log.format.log_line(&r, &sent) + "\n";
        let _ = (&*log.file).write_all(line.as_bytes());
    }
    written && keepalive
}

/// Fills the request from its head, or gives the status nginx refuses it with.
fn parse(r: &mut Request, head: &[u8]) -> Result<(), u16> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    r.line = lines.next().unwrap_or_default().to_string();
    let words: Vec<&str> = r.line.split(' ').filter(|w| !w.is_empty()).collect();
    let [method, target, version] = words[..] else { return Err(400) };
    r.method = method.to_string();
    let valid_method = method.bytes().all(|c| c.is_ascii_uppercase() || c == b'_' || c == b'-');
    if !valid_method || !matches!(version, "HTTP/1.0" | "HTTP/1.1") { return Err(400); }
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        r.headers.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    let hosts: Vec<&String> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).map(|(_, v)| v).collect();
    if hosts.len() > 1 || (hosts.is_empty() && version == "HTTP/1.1") { return Err(400); }
    r.host = hosts.first().map(|h| valid_host(h).ok_or(400u16)).transpose()?;
    if method == "CONNECT" { return Err(if target.starts_with('/') || !target.contains(':') { 400 } else { 405 }); }
    let path = match target.split_once("://") {
        Some((_, rest)) if !target.starts_with('/') => {
            let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
            r.host = Some(valid_host(authority).ok_or(400u16)?);
            path
        }
        _ => target,
    };
    if !path.starts_with('/') { return Err(400); }
    r.uri = path.split('?').next().unwrap_or_default().to_string();
    if method == "TRACE" { return Err(405); }
    Ok(())
}

/// The host as $host gives it: lower case, without the port or a trailing
/// dot; None when nginx refuses it.
fn valid_host(h: &str) -> Option<String> {
    let (host, port) = if h.starts_with('[') { h.split_at(h.find(']')? + 1) } else { h.split_at(h.find(':').unwrap_or(h.len())) };
    let port = if port.is_empty() { "" } else { port.strip_prefix(':')? };
    let port_ok = port.is_empty() || (port.len() <= 5 && port.bytes().all(|c| c.is_ascii_digit()) && port.parse::<u32>().ok()? <= 65535);
    let literal = host.starts_with('[');
    let bad = |c: u8| c <= 0x20 || c == 0x7f || c == b'/' || c == b'\\' || (!literal && (c == b'[' || c == b']'));
    let ok = port_ok && !host.bytes().any(bad) && !host.contains("..") && !host.ends_with("].");
    let host = host.strip_suffix('.').unwrap_or(host);
    let ok = ok && !host.is_empty();
    ok.then(|| host.to_ascii_lowercase())
}

fn keepalive(r: &Request) -> bool {
    let connection = r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("connection")).map(|(_, v)| v.to_ascii_lowercase());
    let http11 = r.line.ends_with("HTTP/1.1");
    connection.map_or(http11, |c| if http11 { c != "close" } else { c == "keep-alive" })
}

/// The location whose prefix is the longest one matching the URI, or the server's own settings.
fn location<'a>(server: &'a Server, uri: &str) -> &'a Level {
    let matching = server.locations.iter().filter(|(prefix, _)| uri.starts_with(prefix.as_str()));
    matching.max_by_key(|(prefix, _)| prefix.len()).map_or(&server.level, |(_, level)| level)
}

/// The page nginx generates for an error status.
fn page(status: u16) -> String {
    let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
    format!(
        "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n\
         <center><h1>{status} {reason}</h1></center>\r\n<hr><center>{NAME}</center>\r\n</body>\r\n</html>\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(head: &str) -> (Result<(), u16>, Request) {
        let mut r = Request {
            method: String::new(),
            uri: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: "localhost".into(),
            peer: "127.0.0.1:1".parse().unwrap(),
            started: Instant::now(),
            pipelined: false,
            length: 0,
        };
        (parse(&mut r, head.as_bytes()), r)
    }

    #[test]
    fn head_end_with_lf_and_crlf() {
        assert_eq!(head_end(b"GET / HTTP/1.0\nHost: a\n\nrest"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n\r\n"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n"), None);
    }

    #[test]
    fn parses_requests() {
        let (res, r) = request("GET /a?b HTTP/1.1\nHost: Example.COM.:80\nConnection: close\n\n");
        assert_eq!(res, Ok(()));
        assert_eq!((r.uri.as_str(), r.host.as_deref()), ("/a", Some("example.com")));
        assert!(!keepalive(&r));
        let (_, r) = request("GET http://[::1]:8/x HTTP/1.0\nHost: a\nConnection: keep-alive\n\n");
        assert_eq!((r.uri.as_str(), r.host.as_deref()), ("/x", Some("[::1]")));
        assert!(keepalive(&r));
    }

    #[test]
    fn refuses_bad_requests() {
        assert_eq!(request("GET / HTTP/1.1\n\n").0, Err(400));
        assert_eq!(request("GET /\n\n").0, Err(400));
        assert_eq!(request("TRACE / HTTP/1.0\n\n").0, Err(405));
        assert_eq!(request("CONNECT a:1 HTTP/1.0\n\n").0, Err(405));
        assert_eq!(request("CONNECT a HTTP/1.0\n\n").0, Err(400));
        assert_eq!(request("GET / HTTP/1.0\nHost: a\nHost: b\n\n").0, Err(400));
        assert_eq!(request("GET / HTTP/1.0\nbad\n\n").0, Err(400));
        assert_eq!(request("GET x HTTP/1.0\n\n").0, Err(400));
    }

    #[test]
    fn hosts() {
        for bad in ["", ".", "a..b", "a..", "a/b", "a:1.2", "a:123456", "x[::1]", "[::1", "[::1].", "a:1:2"] {
            assert_eq!(valid_host(bad), None, "{bad}");
        }
        assert_eq!(valid_host("A.b.:"), Some("a.b".into()));
        assert_eq!(valid_host("[::1]:80"), Some("[::1]".into()));
    }

    #[test]
    fn error_page() {
        assert!(page(404).contains("<title>404 Not Found</title>"));
    }
}
