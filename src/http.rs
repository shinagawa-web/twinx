//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{Config, Level, Proxy, Server};
use crate::vars::{Request, Sent};

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
        let mut r = Request {
            method: String::new(),
            uri: String::new(),
            target: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: server.names.first().cloned().unwrap_or_default(),
            peer,
            started,
            pipelined,
            length: head.len(),
            body: Vec::new(),
            body_file: None,
        };
        let parsed = parse(&mut r, &head);
        let (prefix, level) = location(server, &r.uri);
        let length = header(&r, "content-length").map_or(Ok(0), |v| v.parse::<u64>().map_err(|_| 400u16));
        let parsed = parsed.and(length).and_then(|n| if n > level.max_body { Err(413) } else { Ok(n as usize) });
        if let Ok(n) = parsed {
            while buf.len() < n {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 { return; }
                buf.extend_from_slice(&chunk[..read]);
            }
            r.length += n;
            keep_body(&mut r, level, buf.drain(..n).collect());
        }
        let open = exchange(&mut stream, &r, parsed.map(drop), prefix, level);
        if !level.body_in_file_only { r.body_file.map(std::fs::remove_file); }
        if !open { return linger(&mut stream); }
    }
}

/// Closes the connection as nginx's lingering close does: stops sending, then
/// reads what the client still sends so that it gets the whole answer.
fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut chunk = [0u8; 4096];
    while matches!(stream.read(&mut chunk), Ok(n) if n > 0) {}
}

/// Keeps the request body in memory, or in a file under client_body_temp_path
/// when it does not fit client_body_buffer_size or client_body_in_file_only is on.
fn keep_body(r: &mut Request, level: &Level, body: Vec<u8>) {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let to_file = !body.is_empty() && (level.body_in_file_only || body.len() as u64 > level.body_buffer);
    if !to_file { return r.body = body; }
    let path = level.body_temp_path.join(format!("{:010}", NEXT.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::create_dir_all(&level.body_temp_path);
    r.body_file = std::fs::write(&path, &body).is_ok().then_some(path);
}

fn header<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// An answer before it is written: the status, Content-Type, the other headers in order, and the body.
#[derive(Debug, Default)]
struct Response {
    status: u16,
    ctype: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// The page nginx generates for an error status.
fn special(status: u16) -> Response {
    let ctype = Some("text/html".to_string());
    Response { status, ctype, headers: Vec::new(), body: page(status).into_bytes() }
}

/// Answers one request; true when the connection stays open for the next one.
fn exchange(stream: &mut TcpStream, r: &Request, parsed: Result<(), u16>, prefix: &str, level: &Level) -> bool {
    let mut resp = match (parsed, &level.ret, &level.proxy) {
        (Err(status), _, _) => special(status),
        (Ok(()), Some((code, text)), _) if text.0.is_empty() && *code >= 400 => special(*code),
        (Ok(()), Some((code, text)), _) => {
            let ctype = Some("text/plain".to_string());
            Response { status: *code, ctype, headers: Vec::new(), body: text.render(r, &Sent::default()).into_bytes() }
        }
        (Ok(()), None, Some(p)) => proxy(p, r, prefix),
        (Ok(()), None, None) => special(404),
    };
    if let Some(ep) = level.error_page.iter().find(|e| e.codes.contains(&resp.status)) {
        let location = ep.url.render(r, &Sent::default());
        resp = special(ep.status.unwrap_or(302));
        resp.headers.push(("Location".to_string(), location));
    }
    const ADDED: &[u16] = &[200, 201, 204, 206, 301, 302, 303, 304, 307, 308];
    for (name, value, always) in &level.add_header {
        let value = value.render(r, &Sent::default());
        if !value.is_empty() && (*always || ADDED.contains(&resp.status)) { resp.headers.push((name.clone(), value)); }
    }
    let status = resp.status;
    let keepalive = parsed.is_ok() && keepalive(r) && ![400, 413, 414, 500, 501].contains(&status);
    let mut out = Vec::new();
    if status != 444 {
        let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
        let ctype = resp.ctype.map(|t| format!("Content-Type: {t}\r\n")).unwrap_or_default();
        let connection = if keepalive { "keep-alive" } else { "close" };
        let len = resp.body.len();
        let mut head = format!("HTTP/1.1 {status} {reason}\r\nServer: {NAME}\r\nDate: {date}\r\n{ctype}Content-Length: {len}\r\nConnection: {connection}\r\n");
        resp.headers.iter().for_each(|(n, v)| head += &format!("{n}: {v}\r\n"));
        out = (head + "\r\n").into_bytes();
    }
    let body_len = if r.method == "HEAD" || status == 444 { 0 } else { resp.body.len() };
    out.extend_from_slice(&resp.body[..body_len]);
    let written = stream.write_all(&out).is_ok();
    let sent = Sent { status, bytes: out.len(), body: body_len };
    for log in &level.access_log {
        let line = log.format.log_line(r, &sent) + "\n";
        let _ = (&*log.file).write_all(line.as_bytes());
    }
    written && keepalive && status != 444
}

/// Passes the request to the proxied servers in turn, as HTTP/1.0 with
/// "Connection: close", until one answers with a response head.
fn proxy(p: &Proxy, r: &Request, prefix: &str) -> Response {
    let args = r.target.find('?').map_or("", |i| &r.target[i..]);
    let uri = p.uri.as_ref().map_or_else(|| r.target.clone(), |u| format!("{u}{}{args}", &r.uri[prefix.len()..]));
    let body = r.body_file.as_ref().map_or_else(|| r.body.clone(), |f| std::fs::read(f).unwrap_or_default());
    let mut req = format!("{} {uri} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n", r.method, p.host);
    if header(r, "content-length").is_some() { req += &format!("Content-Length: {}\r\n", body.len()); }
    const DROPPED: &[&str] = &["host", "connection", "content-length", "transfer-encoding", "keep-alive", "te", "expect", "upgrade"];
    let passed = r.headers.iter().filter(|(n, _)| !DROPPED.contains(&n.to_ascii_lowercase().as_str()));
    passed.for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    let mut req = (req + "\r\n").into_bytes();
    req.extend_from_slice(&body);
    p.peers.iter().find_map(|peer| fetch(peer, &req)).unwrap_or_else(|| special(502))
}

/// Sends a request to one server and reads its whole answer.
fn fetch(peer: &SocketAddr, req: &[u8]) -> Option<Response> {
    let timeout = Duration::from_secs(60);
    let mut s = TcpStream::connect_timeout(peer, timeout).ok()?;
    let _ = s.set_read_timeout(Some(timeout));
    let mut answer = Vec::new();
    s.write_all(req).and_then(|_| s.read_to_end(&mut answer)).ok()?;
    let end = head_end(&answer)?;
    let head = String::from_utf8_lossy(&answer[..end]).into_owned();
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty());
    let status = lines.next()?.strip_prefix("HTTP/1.")?.get(2..)?.split(' ').find(|w| !w.is_empty())?.parse().ok()?;
    let mut resp = Response { status, body: answer[end..].to_vec(), ..Response::default() };
    const HIDDEN: &[&str] = &["date", "server", "connection", "keep-alive", "transfer-encoding", "content-length", "x-pad"];
    for (name, value) in lines.filter_map(|l| l.split_once(':')) {
        let (lower, value) = (name.to_ascii_lowercase(), value.trim().to_string());
        if lower == "content-type" { resp.ctype = Some(value); continue; }
        if !HIDDEN.contains(&lower.as_str()) && !lower.starts_with("x-accel-") { resp.headers.push((name.to_string(), value)); }
    }
    Some(resp)
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
    r.target = path.to_string();
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
    let connection = header(r, "connection").map(|v| v.to_ascii_lowercase());
    let http11 = r.line.ends_with("HTTP/1.1");
    connection.map_or(http11, |c| if http11 { c != "close" } else { c == "keep-alive" })
}

/// The location whose prefix is the longest one matching the URI, or the server's own settings.
fn location<'a>(server: &'a Server, uri: &str) -> (&'a str, &'a Level) {
    let matching = server.locations.iter().filter(|(prefix, _)| uri.starts_with(prefix.as_str()));
    matching.max_by_key(|(prefix, _)| prefix.len()).map_or(("", &server.level), |(prefix, level)| (prefix, level))
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
            target: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: "localhost".into(),
            peer: "127.0.0.1:1".parse().unwrap(),
            started: Instant::now(),
            pipelined: false,
            length: 0,
            body: Vec::new(),
            body_file: None,
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
    fn fetches_from_a_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 201 Created\r\nServer: x\r\nContent-Type: a/b\r\nX-A: 1\r\nX-Accel-B: 2\r\n\r\nbody").unwrap();
        });
        let resp = fetch(&addr, b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!((resp.status, resp.ctype.as_deref(), resp.body.as_slice()), (201, Some("a/b"), &b"body"[..]));
        assert_eq!(resp.headers, vec![("X-A".to_string(), "1".to_string())]);
    }

    #[test]
    fn keeps_large_bodies_in_files() {
        let dir = std::env::temp_dir().join(format!("twinx-body-{}", std::process::id()));
        let level = Level { body_buffer: 4, body_temp_path: dir, ..Level::default() };
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        keep_body(&mut r, &level, b"abc".to_vec());
        assert_eq!((r.body.as_slice(), r.body_file.is_none()), (&b"abc"[..], true));
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        keep_body(&mut r, &level, b"abcde".to_vec());
        assert_eq!(std::fs::read(r.body_file.unwrap()).unwrap(), b"abcde");
    }

    #[test]
    fn error_page() {
        assert!(page(404).contains("<title>404 Not Found</title>"));
    }
}
