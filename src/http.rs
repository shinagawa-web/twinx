//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{Config, Fallback, Level, Match, Proxy, Rewrite, Server, ServerName, TryFiles};
use crate::vars::Template;
use crate::expires;
use crate::upstream::{Peer, Upstream};
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
/// Opens the listening sockets: the master does this, so that bind errors stop it and every worker shares them.
pub fn bind(config: &Config) -> Result<Vec<(TcpListener, SocketAddr)>, String> {
    let mut addrs: Vec<SocketAddr> = config.servers.iter().flat_map(|s| s.listen.clone()).collect();
    addrs.dedup();
    addrs.into_iter().map(|addr| TcpListener::bind(addr).map(|l| (l, addr)).map_err(|e| format!("bind() to {addr} failed ({e})"))).collect()
}

/// Accepts connections on the listening sockets, in a worker process.
pub fn accept(config: Arc<Config>, listeners: &[(TcpListener, SocketAddr)]) -> Result<(), String> {
    for (listener, addr) in listeners {
        let (listener, addr, config) = (listener.try_clone().map_err(|e| e.to_string())?, *addr, config.clone());
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

fn connection(config: &Config, mut stream: TcpStream, listen: SocketAddr) {
    let local = stream.local_addr().unwrap_or(listen);
    let peer = stream.peer_addr().unwrap_or(local);
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    // After a kept-alive answer: how long the connection waits for the next request.
    let (connected, mut requests, mut idle) = (Instant::now(), 0, None);
    loop {
        let (pipelined, started) = (!buf.is_empty(), Instant::now());
        requests += 1;
        let end = loop {
            if let Some(end) = head_end(&buf) { break end; }
            let _ = stream.set_read_timeout(idle.filter(|_| buf.is_empty()));
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 { return; }
            buf.extend_from_slice(&chunk[..n]);
        };
        let _ = stream.set_read_timeout(None);
        let head: Vec<u8> = buf.drain(..end).collect();
        let mut r = Request {
            method: String::new(),
            uri: String::new(),
            target: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: String::new(),
            peer,
            local,
            started,
            pipelined,
            connected,
            requests,
            length: head.len(),
            body: Vec::new(),
            body_file: None,
            upstream_addr: None,
            captures: Vec::new(),
            limit_rate: Default::default(),
            client: std::os::fd::AsRawFd::as_raw_fd(&stream),
        };
        // Header lines are read with the settings of the default server of the address.
        let default = config.servers.iter().find(|s| s.listen.contains(&listen)).unwrap_or(&config.servers[0]);
        let parsed = parse(&mut r, &head, &default.level);
        let (server, captures) = server(config, listen, r.host.as_deref());
        r.captures = captures;
        let parsed = parsed.and_then(|()| if r.headers.len() > server.level.max_headers { Err(400) } else { Ok(()) });
        r.server_name = server.name.clone();
        let found = location(server, &r.uri);
        let level = found.1;
        let framing = parsed.and_then(|()| framing(&r)).and_then(|n| if n.unwrap_or(0) > level.max_body { Err(413) } else { Ok(n) });
        let expect = header(&r, "expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        if framing.is_ok() && expect && r.line.ends_with("HTTP/1.1") { let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n"); }
        let parsed = match framing {
            Err(status) => Err(status),
            Ok(length) => loop {
                match take_body(&buf, length, level.max_body) {
                    Ok(None) => {}
                    Ok(Some((body, used))) => {
                        r.length += used;
                        buf.drain(..used);
                        keep_body(&mut r, level, body);
                        break Ok(());
                    }
                    Err(status) => break Err(status),
                }
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 { return; }
                buf.extend_from_slice(&chunk[..read]);
            },
        };
        idle = exchange(&mut stream, server, &r, parsed, found, local);
        if !level.body_in_file_only { r.body_file.map(std::fs::remove_file); }
        if idle.is_none() { return linger(&mut stream); }
    }
}

/// How the request body is framed: Some(length), or None when it is chunked.
fn framing(r: &Request) -> Result<Option<u64>, u16> {
    let te: Vec<&String> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding")).map(|(_, v)| v).collect();
    let length = header(r, "content-length");
    if te.is_empty() { return length.map_or(Ok(Some(0)), |v| v.parse().map(Some).map_err(|_| 400)); }
    if te.len() > 1 || length.is_some() || !r.line.ends_with("HTTP/1.1") { return Err(400); }
    if te[0].eq_ignore_ascii_case("chunked") { Ok(None) } else { Err(501) }
}

/// The whole body and the bytes it took in the buffer, None while more has to be read.
fn take_body(buf: &[u8], length: Option<u64>, max: u64) -> Result<Option<(Vec<u8>, usize)>, u16> {
    match length {
        Some(n) => Ok((buf.len() as u64 >= n).then(|| (buf[..n as usize].to_vec(), n as usize))),
        None => dechunk(buf, max),
    }
}

/// Decodes a chunked body; 400 for malformed chunks, 413 past client_max_body_size.
fn dechunk(buf: &[u8], max: u64) -> Result<Option<(Vec<u8>, usize)>, u16> {
    let (mut body, mut at) = (Vec::new(), 0);
    let line = |at: usize| buf[at..].iter().position(|&c| c == b'\n').map(|n| (String::from_utf8_lossy(&buf[at..at + n]).trim_end_matches('\r').to_string(), at + n + 1));
    loop {
        let Some((size, next)) = line(at) else { return Ok(None) };
        let size = u64::from_str_radix(size.split(';').next().unwrap_or_default().trim(), 16).map_err(|_| 400u16)?;
        at = next;
        if size == 0 { break; }
        if body.len() as u64 + size > max { return Err(413); }
        let end = at + size as usize;
        let after = buf.get(end..).unwrap_or_default();
        if after.is_empty() || after == b"\r" { return Ok(None); }
        let skip = if after.starts_with(b"\r\n") { 2 } else if after.starts_with(b"\n") { 1 } else { return Err(400) };
        body.extend_from_slice(&buf[at..end]);
        at = end + skip;
    }
    loop {
        let Some((trailer, next)) = line(at) else { return Ok(None) };
        at = next;
        if trailer.is_empty() { return Ok(Some((body, at))); }
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
    /// Whether "Vary: Accept-Encoding" is sent when gzip_vary is on.
    vary: bool,
    /// Every header of the proxied server's answer, for $upstream_http_*.
    upstream: Vec<(String, String)>,
    /// The URI and arguments to redirect to internally: the index module's, with
    /// "index.html" added, or the last parameter of try_files.
    internal: Option<String>,
    /// The proxied servers tried ($upstream_addr), and how long each took ($upstream_response_time).
    upstream_addr: Option<String>,
    upstream_time: Option<Vec<[Option<u128>; 3]>>,
    /// The host of the proxy_pass URL ($proxy_host).
    proxy_host: Option<String>,
    /// Whether the internal redirect makes the request a GET, unless it is a
    /// HEAD (X-Accel-Redirect).
    as_get: bool,
    /// Whether the length is not known when the head is sent (the gzip filter
    /// compresses as it goes): the body is chunked, or the connection closed after it.
    unknown_length: bool,
}

/// The page nginx generates for an error status.
fn special(status: u16) -> Response {
    let ctype = Some("text/html".to_string());
    Response { status, ctype, body: page(status).into_bytes(), ..Response::default() }
}

const REDIRECTS: &[u16] = &[301, 302, 303, 307, 308];

/// A redirect: the page nginx generates for the status, with a Location.
fn redirect(status: u16, location: String) -> Response {
    let mut resp = special(status);
    resp.headers.push(("Location".to_string(), location));
    resp
}

/// The answer the location gives, before error_page and the headers every answer gets.
fn respond(r: &Request, parsed: Result<(), u16>, (prefix, level, auto): Found) -> Response {
    // set $limit_rate: a value that is not a size leaves it as it was.
    for value in level.set.iter().filter(|_| parsed.is_ok()) {
        if let Ok(rate) = crate::conf::size(&value.render(r, &Sent::default())) { r.limit_rate.set(rate); }
    }
    let rewrite = level.rewrite.iter().find(|rw| rw.regex.is_match(&r.uri));
    let url = rewrite.map(|rw| (rw, rw.url.render(r, &Sent::default()), args(r)));
    let with_args = |(rw, url, args): (&Rewrite, String, &str)| {
        let sep = if url.contains('?') { "&" } else { "?" };
        if rw.add_args && !args.is_empty() { format!("{url}{sep}{}", &args[1..]) } else { url }
    };
    match (parsed, url) {
        (Err(status), _) => special(status),
        (Ok(()), _) if auto => redirect(301, format!("{}/{}", escape_uri(&r.uri), args(r))),
        // "break": the location goes on with the new URI, without the rewrite module's directives.
        (Ok(()), Some(u)) if u.0.internal => {
            let mut to = r.clone();
            to.target = with_args(u);
            to.uri = to.target.split('?').next().unwrap_or_default().to_string();
            serve(&to, level, prefix, None)
        }
        (Ok(()), Some(u)) => redirect(u.0.status, with_args(u)),
        (Ok(()), None) => serve(r, level, prefix, level.ret.as_ref()),
    }
}

/// The answer of return, else of proxy_pass, else of the static module.
fn serve(r: &Request, level: &Level, prefix: &str, ret: Option<&(u16, Template)>) -> Response {
    match (ret, &level.proxy, level.try_files.as_deref()) {
        (Some((code, text)), _, _) if REDIRECTS.contains(code) => redirect(*code, text.render(r, &Sent::default())),
        (Some((code, text)), _, _) if text.0.is_empty() && *code >= 400 => special(*code),
        (Some((code, text)), _, _) => {
            let ctype = Some("text/plain".to_string());
            Response { status: *code, ctype, body: text.render(r, &Sent::default()).into_bytes(), ..Response::default() }
        }
        (None, _, Some(tf)) => try_files(tf, level, r, prefix),
        (None, Some(p), None) => proxy(p, level, r, prefix),
        (None, None, None) => file(level, r, prefix),
    }
}

/// try_files: the first parameter whose file exists (a directory when it ends
/// with "/") is served, the URI changed to it; when none does, the last
/// parameter gives a status or a URI to redirect to internally.
fn try_files(tf: &TryFiles, level: &Level, r: &Request, prefix: &str) -> Response {
    let sent = Sent::default();
    for (name, dir) in &tf.files {
        let name = name.render(r, &sent);
        let base = level.alias.as_ref().unwrap_or(&level.root);
        // With alias, the location's prefix at the start of the name is replaced, as in the URI.
        let rest = level.alias.as_ref().and(level.alias_len).and_then(|n| name.strip_prefix(r.uri.get(..n)?)).unwrap_or(&name);
        let path = PathBuf::from(format!("{}{rest}", base.display()));
        if std::fs::metadata(&path).is_ok_and(|m| m.is_dir() == *dir) {
            let to = Request { uri: name, ..r.clone() };
            return match &level.proxy { Some(p) => proxy(p, level, &to, prefix), None => file_at(level, &to, path) };
        }
    }
    match &tf.fallback {
        Fallback::Status(code) => special(*code),
        Fallback::Uri(uri) => Response { internal: Some(uri.render(r, &sent)), ..Response::default() },
    }
}

/// "?" and the arguments of the request, or "" when it has none.
fn args(r: &Request) -> &str {
    r.target.find('?').map_or("", |i| &r.target[i..])
}

/// Answers one request; when the connection stays open for the next one, how
/// long it waits for it (keepalive_timeout).
fn exchange(stream: &mut TcpStream, server: &Server, r: &Request, parsed: Result<(), u16>, found: Found, local: SocketAddr) -> Option<Duration> {
    let (mut resp, mut level, mut last) = answer(server, r, parsed, found);
    if let Some(ep) = level.error_page.iter().find(|e| e.codes.contains(&resp.status)) {
        let url = ep.url.render(r, &Sent::default());
        let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && l.path == url);
        if url.starts_with('/') || named.is_some() {
            // An internal redirect: the URI is answered as a GET (or HEAD) request
            // by its location, with the error's status unless that answer has its own.
            // A named location answers the request as it is.
            let mut to = r.clone();
            to.upstream_addr = resp.upstream_addr.take();
            if named.is_none() {
                to.uri = url.split('?').next().unwrap_or_default().to_string();
                to.target = url;
                to.method = if r.method == "HEAD" { "HEAD" } else { "GET" }.to_string();
            }
            let status = ep.status.unwrap_or(resp.status);
            let found = named.map_or_else(|| location(server, &to.uri), |l| (l.path.as_str(), &l.level, false));
            (resp, level, last) = answer(server, &to, Ok(()), found);
            if resp.status == 200 { resp.status = status; }
        } else {
            // A named location that does not exist is an error.
            resp = if url.starts_with('@') { special(500) } else { redirect(ep.status.filter(|s| REDIRECTS.contains(s)).unwrap_or(302), url) };
        }
    }
    // The headers and the log see the request as the last internal redirect left it ($uri).
    let r = &last;
    not_modified(r, level, &mut resp);
    if let Some(h) = resp.headers.iter_mut().find(|h| h.0.eq_ignore_ascii_case("location") && h.1.starts_with('/')).filter(|_| level.absolute_redirect) {
        let host = if level.server_name_in_redirect { r.server_name.clone() } else { r.host.clone().unwrap_or_else(|| local.ip().to_string()) };
        let port = if level.port_in_redirect && local.port() != 80 { format!(":{}", local.port()) } else { String::new() };
        h.1 = format!("http://{host}{port}{}", h.1);
    }
    let gzipped = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("content-encoding") && h.1.eq_ignore_ascii_case("gzip"));
    if level.gunzip && gzipped {
        resp.vary = true;
        if !gzip_ok(r, level) { gunzip(&mut resp); }
    }
    const ADDED: &[u16] = &[200, 201, 204, 206, 301, 302, 303, 304, 307, 308];
    let added = ADDED.contains(&resp.status);
    let expires = level.expires.as_ref().filter(|_| added).and_then(|e| expires::parse(&e.render(r, &Sent::default())));
    let modified = resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case("last-modified"));
    let modified = modified.and_then(|h| chrono::DateTime::parse_from_rfc2822(&h.1).ok()).map(|t| t.timestamp());
    if let Some((e, cc)) = expires.and_then(|e| expires::headers(e, modified)) {
        resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("expires") && !h.0.eq_ignore_ascii_case("cache-control"));
        resp.headers.extend([("Expires".to_string(), e), ("Cache-Control".to_string(), cc)]);
    }
    // What has been sent so far, for $sent_http_* and $upstream_http_*.
    let so_far = |resp: &Response, trailers: &[(String, String)]| {
        let ctype = resp.ctype.iter().map(|t| ("Content-Type".to_string(), t.clone()));
        let headers = ctype.chain(resp.headers.iter().cloned()).collect();
        Sent { status: resp.status, headers, upstream: resp.upstream.clone(), trailers: trailers.to_vec(), upstream_addr: resp.upstream_addr.clone(), upstream_time: resp.upstream_time.clone(), proxy_host: resp.proxy_host.clone(), ..Sent::default() }
    };
    // While the head is made, the last proxied server is still sending ($upstream_response_time).
    let at_head = |resp: &Response| {
        let mut sent = so_far(resp, &[]);
        sent.upstream_time.iter_mut().filter_map(|t| t.last_mut()).for_each(|t| t[2] = None);
        sent
    };
    for (name, value, _) in level.add_header.iter().filter(|h| h.2 || added) {
        let value = value.render(r, &at_head(&resp));
        // These replace what the response has, and an empty value removes it.
        if ["etag", "last-modified"].contains(&name.to_ascii_lowercase().as_str()) { resp.headers.retain(|h| !h.0.eq_ignore_ascii_case(name)); }
        if !value.is_empty() { resp.headers.push((name.clone(), value)); }
    }
    gzip(r, level, &mut resp);
    let status = resp.status;
    // A body of unknown length is chunked for HTTP/1.1; otherwise the connection
    // closes after it. A HEAD answer has neither.
    // add_trailer makes it chunked too, except for a status that has no body.
    let unknown = resp.unknown_length && r.method != "HEAD";
    let trailing = level.add_trailer.iter().any(|t| t.2 || added) && r.method != "HEAD" && ![204, 304].contains(&status);
    let chunked = (unknown || trailing) && r.line.ends_with("HTTP/1.1");
    let keepalive = parsed.is_ok() && keepalive(r) && keeps_alive(r, level) && ![400, 413, 414, 500, 501].contains(&status) && (chunked || !unknown);
    let mut out = Vec::new();
    // 444 closes the connection without an answer; 499 is the status of a client that closed it.
    let silent = [444, 499].contains(&status);
    if !silent {
        let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
        let ctype = resp.ctype.as_ref().map(|t| format!("Content-Type: {t}\r\n")).unwrap_or_default();
        let connection = if keepalive { "keep-alive" } else { "close" };
        let len = resp.body.len();
        let length = if chunked { "Transfer-Encoding: chunked\r\n".to_string() } else if !resp.unknown_length && status != 304 { format!("Content-Length: {len}\r\n") } else { String::new() };
        let header = level.keepalive_header.filter(|_| keepalive).map(|t| format!("Keep-Alive: timeout={t}\r\n")).unwrap_or_default();
        let vary = if resp.vary && level.gzip_vary { "Vary: Accept-Encoding\r\n" } else { "" };
        let mut head = format!("HTTP/1.1 {status} {reason}\r\nServer: {NAME}\r\nDate: {date}\r\n{ctype}{length}Connection: {connection}\r\n{header}{vary}");
        resp.headers.iter().for_each(|(n, v)| head += &format!("{n}: {v}\r\n"));
        out = (head + "\r\n").into_bytes();
    }
    let body_len = if r.method == "HEAD" || silent { 0 } else { resp.body.len() };
    if chunked && body_len > 0 { out.extend_from_slice(format!("{body_len:x}\r\n").as_bytes()); }
    out.extend_from_slice(&resp.body[..body_len]);
    // The trailers are made after the body, each seeing those before it ($sent_trailer_*).
    let mut trailers = Vec::new();
    for (name, value, _) in level.add_trailer.iter().filter(|t| chunked && (t.2 || added)) {
        let value = value.render(r, &so_far(&resp, &trailers));
        if !value.is_empty() { trailers.push((name.clone(), value)); }
    }
    if chunked {
        out.extend_from_slice(if body_len > 0 { b"\r\n0\r\n" } else { b"0\r\n" });
        trailers.iter().for_each(|(n, v)| out.extend_from_slice(format!("{n}: {v}\r\n").as_bytes()));
        out.extend_from_slice(b"\r\n");
    }
    // limit_rate: a rate set $limit_rate or X-Accel-Limit-Rate gave, else the location's.
    let size = |t: &Template| crate::conf::size(&t.render(r, &Sent::default())).unwrap_or(0);
    let rate = r.limit_rate.get().unwrap_or_else(|| size(&level.limit_rate));
    let written = send(stream, &out, rate, size(&level.limit_rate_after), r.started);
    let sent = Sent { bytes: out.len(), body: body_len, ..so_far(&resp, &trailers) };
    if written { post_action(server, r, level); }
    level.access_log.iter().for_each(|log| log.write(level, r, &sent));
    (written && keepalive && !silent).then_some(level.keepalive_timeout)
}

/// post_action: once the answer is sent, the request is redirected internally
/// to the URI (or named location) post_action gives, and what that answers is
/// discarded. The location it goes to does not run its own post_action.
fn post_action(server: &Server, r: &Request, level: &Level) {
    let Some(url) = &level.post_action else { return };
    let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && &l.path == url);
    // A named location answers the request as it is; a URI replaces the request's.
    let uri = || url.split('?').next().unwrap_or_default().to_string();
    let to = if named.is_some() { r.clone() } else { Request { uri: uri(), target: url.clone(), ..r.clone() } };
    let found = named.map_or_else(|| location(server, &to.uri), |l| (l.path.as_str(), &l.level, false));
    answer(server, &to, Ok(()), found);
}

/// The not modified filter, as ngx_http_not_modified_filter() is: a 200
/// answer is 412 when If-Match fails, and 304, with no
/// body, Content-Type, Accept-Ranges or Content-Encoding, when the
/// If-Modified-Since (as if_modified_since says) and If-None-Match it has hold.
fn not_modified(r: &Request, level: &Level, resp: &mut Response) {
    if resp.status != 200 { return; }
    let sent = |name: &str| resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    let (modified, etag) = (sent("last-modified").and_then(|t| expires::http_time(&t)), sent("etag"));
    // If-Unmodified-Since, which no test needs, is not done yet.
    if header(r, "if-match").is_some_and(|v| !etag_match(v, etag.as_deref(), false)) { return *resp = special(412); }
    let (ims, inm) = (header(r, "if-modified-since"), header(r, "if-none-match"));
    let same = |t: &str| level.if_modified_since.zip(modified).is_some_and(|(before, m)| expires::http_time(t).is_some_and(|t| t == m || before && t > m));
    if (ims.is_none() && inm.is_none()) || ims.is_some_and(|t| !same(t)) || inm.is_some_and(|v| !etag_match(v, etag.as_deref(), true)) { return; }
    (resp.status, resp.ctype, resp.body) = (304, None, Vec::new());
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges") && !h.0.eq_ignore_ascii_case("content-encoding"));
}

/// Whether an If-Match (or, weak, If-None-Match) list has the ETag, as
/// ngx_http_test_if_match() reads it: "*" or one of its entries, a weak
/// comparison ignoring "W/".
fn etag_match(list: &str, etag: Option<&str>, weak: bool) -> bool {
    let Some(etag) = etag else { return false };
    if list == "*" { return true; }
    let etag = etag.strip_prefix("W/").filter(|e| weak && !e.is_empty()).unwrap_or(etag);
    list.split(',').map(|e| e.trim_matches([' ', '\t'])).any(|e| (if weak { e.strip_prefix("W/").unwrap_or(e) } else { e }) == etag)
}

/// Writes an answer, paced as ngx_http_write_filter() paces it with a rate:
/// by the end of each second since the request started (counted in whole
/// seconds of the clock) up to limit_rate_after bytes and limit_rate bytes for
/// each second have gone, and after each write the time it is worth at that
/// rate is waited. Without a rate it is written at once.
fn send(stream: &mut TcpStream, out: &[u8], rate: u64, after: u64, started: Instant) -> bool {
    if rate == 0 { return stream.write_all(out).is_ok(); }
    let clock = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let start = (clock() - started.elapsed()).as_secs() as i64;
    let (rate, mut sent) = (rate as i64, 0);
    while sent < out.len() {
        let limit = rate * (clock().as_secs() as i64 - start + 1) - (sent as i64 - after as i64);
        if limit <= 0 { thread::sleep(Duration::from_millis((-limit * 1000 / rate + 1) as u64)); continue; }
        let n = (limit as usize).min(out.len() - sent);
        if stream.write_all(&out[sent..sent + n]).is_err() { return false; }
        sent += n;
        if sent < out.len() { thread::sleep(Duration::from_millis(n as u64 * 1000 / rate as u64)); }
    }
    true
}

/// Whether the location lets the connection serve another request, as
/// ngx_http_update_location_config() decides: keepalive_timeout is not zero,
/// keepalive_requests and keepalive_time are not reached, and keepalive_disable
/// does not name the browser.
fn keeps_alive(r: &Request, level: &Level) -> bool {
    let (msie6, safari) = browser(header(r, "user-agent").unwrap_or_default());
    let limits = !level.keepalive_timeout.is_zero() && r.requests < level.keepalive_requests && r.connected.elapsed() <= level.keepalive_time;
    limits && !(msie6 && r.method == "POST" && level.keepalive_disable_msie6) && !(safari && level.keepalive_disable_safari)
}

/// Whether a User-Agent is MSIE 6 or older, and whether it is Safari on Mac OS X,
/// as ngx_http_process_user_agent() tells them (Opera is neither).
fn browser(ua: &str) -> (bool, bool) {
    let b = ua.as_bytes();
    let has = |h: &[u8], n: &[u8]| h.windows(n.len()).any(|w| w == n);
    let msie = b.windows(5).position(|w| w == b"MSIE ").filter(|i| i + 7 < b.len());
    let opera = has(b, b"Opera");
    let msie6 = !opera && msie.is_some_and(|i| b[i + 6] == b'.' && (matches!(b[i + 5], b'4' | b'5') || b[i + 5] == b'6' && !has(&b[i + 8..], b"SV1")));
    let other = has(b, b"Gecko/") || has(b, b"Chrome/");
    (msie6, msie.is_none() && !opera && !other && has(b, b"Safari/") && has(b, b"Mac OS X"))
}

/// The answer of the location found, after the internal redirects of the
/// index module, and the settings of the location that gave it.
fn answer<'a>(server: &'a Server, r: &Request, parsed: Result<(), u16>, (prefix, mut level, auto): Found<'a>) -> (Response, &'a Level, Request) {
    let mut resp = respond(r, parsed, (prefix, level, auto));
    let (mut redirects, mut to) = (0, r.clone());
    while let Some(target) = resp.internal.take() {
        // nginx gives up after 10 internal redirects.
        redirects += 1;
        if resp.as_get && to.method != "HEAD" { to.method = "GET".to_string(); }
        to.uri = target.split('?').next().unwrap_or_default().to_string();
        to.target = target;
        let found = location(server, &to.uri);
        level = found.1;
        resp = if redirects > 10 { special(500) } else { respond(&to, Ok(()), found) };
    }
    (resp, level, to)
}

/// Serves a file under root (or alias), as nginx's static module does; a
/// directory asked for without the trailing "/" is redirected to it. A URI
/// that ends with "/" is the index module's: "index.html" in that directory,
/// by an internal redirect, else 403 when the directory exists and 404 when not.
fn file(level: &Level, r: &Request, prefix: &str) -> Response {
    if !matches!(r.method.as_str(), "GET" | "HEAD" | "POST") { return special(405); }
    let path = match &level.alias {
        Some(alias) => std::path::PathBuf::from(format!("{}{}", alias.display(), r.uri.get(prefix.len()..).unwrap_or_default())),
        None => level.root.join(r.uri.trim_start_matches('/')),
    };
    if r.uri.ends_with('/') { return index(level, r, &path); }
    file_at(level, r, path)
}

/// The index module, as ngx_http_index_handler() does it: an internal redirect
/// to the first index that exists in the directory, or to an index that starts
/// with "/"; 403 when the directory exists but none does, 404 when it does not.
fn index(level: &Level, r: &Request, dir: &std::path::Path) -> Response {
    use std::io::ErrorKind::{InvalidFilename, NotADirectory, NotFound, PermissionDenied};
    let mut dir_tested = false;
    for name in level.index.iter().map(|t| t.render(r, &Sent::default())) {
        if name.starts_with('/') { return Response { internal: Some(format!("{name}{}", args(r))), ..Response::default() }; }
        let file = dir.join(&name);
        let err = match std::fs::metadata(&file) {
            Ok(_) => return Response { internal: Some(format!("{}{name}{}", r.uri, args(r))), ..Response::default() },
            Err(e) => e,
        };
        if matches!(err.kind(), NotADirectory | InvalidFilename | PermissionDenied) { return index_error(level, r, &file, &err); }
        // A file that is not found is skipped once the directory is known to
        // exist; a directory that does not exist is not found itself.
        let skipped = err.kind() == NotFound && (dir_tested || dir.is_dir());
        if !skipped { return if err.kind() == NotFound { index_error(level, r, &file, &err) } else { special(500) }; }
        dir_tested = true;
    }
    error_log(level, r, &format!("directory index of \"{}/\" is forbidden", dir.display().to_string().trim_end_matches('/')));
    special(403)
}

/// 403 for a path that may not be read, else 404, logged as nginx does.
fn index_error(level: &Level, r: &Request, path: &std::path::Path, err: &std::io::Error) -> Response {
    let reason = format!("({}: {})", err.raw_os_error().unwrap_or(0), err.to_string().split(" (os error").next().unwrap_or_default());
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        error_log(level, r, &format!("\"{}\" is forbidden {reason}", path.display()));
        return special(403);
    }
    if level.log_not_found { error_log(level, r, &format!("\"{}\" is not found {reason}", path.display())); }
    special(404)
}

/// Writes an error of the request to the error_log of its level, as nginx's
/// lines are: the time, the level, the process, the message and the request.
fn error_log(level: &Level, r: &Request, msg: &str) {
    let Some(mut log) = level.error_log.as_deref() else { return };
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let host = r.host.as_ref().map(|h| format!(", host: \"{h}\"")).unwrap_or_default();
    let line = format!("{time} [error] {}#0: {msg}, client: {}, server: {}, request: \"{}\"{host}\n", std::process::id(), r.peer.ip(), r.server_name, r.line);
    let _ = log.write_all(line.as_bytes());
}

/// Serves the file at a path, or redirects to the directory there.
fn file_at(level: &Level, r: &Request, path: PathBuf) -> Response {
    if !r.uri.ends_with('/') && path.is_dir() { return redirect(301, format!("{}/{}", escape_uri(&r.uri), args(r))); }
    let read = |p: &std::path::Path| std::fs::metadata(p).ok().filter(|m| m.is_file()).zip(std::fs::read(p).ok());
    // gzip_static: the file with ".gz" added, for clients that take gzip ("always": for all).
    let gz = level.gzip_static.filter(|_| r.method != "POST").and_then(|always| read(&path.with_added_extension("gz")).map(|f| (always, f)));
    let vary = gz.is_some();
    let gz = gz.filter(|(always, _)| *always || gzip_ok(r, level)).map(|g| g.1);
    let Some((meta, body)) = gz.as_ref().cloned().or_else(|| read(&path)) else { return special(404) };
    if r.method == "POST" { return special(405); }
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    let modified = expires::http_date(mtime as i64);
    const TYPES: &[(&str, &str)] = &[("html", "text/html"), ("gif", "image/gif"), ("jpg", "image/jpeg")];
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    let ctype = TYPES.iter().find(|t| t.0 == ext).map_or(level.default_type.as_str(), |t| t.1);
    let mut headers = vec![("Last-Modified".to_string(), modified)];
    headers.extend(gz.map(|_| ("Content-Encoding".to_string(), "gzip".to_string())));
    headers.push(("ETag".to_string(), format!("\"{mtime:x}-{:x}\"", body.len())));
    headers.push(("Accept-Ranges".to_string(), "bytes".to_string()));
    Response { status: 200, ctype: Some(ctype.to_string()), headers, body, vary, ..Response::default() }
}

/// Whether the client takes gzip, as ngx_http_gzip_ok() decides: it accepts the
/// gzip coding, its HTTP version is at least gzip_http_version, and the request
/// did not come through a proxy (a Via header).
fn gzip_ok(r: &Request, level: &Level) -> bool {
    // A coding is "name" or "name;q=value"; q=0 refuses it.
    let gzip = |c: &str| {
        let (name, q) = c.split_once(';').unwrap_or((c, ""));
        name.trim().eq_ignore_ascii_case("gzip") && q.trim().strip_prefix("q=").is_none_or(|q| q.parse::<f64>() != Ok(0.0))
    };
    let accepts = header(r, "accept-encoding").is_some_and(|v| v.split(',').any(gzip));
    accepts && (r.line.ends_with("HTTP/1.1") || !level.gzip_http_11) && header(r, "via").is_none()
}

/// Takes away what no longer holds once the body is recoded: Content-Encoding,
/// Accept-Ranges, and a strong ETag, which becomes weak (one not quoted is dropped).
fn recoded(resp: &mut Response) {
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("content-encoding") && !h.0.eq_ignore_ascii_case("accept-ranges"));
    resp.headers.retain_mut(|h| !h.0.eq_ignore_ascii_case("etag") || h.1.starts_with("W/") || h.1.starts_with('"') && { h.1.insert_str(0, "W/"); true });
}

/// The gzip filter: with gzip on, an answer with status 200, 403 or 404, no
/// Content-Encoding, at least 20 bytes (gzip_min_length) and a type of
/// gzip_types (text/html always) is compressed for a client that takes gzip,
/// at gzip_comp_level 1, and sent without a length.
fn gzip(r: &Request, level: &Level, resp: &mut Response) {
    let ctype = resp.ctype.as_deref().unwrap_or_default().split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let typed = ctype == "text/html" || level.gzip_types.iter().any(|t| t == "*" || *t == ctype);
    let encoded = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("content-encoding") && !h.1.is_empty());
    if !level.gzip || ![200, 403, 404].contains(&resp.status) || encoded || resp.body.len() < 20 || !typed { return; }
    resp.vary = true;
    if !gzip_ok(r, level) { return; }
    recoded(resp);
    resp.headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
    // The header nginx writes: no name, no time, the Unix OS code.
    let mut crc = flate2::Crc::new();
    crc.update(&resp.body);
    let mut deflate = flate2::write::DeflateEncoder::new(vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3], flate2::Compression::new(1));
    let _ = deflate.write_all(&resp.body);
    let mut body = deflate.finish().unwrap_or_default();
    body.extend(crc.sum().to_le_bytes().into_iter().chain((resp.body.len() as u32).to_le_bytes()));
    (resp.body, resp.unknown_length) = (body, true);
}

/// gunzip: decompresses a gzip answer for a client that does not take gzip,
/// without its Content-Encoding and Accept-Ranges, and with a weak ETag.
fn gunzip(resp: &mut Response) {
    recoded(resp);
    let mut body = Vec::new();
    let _ = flate2::read::MultiGzDecoder::new(resp.body.as_slice()).read_to_end(&mut body);
    resp.body = body;
}

/// Passes the request to the proxied servers in turn, as HTTP/1.0 with
/// "Connection: close", until one answers with a response head.
fn proxy(p: &Proxy, level: &Level, r: &Request, prefix: &str) -> Response {
    let rest = escape_uri(r.uri.get(prefix.len()..).unwrap_or_default());
    let (host, uri, up) = match &p.url {
        None => (p.host.clone(), p.uri.as_ref().map_or_else(|| r.target.clone(), |u| format!("{u}{rest}{}", args(r))), p.upstream.clone()),
        Some(url) => match resolved(&url.render(r, &Sent::default()), p, level, r) {
            Some(t) => t,
            None => return special(502),
        },
    };
    let body = r.body_file.as_ref().map_or_else(|| r.body.clone(), |f| std::fs::read(f).unwrap_or_default());
    // proxy_set_header comes first, then the headers it does not set, as nginx sends them.
    let sent = Sent { proxy_host: Some(host.clone()), ..Sent::default() };
    let set: Vec<(&String, String)> = level.proxy_set_header.iter().map(|(n, v)| (n, v.render(r, &sent))).collect();
    let is_set = |name: &str| set.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    let mut req = format!("{} {uri} HTTP/1.0\r\n", r.method);
    set.iter().filter(|h| !h.1.is_empty()).for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    if !is_set("host") { req += &format!("Host: {host}\r\n"); }
    if !is_set("connection") { req += "Connection: close\r\n"; }
    if framing(r) != Ok(Some(0)) { req += &format!("Content-Length: {}\r\n", body.len()); }
    const DROPPED: &[&str] = &["host", "connection", "content-length", "transfer-encoding", "keep-alive", "te", "expect", "upgrade"];
    let passed = r.headers.iter().filter(|(n, _)| !DROPPED.contains(&n.to_ascii_lowercase().as_str()) && !is_set(n));
    passed.for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    let mut req = (req + "\r\n").into_bytes();
    req.extend_from_slice(&body);
    let (mut tried, mut answer, mut addrs, mut times) = (vec![false; up.peers.len()], None, Vec::new(), Vec::new());
    while answer.is_none() && let Some(i) = up.pick(&mut tried) {
        addrs.push(up.peers[i].addr.to_string());
        let (start, mut time) = (Instant::now(), [None; 3]);
        answer = fetch(&up.peers[i].addr, &req, level, r.client, &mut time);
        time[2] = Some(start.elapsed().as_millis());
        times.push(time);
        up.done(i, answer.is_none());
    }
    let (upstream_addr, upstream_time, proxy_host) = (Some(addrs.join(", ")), Some(times), Some(host));
    let Some(mut resp) = answer else { return Response { upstream_addr, upstream_time, proxy_host, ..special(502) } };
    (resp.upstream_addr, resp.upstream_time, resp.proxy_host) = (upstream_addr, upstream_time, proxy_host);
    // X-Accel-Limit-Rate sets the rate the answer is sent at; X-Accel-Redirect
    // replaces the answer with an internal redirect to its URI.
    let accel = |name: &str| resp.upstream.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    if let Some(rate) = accel("x-accel-limit-rate").and_then(|v| v.parse().ok()) { r.limit_rate.set(rate); }
    if let Some(uri) = accel("x-accel-redirect").filter(|u| u.starts_with('/')) { return Response { internal: Some(uri), as_get: true, ..resp }; }
    let hidden = |name: &str| level.proxy_hide_header.iter().any(|h| h.eq_ignore_ascii_case(name));
    resp.headers.retain(|h| !hidden(&h.0));
    if hidden("content-type") { resp.ctype = None; }
    resp
}

/// The Host, the URI and the servers of a proxy_pass URL with variables: its
/// host is an upstream group, an address, or a name the location's resolver
/// looks up. The URI, when the URL has one, is sent as it is.
fn resolved(url: &str, p: &Proxy, level: &Level, r: &Request) -> Option<(String, String, Arc<Upstream>)> {
    let rest = url.strip_prefix("http://")?;
    let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
    if let Some(up) = p.groups.get(host) { return Some((host.to_string(), uri.unwrap_or_else(|| r.target.clone()), up.clone())); }
    let (name, port) = host.rsplit_once(':').map_or(Some((host, 80)), |(h, p)| p.parse().ok().map(|p| (h, p)))?;
    let resolve = || level.resolver.as_ref()?.resolve(name, level.resolver_timeout);
    let addrs = name.parse::<IpAddr>().map(|a| vec![a]).ok().or_else(resolve)?;
    let peers = addrs.into_iter().map(|a| Peer::new(SocketAddr::new(a, port))).collect();
    Some((host.to_string(), uri.unwrap_or_else(|| r.target.clone()), Arc::new(Upstream::new(peers))))
}

/// Sends a request to one server and reads its whole answer, noting how long
/// it took to connect and to send the response head. While it waits for the
/// head, the client closing the connection ends the request with 499, as
/// proxy_ignore_client_abort off does.
fn fetch(peer: &SocketAddr, req: &[u8], level: &Level, client: i32, time: &mut [Option<u128>; 3]) -> Option<Response> {
    let start = Instant::now();
    let mut s = TcpStream::connect_timeout(peer, level.proxy_connect_timeout).ok()?;
    time[0] = Some(start.elapsed().as_millis());
    let _ = s.set_read_timeout(Some(level.proxy_read_timeout));
    let (mut answer, mut chunk) = (Vec::new(), [0u8; 4096]);
    s.write_all(req).ok()?;
    let end = loop {
        if let Some(end) = head_end(&answer) { break end; }
        if client_closed(&s, client, level.proxy_read_timeout)? { return Some(Response { status: 499, ..Response::default() }); }
        let n = s.read(&mut chunk).ok().filter(|n| *n > 0)?;
        answer.extend_from_slice(&chunk[..n]);
    };
    time[1] = Some(start.elapsed().as_millis());
    let head = String::from_utf8_lossy(&answer[..end]).into_owned();
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty());
    let status = lines.next()?.strip_prefix("HTTP/1.")?.get(2..)?.split(' ').find(|w| !w.is_empty())?.parse().ok()?;
    let mut resp = Response { status, ..Response::default() };
    const HIDDEN: &[&str] = &["date", "server", "connection", "keep-alive", "transfer-encoding", "content-length", "x-pad"];
    for (name, value) in lines.filter_map(|l| l.split_once(':')) {
        let (lower, value) = (name.to_ascii_lowercase(), value.trim().to_string());
        resp.upstream.push((name.to_string(), value.clone()));
        if lower == "content-type" { resp.ctype = Some(value); continue; }
        // A second Expires is ignored.
        let again = lower == "expires" && resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("expires"));
        if !again && !HIDDEN.contains(&lower.as_str()) && !lower.starts_with("x-accel-") { resp.headers.push((name.to_string(), value)); }
    }
    // The body's length: one Content-Length of digits, or one "Transfer-Encoding:
    // chunked" without it; any other mix makes the answer invalid. A HEAD, 204
    // or 304 answer has no body.
    let values = |name: &str| resp.upstream.iter().filter(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone()).collect::<Vec<_>>();
    let length = match (&values("content-length")[..], &values("transfer-encoding")[..]) {
        ([], []) => None,
        ([l], []) => Some(l.bytes().all(|b| b.is_ascii_digit()).then(|| l.parse::<usize>().ok()).flatten()?),
        ([], [c]) if c.eq_ignore_ascii_case("chunked") => None,
        _ => return None,
    };
    let length = if req.starts_with(b"HEAD ") || [204, 304].contains(&status) { Some(0) } else { length };
    // The body of an answer that redirects with X-Accel-Redirect is not read;
    // otherwise it is read up to its length, or until the server closes the connection.
    let accel = resp.upstream.iter().any(|h| h.0.eq_ignore_ascii_case("x-accel-redirect"));
    while !accel && length.is_none_or(|n| answer.len() - end < n) {
        let n = s.read(&mut chunk).ok()?;
        if n == 0 { break; }
        answer.extend_from_slice(&chunk[..n]);
    }
    let body = &answer[end..];
    resp.body = body[..length.unwrap_or(body.len()).min(body.len())].to_vec();
    Some(resp)
}

/// Waits until the proxied server sends something or the client closes the
/// connection (true); None when proxy_read_timeout passes first.
fn client_closed(s: &TcpStream, client: i32, timeout: Duration) -> Option<bool> {
    use std::os::fd::AsRawFd;
    let mut fds = [libc::pollfd { fd: s.as_raw_fd(), events: libc::POLLIN, revents: 0 }, libc::pollfd { fd: client, events: libc::POLLRDHUP, revents: 0 }];
    // SAFETY: fds is an array of two pollfd that lives through the call.
    let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout.as_millis().try_into().unwrap_or(i32::MAX)) };
    (n > 0).then_some(fds[1].revents != 0)
}

/// Fills the request from its head, or gives the status nginx refuses it with.
fn parse(r: &mut Request, head: &[u8], level: &Level) -> Result<(), u16> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    r.line = lines.next().unwrap_or_default().to_string();
    let words: Vec<&str> = r.line.split(' ').filter(|w| !w.is_empty()).collect();
    let [method, target, version] = words[..] else { return Err(400) };
    r.method = method.to_string();
    let valid_method = method.bytes().all(|c| c.is_ascii_uppercase() || c == b'_' || c == b'-');
    if !valid_method || !matches!(version, "HTTP/1.0" | "HTTP/1.1") { return Err(400); }
    for line in lines.filter(|l| !l.is_empty()) {
        let Some((name, value)) = header_line(line, level)? else { continue };
        r.headers.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    // Headers nginx takes only once: a second one is refused.
    const UNIQUE: &[&str] = &["if-modified-since", "if-unmodified-since", "if-match", "if-none-match", "content-length",
                              "content-range", "if-range", "transfer-encoding", "expect", "authorization"];
    let count = |name: &str| r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count();
    if UNIQUE.iter().any(|u| count(u) > 1) { return Err(400); }
    let hosts: Vec<&String> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).map(|(_, v)| v).collect();
    if hosts.len() > 1 || (hosts.is_empty() && version == "HTTP/1.1") { return Err(400); }
    r.host = hosts.first().map(|h| valid_host(h).ok_or(400u16)).transpose()?;
    if method == "CONNECT" { return Err(if target.starts_with('/') || !target.contains(':') { 400 } else { 405 }); }
    if target.bytes().any(|c| c < 0x20 || c == 0x7f) { return Err(400); }
    // A fragment is not part of the request.
    let target = target.split('#').next().unwrap_or_default();
    let path = match target.split_once("://") {
        Some((_, rest)) if !target.starts_with('/') => {
            let (authority, path) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
            r.host = Some(valid_host(authority).ok_or(400u16)?);
            if path.starts_with('/') { path.to_string() } else { format!("/{path}") }
        }
        _ => target.to_string(),
    };
    if !path.starts_with('/') { return Err(400); }
    let uri = decode(path.split('?').next().unwrap_or_default()).ok_or(400u16)?;
    r.uri = dots(&if level.merge_slashes { merge_slashes(&uri) } else { uri }).ok_or(400u16)?;
    r.target = path;
    if method == "TRACE" { return Err(405); }
    Ok(())
}

/// A header line's name and value as ngx_http_parse_header_line() reads
/// them: 400 for a name that is empty or has spaces or control characters,
/// None for a line ignore_invalid_headers drops.
fn header_line<'a>(line: &'a str, level: &Level) -> Result<Option<(&'a str, &'a str)>, u16> {
    let (name, value) = line.split_once(':').ok_or(400u16)?;
    if name.is_empty() || name.bytes().any(|c| c <= 0x20 || c == 0x7f) { return Err(400); }
    let valid = name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || (c == b'_' && level.underscores_in_headers));
    Ok((valid || !level.ignore_invalid_headers).then_some((name, value)))
}

/// The path with its %XX escapes decoded; None when one is malformed.
fn decode(s: &str) -> Option<String> {
    let (b, mut out, mut i) = (s.as_bytes(), Vec::with_capacity(s.len()), 0);
    while i < b.len() {
        let hex = |h: &str| h.bytes().all(|c| c.is_ascii_hexdigit()).then(|| u8::from_str_radix(h, 16).ok()).flatten();
        out.push(if b[i] == b'%' { i += 2; hex(s.get(i - 1..i + 1)?)? } else { b[i] });
        i += 1;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// The path with each run of slashes made one, as merge_slashes does.
fn merge_slashes(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() { if c != '/' || !out.ends_with('/') { out.push(c); } }
    out
}

/// The path with its "." and ".." segments resolved, as nginx does; None when
/// ".." would go above the root. A last "." or ".." leaves the path ending with "/".
fn dots(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let mut out = Vec::new();
    for (i, s) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        match *s {
            "." => {}
            ".." => drop(out.pop()?),
            _ => { out.push(*s); continue }
        }
        if last { out.push(""); }
    }
    Some(format!("/{}", out.join("/")))
}

/// Escapes what may not appear as such in a URI, as nginx's NGX_ESCAPE_URI
/// does: control characters, space, `"#%<>?\^`{|}` and bytes above 0x7e.
fn escape_uri(s: &str) -> String {
    let plain = |c: u8| c > 0x20 && c < 0x7f && !b"\"#%<>?\\^`{|}".contains(&c);
    s.bytes().map(|c| if plain(c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
}

/// The server that answers on a listening address, and the named captures of
/// its name: the one with the host as its name, else the longest "*.name"
/// that matches, else the longest "name.*", else the first regular expression
/// that matches, else the first server listening there. No host is "".
fn server<'a>(config: &'a Config, listen: SocketAddr, host: Option<&str>) -> (&'a Server, Vec<(String, String)>) {
    let on = || config.servers.iter().filter(|s| s.listen.contains(&listen));
    let host = host.unwrap_or_default();
    let mut best: Option<(u8, std::cmp::Reverse<usize>, &Server)> = None;
    for (s, n) in on().flat_map(|s| s.names.iter().map(move |n| (s, n))) {
        let found = match n {
            ServerName::Exact(name) => (name == host).then_some((0, 0)),
            ServerName::Leading(suffix) => (host.len() > suffix.len() && host.ends_with(suffix.as_str())).then_some((1, suffix.len())),
            ServerName::Trailing(prefix) => (host.len() > prefix.len() && host.starts_with(prefix.as_str())).then_some((2, prefix.len())),
            ServerName::Regex(_) => None,
        };
        let found = found.map(|(rank, len)| (rank, std::cmp::Reverse(len), s));
        if found.as_ref().is_some_and(|f| best.as_ref().is_none_or(|b| (f.0, f.1) < (b.0, b.1))) { best = found; }
    }
    if let Some((_, _, s)) = best { return (s, Vec::new()); }
    let regex = on().flat_map(|s| s.names.iter().map(move |n| (s, n))).find_map(|(s, n)| match n {
        ServerName::Regex(re) => re.captures(host).map(|c| (s, re.capture_names().flatten().filter_map(|name| Some((name.to_string(), c.name(name)?.as_str().to_string()))).collect())),
        _ => None,
    });
    regex.unwrap_or_else(|| (on().next().unwrap_or(&config.servers[0]), Vec::new()))
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

/// A location found for a URI: its prefix, its settings, and whether the
/// request is redirected to the URI with "/" added.
type Found<'a> = (&'a str, &'a Level, bool);

/// The location for a URI as nginx finds it: an exact match, else a location
/// whose path is the URI with "/" added and that redirects to it, else the
/// longest prefix if it is "^~", else the first regular expression that
/// matches, else the longest prefix; the server's own settings when nothing matches.
fn location<'a>(server: &'a Server, uri: &str) -> Found<'a> {
    let locs = &server.locations;
    let exact = locs.iter().find(|l| matches!(l.kind, Match::Exact) && l.path == uri);
    let equal = locs.iter().any(|l| !matches!(l.kind, Match::Regex(_)) && l.path == uri);
    let auto = locs.iter().find(|l| l.auto_redirect && !equal && !uri.is_empty() && l.path.strip_prefix(uri) == Some("/"));
    if let Some(l) = auto { return (l.path.as_str(), &l.level, true); }
    let prefixes = locs.iter().filter(|l| matches!(l.kind, Match::Prefix | Match::NoRegex) && uri.starts_with(l.path.as_str()));
    let longest = prefixes.max_by_key(|l| l.path.len());
    let regex = || locs.iter().find(|l| matches!(&l.kind, Match::Regex(re) if re.is_match(uri)));
    let found = exact.or(longest.filter(|l| matches!(l.kind, Match::NoRegex))).or_else(regex).or(longest);
    found.map_or(("", &server.level, false), |l| (l.path.as_str(), &l.level, false))
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
            local: "127.0.0.1:8080".parse().unwrap(),
            started: Instant::now(),
            pipelined: false,
            connected: Instant::now(),
            requests: 1,
            length: 0,
            body: Vec::new(),
            body_file: None,
            upstream_addr: None,
            captures: Vec::new(),
            limit_rate: Default::default(),
            client: -1,
        };
        (parse(&mut r, head.as_bytes(), &Level::default()), r)
    }

    #[test]
    fn ignores_invalid_headers() {
        let names = |head: &str, ignore: bool, underscores: bool| {
            let level = Level { ignore_invalid_headers: ignore, underscores_in_headers: underscores, ..Level::default() };
            let mut r = request("GET / HTTP/1.0\n\n").1;
            parse(&mut r, head.as_bytes(), &level).map(|()| r.headers.iter().map(|h| h.0.clone()).collect::<Vec<_>>())
        };
        let head = "GET / HTTP/1.0\nx_foo: a\n_y: b\nx.z: c\nA-1: d\n\n";
        assert_eq!(names(head, true, false), Ok(vec!["A-1".to_string()]));
        assert_eq!(names(head, true, true), Ok(vec!["x_foo".to_string(), "_y".to_string(), "A-1".to_string()]));
        assert_eq!(names(head, false, false).unwrap().len(), 4);
        for bad in [":a: b", " a: b", "a\x02: b", "a b: c"] {
            assert_eq!(names(&format!("GET / HTTP/1.0\n{bad}\n\n"), false, false), Err(400));
        }
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
        let level = Level { proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let mut time = [None; 3];
        let resp = fetch(&addr, b"GET / HTTP/1.0\r\n\r\n", &level, -1, &mut time).unwrap();
        assert!(time[0].is_some() && time[1].is_some());
        assert_eq!((resp.status, resp.ctype.as_deref(), resp.body.as_slice()), (201, Some("a/b"), &b"body"[..]));
        assert_eq!(resp.headers, vec![("X-A".to_string(), "1".to_string())]);
        assert_eq!(resp.upstream.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), ["Server", "Content-Type", "X-A", "X-Accel-B"]);
    }

    #[test]
    fn checks_the_length_of_answers() {
        let answers: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nExpires: a\r\nExpires: b\r\n\r\nabcd",
            b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        ];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for answer in answers {
                let (mut s, _) = listener.accept().unwrap();
                let _ = s.read(&mut [0u8; 1024]).unwrap();
                s.write_all(answer).unwrap();
                // The connection stays open: Content-Length says where the body ends.
                thread::spawn(move || { thread::sleep(Duration::from_secs(5)); drop(s) });
            }
        });
        let level = Level { proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let resp = fetch(&addr, b"GET / HTTP/1.0\r\n\r\n", &level, -1, &mut [None; 3]).unwrap();
        assert_eq!((resp.body.as_slice(), resp.headers), (&b"ab"[..], vec![("Expires".to_string(), "a".to_string())]));
        for _ in 1..answers.len() {
            assert!(fetch(&addr, b"GET / HTTP/1.0\r\n\r\n", &level, -1, &mut [None; 3]).is_none());
        }
    }

    #[test]
    fn accel_headers_redirect_and_set_the_rate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            // The body never ends: it is not read.
            s.write_all(b"HTTP/1.1 200 OK\r\nX-Accel-Redirect: /b?c=1\r\nX-Accel-Limit-Rate: 13000\r\n\r\nxy").unwrap();
            thread::sleep(Duration::from_secs(5));
        });
        let upstream = Arc::new(crate::upstream::Upstream::new(vec![crate::upstream::Peer::new(addr)]));
        let p = Proxy { host: "h".into(), upstream, uri: None, url: None, groups: Default::default() };
        let level = Level { proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let (_, r) = request("POST /a HTTP/1.0\n\n");
        let resp = proxy(&p, &level, &r, "");
        assert_eq!((resp.internal.as_deref(), resp.as_get, r.limit_rate.get()), (Some("/b?c=1"), true, Some(13000)));
        assert!(resp.upstream_time.unwrap()[0][2].unwrap() < 1000);
    }

    #[test]
    fn not_modified_filter() {
        let level = Level { if_modified_since: Some(false), ..Level::default() };
        let before = Level { if_modified_since: Some(true), ..Level::default() };
        let ok = || Response { status: 200, ctype: Some("t/p".into()), body: b"x".to_vec(), headers: vec![
            ("Last-Modified".into(), "Sun, 06 Nov 1994 08:49:37 GMT".into()), ("ETag".into(), "\"e\"".into()), ("Accept-Ranges".into(), "bytes".into())], ..Response::default() };
        let status = |h: &str, level: &Level| {
            let mut resp = ok();
            not_modified(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, level, &mut resp);
            resp.status
        };
        assert_eq!(status("If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT", &level), 304);
        assert_eq!(status("If-Modified-Since: Sun, 06 Nov 1994 08:49:38 GMT", &level), 200);
        assert_eq!(status("If-Modified-Since: Sun, 06 Nov 1994 08:49:38 GMT", &before), 304);
        assert_eq!(status("If-Modified-Since: x", &before), 200);
        assert_eq!(status("If-None-Match: \"a\",\tW/\"e\"", &level), 304);
        assert_eq!(status("If-Match: W/\"e\"", &level), 412);
        assert_eq!(status("If-Match: *", &level), 200);
        let mut resp = ok();
        not_modified(&request("GET / HTTP/1.0\nIf-None-Match: *\n\n").1, &level, &mut resp);
        assert_eq!((resp.ctype, resp.body.len(), resp.headers.len()), (None, 0, 2));
        assert!(!etag_match("*", None, true));
    }

    #[test]
    fn sends_at_the_rate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut s, _) = listener.accept().unwrap();
        let started = Instant::now();
        assert!(send(&mut s, &[b'x'; 3000], 0, 0, started));
        // 1000 bytes and 1000 a second: the rest goes after a second or two.
        assert!(send(&mut s, &[b'x'; 2500], 1000, 1000, started));
        assert!(started.elapsed() >= Duration::from_millis(1400));
        let mut got = vec![0u8; 5500];
        client.read_exact(&mut got).unwrap();
        drop(client);
        thread::sleep(Duration::from_millis(100));
        assert!(!send(&mut s, &[b'x'; 1 << 22], 1 << 20, 0, Instant::now()));
    }

    #[test]
    fn hides_proxied_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: a/b\r\nX-Location: 1\r\nX-B: 2\r\n\r\n").unwrap();
        });
        let upstream = Arc::new(crate::upstream::Upstream::new(vec![crate::upstream::Peer::new(addr)]));
        let p = Proxy { host: "h".into(), upstream, uri: None, url: None, groups: Default::default() };
        let level = Level { proxy_hide_header: vec!["x-location".into(), "content-type".into()], proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let (_, r) = request("GET / HTTP/1.0\n\n");
        let resp = proxy(&p, &level, &r, "/");
        assert_eq!(resp.upstream_addr, Some(addr.to_string()));
        assert_eq!((resp.ctype, resp.headers), (None, vec![("X-B".to_string(), "2".to_string())]));
    }

    #[test]
    fn urls_with_variables() {
        let (_, r) = request("GET /a?b HTTP/1.0\n\n");
        let group = Arc::new(Upstream::new(Vec::new()));
        let p = Proxy { host: String::new(), upstream: group.clone(), uri: None, url: None, groups: [("u".to_string(), group)].into() };
        assert_eq!(resolved("http://u/y", &p, &Level::default(), &r).map(|t| (t.0, t.1)), Some(("u".into(), "/y".into())));
        let (host, uri, up) = resolved("http://127.0.0.2:81/x", &p, &Level::default(), &r).unwrap();
        assert_eq!((host.as_str(), uri.as_str(), up.peers[0].addr.to_string()), ("127.0.0.2:81", "/x", "127.0.0.2:81".to_string()));
        assert_eq!(resolved("http://127.0.0.2", &p, &Level::default(), &r).map(|t| (t.0, t.1)), Some(("127.0.0.2".into(), "/a?b".into())));
        assert!(resolved("http://example.net/x", &p, &Level::default(), &r).is_none());
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
    fn decodes_and_escapes_uris() {
        assert_eq!(decode("/a%20b%2fc").as_deref(), Some("/a b/c"));
        assert_eq!(decode("/a%2"), None);
        assert_eq!(decode("/a%zz"), None);
        assert_eq!(decode("/a%+1"), None);
        assert_eq!(escape_uri("/a b\"#%<>?\\^`{|}~\u{7f}"), "/a%20b%22%23%25%3C%3E%3F%5C%5E%60%7B%7C%7D~%7F");
        let (res, r) = request("GET /d%20s?a=b HTTP/1.0\n\n");
        assert_eq!((res, r.uri.as_str(), args(&r)), (Ok(()), "/d s", "?a=b"));
        assert_eq!(request("GET /%g HTTP/1.0\n\n").0, Err(400));
        assert_eq!(merge_slashes("//a///b/%2F/"), "/a/b/%2F/");
        let mut r = request("GET / HTTP/1.0\n\n").1;
        let level = Level { merge_slashes: true, ..Level::default() };
        assert_eq!((parse(&mut r, b"GET /foo//../b%2F/c HTTP/1.0\r\n\r\n", &level), r.uri.as_str()), (Ok(()), "/b/c"));
        let (_, r) = request("GET /foo///../bar HTTP/1.0\n\n");
        assert_eq!(r.uri, "/foo//bar");
        assert_eq!(request("GET /\x02 HTTP/1.0\n\n").0, Err(400));
        let (res, r) = request("GET /a/%2e/b/..?x#f HTTP/1.0\n\n");
        assert_eq!((res, r.uri.as_str(), args(&r)), (Ok(()), "/a/", "?x"));
        let (res, r) = request("GET http://h:80?x#f HTTP/1.0\n\n");
        assert_eq!((res, r.uri.as_str(), args(&r), r.host.as_deref()), (Ok(()), "/", "?x", Some("h")));
        assert_eq!([dots("/a/./b/."), dots("/a/b/../c/.."), dots("/a//.x"), dots("/a/../..")], [Some("/a/b/".into()), Some("/a/".into()), Some("/a//.x".into()), None]);
    }

    #[test]
    fn server_names() {
        let text = "http { server { listen 127.0.0.1:8080; server_name a; } server { listen 127.0.0.1:8080; server_name \"\"; } \
                    server { listen 127.0.0.1:8080; server_name *.b.c; } server { listen 127.0.0.1:8080; server_name *.x.b.c .d.e; } \
                    server { listen 127.0.0.1:8080; server_name f.*; server_name f.g.*; } \
                    server { listen 127.0.0.1:8080; server_name \"~^(?P<n1>[a-z]+)\\Q.h\\E$\"; } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let listen = "127.0.0.1:8080".parse().unwrap();
        let name = |host: Option<&str>| server(&config, listen, host).0.name.clone();
        let cases = [(Some("zz"), "a"), (None, ""), (Some("y.b.c"), "*.b.c"), (Some("y.x.b.c"), "*.x.b.c"), (Some("d.e"), "*.x.b.c"), (Some("y.d.e"), "*.x.b.c"),
                     (Some("f.z"), "f.*"), (Some("f.g.z"), "f.*"), (Some("xyz.h"), "~^(?P<n1>[a-z]+)\\Q.h\\E$"), (Some("xyzah"), "a")];
        for (host, expected) in cases { assert_eq!(name(host), expected, "{host:?}"); }
        assert_eq!(server(&config, listen, Some("xyz.h")).1, vec![("n1".to_string(), "xyz".to_string())]);
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        r.captures = vec![("n1".into(), "v".into())];
        assert_eq!(Template::parse("[$n1]").unwrap().render(&r, &Sent::default()), "[v]");
    }

    #[test]
    fn finds_servers_and_auto_redirects() {
        let text = "http { server { listen 127.0.0.1:8080; server_name a; location /p/ { proxy_pass http://127.0.0.1:8081; } \
                    location /q { } location /q/ { proxy_pass http://127.0.0.1:8081; } } \
                    server { listen 127.0.0.1:8080; server_name b; } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let listen = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(server(&config, listen, Some("b")).0.name, "b");
        assert_eq!(server(&config, listen, Some("c")).0.name, "a");
        let s = &config.servers[0];
        assert_eq!((location(s, "/p").0, location(s, "/p").2), ("/p/", true));
        assert_eq!((location(s, "/p/x").0, location(s, "/p/x").2), ("/p/", false));
        assert_eq!((location(s, "/q").0, location(s, "/q").2), ("/q", false));
        assert!(!location(s, "").2);
    }

    #[test]
    fn rewrites_redirect_with_the_arguments() {
        let text = "http { server { location /a { rewrite ^ http://e/$arg_x; } location /b { rewrite ^ http://e/?y=1; } \
                    location /c { rewrite ^/c http://e/? permanent; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let answer = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let resp = respond(&r, Ok(()), location(s, &r.uri));
            (resp.status, resp.headers[0].1.clone())
        };
        assert_eq!(answer("/a?x=1"), (302, "http://e/1?x=1".to_string()));
        assert_eq!(answer("/b?x=1"), (302, "http://e/?y=1&x=1".to_string()));
        assert_eq!(answer("/b"), (302, "http://e/?y=1".to_string()));
        assert_eq!(answer("/c?x=1"), (301, "http://e/".to_string()));
    }

    #[test]
    fn rewrites_with_break_and_named_locations() {
        let text = "http { server { location /a { rewrite ^/a(.*) /b break; return 403; } location @n { return 200 n$uri; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        assert!(location(s, "@n").0.is_empty());
        let (_, r) = request("GET /a?x=1 HTTP/1.0\n\n");
        // break skips return; the new URI keeps the arguments and is looked for under root.
        assert_eq!(respond(&r, Ok(()), location(s, &r.uri)).status, 404);
        let named = (s.locations[1].path.as_str(), &s.locations[1].level, false);
        assert_eq!(respond(&r, Ok(()), named).body, b"n/a");
    }

    #[test]
    fn sets_limit_rate() {
        let text = "http { server { set $limit_rate 1k; location /a { set $limit_rate $arg_l; return 200 $limit_rate; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let rate = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            String::from_utf8(respond(&r, Ok(()), location(s, &r.uri)).body).unwrap()
        };
        assert_eq!(rate("/a?l=40k"), "40960");
        assert_eq!(rate("/a?l=2M"), "2097152");
        // A value that is not a size keeps what the server level set.
        assert_eq!(rate("/a?l=x"), "1024");
        assert_eq!(rate("/a"), "1024");
    }

    #[test]
    fn gzip_ok_and_gunzip() {
        let level = Level { gzip_http_11: true, ..Level::default() };
        let ok = |head: &str, level: &Level| gzip_ok(&request(head).1, level);
        assert!(ok("GET / HTTP/1.1\nHost: a\nAccept-Encoding: deflate, GZIP;q=0.5\n\n", &level));
        assert!(!ok("GET / HTTP/1.1\nHost: a\nAccept-Encoding: gzip;q=0\n\n", &level));
        assert!(!ok("GET / HTTP/1.1\nHost: a\nAccept-Encoding: gzip\nVia: x\n\n", &level));
        assert!(!ok("GET / HTTP/1.0\nAccept-Encoding: gzip\n\n", &level));
        assert!(ok("GET / HTTP/1.0\nAccept-Encoding: gzip\n\n", &Level::default()));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(b"abc").unwrap();
        let member = gz.finish().unwrap();
        let headers = [("Content-Encoding", "gzip"), ("ETag", "\"1-2\""), ("Accept-Ranges", "bytes"), ("X", "y")];
        let mut resp = Response { body: [member.clone(), member].concat(), ..Response::default() };
        resp.headers = headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        gunzip(&mut resp);
        assert_eq!(resp.body, b"abcabc");
        assert_eq!(resp.headers, vec![("ETag".to_string(), "W/\"1-2\"".to_string()), ("X".to_string(), "y".to_string())]);
    }

    #[test]
    fn gzip_compresses_what_it_may() {
        let level = Level { gzip: true, gzip_http_11: true, gzip_types: vec!["text/plain".to_string()], ..Level::default() };
        let (_, r) = request("GET / HTTP/1.1\nHost: a\nAccept-Encoding: gzip\n\n");
        let make = |status, ctype: &str, len| {
            let headers = vec![("ETag".to_string(), "\"1-2\"".to_string()), ("Accept-Ranges".to_string(), "bytes".to_string())];
            Response { status, ctype: Some(ctype.to_string()), headers, body: vec![b'X'; len], ..Response::default() }
        };
        let mut resp = make(404, "text/plain; charset=utf-8", 64);
        gzip(&r, &level, &mut resp);
        assert!(resp.vary && resp.unknown_length);
        assert_eq!(&resp.body[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3]);
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(resp.body.as_slice()).read_to_end(&mut plain).unwrap();
        assert_eq!(plain, vec![b'X'; 64]);
        let etag = ("ETag".to_string(), "W/\"1-2\"".to_string());
        assert_eq!(resp.headers, vec![etag, ("Content-Encoding".to_string(), "gzip".to_string())]);
        // Too short, another type, another status, or gzip off: left as it is.
        for (mut resp, level) in [(make(200, "text/html", 19), &level), (make(200, "image/gif", 64), &level),
                                  (make(301, "text/html", 64), &level), (make(200, "text/html", 64), &Level::default())] {
            gzip(&r, level, &mut resp);
            assert!(!resp.unknown_length && !resp.vary && resp.body.iter().all(|&c| c == b'X'));
        }
        // A client that does not take gzip still makes it vary.
        let (_, r) = request("GET / HTTP/1.1\nHost: a\n\n");
        let mut resp = make(200, "text/html", 64);
        gzip(&r, &level, &mut resp);
        assert!(resp.vary && !resp.unknown_length);
    }

    #[test]
    fn index_redirects_internally() {
        let dir = std::env::temp_dir().join(format!("twinx-index-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("a/empty")).unwrap();
        std::fs::write(dir.join("a/index.html"), "hi").unwrap();
        let text = format!("http {{ server {{ root {}; location /a/ {{ }} location = /a/index.html {{ return 200 i$uri; }} }} }}", dir.display());
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let status = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let (resp, _, _) = answer(s, &r, Ok(()), location(s, &r.uri));
            (resp.status, String::from_utf8_lossy(&resp.body).into_owned())
        };
        assert_eq!(status("/a/?x"), (200, "i/a/index.html".to_string()));
        assert_eq!(status("/a/empty/").0, 403);
        assert_eq!(status("/a/none/").0, 404);
    }

    #[test]
    fn index_directive_and_error_log() {
        let dir = std::env::temp_dir().join(format!("twinx-indices-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("m")).unwrap();
        std::fs::write(dir.join("m/two.html"), "2").unwrap();
        std::fs::write(dir.join("f"), "").unwrap();
        let text = format!("http {{ server {{ root {d}; error_log {d}/e.log; location /m/ {{ index one.html two.html; }} \
                            location /abs/ {{ index /m/$server_name; }} location /q/ {{ log_not_found off; }} \
                            location /c/ {{ error_log {d}/c.log crit; }} }} }}", d = dir.display());
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let answer = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let (resp, _, last) = answer(s, &r, Ok(()), location(s, &r.uri));
            (resp.status, last.target)
        };
        assert_eq!(answer("/m/?a"), (200, "/m/two.html?a".to_string()));
        assert_eq!(answer("/abs/").1, "/m/localhost");
        assert_eq!(answer("/f/").0, 404);
        assert_eq!(answer("/q/").0, 404);
        assert_eq!(answer("/c/").0, 404);
        assert_eq!(answer("/").0, 403);
        let log = std::fs::read_to_string(dir.join("e.log")).unwrap();
        assert!(log.contains(&format!("[error] {}#0: \"{}/f/index.html\" is not found (20: Not a directory), client: 127.0.0.1, server: localhost", std::process::id(), dir.display())));
        assert!(log.contains("directory index of \""));
        assert_eq!(log.lines().count(), 2);
        assert_eq!(std::fs::read_to_string(dir.join("c.log")).unwrap(), "");
    }

    #[test]
    fn try_files() {
        let dir = std::env::temp_dir().join(format!("twinx-try-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("f.html"), "f").unwrap();
        std::fs::write(dir.join("d/r.html"), "r").unwrap();
        let text = format!(
            "http {{ server {{ root {0}; location / {{ try_files $uri /x/ /back?a=1; }} location /back {{ return 200 $uri:$args; }} \
             location /s/ {{ try_files /f.html/ =410; }} location /t/ {{ try_files /d/ =404; }} location ~ /r.html {{ alias {0}/d; try_files $uri =404; }} \
             location /n/ {{ alias {0}/; try_files $uri =404; }} }} }}",
            dir.display()
        );
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let answer = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let (resp, _, _) = answer(s, &r, Ok(()), location(s, &r.uri));
            (resp.status, String::from_utf8_lossy(&resp.body).into_owned())
        };
        assert_eq!(answer("/f.html"), (200, "f".to_string()));
        assert_eq!(answer("/r.html"), (200, "r".to_string()));
        assert_eq!(answer("/n/f.html"), (200, "f".to_string()));
        assert_eq!(answer("/none"), (200, "/back:a=1".to_string()));
        assert_eq!(answer("/s/").0, 410);
        assert_eq!(answer("/t/").0, 301);
    }

    #[test]
    fn keepalive_limits_and_browsers() {
        assert_eq!(browser("Mozilla/4.0 (compatible; MSIE 5.0; Windows)"), (true, false));
        assert_eq!(browser("MSIE 6.0; SV1"), (false, false));
        assert_eq!(browser("MSIE 6.0; X"), (true, false));
        assert_eq!(browser("MSIE 7.0"), (false, false));
        assert_eq!(browser("MSIE 5.0 Opera"), (false, false));
        assert_eq!(browser("Mac OS X Safari/7534.48.3"), (false, true));
        assert_eq!(browser("Mac OS X Chrome/1 Safari/1"), (false, false));
        let level = Level { keepalive_requests: 2, keepalive_timeout: Duration::from_secs(1), keepalive_time: Duration::from_secs(60), keepalive_disable_msie6: true, ..Level::default() };
        let (_, mut r) = request("POST / HTTP/1.1\nHost: a\nUser-Agent: MSIE 5.0\n\n");
        assert!(!keeps_alive(&r, &level));
        r.method = "GET".into();
        assert!(keeps_alive(&r, &level));
        r.requests = 2;
        assert!(!keeps_alive(&r, &level));
        r.requests = 1;
        assert!(!keeps_alive(&r, &Level { keepalive_timeout: Duration::ZERO, ..level }));
    }

    #[test]
    fn refuses_second_unique_headers() {
        assert_eq!(request("GET / HTTP/1.0\nIf-Match: a\nif-match: b\n\n").0, Err(400));
        assert_eq!(request("GET / HTTP/1.0\nAuthorization: a\nAuthorization: a\n\n").0, Err(400));
        assert_eq!(request("GET / HTTP/1.0\nCookie: a\nCookie: b\nVia: x\nVia: y\n\n").0, Ok(()));
    }

    #[test]
    fn post_action_answers_in_the_background() {
        let text = "http { server { location / { post_action @n; } location @n { return 204; } location /u { post_action /x?a; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        for target in ["/", "/u"] {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            post_action(s, &r, location(s, &r.uri).1);
        }
        assert_eq!(location(s, "/").1.post_action.as_deref(), Some("@n"));
    }

    #[test]
    fn error_page() {
        assert!(page(404).contains("<title>404 Not Found</title>"));
    }
}
