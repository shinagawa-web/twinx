//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{Condition, Config, CookieFlags, CookiePattern, CookieRewrite, Fallback, Flag, Level, Match, Op, Proxy, Rewrite, Server, ServerName, Step, TryFiles};
use crate::vars::{Part, Template};
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
    (415, "Unsupported Media Type"), (416, "Requested Range Not Satisfiable"), (421, "Misdirected Request"), (429, "Too Many Requests"),
    (500, "Internal Server Error"), (501, "Not Implemented"), (502, "Bad Gateway"),
    (503, "Service Temporarily Unavailable"), (504, "Gateway Time-out"), (505, "HTTP Version Not Supported"),
];

/// Binds every address the servers listen on and accepts connections on each in a thread.
/// Opens the listening sockets: the master does this, so that bind errors stop it and every worker shares them.
pub fn bind(config: &Config, open: &[(TcpListener, SocketAddr)]) -> Result<Vec<(TcpListener, SocketAddr)>, String> {
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in config.servers.iter().flat_map(|s| &s.listen) { if !addrs.contains(addr) { addrs.push(*addr) } }
    // On a reload, a socket already open on the address is kept. accept() on
    // it gives up after a while, so that a worker shutting down stops accepting.
    let get = |addr| open.iter().find(|o| o.1 == addr).map_or_else(|| TcpListener::bind(addr), |o| o.0.try_clone());
    let timeout = |l: TcpListener| socket2::SockRef::from(&l).set_read_timeout(Some(ACCEPT_WAIT)).map(|()| l);
    addrs.into_iter().map(|addr| get(addr).and_then(timeout).map(|l| (l, addr)).map_err(|e| format!("bind() to {addr} failed ({e})"))).collect()
}

/// How long accept() waits before it looks again whether the worker is shutting down.
const ACCEPT_WAIT: Duration = Duration::from_millis(100);

/// Whether the worker is shutting down gracefully, and how many requests it is answering.
static SHUTTING: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicUsize = AtomicUsize::new(0);
/// How many threads are still accepting connections.
static ACCEPTING: AtomicUsize = AtomicUsize::new(0);

/// A request being answered, counted in BUSY while it lives.
struct Busy;

impl Busy {
    fn new() -> Busy {
        BUSY.fetch_add(1, Ordering::SeqCst);
        Busy
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shuts the worker down gracefully, as QUIT does: it stops accepting, closes
/// each connection once its request is answered, and returns when no request
/// is left, or once worker_shutdown_timeout has passed. Idle connections are
/// closed when the worker exits. A connection accepted while it began to shut
/// down is counted from its accept on, so its request is answered, not dropped.
pub fn shut_down(timeout: Option<Duration>) {
    let start = Instant::now();
    SHUTTING.store(true, Ordering::SeqCst);
    while ACCEPTING.load(Ordering::SeqCst) > 0 { thread::sleep(Duration::from_millis(10)); }
    while BUSY.load(Ordering::SeqCst) > 0 && timeout.is_none_or(|t| start.elapsed() < t) { thread::sleep(Duration::from_millis(10)); }
}

/// Accepts connections on the listening sockets, in a worker process.
pub fn accept(config: Arc<Config>, listeners: &[(TcpListener, SocketAddr)]) -> Result<(), String> {
    for (listener, addr) in listeners {
        let (listener, addr, config) = (listener.try_clone().map_err(|e| e.to_string())?, *addr, config.clone());
        // An address any server listens on with "ssl" takes TLS connections.
        let tls = config.servers.iter().any(|s| s.ssl.contains(&addr));
        ACCEPTING.fetch_add(1, Ordering::SeqCst);
        thread::spawn(move || {
            while !SHUTTING.load(Ordering::SeqCst) {
                let Ok((stream, peer)) = listener.accept() else { continue };
                // Until its first request has arrived, a new connection is busy too.
                let (config, fresh) = (config.clone(), Busy::new());
                let local = stream.local_addr().unwrap_or(addr);
                thread::spawn(move || {
                    let Some((stream, ssl)) = (if tls { crate::tls::accept(stream, &config, addr).map(|(s, ssl)| (s, Some(ssl))) } else { Some((stream, None)) }) else { return };
                    connection(&config, stream, (addr, local, peer, ssl), fresh)
                });
            }
            ACCEPTING.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// The end of the request head (after the empty line), if it has arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    let first = buf.iter().position(|&c| c == b'\n').map(|i| i + 1);
    if let Some(end) = first.filter(|&end| http09(&buf[..end])) { return Some(end) }
    let lf = buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2);
    let crlf = buf.windows(3).position(|w| w == b"\n\r\n").map(|i| i + 3);
    lf.into_iter().chain(crlf).min()
}

/// Whether a request line is of HTTP/0.9: a method and a URI, without a
/// version. Such a request has no headers, and its answer is the body alone.
fn http09(line: &[u8]) -> bool {
    line.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty()).count() == 2
}

/// Serves the requests of a connection accepted on a listening address,
/// with its local and remote addresses.
fn connection(config: &Config, mut stream: TcpStream, (listen, local, peer, ssl): (SocketAddr, SocketAddr, SocketAddr, Option<crate::tls::Session>), fresh: Busy) {
    let mut fresh = Some(fresh);
    let (mut buf, mut chunk) = (Vec::new(), [0u8; 4096]);
    // After a kept-alive answer: how long the connection waits for the next request.
    let (connected, mut requests, mut idle) = (Instant::now(), 0, None);
    loop {
        let (pipelined, started) = (!buf.is_empty(), Instant::now());
        requests += 1;
        // Header lines are read with the settings of the default server of the address.
        let default = config.servers.iter().find(|s| s.listen.contains(&listen)).unwrap_or(&config.servers[0]);
        let buffers = |host: Option<&str>| server(config, listen, host).0.level.large_header_buffers;
        // A head that overflows its buffers is answered with what of it came whole.
        let (end, overflowed) = loop {
            let end = head_end(&buf);
            if let Some((status, at)) = overflow(&buf[..end.unwrap_or(buf.len())], default.level.header_buffer, buffers) { break (at, Some(status)); }
            if let Some(end) = end { break (end, None); }
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
            upstream_status: None,
            upstream: Vec::new(),
            captures: Vec::new(),
            limit_rate: Default::default(),
            vars: Default::default(),
            unread: Default::default(),
            client: std::os::fd::AsRawFd::as_raw_fd(&stream),
            ssl: ssl.clone(),
        };
        let parsed = parse(&mut r, &head, &default.level);
        let parsed = overflowed.map_or(parsed, Err);
        let (server, captures) = server(config, listen, r.host.as_deref());
        r.captures = captures;
        let parsed = parsed.and_then(|()| if r.headers.len() > server.level.max_headers { Err(400) } else { Ok(()) });
        let parsed = parsed.and_then(|()| if misdirected(r.ssl.as_ref(), r.host.as_deref(), server.level.ssl_verify_client) { Err(421) } else { Ok(()) });
        let parsed = parsed.and_then(|()| cert_error(server.level.ssl_verify_client, r.ssl.as_ref()));
        r.server_name = server.name.clone();
        let found = located(server, &r, &r.uri);
        let level = found.1;
        let framing = parsed.and_then(|()| framing(&r)).and_then(|n| if n.unwrap_or(0) > level.max_body { Err(413) } else { Ok(n) });
        let expect = header(&r, "expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        if framing.is_ok() && expect && r.line.ends_with("HTTP/1.1") { let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n"); }
        let parsed = match framing {
            Err(status) => Err(status),
            // With proxy_request_buffering off, what came with the head is passed
            // with the request, and the rest of the body as it comes.
            Ok(Some(n)) if level.proxy.is_some() && !level.proxy_request_buffering && (buf.len() as u64) < n => {
                r.length += n as usize;
                r.body = std::mem::take(&mut buf);
                *r.unread.lock().unwrap() = stream.try_clone().ok().map(|client| Unread { client, left: n - r.body.len() as u64, chunked: None, rest: Vec::new() });
                Ok(())
            }
            // A chunked body only when passed as HTTP/1.1, its data passed in chunks of what has come.
            Ok(None) if level.proxy.is_some() && !level.proxy_request_buffering && level.proxy_http_11 && matches!(dechunk(&buf, level.max_body), Ok(None)) => {
                r.body = decode_chunked(&buf, level.max_body).unwrap_or_default().0;
                *r.unread.lock().unwrap() = stream.try_clone().ok().map(|client| Unread { client, left: 0, chunked: Some((std::mem::take(&mut buf), r.body.len())), rest: Vec::new() });
                Ok(())
            }
            Ok(length) => loop {
                match take_body(&buf, length, level.max_body) {
                    Ok(None) => {}
                    Ok(Some((body, used))) => {
                        r.length += used;
                        buf.drain(..used);
                        break keep_body(&mut r, level, body);
                    }
                    Err(status) => break Err(status),
                }
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 { return; }
                buf.extend_from_slice(&chunk[..read]);
            },
        };
        let busy = Busy::new();
        drop(fresh.take());
        idle = exchange(&mut stream, server, &r, parsed, found, local, &buf);
        drop(busy);
        // What of an unbuffered body was not passed on is read and dropped.
        // What came after a chunked one is the next request.
        if let Some(mut u) = r.unread.lock().unwrap().take() {
            if pass_body(&mut u, level.max_body, &mut std::io::sink()).is_none() { return; }
            buf = u.rest;
        }
        if !level.body_in_file_only || level.body_clean { r.body_file.map(std::fs::remove_file); }
        if idle.is_none() || SHUTTING.load(Ordering::SeqCst) { return linger(&mut stream); }
    }
}

/// Whether a head (what of it has come) overflows the buffers nginx reads it
/// into, as ngx_http_alloc_large_header_buffer() decides: the first buffer
/// is client_header_buffer_size; when it is full in the middle of a line,
/// the line moves to a new large buffer, if one of large_client_header_buffers
/// is left and the line so far is shorter than one. The large buffers are
/// those of the server the Host header selects, once it has come. The status,
/// 414 for the request line and 494 for a header line, and where that line starts.
fn overflow(head: &[u8], first: usize, buffers: impl Fn(Option<&str>) -> (usize, usize)) -> Option<(u16, usize)> {
    let (mut start, mut cap, mut used, mut host) = (0, first, 0, None);
    let mut line = 0;
    while line < head.len() {
        let end = head[line..].iter().position(|&c| c == b'\n').map(|i| line + i + 1);
        // The line fits in the buffer, or the buffer is not full yet.
        if end.unwrap_or(head.len()) <= start + cap && (end.is_some() || head.len() < start + cap) {
            let text = String::from_utf8_lossy(&head[line..end.unwrap_or(head.len())]).into_owned();
            if let Some((name, value)) = text.split_once(':').filter(|_| line > 0) {
                if name.eq_ignore_ascii_case("host") { host = valid_host(value.trim_matches([' ', '\t', '\r', '\n'])); }
            }
            match end { Some(end) => { line = end; continue } None => return None }
        }
        let (number, size) = buffers(host.as_deref());
        if start + cap - line >= size || used >= number { return Some((if line == 0 { 414 } else { 494 }, line)); }
        (start, cap, used) = (line, size, used + 1);
    }
    None
}

/// How the request body is framed: Some(length), or None when it is chunked.
fn framing(r: &Request) -> Result<Option<u64>, u16> {
    let te: Vec<&String> = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding")).map(|(_, v)| v).collect();
    let length = header(r, "content-length");
    // Digits only, up to the largest file offset (2^63 - 1).
    let digits = |v: &str| v.bytes().all(|c| c.is_ascii_digit()).then(|| v.parse::<i64>().ok()).flatten().map(|n| n as u64);
    if te.is_empty() { return length.map_or(Ok(Some(0)), |v| digits(v).map(Some).ok_or(400)); }
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
    decode_chunked(buf, max).map(|(body, used)| used.map(|used| (body, used)))
}

/// The data of a chunked body that has come, and the bytes the whole body took
/// in the buffer once it has all come.
fn decode_chunked(buf: &[u8], max: u64) -> Result<(Vec<u8>, Option<usize>), u16> {
    let (mut body, mut at) = (Vec::new(), 0);
    let line = |at: usize| buf[at..].iter().position(|&c| c == b'\n').map(|n| (String::from_utf8_lossy(&buf[at..at + n]).trim_end_matches('\r').to_string(), at + n + 1));
    loop {
        let Some((size, next)) = line(at) else { return Ok((body, None)) };
        let size = chunk_size(&size).ok_or(400u16)?;
        at = next;
        if size == 0 { break; }
        if (body.len() as u64).saturating_add(size) > max { return Err(413); }
        let end = at + size as usize;
        let after = buf.get(end..).unwrap_or_default();
        if after.is_empty() || after == b"\r" { body.extend_from_slice(&buf[at..end.min(buf.len())]); return Ok((body, None)); }
        let skip = if after.starts_with(b"\r\n") { 2 } else if after.starts_with(b"\n") { 1 } else { return Err(400) };
        body.extend_from_slice(&buf[at..end]);
        at = end + skip;
    }
    loop {
        let Some((trailer, next)) = line(at) else { return Ok((body, None)) };
        at = next;
        if trailer.is_empty() { return Ok((body, Some(at))); }
    }
}

/// A chunk's size as nginx reads it: hex digits from the start of the line, up
/// to 2^63 - 1, then nothing or an extension after ";", a space or a tab.
fn chunk_size(line: &str) -> Option<u64> {
    let digits = line.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(line.len());
    let (hex, rest) = line.split_at(digits);
    let extension = rest.is_empty() || rest.starts_with([';', ' ', '\t']);
    (digits > 0 && extension).then(|| i64::from_str_radix(hex, 16).ok()).flatten().map(|n| n as u64)
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
/// when it does not fit client_body_buffer_size or client_body_in_file_only is on;
/// 500 when the file cannot be written.
fn keep_body(r: &mut Request, level: &Level, body: Vec<u8>) -> Result<(), u16> {
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let to_file = !body.is_empty() && (level.body_in_file_only || body.len() as u64 > level.body_buffer);
    if !to_file { r.body = body; return Ok(()); }
    let path = temp_file(&level.body_temp_path, &level.body_temp_levels, NEXT.fetch_add(1, Ordering::Relaxed));
    let written = path.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&path, &body));
    if let Err(e) = written { error_log(level, r, &format!("open() \"{}\" failed ({e})", path.display())); return Err(500); }
    r.body_file = Some(path);
    Ok(())
}

/// A temporary file's path: the number in ten digits, in the subdirectories
/// the levels name, each taken from the end of the name (levels 1 2: 2/00/0000000002).
fn temp_file(dir: &std::path::Path, levels: &[usize], n: u32) -> PathBuf {
    let name = format!("{n:010}");
    let mut end = name.len();
    let mut path = dir.to_path_buf();
    for &l in levels { path.push(&name[end - l..end]); end -= l; }
    path.join(name)
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
    /// The connection to a proxied server that switched protocols (101) for a
    /// request with Upgrade: once the head is sent, data is passed both ways.
    tunnel: Option<TcpStream>,
    /// Whether this is a page nginx generates for an error or a redirect
    /// (ngx_http_special_response_handler()), which keeps its own status
    /// after an error_page redirect.
    generated: bool,
    /// Every header of the proxied server's answer, for $upstream_http_*.
    upstream: Vec<(String, String)>,
    /// The URI and arguments to redirect to internally: the index module's, with
    /// "index.html" added, or the last parameter of try_files.
    internal: Option<String>,
    /// The proxied servers tried ($upstream_addr), and how long each took ($upstream_response_time).
    upstream_addr: Option<String>,
    /// The status each of them answered with ($upstream_status).
    upstream_status: Option<String>,
    upstream_time: Option<Vec<[Option<u128>; 3]>>,
    /// For each of them, the bytes of the body and of the whole answer read,
    /// and of the request sent ($upstream_response_length, $upstream_bytes_*).
    upstream_bytes: Option<Vec<[u64; 3]>>,
    /// The host of the proxy_pass URL ($proxy_host).
    proxy_host: Option<String>,
    /// Whether the internal redirect makes the request a GET, unless it is a
    /// HEAD (X-Accel-Redirect).
    as_get: bool,
    /// Whether the length is not known when the head is sent (the gzip filter
    /// compresses as it goes): the body is chunked, or the connection closed after it.
    unknown_length: bool,
    /// Whether this is the answer of a proxied server, which error_page
    /// replaces only with proxy_intercept_errors on.
    proxied: bool,
    /// Whether the range filter may answer a Range with a part of it: a
    /// static file's answer (r->allow_ranges).
    ranges: bool,
    /// Whether a Location that starts with "/" is sent as it is: one a proxied
    /// server sent and proxy_redirect did not rewrite.
    relative: bool,
    /// What is left to read of a proxied answer's body that proxy_limit_rate
    /// paces: it is read once the head is made, as nginx sends the head first.
    rest: Option<Rest>,
}

/// The connection to a proxied server whose body is still to be read, with
/// what has been read of the answer, where its head ends, how the body's end
/// is found, the rate, and when the request to it started.
#[derive(Debug)]
struct Rest { s: TcpStream, answer: Vec<u8>, end: usize, length: Option<usize>, chunked: bool, rate: u64, started: Instant }

/// Reads the rest of a proxied answer's body, noting how long the whole answer took.
fn finish(resp: &mut Response) {
    let Some(mut rest) = resp.rest.take() else { return };
    let (body, read) = read_body(&mut rest.s, rest.answer, rest.end, rest.length, rest.chunked, rest.rate).unwrap_or_default();
    resp.body = body;
    if let Some(t) = resp.upstream_time.as_mut().and_then(|t| t.last_mut()) { t[2] = Some(rest.started.elapsed().as_millis()); }
    if let Some(b) = resp.upstream_bytes.as_mut().and_then(|b| b.last_mut()) { (b[0], b[1]) = ((read - rest.end) as u64, read as u64); }
}

/// Whether a request is misdirected (421), as nginx finds it: its Host is not
/// the name the client asked for with SNI, and the server the Host selects
/// asks clients for their certificates (ssl_verify_client).
fn misdirected(ssl: Option<&crate::tls::Session>, host: Option<&str>, verify: u8) -> bool {
    let sni = ssl.map(|s| s.server_name.as_str()).filter(|n| !n.is_empty());
    sni.zip(host).is_some_and(|(sni, host)| !sni.eq_ignore_ascii_case(host) && verify > 0)
}

/// What nginx answers a request on a connection whose client's certificate
/// it asked for (ssl_verify_client): 495 when it did not verify, but for the
/// errors optional_no_ca lets through, and with ssl_verify_client on, 496 without one.
fn cert_error(mode: u8, ssl: Option<&crate::tls::Session>) -> Result<(), u16> {
    const OPTIONAL: &[&str] = &["self-signed certificate", "self-signed certificate in certificate chain", "unable to get issuer certificate", "unable to get local issuer certificate", "unable to verify the first certificate"];
    let Some(verify) = ssl.filter(|_| mode > 0).map(|s| s.verify.as_str()) else { return Ok(()) };
    match verify.strip_prefix("FAILED:") {
        Some(e) if !(mode == 3 && OPTIONAL.contains(&e)) => Err(495),
        _ if mode == 1 && verify == "NONE" => Err(496),
        _ => Ok(()),
    }
}

/// The page nginx generates for an error status.
fn special(status: u16) -> Response {
    let ctype = Some("text/html".to_string());
    // 494, a header line too long, is answered as 400 with a page of its own.
    let (status, body) = match status {
        494 => (400, page_with(400, "Request Header Or Cookie Too Large", "<center>Request Header Or Cookie Too Large</center>\r\n")),
        // A client's certificate that did not verify (495), or none (496).
        495 | 496 => { let text = ["The SSL certificate error", "No required SSL certificate was sent"][usize::from(status == 496)]; (400, page_with(400, text, &format!("<center>{text}</center>\r\n"))) }
        _ => (status, page(status)),
    };
    Response { status, ctype, body: body.into_bytes(), generated: true, ..Response::default() }
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
    match parsed {
        Err(status) => return special(status),
        Ok(()) if auto => return redirect(301, format!("{}/{}", escape_uri(&r.uri), args(r))),
        Ok(()) => {}
    }
    // The rewrite module's directives, in order, as ngx_http_rewrite_handler() runs them.
    let (mut to, mut changed, mut moved) = (r.clone(), false, false);
    for step in &level.rewrite {
        let rw = match step {
            Step::Return(code, text) => return serve(&to, level, prefix, Some((*code, text))),
            Step::Break => { changed = false; break }
            Step::Rewrite(rw) => rw,
        };
        let Some(caps) = rw.regex.captures(&to.uri) else { continue };
        to.set_captures(&caps);
        let (uri, new_args) = replacement(rw, &to);
        let uri = if rw.redirect { unescape_redirect(&uri) } else { uri };
        // The request's arguments follow those of the replacement, "&" between them.
        let old = &args(&to).get(1..).unwrap_or_default().to_string();
        let args = match new_args {
            Some(a) if rw.add_args && !old.is_empty() => format!("?{a}&{old}"),
            Some(a) => format!("?{a}"),
            None if rw.add_args && !old.is_empty() => format!("?{old}"),
            None => String::new(),
        };
        if rw.redirect { return redirect(rw.status, format!("{uri}{args}")); }
        to.target = format!("{uri}{args}");
        to.uri = uri;
        (changed, moved) = (rw.flag != Flag::Break, true);
        if rw.flag != Flag::Next { break; }
    }
    // A URI changed without "break" is looked for again among the locations.
    if changed { return Response { internal: Some(to.target), ..Response::default() }; }
    // Stopped by break, the location goes on with the new URI, and proxy_pass
    // passes it whole, without the URI it has (r->valid_location is 0).
    match level.proxy.as_deref().filter(|p| moved && p.uri.is_some() && level.try_files.is_none()) {
        Some(p) => proxy(&Proxy { uri: None, ..p.clone() }, level, &to, prefix),
        None => serve(&to, level, prefix, None),
    }
}

/// The replacement of a rewrite, as the URI and the arguments after its "?".
/// When the request's URI had "%" or "+", a capture is escaped as
/// NGX_ESCAPE_ARGS does in the arguments and in a redirect
/// (ngx_http_script_copy_capture_code()).
fn replacement(rw: &Rewrite, r: &Request) -> (String, Option<String>) {
    let quoted = r.target.split('?').next().unwrap_or_default().contains(['%', '+']);
    let (mut uri, mut args) = (String::new(), None::<String>);
    for part in &rw.url.0 {
        let value = match part {
            Part::Text(t) => match t.split_once('?').filter(|_| args.is_none()) {
                Some((u, a)) => { uri += u; args = Some(a.to_string()); continue }
                None => t.clone(),
            },
            Part::Var(v) => {
                let value = Template(vec![part.clone()]).render(r, &Sent::default());
                let capture = matches!(v, crate::vars::Var::User(n) if n.bytes().all(|c| c.is_ascii_digit()));
                if capture && quoted && (args.is_some() || rw.redirect) { escape_args(&value) } else { value }
            }
        };
        args.as_mut().unwrap_or(&mut uri).push_str(&value);
    }
    (uri, args)
}

/// Escapes what NGX_ESCAPE_ARGS does: control characters, space, "#%&+;?" and bytes above 0x7e.
fn escape_args(s: &str) -> String {
    s.bytes().map(|c| if c > 0x20 && c < 0x7f && !b"#%&+;?".contains(&c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
}

/// The answer of return, else of proxy_pass, else of the static module.
fn serve(r: &Request, level: &Level, prefix: &str, ret: Option<(u16, &Template)>) -> Response {
    match (ret, &level.proxy, level.try_files.as_deref()) {
        (Some((code, text)), _, _) if REDIRECTS.contains(&code) => redirect(code, text.render(r, &Sent::default())),
        (Some((code, text)), _, _) if text.0.is_empty() && code >= 400 => special(code),
        (Some((code, text)), _, _) => {
            let ctype = Some("text/plain".to_string());
            Response { status: code, ctype, body: crate::vars::bytes(&text.render(r, &Sent::default())), ..Response::default() }
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

/// The URL a rewrite redirects to, as ngx_unescape_uri() with
/// NGX_UNESCAPE_REDIRECT leaves it: "%XX" of a character after "%" and before
/// DEL is decoded and the others kept, an invalid escape loses its "%" (and,
/// after a valid first digit, both characters), and a "?" ends the decoding.
fn unescape_redirect(url: &str) -> String {
    let (b, mut out, mut i) = (url.as_bytes(), Vec::new(), 0);
    let hex = |at: usize| b.get(at).and_then(|&c| (c as char).to_digit(16)).map(|d| d as u8);
    while i < b.len() {
        if b[i] == b'?' { break; }
        if b[i] != b'%' { out.push(b[i]); i += 1; continue; }
        let (c, n) = match (hex(i + 1), hex(i + 2)) { (Some(h), Some(l)) => (Some(h << 4 | l), 3), (Some(_), None) => (None, 3), (None, _) => (None, 2) };
        if c == Some(b'?') { out.push(b'?'); i += 3; break; }
        match c { Some(c) if c > b'%' && c < 0x7f => out.push(c), Some(_) => out.extend_from_slice(&b[i..i + 3]), None => out.extend(b.get(i + 1).filter(|_| n == 2)) }
        i = (i + n).min(b.len());
    }
    out.extend_from_slice(&b[i..]);
    String::from_utf8_lossy(&out).into_owned()
}

/// "?" and the arguments of the request, or "" when it has none.
fn args(r: &Request) -> &str {
    r.target.find('?').map_or("", |i| &r.target[i..])
}

/// Answers one request; when the connection stays open for the next one, how
/// long it waits for it (keepalive_timeout).
fn exchange(stream: &mut TcpStream, server: &Server, r: &Request, parsed: Result<(), u16>, found: Found, local: SocketAddr, ahead: &[u8]) -> Option<Duration> {
    let (mut resp, mut level, mut last) = answer(server, r, parsed, found);
    let intercepted = !resp.proxied || level.proxy_intercept_errors;
    if let Some(ep) = level.error_page.iter().find(|e| e.codes.contains(&resp.status)).filter(|_| intercepted) {
        // An intercepted 401 keeps the proxied server's WWW-Authenticate headers,
        // and a redirect twinx made its Location.
        let auth = |h: &&(String, String)| resp.proxied && resp.status == 401 && h.0.eq_ignore_ascii_case("www-authenticate");
        let kept: Vec<_> = resp.headers.iter().filter(|h| auth(h) || !resp.proxied && h.0.eq_ignore_ascii_case("location")).cloned().collect();
        let url = ep.url.render(r, &Sent::default());
        let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && l.path == url);
        if url.starts_with('/') || named.is_some() {
            // An internal redirect: the URI is answered as a GET (or HEAD) request
            // by its location, with the error's status unless that answer has its own.
            // A named location answers the request as it is.
            let mut to = r.clone();
            (to.upstream_addr, to.upstream_status) = (resp.upstream_addr.take(), resp.upstream_status.take());
            if named.is_none() {
                to.uri = url.split('?').next().unwrap_or_default().to_string();
                to.target = url;
                to.method = if r.method == "HEAD" { "HEAD" } else { "GET" }.to_string();
            }
            // The answer is sent with the error's status ("=code" replaces it, "=" leaves the
            // answer's own), unless it is a page generated for its own error or redirect.
            let status = ep.status.unwrap_or(resp.status);
            let found = named.map_or_else(|| located(server, &to, &to.uri), |l| (l.path.as_str(), &l.level, false));
            (resp, level, last) = answer(server, &to, Ok(()), found);
            if !resp.generated && status != 0 { resp.status = status; }
            // A redirect the new answer makes replaces the Location kept.
            let own = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("location"));
            resp.headers.splice(0..0, kept.into_iter().filter(|h| !own || !h.0.eq_ignore_ascii_case("location")));
        } else {
            // A named location that does not exist is an error.
            resp = if url.starts_with('@') { special(500) } else { redirect(ep.status.filter(|s| REDIRECTS.contains(s)).unwrap_or(302), url) };
        }
    }
    // The headers and the log see the request as the last internal redirect left it ($uri).
    let r = &last;
    not_modified(r, level, &mut resp);
    let absolute = level.absolute_redirect && !resp.relative;
    if let Some(h) = resp.headers.iter_mut().find(|h| h.0.eq_ignore_ascii_case("location") && h.1.starts_with('/')).filter(|_| absolute) {
        let host = if level.server_name_in_redirect { r.server_name.clone() } else { r.host.clone().unwrap_or_else(|| local.ip().to_string()) };
        let port = if level.port_in_redirect && local.port() != 80 { format!(":{}", local.port()) } else { String::new() };
        h.1 = format!("http://{host}{port}{}", h.1);
    }
    let gzipped = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("content-encoding") && h.1.eq_ignore_ascii_case("gzip"));
    if level.gunzip && gzipped {
        resp.vary = true;
        finish(&mut resp);
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
        Sent { status: resp.status, headers, upstream: resp.upstream.clone(), trailers: trailers.to_vec(), upstream_addr: resp.upstream_addr.clone(), upstream_status: resp.upstream_status.clone(), upstream_time: resp.upstream_time.clone(), upstream_bytes: resp.upstream_bytes.clone(), proxy_host: resp.proxy_host.clone(), ..Sent::default() }
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
    finish(&mut resp);
    // server_tokens off: the pages twinx generates give its name without the version.
    if resp.generated && !level.server_tokens {
        resp.body = String::from_utf8_lossy(&resp.body).replace(&format!("<hr><center>{NAME}</center>"), "<hr><center>twinx</center>").into_bytes();
    }
    gzip(r, level, &mut resp);
    range(r, &mut resp);
    let status = resp.status;
    // A body of unknown length is chunked for HTTP/1.1; otherwise the connection
    // closes after it. A HEAD answer has neither.
    // add_trailer makes it chunked too, except for a status that has no body.
    // chunked_transfer_encoding off leaves both unchunked.
    let unknown = resp.unknown_length && r.method != "HEAD";
    let trailing = level.add_trailer.iter().any(|t| t.2 || added) && r.method != "HEAD" && ![204, 304].contains(&status);
    // An upgraded connection is neither chunked nor kept alive, and has no length.
    let upgraded = resp.tunnel.is_some();
    let chunked = (unknown || trailing) && r.line.ends_with("HTTP/1.1") && level.chunked && !upgraded;
    let keepalive = parsed.is_ok() && keepalive(r) && keeps_alive(r, level) && ![400, 413, 414, 500, 501].contains(&status) && (chunked || !unknown) && !upgraded;
    let mut out = Vec::new();
    // 444 closes the connection without an answer; 499 is the status of a client that closed it.
    let silent = [444, 499].contains(&status);
    if !silent && !http09(r.line.as_bytes()) {
        let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
        let ctype = resp.ctype.as_ref().map(|t| format!("Content-Type: {t}\r\n")).unwrap_or_default();
        let connection = if upgraded { "upgrade" } else if keepalive { "keep-alive" } else { "close" };
        let len = resp.body.len();
        let length = if chunked { "Transfer-Encoding: chunked\r\n".to_string() } else if !resp.unknown_length && status != 304 && !upgraded { format!("Content-Length: {len}\r\n") } else { String::new() };
        let header = level.keepalive_header.filter(|_| keepalive).map(|t| format!("Keep-Alive: timeout={t}\r\n")).unwrap_or_default();
        let vary = if resp.vary && level.gzip_vary { "Vary: Accept-Encoding\r\n" } else { "" };
        let server = if level.server_tokens { NAME } else { "twinx" };
        let mut head = format!("HTTP/1.1 {status} {reason}\r\nServer: {server}\r\nDate: {date}\r\n{ctype}{length}Connection: {connection}\r\n{header}{vary}");
        resp.headers.iter().for_each(|(n, v)| head += &format!("{n}: {v}\r\n"));
        out = crate::vars::bytes(&(head + "\r\n"));
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
        trailers.iter().for_each(|(n, v)| out.extend(crate::vars::bytes(&format!("{n}: {v}\r\n"))));
        out.extend_from_slice(b"\r\n");
    }
    // limit_rate: a rate set $limit_rate or X-Accel-Limit-Rate gave, else the location's.
    let size = |t: &Template| crate::conf::size(&t.render(r, &Sent::default())).unwrap_or(0);
    let rate = r.limit_rate.get().unwrap_or_else(|| size(&level.limit_rate));
    let _ = stream.set_write_timeout(Some(level.send_timeout).filter(|t| !t.is_zero()));
    let written = send(stream, &out, rate, size(&level.limit_rate_after), r.started);
    // What was passed from the proxied server through an upgraded connection counts as sent, as body.
    let tunneled = resp.tunnel.take().filter(|_| written).map_or(0, |up| tunnel(stream, up, ahead));
    let sent = Sent { bytes: out.len() + tunneled, body: body_len + tunneled, ..so_far(&resp, &trailers) };
    if written { post_action(server, r, level); }
    level.access_log.iter().for_each(|log| log.write(level, r, &sent));
    (written && keepalive && !silent).then_some(level.keepalive_timeout)
}

/// Passes data both ways between a client and the proxied server its
/// connection was upgraded to, until either closes it or sends nothing for
/// proxy_read_timeout.
fn tunnel(client: &TcpStream, up: TcpStream, ahead: &[u8]) -> usize {
    let _ = client.set_read_timeout(up.read_timeout().ok().flatten());
    let (Ok(mut from_client), Ok(mut to_up)) = (client.try_clone(), up.try_clone()) else { return 0 };
    // What the client sent after the request's head goes first.
    let ahead = ahead.to_vec();
    let other = thread::spawn(move || { if to_up.write_all(&ahead).is_ok() { let _ = std::io::copy(&mut from_client, &mut to_up); } let _ = to_up.shutdown(Shutdown::Both); });
    let (mut passed, mut chunk) = (0, [0u8; 16384]);
    while let Ok(n @ 1..) = (&up).read(&mut chunk) { if (&*client).write_all(&chunk[..n]).is_err() { break } passed += n; }
    let _ = client.shutdown(Shutdown::Both);
    let _ = other.join();
    passed
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
    let found = named.map_or_else(|| located(server, &to, &to.uri), |l| (l.path.as_str(), &l.level, false));
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
    (resp.status, resp.ctype, resp.body, resp.rest) = (304, None, Vec::new(), None);
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges") && !h.0.eq_ignore_ascii_case("content-encoding"));
}

/// The range filter, as ngx_http_range_header_filter() is: a 200 answer of a
/// known length that allows ranges, to a request with a "bytes=" Range, is
/// 206 with the part the range asks for ("start-end", "start-" or "-suffix"),
/// unless an If-Range differs from its ETag (a quoted value, compared exactly)
/// or its Last-Modified time. A range that starts past the end is 416.
/// Several ranges (multipart), which no test needs, are not done yet.
fn range(r: &Request, resp: &mut Response) {
    let ok = resp.status == 200 && resp.ranges && !resp.unknown_length && !http09(r.line.as_bytes());
    let Some(spec) = header(r, "range").filter(|v| ok && v.len() > 6 && v[..6].eq_ignore_ascii_case("bytes=")).map(|v| v[6..].trim()) else { return };
    let sent = |name: &str| resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    let same = |v: &str| if v.len() >= 2 && v.ends_with('"') { sent("etag").as_deref() == Some(v) } else { sent("last-modified").and_then(|t| expires::http_time(&t)).is_some_and(|t| expires::http_time(v) == Some(t)) };
    if !header(r, "if-range").is_none_or(same) || spec.contains(',') { return; }
    let len = resp.body.len() as u64;
    let num = |s: &str| Some(s).filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).and_then(|s| s.parse::<u64>().ok());
    let Some((from, to)) = spec.split_once('-').map(|(f, t)| (f.trim(), t.trim())) else { return };
    // "-suffix" is the last bytes; "start-end" and "start-" start at start.
    let suffix = from.is_empty();
    let (Some(n), true) = (num(if suffix { to } else { from }), suffix || to.is_empty() || num(to).is_some()) else { return };
    let (start, end) = if suffix { (len.saturating_sub(n), len) } else { (n, num(to).map_or(len, |e| e.saturating_add(1).min(len))) };
    if start >= end { if start > 0 { *resp = Response { headers: vec![("Content-Range".into(), format!("bytes */{len}"))], ..special(416) }; } return; }
    resp.status = 206;
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges"));
    resp.headers.push(("Content-Range".into(), format!("bytes {start}-{}/{len}", end - 1)));
    resp.body = resp.body[start as usize..end as usize].to_vec();
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
    // Once the location or an if block that applied has proxy_pass, the request
    // is proxied: when the last if block that applied has no proxy_pass to
    // inherit, nginx has no upstream for it and answers 500.
    let mut proxied = level.proxy.is_some();
    if parsed.is_ok() { level = run(r, &level.script, run(r, &level.server_script, level, &mut proxied), &mut proxied); }
    let mut resp = if proxied && level.proxy.is_none() { log_at(level, r, "alert", "no upstream configuration"); special(500) } else { respond(r, parsed, (prefix, level, auto)) };
    let (mut redirects, mut to) = (0, r.clone());
    while let Some(target) = resp.internal.take() {
        // nginx gives up after 10 internal redirects.
        redirects += 1;
        // After X-Accel-Redirect the proxied answer's headers stay ($upstream_http_*),
        // and the new answer has those of them nginx keeps.
        let kept = resp.proxied.then(|| { to.upstream = std::mem::take(&mut resp.upstream); (std::mem::take(&mut resp.headers), resp.ctype.take()) });
        // A named location answers the request as it is, without the server's rewrites.
        let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && l.path == target);
        let (prefix, found, auto) = if let Some(l) = named { (l.path.as_str(), &l.level, false) } else {
            if resp.as_get && to.method != "HEAD" { to.method = "GET".to_string(); }
            to.uri = target.split('?').next().unwrap_or_default().to_string();
            to.target = target.clone();
            located(server, &to, &to.uri)
        };
        let proxied = &mut false;
        level = run(&to, &found.script, if named.is_some() { found } else { run(&to, &found.server_script, found, proxied) }, proxied);
        resp = if redirects > 10 || (target.starts_with('@') && named.is_none()) { special(500) } else { respond(&to, Ok(()), (prefix, level, auto)) };
        if let Some((headers, ctype)) = kept {
            resp.headers.splice(0..0, headers);
            if let Some(ctype) = ctype.filter(|_| resp.status < 300) { resp.ctype = Some(ctype); }
            resp.upstream = to.upstream.clone();
        }
    }
    (resp, level, to)
}

/// Runs set and if in order, and gives the settings the request goes on with:
/// those of the last if block whose condition held, else the level's own.
/// Notes whether one of those had proxy_pass.
fn run<'a>(r: &Request, ops: &'a [Op], mut level: &'a Level, proxied: &mut bool) -> &'a Level {
    for op in ops {
        match op {
            // set $limit_rate: a value that is not a size leaves it as it was.
            Op::Set(name, value) if name == "limit_rate" => if let Ok(rate) = crate::conf::size(&value.render(r, &Sent::default())) { r.limit_rate.set(rate); },
            Op::Set(name, value) => r.set_var(name, value.render(r, &Sent::default())),
            Op::If(cond, body, to) => if holds(r, cond) {
                level = to.as_deref().unwrap_or(level);
                *proxied |= level.proxy.is_some();
                level = run(r, body, level, proxied);
            },
        }
    }
    level
}

/// Whether the condition of an if holds; a regular expression that matches
/// gives its captures.
fn holds(r: &Request, cond: &Condition) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let value = |t: &Template| t.render(r, &Sent::default());
    match cond {
        Condition::Var(var) => !matches!(value(var).as_str(), "" | "0"),
        Condition::Equal(var, to, not) => (value(var) == value(to)) != *not,
        Condition::Match(var, re, not) => re.captures(&value(var)).map(|c| r.set_captures(&c)).is_some() != *not,
        Condition::File(path, test, not) => {
            let meta = std::fs::metadata(value(path));
            let is = meta.is_ok_and(|m| match test { 'f' => m.is_file(), 'd' => m.is_dir(), 'x' => m.permissions().mode() & 0o111 != 0, _ => true });
            is != *not
        }
    }
}

/// Serves a file under root (or alias), as nginx's static module does; a
/// directory asked for without the trailing "/" is redirected to it. A URI
/// that ends with "/" is the index module's: "index.html" in that directory,
/// by an internal redirect, else 403 when the directory exists and 404 when not.
fn file(level: &Level, r: &Request, prefix: &str) -> Response {
    if !matches!(r.method.as_str(), "GET" | "HEAD" | "POST") { return special(405); }
    let path = match &level.alias {
        // In a regular expression location, alias with captures names the whole path.
        Some(_) if let (Some(t), None) = (&level.alias_vars, level.alias_len) => PathBuf::from(t.render(r, &Sent::default())),
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
    log_at(level, r, "error", msg)
}

/// Writes an error of the request at a level of error_log ("error", "alert").
fn log_at(level: &Level, r: &Request, severity: &str, msg: &str) {
    let Some(mut log) = level.error_log.as_deref() else { return };
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let host = r.host.as_ref().map(|h| format!(", host: \"{h}\"")).unwrap_or_default();
    let line = format!("{time} [{severity}] {}#0: {msg}, client: {}, server: {}, request: \"{}\"{host}\n", std::process::id(), r.peer.ip(), r.server_name, r.line);
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
    Response { status: 200, ctype: Some(ctype.to_string()), headers, body, vary, ranges: true, ..Response::default() }
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

/// Passes the request to the proxied servers in turn, as proxy_http_version
/// says (1.1 by default) and, as nginx 1.30 does, with no Connection header of
/// its own, until one answers with a response head.
fn proxy(p: &Proxy, level: &Level, r: &Request, prefix: &str) -> Response {
    let rest = escape_uri(r.uri.get(prefix.len()..).unwrap_or_default());
    let (host, uri, up) = match &p.url {
        None => (p.host.clone(), p.uri.as_ref().map_or_else(|| r.target.clone(), |u| format!("{u}{rest}{}", args(r))), p.upstream.clone()),
        Some(url) => match resolved(&url.render(r, &Sent::default()), p, level, r) {
            Some(t) => t,
            None => return special(502),
        },
    };
    // proxy_set_header comes first, then the headers it does not set, as nginx sends them.
    let sent = Sent { proxy_host: Some(host.clone()), ..Sent::default() };
    // proxy_set_body replaces the client's body, whatever proxy_pass_request_body
    // says; proxy_pass_request_body off sends no body, and so no Content-Length.
    let set_body = level.proxy_set_body.as_ref().map(|b| b.render(r, &sent).into_bytes());
    let pass_body = level.proxy_pass_request_body && set_body.is_none();
    let body = match &set_body {
        Some(b) => b.clone(),
        None if pass_body => r.body_file.as_ref().map_or_else(|| r.body.clone(), |f| std::fs::read(f).unwrap_or_default()),
        None => Vec::new(),
    };
    let set: Vec<(&String, String)> = level.proxy_set_header.iter().map(|(n, v)| (n, v.render(r, &sent))).collect();
    let is_set = |name: &str| set.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    // proxy_method replaces the request's method.
    let method = level.proxy_method.as_ref().map_or_else(|| r.method.clone(), |m| m.render(r, &sent));
    let mut req = format!("{method} {uri} HTTP/1.{}\r\n", level.proxy_http_11 as u8);
    set.iter().filter(|h| !h.1.is_empty()).for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    if !is_set("host") { req += &format!("Host: {host}\r\n"); }
    // A body passed as it comes: the rest of one with a Content-Length, or chunks.
    let mut unread = r.unread.lock().unwrap();
    let chunked = unread.as_ref().is_some_and(|u| u.chunked.is_some());
    if pass_body && chunked { req += "Transfer-Encoding: chunked\r\n"; }
    if pass_body && !chunked && framing(r) != Ok(Some(0)) { req += &format!("Content-Length: {}\r\n", body.len() as u64 + unread.as_ref().map_or(0, |u| u.left)); }
    if set_body.is_some() { req += &format!("Content-Length: {}\r\n", body.len()); }
    let body = if pass_body && chunked && !body.is_empty() { chunk(&body) } else { body };
    const DROPPED: &[&str] = &["host", "connection", "content-length", "transfer-encoding", "keep-alive", "te", "expect", "upgrade"];
    // proxy_pass_request_headers off passes none of the client's headers.
    let passed = r.headers.iter().filter(|_| level.proxy_pass_request_headers).filter(|(n, _)| !DROPPED.contains(&n.to_ascii_lowercase().as_str()) && !is_set(n));
    passed.for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    let mut req = crate::vars::bytes(&(req + "\r\n"));
    req.extend_from_slice(&body);
    // proxy_bind: an empty value binds to nothing; a value that is no address fails the request.
    let bind = level.proxy_bind.as_ref().map(|(a, t)| (a.render(r, &Sent::default()), *t)).filter(|(a, _)| !a.is_empty());
    let Some(bind) = bind.map(|(a, t)| crate::conf::local_addr(&a).map(|a| (a, t))).map_or(Some(None), |b| b.map(Some)) else { return special(500) };
    // proxy_limit_rate, which may have the answer's headers ($upstream_http_*).
    let rate = |resp: &Response| crate::conf::size(&level.proxy_limit_rate.render(r, &Sent { upstream: resp.upstream.clone(), ..Sent::default() })).unwrap_or(0);
    let (mut tried, mut answer, mut addrs, mut times, mut bytes) = (vec![false; up.peers.len()], None, Vec::new(), Vec::new(), Vec::new());
    let (mut statuses, limit, first) = (Vec::new(), level.proxy_next_upstream_tries, Instant::now());
    let (mut tries, next) = (if limit > 0 { up.tries().min(limit) } else { up.tries() }, |cond: &str| level.proxy_next_upstream.iter().any(|c| c == cond));
    let upgrade = r.headers.iter().any(|h| h.0.eq_ignore_ascii_case("upgrade"));
    // The name certificates are verified for (proxy_ssl_verify) and SNI sends
    // (proxy_ssl_server_name): proxy_ssl_name or $proxy_host, without the port.
    let name = ((level.proxy_ssl_verify || level.proxy_ssl_server_name) && p.ssl).then(|| ssl_name(&level.proxy_ssl_name.as_ref().map_or_else(|| host.clone(), |t| t.render(r, &sent))).to_string());
    while let Some(i) = up.pick(&mut tried) {
        addrs.push(up.peers[i].addr.to_string());
        // A socket that cannot be bound fails the request without trying the next server.
        let socket = bind.map(|b| bound(&up.peers[i].addr, b));
        if socket.as_ref().is_some_and(Option::is_none) { return special(500); }
        let (start, mut time, mut counted) = (Instant::now(), [None; 3], [0; 3]);
        // Names of proxy_ssl_certificate with variables are loaded for each connection; failing to is 500.
        let names = level.proxy_ssl_certificate_vars.as_ref().filter(|_| p.ssl).map(|(c, k, prefix)| (c.render(r, &Sent::default()), k.render(r, &Sent::default()), prefix));
        let tls = match (names.filter(|(c, ..)| !c.is_empty()), level.proxy_tls.as_ref().filter(|_| p.ssl)) {
            (Some((c, k, prefix)), Some(base)) => match crate::tls::client_cert(base, (&prefix.join(c), &prefix.join(k), level.proxy_ssl_password_file.as_deref()), level.proxy_ssl_certificate_cache.as_deref()) {
                Ok(tls) => Some(tls),
                Err(e) => { error_log(level, r, &e); return special(500) }
            },
            (_, tls) => tls.cloned(),
        };
        answer = fetch((&up.peers[i].addr, tls.as_ref().map(|t| (t, name.as_deref()))), socket.flatten(), &req, level, r.client, (&mut time, &mut counted), &rate, unread.as_mut().filter(|_| pass_body), level.max_body, upgrade);
        time[2] = Some(start.elapsed().as_millis());
        times.push(time);
        bytes.push(counted);
        // An error, or a status proxy_next_upstream names while servers are
        // left to try, goes on to the next server; 403 and 404 are no failures.
        tries -= 1;
        let status = answer.as_ref().map(|a| a.status);
        statuses.push(status.unwrap_or(502).to_string());
        // proxy_next_upstream_tries and proxy_next_upstream_timeout end the tries too.
        let timeout = level.proxy_next_upstream_timeout;
        // The page fetch() generates for a timeout, rather than an answer of the server.
        let timed_out = answer.as_ref().is_some_and(|a| a.generated);
        let again = if timed_out { next("timeout") } else { status.map_or(next("error"), |s| tries > 0 && next(&format!("http_{s}"))) } && (timeout.is_zero() || first.elapsed() < timeout);
        up.done(i, answer.is_none() || timed_out || again && !matches!(status, Some(403 | 404)));
        if !again || tries == 0 { break; }
        answer = None;
    }
    let (upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host) = (Some(addrs.join(", ")), Some(statuses.join(", ")), Some(times), Some(bytes), Some(host));
    let Some(mut resp) = answer else { return Response { upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host, ..special(502) } };
    (resp.upstream_addr, resp.upstream_status, resp.upstream_time, resp.upstream_bytes, resp.proxy_host) = (upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host);
    // X-Accel-Limit-Rate sets the rate the answer is sent at; X-Accel-Redirect
    // replaces the answer with an internal redirect to its URI.
    let accel = |name: &str| resp.upstream.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    if let Some(rate) = accel("x-accel-limit-rate").and_then(|v| v.parse().ok()) { r.limit_rate.set(rate); }
    // It keeps Content-Type and the headers below; an unsafe URI is 404.
    if let Some(to) = accel("x-accel-redirect") {
        const KEPT: &[&str] = &["set-cookie", "content-disposition", "cache-control", "expires", "accept-ranges"];
        resp.headers.retain(|h| KEPT.contains(&h.0.to_ascii_lowercase().as_str()));
        let named = to.starts_with('@');
        let Some((uri, args)) = (if named { Some((to, None)) } else { unsafe_uri(&to) }) else { return special(404) };
        return Response { internal: Some(args.map_or_else(|| uri.clone(), |a| format!("{uri}?{a}"))), as_get: !named, ..resp };
    }
    let hidden = |name: &str| level.proxy_hide_header.iter().any(|h| h.eq_ignore_ascii_case(name));
    resp.headers.retain(|h| !hidden(&h.0));
    if hidden("content-type") { resp.ctype = None; }
    for h in resp.headers.iter_mut().filter(|h| h.0.eq_ignore_ascii_case("set-cookie")) {
        if let Some(cookie) = rewrite_cookie(r, &h.1, level) { h.1 = cookie; }
    }
    resp.relative = !rewrite_redirect(r, level, &mut resp.headers);
    resp
}

/// proxy_redirect: the first rule that matches the Location, or what follows
/// "url=" in a Refresh, replaces what it matched; true when a Location changed.
fn rewrite_redirect(r: &Request, level: &Level, headers: &mut [(String, String)]) -> bool {
    let rules = level.proxy_redirect.as_deref().unwrap_or_default();
    let mut changed = false;
    for (name, value) in headers.iter_mut() {
        let location = name.eq_ignore_ascii_case("location");
        let start = if location { Some(0) } else if name.eq_ignore_ascii_case("refresh") { value.to_ascii_lowercase().find("url=").map(|i| i + 4) } else { None };
        let Some(start) = start else { continue };
        if let Some(new) = rules.iter().find_map(|rw| cookie_value(r, rw, &value[start..], false)) {
            *value = format!("{}{new}", &value[..start]);
            changed |= location;
        }
    }
    changed
}

/// proxy_cookie_domain and proxy_cookie_path: the Domain and Path attributes of
/// a Set-Cookie the proxied server sends are replaced by the first rewrite that
/// matches them. A cookie changed is written again as nginx writes it, its
/// attributes separated by "; "; None leaves it as it was.
fn rewrite_cookie(r: &Request, cookie: &str, level: &Level) -> Option<String> {
    let mut attrs: Vec<(String, Option<String>)> = cookie.split(';').map(|a| {
        let a = a.trim_start_matches(' ');
        a.split_once('=').map_or((a.trim_end_matches(' ').to_string(), None), |(n, v)| (n.trim_end_matches(' ').to_string(), Some(v.trim_matches(' ').to_string())))
    }).collect();
    attrs[0].1.as_ref()?;
    let mut changed = false;
    for (name, value) in attrs.iter_mut().skip(1) {
        let (domain, rules) = match name.to_ascii_lowercase().as_str() { "domain" => (true, &level.proxy_cookie_domain), "path" => (false, &level.proxy_cookie_path), _ => continue };
        let (Some(rules), Some(v)) = (rules, value.as_mut()) else { continue };
        if let Some(new) = rules.iter().find_map(|rw| cookie_value(r, rw, v, domain)) { (*v, changed) = (new, true); }
    }
    if let Some(rules) = &level.proxy_cookie_flags { changed |= cookie_flags(r, rules, level, &mut attrs); }
    changed.then(|| attrs.iter().map(|(n, v)| v.as_ref().map_or(n.to_string(), |v| format!("{n}={v}"))).collect::<Vec<_>>().join("; "))
}

/// proxy_cookie_flags: the flags of the first rule whose cookie the name
/// matches set Secure, HttpOnly and SameSite (changing the value of one the
/// cookie has), or remove them; false when no rule matches or it gives no
/// flag. A flag that is not one nginx knows is logged and left out.
fn cookie_flags(r: &Request, rules: &[CookieFlags], level: &Level, attrs: &mut Vec<(String, Option<String>)>) -> bool {
    let (sent, name) = (Sent::default(), attrs[0].0.clone());
    let matches = |rule: &&CookieFlags| match &rule.cookie { CookiePattern::Regex(re) => re.captures(&name).map(|c| r.set_captures(&c)).is_some(), CookiePattern::Text(t) => t.render(r, &sent).eq_ignore_ascii_case(&name) };
    let Some(rule) = rules.iter().find(matches) else { return false };
    let mut bits = 0;
    for f in rule.flags.iter().map(|f| f.render(r, &sent)).filter(|f| !f.is_empty()) {
        match crate::conf::COOKIE_FLAGS.iter().position(|k| k.eq_ignore_ascii_case(&f)) { Some(i) => bits |= 1 << i, None => error_log(level, r, &format!("invalid proxy_cookie_flags flag \"{f}\"")) }
    }
    // Secure, HttpOnly and SameSite: whether each is set (SameSite to Strict
    // before Lax before None), and whether it is removed.
    let samesite = [6, 5, 4].into_iter().find(|i| bits & 1 << i != 0).map(|i| ["None", "Lax", "Strict"][i - 4]);
    let (mut set, removed) = ([bits & 1 != 0, bits & 2 != 0, samesite.is_some()], [bits & 4 != 0, bits & 8 != 0, bits & 128 != 0]);
    attrs.retain_mut(|(name, value)| {
        let Some(k) = ["secure", "httponly", "samesite"].iter().position(|k| k.eq_ignore_ascii_case(name)) else { return true };
        if k == 2 && set[k] { *value = samesite.map(String::from); }
        std::mem::take(&mut set[k]) || !removed[k]
    });
    attrs.extend((0..3).filter(|&k| set[k]).map(|k| (["Secure", "HttpOnly", "SameSite"][k].to_string(), samesite.filter(|_| k == 2).map(String::from))));
    bits != 0
}

/// The value one rewrite makes of a Domain or Path (or, for proxy_redirect, of
/// a Location as of a Path), None when it does not match.
fn cookie_value(r: &Request, rw: &CookieRewrite, value: &str, domain: bool) -> Option<String> {
    let replacement = || rw.replacement.render(r, &Sent::default());
    match &rw.pattern {
        CookiePattern::Regex(re) => {
            r.set_captures(&re.captures(value)?);
            Some(replacement())
        }
        CookiePattern::Text(p) if domain => {
            let (dot, rest) = value.strip_prefix('.').map_or(("", value), |rest| (".", rest));
            rest.eq_ignore_ascii_case(&p.render(r, &Sent::default())).then(|| format!("{dot}{}", replacement()))
        }
        CookiePattern::Text(p) => value.strip_prefix(p.render(r, &Sent::default()).as_str()).map(|rest| format!("{}{rest}", replacement())),
    }
}

/// The Host, the URI and the servers of a proxy_pass URL with variables: its
/// host is an upstream group, an address, or a name the location's resolver
/// looks up. The URI, when the URL has one, is sent as it is.
fn resolved(url: &str, p: &Proxy, level: &Level, r: &Request) -> Option<(String, String, Arc<Upstream>)> {
    let rest = url.strip_prefix("http://")?;
    let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
    if let Some(up) = p.groups.get(host) { return Some((host.to_string(), uri.unwrap_or_else(|| r.target.clone()), up.clone())); }
    let (name, port) = crate::conf::host_port(host, 80)?;
    // As in nginx, the implicit upstream of a proxy_pass with this host and port comes before the resolver.
    let implicit = p.implicit.lock().unwrap().get(&format!("{}:{port}", name.to_ascii_lowercase())).cloned();
    if let Some(up) = implicit { return Some((host.to_string(), uri.unwrap_or_else(|| r.target.clone()), up)); }
    let resolve = || level.resolver.as_ref()?.resolve(name, level.resolver_timeout);
    let addrs = name.parse::<IpAddr>().map(|a| vec![a]).ok().or_else(resolve)?;
    let peers = addrs.into_iter().map(|a| Peer::new(SocketAddr::new(a, port))).collect();
    Some((host.to_string(), uri.unwrap_or_else(|| r.target.clone()), Arc::new(Upstream::new(peers))))
}

/// Sends a request to one server and reads its whole answer, noting how long
/// it took to connect and to send the response head. While it waits for the
/// head, the client closing the connection ends the request with 499, as
/// proxy_ignore_client_abort off does.
/// The host of a name such as proxy_ssl_name gives, as nginx takes it: up to a
/// port, if any, and without the brackets of an IPv6 address.
fn ssl_name(name: &str) -> &str {
    let bracket = if name.starts_with('[') { name.find(']').unwrap_or(0) } else { 0 };
    let host = name[bracket..].find(':').map_or(name, |i| &name[..bracket + i]);
    host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host)
}

fn fetch((peer, tls): (&SocketAddr, Option<(&Arc<rustls::ClientConfig>, Option<&str>)>), socket: Option<socket2::Socket>, req: &[u8], level: &Level, client: i32, (time, bytes): (&mut [Option<u128>; 3], &mut [u64; 3]), rate: &dyn Fn(&Response) -> u64, unread: Option<&mut Unread>, max: u64, upgrade: bool) -> Option<Response> {
    let start = Instant::now();
    let s = match socket {
        Some(socket) => socket.connect_timeout(&(*peer).into(), level.proxy_connect_timeout).ok().map(|()| TcpStream::from(socket))?,
        None => TcpStream::connect_timeout(peer, level.proxy_connect_timeout).ok()?,
    };
    // proxy_pass https://: the TLS handshake is part of connecting.
    // A handshake that does not end within proxy_connect_timeout is a timeout, answered with 504.
    let mut s = if let Some((tls, name)) = tls { match crate::tls::connect(s, (peer.ip(), name), level.proxy_connect_timeout, tls) { Ok(s) => s, Err(e) => return (e.kind() == std::io::ErrorKind::WouldBlock).then(|| special(504)) } } else { s };
    time[0] = Some(start.elapsed().as_millis());
    let _ = s.set_read_timeout(Some(level.proxy_read_timeout));
    let (mut answer, mut chunk) = (Vec::new(), [0u8; 4096]);
    s.write_all(req).ok()?;
    bytes[2] = req.len() as u64;
    // The rest of a body that is not buffered goes on as the client sends it.
    if let Some(u) = unread { bytes[2] += pass_body(u, max, &mut s)?; }
    // A head that does not fit in proxy_buffer_size is too big: the answer is invalid.
    let end = loop {
        if let Some(end) = head_end(&answer[..answer.len().min(level.proxy_buffer_size)]) { break end; }
        if answer.len() >= level.proxy_buffer_size { return None; }
        if client_closed(&s, client, level.proxy_read_timeout)? { return Some(Response { status: 499, ..Response::default() }); }
        let n = s.read(&mut chunk).ok().filter(|n| *n > 0)?;
        answer.extend_from_slice(&chunk[..n]);
        bytes[1] = answer.len() as u64;
    };
    time[1] = Some(start.elapsed().as_millis());
    let head = crate::vars::text(&answer[..end]);
    let mut lines = head.split('\n').map(|l| l.trim_end_matches('\r')).filter(|l| !l.is_empty());
    let status = lines.next()?.strip_prefix("HTTP/1.")?.get(2..)?.split(' ').find(|w| !w.is_empty())?.parse().ok()?;
    let mut resp = Response { status, proxied: true, ..Response::default() };
    const HIDDEN: &[&str] = &["date", "server", "connection", "keep-alive", "transfer-encoding", "content-length", "x-pad"];
    for line in lines {
        let (name, value) = upstream_header(line)?;
        let (lower, value) = (name.to_ascii_lowercase(), value.to_string());
        resp.upstream.push((name.to_string(), value.clone()));
        if lower == "content-type" { resp.ctype = Some(value); continue; }
        // A second Expires is ignored.
        let again = lower == "expires" && resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("expires"));
        if !again && !HIDDEN.contains(&lower.as_str()) && !lower.starts_with("x-accel-") { resp.headers.push((name.to_string(), value)); }
    }
    // 101 to a request with Upgrade: what came after the head goes to the client first.
    if status == 101 && upgrade { return Some(Response { body: answer[end..].to_vec(), tunnel: Some(s), ..resp }); }
    // The body's length: one Content-Length of digits, or one "Transfer-Encoding:
    // chunked" without it; any other mix makes the answer invalid. A HEAD, 204
    // or 304 answer has no body.
    let values = |name: &str| resp.upstream.iter().filter(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone()).collect::<Vec<_>>();
    let (length, chunked) = match (&values("content-length")[..], &values("transfer-encoding")[..]) {
        ([], []) => (None, false),
        ([l], []) => (Some(l.bytes().all(|b| b.is_ascii_digit()).then(|| l.parse::<usize>().ok()).flatten()?), false),
        ([], [c]) if c.eq_ignore_ascii_case("chunked") => (None, true),
        _ => return None,
    };
    // The body of an answer that redirects with X-Accel-Redirect is not read.
    let accel = resp.upstream.iter().any(|h| h.0.eq_ignore_ascii_case("x-accel-redirect"));
    let no_body = req.starts_with(b"HEAD ") || [204, 304].contains(&status) || accel;
    let (length, chunked) = if no_body { (Some(0), false) } else { (length, chunked) };
    let rate = rate(&resp);
    if rate > 0 { return Some(Response { rest: Some(Rest { s, answer, end, length, chunked, rate, started: start }), ..resp }); }
    let (body, read) = read_body(&mut s, answer, end, length, chunked, 0)?;
    (resp.body, bytes[0], bytes[1]) = (body, (read - end) as u64, read as u64);
    Some(resp)
}


/// A header line of a proxied server's answer as ngx_http_parse_header_line()
/// reads it: a line without ":" is a name with an empty value, and the value
/// loses the spaces around it. None when the line is invalid: it starts with a
/// space (a folded line) or ":", its name has spaces or control characters, or
/// it has a NUL or a CR that does not end it.
fn upstream_header(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.split_once(':').unwrap_or((line, ""));
    let invalid = name.is_empty() || name.bytes().any(|c| c <= 0x20 || c == 0x7f) || value.contains(['\0', '\r']);
    (!invalid).then(|| (name, value.trim_matches(' ')))
}

/// Reads a proxied answer's body up to its length, up to its last chunk, or
/// until the server closes the connection; what follows the last chunk is
/// dropped. With a rate it is read as ngx_event_pipe_read_upstream() paces
/// proxy_limit_rate: by the end of each second since the body started
/// (counted in whole seconds of the clock) up to the rate for each second has
/// been read, and when that much has, it waits for the time it is worth.
/// Returns the body and the bytes of the whole answer read.
fn read_body(s: &mut TcpStream, mut answer: Vec<u8>, end: usize, length: Option<usize>, chunked: bool, rate: u64) -> Option<(Vec<u8>, usize)> {
    let secs = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let (start, rate, mut chunk) = (secs(), rate as i64, [0u8; 4096]);
    while length.is_none_or(|n| answer.len() - end < n) && !(chunked && unchunk(&answer[end..]).1) {
        let limit = if rate == 0 { chunk.len() as i64 } else { rate * (secs() - start + 1) - (answer.len() - end) as i64 };
        if limit <= 0 { thread::sleep(Duration::from_millis((-limit * 1000 / rate + 1) as u64)); continue; }
        let n = s.read(&mut chunk[..(limit as usize).min(4096)]).ok()?;
        if n == 0 { break; }
        answer.extend_from_slice(&chunk[..n]);
    }
    let body = &answer[end..];
    Some((if chunked { unchunk(body).0 } else { body[..length.unwrap_or(body.len()).min(body.len())].to_vec() }, answer.len()))
}

/// A socket for connecting to a proxied server from a local address, set up
/// as nginx does: with a port, the address may be reused; without one, the
/// port is chosen when connecting; "transparent" allows a foreign address.
fn bound(peer: &SocketAddr, (local, transparent): (SocketAddr, bool)) -> Option<socket2::Socket> {
    use std::os::fd::AsRawFd;
    let s = socket2::Socket::new(socket2::Domain::for_address(*peer), socket2::Type::STREAM, None).ok()?;
    let set = |level: i32, name: i32| {
        let on: libc::c_int = 1;
        // SAFETY: the option value is a c_int that lives through the call.
        unsafe { libc::setsockopt(s.as_raw_fd(), level, name, (&on as *const libc::c_int).cast(), size_of::<libc::c_int>() as libc::socklen_t) == 0 }
    };
    let v4 = peer.is_ipv4();
    if transparent && !(if v4 { set(libc::IPPROTO_IP, libc::IP_TRANSPARENT) } else { set(libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT) }) { return None; }
    let _ = if local.port() == 0 { set(libc::IPPROTO_IP, libc::IP_BIND_ADDRESS_NO_PORT) } else { set(libc::SOL_SOCKET, libc::SO_REUSEADDR) };
    s.bind(&local.into()).ok()?;
    Some(s)
}

/// The data of the chunks of a proxied answer read so far, and whether
/// nothing more is to be read: the last chunk came, or a chunk is invalid.
fn unchunk(buf: &[u8]) -> (Vec<u8>, bool) {
    let (mut body, mut at) = (Vec::new(), 0);
    while let Some(n) = buf[at..].iter().position(|&c| c == b'\n') {
        let line = String::from_utf8_lossy(&buf[at..at + n]);
        let Ok(size) = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16) else { return (body, true) };
        let (start, end) = (at + n + 1, at + n + 1 + size);
        if size == 0 { return (body, true); }
        let Some(after) = buf.get(end..).filter(|a| a.len() >= 2) else { break };
        if !after.starts_with(b"\r\n") && !after.starts_with(b"\n") { return (body, true); }
        body.extend_from_slice(&buf[start..end]);
        at = end + if after[0] == b'\r' { 2 } else { 1 };
    }
    (body, false)
}

/// A body read as it is passed on (proxy_request_buffering off): the
/// client's socket, the bytes left of a body with a Content-Length, or what
/// has come of a chunked one and how much of its data was passed; and, once
/// a chunked body ended, what came after it.
#[derive(Debug)]
pub struct Unread { client: TcpStream, left: u64, chunked: Option<(Vec<u8>, usize)>, rest: Vec<u8> }

/// Data as one chunk.
fn chunk(data: &[u8]) -> Vec<u8> {
    [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat()
}

/// Reads the rest of a body from the client and writes it as it comes: the
/// bytes of a body with a Content-Length as they are, the data of a chunked
/// one in a chunk for each read, with the last chunk once it ends, and returns
/// how many bytes it wrote ($upstream_bytes_sent). None when
/// the client closes, the body is invalid or the writing fails.
fn pass_body(u: &mut Unread, max: u64, to: &mut dyn Write) -> Option<u64> {
    let (mut buf, mut written) = ([0u8; 4096], 0);
    let Some((raw, sent)) = &mut u.chunked else {
        while u.left > 0 {
            let got = u.client.read(&mut buf[..u.left.min(4096) as usize]).ok().filter(|g| *g > 0)?;
            u.left -= got as u64;
            to.write_all(&buf[..got]).ok()?;
            written += got as u64;
        }
        return Some(written);
    };
    loop {
        let (data, used) = decode_chunked(raw, max).ok()?;
        let mut out = if data.len() > *sent { chunk(&data[*sent..]) } else { Vec::new() };
        *sent = data.len();
        if used.is_some() { out.extend_from_slice(b"0\r\n\r\n"); }
        to.write_all(&out).ok()?;
        written += out.len() as u64;
        if let Some(used) = used { u.rest = raw.split_off(used); u.chunked = None; return Some(written); }
        let got = u.client.read(&mut buf).ok().filter(|g| *g > 0)?;
        raw.extend_from_slice(&buf[..got]);
    }
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
    let text = crate::vars::text(head);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    r.line = lines.next().unwrap_or_default().to_string();
    let words: Vec<&str> = r.line.split(' ').filter(|w| !w.is_empty()).collect();
    // HTTP/0.9, which has no version, has only GET.
    let (method, target, version) = match words[..] { [m, t, v] => (m, t, v), [m @ "GET", t] => (m, t, ""), _ => return Err(400) };
    r.method = method.to_string();
    let valid_method = method.bytes().all(|c| c.is_ascii_uppercase() || c == b'_' || c == b'-');
    if !valid_method || !matches!(version, "HTTP/1.0" | "HTTP/1.1" | "") { return Err(400); }
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

/// An X-Accel-Redirect URI as ngx_http_parse_unsafe_uri() takes it: its path,
/// unescaped, and its arguments; None when it is empty, has no path, has a NUL
/// or a ".." segment, before or after unescaping.
fn unsafe_uri(value: &str) -> Option<(String, Option<String>)> {
    let (path, args) = value.split_once('?').map_or((value, None), |(p, a)| (p, Some(a)));
    if path.is_empty() || value.contains('\0') || path.split('/').any(|s| s == "..") { return None; }
    // An unescaped path is looked at again; arguments it has replace the others.
    if let Some(d) = decode(path).filter(|d| d != path) { return unsafe_uri(&d).map(|(p, a)| (p, a.or(args.map(String::from)))); }
    Some((path.to_string(), args.map(String::from)))
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
pub fn server<'a>(config: &'a Config, listen: SocketAddr, host: Option<&str>) -> (&'a Server, Vec<(String, String)>) {
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
    regex.unwrap_or_else(|| (default_server(config, listen), Vec::new()))
}

/// The default server of a listening address: the one listening there with
/// default_server, else the first server listening there.
pub fn default_server(config: &Config, listen: SocketAddr) -> &Server {
    let on = || config.servers.iter().filter(|s| s.listen.contains(&listen));
    on().find(|s| s.defaults.contains(&listen)).or_else(|| on().next()).unwrap_or(&config.servers[0])
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
/// The location of a URI, as location() finds it, with the captures of a
/// regular expression location set for the request.
fn located<'a>(server: &'a Server, r: &Request, uri: &str) -> Found<'a> {
    let found = location(server, uri);
    let kind = server.locations.iter().find(|l| std::ptr::eq(&l.level, found.1)).map(|l| &l.kind);
    if let Some(caps) = kind.and_then(|k| if let Match::Regex(re) = k { re.captures(uri) } else { None }) { r.set_captures(&caps); }
    // A method limit_except does not allow gets the settings of its block.
    let limited = found.1.limit_except.as_ref().filter(|(methods, _)| !methods.contains(&r.method)).map(|(_, l)| &**l);
    (found.0, limited.unwrap_or(found.1), found.2)
}

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
    page_with(status, reason(status), "")
}

fn reason(status: u16) -> &'static str {
    REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r)
}

/// An error page with its own title and lines after the heading.
fn page_with(status: u16, title: &str, more: &str) -> String {
    let reason = reason(status);
    format!(
        "<html>\r\n<head><title>{status} {title}</title></head>\r\n<body>\r\n\
         <center><h1>{status} {reason}</h1></center>\r\n{more}<hr><center>{NAME}</center>\r\n</body>\r\n</html>\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_buffers_overflow() {
        let four = |_: Option<&str>| (4, 16);
        // Lines that fit in the first buffer, or move whole to a large one.
        assert_eq!(overflow(b"GET / HTTP/1.0\r\nA: b\r\n\r\n", 8, four), None);
        assert_eq!(overflow(b"GET /12345678901 HTTP/1.0\r\n", 8, four), Some((414, 0)));
        assert_eq!(overflow(b"GET / HTTP/1.0\r\nX: 123456789012345\r\n", 32, four), Some((494, 16)));
        // A line that has not filled its buffer yet is waited for.
        assert_eq!(overflow(b"GET / HTTP/1.0\r\nX: 12", 32, four), None);
        // Out of large buffers.
        let one = |_: Option<&str>| (1, 16);
        assert_eq!(overflow(b"GET / HTTP/1.0\r\nA: 1234567\r\nB: 1234567\r\n", 8, one), Some((494, 16)));
        // The large buffers of the server Host selects, once it has come.
        let by_host = |h: Option<&str>| if h == Some("big") { (4, 64) } else { (4, 16) };
        assert_eq!(overflow(b"GET / HTTP/1.0\r\nHost: big\r\nX: 123456789012345\r\n", 8, by_host), None);
        let page = String::from_utf8(special(494).body).unwrap();
        assert_eq!(special(494).status, 400);
        assert!(page.starts_with("<html>\r\n<head><title>400 Request Header Or Cookie Too Large</title></head>\r\n<body>\r\n\
            <center><h1>400 Bad Request</h1></center>\r\n<center>Request Header Or Cookie Too Large</center>\r\n<hr>"));
    }

    #[test]
    fn tunnel_passes_data_both_ways() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let (mut client, accepted) = (TcpStream::connect(addr).unwrap(), l.accept().unwrap().0);
        let (mut server, up) = (TcpStream::connect(addr).unwrap(), l.accept().unwrap().0);
        let t = thread::spawn(move || tunnel(&accepted, up, b"early"));
        let mut buf = [0u8; 4];
        let mut early = [0u8; 5];
        server.read_exact(&mut early).unwrap();
        assert_eq!(&early, b"early");
        client.write_all(b"ping").unwrap();
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").unwrap();
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        // The proxied server closing ends the client's connection too.
        drop(server);
        assert_eq!(client.read(&mut buf).unwrap(), 0);
        assert_eq!(t.join().unwrap(), 4);
    }

    #[test]
    fn bind_keeps_open_sockets() {
        let open = vec![(TcpListener::bind("127.0.0.1:0").unwrap(), "0.0.0.0:0".parse::<SocketAddr>().unwrap())];
        let addr = open[0].0.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr}; }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        // The address is taken already, so a socket of its own could not be bound.
        assert!(bind(&config, &[]).unwrap_err().starts_with(&format!("bind() to {addr} failed")));
        let open = vec![(open.into_iter().next().unwrap().0, addr)];
        assert_eq!(bind(&config, &open).unwrap()[0].0.local_addr().unwrap(), addr);
    }

    #[test]
    fn binds_each_address_once_and_finds_its_default_server() {
        let (a, b) = (TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap());
        let (a, b) = ((a.local_addr().unwrap(), a), (b.local_addr().unwrap(), b));
        let text = format!("http {{ server {{ listen {}; listen {}; server_name one; }} server {{ listen {}; listen {} default_server; server_name two; }} }}", a.0, b.0, a.0, b.0);
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let open = vec![(a.1, a.0), (b.1, b.0)];
        assert_eq!(bind(&config, &open).unwrap().iter().map(|l| l.1).collect::<Vec<_>>(), [a.0, b.0]);
        assert_eq!((default_server(&config, a.0).name.as_str(), default_server(&config, b.0).name.as_str()), ("one", "two"));
        assert_eq!(server(&config, b.0, Some("other")).0.name, "two");
    }

    #[test]
    fn shutting_down_answers_connections_already_accepted() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        socket2::SockRef::from(&l).set_read_timeout(Some(ACCEPT_WAIT)).unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr}; location / {{ return 200 done; }} }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap());
        let mut client = TcpStream::connect(addr).unwrap();
        accept(config, &[(l, addr)]).unwrap();
        while BUSY.load(Ordering::SeqCst) == 0 { thread::sleep(Duration::from_millis(1)); }
        // The connection was accepted before its request came: shutting down waits for it.
        let shut = thread::spawn(|| shut_down(None));
        thread::sleep(Duration::from_millis(300));
        assert!(!shut.is_finished());
        client.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        shut.join().unwrap();
        let mut text = String::new();
        client.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 ") && text.ends_with("done"), "{text}");
    }

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
            upstream_status: None,
            upstream: Vec::new(),
            captures: Vec::new(),
            limit_rate: Default::default(),
            vars: Default::default(),
            unread: Default::default(),
            client: -1,
            ssl: None,
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
    fn upstream_header_lines() {
        assert_eq!(upstream_header("X-A:  a b \t "), Some(("X-A", "a b \t")));
        assert_eq!(upstream_header("X_a!b"), Some(("X_a!b", "")));
        for bad in [" Folded: yes", ": a", "X a: 1", "X-A: a\rB: c", "X-A: a\0b", "X\x7f: a"] { assert_eq!(upstream_header(bad), None, "{bad:?}"); }
    }

    #[test]
    fn head_end_with_lf_and_crlf() {
        assert_eq!(head_end(b"GET / HTTP/1.0\nHost: a\n\nrest"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n\r\n"), Some(18));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n"), None);
        assert_eq!(head_end(b"GET /\r\nextra"), Some(7));
    }

    #[test]
    fn parses_http09_requests_of_get_only() {
        let (res, r) = request("GET /a\r\n");
        assert_eq!((res, r.uri.as_str(), keepalive(&r)), (Ok(()), "/a", false));
        assert_eq!(request("POST /a\r\n").0, Err(400));
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
        assert_eq!(request("GET\n\n").0, Err(400));
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
    fn takes_the_host_of_ssl_names() {
        assert_eq!(ssl_name("example.com"), "example.com");
        assert_eq!(ssl_name("127.0.0.1:8081"), "127.0.0.1");
        assert_eq!(ssl_name("[::1]:8081"), "::1");
        assert_eq!(ssl_name("[::1]"), "::1");
        assert_eq!(ssl_name("::1"), "");
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
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let (mut time, mut bytes) = ([None; 3], [0; 3]);
        let resp = fetch((&addr, None), None, b"GET / HTTP/1.0\r\n\r\n", &level, -1, (&mut time, &mut bytes), &|_| 0, None, 0, false).unwrap();
        assert!(time[0].is_some() && time[1].is_some());
        // The body, the whole answer and the request, in bytes.
        assert_eq!(bytes, [4, 80, 18]);
        assert_eq!((resp.status, resp.ctype.as_deref(), resp.body.as_slice()), (201, Some("a/b"), &b"body"[..]));
        assert_eq!(resp.headers, vec![("X-A".to_string(), "1".to_string())]);
        assert_eq!(resp.upstream.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), ["Server", "Content-Type", "X-A", "X-Accel-B"]);
    }

    #[test]
    fn intercepts_errors_of_proxied_servers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for s in listener.incoming() {
                let mut s = s.unwrap();
                let _ = s.read(&mut [0u8; 1024]).unwrap();
                s.write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: a\r\nX-A: 1\r\nWWW-Authenticate: b\r\n\r\nupstream").unwrap();
            }
        });
        let text = format!("http {{ server {{ error_page 401 /e; location /on {{ proxy_pass http://{addr}; proxy_intercept_errors on; }} \
                            location /off {{ proxy_pass http://{addr}; }} location /e {{ return 200 e; }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let answer = |target: &str| {
            let client = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut out = TcpStream::connect(client.local_addr().unwrap()).unwrap();
            let (mut stream, _) = client.accept().unwrap();
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            exchange(&mut stream, s, &r, Ok(()), location(s, &r.uri), "127.0.0.1:8080".parse().unwrap(), &[]);
            drop(stream);
            let mut text = String::new();
            out.read_to_string(&mut text).unwrap();
            text
        };
        let on = answer("/on");
        assert!(on.starts_with("HTTP/1.1 401 ") && on.ends_with("\r\n\r\ne"), "{on}");
        assert!(on.contains("WWW-Authenticate: a\r\nWWW-Authenticate: b\r\n") && !on.contains("X-A"), "{on}");
        let off = answer("/off");
        assert!(off.starts_with("HTTP/1.1 401 ") && off.contains("X-A: 1") && off.ends_with("upstream"), "{off}");
    }

    #[test]
    fn answers_certificate_errors() {
        let ssl = |verify: &str| Some(crate::tls::Session { verify: verify.to_string(), ..Default::default() });
        assert_eq!(cert_error(1, ssl("FAILED:certificate revoked").as_ref()), Err(495));
        assert_eq!(cert_error(3, ssl("FAILED:self-signed certificate").as_ref()), Ok(()));
        assert_eq!(cert_error(3, ssl("FAILED:certificate has expired").as_ref()), Err(495));
        assert_eq!(cert_error(1, ssl("NONE").as_ref()), Err(496));
        assert_eq!(cert_error(2, ssl("NONE").as_ref()), Ok(()));
        assert_eq!(cert_error(0, ssl("FAILED:certificate revoked").as_ref()), Ok(()));
        assert_eq!(cert_error(1, None), Ok(()));
        assert_eq!(special(495).status, 400);
        assert!(String::from_utf8(special(496).body).unwrap().contains("<center>No required SSL certificate was sent</center>"));
    }

    #[test]
    fn finds_misdirected_requests() {
        let ssl = |name: &str| Some(crate::tls::Session { server_name: name.to_string(), ..Default::default() });
        assert!(misdirected(ssl("a").as_ref(), Some("b"), 2));
        assert!(!misdirected(ssl("A").as_ref(), Some("a"), 2));
        assert!(!misdirected(ssl("a").as_ref(), Some("b"), 0));
        assert!(!misdirected(ssl("").as_ref(), Some("b"), 1));
        assert!(!misdirected(None, Some("b"), 1));
        assert!(!misdirected(ssl("a").as_ref(), None, 1));
        assert!(String::from_utf8(special(421).body).unwrap().contains("<title>421 Misdirected Request</title>"));
    }

    #[test]
    fn server_tokens() {
        let text = "http { server { location /a { return 404; } location /b { server_tokens off; return 404; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let get = |target: &str| {
            let client = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut out = TcpStream::connect(client.local_addr().unwrap()).unwrap();
            let (mut stream, _) = client.accept().unwrap();
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            exchange(&mut stream, s, &r, Ok(()), location(s, &r.uri), "127.0.0.1:8080".parse().unwrap(), &[]);
            drop(stream);
            let mut text = String::new();
            out.read_to_string(&mut text).unwrap();
            text
        };
        let a = get("/a");
        assert!(a.contains(&format!("Server: {NAME}\r\n")) && a.contains(&format!("<center>{NAME}</center>")), "{a}");
        let b = get("/b");
        assert!(b.contains("Server: twinx\r\n") && b.contains("<center>twinx</center>"), "{b}");
        let refused = crate::conf::build(&crate::config::parse("http { server_tokens x; }", std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap_err();
        assert_eq!(refused, "invalid value \"x\" in \"server_tokens\" directive, it must be \"on\", \"off\" or \"build\" in t:1");
    }

    #[test]
    fn error_pages_keep_the_status_and_location() {
        let text = "http { server { location /a { error_page 405 /n; return 405; } location /b { error_page 302 /t; return 302 x; } \
                    location /c { error_page 302 /r; return 302 x; } location /d { error_page 405 = /n; return 405; } \
                    location /n { return 204; } location /t { return 200 t; } location /r { return 302 y; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let get = |target: &str| {
            let client = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut out = TcpStream::connect(client.local_addr().unwrap()).unwrap();
            let (mut stream, _) = client.accept().unwrap();
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            exchange(&mut stream, s, &r, Ok(()), location(s, &r.uri), "127.0.0.1:8080".parse().unwrap(), &[]);
            drop(stream);
            let mut text = String::new();
            out.read_to_string(&mut text).unwrap();
            text
        };
        // The answer takes the error's status, unless it is a page of its own, or "=" is given.
        assert!(get("/a").starts_with("HTTP/1.1 405 "));
        assert!(get("/d").starts_with("HTTP/1.1 204 "));
        let b = get("/b");
        assert!(b.starts_with("HTTP/1.1 302 ") && b.contains("Location: x\r\n") && b.ends_with("\r\n\r\nt"), "{b}");
        let c = get("/c");
        assert!(c.contains("Location: y\r\n") && !c.contains("Location: x"), "{c}");
    }

    #[test]
    fn connects_from_the_bound_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let from = thread::spawn(move || {
            let (mut s, from) = listener.accept().unwrap();
            let _ = s.read(&mut [0u8; 1024]).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
            from
        });
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let socket = bound(&addr, ("127.0.0.2:0".parse().unwrap(), false));
        assert_eq!(fetch((&addr, None), socket, b"GET / HTTP/1.0\r\n\r\n", &level, -1, (&mut [None; 3], &mut [0; 3]), &|_| 0, None, 0, false).unwrap().status, 200);
        assert_eq!(from.join().unwrap().ip().to_string(), "127.0.0.2");
        let taken = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(bound(&addr, (taken, false)).is_some());
        assert!(bound(&addr, ("192.0.2.1:0".parse().unwrap(), false)).is_none());
    }

    #[test]
    fn reads_proxied_answers_at_the_rate() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.read(&mut [0u8; 1024]).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12000\r\nX-Rate: 4000\r\n\r\n").unwrap();
            s.write_all(&[b'x'; 12000]).unwrap();
        });
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(5), ..Level::default() };
        let rate = |resp: &Response| resp.upstream.iter().find(|h| h.0 == "X-Rate").map_or(0, |h| h.1.parse().unwrap());
        let mut resp = fetch((&addr, None), None, b"GET / HTTP/1.0\r\n\r\n", &level, -1, (&mut [None; 3], &mut [0; 3]), &rate, None, 0, false).unwrap();
        // The body is read after the head, 4000 bytes (what came with the head too)
        // in each second of the clock: it ends in the third second.
        assert!(resp.body.is_empty() && resp.rest.is_some());
        resp.upstream_time = Some(vec![[None; 3]]);
        let started = Instant::now();
        finish(&mut resp);
        assert!(started.elapsed() >= Duration::from_millis(900));
        assert_eq!((resp.body.len(), resp.rest.is_none()), (12000, true));
        assert!(resp.upstream_time.unwrap()[0][2].is_some());
    }

    #[test]
    fn unchunks_answers() {
        assert_eq!(unchunk(b"3\r\nabc\r\n2;x=y\nde\n0\r\n\r\n3\r\nzzz\r\n"), (b"abcde".to_vec(), true));
        assert_eq!(unchunk(b"3\r\nabc\r\n2\r\nd"), (b"abc".to_vec(), false));
        assert_eq!(unchunk(b"3\r\nabc"), (Vec::new(), false));
        assert_eq!(unchunk(b"3\r\nabcd\r\n"), (Vec::new(), true));
        assert_eq!(unchunk(b"x\r\n"), (Vec::new(), true));
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
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let resp = fetch((&addr, None), None, b"GET / HTTP/1.0\r\n\r\n", &level, -1, (&mut [None; 3], &mut [0; 3]), &|_| 0, None, 0, false).unwrap();
        assert_eq!((resp.body.as_slice(), resp.headers), (&b"ab"[..], vec![("Expires".to_string(), "a".to_string())]));
        for _ in 1..answers.len() {
            assert!(fetch((&addr, None), None, b"GET / HTTP/1.0\r\n\r\n", &level, -1, (&mut [None; 3], &mut [0; 3]), &|_| 0, None, 0, false).is_none());
        }
    }

    #[test]
    fn unsafe_uris() {
        assert_eq!(unsafe_uri("/a%20b?c=1"), Some(("/a b".into(), Some("c=1".into()))));
        assert_eq!(unsafe_uri("/a%3Fd?c"), Some(("/a".into(), Some("d".into()))));
        for u in ["", "?a", "..", "../a", "/a/..", "/a/../b", "/a/.%2e", "/a\0"] { assert_eq!(unsafe_uri(u), None, "{u}"); }
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
        let p = Proxy { host: "h".into(), ssl: false, upstream, uri: None, url: None, groups: Default::default(), implicit: Default::default() };
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let (_, r) = request("POST /a HTTP/1.0\n\n");
        let resp = proxy(&p, &level, &r, "");
        assert_eq!((resp.internal.as_deref(), resp.as_get, r.limit_rate.get()), (Some("/b?c=1"), true, Some(13000)));
        assert!(resp.upstream_time.unwrap()[0][2].unwrap() < 1000);
    }

    #[test]
    fn range_filter() {
        let file = || Response { status: 200, body: b"0123456789".to_vec(), ranges: true, headers: vec![
            ("Last-Modified".into(), "Sun, 06 Nov 1994 08:49:37 GMT".into()), ("ETag".into(), "\"e\"".into()), ("Accept-Ranges".into(), "bytes".into())], ..Response::default() };
        let ranged = |h: &str| { let mut resp = file(); range(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, &mut resp); resp };
        let part = |resp: Response| (resp.status, String::from_utf8_lossy(&resp.body).into_owned(), resp.headers.last().map(|h| h.1.clone()).unwrap_or_default());
        assert_eq!(part(ranged("Range: bytes=2-4")), (206, "234".into(), "bytes 2-4/10".into()));
        assert_eq!(part(ranged("Range: BYTES=7-")), (206, "789".into(), "bytes 7-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=-3")), (206, "789".into(), "bytes 7-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=8-20\nIf-Range: \"e\"")), (206, "89".into(), "bytes 8-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=0-0\nIf-Range: Sun, 06 Nov 1994 08:49:37 GMT")).0, 206);
        // Past the end, or backwards, is 416; a 206 has no Accept-Ranges.
        assert_eq!(part(ranged("Range: bytes=10-")).2, "bytes */10");
        assert_eq!(ranged("Range: bytes=5-3").status, 416);
        assert!(!ranged("Range: bytes=1-2").headers.iter().any(|h| h.0 == "Accept-Ranges"));
        // Not ranged: an If-Range that differs, an invalid or multiple range, no "bytes=".
        for h in ["Range: bytes=1-2\nIf-Range: \"x\"", "Range: bytes=1-2\nIf-Range: wrong", "Range: bytes=a-2", "Range: bytes=1-2,4-5", "Range: bytes=12", "Range: items=1-2", "X: y"] {
            assert_eq!(ranged(h).status, 200, "{h}");
        }
        let mut resp = Response { ranges: false, ..file() };
        range(&request("GET / HTTP/1.0\nRange: bytes=1-2\n\n").1, &mut resp);
        assert_eq!(resp.status, 200);
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
        let p = Proxy { host: "h".into(), ssl: false, upstream, uri: None, url: None, groups: Default::default(), implicit: Default::default() };
        let level = Level { proxy_hide_header: vec!["x-location".into(), "content-type".into()], proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        let (_, r) = request("GET / HTTP/1.0\n\n");
        let resp = proxy(&p, &level, &r, "/");
        assert_eq!(resp.upstream_addr, Some(addr.to_string()));
        assert_eq!((resp.ctype, resp.headers), (None, vec![("X-B".to_string(), "2".to_string())]));
    }

    #[test]
    fn urls_with_variables() {
        let (_, r) = request("GET /a?b HTTP/1.0\n\n");
        let group = Arc::new(Upstream::new(Vec::new()));
        let p = Proxy { host: String::new(), ssl: false, upstream: group.clone(), uri: None, url: None, groups: [("u".to_string(), group)].into(), implicit: Default::default() };
        assert_eq!(resolved("http://u/y", &p, &Level::default(), &r).map(|t| (t.0, t.1)), Some(("u".into(), "/y".into())));
        let (host, uri, up) = resolved("http://127.0.0.2:81/x", &p, &Level::default(), &r).unwrap();
        assert_eq!((host.as_str(), uri.as_str(), up.peers[0].addr.to_string()), ("127.0.0.2:81", "/x", "127.0.0.2:81".to_string()));
        assert_eq!(resolved("http://127.0.0.2", &p, &Level::default(), &r).map(|t| (t.0, t.1)), Some(("127.0.0.2".into(), "/a?b".into())));
        assert!(resolved("http://example.net/x", &p, &Level::default(), &r).is_none());
        let (_, _, up) = resolved("http://[::1]:82/x", &p, &Level::default(), &r).unwrap();
        assert_eq!(up.peers[0].addr.to_string(), "[::1]:82");
    }

    #[test]
    fn keeps_large_bodies_in_files() {
        let dir = std::env::temp_dir().join(format!("twinx-body-{}", std::process::id()));
        let level = Level { body_buffer: 4, body_temp_path: dir, ..Level::default() };
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        keep_body(&mut r, &level, b"abc".to_vec()).unwrap();
        assert_eq!((r.body.as_slice(), r.body_file.is_none()), (&b"abc"[..], true));
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        keep_body(&mut r, &level, b"abcde".to_vec()).unwrap();
        assert_eq!(std::fs::read(r.body_file.unwrap()).unwrap(), b"abcde");
        // A file that cannot be written (its directory is a file) is 500.
        let level = Level { body_buffer: 4, body_temp_path: std::env::current_exe().unwrap(), ..Level::default() };
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        assert_eq!(keep_body(&mut r, &level, b"abcde".to_vec()), Err(500));
    }

    #[test]
    fn temp_files_under_levels() {
        let dir = std::path::Path::new("/t");
        assert_eq!(temp_file(dir, &[], 2), PathBuf::from("/t/0000000002"));
        assert_eq!(temp_file(dir, &[1, 2], 1234), PathBuf::from("/t/4/23/0000001234"));
    }

    #[test]
    fn chunk_sizes() {
        assert_eq!((chunk_size("a"), chunk_size("00"), chunk_size("5;x=1"), chunk_size("5 ")), (Some(10), Some(0), Some(5), Some(5)));
        assert_eq!((chunk_size("7fffffffffffffff"), chunk_size("8000000000000000")), (Some(i64::MAX as u64), None));
        assert_eq!((chunk_size("+5"), chunk_size(" 5"), chunk_size(""), chunk_size("5x")), (None, None, None, None));
    }

    #[test]
    fn content_length_digits_only() {
        let length = |v: &str| framing(&request(&format!("POST / HTTP/1.0\nContent-Length: {v}\n\n")).1);
        assert_eq!(length("9223372036854775807"), Ok(Some(i64::MAX as u64)));
        assert_eq!((length("+0"), length("9223372036854775808"), length("")), (Err(400), Err(400), Err(400)));
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
    fn regex_locations_set_their_captures() {
        let dir = std::env::temp_dir().join(format!("twinx-captures-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/f.txt"), "F").unwrap();
        let text = format!("http {{ server {{ location ~ ^/c/(\\w+)$ {{ return 200 $1; }} location ~ ^/a/(.+)$ {{ alias {}/sub/$1; }} }} }}", dir.display());
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &dir).unwrap();
        let s = &config.servers[0];
        let body = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            String::from_utf8(answer(s, &r, Ok(()), located(s, &r, &r.uri)).0.body).unwrap()
        };
        assert_eq!(body("/c/xyz"), "xyz");
        assert_eq!(body("/a/f.txt"), "F");
    }

    #[test]
    fn limit_except_and_proxy_pass_in_if() {
        let text = "http { server { location /lg { limit_except GET { proxy_pass http://127.0.0.1:1; } } \
                    location /i { set $t 1; if ($t) { proxy_pass http://127.0.0.1:1; } if ($t) { } } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let status = |line: &str| {
            let (_, r) = request(&format!("{line} HTTP/1.0\n\n"));
            let found = located(s, &r, &r.uri);
            (answer(s, &r, Ok(()), found).0.status, found.1.proxy.is_some())
        };
        // GET allows HEAD too.
        assert_eq!(status("HEAD /lg"), (404, false));
        assert_eq!(status("PUT /lg").1, true);
        // The last if has no proxy_pass to inherit, after one that had.
        assert_eq!(status("GET /i"), (500, false));
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
        // The URL is unescaped as far as its first "?", the arguments are not.
        assert_eq!(answer("/a?x=%2Fa%0D%3Fb%3D?c%3D"), (302, "http://e//a%0D?b%3D?c%3D?x=%2Fa%0D%3Fb%3D?c%3D".to_string()));
        assert_eq!(unescape_redirect("/%zz/%4z/%41%3d?%41"), "/zz//A=?%41");
        assert_eq!(unescape_redirect("/%4"), "/");
    }

    #[test]
    fn rewrites_to_uris() {
        let text = "http { server { location /a { rewrite ^/a(.*) /b$1?c=$1; rewrite ^/b /c; return 200 $uri:$args; } \
                    location /l { rewrite ^ /n last; return 403; } location /n { return 200 n$uri; } \
                    location /k { break; return 403; } location /r { rewrite ^/r(.*) http://e$1?$1 redirect; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let get = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let resp = answer(s, &r, Ok(()), location(s, &r.uri)).0;
            (resp.status, String::from_utf8(resp.body).unwrap(), resp.headers.first().map(|h| h.1.clone()))
        };
        // Without a flag the next rewrite and return see the new URI; a capture in the
        // arguments is escaped when the request's URI had "%".
        assert_eq!(get("/a/%25?x=1").1, "/c:c=/%25&x=1");
        assert_eq!(get("/a/x").1, "/c:c=/x");
        // "last" looks for the location of the new URI; break stops before return.
        assert_eq!(get("/l?x=1").1, "n/n");
        assert_eq!(get("/k").0, 404);
        // In a redirect, the URL is unescaped again as far as its "?".
        assert_eq!(get("/r/a+b").2.unwrap(), "http://e/a+b?/a%2Bb");
        assert_eq!(escape_args("a b#%&+;?\x7f"), "a%20b%23%25%26%2B%3B%3F%7F");
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
            String::from_utf8(super::answer(s, &r, Ok(()), location(s, &r.uri)).0.body).unwrap()
        };
        assert_eq!(rate("/a?l=40k"), "40960");
        assert_eq!(rate("/a?l=2M"), "2097152");
        // A value that is not a size keeps what the server level set.
        assert_eq!(rate("/a?l=x"), "1024");
        assert_eq!(rate("/a"), "1024");
    }

    #[test]
    fn set_and_if() {
        let text = "http { server { set $s srv; if ($s) { set $t x; } location / { if ($arg_a) { set $v \"[$arg_a]\"; add_header X-If $s; } set $w $v$t; return 200 $v$w; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let answer = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let (resp, level, _) = answer(s, &r, Ok(()), location(s, &r.uri));
            (String::from_utf8(resp.body).unwrap(), level.add_header.len())
        };
        assert_eq!(answer("/?a=1"), ("[1][1]x".to_string(), 1));
        // "0" and "" are false.
        assert_eq!(answer("/?a=0"), ("x".to_string(), 0));
        assert_eq!(answer("/"), ("x".to_string(), 0));
        // return in an if of the server answers at once.
        let text = "http { server { if ($arg_r) { return 200 r; } location / { return 200 l; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let body = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            String::from_utf8(super::answer(s, &r, Ok(()), location(s, &r.uri)).0.body).unwrap()
        };
        assert_eq!((body("/?r=1"), body("/")), ("r".to_string(), "l".to_string()));
        let refused = |text: &str| crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap_err();
        assert_eq!(refused("http { server { set $uri x; } }"), "the duplicate \"uri\" variable in t:1");
        assert_eq!(refused("http { server { if $a { } } }"), "invalid condition \"$a\" in t:1");
        assert_eq!(refused("http { server { if ($arg_a <> b) { } } }"), "invalid condition \"($arg_a\" in t:1");
        assert_eq!(refused("http { server { if ($arg_a ~ a( ) { } } }").split(':').next().unwrap(), "invalid regular expression \"a(\"");
        assert_eq!(refused("http { server { location / { if ($arg_a) { listen 80; } } } }"), "\"listen\" directive is not allowed here in t:1");
    }

    #[test]
    fn if_conditions() {
        let dir = std::env::temp_dir().join(format!("twinx-if-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("d")).unwrap();
        std::fs::write(dir.join("f"), "").unwrap();
        let text = format!("http {{ server {{ location /eq {{ if ( $arg_c != 1 ) {{ return 204; }} }} \
                            location /re {{ if ($arg_c ~* ^F(o+)) {{ return 200 $1; }} }} \
                            location /f {{ if (!-f {d}/$arg_c) {{ return 204; }} }} location /x {{ if (-x {d}/$arg_c) {{ return 204; }} }} \
                            location /e {{ if (-e {d}/$arg_c) {{ return 204; }} }} location /d {{ if (-d {d}/$arg_c) {{ return 204; }} }} }} }}", d = dir.display());
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let get = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            let resp = answer(s, &r, Ok(()), location(s, &r.uri)).0;
            (resp.status, String::from_utf8(resp.body).unwrap())
        };
        assert_eq!((get("/eq?c=2").0, get("/eq?c=1").0), (204, 404));
        assert_eq!(get("/re?c=fOOd"), (200, "OO".to_string()));
        assert_eq!(get("/re?c=bar").0, 404);
        assert_eq!((get("/f?c=d").0, get("/f?c=f").0), (204, 404));
        assert_eq!((get("/x?c=d").0, get("/x?c=f").0), (204, 404));
        assert_eq!((get("/e?c=f").0, get("/e?c=n").0), (204, 404));
        assert_eq!((get("/d?c=d").0, get("/d?c=f").0), (204, 404));
    }

    #[test]
    fn rewrites_cookies() {
        let text = "http { server { proxy_cookie_domain .a.org b.org; proxy_cookie_domain ~^(.+)\\.com$ $1.net; proxy_cookie_path /p/ /$server_name/; proxy_cookie_path ~*^/R/(.*) /$1; \
                    location /off/ { proxy_cookie_domain off; proxy_cookie_path off; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let (on, off) = (&config.servers[0].level, &config.servers[0].locations[0].level);
        let (_, r) = request("GET / HTTP/1.0\n\n");
        let rw = |cookie: &str, level: &Level| rewrite_cookie(&r, cookie, level);
        assert_eq!(rw("v=1;domain=.A.org", on).as_deref(), Some("v=1; domain=.b.org"));
        assert_eq!(rw("v=1; Domain = x.COM ;Secure", on).as_deref(), Some("v=1; Domain=x.net; Secure"));
        assert_eq!(rw("v=1; Path=/p/x; Domain=c.org", on).as_deref(), Some("v=1; Path=/localhost/x; Domain=c.org"));
        assert_eq!(rw("v=1; Path=/r/x", on).as_deref(), Some("v=1; Path=/x"));
        // Nothing matches, the cookie has no value, or the rewrites are off: as it was.
        assert_eq!(rw("v=1; Path=/q/; Domain=c.org; Max-Age=1", on), None);
        assert_eq!(rw("v; Path=/p/", on), None);
        assert_eq!(rw("v=1; Path=/p/", off), None);
        let refused = |text: &str| crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap_err();
        assert_eq!(refused("http { proxy_cookie_path off; proxy_cookie_path /a /b; }"), "\"proxy_cookie_path\" directive is duplicate in t:1");
        assert_eq!(refused("http { proxy_cookie_path on; }"), "invalid parameter \"on\" in t:1");
    }

    #[test]
    fn sets_the_body_sent_to_proxied_servers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let got = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.0 204 No Content\r\n\r\n").unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let upstream = Arc::new(crate::upstream::Upstream::new(vec![crate::upstream::Peer::new(addr)]));
        let p = Proxy { host: "h".into(), ssl: false, upstream, uri: None, url: None, groups: Default::default(), implicit: Default::default() };
        let set = Some(Template::parse("b=$arg_a").unwrap());
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), proxy_set_body: set, ..Level::default() };
        let (_, mut r) = request("POST /a?a=1 HTTP/1.0\nContent-Length: 3\n\n");
        r.body = b"xyz".to_vec();
        assert_eq!(proxy(&p, &level, &r, "").status, 204);
        let sent = got.join().unwrap();
        assert!(sent.contains("Content-Length: 3\r\n") && sent.ends_with("\r\n\r\nb=1"), "{sent}");
    }

    #[test]
    fn passes_bodies_as_they_come() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut out = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut client, _) = listener.accept().unwrap();
        let unread = |client: &TcpStream, left: u64, chunked: Option<&[u8]>| Unread { client: client.try_clone().unwrap(), left, chunked: chunked.map(|c| (c.to_vec(), 1)), rest: Vec::new() };
        out.write_all(b"abcdef").unwrap();
        let (mut to, mut u) = (Vec::new(), unread(&client, 4, None));
        assert_eq!(pass_body(&mut u, 100, &mut to), Some(4));
        assert_eq!((to.as_slice(), u.left), (&b"abcd"[..], 0));
        // A chunked body: the data that came after the one passed, in one chunk
        // for each read, then the last chunk; what follows it is kept.
        let (mut to, mut u) = (Vec::new(), unread(&client, 0, Some(b"3\r\nx")));
        out.write_all(b"\r\n4\r\nmany\r\n0\r\n\r\nGET").unwrap();
        assert_eq!(pass_body(&mut u, 100, &mut to), Some(16));
        assert_eq!((String::from_utf8_lossy(&to), u.rest.as_slice()), ("6\r\nefmany\r\n0\r\n\r\n".into(), &b"GET"[..]));
        // An invalid chunk, or the client closing before the end, fails it.
        assert_eq!(pass_body(&mut unread(&client, 0, Some(b"z\r\n")), 100, &mut to), None);
        drop(out);
        let mut u = unread(&client, 5, None);
        assert_eq!(pass_body(&mut u, 100, &mut to), None);
        assert_eq!(u.left, 5);
    }

    #[test]
    fn decodes_chunks_that_have_come() {
        assert_eq!(decode_chunked(b"3\r\nabc\r\n2\r\nde", 100), Ok((b"abcde".to_vec(), None)));
        assert_eq!(decode_chunked(b"3\r\nabc\r\n0\r\n\r\nX", 100), Ok((b"abc".to_vec(), Some(13))));
        assert_eq!(decode_chunked(b"3\r\nabc\r\n0\r\n", 100), Ok((b"abc".to_vec(), None)));
        assert_eq!(decode_chunked(b"3\r\nabc\r\n", 2), Err(413));
    }

    #[test]
    fn rewrites_redirects() {
        let text = "http { server { location /d/ { proxy_pass http://127.0.0.1:1/u/; } location /n/ { proxy_pass http://127.0.0.1:1; \
                    proxy_redirect http://a/$server_name/ /x/; proxy_redirect ~*^(.+)/RE/ $1/y/; location /n/i/ { proxy_pass http://127.0.0.1:2; } } \
                    location /o/ { proxy_pass http://127.0.0.1:1; proxy_redirect off; location /o/i/ { } } location /p/ { proxy_pass http://127.0.0.1:1; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let level = |i: usize| &config.servers[0].locations[i].level;
        let (_, r) = request("GET / HTTP/1.0\n\n");
        let rw = |i: usize, name: &str, value: &str| {
            let mut headers = vec![(name.to_string(), value.to_string())];
            (rewrite_redirect(&r, level(i), &mut headers), headers.remove(0).1)
        };
        // The implicit default: the URL with its URI becomes the location's name, one without it "/".
        assert_eq!(rw(0, "Location", "http://127.0.0.1:1/u/a"), (true, "/d/a".into()));
        assert_eq!(rw(5, "location", "http://127.0.0.1:1/a"), (true, "/a".into()));
        // The first rule that matches, which may have variables or be a regular expression replacing all.
        assert_eq!(rw(1, "Location", "http://a/localhost/b"), (true, "/x/b".into()));
        assert_eq!(rw(1, "Location", "http://b/re/c"), (true, "http://b/y/".into()));
        assert_eq!(rw(1, "Refresh", "7; URL=http://a/localhost/b"), (false, "7; URL=/x/b".into()));
        // A nested location inherits the rules; nothing matching, off, or a Refresh without a URL leaves it.
        assert_eq!(rw(2, "Location", "http://a/localhost/"), (true, "/x/".into()));
        assert_eq!(rw(1, "Location", "/c"), (false, "/c".into()));
        assert_eq!(rw(1, "Refresh", "7"), (false, "7".into()));
        assert_eq!(rw(3, "Location", "http://127.0.0.1:1/a"), (false, "http://127.0.0.1:1/a".into()));
        assert_eq!(level(4).proxy_redirect.as_ref().map(Vec::len), None);
        let refused = |text: &str| crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap_err();
        assert_eq!(refused("http { server { location / { proxy_redirect default; } } }"), "\"proxy_redirect default\" should be placed after the \"proxy_pass\" directive in t:1");
        assert_eq!(refused("http { server { location / { proxy_pass http://$host; proxy_redirect default; } } }"), "\"proxy_redirect default\" cannot be used with \"proxy_pass\" directive with variables in t:1");
        assert_eq!(refused("http { proxy_redirect off; proxy_redirect /a /b; }"), "\"proxy_redirect\" directive is duplicate in t:1");
        assert_eq!(refused("http { proxy_redirect on; }"), "invalid parameter \"on\" in t:1");
    }

    #[test]
    fn sets_cookie_flags() {
        let text = "http { server { proxy_cookie_flags a secure SameSite=Lax samesite=strict; proxy_cookie_flags ~^B nosecure nosamesite $arg_f; \
                    proxy_cookie_flags c; location /off/ { proxy_cookie_flags off; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let (on, off) = (&config.servers[0].level, &config.servers[0].locations[0].level);
        let (_, r) = request("GET /?f=httponly HTTP/1.0\n\n");
        let rw = |cookie: &str, level: &Level| rewrite_cookie(&r, cookie, level);
        assert_eq!(rw("A=1;HttpOnly;samesite", on).as_deref(), Some("A=1; HttpOnly; samesite=Strict; Secure"));
        assert_eq!(rw("bb=1; Secure; HttpOnly; SameSite=None", on).as_deref(), Some("bb=1; HttpOnly"));
        assert_eq!(rw("bb=1", on).as_deref(), Some("bb=1; HttpOnly"));
        // A rule without flags, no rule, or off: as it was.
        assert_eq!(rw("c=1;Secure", on), None);
        assert_eq!(rw("d=1;Secure", on), None);
        assert_eq!(rw("a=1", off), None);
        let refused = |text: &str| crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap_err();
        assert_eq!(refused("http { proxy_cookie_flags a secure; proxy_cookie_flags off; }"), "\"proxy_cookie_flags\" directive is duplicate in t:1");
        assert_eq!(refused("http { proxy_cookie_flags off; proxy_cookie_flags a secure; }"), "\"proxy_cookie_flags\" directive is duplicate in t:1");
        assert_eq!(refused("http { proxy_cookie_flags a sure; }"), "invalid parameter \"sure\" in t:1");
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
