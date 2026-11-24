//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::body::{Body, Buffers, Came, Sizes};
use crate::coding::Coder;
use crate::conf::{Condition, Config, CookieFlags, CookiePattern, CookieRewrite, Fallback, Flag, Level, Match, Op, Proxy, Rewrite, Server, ServerName, Step, TryFiles};
use crate::vars::{Part, Template};
use crate::expires;
use crate::upstream::{Conn, Peer, Upstream};
use crate::vars::{Request, Sent};
use crate::spool::{Spool, temp_path};
use crate::stream::{Stream, Writing, at_once, buffer, read_into, read_ready, read_until, recycle, unless_closed, within, write_all};

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

/// Opens the listening sockets: the master does this, so that bind errors stop it and every worker shares them.
pub fn bind(config: &Config, open: &[(TcpListener, SocketAddr)]) -> Result<Vec<(TcpListener, SocketAddr)>, String> {
    let mut addrs: Vec<SocketAddr> = Vec::new();
    for addr in config.servers.iter().flat_map(|s| &s.listen) { if !addrs.contains(addr) { addrs.push(*addr) } }
    // On a reload, a socket already open on the address is kept.
    let backlog = |addr| config.servers.iter().flat_map(|s| &s.backlogs).find(|b| b.0 == addr).map_or(crate::conf::LISTEN_BACKLOG, |b| b.1);
    let get = |addr| open.iter().find(|o| o.1 == addr).map_or_else(|| listen(addr, backlog(addr)), |o| o.0.try_clone());
    addrs.into_iter().map(|addr| get(addr).map(|l| (l, addr)).map_err(|e| format!("bind() to {addr} failed ({e})"))).collect()
}

/// A listening socket as nginx opens it: SO_REUSEADDR, then listen() with the
/// backlog of "listen" (511 unless it sets one; the standard library's is 128).
fn listen(addr: SocketAddr, backlog: i32) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    Ok(socket.into())
}

/// Whether the worker is shutting down gracefully, and how many requests it is answering.
static SHUTTING: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicUsize = AtomicUsize::new(0);
/// Wakes the connections that wait when the worker starts shutting down.
pub(crate) static SHUTDOWN: tokio::sync::Notify = tokio::sync::Notify::const_new();
/// Whether worker_shutdown_timeout has passed, and what wakes the requests then waiting.
static HALTED: AtomicBool = AtomicBool::new(false);
static HALT: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Ends once worker_shutdown_timeout has passed while the worker shuts down.
async fn halted() {
    loop {
        let halt = HALT.notified();
        if HALTED.load(Ordering::SeqCst) { return }
        halt.await;
    }
}

/// Whether the worker is shutting down gracefully.
pub(crate) fn shutting() -> bool {
    SHUTTING.load(Ordering::SeqCst)
}

/// A request being answered, counted in BUSY while it lives.
pub(crate) struct Busy;

impl Busy {
    pub(crate) fn new() -> Busy {
        BUSY.fetch_add(1, Ordering::SeqCst);
        Busy
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Shuts the worker down gracefully, as QUIT does: it stops the tasks that
/// accept, closes each connection once its request is answered, and returns
/// when no request is left, or once worker_shutdown_timeout has passed. Those
/// kept to proxied servers are closed first, idle ones of clients when the
/// worker exits. A connection accepted before the tasks stopped is counted
/// from its accept on, so its request is answered, not dropped.
pub async fn shut_down(accepting: Vec<JoinHandle<()>>, timeout: Option<Duration>) {
    let start = Instant::now();
    SHUTTING.store(true, Ordering::SeqCst);
    SHUTDOWN.notify_waiters();
    crate::upstream::close_idle();
    accepting.iter().for_each(JoinHandle::abort);
    for task in accepting { let _ = task.await; }
    while BUSY.load(Ordering::SeqCst) > 0 && timeout.is_none_or(|t| start.elapsed() < t) { tokio::time::sleep(Duration::from_millis(10)).await; }
    // Once the timeout has passed, as nginx closes their connections, the requests waiting
    // for proxied servers end as their clients had closed them (499), and are logged so.
    if BUSY.load(Ordering::SeqCst) == 0 { return }
    HALTED.store(true, Ordering::SeqCst);
    HALT.notify_waiters();
    for _ in 0..100 { if BUSY.load(Ordering::SeqCst) == 0 { break } tokio::task::yield_now().await; }
}

thread_local! {
    /// The number of the last connection of the worker.
    static NUMBER: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The number of a new connection, accepted or to a proxied server, in error logs.
fn number() -> u64 {
    NUMBER.set(NUMBER.get() + 1);
    NUMBER.get()
}

/// Accepts connections on the listening sockets, in a worker process: a task
/// of the worker's event loop accepts on each socket, and each connection is
/// served by a task of its own. Gives the tasks that accept, for shut_down.
pub fn accept(config: Arc<Config>, listeners: &[(TcpListener, SocketAddr)]) -> Result<Vec<JoinHandle<()>>, String> {
    let mut tasks = Vec::new();
    for (listener, addr) in listeners {
        // The socket keeps the options it was opened with; the event loop needs it non-blocking.
        let listener = listener.try_clone().and_then(|l| l.set_nonblocking(true).and_then(|()| tokio::net::TcpListener::from_std(l))).map_err(|e| e.to_string())?;
        let (addr, config) = (*addr, config.clone());
        // An address any server listens on with "ssl" takes TLS connections.
        let tls = config.servers.iter().any(|s| s.ssl.contains(&addr));
        tasks.push(tokio::task::spawn_local(async move {
            loop {
                // Out of descriptors, say: accept() is tried again a little later.
                let Ok((stream, peer)) = listener.accept().await else { tokio::time::sleep(Duration::from_millis(10)).await; continue };
                // Until its first request has arrived, a new connection is busy too.
                let (config, fresh) = (config.clone(), Busy::new());
                // As in nginx, only a socket that listens on every address is asked which one it is.
                let local = if addr.ip().is_unspecified() { stream.local_addr().unwrap_or(addr) } else { addr };
                tokio::task::spawn_local(Box::pin(serving(config, stream, tls, (addr, local, (peer, number())), fresh)));
            }
        }));
    }
    Ok(tasks)
}

/// What the task of a connection runs. It is copied when it is made, spawned
/// and done, so it is kept small: what few connections use is boxed where it
/// is awaited.
fn serving(config: Arc<Config>, stream: TcpStream, tls: bool, (addr, local, peer): (SocketAddr, SocketAddr, (SocketAddr, u64)), fresh: Busy) -> impl Future<Output = ()> {
    async move {
        // As nginx does, a connection to an address that takes TLS but does not start with it is served as plain HTTP.
        let Some(plain) = (if tls { Box::pin(crate::tls::plain(&stream)).await } else { Some(true) }) else { return };
        let accepted = if !plain { Box::pin(crate::tls::accept(stream, &config, addr)).await.map(|(s, ssl)| (s, Some(Arc::new(ssl)))) } else { Some((Stream::Tcp(stream), None)) };
        let Some((stream, ssl)) = accepted else { return };
        connection(&config, stream, (addr, local, peer, ssl), fresh, None).await
    }
}

/// The end of the request head (after the empty line), if it has arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    let at = line_end(buf)?;
    if http09(&buf[..at]) { return Some(at) }
    lines_end(buf, at)
}

/// The end of the head whose first line ends at so many bytes, after the empty
/// line: that of a proxied server's answer, whose status line has no reason at times.
fn lines_end(buf: &[u8], mut at: usize) -> Option<usize> {
    loop {
        match buf[at..] {
            [b'\n', ..] => return Some(at + 1),
            [b'\r', b'\n', ..] => return Some(at + 2),
            _ => at += line_end(&buf[at..])?,
        }
    }
}

/// Where the first line of the buffer ends, after its LF, if that has come.
fn line_end(buf: &[u8]) -> Option<usize> {
    // SAFETY: memchr() reads the buffer's length from its start, and gives a
    // place in it or null.
    let lf = unsafe { libc::memchr(buf.as_ptr().cast(), b'\n'.into(), buf.len()) };
    (!lf.is_null()).then(|| lf as usize - buf.as_ptr() as usize + 1)
}

/// Whether a request line is of HTTP/0.9: a method and a URI, without a
/// version. Such a request has no headers, and its answer is the body alone.
fn http09(line: &[u8]) -> bool {
    line.split(u8::is_ascii_whitespace).filter(|w| !w.is_empty()).take(3).count() == 2
}

/// How the body of a stream of HTTP/2 is read, as nginx decides once the
/// stream's location is found: into buffers, with its window then opened as
/// wide as it goes; passed on as it comes (proxy_request_buffering off); or
/// discarded, by a location whose content handler does not read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reading { Buffered, Unbuffered, Discarded }

/// What a stream of an HTTP/2 connection comes with: when that connection was
/// made, the number of its request, how many of its header lines were made
/// from its pseudo-header and cookie fields, which max_headers does not count,
/// as nginx counts only the others; the length of its header block, which is
/// that of its head for $request_length; and what to tell how its body is read.
pub(crate) struct Origin {
    pub connected: Instant,
    pub number: u64,
    pub made: usize,
    pub length: usize,
    pub reading: Option<Box<dyn FnOnce(Reading)>>,
}

/// Serves the requests of a connection accepted on a listening address,
/// with its local and remote addresses and its number, or a stream of an HTTP/2 connection.
pub(crate) async fn connection(config: &Arc<Config>, mut stream: Stream, (listen, local, peer, ssl): crate::h2::Addrs, fresh: Busy, mut origin: Option<Box<Origin>>) {
    let mut fresh = Some(fresh);
    let mut buf = Vec::new();
    // After a kept-alive answer: how long the connection waits for the next request.
    let ((connected, mut requests), mut idle) = (origin.as_ref().map_or((Instant::now(), 0), |o| (o.connected, o.number - 1)), None);
    // Whether any of its requests was pipelined, as nginx's c->pipeline stays set.
    let mut piped = false;
    // A plain connection to an address that takes TLS has its requests answered with 497.
    let to_https = ssl.is_none() && !matches!(stream, Stream::Pipe(_)) && config.servers.iter().any(|s| s.ssl.contains(&listen));
    // A TLS connection whose client and server agreed on h2 (ALPN) speaks HTTP/2.
    if ssl.as_ref().is_some_and(|s| s.alpn == "h2") && !matches!(stream, Stream::Pipe(_)) {
        return Box::pin(crate::h2::serve(config.clone(), stream, buf, (listen, local, peer, ssl), fresh.take())).await;
    }
    loop {
        // As in nginx, the clock of a request starts when its first bytes have come,
        // and that of a pipelined one when the request before it is done.
        let pipelined = !buf.is_empty();
        let mut started = if pipelined { Instant::now() } else { connected };
        piped |= pipelined;
        requests += 1;
        // Header lines are read with the settings of the default server of the address.
        let default = config.servers.iter().find(|s| s.listen.contains(&listen)).unwrap_or(&config.servers[0]);
        let buffers = |host: Option<&str>| server(config, listen, host).0.level.large_header_buffers;
        // A head that overflows its buffers is answered with what of it came whole.
        let (end, overflowed) = loop {
            let end = head_end(&buf);
            if let Some((status, at)) = overflow(&buf[..end.unwrap_or(buf.len())], default.level.header_buffer, buffers) { break (at, Some(status)); }
            if let Some(end) = end { break (end, None); }
            // Waiting for a next request, the time left counts from the end of the last one.
            let first = buf.is_empty();
            let wait = idle.filter(|_| first);
            if read_until(&mut stream, &mut buf, || wait.and_then(|t| crate::clock::coarse().checked_add(t))).await == 0 { return; }
            if first { started = Instant::now(); }
        };
        // With http2 on in the default server of the address, a connection
        // that starts with the preface of HTTP/2 speaks it, as nginx decides.
        if requests == 1 && ssl.is_none() && !to_https && http2(config, listen, default) && buf.starts_with(b"PRI * HTTP/2.0\r\n") && !matches!(stream, Stream::Pipe(_)) {
            return Box::pin(crate::h2::serve(config.clone(), stream, buf, (listen, local, peer, None), fresh.take())).await;
        }
        let mut r = Request {
            method: String::new(),
            uri: String::new(),
            target: String::new(),
            line: String::new(),
            headers: Vec::new(),
            host: None,
            server_name: String::new(),
            peer: peer.0,
            local,
            started,
            pipelined,
            connected,
            requests,
            length: origin.as_ref().map_or(end, |o| o.length),
            body: Vec::new(),
            body_file: None,
            upstream_addr: None,
            upstream_status: None,
            upstream: Vec::new(),
            captures: Vec::new(),
            shared: Arc::new(crate::vars::Shared { number: peer.1, ..Default::default() }),
            ssl: ssl.clone(),
        };
        let parsed = parse(&mut r, &buf[..end], &default.level, matches!(stream, Stream::Pipe(_)));
        buf.drain(..end);
        let parsed = overflowed.map_or(parsed, Err);
        let (server, captures) = server(config, listen, r.host.as_deref());
        r.captures = captures;
        let parsed = parsed.and_then(|()| if r.headers.len().saturating_sub(origin.as_ref().map_or(0, |o| o.made)) > server.level.max_headers { Err(400) } else { Ok(()) });
        let parsed = parsed.and_then(|()| if to_https { Err(497) } else { Ok(()) });
        let parsed = parsed.and_then(|()| if misdirected(r.ssl.as_deref(), r.host.as_deref(), server.level.ssl_verify_client) { Err(421) } else { Ok(()) });
        // A stream of HTTP/2 asking for a server that does not speak it is misdirected too.
        let parsed = parsed.and_then(|()| if matches!(stream, Stream::Pipe(_)) && !http2(config, listen, server) { Err(421) } else { Ok(()) });
        let parsed = parsed.and_then(|()| cert_error(server.level.ssl_verify_client, r.ssl.as_deref()));
        r.server_name = server.name.clone();
        let found = located(server, &r, &r.uri);
        let level = found.1;
        let framing = parsed.and_then(|()| framing(&r)).and_then(|n| if n.unwrap_or(0) > level.max_body { Err(413) } else { Ok(n) });
        let expect = header(&r, "expect").is_some_and(|e| e.eq_ignore_ascii_case("100-continue"));
        if framing.is_ok() && expect && r.line.ends_with("HTTP/1.1") { write_all(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n", send_timeout(level)).await; }
        let reading = if !reads_body(level) { Reading::Discarded } else if level.proxy.is_some() && !level.proxy_request_buffering { Reading::Unbuffered } else { Reading::Buffered };
        if framing.is_ok() { if let Some(tell) = origin.as_mut().and_then(|o| o.reading.take()) { tell(reading); } }
        // A stream of HTTP/2 whose body is discarded is answered without waiting for it.
        let discarded = origin.is_some() && reading == Reading::Discarded;
        let parsed = match framing {
            Ok(_) if discarded => Ok(()),
            Err(status) => Err(status),
            // With proxy_request_buffering off, what came with the head is passed
            // with the request, and the rest of the body as it comes.
            Ok(Some(n)) if level.proxy.is_some() && !level.proxy_request_buffering && (buf.len() as u64) < n => {
                r.length += n as usize;
                r.body = std::mem::take(&mut buf);
                *r.shared.unread.lock().unwrap() = Some(Unread { left: n - r.body.len() as u64, chunked: None, rest: Vec::new() });
                Ok(())
            }
            // A chunked body only when passed as HTTP/1.1, its data passed in chunks of what has come.
            Ok(None) if level.proxy.is_some() && !level.proxy_request_buffering && level.proxy_http_11 && matches!(dechunk(&buf, level.max_body), Ok(None)) => {
                r.body = decode_chunked(&buf, level.max_body).unwrap_or_default().0;
                *r.shared.unread.lock().unwrap() = Some(Unread { left: 0, chunked: Some((std::mem::take(&mut buf), r.body.len())), rest: Vec::new() });
                Ok(())
            }
            Ok(length) => loop {
                match take_body(&buf, length, level.max_body) {
                    Ok(None) => {}
                    Ok(Some((body, used))) => {
                        r.length += used;
                        buf.drain(..used);
                        // A body that would be passed as it comes but came whole with the
                        // head stays in memory, client_body_in_file_only or not, as nginx's
                        // request_body_no_buffering keeps it out of a file.
                        if !body.is_empty() && unbuffered(level, length.is_none()) { r.body = body; break Ok(()); }
                        break keep_body(&mut r, level, body);
                    }
                    Err(status) => break Err(status),
                }
                if read_into(&mut stream, &mut buf, None).await == 0 { return; }
            },
        };
        let busy = Busy::new();
        drop(fresh.take());
        idle = exchange(&mut stream, server, &r, parsed, found, local, &buf).await;
        drop(busy);
        // What of an unbuffered body was not passed on is read and dropped.
        // What came after a chunked one is the next request.
        let unread = r.shared.unread.lock().unwrap().take();
        let unbuffered = unread.is_some();
        if let Some(mut u) = unread {
            if pass_body(&mut u, &mut stream, level.max_body, &mut tokio::io::sink()).await.is_none() { return; }
            buf = u.rest;
        }
        if !level.body_in_file_only || level.body_clean { r.body_file.map(std::fs::remove_file); }
        // A stream of HTTP/2 has one request: the rest of the pipe is its body.
        if idle.is_none() || SHUTTING.load(Ordering::SeqCst) || matches!(stream, Stream::Pipe(_)) {
            // As ngx_http_finalize_connection() decides, but with the location
            // first found, not the one an internal redirect ended in.
            let lingers = match level.lingering_close {
                // Closing with something unread resets the connection, which can
                // destroy the answer before the client reads it.
                Some(false) => !discarded && (parsed.is_err() || unbuffered || piped || !buf.is_empty() || stream.waiting()),
                always => always.is_some(),
            };
            return close(&mut stream, lingers).await;
        }
        // An idle connection keeps no buffer.
        if buf.is_empty() { recycle(std::mem::take(&mut buf)); }
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
    // Most heads fit in the first buffer, whatever lines they have.
    if head.len() < first { return None }
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
    // A stream of HTTP/2 without a length passes its body in chunks too.
    if te.len() > 1 || length.is_some() || !(r.line.ends_with("HTTP/1.1") || r.line.ends_with("HTTP/2.0")) { return Err(400); }
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

/// Ends the connection, which is closed when it is dropped, after a close_notify
/// with TLS. With lingers, as nginx's lingering close does: stops sending, then
/// reads what the client still sends so that it gets the whole answer.
pub(crate) async fn close(stream: &mut Stream, lingers: bool) {
    let wait = Some(Duration::from_secs(5));
    if lingers || !matches!(stream, Stream::Tcp(_)) { let _ = within(wait, tokio::io::AsyncWriteExt::shutdown(stream)).await; }
    if !lingers { return }
    let mut buf = Vec::new();
    while read_into(stream, &mut buf, wait).await > 0 { buf.clear(); }
}

/// How long a write to the client may wait (send_timeout; zero: no limit).
pub fn send_timeout(level: &Level) -> Option<Duration> {
    Some(level.send_timeout).filter(|t| !t.is_zero())
}

/// Keeps the request body in memory, or in a file under client_body_temp_path
/// when it does not fit client_body_buffer_size or client_body_in_file_only is on;
/// 500 when the file cannot be written.
fn keep_body(r: &mut Request, level: &Level, body: Vec<u8>) -> Result<(), u16> {
    // A body that was framed, even empty, goes in a file with client_body_in_file_only.
    let framed = header(r, "content-length").is_some() || header(r, "transfer-encoding").is_some();
    let to_file = (!body.is_empty() || framed) && (level.body_in_file_only || body.len() as u64 > level.body_buffer);
    if !to_file { r.body = body; return Ok(()); }
    let path = temp_path(&level.body_temp_path, &level.body_temp_levels);
    let written = path.parent().map_or(Ok(()), std::fs::create_dir_all).and_then(|()| std::fs::write(&path, &body));
    if let Err(e) = written { error_log(level, r, &format!("open() \"{}\" failed ({e})", path.display())); return Err(500); }
    r.body_file = Some(path);
    Ok(())
}

/// Whether a location's proxy reads the request body as it passes it on, as
/// ngx_http_proxy_handler() sets request_body_no_buffering: with
/// proxy_request_buffering off, the client's body passed, no proxy_set_body,
/// and a chunked body only to a server of HTTP/1.1 or later.
fn unbuffered(level: &Level, chunked: bool) -> bool {
    level.proxy.is_some() && !level.proxy_request_buffering && level.proxy_pass_request_body && level.proxy_set_body.is_none() && (!chunked || level.proxy_http_11)
}

/// Whether a location may read the request body: it proxies, or its rewrite
/// module directives or try_files may lead elsewhere. Otherwise its content
/// handler (static files) discards the body, as nginx's does.
fn reads_body(level: &Level) -> bool {
    level.proxy.is_some() || !level.rewrite.is_empty() || !level.script.is_empty() || !level.server_script.is_empty() || level.try_files.is_some() || level.post_action.is_some()
}

fn header<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
    r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// An answer before it is written: the status, Content-Type, the other headers in order, and the body.
#[derive(Debug, Default)]
struct Response {
    status: u16,
    ctype: Option<Cow<'static, str>>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The file the body is in, instead, until it is read.
    file: Option<Box<FileBody>>,
    /// Whether "Vary: Accept-Encoding" is sent when gzip_vary is on.
    vary: bool,
    /// The connection to a proxied server that switched protocols (101) for a
    /// request with Upgrade: once the head is sent, data is passed both ways.
    tunnel: Option<Stream>,
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
    /// Whether the not modified filter leaves it as it is: the answer of a proxied
    /// server that is not cached (r->disable_not_modified).
    unconditional: bool,
    /// Whether the range filter may answer a Range with a part of it: a
    /// static file's answer (r->allow_ranges).
    ranges: bool,
    /// Whether it may be only one range (r->single_range): several are answered with the whole.
    single_range: bool,
    /// Whether a Location that starts with "/" is sent as it is: one a proxied
    /// server sent and proxy_redirect did not rewrite.
    relative: bool,
    /// The body of a proxied answer, still to be read: it is read once the head
    /// is made, as nginx sends the head first.
    rest: Option<Box<Rest>>,
    /// Set when the body is only what came of a proxied answer's, its server having
    /// closed the connection before the end of it, or a read of it having failed or
    /// waited longer than proxy_read_timeout, or its chunks being malformed.
    cut: Option<Box<Cut>>,
    /// Of a proxied answer whose body does not come (to HEAD, or 204 or 304): the length
    /// the server gave of it, if it did.
    told: Option<Option<usize>>,
    /// Whether it is a proxied answer that is not buffered, which limit_rate does not pace.
    unbuffered: bool,
}

impl Response {
    /// The length of the body, be it in memory or in a file.
    fn len(&self) -> usize {
        self.file.as_ref().map_or(self.body.len(), |f| f.len as usize)
    }
}

/// How much of a file is read at once, as by nginx's output_buffers.
const PIECE: u64 = 32768;

/// The file an answer's body is in, open, with its path, and where the part of it that
/// is still to be sent starts and how long that is, and what compresses it.
#[derive(Debug)]
struct FileBody { file: std::fs::File, path: PathBuf, start: u64, len: u64, coder: Option<Box<Coder>> }

impl FileBody {
    /// Fills the buffer with what is at so many bytes after the start. Logs, as nginx
    /// does, what keeps it from that: an error, or that the file has become shorter.
    fn read(&self, at: u64, buf: &mut [u8], (r, level): (&Request, &Level)) -> bool {
        let got = self.file.read_at(buf, self.start + at);
        let path = self.path.display();
        match got {
            Ok(n) if n == buf.len() => return true,
            Ok(n) => log_at(level, r, "alert", &format!("pread() read only {n} of {} from \"{path}\" while sending response to client", buf.len()), ""),
            Err(e) => log_at(level, r, "crit", &format!("pread() \"{path}\" failed {} while sending response to client", os_error(&e)), ""),
        }
        false
    }
}

/// Reads the body that is in a file, for what needs all of it at once. When it cannot be
/// read, nothing is sent and the connection is closed, as nginx does.
fn load(r: &Request, level: &Level, resp: &mut Response) {
    let Some(file) = resp.file.take() else { return };
    let mut body = vec![0; file.len as usize];
    // One read gives less than 2 GB.
    if body.chunks_mut(1 << 30).enumerate().all(|(i, part)| file.read((i as u64) << 30, part, (r, level))) { resp.body = body; return }
    resp.cut = Some(Box::new(Cut { length: None, malformed: true, failed: None }));
}

/// Sends an answer whose body is in a file: the head with the first piece of it, then
/// each piece, read once the one before is written, in a chunk if the body is chunked,
/// with what ends that. What compresses it makes of each piece what is sent, which may be
/// nothing or more than one part. A file that has become shorter ends it there, with no
/// more sent. It ends too when a write fails, the client goes away or worker_shutdown_timeout passes. Gives whether
/// all was written, how much was, and how much of that of the body, and the trailers.
async fn send_file<E: FnOnce(&Response, &mut Vec<u8>) -> Vec<(String, String)>>(stream: &mut Stream, mut file: Box<FileBody>, resp: &Response, (mut head, chunked): (&[u8], bool), mut pace: Pace, asked: (&Request, &Level), ending: E) -> (bool, (usize, usize), Vec<(String, String)>) {
    let direct = asked.1.sendfile && file.coder.is_none() && matches!(stream, Stream::Tcp(_));
    let (mut buf, mut size, mut tail, mut passed, mut trailers) = (vec![0; if direct { 0 } else { file.len.min(PIECE) as usize }], Vec::new(), Vec::new(), 0, Vec::new());
    let (time, mut ending) = (send_timeout(asked.1), Some(ending));
    let written = async {
        if direct {
            // One chunk, as in nginx, whose end is made before any of it is sent.
            in_chunk(chunked, file.len as usize, &mut size, &mut tail);
            if let Some(ending) = ending.take().filter(|_| chunked) { trailers = ending(resp, &mut tail); }
            let sent = send_direct(stream, (&[head, &size], &tail), &file, &mut pace, asked).await;
            passed = pace.sent.saturating_sub(head.len() + size.len()).min(file.len as usize);
            return sent
        }
        loop {
            let n = file.len.min(PIECE);
            let piece = &mut buf[..n as usize];
            if !file.read(0, piece, asked) { return false }
            (file.start, file.len) = (file.start + n, file.len - n);
            loop {
                let (mut part, mut all) = (&*piece, true);
                if let Some(c) = &mut file.coder {
                    let Ok(is) = c.code(piece, false, false) else { return false };
                    all = is;
                    if all && file.len == 0 && c.end().is_err() { return false }
                    part = c.ready();
                }
                let last = all && file.len == 0;
                in_chunk(chunked, part.len(), &mut size, &mut tail);
                if let Some(ending) = ending.take_if(|_| chunked && last) { trailers = ending(resp, &mut tail); }
                if last || !part.is_empty() {
                    // The last of it, small as it may be, does not wait for the client to acknowledge what was before (tcp_nodelay).
                    if let Some(tcp) = stream.tcp().filter(|_| last && asked.1.tcp_nodelay) { let _ = tcp.set_nodelay(true); }
                    let (before, sent) = (pace.sent, send_watched(stream, &[head, &size, part, &tail], &mut pace, time).await);
                    passed += (pace.sent - before).saturating_sub(head.len() + size.len()).min(part.len());
                    if !sent || last { return sent }
                    head = &[];
                }
                if let Some(c) = &mut file.coder { c.written(); }
                if all { break }
            }
        }
    };
    let written = tokio::select! { biased; written = written => written, () = halted() => false };
    (written, (pace.sent, passed), trailers)
}

/// Sends what is before a file, the file, and what is after it, with sendfile, as nginx's
/// ngx_linux_sendfile_chain() does: as much at a time as limit_rate lets it, up to
/// sendfile_max_chunk, after which it is the turn of other connections. It ends when the
/// client goes away, or waits for send_timeout. A file that has become shorter ends it there.
async fn send_direct(stream: &Stream, (before, after): (&[&[u8]; 2], &[u8]), file: &FileBody, pace: &mut Pace, (r, level): (&Request, &Level)) -> bool {
    let Stream::Tcp(tcp) = stream else { return false };
    let lead = before[0].len() + before[1].len();
    let (end, total) = (lead + file.len as usize, lead + file.len as usize + after.len());
    let chunk = if level.sendfile_max_chunk == 0 { usize::MAX } else { level.sendfile_max_chunk as usize };
    let sent = async {
        let mut at = 0;
        while at < total {
            let (from, to) = (at, at + pace.allowed(total - at).await.min(chunk));
            let failed = loop {
                if at >= to { break None }
                let sent = if at < lead {
                    let first = before[0].len().min(to);
                    tcp.try_write_vectored(&[std::io::IoSlice::new(&before[0][at.min(first)..first]), std::io::IoSlice::new(&before[1][at.saturating_sub(first)..to.min(lead) - first])])
                } else if at < end {
                    // What is not all that is left of it goes up to the end of a page, as in nginx.
                    let start = file.start as usize + at - lead;
                    let n = ((start + to.min(end) - at).next_multiple_of(4096) - start).min(end - at);
                    crate::stream::sendfile(tcp, &file.file, start as u64, n)
                } else {
                    tcp.try_write(&after[at - end..to - end])
                };
                match sent {
                    Ok(0) => break Some(std::io::ErrorKind::UnexpectedEof.into()),
                    Ok(n) => at += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => break Some(e),
                }
            };
            pace.wrote(at - from);
            match failed {
                None if at < total => tokio::task::yield_now().await,
                None => {}
                Some(e) if e.kind() == std::io::ErrorKind::WouldBlock => if !matches!(within(send_timeout(level), tcp.writable()).await, Some(Ok(()))) { return false },
                Some(e) => {
                    let path = file.path.display();
                    match e.raw_os_error() {
                        None => log_at(level, r, "alert", &format!("sendfile() reported that \"{path}\" was truncated at {} while sending response to client", file.start + at.saturating_sub(lead) as u64), ""),
                        // What a client that went away makes of it is no error of the server's.
                        Some(libc::EPIPE | libc::ECONNRESET | libc::ENOTCONN | libc::ETIMEDOUT | libc::EHOSTUNREACH | libc::ENETUNREACH | libc::ENETDOWN | libc::EHOSTDOWN) => {}
                        Some(_) => log_at(level, r, "alert", &format!("sendfile() failed {} while sending response to client", os_error(&e)), ""),
                    }
                    return false
                }
            }
        }
        true
    };
    let socket = socket2::SockRef::from(tcp);
    // As in nginx, only full packets are sent until all is written (tcp_nopush); what is left then, and what
    // follows it, does not wait for the client to acknowledge what was before (tcp_nodelay).
    if level.tcp_nopush { let _ = socket.set_tcp_cork(true); }
    let sent = tokio::select! { biased; sent = sent => sent, () = crate::stream::closed(tcp) => false };
    if level.tcp_nopush { let _ = socket.set_tcp_cork(false); }
    if level.tcp_nodelay { let _ = tcp.set_nodelay(true); }
    sent
}

/// A proxied answer cut off: the length its server gave it, if any, until a
/// filter changes the body, whether its chunks are malformed, and what is logged
/// of it if it is not what its coding says.
#[derive(Debug)]
struct Cut { length: Option<usize>, malformed: bool, failed: Option<String> }

/// The connection to a proxied server whose body is still to be read, with
/// what has been read of the answer, where its head ends, how the body's end
/// is found, the rate, when the request to it started, and how long a read may wait;
/// whether the connection may be used again once the body has ended, and where it
/// goes back to then: the upstream, the server's address and the location's tag;
/// where the trailers are then, if they are passed, and, over HTTP/2, how the answer
/// ended; the sizes of the buffers it is read into, without proxy_buffering how
/// much is read at once; what compresses or decompresses the body sent as it comes; and
/// the scheme, the address and the URI the request went to.
#[derive(Debug)]
struct Rest { conn: Conn, answer: Vec<u8>, end: usize, length: Option<usize>, chunked: bool, rate: u64, started: Instant, wait: Option<Duration>, keep: bool, home: Option<(Arc<Upstream>, SocketAddr, usize)>, trailers: Option<Trailers>, slot: Option<crate::h2::Slot>, sizes: Result<Sizes, usize>, coder: Option<Box<Coder>>, to: Option<(&'static str, SocketAddr, String)> }

/// The trailers of an answer over HTTP/2 (proxy_pass_trailers): the slot they come
/// in, the headers proxy_hide_header names, and what they are passed through.
#[derive(Debug)]
struct Trailers { slot: crate::h2::Slot, hide: Vec<String>, to: Arc<crate::vars::Shared> }

impl Trailers {
    /// Takes the trailers, which are there once the answer's stream has ended as it
    /// should; those proxy_hide_header names, or that nginx hides, are not passed.
    /// Tells whether there are any.
    async fn take(&self, s: &mut Stream, wait: Option<Duration>) -> bool {
        while read_into(s, &mut Vec::new(), wait).await > 0 {}
        let mut ending = self.slot.lock().unwrap();
        let whole = ending.end == crate::h2::End::Whole;
        let passed: Vec<_> = std::mem::take(&mut ending.trailers).into_iter().filter(|(n, _)| whole && !hidden(&self.hide, n)).collect();
        let any = !passed.is_empty();
        *self.to.trailers.lock().unwrap() = passed;
        any
    }
}

/// Reads the body of a proxied answer, if it is still to be read, noting how long
/// the whole answer took and how many bytes it has, and gives its connection back.
async fn finish(resp: &mut Response, (level, r): (&Level, &Request)) {
    let Some(mut rest) = resp.rest.take() else { return };
    let (read, ended, why);
    (resp.body, read, ended, resp.cut, why) = read_body(&mut rest.conn.stream, &rest.answer[rest.end..], rest.length, rest.chunked, rest.rate, rest.wait, rest.slot.as_ref()).await;
    if let Some(t) = rest.trailers.as_ref().filter(|_| resp.cut.is_none()) {
        let any = t.take(&mut rest.conn.stream, Some(rest.wait.unwrap_or_default())).await;
        // They come after a body in chunks, if it has no length of the server's.
        resp.unknown_length |= any && rest.length.is_none();
    }
    note(resp, &rest, read);
    if !why.is_empty() { log_at(level, r, "error", &why, &rest.url()); }
    rest.give_back(ended, resp.cut.is_none());
}

/// Notes how long the last proxied server took for its answer, of whose body, with
/// what makes it chunks, so many bytes were read.
fn note(resp: &mut Response, rest: &Rest, read: usize) {
    if let Some(t) = resp.upstream_time.as_mut().and_then(|t| t.last_mut()) { t[2] = Some(rest.started.elapsed().as_millis()); }
    if let Some(b) = resp.upstream_bytes.as_mut().and_then(|b| b.last_mut()) { (b[0], b[1]) = (read as u64, (rest.end + read) as u64); }
}

impl Rest {
    /// The URL the request went to, for the error log.
    fn url(&self) -> String {
        self.to.as_ref().map_or_else(String::new, |(scheme, addr, uri)| format!("{scheme}://{addr}{uri}"))
    }

    /// Gives the connection back for other requests, if the answer ended so that it may be,
    /// or, over HTTP/2, is whole.
    fn give_back(self, ended: bool, whole: bool) {
        match (self.home, &self.slot) {
            (Some((up, addr, tag)), Some(slot)) if whole => crate::h2::give_back(slot, (up, addr, tag, self.wait)),
            (Some((up, addr, tag)), None) if self.keep && ended => up.put(self.conn, addr, tag),
            _ => {}
        }
    }
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
    let ctype = Some("text/html".into());
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
const TO_HTTPS: &str = "The plain HTTP request was sent to HTTPS port";

/// A redirect: the page nginx generates for the status, with a Location.
fn redirect(status: u16, location: String) -> Response {
    let mut resp = special(status);
    resp.headers.push(("Location".to_string(), location));
    resp
}

/// The answer the location gives, before error_page and the headers every answer gets.
async fn respond(r: &Request, parsed: Result<(), u16>, (prefix, level, auto): Found<'_>, client: Option<&mut Stream>) -> Response {
    match parsed {
        Err(status) => return special(status),
        Ok(()) if auto => return redirect(301, format!("{}/{}", escape_uri(&r.uri), args(r))),
        Ok(()) => {}
    }
    // The rewrite module's directives, in order, as ngx_http_rewrite_handler() runs them.
    let (mut to, mut changed, mut moved) = (Cow::Borrowed(r), false, false);
    for step in &level.rewrite {
        let rw = match step {
            Step::Return(code, text) => return serve(&to, level, prefix, Some((*code, text)), client).await,
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
        let target = format!("{uri}{args}");
        to.to_mut().redirect(uri, target);
        (changed, moved) = (rw.flag != Flag::Break, true);
        if rw.flag != Flag::Next { break; }
    }
    // A URI changed without "break" is looked for again among the locations.
    if changed { return Response { internal: Some(to.into_owned().target), ..Response::default() }; }
    // Stopped by break, the location goes on with the new URI, and proxy_pass
    // passes it whole, without the URI it has (r->valid_location is 0).
    match level.proxy.as_deref().filter(|p| moved && p.uri.is_some() && level.try_files.is_none()) {
        Some(p) => Box::pin(async { proxy(&Proxy { uri: None, ..p.clone() }, level, &to, prefix, client).await }).await,
        None => serve(&to, level, prefix, None, client).await,
    }
}

/// The replacement of a rewrite, as the URI and the arguments after its "?".
/// When the request's URI had "%" or "+", a capture is escaped as
/// NGX_ESCAPE_ARGS does in the arguments and in a redirect
/// (ngx_http_script_copy_capture_code()).
fn replacement(rw: &Rewrite, r: &Request) -> (String, Option<String>) {
    let quoted = r.request_uri().split('?').next().unwrap_or_default().contains(['%', '+']);
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
async fn serve(r: &Request, level: &Level, prefix: &str, ret: Option<(u16, &Template)>, client: Option<&mut Stream>) -> Response {
    match (ret, &level.proxy, level.try_files.as_deref()) {
        (Some((code, text)), _, _) if REDIRECTS.contains(&code) => redirect(code, text.render(r, &Sent::default())),
        (Some((code, text)), _, _) if text.0.is_empty() && code >= 400 => special(code),
        (Some((code, text)), _, _) => {
            let ctype = Some("text/plain".into());
            Response { status: code, ctype, body: crate::vars::bytes(&text.value(r, &Sent::default())), ..Response::default() }
        }
        (None, _, Some(tf)) => try_files(tf, level, r, prefix, client).await,
        (None, Some(p), None) => Box::pin(proxy(p, level, r, prefix, client)).await,
        (None, None, None) => file(level, r, prefix),
    }
}

/// try_files: the first parameter whose file exists (a directory when it ends
/// with "/") is served, the URI changed to it; when none does, the last
/// parameter gives a status or a URI to redirect to internally.
async fn try_files(tf: &TryFiles, level: &Level, r: &Request, prefix: &str, client: Option<&mut Stream>) -> Response {
    for (name, dir) in &tf.files {
        let name = name.render(r, &Sent::default());
        let base = level.alias.as_ref().unwrap_or(&level.root);
        // With alias, the location's prefix at the start of the name is replaced, as in the URI.
        let rest = level.alias.as_ref().and(level.alias_len).and_then(|n| name.strip_prefix(r.uri.get(..n)?)).unwrap_or(&name);
        let path = PathBuf::from(format!("{}{rest}", base.display()));
        if std::fs::metadata(&path).is_ok_and(|m| m.is_dir() == *dir) {
            let to = Request { uri: name, ..r.clone() };
            return match &level.proxy { Some(p) => Box::pin(async move { proxy(p, level, &to, prefix, client).await }).await, None => file_at(level, &to, path) };
        }
    }
    match &tf.fallback {
        Fallback::Status(code) => special(*code),
        Fallback::Uri(uri) => Response { internal: Some(uri.render(r, &Sent::default())), ..Response::default() },
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

/// "?" and the arguments of the request, or "" when it has none or they are empty.
fn args(r: &Request) -> &str {
    r.target.find('?').map(|i| &r.target[i..]).filter(|a| a.len() > 1).unwrap_or_default()
}

/// Answers one request; when the connection stays open for the next one, how
/// long it waits for it (keepalive_timeout).
async fn exchange(stream: &mut Stream, server: &Server, r: &Request, parsed: Result<(), u16>, found: Found<'_>, local: SocketAddr, ahead: &[u8]) -> Option<Duration> {
    let redirected;
    let (mut resp, mut level, mut last) = answer(server, r, parsed, found, Some(&mut *stream)).await;
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
            let mut to = Box::new(r.clone());
            (to.upstream_addr, to.upstream_status) = (resp.upstream_addr.take(), resp.upstream_status.take());
            if named.is_none() {
                to.redirect(url.split('?').next().unwrap_or_default().to_string(), url);
                to.method = if r.method == "HEAD" { "HEAD" } else { "GET" }.to_string();
            }
            // The answer is sent with the error's status ("=code" replaces it, "=" leaves the
            // answer's own), unless it is a page generated for its own error or redirect.
            let status = ep.status.unwrap_or(resp.status);
            let found = named.map_or_else(|| located(server, &to, &to.uri), |l| (l.path.as_str(), &l.level, false));
            redirected = to;
            (resp, level, last) = Box::pin(answer(server, &redirected, Ok(()), found, Some(&mut *stream))).await;
            if !resp.generated && status != 0 { resp.status = status; }
            // A redirect the new answer makes replaces the Location kept.
            let own = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("location"));
            resp.headers.splice(0..0, kept.into_iter().filter(|h| !own || !h.0.eq_ignore_ascii_case("location")));
        } else {
            // A named location that does not exist is an error.
            resp = if url.starts_with('@') { special(500) } else { redirect(ep.status.filter(|s| REDIRECTS.contains(s)).unwrap_or(302), url) };
        }
    }
    // 497, a plain request to an address that takes TLS, is answered as 400 with a page of its own when error_page does not take it.
    if resp.status == 497 && resp.generated { (resp.status, resp.body) = (400, page_with(400, TO_HTTPS, &format!("<center>{TO_HTTPS}</center>\r\n")).into_bytes()); }
    // The headers and the log see the request as the last internal redirect left it ($uri).
    let r = &*last;
    not_modified(r, level, &mut resp);
    let absolute = level.absolute_redirect && !resp.relative;
    if let Some(h) = resp.headers.iter_mut().find(|h| h.0.eq_ignore_ascii_case("location") && h.1.starts_with('/')).filter(|_| absolute) {
        let host = if level.server_name_in_redirect { r.server_name.clone() } else { r.host.clone().unwrap_or_else(|| local.ip().to_string()) };
        let port = if level.port_in_redirect && local.port() != 80 { format!(":{}", local.port()) } else { String::new() };
        h.1 = format!("http://{host}{port}{}", h.1);
    }
    let gzipped = resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("content-encoding") && h.1.eq_ignore_ascii_case("gzip"));
    let streams = streams(r, &resp);
    if level.gunzip && gzipped {
        resp.vary = true;
        if !streams { finish(&mut resp, (level, r)).await; }
        if !gzip_ok(r, level) {
            load(r, level, &mut resp);
            if streams || resp.told.is_some() { coded(&mut resp, Coder::gunzip()); } else { gunzip(&mut resp); }
        }
    }
    const ADDED: &[u16] = &[200, 201, 204, 206, 301, 302, 303, 304, 307, 308];
    let added = ADDED.contains(&resp.status);
    let expires = level.expires.as_ref().filter(|_| added).and_then(|e| expires::parse(&e.render(r, &Sent::default())));
    let modified = |resp: &Response| resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case("last-modified")).and_then(|h| chrono::DateTime::parse_from_rfc2822(&h.1).ok()).map(|t| t.timestamp());
    if let Some((e, cc)) = expires.and_then(|e| expires::headers(e, modified(&resp))) {
        resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("expires") && !h.0.eq_ignore_ascii_case("cache-control"));
        resp.headers.extend([("Expires".to_string(), e), ("Cache-Control".to_string(), cc)]);
    }
    // What has been sent so far, for $sent_http_* and $upstream_http_*.
    let so_far = |resp: Response, trailers: Vec<(String, String)>| {
        let mut headers = resp.headers;
        if let Some(ctype) = resp.ctype { headers.insert(0, ("Content-Type".to_string(), ctype.into_owned())); }
        Sent { status: resp.status, headers, upstream: resp.upstream, trailers, upstream_addr: resp.upstream_addr, upstream_status: resp.upstream_status, upstream_time: resp.upstream_time, upstream_bytes: resp.upstream_bytes, proxy_host: resp.proxy_host, ..Sent::default() }
    };
    let copy = |resp: &Response| Response { status: resp.status, ctype: resp.ctype.clone(), headers: resp.headers.clone(), upstream: resp.upstream.clone(), upstream_addr: resp.upstream_addr.clone(), upstream_status: resp.upstream_status.clone(), upstream_time: resp.upstream_time.clone(), upstream_bytes: resp.upstream_bytes.clone(), proxy_host: resp.proxy_host.clone(), ..Response::default() };
    // While the head is made, the last proxied server is still sending ($upstream_response_time).
    let at_head = move |resp: &Response| {
        let mut sent = so_far(copy(resp), Vec::new());
        sent.upstream_time.iter_mut().filter_map(|t| t.last_mut()).for_each(|t| t[2] = None);
        sent
    };
    for (name, value, _) in level.add_header.iter().filter(|h| h.2 || added) {
        let value = value.render(r, &at_head(&resp));
        // These replace what the response has, and an empty value removes it.
        if ["etag", "last-modified"].contains(&name.to_ascii_lowercase().as_str()) { resp.headers.retain(|h| !h.0.eq_ignore_ascii_case(name)); }
        if !value.is_empty() { resp.headers.push((name.clone(), value)); }
    }
    if !streams { finish(&mut resp, (level, r)).await; }
    // server_tokens off: the pages twinx generates give its name without the version.
    if resp.generated && !level.server_tokens {
        resp.body = String::from_utf8_lossy(&resp.body).replace(&format!("<hr><center>{NAME}</center>"), "<hr><center>twinx</center>").into_bytes();
    }
    // The length the server gave of a proxied answer, if any, also of one without its body.
    match resp.rest.as_ref().map(|rest| rest.length).or(resp.told) {
        // As gzip() does. It may be compressed for another client.
        Some(length) => if length.is_none_or(|n| n as u64 >= level.gzip_min_length) && gzips(level, &resp) {
            resp.vary = true;
            if gzip_ok(r, level) {
                coded(&mut resp, Coder::gzip());
                resp.headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
            }
        },
        None => {
            if resp.file.as_ref().is_some_and(|f| f.len >= level.gzip_min_length) && gzips(level, &resp) {
                resp.vary = true;
                if gzip_ok(r, level) {
                    if resp.len() as u64 > PIECE || r.method == "HEAD" {
                        coded(&mut resp, Coder::gzip());
                        resp.headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
                    } else { load(r, level, &mut resp); }
                }
            }
            gzip(r, level, &mut resp);
        }
    }
    range(r, level, &mut resp);
    // What is read at once is written with the head. With sendfile, less is: one write of both costs less than two up to about there.
    let once = if level.sendfile && matches!(stream, Stream::Tcp(_)) { PIECE / 2 } else { PIECE };
    if r.method != "HEAD" && resp.len() as u64 <= once { load(r, level, &mut resp); }
    let status = resp.status;
    // 444 closes the connection without an answer; 499 is the status of a client that closed it.
    let silent = [444, 499].contains(&status);
    // An answer cut off has the length it would have whole, and the connection
    // closes after it, so that the client can tell. Without a body to send, it is not one.
    let mut cut = resp.cut.is_some() && r.method != "HEAD" && !silent && ![204, 304].contains(&status);
    // Nothing is sent of one whose chunks are malformed: nginx, which finds that
    // before it sends the head it has made, closes the connection too.
    let silent = silent || cut && resp.cut.as_ref().is_some_and(|c| c.malformed);
    // A body of unknown length is chunked for HTTP/1.1; otherwise the connection
    // closes after it. A HEAD answer has neither.
    // add_trailer makes it chunked too, except for a status that has no body.
    // chunked_transfer_encoding off leaves both unchunked.
    // One whose body is still to be read has the length its server gave.
    let whole = || resp.cut.as_ref().filter(|_| cut).map_or(Some(resp.len()), |c| c.length);
    let length = resp.told.unwrap_or_else(|| resp.rest.as_ref().map_or_else(whole, |rest| rest.length)).filter(|_| !resp.unknown_length);
    let unknown = length.is_none() && r.method != "HEAD" && ![204, 304].contains(&status);
    let trailing = level.add_trailer.iter().any(|t| t.2 || added) && r.method != "HEAD" && ![204, 304].contains(&status);
    // An upgraded connection is neither chunked nor kept alive, and has no length.
    let upgraded = resp.tunnel.is_some();
    // An HTTP/2 stream's answer without a length, or with trailers, which the proxied server
    // may have too, comes to crate::h2 chunked, with its length if it has one, to tell its end and carry them.
    let passed = resp.proxied && (!r.shared.trailers.lock().unwrap().is_empty() || resp.rest.as_ref().is_some_and(|rest| rest.trailers.is_some())) && r.method != "HEAD" && ![204, 304].contains(&status);
    let h2 = (unknown || trailing || passed) && !upgraded && r.line.ends_with("HTTP/2.0");
    let chunked = (unknown || trailing) && r.line.ends_with("HTTP/1.1") && level.chunked && !upgraded || h2;
    let keepalive = parsed.is_ok() && keepalive(r) && keeps_alive(r, level) && ![400, 413, 414, 500, 501].contains(&status) && (chunked || !unknown) && !upgraded;
    let mut out = buffer();
    if !silent && !http09(r.line.as_bytes()) {
        let mut add = |parts: &[&str]| parts.iter().for_each(|p| out.extend_from_slice(p.as_bytes()));
        let server = if level.server_tokens { NAME } else { "twinx" };
        add(&["HTTP/1.1 ", decimal(&mut [0; 20], status.into()), " ", reason(status), "\r\nServer: ", server, "\r\nDate: "]);
        crate::clock::date(|date| add(&[date, "\r\n"]));
        if let Some(ctype) = &resp.ctype { add(&["Content-Type: ", ctype, "\r\n"]); }
        if chunked { add(&["Transfer-Encoding: chunked\r\n"]); }
        if let Some(n) = length.filter(|_| (!chunked || h2) && (![204, 304].contains(&status) || resp.told.is_some() && (status == 304 || !r.line.ends_with("HTTP/2.0"))) && !upgraded) { add(&["Content-Length: ", decimal(&mut [0; 20], n as u64), "\r\n"]); }
        add(&["Connection: ", if upgraded { "upgrade" } else if keepalive { "keep-alive" } else { "close" }, "\r\n"]);
        if let Some(t) = level.keepalive_header.filter(|_| keepalive) { add(&["Keep-Alive: timeout=", decimal(&mut [0; 20], t), "\r\n"]); }
        if resp.vary && level.gzip_vary { add(&["Vary: Accept-Encoding\r\n"]); }
        resp.headers.iter().for_each(|(n, v)| add(&[n, ": ", v, "\r\n"]));
        add(&["\r\n"]);
        if !crate::vars::plain(&out) { out = crate::vars::bytes(&String::from_utf8_lossy(&out)); }
    }
    let head_len = out.len();
    let body_len = if r.method == "HEAD" || silent { 0 } else { resp.body.len() };
    if chunked && body_len > 0 { out.extend_from_slice(format!("{body_len:x}\r\n").as_bytes()); }
    // The trailers are made after the body, each seeing those before it ($sent_trailer_*);
    // those of the proxied server come first.
    let ending = |resp: &Response, to: &mut Vec<u8>| {
        let mut trailers = std::mem::take(&mut *r.shared.trailers.lock().unwrap());
        trailers.retain(|_| resp.proxied);
        for (name, value, _) in level.add_trailer.iter().filter(|t| t.2 || added) {
            let value = value.render(r, &so_far(copy(resp), trailers.clone()));
            if !value.is_empty() { trailers.push((name.clone(), value)); }
        }
        to.extend_from_slice(b"0\r\n");
        trailers.iter().for_each(|(n, v)| to.extend(crate::vars::bytes(&format!("{n}: {v}\r\n"))));
        to.extend_from_slice(b"\r\n");
        trailers
    };
    let pace = {
        // limit_rate: a rate set $limit_rate or X-Accel-Limit-Rate gave, else the location's.
        let size = |t: &Template| if t.0.is_empty() { 0 } else { crate::conf::size(&t.value(r, &Sent::default())).unwrap_or(0) };
        let rate = if resp.unbuffered { 0 } else { r.shared.limit_rate.get().unwrap_or_else(|| size(&level.limit_rate)) };
        Pace::new(rate, size(&level.limit_rate_after), r.started)
    };
    let (written, mut bytes, mut body, trailers, data);
    if let Some(rest) = resp.rest.take() {
        (written, (bytes, data), trailers) = Box::pin(pass(stream, rest, &mut resp, (&out, chunked), pace, (level, r), ending)).await;
        // All that was written, whatever makes it chunks too.
        (body, cut) = (bytes.saturating_sub(head_len), resp.cut.is_some());
        if let Some(failed) = resp.cut.as_ref().and_then(|c| c.failed.as_ref()) { error_log(level, r, failed); }
    } else if let Some(file) = resp.file.take().filter(|_| r.method != "HEAD" && !silent) {
        (written, (bytes, data), trailers) = Box::pin(send_file(stream, file, &resp, (&out, chunked), pace, (r, level), ending)).await;
        body = bytes.saturating_sub(head_len);
    } else {
        // The body is written from where it is, after the head, not copied after it.
        // What came of one cut off is a whole chunk, but there is no last one.
        let mut tail = Vec::new();
        if chunked && body_len > 0 { tail.extend_from_slice(b"\r\n"); }
        trailers = if chunked && !cut { ending(&resp, &mut tail) } else { Vec::new() };
        // The body sent of an answer cut off has what makes it a chunk.
        (bytes, body) = (out.len() + body_len + tail.len(), body_len + if cut { out.len() - head_len + tail.len() } else { 0 });
        written = send(stream, &[&out, &resp.body[..body_len], &tail], &mut { pace }, send_timeout(level)).await;
        data = body_len;
    }
    // What makes the body chunks on the pipe to crate::h2, and says so in the head, is not sent.
    if h2 { (bytes, body) = (bytes.min(head_len).saturating_sub("Transfer-Encoding: chunked\r\n".len()) + data + trailers.iter().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>(), data); }
    // What was passed from the proxied server through an upgraded connection counts as sent, as body.
    if let Some(up) = resp.tunnel.take().filter(|_| written) {
        let passed = tunnel(stream, up, ahead, (Some(level.proxy_read_timeout).filter(|t| !t.is_zero()), send_timeout(level))).await;
        (bytes, body) = (bytes + passed, body + passed);
    }
    if written && level.post_action.is_some() { Box::pin(post_action(server, r, level, Some(stream))).await; }
    if !level.access_log.is_empty() {
        let sent = Sent { bytes, body, ..so_far(resp, trailers) };
        level.access_log.iter().for_each(|log| log.write(level, r, &sent));
    }
    recycle(out);
    (written && keepalive && !silent && !cut).then_some(level.keepalive_timeout)
}

/// A number in decimal digits, written at the end of the space given.
fn decimal(space: &mut [u8; 20], mut n: u64) -> &str {
    let mut at = space.len();
    loop {
        at -= 1;
        space[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 { break }
    }
    std::str::from_utf8(&space[at..]).unwrap_or_default()
}

/// Passes data both ways between a client and the proxied server its
/// connection was upgraded to, until either closes it or sends nothing for
/// proxy_read_timeout (read), a write to the client waiting at most
/// send_timeout; then both connections are closed. Gives the bytes passed
/// from the proxied server.
async fn tunnel(client: &mut Stream, mut up: Stream, ahead: &[u8], (read, send): (Option<Duration>, Option<Duration>)) -> usize {
    let mut passed = 0;
    {
        let ((mut from_client, mut to_client), (mut from_up, mut to_up)) = (tokio::io::split(&mut *client), tokio::io::split(&mut up));
        // What the client sent after the request's head goes first.
        let upward = async {
            let mut buf = vec![0u8; 16384];
            if !write_all(&mut to_up, ahead, None).await { return }
            while let Some(Ok(n @ 1..)) = within(read, from_client.read(&mut buf)).await { if !write_all(&mut to_up, &buf[..n], None).await { return } }
        };
        let downward = async {
            let mut buf = vec![0u8; 16384];
            while let Some(Ok(n @ 1..)) = within(read, from_up.read(&mut buf)).await { if !write_all(&mut to_client, &buf[..n], send).await { return } passed += n; }
        };
        tokio::select! { () = upward => {} () = downward => {} }
    }
    client.close();
    up.close();
    passed
}

/// post_action: once the answer is sent, the request is redirected internally
/// to the URI (or named location) post_action gives, and what that answers is
/// discarded. The location it goes to does not run its own post_action.
async fn post_action(server: &Server, r: &Request, level: &Level, client: Option<&mut Stream>) {
    let Some(url) = &level.post_action else { return };
    let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && &l.path == url);
    // A named location answers the request as it is; a URI replaces the request's.
    let mut to = r.clone();
    if named.is_none() { to.redirect(url.split('?').next().unwrap_or_default().to_string(), url.clone()); }
    let found = named.map_or_else(|| located(server, &to, &to.uri), |l| (l.path.as_str(), &l.level, false));
    answer(server, &to, Ok(()), found, client).await;
}

/// The not modified filter, as ngx_http_not_modified_filter() is: a 200
/// answer, unless it is one a proxied server sent and the cache does not keep, is
/// 412 when If-Unmodified-Since is before its Last-Modified (or it has none) or
/// If-Match fails, and 304, with no body, Content-Type, Accept-Ranges or
/// Content-Encoding, when the If-Modified-Since (as if_modified_since says) and
/// If-None-Match it has hold.
fn not_modified(r: &Request, level: &Level, resp: &mut Response) {
    const CONDITIONS: &[&str] = &["if-match", "if-modified-since", "if-none-match", "if-unmodified-since"];
    if resp.status != 200 || resp.unconditional || !r.headers.iter().any(|h| CONDITIONS.iter().any(|c| h.0.eq_ignore_ascii_case(c))) { return; }
    let sent = |name: &str| resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    let (modified, etag) = (sent("last-modified").and_then(|t| expires::http_time(&t)), sent("etag"));
    if header(r, "if-unmodified-since").is_some_and(|t| !modified.zip(expires::http_time(t)).is_some_and(|(m, t)| t >= m)) { return *resp = special(412); }
    if header(r, "if-match").is_some_and(|v| !etag_match(v, etag.as_deref(), false)) { return *resp = special(412); }
    let (ims, inm) = (header(r, "if-modified-since"), header(r, "if-none-match"));
    let same = |t: &str| level.if_modified_since.zip(modified).is_some_and(|(before, m)| expires::http_time(t).is_some_and(|t| t == m || before && t > m));
    if (ims.is_none() && inm.is_none()) || ims.is_some_and(|t| !same(t)) || inm.is_some_and(|v| !etag_match(v, etag.as_deref(), true)) { return; }
    (resp.status, resp.ctype, resp.body, resp.file, resp.rest, resp.cut, resp.told) = (304, None, Vec::new(), None, None, None, None);
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges") && !h.0.eq_ignore_ascii_case("content-encoding"));
}

/// The range filter, as ngx_http_range_header_filter() is: a 200 answer of a
/// known length that allows ranges and is whole, to a request with a "bytes="
/// Range, is 206 with the part the range asks for ("start-end", "start-" or "-suffix"),
/// unless an If-Range differs from its ETag (a quoted value, compared exactly)
/// or its Last-Modified time. A range that starts past the end is 416.
/// Several ranges (multipart), which no test needs, are not done yet.
fn range(r: &Request, level: &Level, resp: &mut Response) {
    let ok = resp.status == 200 && resp.ranges && resp.cut.is_none() && !resp.unknown_length && !http09(r.line.as_bytes());
    // max_ranges 0: none, and no Accept-Ranges either.
    if ok && level.max_ranges == Some(0) { resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges")); return; }
    let Some(spec) = header(r, "range").filter(|v| ok && v.len() > 6 && v[..6].eq_ignore_ascii_case("bytes=")).map(|v| v[6..].trim()) else { return };
    let sent = |name: &str| resp.headers.iter().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    let same = |v: &str| if v.len() >= 2 && v.ends_with('"') { sent("etag").as_deref() == Some(v) } else { sent("last-modified").and_then(|t| expires::http_time(&t)).is_some_and(|t| expires::http_time(v) == Some(t)) };
    if !header(r, "if-range").is_none_or(same) { return; }
    let len = resp.len() as u64;
    let ranges = match byte_ranges(spec, len) {
        Ok(Some(ranges)) if !(resp.single_range && ranges.len() > 1) && level.max_ranges.is_none_or(|max| ranges.len() <= max) => ranges,
        Ok(_) => return,
        Err(()) => { *resp = Response { headers: vec![("Content-Range".into(), format!("bytes */{len}"))], ..special(416) }; return }
    };
    resp.status = 206;
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges"));
    if let [(start, end)] = ranges[..] {
        resp.headers.push(("Content-Range".into(), format!("bytes {start}-{}/{len}", end - 1)));
        match &mut resp.file {
            Some(file) => (file.start, file.len) = (file.start + start, end - start),
            None => resp.body = resp.body[start as usize..end as usize].to_vec(),
        }
        return;
    }
    // More than one: each a part of a multipart/byteranges body, with the type of the whole.
    load(r, level, resp);
    let boundary = format!("{:020}", BOUNDARY.fetch_add(1, Ordering::Relaxed) + 1);
    let ctype = resp.ctype.as_ref().map_or_else(String::new, |t| format!("Content-Type: {t}\r\n"));
    let mut body = Vec::new();
    for (start, end) in ranges {
        body.extend_from_slice(format!("\r\n--{boundary}\r\n{ctype}Content-Range: bytes {start}-{}/{len}\r\n\r\n", end - 1).as_bytes());
        body.extend_from_slice(resp.body.get(start as usize..end as usize).unwrap_or_default());
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (resp.body, resp.ctype) = (body, Some(format!("multipart/byteranges; boundary={boundary}").into()));
}

/// The boundaries of multipart/byteranges bodies are numbered, from 1.
static BOUNDARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The byte ranges, each from its start to before its end, of a body so long that a Range
/// header's value after "bytes=" asks for, as ngx_http_range_parse() reads it. None when the
/// whole body is sent instead (a range from 0 that is empty, or ranges longer than the body
/// together); an error when the value is malformed or no range is in the body (416).
fn byte_ranges(spec: &str, len: u64) -> Result<Option<Vec<(u64, u64)>>, ()> {
    let b = spec.as_bytes();
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    let spaces = |i: &mut usize| while at(*i) == b' ' { *i += 1 };
    let number = |i: &mut usize| {
        if !at(*i).is_ascii_digit() { return Err(()) }
        let mut n: u64 = 0;
        while at(*i).is_ascii_digit() {
            n = n.checked_mul(10).and_then(|n| n.checked_add(u64::from(at(*i) - b'0'))).filter(|&n| n <= i64::MAX as u64).ok_or(())?;
            *i += 1;
        }
        Ok(n)
    };
    let (mut i, mut ranges, mut size) = (0, Vec::new(), 0u64);
    loop {
        spaces(&mut i);
        let suffix = at(i) == b'-';
        let mut start = 0;
        if suffix { i += 1 } else {
            start = number(&mut i)?;
            spaces(&mut i);
            if at(i) != b'-' { return Err(()) }
            i += 1;
            spaces(&mut i);
        }
        let end = if !suffix && matches!(at(i), b',' | 0) { len } else {
            let n = number(&mut i)?;
            spaces(&mut i);
            if !matches!(at(i), b',' | 0) { return Err(()) }
            if suffix { start = len.saturating_sub(n); len } else { n.saturating_add(1).min(len) }
        };
        if start < end { ranges.push((start, end)); size += end - start; } else if start == 0 { return Ok(None) }
        if at(i) != b',' { break }
        i += 1;
    }
    if ranges.is_empty() { return Err(()) }
    Ok(Some(ranges).filter(|_| size <= len))
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

/// Whether a proxied answer is sent as its body comes, not once all of it has: if it has
/// one that is sent.
fn streams(r: &Request, resp: &Response) -> bool {
    resp.rest.is_some() && r.method != "HEAD" && ![204, 304, 444, 499].contains(&resp.status)
}

/// The body still to be read is sent as the coder makes it: of another length, and with
/// what recoded() leaves.
fn coded(resp: &mut Response, coder: Coder) {
    recoded(resp);
    resp.unknown_length = true;
    let coder = Some(Box::new(coder));
    match (&mut resp.rest, &mut resp.file) { (Some(rest), _) => rest.coder = coder, (_, Some(file)) => file.coder = coder, _ => {} }
}

/// Sends a proxied answer as its body comes: the head, with the first of the body that
/// goes on, then each part as it does (Buffers), in a chunk if the body is chunked, and
/// then what ends that. The next is read once that is written, and also while the client
/// is behind, as it does not take what is written to it or limit_rate makes it wait: then
/// what is read goes into the buffers that are free, and what the full ones have to a
/// file, if there may be one, to be sent after what is being written, as ngx_event_pipe()
/// does. Without buffering, the head goes as soon as it has come, and nothing is read
/// ahead. A body cut off has no last chunk; when a read fails or times out, only what
/// is being written is sent still, and of one found malformed nothing more. With a coder,
/// what it makes of each part goes on, which is flushed without buffering, and when the
/// body is cut off, then without its end; and the body is cut off where it is not what
/// its coding says. The connection to the server goes back, or is closed, once the body
/// has ended, before what is left is written, or when the client closes its connection, a
/// write or the file fails or worker_shutdown_timeout passes meanwhile. As in nginx, the
/// status is 499 when the client goes away before anything was sent; else it stays.
/// Gives whether all was written that there was, how much was, and how much of that of
/// the body, and the trailers.
async fn pass<E: FnOnce(&Response, &mut Vec<u8>) -> Vec<(String, String)>>(stream: &mut Stream, rest: Box<Rest>, resp: &mut Response, head: (&[u8], bool), mut pace: Pace, of: (&Level, &Request), ending: E) -> (bool, (usize, usize), Vec<(String, String)>) {
    let (mut rest, mut read, mut passed, mut trailers) = (Some(rest), 0, 0, Vec::new());
    let ending = |resp: &Response, to: &mut Vec<u8>| trailers = ending(resp, to);
    let written = tokio::select! {
        biased;
        written = pass_pieces(stream, (&mut rest, &mut read, &mut passed), resp, head, &mut pace, of, ending) => written.unwrap_or_else(|| {
            if pace.sent == 0 { resp.status = 499; }
            let action = |rest: &Rest| if rest.sizes.is_err() && pace.sent > 0 { "sending to client" } else { "reading upstream" };
            if let Some((rest, gone)) = rest.as_ref().and_then(|rest| Some((rest, client_gone(stream, action(rest))?))) { log_at(of.0, of.1, "info", &gone, &rest.url()); }
            false
        }),
        () = halted() => false,
    };
    if let Some(rest) = rest { note(resp, &rest, read); }
    (written, (pace.sent, passed), trailers)
}

/// The body of a proxied answer as it is read: the rest of the answer until it has ended,
/// how much of it was read, and what is sent of it; the buffers and the file, and whose
/// answer it is; where is read to, and how reading is paced; whether anything came
/// since the last write, the answer has ended, a read failed, what came is malformed, and
/// it is not buffered; and why a read failed.
struct Incoming<'a> { rest: &'a mut Option<Box<Rest>>, read: &'a mut usize, resp: &'a mut Response, buffers: Buffers, spool: Spool<'a>, of: (&'a Level, &'a Request), buf: Vec<u8>, intake: Intake, came: bool, ended: bool, failed: bool, malformed: bool, unbuffered: bool, why: String }

impl Incoming<'_> {
    /// Reads the next into what room there is for it, waiting for it or not: whether
    /// anything came, or the end. When it is dropped, nothing was read.
    async fn next(&mut self, waits: bool) -> bool {
        let Some(from) = self.rest.as_mut() else { return false };
        if self.buf.is_empty() { self.buf.resize(from.sizes.map_or_else(|n| n, |s| 65536.min(s.first.saturating_add(s.count.saturating_mul(s.size)))).max(1), 0); }
        let part = if self.intake.rate > 0 { self.buffers.at_once() } else { self.buffers.room() }.min(self.buf.len());
        let part = &mut self.buf[..part];
        let got = if waits {
            read_piece(&mut from.conn.stream, part, (&mut self.intake, *self.read), from.wait).await
        } else {
            match read_ready(&mut from.conn.stream, part).await { Some(got) => got, None => return false }
        };
        self.ended = !matches!(got, Ok(1..));
        let all = got.is_ok() || self.came;
        self.failed = got.is_err();
        if let Err(e) = &got { self.why = read_failed(if self.unbuffered { "recv" } else { "readv" }, e); }
        let n = got.unwrap_or(0);
        *self.read += n;
        self.buffers.take(&part[..n]);
        self.came = true;
        if let Some(slot) = from.slot.as_ref().filter(|_| self.ended && !self.failed) { (self.failed, self.malformed) = ended_over_h2(slot); }
        if self.ended && all { self.buffers.let_go(); }
        if self.ended && !all {
            self.buffers.drop_held();
            self.spool.drop_unseen();
        }
        true
    }

    /// There is nothing more to read for now: what may be is passed on. Tells whether the
    /// answer has ended.
    fn pause(&mut self) -> bool {
        if !self.ended { self.buffers.pause(); }
        self.malformed |= self.buffers.came() == Came::Malformed;
        self.ended |= self.buffers.came() != Came::More;
        self.came = false;
        self.ended
    }

    /// The answer has ended: notes that and gives its connection back. It may be dropped and
    /// called again.
    async fn finish(&mut self) {
        let Some(from) = self.rest.as_mut() else { return };
        self.resp.cut = self.buffers.cut(self.failed).then(|| Box::new(Cut { length: from.length, malformed: self.malformed, failed: None }));
        if let Some(t) = from.trailers.as_ref().filter(|_| self.resp.cut.is_none()) { t.take(&mut from.conn.stream, Some(from.wait.unwrap_or_default())).await; }
        note(self.resp, from, *self.read);
        self.log();
        if let Some(rest) = self.rest.take() { rest.give_back(self.buffers.came() == Came::Whole { followed: false }, self.resp.cut.is_none()); }
        self.buf = Vec::new();
    }

    /// Logs that the answer is cut off, and why, or that more came than it has.
    fn log(&self) {
        let Some(from) = self.rest.as_ref() else { return };
        // Nothing is known of why a stream of HTTP/2 failed.
        if from.slot.as_ref().is_some_and(|slot| slot.lock().unwrap().end == crate::h2::End::Failed) { return }
        let (severity, msg) = match self.buffers.came() {
            _ if self.malformed => ("error", "upstream sent invalid chunked response"),
            Came::Whole { followed: true } if from.slot.is_none() => ("warn", if from.chunked { "upstream sent data after final chunk" } else { MORE }),
            _ if self.resp.cut.is_none() => return,
            _ if self.why.is_empty() => ("error", PREMATURE),
            _ => ("error", self.why.as_str()),
        };
        // What came with the head is looked at with it, without buffering.
        let with_head = self.unbuffered && *self.read == from.answer.len() - from.end && (self.malformed || severity == "warn");
        log_at(self.of.0, self.of.1, severity, &format!("{msg} while {}", if with_head { READING_HEAD } else { "reading upstream" }), &from.url());
    }

    /// Reads ahead while the client is behind: waits for what comes next and takes what
    /// there is then. An error is that nothing more is sent, as pass_pieces() gives it. When
    /// this is dropped, nothing is lost.
    async fn ahead(&mut self) -> Result<(), Option<bool>> {
        // That may have been dropped.
        if self.ended { self.finish().await; }
        if self.ended || self.unbuffered { std::future::pending::<()>().await; }
        let paced = self.intake.rate > 0;
        while self.buffers.came() == Came::More && !self.ended {
            if self.buffers.room() == 0 && !self.to_file()? {
                if self.came { break }
                std::future::pending::<()>().await;
            }
            if self.came && paced || !self.next(!self.came).await { break }
        }
        if self.pause() { self.finish().await; }
        if self.malformed { Err(Some(true)) } else { Ok(()) }
    }

    /// Writes what the full buffers have to the file, as much as may be at once: whether
    /// there is room in them then.
    fn to_file(&mut self) -> Result<bool, Option<bool>> {
        let (end, buffers) = self.buffers.for_file(self.spool.room().min(self.spool.at_once as u64));
        if end == 0 { return Ok(false) }
        let (severity, msg) = match self.spool.write(&self.buffers.data[..end], buffers) {
            Ok(None) => ("", String::new()),
            Ok(Some(path)) => ("warn", format!("an upstream response is buffered to a temporary file {}", path.display())),
            Err(msg) => ("crit", msg),
        };
        if !severity.is_empty() {
            let url = self.rest.as_ref().map_or_else(String::new, |rest| rest.url());
            log_at(self.of.0, self.of.1, severity, &format!("{msg} while reading upstream"), &url);
        }
        if severity == "crit" { return Err(Some(false)) }
        self.buffers.in_file(end);
        Ok(true)
    }
}

/// Writes the parts from there on to a client that is behind, as it takes them, or waits
/// until limit_rate lets it when there are none, reading ahead meanwhile. As in nginx, the
/// time a write may wait (send_timeout) and that of a read (proxy_read_timeout) begin again
/// each time one of the two goes on. An error is what pass_pieces() gives then.
async fn behind<const N: usize>(stream: &mut Stream, parts: &[&[u8]; N], mut from: usize, pace: &mut Pace, incoming: &mut Incoming<'_>) -> Result<(), Option<bool>> {
    let (total, time) = (parts.iter().map(|p| p.len()).sum::<usize>(), send_timeout(incoming.of.0));
    let client = RefCell::new(stream);
    let (mut to, watched) = (Writing(&client), Writing(&client));
    let mut gone = std::pin::pin!(watched.gone());
    loop {
        let before = pace.sent;
        let wrote = tokio::select! {
            biased;
            wrote = write_some(&mut to, parts, from, pace, time) => { if !wrote { return Err(Some(false)) } true }
            read = incoming.ahead() => { read?; false }
            () = &mut gone => return Err(None),
        };
        from += pace.sent - before;
        if wrote && from >= total { return Ok(()) }
    }
}

/// Does that, leaving the rest of an answer that has not ended, with how much of it was
/// read and how much of its body written; None when the client goes away meanwhile.
async fn pass_pieces(stream: &mut Stream, (rest, read, passed): (&mut Option<Box<Rest>>, &mut usize, &mut usize), resp: &mut Response, (mut head, chunked): (&[u8], bool), pace: &mut Pace, of: (&Level, &Request), ending: impl FnOnce(&Response, &mut Vec<u8>)) -> Option<bool> {
    let Some(from) = rest.as_mut() else { return Some(true) };
    let (level, time) = (of.0, send_timeout(of.0));
    let (mut size, mut tail, mut lent, mut ending) = (Vec::new(), Vec::new(), Vec::new(), Some(ending));
    let body = Body::new(from.length.map(|n| n as u64), from.chunked);
    let mut buffers = Buffers::new(body, from.slot.is_some(), from.sizes.ok(), from.end, buffer());
    let (mut coder, unbuffered, rate) = (from.coder.take(), from.sizes.is_err(), from.rate);
    // Whether anything came with the head.
    let came = from.answer.len() > from.end;
    // Without buffering, a head that nothing came with is flushed.
    let alone = unbuffered && !came;
    *read = from.answer.len() - from.end;
    buffers.late = rate > 0;
    buffers.take(&from.answer[from.end..]);
    let largest = level.proxy_buffer_size.max(level.proxy_buffers.1);
    let spool = Spool::new((&level.proxy_temp_path, &level.proxy_temp_levels), level.proxy_max_temp_file_size, level.proxy_temp_file_write_size.unwrap_or(2 * largest));
    let intake = Intake::new(rate, *read);
    let mut incoming = Incoming { rest, read, resp, buffers, spool, of, buf: Vec::new(), intake, came, ended: false, failed: false, malformed: false, unbuffered, why: String::new() };
    // A head as large as nginx's postpone_output does not wait for the body, nor does one
    // without buffering, if nothing came with it, or one to a client of HTTP/2.
    let postponed = !matches!(stream, Stream::Pipe(_)) && head.len() < 1460 && (!unbuffered || came);
    while incoming.rest.is_some() {
        // Waits for the next that comes and takes what there is then, up to the size of
        // the buffers, or only one read without them, or with a rate.
        while incoming.buffers.came() == Came::More && !incoming.ended {
            if incoming.buffers.room() == 0 || incoming.came && (unbuffered || rate > 0) { break }
            if incoming.came {
                if !incoming.next(false).await { break }
                continue
            }
            if !postponed && !head.is_empty() {
                let mut part: &[u8] = &[];
                if let Some(c) = coder.as_mut().filter(|_| alone) {
                    let _ = c.code(&[], true, false);
                    part = c.ready();
                }
                in_chunk(chunked, part.len(), &mut size, &mut tail);
                if !send(stream, &[head, &size, part, &tail], pace, time).await { return Some(false) }
                *passed += part.len();
                if let Some(c) = &mut coder { c.written(); }
                if let Some(tcp) = stream.tcp().filter(|_| level.tcp_nodelay) { let _ = tcp.set_nodelay(true); }
                head = &[];
            }
            unless_closed(stream, incoming.next(true)).await?;
        }
        if incoming.pause() { unless_closed(stream, incoming.finish()).await?; }
        // Nothing is sent of what came in one go with what is malformed.
        if incoming.malformed { return Some(true) }
        // What is in the file is before what is not. A chunk, or what is paced, is a part of
        // what goes on; all of it is, otherwise and at the end.
        while !lent.is_empty() || incoming.spool.left() > 0 || incoming.buffers.ready > 0 || incoming.ended && ending.is_some() {
            if pace.until.is_some_and(|until| !incoming.ended && !unbuffered && until > Instant::now()) {
                if let Err(written) = behind(stream, &[], 0, pace, &mut incoming).await { return written }
                continue
            }
            if lent.is_empty() && incoming.spool.left() > 0 {
                if let Err(msg) = incoming.spool.read(&mut lent) {
                    log_at(level, of.1, "crit", &format!("{msg} while sending to client"), "");
                    return Some(false)
                }
            }
            let mut owned = !lent.is_empty();
            let end = if owned { 0 } else { incoming.buffers.part(incoming.ended || !chunked && pace.rate == 0) };
            let mut part: &[u8] = if owned { &lent } else { &incoming.buffers.data[..end] };
            // Whether this is the last of it there is.
            let (mut goes, mut last) = (true, incoming.ended && incoming.spool.left() == 0 && (!owned || incoming.buffers.ready == 0));
            if let Some(c) = &mut coder {
                let failed = |error| Some(Box::new(Cut { length: None, malformed: false, failed: Some(error) }));
                let flush = unbuffered && !part.is_empty();
                let all = match c.code(part, flush, last && incoming.resp.cut.is_some()) {
                    Ok(all) => all,
                    Err(error) => {
                        incoming.resp.cut = failed(error);
                        // But the head, to a client of HTTP/2.
                        return Some(!matches!(stream, Stream::Pipe(_)) || send(stream, &[head], pace, time).await);
                    }
                };
                // The data is not needed any more, although what is made of it is not written
                // yet, or the rest of it is next, whatever is read ahead meanwhile.
                if all { release(&mut incoming.buffers, &mut lent, owned, end); } else if !owned { incoming.buffers.lend(end, &mut lent); }
                last &= all;
                goes = last;
                if last && incoming.resp.cut.is_none() { if let Err(error) = c.end() { (incoming.resp.cut, goes) = (failed(error), matches!(stream, Stream::Pipe(_))); } }
                part = c.ready();
                goes |= !part.is_empty() || all && flush && !head.is_empty();
            }
            in_chunk(chunked, part.len(), &mut size, &mut tail);
            if let Some(ending) = ending.take_if(|_| last) { if chunked && incoming.resp.cut.is_none() { ending(incoming.resp, &mut tail); } }
            if goes {
                let (before, lead, mut length) = (pace.sent, head.len() + size.len(), part.len());
                let written = match send_now(stream, &[head, &size, part, &tail], pace).await {
                    Some(sent) => if sent { Ok(()) } else { Err(Some(false)) },
                    None => {
                        let (mut done, mut first) = (pace.sent - before, [head, size.as_slice()]);
                        let part = if let Some(c) = &coder { c.ready() } else {
                            // The buffers written whole are free, and no more than a part is
                            // being written: the rest may be written to the file.
                            if !owned {
                                let (data, mut whole) = (done.saturating_sub(lead).min(end), 0);
                                length = if incoming.ended { end } else { incoming.buffers.part_of(data).min(end) };
                                if !incoming.ended { whole = incoming.buffers.whole(data); }
                                if whole > 0 {
                                    incoming.buffers.written(whole);
                                    (done, first) = (done - lead - whole, [&[][..]; 2]);
                                }
                                incoming.buffers.lend(length - whole, &mut lent);
                                owned = true;
                            }
                            &lent
                        };
                        behind(stream, &[first[0], first[1], part, &tail], done, pace, &mut incoming).await
                    }
                };
                *passed += (pace.sent - before).saturating_sub(lead).min(length);
                if let Err(written) = written { return written }
                // What follows, small as it may be, does not wait for the client to acknowledge that (tcp_nodelay).
                if let Some(tcp) = stream.tcp().filter(|_| level.tcp_nodelay && !head.is_empty() && !last) { let _ = tcp.set_nodelay(true); }
                head = &[];
            }
            match &mut coder { Some(c) => c.written(), None => release(&mut incoming.buffers, &mut lent, owned, end) }
        }
    }
    recycle(std::mem::take(&mut incoming.buffers.data));
    Some(true)
}

/// The data up to there, or what was lent, is not needed any more.
fn release(buffers: &mut Buffers, lent: &mut Vec<u8>, owned: bool, end: usize) {
    if owned {
        lent.clear();
        buffers.returned();
    } else {
        buffers.written(end);
    }
}

/// What is before and after data of the length, if any, in a chunk.
fn in_chunk(chunked: bool, length: usize, before: &mut Vec<u8>, after: &mut Vec<u8>) {
    before.clear();
    after.clear();
    if chunked && length > 0 {
        let _ = write!(before, "{length:x}\r\n");
        after.extend_from_slice(b"\r\n");
    }
}

/// How the writes of an answer are paced (limit_rate): the rate, what goes before it is
/// looked at (limit_rate_after), the second the request started in, the bytes written
/// so far, and when the next write may be.
struct Pace { rate: i64, after: i64, start: i64, sent: usize, until: Option<Instant> }

impl Pace {
    fn new(rate: u64, after: u64, started: Instant) -> Pace {
        // Without a rate, the clock is not read.
        let start = if rate == 0 { 0 } else { (now() - started.elapsed()).as_secs() as i64 };
        Pace { rate: rate as i64, after: after as i64, start, sent: 0, until: None }
    }

    /// How much of what is left may be written, waited for until any of it may.
    async fn allowed(&mut self, left: usize) -> usize {
        while self.rate != 0 {
            if let Some(until) = self.until {
                tokio::time::sleep_until(until.into()).await;
                self.until = None;
            } else {
                let limit = self.rate * (seconds() - self.start + 1) - (self.sent as i64 - self.after);
                if limit > 0 || left == 0 { return left.min(limit.max(0) as usize) }
                self.until = Some(Instant::now() + Duration::from_millis((-limit * 1000 / self.rate + 1) as u64));
            }
        }
        left
    }

    /// So much was written.
    fn wrote(&mut self, n: usize) {
        let paced = |sent: usize| (sent as i64 - self.after).max(0);
        let before = paced(self.sent);
        self.sent += n;
        if self.rate != 0 {
            let delay = (paced(self.sent) - before) * 1000 / self.rate;
            if delay > 0 { self.until = Some(Instant::now() + Duration::from_millis(delay as u64)); }
        }
    }
}

/// The time of day, and in whole seconds.
fn now() -> Duration {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default()
}

fn seconds() -> i64 {
    now().as_secs() as i64
}

/// Writes the parts of an answer one after another (the head, the body, the end of a
/// chunked body), together (writev) without copying them into one buffer, as
/// write_some() does until all is written.
async fn send<const N: usize>(stream: &mut Stream, parts: &[&[u8]; N], pace: &mut Pace, time: Option<Duration>) -> bool {
    send_from(stream, parts, 0, pace, time).await
}

async fn send_from<S: AsyncWrite + Unpin, const N: usize>(stream: &mut S, parts: &[&[u8]; N], mut from: usize, pace: &mut Pace, time: Option<Duration>) -> bool {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    loop {
        let before = pace.sent;
        if !write_some(stream, parts, from, pace, time).await { return false }
        from += pace.sent - before;
        if from >= total { return true }
    }
}

/// Writes what one write takes of the parts from there on, and flushes it if that is all,
/// paced as ngx_http_write_filter() paces it with a rate: by the end of each second since
/// the request started (counted in whole seconds of the clock) up to limit_rate_after
/// bytes and limit_rate bytes for each second have gone, and after each write the time is
/// waited that what it wrote after the first limit_rate_after bytes is worth at that
/// rate. Without a rate it is written at once. The write waits at most the time
/// (send_timeout). When this is dropped, the pace tells what was done.
async fn write_some<S: AsyncWrite + Unpin, const N: usize>(stream: &mut S, parts: &[&[u8]; N], from: usize, pace: &mut Pace, time: Option<Duration>) -> bool {
    let total = parts.iter().map(|p| p.len()).sum::<usize>();
    let to = if from < total || total == 0 { from + pace.allowed(total - from).await } else { total };
    if from < to {
        let (mut at, mut used, mut bufs) = (0, 0, [std::io::IoSlice::new(&[]); N]);
        for p in parts {
            let (start, end) = (from.max(at), to.min(at + p.len()));
            if start < end {
                bufs[used] = std::io::IoSlice::new(&p[start - at..end - at]);
                used += 1;
            }
            at += p.len();
        }
        let Some(n) = crate::stream::write_once(stream, &bufs[..used], time).await else { return false };
        pace.wrote(n);
        if from + n < total && pace.rate == 0 { return true }
    }
    matches!(within(time, tokio::io::AsyncWriteExt::flush(stream)).await, Some(Ok(())))
}

/// Does what send() does, until the client goes away when it is behind.
async fn send_watched<const N: usize>(stream: &mut Stream, parts: &[&[u8]; N], pace: &mut Pace, time: Option<Duration>) -> bool {
    let start = pace.sent;
    if let Some(sent) = send_now(stream, parts, pace).await { return sent }
    let client = RefCell::new(stream);
    let (mut to, watched) = (Writing(&client), Writing(&client));
    tokio::select! { biased; sent = send_from(&mut to, parts, pace.sent - start, pace, time) => sent, () = watched.gone() => false }
}

/// Does what send() does as long as it need not wait; None when the client is behind,
/// with the pace telling how much was written.
async fn send_now<const N: usize>(stream: &mut Stream, parts: &[&[u8]; N], pace: &mut Pace) -> Option<bool> {
    let start = pace.sent;
    loop {
        let sent = at_once(send_from(stream, parts, pace.sent - start, pace, None)).await;
        // It may be that the task is to yield, not that the client is behind.
        if sent.is_some() || tokio::task::coop::has_budget_remaining() { return sent }
        tokio::task::yield_now().await;
    }
}

/// Whether the location lets the connection serve another request, as
/// ngx_http_update_location_config() decides: keepalive_timeout is not zero,
/// keepalive_requests and keepalive_time are not reached, and keepalive_disable
/// does not name the browser.
fn keeps_alive(r: &Request, level: &Level) -> bool {
    let (post, safari) = (r.method == "POST" && level.keepalive_disable_msie6, level.keepalive_disable_safari);
    let limits = !level.keepalive_timeout.is_zero() && r.requests < level.keepalive_requests && crate::clock::coarse().saturating_duration_since(r.connected) <= level.keepalive_time;
    // The browser matters only to a POST, or with "keepalive_disable safari".
    limits && (!post && !safari || { let is = browser(header(r, "user-agent").unwrap_or_default()); !(post && is.0) && !(safari && is.1) })
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
async fn answer<'a, 'r>(server: &'a Server, r: &'r Request, parsed: Result<(), u16>, (prefix, mut level, auto): Found<'a>, mut client: Option<&mut Stream>) -> (Response, &'a Level, Cow<'r, Request>) {
    // Once the location or an if block that applied has proxy_pass, the request
    // is proxied: when the last if block that applied has no proxy_pass to
    // inherit, nginx has no upstream for it and answers 500.
    let mut proxied = level.proxy.is_some();
    if parsed.is_ok() { level = run(r, &level.script, run(r, &level.server_script, level, &mut proxied), &mut proxied); }
    let mut resp = if proxied && level.proxy.is_none() { log_at(level, r, "alert", "no upstream configuration", ""); special(500) } else { respond(r, parsed, (prefix, level, auto), client.as_deref_mut()).await };
    let (mut redirects, mut to) = (0, Cow::Borrowed(r));
    while let Some(target) = resp.internal.take() {
        // nginx gives up after 10 internal redirects.
        redirects += 1;
        // After X-Accel-Redirect the proxied answer's headers stay ($upstream_http_*),
        // and the new answer has those of them nginx keeps.
        let kept = resp.proxied.then(|| { to.to_mut().upstream = std::mem::take(&mut resp.upstream); (std::mem::take(&mut resp.headers), resp.ctype.take()) });
        // A named location answers the request as it is, without the server's rewrites.
        let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && l.path == target);
        let (prefix, found, auto) = if let Some(l) = named { (l.path.as_str(), &l.level, false) } else {
            let next = to.to_mut();
            if resp.as_get && next.method != "HEAD" { next.method = "GET".to_string(); }
            next.redirect(target.split('?').next().unwrap_or_default().to_string(), target.clone());
            located(server, &to, &to.uri)
        };
        let proxied = &mut false;
        level = run(&to, &found.script, if named.is_some() { found } else { run(&to, &found.server_script, found, proxied) }, proxied);
        resp = if redirects > 10 || (target.starts_with('@') && named.is_none()) { special(500) } else { respond(&to, Ok(()), (prefix, level, auto), client.as_deref_mut()).await };
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
            Op::Set(name, value) if name == "limit_rate" => if let Ok(rate) = crate::conf::size(&value.render(r, &Sent::default())) { r.shared.limit_rate.set(rate); },
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
    let reason = os_error(err);
    if err.kind() == std::io::ErrorKind::PermissionDenied {
        error_log(level, r, &format!("\"{}\" is forbidden {reason}", path.display()));
        return special(403);
    }
    if level.log_not_found { error_log(level, r, &format!("\"{}\" is not found {reason}", path.display())); }
    special(404)
}

/// An error of the system as nginx logs it.
fn os_error(err: &std::io::Error) -> String {
    format!("({}: {})", err.raw_os_error().unwrap_or(0), err.to_string().split(" (os error").next().unwrap_or_default())
}

/// Writes an error of the request to the error_log of its level, as nginx's
/// lines are: the time, the level, the process, the message and the request.
fn error_log(level: &Level, r: &Request, msg: &str) {
    log_at(level, r, "error", msg, "")
}

/// Writes an error of the request at a level of error_log ("error", "alert"), if that is
/// logged, with the URL at the proxied server, if there is one.
fn log_at(level: &Level, r: &Request, severity: &str, msg: &str, upstream: &str) {
    let least = crate::conf::LEVELS.iter().position(|l| *l == severity);
    let mut logs = level.error_log.iter().filter(|l| least >= Some(l.1)).peekable();
    if logs.peek().is_none() { return }
    let time = chrono::Local::now().format("%Y/%m/%d %H:%M:%S");
    let host = header(r, "host").map(|h| format!(", host: \"{h}\"")).unwrap_or_default();
    let upstream = if upstream.is_empty() { String::new() } else { format!(", upstream: \"{upstream}\"") };
    let number = if r.shared.number > 0 { format!("*{} ", r.shared.number) } else { String::new() };
    let line = format!("{time} [{severity}] {}#0: {number}{msg}, client: {}, server: {}, request: \"{}\"{upstream}{host}\n", std::process::id(), r.peer.ip(), r.server_name, r.line);
    logs.for_each(|l| { let _ = (&*l.0).write_all(line.as_bytes()); });
}

/// Serves the file at a path, or redirects to the directory there. Nothing of the file
/// is read here: it is told from what is open what it is and how long.
fn file_at(level: &Level, r: &Request, path: PathBuf) -> Response {
    // As nginx does, without waiting for the other end of a named pipe.
    let open = |p: &std::path::Path| std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(p).and_then(|f| f.metadata().map(|m| (f, m)));
    // gzip_static: the file with ".gz" added, for clients that take gzip ("always": for all).
    let gz = level.gzip_static.filter(|_| r.method != "POST").and_then(|always| {
        let path = path.with_added_extension("gz");
        open(&path).ok().filter(|f| f.1.is_file()).map(|open| (always, open, path))
    });
    let vary = gz.is_some();
    let (opened, gz) = match gz.filter(|(always, ..)| *always || gzip_ok(r, level)) {
        Some((_, open, path)) => (Ok(open), Some(path)),
        None => (open(&path), None),
    };
    let (file, meta) = match opened {
        Ok(opened) => opened,
        Err(e) => return special(if e.kind() == std::io::ErrorKind::PermissionDenied { 403 } else { 404 }),
    };
    if meta.is_dir() && !r.uri.ends_with('/') { return redirect(301, format!("{}/{}", escape_uri(&r.uri), args(r))); }
    if !meta.is_file() { return special(404); }
    if r.method == "POST" { return special(405); }
    let mtime = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
    let modified = expires::http_date(mtime as i64);
    const TYPES: &[(&str, &str)] = &[("html", "text/html"), ("gif", "image/gif"), ("jpg", "image/jpeg")];
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default();
    let ctype = TYPES.iter().find(|t| t.0 == ext).map_or_else(|| level.default_type.clone().into(), |t| t.1.into());
    let mut headers = vec![("Last-Modified".to_string(), modified)];
    headers.extend(gz.as_ref().map(|_| ("Content-Encoding".to_string(), "gzip".to_string())));
    headers.push(("ETag".to_string(), format!("\"{mtime:x}-{:x}\"", meta.len())));
    headers.push(("Accept-Ranges".to_string(), "bytes".to_string()));
    let file = Some(Box::new(FileBody { file, path: gz.unwrap_or(path), start: 0, len: meta.len(), coder: None }));
    Response { status: 200, ctype: Some(ctype), headers, file, vary, ranges: true, ..Response::default() }
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
    accepts && (["HTTP/1.1", "HTTP/2.0"].iter().any(|v| r.line.ends_with(v)) || !level.gzip_http_11) && header(r, "via").is_none()
}

/// Takes away what no longer holds once the body is recoded: Content-Encoding,
/// Accept-Ranges, and a strong ETag, which becomes weak (one not quoted is dropped).
fn recoded(resp: &mut Response) {
    resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("content-encoding") && !h.0.eq_ignore_ascii_case("accept-ranges"));
    resp.headers.retain_mut(|h| !h.0.eq_ignore_ascii_case("etag") || h.1.starts_with("W/") || h.1.starts_with('"') && { h.1.insert_str(0, "W/"); true });
}

/// The gzip filter: with gzip on, an answer with status 200, 403 or 404, no
/// Content-Encoding, at least gzip_min_length bytes (20 by default) and a type of
/// gzip_types (text/html always) is compressed for a client that takes gzip,
/// at gzip_comp_level 1, and sent without a length.
fn gzip(r: &Request, level: &Level, resp: &mut Response) {
    if (resp.body.len() as u64) < level.gzip_min_length || !gzips(level, resp) { return; }
    resp.vary = true;
    if !gzip_ok(r, level) { return; }
    recoded(resp);
    resp.headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
    let (mut coder, mut body) = (Coder::gzip(), Vec::new());
    loop {
        let all = coder.code(&resp.body, false, false).unwrap_or(true);
        if all { let _ = coder.end(); }
        body.extend_from_slice(coder.ready());
        coder.written();
        if all { break }
    }
    (resp.body, resp.unknown_length) = (body, true);
}

/// Whether the gzip filter would compress an answer that is long enough for a client
/// that takes gzip.
fn gzips(level: &Level, resp: &Response) -> bool {
    if !level.gzip || ![200, 403, 404].contains(&resp.status) { return false; }
    let ctype = resp.ctype.as_deref().unwrap_or_default().split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
    let typed = ctype == "text/html" || level.gzip_types.iter().any(|t| t == "*" || *t == ctype);
    typed && !resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("content-encoding") && !h.1.is_empty())
}

/// gunzip: decompresses a gzip answer for a client that does not take gzip,
/// without its Content-Encoding and Accept-Ranges, and with a weak ETag.
fn gunzip(resp: &mut Response) {
    recoded(resp);
    let mut body = Vec::new();
    let _ = flate2::read::MultiGzDecoder::new(resp.body.as_slice()).read_to_end(&mut body);
    resp.body = body;
    if let Some(cut) = &mut resp.cut { cut.length = None; }
}

/// The URI a proxied server is sent when proxy_pass has none: the request line's
/// as it is, else, once another replaced it, that one escaped and its arguments
/// (r->valid_unparsed_uri).
fn passed(r: &Request) -> String {
    if r.shared.unparsed.get().is_none() { r.target.clone() } else { format!("{}{}", escape_uri(&r.uri), args(r)) }
}

/// Passes the request to the proxied servers in turn, as proxy_http_version
/// says (1.1 by default) and, as nginx 1.30 does, with no Connection header of
/// its own, until one answers with a response head.
async fn proxy(p: &Proxy, level: &Level, r: &Request, prefix: &str, mut client: Option<&mut Stream>) -> Response {
    let rest = escape_uri(r.uri.get(prefix.len()..).unwrap_or_default());
    let (host, mut uri, up) = match &p.url {
        None => (p.host.clone(), p.uri.as_ref().map_or_else(|| passed(r), |u| format!("{u}{rest}{}", args(r))), p.upstream.clone()),
        Some(url) => match resolved(&url.render(r, &Sent::default()), p, level, r).await {
            Some(t) => t,
            None => return special(502),
        },
    };
    // proxy_cache: a GET or HEAD is answered with what the cache keeps for its key
    // ($scheme$proxy_host$request_uri) while that is valid.
    // One with variables names the zone for each request; nothing, or "off", is none.
    let get = matches!(r.method.as_str(), "GET" | "HEAD");
    let cache = match level.proxy_cache.as_ref().filter(|_| get) {
        Some(crate::conf::CacheZone::Named(name, zones)) => match name.render(r, &Sent::default()) {
            n if n.is_empty() || n == "off" => None,
            n => match zones.get(&n) { Some(z) => Some(z), None => { error_log(level, r, &format!("cache \"{n}\" not found")); return special(500) } },
        },
        Some(crate::conf::CacheZone::Fixed(z)) => Some(z),
        None => None,
    };
    let to_host = Sent { proxy_host: Some(host.clone()), ..Sent::default() };
    let main = level.proxy_cache_key.as_ref().map_or_else(|| format!("{}://{host}{}", if r.ssl.is_some() { "https" } else { "http" }, r.request_uri()), |k| k.render(r, &to_host));
    // That of the variant of the request when what the key keeps has a Vary it does not match.
    let key = cache.map_or_else(|| main.clone(), |z| z.resolve(&main, &r.headers));
    // proxy_cache_bypass: the server is asked whatever the cache keeps.
    let any_set = |t: &[Template]| t.iter().any(|t| !matches!(t.render(r, &to_host).as_str(), "" | "0"));
    let bypass = cache.is_some() && any_set(&level.proxy_cache_bypass);
    let hit = |e: crate::cache::Entry| Response { status: e.status, ctype: e.ctype.map(Into::into), headers: e.headers, body: e.body, proxied: true, ranges: true, proxy_host: Some(host.clone()), ..Response::default() };
    // $upstream_cache_status: how the cache answered.
    let noted = |status| { if cache.is_some() { *r.shared.cache_status.lock().unwrap() = Some(status); } };
    if let Some(e) = cache.filter(|_| !bypass).and_then(|z| z.get(&key)) { noted("HIT"); return hit(e) }
    // What is kept but no longer valid may be given instead of the server's answer (proxy_cache_use_stale).
    let stale = cache.filter(|_| !bypass).and_then(|z| z.stale(&key));
    // proxy_cache_background_update: what may be given while it is updated is given at
    // once, and the server is asked for the update by a request of its own.
    let updating = |e: &crate::cache::Entry| e.updating() || level.proxy_cache_use_stale.iter().any(|c| c == "updating");
    if let Some(e) = stale.clone().filter(|e| level.proxy_cache_background_update && !r.shared.updater && updating(e)) {
        noted("STALE");
        let (p, level, mut update, prefix) = (p.clone(), level.clone(), r.clone(), prefix.to_string());
        update.shared = Arc::new(crate::vars::Shared { number: r.shared.number, updater: true, ..Default::default() });
        tokio::task::spawn_local(async move { Box::pin(proxy(&p, &level, &update, &prefix, None)).await });
        return hit(e);
    }
    noted(if bypass { "BYPASS" } else if stale.is_some() { "EXPIRED" } else { "MISS" });
    let uses = cache.map_or(0, |z| z.used(&key));
    // proxy_cache_lock: while another request asks the server for the key, this one waits
    // for what it caches; once that wait is over, it asks too, and its answer is not cached.
    let locked = match cache.filter(|_| level.proxy_cache_lock && !bypass) {
        Some(zone) => Some(zone.lock(&key, level.proxy_cache_lock_timeout, level.proxy_cache_lock_age).await),
        None => None,
    };
    if let Some(e) = cache.filter(|_| locked.is_some()).and_then(|z| z.get(&key)) { noted("HIT"); return hit(e) }
    // Before proxy_cache_min_uses requests asked for the key, and when the range asked for
    // starts too far (proxy_cache_max_range_offset), the request is passed with its
    // conditions and ranges, and the answer is not cached.
    let scarce = cache.is_some() && !bypass && uses < level.proxy_cache_min_uses;
    let far = cache.is_some() && !bypass && !scarce && !range_cacheable(r, level.proxy_cache_max_range_offset);
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
    // One that may be cached asks for the body of a HEAD too, unless proxy_cache_convert_head is off.
    let method = level.proxy_method.as_ref().map_or_else(|| if cache.is_some() && level.proxy_cache_convert_head { "GET".to_string() } else { r.method.clone() }, |m| m.render(r, &sent));
    let mut req = format!("{method} {uri} HTTP/1.{}\r\n", level.proxy_http_11 as u8);
    set.iter().filter(|h| !h.1.is_empty()).for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    if !is_set("host") { req += &format!("Host: {host}\r\n"); }
    // proxy_cache_revalidate: what is kept but no longer valid is asked for on its conditions.
    let revalidate = stale.is_some() && level.proxy_cache_revalidate && !bypass && !scarce && !far;
    stale.iter().filter(|_| revalidate).flat_map(|e| e.conditions()).filter(|(n, _)| !is_set(n)).for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    // A body passed as it comes: the rest of one with a Content-Length, or chunks.
    let mut unread = r.shared.unread.lock().unwrap();
    let chunked = unread.as_ref().is_some_and(|u| u.chunked.is_some());
    if pass_body && chunked { req += "Transfer-Encoding: chunked\r\n"; }
    if pass_body && !chunked && framing(r) != Ok(Some(0)) { req += &format!("Content-Length: {}\r\n", body.len() as u64 + unread.as_ref().map_or(0, |u| u.left)); }
    if set_body.is_some() { req += &format!("Content-Length: {}\r\n", body.len()); }
    let body = if pass_body && chunked && !body.is_empty() { chunk(&body) } else { body };
    const DROPPED: &[&str] = &["host", "connection", "content-length", "transfer-encoding", "keep-alive", "te", "expect", "upgrade"];
    // With a cache, the server is asked for the whole answer, whatever the client's conditions and ranges.
    const WHOLE: &[&str] = &["if-modified-since", "if-unmodified-since", "if-none-match", "if-match", "range", "if-range"];
    let dropped = |n: &str| DROPPED.contains(&n) || (if get { cache.is_some() } else { level.proxy_cache.is_some() }) && !scarce && !far && WHOLE.contains(&n);
    // proxy_pass_request_headers off passes none of the client's headers.
    let passed = r.headers.iter().filter(|_| level.proxy_pass_request_headers).filter(|(n, _)| !dropped(&n.to_ascii_lowercase()) && !is_set(n));
    passed.for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    let mut req = crate::vars::bytes(&(req + "\r\n"));
    req.extend_from_slice(&body);
    // proxy_bind: an empty value binds to nothing; a value that is no address fails the request.
    let bind = level.proxy_bind.as_ref().map(|(a, t)| (a.render(r, &Sent::default()), *t)).filter(|(a, _)| !a.is_empty());
    let Some(bind) = bind.map(|(a, t)| crate::conf::local_addr(&a).map(|a| (a, t))).map_or(Some(None), |b| b.map(Some)) else { return special(500) };
    // proxy_limit_rate, which may have the answer's headers ($upstream_http_*).
    let rate = |resp: &Response| crate::conf::size(&level.proxy_limit_rate.render(r, &Sent { upstream: resp.upstream.clone(), ..Sent::default() })).unwrap_or(0);
    let (mut tried, mut answer, mut addrs, mut times, mut bytes) = (vec![false; up.peers.len()], None, Vec::new(), Vec::new(), Vec::new());
    let (mut statuses, limit, first, mut failed) = (Vec::new(), level.proxy_next_upstream_tries, Instant::now(), "error");
    let (mut tries, next) = (if limit > 0 { up.tries().min(limit) } else { up.tries() }, |cond: &str| level.proxy_next_upstream.iter().any(|c| c == cond));
    // Whether a request that a server may have got can go on to another: not one whose
    // body is passed as it comes, nor, without non_idempotent, one of these methods.
    let resend = !(pass_body && unread.is_some()) && (!matches!(r.method.as_str(), "POST" | "LOCK" | "PATCH") || next("non_idempotent"));
    let upgrade = r.headers.iter().any(|h| h.0.eq_ignore_ascii_case("upgrade"));
    // early_hints: whether a value is neither empty nor "0", for a client of HTTP/1.1.
    let hints = r.line.ends_with("HTTP/1.1") && level.early_hints.iter().any(|t| !matches!(t.render(r, &sent).as_str(), "" | "0"));
    // The name certificates are verified for (proxy_ssl_verify) and SNI sends
    // (proxy_ssl_server_name): proxy_ssl_name or $proxy_host, without the port.
    let name = ((level.proxy_ssl_verify || level.proxy_ssl_server_name) && p.ssl).then(|| ssl_name(&level.proxy_ssl_name.as_ref().map_or_else(|| host.clone(), |t| t.render(r, &sent))).to_string());
    // What tells the location from others in the cache of connections: its settings live as long as the worker.
    let tag = level as *const Level as usize;
    let url = |peer: &dyn std::fmt::Display, uri: &str| format!("{}://{peer}{uri}", if p.ssl { "https" } else { "http" });
    loop {
        let Some(i) = up.pick(&mut tried) else { log_at(level, r, "error", "no live upstreams while connecting to upstream", &url(&host, &uri)); break };
        let addr = up.peers[i].addr;
        addrs.push(addr.to_string());
        // A kept connection is used wherever it was bound, as in nginx.
        let taken = up.take_for(&addr, tag, level.proxy_h2);
        let cached = taken.is_some();
        // A socket that cannot be bound fails the request without trying the next server.
        let socket = bind.filter(|_| taken.is_none()).map(|b| bound(&addr, b));
        if socket.as_ref().is_some_and(Option::is_none) { return special(500); }
        let (start, mut time, mut counted) = (Instant::now(), [None; 3], [0; 3]);
        // As in nginx, one over TLS is used as it is, whatever it was made with, and
        // one without makes the handshake for https:// now.
        let handshake = p.ssl && taken.as_ref().is_none_or(|c| matches!(c.stream, Stream::Tcp(_)));
        // Names of proxy_ssl_certificate with variables are loaded for each handshake; failing to is 500.
        let names = level.proxy_ssl_certificate_vars.as_ref().filter(|_| handshake).map(|(c, k, prefix)| (c.render(r, &Sent::default()), k.render(r, &Sent::default()), prefix));
        let tls = match (names.filter(|(c, ..)| !c.is_empty()), level.proxy_tls.as_ref().filter(|_| handshake)) {
            (Some((c, k, prefix)), Some(base)) => match crate::tls::client_cert(base, (&prefix.join(c), &prefix.join(k), level.proxy_ssl_password_file.as_deref()), level.proxy_ssl_certificate_cache.as_deref()) {
                Ok(tls) => Some(tls),
                Err(e) => { error_log(level, r, &e); return special(500) }
            },
            (_, tls) => tls.cloned(),
        };
        let connecting = Instant::now();
        let conn = match taken {
            Some(conn) => Ok(conn),
            None => connect(&addr, socket.flatten(), level).await.map(|s| Conn::new(Stream::Tcp(s), connecting)),
        };
        let conn = match (conn, &tls) {
            // Over HTTP/2, ALPN offers h2.
            (Ok(conn), Some(tls)) if level.proxy_h2 => secure(conn, &addr, (&crate::tls::h2(tls), name.as_deref()), level).await,
            (Ok(conn), Some(tls)) => secure(conn, &addr, (tls, name.as_deref()), level).await,
            (conn, _) => conn,
        };
        // proxy_http_version 2: the request goes through a pipe, over HTTP/2 beyond it.
        // Its trailers come in a slot of their own.
        let slot = crate::h2::Slot::default();
        let conn = conn.map(|c| if level.proxy_h2 { let (ours, theirs) = tokio::io::duplex(65536); tokio::task::spawn_local(crate::h2::upstream(c, theirs, if p.ssl { "https" } else { "http" }, level.proxy_buffer_size, slot.clone())); Conn::new(Stream::Pipe(ours.into()), connecting) } else { c });
        let begun = conn.is_ok();
        let mut fetched = match conn {
            Ok(conn) => {
                time[0] = Some(connecting.elapsed().as_millis());
                fetch(conn, connecting, &req, level, client.as_deref_mut(), (&mut time, &mut counted), &rate, unread.as_mut().filter(|_| pass_body), level.max_body, (upgrade, hints)).await
            }
            Err(e) => Err(e),
        };
        // proxy_pass_trailers: those of an answer without a body are taken now.
        let trailers = (level.proxy_pass_trailers && level.proxy_h2).then(|| Trailers { slot: slot.clone(), hide: level.proxy_hide_header.clone(), to: r.shared.clone() });
        if let (Some(t), Ok((_, Some(c)))) = (&trailers, &mut fetched) { t.take(&mut c.stream, Some(level.proxy_read_timeout)).await; }
        // A kept connection whose handshake fails counts as closed, as in nginx; one that times out does not.
        let closed = matches!(fetched, Err(NoAnswer::Closed(_)));
        // Over HTTP/2, what fails the stream before the head makes the answer invalid too.
        let stream_failed = slot.lock().unwrap().end == crate::h2::End::Failed;
        let failure = if stream_failed || matches!(fetched, Err(NoAnswer::Other(_))) { "invalid_header" } else { "error" };
        failed = failure;
        let (mut kept, mut why) = (None, String::new());
        answer = match fetched {
            Ok((resp, conn)) => { kept = Some(conn); Some(resp) }
            Err(NoAnswer::Gone(gone)) => {
                if !gone.is_empty() { log_at(level, r, "info", &gone, &url(&addr, &uri)); }
                Some(Response { status: 499, ..Response::default() })
            }
            // A head that does not come in time, or a connection that is not made, is a timeout.
            Err(NoAnswer::TimedOut(action)) => { why = format!("{TIMED_OUT} while {action}"); Some(special(504)) }
            Err(NoAnswer::Closed(msg) | NoAnswer::Other(msg)) => { why = msg; None }
        };
        // Nothing is known of why a stream of HTTP/2 failed.
        if !why.is_empty() && !stream_failed { log_at(level, r, "error", &why, &url(&addr, &uri)); }
        // More than the head of an answer without a body.
        if counted[0] > 0 && r.method != "HEAD" && answer.as_ref().is_some_and(|a| a.rest.is_none() && !a.upstream.iter().any(|h| h.0.eq_ignore_ascii_case("x-accel-redirect"))) {
            log_at(level, r, "warn", &format!("{MORE} while {}", if level.proxy_buffering { "reading upstream" } else { READING_HEAD }), &url(&addr, &uri));
        }
        time[2] = Some(start.elapsed().as_millis());
        times.push(time);
        bytes.push(counted);
        // An error, or a status proxy_next_upstream names while servers are
        // left to try, goes on to the next server; 403 and 404 are no failures.
        // A kept connection that turns out to be closed, which is in the cache no
        // more, does not use up a try.
        if !(cached && closed && failure == "error") { tries -= 1; }
        let status = answer.as_ref().map(|a| a.status);
        statuses.push(status.unwrap_or(502).to_string());
        // proxy_next_upstream_tries and proxy_next_upstream_timeout end the tries too.
        let timeout = level.proxy_next_upstream_timeout;
        // The page generated for a timeout, rather than an answer of the server.
        let timed_out = answer.as_ref().is_some_and(|a| a.generated);
        let again = if timed_out { next("timeout") } else { status.map_or(next(failure), |s| tries > 0 && next(&format!("http_{s}"))) } && (timeout.is_zero() || first.elapsed() < timeout) && (resend || !begun);
        // The connection of an answer that is not used is closed.
        match kept.filter(|_| !again) {
            // That of HTTP/2 under the pipe, whatever the headers say.
            Some(conn) if level.proxy_h2 => if answer.as_ref().is_some_and(|a| a.rest.is_none()) && (conn.is_some() || slot.lock().unwrap().bodiless) {
                crate::h2::give_back(&slot, (up.clone(), addr, tag, Some(level.proxy_read_timeout).filter(|t| !t.is_zero())));
            }
            conn => if let Some(conn) = conn.flatten() { up.put(conn, addr, tag) },
        }
        // That of one whose body is still to be read goes back after it, when the
        // trailers are taken and the time is noted too.
        if let Some(rest) = answer.as_mut().and_then(|a| a.rest.as_mut()).filter(|_| !again) {
            (rest.started, rest.trailers, rest.to) = (start, trailers, Some((if p.ssl { "https" } else { "http" }, addr, std::mem::take(&mut uri))));
            (rest.slot, rest.home) = (Some(slot).filter(|_| level.proxy_h2), Some((up.clone(), addr, tag)));
        }
        if up.done(i, answer.is_none() || timed_out || again && !matches!(status, Some(403 | 404))) {
            let action = why.rsplit_once(" while ").map_or(READING_HEAD, |w| w.1);
            log_at(level, r, "warn", &format!("upstream server temporarily disabled while {action}"), &url(&addr, &uri));
        }
        if !again || tries == 0 { break; }
        answer = None;
    }
    // A 304 to them gives what is kept, valid again for as long as the 304 says, else as
    // proxy_cache_valid says for the status kept.
    if let (Some(zone), Some(a), Some(e)) = (cache, answer.as_ref().filter(|a| a.status == 304 && !a.generated), stale.as_ref().filter(|_| revalidate)) {
        noted("REVALIDATED");
        let now = crate::clock::seconds();
        let said = crate::cache::said(&a.upstream, &level.proxy_ignore_headers, now).and_then(|(until, updating)| until.map(|u| (u, updating)));
        let valid = said.or_else(|| crate::cache::validity(&level.proxy_cache_valid, e.status).map(|t| (now.saturating_add(t.as_secs() as i64), 0)));
        if let Some(valid) = valid { zone.renew(&key, valid); }
        let mut kept = hit(e.clone());
        (kept.upstream_addr, kept.upstream_status, kept.upstream_time, kept.upstream_bytes) = (Some(addrs.join(", ")), Some(statuses.join(", ")), Some(times), Some(bytes));
        return kept;
    }
    // proxy_cache_use_stale: what the cache keeps is given when the server failed so.
    let condition = answer.as_ref().map_or_else(|| failed.to_string(), |a| if a.generated { "timeout".to_string() } else { format!("http_{}", a.status) });
    if let Some(e) = stale.filter(|_| level.proxy_cache_use_stale.contains(&condition)) { noted("STALE"); return hit(e) }
    let (upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host) = (Some(addrs.join(", ")), Some(statuses.join(", ")), Some(times), Some(bytes), Some(host));
    let Some(mut resp) = answer else { return Response { upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host, ..special(502) } };
    (resp.upstream_addr, resp.upstream_status, resp.upstream_time, resp.upstream_bytes, resp.proxy_host) = (upstream_addr, upstream_status, upstream_time, upstream_bytes, proxy_host);
    // X-Accel-Limit-Rate sets the rate the answer is sent at; X-Accel-Redirect
    // replaces the answer with an internal redirect to its URI.
    let ignored = |name: &str| level.proxy_ignore_headers.iter().any(|i| i == name);
    let accel = |name: &str| resp.upstream.iter().filter(|_| !ignored(name)).find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
    if let Some(rate) = accel("x-accel-limit-rate").and_then(|v| v.parse().ok()) { r.shared.limit_rate.set(rate); }
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
    // The page generated for a timeout keeps its own.
    if hidden("content-type") && !resp.generated { resp.ctype = None; }
    for h in resp.headers.iter_mut().filter(|h| h.0.eq_ignore_ascii_case("set-cookie")) {
        if let Some(cookie) = rewrite_cookie(r, &h.1, level) { h.1 = cookie; }
    }
    resp.relative = !rewrite_redirect(r, level, &mut resp.headers);
    // Conditions are only for what the cache may keep.
    resp.unconditional = cache.is_none();
    // An answer whose status proxy_cache_valid names is read whole and kept.
    // Not before proxy_cache_min_uses requests asked for it, nor when proxy_no_cache says so.
    let no_cache = any_set(&level.proxy_no_cache);
    // Nor one whose Vary is "*", unless proxy_ignore_headers has Vary.
    let vary = if ignored("vary") { Some(Vec::new()) } else { crate::cache::vary(&resp.upstream) };
    let cacheable = !matches!(locked, Some(None)) && uses >= level.proxy_cache_min_uses && !far && !no_cache && vary.is_some();
    // X-Accel-Expires, Cache-Control and Expires say for how long, before proxy_cache_valid.
    let now = crate::clock::seconds();
    let said = cache.filter(|_| cacheable).and_then(|_| crate::cache::said(&resp.upstream, &level.proxy_ignore_headers, now));
    let valid = said.and_then(|(until, updating)| until.or_else(|| crate::cache::validity(&level.proxy_cache_valid, resp.status).map(|t| now.saturating_add(t.as_secs() as i64))).map(|u| (u, updating)));
    if let Some((zone, valid)) = cache.zip(valid) {
        finish(&mut resp, (level, r)).await;
        // One range of what is being cached may be given, read whole as it is.
        (resp.ranges, resp.single_range) = (true, true);
        if resp.cut.is_none() { zone.put((&main, &key), (resp.status, resp.ctype.as_deref().map(str::to_string), resp.headers.clone(), resp.body.clone()), valid, (vary.unwrap_or_default(), &r.headers)); }
    }
    // proxy_force_ranges: one range of any other answer is given too, whatever its Accept-Ranges
    // says, read whole for it.
    if level.proxy_force_ranges && !resp.ranges {
        resp.headers.retain(|h| !h.0.eq_ignore_ascii_case("accept-ranges"));
        if resp.status == 200 { resp.headers.push(("Accept-Ranges".to_string(), "bytes".to_string())); }
        if resp.status == 200 && header(r, "range").is_some() { finish(&mut resp, (level, r)).await; }
        (resp.ranges, resp.single_range) = (true, true);
    }
    resp
}

/// proxy_cache_max_range_offset, as ngx_http_upstream_cache_check_range() reads a
/// "bytes=" Range: false when its first range is a suffix ("-n") or starts at the
/// offset or past it, and for any Range when the offset is 0.
fn range_cacheable(r: &Request, max: Option<u64>) -> bool {
    let (Some(max), Some(v)) = (max, header(r, "range")) else { return true };
    if max == 0 { return false }
    let Some(spec) = v.get(..6).filter(|p| p.eq_ignore_ascii_case("bytes=")).map(|_| v[6..].trim_start_matches(' ')) else { return true };
    if spec.starts_with('-') { return false }
    // What is no number, or too large for one, is no offset.
    let digits = &spec[..spec.find(|c: char| !c.is_ascii_digit()).unwrap_or(spec.len())];
    digits.parse::<u64>().ok().filter(|&o| o <= i64::MAX as u64).is_none_or(|o| o < max)
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
async fn resolved(url: &str, p: &Proxy, level: &Level, r: &Request) -> Option<(String, String, Arc<Upstream>)> {
    let rest = url.strip_prefix("http://")?;
    let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
    if let Some(up) = p.groups.get(host) { return Some((host.to_string(), uri.unwrap_or_else(|| passed(r)), up.clone())); }
    let (name, port) = crate::conf::host_port(host, 80)?;
    // As in nginx, the implicit upstream of a proxy_pass with this host and port comes before the resolver.
    let implicit = p.implicit.lock().unwrap().get(&format!("{}:{port}", name.to_ascii_lowercase())).cloned();
    if let Some(up) = implicit { return Some((host.to_string(), uri.unwrap_or_else(|| passed(r)), up)); }
    let addrs = match name.parse::<IpAddr>() {
        Ok(a) => vec![a],
        Err(_) => level.resolver.as_ref()?.resolve(name, level.resolver_timeout).await?,
    };
    let peers = addrs.into_iter().map(|a| Peer::new(SocketAddr::new(a, port))).collect();
    Some((host.to_string(), uri.unwrap_or_else(|| passed(r)), Arc::new(Upstream::new(peers))))
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

/// Opens a TCP connection to a proxied server, from the bound socket if one is given.
/// A connection that is not made within proxy_connect_timeout is a timeout, answered with 504.
async fn connect(peer: &SocketAddr, socket: Option<socket2::Socket>, level: &Level) -> Result<TcpStream, NoAnswer> {
    // It takes a number, as in nginx.
    number();
    let connect = async {
        match socket {
            Some(socket) => { socket.set_nonblocking(true)?; tokio::net::TcpSocket::from_std_stream(socket.into()).connect(*peer).await }
            None => TcpStream::connect(peer).await,
        }
    };
    tokio::time::timeout(level.proxy_connect_timeout, connect).await.map_err(|_| NoAnswer::TimedOut(CONNECTING))?.map_err(|e: std::io::Error| {
        // Those connect() gives at once, not once the connection is made.
        let to = if matches!(e.raw_os_error(), Some(libc::ENETUNREACH | libc::EADDRNOTAVAIL)) { format!(" to {peer}") } else { String::new() };
        NoAnswer::Closed(format!("connect(){to} failed {} while {CONNECTING}", os_error(&e)))
    })
}

/// Makes the TLS handshake of proxy_pass https:// on a TCP connection; one over
/// TLS stays as it is. A handshake that does not end within proxy_connect_timeout is a
/// timeout, answered with 504.
async fn secure(mut conn: Conn, peer: &SocketAddr, (tls, name): (&Arc<rustls::ClientConfig>, Option<&str>), level: &Level) -> Result<Conn, NoAnswer> {
    use std::io::ErrorKind::{UnexpectedEof, WouldBlock};
    if let Stream::Tcp(s) = conn.stream {
        conn.stream = crate::tls::connect(s, (peer.ip(), name), level.proxy_connect_timeout, tls).await.map_err(|e| match e.kind() {
            WouldBlock => NoAnswer::TimedOut(HANDSHAKING),
            UnexpectedEof => NoAnswer::Closed(format!("peer closed connection in SSL handshake while {HANDSHAKING}")),
            _ if e.raw_os_error().is_some() => NoAnswer::Closed(format!("peer closed connection in SSL handshake {} while {HANDSHAKING}", os_error(&e))),
            _ => NoAnswer::Closed(format!("SSL_do_handshake() failed (SSL: {e}) while {HANDSHAKING}")),
        })?;
    }
    Ok(conn)
}

/// Why there is no answer of a proxied server, as it is logged, if it is not empty.
enum NoAnswer {
    /// The connection failed or was closed before the whole head came.
    Closed(String),
    /// What was done when the time for it had passed.
    TimedOut(&'static str),
    /// The client has gone, or the worker's time to shut down has passed.
    Gone(String),
    /// The answer's head is invalid, or the request's body could not be passed.
    Other(String),
}

const CONNECTING: &str = "connecting to upstream";
const HANDSHAKING: &str = "SSL handshaking to upstream";
const READING_HEAD: &str = "reading response header from upstream";
const TIMED_OUT: &str = "upstream timed out (110: Connection timed out)";
const PREMATURE: &str = "upstream prematurely closed connection";
const MORE: &str = "upstream sent more data than specified in \"Content-Length\" header";

/// Why reading an answer failed: an end of TLS without its alert is an end.
fn read_failed(call: &str, e: &std::io::Error) -> String {
    match (e.raw_os_error(), e.kind()) {
        (Some(_), _) => format!("{call}() failed {}", os_error(e)),
        (None, std::io::ErrorKind::TimedOut) => TIMED_OUT.to_string(),
        (None, std::io::ErrorKind::UnexpectedEof) => PREMATURE.to_string(),
        (None, _) => format!("SSL_read() failed (SSL: {e})"),
    }
}

/// What is logged of a client that went away meanwhile; not of one of HTTP/2.
fn client_gone(client: &Stream, action: &str) -> Option<String> {
    let error = client.tcp()?.take_error().ok().flatten().map_or_else(String::new, |e| format!(" {}", os_error(&e)));
    Some(format!("epoll_wait() reported that client prematurely closed connection, so upstream connection is closed too{error} while {action}"))
}

/// What is invalid in a header line of an answer: what there is of it up to the first
/// character that may not be there.
fn invalid_header(line: &str) -> String {
    let name = line.find(':').unwrap_or(line.len());
    let at = line.bytes().enumerate().position(|(i, c)| if i < name { c <= 0x20 || c == 0x7f } else { name == 0 || i > name && matches!(c, 0 | b'\r') }).unwrap_or(0);
    format!("upstream sent invalid header: \"{}\\x{:02x}...\"", &line[..at], line.as_bytes().get(at).unwrap_or(&b'\r'))
}

/// What is invalid in the headers of an answer that tell its body's length.
fn invalid_length(headers: &[(String, String)]) -> String {
    let (mut length, mut coding): (Option<&(String, String)>, Option<&(String, String)>) = (None, None);
    for h in headers {
        let is_length = h.0.eq_ignore_ascii_case("content-length");
        if !is_length && !h.0.eq_ignore_ascii_case("transfer-encoding") { continue }
        let (same, other) = if is_length { (&mut length, coding) } else { (&mut coding, length) };
        if let Some(before) = same { return format!("upstream sent duplicate header line: \"{}: {}\", previous value: \"{}: {}\"", h.0, h.1, before.0, before.1) }
        if other.is_some() { return "upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time".to_string() }
        if is_length && h.1.parse::<usize>().is_err() { return format!("upstream sent invalid \"Content-Length\" header: \"{}: {}\"", h.0, h.1) }
        if !is_length && !h.1.eq_ignore_ascii_case("chunked") { return format!("upstream sent unknown \"Transfer-Encoding\": \"{}\"", h.1) }
        *same = Some(h);
    }
    String::new()
}

/// Sends a request to a proxied server and reads the head of its answer; the
/// body, if there is one to read, is in the answer's rest. Without one, the
/// connection comes with it only when it may be used for another request: the
/// server does not close it, and nothing came after the head.
#[allow(clippy::too_many_arguments)]
async fn fetch(mut conn: Conn, start: Instant, req: &[u8], level: &Level, mut client: Option<&mut Stream>, (time, bytes): (&mut [Option<u128>; 3], &mut [u64; 3]), rate: &dyn Fn(&Response) -> u64, unread: Option<&mut Unread>, max: u64, (upgrade, hints): (bool, bool)) -> Result<(Response, Option<Conn>), NoAnswer> {
    use NoAnswer::{Closed, Gone, Other, TimedOut};
    let invalid = |msg: &str| Other(format!("{msg} while {READING_HEAD}"));
    let s = &mut conn.stream;
    // proxy_read_timeout: how long each read may wait.
    let wait = Some(level.proxy_read_timeout).filter(|t| !t.is_zero());
    let (mut answer, mut chunk) = (Vec::new(), vec![0u8; 4096]);
    let wrote = async { tokio::io::AsyncWriteExt::write_all(s, req).await?; tokio::io::AsyncWriteExt::flush(s).await }.await;
    wrote.map_err(|e| Closed(format!("writev() failed {} while sending request to upstream", os_error(&e))))?;
    bytes[2] = req.len() as u64;
    // The rest of a body that is not buffered goes on as the client sends it.
    if let Some(u) = unread { bytes[2] += pass_body(u, client.as_deref_mut().ok_or(Other(String::new()))?, max, s).await.ok_or(Other(String::new()))?; }
    let (head, end, status) = loop {
        // A head that does not fit in proxy_buffer_size is too big: the answer is invalid.
        let end = loop {
            let buf = &answer[..answer.len().min(level.proxy_buffer_size)];
            if let Some(end) = line_end(buf).and_then(|at| lines_end(buf, at)) { break end; }
            if answer.len() >= level.proxy_buffer_size { return Err(invalid("upstream sent too big header")); }
            let closed = async { match client.as_deref() { Some(c) => crate::stream::gone(c).await, None => std::future::pending().await } };
            // So does the worker_shutdown_timeout of a worker shutting down.
            let closed = async { tokio::select! { () = closed => true, () = halted() => false } };
            let n = tokio::select! {
                biased;
                gone = closed => {
                    let action = if answer.is_empty() { "sending request to upstream" } else { READING_HEAD };
                    return Err(Gone(client.as_deref().filter(|_| gone).and_then(|c| client_gone(c, action)).unwrap_or_default()))
                }
                n = within(wait, s.read(&mut chunk)) => match n.ok_or(TimedOut(READING_HEAD))? {
                    Ok(0) => return Err(Closed(format!("{PREMATURE} while {READING_HEAD}"))),
                    Ok(n) => n,
                    Err(e) => return Err(Closed(format!("{} while {READING_HEAD}", read_failed("recv", &e)))),
                },
            };
            answer.extend_from_slice(&chunk[..n]);
            bytes[1] = answer.len() as u64;
        };
        let head = crate::vars::text(&answer[..end]);
        let first = head.split('\n').next().unwrap_or_default().trim_end_matches('\r');
        let status: u16 = first.strip_prefix("HTTP/1.").and_then(|f| f.get(2..)?.split(' ').find(|w| !w.is_empty())?.parse().ok()).ok_or_else(|| invalid("upstream sent no valid HTTP/1.0 header"))?;
        if status != 103 { break (head, end, status) }
        // Early hints go to the client, with the headers of the answer that are
        // not hidden, when early_hints lets them and it has any; the answer comes after.
        if first.starts_with("HTTP/1.0") { return Err(invalid("upstream sent HTTP/1.0 response with early hints")) }
        let fields = upstream_lines(&head).map(|l| upstream_header(l).ok_or_else(|| invalid(&invalid_header(l)))).collect::<Result<Vec<_>, _>>()?;
        let lines: String = fields.iter().filter(|(n, _)| !hidden(&level.proxy_hide_header, n)).map(|(n, v)| format!("{n}: {v}\r\n")).collect();
        if let Some(c) = client.as_deref_mut().filter(|c| hints && !lines.is_empty() && !matches!(c, Stream::Pipe(_))) {
            write_all(c, format!("HTTP/1.1 103 Early Hints\r\n{lines}\r\n").as_bytes(), send_timeout(level)).await;
        }
        answer.drain(..end);
    };
    time[1] = Some(start.elapsed().as_millis());
    let version = head.split(['\r', '\n', ' ']).next().unwrap_or_default();
    let mut resp = Response { status, proxied: true, ..Response::default() };
    const HIDDEN: &[&str] = &["date", "server", "connection", "keep-alive", "transfer-encoding", "content-length", "x-pad"];
    for line in upstream_lines(&head) {
        let (name, value) = upstream_header(line).ok_or_else(|| invalid(&invalid_header(line)))?;
        let (lower, value) = (name.to_ascii_lowercase(), value.to_string());
        resp.upstream.push((name.to_string(), value.clone()));
        if lower == "content-type" { resp.ctype = Some(value.into()); continue; }
        // A second Expires is ignored.
        let again = lower == "expires" && resp.headers.iter().any(|h| h.0.eq_ignore_ascii_case("expires"));
        if !again && !HIDDEN.contains(&lower.as_str()) && !lower.starts_with("x-accel-") { resp.headers.push((name.to_string(), value)); }
    }
    // 101 to a request with Upgrade: what came after the head goes to the client first.
    if status == 101 && upgrade { return Ok((Response { body: answer[end..].to_vec(), tunnel: Some(conn.stream), ..resp }, None)); }
    // The body's length: one Content-Length of digits, or one "Transfer-Encoding:
    // chunked" without it; any other mix makes the answer invalid. A HEAD, 204
    // or 304 answer has no body.
    let values = |name: &str| resp.upstream.iter().filter(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone()).collect::<Vec<_>>();
    let (length, chunked) = match (&values("content-length")[..], &values("transfer-encoding")[..]) {
        ([], []) => (None, false),
        ([l], []) => (Some(l.bytes().all(|b| b.is_ascii_digit()).then(|| l.parse::<usize>().ok()).flatten().ok_or_else(|| invalid(&invalid_length(&resp.upstream)))?), false),
        // Over HTTP/2 it says nothing about the body.
        ([], [c]) if c.eq_ignore_ascii_case("chunked") => (None, !level.proxy_h2),
        _ => return Err(invalid(&invalid_length(&resp.upstream))),
    };
    // The body of an answer that redirects with X-Accel-Redirect is not read.
    let accel = resp.upstream.iter().any(|h| h.0.eq_ignore_ascii_case("x-accel-redirect"));
    let no_body = req.starts_with(b"HEAD ") || [204, 304].contains(&status);
    // An informational answer (1xx) has another after it; the body that is not
    // read for X-Accel-Redirect would come before the next answer.
    let skipped = accel && !no_body && length != Some(0);
    let keep = status >= 200 && !closes(version, &values("connection")) && !skipped;
    let told = no_body.then_some(length);
    let (length, chunked) = if no_body || accel { (Some(0), false) } else { (length, chunked) };
    if length == Some(0) {
        (bytes[0], bytes[1]) = ((answer.len() - end) as u64, answer.len() as u64);
        return Ok((Response { told, ..resp }, Some(conn).filter(|_| keep && answer.len() == end)));
    }
    // X-Accel-Buffering, the last of them that is "yes" or "no", comes before proxy_buffering.
    let buffering = values("x-accel-buffering").iter().rev().find_map(|v| match v.to_ascii_lowercase().as_str() { "yes" => Some(true), "no" => Some(false), _ => None }).unwrap_or(level.proxy_buffering);
    let (first, (count, size)) = (level.proxy_buffer_size, level.proxy_buffers);
    let sizes = if buffering { Ok(Sizes { first, count, size, busy: level.proxy_busy_buffers_size.unwrap_or(2 * first.max(size)) }) } else { Err(first) };
    // proxy_limit_rate is for answers that are buffered.
    let rate = if buffering { rate(&resp) } else { 0 };
    Ok((Response { rest: Some(Box::new(Rest { conn, answer, end, length, chunked, rate, started: start, wait, keep, home: None, trailers: None, slot: None, sizes, coder: None, to: None })), unbuffered: !buffering, ..resp }, None))
}

/// Whether a header of a proxied server's early hints is hidden, as those of
/// proxy_hide_header and those nginx hides by default are.
fn hidden(hide: &[String], name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["date", "server", "x-pad"].contains(&lower.as_str()) || lower.starts_with("x-accel-") || hide.contains(&lower)
}

/// The header lines of the head of a proxied server's answer, up to the empty line that
/// ends it, without those that look like another status line, which nginx ignores.
fn upstream_lines(head: &str) -> impl Iterator<Item = &str> {
    head.split('\n').skip(1).take_while(|l| !matches!(*l, "" | "\r")).filter(|l| !l.starts_with("HTTP/")).map(|l| l.trim_end_matches('\r'))
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

/// Reads a proxied answer's body up to its length, up to its last chunk, until
/// its chunks are malformed, or until the server closes the connection; what follows
/// the last chunk is dropped, but read up to the empty line after the trailer
/// lines, where the body ends for nginx. With a rate it is read as ngx_event_pipe_read_upstream()
/// paces proxy_limit_rate: by the end of each second since the body started
/// (counted in whole seconds of the clock) up to the rate for each second has
/// been read, and when that much has, it waits for the time it is worth, as it
/// does after each read for what that read is worth.
/// Returns the body, with what came of the chunk it is cut off in, the bytes read
/// after the head, whether they end where the body does, and the cut, when
/// the server closed the connection before the body's end, or a read failed or
/// waited longer than the time, or the chunks are malformed. Over HTTP/2, the slot
/// says whether the connection's end is the body's; the frames that fail an answer
/// before any of the body are as malformed chunks. Last is what is logged of the cut.
async fn read_body(s: &mut Stream, after: &[u8], length: Option<usize>, chunked: bool, rate: u64, wait: Option<Duration>, slot: Option<&crate::h2::Slot>) -> (Vec<u8>, usize, bool, Option<Box<Cut>>, String) {
    let (mut intake, mut chunk, mut failed, mut malformed, mut why) = (Intake::new(rate, after.len()), vec![0u8; 4096], false, false, PREMATURE.to_string());
    let (mut body, mut data, mut read) = (Body::new(length.map(|n| n as u64), chunked), Vec::new(), after.len());
    let mut came = body.take(after, &mut data);
    while came == Came::More {
        let n = match read_piece(s, &mut chunk, (&mut intake, read), wait).await {
            Ok(n) => n,
            Err(e) => { (failed, why) = (true, read_failed("readv", &e)); break }
        };
        if n == 0 {
            if let Some(slot) = slot {
                (failed, malformed) = ended_over_h2(slot);
                // Nothing is known of why a stream of HTTP/2 failed.
                if malformed { why.clear(); }
            }
            malformed &= data.is_empty();
            break;
        }
        read += n;
        came = body.take(&chunk[..n], &mut data);
    }
    let cut = body.cut(failed).then(|| Box::new(Cut { length, malformed: malformed || came == Came::Malformed, failed: None }));
    if came == Came::Malformed { why = "upstream sent invalid chunked response".to_string(); }
    let why = if cut.is_none() || why.is_empty() { String::new() } else { format!("{why} while reading upstream") };
    (data, read, came == Came::Whole { followed: false }, cut, why)
}

/// How the reads of an answer's body are paced (proxy_limit_rate): the rate, the second
/// the body started in, and when the next read may be.
struct Intake { rate: i64, start: i64, until: Option<Instant> }

impl Intake {
    /// At the rate, with so much read with the head.
    fn new(rate: u64, read: usize) -> Intake {
        let mut intake = Intake { rate: rate as i64, start: if rate == 0 { 0 } else { seconds() }, until: None };
        intake.took(read);
        intake
    }

    /// Nothing is read for the time what was read is worth.
    fn took(&mut self, n: usize) {
        let delay = if self.rate == 0 { 0 } else { (n as i64).saturating_mul(1000) / self.rate };
        if delay > 0 { self.until = Some(Instant::now() + Duration::from_millis(delay as u64)); }
    }

    /// How much may be read, with so much read before, once any may. When this is dropped,
    /// the time goes on.
    async fn limit(&mut self, read: usize) -> usize {
        if self.rate == 0 { return usize::MAX }
        loop {
            if let Some(until) = self.until { tokio::time::sleep_until(until.into()).await; }
            let limit = self.rate.saturating_mul(seconds() - self.start + 1) - read as i64;
            self.until = (limit <= 0).then(|| Instant::now() + Duration::from_millis((-limit * 1000 / self.rate + 1) as u64));
            if limit > 0 { return limit as usize }
        }
    }
}

/// Reads a piece of a proxied answer's body into the buffer, as it is paced, with so much
/// of it read before; an error when the read fails or waits longer than the time.
async fn read_piece(s: &mut Stream, buf: &mut [u8], (intake, read): (&mut Intake, usize), wait: Option<Duration>) -> std::io::Result<usize> {
    let limit = intake.limit(read).await.min(buf.len());
    let got = within(wait, s.read(&mut buf[..limit])).await.unwrap_or_else(|| Err(std::io::ErrorKind::TimedOut.into()));
    if let Ok(n) = got { intake.took(n); }
    got
}

/// Whether an answer over HTTP/2 whose connection has ended is cut off, and whether a
/// frame failed it.
fn ended_over_h2(slot: &crate::h2::Slot) -> (bool, bool) {
    let end = slot.lock().unwrap().end;
    (end != crate::h2::End::Whole, end == crate::h2::End::Failed)
}

/// Whether a proxied server closes the connection after its answer, as nginx
/// finds it: the version of the status line is not HTTP/1.1 or a later 1.x, or
/// a Connection header has "close" anywhere in it.
fn closes(version: &str, connection: &[String]) -> bool {
    !matches!(version.strip_prefix("HTTP/1.").map(str::as_bytes), Some([b'1'..=b'9'])) || connection.iter().any(|v| v.to_ascii_lowercase().contains("close"))
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

/// A body read as it is passed on (proxy_request_buffering off): the
/// bytes left of a body with a Content-Length, or what
/// has come of a chunked one and how much of its data was passed; and, once
/// a chunked body ended, what came after it.
#[derive(Debug)]
pub struct Unread { left: u64, chunked: Option<(Vec<u8>, usize)>, rest: Vec<u8> }

/// Data as one chunk.
fn chunk(data: &[u8]) -> Vec<u8> {
    [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat()
}

/// Reads the rest of a body from the client and writes it as it comes: the
/// bytes of a body with a Content-Length as they are, the data of a chunked
/// one in a chunk for each read, with the last chunk once it ends, and returns
/// how many bytes it wrote ($upstream_bytes_sent). None when
/// the client closes, the body is invalid or the writing fails.
async fn pass_body<C: AsyncRead + Unpin, W: AsyncWrite + Unpin>(u: &mut Unread, client: &mut C, max: u64, to: &mut W) -> Option<u64> {
    let (mut buf, mut written) = (vec![0u8; 4096], 0);
    let Some((raw, sent)) = &mut u.chunked else {
        while u.left > 0 {
            let got = client.read(&mut buf[..u.left.min(4096) as usize]).await.ok().filter(|g| *g > 0)?;
            u.left -= got as u64;
            if !write_all(to, &buf[..got], None).await { return None }
            written += got as u64;
        }
        return Some(written);
    };
    loop {
        let (data, used) = decode_chunked(raw, max).ok()?;
        let mut out = if data.len() > *sent { chunk(&data[*sent..]) } else { Vec::new() };
        *sent = data.len();
        if used.is_some() { out.extend_from_slice(b"0\r\n\r\n"); }
        if !write_all(to, &out, None).await { return None }
        written += out.len() as u64;
        if let Some(used) = used { u.rest = raw.split_off(used); u.chunked = None; return Some(written); }
        let got = client.read(&mut buf).await.ok().filter(|g| *g > 0)?;
        raw.extend_from_slice(&buf[..got]);
    }
}

/// Fills the request from its head, or gives the status nginx refuses it with.
fn parse(r: &mut Request, head: &[u8], level: &Level, h2: bool) -> Result<(), u16> {
    let text = std::str::from_utf8(head).map_or_else(|_| Cow::Owned(crate::vars::text(head)), Cow::Borrowed);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    r.line = lines.next().unwrap_or_default().to_string();
    let mut words = r.line.split(' ').filter(|w| !w.is_empty());
    // HTTP/0.9, which has no version, has only GET.
    let (method, target, version) = match [(); 4].map(|()| words.next()) { [Some(m), Some(t), Some(v), None] => (m, t, v), [Some(m @ "GET"), Some(t), None, _] => (m, t, ""), _ => return Err(400) };
    r.method = method.to_string();
    let valid_method = method.bytes().all(|c| c.is_ascii_uppercase() || c == b'_' || c == b'-');
    // HTTP/2.0 is the version of a request of an HTTP/2 stream (crate::h2).
    if !valid_method || !(matches!(version, "HTTP/1.0" | "HTTP/1.1" | "") || h2 && version == "HTTP/2.0") { return Err(400); }
    for line in lines.filter(|l| !l.is_empty()) {
        let Some((name, value)) = header_line(line, level)? else { continue };
        r.headers.push((name.to_string(), value.trim_matches([' ', '\t']).to_string()));
    }
    // Headers nginx takes only once: a second one is refused.
    const UNIQUE: &[&str] = &["if-modified-since", "if-unmodified-since", "if-match", "if-none-match", "content-length",
                              "content-range", "if-range", "transfer-encoding", "expect", "authorization"];
    let mut seen = 0u16;
    for i in r.headers.iter().filter_map(|(n, _)| UNIQUE.iter().position(|u| n.eq_ignore_ascii_case(u))) {
        if seen & 1 << i != 0 { return Err(400); }
        seen |= 1 << i;
    }
    let mut hosts = r.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("host")).map(|(_, v)| v);
    let host = hosts.next();
    if hosts.next().is_some() || (host.is_none() && version == "HTTP/1.1") { return Err(400); }
    r.host = host.map(|h| valid_host(h).ok_or(400u16)).transpose()?;
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
    // A path with nothing to decode, merge or resolve is the URI as it is.
    let mut uri = Cow::Borrowed(path.split('?').next().unwrap_or_default());
    if uri.contains('%') { uri = decode(&uri).ok_or(400u16)?.into(); }
    if level.merge_slashes && uri.contains("//") { uri = merge_slashes(&uri).into(); }
    if uri.contains("/.") { uri = dots(&uri).ok_or(400u16)?.into(); }
    r.uri = uri.into_owned();
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
    crate::vars::bytes(s).into_iter().map(|c| if plain(c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
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
/// Whether a server speaks HTTP/2 on a listening address: http2 is on in
/// it, or any server listens on the address with "http2".
pub fn http2(config: &Config, listen: SocketAddr, server: &Server) -> bool {
    server.level.http2 || config.servers.iter().any(|s| s.http2.contains(&listen))
}

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
    // As nginx reads it, "close" anywhere in the value closes; else "keep-alive" keeps alive.
    connection.map_or(http11, |c| !c.contains("close") && (http11 || c.contains("keep-alive")))
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
pub(crate) mod tests {
    use super::*;
    use crate::stream::block_on;
    use std::net::TcpStream;
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt;
    use std::thread;

    /// What the tests that count in BUSY, or wait for it, run one at a time under.
    fn counted() -> std::sync::MutexGuard<'static, ()> {
        static COUNTED: Mutex<()> = Mutex::new(());
        COUNTED.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn listens_with_the_backlog() {
        let l = listen("127.0.0.1:0".parse().unwrap(), 511).unwrap();
        let addr = l.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        assert_eq!(l.accept().unwrap().1.ip(), addr.ip());
        assert!(listen(addr, 511).is_err());
    }

    #[test]
    fn the_future_of_a_connection_is_small() {
        let config = crate::conf::build(&crate::config::parse("http { server { } }", std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        block_on(async {
            let Stream::Tcp(stream) = pair().await.0 else { unreachable!() };
            let addr = "127.0.0.1:80".parse().unwrap();
            // Not counted in BUSY, which another test waits for, so not dropped either.
            let future = std::mem::ManuallyDrop::new(serving(Arc::new(config), stream, false, (addr, addr, (addr, 0)), Busy));
            let size = size_of_val(&future);
            assert!(size < 4096, "{size} bytes");
        });
    }

    #[test]
    fn max_ranges_limits_ranges() {
        let ranged = |max, h: &str| {
            let mut resp = Response { status: 200, body: b"0123456789".to_vec(), ranges: true, headers: vec![("Accept-Ranges".into(), "bytes".into())], ..Response::default() };
            range(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, &Level { max_ranges: max, ..Level::default() }, &mut resp);
            (resp.status, resp.headers.len())
        };
        assert_eq!(ranged(Some(0), "Range: bytes=1-2"), (200, 0));
        assert_eq!(ranged(Some(1), "Range: bytes=1-2,4-5"), (200, 1));
        assert_eq!(ranged(Some(2), "Range: bytes=1-2,4-5").0, 206);
        assert_eq!(ranged(None, "Range: bytes=1-2").0, 206);
    }

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

    /// What exchange() writes to a client for a GET of a server.
    fn exchanged(s: &Server, target: &str) -> String {
        String::from_utf8(exchanged_bytes(s, target)).unwrap()
    }

    fn exchanged_bytes(s: &Server, target: &str) -> Vec<u8> {
        block_on(async {
            let (mut stream, mut out) = pair().await;
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            exchange(&mut stream, s, &r, Ok(()), location(s, &r.uri), "127.0.0.1:8080".parse().unwrap(), &[]).await;
            drop(stream);
            let mut got = Vec::new();
            out.read_to_end(&mut got).await.unwrap();
            got
        })
    }

    #[test]
    fn writes_the_head() {
        // A byte that is not UTF-8 is sent as it is, and UTF-8 text too.
        let byte = crate::vars::text(b"/\xff");
        let text = format!("http {{ server {{ keepalive_timeout 5 9; location / {{ add_header X \"\u{e9}\"; return 302 {byte}; }} location /a {{ return 200 ok; }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let got = exchanged_bytes(&config.servers[0], "/");
        let has = |part: &[u8]| got.windows(part.len()).any(|w| w == part);
        assert!(has(b"HTTP/1.1 302 Moved Temporarily\r\nServer: ") && has(b":8080/\xff\r\n") && has("X: \u{e9}\r\n\r\n".as_bytes()), "{}", String::from_utf8_lossy(&got));
        let got = exchanged(&config.servers[0], "/a");
        let (head, date) = got.split_once("Date: ").unwrap();
        assert_eq!((head, &date[29..]), (format!("HTTP/1.1 200 OK\r\nServer: {NAME}\r\n").as_str(), "\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"));
    }

    /// A connection accepted on the event loop, and the other end.
    async fn pair() -> (Stream, tokio::net::TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        (Stream::Tcp(l.accept().await.unwrap().0), other)
    }

    /// Serves a connection, which counts in BUSY, for a server with the
    /// directives: the client's end, and the task.
    async fn served(directives: &str) -> (tokio::net::TcpStream, JoinHandle<()>) {
        served_by(&format!("server {{ {directives} }}")).await
    }

    /// The same for the http block's directives, with the server.
    pub(crate) async fn served_by(directives: &str) -> (tokio::net::TcpStream, JoinHandle<()>) {
        let text = format!("http {{ {directives} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let (Stream::Tcp(stream), client) = pair().await else { unreachable!() };
        let addr = "127.0.0.1:80".parse().unwrap();
        (client, tokio::task::spawn_local(serving(Arc::new(config), stream, false, (addr, addr, (addr, 0)), Busy::new())))
    }

    #[test]
    fn lingers_only_when_told_to_with_nothing_unread() {
        let _busy = counted();
        for (directive, lingers) in [("", false), ("lingering_close on;", false), ("lingering_close off;", false), ("lingering_close always;", true)] {
            block_on(async {
                let (mut client, mut task) = served(&format!("{directive} location / {{ return 200 ok; }}")).await;
                client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").await.unwrap();
                let mut text = String::new();
                client.read_to_string(&mut text).await.unwrap();
                assert!(text.starts_with("HTTP/1.1 200 ") && text.ends_with("\r\n\r\nok"), "{text}");
                // Lingering waits for the client to close, up to 5 seconds.
                let ended = within(Some(Duration::from_secs(1)), &mut task).await;
                assert_eq!(ended.is_none(), lingers, "{directive}");
                drop(client);
                if lingers { within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap(); }
            });
        }
    }

    /// Sends the start of a request, then more, slowly, whatever comes back:
    /// the whole answer does, with the status and the end, and no reset.
    fn answered_while_sending(directives: &str, start: &str, (status, end): (u16, &str)) {
        let _busy = counted();
        block_on(async {
            let (mut client, task) = served(directives).await;
            client.write_all(start.as_bytes()).await.unwrap();
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                client.write_all(&[b'x'; 16384]).await.unwrap();
            }
            let mut text = String::new();
            client.read_to_string(&mut text).await.unwrap();
            assert!(text.starts_with(&format!("HTTP/1.1 {status} ")) && text.ends_with(end), "{text}");
            drop(client);
            within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
        });
    }

    #[test]
    fn refusing_a_body_resets_nothing() {
        answered_while_sending("client_max_body_size 1k;", "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 491520\r\n\r\n", (413, "</html>\r\n"));
    }

    #[test]
    fn refusing_a_head_resets_nothing() {
        answered_while_sending("", "GET / HTTP/1.1\r\nNo-Host: a\r\n\r\n", (400, "</html>\r\n"));
    }

    #[test]
    fn refusing_a_long_line_resets_nothing() {
        answered_while_sending("", &format!("GET /{}", "a".repeat(10000)), (414, "</html>\r\n"));
    }

    #[test]
    fn closing_with_pipelined_data_resets_nothing() {
        answered_while_sending("location / { return 200 ok; }", "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nextra", (200, "\r\n\r\nok"));
    }

    #[test]
    fn closing_with_data_on_the_socket_resets_nothing() {
        // The answer takes longer than what comes meanwhile, which is not read.
        let body = "b".repeat(1000);
        answered_while_sending(&format!("location / {{ limit_rate 500; return 200 {body}; }}"), "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", (200, &body));
    }

    /// Serves a connection whose client sends the parts, each after a wait of so
    /// many milliseconds: the $request_time of each of its requests, as logged,
    /// and how long the rest of the answers took from the last part on.
    async fn timed(name: &str, parts: &[(u64, &str)]) -> (Vec<f64>, Duration) {
        // A test of shutting down leaves it set, which closes connections.
        SHUTTING.store(false, Ordering::SeqCst);
        let log = std::env::temp_dir().join(format!("twinx-timed-{name}-{}", std::process::id()));
        let (file, body) = (log.display(), "b".repeat(2500));
        let (mut client, task) = served_by(&format!("log_format f $request_time; server {{ access_log {file} f; location / {{ return 200 ok; }} location /slow {{ limit_rate 1000; return 200 {body}; }} }}")).await;
        let mut sent = Instant::now();
        for (wait, part) in parts {
            tokio::time::sleep(Duration::from_millis(*wait)).await;
            client.write_all(part.as_bytes()).await.unwrap();
            sent = Instant::now();
        }
        client.read_to_end(&mut Vec::new()).await.unwrap();
        let took = sent.elapsed();
        drop(client);
        task.await.unwrap();
        let times = std::fs::read_to_string(&log).unwrap().lines().map(|l| l.parse().unwrap()).collect();
        std::fs::remove_file(log).unwrap();
        (times, took)
    }

    #[test]
    fn the_clock_of_a_request_starts_at_its_first_bytes() {
        let _busy = counted();
        const KEPT: &str = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        const LAST: &str = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        block_on(async {
            let piped = format!("GET /slow HTTP/1.1\r\nHost: a\r\n\r\n{LAST}");
            // The parts are read a little more or less than 0.55 s apart.
            let parts = [(0, KEPT), (700, &LAST[..20]), (550, &LAST[20..])];
            let piped = [(0, piped.as_str())];
            let (first, idle, parts, piped) = tokio::join!(
                timed("first", &[(700, LAST)]),
                timed("idle", &[(0, KEPT), (1200, LAST)]),
                timed("parts", &parts),
                timed("piped", &piped),
            );
            assert!(matches!(first.0[..], [a] if a < 0.2), "{first:?}");
            assert!(matches!(idle.0[..], [a, b] if a < 0.2 && b < 0.2), "{idle:?}");
            assert!(matches!(parts.0[..], [a, b] if a < 0.2 && (0.5..0.9).contains(&b)), "{parts:?}");
            // The pipelined request waits for the answer before it, 1 or 2 s long at its rate.
            assert!(matches!(piped.0[..], [a, b] if a >= 0.9 && b < 0.2), "{piped:?}");
        });
    }

    #[test]
    fn limit_rate_does_not_count_the_idle_wait() {
        let _busy = counted();
        const SLOW: &str = "GET /slow HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        block_on(async {
            let (first, idle) = tokio::join!(
                timed("paced", &[(0, SLOW)]),
                timed("paced-idle", &[(0, "GET / HTTP/1.1\r\nHost: a\r\n\r\n"), (2200, SLOW)]),
            );
            // What goes before the last write is worth 1 or 2 s, by what part of a second it starts
            // in; the idle wait, counted too, would let the whole answer go at once.
            assert!(first.1 >= Duration::from_millis(900) && idle.1 >= Duration::from_millis(900), "{first:?} {idle:?}");
        });
    }

    #[test]
    fn tunnel_passes_data_both_ways() {
        block_on(async {
            let ((mut accepted, mut client), (up, mut server)) = (pair().await, pair().await);
            let t = tokio::task::spawn_local(async move { tunnel(&mut accepted, up, b"early", (Some(Duration::from_secs(5)), None)).await });
            let mut buf = [0u8; 4];
            let mut early = [0u8; 5];
            server.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early");
            client.write_all(b"ping").await.unwrap();
            server.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").await.unwrap();
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
            // The proxied server closing ends the client's connection too.
            drop(server);
            assert_eq!(client.read(&mut buf).await.unwrap(), 0);
            assert_eq!(t.await.unwrap(), 4);
            // So does a client that sends nothing for proxy_read_timeout.
            let ((mut accepted, _client), (up, mut server)) = (pair().await, pair().await);
            assert_eq!(tunnel(&mut accepted, up, b"", (Some(Duration::from_millis(50)), None)).await, 0);
            assert_eq!(server.read(&mut buf).await.unwrap(), 0);
        });
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
        let _busy = counted();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let text = format!("http {{ server {{ listen {addr}; location / {{ return 200 done; }} }} }}");
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap());
        let mut client = TcpStream::connect(addr).unwrap();
        let writer = thread::spawn(move || {
            // The connection was accepted before its request came: shutting down waits for it.
            thread::sleep(Duration::from_millis(300));
            client.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
            let mut text = String::new();
            client.read_to_string(&mut text).unwrap();
            text
        });
        block_on(async {
            let accepting = accept(config, &[(l, addr)]).unwrap();
            while BUSY.load(Ordering::SeqCst) == 0 { tokio::time::sleep(Duration::from_millis(1)).await; }
            let started = Instant::now();
            shut_down(accepting, None).await;
            assert!(started.elapsed() >= Duration::from_millis(200));
        });
        let text = writer.join().unwrap();
        assert!(text.starts_with("HTTP/1.1 200 ") && text.ends_with("done"), "{text}");
        // worker_shutdown_timeout: a request that does not come is not waited for longer.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let config = Arc::new(crate::conf::build(&crate::config::parse(&format!("http {{ server {{ listen {addr}; }} }}"), std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap());
        let _idle = TcpStream::connect(addr).unwrap();
        block_on(async {
            let accepting = accept(config, &[(l, addr)]).unwrap();
            while BUSY.load(Ordering::SeqCst) == 0 { tokio::time::sleep(Duration::from_millis(1)).await; }
            let started = Instant::now();
            shut_down(accepting, Some(Duration::from_millis(100))).await;
            assert!(started.elapsed() < Duration::from_secs(2));
            // The timeout passed with a request left: what waits for proxied servers ends.
            assert!(tokio::time::timeout(Duration::from_secs(1), halted()).await.is_ok());
        });
        HALTED.store(false, Ordering::SeqCst);
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
            shared: Default::default(),
            ssl: None,
        };
        (parse(&mut r, head.as_bytes(), &Level::default(), false), r)
    }

    #[test]
    fn ignores_invalid_headers() {
        let names = |head: &str, ignore: bool, underscores: bool| {
            let level = Level { ignore_invalid_headers: ignore, underscores_in_headers: underscores, ..Level::default() };
            let mut r = request("GET / HTTP/1.0\n\n").1;
            parse(&mut r, head.as_bytes(), &level, false).map(|()| r.headers.iter().map(|h| h.0.clone()).collect::<Vec<_>>())
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
        // Up to the empty line; a line with more CRs is not empty, and one like a status line is ignored.
        assert_eq!(upstream_lines("HTTP/1.1 200\r\nA: b\r\r\nHTTP/1.1 301 x: \0\r\n\r\r\nC\n\r\n").collect::<Vec<_>>(), ["A: b", "", "C"]);
        assert_eq!(upstream_lines("HTTP/1.1 200\nHTTP: b\n\n").collect::<Vec<_>>(), ["HTTP: b"]);
    }

    #[test]
    fn head_end_with_lf_and_crlf() {
        assert_eq!(head_end(b"GET / HTTP/1.0\nHost: a\n\nrest"), Some(24));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n\r\n"), Some(18));
        let level = Level { proxy_hide_header: vec!["x-b".into()], ..Level::default() };
        assert_eq!(["Date", "X-Accel-A", "x-pad", "X-B", "Link"].map(|n| hidden(&level.proxy_hide_header, n)), [true, true, true, true, false]);
        // A status line without a reason is no HTTP/0.9 request line.
        let answer = b"HTTP/1.1 103 \r\nLink: a\r\n\r\nHTTP/1.1 200 \r\n";
        assert_eq!((head_end(answer), line_end(answer).and_then(|at| lines_end(answer, at))), (Some(15), Some(26)));
        assert_eq!(head_end(b"GET / HTTP/1.0\r\n"), None);
        assert_eq!(head_end(b"GET /\r\nextra"), Some(7));
        // The first empty line ends the head, whichever way its lines end.
        assert_eq!(head_end(b"GET / HTTP/1.0\r\nA: b\n\r\n\n\n"), Some(23));
        assert_eq!((head_end(b"\nGET / HTTP/1.0\n\nx"), head_end(b"\r\n\r\n"), head_end(b"GET / HTTP/1.0\n\r")), (Some(17), Some(4), None));
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
        // "close" anywhere in the value closes, as for nginx; else "keep-alive" anywhere keeps alive.
        for (version, connection, kept) in [("1.1", "te, close", false), ("1.0", "Keep-Alive, te", true), ("1.0", "keep-alive, close", false), ("1.0", "te", false), ("1.1", "te", true)] {
            let (_, r) = request(&format!("GET / HTTP/{version}\nHost: a\nConnection: {connection}\n\n"));
            assert_eq!(keepalive(&r), kept, "{version} {connection}");
        }
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
        assert_eq!(request("GET / HTTP/1.0\nIf-Range: a\nAccept: b\nAccept: c\n\n").0, Ok(()));
        assert_eq!(request("GET / HTTP/1.0\nIf-Range: a\nif-range: b\n\n").0, Err(400));
        assert_eq!(request("GET / HTTP/1.0 x\n\n").0, Err(400));
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

    /// Connects to a server and fetches its answer to a GET request.
    async fn fetched(addr: &SocketAddr, socket: Option<socket2::Socket>, level: &Level, (time, bytes): (&mut [Option<u128>; 3], &mut [u64; 3]), rate: &dyn Fn(&Response) -> u64) -> Option<Response> {
        let start = Instant::now();
        let s = connect(addr, socket, level).await.ok()?;
        time[0] = Some(start.elapsed().as_millis());
        fetch(Conn::new(Stream::Tcp(s), start), start, b"GET / HTTP/1.0\r\n\r\n", level, None, (time, bytes), rate, None, 0, (false, false)).await.ok().map(|(resp, _)| resp)
    }

    #[test]
    fn fetches_from_a_server() {
        let _busy = serving_on();
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
        let resp = block_on(async {
            let mut resp = fetched(&addr, None, &level, (&mut time, &mut bytes), &|_| 0).await.unwrap();
            resp.upstream_bytes = Some(vec![bytes]);
            finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
            resp
        });
        assert!(time[0].is_some() && time[1].is_some());
        // The body, the whole answer and the request, in bytes.
        assert_eq!(resp.upstream_bytes.unwrap(), [[4, 80, 18]]);
        assert_eq!((resp.status, resp.ctype.as_deref(), resp.body.as_slice()), (201, Some("a/b"), &b"body"[..]));
        assert_eq!(resp.headers, vec![("X-A".to_string(), "1".to_string())]);
        assert_eq!(resp.upstream.iter().map(|h| h.0.as_str()).collect::<Vec<_>>(), ["Server", "Content-Type", "X-A", "X-Accel-B"]);
    }

    #[test]
    fn intercepts_errors_of_proxied_servers() {
        let _busy = serving_on();
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
        let answer = |target: &str| exchanged(s, target);
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
    fn speaks_http2_where_the_address_or_the_server_says_so() {
        let text = "events {} http { server { listen 127.0.0.1:8080; server_name one; } server { listen 127.0.0.1:8080 http2; server_name two; } server { listen 127.0.0.1:8081; server_name three; } server { listen 127.0.0.1:8081; server_name four; http2 on; } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let on = |addr: &str, name: &str| http2(&config, addr.parse().unwrap(), server(&config, addr.parse().unwrap(), Some(name)).0);
        // "listen ... http2" makes every server of the address speak it, http2 only its own.
        assert!(on("127.0.0.1:8080", "one") && on("127.0.0.1:8080", "two"));
        assert!(!on("127.0.0.1:8081", "three") && on("127.0.0.1:8081", "four"));
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
        let get = |target: &str| exchanged(s, target);
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
        let get = |target: &str| exchanged(s, target);
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
        let _busy = serving_on();
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
        assert_eq!(block_on(fetched(&addr, socket, &level, (&mut [None; 3], &mut [0; 3]), &|_| 0)).unwrap().status, 200);
        assert_eq!(from.join().unwrap().ip().to_string(), "127.0.0.2");
        let taken = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(bound(&addr, (taken, false)).is_some());
        assert!(bound(&addr, ("192.0.2.1:0".parse().unwrap(), false)).is_none());
    }

    #[test]
    fn reads_proxied_answers_at_the_rate() {
        let _busy = serving_on();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.read(&mut [0u8; 1024]).unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 12000\r\nX-Rate: 4000\r\n\r\n").unwrap();
            s.write_all(&[b'x'; 12000]).unwrap();
        });
        let level = Level { proxy_buffering: true, proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(5), ..Level::default() };
        let rate = |resp: &Response| resp.upstream.iter().find(|h| h.0 == "X-Rate").map_or(0, |h| h.1.parse().unwrap());
        block_on(async {
            let mut resp = fetched(&addr, None, &level, (&mut [None; 3], &mut [0; 3]), &rate).await.unwrap();
            // The body is read after the head, 4000 bytes (what came with the head too)
            // in each second of the clock, and nothing for the time they are worth after
            // each read: the last at most 4096 of them.
            assert!(resp.body.is_empty() && resp.rest.is_some());
            resp.upstream_time = Some(vec![[None; 3]]);
            let started = Instant::now();
            finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
            assert!(started.elapsed() >= Duration::from_millis(1900));
            assert_eq!((resp.body.len(), resp.rest.is_none()), (12000, true));
            assert!(resp.upstream_time.unwrap()[0][2].is_some());
        });
    }

    /// What comes back for the requests sent at once on a connection, until it is
    /// closed, without the Date lines, when a server's location has the
    /// directives and passes them to a server that sends the answer to each and closes
    /// the connection; and how many requests came to that one.
    fn passed_on(answer: &str, directives: &str, requests: &str) -> (Vec<u8>, usize) {
        let _busy = counted();
        // A test of shutting down leaves it set, which closes connections.
        SHUTTING.store(false, Ordering::SeqCst);
        HALTED.store(false, Ordering::SeqCst);
        let (addr, came) = closing(answer.to_string().leak());
        let text = block_on(received(&format!("server {{ location /e {{ return 200 e; }} location / {{ proxy_pass http://{addr}; {directives} }} }}"), requests));
        let came = *came.lock().unwrap();
        (text, came)
    }

    /// What comes back for the requests sent at once on a connection, until it is
    /// closed, without the Date lines, with the http block's directives.
    async fn received(directives: &str, requests: &str) -> Vec<u8> {
        let (mut client, task) = served_by(directives).await;
        client.write_all(requests.as_bytes()).await.unwrap();
        let mut got = Vec::new();
        within(Some(Duration::from_secs(4)), client.read_to_end(&mut got)).await.unwrap().unwrap();
        drop(client);
        within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
        let mut text = Vec::new();
        for line in got.split_inclusive(|&c| c == b'\n').filter(|l| !l.starts_with(b"Date: ")) { text.extend_from_slice(line); }
        text
    }

    pub(crate) const LENGTH: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 30000\r\n\r\n";
    pub(crate) const CHUNKED: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n";

    /// What a location has besides, if anything, for its answers to be read without
    /// and with a rate.
    const RATES: [&str; 2] = ["", "proxy_limit_rate 1m;"];

    /// The head of an answer with the Content-Length or Transfer-Encoding line, if
    /// any, and the Connection header.
    fn head(line: &str, connection: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nServer: {NAME}\r\nContent-Type: text/html\r\n{line}Connection: {connection}\r\n\r\n")
    }

    #[test]
    fn answers_cut_off_are_sent_so() {
        let big = "x".repeat(20000);
        let (http11, http10, keep) = ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GET / HTTP/1.0\r\n\r\n", "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        let (length, chunked) = (head("Content-Length: 30000\r\n", "keep-alive"), head("Transfer-Encoding: chunked\r\n", "keep-alive"));
        for (answer, directives, request, want) in [
            (format!("{CHUNKED}2\r\nab\r\n"), "", http11, format!("{chunked}2\r\nab\r\n")),
            (format!("{CHUNKED}4e20\r\n{big}\r\n"), "", http11, format!("{chunked}4e20\r\n{big}\r\n")),
            (format!("{LENGTH}ab"), "", http11, format!("{length}ab")),
            (format!("{LENGTH}{big}"), "", http11, format!("{length}{big}")),
            // In a chunk, before any, and after the last one.
            (format!("{CHUNKED}2\r\nab\r\n5\r\ncd"), "", http11, format!("{chunked}4\r\nabcd\r\n")),
            (CHUNKED.to_string(), "", http11, chunked.clone()),
            (format!("{CHUNKED}2\r\nab\r\n0\r\n"), "", http11, format!("{chunked}2\r\nab\r\n")),
            // Without chunks.
            (format!("{CHUNKED}2\r\nab\r\n"), "", http10, format!("{}ab", head("", "close"))),
            (format!("{CHUNKED}2\r\nab\r\n"), "", keep, format!("{}ab", head("", "close"))),
            (format!("{CHUNKED}2\r\nab\r\n"), "chunked_transfer_encoding off;", http11, format!("{}ab", head("", "close"))),
            (format!("{LENGTH}ab"), "", keep, format!("{length}ab")),
            // No trailers.
            (format!("{LENGTH}ab"), "add_trailer X 1;", http11, format!("{chunked}2\r\nab\r\n")),
            // Nothing of what gunzip finds malformed.
            (format!("{LENGTH}ab").replace("Content-Length", "Content-Encoding: gzip\r\nContent-Length"), "gunzip on;", http11, String::new()),
        ] {
            // Nothing more comes, not even the answer to a second request.
            for (requests, rate) in [request.to_string(), request.repeat(2)].iter().flat_map(|r| RATES.map(|rate| (r, rate))) {
                let (got, came) = passed_on(&answer, &format!("{directives} {rate}"), requests);
                assert_eq!((joined(&got), came), (want.clone(), 1), "{answer} {directives} {rate} {requests}");
            }
        }
    }

    /// An answer whose body, if it is in chunks, is in one.
    fn joined(got: &[u8]) -> String {
        let text = std::str::from_utf8(got).unwrap();
        let Some((head, mut rest)) = text.split_once("\r\n\r\n").filter(|(head, _)| head.contains("Transfer-Encoding: chunked")) else { return text.to_string() };
        let mut data = String::new();
        while let Some((n, after)) = rest.split_once("\r\n").map(|(size, after)| (usize::from_str_radix(size, 16).unwrap(), after)).filter(|(n, _)| *n > 0) {
            assert_eq!(&after[n..n + 2], "\r\n", "{text}");
            data += &after[..n];
            rest = &after[n + 2..];
        }
        let data = if data.is_empty() { data } else { format!("{:x}\r\n{data}\r\n", data.len()) };
        format!("{head}\r\n\r\n{data}{rest}")
    }

    #[test]
    fn whole_answers_stay_so() {
        let (http11, two) = ("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", "GET / HTTP/1.1\r\nHost: a\r\n\r\n".repeat(2));
        // Without a length of the server's they are in chunks.
        let whole = head("Content-Length: 2\r\n", "close") + "ab";
        let chunked = head("Transfer-Encoding: chunked\r\n", "close") + "2\r\nab\r\n0\r\n\r\n";
        let length = LENGTH.replace("30000", "2");
        for (answer, want) in [
            (format!("{length}ab"), &whole), (format!("{length}abc"), &whole), (LENGTH.replace("Content-Length: 30000\r\n", "") + "ab", &chunked),
            (format!("{CHUNKED}2\r\nab\r\n0\r\n\r\n"), &chunked), (format!("{CHUNKED}2\r\nab\r\n0\r\nX: 1\r\n\r\n"), &chunked),
        ] {
            for rate in RATES {
                let (got, _) = passed_on(&answer, rate, http11);
                assert_eq!(String::from_utf8(got).unwrap(), *want, "{answer} {rate}");
            }
        }
        // Requests on one connection are all answered. A page or a head instead of the
        // answer cut off is whole too.
        let error = format!("{LENGTH}ab").replace("200 OK", "404 Not Found");
        let malformed = format!("{CHUNKED}2\r\nab\r\nzz\r\n");
        for (answer, directives, requests, status, ends) in [
            (format!("{length}ab"), "", two.as_str(), 200, "\r\n\r\nab"),
            (error, "proxy_intercept_errors on; error_page 404 /e;", &two, 404, "\r\n\r\ne"),
            (format!("{CHUNKED}2\r\nab\r\n"), "proxy_method GET;", &two.replace("GET", "HEAD"), 200, "\r\n\r\n"),
            (LENGTH.replace("\r\n\r\n", "\r\nX-Accel-Redirect: /e\r\n\r\n"), "", &two, 200, "\r\n\r\ne"),
            (malformed.replace("200 OK", "404 Not Found"), "proxy_intercept_errors on; error_page 404 /e;", &two, 404, "\r\n\r\ne"),
            (malformed.clone(), "proxy_method GET;", &two.replace("GET", "HEAD"), 200, "\r\n\r\n"),
            (malformed.replace("\r\n\r\n", "\r\nX-Accel-Redirect: /e\r\n\r\n"), "", &two, 200, "\r\n\r\ne"),
        ] {
            for rate in RATES {
                let (got, came) = passed_on(&answer, &format!("{directives} {rate}"), &(requests.to_string() + "GET /e HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"));
                let got = String::from_utf8(got).unwrap();
                let answers: Vec<_> = got.split("HTTP/1.1 ").collect();
                assert_eq!((answers.len(), came), (4, 2), "{got}");
                for a in &answers[1..3] { assert!(a.starts_with(&status.to_string()) && a.contains("Connection: keep-alive") && !a.contains("chunked") && a.ends_with(ends), "{got}"); }
            }
        }
    }

    /// Chunked bodies that are malformed: in the size, after a chunk or at first, in
    /// what follows the data of a chunk, and in what follows the last one.
    const MALFORMED: [&str; 13] = [
        "2\r\nab\r\nzz\r\nab\r\n0\r\n\r\n", "2\r\nab\r\nzz", "zz\r\n", "\r\n", "+2\r\nab\r\n0\r\n\r\n", "2\rx",
        "ffffffffffffffff\nab\n0\n\n", "2\r\nab\r\nffffffffffffffff\r\nab\r\n0\r\n\r\n", "7fffffffffffffff\r\nab\r\n0\r\n\r\n", "2\r\nab\r\n10000000000000002\r\nab\r\n0\r\n\r\n",
        "2\r\nabcd\r\n0\r\n\r\n", "2\r\nab2\r\ncd\r\n0\r\n\r\n", "2\r\nab\r\n0\r\nX\r: 1\r\n\r\n",
    ];

    #[test]
    fn nothing_is_sent_of_malformed_chunks() {
        let (http11, http10) = ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GET / HTTP/1.0\r\n\r\n");
        let takes_gzip = "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n";
        let big = format!("4e20\r\n{}\r\nzz\r\n", "x".repeat(20000));
        let answer = format!("{CHUNKED}{}", MALFORMED[0]);
        let encoded = answer.replacen("\r\n\r\n", "\r\nContent-Encoding: gzip\r\n\r\n", 1);
        let mut cases: Vec<_> = MALFORMED.into_iter().map(|body| (format!("{CHUNKED}{body}"), "", http11)).collect();
        cases.extend([
            (answer.clone(), "", http10), (answer.clone(), "add_trailer X 1 always; add_header X 1 always;", http11),
            (answer.clone(), "chunked_transfer_encoding off;", http11), (encoded, "gunzip on;", http11),
            (format!("{CHUNKED}{big}"), "gzip on;", takes_gzip), (answer.replace("200 OK", "404 Not Found"), "error_page 404 /e;", http11),
        ]);
        for (answer, directives, request) in &cases {
            for rate in RATES {
                // Nor of a second request's, as the connection closes.
                let (got, came) = passed_on(answer, &format!("{directives} {rate}"), &request.repeat(2));
                assert_eq!((String::from_utf8(got).unwrap(), came), (String::new(), 1), "{answer} {directives} {rate} {request}");
            }
        }
    }

    #[test]
    fn servers_that_send_malformed_chunks_have_not_failed() {
        let _busy = counted();
        for (body, rate) in [MALFORMED[0], "zz\r\nz", "2\r\nab\r\n0\r\nX\r: 1\r\n\r\n"].into_iter().flat_map(|body| RATES.map(|rate| (body, rate))) {
            let answer = format!("{CHUNKED}{body}");
            let servers = [failing(&answer, false), failing(&answer, false)];
            let text = format!("http {{ upstream u {{ server {}; server {}; keepalive 2; }} server {{ proxy_read_timeout 1s; proxy_next_upstream error timeout invalid_header http_502 non_idempotent; \
                                location / {{ proxy_pass http://u; {rate} }} }} }}", servers[0].0, servers[1].0);
            let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
            // Each request goes to one of them, in turn, on a connection of its own.
            for want in [[1, 0], [1, 1], [2, 1], [2, 2]] {
                assert_eq!(exchanged(&config.servers[0], "/"), "", "{answer} {rate}");
                assert_eq!([0, 1].map(|i| *servers[i].1.lock().unwrap()), want, "{answer} {rate}");
            }
        }
    }

    #[test]
    fn malformed_chunks_are_logged() {
        let log = std::env::temp_dir().join(format!("twinx-malformed-{}", std::process::id()));
        for (body, rate) in [MALFORMED[0], "zz\r\n"].into_iter().flat_map(|body| RATES.map(|rate| (body, rate))) {
            let _ = std::fs::remove_file(&log);
            for status in ["200 OK", "404 Not Found"] {
                passed_on(&format!("{CHUNKED}{body}").replace("200 OK", status), &format!("access_log {}; {rate}", log.display()), "GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            }
            // The server's status, and $body_bytes_sent.
            let lines = std::fs::read_to_string(&log).unwrap();
            assert_eq!(lines.lines().map(|l| l.split(' ').skip(8).take(2).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>(), ["200 0", "404 0"], "{body} {rate} {lines}");
        }
    }

    #[test]
    fn answers_cut_off_are_compressed_as_far_as_they_came() {
        let body = "x".repeat(64);
        for answer in [format!("{CHUNKED}40\r\n{body}\r\n"), format!("{LENGTH}{body}")] {
            let (got, _) = passed_on(&answer, "gzip on;", "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n");
            let start = head_end(&got).unwrap();
            let text = String::from_utf8_lossy(&got[..start]);
            assert!(text.contains("Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n") && text.contains("Content-Encoding: gzip\r\n") && !text.contains("Content-Length"), "{text}");
            let n = got[start..].iter().position(|&c| c == b'\n').unwrap() + start + 1;
            let size = usize::from_str_radix(std::str::from_utf8(&got[start..n - 2]).unwrap(), 16).unwrap();
            // One chunk, and no last one; flushed, without the end of what is compressed.
            assert_eq!(&got[n + size - 4..], b"\0\0\xff\xff\r\n");
            let (mut plain, mut inflate) = (Vec::with_capacity(100), flate2::Decompress::new(false));
            inflate.decompress_vec(&got[n + 10..n + size], &mut plain, flate2::FlushDecompress::None).unwrap();
            assert_eq!(plain, body.as_bytes());
        }
    }

    #[test]
    fn answers_cut_off_are_logged_as_sent() {
        let log = std::env::temp_dir().join(format!("twinx-cut-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        let directives = format!("access_log {};", log.display());
        for answer in [format!("{CHUNKED}2\r\nab\r\n"), format!("{LENGTH}ab"), format!("{CHUNKED}2\r\nab\r\n0\r\n\r\n")] {
            passed_on(&answer, &directives, "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
        }
        // The status and $body_bytes_sent, with what makes it a chunk.
        let lines = std::fs::read_to_string(&log).unwrap();
        assert_eq!(lines.lines().map(|l| l.split(' ').skip(8).take(2).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>(), ["200 7", "200 2", "200 12"], "{lines}");
    }

    /// What a server sends, each piece so many milliseconds after the one before it.
    pub(crate) type Pieces = Vec<(u64, Vec<u8>)>;

    /// A server that sends the pieces in answer to each request, and closes the connection
    /// then or waits for the next one; and how many connections came, how many of
    /// those the other side closed, and how many answers all of which it took. It ends
    /// once that count is dropped.
    pub(crate) fn plays(pieces: &Pieces, closes: bool) -> (SocketAddr, Arc<Mutex<[usize; 3]>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, count) = (listener.local_addr().unwrap(), Arc::new(Mutex::new([0; 3])));
        let (counts, pieces) = (count.clone(), pieces.clone());
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || while Arc::strong_count(&counts) > 1 {
            let Ok((mut s, _)) = listener.accept() else { thread::sleep(Duration::from_millis(1)); continue };
            counts.lock().unwrap()[0] += 1;
            let (counts, pieces) = (counts.clone(), pieces.clone());
            s.set_nonblocking(false).and_then(|()| s.set_nodelay(true)).unwrap();
            thread::spawn(move || {
                let mut got = Vec::new();
                loop {
                    while head_end(&got).is_none() {
                        let mut part = [0; 1024];
                        match s.read(&mut part) {
                            Ok(n @ 1..) => got.extend_from_slice(&part[..n]),
                            _ => { counts.lock().unwrap()[1] += 1; return }
                        }
                    }
                    got.clear();
                    let taken = pieces.iter().all(|(ms, piece)| {
                        thread::sleep(Duration::from_millis(*ms));
                        s.write_all(piece).is_ok()
                    });
                    if taken { counts.lock().unwrap()[2] += 1; }
                    if closes { return }
                }
            });
        });
        (addr, count)
    }

    /// What tests of answers sent as they come run under: nothing is shutting down.
    pub(crate) fn serving_on() -> std::sync::MutexGuard<'static, ()> {
        let busy = counted();
        SHUTTING.store(false, Ordering::SeqCst);
        HALTED.store(false, Ordering::SeqCst);
        busy
    }

    /// What location / of a server with the directives has for the server it passes to.
    pub(crate) fn passing(addr: SocketAddr, directives: &str) -> String {
        format!("log_format f '$status $body_bytes_sent $bytes_sent $upstream_status $upstream_response_length $upstream_bytes_received $sent_trailer_x'; access_log off; upstream u {{ server {addr}; keepalive 4; }} \
                 server {{ location / {{ proxy_pass http://u; {directives} }} }}")
    }

    /// What comes at once, and the milliseconds after the request it comes at, until the connection is closed.
    async fn arrivals(http: &str, request: &str) -> Vec<(u128, String)> {
        let (mut client, task) = served_by(http).await;
        client.write_all(request.as_bytes()).await.unwrap();
        let (started, mut all, mut buf) = (Instant::now(), Vec::new(), [0; 16384]);
        while let n @ 1.. = within(Some(Duration::from_secs(4)), client.read(&mut buf)).await.unwrap().unwrap() {
            all.push((started.elapsed().as_millis(), undated(&buf[..n])));
        }
        drop(client);
        within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
        all
    }

    /// Text without its Date lines.
    fn undated(text: &[u8]) -> String {
        String::from_utf8_lossy(text).split_inclusive('\n').filter(|l| !l.starts_with("Date: ")).collect()
    }

    /// What was written to a log, which is removed.
    pub(crate) fn logged(log: &std::path::Path) -> String {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let _ = std::fs::remove_file(log);
        text
    }

    /// Where a test logs to.
    pub(crate) fn log_path(name: &str) -> PathBuf {
        let log = std::env::temp_dir().join(format!("twinx-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&log);
        log
    }

    const OFF: &str = "proxy_buffering off;";
    pub(crate) const DELIMITED: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
    const HTTP11: &str = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    const HTTP10: &str = "GET / HTTP/1.0\r\n\r\n";

    /// Data as one chunk, in text.
    fn chunk_of(data: &str) -> String {
        format!("{:x}\r\n{data}\r\n", data.len())
    }

    /// The pieces, the first of them with the head.
    pub(crate) fn after_head(head: &str, pieces: &[&str], ms: u64) -> Pieces {
        pieces.iter().enumerate().map(|(i, p)| if i == 0 { (0, format!("{head}{p}").into_bytes()) } else { (ms, p.as_bytes().to_vec()) }).collect()
    }

    #[test]
    fn answers_are_sent_as_they_come() {
        let _busy = serving_on();
        let parts = ["one--", "two--", "three", "four-", "five-", "six--"];
        let chunks: Vec<String> = parts.iter().map(|p| chunk_of(p)).collect();
        let chunks: Vec<&str> = chunks.iter().map(String::as_str).collect();
        let length = LENGTH.replace("30000", "30");
        let chunked = [&chunks[..], &["0\r\n\r\n"]].concat();
        let (with_length, in_chunks, plain) = (head("Content-Length: 30\r\n", "close"), head("Transfer-Encoding: chunked\r\n", "close"), head("", "close"));
        let cases = [
            (&length, &parts[..], false, HTTP11, OFF, &with_length, &parts[..]), (&length, &parts, false, HTTP10, OFF, &with_length, &parts),
            (&CHUNKED.to_string(), &chunked, false, HTTP11, "", &in_chunks, &chunked), (&CHUNKED.to_string(), &chunked, false, HTTP10, "", &plain, &parts),
            (&CHUNKED.to_string(), &chunked, false, HTTP11, OFF, &in_chunks, &chunked), (&CHUNKED.to_string(), &chunked, false, HTTP10, OFF, &plain, &parts),
            (&DELIMITED.to_string(), &parts, true, HTTP11, OFF, &in_chunks, &chunked), (&DELIMITED.to_string(), &parts, true, HTTP10, OFF, &plain, &parts),
            (&CHUNKED.to_string(), &chunked, false, HTTP11, "chunked_transfer_encoding off;", &plain, &parts),
            (&CHUNKED.to_string(), &chunked, false, HTTP11, "proxy_limit_rate 1m;", &in_chunks, &chunked),
        ];
        block_on(async {
            let all = cases.map(|(head, pieces, closes, request, directives, sent_head, want)| {
                let (addr, count) = plays(&after_head(head, pieces, 200), closes);
                let (http, mut want) = (passing(addr, directives), want.iter().map(|p| p.to_string()).collect::<Vec<_>>());
                want[0].insert_str(0, sent_head);
                tokio::task::spawn_local(async move {
                    let (_count, mut got) = (count, arrivals(&http, request).await);
                    // The end may come with what it ends.
                    let end = got.pop_if(|g| g.1 == "0\r\n\r\n").map(|g| g.1);
                    if let Some(end) = end { got.last_mut().unwrap().1 += &end; }
                    let last = want.pop_if(|w| w == "0\r\n\r\n").unwrap_or_default();
                    *want.last_mut().unwrap() += &last;
                    assert_eq!(got.iter().map(|g| &g.1).collect::<Vec<_>>(), want.iter().collect::<Vec<_>>(), "{http} {request}");
                    for (i, g) in got.iter().enumerate() { assert!(g.0 + 20 >= i as u128 * 200 && g.0 < i as u128 * 200 + 190, "{i} {got:?}"); }
                })
            });
            for task in all { task.await.unwrap(); }
        });
    }

    /// What a case of the next test is: the head, the pieces and whether the server
    /// closes the connection after them, what the location has and the client's request,
    /// and the steps something came in, with how many bytes of the body, as sent, did.
    type Steps = (String, Vec<String>, bool, &'static str, &'static str, Vec<(u128, usize)>);

    /// What comes of the cases in each step, as long as the time between their pieces.
    fn steps(cases: Vec<Steps>) {
        let _busy = serving_on();
        block_on(async {
            let all: Vec<_> = cases.into_iter().map(|(head, pieces, closes, directives, request, want)| {
                let (addr, count) = plays(&after_head(&head, &pieces.iter().map(String::as_str).collect::<Vec<_>>(), 200), closes);
                let (http, name) = (passing(addr, directives), format!("{head} {:?} {directives} {request}", pieces.iter().map(String::len).collect::<Vec<_>>()));
                tokio::task::spawn_local(async move {
                    let (_count, got) = (count, arrivals(&http, request).await);
                    let mut steps: Vec<(u128, usize)> = Vec::new();
                    let mut head = true;
                    for (ms, text) in got {
                        // Those of one step may come in parts.
                        assert!((ms + 20) % 200 < 190, "{name} {ms}");
                        let body = if std::mem::take(&mut head) { text.len() - head_end(text.as_bytes()).unwrap() } else { text.len() };
                        match steps.last_mut().filter(|s| s.0 == (ms + 20) / 200) { Some(s) => s.1 += body, None => steps.push(((ms + 20) / 200, body)) }
                    }
                    assert_eq!(steps, want, "{name}");
                })
            }).collect();
            for task in all { task.await.unwrap(); }
        });
    }

    #[test]
    fn what_came_goes_on_when_a_buffer_is_full_or_at_the_end() {
        let x = "x".repeat(8192);
        let (parts, whole, each) = (vec!["part-"; 6], [(5, 30)], [0, 1, 2, 3, 4, 5].map(|i| (i, 5)));
        let of = |n: usize, more: &str| LENGTH.replace("30000\r\n", &format!("{n}\r\n{more}"));
        // As many bytes of a chunk, with what makes it one.
        let c = |n: usize| n + format!("{n:x}").len() + 4;
        let chunks = [["5\r\npart-\r\n"; 3].as_slice(), &["0\r\n\r\n"]].concat();
        let on = |head: String, pieces: &[&'static str], want: &[(u128, usize)]| (head, pieces.iter().map(|p| p.to_string()).collect(), false, "", HTTP11, want.to_vec());
        let xs = |sizes: &[usize]| sizes.iter().map(|n| x[..*n].to_string()).collect::<Vec<_>>();
        let (long, ten, six) = (of(20000, ""), of(10000, ""), of(6000, ""));
        let (room, of_ten) = (4096 - long.len(), 4096 - ten.len());
        let mut cases: Vec<Steps> = vec![
            on(of(30, ""), &parts, &whole),
            (of(30, ""), xs(&[5; 6]), false, "", HTTP10, whole.to_vec()),
            (of(30, ""), xs(&[5; 6]), false, "proxy_limit_rate 1m;", HTTP11, whole.to_vec()),
            (DELIMITED.into(), xs(&[5; 6]), true, "", HTTP11, vec![(5, c(30) + 5)]),
            (DELIMITED.into(), xs(&[5; 6]), true, "", HTTP10, whole.to_vec()),
            on(CHUNKED.into(), &chunks, &[(0, 10), (1, 10), (2, 10), (3, 5)]),
            // Parts of chunks: what is less than the rest of one and the end of the body waits.
            on(CHUNKED.into(), &["a\r\nhello", "world\r\n", "a\r\nhello", "world\r\n", "0\r\n\r\n"], &[(0, c(5)), (2, c(10)), (4, c(5) + 5)]),
            on(CHUNKED.into(), &["5\r\n", "abcde", "\r\n", "2", "\r\nhe\r\n", "0\r\n\r\n"], &[(1, c(5)), (4, c(2)), (5, 5)]),
            on(CHUNKED.into(), &["5\r\nabcde\r\n", "3\r\na", "b", "c\r\n", "0\r\n\r\n"], &[(0, c(5)), (2, c(2)), (4, c(1) + 5)]),
            (CHUNKED.into(), [vec!["2710\r\n".to_string()], xs(&[4000, 4000, 2000]), vec!["\r\n0\r\n\r\n".into()]].concat(), false, "", HTTP11, vec![(2, c(4096)), (3, c(4096)), (4, c(1808) + 5)]),
            // Up to the last byte of a buffer, the first of which has the head too.
            (long.clone(), xs(&[room - 1, 1, 4095, 1, 8191, 1, 20000 - room - 3 * 4096]), false, "", HTTP11, vec![(1, room), (3, 4096), (4, 4096), (5, 4096), (6, 20000 - room - 3 * 4096)]),
            (ten.clone(), xs(&[1000; 10]), false, "", HTTP11, vec![(4, of_ten), (8, 4096), (9, 10000 - of_ten - 4096)]),
            (DELIMITED.into(), xs(&[1000; 10]), true, "", HTTP10, vec![(4, 4096 - DELIMITED.len()), (8, 4096), (9, 10000 - 2 * 4096 + DELIMITED.len())]),
            (six.clone(), xs(&[1000; 6]), false, "proxy_buffer_size 1k; proxy_buffers 4 1k;", HTTP11, vec![(0, 1024 - six.len()), (1, 1024), (3, 1024), (4, 1024), (5, 6000 - 4096 + six.len())]),
            // A head waits for the body, but for a large one, or without buffering.
            on(of(30, ""), &["", "part-", "part-part-part-part-part-"], &[(2, 30)]),
            on(of(30, &format!("X-Big: {}\r\n", &x[..1500])), &["", "part-", "part-part-part-part-part-"], &[(0, 0), (2, 30)]),
            (of(30, ""), xs(&[0, 10, 20]), false, OFF, HTTP11, vec![(0, 0), (1, 10), (2, 20)]),
            (CHUNKED.into(), ["", "5\r\npart-\r\n", "0\r\n\r\n"].map(String::from).to_vec(), false, OFF, HTTP11, vec![(0, 0), (1, 10), (2, 5)]),
            (CHUNKED.into(), ["5\r\n", "part-\r\n", "0\r\n\r\n"].map(String::from).to_vec(), false, OFF, HTTP11, vec![(1, 10), (2, 5)]),
            // Of what fails, what has gone on.
            (long.clone(), xs(&[2000, 3000]), false, "proxy_read_timeout 1s;", HTTP11, vec![(1, room)]),
            (long.clone(), xs(&[2000, 3000]), false, "proxy_read_timeout 1s; proxy_buffering off;", HTTP11, vec![(0, 2000), (1, 3000)]),
            (long.clone(), xs(&[2000, 3000, 0]), true, "", HTTP11, vec![(1, room), (2, 5000 - room)]),
            (long, xs(&[2000, 3000, 0]), true, OFF, HTTP11, vec![(0, 2000), (1, 3000)]),
        ];
        // X-Accel-Buffering, whatever proxy_buffering is.
        for (value, passes) in [("no", Some(true)), ("No", Some(true)), ("yes", Some(false)), ("YES", Some(false)), ("off", None), ("", None), ("no\r\nX-Accel-Buffering: yes", Some(false)), ("yes\r\nx-accel-buffering: no", Some(true)), ("no\r\nX-Accel-Buffering: x", Some(true))] {
            for (directives, off) in [("", false), (OFF, true)] {
                cases.push((of(30, &format!("X-Accel-Buffering: {value}\r\n")), xs(&[5; 6]), false, directives, HTTP11, if passes.unwrap_or(off) { each.to_vec() } else { whole.to_vec() }));
            }
        }
        steps(cases);
    }

    #[test]
    fn small_answers_are_written_at_once() {
        let _busy = serving_on();
        let (length, chunked) = (LENGTH.replace("30000", "2"), format!("{CHUNKED}2\r\nab\r\n0\r\n\r\n"));
        for (answer, request, want) in [
            (format!("{length}ab"), HTTP11, head("Content-Length: 2\r\n", "close") + "ab"),
            (format!("{length}ab"), HTTP10, head("Content-Length: 2\r\n", "close") + "ab"),
            (chunked.clone(), HTTP11, head("Transfer-Encoding: chunked\r\n", "close") + "2\r\nab\r\n0\r\n\r\n"),
            (chunked, HTTP10, head("", "close") + "ab"),
            (format!("{CHUNKED}0\r\n\r\n"), HTTP11, head("Transfer-Encoding: chunked\r\n", "close") + "0\r\n\r\n"),
        ] {
            let (addr, _count) = plays(&vec![(0, answer.into_bytes())], false);
            let got = block_on(arrivals(&passing(addr, ""), request));
            assert_eq!(got.iter().map(|g| &g.1).collect::<Vec<_>>(), [&want]);
        }
        // A head waits for the first of the body, and for its end if there is none.
        let pieces = |last: &str| vec![(0, length.clone().into_bytes()), (200, last.as_bytes().to_vec())];
        for (last, closes, want) in [("ab", false, "ab"), ("", true, "")] {
            let (addr, _count) = plays(&pieces(last), closes);
            let got = block_on(arrivals(&passing(addr, ""), HTTP11));
            assert_eq!(got.iter().map(|g| g.1.as_str()).collect::<Vec<_>>(), [head("Content-Length: 2\r\n", "close") + want]);
            assert!(got[0].0 >= 190);
        }
    }

    #[test]
    fn large_answers_are_the_same_byte_for_byte() {
        let _busy = serving_on();
        let data: Vec<u8> = (0..5usize << 20).map(|i| (i * 7 + i / 251) as u8).collect();
        let mut chunks: Vec<u8> = data.chunks(50_000).flat_map(chunk).collect();
        chunks.extend_from_slice(b"0\r\n\r\n");
        let length = LENGTH.replace("30000", &data.len().to_string());
        for (answer, closes, request) in [
            ([length.as_bytes(), &data].concat(), false, HTTP11), ([CHUNKED.as_bytes(), &chunks].concat(), false, HTTP11),
            ([CHUNKED.as_bytes(), &chunks].concat(), false, HTTP10), ([DELIMITED.as_bytes(), &data].concat(), true, HTTP11),
        ] {
            let (addr, _count) = plays(&vec![(0, answer)], closes);
            block_on(async {
                let (mut client, task) = served_by(&passing(addr, "")).await;
                client.write_all(request.as_bytes()).await.unwrap();
                // A client that reads slowly.
                let (mut got, mut buf) = (Vec::new(), vec![0; 65536]);
                while let n @ 1.. = within(Some(Duration::from_secs(4)), client.read(&mut buf)).await.unwrap().unwrap() {
                    got.extend_from_slice(&buf[..n]);
                    if got.len() % 3 == 0 { tokio::time::sleep(Duration::from_millis(2)).await; }
                }
                drop(client);
                within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
                let start = head_end(&got).unwrap();
                let chunked = got[..start].windows(7).any(|w| w == b"chunked");
                assert_eq!(chunked, request == HTTP11 && !answer_has_length(&got[..start]));
                let body = if chunked { dechunk(&got[start..], u64::MAX).unwrap().map(|(body, used)| { assert_eq!(used, got.len() - start); body }).unwrap() } else { got[start..].to_vec() };
                assert!(body == data);
            });
        }
    }

    fn answer_has_length(head: &[u8]) -> bool {
        head.windows(16).any(|w| w == b"Content-Length: ")
    }

    #[test]
    fn connections_are_used_again_after_answers_sent_as_they_come() {
        let _busy = serving_on();
        let request = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let length = LENGTH.replace("30000", "4");
        for (pieces, connections, want) in [
            (after_head(&length, &["ab", "cd"], 30), 1, head("Content-Length: 4\r\n", "keep-alive") + "abcd"),
            (after_head(CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], 30), 1, head("Transfer-Encoding: chunked\r\n", "keep-alive") + "4\r\nabcd\r\n0\r\n\r\n"),
            // More than the body, with it or in its last piece.
            (after_head(&length, &["ab", "cde"], 30), 2, head("Content-Length: 4\r\n", "keep-alive") + "abcd"),
            (after_head(&length, &["abcde"], 30), 2, head("Content-Length: 4\r\n", "keep-alive") + "abcd"),
        ] {
            let (addr, count) = plays(&pieces, false);
            block_on(async {
                let (mut client, _task) = served_by(&passing(addr, "")).await;
                for _ in 0..2 {
                    client.write_all(request.as_bytes()).await.unwrap();
                    let mut got = Vec::new();
                    let ends = |got: &[u8]| head_end(got).is_some_and(|end| if answer_has_length(&got[..end]) { got.len() - end >= 4 } else { got.ends_with(b"0\r\n\r\n") });
                    while !ends(&got) { assert!(read_into(&mut client, &mut got, Some(Duration::from_secs(2))).await > 0); }
                    // The server's connection is there again once the client has the end.
                    assert_eq!(joined(undated(&got).as_bytes()), want);
                }
            });
            assert_eq!(count.lock().unwrap()[0], connections, "{pieces:?}");
        }
        // Both requests at once.
        let (addr, count) = plays(&after_head(&length, &["ab", "cd"], 30), false);
        let got = block_on(received(&passing(addr, ""), &(request.to_string() + HTTP11)));
        assert_eq!(String::from_utf8(got).unwrap(), head("Content-Length: 4\r\n", "keep-alive") + "abcd" + &head("Content-Length: 4\r\n", "close") + "abcd");
        assert_eq!(count.lock().unwrap()[0], 1);
    }

    #[test]
    fn answers_cut_off_or_malformed_later_end_there() {
        let _busy = serving_on();
        let log = log_path("later");
        let (with_length, in_chunks, plain) = (head("Content-Length: 30000\r\n", "close"), head("Transfer-Encoding: chunked\r\n", "close"), head("", "close"));
        // The Date line, which is left out of what comes, is counted.
        let counted = |head: &str, body: usize| format!("200 {body} {} 200", head.len() + 37 + body);
        for (head, pieces, closes, request, directives, want, received) in [
            (LENGTH, &["ab", "cd", ""][..], true, HTTP11, "", vec![with_length.clone() + "abcd"], 4),
            (LENGTH, &["ab", "cd", ""], true, HTTP11, OFF, vec![with_length.clone() + "ab", "cd".into()], 4),
            (LENGTH, &["ab", ""], true, HTTP11, "", vec![with_length.clone() + "ab"], 2),
            (LENGTH, &["", ""], true, HTTP11, "", vec![with_length.clone()], 0),
            (CHUNKED, &["2\r\nab\r\n", "3\r\ncd", ""], true, HTTP11, "", vec![in_chunks.clone() + "2\r\nab\r\n", "2\r\ncd\r\n".into()], 12),
            (CHUNKED, &["2\r\nab\r\n", "0\r\n", ""], true, HTTP10, "", vec![plain.clone() + "ab"], 10),
            (CHUNKED, &["", ""], true, HTTP11, "", vec![in_chunks.clone()], 0),
            // Malformed, where nothing more is sent, not what came with it either.
            (CHUNKED, &["2\r\nab\r\n", "zz\r\nz"], false, HTTP11, "", vec![in_chunks.clone() + "2\r\nab\r\n"], 12),
            (CHUNKED, &["2\r\nab\r\n", "zz"], false, HTTP11, OFF, vec![in_chunks.clone() + "2\r\nab\r\n"], 9),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\nzz"], false, HTTP11, "", vec![in_chunks.clone() + "2\r\nab\r\n"], 16),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\nzz"], false, HTTP11, OFF, vec![in_chunks.clone() + "2\r\nab\r\n"], 16),
            (CHUNKED, &["2\r\nab\r\n", "zz"], false, HTTP10, OFF, vec![plain.clone() + "ab"], 9),
            (CHUNKED, &["", "2\r\nab\r\nzz"], false, HTTP11, "", vec![], 9),
            (CHUNKED, &["2\r\nab\r\nzz"], false, HTTP11, "", vec![], 9),
            // Too little to be looked at before the server closes the connection.
            (CHUNKED, &["2\r\nab\r\n", "zz", ""], true, HTTP11, "", vec![in_chunks.clone() + "2\r\nab\r\n"], 9),
        ] {
            let (addr, count) = plays(&after_head(head, pieces, 60), closes);
            let got = block_on(arrivals(&passing(addr, &format!("{directives} access_log {} f;", log.display())), request));
            assert_eq!(got.iter().map(|g| &g.1).collect::<Vec<_>>(), want.iter().collect::<Vec<_>>(), "{head} {pieces:?}");
            let sent: usize = want.iter().map(String::len).sum();
            let start = want.first().map_or(0, |w| head_end(w.as_bytes()).unwrap());
            let line = if want.is_empty() { "200 0 0 200".to_string() } else { counted(&want[0][..start], sent - start) };
            assert_eq!(logged(&log), format!("{line} {received} {} -\n", head.len() + received), "{head} {pieces:?}");
            assert_eq!(count.lock().unwrap()[0], 1);
        }
        // A read of it that waits longer than proxy_read_timeout.
        for (directives, want) in [("", ""), (OFF, "abcd")] {
            let (addr, count) = plays(&after_head(LENGTH, &["ab", "cd"], 60), false);
            let got = block_on(arrivals(&passing(addr, &format!("proxy_read_timeout 1s; {directives}")), HTTP11));
            assert_eq!(got.iter().map(|g| g.1.as_str()).collect::<String>(), with_length.clone() + want);
            while count.lock().unwrap()[1] == 0 { thread::sleep(Duration::from_millis(1)); }
        }
    }

    #[test]
    fn answers_sent_as_they_come_are_sent_at_the_rate() {
        let _busy = serving_on();
        let length = LENGTH.replace("30000", "3000");
        let data = "x".repeat(1500);
        let pieces = after_head(&length, &[&data, &data], 100);
        let (addr, _count) = plays(&pieces, false);
        let run = |directives: &str| block_on(arrivals(&passing(addr, directives), HTTP11));
        // Head and body are paced together: 2000 bytes in the first second of the clock, in
        // which the last of the body comes, or 4000 in two.
        while now().subsec_millis() > 600 { thread::sleep(Duration::from_millis(1)); }
        let got = run("limit_rate 2000;");
        assert_eq!(got.iter().map(|g| g.1.as_str()).collect::<String>(), head("Content-Length: 3000\r\n", "close") + &data + &data);
        assert!((600..2000).contains(&got.last().unwrap().0), "{:?}", got.iter().map(|g| g.0).collect::<Vec<_>>());
        // What goes before limit_rate_after is not waited for.
        let got = run("limit_rate 100; limit_rate_after 10000;");
        assert!(got.len() == 1 && got[0].0 < 600, "{:?}", got.iter().map(|g| g.0).collect::<Vec<_>>());
        // Without buffering there is no rate, the server's neither.
        let length = LENGTH.replacen("30000\r\n", "3000\r\nX-Accel-Limit-Rate: 100\r\n", 1);
        let (addr, _count) = plays(&after_head(&length, &[&data, &data], 100), false);
        let got = block_on(arrivals(&passing(addr, "proxy_buffering off; limit_rate 100; proxy_limit_rate 100;"), HTTP11));
        assert!(got.len() == 2 && got[0].0 < 90 && got[1].0 < 600, "{:?}", got.iter().map(|g| g.0).collect::<Vec<_>>());
    }

    #[test]
    fn reads_are_paced_by_the_time_they_are_worth() {
        let _busy = serving_on();
        // All of it is there at once, in buffers of 4096 bytes, of which the last is read
        // after the time of those before it. It goes on while the client is behind.
        let data = "x".repeat(9000);
        let length = LENGTH.replace("30000", "9000") + &data;
        let chunks = CHUNKED.to_string() + &chunk_of(&data) + "0\r\n\r\n";
        for (answer, directives) in [(&length, ""), (&chunks, ""), (&length, "limit_rate 100k;"), (&length, "limit_rate 10000; limit_rate_after 1000;")] {
            let (addr, _count) = plays(&vec![(0, answer.clone().into_bytes())], false);
            let got = block_on(arrivals(&passing(addr, &format!("proxy_limit_rate 10000; {directives}")), HTTP11));
            let all = got.iter().map(|g| g.1.as_str()).collect::<String>();
            assert!(all.matches('x').count() >= 9000 && got[0].1.matches('x').count() <= 4096 && got.last().unwrap().0 >= 450, "{directives} {:?}", got.iter().map(|g| (g.0, g.1.len())).collect::<Vec<_>>());
        }
        // Nothing is waited for before the first read, and for nothing.
        block_on(async {
            let mut intake = Intake::new(1000, 0);
            let started = Instant::now();
            assert!(intake.limit(0).await >= 1000);
            intake.took(0);
            assert!(intake.limit(0).await >= 1000 && Intake::new(0, 5000).limit(5000).await == usize::MAX);
            intake.took(100);
            // When it is dropped, the time goes on.
            assert!(within(Some(Duration::from_millis(1)), intake.limit(100)).await.is_none() && intake.until.is_some());
            intake.limit(100).await;
            assert!(started.elapsed() >= Duration::from_millis(100));
        });
    }

    #[test]
    fn clients_may_go_away_at_any_point() {
        let _busy = serving_on();
        let log = log_path("gone");
        let length = LENGTH.replace("30000", "60000000");
        let big = "x".repeat(8 << 20);
        for resets in [false, true] {
            for (pieces, directives, reads, status) in [
                // Before the body, after the first of it, in it, while it is paced, and while the client takes no more.
                (vec![(0, length.clone().into_bytes())], "", 0, "499"),
                (vec![(0, length.clone().into_bytes())], OFF, 1, "200"),
                (after_head(&length, &["ab"], 0), "", 0, "499"),
                (after_head(&length, &["ab"], 0), OFF, 1, "200"),
                (after_head(&length, &["ab", "cd", "ef"], 60), OFF, 2, "200"),
                (after_head(&length, &["ab", &"x".repeat(5000)], 0), "limit_rate 500;", 1, "200"),
                (after_head(&length, &["ab", &big, &big], 0), "proxy_max_temp_file_size 0;", 1, "200"),
                (after_head(CHUNKED, &["2\r\nab\r\n"], 0), "", 1, "200"),
            ] {
                let (addr, count) = plays(&pieces, false);
                block_on(async {
                    let (mut client, task) = served_by(&passing(addr, &format!("{directives} access_log {} f;", log.display()))).await;
                    client.write_all(HTTP11.as_bytes()).await.unwrap();
                    let (mut came, mut buf) = (0, [0; 512]);
                    if reads == 0 { tokio::time::sleep(Duration::from_millis(60)).await; }
                    for _ in 0..reads { came += client.read(&mut buf).await.unwrap(); }
                    if pieces.len() == 3 { tokio::time::sleep(Duration::from_millis(60)).await; }
                    if resets { socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap(); }
                    drop(client);
                    within(Some(Duration::from_secs(1)), task).await.unwrap().unwrap();
                    let text = logged(&log);
                    let line: Vec<usize> = text.split(' ').take(6).map(|n| n.parse().unwrap()).collect();
                    assert!(text.starts_with(&format!("{status} ")) && line[2] >= came && (reads > 0 || line[2] == 0) && line[1] <= line[2] && line[4] < 2 * big.len(), "{pieces:.0?} {text}");
                });
                // The server's connection is closed at once.
                let started = Instant::now();
                while count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(2)); thread::sleep(Duration::from_millis(1)); }
            }
        }
        // One that closes its side only has gone away too; one that takes nothing for send_timeout as well.
        let (addr, count) = plays(&after_head(&length, &["ab"], 0), false);
        block_on(async {
            let (mut client, _task) = served_by(&passing(addr, OFF)).await;
            client.write_all(HTTP11.as_bytes()).await.unwrap();
            assert!(client.read(&mut [0; 512]).await.unwrap() > 0);
            client.shutdown().await.unwrap();
            assert_eq!(within(Some(Duration::from_secs(1)), client.read(&mut [0; 512])).await.unwrap().unwrap(), 0);
        });
        let (stuck, stuck_count) = plays(&after_head(&length, &[&big, &big], 0), false);
        block_on(async {
            let (mut client, task) = served_by(&passing(stuck, "send_timeout 1s;")).await;
            client.write_all(HTTP11.as_bytes()).await.unwrap();
            within(Some(Duration::from_secs(3)), task).await.unwrap().unwrap();
        });
        while count.lock().unwrap()[1] + stuck_count.lock().unwrap()[1] < 2 { thread::sleep(Duration::from_millis(1)); }
    }

    /// What a client gets that takes nothing until that is so, with the task that serves it.
    async fn got_late(http: &str, request: &str, until: impl Fn() -> bool) -> Vec<u8> {
        let (mut client, task) = served_by(http).await;
        client.write_all(request.as_bytes()).await.unwrap();
        let (started, mut got) = (Instant::now(), Vec::new());
        while !until() {
            assert!(started.elapsed() < Duration::from_secs(8), "{http}");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = within(Some(Duration::from_secs(8)), client.read_to_end(&mut got)).await.unwrap();
        drop(client);
        within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
        got
    }

    /// The data of a body as it was sent, and whether it is whole, if it is in chunks or compressed.
    fn data_of(got: &[u8]) -> (Vec<u8>, bool) {
        let end = head_end(got).unwrap();
        let (head, mut data, mut whole) = (String::from_utf8_lossy(&got[..end]).to_string(), Vec::new(), true);
        if head.contains("chunked") { whole = matches!(Body::new(None, true).take(&got[end..], &mut data), Came::Whole { .. }); } else { data = got[end..].to_vec(); }
        if head.contains("gzip") {
            let (mut coder, mut plain) = (Coder::gunzip(), Vec::new());
            while !coder.code(&data, false, false).unwrap() {
                plain.extend_from_slice(coder.ready());
                coder.written();
            }
            plain.extend_from_slice(coder.ready());
            data = plain;
        }
        (data, whole)
    }

    /// More than what the sockets between take, no part of which is as another.
    fn much() -> Vec<u8> {
        (0..1_500_000).flat_map(|i| format!("{i:010}\n").into_bytes()).collect()
    }

    #[test]
    fn slow_clients_do_not_hold_servers_back() {
        let _busy = serving_on();
        let (log, data) = (log_path("behind"), much());
        let dir = std::env::temp_dir().join(format!("twinx-behind-files-{}", std::process::id()));
        let length = LENGTH.replace("30000", &data.len().to_string());
        let chunks: Vec<u8> = data.chunks(10_000).flat_map(|d| [format!("{:x}\r\n", d.len()).as_bytes(), d, b"\r\n"].concat()).chain(*b"0\r\n\r\n").collect();
        let (with_length, in_chunks, to_end) = ([length.as_bytes(), &data].concat(), [CHUNKED.as_bytes(), &chunks].concat(), [DELIMITED.as_bytes(), &data].concat());
        let gzip = HTTP11.replacen("\r\n\r\n", "\r\nAccept-Encoding: gzip\r\n\r\n", 1);
        for (answer, closes, directives, request) in [
            (&with_length, false, "", HTTP11),
            (&with_length, false, "proxy_buffers 4 16k; proxy_buffer_size 2k;", HTTP11),
            (&with_length, false, "proxy_temp_file_write_size 4k; add_trailer X 1;", HTTP11),
            (&with_length, false, "limit_rate 100; limit_rate_after 4m; send_timeout 1s;", HTTP10),
            (&in_chunks, false, "", HTTP11),
            (&in_chunks, false, "proxy_limit_rate 100m;", HTTP10),
            (&to_end, true, "", HTTP11),
            (&with_length, false, "gzip on;", &gzip),
        ] {
            let (addr, count) = plays(&vec![(0, answer.clone())], closes);
            let http = passing(addr, &format!("proxy_temp_path {} 1 2; access_log {} f; {directives}", dir.display(), log.display()));
            // With limit_rate, the rest of it does not come in the time there is.
            let paced = directives.starts_with("limit");
            block_on(async {
                let got = if paced {
                    let (mut client, _task) = served_by(&http).await;
                    client.write_all(request.as_bytes()).await.unwrap();
                    while count.lock().unwrap()[2] == 0 { tokio::time::sleep(Duration::from_millis(2)).await; }
                    return
                } else {
                    got_late(&http, request, || count.lock().unwrap()[2] == 1).await
                };
                let (got, whole) = data_of(&got);
                assert!(whole && got == data, "{directives} {} {}", got.len(), data.len());
                // All that was read of it is told, and the connection is used again.
                let received = answer.len() - head_end(answer).unwrap();
                assert!(logged(&log).contains(&format!(" 200 {received} {} ", answer.len())));
            });
            assert_eq!(count.lock().unwrap()[0], 1);
        }
        // What becomes much more than what came of it, while limit_rate makes the rest wait.
        let long: String = (0..120_000).map(|i| format!("{:-<300}{i}\n", "")).collect();
        let parts: Vec<&str> = long.as_bytes().chunks(100_000).map(|c| std::str::from_utf8(c).unwrap()).collect();
        let one = member(&parts).concat();
        assert!(one.len() > 300_000 && one.len() * 30 < long.len(), "{} {}", one.len(), long.len());
        let coded = LENGTH.replace("30000", &one.len().to_string()).replace("Content-Type", "Content-Encoding: gzip\r\nContent-Type");
        let (addr, _count) = plays(&vec![(0, [coded.as_bytes(), &one].concat())], false);
        let http = passing(addr, &format!("proxy_temp_path {}; proxy_max_temp_file_size 4k; gunzip on; limit_rate 100m;", dir.display()));
        let (got, whole) = data_of(&block_on(got_late(&http, HTTP11, || true)));
        assert!(got == long.as_bytes() && whole, "{} {} {:?}", got.len(), long.len(), got.iter().zip(long.as_bytes()).position(|(a, b)| a != b));
        // Without a file, or with a small one, it is held back, and so it is without buffering.
        for directives in ["proxy_max_temp_file_size 0;", "proxy_max_temp_file_size 16k;", OFF] {
            let (addr, count) = plays(&vec![(0, with_length.clone())], false);
            let http = passing(addr, &format!("proxy_temp_path {}; {directives}", dir.display()));
            let started = Instant::now();
            let got = block_on(got_late(&http, HTTP11, || started.elapsed() > Duration::from_millis(400) && count.lock().unwrap()[0] == 1));
            assert!(data_of(&got) == (data.clone(), true) && count.lock().unwrap()[2] == 1);
            let (addr, count) = plays(&vec![(0, with_length.clone())], false);
            block_on(async {
                let (mut client, _task) = served_by(&passing(addr, directives)).await;
                client.write_all(HTTP11.as_bytes()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(300)).await;
                assert_eq!(*count.lock().unwrap(), [1, 0, 0], "{directives}");
            });
        }
        // The directories are left, with no file in them.
        assert!(dir.exists());
        fn files(dir: &std::path::Path) -> usize {
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).map(|e| if e.file_type().unwrap().is_dir() { files(&e.path()) } else { 1 }).sum()
        }
        assert_eq!(files(&dir), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn answers_that_fail_while_the_client_is_behind() {
        let _busy = serving_on();
        let (log, data) = (log_path("behind-cut"), much());
        let length = LENGTH.replace("30000", "60000000");
        let big = [length.as_bytes(), &data].concat();
        let chunk = [CHUNKED.as_bytes(), format!("{:x}\r\n", data.len()).as_bytes(), &data, b"\r\n"].concat();
        for (pieces, closes, all) in [
            // Cut off where the connection ends, all that came is sent.
            (vec![(0, big.clone()), (50, Vec::new())], true, true),
            (vec![(0, chunk.clone()), (50, Vec::new())], true, true),
            // When a read times out, nothing is that was not being written, and nothing is once chunks are malformed.
            (vec![(0, big.clone())], false, false),
            (vec![(0, chunk.clone())], false, false),
            (vec![(0, chunk.clone()), (50, b"zz\r\nzzzz".to_vec())], false, false),
        ] {
            let malformed = pieces.last().unwrap().1.starts_with(b"zz");
            let (addr, count) = plays(&pieces, closes);
            let http = passing(addr, &format!("proxy_read_timeout 1s; access_log {} f;", log.display()));
            let done = || { let c = count.lock().unwrap(); c[2] == 1 && (all || c[1] == 1) };
            let got = block_on(async {
                let (mut client, task) = served_by(&http).await;
                client.write_all(HTTP11.as_bytes()).await.unwrap();
                let (started, mut got) = (Instant::now(), Vec::new());
                while !done() {
                    assert!(started.elapsed() < Duration::from_secs(8));
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                if all { tokio::time::sleep(Duration::from_millis(150)).await; }
                // What is malformed ends it at once, however far behind the client is.
                if malformed { while !task.is_finished() { tokio::time::sleep(Duration::from_millis(2)).await; } }
                let _ = client.read_to_end(&mut got).await;
                got
            });
            let (got, _) = data_of(&got);
            assert!(data.starts_with(&got) && (got.len() == data.len()) == all, "{} {} {all}", got.len(), data.len());
            let text = logged(&log);
            assert!(text.starts_with("200 ") && text.contains(&format!(" 200 {} ", pieces.iter().map(|p| p.1.len()).sum::<usize>() - head_end(&pieces[0].1).unwrap())), "{text}");
        }
    }

    #[test]
    fn files_of_answers_are_logged() {
        let _busy = serving_on();
        let (errors, data) = (log_path("spool-errors"), much());
        let dir = std::env::temp_dir().join(format!("twinx-logged-{}", std::process::id()));
        let length = LENGTH.replace("30000", &data.len().to_string());
        let request = "GET /a?b HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n";
        let run = |level: &str, fails: bool| {
            let (addr, count) = plays(&vec![(0, [length.as_bytes(), &data].concat())], false);
            let http = passing(addr, &format!("proxy_temp_path {}; error_log {} {level};", dir.display(), errors.display()));
            let got = block_on(got_late(&http, request, || count.lock().unwrap()[if fails { 1 } else { 2 }] == 1));
            let (got, _) = data_of(&got);
            assert!(data.starts_with(&got) && (got.len() < data.len()) == fails);
            (addr, logged(&errors))
        };
        let (addr, text) = run("warn", false);
        let start = format!(" [warn] {}#0: an upstream response is buffered to a temporary file {}/00", std::process::id(), dir.display());
        let end = format!(", request: \"GET /a?b HTTP/1.1\", upstream: \"http://{addr}/a?b\", host: \"h\"\n");
        assert!(text.lines().count() == 1 && text.contains(&start) && text.contains(" while reading upstream, client: 127.0.0.1, server: ") && text.ends_with(&end), "{text}");
        assert_eq!(run("error", false).1, "");
        // A file that cannot be made cuts the answer off.
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "").unwrap();
        for level in ["", "crit"] {
            let text = run(level, true).1;
            assert!(text.lines().count() == 1 && text.contains(&format!(" [crit] {}#0: open() \"{}/00", std::process::id(), dir.display())) && text.contains("\" failed (20: Not a directory) while reading upstream, client: 127.0.0.1"), "{text}");
        }
        assert_eq!(run("alert", true).1, "");
        std::fs::remove_file(&dir).unwrap();
    }

    /// The lines of an error log, without the time and the process, and from the client on.
    fn messages(log: &std::path::Path) -> Vec<String> {
        logged(log).lines().map(|l| {
            let (level, msg) = (l.split(['[', ']']).nth(1).unwrap(), l.split_once("#0: ").unwrap().1);
            format!("{level} {}", msg.split(", client: 127.0.0.1, server: ").next().unwrap())
        }).collect()
    }

    #[test]
    fn failures_of_servers_are_logged() {
        let _busy = serving_on();
        let errors = log_path("failures");
        const HEAD: &str = "HTTP/1.1 200 OK\r\n";
        let head = |headers: &str| format!("{HEAD}{headers}\r\n\r\n");
        // As nginx logs them: at most one line of each.
        for (pieces, directives, want) in [
            (vec![], "", "error upstream prematurely closed connection while reading response header from upstream"),
            (vec![HEAD.to_string()], "", "error upstream prematurely closed connection while reading response header from upstream"),
            (vec![head(&format!("X: {}", "a".repeat(5000)))], "", "error upstream sent too big header while reading response header from upstream"),
            (vec![head(" Bad: x")], "", "error upstream sent invalid header: \"\\x20...\" while reading response header from upstream"),
            (vec![head("Good: x\r\nB\u{1}d: x")], "", "error upstream sent invalid header: \"B\\x01...\" while reading response header from upstream"),
            (vec![head("\r")], "", "error upstream sent invalid header: \"\\x0d...\" while reading response header from upstream"),
            (vec!["HTTP/1.1 103 E\r\nA\u{1}: b\r\n\r\n".to_string() + &head("X: a")], "", "error upstream sent invalid header: \"A\\x01...\" while reading response header from upstream"),
            (vec!["HTTP/1.0 103 E\r\n\r\n".to_string() + &head("X: a")], "", "error upstream sent HTTP/1.0 response with early hints while reading response header from upstream"),
            (vec![head("X: a\0b")], "", "error upstream sent invalid header: \"X: a\\x00...\" while reading response header from upstream"),
            (vec!["HTTP/1.1 abc\r\n\r\n".to_string()], "", "error upstream sent no valid HTTP/1.0 header while reading response header from upstream"),
            (vec![head("Content-Length: 5\r\ncontent-length: 6")], "", "error upstream sent duplicate header line: \"content-length: 6\", previous value: \"Content-Length: 5\" while reading response header from upstream"),
            (vec![head("Transfer-Encoding: chunked\r\nContent-Length: 5")], "", "error upstream sent \"Content-Length\" and \"Transfer-Encoding\" headers at the same time while reading response header from upstream"),
            (vec![head("Content-Length: 5x")], "", "error upstream sent invalid \"Content-Length\" header: \"Content-Length: 5x\" while reading response header from upstream"),
            (vec![head("Transfer-Encoding: gzip")], "", "error upstream sent unknown \"Transfer-Encoding\": \"gzip\" while reading response header from upstream"),
            (vec![head("Content-Length: 10"), "ab".to_string()], "", "error upstream prematurely closed connection while reading upstream"),
            (vec![head("Content-Length: 10"), "ab".to_string()], OFF, "error upstream prematurely closed connection while reading upstream"),
            (vec![CHUNKED.to_string(), chunk_of("ab")], "proxy_limit_rate 1m;", "error upstream prematurely closed connection while reading upstream"),
            (vec![CHUNKED.to_string() + "zz\r\n"], "", "error upstream sent invalid chunked response while reading upstream"),
            (vec![CHUNKED.to_string() + "zz\r\n"], OFF, "error upstream sent invalid chunked response while reading response header from upstream"),
            (vec![CHUNKED.to_string(), chunk_of("ab"), "zz\r\n".to_string()], OFF, "error upstream sent invalid chunked response while reading upstream"),
            (vec![head("Content-Length: 2") + "abc"], "", "warn upstream sent more data than specified in \"Content-Length\" header while reading upstream"),
            (vec![head("Content-Length: 2") + "abc"], OFF, "warn upstream sent more data than specified in \"Content-Length\" header while reading response header from upstream"),
            (vec![head("Content-Length: 0") + "abc"], "", "warn upstream sent more data than specified in \"Content-Length\" header while reading upstream"),
            (vec![CHUNKED.to_string() + &chunk_of("ab") + "0\r\n\r\nx"], "", "warn upstream sent data after final chunk while reading upstream"),
            (vec![head("Content-Length: 2") + "ab"], "", ""),
            (vec![head("Content-Length: 2") + "ab"], OFF, ""),
            (vec![CHUNKED.to_string() + &chunk_of("ab") + "0\r\n\r\n"], "", ""),
            (vec!["HTTP/1.1 204 No Content\r\n\r\n".to_string()], "", ""),
        ] {
            // The pieces after the first come once that has been taken.
            let pieces = pieces.into_iter().enumerate().map(|(i, p)| (if i > 0 { 60 } else { 0 }, p.into_bytes())).collect();
            let (addr, count) = plays(&pieces, true);
            block_on(arrivals(&passing(addr, &format!("{directives} error_log {} info;", errors.display())), HTTP11));
            let got = messages(&errors);
            assert_eq!(got, if want.is_empty() { vec![] } else { vec![want.to_string()] }, "{pieces:?} {directives}");
            assert_eq!(count.lock().unwrap()[0], 1);
        }
        // With the URL at the server.
        let (addr, _count) = plays(&vec![], true);
        block_on(arrivals(&passing(addr, &format!("error_log {};", errors.display())), "GET /a?b HTTP/1.0\r\nHost: h:81\r\n\r\n"));
        let text = logged(&errors);
        assert!(text.ends_with(&format!(", client: 127.0.0.1, server: , request: \"GET /a?b HTTP/1.0\", upstream: \"http://{addr}/a?b\", host: \"h:81\"\n")), "{text}");
    }

    #[test]
    fn failures_to_reach_servers_are_logged() {
        let _busy = serving_on();
        let errors = log_path("unreached");
        // Nothing listens on these, and nothing else takes their ports.
        let bound = [(); 2].map(|_| socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap());
        let [a, b] = [0, 1].map(|i| {
            bound[i].bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
            bound[i].local_addr().unwrap().as_socket().unwrap()
        });
        let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}", "x".repeat(10));
        let ((silent, _one), (resets, _two), (late, _three)) = (failing("", false), failing("", true), failing(&answer, false));
        let refused = "error connect() failed (111: Connection refused) while connecting to upstream";
        let disabled = "warn upstream server temporarily disabled while connecting to upstream";
        for (servers, want) in [
            (format!("server {a};"), vec![refused]),
            (format!("server {a}; server {b};"), vec![refused, disabled, refused, disabled]),
            (format!("server {a} max_fails=0; server {b} max_fails=0;"), vec![refused, refused]),
            (format!("server {a} down;"), vec!["error no live upstreams while connecting to upstream"]),
            (format!("server {silent};"), vec!["error upstream timed out (110: Connection timed out) while reading response header from upstream"]),
            (format!("server {resets};"), vec!["error recv() failed (104: Connection reset by peer) while reading response header from upstream"]),
            (format!("server {late};"), vec!["error upstream timed out (110: Connection timed out) while reading upstream"]),
        ] {
            let http = format!("upstream u {{ {servers} }} server {{ proxy_read_timeout 1s; location / {{ proxy_pass http://u/x/; error_log {} warn; }} }}", errors.display());
            block_on(arrivals(&http, HTTP11));
            let text = std::fs::read_to_string(&errors).unwrap();
            if want[0].contains("no live") { assert!(text.contains(", upstream: \"http://u/x/\", host: "), "{text}"); }
            assert_eq!(messages(&errors), want, "{servers}");
        }
    }

    #[test]
    fn clients_that_go_away_are_logged() {
        let _busy = serving_on();
        let errors = log_path("gone-errors");
        let gone = "info epoll_wait() reported that client prematurely closed connection, so upstream connection is closed too while ";
        let answer = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        for (answer, action) in [("", "sending request to upstream"), ("HTTP/1.1", "reading response header from upstream"), (answer, "reading upstream")] {
            let (addr, _count) = failing(answer, false);
            block_on(async {
                let (mut client, task) = served_by(&passing(addr, &format!("error_log {} info;", errors.display()))).await;
                client.write_all(HTTP11.as_bytes()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                drop(client);
                within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
            });
            assert_eq!(messages(&errors), [format!("{gone}{action}")]);
        }
    }

    #[test]
    fn connections_have_numbers_in_the_log() {
        let _busy = serving_on();
        let errors = log_path("numbers");
        let (addr, _count) = plays(&vec![], true);
        let text = format!("http {{ error_log {}; server {{ location / {{ proxy_pass http://{addr}; }} }} }}", errors.display());
        let config = Arc::new(crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap());
        block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let to = listener.local_addr().unwrap();
            let tasks = accept(config, &[(listener, to)]).unwrap();
            // The connection to the server is the second one, that to it for the next the fourth.
            for _ in 0..2 {
                let mut client = tokio::net::TcpStream::connect(to).await.unwrap();
                client.write_all(HTTP11.as_bytes()).await.unwrap();
                let _ = within(Some(Duration::from_secs(2)), client.read_to_end(&mut Vec::new())).await.unwrap();
            }
            tasks.iter().for_each(JoinHandle::abort);
        });
        let failed = "upstream prematurely closed connection while reading response header from upstream";
        assert_eq!(messages(&errors), [1, 3].map(|n| format!("error *{n} {failed}")));
    }

    #[test]
    fn clients_that_are_behind_may_go_away() {
        let _busy = serving_on();
        let log = log_path("behind-gone");
        let big = [LENGTH.replace("30000", "60000000").as_bytes(), &much()].concat();
        let whole = [LENGTH.replace("30000", &much().len().to_string()).as_bytes(), &much()].concat();
        // While the server is read ahead, held back, or done with; with the connection closed, or one side of it.
        for (answer, directives, done) in [(&big, "", 2), (&big, "proxy_max_temp_file_size 0;", 0), (&big, OFF, 0), (&big, "limit_rate 1;", 2), (&whole, "", 2)] {
            for half in [false, true] {
                let (addr, count) = plays(&vec![(0, answer.clone())], false);
                block_on(async {
                    let (mut client, task) = served_by(&passing(addr, &format!("access_log {} f; {directives}", log.display()))).await;
                    client.write_all(HTTP11.as_bytes()).await.unwrap();
                    assert!(client.read(&mut [0; 100]).await.unwrap() > 0);
                    while count.lock().unwrap()[done] == 0 { tokio::time::sleep(Duration::from_millis(2)).await; }
                    if done == 0 { tokio::time::sleep(Duration::from_millis(50)).await; }
                    if half { client.shutdown().await.unwrap(); } else { drop(std::mem::replace(&mut client, tokio::net::TcpStream::connect(addr).await.unwrap())); }
                    let started = Instant::now();
                    while !task.is_finished() && started.elapsed() < Duration::from_secs(5) { tokio::time::sleep(Duration::from_millis(2)).await; }
                    assert!(task.is_finished() && logged(&log).starts_with("200 "), "{directives} {half}");
                });
                // The server's connection is closed then, if its answer has not ended.
                let started = Instant::now();
                while answer.len() == big.len() && count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(2)); thread::sleep(Duration::from_millis(1)); }
            }
        }
    }

    #[test]
    fn answers_sent_as_they_come_have_trailers_and_are_logged() {
        let _busy = serving_on();
        let log = log_path("passed");
        let length = LENGTH.replace("30000", "4");
        let in_chunks = head("Transfer-Encoding: chunked\r\n", "close");
        let trailer = "0\r\nX: 4-200\r\n\r\n";
        for (answer, pieces, directives, request, want, body, read) in [
            (&length, &["ab", "cd"][..], "add_trailer X $upstream_response_length-$upstream_status;", HTTP11, in_chunks.clone() + "4\r\nabcd\r\n" + trailer, 24, "4 4-200"),
            (&length, &["ab", "cd"], "proxy_buffering off; add_trailer X $upstream_response_length-$upstream_status;", HTTP11, in_chunks.clone() + "4\r\nabcd\r\n" + trailer, 29, "4 4-200"),
            (&length, &["ab", "cd"], "add_trailer X 1;", HTTP10, head("Content-Length: 4\r\n", "close") + "abcd", 4, "4 -"),
            (&CHUNKED.to_string(), &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], "", HTTP11, in_chunks.clone() + "4\r\nabcd\r\n0\r\n\r\n", 19, "19 -"),
            (&CHUNKED.to_string(), &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], "", HTTP10, head("", "close") + "abcd", 4, "19 -"),
        ] {
            let (addr, _count) = plays(&after_head(answer, pieces, 40), false);
            let got = block_on(arrivals(&passing(addr, &format!("{directives} access_log {} f;", log.display())), request));
            let got: String = got.into_iter().map(|g| g.1).collect();
            assert_eq!(joined(got.as_bytes()), want);
            let start = head_end(want.as_bytes()).unwrap();
            let (length, trailer) = read.split_once(' ').unwrap();
            assert_eq!(logged(&log), format!("200 {body} {} 200 {length} {} {trailer}\n", start + 37 + body, answer.len() + length.parse::<usize>().unwrap()));
        }
    }

    /// What comes at once, as arrivals() has it, but in bytes.
    async fn bytes_arriving(http: &str, request: &str) -> Vec<Vec<u8>> {
        let (mut client, task) = served_by(http).await;
        client.write_all(request.as_bytes()).await.unwrap();
        let (mut all, mut buf) = (Vec::new(), vec![0; 1 << 20]);
        while let n @ 1.. = within(Some(Duration::from_secs(4)), client.read(&mut buf)).await.unwrap().unwrap() { all.push(buf[..n].to_vec()); }
        drop(client);
        within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
        all
    }

    /// The head of an answer, the data in its chunks, decompressed as far as it came if
    /// it is compressed, and whether there is a last chunk.
    fn opened(got: &[u8]) -> (String, String, bool) {
        if got.is_empty() { return (String::new(), String::new(), false) }
        let (head, mut rest) = got.split_at(head_end(got).unwrap());
        let (head, mut data, mut last) = (undated(head), rest.to_vec(), false);
        if head.contains("Transfer-Encoding: chunked") {
            data.clear();
            while !rest.is_empty() && !last {
                let at = rest.iter().position(|&c| c == b'\n').unwrap() + 1;
                let n = usize::from_str_radix(std::str::from_utf8(&rest[..at - 2]).unwrap(), 16).unwrap();
                data.extend_from_slice(&rest[at..at + n]);
                rest = &rest[at + n + 2..];
                last = n == 0;
            }
        }
        if head.contains("Content-Encoding: gzip") && !data.is_empty() {
            let mut plain = Vec::with_capacity(1 << 20);
            flate2::Decompress::new(false).decompress_vec(&data[10..], &mut plain, flate2::FlushDecompress::None).unwrap();
            data = plain;
        }
        (head, String::from_utf8(data).unwrap(), last)
    }

    pub(crate) const GZ: &str = "Content-Encoding: gzip\r\n";
    const GZIP11: &str = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n";

    /// The head of such an answer.
    pub(crate) fn with_length(length: usize, more: &str) -> String {
        LENGTH.replace("30000", &length.to_string()).replacen("\r\n\r\n", &format!("\r\n{more}\r\n"), 1)
    }

    /// Data as a member of gzip, of several blocks, so that what came of it can be decompressed.
    pub(crate) fn member(parts: &[&str]) -> Vec<Vec<u8>> {
        let mut coder = Coder::gzip();
        let mut gz: Vec<Vec<u8>> = parts.iter().map(|p| {
            coder.code(p.as_bytes(), true, false).unwrap();
            let part = coder.ready().to_vec();
            coder.written();
            part
        }).collect();
        coder.end().unwrap();
        gz.last_mut().unwrap().extend(coder.ready());
        gz
    }

    /// The pieces so far apart, the first with the head.
    pub(crate) fn pieces_after(head: &str, pieces: &[Vec<u8>]) -> Pieces {
        pieces.iter().enumerate().map(|(i, p)| if i == 0 { (0, [head.as_bytes(), p].concat()) } else { (100, p.clone()) }).collect()
    }

    #[test]
    fn what_gzip_changes_is_sent_as_it_comes() {
        let _busy = serving_on();
        let strong = "ETag: \"1-2\"\r\nAccept-Ranges: bytes\r\n";
        let parts = ["one-one-one-one-", "two-two-two-two-", "three-three-threeee"].map(|p| p.repeat(2));
        let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
        let (plain, raw) = (parts.concat(), parts.iter().map(|p| p.as_bytes().to_vec()).collect::<Vec<_>>());
        let gz = member(&parts);
        let gz_len = gz.iter().map(Vec::len).sum();
        let chunks = |pieces: &[Vec<u8>]| pieces.iter().map(|p| [format!("{:x}\r\n", p.len()).as_bytes(), p, b"\r\n"].concat()).chain([b"0\r\n\r\n".to_vec()]).collect::<Vec<_>>();
        let http10 = GZIP11.replace("1.1", "1.0");
        let in_chunks = head("Transfer-Encoding: chunked\r\n", "close").replace("\r\n\r\n", "\r\nVary: Accept-Encoding\r\n");
        let (recoded, kept) = ("ETag: W/\"1-2\"\r\n", head(&format!("Content-Length: {}\r\n", plain.len()), "close").replace("\r\n\r\n", "\r\nVary: Accept-Encoding\r\n"));
        let css = plain.len().to_string();
        let gzip = "gzip on; gzip_vary on;";
        let gunzip = "gunzip on; gzip_vary on;";
        let (length, chunked) = (with_length(plain.len(), strong), CHUNKED.to_string());
        let (gz_length, gz_chunked) = (with_length(gz_len, &format!("{GZ}{strong}")), CHUNKED.replacen("\r\n\r\n", &format!("\r\n{GZ}\r\n"), 1));
        let delimited = DELIMITED.to_string();
        let none = String::new();
        for (answer, pieces, closes, directives, request, want, came) in [
            // Each read is flushed without buffering; else it waits for a buffer to be full, or the end.
            (&length, raw.clone(), false, format!("{gzip} {OFF}"), GZIP11, format!("{in_chunks}{recoded}{GZ}\r\n"), &[32, 32, 38][..]),
            (&chunked, chunks(&raw), false, format!("{gzip} {OFF}"), GZIP11, format!("{in_chunks}{GZ}\r\n"), &[32, 32, 38]),
            (&delimited, raw.clone(), true, format!("{gzip} {OFF}"), GZIP11, format!("{in_chunks}{GZ}\r\n"), &[32, 32, 38]),
            (&length, raw.clone(), false, gzip.to_string(), GZIP11, format!("{in_chunks}{recoded}{GZ}\r\n"), &[102]),
            (&chunked, chunks(&raw), false, gzip.to_string(), GZIP11, format!("{in_chunks}{GZ}\r\n"), &[102]),
            // HTTP/1.0, where the connection's end is that of the body.
            (&length, raw.clone(), false, format!("gzip on; gzip_http_version 1.0; {OFF}"), &http10, head("", "close").replace("\r\n\r\n", &format!("\r\n{recoded}{GZ}\r\n")), &[32, 32, 38]),
            // Without buffering, a head that comes alone goes alone, the beginning of gzip with it.
            (&chunked, [vec![Vec::new()], chunks(&raw)].concat(), false, format!("{gzip} {OFF}"), GZIP11, format!("{in_chunks}{GZ}\r\n"), &[0, 32, 32, 38]),
            // Not compressed for this client, not of a type that is, or too short.
            (&length, raw.clone(), false, format!("{gzip} {OFF}"), HTTP11, format!("{kept}{strong}\r\n"), &[32, 32, 38]),
            (&with_length(plain.len(), "").replace("html", "css"), raw.clone(), false, format!("{gzip} {OFF}"), GZIP11, head(&format!("Content-Length: {css}\r\n"), "close").replace("html", "css"), &[32, 32, 38]),
            (&with_length(19, ""), vec![b"x".repeat(10), b"y".repeat(9)], false, format!("{gzip} {OFF}"), GZIP11, head("Content-Length: 19\r\n", "close"), &[10, 9]),
            // Decompressed for one that does not take gzip, and what there is of it goes on.
            (&gz_length, gz.clone(), false, format!("{gunzip} {OFF}"), HTTP11, format!("{in_chunks}{recoded}\r\n"), &[32, 32, 38]),
            (&gz_chunked, chunks(&gz), false, gunzip.to_string(), HTTP11, format!("{in_chunks}\r\n"), &[32, 32, 38]),
            (&gz_length, gz.clone(), false, gunzip.to_string(), HTTP11, format!("{in_chunks}{recoded}\r\n"), &[102]),
            (&gz_length, gz.clone(), false, format!("gunzip on; {OFF}"), HTTP10, head("", "close").replace("\r\n\r\n", &format!("\r\n{recoded}\r\n")), &[32, 32, 38]),
            (&gz_length, gz.clone(), false, format!("{gunzip} {OFF}"), GZIP11, none.clone(), &[]),
        ] {
            let (addr, _count) = plays(&pieces_after(answer, &pieces), closes);
            let got = block_on(bytes_arriving(&passing(addr, &directives), request));
            let (head, data, last) = opened(&got.concat());
            if want.is_empty() {
                // It takes gzip: the answer stays as it is.
                assert!(head.contains("Content-Length") && head.contains(GZ) && head.contains("Vary") && head.contains(strong), "{head}");
                assert_eq!(got.concat()[got[0].len() - gz[0].len()..], gz.concat(), "{head}");
                continue;
            }
            assert_eq!((&head, last), (&want, head.contains("chunked")), "{directives} {request}");
            let all = if came.iter().sum::<usize>() == 19 { "x".repeat(10) + &"y".repeat(9) } else { plain.clone() };
            assert_eq!(data, all);
            // What there is after each arrival, but for those of the end alone.
            let (mut sum, mut whole, mut is) = (0, Vec::new(), Vec::new());
            for part in &got {
                whole.extend_from_slice(part);
                let n = opened(&whole).1.len();
                if n > sum || is.is_empty() { is.push(n - sum); }
                sum = n;
            }
            assert_eq!(is, came, "{answer} {directives} {request}");
        }
    }

    #[test]
    fn what_gzip_changes_ends_where_the_answer_does() {
        let _busy = serving_on();
        let log = log_path("coded");
        let errors = log_path("coded-errors");
        let (a, b) = ("a".repeat(50), "b".repeat(50));
        let gz = member(&[&a, &b]);
        let whole = gz.concat();
        let (one, two) = (gz[0].clone(), gz[1].clone());
        let bad = [&two[..two.len() - 8], b"12345678"].concat();
        let (long, gz_long) = (with_length(30000, ""), with_length(30000, GZ));
        let exact = |n: usize| with_length(n, GZ);
        let response_end = "inflate() returned -5 on response end";
        let in_chunks = head("Transfer-Encoding: chunked\r\n", "close");
        let compressed = in_chunks.replace("\r\n\r\n", &format!("\r\n{GZ}\r\n"));
        let (half, half_bad) = (exact(one.len() + 5), exact(one.len() + bad.len()));
        let (alone, junk) = (exact(5), exact(whole.len() + 4));
        let raw = [a.as_bytes().to_vec(), b.as_bytes().to_vec(), Vec::new()];
        for (answer, pieces, closes, directives, request, want, data, error) in [
            // Cut off: what was held goes on, without the end of gzip; but what is in a buffer
            // not full when a read waits too long does not.
            (&long, raw.to_vec(), true, "gzip on;", GZIP11, &compressed, a.clone() + &b, ""),
            (&long, raw.to_vec(), true, "gzip on; proxy_buffering off;", GZIP11, &compressed, a.clone() + &b, ""),
            (&long, raw[..2].to_vec(), false, "gzip on; proxy_read_timeout 1s;", GZIP11, &compressed, String::new(), ""),
            (&long, raw[..2].to_vec(), false, "gzip on; proxy_read_timeout 1s; proxy_buffering off;", GZIP11, &compressed, a.clone() + &b, ""),
            (&gz_long, vec![one.clone(), Vec::new()], true, "gunzip on;", HTTP11, &in_chunks, a.clone(), ""),
            (&gz_long, vec![one.clone(), Vec::new()], true, "gunzip on; proxy_buffering off;", HTTP11, &in_chunks, a.clone(), ""),
            (&gz_long, vec![one.clone()], false, "gunzip on; proxy_read_timeout 1s;", HTTP11, &in_chunks, String::new(), ""),
            // It ends, but not what is compressed: then it is cut off, but what came goes on.
            (&half, vec![one.clone(), two[..5].to_vec()], false, "gunzip on;", HTTP11, &in_chunks, a.clone(), response_end),
            (&half, vec![one.clone(), two[..5].to_vec()], false, "gunzip on; proxy_buffering off;", HTTP11, &in_chunks, a.clone(), response_end),
            (&alone, vec![whole[..5].to_vec()], false, "gunzip on;", HTTP11, &String::new(), String::new(), response_end),
            (&alone, vec![whole[..5].to_vec()], false, "gunzip on; proxy_buffering off;", HTTP11, &in_chunks, String::new(), response_end),
            // Malformed: nothing that came with that goes on.
            (&half_bad, vec![one.clone(), bad.clone()], false, "gunzip on;", HTTP11, &String::new(), String::new(), "inflate() failed: 0, -3"),
            (&half_bad, vec![one.clone(), bad.clone()], false, "gunzip on; proxy_buffering off;", HTTP11, &in_chunks, a.clone(), "inflate() failed: 2, -3"),
            (&gz_long, vec![[&one[..], &bad].concat()], false, "gunzip on; proxy_buffering off;", HTTP11, &String::new(), String::new(), "inflate() failed: 2, -3"),
            (&junk, vec![[&whole[..], b"junk"].concat()], false, "gunzip on;", HTTP11, &String::new(), String::new(), "inflate() failed: 0, -3"),
            (&junk, vec![[&whole[..], b"junk"].concat()], false, "gunzip on; proxy_buffering off;", HTTP11, &in_chunks, a.clone() + &b, "inflate() failed: 0, -3"),
        ] {
            let (addr, count) = plays(&pieces_after(answer, &pieces), closes);
            // The connection would stay open otherwise.
            let request = request.replace("Connection: close\r\n", "");
            let got = block_on(bytes_arriving(&passing(addr, &format!("{directives} access_log {} f; error_log {};", log.display(), errors.display())), &request)).concat();
            let want = want.replace("Connection: close", "Connection: keep-alive");
            assert_eq!(opened(&got), (want, data, false), "{directives} {pieces:?}");
            let start = if got.is_empty() { 0 } else { head_end(&got).unwrap() };
            let line = logged(&log);
            assert!(line.starts_with(&format!("200 {} {} 200 ", got.len() - start, got.len())), "{line}");
            // Besides how the server failed.
            let line = logged(&errors).lines().filter(|l| !l.contains(" while reading upstream")).collect::<String>();
            assert!(if error.is_empty() { line.is_empty() } else { line.contains(&format!(": {error}, client: ")) }, "{directives} {line}");
            assert_eq!(count.lock().unwrap()[0], 1);
        }
    }

    #[test]
    fn what_becomes_much_is_not_held() {
        let _busy = serving_on();
        let data = "x".repeat(10 << 20);
        let bomb = member(&[&data]).concat();
        let (addr, _count) = plays(&pieces_after(&with_length(bomb.len(), GZ), &[bomb]), false);
        let got = block_on(bytes_arriving(&passing(addr, "gunzip on;"), HTTP11)).concat();
        // In chunks of all its buffers.
        let start = head_end(&got).unwrap();
        assert!(got[start..].starts_with(b"20000\r\n"));
        let (_, plain, last) = opened(&got);
        assert!(plain == data && last);
    }

    #[test]
    fn answers_changed_by_gzip_leave_the_connections_open() {
        let _busy = serving_on();
        let data = "abc".repeat(30);
        let gz = member(&[&data]).concat();
        for (pieces, request, directives) in [
            (pieces_after(&with_length(90, ""), &[data.as_bytes().to_vec()]), GZIP11, "gzip on; add_trailer X 1;"),
            (pieces_after(&with_length(gz.len(), GZ), &[gz.clone()]), HTTP11, "gunzip on; add_trailer X 1;"),
            (pieces_after(&with_length(gz.len(), GZ), &[gz.clone()]), HTTP11, "gunzip on; add_trailer X 1; proxy_buffering off;"),
        ] {
            let (addr, count) = plays(&pieces, false);
            let requests = request.replace("Connection: close\r\n", "") + request;
            let got = block_on(bytes_arriving(&passing(addr, directives), &requests)).concat();
            let text = String::from_utf8_lossy(&got);
            assert_eq!((text.matches("HTTP/1.1 200 OK\r\n").count(), text.matches("0\r\nX: 1\r\n\r\n").count()), (2, 2), "{text}");
            assert_eq!((opened(&got).1, count.lock().unwrap()[0]), (data.clone(), 1));
        }
    }

    #[test]
    fn answers_being_passed_end_when_the_time_to_shut_down_has_passed() {
        let _busy = serving_on();
        let log = log_path("halted");
        let head_only = vec![(0, LENGTH.as_bytes().to_vec())];
        for (pieces, directives, line) in [(after_head(LENGTH, &["ab"], 0), OFF, "200 2 "), (after_head(LENGTH, &["ab"], 0), "", "200 0 0 "), (head_only, "", "200 0 0 ")] {
            let (addr, count) = plays(&pieces, false);
            block_on(async {
                let (mut client, task) = served_by(&passing(addr, &format!("{directives} access_log {} f;", log.display()))).await;
                client.write_all(HTTP11.as_bytes()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
                HALTED.store(true, Ordering::SeqCst);
                HALT.notify_waiters();
                within(Some(Duration::from_secs(1)), task).await.unwrap().unwrap();
                HALTED.store(false, Ordering::SeqCst);
            });
            let text = logged(&log);
            assert!(text.starts_with(line), "{text}");
            while count.lock().unwrap()[1] == 0 { thread::sleep(Duration::from_millis(1)); }
        }
    }

    /// A server that reads a request, sends the answer and then nothing until the
    /// connection is closed, or resets it; and how many connections came. It ends once
    /// that count is dropped.
    fn failing(answer: &str, resets: bool) -> (SocketAddr, Arc<Mutex<usize>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(0)));
        let (all, answer) = (came.clone(), answer.to_string());
        listener.set_nonblocking(true).unwrap();
        thread::spawn(move || {
            while Arc::strong_count(&all) > 1 {
                let Ok((mut s, _)) = listener.accept() else { thread::sleep(Duration::from_millis(1)); continue };
                *all.lock().unwrap() += 1;
                s.set_nonblocking(false).unwrap();
                assert!(s.read(&mut [0u8; 1024]).unwrap() > 0);
                s.write_all(answer.as_bytes()).unwrap();
                if resets {
                    // After what was sent has come.
                    thread::sleep(Duration::from_millis(50));
                    socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
                } else {
                    let _ = s.read(&mut [0u8; 1]);
                }
            }
        });
        (addr, came)
    }

    /// A frame of HTTP/2.
    fn h2_frame(kind: u8, flags: u8, sid: u8, payload: &[u8]) -> Vec<u8> {
        [&(payload.len() as u32).to_be_bytes()[1..], &[kind, flags, 0, 0, 0, sid], payload].concat()
    }

    /// A server of HTTP/2 that sends the pieces, one after another, when a request has
    /// come, and then nothing until the connection is closed, or closes it; and how many connections came.
    pub(crate) fn sends(pieces: &[Vec<u8>], closes: bool) -> (SocketAddr, Arc<Mutex<usize>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(0)));
        let (all, pieces) = (came.clone(), pieces.to_vec());
        thread::spawn(move || {
            for s in listener.incoming() {
                *all.lock().unwrap() += 1;
                let mut s = s.unwrap();
                // The preface, two frames, and the HEADERS.
                let mut got = Vec::new();
                while got.len() < 24 + 27 + 13 + 9 { let mut part = [0; 1024]; let n = s.read(&mut part).unwrap(); assert!(n > 0); got.extend_from_slice(&part[..n]); }
                for (i, piece) in pieces.iter().enumerate() {
                    if i > 0 { thread::sleep(Duration::from_millis(50)); }
                    if s.write_all(piece).is_err() { break }
                }
                if !closes { while s.read(&mut [0; 1024]).is_ok_and(|n| n > 0) {} }
            }
        });
        (addr, came)
    }

    /// What received() gives for a request to a location with the directives, passed over
    /// HTTP/2 to an upstream of two servers that send the pieces so, without its first
    /// lines, the body's framing aside, and how many connections came to both.
    fn over_h2(pieces: &[Vec<u8>], closes: bool, directives: &str, request: &str) -> (String, usize) {
        let _busy = counted();
        SHUTTING.store(false, Ordering::SeqCst);
        HALTED.store(false, Ordering::SeqCst);
        let ((a, came_a), (b, came_b)) = (sends(pieces, closes), sends(pieces, closes));
        let http = format!("access_log off; upstream u {{ server {a}; server {b}; }} server {{ proxy_read_timeout 1s; location / {{ proxy_http_version 2; proxy_pass http://u; {directives} }} }}");
        let got = String::from_utf8(block_on(received(&http, request))).unwrap();
        let came = *came_a.lock().unwrap() + *came_b.lock().unwrap();
        (got, came)
    }

    #[test]
    fn answers_over_http2_end_as_their_streams_do() {
        let request = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        let head = h2_frame(1, 4, 1, &[0x88]);
        let length = h2_frame(1, 4, 1, b"\x88\x0f\x0d\x0210");
        let data = h2_frame(0, 0, 1, b"abcde");
        let text = |framing: &str, body: &str| format!("HTTP/1.1 200 OK\r\nServer: {NAME}\r\n{framing}\r\nConnection: close\r\n\r\n{body}");
        let cut = |head: &Vec<u8>, body: &str| if *head == length { text("Content-Length: 10", body) } else if body.is_empty() { text("Transfer-Encoding: chunked", "") } else { text("Transfer-Encoding: chunked", &format!("5\r\n{body}\r\n")) };
        // Reset, with an error or without one; going away before the stream; a frame too short.
        let fails = [h2_frame(3, 0, 1, &[0, 0, 0, 2]), h2_frame(3, 0, 1, &[0; 4]), h2_frame(7, 0, 0, &[0; 8]), h2_frame(8, 0, 0, &[0; 3])];
        let going = h2_frame(7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]);
        for head in [&head, &length] {
            for fail in &fails {
                assert_eq!(over_h2(&[head.clone(), data.clone(), fail.clone()], false, "", request), (cut(head, "abcde"), 1), "{fail:?}");
                // Nothing is sent of the answer when no part of its body came before.
                assert_eq!(over_h2(&[head.clone(), fail.clone()], false, "", request), (String::new(), 1), "{fail:?}");
                assert_eq!(over_h2(&[[&head[..], &data, fail].concat()], false, "", request), (String::new(), 1), "{fail:?}");
            }
            for closing in [Vec::new(), going.clone()] {
                assert_eq!(over_h2(&[head.clone(), data.clone(), closing.clone()], true, "", request), (cut(head, "abcde"), 1));
                assert_eq!(over_h2(&[head.clone(), closing], true, "", request), (cut(head, ""), 1));
            }
            // One going away after the stream goes on with it.
            let (whole, came) = over_h2(&[head.clone(), data.clone(), going.clone(), h2_frame(0, 1, 1, b"fghij")], false, "", request);
            let want = if *head == length { text("Content-Length: 10", "abcdefghij") } else { text("Transfer-Encoding: chunked", "a\r\nabcdefghij\r\n0\r\n\r\n") };
            assert_eq!((joined(whole.as_bytes()), came), (want, 1));
        }
        // What has no body is not cut.
        let head_only = "HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
        let (got, came) = over_h2(&[[&length[..], &fails[0]].concat()], false, "", head_only);
        assert!(got.starts_with("HTTP/1.1 200 ") && came == 1, "{got}");
        // Before the head, what fails is an invalid header, and the connection closing an error.
        for fail in &fails {
            for (next, want) in [("", 1), ("proxy_next_upstream error;", 1), ("proxy_next_upstream invalid_header;", 2)] {
                let (got, came) = over_h2(&[Vec::new(), fail.clone()], false, next, request);
                assert!(got.starts_with("HTTP/1.1 502 ") && came == want, "{fail:?} {next} {came} {got}");
            }
        }
        for closing in [Vec::new(), going] {
            for (next, want) in [("", 2), ("proxy_next_upstream error;", 2), ("proxy_next_upstream invalid_header;", 1)] {
                let (got, came) = over_h2(&[Vec::new(), closing.clone()], true, next, request);
                assert!(got.starts_with("HTTP/1.1 502 ") && came == want, "{closing:?} {next} {came} {got}");
            }
        }
    }

    #[test]
    fn trailers_over_http2_are_passed_once_the_stream_ends() {
        let (request, old) = ("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", "GET / HTTP/1.0\r\nHost: a\r\n\r\n");
        let head = h2_frame(1, 4, 1, &[0x88]);
        let length = h2_frame(1, 4, 1, b"\x88\x0f\x0d\x015");
        let data = h2_frame(0, 0, 1, b"abcde");
        let trailer = |flags: u8| h2_frame(1, flags, 1, b"\x00\x03x-t\x011");
        let (on, added) = ("proxy_pass_trailers on;", "proxy_pass_trailers on; add_trailer X-A b;");
        let body = |got: &(String, usize)| got.0.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        for apart in [false, true] {
            let pieces = |parts: [&[u8]; 3]| if apart { parts.iter().map(|p| p.to_vec()).collect() } else { vec![parts.concat()] };
            let get = |head: &[u8], trailer: &[u8], directives: &str, request: &str| body(&over_h2(&pieces([head, &data, trailer]), false, directives, request));
            assert_eq!(get(&head, &trailer(5), on, request), "5\r\nabcde\r\n0\r\nx-t: 1\r\n\r\n");
            assert_eq!(get(&head, &trailer(5), added, request), "5\r\nabcde\r\n0\r\nx-t: 1\r\nX-A: b\r\n\r\n");
            assert_eq!(get(&length, &trailer(5), added, request), "5\r\nabcde\r\n0\r\nx-t: 1\r\nX-A: b\r\n\r\n");
            // Not in a body of a length, nor to one of HTTP/1.0, nor of a stream that fails.
            assert_eq!(get(&length, &trailer(5), on, request), "abcde");
            assert_eq!(get(&head, &trailer(5), on, old), "abcde");
            assert!(!get(&head, &[trailer(5), h2_frame(3, 0, 1, &[0, 0, 0, 2])].concat(), on, request).contains("x-t"));
            assert!(!get(&head, &trailer(4), on, request).contains("x-t"));
        }
        // A "connection" header does not matter.
        let close = h2_frame(1, 4, 1, b"\x88\x00\x0aconnection\x05close");
        assert_eq!(body(&over_h2(&[[&close[..], &data, &trailer(5)].concat()], false, on, request)), "5\r\nabcde\r\n0\r\nx-t: 1\r\n\r\n");
    }

    /// What received() gives for a request when a server has the directives and passes
    /// it to an upstream of two servers that fail so after the answer; it is not sent to
    /// the second one.
    async fn failed_on(answer: &str, resets: bool, directives: &str, request: &str) -> String {
        let ((a, came_a), (b, came_b)) = (failing(answer, resets), failing(answer, resets));
        let http = format!("log_format f '$status $upstream_status $upstream_bytes_received $upstream_response_length'; access_log off; upstream u {{ server {a}; server {b}; }} \
                            server {{ proxy_read_timeout 1s; proxy_next_upstream error timeout; {directives} location / {{ proxy_pass http://u; }} }}");
        let got = received(&http, request).await;
        assert_eq!((*came_a.lock().unwrap(), *came_b.lock().unwrap()), (1, 0), "{answer} {resets} {directives}");
        String::from_utf8(got).unwrap()
    }

    #[test]
    fn answers_whose_reading_fails_are_cut_off() {
        let (http11, http10) = ("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "GET / HTTP/1.0\r\n\r\n");
        let (length, chunked) = (head("Content-Length: 30000\r\n", "keep-alive"), head("Transfer-Encoding: chunked\r\n", "keep-alive"));
        let _busy = counted();
        // A test of shutting down leaves it set, which closes connections.
        SHUTTING.store(false, Ordering::SeqCst);
        HALTED.store(false, Ordering::SeqCst);
        let (big, delimited) = ("x".repeat(20000), LENGTH.replace("Content-Length: 30000\r\n", ""));
        // What is in the full buffers of 4k, the first of which has the head.
        let full = "x".repeat(4 * 4096 - LENGTH.len());
        let cases = [
            (format!("{LENGTH}ab"), http11, "", length.clone()),
            (format!("{LENGTH}ab"), http11, OFF, format!("{length}ab")),
            (LENGTH.to_string(), http11, "", length.clone()),
            (format!("{LENGTH}{big}"), http11, "", format!("{length}{full}")),
            (format!("{LENGTH}{big}"), http11, OFF, format!("{length}{big}")),
            // After a chunk, in one, before any, and after the last one.
            (format!("{CHUNKED}2\r\nab\r\n"), http11, "", format!("{chunked}2\r\nab\r\n")),
            (format!("{CHUNKED}2\r\nab\r\n5\r\ncd"), http11, "", format!("{chunked}4\r\nabcd\r\n")),
            (CHUNKED.to_string(), http11, "", chunked.clone()),
            (format!("{CHUNKED}2\r\nab\r\n0\r\n"), http11, "", format!("{chunked}2\r\nab\r\n")),
            (format!("{CHUNKED}2\r\nab\r\n"), http10, "", format!("{}ab", head("", "close"))),
            // In what cannot become a chunk, where nothing is sent.
            (format!("{CHUNKED}2\r\nab\r\nzz"), http11, "", String::new()),
            // A body that only the connection's end delimits.
            (format!("{delimited}ab"), http11, "", chunked.clone()),
            (format!("{delimited}ab"), http11, OFF, format!("{chunked}2\r\nab\r\n")),
            (format!("{delimited}ab"), http10, "", head("", "close")),
            (format!("{delimited}ab"), http10, OFF, format!("{}ab", head("", "close"))),
            // After a whole body nothing more is read.
            (format!("{}ab", LENGTH.replace("30000", "2")), http10, "", format!("{}ab", head("Content-Length: 2\r\n", "close"))),
        ];
        block_on(async {
            // At once, as each waits for the timeout.
            for rate in RATES {
                let all: Vec<_> = [false, true].into_iter().flat_map(|resets| cases.iter().cloned().map(move |c| (c, resets))).map(|((answer, request, directives, want), resets)| tokio::task::spawn_local(async move {
                    let directives = format!("{directives} {rate}");
                    assert_eq!(failed_on(&answer, resets, &directives, request).await, want, "{answer} {resets} {directives}");
                })).collect();
                for task in all { task.await.unwrap(); }
            }
        });
    }

    #[test]
    fn answers_whose_reading_fails_are_logged() {
        let _busy = counted();
        let log = std::env::temp_dir().join(format!("twinx-failed-{}", std::process::id()));
        let answer = format!("HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\n{}", "x".repeat(100));
        for (resets, rate) in [false, true].into_iter().flat_map(|resets| [RATES[0], RATES[1], OFF].map(|rate| (resets, rate))) {
            let _ = std::fs::remove_file(&log);
            let got = block_on(failed_on(&answer, resets, &format!("access_log {} f; {rate}", log.display()), "GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
            assert!(got.ends_with(&if rate == OFF { "x".repeat(100) } else { "\r\n\r\n".into() }), "{got}");
            assert_eq!(std::fs::read_to_string(&log).unwrap(), "200 200 142 100\n");
        }
    }

    #[test]
    fn servers_that_close() {
        for (version, connection, is) in [
            ("HTTP/1.1", &[][..], false), ("HTTP/1.2", &[], false), ("HTTP/1.1", &["keep-alive"], false), ("HTTP/1.1", &["clos"], false),
            ("HTTP/1.0", &[], true), ("HTTP/1.0", &["keep-alive"], true), ("HTTP/2.0", &[], true), ("HTTP/1.x", &[], true), ("HTTP/1.1\t200", &[], true),
            ("HTTP/1.1", &["close"], true), ("HTTP/1.1", &["Close"], true), ("HTTP/1.1", &["keep-alive, CLOSE"], true), ("HTTP/1.1", &["disclosed"], true),
            ("HTTP/1.1", &["keep-alive", "close"], true),
        ] {
            let values: Vec<String> = connection.iter().map(|v| v.to_string()).collect();
            assert_eq!(closes(version, &values), is, "{version} {connection:?}");
        }
    }

    #[test]
    fn connections_that_may_be_used_again() {
        let _busy = serving_on();
        // Whether the server closes the connection after its answer comes before
        // whether fetch() returns the connection, or finish() gives it back.
        let answers: [(&str, &str, bool, bool); 19] = [
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nab", false, true),
            ("GET", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nab", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: Close\r\n\r\nab", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na", true, false),
            ("GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n", false, true),
            ("GET", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n", false, false),
            ("GET", "HTTP/1.1 200 OK\r\n\r\nab", true, false),
            ("GET", "HTTP/1.1 204 No Content\r\n\r\n", false, true),
            ("GET", "HTTP/1.1 204 No Content\r\n\r\nab", false, false),
            ("HEAD", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", false, true),
            ("GET", "HTTP/1.1 101 Switching Protocols\r\nContent-Length: 0\r\n\r\n", false, false),
            ("HEAD", "HTTP/1.1 102 Processing\r\n\r\n", false, false),
            // Early hints come before the answer.
            ("HEAD", "HTTP/1.1 103 \r\nLink: a\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", false, true),
            // The body of an X-Accel-Redirect answer is not read, whether it came or not.
            ("GET", "HTTP/1.1 200 OK\r\nX-Accel-Redirect: /a\r\nContent-Length: 2\r\n\r\nab", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nX-Accel-Redirect: /a\r\nContent-Length: 2\r\n\r\n", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nX-Accel-Redirect: /a\r\nTransfer-Encoding: chunked\r\n\r\n", false, false),
            ("GET", "HTTP/1.1 200 OK\r\nX-Accel-Redirect: /a\r\nContent-Length: 0\r\n\r\n", false, true),
            ("HEAD", "HTTP/1.1 200 OK\r\nX-Accel-Redirect: /a\r\nContent-Length: 2\r\n\r\n", false, true),
        ];
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let mut open = Vec::new();
            for (_, answer, close, _) in answers {
                let (mut s, _) = listener.accept().unwrap();
                let _ = s.read(&mut [0u8; 1024]).unwrap();
                s.write_all(answer.as_bytes()).unwrap();
                if !close { open.push(s); }
            }
            thread::sleep(Duration::from_secs(5));
        });
        let level = Level { proxy_buffer_size: 4096, proxy_connect_timeout: Duration::from_secs(1), proxy_read_timeout: Duration::from_secs(1), ..Level::default() };
        for (method, answer, _, kept) in answers {
            let req = format!("{method} / HTTP/1.1\r\n\r\n");
            let back = block_on(async {
                let s = connect(&addr, None, &level).await.ok()?;
                let (mut resp, conn) = fetch(Conn::new(Stream::Tcp(s), Instant::now()), Instant::now(), req.as_bytes(), &level, None, (&mut [None; 3], &mut [0; 3]), &|_| 0, None, 0, (false, false)).await.ok()?;
                let mut up = Upstream::new(vec![crate::upstream::Peer::new(addr)]);
                up.keepalive = Some(Default::default());
                let up = Arc::new(up);
                if let Some(rest) = &mut resp.rest { rest.home = Some((up.clone(), addr, 0)); }
                finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
                Some(conn.is_some() || up.take(&addr, 0).is_some())
            }).unwrap();
            assert_eq!(back, kept, "{method} {answer}");
        }
    }

    /// A server that answers each request of a connection with the header lines and
    /// its request line as the body, and leaves the connection open; and the requests
    /// that came, each with the number of its connection.
    fn answering(lines: &'static str) -> (SocketAddr, Arc<Mutex<Vec<(usize, String)>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
        let all = came.clone();
        thread::spawn(move || {
            for (i, s) in listener.incoming().enumerate() {
                let (mut s, came) = (s.unwrap(), all.clone());
                thread::spawn(move || {
                    let (mut buf, mut chunk) = (Vec::new(), [0u8; 1024]);
                    loop {
                        let whole = head_end(&buf).filter(|end| {
                            let head = String::from_utf8_lossy(&buf[..*end]);
                            let length = head.split_once("Content-Length: ").map_or(0, |(_, l)| l.lines().next().unwrap().parse().unwrap());
                            buf.len() - end >= length
                        });
                        if whole.is_none() {
                            let Ok(n @ 1..) = s.read(&mut chunk) else { return };
                            buf.extend_from_slice(&chunk[..n]);
                            continue;
                        }
                        // Whatever came with the request is taken for a part of it.
                        let req = String::from_utf8(std::mem::take(&mut buf)).unwrap();
                        let line = req.lines().next().unwrap().to_string();
                        came.lock().unwrap().push((i, req));
                        s.write_all(format!("HTTP/1.1 200 OK\r\n{lines}Content-Length: {}\r\n\r\n{line}", line.len()).as_bytes()).unwrap();
                    }
                });
            }
        });
        (addr, came)
    }

    /// The bodies that answer the requests, which are sent one after another to the
    /// locations /a, /b and, with proxy_limit_rate, /c that pass them to an upstream
    /// with the settings and the server, and the requests that came to it.
    fn proxied(settings: &str, lines: &'static str, requests: &[(&str, &str)]) -> (Vec<String>, Vec<(usize, String)>) {
        let (addr, came) = answering(lines);
        let text = format!("http {{ upstream u {{ server {addr}; {settings} }} server {{ location /a {{ proxy_pass http://u; }} location /b {{ proxy_pass http://u; }} location /c {{ proxy_pass http://u; proxy_limit_rate 1m; }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let bodies = block_on(async {
            let mut bodies = Vec::new();
            for (head, body) in requests {
                let (parsed, mut r) = request(head);
                r.body = body.as_bytes().to_vec();
                let found = located(&config.servers[0], &r, &r.uri);
                let (mut resp, _, _) = answer(&config.servers[0], &r, parsed, found, None).await;
                assert_eq!((resp.status, resp.rest.is_some()), (200, true));
                finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
                assert!(resp.upstream_time.unwrap()[0].iter().all(Option::is_some));
                bodies.push(String::from_utf8(resp.body).unwrap());
            }
            bodies
        });
        let came = came.lock().unwrap().clone();
        (bodies, came)
    }

    #[test]
    fn proxied_connections_are_kept() {
        let _busy = serving_on();
        let (a, b) = (("GET /a HTTP/1.0\n\n", ""), ("GET /b HTTP/1.0\n\n", ""));
        for (settings, lines, requests, connections) in [
            ("keepalive 2;", "", [a, a], [0, 0]),
            ("keepalive 0;", "", [a, a], [0, 1]),
            ("keepalive 2;", "Connection: close\r\n", [a, a], [0, 1]),
            // A connection is of the location that opened it only with local.
            ("keepalive 2 local;", "", [a, a], [0, 0]),
            ("keepalive 2 local;", "", [a, b], [0, 1]),
            ("keepalive 2;", "", [a, b], [0, 0]),
        ] {
            let (_, came) = proxied(settings, lines, &requests);
            assert_eq!(came.iter().map(|c| c.0).collect::<Vec<_>>(), connections, "{settings} {lines}");
        }
    }

    #[test]
    fn connections_of_answers_read_at_the_rate_are_kept() {
        let _busy = serving_on();
        // The bodies are too long to come with the head.
        let long = "x".repeat(6000);
        let (one, two) = (format!("GET /c?1{long} HTTP/1.0\n\n"), format!("GET /c?2{long} HTTP/1.0\n\n"));
        for (lines, connections) in [("", [0, 0]), ("Connection: close\r\n", [0, 1])] {
            let (bodies, came) = proxied("keepalive 2;", lines, &[(&one, ""), (&two, "")]);
            assert_eq!(bodies, [format!("GET /c?1{long} HTTP/1.1"), format!("GET /c?2{long} HTTP/1.1")]);
            assert_eq!(came.iter().map(|c| c.0).collect::<Vec<_>>(), connections, "{lines}");
        }
        // A body that is shorter than its length.
        let (addr, came) = closing("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab");
        let text = format!("http {{ upstream u {{ server {addr}; keepalive 2; }} server {{ location / {{ proxy_pass http://u; proxy_limit_rate 1m; }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        block_on(async {
            for connections in 1..3 {
                let mut resp = answered(&config.servers[0], "GET / HTTP/1.0\n\n").await;
                assert!(resp.rest.is_some());
                finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
                assert_eq!((resp.body.as_slice(), resp.upstream_status.as_deref()), (&b"ab"[..], Some("200")));
                assert_eq!(*came.lock().unwrap(), connections);
            }
        });
    }

    #[test]
    fn requests_on_kept_connections() {
        let _busy = serving_on();
        let requests = [("GET /a?1 HTTP/1.0\nX: 1\n\n", ""), ("POST /a/b HTTP/1.0\nContent-Length: 3\nX: 2\n\n", "xyz"), ("GET /a?3 HTTP/1.0\n\n", "")];
        let (bodies, came) = proxied("keepalive 1;", "", &requests);
        assert_eq!(bodies, ["GET /a?1 HTTP/1.1", "POST /a/b HTTP/1.1", "GET /a?3 HTTP/1.1"]);
        assert_eq!(came, [
            (0, "GET /a?1 HTTP/1.1\r\nHost: u\r\nX: 1\r\n\r\n".to_string()),
            (0, "POST /a/b HTTP/1.1\r\nHost: u\r\nContent-Length: 3\r\nX: 2\r\n\r\nxyz".to_string()),
            (0, "GET /a?3 HTTP/1.1\r\nHost: u\r\n\r\n".to_string()),
        ]);
    }

    /// A server that reads a request, sends the answer, if any, and closes the
    /// connection; and how many connections came.
    fn closing(answer: &'static str) -> (SocketAddr, Arc<Mutex<usize>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(0)));
        let all = came.clone();
        thread::spawn(move || {
            for s in listener.incoming() {
                *all.lock().unwrap() += 1;
                let (mut s, mut req, mut chunk) = (s.unwrap(), String::new(), [0u8; 1024]);
                // The body, if any, is one byte, or ends with the last chunk.
                let whole = |req: &str| req.split_once("\r\n\r\n").is_some_and(|(head, body)| {
                    if head.contains("chunked") { body.ends_with("0\r\n\r\n") } else { !head.contains("Content-Length") || !body.is_empty() }
                });
                while !whole(&req) {
                    let n = s.read(&mut chunk).unwrap();
                    assert!(n > 0, "{req}");
                    req += std::str::from_utf8(&chunk[..n]).unwrap();
                }
                s.write_all(answer.as_bytes()).unwrap();
            }
        });
        (addr, came)
    }

    /// The status of the answer to a request passed to an upstream of the two
    /// servers, with the directives in its location and the rest of its body, if
    /// any, coming from the client as "c".
    fn passed_to(servers: [SocketAddr; 2], directives: &str, head: &str, rest: Option<Unread>) -> u16 {
        let [first, second] = servers;
        let text = format!("http {{ upstream u {{ server {first}; server {second}; }} proxy_read_timeout 1s; server {{ location / {{ proxy_pass http://u; {directives} }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        block_on(async {
            let (mut client, mut out) = pair().await;
            if let Some(u) = &rest { out.write_all(if u.chunked.is_some() { b"1\r\nc\r\n0\r\n\r\n" } else { b"c" }).await.unwrap(); }
            let (parsed, r) = request(head);
            *r.shared.unread.lock().unwrap() = rest;
            let found = located(&config.servers[0], &r, &r.uri);
            answer(&config.servers[0], &r, parsed, found, Some(&mut client)).await.0.status
        })
    }

    #[test]
    fn requests_sent_are_not_sent_again() {
        let _busy = serving_on();
        const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const UNAVAILABLE: &str = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
        let (error, any) = ("proxy_next_upstream error;", "proxy_next_upstream error non_idempotent;");
        let (status, status_any) = ("proxy_next_upstream http_503;", "proxy_next_upstream http_503 non_idempotent;");
        // What the first server answers, and the status of the answer: 200 when the second server got the request.
        for (first, directives, method, want) in [
            ("", "", "GET", 200), ("", "", "PUT", 200),
            ("", "", "POST", 502), ("", error, "LOCK", 502), ("", error, "PATCH", 502),
            ("", any, "POST", 200),
            // It is the client's method that matters.
            ("", "proxy_method GET;", "POST", 502), ("", "proxy_method POST;", "GET", 200),
            (UNAVAILABLE, status, "GET", 200), (UNAVAILABLE, status, "POST", 503), (UNAVAILABLE, status_any, "POST", 200),
        ] {
            let ((a, sent), (b, again)) = (closing(first), closing(OK));
            assert_eq!(passed_to([a, b], directives, &format!("{method} / HTTP/1.0\n\n"), None), want, "{method} {directives}");
            assert_eq!((*sent.lock().unwrap(), *again.lock().unwrap()), (1, (want == 200) as usize), "{method} {directives}");
        }
        // An answer whose head is invalid is not an error, but invalid_header.
        let hints = |fields: &str| format!("HTTP/1.1 103 E\r\n{fields}\r\n{OK}");
        let ((b, again), invalid) = (closing(OK), "proxy_next_upstream invalid_header;");
        for (first, directives, want) in [
            (OK.replace("0\r", "x\r"), "", 502), (OK.replace("0\r", "0\r\nA: b\0\r"), invalid, 200), (OK.replace("0\r", "0\r\n\r\r"), invalid, 200),
            (hints("A: b\0\r\n"), invalid, 200), (hints("A: b\r\n").replacen("1.1", "1.0", 1), invalid, 200),
            (hints("A: b\r\n").replace("OK\r\n", "OK\r\nHTTP/1.1 301 x\r\n").replace(" OK", ""), "", 200),
        ] {
            let ((a, _), before) = (closing(first.clone().leak()), *again.lock().unwrap());
            assert_eq!((passed_to([a, b], directives, "GET / HTTP/1.0\n\n", None), *again.lock().unwrap() - before), (want, !directives.is_empty() as usize), "{first:?} {directives}");
        }
        // Nothing was sent to a server that refuses the connection: its port is bound, but nothing listens.
        let refusing = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        refusing.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
        let a = refusing.local_addr().unwrap().as_socket().unwrap();
        let (b, again) = closing(OK);
        assert_eq!((passed_to([a, b], "", "POST / HTTP/1.0\n\n", None), *again.lock().unwrap()), (200, 1));
        // A body passed as it comes is passed once, whatever the method.
        for (first, directives, want) in [("", any, 502), (UNAVAILABLE, status_any, 503)] {
            for (framing, left, chunked) in [("Content-Length: 1", 1, None), ("Transfer-Encoding: chunked", 0, Some((Vec::new(), 0)))] {
                let ((a, sent), (b, again)) = (closing(first), closing(OK));
                let directives = format!("proxy_request_buffering off; {directives}");
                assert_eq!(passed_to([a, b], &directives, &format!("PUT / HTTP/1.1\nHost: h\n{framing}\n\n"), Some(Unread { left, chunked, rest: Vec::new() })), want, "{framing}");
                assert_eq!((*sent.lock().unwrap(), *again.lock().unwrap()), (1, 0), "{framing}");
            }
        }
    }

    /// A server whose connections answer so many requests each, those that are not
    /// listed any number, read the next one and close without answering it; and how
    /// many requests came.
    fn dropping(answers: &'static [usize]) -> (SocketAddr, Arc<Mutex<usize>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(0)));
        let all = came.clone();
        thread::spawn(move || {
            for (i, s) in listener.incoming().enumerate() {
                let (mut s, came, mut left) = (s.unwrap(), all.clone(), answers.get(i).copied());
                thread::spawn(move || {
                    let (mut buf, mut chunk) = (Vec::new(), [0u8; 1024]);
                    loop {
                        while head_end(&buf).is_none() {
                            let Ok(n @ 1..) = s.read(&mut chunk) else { return };
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        buf.clear();
                        *came.lock().unwrap() += 1;
                        if left == Some(0) { return }
                        left = left.map(|n| n - 1);
                        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
                    }
                });
            }
        });
        (addr, came)
    }

    /// The answer of a server to a request without a body.
    async fn answered(server: &Server, head: &str) -> Response {
        let (parsed, r) = request(head);
        answer(server, &r, parsed, located(server, &r, &r.uri), None).await.0
    }

    #[test]
    fn kept_connections_that_are_closed_use_up_no_try() {
        let _busy = serving_on();
        let (any, off, once) = ("proxy_next_upstream error non_idempotent;", "proxy_next_upstream off;", "proxy_next_upstream_tries 1;");
        // How many requests the connections to each server answer, and how many
        // connections there are to keep, as many to each server; the directives and the
        // method; and the servers tried, each with its status.
        let one: &[&[usize]] = &[&[1]];
        let cases: [(&[&'static [usize]], usize, &str, &str, &[(usize, u16)]); 13] = [
            (one, 1, "", "GET", &[(0, 502), (0, 200)]),
            (one, 1, once, "GET", &[(0, 502), (0, 200)]),
            (one, 1, "", "POST", &[(0, 502)]),
            (one, 1, any, "POST", &[(0, 502), (0, 200)]),
            (one, 1, off, "GET", &[(0, 502)]),
            (&[&[1, 1]], 2, "", "GET", &[(0, 502), (0, 502), (0, 200)]),
            // A new connection uses up the try, also after a kept one.
            (&[&[0]], 0, "", "GET", &[(0, 502)]),
            (&[&[1, 0]], 1, "", "GET", &[(0, 502), (0, 502)]),
            (&[&[1], &[]], 2, "", "GET", &[(0, 502), (1, 200)]),
            (&[&[1], &[]], 2, once, "GET", &[(0, 502), (1, 200)]),
            (&[&[0], &[]], 0, "", "GET", &[(0, 502), (1, 200)]),
            (&[&[0], &[]], 0, once, "GET", &[(0, 502)]),
            // Neither of two servers is tried again.
            (&[&[1], &[1]], 2, "", "GET", &[(0, 502), (1, 502)]),
        ];
        for (answers, kept, directives, method, want) in cases {
            let servers: Vec<_> = answers.iter().map(|a| dropping(a)).collect();
            let list: String = servers.iter().map(|s| format!("server {}; ", s.0)).collect();
            let text = format!("http {{ upstream u {{ {list}keepalive 2; }} proxy_read_timeout 1s; server {{ location / {{ proxy_pass http://u; {directives} }} }} }}");
            let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
            let server = &config.servers[0];
            let resp = block_on(async {
                let get = || answered(server, "GET / HTTP/1.0\n\n");
                // Two at once have a connection each.
                let statuses = match kept {
                    0 => Vec::new(),
                    1 => vec![get().await.status],
                    _ => <[Response; 2]>::from(tokio::join!(get(), get())).map(|r| r.status).to_vec(),
                };
                assert_eq!(statuses, vec![200; kept]);
                answered(server, &format!("{method} / HTTP/1.0\n\n")).await
            });
            let joined = |f: &dyn Fn(&(usize, u16)) -> String| Some(want.iter().map(f).collect::<Vec<_>>().join(", "));
            let case = format!("{answers:?} {method} {directives}");
            assert_eq!(Some(resp.status), want.last().map(|w| w.1), "{case}");
            assert_eq!(resp.upstream_status, joined(&|w| w.1.to_string()), "{case}");
            assert_eq!(resp.upstream_addr, joined(&|w| servers[w.0].0.to_string()), "{case}");
            for (i, (_, came)) in servers.iter().enumerate() {
                assert_eq!(*came.lock().unwrap(), kept / servers.len() + want.iter().filter(|w| w.0 == i).count(), "{case}");
            }
        }
    }

    /// A server that sends the answers to a connection's requests in turn, and then
    /// nothing until the connection is closed; and how many connections came.
    fn silent(answers: &'static [&str]) -> (SocketAddr, Arc<Mutex<usize>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(0)));
        let all = came.clone();
        thread::spawn(move || {
            for s in listener.incoming() {
                *all.lock().unwrap() += 1;
                let mut s = s.unwrap();
                for answer in answers {
                    if request_line(&mut s).is_none() { break }
                    s.write_all(answer.as_bytes()).unwrap();
                }
                let _ = s.read_to_end(&mut Vec::new());
            }
        });
        (addr, came)
    }

    /// A configuration whose server passes requests to an upstream of the servers,
    /// with the directives in its location.
    fn passing_to(servers: &[SocketAddr], directives: &str) -> crate::conf::Config {
        let list: String = servers.iter().map(|s| format!("server {s}; ")).collect();
        let text = format!("http {{ upstream u {{ {list}keepalive 2; }} proxy_connect_timeout 1s; proxy_read_timeout 1s; \
                            server {{ location / {{ proxy_pass http://u; {directives} }} }} }}");
        crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap()
    }

    #[test]
    fn servers_that_do_not_answer_in_time() {
        const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        const NEVER: &[&str] = &[];
        const PARTIAL: &[&str] = &["HTTP/1.1 200 OK\r\nX: 1\r\n"];
        let (error, timeout, off, any) = ("proxy_next_upstream error;", "proxy_next_upstream timeout;", "proxy_next_upstream off;", "proxy_next_upstream timeout non_idempotent;");
        // What the servers answer, the directives and the method, the status, and $upstream_status.
        let cases: [(&[&'static [&str]], &str, &str, u16, &str); 15] = [
            (&[NEVER], "", "GET", 504, "504"),
            (&[PARTIAL], "", "GET", 504, "504"),
            (&[NEVER, &[OK]], "", "GET", 200, "504, 200"),
            (&[PARTIAL, &[OK]], "", "GET", 200, "504, 200"),
            (&[NEVER, NEVER], "", "GET", 504, "504, 504"),
            (&[NEVER, &[OK]], timeout, "GET", 200, "504, 200"),
            (&[NEVER, &[OK]], error, "GET", 504, "504"),
            (&[NEVER, &[OK]], off, "GET", 504, "504"),
            (&[NEVER, &[OK]], "proxy_next_upstream http_504;", "GET", 504, "504"),
            (&[NEVER, &[OK]], "proxy_next_upstream_tries 1;", "GET", 504, "504"),
            (&[NEVER, &[OK]], "", "POST", 504, "504"),
            (&[NEVER, &[OK]], "", "LOCK", 504, "504"),
            (&[NEVER, &[OK]], "", "PATCH", 504, "504"),
            (&[NEVER, &[OK]], any, "POST", 200, "504, 200"),
            (&[NEVER], "proxy_hide_header Content-Type;", "GET", 504, "504"),
        ];
        let _busy = counted();
        // A test of shutting down leaves it set, which ends requests.
        HALTED.store(false, Ordering::SeqCst);
        block_on(async {
            // At once, as each waits for the timeout.
            let all: Vec<_> = cases.into_iter().map(|(answers, directives, method, status, statuses)| tokio::task::spawn_local(async move {
                let servers: Vec<_> = answers.iter().map(|a| silent(a)).collect();
                let config = passing_to(&servers.iter().map(|s| s.0).collect::<Vec<_>>(), directives);
                let resp = answered(&config.servers[0], &format!("{method} / HTTP/1.0\n\n")).await;
                let case = format!("{answers:?} {method} {directives}");
                assert_eq!((resp.status, resp.upstream_status.as_deref()), (status, Some(statuses)), "{case}");
                assert_eq!(resp.ctype.as_deref(), (status != 200).then_some("text/html"), "{case}");
                // Each server got the request once, or not at all.
                let tried = statuses.split(", ").count();
                for (i, (_, came)) in servers.iter().enumerate() { assert_eq!(*came.lock().unwrap(), (i < tried) as usize, "{case}"); }
            })).collect();
            for task in all { task.await.unwrap(); }
        });
        // error_page takes the 504.
        let http = format!("server {{ proxy_read_timeout 1s; location / {{ proxy_pass http://{}; error_page 504 = /e; }} location = /e {{ return 403; }} }}", silent(NEVER).0);
        let got = block_on(received(&http, "GET / HTTP/1.0\r\n\r\n"));
        assert!(got.starts_with(b"HTTP/1.1 403 "), "{got:?}");
        // A body passed as it comes is passed once.
        let ((a, sent), (b, again)) = (silent(NEVER), silent(&[OK]));
        let body = Unread { left: 1, chunked: None, rest: Vec::new() };
        assert_eq!(passed_to([a, b], "proxy_request_buffering off;", "PUT / HTTP/1.1\nHost: h\nContent-Length: 1\n\n", Some(body)), 504);
        assert_eq!((*sent.lock().unwrap(), *again.lock().unwrap()), (1, 0));
        // On a kept connection it uses up the try: no other is made to the server.
        let (a, came) = silent(&[OK]);
        let config = passing_to(&[a], "");
        // A server that timed out has failed: the other one gets the requests for a while.
        let ((b, sent), (c, _)) = (silent(NEVER), silent(&[OK, OK]));
        let two = passing_to(&[b, c], off);
        block_on(async {
            for want in [200, 504] {
                let resp = answered(&config.servers[0], "GET / HTTP/1.0\n\n").await;
                assert_eq!((resp.status, resp.upstream_status), (want, Some(want.to_string())));
            }
            for want in [504, 200, 200] { assert_eq!(answered(&two.servers[0], "GET / HTTP/1.0\n\n").await.status, want); }
        });
        assert_eq!((*came.lock().unwrap(), *sent.lock().unwrap()), (1, 1));
    }

    #[test]
    fn servers_that_take_no_connection_in_time() {
        // Its queue of connections, for as many as none, is full.
        let full = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        full.bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into()).unwrap();
        full.listen(0).unwrap();
        let a = full.local_addr().unwrap().as_socket().unwrap();
        let mut queue = Vec::new();
        while let Ok(s) = std::net::TcpStream::connect_timeout(&a, Duration::from_millis(200)) { queue.push(s); }
        let _busy = counted();
        HALTED.store(false, Ordering::SeqCst);
        for (directives, method, status, statuses) in [
            ("", "GET", 200, "504, 200"), ("proxy_next_upstream error;", "GET", 504, "504"), ("proxy_next_upstream timeout;", "GET", 200, "504, 200"),
            // Nothing was sent to it.
            ("", "POST", 200, "504, 200"),
        ] {
            let (b, came) = silent(&["HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"]);
            let config = passing_to(&[a, b], directives);
            let resp = block_on(answered(&config.servers[0], &format!("{method} / HTTP/1.0\n\n")));
            assert_eq!((resp.status, resp.upstream_status.as_deref()), (status, Some(statuses)), "{directives} {method}");
            assert_eq!(*came.lock().unwrap(), (status == 200) as usize, "{directives} {method}");
        }
    }

    /// An Ed25519 key and its certificate, made by openssl only for these tests (those of src/tls.rs).
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIABI8p3dtZAQNO9IIpddv0KdrpTZgBtF07GcXXMRAqlr\n-----END PRIVATE KEY-----\n";
    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBMDCB46ADAgECAhQw6INwvSpRntD3tYuScAjkJthNEDAFBgMrZXAwDTELMAkG
A1UEAwwCZWQwIBcNMjYxMTIyMTE0MTE3WhgPMjEyNjEwMjkxMTQxMTdaMA0xCzAJ
BgNVBAMMAmVkMCowBQYDK2VwAyEAL8XKbEjgrlhEUcjM4UHN6toe66wfOnYQD/ra
ShFX2D6jUzBRMB0GA1UdDgQWBBRx0M5Y4lwOex/ffMorAD1tsQoe8TAfBgNVHSME
GDAWgBRx0M5Y4lwOex/ffMorAD1tsQoe8TAPBgNVHRMBAf8EBTADAQH/MAUGAytl
cANBAI+4pL55PDAZuSVQBnX+wbeY2bLsGvIt8cw+b8Ugbunb6nN+nFiEuOXlpGgT
4q04yOy8aX97GVjXKn4C5xldyA0=
-----END CERTIFICATE-----
";

    /// What a server does with a request.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Act {
        Answer,
        /// Answers it, with close_notify after the answer.
        Notify,
        /// Answers it in so many bytes at least, with more plaintext after them.
        More(usize),
        /// Closes the connection, without an answer or a handshake.
        Close,
        /// Sends that, and closes the connection without close_notify.
        End(&'static str),
    }

    /// Reads a request and gives its request line.
    fn request_line(s: &mut impl Read) -> Option<String> {
        let (mut buf, mut chunk) = (Vec::new(), [0u8; 1024]);
        while head_end(&buf).is_none() {
            let n = s.read(&mut chunk).ok().filter(|n| *n > 0)?;
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8(buf).unwrap().lines().next().map(str::to_string)
    }

    /// The answer to a request, with its request line as the body.
    fn echo(line: &str, act: Act) -> String {
        let answer = |pad: usize| format!("HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: {}\r\n\r\n{line}", "x".repeat(pad), line.len());
        let Act::More(size) = act else { return answer(1) };
        answer(size.saturating_sub(answer(0).len())) + "more"
    }

    /// A server that does what act says with each request of a connection (both
    /// counted from 0), over TLS of the version once a handshake begins; and the
    /// requests that came, each with the number of its connection.
    fn securing(version: &'static rustls::SupportedProtocolVersion, act: fn(usize, usize) -> Act) -> (SocketAddr, Arc<Mutex<Vec<(usize, String)>>>) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        let key = PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap();
        let chain = vec![CertificateDer::from_pem_slice(CERT.as_bytes()).unwrap()];
        let config = Arc::new(rustls::ServerConfig::builder_with_protocol_versions(&[version]).with_no_client_auth().with_single_cert(chain, key).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let (addr, came) = (listener.local_addr().unwrap(), Arc::new(Mutex::new(Vec::new())));
        let all = came.clone();
        thread::spawn(move || {
            for (i, s) in listener.incoming().enumerate() {
                let (mut s, came, config, mut tls) = (s.unwrap(), all.clone(), config.clone(), None);
                thread::spawn(move || {
                    let mut first = [0];
                    for n in 0.. {
                        if s.peek(&mut first).ok() != Some(1) { return }
                        let act = act(i, n);
                        if act == Act::Close {
                            came.lock().unwrap().push((i, "closed".to_string()));
                            let _ = s.read(&mut [0u8; 4096]);
                            return;
                        }
                        // A handshake record begins with 22.
                        if tls.is_none() && first[0] == 22 { tls = Some(rustls::ServerConnection::new(config.clone()).unwrap()); }
                        let Some(tls) = &mut tls else {
                            let Some(line) = request_line(&mut s) else { return };
                            let answer = echo(&line, act);
                            came.lock().unwrap().push((i, line));
                            s.write_all(answer.as_bytes()).unwrap();
                            continue;
                        };
                        let Some(line) = request_line(&mut rustls::Stream::new(tls, &mut s)) else { return };
                        // What is written at once comes at once: the answer is one record.
                        let answer = if let Act::End(answer) = act { answer.to_string() } else { echo(&line, act) };
                        tls.writer().write_all(answer.as_bytes()).unwrap();
                        if act == Act::Notify { tls.send_close_notify(); }
                        came.lock().unwrap().push((i, line));
                        while tls.wants_write() { tls.write_tls(&mut s).unwrap(); }
                        if matches!(act, Act::End(_)) { return }
                    }
                });
            }
        });
        (addr, came)
    }

    /// The answers to the requests, which are sent one after another, each its body
    /// and $upstream_status, to the locations /s, which passes them over TLS, and
    /// /p, which does not, to an upstream with the settings and the server.
    fn secured(settings: &str, addr: SocketAddr, requests: &[&str]) -> Vec<(String, String)> {
        let text = format!("http {{ upstream u {{ server {addr}; {settings} }} server {{ location /s {{ proxy_pass https://u; }} location /p {{ proxy_pass http://u; }} }} }}");
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        block_on(async {
            let mut answers = Vec::new();
            for target in requests {
                let mut resp = answered(&config.servers[0], &format!("GET {target} HTTP/1.0\n\n")).await;
                finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
                // $upstream_connect_time of the last try.
                let times = resp.upstream_time.unwrap();
                assert!(times.last().unwrap()[0].is_some(), "{times:?}");
                answers.push((String::from_utf8(resp.body).unwrap(), resp.upstream_status.unwrap()));
            }
            answers
        })
    }

    #[test]
    fn an_end_without_close_notify_is_an_end() {
        let _busy = serving_on();
        // What the server sends before it closes, the body of the answer as it goes to the
        // client, whether the client's connection stays, and the log.
        const CASES: [(&str, &str, bool, &str); 7] = [
            ("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody", "body", true, "200 200 4"),
            ("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nbody", "body", false, "200 200 4"),
            ("HTTP/1.1 200 OK\r\n\r\nbody", "4\r\nbody\r\n0\r\n\r\n", true, "200 200 14"),
            ("HTTP/1.1 200 OK\r\n\r\n", "0\r\n\r\n", true, "200 200 5"),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n", "4\r\nbody\r\n", false, "200 200 9"),
            ("HTTP/1.1 200 OK\r\nX: ", "", true, "502 502"),
            ("", "", true, "502 502"),
        ];
        // The case of a connection to the server: each request has one.
        let act = |i, _| Act::End(CASES.iter().flat_map(|c| vec![c.0; 1 + c.2 as usize]).cycle().nth(i).unwrap());
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let (addr, _) = securing(version, act);
            for directives in ["", OFF] {
                for (_, body, stays, log) in CASES {
                    let path = log_path("tls-end");
                    let http = format!("log_format f '$status $upstream_status $body_bytes_sent'; access_log {} f; server {{ location / {{ proxy_pass https://{addr}; {directives} }} }}", path.display());
                    let got = block_on(async {
                        let (mut client, task) = served_by(&http).await;
                        client.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").await.unwrap();
                        let mut got = Vec::new();
                        within(Some(Duration::from_secs(4)), client.read_to_end(&mut got)).await.unwrap().unwrap();
                        drop(client);
                        within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
                        String::from_utf8(got).unwrap()
                    });
                    let (logged, status) = (logged(&path), format!("HTTP/1.1 {} ", &log[..3]));
                    assert_eq!((got.matches(&status).count(), logged.lines().count()), if stays { (2, 2) } else { (1, 1) }, "{got}");
                    assert!(got.starts_with(&status) && logged.starts_with(log), "{got} {logged}");
                    if !body.is_empty() { assert!(got.split_once("\r\n\r\n").unwrap().1.starts_with(body) && got.ends_with(body), "{got}"); }
                }
            }
        }
    }

    #[test]
    fn connections_over_tls_are_kept() {
        let _busy = serving_on();
        let all = |_, _| Act::Answer;
        let second = |i, n| if (i, n) == (0, 1) { Act::Close } else { Act::Answer };
        let (one, local) = ("keepalive 5;", "keepalive 5 local;");
        // The requests, and the connection each was answered on; "closed" is one
        // closed instead, after which the request is tried again.
        let cases: [(&str, fn(usize, usize) -> Act, &[&str], &[usize]); 11] = [
            (one, all, &["/s?1", "/s?2"], &[0, 0]),
            ("keepalive 0;", all, &["/s?1", "/s?2"], &[0, 1]),
            (one, |_, _| Act::Notify, &["/s?1", "/s?2"], &[0, 1]),
            (one, |_, _| Act::More(0), &["/s?1", "/s?2"], &[0, 1]),
            // What comes after the answer is not read with it.
            (one, |_, _| Act::More(4096), &["/s?1", "/s?2"], &[0, 1]),
            (one, second, &["/s?1", "/s?2", "/s?3"], &[0, 1, 1]),
            // The handshake is made on a connection kept without TLS.
            (one, all, &["/p?1", "/s?2", "/s?3"], &[0, 0, 0]),
            (one, second, &["/p?1", "/s?2", "/s?3"], &[0, 1, 1]),
            // One over TLS is used as it is.
            (one, all, &["/s?1", "/p?2"], &[0, 0]),
            (local, all, &["/p?1", "/s?2"], &[0, 1]),
            (local, all, &["/s?1", "/p?2", "/s?3"], &[0, 1, 0]),
        ];
        for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
            for (case, (settings, act, requests, connections)) in cases.iter().enumerate() {
                let (addr, came) = securing(version, *act);
                let answers = secured(settings, addr, requests);
                let mut want = Vec::new();
                for (n, (target, i)) in requests.iter().zip(*connections).enumerate() {
                    let again = (n, act(0, 1)) == (1, Act::Close);
                    if again { want.push((0, "closed".to_string())); }
                    want.push((*i, format!("GET {target} HTTP/1.1")));
                    assert_eq!(answers[n], (format!("GET {target} HTTP/1.1"), if again { "502, 200" } else { "200" }.to_string()), "{version:?} {case}");
                }
                assert_eq!(*came.lock().unwrap(), want, "{version:?} {case}");
            }
        }
    }

    #[test]
    fn checks_the_length_of_answers() {
        let _busy = serving_on();
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
        let resp = block_on(async {
            let mut resp = fetched(&addr, None, &level, (&mut [None; 3], &mut [0; 3]), &|_| 0).await.unwrap();
            finish(&mut resp, (&Level::default(), &request("GET / HTTP/1.1\n\n").1)).await;
            resp
        });
        assert_eq!((resp.body.as_slice(), resp.headers), (&b"ab"[..], vec![("Expires".to_string(), "a".to_string())]));
        for _ in 1..answers.len() {
            assert!(block_on(fetched(&addr, None, &level, (&mut [None; 3], &mut [0; 3]), &|_| 0)).is_none());
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
        let _busy = serving_on();
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
        let resp = block_on(proxy(&p, &level, &r, "", None));
        assert_eq!((resp.internal.as_deref(), resp.as_get, r.shared.limit_rate.get()), (Some("/b?c=1"), true, Some(13000)));
        assert!(resp.upstream_time.unwrap()[0][2].unwrap() < 1000);
    }

    #[test]
    fn range_offset() {
        let ranged = |h: &str, max| range_cacheable(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, max);
        assert!(ranged("Range: bytes=1-", Some(2)) && ranged("Range: bytes=  1-1,3-", Some(2)) && ranged("Range: bytes=9-", None));
        assert!(!ranged("Range: bytes=2-", Some(2)) && !ranged("Range: BYTES=-1", Some(2)) && !ranged("Range: bytes=0-0", Some(0)));
        // No Range, one that is not of bytes, or no offset in it, may be cached.
        assert!(ranged("Accept: a", Some(0)) && ranged("Range: items=5-", Some(2)) && ranged("Range: bytes=x", Some(2)) && ranged("Range: bytes=99999999999999999999-", Some(2)));
    }

    #[test]
    fn range_filter() {
        let file = || Response { status: 200, body: b"0123456789".to_vec(), ranges: true, headers: vec![
            ("Last-Modified".into(), "Sun, 06 Nov 1994 08:49:37 GMT".into()), ("ETag".into(), "\"e\"".into()), ("Accept-Ranges".into(), "bytes".into())], ..Response::default() };
        let ranged = |h: &str| { let mut resp = file(); range(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, &Level::default(), &mut resp); resp };
        let part = |resp: Response| (resp.status, String::from_utf8_lossy(&resp.body).into_owned(), resp.headers.last().map(|h| h.1.clone()).unwrap_or_default());
        assert_eq!(part(ranged("Range: bytes=2-4")), (206, "234".into(), "bytes 2-4/10".into()));
        assert_eq!(part(ranged("Range: BYTES=7-")), (206, "789".into(), "bytes 7-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=-3")), (206, "789".into(), "bytes 7-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=8-20\nIf-Range: \"e\"")), (206, "89".into(), "bytes 8-9/10".into()));
        assert_eq!(part(ranged("Range: bytes=0-0\nIf-Range: Sun, 06 Nov 1994 08:49:37 GMT")).0, 206);
        // Several ranges of what may have only one are answered with the whole.
        let single = |h: &str| { let mut resp = Response { single_range: true, ..file() }; range(&request(&format!("GET / HTTP/1.0\n{h}\n\n")).1, &Level::default(), &mut resp); (resp.status, resp.body) };
        assert_eq!(single("Range: bytes=0-1,4-5"), (200, b"0123456789".to_vec()));
        assert_eq!(single("Range: bytes=4-5"), (206, b"45".to_vec()));
        // Past the end, or backwards, is 416; a 206 has no Accept-Ranges.
        assert_eq!(part(ranged("Range: bytes=10-")).2, "bytes */10");
        assert_eq!(ranged("Range: bytes=5-3").status, 416);
        assert!(!ranged("Range: bytes=1-2").headers.iter().any(|h| h.0 == "Accept-Ranges"));
        // A malformed range is 416 too.
        for h in ["Range: bytes=a-2", "Range: bytes=12", "Range: bytes=1-2x", "Range: bytes=99999999999999999999-"] {
            assert_eq!(ranged(h).status, 416, "{h}");
        }
        // Not ranged: an If-Range that differs, an empty range from 0, ranges longer than the body, no "bytes=".
        for h in ["Range: bytes=1-2\nIf-Range: \"x\"", "Range: bytes=1-2\nIf-Range: wrong", "Range: bytes=0-,1-", "Range: items=1-2", "X: y"] {
            assert_eq!(ranged(h).status, 200, "{h}");
        }
        // More than one: parts of a multipart body, those past the end left out.
        let multi = ranged("Range: bytes=1-2, 4-4,20-");
        let boundary = multi.ctype.as_deref().unwrap().strip_prefix("multipart/byteranges; boundary=").unwrap().to_string();
        assert_eq!(boundary.len(), 20);
        let want = format!("\r\n--{boundary}\r\nContent-Range: bytes 1-2/10\r\n\r\n12\r\n--{boundary}\r\nContent-Range: bytes 4-4/10\r\n\r\n4\r\n--{boundary}--\r\n");
        assert_eq!((multi.status, String::from_utf8_lossy(&multi.body).into_owned()), (206, want));
        let typed = { let mut resp = Response { ctype: Some("text/plain".into()), ..file() }; range(&request("GET / HTTP/1.0\nRange: bytes=-1,0-0\n\n").1, &Level::default(), &mut resp); resp };
        assert!(String::from_utf8_lossy(&typed.body).contains("\r\nContent-Type: text/plain\r\nContent-Range: bytes 9-9/10\r\n\r\n9\r\n"));
        let mut resp = Response { ranges: false, ..file() };
        range(&request("GET / HTTP/1.0\nRange: bytes=1-2\n\n").1, &Level::default(), &mut resp);
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
        // If-Unmodified-Since holds at Last-Modified and after it; before it, unreadable, or without one, it fails.
        assert_eq!(status("If-Unmodified-Since: Sun, 06 Nov 1994 08:49:37 GMT", &level), 200);
        assert_eq!(status("If-Unmodified-Since: Sun, 06 Nov 1994 08:49:38 GMT", &level), 200);
        assert_eq!(status("If-Unmodified-Since: Sun, 06 Nov 1994 08:49:36 GMT", &level), 412);
        assert_eq!(status("If-Unmodified-Since: x", &level), 412);
        let mut resp = Response { headers: Vec::new(), ..ok() };
        not_modified(&request("GET / HTTP/1.0\nIf-Unmodified-Since: Sun, 06 Nov 1994 08:49:38 GMT\n\n").1, &level, &mut resp);
        assert_eq!(resp.status, 412);
        // The answer of a proxied server that is not cached is left as it is.
        let mut resp = Response { unconditional: true, ..ok() };
        not_modified(&request("GET / HTTP/1.0\nIf-None-Match: *\nIf-Match: \"x\"\n\n").1, &level, &mut resp);
        assert_eq!(resp.status, 200);
        let mut resp = ok();
        not_modified(&request("GET / HTTP/1.0\nIf-None-Match: *\n\n").1, &level, &mut resp);
        assert_eq!((resp.ctype, resp.body.len(), resp.headers.len()), (None, 0, 2));
        assert!(!etag_match("*", None, true));
    }

    #[test]
    fn sends_at_the_rate() {
        block_on(async {
            let (mut s, mut client) = pair().await;
            let started = Instant::now();
            let pace = |rate, after| Pace::new(rate, after, started);
            assert!(send(&mut s, &[&[b'x'; 1000], &[b'y'; 2000], &[]], &mut pace(0, 0), None).await);
            // 1000 bytes and 1000 a second: the rest goes after a second.
            assert!(send(&mut s, &[&[b'z'; 700], &[b'w'; 1800]], &mut pace(1000, 1000), None).await);
            assert!((1000..1900).contains(&started.elapsed().as_millis()));
            // So it does in several writes, which go on counting.
            let (started, mut pace) = (Instant::now(), Pace::new(1000, 1000, Instant::now()));
            for part in [&[b'z'; 900][..], &[b'w'; 100], &[b'w'; 1000], &[b'w'; 500]] {
                let before = started.elapsed();
                assert!(send(&mut s, &[part], &mut pace, None).await);
                // What goes before the rate is looked at is not waited for.
                assert!(part.len() == 500 || started.elapsed() - before < Duration::from_millis(500));
            }
            assert!(pace.sent == 2500 && (1000..1900).contains(&started.elapsed().as_millis()));
            let mut got = vec![0u8; 8000];
            client.read_exact(&mut got).await.unwrap();
            let want = [vec![b'x'; 1000], vec![b'y'; 2000], vec![b'z'; 700], vec![b'w'; 1800], vec![b'z'; 900], vec![b'w'; 1600]].concat();
            assert!(got == want);
            drop(client);
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!send(&mut s, &[&vec![b'x'; 1 << 22]], &mut Pace::new(1 << 20, 0, Instant::now()), None).await);
            // A client that does not read for send_timeout fails the write.
            let (mut s, _client) = pair().await;
            let mut pace = Pace::new(0, 0, Instant::now());
            assert!(!send(&mut s, &[&vec![b'x'; 1 << 24]], &mut pace, Some(Duration::from_millis(200))).await);
            // What it took before is counted.
            assert!((1..1 << 24).contains(&pace.sent));
        });
    }

    #[test]
    fn decimal_digits() {
        assert_eq!([0, 7, 200, u64::MAX].map(|n| decimal(&mut [0; 20], n).to_string()), ["0", "7", "200", "18446744073709551615"]);
    }

    #[test]
    fn hides_proxied_headers() {
        let _busy = serving_on();
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
        let resp = block_on(proxy(&p, &level, &r, "/", None));
        assert_eq!(resp.upstream_addr, Some(addr.to_string()));
        assert_eq!((resp.ctype, resp.headers), (None, vec![("X-B".to_string(), "2".to_string())]));
    }

    #[test]
    fn urls_with_variables() {
        let (_, r) = request("GET /a?b HTTP/1.0\n\n");
        let group = Arc::new(Upstream::new(Vec::new()));
        let p = Proxy { host: String::new(), ssl: false, upstream: group.clone(), uri: None, url: None, groups: [("u".to_string(), group)].into(), implicit: Default::default() };
        assert_eq!(block_on(resolved("http://u/y", &p, &Level::default(), &r)).map(|t| (t.0, t.1)), Some(("u".into(), "/y".into())));
        let (host, uri, up) = block_on(resolved("http://127.0.0.2:81/x", &p, &Level::default(), &r)).unwrap();
        assert_eq!((host.as_str(), uri.as_str(), up.peers[0].addr.to_string()), ("127.0.0.2:81", "/x", "127.0.0.2:81".to_string()));
        assert_eq!(block_on(resolved("http://127.0.0.2", &p, &Level::default(), &r)).map(|t| (t.0, t.1)), Some(("127.0.0.2".into(), "/a?b".into())));
        assert!(block_on(resolved("http://example.net/x", &p, &Level::default(), &r)).is_none());
        let (_, _, up) = block_on(resolved("http://[::1]:82/x", &p, &Level::default(), &r)).unwrap();
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
    fn reads_unbuffered_as_the_proxy_handler_decides() {
        let text = "http { server { proxy_request_buffering off; \
                    location /a { proxy_pass http://127.0.0.1:1; } \
                    location /b { proxy_pass http://127.0.0.1:1; proxy_http_version 1.0; } \
                    location /c { proxy_pass http://127.0.0.1:1; proxy_set_body x; } \
                    location /d { proxy_pass http://127.0.0.1:1; proxy_pass_request_body off; } \
                    location /e { proxy_pass http://127.0.0.1:1; proxy_request_buffering on; } \
                    location /f { } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let got: Vec<_> = config.servers[0].locations.iter().map(|l| (unbuffered(&l.level, false), unbuffered(&l.level, true))).collect();
        assert_eq!(got, [(true, true), (true, false), (false, false), (false, false), (false, false), (false, false)]);
    }

    #[test]
    fn keeps_empty_framed_bodies_in_files() {
        // With client_body_in_file_only, an empty body goes in a file when the request framed it, not when it has none.
        let dir = std::env::temp_dir().join(format!("twinx-empty-body-{}", std::process::id()));
        let level = Level { body_in_file_only: true, body_buffer: 4, body_temp_path: dir, ..Level::default() };
        let (_, mut r) = request("POST / HTTP/1.0\nContent-Length: 0\n\n");
        keep_body(&mut r, &level, Vec::new()).unwrap();
        assert_eq!(std::fs::read(r.body_file.unwrap()).unwrap(), b"");
        let (_, mut r) = request("GET / HTTP/1.0\n\n");
        keep_body(&mut r, &level, Vec::new()).unwrap();
        assert!(r.body_file.is_none());
    }

    #[test]
    fn locations_that_read_bodies() {
        assert!(!reads_body(&Level::default()));
        assert!(reads_body(&Level { try_files: Some(Arc::new(TryFiles { files: Vec::new(), fallback: Fallback::Status(404) })), ..Level::default() }));
        assert!(reads_body(&Level { post_action: Some("/a".into()), ..Level::default() }));
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
        assert_eq!((parse(&mut r, b"GET /foo//../b%2F/c HTTP/1.0\r\n\r\n", &level, false), r.uri.as_str()), (Ok(()), "/b/c"));
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
            let (mut resp, level, _) = block_on(answer(s, &r, Ok(()), located(s, &r, &r.uri), None));
            load(&r, level, &mut resp);
            String::from_utf8(resp.body).unwrap()
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
            (block_on(answer(s, &r, Ok(()), found, None)).0.status, found.1.proxy.is_some())
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
            let resp = block_on(respond(&r, Ok(()), location(s, &r.uri), None));
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
            let resp = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None)).0;
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
        assert_eq!(block_on(respond(&r, Ok(()), location(s, &r.uri), None)).status, 404);
        let named = (s.locations[1].path.as_str(), &s.locations[1].level, false);
        assert_eq!(block_on(respond(&r, Ok(()), named, None)).body, b"n/a");
    }

    #[test]
    fn sets_limit_rate() {
        let text = "http { server { set $limit_rate 1k; location /a { set $limit_rate $arg_l; return 200 $limit_rate; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        let rate = |target: &str| {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            String::from_utf8(block_on(super::answer(s, &r, Ok(()), location(s, &r.uri), None)).0.body).unwrap()
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
            let (resp, level, _) = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None));
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
            String::from_utf8(block_on(super::answer(s, &r, Ok(()), location(s, &r.uri), None)).0.body).unwrap()
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
            let resp = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None)).0;
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
        let _busy = serving_on();
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
        assert_eq!(block_on(proxy(&p, &level, &r, "", None)).status, 204);
        let sent = got.join().unwrap();
        assert!(sent.contains("Content-Length: 3\r\n") && sent.ends_with("\r\n\r\nb=1"), "{sent}");
    }

    #[test]
    fn passes_bodies_as_they_come() {
        block_on(async {
            let (mut client, mut out) = pair().await;
            let unread = |left: u64, chunked: Option<&[u8]>| Unread { left, chunked: chunked.map(|c| (c.to_vec(), 1)), rest: Vec::new() };
            out.write_all(b"abcdef").await.unwrap();
            let (mut to, mut u) = (Vec::new(), unread(4, None));
            assert_eq!(pass_body(&mut u, &mut client, 100, &mut to).await, Some(4));
            assert_eq!((to.as_slice(), u.left), (&b"abcd"[..], 0));
            // A chunked body: the data that came after the one passed, in one chunk
            // for each read, then the last chunk; what follows it is kept.
            let (mut to, mut u) = (Vec::new(), unread(0, Some(b"3\r\nx")));
            out.write_all(b"\r\n4\r\nmany\r\n0\r\n\r\nGET").await.unwrap();
            assert_eq!(pass_body(&mut u, &mut client, 100, &mut to).await, Some(16));
            assert_eq!((String::from_utf8_lossy(&to), u.rest.as_slice()), ("6\r\nefmany\r\n0\r\n\r\n".into(), &b"GET"[..]));
            // An invalid chunk, or the client closing before the end, fails it.
            assert_eq!(pass_body(&mut unread(0, Some(b"z\r\n")), &mut client, 100, &mut to).await, None);
            drop(out);
            let mut u = unread(5, None);
            assert_eq!(pass_body(&mut u, &mut client, 100, &mut to).await, None);
            assert_eq!(u.left, 5);
        });
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
        assert!(gzip_ok(&Request { line: "GET / HTTP/2.0".to_string(), ..request("GET / HTTP/1.1\nHost: a\nAccept-Encoding: gzip\n\n").1 }, &level));
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
        let level = Level { gzip: true, gzip_http_11: true, gzip_min_length: 20, gzip_types: vec!["text/plain".to_string()], ..Level::default() };
        let (_, r) = request("GET / HTTP/1.1\nHost: a\nAccept-Encoding: gzip\n\n");
        let make = |status, ctype: &str, len| {
            let headers = vec![("ETag".to_string(), "\"1-2\"".to_string()), ("Accept-Ranges".to_string(), "bytes".to_string())];
            Response { status, ctype: Some(ctype.to_string().into()), headers, body: vec![b'X'; len], ..Response::default() }
        };
        let mut resp = make(404, "text/plain; charset=utf-8", 64);
        gzip(&r, &level, &mut resp);
        assert!(resp.vary && resp.unknown_length);
        assert_eq!(&resp.body[..10], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 3]);
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
        // gzip_min_length 0 compresses an empty body too.
        let mut empty = make(200, "text/html", 0);
        gzip(&r, &Level { gzip_min_length: 0, ..level.clone() }, &mut empty);
        assert_eq!(empty.body.len(), 20);
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
            let (resp, _, _) = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None));
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
            let (resp, _, last) = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None));
            (resp.status, last.into_owned().target)
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
            let (mut resp, level, _) = block_on(answer(s, &r, Ok(()), location(s, &r.uri), None));
            load(&r, level, &mut resp);
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
    fn request_uri_is_that_of_the_request_line_after_redirects() {
        let _busy = serving_on();
        // A server that answers with the request line it got, or redirects to /out.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for s in listener.incoming() {
                let (mut s, mut req, mut chunk) = (s.unwrap(), Vec::new(), [0u8; 1024]);
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    req.extend_from_slice(&chunk[..n]);
                }
                let req = String::from_utf8(req).unwrap();
                let to = if req.contains(" /xa") { "X-Accel-Redirect: /out?x=1\r\n" } else { "" };
                let of = req.split("\r\n").find_map(|l| l.strip_prefix("X-Of: ")).unwrap_or_default();
                let line = req.split(" HTTP/").next().unwrap();
                s.write_all(format!("HTTP/1.1 200 OK\r\n{to}\r\n{line}|{of}").as_bytes()).unwrap();
            }
        });
        let dir = files("request-uri");
        std::fs::create_dir_all(dir.join("i")).unwrap();
        std::fs::write(dir.join("i/index.html"), "").unwrap();
        let text = format!("http {{ server {{ root {}; proxy_set_header X-Of $request_uri; location /out {{ return 200 \"$request_uri $uri $args\"; }} \
            location /rw {{ rewrite ^ /out?x=1 last; }} location /two {{ rewrite ^ /ep?y=2 last; }} location /break {{ rewrite ^ /out; return 200 \"$request_uri $uri $args\"; }} \
            location /ep {{ error_page 404 = /out; }} location /tf {{ try_files /none /out; }} location /en {{ error_page 404 = @n; }} location /tn {{ try_files /none @n; }} \
            location @n {{ proxy_pass http://{addr}; }} location = /i/index.html {{ return 200 \"$request_uri $uri $args\"; }} location /xa {{ proxy_pass http://{addr}; }} \
            location /if {{ rewrite ^ /fi?x=1 last; }} location /fi {{ set $was no; if ($request_uri ~ ^/if) {{ set $was if; }} return 200 $was; }} \
            location /px/ {{ proxy_pass http://{addr}; }} location /pu/ {{ proxy_pass http://{addr}/base/; }} location /pv/ {{ set $to {addr}; proxy_pass http://$to; }} \
            location /rx/ {{ rewrite ^/rx(/(.|\\n)*)$ /px$1?x=1 last; }} location /ru/ {{ rewrite ^/ru(.*)$ /pu$1 last; }} location /rv/ {{ rewrite ^/rv(.*)$ /pv$1 last; }} \
            location /rn/ {{ rewrite ^/rn(.*)$ /tn$1 last; }} location /bx/ {{ rewrite ^/bx(.*)$ /b$1 break; proxy_pass http://{addr}; }} \
            location /ta {{ try_files /none /px/t?$args; }} location /q/ {{ rewrite ^/q/(.*)$ /r/$1 last; }} location /p/ {{ rewrite ^/p/(.*)$ /r/+$1 last; }} \
            location /r/ {{ rewrite ^/r/(.*)$ /out?z=$1 last; }} }} }}", dir.display());
        let config = crate::conf::build(&crate::config::parse(&text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        for (target, body) in [
            ("/rw", "/rw /out x=1"), ("/rw?q=2", "/rw?q=2 /out x=1&q=2"), ("/two?q=2", "/two?q=2 /out "), ("/break?q=2", "/break?q=2 /out q=2"),
            ("/ep?q=2", "/ep?q=2 /out "), ("/tf?q=2", "/tf?q=2 /out "), ("/i/?q=2", "/i/?q=2 /i/index.html q=2"), ("/xa?q=2", "/xa?q=2 /out x=1"), ("/if", "if"),
            // A named location, which leaves the URI, passes the request line's.
            ("/en/%61?q=2", "GET /en/%61?q=2|/en/%61?q=2"), ("/tn/%61?", "GET /tn/%61?|/tn/%61?"), ("/px/%61?", "GET /px/%61?|/px/%61?"),
            // A URI that replaced it is passed escaped, without a "?" that nothing follows.
            ("/rx/a%20b%0D%0AX:%201?q=2", "GET /px/a%20b%0D%0AX:%201?x=1&q=2|/rx/a%20b%0D%0AX:%201?q=2"), ("/ru/a%20b?q=2", "GET /base/a%20b?q=2|/ru/a%20b?q=2"),
            ("/rv/a%20b", "GET /pv/a%20b|/rv/a%20b"), ("/rn/a%20b", "GET /tn/a%20b|/rn/a%20b"), ("/bx/a%20b?", "GET /b/a%20b|/bx/a%20b?"),
            ("/ta", "GET /px/t|/ta"), ("/ta?", "GET /px/t|/ta?"), ("/ta?q=2", "GET /px/t?q=2|/ta?q=2"), ("/pu/a?", "GET /base/a|/pu/a?"),
            // Whether a capture is escaped in the arguments depends on the request line's.
            ("/q/a%26b?q=2", "/q/a%26b?q=2 /out z=a%26b&q=2"), ("/p/a", "/p/a /out z=+a"),
        ] {
            let got = exchanged(&config.servers[0], target);
            assert_eq!(got.split_once("\r\n\r\n").map(|a| a.1), Some(body), "{target}");
        }
        assert_eq!(escape_uri(&crate::vars::text(b"/\xff\xc3\xa9")), "/%FF%C3%A9");
    }

    #[test]
    fn post_action_answers_in_the_background() {
        let text = "http { server { location / { post_action @n; } location @n { return 204; } location /u { post_action /x?a; } } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let s = &config.servers[0];
        for target in ["/", "/u"] {
            let (_, r) = request(&format!("GET {target} HTTP/1.0\n\n"));
            block_on(post_action(s, &r, location(s, &r.uri).1, None));
        }
        assert_eq!(location(s, "/").1.post_action.as_deref(), Some("@n"));
    }

    /// Bytes that tell where in a file they are, letters, so many of them.
    pub(crate) fn letters(n: usize) -> Vec<u8> {
        (0..n).map(|i| b'a' + ((i + i / 26 + i / 32768 * 7) % 26) as u8).collect()
    }

    /// An empty directory of a test, for the files it serves and what it logs.
    pub(crate) fn files(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("twinx-files-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The http block of a server of the files in a directory, with what it logs there.
    pub(crate) fn serves_files(dir: &std::path::Path, directives: &str) -> String {
        format!("log_format f '$status $bytes_sent $body_bytes_sent'; access_log {0}/log f; error_log {0}/errors; server {{ root {0}; {directives} }}", dir.display())
    }

    /// The answer without its Date line as its head and its body, taken out of its chunks, whose sizes are the third.
    fn parted(answer: &[u8]) -> (String, Vec<u8>, Vec<usize>) {
        let end = head_end(answer).unwrap();
        let (head, mut left, mut body, mut sizes) = (undated(&answer[..end]), &answer[end..], Vec::new(), Vec::new());
        if !head.contains("Transfer-Encoding: chunked") { return (head, left.to_vec(), sizes) }
        loop {
            let line = line_end(left).unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&left[..line - 2]).unwrap(), 16).unwrap();
            if size == 0 { return (head, body, sizes) }
            sizes.push(size);
            body.extend_from_slice(&left[line..line + size]);
            left = &left[line + size + 2..];
        }
    }

    #[test]
    fn files_are_sent_piece_by_piece() {
        let _busy = serving_on();
        let dir = files("pieces");
        let directives = "location /t { alias DIR/f; add_trailer X-T v; } location /g { gzip_static always; alias DIR/f; } location /e { error_page 404 /f; return 404; }
            location /x { try_files /none /f =404; } location /i/ { alias DIR/; index f; } location /r { rewrite . /f; } location /z { alias DIR/f; gzip on; gzip_types *; }".replace("DIR", &dir.display().to_string());
        const SENDFILE: [&str; 5] = ["", "sendfile on;", "sendfile on; sendfile_max_chunk 100;", "sendfile on; sendfile_max_chunk 0; tcp_nopush on; tcp_nodelay off;", "sendfile on; tcp_nopush on; limit_rate 100m;"];
        for (n, sendfile) in [0, 1, 20, 16384, 16385, 32767, 32768, 32769, 65535, 65536, 65537, 100_000, 300_001].into_iter().flat_map(|n| SENDFILE.map(|s| (n, s))) {
            let directives = format!("{sendfile} {directives}");
            let data = letters(n);
            std::fs::write(dir.join("f"), &data).unwrap();
            std::fs::write(dir.join("f.gz"), &data).unwrap();
            let got = |requests: &str| block_on(received(&serves_files(&dir, &directives), requests));
            let ask = |uri: &str| parted(&got(&format!("GET {uri} HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")));
            let pieces: Vec<usize> = if n <= 32768 || !sendfile.is_empty() { [n].into_iter().filter(|&n| n > 0).collect() } else { data.chunks(32768).map(<[u8]>::len).collect() };
            for (uri, status) in [("/f", 200), ("/e", 404), ("/x", 200), ("/i/", 200), ("/r", 200), ("/g", 200)] {
                let (head, body, _) = ask(uri);
                assert!(head.starts_with(&format!("HTTP/1.1 {status} ")) && head.contains(&format!("\r\nContent-Length: {n}\r\n")) && body == data, "{uri} {n} {head}");
                assert_eq!(head.contains("Content-Encoding: gzip"), uri == "/g");
            }
            let (head, body, sizes) = ask("/t");
            assert!(body == data && sizes == pieces, "{n} {head} {sizes:?}");
            // With gzip, for a client that takes it and one that does not.
            let (head, body, _) = parted(&got("GET /z HTTP/1.1\r\nHost: a\r\nConnection: close\r\nAccept-Encoding: gzip\r\n\r\n"));
            let mut plain = Vec::new();
            if n >= 20 { flate2::read::GzDecoder::new(body.as_slice()).read_to_end(&mut plain).unwrap() } else { plain = body; n };
            assert!(plain == data && head.contains("Content-Encoding: gzip") == (n >= 20), "{n} {head}");
            assert!(ask("/z").1 == data);
            // After each other on a connection, without a head, to HTTP/1.0 and to HEAD.
            let _ = std::fs::remove_file(dir.join("log"));
            let head = format!("HTTP/1.1 200 OK\r\nServer: {NAME}\r\nContent-Type: text/plain\r\nContent-Length: {n}\r\nConnection: CONNECTION\r\nLAST");
            let text = got("GET /f HTTP/1.1\r\nHost: a\r\n\r\nHEAD /f HTTP/1.1\r\nHost: a\r\n\r\nGET /f HTTP/1.0\r\n\r\n");
            let modified = String::from_utf8_lossy(&text).split_once("Last-Modified").unwrap().1.split_once("\r\n\r\n").unwrap().0.to_string();
            let head = |connection: &str| head.replace("CONNECTION", connection).replace("LAST", &format!("Last-Modified{modified}\r\n\r\n")).into_bytes();
            let want = [head("keep-alive"), data.clone(), head("keep-alive"), head("close"), data.clone()].concat();
            assert!(String::from_utf8_lossy(&text) == String::from_utf8_lossy(&want), "{n} {}", text.len());
            let log = std::fs::read_to_string(dir.join("log")).unwrap();
            let date = "Date: Mon, 23 Nov 2026 00:00:00 GMT\r\n".len();
            let line = |head: usize, body: usize| format!("200 {} {body}\n", head + date + body);
            assert_eq!(log, [line(head("keep-alive").len(), n), line(head("keep-alive").len(), 0), line(head("close").len(), n)].concat());
            assert!(got("GET /f\r\n") == data);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn answers_without_their_body_have_its_length() {
        let _busy = serving_on();
        let gz = "gzip on; gunzip on; gzip_vary on;";
        for (method, status, more, directives, want) in [
            ("HEAD", "200 OK", "Content-Length: 1234\r\n", "", "Content-Length: 1234\r\n"),
            ("HEAD", "404 Not Found", "Content-Length: 77\r\n", "", "Content-Length: 77\r\n"),
            ("HEAD", "200 OK", "", "", ""),
            ("HEAD", "200 OK", "Content-Length: 0\r\n", "", "Content-Length: 0\r\n"),
            ("HEAD", "200 OK", "Transfer-Encoding: chunked\r\n", "", ""),
            ("HEAD", "200 OK", "Content-Length: 1234\r\n", "add_trailer X 1;", "Content-Length: 1234\r\n"),
            ("HEAD", "200 OK", "Content-Length: 1234\r\n", gz, "Vary: Accept-Encoding\r\nContent-Encoding: gzip\r\n"),
            ("HEAD", "200 OK", "", gz, "Vary: Accept-Encoding\r\nContent-Encoding: gzip\r\n"),
            ("HEAD", "200 OK", "Content-Length: 19\r\n", gz, "Content-Length: 19\r\n"),
            ("HEAD", "201 Created", "Content-Length: 1234\r\n", gz, "Content-Length: 1234\r\n"),
            ("HEAD", "200 OK", "Content-Length: 1234\r\nContent-Encoding: gzip\r\n", "gunzip on; gzip_http_version 1.1; proxy_set_header X 1;", "Content-Length: 1234\r\nContent-Encoding: gzip\r\n"),
            ("GET", "204 No Content", "", "", ""), ("GET", "204 No Content", "Content-Length: 5\r\n", gz, "Content-Length: 5\r\n"),
            ("GET", "304 Not Modified", "", "", ""), ("GET", "304 Not Modified", "Content-Length: 1234\r\n", gz, "Content-Length: 1234\r\n"),
            ("HEAD", "304 Not Modified", "Content-Length: 1234\r\n", "", "Content-Length: 1234\r\n"),
            // What twinx answers itself has no length then.
            ("GET", "200 OK", "Content-Length: 4\r\n\r\nabcd", "return 204;", ""),
        ] {
            let head = format!("HTTP/1.1 {status}\r\nContent-Type: text/html\r\n{more}\r\n");
            let (addr, _count) = plays(&vec![(0, head.into_bytes())], false);
            let requests = format!("{method} / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip\r\n\r\n");
            // The connection serves the next request.
            let got = String::from_utf8(block_on(received(&passing(addr, directives), &format!("{requests}{}", requests.replace("\r\n\r\n", "\r\nConnection: close\r\n\r\n"))))).unwrap();
            let lines = |part: &str| part.split("\r\n").skip(1).filter(|l| ["content-length", "content-encoding", "transfer-encoding", "vary"].iter().any(|n| l.to_ascii_lowercase().starts_with(n))).map(|l| format!("{l}\r\n")).collect::<String>();
            let parts: Vec<_> = got.split_inclusive("\r\n\r\n").map(lines).collect();
            assert_eq!(parts, [want, want], "{method} {status} {more} {directives} {got}");
        }
    }

    #[test]
    fn files_are_compressed_piece_by_piece() {
        let _busy = serving_on();
        let dir = files("coded");
        // What compresses to nearly as much, so that a piece gives more than one buffer.
        let mut x = 1u32;
        let data: Vec<u8> = (0..300_001).map(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; x as u8 }).collect();
        std::fs::write(dir.join("f"), &data).unwrap();
        let http = serves_files(&dir, "gzip on; gzip_types *; location /t { alias DIR/f; add_trailer X-T v; }".replace("DIR", &dir.display().to_string()).as_str());
        let got = |line: &str, more: &str| block_on(received(&http, &format!("{line}\r\nHost: a\r\nConnection: close\r\nAccept-Encoding: gzip\r\n{more}\r\n")));
        for (line, trailer) in [("GET /f HTTP/1.1", false), ("GET /t HTTP/1.1", true)] {
            let answer = got(line, "");
            let (head, body, sizes) = parted(&answer);
            assert!(head.contains("\r\nContent-Encoding: gzip\r\n") && head.contains("ETag: W/") && !head.contains("Content-Length") && !head.contains("Accept-Ranges"), "{head}");
            let mut plain = Vec::new();
            flate2::read::GzDecoder::new(body.as_slice()).read_to_end(&mut plain).unwrap();
            assert!(plain == data && sizes.len() > 4 && sizes.iter().all(|n| *n <= 1 << 17), "{sizes:?}");
            assert_eq!(answer.ends_with(b"0\r\nX-T: v\r\n\r\n"), trailer);
        }
        // A range of what is compressed is not given.
        assert!(parted(&got("GET /f HTTP/1.1", "Range: bytes=1-2\r\n")).0.starts_with("HTTP/1.1 200 "));
        // The head for HEAD is that for GET, but for how the body comes.
        let heads = ["GET", "HEAD"].map(|m| { let answer = got(&format!("{m} /f HTTP/1.1"), ""); undated(&answer[..head_end(&answer).unwrap()]) });
        assert_eq!(heads[1], heads[0].replace("Transfer-Encoding: chunked\r\n", ""));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parts_of_files_are_sent() {
        let _busy = serving_on();
        let (dir, data) = (files("parts"), letters(100_000));
        std::fs::write(dir.join("f"), &data).unwrap();
        for directives in ["", "sendfile on;", "sendfile on; sendfile_max_chunk 5k; tcp_nopush on;"] {
            let get = |more: &str| parted(&block_on(received(&serves_files(&dir, directives), &format!("GET /f HTTP/1.1\r\nHost: a\r\nConnection: close\r\n{more}\r\n"))));
            for (range, from, to) in [("0-0", 0, 1), ("0-32767", 0, 32768), ("0-32768", 0, 32769), ("32767-32768", 32767, 32769), ("32768-65535", 32768, 65536), ("10-99998", 10, 99999), ("0-", 0, 100_000),
                                      ("99999-", 99999, 100_000), ("-1", 99999, 100_000), ("-40000", 60000, 100_000), ("-200000", 0, 100_000), ("50000-200000", 50000, 100_000)] {
                let (head, body, _) = get(&format!("Range: bytes={range}\r\n"));
                assert!(head.starts_with("HTTP/1.1 206 ") && head.contains(&format!("\r\nContent-Length: {}\r\n", to - from)) && head.contains(&format!("\r\nContent-Range: bytes {from}-{}/100000\r\n", to - 1)), "{range} {head}");
                assert!(body == data[from..to], "{range}");
            }
            let etag = get("").0.split_once("ETag: ").unwrap().1.split_once("\r\n").unwrap().0.to_string();
            assert!(etag.ends_with("-186a0\""));
            for (more, status, length, has) in [("Range: bytes=100000-\r\n".to_string(), "416", None, "bytes */100000"), ("If-None-Match: *\r\n".into(), "304", Some(0), ""), ("If-Match: \"x\"\r\n".into(), "412", None, ""),
                                                (format!("If-Range: {etag}\r\nRange: bytes=1-40000\r\n"), "206", Some(40000), ""), ("If-Range: \"x\"\r\nRange: bytes=1-2\r\n".into(), "200", Some(100_000), "")] {
                let (head, body, _) = get(&more);
                assert!(head.starts_with(&format!("HTTP/1.1 {status} ")) && head.contains(has) && length.is_none_or(|n| body.len() == n), "{more} {head}");
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The server of the files in a directory, a request of it, and its answer, of whose file nothing is read yet.
    fn unread(dir: &std::path::Path, head: &str) -> (Config, Request, Response) {
        let config = crate::conf::build(&crate::config::parse(&format!("http {{ {} }}", serves_files(dir, "")), std::path::Path::new("t")).unwrap(), dir).unwrap();
        let (_, r) = request(head);
        let resp = block_on(answered(&config.servers[0], head));
        (config, r, resp)
    }

    #[test]
    fn files_are_opened_and_nothing_is_read() {
        let dir = files("opened");
        std::fs::create_dir(dir.join("d")).unwrap();
        for (name, n) in [("small", 100), ("large", 100_000)] {
            std::fs::write(dir.join(name), letters(n)).unwrap();
            let head = format!("HEAD /{name} HTTP/1.1\nHost: a\nIf-None-Match: *\nRange: bytes=10-29\n\n");
            let (config, r, mut resp) = unread(&dir, &head);
            assert!(resp.body.is_empty() && resp.len() == n);
            range(&r, &Level::default(), &mut resp);
            let file = resp.file.as_ref().unwrap();
            assert!((resp.status, file.start, file.len, resp.len(), resp.body.len()) == (206, 10, 20, 20, 0));
            load(&r, &config.servers[0].level, &mut resp);
            assert!(resp.file.is_none() && resp.body == letters(n)[10..30]);
            let (config, r, mut resp) = unread(&dir, &head);
            not_modified(&r, &config.servers[0].level, &mut resp);
            assert!((resp.status, resp.file.is_none(), resp.len()) == (304, true, 0));
        }
        // What is no file, a named pipe that no one writes to among that, and what may not be read.
        let fifo = std::ffi::CString::new(dir.join("p").display().to_string()).unwrap();
        // SAFETY: the path ends with a NUL.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        for (target, method, status) in [("/p", "GET", 404), ("/none", "GET", 404), ("/d", "GET", 301), ("/d", "POST", 301), ("/small", "POST", 405), ("/small/x", "GET", 404)] {
            let (.., resp) = unread(&dir, &format!("{method} {target} HTTP/1.0\n\n"));
            assert_eq!((resp.status, resp.file.is_none()), (status, true), "{method} {target}");
        }
        std::fs::set_permissions(dir.join("small"), std::os::unix::fs::PermissionsExt::from_mode(0)).unwrap();
        // For root, it may be.
        if std::fs::File::open(dir.join("small")).is_err() { assert_eq!(unread(&dir, "GET /small HTTP/1.0\n\n").2.status, 403); }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_that_become_shorter_or_longer_meanwhile() {
        let _busy = serving_on();
        let (dir, data) = (files("shorter"), letters(200_000));
        let path = dir.join("f");
        let length = |n| std::fs::File::options().write(true).open(&path).unwrap().set_len(n).unwrap();
        let shorter = |of: usize| format!(" [alert] {}#0: pread() read only NUMBER of {of} from \"{}\" while sending response to client, client: ", std::process::id(), path.display());
        for (n, to, got) in [(200_000, 0, 0), (20_000, 19_999, 19_999), (40_000, 32767, 32767), (200_000, 32768, 0)] {
            std::fs::write(&path, &data[..n]).unwrap();
            let (config, r, resp) = unread(&dir, "GET /f HTTP/1.0\n\n");
            length(to);
            let sent = block_on(async {
                let (mut s, mut client) = pair().await;
                let mut file = resp.file.unwrap();
                file.start += if got == 0 && to > 0 { to } else { 0 };
                file.len -= file.start;
                let level = &config.servers[0].level;
                let sent = send_file(&mut s, file, &Response::default(), (b"head", false), Pace::new(0, 0, Instant::now()), (&r, level), |_, _| Vec::new()).await;
                drop(s);
                // Nothing of the piece that is not all there is sent.
                assert_eq!(client.read_to_end(&mut Vec::new()).await.unwrap(), 0);
                sent
            });
            assert_eq!((sent.0, sent.1), (false, (0, 0)));
            let log = std::fs::read_to_string(dir.join("errors")).unwrap();
            assert!(log.contains(&shorter(n.min(32768)).replace("NUMBER", &got.to_string())), "{log}");
        }
        for (requested, to) in [("GET /f HTTP/1.1\r\nHost: a\r\n\r\n", 70_000), ("GET /f HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n", 400_000)] {
            std::fs::write(&path, &data).unwrap();
            let _ = std::fs::remove_file(dir.join("log"));
            block_on(async {
                let (mut client, task) = served_by(&serves_files(&dir, "limit_rate 200k; limit_rate_after 1;")).await;
                client.write_all(requested.as_bytes()).await.unwrap();
                let mut got = vec![0; 1];
                client.read_exact(&mut got).await.unwrap();
                length(to);
                within(Some(Duration::from_secs(4)), client.read_to_end(&mut got)).await.unwrap().unwrap();
                within(Some(Duration::from_secs(2)), task).await.unwrap().unwrap();
                let (head, body, _) = parted(&got);
                // One that has become shorter is sent as far as it was read in whole pieces, one that is longer up to its length.
                assert!(head.contains("\r\nContent-Length: 200000\r\n") && body == data[..if to < 200_000 { 65536 } else { 200_000 }], "{} {to}", body.len());
                let log = std::fs::read_to_string(dir.join("log")).unwrap();
                assert_eq!(log, format!("200 {} {}\n", got.len(), body.len()));
            });
        }
        assert!(std::fs::read_to_string(dir.join("errors")).unwrap().contains(&shorter(32768).replace("NUMBER", "4464")));
        // With sendfile, it is sent as far as it goes.
        let log = std::fs::read_to_string(dir.join("errors")).unwrap().len();
        for (n, to, kept) in [(200_000, 0, 0), (200_000, 70_000, 70_000), (40_000, 39_999, 39_999), (200_000, 400_000, 200_000)] {
            std::fs::write(&path, &data[..n]).unwrap();
            let (mut config, r, resp) = unread(&dir, "GET /f HTTP/1.0\n\n");
            config.servers[0].level.sendfile = true;
            length(to);
            block_on(async {
                let (mut s, mut client) = pair().await;
                let sent = send_file(&mut s, resp.file.unwrap(), &Response::default(), (b"head", false), Pace::new(0, 0, Instant::now()), (&r, &config.servers[0].level), |_, _| Vec::new()).await;
                drop(s);
                let mut got = Vec::new();
                client.read_to_end(&mut got).await.unwrap();
                assert!((sent.0, sent.1) == (kept == n, (4 + kept, kept)) && got[..4] == *b"head" && got[4..] == data[..kept], "{n} {to} {}", got.len());
            });
        }
        let log = std::fs::read_to_string(dir.join("errors")).unwrap().split_off(log);
        let said: Vec<_> = log.lines().map(|l| l.split_once("#0: ").unwrap().1.split_once(", client: ").unwrap().0).collect();
        assert_eq!(said, [0, 70_000, 39_999].map(|n| format!("sendfile() reported that \"{}\" was truncated at {n} while sending response to client", path.display())));
        // One loaded whole is not sent in part either.
        let (config, r, mut resp) = unread(&dir, "GET /f HTTP/1.0\n\n");
        length(100);
        load(&r, &config.servers[0].level, &mut resp);
        assert!(resp.body.is_empty() && resp.cut.unwrap().malformed);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clients_may_go_away_while_files_are_sent() {
        let _busy = serving_on();
        let (dir, data) = (files("gone"), letters(16 << 20));
        std::fs::write(dir.join("f"), &data).unwrap();
        // While the client takes no more, while that is paced, for send_timeout, and until worker_shutdown_timeout has passed.
        for (directives, ends) in [("", "close"), ("", "reset"), ("limit_rate 40k;", "close"), ("limit_rate 40k;", "reset"), ("limit_rate 40k;", "shut"), ("send_timeout 1s;", "wait"), ("", "halt"), ("limit_rate 40k;", "halt"),
                                   ("sendfile on;", "close"), ("sendfile on;", "reset"), ("sendfile on; sendfile_max_chunk 0;", "shut"), ("sendfile on; tcp_nopush on; limit_rate 40k;", "close"), ("sendfile on; limit_rate 40k;", "reset"),
                                   ("sendfile on; send_timeout 1s;", "wait"), ("sendfile on; tcp_nopush on;", "halt"), ("sendfile on; limit_rate 40k;", "halt")] {
            let _ = std::fs::remove_file(dir.join("log"));
            block_on(async {
                let (mut client, task) = served_by(&serves_files(&dir, directives)).await;
                client.write_all(b"GET /f HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
                let came = client.read(&mut [0; 1000]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(60)).await;
                let started = Instant::now();
                match ends {
                    "reset" => { socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO)).unwrap(); drop(client) }
                    "close" => drop(client),
                    "shut" => client.shutdown().await.unwrap(),
                    "halt" => { HALTED.store(true, Ordering::SeqCst); HALT.notify_waiters() }
                    _ => {}
                }
                within(Some(Duration::from_secs(3)), task).await.expect(ends).unwrap();
                HALTED.store(false, Ordering::SeqCst);
                let took = started.elapsed().as_millis();
                assert!(if ends == "wait" { (800..2500).contains(&took) } else { took < 500 }, "{directives} {ends} {took}");
                let log = std::fs::read_to_string(dir.join("log")).unwrap();
                let line: Vec<usize> = log.trim_end().split(' ').map(|n| n.parse().unwrap()).collect();
                assert!(line[0] == 200 && line[1] >= came && line[2] < line[1] && line[1] < data.len(), "{directives} {ends} {log}");
            });
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_are_sent_at_the_rate() {
        let _busy = serving_on();
        let (dir, data) = (files("rate"), letters(150_000));
        std::fs::write(dir.join("f"), &data).unwrap();
        for (directives, ms) in [("limit_rate 100k;", 500..1800), ("limit_rate 50k; limit_rate_after 100k;", 400..1800), ("sendfile on; limit_rate 100k;", 500..1800), ("sendfile on; tcp_nopush on; limit_rate 50k; limit_rate_after 50k;", 500..1800)] {
            let started = Instant::now();
            let got = block_on(received(&serves_files(&dir, directives), "GET /f HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"));
            assert!(parted(&got).1 == data && ms.contains(&started.elapsed().as_millis()), "{directives} {:?}", started.elapsed());
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn error_page() {
        assert!(page(404).contains("<title>404 Not Found</title>"));
    }
}
