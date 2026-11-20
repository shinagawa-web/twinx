//! HTTP/1.x connections: reading requests, choosing the server and location,
//! answering, and writing the access log.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::conf::{Config, Level, Match, Proxy, Rewrite, Server};
use crate::vars::Template;
use crate::expires;
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

fn connection(config: &Config, mut stream: TcpStream, listen: SocketAddr) {
    let local = stream.local_addr().unwrap_or(listen);
    let peer = stream.peer_addr().unwrap_or(local);
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
            server_name: String::new(),
            peer,
            local,
            started,
            pipelined,
            length: head.len(),
            body: Vec::new(),
            body_file: None,
        };
        let parsed = parse(&mut r, &head);
        let server = server(config, listen, r.host.as_deref());
        r.server_name = server.names.first().cloned().unwrap_or_default();
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
        let open = exchange(&mut stream, server, &r, parsed, found, local);
        if !level.body_in_file_only { r.body_file.map(std::fs::remove_file); }
        if !open { return linger(&mut stream); }
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
    /// The URI the index module redirects to internally, with "index.html" added.
    index: Option<String>,
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
    match (ret, &level.proxy) {
        (Some((code, text)), _) if REDIRECTS.contains(code) => redirect(*code, text.render(r, &Sent::default())),
        (Some((code, text)), _) if text.0.is_empty() && *code >= 400 => special(*code),
        (Some((code, text)), _) => {
            let ctype = Some("text/plain".to_string());
            Response { status: *code, ctype, body: text.render(r, &Sent::default()).into_bytes(), ..Response::default() }
        }
        (None, Some(p)) => proxy(p, level, r, prefix),
        (None, None) => file(level, r, prefix),
    }
}

/// "?" and the arguments of the request, or "" when it has none.
fn args(r: &Request) -> &str {
    r.target.find('?').map_or("", |i| &r.target[i..])
}

/// Answers one request; true when the connection stays open for the next one.
fn exchange(stream: &mut TcpStream, server: &Server, r: &Request, parsed: Result<(), u16>, found: Found, local: SocketAddr) -> bool {
    let (mut resp, mut level) = answer(server, r, parsed, found);
    if let Some(ep) = level.error_page.iter().find(|e| e.codes.contains(&resp.status)) {
        let url = ep.url.render(r, &Sent::default());
        let named = server.locations.iter().find(|l| matches!(l.kind, Match::Named) && l.path == url);
        if url.starts_with('/') || named.is_some() {
            // An internal redirect: the URI is answered as a GET (or HEAD) request
            // by its location, with the error's status unless that answer has its own.
            // A named location answers the request as it is.
            let mut to = r.clone();
            if named.is_none() {
                to.uri = url.split('?').next().unwrap_or_default().to_string();
                to.target = url;
                to.method = if r.method == "HEAD" { "HEAD" } else { "GET" }.to_string();
            }
            let status = ep.status.unwrap_or(resp.status);
            let found = named.map_or_else(|| location(server, &to.uri), |l| (l.path.as_str(), &l.level, false));
            (resp, level) = answer(server, &to, Ok(()), found);
            if resp.status == 200 { resp.status = status; }
        } else {
            // A named location that does not exist is an error.
            resp = if url.starts_with('@') { special(500) } else { redirect(ep.status.filter(|s| REDIRECTS.contains(s)).unwrap_or(302), url) };
        }
    }
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
    for (name, value, _) in level.add_header.iter().filter(|h| h.2 || added) {
        let value = value.render(r, &Sent::default());
        // These replace what the response has, and an empty value removes it.
        if ["etag", "last-modified"].contains(&name.to_ascii_lowercase().as_str()) { resp.headers.retain(|h| !h.0.eq_ignore_ascii_case(name)); }
        if !value.is_empty() { resp.headers.push((name.clone(), value)); }
    }
    gzip(r, level, &mut resp);
    let status = resp.status;
    // A body of unknown length is chunked for HTTP/1.1; otherwise the connection
    // closes after it. A HEAD answer has neither.
    let unknown = resp.unknown_length && r.method != "HEAD";
    let chunked = unknown && r.line.ends_with("HTTP/1.1");
    let keepalive = parsed.is_ok() && keepalive(r) && ![400, 413, 414, 500, 501].contains(&status) && (chunked || !unknown);
    let mut out = Vec::new();
    if status != 444 {
        let reason = REASONS.iter().find(|(c, _)| *c == status).map_or("", |(_, r)| r);
        let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
        let ctype = resp.ctype.map(|t| format!("Content-Type: {t}\r\n")).unwrap_or_default();
        let connection = if keepalive { "keep-alive" } else { "close" };
        let len = resp.body.len();
        let length = if !resp.unknown_length { format!("Content-Length: {len}\r\n") } else if chunked { "Transfer-Encoding: chunked\r\n".to_string() } else { String::new() };
        let vary = if resp.vary && level.gzip_vary { "Vary: Accept-Encoding\r\n" } else { "" };
        let mut head = format!("HTTP/1.1 {status} {reason}\r\nServer: {NAME}\r\nDate: {date}\r\n{ctype}{length}Connection: {connection}\r\n{vary}");
        resp.headers.iter().for_each(|(n, v)| head += &format!("{n}: {v}\r\n"));
        out = (head + "\r\n").into_bytes();
    }
    let body_len = if r.method == "HEAD" || status == 444 { 0 } else { resp.body.len() };
    if chunked && body_len > 0 { out.extend_from_slice(format!("{body_len:x}\r\n").as_bytes()); }
    out.extend_from_slice(&resp.body[..body_len]);
    if chunked { out.extend_from_slice(if body_len > 0 { b"\r\n0\r\n\r\n" } else { b"0\r\n\r\n" }); }
    let written = stream.write_all(&out).is_ok();
    let sent = Sent { status, bytes: out.len(), body: body_len };
    level.access_log.iter().for_each(|log| log.write(level, r, &sent));
    written && keepalive && status != 444
}

/// The answer of the location found, after the internal redirects of the
/// index module, and the settings of the location that gave it.
fn answer<'a>(server: &'a Server, r: &Request, parsed: Result<(), u16>, (prefix, mut level, auto): Found<'a>) -> (Response, &'a Level) {
    let mut resp = respond(r, parsed, (prefix, level, auto));
    let mut redirects = 0;
    while let Some(uri) = resp.index.take() {
        // nginx gives up after 10 internal redirects.
        redirects += 1;
        let mut to = r.clone();
        to.target = format!("{uri}{}", args(r));
        to.uri = uri;
        let found = location(server, &to.uri);
        level = found.1;
        resp = if redirects > 10 { special(500) } else { respond(&to, Ok(()), found) };
    }
    (resp, level)
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
    if r.uri.ends_with('/') {
        let index = path.join("index.html").is_file().then(|| format!("{}index.html", r.uri));
        return if index.is_some() { Response { index, ..Response::default() } } else { special(if path.is_dir() { 403 } else { 404 }) };
    }
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
    let uri = p.uri.as_ref().map_or_else(|| r.target.clone(), |u| format!("{u}{rest}{}", args(r)));
    let body = r.body_file.as_ref().map_or_else(|| r.body.clone(), |f| std::fs::read(f).unwrap_or_default());
    // proxy_set_header comes first, then the headers it does not set, as nginx sends them.
    let set: Vec<(&String, String)> = level.proxy_set_header.iter().map(|(n, v)| (n, v.render(r, &Sent::default()))).collect();
    let is_set = |name: &str| set.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    let mut req = format!("{} {uri} HTTP/1.0\r\n", r.method);
    set.iter().filter(|h| !h.1.is_empty()).for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    if !is_set("host") { req += &format!("Host: {}\r\n", p.host); }
    if !is_set("connection") { req += "Connection: close\r\n"; }
    if framing(r) != Ok(Some(0)) { req += &format!("Content-Length: {}\r\n", body.len()); }
    const DROPPED: &[&str] = &["host", "connection", "content-length", "transfer-encoding", "keep-alive", "te", "expect", "upgrade"];
    let passed = r.headers.iter().filter(|(n, _)| !DROPPED.contains(&n.to_ascii_lowercase().as_str()) && !is_set(n));
    passed.for_each(|(n, v)| req += &format!("{n}: {v}\r\n"));
    let mut req = (req + "\r\n").into_bytes();
    req.extend_from_slice(&body);
    let up = &p.upstream;
    let (mut tried, mut answer) = (vec![false; up.peers.len()], None);
    while answer.is_none() && let Some(i) = up.pick(&mut tried) {
        answer = fetch(&up.peers[i].addr, &req);
        up.done(i, answer.is_none());
    }
    answer.unwrap_or_else(|| special(502))
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
    r.uri = decode(path.split('?').next().unwrap_or_default()).ok_or(400u16)?;
    if method == "TRACE" { return Err(405); }
    Ok(())
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

/// Escapes what may not appear as such in a URI, as nginx's NGX_ESCAPE_URI
/// does: control characters, space, `"#%<>?\^`{|}` and bytes above 0x7e.
fn escape_uri(s: &str) -> String {
    let plain = |c: u8| c > 0x20 && c < 0x7f && !b"\"#%<>?\\^`{|}".contains(&c);
    s.bytes().map(|c| if plain(c) { (c as char).to_string() } else { format!("%{c:02X}") }).collect()
}

/// The server that answers on a listening address: the one named by the
/// host, else the first one listening there.
fn server<'a>(config: &'a Config, listen: SocketAddr, host: Option<&str>) -> &'a Server {
    let on = || config.servers.iter().filter(|s| s.listen.contains(&listen));
    let named = host.and_then(|h| on().find(|s| s.names.iter().any(|n| n == h)));
    named.or_else(|| on().next()).unwrap_or(&config.servers[0])
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
    fn decodes_and_escapes_uris() {
        assert_eq!(decode("/a%20b%2fc").as_deref(), Some("/a b/c"));
        assert_eq!(decode("/a%2"), None);
        assert_eq!(decode("/a%zz"), None);
        assert_eq!(decode("/a%+1"), None);
        assert_eq!(escape_uri("/a b\"#%<>?\\^`{|}~\u{7f}"), "/a%20b%22%23%25%3C%3E%3F%5C%5E%60%7B%7C%7D~%7F");
        let (res, r) = request("GET /d%20s?a=b HTTP/1.0\n\n");
        assert_eq!((res, r.uri.as_str(), args(&r)), (Ok(()), "/d s", "?a=b"));
        assert_eq!(request("GET /%g HTTP/1.0\n\n").0, Err(400));
    }

    #[test]
    fn finds_servers_and_auto_redirects() {
        let text = "http { server { listen 127.0.0.1:8080; server_name a; location /p/ { proxy_pass http://127.0.0.1:8081; } \
                    location /q { } location /q/ { proxy_pass http://127.0.0.1:8081; } } \
                    server { listen 127.0.0.1:8080; server_name b; } }";
        let config = crate::conf::build(&crate::config::parse(text, std::path::Path::new("t")).unwrap(), &std::env::temp_dir()).unwrap();
        let listen = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(server(&config, listen, Some("b")).names, vec!["b"]);
        assert_eq!(server(&config, listen, Some("c")).names, vec!["a"]);
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
            let (resp, _) = answer(s, &r, Ok(()), location(s, &r.uri));
            (resp.status, String::from_utf8_lossy(&resp.body).into_owned())
        };
        assert_eq!(status("/a/?x"), (200, "i/a/index.html".to_string()));
        assert_eq!(status("/a/empty/").0, 403);
        assert_eq!(status("/a/none/").0, 404);
    }

    #[test]
    fn error_page() {
        assert!(page(404).contains("<title>404 Not Found</title>"));
    }
}
