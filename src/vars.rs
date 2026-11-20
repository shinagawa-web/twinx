//! Variables ($uri, $status, ...) and the strings built from them: the
//! complex values of directives such as return, and access log formats.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Local};

/// What a request carries, as the variables see it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    /// The URI as the request line has it, with the arguments ($request_uri).
    pub target: String,
    pub line: String,
    pub headers: Vec<(String, String)>,
    /// The validated host of the request line or the Host header.
    pub host: Option<String>,
    /// The first name of the server that answers, for $host when the request has none.
    pub server_name: String,
    pub peer: SocketAddr,
    /// The address the connection was accepted on.
    pub local: SocketAddr,
    pub started: Instant,
    pub pipelined: bool,
    /// When the connection was accepted, and how many requests it has had, this one included.
    pub connected: Instant,
    pub requests: u64,
    pub length: usize,
    /// The body when it is kept in memory, and the file it was written to otherwise.
    pub body: Vec<u8>,
    pub body_file: Option<PathBuf>,
    /// The proxied servers tried before an internal redirect ($upstream_addr).
    pub upstream_addr: Option<String>,
}

/// What the answer to a request was, once it was sent.
#[derive(Debug, Clone, Default)]
pub struct Sent {
    pub status: u16,
    pub bytes: usize,
    pub body: usize,
    /// The headers of the answer so far ($sent_http_*).
    pub headers: Vec<(String, String)>,
    /// The headers of the proxied server's answer ($upstream_http_*, $upstream_cookie_*).
    pub upstream: Vec<(String, String)>,
    /// The trailers so far ($sent_trailer_*).
    pub trailers: Vec<(String, String)>,
    /// The proxied servers tried, as $upstream_addr gives them.
    pub upstream_addr: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Var {
    Uri,
    Status,
    RequestLength,
    RequestTime,
    BytesSent,
    BodyBytesSent,
    Pipe,
    Msec,
    TimeIso8601,
    TimeLocal,
    RemoteAddr,
    RemotePort,
    BinaryRemoteAddr,
    ServerAddr,
    ServerPort,
    RemoteUser,
    Request,
    Host,
    RequestUri,
    Args,
    RequestBody,
    RequestBodyFile,
    ConnectionRequests,
    ConnectionTime,
    RequestPort,
    IsRequestPort,
    UpstreamAddr,
    Pid,
    Arg(String),
    Http(String),
    Cookie(String),
    SentHttp(String),
    SentTrailer(String),
    UpstreamHttp(String),
    UpstreamCookie(String),
}

impl Var {
    fn named(name: &str) -> Option<Var> {
        let known = [
            ("uri", Var::Uri), ("status", Var::Status), ("request_length", Var::RequestLength),
            ("request_time", Var::RequestTime), ("bytes_sent", Var::BytesSent),
            ("body_bytes_sent", Var::BodyBytesSent), ("pipe", Var::Pipe), ("msec", Var::Msec),
            ("time_iso8601", Var::TimeIso8601), ("time_local", Var::TimeLocal),
            ("remote_addr", Var::RemoteAddr), ("remote_port", Var::RemotePort), ("binary_remote_addr", Var::BinaryRemoteAddr),
            ("server_addr", Var::ServerAddr), ("server_port", Var::ServerPort), ("remote_user", Var::RemoteUser), ("request", Var::Request), ("host", Var::Host),
            ("request_uri", Var::RequestUri), ("args", Var::Args), ("request_body", Var::RequestBody), ("request_body_file", Var::RequestBodyFile),
            ("connection_requests", Var::ConnectionRequests), ("connection_time", Var::ConnectionTime),
            ("request_port", Var::RequestPort), ("is_request_port", Var::IsRequestPort), ("upstream_addr", Var::UpstreamAddr), ("pid", Var::Pid),
            ("content_length", Var::Http("content-length".into())), ("content_type", Var::Http("content-type".into())),
        ];
        // Header names have "-" where the variable has "_"; cookie names are as they are.
        let prefixed: [(&str, fn(String) -> Var, bool); 7] = [
            ("http_", Var::Http, true), ("sent_http_", Var::SentHttp, true), ("sent_trailer_", Var::SentTrailer, true),
            ("upstream_http_", Var::UpstreamHttp, true), ("arg_", Var::Arg, false), ("cookie_", Var::Cookie, false),
            ("upstream_cookie_", Var::UpstreamCookie, false),
        ];
        let found = prefixed.into_iter().find_map(|(p, var, dashes)| name.strip_prefix(p).map(|n| var(if dashes { n.replace('_', "-") } else { n.to_string() })));
        found.or_else(|| known.into_iter().find(|(n, _)| *n == name).map(|(_, v)| v))
    }

    /// The value, or None when the variable is "not found" (no such header, no user).
    pub fn value(&self, r: &Request, s: &Sent, now: &DateTime<Local>) -> Option<Vec<u8>> {
        Some(match self {
            Var::Uri => r.uri.clone(),
            Var::Status => format!("{:03}", s.status),
            Var::RequestLength => r.length.to_string(),
            Var::RequestTime => format!("{:.3}", r.started.elapsed().as_secs_f64()),
            Var::BytesSent => s.bytes.to_string(),
            Var::BodyBytesSent => s.body.to_string(),
            Var::Pipe => (if r.pipelined { "p" } else { "." }).to_string(),
            Var::Msec => format!("{}.{:03}", now.timestamp(), now.timestamp_subsec_millis()),
            Var::TimeIso8601 => now.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
            Var::TimeLocal => now.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
            Var::RemoteAddr => r.peer.ip().to_string(),
            Var::RemotePort => r.peer.port().to_string(),
            Var::BinaryRemoteAddr => return Some(match r.peer.ip() { IpAddr::V4(a) => a.octets().to_vec(), IpAddr::V6(a) => a.octets().to_vec() }),
            Var::ServerAddr => r.local.ip().to_string(),
            Var::ServerPort => r.local.port().to_string(),
            Var::RemoteUser => basic_user(r)?,
            Var::Request => r.line.clone(),
            Var::ConnectionRequests => r.requests.to_string(),
            Var::ConnectionTime => { let ms = r.connected.elapsed().as_millis(); format!("{}.{:03}", ms / 1000, ms % 1000) }
            Var::Host => r.host.clone().unwrap_or_else(|| r.server_name.clone()),
            Var::RequestUri => r.target.clone(),
            Var::RequestPort => request_port(r).to_string(),
            Var::IsRequestPort => (if request_port(r).is_empty() { "" } else { ":" }).to_string(),
            Var::Pid => std::process::id().to_string(),
            Var::UpstreamAddr => s.upstream_addr.clone().or_else(|| r.upstream_addr.clone())?,
            Var::Args => r.target.split_once('?').map_or("", |(_, a)| a).to_string(),
            Var::RequestBody => String::from_utf8_lossy(&r.body).into_owned(),
            Var::RequestBodyFile => r.body_file.as_ref()?.display().to_string(),
            Var::Arg(name) => {
                let args = r.target.split_once('?').map_or("", |(_, a)| a).split('&');
                args.filter_map(|a| a.split_once('=')).find(|(n, _)| n.eq_ignore_ascii_case(name))?.1.to_string()
            }
            // Cookie headers are joined with "; ", the others with ", ".
            Var::Http(name) => joined(&r.headers, name, if name.eq_ignore_ascii_case("cookie") { "; " } else { ", " })?,
            Var::Cookie(name) => cookie(&r.headers, name)?,
            Var::SentHttp(name) => joined(&s.headers, name, ", ")?,
            Var::SentTrailer(name) => joined(&s.trailers, name, ", ")?,
            Var::UpstreamHttp(name) => joined(&s.upstream, name, ", ")?,
            Var::UpstreamCookie(name) => set_cookie(&s.upstream, name)?,
        }.into_bytes())
    }
}

/// The values of every header with the name, joined; None when there is none.
fn joined(headers: &[(String, String)], name: &str, sep: &str) -> Option<String> {
    let values: Vec<&str> = headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect();
    (!values.is_empty()).then(|| values.join(sep))
}

/// A cookie of the Cookie headers, as nginx 1.30 finds it: pairs are separated
/// by ";", and the value runs to the next ";". As in nginx, a pair that starts
/// with the name but has no "=" after it hides the pair that follows.
fn cookie(headers: &[(String, String)], name: &str) -> Option<String> {
    for (_, line) in headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("cookie")) {
        let (b, mut at) = (line.as_bytes(), 0);
        while at < b.len() {
            if b[at..].len() >= name.len() && b[at..at + name.len()].eq_ignore_ascii_case(name.as_bytes()) {
                at += name.len();
                while b.get(at) == Some(&b' ') { at += 1; }
                if b.get(at) == Some(&b'=') {
                    at += 1;
                    while b.get(at) == Some(&b' ') { at += 1; }
                    let end = b[at..].iter().position(|&c| c == b';').map_or(b.len(), |i| at + i);
                    return Some(String::from_utf8_lossy(&b[at..end]).into_owned());
                }
                at += 1;
            }
            while at < b.len() && { at += 1; b[at - 1] != b';' } {}
            while b.get(at) == Some(&b' ') { at += 1; }
        }
    }
    None
}

/// A cookie the proxied server sets: the first Set-Cookie that starts with
/// "name=", its value up to ";".
fn set_cookie(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie")).find_map(|(_, v)| {
        let starts = v.len() > name.len() && v.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes());
        let value = v.get(name.len()..).filter(|_| starts)?.trim_start_matches(' ').strip_prefix('=')?.trim_start_matches(' ');
        Some(value.split(';').next().unwrap_or_default().to_string())
    })
}

/// The port of the request: the one in an absolute URI of the request line,
/// else the one in the Host header; empty when neither has one.
fn request_port(r: &Request) -> &str {
    let target = r.line.split(' ').filter(|w| !w.is_empty()).nth(1).unwrap_or_default();
    let absolute = target.split_once("://").filter(|_| !target.starts_with('/')).map(|(_, rest)| rest.split(['/', '?']).next().unwrap_or_default());
    let host = absolute.or_else(|| r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("host")).map(|h| h.1.as_str())).unwrap_or_default();
    let host = host.rsplit_once(']').map_or(host, |(_, after)| after);
    host.split_once(':').map_or("", |(_, port)| port)
}

/// The user of "Authorization: Basic <base64 of user:password>"; None when the
/// header is not that or the user is empty, as ngx_http_auth_basic_user() decides.
fn basic_user(r: &Request) -> Option<String> {
    let auth = r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("authorization"))?.1.as_str();
    let credentials = auth.get(..6).filter(|s| s.eq_ignore_ascii_case("basic ")).and(auth.get(6..))?.trim_start_matches(' ');
    let decoded = decode_base64(credentials).filter(|_| !credentials.is_empty())?;
    let user = &decoded[..decoded.iter().position(|&c| c == b':')?];
    (!user.is_empty()).then(|| String::from_utf8_lossy(user).into_owned())
}

/// Base64 as ngx_decode_base64() reads it: up to the first "=", None for any
/// other character outside the alphabet or a length that cannot be decoded.
fn decode_base64(s: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digits: Option<Vec<u32>> = s.bytes().take_while(|&c| c != b'=').map(|c| ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)).collect();
    let digits = digits.filter(|d| d.len() % 4 != 1)?;
    let mut out = Vec::new();
    for group in digits.chunks(4) {
        let n = group.iter().enumerate().fold(0u32, |n, (i, d)| n | d << (18 - 6 * i));
        out.extend_from_slice(&n.to_be_bytes()[1..group.len()]);
    }
    Some(out)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    Var(Var),
}

/// A string with variables in it, compiled once from the configuration.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Template(pub Vec<Part>);

impl Template {
    /// Compiles "$name" and "${name}" references; the error is nginx's message.
    pub fn parse(s: &str) -> Result<Template, String> {
        let (mut parts, mut text, mut rest) = (Vec::new(), String::new(), s);
        while let Some(i) = rest.find('$') {
            text.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            let braced = after.starts_with('{');
            let body = if braced { &after[1..] } else { after };
            let len = body.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(body.len());
            let name = &body[..len];
            if name.is_empty() || (braced && !body[len..].starts_with('}')) { return Err(format!("invalid variable name in \"{s}\"")); }
            let var = Var::named(name).ok_or_else(|| format!("unknown \"{name}\" variable"))?;
            parts.extend((!text.is_empty()).then(|| Part::Text(std::mem::take(&mut text))));
            parts.push(Part::Var(var));
            rest = &body[len + braced as usize..];
        }
        text.push_str(rest);
        parts.extend((!text.is_empty()).then_some(Part::Text(text)));
        Ok(Template(parts))
    }

    /// The value for a directive: variables that are not found give "".
    pub fn render(&self, r: &Request, s: &Sent) -> String {
        let now = Local::now();
        let value = |v: &Var| v.value(r, s, &now).map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
        self.0.iter().map(|p| match p { Part::Text(t) => t.clone(), Part::Var(v) => value(v) }).collect()
    }

    /// The value for an access log line, its variables escaped as log_format
    /// says: "-" for variables that are not found by default, nothing otherwise.
    pub fn log_line(&self, r: &Request, s: &Sent, escape: Escape) -> Vec<u8> {
        let (now, mut out) = (Local::now(), Vec::new());
        for part in &self.0 {
            let value = match part { Part::Text(t) => { out.extend_from_slice(t.as_bytes()); continue } Part::Var(v) => v.value(r, s, &now) };
            match (value, escape) {
                (None, Escape::Default) => out.push(b'-'),
                (None, _) => {}
                (Some(v), Escape::Default) => v.iter().for_each(|&b| escape_default(b, &mut out)),
                (Some(v), Escape::Json) => v.iter().for_each(|&b| escape_json(b, &mut out)),
                (Some(v), Escape::None) => out.extend(v),
            }
        }
        out
    }
}

/// How log_format escapes the values of variables (its "escape=" parameter).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Escape {
    Default,
    Json,
    None,
}

/// '"', '\\', control characters and bytes above 0x7e as \xXX.
fn escape_default(b: u8, out: &mut Vec<u8>) {
    let plain = (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\';
    if plain { out.push(b) } else { out.extend(format!("\\x{b:02X}").bytes()) }
}

/// As in a JSON string: '"' and '\\' with a backslash, control characters as
/// \n, \r, \t, \b, \f or \u00XX.
fn escape_json(b: u8, out: &mut Vec<u8>) {
    const NAMED: &[(u8, u8)] = &[(b'"', b'"'), (b'\\', b'\\'), (b'\n', b'n'), (b'\r', b'r'), (b'\t', b't'), (8, b'b'), (12, b'f')];
    match NAMED.iter().find(|e| e.0 == b) {
        Some(&(_, c)) => out.extend([b'\\', c]),
        None if b < 0x20 => out.extend(format!("\\u{b:04X}").bytes()),
        None => out.push(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            method: "GET".into(),
            uri: "/a".into(),
            target: "/a?b".into(),
            line: "GET /a?b HTTP/1.0".into(),
            headers: vec![("User-Agent".into(), "x\"y".into())],
            host: None,
            server_name: "localhost".into(),
            peer: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:8080".parse().unwrap(),
            started: Instant::now(),
            pipelined: true,
            connected: Instant::now(),
            requests: 2,
            length: 39,
            body: b"xy".to_vec(),
            body_file: None,
            upstream_addr: None,
        }
    }

    #[test]
    fn compiles_and_renders() {
        let t = Template::parse("$uri ${status}x $pipe $request_length $http_user_agent").unwrap();
        let s = Sent { status: 200, bytes: 10, body: 2, ..Sent::default() };
        assert_eq!(t.render(&request(), &s), "/a 200x p 39 x\"y");
        assert_eq!(t.log_line(&request(), &s, Escape::Default), b"/a 200x p 39 x\\x22y");
    }

    #[test]
    fn not_found_variables() {
        let t = Template::parse("[$remote_user][$http_referer][$request_body_file]").unwrap();
        assert_eq!(t.render(&request(), &Sent::default()), "[][][]");
        assert_eq!(t.log_line(&request(), &Sent::default(), Escape::Default), b"[-][-][-]");
        assert_eq!(t.log_line(&request(), &Sent::default(), Escape::Json), b"[][][]");
        let t = Template::parse("$request_uri $request_body").unwrap();
        assert_eq!(t.render(&request(), &Sent::default()), "/a?b xy");
        assert_eq!(Template::parse("[$args]").unwrap().render(&request(), &Sent::default()), "[b]");
        let mut r = request();
        r.target = "/a?x=1&E=2".into();
        assert_eq!(Template::parse("[$arg_e][$arg_y]").unwrap().render(&r, &Sent::default()), "[2][]");
    }

    #[test]
    fn addresses_and_escaping() {
        let t = Template::parse("$remote_addr:$remote_port:$server_addr:$server_port|$binary_remote_addr|$http_x").unwrap();
        let mut r = request();
        r.headers = vec![("X".into(), "\"\\\n\x01\u{e9}".into())];
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Default), b"127.0.0.1:1234:127.0.0.1:8080|\\x7F\\x00\\x00\\x01|\\x22\\x5C\\x0A\\x01\\xC3\\xA9");
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Json), b"127.0.0.1:1234:127.0.0.1:8080|\x7F\\u0000\\u0000\\u0001|\\\"\\\\\\n\\u0001\xC3\xA9".as_slice());
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::None), b"127.0.0.1:1234:127.0.0.1:8080|\x7F\x00\x00\x01|\"\\\n\x01\xC3\xA9");
    }

    #[test]
    fn pid_and_upstream_addr() {
        let mut r = request();
        r.upstream_addr = Some("a".into());
        let t = Template::parse("$pid|$upstream_addr").unwrap();
        assert_eq!(t.render(&r, &Sent::default()), format!("{}|a", std::process::id()));
        assert_eq!(t.render(&r, &Sent { upstream_addr: Some("b".into()), ..Sent::default() }), format!("{}|b", std::process::id()));
    }

    #[test]
    fn request_port() {
        let t = Template::parse("[$is_request_port$request_port]").unwrap();
        let port = |line: &str, host: &str| {
            let mut r = request();
            r.line = line.into();
            r.headers = vec![("Host".into(), host.into())];
            t.render(&r, &Sent::default())
        };
        assert_eq!(port("GET / HTTP/1.0", "a"), "[]");
        assert_eq!(port("GET / HTTP/1.0", "a:81"), "[:81]");
        assert_eq!(port("GET / HTTP/1.0", "[::1]:82"), "[:82]");
        assert_eq!(port("GET http://a:83/x HTTP/1.0", "a:9"), "[:83]");
        assert_eq!(port("GET http://[::1] HTTP/1.0", "a:9"), "[]");
        assert_eq!(Template::parse("[$request_port]").unwrap().render(&request(), &Sent::default()), "[]");
    }

    #[test]
    fn errors() {
        assert_eq!(Template::parse("$nope").unwrap_err(), "unknown \"nope\" variable");
        assert_eq!(Template::parse("a $").unwrap_err(), "invalid variable name in \"a $\"");
        assert_eq!(Template::parse("${uri").unwrap_err(), "invalid variable name in \"${uri\"");
    }

    #[test]
    fn headers_cookies_and_users() {
        let mut r = request();
        let h = |n: &str, v: &str| (n.to_string(), v.to_string());
        r.headers = vec![h("Cookie", "foo=1, qux=0; bar = 2"), h("cookie", "a; a=1; x=3"), h("X", "a"), h("x", "b"), h("Authorization", "basic dXNlcjpzZWNyZXQ=")];
        let s = Sent { headers: vec![h("L", "1"), h("L", "2")], upstream: vec![h("Set-Cookie", "s = 5; path=/"), h("Set-Cookie", "t")], trailers: vec![h("T", "x")], ..Sent::default() };
        let t = Template::parse("$http_cookie|$http_x|$cookie_foo|$cookie_bar|[$cookie_qux]|[$cookie_a]|$cookie_x|$sent_http_l|$sent_trailer_t|$upstream_cookie_s|[$upstream_cookie_t]|$remote_user").unwrap();
        assert_eq!(t.render(&r, &s), "foo=1, qux=0; bar = 2; a; a=1; x=3|a, b|1, qux=0|2|[]|[]|3|1, 2|x|5|[]|user");
        assert_eq!(Template::parse("$upstream_http_set_cookie").unwrap().render(&r, &s), "s = 5; path=/, t");
        for (auth, user) in [("Basic dXNlcg==", None), ("Basic OnB3", None), ("Basic a", None), ("Basic !!!!", None), ("Basic ", None), ("Digest x", None), ("Basic dTpw", Some("u"))] {
            r.headers = vec![h("Authorization", auth)];
            assert_eq!(basic_user(&r).as_deref(), user, "{auth}");
        }
    }

    #[test]
    fn connection_variables() {
        let t = Template::parse("$connection_requests:$connection_time").unwrap();
        assert!(t.render(&request(), &Sent::default()).starts_with("2:0."));
    }

    #[test]
    fn times() {
        let t = Template::parse("$msec|$time_iso8601|$time_local").unwrap();
        let line = t.render(&request(), &Sent::default());
        let parts: Vec<&str> = line.split('|').collect();
        assert!(parts[0].contains('.') && parts[1].contains('T') && parts[2].contains('/'));
    }
}
