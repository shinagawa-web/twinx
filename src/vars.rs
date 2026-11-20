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
    pub length: usize,
    /// The body when it is kept in memory, and the file it was written to otherwise.
    pub body: Vec<u8>,
    pub body_file: Option<PathBuf>,
}

/// What the answer to a request was, once it was sent.
#[derive(Debug, Clone, Default)]
pub struct Sent {
    pub status: u16,
    pub bytes: usize,
    pub body: usize,
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
    Arg(String),
    Http(String),
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
        ];
        let header = name.strip_prefix("http_").map(|h| Var::Http(h.replace('_', "-")));
        let arg = || name.strip_prefix("arg_").map(|a| Var::Arg(a.to_string()));
        header.or_else(arg).or_else(|| known.into_iter().find(|(n, _)| *n == name).map(|(_, v)| v))
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
            Var::RemoteUser => return None,
            Var::Request => r.line.clone(),
            Var::Host => r.host.clone().unwrap_or_else(|| r.server_name.clone()),
            Var::RequestUri => r.target.clone(),
            Var::Args => r.target.split_once('?').map_or("", |(_, a)| a).to_string(),
            Var::RequestBody => String::from_utf8_lossy(&r.body).into_owned(),
            Var::RequestBodyFile => r.body_file.as_ref()?.display().to_string(),
            Var::Arg(name) => {
                let args = r.target.split_once('?').map_or("", |(_, a)| a).split('&');
                args.filter_map(|a| a.split_once('=')).find(|(n, _)| n.eq_ignore_ascii_case(name))?.1.to_string()
            }
            Var::Http(name) => r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))?.1.clone(),
        }.into_bytes())
    }
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
            length: 39,
            body: b"xy".to_vec(),
            body_file: None,
        }
    }

    #[test]
    fn compiles_and_renders() {
        let t = Template::parse("$uri ${status}x $pipe $request_length $http_user_agent").unwrap();
        let s = Sent { status: 200, bytes: 10, body: 2 };
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
    fn errors() {
        assert_eq!(Template::parse("$nope").unwrap_err(), "unknown \"nope\" variable");
        assert_eq!(Template::parse("a $").unwrap_err(), "invalid variable name in \"a $\"");
        assert_eq!(Template::parse("${uri").unwrap_err(), "invalid variable name in \"${uri\"");
    }

    #[test]
    fn times() {
        let t = Template::parse("$msec|$time_iso8601|$time_local").unwrap();
        let line = t.render(&request(), &Sent::default());
        let parts: Vec<&str> = line.split('|').collect();
        assert!(parts[0].contains('.') && parts[1].contains('T') && parts[2].contains('/'));
    }
}
