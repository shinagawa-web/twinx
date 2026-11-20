//! Variables ($uri, $status, ...) and the strings built from them: the
//! complex values of directives such as return, and access log formats.

use std::net::SocketAddr;
use std::time::Instant;

use chrono::{DateTime, Local};

/// What a request carries, as the variables see it.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub line: String,
    pub headers: Vec<(String, String)>,
    /// The validated host of the request line or the Host header.
    pub host: Option<String>,
    /// The first name of the server that answers, for $host when the request has none.
    pub server_name: String,
    pub peer: SocketAddr,
    pub started: Instant,
    pub pipelined: bool,
    pub length: usize,
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
    RemoteUser,
    Request,
    Host,
    Http(String),
}

impl Var {
    fn named(name: &str) -> Option<Var> {
        let known = [
            ("uri", Var::Uri), ("status", Var::Status), ("request_length", Var::RequestLength),
            ("request_time", Var::RequestTime), ("bytes_sent", Var::BytesSent),
            ("body_bytes_sent", Var::BodyBytesSent), ("pipe", Var::Pipe), ("msec", Var::Msec),
            ("time_iso8601", Var::TimeIso8601), ("time_local", Var::TimeLocal),
            ("remote_addr", Var::RemoteAddr), ("remote_user", Var::RemoteUser), ("request", Var::Request), ("host", Var::Host),
        ];
        let header = name.strip_prefix("http_").map(|h| Var::Http(h.replace('_', "-")));
        header.or_else(|| known.into_iter().find(|(n, _)| *n == name).map(|(_, v)| v))
    }

    /// The value, or None when the variable is "not found" (no such header, no user).
    pub fn value(&self, r: &Request, s: &Sent, now: &DateTime<Local>) -> Option<String> {
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
            Var::RemoteUser => return None,
            Var::Request => r.line.clone(),
            Var::Host => r.host.clone().unwrap_or_else(|| r.server_name.clone()),
            Var::Http(name) => r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name))?.1.clone(),
        })
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
        self.join(r, s, |v| v.unwrap_or_default())
    }

    /// The value for an access log line: "-" for variables that are not found,
    /// and the bytes nginx's default escaping replaces written as \xXX.
    pub fn log_line(&self, r: &Request, s: &Sent) -> String {
        self.join(r, s, |v| v.map_or_else(|| "-".to_string(), |v| escape(&v)))
    }

    fn join(&self, r: &Request, s: &Sent, value: impl Fn(Option<String>) -> String) -> String {
        let now = Local::now();
        let piece = |p: &Part| match p {
            Part::Text(t) => t.clone(),
            Part::Var(v) => value(v.value(r, s, &now)),
        };
        self.0.iter().map(piece).collect()
    }
}

fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        let plain = (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\';
        if plain { out.push(b as char) } else { out.push_str(&format!("\\x{b:02X}")) }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            method: "GET".into(),
            uri: "/a".into(),
            line: "GET /a?b HTTP/1.0".into(),
            headers: vec![("User-Agent".into(), "x\"y".into())],
            host: None,
            server_name: "localhost".into(),
            peer: "127.0.0.1:1234".parse().unwrap(),
            started: Instant::now(),
            pipelined: true,
            length: 39,
        }
    }

    #[test]
    fn compiles_and_renders() {
        let t = Template::parse("$uri ${status}x $pipe $request_length $http_user_agent").unwrap();
        let s = Sent { status: 200, bytes: 10, body: 2 };
        assert_eq!(t.render(&request(), &s), "/a 200x p 39 x\"y");
        assert_eq!(t.log_line(&request(), &s), "/a 200x p 39 x\\x22y");
    }

    #[test]
    fn not_found_variables() {
        let t = Template::parse("[$remote_user][$http_referer]").unwrap();
        assert_eq!(t.render(&request(), &Sent::default()), "[][]");
        assert_eq!(t.log_line(&request(), &Sent::default()), "[-][-]");
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
