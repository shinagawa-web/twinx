//! proxy_pass: building the upstream request the way ngx_http_proxy_module
//! does, and passing the upstream response back.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::config::{ProxyPass, ProxyTarget};
use crate::handler::{escape_uri, Ctx};
use crate::http::{decode_chunked, find};
use crate::response::{self, Response};
use crate::template::Template;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The URI sent upstream.
pub fn upstream_uri(cx: &Ctx, pass: &ProxyPass) -> String {
    match &pass.uri {
        None => {
            if !cx.internal {
                return cx.req.unparsed_uri.clone();
            }
            let mut uri = escape_uri(&cx.uri);
            if !cx.args.is_empty() {
                uri.push('?');
                uri.push_str(&cx.args);
            }
            uri
        }
        Some(base) => {
            let name = &cx.conf.location_name;
            let rest = if cx.uri.starts_with(name.as_str()) { &cx.uri[name.len()..] } else { &cx.uri[..] };
            let mut uri = base.clone();
            uri.push_str(&escape_uri(rest));
            if !cx.args.is_empty() {
                uri.push('?');
                uri.push_str(&cx.args);
            }
            uri
        }
    }
}

/// The headers sent upstream: proxy_set_header first, then the defaults
/// they do not override, then the client's headers that none of them name.
pub fn upstream_headers(cx: &Ctx) -> Vec<(String, String)> {
    let mut set: Vec<(String, Template)> = cx.conf.proxy_set_headers.clone();
    let connection = if cx.conf.proxy_http_version == "1.0" { "close" } else { "" };
    let defaults: [(&str, String); 8] = [
        ("Host", "$proxy_host".into()),
        ("Connection", connection.into()),
        ("Content-Length", String::new()),
        ("Transfer-Encoding", String::new()),
        ("TE", String::new()),
        ("Keep-Alive", String::new()),
        ("Expect", String::new()),
        ("Upgrade", String::new()),
    ];
    for (name, value) in defaults {
        if !set.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            set.push((name.to_string(), Template::parse(&value).expect("default header")));
        }
    }
    let has_body = cx.req.content_length.is_some() || cx.req.chunked;
    let mut out = Vec::new();
    for (name, value) in &set {
        let v = if name.eq_ignore_ascii_case("content-length") && value.raw.is_empty() {
            if has_body { cx.body.len().to_string() } else { String::new() }
        } else {
            value.eval(cx)
        };
        if !v.is_empty() {
            out.push((name.clone(), v));
        }
    }
    for (name, value) in &cx.req.headers {
        if set.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
            continue;
        }
        out.push((name.clone(), value.clone()));
    }
    out
}

pub fn forward(cx: &mut Ctx, pass: &ProxyPass) -> Response {
    cx.proxy_host = Some(pass.host.clone());
    let uri = upstream_uri(cx, pass);
    let mut request = format!("{} {} HTTP/{}\r\n", cx.method, uri, cx.conf.proxy_http_version);
    for (name, value) in upstream_headers(cx) {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(cx.body);

    let peers: Vec<SocketAddr> = match &pass.target {
        ProxyTarget::Upstream(up) => up.peers(),
        ProxyTarget::Addrs(addrs) => addrs.clone(),
    };
    let mut last = 502;
    for peer in peers {
        let mut stream = match TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT) {
            Ok(s) => s,
            Err(e) => {
                last = if e.kind() == ErrorKind::TimedOut { 504 } else { 502 };
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
        let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
        if stream.write_all(&bytes).is_err() {
            last = 502;
            continue;
        }
        match read_response(&mut stream, cx, pass) {
            Ok(resp) => return resp,
            Err(code) => {
                last = code;
                continue;
            }
        }
    }
    response::special(last, cx.conf.server_tokens)
}

fn read_response(stream: &mut TcpStream, cx: &Ctx, pass: &ProxyPass) -> Result<Response, u16> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 16384];
    let head_end = loop {
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            break i + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(502),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Err(504),
            Err(_) => return Err(502),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let rest = status_line.strip_prefix("HTTP/").ok_or(502u16)?;
    let (_, after_version) = rest.split_once(' ').ok_or(502u16)?;
    let after_version = after_version.trim_start();
    let code: u16 = after_version.get(..3).and_then(|c| c.parse().ok()).ok_or(502u16)?;
    let mut resp = Response::new(code);
    resp.status_line = Some(after_version.to_string());

    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { return Err(502) };
        let value = value.trim().to_string();
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "date" | "server" | "x-pad" | "connection" | "keep-alive" => {}
            n if n.starts_with("x-accel-") => {}
            "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
            "content-length" => {
                length = Some(value.parse().map_err(|_| 502u16)?);
            }
            "content-type" => resp.content_type = Some(value),
            "location" => match rewrite_redirect(&value, cx, pass) {
                Some(rewritten) => resp.location = Some(rewritten),
                None => resp.headers.push((name.trim().to_string(), value)),
            },
            _ => resp.headers.push((name.trim().to_string(), value)),
        }
    }
    let no_body = cx.method == "HEAD" || code == 204 || code == 304 || code < 200;
    let mut body = buf[head_end..].to_vec();
    if no_body {
        resp.content_length = length.map(|l| l as u64);
        return Ok(resp);
    }
    if chunked {
        loop {
            match decode_chunked(&body) {
                Ok(Some((decoded, _))) => {
                    body = decoded;
                    break;
                }
                Ok(None) => {}
                Err(_) => return Err(502),
            }
            match stream.read(&mut chunk) {
                Ok(0) => return Err(502),
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => return Err(502),
            }
        }
        set_unknown_length(&mut resp, cx);
    } else if let Some(len) = length {
        while body.len() < len {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        body.truncate(len);
        resp.content_length = Some(len as u64);
    } else {
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        set_unknown_length(&mut resp, cx);
    }
    resp.body = body;
    Ok(resp)
}

fn set_unknown_length(resp: &mut Response, cx: &Ctx) {
    if cx.req.version >= (1, 1) {
        resp.chunked = true;
    } else {
        resp.close = true;
    }
}

/// proxy_redirect default: the proxy_pass URL (with "/" when it has no URI)
/// is replaced by the location name (by "/").
fn rewrite_redirect(value: &str, cx: &Ctx, pass: &ProxyPass) -> Option<String> {
    let (prefix, replacement) = match &pass.uri {
        Some(_) => (pass.url.clone(), cx.conf.location_name.clone()),
        None => (format!("{}/", pass.url), "/".to_string()),
    };
    let rest = value.strip_prefix(prefix.as_str())?;
    Some(format!("{replacement}{rest}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::http::parse_head;

    fn with_ctx<T>(server_block: &str, raw: &str, f: impl FnOnce(&mut Ctx) -> T) -> T {
        let text = format!("events {{}} http {{ server {{ {server_block} }} }}");
        let tree = config::parse_text(&text, "t", std::path::Path::new("/")).unwrap();
        let c = config::build(&tree).unwrap();
        let server = c.servers[0].clone();
        let req = parse_head(raw.as_bytes(), true).unwrap();
        let loc = match crate::location::find(&server.locations, &req.uri) {
            crate::location::Found::Location(l, _) => l,
            _ => panic!("no location"),
        };
        let mut cx = Ctx {
            req: &req,
            method: req.method.clone(),
            body: b"",
            server: &server,
            local: "127.0.0.1:80".parse().unwrap(),
            remote: "127.0.0.1:5000".parse().unwrap(),
            uri: req.uri.clone(),
            args: req.args.clone(),
            conf: loc.conf.clone(),
            location: Some(loc.clone()),
            captures: Vec::new(),
            internal: false,
            proxy_host: Some(loc.conf.proxy.as_ref().unwrap().host.clone()),
        };
        f(&mut cx)
    }

    #[test]
    fn keeps_the_request_uri_without_a_uri_part() {
        let uri = with_ctx(
            "location /api/ { proxy_pass http://127.0.0.1:9; }",
            "GET /api/a%20b?x=1 HTTP/1.1\r\nHost: h\r\n\r\n",
            |cx| upstream_uri(cx, &cx.conf.proxy.clone().unwrap()),
        );
        assert_eq!(uri, "/api/a%20b?x=1");
    }

    #[test]
    fn replaces_the_location_prefix_with_the_uri_part() {
        let uri = with_ctx(
            "location /v2/ { proxy_pass http://127.0.0.1:9/internal/; }",
            "GET /v2/a%20b?x=1 HTTP/1.1\r\nHost: h\r\n\r\n",
            |cx| upstream_uri(cx, &cx.conf.proxy.clone().unwrap()),
        );
        assert_eq!(uri, "/internal/a%20b?x=1");
    }

    #[test]
    fn builds_headers_in_nginx_order() {
        let headers = with_ctx(
            "location / { proxy_pass http://127.0.0.1:9; proxy_set_header X-Real-IP $remote_addr; }",
            "POST / HTTP/1.1\r\nHost: h\r\nContent-Type: a/b\r\nContent-Length: 0\r\nConnection: close\r\nX-Other: 1\r\n\r\n",
            |cx| upstream_headers(cx),
        );
        let names: Vec<&str> = headers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["X-Real-IP", "Host", "Content-Length", "Content-Type", "X-Other"]);
        assert_eq!(headers[1].1, "127.0.0.1:9");
        assert_eq!(headers[2].1, "0");
    }
}
