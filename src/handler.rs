//! Answering one request: server rewrite phase, location choice, the
//! location rewrite phase (`return`), `try_files`, then the content
//! handlers (proxy, index, static), and the header filters (`add_header`,
//! absolute `Location`).

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{LocConf, Location, Modifier, Return, Server};
use crate::http::Request;
use crate::location::{self, Captures, Found};
use crate::response::{self, Response};
use crate::template::{Template, Vars};

/// The state of a request while it moves through the phases.
pub struct Ctx<'a> {
    pub req: &'a Request,
    pub body: &'a [u8],
    pub server: &'a Server,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub uri: String,
    pub args: String,
    pub conf: Arc<LocConf>,
    pub location: Option<Arc<Location>>,
    pub captures: Captures,
    /// Set after an internal redirect: the request URI no longer describes `uri`.
    pub internal: bool,
    /// The value of $proxy_host while a request is being proxied.
    pub proxy_host: Option<String>,
}

impl Vars for Ctx<'_> {
    fn var(&self, name: &str) -> Option<String> {
        let req = self.req;
        Some(match name {
            "uri" | "document_uri" => self.uri.clone(),
            "args" | "query_string" => self.args.clone(),
            "is_args" => if self.args.is_empty() { String::new() } else { "?".into() },
            "request_uri" => req.unparsed_uri.clone(),
            "request" => req.request_line.clone(),
            "request_method" => req.method.clone(),
            "host" => self.host_name(),
            "hostname" => hostname(),
            "scheme" => "http".into(),
            "https" => String::new(),
            "server_name" => self.server.names.first().cloned().unwrap_or_default(),
            "server_port" => self.local.port().to_string(),
            "server_addr" => self.local.ip().to_string(),
            "server_protocol" => format!("HTTP/{}.{}", req.version.0, req.version.1),
            "remote_addr" => self.remote.ip().to_string(),
            "remote_port" => self.remote.port().to_string(),
            "document_root" | "realpath_root" => self.conf.root.eval(self),
            "request_filename" => self.map_path(&self.uri).to_string_lossy().into_owned(),
            "content_length" => req.header("content-length")?.to_string(),
            "content_type" => req.header("content-type")?.to_string(),
            "nginx_version" => "1.30.6".into(),
            "proxy_host" => self.proxy_host.clone()?,
            "proxy_add_x_forwarded_for" => match req.header("x-forwarded-for") {
                Some(v) => format!("{v}, {}", self.remote.ip()),
                None => self.remote.ip().to_string(),
            },
            "pid" => std::process::id().to_string(),
            _ => {
                if let Some(h) = name.strip_prefix("http_") {
                    let wanted = h.replace('_', "-");
                    let values: Vec<&str> = req
                        .headers
                        .iter()
                        .filter(|(n, _)| n.eq_ignore_ascii_case(&wanted))
                        .map(|(_, v)| v.as_str())
                        .collect();
                    if values.is_empty() {
                        return None;
                    }
                    let sep = if wanted == "cookie" { "; " } else { ", " };
                    return Some(values.join(sep));
                }
                if let Some(a) = name.strip_prefix("arg_") {
                    return self.args.split('&').find_map(|pair| {
                        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                        k.eq_ignore_ascii_case(a).then(|| v.to_string())
                    });
                }
                if let Some(c) = name.strip_prefix("cookie_") {
                    let cookies = req.header("cookie")?;
                    return cookies.split(';').find_map(|pair| {
                        let (k, v) = pair.trim().split_once('=')?;
                        (k == c).then(|| v.to_string())
                    });
                }
                return None;
            }
        })
    }

    fn capture(&self, index: usize) -> Option<String> {
        self.captures.get(index).cloned().flatten()
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "localhost".into())
}

impl Ctx<'_> {
    /// $host: the request host, or the server's first name.
    pub fn host_name(&self) -> String {
        match &self.req.host {
            Some(h) => h.clone(),
            None => self.server.names.first().cloned().unwrap_or_default(),
        }
    }

    /// Maps a URI to a file path with root or alias.
    pub fn map_path(&self, uri: &str) -> PathBuf {
        if let Some(alias) = &self.conf.alias {
            let base = alias.eval(self);
            let regex = self
                .location
                .as_ref()
                .is_some_and(|l| matches!(l.modifier, Modifier::Regex | Modifier::RegexCaseless));
            if regex {
                return PathBuf::from(base);
            }
            let name = &self.conf.location_name;
            let rest = if uri.starts_with(name.as_str()) { &uri[name.len()..] } else { uri };
            return PathBuf::from(format!("{base}{rest}"));
        }
        PathBuf::from(format!("{}{}", self.conf.root.eval(self), uri))
    }

    fn set_location(&mut self, loc: Arc<Location>, captures: Captures) {
        self.conf = loc.conf.clone();
        self.location = Some(loc);
        self.captures = captures;
    }

    fn eval(&self, t: &Template) -> String {
        t.eval(self)
    }
}

const MAX_REDIRECTS: usize = 10;

enum Next {
    Find,
    Named(Arc<Location>),
}

/// Answers a request. The returned response still needs no further filtering.
pub fn handle(server: &Server, req: &Request, body: &[u8], local: SocketAddr, remote: SocketAddr) -> Response {
    let mut cx = Ctx {
        req,
        body,
        server,
        local,
        remote,
        uri: req.uri.clone(),
        args: req.args.clone(),
        conf: server.conf.clone(),
        location: None,
        captures: Vec::new(),
        internal: false,
        proxy_host: None,
    };
    let resp = run(&mut cx);
    finalize(&cx, resp)
}

fn run(cx: &mut Ctx) -> Response {
    if let Some(ret) = cx.server.ret.clone() {
        return do_return(cx, &ret);
    }
    let mut next = Next::Find;
    for _ in 0..=MAX_REDIRECTS {
        match std::mem::replace(&mut next, Next::Find) {
            Next::Named(loc) => cx.set_location(loc, Vec::new()),
            Next::Find => match location::find(&cx.server.locations, &cx.uri) {
                Found::Location(loc, captures) => cx.set_location(loc, captures),
                Found::AutoRedirect(loc) => {
                    cx.set_location(loc.clone(), Vec::new());
                    let mut resp = response::special(301, cx.conf.server_tokens);
                    let mut target = escape_uri(&loc.name);
                    if !cx.args.is_empty() {
                        target.push('?');
                        target.push_str(&cx.args);
                    }
                    resp.location = Some(target);
                    return resp;
                }
                Found::None => {
                    cx.conf = cx.server.conf.clone();
                    cx.location = None;
                    cx.captures = Vec::new();
                }
            },
        }
        if let Some(ret) = cx.conf.ret.clone() {
            return do_return(cx, &ret);
        }
        if let Some(list) = cx.conf.try_files.clone() {
            match try_files(cx, &list) {
                Tried::Found(uri) => cx.uri = uri,
                Tried::Code(code) => return special(cx, code),
                Tried::Redirect(uri, args) => {
                    cx.uri = uri;
                    cx.args = args;
                    cx.internal = true;
                    continue;
                }
                Tried::Named(name) => match cx.server.named.get(&name) {
                    Some(loc) => {
                        cx.internal = true;
                        next = Next::Named(loc.clone());
                        continue;
                    }
                    None => return special(cx, 500),
                },
            }
        }
        if let Some(pass) = cx.conf.proxy.clone() {
            return crate::proxy::forward(cx, &pass);
        }
        match static_content(cx) {
            Content::Done(resp) => return resp,
            Content::Redirect(uri) => {
                cx.uri = uri;
                cx.internal = true;
            }
        }
    }
    // "rewrite or internal redirection cycle"
    special(cx, 500)
}

fn special(cx: &Ctx, code: u16) -> Response {
    response::special(code, cx.conf.server_tokens)
}

fn do_return(cx: &Ctx, ret: &Return) -> Response {
    if ret.code == 444 {
        let mut resp = Response::new(444);
        resp.close = true;
        return resp;
    }
    let Some(text) = &ret.text else {
        return special(cx, ret.code);
    };
    let value = cx.eval(text);
    if matches!(ret.code, 301 | 302 | 303 | 307 | 308) {
        let mut resp = special(cx, ret.code);
        resp.location = Some(value);
        return resp;
    }
    let mut resp = Response::new(ret.code);
    resp.content_type = Some(content_type(cx, &cx.uri));
    resp.content_length = Some(value.len() as u64);
    resp.body = value.into_bytes();
    resp
}

/// The MIME type for a URI, from its extension, or default_type.
pub fn content_type(cx: &Ctx, uri: &str) -> String {
    let last = uri.rsplit('/').next().unwrap_or("");
    if let Some(dot) = last.rfind('.') {
        let ext = last[dot + 1..].to_ascii_lowercase();
        if let Some(t) = cx.conf.types.get(&ext) {
            return t.clone();
        }
    }
    cx.conf.default_type.clone()
}

enum Tried {
    Found(String),
    Code(u16),
    Redirect(String, String),
    Named(String),
}

fn try_files(cx: &Ctx, list: &[Template]) -> Tried {
    let last = list.len() - 1;
    for (i, t) in list.iter().enumerate() {
        let value = cx.eval(t);
        if i == last {
            if let Some(code) = value.strip_prefix('=') {
                return Tried::Code(code.parse().unwrap_or(500));
            }
            if value.starts_with('@') {
                return Tried::Named(value);
            }
            return match value.split_once('?') {
                Some((u, a)) => Tried::Redirect(u.to_string(), a.to_string()),
                None => Tried::Redirect(value, String::new()),
            };
        }
        let (name, test_dir) = match value.strip_suffix('/') {
            Some("") => (value.clone(), true),
            Some(n) => (n.to_string(), true),
            None => (value.clone(), false),
        };
        let path = cx.map_path(&name);
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.is_dir() != test_dir {
            continue;
        }
        return Tried::Found(name);
    }
    Tried::Code(404)
}

enum Content {
    Done(Response),
    Redirect(String),
}

fn method_allowed(m: &str) -> bool {
    matches!(m, "GET" | "HEAD" | "POST")
}

fn static_content(cx: &Ctx) -> Content {
    let uri = cx.uri.clone();
    let method = cx.req.method.as_str();
    if uri.ends_with('/') {
        if !method_allowed(method) {
            return Content::Done(special(cx, 405));
        }
        // The index module.
        for (i, t) in cx.conf.index.iter().enumerate() {
            let name = cx.eval(t);
            if name.starts_with('/') {
                if i == cx.conf.index.len() - 1 {
                    return Content::Redirect(name);
                }
                if std::fs::metadata(cx.map_path(&name)).is_ok() {
                    return Content::Redirect(name);
                }
                continue;
            }
            let candidate = format!("{uri}{name}");
            match std::fs::metadata(cx.map_path(&candidate)) {
                Ok(_) => return Content::Redirect(candidate),
                Err(e) if e.kind() == ErrorKind::PermissionDenied => {
                    return Content::Done(special(cx, 403))
                }
                Err(_) => continue,
            }
        }
        return match std::fs::metadata(cx.map_path(&uri)) {
            Ok(m) if m.is_dir() => Content::Done(special(cx, 403)),
            Ok(_) | Err(_) => Content::Done(special(cx, 404)),
        };
    }
    if !method_allowed(method) {
        return Content::Done(special(cx, 405));
    }
    let path = cx.map_path(&uri);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => return Content::Done(special(cx, 403)),
        Err(_) => return Content::Done(special(cx, 404)),
    };
    if meta.is_dir() {
        let mut resp = special(cx, 301);
        let mut location = format!("{uri}/");
        if !cx.args.is_empty() {
            location.push('?');
            location.push_str(&cx.args);
        }
        resp.location = Some(location);
        return Content::Done(resp);
    }
    if !meta.is_file() {
        return Content::Done(special(cx, 404));
    }
    if method == "POST" {
        return Content::Done(special(cx, 405));
    }
    let body = if method == "HEAD" {
        Vec::new()
    } else {
        match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Content::Done(special(cx, 403)),
            Err(_) => return Content::Done(special(cx, 404)),
        }
    };
    use std::os::unix::fs::MetadataExt;
    let mtime = meta.mtime();
    let size = meta.len();
    let mut resp = Response::new(200);
    resp.content_type = Some(content_type(cx, &uri));
    resp.content_length = Some(size);
    resp.last_modified = Some(mtime);
    resp.headers.push(("ETag".into(), format!("\"{:x}-{:x}\"", mtime, size)));
    resp.headers.push(("Accept-Ranges".into(), "bytes".into()));
    resp.body = body;
    Content::Done(resp)
}

/// Escapes a URI the way ngx_escape_uri(NGX_ESCAPE_URI) does: space, "#",
/// "%", "?" and bytes outside printable ASCII.
pub fn escape_uri(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b <= 0x20 || b >= 0x7f || b == b'#' || b == b'%' || b == b'?' {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// Statuses add_header applies to without "always".
fn add_header_applies(status: u16) -> bool {
    matches!(status, 200 | 201 | 204 | 206 | 301 | 302 | 303 | 304 | 307 | 308)
}

fn finalize(cx: &Ctx, mut resp: Response) -> Response {
    if resp.status == 444 {
        return resp;
    }
    let applies = add_header_applies(resp.status);
    for h in &cx.conf.add_headers {
        if !(applies || h.always) {
            continue;
        }
        let value = cx.eval(&h.value);
        if value.is_empty() {
            continue;
        }
        resp.headers.push((h.name.clone(), value));
    }
    if let Some(loc) = &resp.location {
        if loc.starts_with('/') && cx.conf.absolute_redirect {
            let host = if cx.conf.server_name_in_redirect {
                cx.server.names.first().cloned().unwrap_or_default()
            } else {
                cx.host_name()
            };
            let port = cx.local.port();
            let port_part = if !cx.conf.port_in_redirect || port == 80 {
                String::new()
            } else {
                format!(":{port}")
            };
            resp.location = Some(format!("http://{host}{port_part}{loc}"));
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_uris_like_nginx() {
        assert_eq!(escape_uri("/a b/%?#x"), "/a%20b/%25%3F%23x");
        assert_eq!(escape_uri("/caf\u{e9}"), "/caf%C3%A9");
        assert_eq!(escape_uri("/a=b&c"), "/a=b&c");
    }

    #[test]
    fn add_header_statuses() {
        assert!(add_header_applies(200));
        assert!(add_header_applies(301));
        assert!(!add_header_applies(404));
        assert!(!add_header_applies(418));
    }
}
