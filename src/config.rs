//! Reading nginx's configuration language: the tokenizer, the directive tree,
//! and the runtime model that the server answers requests with.

use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::template::Template;

/// The prefix nginx resolves relative paths such as `root html` against.
pub const PREFIX: &str = "/etc/nginx/";

// ---------------------------------------------------------------------------
// Tokens and the directive tree

#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    pub name: String,
    pub args: Vec<String>,
    pub file: String,
    pub line: usize,
    pub block: Option<Vec<Directive>>,
}

impl Directive {
    fn at(&self) -> String {
        format!("{}:{}", self.file, self.line)
    }
    fn err(&self, msg: impl AsRef<str>) -> String {
        format!("{} in {}", msg.as_ref(), self.at())
    }
}

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Semi,
    Open,
    Close,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
    file: String,
}

impl<'a> Lexer<'a> {
    /// Returns the next token and the line it started on, or None at the end.
    fn next(&mut self) -> Result<Option<(Tok, usize)>, String> {
        loop {
            while self.pos < self.src.len() && self.src[self.pos].is_ascii_whitespace() {
                if self.src[self.pos] == b'\n' {
                    self.line += 1;
                }
                self.pos += 1;
            }
            if self.pos >= self.src.len() {
                return Ok(None);
            }
            if self.src[self.pos] == b'#' {
                while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
        let line = self.line;
        let c = self.src[self.pos];
        match c {
            b';' => {
                self.pos += 1;
                return Ok(Some((Tok::Semi, line)));
            }
            b'{' => {
                self.pos += 1;
                return Ok(Some((Tok::Open, line)));
            }
            b'}' => {
                self.pos += 1;
                return Ok(Some((Tok::Close, line)));
            }
            _ => {}
        }
        let mut raw = Vec::new();
        if c == b'"' || c == b'\'' {
            self.pos += 1;
            loop {
                if self.pos >= self.src.len() {
                    return Err(format!(
                        "unexpected end of file, expecting \";\" or \"}}\" in {}:{}",
                        self.file, self.line
                    ));
                }
                let ch = self.src[self.pos];
                if ch == b'\\' && self.pos + 1 < self.src.len() {
                    raw.push(ch);
                    raw.push(self.src[self.pos + 1]);
                    if self.src[self.pos + 1] == b'\n' {
                        self.line += 1;
                    }
                    self.pos += 2;
                    continue;
                }
                self.pos += 1;
                if ch == c {
                    break;
                }
                if ch == b'\n' {
                    self.line += 1;
                }
                raw.push(ch);
            }
            if self.pos < self.src.len() {
                let next = self.src[self.pos];
                if !(next.is_ascii_whitespace() || next == b';' || next == b'{' || next == b'}') {
                    return Err(format!(
                        "unexpected \"{}\" in {}:{}",
                        next as char, self.file, self.line
                    ));
                }
            }
        } else {
            let mut in_var_braces = false;
            while self.pos < self.src.len() {
                let ch = self.src[self.pos];
                if ch == b'\\' && self.pos + 1 < self.src.len() {
                    raw.push(ch);
                    raw.push(self.src[self.pos + 1]);
                    self.pos += 2;
                    continue;
                }
                if in_var_braces {
                    if ch == b'}' {
                        in_var_braces = false;
                    }
                    raw.push(ch);
                    self.pos += 1;
                    continue;
                }
                if ch == b'{' && raw.last() == Some(&b'$') {
                    in_var_braces = true;
                    raw.push(ch);
                    self.pos += 1;
                    continue;
                }
                if ch.is_ascii_whitespace() || ch == b';' || ch == b'{' || ch == b'}' {
                    break;
                }
                raw.push(ch);
                self.pos += 1;
            }
        }
        Ok(Some((Tok::Word(unescape(&raw)), line)))
    }
}

/// Applies the escapes nginx applies to every token: \" \' \\ \t \r \n.
fn unescape(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' && i + 1 < raw.len() {
            match raw[i + 1] {
                b'"' | b'\'' | b'\\' => {
                    out.push(raw[i + 1]);
                    i += 2;
                    continue;
                }
                b't' => {
                    out.push(b'\t');
                    i += 2;
                    continue;
                }
                b'r' => {
                    out.push(b'\r');
                    i += 2;
                    continue;
                }
                b'n' => {
                    out.push(b'\n');
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses configuration text into directives, expanding `include`.
pub fn parse_text(text: &str, file: &str, conf_dir: &Path) -> Result<Vec<Directive>, String> {
    let mut lexer = Lexer { src: text.as_bytes(), pos: 0, line: 1, file: file.to_string() };
    let (directives, closed) = parse_block(&mut lexer, conf_dir, 0)?;
    if closed {
        return Err(format!("unexpected \"}}\" in {}:{}", file, lexer.line));
    }
    Ok(directives)
}

fn parse_block(lexer: &mut Lexer, conf_dir: &Path, depth: usize) -> Result<(Vec<Directive>, bool), String> {
    let mut out = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut start_line = 0;
    loop {
        let Some((tok, line)) = lexer.next()? else {
            if !words.is_empty() || depth > 0 {
                return Err(format!(
                    "unexpected end of file, expecting \";\" or \"}}\" in {}:{}",
                    lexer.file, lexer.line
                ));
            }
            return Ok((out, false));
        };
        match tok {
            Tok::Word(w) => {
                if words.is_empty() {
                    start_line = line;
                }
                words.push(w);
            }
            Tok::Semi => {
                if words.is_empty() {
                    return Err(format!("unexpected \";\" in {}:{}", lexer.file, line));
                }
                let name = words.remove(0);
                let d = Directive {
                    name,
                    args: std::mem::take(&mut words),
                    file: lexer.file.clone(),
                    line: start_line,
                    block: None,
                };
                if d.name == "include" {
                    if d.args.len() != 1 {
                        return Err(d.err("invalid number of arguments in \"include\" directive"));
                    }
                    out.extend(include(&d, conf_dir)?);
                } else {
                    out.push(d);
                }
            }
            Tok::Open => {
                if words.is_empty() {
                    return Err(format!("unexpected \"{{\" in {}:{}", lexer.file, line));
                }
                let name = words.remove(0);
                let args = std::mem::take(&mut words);
                let (inner, closed) = parse_block(lexer, conf_dir, depth + 1)?;
                if !closed {
                    return Err(format!(
                        "unexpected end of file, expecting \"}}\" in {}:{}",
                        lexer.file, lexer.line
                    ));
                }
                out.push(Directive {
                    name,
                    args,
                    file: lexer.file.clone(),
                    line: start_line,
                    block: Some(inner),
                });
            }
            Tok::Close => {
                if !words.is_empty() {
                    return Err(format!("unexpected \"}}\" in {}:{}", lexer.file, line));
                }
                if depth == 0 {
                    return Err(format!("unexpected \"}}\" in {}:{}", lexer.file, line));
                }
                return Ok((out, true));
            }
        }
    }
}

fn include(d: &Directive, conf_dir: &Path) -> Result<Vec<Directive>, String> {
    let pattern = &d.args[0];
    let full = if pattern.starts_with('/') {
        PathBuf::from(pattern)
    } else {
        conf_dir.join(pattern)
    };
    let files = if full.to_string_lossy().contains(['*', '?', '[']) {
        glob(&full)
    } else {
        vec![full]
    };
    let mut out = Vec::new();
    for file in files {
        let name = file.to_string_lossy().to_string();
        let text = std::fs::read_to_string(&file).map_err(|e| {
            d.err(format!("open() \"{}\" failed ({})", name, os_error(&e)))
        })?;
        out.extend(parse_text(&text, &name, conf_dir)?);
    }
    Ok(out)
}

fn os_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("{code}: {}", e.kind()),
        None => e.to_string(),
    }
}

/// Expands a glob in the last path component (`conf.d/*.conf`), sorted.
fn glob(path: &Path) -> Vec<PathBuf> {
    let dir = path.parent().unwrap_or(Path::new("/"));
    let pat = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| wildcard(&pat, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn wildcard(pat: &str, name: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|i| go(&p[1..], &n[i..])),
            Some('?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    if name.starts_with('.') && !pat.starts_with('.') {
        return false;
    }
    go(&p, &n)
}

// ---------------------------------------------------------------------------
// The runtime model

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ctx {
    Main,
    Events,
    Http,
    Server,
    Location,
    Upstream,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AddHeader {
    pub name: String,
    pub value: Template,
    pub always: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Return {
    pub code: u16,
    pub text: Option<Template>,
}

/// How a matching `rewrite` goes on: `last` searches the locations again
/// with the new URI, `break` keeps serving it in the current location.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RewriteFlag {
    Last,
    Break,
}

#[derive(Debug)]
pub struct Rewrite {
    pub regex: Regex,
    pub replacement: Template,
    pub flag: RewriteFlag,
}

/// A directive of the rewrite module, run in configuration order.
#[derive(Debug, Clone)]
pub enum RewriteOp {
    Rewrite(Arc<Rewrite>),
    Return(Return),
}

#[derive(Debug)]
pub struct UpstreamServer {
    pub addrs: Vec<SocketAddr>,
    pub weight: u32,
    pub backup: bool,
    pub down: bool,
}

#[derive(Debug)]
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    /// Round-robin position.
    pub next: std::sync::atomic::AtomicUsize,
}

impl Upstream {
    /// The peers to try, in the order round-robin picks them.
    pub fn peers(&self) -> Vec<SocketAddr> {
        let mut ring = Vec::new();
        for server in self.servers.iter().filter(|s| !s.down && !s.backup) {
            for addr in &server.addrs {
                for _ in 0..server.weight.max(1) {
                    ring.push(*addr);
                }
            }
        }
        let backups: Vec<SocketAddr> = self
            .servers
            .iter()
            .filter(|s| !s.down && s.backup)
            .flat_map(|s| s.addrs.clone())
            .collect();
        if ring.is_empty() {
            return backups;
        }
        let start = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % ring.len();
        let mut out = Vec::new();
        for i in 0..ring.len() {
            let a = ring[(start + i) % ring.len()];
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out.extend(backups);
        out
    }
}

#[derive(Debug)]
pub enum ProxyTarget {
    Upstream(Arc<Upstream>),
    Addrs(Vec<SocketAddr>),
}

#[derive(Debug)]
pub struct ProxyPass {
    pub url: String,
    /// The value of $proxy_host: the host as written, with the port if one was given.
    pub host: String,
    pub port: u16,
    pub target: ProxyTarget,
    /// The URI part of proxy_pass, when it has one (even just "/").
    pub uri: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LocConf {
    pub root: Template,
    pub alias: Option<Template>,
    pub index: Vec<Template>,
    pub try_files: Option<Vec<Template>>,
    /// The rewrite module's directives of this level, which are not inherited.
    pub rewrites: Vec<RewriteOp>,
    pub proxy: Option<Arc<ProxyPass>>,
    pub add_headers: Vec<AddHeader>,
    pub proxy_set_headers: Vec<(String, Template)>,
    pub proxy_http_version: String,
    pub default_type: String,
    pub types: Arc<HashMap<String, String>>,
    pub absolute_redirect: bool,
    pub port_in_redirect: bool,
    pub server_name_in_redirect: bool,
    pub server_tokens: bool,
    pub merge_slashes: bool,
    /// The name of the location this configuration belongs to ("" at server level).
    pub location_name: String,
    pub auto_redirect: bool,
}

impl Default for LocConf {
    fn default() -> Self {
        LocConf {
            root: Template::literal(&format!("{PREFIX}html")),
            alias: None,
            index: vec![Template::literal("index.html")],
            try_files: None,
            rewrites: Vec::new(),
            proxy: None,
            add_headers: Vec::new(),
            proxy_set_headers: Vec::new(),
            proxy_http_version: "1.1".to_string(),
            default_type: "text/plain".to_string(),
            types: Arc::new(default_types()),
            absolute_redirect: true,
            port_in_redirect: true,
            server_name_in_redirect: false,
            server_tokens: true,
            merge_slashes: true,
            location_name: String::new(),
            auto_redirect: false,
        }
    }
}

fn default_types() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("html".into(), "text/html".into());
    m.insert("gif".into(), "image/gif".into());
    m.insert("jpg".into(), "image/jpeg".into());
    m
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Modifier {
    Prefix,
    Exact,
    NoRegex,
    Regex,
    RegexCaseless,
    Named,
}

#[derive(Debug)]
pub struct Location {
    pub modifier: Modifier,
    pub name: String,
    pub regex: Option<Regex>,
    pub conf: Arc<LocConf>,
    pub children: Vec<Arc<Location>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Listen {
    pub addr: Option<IpAddr>,
    pub port: u16,
    pub default_server: bool,
}

#[derive(Debug)]
pub struct Server {
    pub listens: Vec<Listen>,
    pub names: Vec<String>,
    pub conf: Arc<LocConf>,
    /// The rewrite module's directives at server level, run before a location is chosen.
    pub rewrites: Vec<RewriteOp>,
    pub locations: Vec<Arc<Location>>,
    pub named: HashMap<String, Arc<Location>>,
}

#[derive(Debug)]
pub struct Config {
    pub servers: Vec<Arc<Server>>,
}

pub fn load(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!("open() \"{path}\" failed ({})", os_error(&e))
    })?;
    let conf_dir = Path::new(path).parent().unwrap_or(Path::new("/")).to_path_buf();
    let tree = parse_text(&text, path, &conf_dir)?;
    build(&tree)
}

pub fn build(tree: &[Directive]) -> Result<Config, String> {
    let mut servers = Vec::new();
    let mut seen_http = false;
    for d in tree {
        check(d, Ctx::Main)?;
        match d.name.as_str() {
            "events" => {
                for e in d.block.as_deref().unwrap_or_default() {
                    check(e, Ctx::Events)?;
                }
            }
            "http" => {
                if seen_http {
                    return Err(d.err("\"http\" directive is duplicate"));
                }
                seen_http = true;
                servers = build_http(d.block.as_deref().unwrap_or_default())?;
            }
            _ => {}
        }
    }
    if !tree.iter().any(|d| d.name == "events") {
        return Err("no \"events\" section in configuration".to_string());
    }
    Ok(Config { servers })
}

/// Checks that a directive is known, allowed in this context, has a
/// block when it needs one and a valid number of arguments.
fn check(d: &Directive, ctx: Ctx) -> Result<(), String> {
    use Ctx::*;
    const HSL: &[Ctx] = &[Http, Server, Location];
    let (ctxs, min, max, block): (&[Ctx], usize, usize, bool) = match d.name.as_str() {
        "worker_processes" | "pid" | "daemon" | "master_process" | "worker_rlimit_nofile"
        | "pcre_jit" | "worker_shutdown_timeout" => (&[Main], 1, 1, false),
        "user" => (&[Main], 1, 2, false),
        "error_log" => (&[Main, Http, Server, Location], 1, 9, false),
        "events" => (&[Main], 0, 0, true),
        "http" => (&[Main], 0, 0, true),
        "worker_connections" | "use" | "multi_accept" | "accept_mutex" => (&[Events], 1, 1, false),
        "server" => (&[Http, Upstream], 0, 99, false),
        "upstream" => (&[Http], 1, 1, true),
        "keepalive" | "keepalive_timeout" if ctx == Upstream => (&[Upstream], 1, 1, false),
        "keepalive_requests" | "keepalive_time" if ctx == Upstream => (&[Upstream], 1, 1, false),
        "listen" => (&[Server], 1, 99, false),
        "server_name" => (&[Server], 1, 999, false),
        "location" => (&[Server, Location], 1, 2, true),
        "types" => (HSL, 0, 0, true),
        "default_type" | "root" | "sendfile" | "tcp_nopush" | "tcp_nodelay" | "server_tokens"
        | "client_max_body_size" | "client_body_buffer_size" | "absolute_redirect"
        | "port_in_redirect" | "server_name_in_redirect" | "keepalive_requests"
        | "send_timeout" | "proxy_http_version" | "proxy_buffering" | "proxy_connect_timeout"
        | "proxy_read_timeout" | "proxy_send_timeout" | "etag" | "if_modified_since"
        | "keepalive_time" | "types_hash_max_size" | "types_hash_bucket_size"
        | "log_not_found" | "msie_padding" | "recursive_error_pages" => (HSL, 1, 1, false),
        "keepalive_timeout" => (HSL, 1, 2, false),
        "access_log" => (HSL, 1, 9, false),
        "log_format" => (&[Http], 2, 999, false),
        "merge_slashes" | "server_names_hash_bucket_size" | "server_names_hash_max_size"
        | "client_header_buffer_size" | "client_header_timeout" | "ignore_invalid_headers"
        | "underscores_in_headers" => (&[Http, Server], 1, 1, false),
        "large_client_header_buffers" => (&[Http, Server], 2, 2, false),
        "alias" => (&[Location], 1, 1, false),
        "index" => (HSL, 1, 999, false),
        "try_files" => (&[Server, Location], 2, 999, false),
        "return" => (&[Server, Location], 1, 2, false),
        "rewrite" => (&[Server, Location], 2, 3, false),
        "add_header" => (HSL, 2, 3, false),
        "proxy_pass" => (&[Location], 1, 1, false),
        "proxy_set_header" => (HSL, 2, 2, false),
        _ => return Err(d.err(format!("unknown directive \"{}\"", d.name))),
    };
    if !ctxs.contains(&ctx) {
        return Err(d.err(format!("\"{}\" directive is not allowed here", d.name)));
    }
    let wants_block = block || (d.name == "server" && ctx == Http);
    match (&d.block, wants_block) {
        (None, true) => {
            return Err(d.err(format!("directive \"{}\" has no opening \"{{\"", d.name)))
        }
        (Some(_), false) => {
            return Err(d.err(format!("directive \"{}\" is not terminated by \";\"", d.name)))
        }
        _ => {}
    }
    let (min, max) = if d.name == "server" && ctx == Http { (0, 0) } else if d.name == "server" { (1, 99) } else { (min, max) };
    if d.args.len() < min || d.args.len() > max {
        return Err(d.err(format!("invalid number of arguments in \"{}\" directive", d.name)));
    }
    Ok(())
}

fn flag(d: &Directive) -> Result<bool, String> {
    match d.args[0].as_str() {
        "on" => Ok(true),
        "off" => Ok(false),
        other => Err(d.err(format!(
            "invalid value \"{other}\" in \"{}\" directive, it must be \"on\" or \"off\"",
            d.name
        ))),
    }
}

fn template(d: &Directive, s: &str) -> Result<Template, String> {
    Template::parse(s).map_err(|e| d.err(e))
}

struct Ctxt<'a> {
    upstreams: &'a HashMap<String, Arc<Upstream>>,
}

fn build_http(block: &[Directive]) -> Result<Vec<Arc<Server>>, String> {
    let mut upstreams = HashMap::new();
    for d in block {
        check(d, Ctx::Http)?;
        if d.name == "upstream" {
            let name = d.args[0].clone();
            if upstreams.contains_key(&name) {
                return Err(d.err(format!("duplicate upstream \"{name}\"")));
            }
            upstreams.insert(name, Arc::new(build_upstream(d)?));
        }
    }
    let cx = Ctxt { upstreams: &upstreams };
    let base = LocConf::default();
    let http_conf = apply_level(&base, block, Ctx::Http, &cx, None)?;
    let mut servers = Vec::new();
    for d in block {
        if d.name == "server" {
            servers.push(Arc::new(build_server(d, &http_conf, &cx)?));
        }
    }
    let mut defaults: HashMap<(Option<IpAddr>, u16), usize> = HashMap::new();
    for server in &servers {
        for l in server.listens.iter().filter(|l| l.default_server) {
            let n = defaults.entry((l.addr, l.port)).or_default();
            *n += 1;
            if *n > 1 {
                let addr = l.addr.map(|a| a.to_string()).unwrap_or_else(|| "0.0.0.0".into());
                return Err(format!("a duplicate default server for {addr}:{}", l.port));
            }
        }
    }
    Ok(servers)
}

fn build_upstream(d: &Directive) -> Result<Upstream, String> {
    let mut servers = Vec::new();
    for s in d.block.as_deref().unwrap_or_default() {
        check(s, Ctx::Upstream)?;
        if s.name != "server" {
            continue;
        }
        let mut weight = 1;
        let mut backup = false;
        let mut down = false;
        for p in &s.args[1..] {
            if let Some(w) = p.strip_prefix("weight=") {
                weight = w.parse().ok().filter(|w| *w > 0).ok_or_else(|| s.err(format!("invalid parameter \"{p}\"")))?;
            } else if p == "backup" {
                backup = true;
            } else if p == "down" {
                down = true;
            } else if p.starts_with("max_fails=") || p.starts_with("fail_timeout=") || p.starts_with("max_conns=") {
            } else {
                return Err(s.err(format!("invalid parameter \"{p}\"")));
            }
        }
        let addrs = resolve(&s.args[0], 80)
            .map_err(|_| s.err(format!("host not found in upstream \"{}\"", s.args[0])))?;
        servers.push(UpstreamServer { addrs, weight, backup, down });
    }
    if servers.is_empty() {
        return Err(format!("no servers are inside upstream in {}", d.at()));
    }
    Ok(Upstream { name: d.args[0].clone(), servers, next: Default::default() })
}

fn split_host_port(s: &str) -> (String, Option<String>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..].strip_prefix(':').map(|p| p.to_string());
            return (host, port);
        }
    }
    match s.rfind(':') {
        Some(i) if !s[..i].contains(':') => (s[..i].to_string(), Some(s[i + 1..].to_string())),
        _ => (s.to_string(), None),
    }
}

fn resolve(s: &str, default_port: u16) -> Result<Vec<SocketAddr>, ()> {
    let (host, port) = split_host_port(s);
    let port: u16 = match port {
        Some(p) => p.parse().map_err(|_| ())?,
        None => default_port,
    };
    let addrs: Vec<SocketAddr> = (host.as_str(), port).to_socket_addrs().map_err(|_| ())?.collect();
    if addrs.is_empty() {
        return Err(());
    }
    Ok(addrs)
}

/// Builds the configuration of one level (http, server or location) from
/// its simple directives, inheriting from the parent.
fn apply_level(
    parent: &LocConf,
    block: &[Directive],
    ctx: Ctx,
    cx: &Ctxt,
    location: Option<(&str, Modifier)>,
) -> Result<LocConf, String> {
    let mut conf = parent.clone();
    conf.try_files = None;
    conf.rewrites = Vec::new();
    conf.proxy = None;
    conf.auto_redirect = false;
    if let Some((name, _)) = location {
        conf.location_name = name.to_string();
    }
    let mut own_add_headers = false;
    let mut own_proxy_headers = false;
    let mut own_index = false;
    let mut seen: Vec<&str> = Vec::new();
    for d in block {
        check(d, ctx)?;
        let once = matches!(
            d.name.as_str(),
            "root" | "alias" | "default_type" | "try_files" | "proxy_pass" | "types"
        );
        if once {
            if seen.contains(&d.name.as_str()) {
                return Err(d.err(format!("\"{}\" directive is duplicate", d.name)));
            }
            seen.push(&d.name);
        }
        match d.name.as_str() {
            "root" | "alias" => {
                let other = if d.name == "root" { "alias" } else { "root" };
                if seen.contains(&other) {
                    return Err(d.err(format!(
                        "\"{}\" directive is duplicate, \"{other}\" directive was specified earlier",
                        d.name
                    )));
                }
                let mut path = d.args[0].clone();
                if !path.starts_with('/') && !path.starts_with('$') {
                    path = format!("{PREFIX}{path}");
                }
                if d.name == "root" {
                    if path.len() > 1 && path.ends_with('/') && d.args[0] != "/" {
                        path.pop();
                    }
                    conf.root = template(d, &path)?;
                    conf.alias = None;
                } else {
                    if let Some((_, Modifier::Named)) = location {
                        return Err(d.err(format!("\"alias\" directive cannot be used inside the named location")));
                    }
                    conf.alias = Some(template(d, &path)?);
                }
            }
            "index" => {
                if !own_index {
                    conf.index.clear();
                    own_index = true;
                }
                for a in &d.args {
                    if a.is_empty() {
                        return Err(d.err("index \"\" in \"index\" directive is invalid"));
                    }
                    conf.index.push(template(d, a)?);
                }
            }
            "default_type" => conf.default_type = d.args[0].clone(),
            "types" => {
                let mut map = HashMap::new();
                for t in d.block.as_deref().unwrap_or_default() {
                    for ext in &t.args {
                        map.insert(ext.to_ascii_lowercase(), t.name.clone());
                    }
                }
                conf.types = Arc::new(map);
            }
            "try_files" => {
                let mut list = Vec::new();
                for a in &d.args {
                    list.push(template(d, a)?);
                }
                conf.try_files = Some(list);
            }
            "return" => conf.rewrites.push(RewriteOp::Return(parse_return(d)?)),
            "rewrite" => conf.rewrites.push(RewriteOp::Rewrite(Arc::new(parse_rewrite(d)?))),
            "add_header" => {
                if !own_add_headers {
                    conf.add_headers.clear();
                    own_add_headers = true;
                }
                let always = match d.args.get(2).map(|s| s.as_str()) {
                    None => false,
                    Some("always") => true,
                    Some(other) => return Err(d.err(format!("invalid parameter \"{other}\""))),
                };
                conf.add_headers.push(AddHeader {
                    name: d.args[0].clone(),
                    value: template(d, &d.args[1])?,
                    always,
                });
            }
            "proxy_set_header" => {
                if !own_proxy_headers {
                    conf.proxy_set_headers.clear();
                    own_proxy_headers = true;
                }
                conf.proxy_set_headers.push((d.args[0].clone(), template(d, &d.args[1])?));
            }
            "proxy_pass" => {
                let (name, modifier) = location.unwrap_or(("", Modifier::Prefix));
                let pass = parse_proxy_pass(d, cx)?;
                if pass.uri.is_some()
                    && matches!(modifier, Modifier::Regex | Modifier::RegexCaseless | Modifier::Named)
                {
                    return Err(d.err("\"proxy_pass\" cannot have URI part in location given by regular expression, or inside named location, or inside \"if\" statement, or inside \"limit_except\" block"));
                }
                if name.ends_with('/') {
                    conf.auto_redirect = true;
                }
                conf.proxy = Some(Arc::new(pass));
            }
            "absolute_redirect" => conf.absolute_redirect = flag(d)?,
            "port_in_redirect" => conf.port_in_redirect = flag(d)?,
            "server_name_in_redirect" => conf.server_name_in_redirect = flag(d)?,
            "server_tokens" => {
                if d.args[0] != "build" {
                    conf.server_tokens = flag(d)?;
                }
            }
            "merge_slashes" => conf.merge_slashes = flag(d)?,
            "sendfile" | "tcp_nopush" | "tcp_nodelay" | "absolute_redirect_" | "etag"
            | "proxy_buffering" | "log_not_found" | "msie_padding" | "recursive_error_pages"
            | "ignore_invalid_headers" | "underscores_in_headers" => {
                flag(d)?;
            }
            "proxy_http_version" => {
                if d.args[0] != "1.0" && d.args[0] != "1.1" {
                    return Err(d.err(format!(
                        "invalid value \"{}\" in \"proxy_http_version\" directive",
                        d.args[0]
                    )));
                }
                conf.proxy_http_version = d.args[0].clone();
            }
            _ => {}
        }
    }
    Ok(conf)
}

fn parse_return(d: &Directive) -> Result<Return, String> {
    let first = &d.args[0];
    if d.args.len() == 1 {
        if let Ok(code) = first.parse::<u16>() {
            if code > 999 {
                return Err(d.err(format!("invalid return code \"{first}\"")));
            }
            return Ok(Return { code, text: None });
        }
        if first.starts_with("http://") || first.starts_with("https://") || first.starts_with("$scheme") {
            return Ok(Return { code: 302, text: Some(template(d, first)?) });
        }
        return Err(d.err(format!("invalid return code \"{first}\"")));
    }
    let code = first
        .parse::<u16>()
        .ok()
        .filter(|c| *c <= 999)
        .ok_or_else(|| d.err(format!("invalid return code \"{first}\"")))?;
    Ok(Return { code, text: Some(template(d, &d.args[1])?) })
}

fn parse_rewrite(d: &Directive) -> Result<Rewrite, String> {
    let regex = Regex::new(&d.args[0]).map_err(|e| d.err(format!("pcre2_compile() failed: {e} in \"{}\"", d.args[0])))?;
    let flag = match d.args.get(2).map(String::as_str) {
        Some("last") => RewriteFlag::Last,
        Some("break") => RewriteFlag::Break,
        other => {
            return Err(d.err(format!("rewrite flag \"{}\" is not supported by twinx yet", other.unwrap_or(""))))
        }
    };
    Ok(Rewrite { regex, replacement: template(d, &d.args[1])?, flag })
}

fn parse_proxy_pass(d: &Directive, cx: &Ctxt) -> Result<ProxyPass, String> {
    let url = &d.args[0];
    if url.contains('$') {
        return Err(d.err("proxy_pass with variables is not supported by twinx yet"));
    }
    let rest = if let Some(r) = url.strip_prefix("http://") {
        r
    } else if url.starts_with("https://") {
        return Err(d.err("proxy_pass to https is not supported by twinx yet"));
    } else {
        return Err(d.err(format!("invalid URL prefix in \"{url}\"")));
    };
    let (authority, uri) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(rest[i..].to_string())),
        None => (rest, None),
    };
    if authority.is_empty() {
        return Err(d.err(format!("no host in \"{url}\"")));
    }
    let (host, port) = split_host_port(authority);
    if let Some(up) = cx.upstreams.get(authority) {
        return Ok(ProxyPass {
            url: url.clone(),
            host: authority.to_string(),
            port: 80,
            target: ProxyTarget::Upstream(up.clone()),
            uri,
        });
    }
    let port_num: u16 = match &port {
        Some(p) => p.parse().map_err(|_| d.err(format!("invalid port in upstream \"{authority}\"")))?,
        None => 80,
    };
    let addrs = resolve(authority, 80)
        .map_err(|_| d.err(format!("host not found in upstream \"{authority}\"")))?;
    let _ = host;
    Ok(ProxyPass {
        url: url.clone(),
        host: authority.to_string(),
        port: port_num,
        target: ProxyTarget::Addrs(addrs),
        uri,
    })
}

fn parse_listen(d: &Directive) -> Result<Listen, String> {
    let spec = &d.args[0];
    let (addr, port) = if let Ok(port) = spec.parse::<u16>() {
        (None, port)
    } else {
        let (host, port) = split_host_port(spec);
        let port = match port {
            Some(p) => p.parse::<u16>().map_err(|_| d.err(format!("invalid port in \"{spec}\" of the \"listen\" directive")))?,
            None => 80,
        };
        let addr = if host == "*" {
            None
        } else if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_unspecified() { None } else { Some(ip) }
        } else {
            let resolved = (host.as_str(), port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut a| a.next())
                .ok_or_else(|| d.err(format!("host not found in \"{spec}\" of the \"listen\" directive")))?;
            Some(resolved.ip())
        };
        (addr, port)
    };
    let mut default_server = false;
    for p in &d.args[1..] {
        match p.as_str() {
            "default_server" | "default" => default_server = true,
            "reuseport" | "deferred" | "bind" => {}
            p if p.starts_with("backlog=") || p.starts_with("rcvbuf=") || p.starts_with("sndbuf=") => {}
            other => return Err(d.err(format!("invalid parameter \"{other}\""))),
        }
    }
    Ok(Listen { addr, port, default_server })
}

fn build_server(d: &Directive, http_conf: &LocConf, cx: &Ctxt) -> Result<Server, String> {
    let block = d.block.as_deref().unwrap_or_default();
    let conf = apply_level(http_conf, block, Ctx::Server, cx, None)?;
    let mut listens = Vec::new();
    let mut names = Vec::new();
    for s in block {
        match s.name.as_str() {
            "listen" => {
                let l = parse_listen(s)?;
                if listens.iter().any(|x: &Listen| x.addr == l.addr && x.port == l.port) {
                    let addr = l.addr.map(|a| a.to_string()).unwrap_or_else(|| "0.0.0.0".into());
                    return Err(s.err(format!("duplicate listen {addr}:{}", l.port)));
                }
                listens.push(l);
            }
            "server_name" => {
                for n in &s.args {
                    names.push(n.to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    if listens.is_empty() {
        listens.push(Listen { addr: None, port: 80, default_server: false });
    }
    let mut server_conf = conf;
    let rewrites = std::mem::take(&mut server_conf.rewrites);
    let server_conf = Arc::new(server_conf);
    let mut named = HashMap::new();
    let locations = build_locations(block, &server_conf, cx, None, &mut named)?;
    Ok(Server { listens, names, conf: server_conf, rewrites, locations, named })
}

fn build_locations(
    block: &[Directive],
    parent_conf: &LocConf,
    cx: &Ctxt,
    parent: Option<(&str, Modifier)>,
    named: &mut HashMap<String, Arc<Location>>,
) -> Result<Vec<Arc<Location>>, String> {
    let mut out: Vec<Arc<Location>> = Vec::new();
    for d in block.iter().filter(|d| d.name == "location") {
        let (modifier, name) = if d.args.len() == 2 {
            let m = match d.args[0].as_str() {
                "=" => Modifier::Exact,
                "^~" => Modifier::NoRegex,
                "~" => Modifier::Regex,
                "~*" => Modifier::RegexCaseless,
                other => return Err(d.err(format!("invalid location modifier \"{other}\""))),
            };
            (m, d.args[1].clone())
        } else {
            let a = &d.args[0];
            if let Some(n) = a.strip_prefix('=') {
                (Modifier::Exact, n.to_string())
            } else if let Some(n) = a.strip_prefix("^~") {
                (Modifier::NoRegex, n.to_string())
            } else if let Some(n) = a.strip_prefix("~*") {
                (Modifier::RegexCaseless, n.to_string())
            } else if let Some(n) = a.strip_prefix('~') {
                (Modifier::Regex, n.to_string())
            } else if a.starts_with('@') {
                (Modifier::Named, a.clone())
            } else {
                (Modifier::Prefix, a.clone())
            }
        };
        if let Some((pname, pmod)) = parent {
            if pmod == Modifier::Exact {
                return Err(d.err(format!("location \"{name}\" cannot be inside the exact location \"{pname}\"")));
            }
            if pmod == Modifier::Named {
                return Err(d.err(format!("location \"{name}\" cannot be inside the named location \"{pname}\"")));
            }
            if modifier == Modifier::Named {
                return Err(d.err(format!("named location \"{name}\" can be on the server level only")));
            }
            let is_regex = |m| matches!(m, Modifier::Regex | Modifier::RegexCaseless);
            if !is_regex(pmod) && !is_regex(modifier) && !name.starts_with(pname) {
                return Err(d.err(format!("location \"{name}\" is outside location \"{pname}\"")));
            }
        }
        let regex = match modifier {
            Modifier::Regex | Modifier::RegexCaseless => {
                let pat = if modifier == Modifier::RegexCaseless { format!("(?i){name}") } else { name.clone() };
                Some(Regex::new(&pat).map_err(|e| d.err(format!("pcre2_compile() failed: {e} in \"{name}\"")))?)
            }
            _ => None,
        };
        let dup = out.iter().any(|l| {
            l.name == name
                && match (l.modifier, modifier) {
                    (Modifier::Exact, Modifier::Exact) => true,
                    (Modifier::Prefix | Modifier::NoRegex, Modifier::Prefix | Modifier::NoRegex) => true,
                    _ => false,
                }
        }) || (modifier == Modifier::Named && named.contains_key(&name));
        if dup {
            return Err(d.err(format!("duplicate location \"{name}\"")));
        }
        let inner = d.block.as_deref().unwrap_or_default();
        let conf = apply_level(parent_conf, inner, Ctx::Location, cx, Some((&name, modifier)))?;
        if conf.alias.is_some() && modifier != Modifier::Regex && modifier != Modifier::RegexCaseless {
            // alias in a prefix location replaces the location name.
        }
        let conf = Arc::new(conf);
        let children = build_locations(inner, &conf, cx, Some((&name, modifier)), named)?;
        let loc = Arc::new(Location { modifier, name: name.clone(), regex, conf, children });
        if modifier == Modifier::Named {
            named.insert(name, loc);
        } else {
            out.push(loc);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Vec<Directive>, String> {
        parse_text(s, "t.conf", Path::new("/nonexistent"))
    }

    #[test]
    fn tokenizes_quotes_escapes_and_comments() {
        let t = parse("a \"x y\" 'z' up\\n; # comment\nb { c; }").unwrap();
        assert_eq!(t[0].name, "a");
        assert_eq!(t[0].args, vec!["x y", "z", "up\n"]);
        assert_eq!(t[1].name, "b");
        assert_eq!(t[1].line, 2);
        assert_eq!(t[1].block.as_ref().unwrap()[0].name, "c");
    }

    #[test]
    fn keeps_variable_braces_in_words() {
        let t = parse("x ${host}a;").unwrap();
        assert_eq!(t[0].args, vec!["${host}a"]);
    }

    #[test]
    fn reports_unbalanced_blocks() {
        assert!(parse("a {").unwrap_err().contains("unexpected end of file"));
        assert!(parse("}").unwrap_err().contains("unexpected \"}\""));
        assert!(parse("a b").unwrap_err().contains("unexpected end of file"));
    }

    fn conf(http: &str) -> Result<Config, String> {
        let text = format!("events {{}}\nhttp {{\n{http}\n}}\n");
        build(&parse(&text)?)
    }

    #[test]
    fn refuses_unknown_and_misplaced_directives() {
        assert!(conf("server { frobnicate on; }").unwrap_err().contains("unknown directive \"frobnicate\""));
        assert!(conf("listen 80;").unwrap_err().contains("\"listen\" directive is not allowed here"));
        assert!(conf("server { listen 1; root; }").unwrap_err().contains("invalid number of arguments"));
    }

    #[test]
    fn builds_servers_locations_and_inheritance() {
        let c = conf(
            "root /srv; add_header A 1; server { listen 8080; server_name Example.test;
             location /a/ { add_header B 2; location /a/b/ { } }
             location = /x { return 301 /y; }
             location ~* \\.png$ { }
             location @fallback { return 404; } }",
        )
        .unwrap();
        let s = &c.servers[0];
        assert_eq!(s.listens[0].port, 8080);
        assert_eq!(s.names, vec!["example.test"]);
        assert_eq!(s.locations.len(), 3);
        assert_eq!(s.conf.root.raw, "/srv");
        assert_eq!(s.conf.add_headers.len(), 1);
        let a = &s.locations[0];
        assert_eq!(a.conf.add_headers[0].name, "B");
        assert_eq!(a.children[0].conf.add_headers[0].name, "B");
        assert_eq!(ret(&s.locations[1].conf), &Return { code: 301, text: Some(Template::literal("/y")) });
        assert!(s.named.contains_key("@fallback"));
    }

    #[test]
    fn checks_nested_location_names() {
        assert!(conf("server { location /a/ { location /b/ {} } }").unwrap_err().contains("is outside location"));
    }

    #[test]
    fn parses_proxy_pass() {
        let c = conf("upstream app { server 127.0.0.1:9000; } server { location /x/ { proxy_pass http://app/y/; } location /z { proxy_pass http://127.0.0.1:9001; } }").unwrap();
        let x = c.servers[0].locations[0].conf.proxy.clone().unwrap();
        assert_eq!(x.uri.as_deref(), Some("/y/"));
        assert_eq!(x.host, "app");
        assert!(c.servers[0].locations[0].conf.auto_redirect);
        let z = c.servers[0].locations[1].conf.proxy.clone().unwrap();
        assert_eq!(z.uri, None);
        assert_eq!(z.host, "127.0.0.1:9001");
        assert!(conf("server { location ~ x { proxy_pass http://127.0.0.1:1/a; } }").is_err());
    }

    #[test]
    fn parses_return_forms() {
        let c = conf("server { location /a { return 404; } location /b { return https://x/; } location /c { return 200 \"ok\"; } }").unwrap();
        let l = &c.servers[0].locations;
        assert_eq!(ret(&l[0].conf).code, 404);
        assert_eq!(ret(&l[1].conf).code, 302);
        assert_eq!(ret(&l[2].conf).text.as_ref().unwrap().raw, "ok");
        assert!(conf("server { return abc; }").is_err());
    }

    fn ret(conf: &LocConf) -> &Return {
        match &conf.rewrites[0] {
            RewriteOp::Return(r) => r,
            other => panic!("not a return: {other:?}"),
        }
    }

    #[test]
    fn parses_rewrites_in_order_without_inheriting_them() {
        let c = conf(
            "server { rewrite ^/a/(.*)$ /b/$1 last;
             location /b/ { rewrite ^/b/(\\w+)$ /c/$1 break; return 403; location /b/x/ {} } }",
        )
        .unwrap();
        let s = &c.servers[0];
        assert_eq!(s.rewrites.len(), 1);
        assert!(s.conf.rewrites.is_empty());
        let b = &s.locations[0];
        let RewriteOp::Rewrite(rw) = &b.conf.rewrites[0] else { panic!() };
        assert_eq!(rw.flag, RewriteFlag::Break);
        assert_eq!(rw.replacement.raw, "/c/$1");
        assert!(rw.regex.is_match("/b/abc"));
        assert!(matches!(b.conf.rewrites[1], RewriteOp::Return(Return { code: 403, .. })));
        assert!(b.children[0].conf.rewrites.is_empty());
    }

    #[test]
    fn refuses_rewrites_twinx_does_not_implement() {
        assert!(conf("server { rewrite ^ /x redirect; }").unwrap_err().contains("rewrite flag \"redirect\" is not supported"));
        assert!(conf("server { rewrite ^ /x; }").unwrap_err().contains("rewrite flag \"\""));
        assert!(conf("server { rewrite ( /x last; }").unwrap_err().contains("pcre2_compile() failed"));
        assert!(conf("location / { rewrite ^ /x last; }").unwrap_err().contains("not allowed here"));
    }
}
