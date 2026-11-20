//! What the directives mean: checks each one as nginx does (known, allowed in
//! its block, right number of arguments) and builds the configuration twinx runs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Directive;
use crate::upstream::{Peer, Upstream};
use crate::vars::Template;

const MAIN: u8 = 1;
const EVENTS: u8 = 2;
const HTTP: u8 = 4;
const SRV: u8 = 8;
const LOC: u8 = 16;
const UPS: u8 = 32;
const HSL: u8 = HTTP | SRV | LOC;

/// Every directive twinx knows: where it may appear, its argument counts, and
/// whether it takes a block.
const DIRECTIVES: &[(&str, u8, usize, usize, bool)] = &[
    ("daemon", MAIN, 1, 1, false),
    ("pid", MAIN, 1, 1, false),
    ("error_log", MAIN, 1, usize::MAX, false),
    ("events", MAIN, 0, 0, true),
    ("http", MAIN, 0, 0, true),
    ("server", HTTP, 0, 0, true),
    ("upstream", HTTP, 1, 1, true),
    ("server", UPS, 1, usize::MAX, false),
    ("listen", SRV, 1, usize::MAX, false),
    ("server_name", SRV, 1, usize::MAX, false),
    ("location", SRV | LOC, 1, 2, true),
    ("return", SRV | LOC, 1, 2, false),
    ("root", HTTP | SRV | LOC, 1, 1, false),
    ("log_format", HTTP, 2, usize::MAX, false),
    ("access_log", HTTP | SRV | LOC, 1, usize::MAX, false),
    ("client_body_temp_path", HTTP | SRV | LOC, 1, 4, false),
    ("proxy_temp_path", HTTP | SRV | LOC, 1, 4, false),
    ("client_header_buffer_size", HTTP | SRV, 1, 1, false),
    ("client_body_buffer_size", HSL, 1, 1, false),
    ("client_body_in_file_only", HSL, 1, 1, false),
    ("client_body_in_single_buffer", HSL, 1, 1, false),
    ("client_max_body_size", HSL, 1, 1, false),
    ("add_header", HSL, 2, 3, false),
    ("error_page", HSL, 2, usize::MAX, false),
    ("proxy_pass", LOC, 1, 1, false),
    ("expires", HSL, 1, 2, false),
];

const COMBINED: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

#[derive(Debug)]
pub struct AccessLog {
    pub file: Arc<File>,
    pub format: Arc<Template>,
}

/// Where proxy_pass sends requests: the servers in the order they are tried
/// (backup servers last), the Host to send, and the URI that replaces the
/// location's prefix, if the directive has one.
#[derive(Debug)]
pub struct Proxy {
    pub host: String,
    pub upstream: Arc<Upstream>,
    pub uri: Option<String>,
}

/// An error_page: the statuses, the status to answer with instead (None keeps
/// the status, as nginx does for redirects it turns into 302), and the URL.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorPage {
    pub codes: Vec<u16>,
    pub status: Option<u16>,
    pub url: Template,
}

/// The settings of one level (http, server or location) after inheriting from the one above.
#[derive(Debug, Clone, Default)]
pub struct Level {
    pub ret: Option<(u16, Template)>,
    pub access_log: Vec<Arc<AccessLog>>,
    pub root: PathBuf,
    /// add_header: name, value, and whether it is added whatever the status ("always").
    pub add_header: Vec<(String, Template, bool)>,
    pub error_page: Vec<ErrorPage>,
    pub proxy: Option<Arc<Proxy>>,
    pub max_body: u64,
    pub body_buffer: u64,
    pub body_in_file_only: bool,
    pub body_temp_path: PathBuf,
    /// expires, as written ("modified 1h", "$arg_e"): parsed for each response.
    pub expires: Option<Template>,
}

/// How a location matches the URI: "=", a prefix, "^~" (a prefix that stops
/// the regular expressions from being checked), or "~" / "~*".
#[derive(Debug)]
pub enum Match {
    Exact,
    Prefix,
    NoRegex,
    Regex(regex::Regex),
}

#[derive(Debug)]
pub struct Location {
    pub kind: Match,
    pub path: String,
    pub level: Level,
}

#[derive(Debug)]
pub struct Server {
    pub listen: Vec<SocketAddr>,
    pub names: Vec<String>,
    pub level: Level,
    pub locations: Vec<Location>,
}

#[derive(Debug)]
pub struct Config {
    pub pid: PathBuf,
    pub servers: Vec<Server>,
}

struct Builder<'a> {
    prefix: &'a Path,
    formats: HashMap<String, Arc<Template>>,
    logs: HashMap<PathBuf, Arc<File>>,
    upstreams: HashMap<String, Arc<Upstream>>,
}

/// Interprets the main block. Errors are nginx's messages, with the place.
pub fn build(main: &[Directive], prefix: &Path) -> Result<Config, String> {
    let combined = Arc::new(Template::parse(COMBINED)?);
    let formats = HashMap::from([("combined".to_string(), combined)]);
    let mut b = Builder { prefix, formats, logs: HashMap::new(), upstreams: HashMap::new() };
    let mut config = Config { pid: prefix.join("logs/nginx.pid"), servers: Vec::new() };
    for d in main {
        b.check(d, MAIN)?;
        match d.name.as_str() {
            "pid" => config.pid = b.path(&d.args[0]),
            "error_log" => b.open(&d.args[0]).map(drop).map_err(|e| format!("{e} in {}", d.at))?,
            "events" => d.block.iter().flatten().try_for_each(|e| b.check(e, EVENTS))?,
            "http" => config.servers = b.http(d.block.as_deref().unwrap_or_default())?,
            _ => {}
        }
    }
    Ok(config)
}

impl Builder<'_> {
    fn check(&self, d: &Directive, ctx: u8) -> Result<(), String> {
        let at = &d.at;
        let named = || DIRECTIVES.iter().filter(|s| s.0 == d.name);
        let spec = named().find(|s| s.1 & ctx != 0).or_else(|| named().next());
        let (_, where_, min, max, block) = spec.ok_or_else(|| format!("unknown directive \"{}\" in {at}", d.name))?;
        if where_ & ctx == 0 { return Err(format!("\"{}\" directive is not allowed here in {at}", d.name)); }
        if d.block.is_some() != *block { return Err(format!("directive \"{}\" has no opening \"{{\" in {at}", d.name)); }
        if d.args.len() < *min || d.args.len() > *max { return Err(format!("invalid number of arguments in \"{}\" directive in {at}", d.name)); }
        Ok(())
    }

    fn path(&self, p: &str) -> PathBuf {
        self.prefix.join(p)
    }

    /// Opens (creating it) a log file to append to; one handle per path.
    fn open(&mut self, p: &str) -> Result<Arc<File>, String> {
        let path = self.path(p);
        if let Some(f) = self.logs.get(&path) { return Ok(f.clone()); }
        let file = OpenOptions::new().create(true).append(true).open(&path);
        let file = Arc::new(file.map_err(|e| format!("open() \"{}\" failed ({e})", path.display()))?);
        self.logs.insert(path, file.clone());
        Ok(file)
    }

    fn http(&mut self, block: &[Directive]) -> Result<Vec<Server>, String> {
        let temp = self.path("client_body_temp");
        let mut level = Level { max_body: 1 << 20, body_buffer: 16 << 10, body_temp_path: temp, ..Level::default() };
        for d in block.iter().filter(|d| d.name == "upstream") {
            let servers = d.block.as_deref().unwrap_or_default();
            servers.iter().try_for_each(|s| self.check(s, UPS))?;
            let peers = servers.iter().map(|s| peer(&s.args).map_err(|e| format!("{e} in {}", s.at)));
            let upstream = Upstream::new(peers.collect::<Result<_, _>>()?);
            self.upstreams.insert(d.args[0].clone(), Arc::new(upstream));
        }
        self.level(block, HTTP, &mut level)?;
        let servers = block.iter().filter(|d| d.name == "server");
        servers.map(|d| self.server(d.block.as_deref().unwrap_or_default(), &level)).collect()
    }

    fn server(&mut self, block: &[Directive], parent: &Level) -> Result<Server, String> {
        let mut s = Server { listen: Vec::new(), names: Vec::new(), level: parent.clone(), locations: Vec::new() };
        self.level(block, SRV, &mut s.level)?;
        for d in block {
            match d.name.as_str() {
                "listen" => s.listen.push(listen(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?),
                "server_name" => s.names.extend(d.args.iter().map(|n| n.to_lowercase())),
                _ => {}
            }
        }
        if s.listen.is_empty() { s.listen.push(SocketAddr::from(([0, 0, 0, 0], 80))); }
        let level = s.level.clone();
        self.locations(block, &level, &mut s.locations)?;
        Ok(s)
    }

    fn locations(&mut self, block: &[Directive], parent: &Level, out: &mut Vec<Location>) -> Result<(), String> {
        for d in block.iter().filter(|d| d.name == "location") {
            let mut level = Level { proxy: None, ..parent.clone() };
            let inner = d.block.as_deref().unwrap_or_default();
            self.level(inner, LOC, &mut level)?;
            let (kind, path) = location(&d.args).map_err(|e| format!("{e} in {}", d.at))?;
            out.push(Location { kind, path, level: level.clone() });
            self.locations(inner, &level, out)?;
        }
        Ok(())
    }

    /// Applies the directives of one level that are not blocks of their own;
    /// access_log replaces what the level above set as a whole.
    fn level(&mut self, block: &[Directive], ctx: u8, level: &mut Level) -> Result<(), String> {
        let mut logs: Option<Vec<Arc<AccessLog>>> = None;
        let mut headers: Option<Vec<(String, Template, bool)>> = None;
        let mut pages: Option<Vec<ErrorPage>> = None;
        for d in block {
            self.check(d, ctx)?;
            let at = |e: String| format!("{e} in {}", d.at);
            match d.name.as_str() {
                "return" => level.ret = Some(ret(&d.args).map_err(at)?),
                "root" => level.root = self.path(&d.args[0]),
                "log_format" => {
                    let t = Template::parse(&d.args[1..].concat()).map_err(at)?;
                    self.formats.insert(d.args[0].clone(), Arc::new(t));
                }
                "access_log" => logs.get_or_insert_default().extend(self.access_log(&d.args).map_err(at)?),
                "add_header" => headers.get_or_insert_default().push(add_header(&d.args).map_err(at)?),
                "error_page" => pages.get_or_insert_default().push(error_page(&d.args).map_err(at)?),
                "proxy_pass" => level.proxy = Some(Arc::new(self.proxy(&d.args[0]).map_err(at)?)),
                "client_max_body_size" => level.max_body = size(&d.args[0]).map_err(at)?,
                "client_body_buffer_size" => level.body_buffer = size(&d.args[0]).map_err(at)?,
                "client_body_in_file_only" => level.body_in_file_only = d.args[0] != "off",
                "client_body_temp_path" => level.body_temp_path = self.path(&d.args[0]),
                "expires" => level.expires = Some(expires(&d.args).map_err(at)?),
                _ => {}
            }
        }
        if let Some(logs) = logs { level.access_log = logs; }
        if let Some(headers) = headers { level.add_header = headers; }
        if let Some(pages) = pages { level.error_page = pages; }
        Ok(())
    }

    fn access_log(&mut self, args: &[String]) -> Result<Option<Arc<AccessLog>>, String> {
        if args[0] == "off" { return Ok(None); }
        let name = args.get(1).map_or("combined", |n| n.as_str());
        let format = self.formats.get(name).cloned().ok_or_else(|| format!("unknown log format \"{name}\""))?;
        let file = self.open(&args[0])?;
        Ok(Some(Arc::new(AccessLog { file, format })))
    }

    /// proxy_pass http://host[:port][/uri], where host may name an upstream block.
    fn proxy(&self, url: &str) -> Result<Proxy, String> {
        let rest = url.strip_prefix("http://").ok_or_else(|| format!("invalid URL prefix in \"{url}\""))?;
        let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
        let single = || listen(host).map(|a| Arc::new(Upstream::new(vec![Peer::new(a)])));
        let upstream = self.upstreams.get(host).cloned().map_or_else(single, Ok);
        let upstream = upstream.map_err(|_| format!("host not found in upstream \"{host}\""))?;
        Ok(Proxy { host: host.to_string(), upstream, uri })
    }
}

/// location [ = | ^~ | ~ | ~* ] uri
fn location(args: &[String]) -> Result<(Match, String), String> {
    let (modifier, path) = if args.len() == 2 { (args[0].as_str(), &args[1]) } else { ("", &args[0]) };
    let regex = |p: String| regex::Regex::new(&p).map(Match::Regex).map_err(|e| format!("invalid regular expression \"{path}\": {e}"));
    let kind = match modifier {
        "~" | "~*" => regex(if modifier == "~*" { format!("(?i){path}") } else { path.clone() })?,
        _ => {
            let plain = [("", Match::Prefix), ("=", Match::Exact), ("^~", Match::NoRegex)].into_iter().find(|k| k.0 == modifier);
            plain.ok_or_else(|| format!("invalid location modifier \"{modifier}\""))?.1
        }
    };
    Ok((kind, path.clone()))
}

/// server address [weight=n] [max_fails=n] [fail_timeout=time] [backup] in an upstream block.
fn peer(args: &[String]) -> Result<Peer, String> {
    let addr = listen(&args[0]).map_err(|_| format!("host not found in upstream \"{}\"", args[0]))?;
    let (mut values, mut backup) = ([("weight", 1u64), ("max_fails", 1), ("fail_timeout", 10)], false);
    for a in &args[1..] {
        if a == "backup" { backup = true; continue; }
        let invalid = || format!("invalid parameter \"{a}\"");
        let (name, value) = a.split_once('=').ok_or_else(invalid)?;
        let slot = values.iter_mut().find(|v| v.0 == name).ok_or_else(invalid)?;
        slot.1 = value.trim_end_matches('s').parse().map_err(|_| invalid())?;
    }
    let [weight, max_fails, fail_timeout] = values.map(|v| v.1);
    Ok(Peer { addr, weight: weight as i64, max_fails, fail_timeout, backup })
}

/// expires [modified] time | epoch | max | off; a value without variables must be valid.
fn expires(args: &[String]) -> Result<Template, String> {
    let (value, t) = (args.join(" "), Template::parse(&args.join(" "))?);
    let literal = t.0.iter().all(|p| matches!(p, crate::vars::Part::Text(_)));
    if literal && crate::expires::parse(&value).is_none() { return Err(format!("invalid value \"{value}\"")); }
    Ok(t)
}

/// A size such as "512", "8k" or "1m".
fn size(s: &str) -> Result<u64, String> {
    let (digits, unit) = s.find(|c: char| !c.is_ascii_digit()).map_or((s, ""), |i| s.split_at(i));
    let scale = [("", 1), ("k", 1 << 10), ("K", 1 << 10), ("m", 1 << 20), ("M", 1 << 20)].into_iter().find(|u| u.0 == unit);
    digits.parse::<u64>().ok().zip(scale).map(|(n, (_, scale))| n * scale).ok_or_else(|| format!("\"{s}\" is invalid"))
}

fn add_header(args: &[String]) -> Result<(String, Template, bool), String> {
    let always = args.get(2).map(|a| a == "always").unwrap_or(false);
    Ok((args[0].clone(), Template::parse(&args[1])?, always))
}

/// error_page code ... [=[response]] url. twinx sends redirects only, so the
/// target must be a URL; nginx's internal redirects to a local URI are not done yet.
fn error_page(args: &[String]) -> Result<ErrorPage, String> {
    let (url, rest) = args.split_last().unwrap();
    let (status, codes) = match rest.split_last() {
        Some((last, codes)) if last.starts_with('=') => (Some(last[1..].parse::<u16>().unwrap_or(302)), codes),
        _ => (None, rest),
    };
    let codes = codes.iter().map(|c| c.parse::<u16>().ok().filter(|c| (300..=599).contains(c)).ok_or_else(|| format!("value \"{c}\" must be between 300 and 599")));
    let codes = codes.collect::<Result<Vec<u16>, String>>()?;
    if url.starts_with('/') || url.starts_with('@') { return Err(format!("twinx does not support redirecting errors to \"{url}\" yet")); }
    Ok(ErrorPage { codes, status, url: Template::parse(url)? })
}

fn ret(args: &[String]) -> Result<(u16, Template), String> {
    let code = args[0].parse::<u16>().ok().filter(|c| *c <= 999);
    let code = code.ok_or_else(|| format!("invalid return code \"{}\"", args[0]))?;
    Ok((code, Template::parse(args.get(1).map_or("", |t| t.as_str()))?))
}

/// "addr:port", "addr" (port 80) or "port" (all addresses).
fn listen(arg: &str) -> Result<SocketAddr, String> {
    let with_port = if arg.contains(':') { arg.to_string() } else if arg.parse::<u16>().is_ok() { format!("0.0.0.0:{arg}") } else { format!("{arg}:80") };
    let addr = with_port.to_socket_addrs().ok().and_then(|mut a| a.next());
    addr.ok_or_else(|| format!("host not found in \"{arg}\" of the \"listen\" directive"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn build_text(text: &str) -> Result<Config, String> {
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        build(&parse(text, Path::new("t.conf")).unwrap(), &dir)
    }

    #[test]
    fn inherits_and_overrides_access_log() {
        let c = build_text(
            "http { log_format f '$uri' ' $status'; access_log a.log; server { listen 127.0.0.1:8080; \
             location /x { access_log b.log f; return 200 'ok $uri'; } location /y { } } }",
        )
        .unwrap();
        let s = &c.servers[0];
        assert_eq!(s.listen, vec!["127.0.0.1:8080".parse().unwrap()]);
        assert_eq!(s.locations[0].level.access_log[0].format.0.len(), 3);
        assert_eq!(s.locations[0].level.ret.as_ref().unwrap().0, 200);
        assert_eq!(s.locations[1].level.access_log[0].format.0.len(), 16);
    }

    #[test]
    fn proxy_upstream_and_body_settings() {
        let c = build_text(
            "http { upstream u { server 127.0.0.1:8082 backup; server 127.0.0.1:8081 weight=2; } \
             client_max_body_size 1k; server { listen 127.0.0.1:8080; add_header X a; \
             location /a { proxy_pass http://u/x; client_body_buffer_size 2k; client_body_in_file_only on; } \
             location /b { proxy_pass http://127.0.0.1:8083; error_page 404 =301 http://e/; } } }",
        )
        .unwrap();
        let (a, b) = (&c.servers[0].locations[0].level, &c.servers[0].locations[1].level);
        let p = a.proxy.as_ref().unwrap();
        assert_eq!((p.host.as_str(), p.uri.as_deref()), ("u", Some("/x")));
        let addrs: Vec<String> = p.upstream.peers.iter().map(|p| format!("{} {} {}", p.addr, p.weight, p.backup)).collect();
        assert_eq!(addrs, vec!["127.0.0.1:8082 1 true", "127.0.0.1:8081 2 false"]);
        assert_eq!((a.max_body, a.body_buffer, a.body_in_file_only), (1024, 2048, true));
        assert_eq!(a.add_header[0].0, "X");
        assert_eq!(b.proxy.as_ref().unwrap().host, "127.0.0.1:8083");
        assert_eq!((b.error_page[0].codes.clone(), b.error_page[0].status), (vec![404], Some(301)));
        assert_eq!(b.body_buffer, 16384);
        let e = build_text("http { server { expires modified 1h; location / { expires $arg_e; } } }").unwrap();
        assert!(e.servers[0].level.expires.is_some() && e.servers[0].locations[0].level.expires.is_some());
        let e = build_text("http { expires bad; }").unwrap_err();
        assert_eq!(e, "invalid value \"bad\" in t.conf:1");
    }

    #[test]
    fn locations_and_peers() {
        assert!(matches!(location(&["=".into(), "/".into()]).unwrap().0, Match::Exact));
        assert!(matches!(location(&["^~".into(), "/i/".into()]).unwrap().0, Match::NoRegex));
        assert!(matches!(location(&["/".into()]).unwrap().0, Match::Prefix));
        let Match::Regex(re) = location(&["~*".into(), "\\.GIF$".into()]).unwrap().0 else { panic!() };
        assert!(re.is_match("/a.gif"));
        assert_eq!(location(&["!".into(), "/".into()]).unwrap_err(), "invalid location modifier \"!\"");
        assert!(location(&["~".into(), "(".into()]).is_err());
        let p = peer(&["127.0.0.1:1".into(), "max_fails=3".into(), "fail_timeout=5s".into()]).unwrap();
        assert_eq!((p.max_fails, p.fail_timeout, p.weight, p.backup), (3, 5, 1, false));
        assert_eq!(peer(&["127.0.0.1:1".into(), "down".into()]).unwrap_err(), "invalid parameter \"down\"");
    }

    #[test]
    fn sizes_and_error_pages() {
        assert_eq!(size("8k"), Ok(8192));
        assert_eq!(size("1M"), Ok(1 << 20));
        assert_eq!(size("10"), Ok(10));
        assert_eq!(size("1x"), Err("\"1x\" is invalid".into()));
        assert_eq!(error_page(&["200".into(), "http://e/".into()]).unwrap_err(), "value \"200\" must be between 300 and 599");
        assert!(error_page(&["404".into(), "/local".into()]).is_err());
        assert_eq!(error_page(&["404".into(), "500".into(), "http://e/".into()]).unwrap().codes, vec![404, 500]);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(listen("8080").unwrap(), "0.0.0.0:8080".parse().unwrap());
        assert_eq!(listen("127.0.0.1").unwrap(), "127.0.0.1:80".parse().unwrap());
    }

    #[test]
    fn errors() {
        assert_eq!(build_text("nope;").unwrap_err(), "unknown directive \"nope\" in t.conf:1");
        assert_eq!(build_text("listen 80;").unwrap_err(), "\"listen\" directive is not allowed here in t.conf:1");
        assert_eq!(build_text("http;").unwrap_err(), "directive \"http\" has no opening \"{\" in t.conf:1");
        assert_eq!(build_text("pid;").unwrap_err(), "invalid number of arguments in \"pid\" directive in t.conf:1");
        let e = build_text("http { server { return x; } }").unwrap_err();
        assert_eq!(e, "invalid return code \"x\" in t.conf:1");
        let e = build_text("http { server { location / { proxy_pass ftp://x; } } }").unwrap_err();
        assert_eq!(e, "invalid URL prefix in \"ftp://x\" in t.conf:1");
        let e = build_text("http { server { listen 80; } upstream u { listen 80; } }").unwrap_err();
        assert_eq!(e, "\"listen\" directive is not allowed here in t.conf:1");
        let e = build_text("http { access_log a.log nope; }").unwrap_err();
        assert_eq!(e, "unknown log format \"nope\" in t.conf:1");
    }
}
