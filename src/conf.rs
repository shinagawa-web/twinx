//! What the directives mean: checks each one as nginx does (known, allowed in
//! its block, right number of arguments) and builds the configuration twinx runs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Directive;
use crate::vars::Template;

const MAIN: u8 = 1;
const EVENTS: u8 = 2;
const HTTP: u8 = 4;
const SRV: u8 = 8;
const LOC: u8 = 16;

/// Every directive twinx knows: where it may appear, its argument counts, and
/// whether it takes a block.
const DIRECTIVES: &[(&str, u8, usize, usize, bool)] = &[
    ("daemon", MAIN, 1, 1, false),
    ("pid", MAIN, 1, 1, false),
    ("error_log", MAIN, 1, usize::MAX, false),
    ("events", MAIN, 0, 0, true),
    ("http", MAIN, 0, 0, true),
    ("server", HTTP, 0, 0, true),
    ("listen", SRV, 1, usize::MAX, false),
    ("server_name", SRV, 1, usize::MAX, false),
    ("location", SRV | LOC, 1, 2, true),
    ("return", SRV | LOC, 1, 2, false),
    ("root", HTTP | SRV | LOC, 1, 1, false),
    ("log_format", HTTP, 2, usize::MAX, false),
    ("access_log", HTTP | SRV | LOC, 1, usize::MAX, false),
    ("client_body_temp_path", HTTP | SRV | LOC, 1, 4, false),
    ("proxy_temp_path", HTTP | SRV | LOC, 1, 4, false),
];

const COMBINED: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

#[derive(Debug)]
pub struct AccessLog {
    pub file: Arc<File>,
    pub format: Arc<Template>,
}

/// The settings of one level (http, server or location) after inheriting from the one above.
#[derive(Debug, Clone, Default)]
pub struct Level {
    pub ret: Option<(u16, Template)>,
    pub access_log: Vec<Arc<AccessLog>>,
    pub root: PathBuf,
}

#[derive(Debug)]
pub struct Server {
    pub listen: Vec<SocketAddr>,
    pub names: Vec<String>,
    pub level: Level,
    pub locations: Vec<(String, Level)>,
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
}

/// Interprets the main block. Errors are nginx's messages, with the place.
pub fn build(main: &[Directive], prefix: &Path) -> Result<Config, String> {
    let combined = Arc::new(Template::parse(COMBINED)?);
    let formats = HashMap::from([("combined".to_string(), combined)]);
    let mut b = Builder { prefix, formats, logs: HashMap::new() };
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
        let spec = DIRECTIVES.iter().find(|s| s.0 == d.name);
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
        let mut level = Level::default();
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

    fn locations(&mut self, block: &[Directive], parent: &Level, out: &mut Vec<(String, Level)>) -> Result<(), String> {
        for d in block.iter().filter(|d| d.name == "location") {
            let mut level = parent.clone();
            let inner = d.block.as_deref().unwrap_or_default();
            self.level(inner, LOC, &mut level)?;
            out.push((d.args[0].clone(), level.clone()));
            self.locations(inner, &level, out)?;
        }
        Ok(())
    }

    /// Applies the directives of one level that are not blocks of their own;
    /// access_log replaces what the level above set as a whole.
    fn level(&mut self, block: &[Directive], ctx: u8, level: &mut Level) -> Result<(), String> {
        let mut logs: Option<Vec<Arc<AccessLog>>> = None;
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
                _ => {}
            }
        }
        if let Some(logs) = logs { level.access_log = logs; }
        Ok(())
    }

    fn access_log(&mut self, args: &[String]) -> Result<Option<Arc<AccessLog>>, String> {
        if args[0] == "off" { return Ok(None); }
        let name = args.get(1).map_or("combined", |n| n.as_str());
        let format = self.formats.get(name).cloned().ok_or_else(|| format!("unknown log format \"{name}\""))?;
        let file = self.open(&args[0])?;
        Ok(Some(Arc::new(AccessLog { file, format })))
    }
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
        assert_eq!(s.locations[0].1.access_log[0].format.0.len(), 3);
        assert_eq!(s.locations[0].1.ret.as_ref().unwrap().0, 200);
        assert_eq!(s.locations[1].1.access_log[0].format.0.len(), 16);
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
        let e = build_text("http { access_log a.log nope; }").unwrap_err();
        assert_eq!(e, "unknown log format \"nope\" in t.conf:1");
    }
}
