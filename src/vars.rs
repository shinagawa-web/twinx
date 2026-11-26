use std::borrow::Cow;
use std::cell::{OnceCell, RefCell};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Instant;

use chrono::{DateTime, Local};

#[derive(Debug, Default)]
pub struct Shared {
    pub number: u64,
    pub unread: std::sync::Mutex<Option<crate::http::Unread>>,
    pub limit_rate: Rate,
    pub vars: std::sync::Mutex<Vec<(String, String)>>,
    pub unparsed: std::sync::OnceLock<String>,
    pub trailers: std::sync::Mutex<Vec<(String, String)>>,
    pub cache_status: std::sync::Mutex<Option<&'static str>>,
    pub updater: bool,
    pub background: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub err_status: std::sync::atomic::AtomicU16,
    pub files: std::sync::Mutex<Option<Files>>,
    pub id: std::sync::OnceLock<String>,
    pub fd: Option<i32>,
    pub completion: std::sync::OnceLock<bool>,
    pub gzip: std::sync::Mutex<Option<(u64, u64)>>,
    pub nodelay: std::sync::atomic::AtomicBool,
    pub rewritten: std::sync::atomic::AtomicBool,
}

#[derive(Debug, Clone, Default)]
pub struct Files {
    pub root: PathBuf,
    pub root_vars: Option<Template>,
    pub alias: Option<PathBuf>,
    pub alias_vars: Option<Template>,
    pub alias_len: Option<usize>,
    pub prefix: String,
}

impl Files {
    fn root(&self, r: &Request, s: &Sent) -> String {
        match &self.alias {
            Some(alias) => self.alias_vars.as_ref().map_or_else(|| alias.display().to_string(), |t| t.render(r, s)),
            None => self.root_vars.as_ref().map_or_else(|| self.root.display().to_string(), |t| t.render(r, s)),
        }
    }

    fn filename(&self, r: &Request, s: &Sent) -> Option<String> {
        if self.alias.is_some() && r.rewritten() { return None }
        let whole = self.alias_vars.is_some() && self.alias_len.is_none();
        let rest = if self.alias.is_none() { &r.uri[..] } else if whole { "" } else { r.uri.get(self.prefix.len()..).unwrap_or_default() };
        Some(format!("{}{rest}", self.root(r, s)))
    }
}

static FILES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn files_used() -> bool {
    FILES.load(std::sync::atomic::Ordering::Relaxed)
}

fn hostname() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let mut buf = [0u8; 256];
        // SAFETY: the buffer is as long as the length given.
        let ok = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0;
        if ok { String::from_utf8_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())]).into_owned() } else { String::new() }
    })
}

fn tcpinfo(fd: i32, which: u8) -> Option<u32> {
    // SAFETY: tcp_info is plain data, and the length given is its size.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let got = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, (&raw mut info).cast(), &mut len) };
    (got == 0).then_some(match which { 0 => info.tcpi_rtt, 1 => info.tcpi_rttvar, 2 => info.tcpi_snd_cwnd, _ => info.tcpi_rcv_space })
}

fn request_id() -> String {
    let mut id = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id).ok();
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub uri: String,
    pub target: String,
    pub line: String,
    pub headers: Vec<(String, String)>,
    pub host: Option<String>,
    pub server_name: std::sync::Arc<str>,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub started: Instant,
    pub pipelined: bool,
    pub connected: Instant,
    pub requests: u64,
    pub length: usize,
    pub body: Vec<u8>,
    pub body_file: Option<PathBuf>,
    pub upstream_addr: Option<String>,
    pub upstream_status: Option<String>,
    pub upstream: Vec<(String, String)>,
    pub captures: Vec<(String, String)>,
    pub shared: std::sync::Arc<Shared>,
    pub ssl: Option<std::sync::Arc<crate::tls::Session>>,
}

impl Request {
    pub fn connection(peer: SocketAddr, local: SocketAddr, ssl: Option<std::sync::Arc<crate::tls::Session>>) -> Request {
        let now = Instant::now();
        Request {
            method: String::new(), uri: String::new(), target: String::new(), line: String::new(), headers: Vec::new(), host: None,
            server_name: "".into(), peer, local, started: now, pipelined: false, connected: now, requests: 0, length: 0,
            body: Vec::new(), body_file: None, upstream_addr: None, upstream_status: None, upstream: Vec::new(), captures: Vec::new(),
            shared: Default::default(), ssl,
        }
    }

    pub fn rewritten(&self) -> bool { self.shared.rewritten.load(std::sync::atomic::Ordering::Relaxed) }

    pub fn request_uri(&self) -> &str { self.shared.unparsed.get().unwrap_or(&self.target) }

    pub fn args_at(&self) -> Option<usize> {
        let after = self.shared.unparsed.get().and(self.target.strip_prefix(self.uri.as_str()));
        match after { Some(a) if a.is_empty() || a.starts_with('?') => (!a.is_empty()).then_some(self.uri.len()), _ => self.target.find('?') }
    }

    pub fn redirect(&mut self, uri: String, target: String) {
        let old = std::mem::replace(&mut self.target, target);
        self.shared.unparsed.get_or_init(|| old);
        self.uri = uri;
    }

    pub fn set_var(&self, name: &str, value: String) {
        let mut vars = self.shared.vars.lock().unwrap();
        vars.retain(|v| v.0 != name);
        vars.push((name.to_string(), value));
    }

    pub fn set_captures(&self, re: &regex::Regex, caps: &regex::Captures) {
        self.clear_captures();
        let value = |i: usize| caps.get(i).map_or("", |m| m.as_str()).to_string();
        (0..caps.len()).for_each(|i| self.set_var(&i.to_string(), value(i)));
        re.capture_names().enumerate().for_each(|(i, name)| if let Some(name) = name { self.set_var(name, value(i)) });
    }

    pub fn clear_captures(&self) {
        self.shared.vars.lock().unwrap().retain(|v| !v.0.bytes().all(|c| c.is_ascii_digit()));
    }

    pub fn set_byte_captures(&self, re: &regex::bytes::Regex, caps: &regex::bytes::Captures) {
        self.shared.vars.lock().unwrap().retain(|v| !v.0.bytes().all(|c| c.is_ascii_digit()));
        let value = |i: usize| text(caps.get(i).map_or(&b""[..], |m| m.as_bytes()));
        (0..caps.len()).for_each(|i| self.set_var(&i.to_string(), value(i)));
        re.capture_names().enumerate().for_each(|(i, name)| if let Some(name) = name { self.set_var(name, value(i)) });
    }
}

#[derive(Debug)]
pub struct Rate(std::sync::atomic::AtomicU64);

impl Default for Rate {
    fn default() -> Rate { Rate(std::sync::atomic::AtomicU64::new(u64::MAX)) }
}

impl Rate {
    pub fn set(&self, rate: u64) { self.0.store(rate, std::sync::atomic::Ordering::Relaxed) }
    pub fn get(&self) -> Option<u64> { Some(self.0.load(std::sync::atomic::Ordering::Relaxed)).filter(|r| *r != u64::MAX) }
}

static CAPTURES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn add_captures<'a>(names: impl Iterator<Item = &'a str>) {
    CAPTURES.lock().unwrap().extend(names.map(String::from));
}

static USER: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub fn add_user(name: &str) {
    USER.lock().unwrap().push(name.to_string());
}

pub fn builtin(name: &str) -> bool {
    !matches!(Var::named(name), None | Some(Var::User(_)))
}

#[derive(Debug, Clone, Default)]
pub struct Sent {
    pub status: u16,
    pub bytes: usize,
    pub body: usize,
    pub headers: Vec<(String, String)>,
    pub upstream: Vec<(String, String)>,
    pub trailers: Vec<(String, String)>,
    pub upstream_addr: Option<String>,
    pub upstream_status: Option<String>,
    pub upstream_time: Option<Vec<[Option<u128>; 3]>>,
    pub upstream_bytes: Option<Vec<[u64; 3]>>,
    pub proxy_host: Option<String>,
    pub complete: bool,
}

#[derive(Debug, Default)]
pub struct Now(OnceCell<DateTime<Local>>);

impl Now {
    fn get(&self) -> &DateTime<Local> { self.0.get_or_init(Local::now) }

    fn text(&self, iso: bool) -> Vec<u8> {
        thread_local! { static TEXT: RefCell<[(i64, String); 2]> = const { RefCell::new([(i64::MIN, String::new()), (i64::MIN, String::new())]) } }
        let now = self.get();
        TEXT.with_borrow_mut(|texts| {
            let (at, text) = &mut texts[iso as usize];
            if *at != now.timestamp() {
                (*at, *text) = (now.timestamp(), now.format(if iso { "%Y-%m-%dT%H:%M:%S%:z" } else { "%d/%b/%Y:%H:%M:%S %z" }).to_string());
            }
            text.as_bytes().to_vec()
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Var {
    Uri,
    RequestMethod,
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
    Connection,
    ConnectionRequests,
    ConnectionTime,
    RequestPort,
    IsRequestPort,
    UpstreamAddr,
    UpstreamStatus,
    UpstreamCacheStatus,
    UpstreamTime(usize),
    UpstreamBytes(usize),
    ProxyHost,
    ProxyPort,
    ProxyAddXForwardedFor,
    Pid,
    ServerName,
    Scheme,
    Https,
    Http2,
    ServerProtocol,
    SslProtocol,
    SslServerName,
    SslSessionReused,
    SslClientVerify,
    SslClientSDn,
    SslSessionId,
    SslCipher,
    SslCiphers,
    SslCurve,
    SslSigalg,
    SslClientSigalg,
    SslCurves,
    SslAlpnProtocol,
    DocumentRoot,
    RealpathRoot,
    RequestFilename,
    RequestId,
    IsArgs,
    NginxVersion,
    Hostname,
    TcpInfo(u8),
    RequestCompletion,
    NotFound,
    SslNone,
    SslClient(&'static str),
    LimitRate,
    Capture(String),
    User(String),
    Arg(String),
    Http(String),
    Cookie(String),
    SentHttp(String),
    SentTrailer(String),
    UpstreamHttp(String),
    UpstreamCookie(String),
    UpstreamTrailer(String),
    GzipRatio,
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
            ("connection", Var::Connection), ("connection_requests", Var::ConnectionRequests), ("connection_time", Var::ConnectionTime),
            ("request_port", Var::RequestPort), ("is_request_port", Var::IsRequestPort), ("upstream_addr", Var::UpstreamAddr), ("upstream_status", Var::UpstreamStatus), ("upstream_cache_status", Var::UpstreamCacheStatus), ("pid", Var::Pid),
            ("upstream_connect_time", Var::UpstreamTime(0)), ("upstream_header_time", Var::UpstreamTime(1)), ("upstream_response_time", Var::UpstreamTime(2)),
            ("upstream_response_length", Var::UpstreamBytes(0)), ("upstream_bytes_received", Var::UpstreamBytes(1)), ("upstream_bytes_sent", Var::UpstreamBytes(2)),
            ("proxy_host", Var::ProxyHost), ("proxy_port", Var::ProxyPort), ("proxy_add_x_forwarded_for", Var::ProxyAddXForwardedFor),
            ("server_name", Var::ServerName), ("scheme", Var::Scheme), ("https", Var::Https), ("http2", Var::Http2), ("server_protocol", Var::ServerProtocol), ("request_method", Var::RequestMethod), ("limit_rate", Var::LimitRate),
            ("ssl_protocol", Var::SslProtocol), ("ssl_server_name", Var::SslServerName), ("ssl_session_reused", Var::SslSessionReused),
            ("ssl_client_verify", Var::SslClientVerify), ("ssl_client_s_dn", Var::SslClientSDn),
            ("ssl_session_id", Var::SslSessionId), ("ssl_cipher", Var::SslCipher), ("ssl_ciphers", Var::SslCiphers),
            ("ssl_curve", Var::SslCurve), ("ssl_curves", Var::SslCurves), ("ssl_sigalg", Var::SslSigalg), ("ssl_client_sigalg", Var::SslClientSigalg),
            ("ssl_alpn_protocol", Var::SslAlpnProtocol), ("ssl_early_data", Var::SslNone), ("ssl_ech_status", Var::SslNone), ("ssl_ech_outer_server_name", Var::SslNone),
            ("ssl_client_serial", Var::SslClient("serial")), ("ssl_client_fingerprint", Var::SslClient("fingerprint")),
            ("ssl_client_i_dn", Var::SslClient("i_dn")), ("ssl_client_s_dn_legacy", Var::SslClient("s_dn_legacy")), ("ssl_client_i_dn_legacy", Var::SslClient("i_dn_legacy")),
            ("ssl_client_v_start", Var::SslClient("v_start")), ("ssl_client_v_end", Var::SslClient("v_end")), ("ssl_client_v_remain", Var::SslClient("v_remain")),
            ("ssl_client_raw_cert", Var::SslClient("raw_cert")), ("ssl_client_cert", Var::SslClient("cert")), ("ssl_client_escaped_cert", Var::SslClient("escaped_cert")),
            ("document_uri", Var::Uri), ("query_string", Var::Args), ("is_args", Var::IsArgs),
            ("document_root", Var::DocumentRoot), ("realpath_root", Var::RealpathRoot), ("request_filename", Var::RequestFilename),
            ("request_id", Var::RequestId), ("nginx_version", Var::NginxVersion), ("hostname", Var::Hostname), ("request_completion", Var::RequestCompletion), ("gzip_ratio", Var::GzipRatio),
            ("tcpinfo_rtt", Var::TcpInfo(0)), ("tcpinfo_rttvar", Var::TcpInfo(1)), ("tcpinfo_snd_cwnd", Var::TcpInfo(2)), ("tcpinfo_rcv_space", Var::TcpInfo(3)),
            ("proxy_protocol_addr", Var::NotFound), ("proxy_protocol_port", Var::NotFound), ("proxy_protocol_server_addr", Var::NotFound),
            ("proxy_protocol_server_port", Var::NotFound), ("proxy_protocol_tlv_alpn", Var::NotFound),
            ("content_length", Var::Http("content-length".into())), ("content_type", Var::Http("content-type".into())),
        ];
        let prefixed: [(&str, fn(String) -> Var, bool); 8] = [
            ("http_", Var::Http, true), ("sent_http_", Var::SentHttp, true), ("sent_trailer_", Var::SentTrailer, true),
            ("upstream_http_", Var::UpstreamHttp, true), ("arg_", Var::Arg, false), ("cookie_", Var::Cookie, false),
            ("upstream_cookie_", Var::UpstreamCookie, false), ("upstream_trailer_", Var::UpstreamTrailer, true),
        ];
        let found = prefixed.into_iter().find_map(|(p, var, dashes)| name.strip_prefix(p).map(|n| var(if dashes { n.replace('_', "-") } else { n.to_string() })));
        let capture = || CAPTURES.lock().unwrap().iter().any(|c| c == name).then(|| Var::Capture(name.to_string()));
        let user = || (name.bytes().all(|c| c.is_ascii_digit()) || USER.lock().unwrap().iter().any(|u| u == name)).then(|| Var::User(name.to_string()));
        let var = found.or_else(|| known.into_iter().find(|(n, _)| *n == name).map(|(_, v)| v)).or_else(capture).or_else(user);
        if matches!(var, Some(Var::DocumentRoot | Var::RealpathRoot | Var::RequestFilename)) { FILES.store(true, std::sync::atomic::Ordering::Relaxed); }
        var
    }

    pub fn value(&self, r: &Request, s: &Sent, now: &Now) -> Option<Vec<u8>> {
        Some(bytes(match self {
            Var::Uri | Var::RequestMethod if r.method.is_empty() => return None,
            Var::Uri => r.uri.clone(),
            Var::RequestMethod => r.method.clone(),
            Var::Status => format!("{:03}", if s.status == 0 { r.shared.err_status.load(std::sync::atomic::Ordering::Relaxed) } else { s.status }),
            Var::RequestLength => r.length.to_string(),
            Var::RequestTime => format!("{:.3}", r.started.elapsed().as_secs_f64()),
            Var::BytesSent => s.bytes.to_string(),
            Var::BodyBytesSent => s.body.to_string(),
            Var::Pipe => (if r.pipelined { "p" } else { "." }).to_string(),
            Var::Msec => { let now = now.get(); format!("{}.{:03}", now.timestamp(), now.timestamp_subsec_millis()) }
            Var::TimeIso8601 => return Some(now.text(true)),
            Var::TimeLocal => return Some(now.text(false)),
            Var::RemoteAddr => r.peer.ip().to_string(),
            Var::RemotePort => r.peer.port().to_string(),
            Var::BinaryRemoteAddr => return Some(match r.peer.ip() { IpAddr::V4(a) => a.octets().to_vec(), IpAddr::V6(a) => a.octets().to_vec() }),
            Var::ServerAddr => r.local.ip().to_string(),
            Var::ServerPort => r.local.port().to_string(),
            Var::RemoteUser => basic_user(r)?,
            Var::Request => r.line.clone(),
            Var::Connection => r.shared.number.to_string(),
            Var::ConnectionRequests => r.requests.to_string(),
            Var::ConnectionTime => { let ms = r.connected.elapsed().as_millis(); format!("{}.{:03}", ms / 1000, ms % 1000) }
            Var::Host => r.host.clone().unwrap_or_else(|| r.server_name.to_string()),
            Var::RequestUri => Some(r.request_uri()).filter(|u| !u.is_empty())?.to_string(),
            Var::RequestPort => request_port(r).to_string(),
            Var::IsRequestPort => (if request_port(r).is_empty() { "" } else { ":" }).to_string(),
            Var::Pid => std::process::id().to_string(),
            Var::ServerName => r.server_name.to_string(),
            Var::Scheme => (if r.ssl.is_some() { "https" } else { "http" }).to_string(),
            Var::Https => (if r.ssl.is_some() { "on" } else { "" }).to_string(),
            Var::Http2 => (if !r.line.ends_with(" HTTP/2.0") { "" } else if r.ssl.is_some() { "h2" } else { "h2c" }).to_string(),
            Var::ServerProtocol => r.line.split(' ').filter(|w| !w.is_empty()).nth(2).unwrap_or_default().to_string(),
            Var::SslProtocol => r.ssl.as_ref()?.protocol.clone(),
            Var::SslServerName => r.ssl.as_ref()?.server_name.clone(),
            Var::SslSessionReused => (if r.ssl.as_ref()?.reused { "r" } else { "." }).to_string(),
            Var::SslClientVerify => r.ssl.as_ref()?.verify.clone(),
            Var::SslClientSDn => r.ssl.as_ref()?.subject.clone()?,
            Var::SslSessionId => r.ssl.as_ref()?.id.clone(),
            Var::SslCipher => r.ssl.as_ref()?.cipher.clone(),
            Var::SslCiphers => r.ssl.as_ref()?.ciphers.clone(),
            Var::SslCurve => r.ssl.as_ref()?.curve.clone(),
            Var::SslSigalg => r.ssl.as_ref()?.sigalg.clone(),
            Var::SslClientSigalg => r.ssl.as_ref()?.client_sigalg.clone(),
            Var::SslCurves => r.ssl.as_ref()?.curves.clone(),
            Var::SslAlpnProtocol => r.ssl.as_ref()?.alpn.clone(),
            Var::SslNone => { r.ssl.as_ref()?; String::new() }
            Var::DocumentRoot => r.shared.files.lock().unwrap().clone()?.root(r, s),
            Var::RealpathRoot => std::fs::canonicalize(r.shared.files.lock().unwrap().clone()?.root(r, s)).ok()?.display().to_string(),
            Var::RequestFilename => r.shared.files.lock().unwrap().clone()?.filename(r, s)?,
            Var::RequestId => r.shared.id.get_or_init(request_id).clone(),
            Var::IsArgs => (if Var::Args.value(r, s, now).is_some_and(|a| !a.is_empty()) { "?" } else { "" }).to_string(),
            Var::NginxVersion => env!("CARGO_PKG_VERSION").to_string(),
            Var::Hostname => hostname().to_string(),
            Var::TcpInfo(which) => tcpinfo(r.shared.fd?, *which)?.to_string(),
            Var::RequestCompletion => (if *r.shared.completion.get_or_init(|| s.complete) { "OK" } else { "" }).to_string(),
            Var::GzipRatio => ratio((*r.shared.gzip.lock().unwrap())?)?,
            Var::NotFound => return None,
            Var::SslClient(var) => r.ssl.as_ref()?.client_var(var),
            Var::LimitRate => r.shared.limit_rate.get().unwrap_or(0).to_string(),
            Var::Capture(name) => r.captures.iter().find(|c| c.0 == *name)?.1.clone(),
            Var::User(name) => r.shared.vars.lock().unwrap().iter().find(|v| v.0 == *name)?.1.clone(),
            Var::UpstreamAddr => s.upstream_addr.clone().or_else(|| r.upstream_addr.clone())?,
            Var::UpstreamStatus => s.upstream_status.clone().or_else(|| r.upstream_status.clone())?,
            Var::UpstreamCacheStatus => r.shared.cache_status.lock().unwrap().map(str::to_string)?,
            Var::UpstreamBytes(i) => s.upstream_bytes.as_ref()?.iter().map(|b| b[*i].to_string()).collect::<Vec<_>>().join(", "),
            Var::UpstreamTime(i) => {
                let time = |t: &[Option<u128>; 3]| t[*i].map_or("-".to_string(), |ms| format!("{}.{:03}", ms / 1000, ms % 1000));
                s.upstream_time.as_ref()?.iter().map(time).collect::<Vec<_>>().join(", ")
            }
            Var::ProxyHost => s.proxy_host.clone()?,
            Var::ProxyPort => s.proxy_host.as_ref()?.rsplit_once(':').map_or("80", |(_, p)| p).to_string(),
            Var::ProxyAddXForwardedFor => joined(&r.headers, "x-forwarded-for", ", ").map_or_else(|| r.peer.ip().to_string(), |x| format!("{x}, {}", r.peer.ip())),
            Var::Args => r.target.get(r.args_at()? + 1..).filter(|a| !a.is_empty() || r.shared.unparsed.get().is_some())?.to_string(),
            Var::RequestBody => String::from_utf8_lossy(&r.body).into_owned(),
            Var::RequestBodyFile => r.body_file.as_ref()?.display().to_string(),
            Var::Arg(name) => {
                let args = r.target.get(r.args_at()? + 1..)?.split('&');
                args.filter_map(|a| a.split_once('=')).find(|(n, _)| n.eq_ignore_ascii_case(name))?.1.to_string()
            }
            Var::Http(name) => joined(&r.headers, name, if name.eq_ignore_ascii_case("cookie") { "; " } else { ", " })?,
            Var::Cookie(name) => cookie(&r.headers, name)?,
            Var::SentHttp(name) => joined(&s.headers, name, ", ")?,
            Var::SentTrailer(name) => joined(&s.trailers, name, ", ")?,
            Var::UpstreamHttp(name) => joined(if s.upstream.is_empty() { &r.upstream } else { &s.upstream }, name, ", ")?,
            Var::UpstreamCookie(name) => set_cookie(if s.upstream.is_empty() { &r.upstream } else { &s.upstream }, name)?,
            Var::UpstreamTrailer(name) => joined(&r.shared.trailers.lock().unwrap(), name, ", ")?,
        }.as_str()))
    }
}

fn ratio((taken, made): (u64, u64)) -> Option<String> {
    let hundredths = taken.checked_mul(100)?.checked_div(made)? + u64::from(taken * 1000 / made % 10 > 4);
    Some(format!("{}.{:02}", hundredths / 100, hundredths % 100))
}

pub fn text(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) { return s.to_string() }
    let mut out = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(chunk.invalid().iter().filter_map(|&c| char::from_u32(0x10FF00 + c as u32)));
    }
    out
}

pub fn bytes(s: &str) -> Vec<u8> {
    if plain(s.as_bytes()) { return s.as_bytes().to_vec() }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match c as u32 { n @ 0x10FF00.. => out.push(n as u8), _ => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()) }
    }
    out
}

/// The characters that stand for a byte all begin with the byte 0xf4 in UTF-8.
pub fn plain(utf8: &[u8]) -> bool {
    !utf8.contains(&0xf4)
}

fn joined(headers: &[(String, String)], name: &str, sep: &str) -> Option<String> {
    let same = |n: &str| n.len() == name.len() && n.bytes().zip(name.bytes()).all(|(a, b)| a.eq_ignore_ascii_case(&b) || a == b'_' && b == b'-');
    let values: Vec<&str> = headers.iter().filter(|(n, _)| same(n)).map(|(_, v)| v.as_str()).collect();
    (!values.is_empty()).then(|| values.join(sep))
}

/// As in nginx, a pair that starts with the name but has no "=" after it hides the pair that follows.
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

fn set_cookie(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("set-cookie")).find_map(|(_, v)| {
        let starts = v.len() > name.len() && v.as_bytes()[..name.len()].eq_ignore_ascii_case(name.as_bytes());
        let value = v.get(name.len()..).filter(|_| starts)?.trim_start_matches(' ').strip_prefix('=')?.trim_start_matches(' ');
        Some(value.split(';').next().unwrap_or_default().to_string())
    })
}

fn request_port(r: &Request) -> &str {
    let target = r.line.split(' ').filter(|w| !w.is_empty()).nth(1).unwrap_or_default();
    let absolute = target.split_once("://").filter(|_| !target.starts_with('/')).map(|(_, rest)| rest.split(['/', '?']).next().unwrap_or_default());
    let host = absolute.or_else(|| r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("host")).map(|h| h.1.as_str())).unwrap_or_default();
    let host = host.rsplit_once(']').map_or(host, |(_, after)| after);
    host.split_once(':').map_or("", |(_, port)| port)
}

fn basic_user(r: &Request) -> Option<String> {
    let auth = r.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("authorization"))?.1.as_str();
    let credentials = auth.get(..6).filter(|s| s.eq_ignore_ascii_case("basic ")).and(auth.get(6..))?.trim_start_matches(' ');
    let decoded = decode_base64(credentials).filter(|_| !credentials.is_empty())?;
    let user = &decoded[..decoded.iter().position(|&c| c == b':')?];
    (!user.is_empty()).then(|| String::from_utf8_lossy(user).into_owned())
}

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

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Template(pub Vec<Part>);

impl Template {
    pub fn parse(s: &str) -> Result<Template, String> {
        let (mut parts, mut text, mut rest) = (Vec::new(), String::new(), s);
        while let Some(i) = rest.find('$') {
            text.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            let braced = after.starts_with('{');
            let body = if braced { &after[1..] } else { after };
            let len = if body.starts_with(|c: char| c.is_ascii_digit()) { 1 } else { body.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(body.len()) };
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

    pub fn fixed(&self) -> Option<&str> {
        match &self.0[..] { [] => Some(""), [Part::Text(t)] => Some(t), _ => None }
    }

    pub fn value(&self, r: &Request, s: &Sent) -> Cow<'_, str> {
        self.fixed().map_or_else(|| Cow::Owned(self.render(r, s)), Cow::Borrowed)
    }

    pub fn render(&self, r: &Request, s: &Sent) -> String {
        let now = Now::default();
        let value = |v: &Var| v.value(r, s, &now).map(|v| text(&v)).unwrap_or_default();
        self.0.iter().map(|p| match p { Part::Text(t) => t.clone(), Part::Var(v) => value(v) }).collect()
    }

    pub fn log_line(&self, r: &Request, s: &Sent, escape: Escape) -> Vec<u8> {
        let (now, mut out) = (Now::default(), Vec::new());
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Escape {
    Default,
    Json,
    None,
}

fn escape_default(b: u8, out: &mut Vec<u8>) {
    let plain = (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\';
    if plain { out.push(b) } else { out.extend(format!("\\x{b:02X}").bytes()) }
}

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
            upstream_status: None,
            upstream: Vec::new(),
            captures: Vec::new(),
            shared: Default::default(),
            ssl: None,
        }
    }

    #[test]
    fn compiles_and_renders() {
        let t = Template::parse("$uri ${status}x $pipe $request_length $http_user_agent").unwrap();
        let s = Sent { status: 200, bytes: 10, body: 2, ..Sent::default() };
        assert_eq!(t.render(&request(), &s), "/a 200x p 39 x\"y");
        assert_eq!((t.fixed(), t.value(&request(), &s).as_ref()), (None, "/a 200x p 39 x\"y"));
        let fixed = Template::parse("ok").unwrap();
        assert_eq!((fixed.fixed(), fixed.value(&request(), &s).as_ref(), Template::default().fixed()), (Some("ok"), "ok", Some("")));
        assert_eq!(t.log_line(&request(), &s, Escape::Default), b"/a 200x p 39 x\\x22y");
    }

    #[test]
    fn variables_of_files_and_the_request() {
        let r = request();
        let t = Template::parse("[$document_root][$request_filename][$realpath_root]").unwrap();
        assert_eq!(t.render(&r, &Sent::default()), "[][][]");
        *r.shared.files.lock().unwrap() = Some(Files { root: "/no/such/root".into(), ..Files::default() });
        assert_eq!(t.render(&r, &Sent::default()), "[/no/such/root][/no/such/root/a][]");
        let alias = |alias_vars: Option<Template>, alias_len| Files { alias: Some("/al/".into()), alias_vars, alias_len, prefix: "/".into(), ..Files::default() };
        *r.shared.files.lock().unwrap() = Some(alias(None, Some(1)));
        assert_eq!(t.render(&r, &Sent::default()), "[/al/][/al/a][]");
        *r.shared.files.lock().unwrap() = Some(alias(Some(Template::parse("/x$uri").unwrap()), None));
        assert_eq!(t.render(&r, &Sent::default()), "[/x/a][/x/a][]");
        r.shared.rewritten.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(t.render(&r, &Sent::default()), "[/x/a][][]");
        r.shared.rewritten.store(false, std::sync::atomic::Ordering::Relaxed);
        *r.shared.files.lock().unwrap() = Some(Files { root: "/".into(), ..Files::default() });
        assert_eq!(Template::parse("$realpath_root").unwrap().render(&r, &Sent::default()), "/");
        let t = Template::parse("$request_id $request_id").unwrap().render(&r, &Sent::default());
        assert!(t.len() == 65 && t[..32] == t[33..] && t[..32] != *request_id(), "{t}");
        let t = Template::parse("$is_args|$document_uri|$query_string|$request_completion|$proxy_protocol_addr|$tcpinfo_rtt").unwrap();
        assert_eq!(t.render(&r, &Sent { complete: true, ..Sent::default() }), "?|/a|b|OK||");
        assert_eq!(tcpinfo(-1, 0), None);
        assert!(!hostname().is_empty() && Template::parse("$nginx_version").unwrap().render(&r, &Sent::default()) == env!("CARGO_PKG_VERSION"));
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
        r.redirect("/a?x=3".into(), "/a?x=3?x=4".into());
        assert_eq!(Template::parse("[$arg_x][$args]").unwrap().render(&r, &Sent::default()), "[4][x=4]");
        r.redirect("/a?x=3".into(), "/a?x=3".into());
        assert_eq!(Template::parse("[$arg_x][$args]").unwrap().render(&r, &Sent::default()), "[][]");
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
    fn bytes_that_are_not_utf8() {
        let raw = b"/\xff\xfe?q=\xc3\xa9\xc3";
        assert_eq!(text(raw), "/\u{10ffff}\u{10fffe}?q=\u{e9}\u{10ffc3}");
        assert_eq!(bytes(&text(raw)), raw);
        assert_eq!((bytes("\u{10fffd}\u{10fe00}"), bytes("\u{e9}a")), ([&b"\xfd"[..], "\u{10fe00}".as_bytes()].concat(), "\u{e9}a".as_bytes().to_vec()));
        let mut r = request();
        r.target = text(raw);
        assert_eq!(Template::parse("$args").unwrap().log_line(&r, &Sent::default(), Escape::Default), b"q=\\xC3\\xA9\\xC3");
        r.target = "/a?".into();
        assert_eq!(Template::parse("[$args]").unwrap().log_line(&r, &Sent::default(), Escape::Default), b"[-]");
        r.redirect("/b".into(), "/b?".into());
        assert_eq!(Template::parse("[$args][$is_args]").unwrap().log_line(&r, &Sent::default(), Escape::Default), b"[][]");
    }

    #[test]
    fn proxy_variables() {
        let t = Template::parse("$proxy_host|$proxy_port|$proxy_add_x_forwarded_for|$upstream_connect_time|$upstream_header_time").unwrap();
        let mut r = request();
        let s = Sent { proxy_host: Some("h:81".into()), upstream_time: Some(vec![[Some(2), None, None], [Some(1001), Some(1002), None]]), ..Sent::default() };
        assert_eq!(t.render(&r, &s), "h:81|81|127.0.0.1|0.002, 1.001|-, 1.002");
        r.headers.push(("X-Forwarded-For".into(), "192.0.2.1".into()));
        let s = Sent { proxy_host: Some("u".into()), ..Sent::default() };
        assert_eq!(t.render(&r, &s), "u|80|192.0.2.1, 127.0.0.1||");
    }

    #[test]
    fn pid_and_upstream_addr() {
        let mut r = request();
        r.upstream_addr = Some("a".into());
        let t = Template::parse("$pid|$upstream_addr").unwrap();
        assert_eq!(t.render(&r, &Sent::default()), format!("{}|a", std::process::id()));
        r.method = "PUT".into();
        assert_eq!(Template::parse("$request_method").unwrap().render(&r, &Sent::default()), "PUT");
        assert_eq!(Template::parse("$scheme://x").unwrap().render(&r, &Sent::default()), "http://x");
        r.line = "GET /a HTTP/2.0".into();
        assert_eq!(Template::parse("[$https][$http2][$server_protocol]").unwrap().render(&r, &Sent::default()), "[][h2c][HTTP/2.0]");
        r.line = "GET /a".into();
        assert_eq!(Template::parse("[$http2][$server_protocol]").unwrap().render(&r, &Sent::default()), "[][]");
        assert_eq!(t.render(&r, &Sent { upstream_addr: Some("b".into()), ..Sent::default() }), format!("{}|b", std::process::id()));
        r.upstream_status = Some("404, 404".into());
        assert_eq!(Template::parse("x${upstream_status}x").unwrap().render(&r, &Sent::default()), "x404, 404x");
        assert_eq!(Template::parse("$upstream_status").unwrap().render(&r, &Sent { upstream_status: Some("200".into()), ..Sent::default() }), "200");
        let t = Template::parse("$upstream_response_time|$limit_rate").unwrap();
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Default), b"-|0");
        r.shared.limit_rate.set(5);
        assert_eq!(t.render(&r, &Sent { upstream_time: Some(vec![[Some(1), None, Some(1)], [None, None, Some(2040)]]), ..Sent::default() }), "0.001, 2.040|5");
        let t = Template::parse("$upstream_response_length:$upstream_bytes_received:$upstream_bytes_sent").unwrap();
        assert_eq!(t.render(&r, &Sent { upstream_bytes: Some(vec![[0, 0, 0], [23, 68, 45]]), ..Sent::default() }), "0, 23:0, 68:0, 45");
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
        let t = Template::parse("$connection:$connection_requests:$connection_time").unwrap();
        let r = Request { shared: std::sync::Arc::new(Shared { number: 7, ..Default::default() }), ..request() };
        assert!(t.render(&r, &Sent::default()).starts_with("7:2:0."));
    }

    #[test]
    fn times() {
        let t = Template::parse("$msec|$time_iso8601|$time_local").unwrap();
        let line = t.render(&request(), &Sent::default());
        let parts: Vec<&str> = line.split('|').collect();
        assert!(parts[0].contains('.') && parts[1].contains('T') && parts[2].contains('/'));
    }

    #[test]
    fn times_of_another_second_are_formatted_again() {
        let at = |t: i64| Now(OnceCell::from(DateTime::from_timestamp(t, 0).unwrap().with_timezone(&Local)));
        for t in [1_700_000_000, 1_700_000_000, 1_700_000_001, 1_700_003_600, 1_700_000_000] {
            let now = at(t);
            assert_eq!(now.text(false), now.get().format("%d/%b/%Y:%H:%M:%S %z").to_string().into_bytes());
            assert_eq!(now.text(true), now.get().format("%Y-%m-%dT%H:%M:%S%:z").to_string().into_bytes());
        }
    }

    #[test]
    fn variables_of_what_ended() {
        let r = request();
        let t = Template::parse("[$request_completion]").unwrap();
        assert_eq!(t.render(&r, &Sent::default()), "[]");
        assert_eq!(t.render(&r, &Sent { complete: true, ..Sent::default() }), "[]");
        let t = Template::parse("[$gzip_ratio][$upstream_trailer_x_a]").unwrap();
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Default), b"[-][-]");
        *r.shared.gzip.lock().unwrap() = Some((800, 44));
        r.shared.trailers.lock().unwrap().push(("X-A".into(), "b".into()));
        assert_eq!(t.render(&r, &Sent::default()), "[18.18][b]");
        assert_eq!([(1000, 3), (2000, 1001), (1999, 1000), (1, 0), (2, 3)].map(ratio), [Some("333.33".into()), Some("2.00".into()), Some("2.00".into()), None, Some("0.67".into())]);
    }

    #[test]
    fn variables_of_a_request_not_read() {
        let r = Request { method: String::new(), target: String::new(), uri: String::new(), ..request() };
        let t = Template::parse("$request_method $request_uri $uri").unwrap();
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Default), b"- - -");
        let r = Request { target: String::new(), uri: String::new(), ..request() };
        assert_eq!(t.log_line(&r, &Sent::default(), Escape::Default), b"GET - ");
    }
}
