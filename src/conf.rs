use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Directive;
use crate::log::{AccessLog, Cache, Format, Target};
use crate::resolver::Resolver;
use crate::upstream::{Addr, Balance, Keepalive, Peer, Upstream};
use crate::vars::{Escape, Part, Template};

const MAIN: u16 = 1;
const EVENTS: u16 = 2;
const HTTP: u16 = 4;
const SRV: u16 = 8;
const LOC: u16 = 16;
const UPS: u16 = 32;
const LIF: u16 = 64;
const SIF: u16 = 128;
const LMT: u16 = 256;
const HSL: u16 = HTTP | SRV | LOC;

pub const LEVELS: &[&str] = &["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"];

const DIRECTIVES: &[(&str, u16, usize, usize, bool)] = &[
    ("daemon", MAIN, 1, 1, false),
    ("pid", MAIN, 1, 1, false),
    ("user", MAIN, 1, 2, false),
    ("ssl_object_cache_inheritable", MAIN, 1, 1, false),
    ("worker_rlimit_nofile", MAIN, 1, 1, false),
    ("worker_processes", MAIN, 1, 1, false),
    ("working_directory", MAIN, 1, 1, false),
    ("worker_shutdown_timeout", MAIN, 1, 1, false),
    ("error_log", MAIN | HSL, 1, usize::MAX, false),
    ("log_not_found", HSL, 1, 1, false),
    ("index", HSL, 1, usize::MAX, false),
    ("events", MAIN, 0, 0, true),
    ("worker_connections", EVENTS, 1, 1, false),
    ("http", MAIN, 0, 0, true),
    ("server", HTTP, 0, 0, true),
    ("upstream", HTTP, 1, 1, true),
    ("server", UPS, 1, usize::MAX, false),
    ("keepalive", UPS, 1, 2, false),
    ("ip_hash", UPS, 0, 0, false),
    ("least_conn", UPS, 0, 0, false),
    ("keepalive_requests", UPS, 1, 1, false),
    ("keepalive_time", UPS, 1, 1, false),
    ("keepalive_timeout", UPS, 1, 1, false),
    ("listen", SRV, 1, usize::MAX, false),
    ("server_name", SRV, 1, usize::MAX, false),
    ("server_names_hash_bucket_size", HTTP, 1, 1, false),
    ("server_names_hash_max_size", HTTP, 1, 1, false),
    ("location", SRV | LOC, 1, 2, true),
    ("try_files", SRV | LOC, 2, usize::MAX, false),
    ("return", SRV | LOC | SIF | LIF, 1, 2, false),
    ("break", SRV | LOC | SIF | LIF, 0, 0, false),
    ("set", SRV | LOC | SIF | LIF, 2, 2, false),
    ("if", SRV | LOC, 1, usize::MAX, true),
    ("root", HSL | LIF, 1, 1, false),
    ("log_format", HTTP, 2, usize::MAX, false),
    ("access_log", HSL | LIF, 1, usize::MAX, false),
    ("open_log_file_cache", HSL, 1, 4, false),
    ("client_body_temp_path", HTTP | SRV | LOC, 1, 4, false),
    ("proxy_temp_path", HTTP | SRV | LOC, 1, 4, false),
    ("client_header_buffer_size", HTTP | SRV, 1, 1, false),
    ("large_client_header_buffers", HTTP | SRV, 2, 2, false),
    ("connection_pool_size", HTTP | SRV, 1, 1, false),
    ("max_headers", HTTP | SRV, 1, 1, false),
    ("ignore_invalid_headers", HTTP | SRV, 1, 1, false),
    ("underscores_in_headers", HTTP | SRV, 1, 1, false),
    ("merge_slashes", HTTP | SRV, 1, 1, false),
    ("client_body_buffer_size", HSL, 1, 1, false),
    ("client_body_in_file_only", HSL, 1, 1, false),
    ("client_body_in_single_buffer", HSL, 1, 1, false),
    ("client_max_body_size", HSL, 1, 1, false),
    ("add_header", HSL | LIF, 2, 3, false),
    ("add_trailer", HSL | LIF, 2, 3, false),
    ("add_header_inherit", HSL | LIF, 1, 1, false),
    ("add_trailer_inherit", HSL | LIF, 1, 1, false),
    ("chunked_transfer_encoding", HSL, 1, 1, false),
    ("keepalive_requests", HSL, 1, 1, false),
    ("keepalive_timeout", HSL, 1, 2, false),
    ("lingering_close", HSL, 1, 1, false),
    ("keepalive_time", HSL, 1, 1, false),
    ("keepalive_disable", HSL, 1, usize::MAX, false),
    ("error_page", HSL | LIF, 2, usize::MAX, false),
    ("proxy_pass", LOC | LIF | LMT, 1, 1, false),
    ("limit_except", LOC, 1, usize::MAX, true),
    ("ssl_certificate", HTTP | SRV, 1, 1, false),
    ("ssl_certificate_key", HTTP | SRV, 1, 1, false),
    ("ssl_certificate_compression", HTTP | SRV, 1, 1, false),
    ("ssl_ciphers", HTTP | SRV, 1, 1, false),
    ("ssl_protocols", HTTP | SRV, 1, usize::MAX, false),
    ("ssl_ecdh_curve", HTTP | SRV, 1, 1, false),
    ("ssl_prefer_server_ciphers", HTTP | SRV, 1, 1, false),
    ("ssl_reject_handshake", HTTP | SRV, 1, 1, false),
    ("http2", HTTP | SRV, 1, 1, false),
    ("ssl_conf_command", HTTP | SRV, 2, 2, false),
    ("ssl_session_cache", HTTP | SRV, 1, 2, false),
    ("ssl_session_tickets", HTTP | SRV, 1, 1, false),
    ("ssl_session_ticket_key", HTTP | SRV, 1, 1, false),
    ("ssl_certificate_cache", HTTP | SRV, 1, 3, false),
    ("ssl_session_timeout", HTTP | SRV, 1, 1, false),
    ("proxy_ssl_session_reuse", HSL, 1, 1, false),
    ("ssl_password_file", HTTP | SRV, 1, 1, false),
    ("ssl_verify_client", HTTP | SRV, 1, 1, false),
    ("ssl_trusted_certificate", HTTP | SRV, 1, 1, false),
    ("ssl_client_certificate", HTTP | SRV, 1, 1, false),
    ("ssl_crl", HTTP | SRV, 1, 1, false),
    ("ssl_ocsp", HTTP | SRV, 1, 1, false),
    ("ssl_stapling", HTTP | SRV, 1, 1, false),
    ("ssl_stapling_file", HTTP | SRV, 1, 1, false),
    ("ssl_stapling_responder", HTTP | SRV, 1, 1, false),
    ("ssl_stapling_verify", HTTP | SRV, 1, 1, false),
    ("ssl_ocsp_responder", HTTP | SRV, 1, 1, false),
    ("ssl_ocsp_cache", HTTP | SRV, 1, 1, false),
    ("ssl_verify_depth", HTTP | SRV, 1, 1, false),
    ("proxy_ssl_certificate", HSL, 1, 1, false),
    ("proxy_ssl_certificate_key", HSL, 1, 1, false),
    ("proxy_ssl_password_file", HSL, 1, 1, false),
    ("proxy_ssl_certificate_cache", HSL, 1, 3, false),
    ("proxy_ssl_verify", HSL, 1, 1, false),
    ("proxy_ssl_trusted_certificate", HSL, 1, 1, false),
    ("proxy_ssl_crl", HSL, 1, 1, false),
    ("proxy_ssl_verify_depth", HSL, 1, 1, false),
    ("proxy_ssl_name", HSL, 1, 1, false),
    ("proxy_ssl_server_name", HSL, 1, 1, false),
    ("proxy_ssl_protocols", HSL, 1, usize::MAX, false),
    ("proxy_pass_trailers", HSL, 1, 1, false),
    ("proxy_method", HSL, 1, 1, false),
    ("early_hints", HSL, 1, usize::MAX, false),
    ("proxy_set_body", HSL, 1, 1, false),
    ("expires", HSL | LIF, 1, 2, false),
    ("post_action", HSL, 1, 1, false),
    ("alias", LOC, 1, 1, false),
    ("absolute_redirect", HSL, 1, 1, false),
    ("server_tokens", HSL, 1, 1, false),
    ("server_name_in_redirect", HSL, 1, 1, false),
    ("port_in_redirect", HSL, 1, 1, false),
    ("rewrite", SRV | LOC | SIF | LIF, 2, 3, false),
    ("default_type", HSL, 1, 1, false),
    ("types", HSL, 0, 0, true),
    ("proxy_set_header", HSL, 2, 2, false),
    ("proxy_hide_header", HSL, 1, 1, false),
    ("proxy_pass_header", HSL, 1, 1, false),
    ("proxy_next_upstream", HSL, 1, usize::MAX, false),
    ("proxy_next_upstream_tries", HSL, 1, 1, false),
    ("proxy_next_upstream_timeout", HSL, 1, 1, false),
    ("proxy_intercept_errors", HSL, 1, 1, false),
    ("proxy_pass_request_headers", HSL, 1, 1, false),
    ("proxy_pass_request_body", HSL, 1, 1, false),
    ("proxy_connect_timeout", HSL, 1, 1, false),
    ("proxy_read_timeout", HSL, 1, 1, false),
    ("proxy_send_timeout", HSL, 1, 1, false),
    ("send_timeout", HSL, 1, 1, false),
    ("proxy_buffer_size", HSL, 1, 1, false),
    ("proxy_buffering", HSL, 1, 1, false),
    ("proxy_ignore_client_abort", HSL, 1, 1, false),
    ("proxy_socket_keepalive", HSL, 1, 1, false),
    ("proxy_cache_path", HTTP, 2, usize::MAX, false),
    ("proxy_cache", HSL, 1, 1, false),
    ("proxy_cache_valid", HSL, 1, usize::MAX, false),
    ("proxy_cache_lock", HSL, 1, 1, false),
    ("proxy_cache_lock_timeout", HSL, 1, 1, false),
    ("proxy_cache_lock_age", HSL, 1, 1, false),
    ("proxy_cache_min_uses", HSL, 1, 1, false),
    ("proxy_cache_max_range_offset", HSL, 1, 1, false),
    ("proxy_cache_use_stale", HSL, 1, usize::MAX, false),
    ("proxy_no_cache", HSL, 1, usize::MAX, false),
    ("proxy_cache_bypass", HSL, 1, usize::MAX, false),
    ("proxy_cache_key", HSL, 1, 1, false),
    ("proxy_cache_background_update", HSL, 1, 1, false),
    ("proxy_cache_convert_head", HSL, 1, 1, false),
    ("proxy_cache_methods", HSL, 1, usize::MAX, false),
    ("proxy_cache_revalidate", HSL, 1, 1, false),
    ("proxy_force_ranges", HSL, 1, 1, false),
    ("max_ranges", HSL, 1, 1, false),
    ("proxy_ignore_headers", HSL, 1, usize::MAX, false),
    ("proxy_request_buffering", HSL, 1, 1, false),
    ("proxy_http_version", HSL, 1, 1, false),
    ("proxy_bind", HSL, 1, 2, false),
    ("proxy_buffers", HSL, 2, 2, false),
    ("proxy_busy_buffers_size", HSL, 1, 1, false),
    ("proxy_max_temp_file_size", HSL, 1, 1, false),
    ("proxy_temp_file_write_size", HSL, 1, 1, false),
    ("proxy_cookie_domain", HSL, 1, 2, false),
    ("proxy_cookie_path", HSL, 1, 2, false),
    ("proxy_redirect", HSL, 1, 2, false),
    ("proxy_cookie_flags", HSL, 1, 4, false),
    ("resolver", HSL, 1, usize::MAX, false),
    ("resolver_timeout", HSL, 1, 1, false),
    ("gzip", HSL | LIF, 1, 1, false),
    ("gzip_static", HSL, 1, 1, false),
    ("gunzip", HSL, 1, 1, false),
    ("gzip_vary", HSL, 1, 1, false),
    ("sendfile", HSL | LIF, 1, 1, false),
    ("sendfile_max_chunk", HSL, 1, 1, false),
    ("tcp_nopush", HSL, 1, 1, false),
    ("postpone_output", HSL, 1, 1, false),
    ("tcp_nodelay", HSL, 1, 1, false),
    ("gzip_http_version", HSL, 1, 1, false),
    ("gzip_types", HSL, 1, usize::MAX, false),
    ("gzip_min_length", HSL, 1, 1, false),
    ("limit_rate", HSL | LIF, 1, 1, false),
    ("proxy_limit_rate", HSL, 1, 1, false),
    ("limit_rate_after", HSL | LIF, 1, 1, false),
    ("if_modified_since", HSL, 1, 1, false),
];

const REPEATED: &[&str] = &[
    "error_log", "index", "server", "upstream", "listen", "server_name", "location", "return", "break", "set", "if", "rewrite", "log_format", "access_log", "add_header", "add_trailer", "keepalive_disable", "error_page", "ip_hash", "least_conn",
    "ssl_certificate", "ssl_certificate_key", "ssl_protocols", "proxy_ssl_protocols", "ssl_conf_command", "ssl_session_cache", "ssl_session_ticket_key", "early_hints", "proxy_set_header", "proxy_hide_header", "proxy_pass_header", "proxy_next_upstream",
    "proxy_cookie_domain", "proxy_cookie_path", "proxy_redirect", "proxy_cookie_flags", "gzip_types", "proxy_cache_path", "proxy_cache_valid",
    "proxy_no_cache", "proxy_cache_bypass", "proxy_ignore_headers",
    "types",
];

const COMBINED: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

#[derive(Debug, Clone)]
pub struct Proxy {
    pub host: String,
    pub ssl: bool,
    pub upstream: Arc<Upstream>,
    pub uri: Option<String>,
    pub url: Option<Template>,
    pub groups: HashMap<String, Arc<Upstream>>,
    pub implicit: Implicit,
}

pub type Implicit = Arc<Mutex<HashMap<String, Arc<Upstream>>>>;

#[derive(Debug, Clone, PartialEq)]
pub struct ErrorPage {
    pub codes: Vec<u16>,
    pub status: Option<u16>,
    pub url: Template,
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub regex: regex::Regex,
    pub url: Template,
    pub status: u16,
    pub add_args: bool,
    pub redirect: bool,
    pub flag: Flag,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flag {
    Next,
    Last,
    Break,
}

#[derive(Debug, Clone)]
pub enum Op {
    Rewrite(Rewrite),
    Return(u16, Template),
    Break,
    Set(String, Template),
    If(Condition, Vec<Op>, Arc<Level>),
}

#[derive(Debug, Clone)]
pub enum Condition {
    Var(Template),
    Equal(Template, Template, bool),
    Match(Template, regex::Regex, bool),
    File(Template, char, bool),
}

#[derive(Debug, Clone)]
pub struct CookieRewrite {
    pub pattern: CookiePattern,
    pub replacement: Template,
}

#[derive(Debug, Clone)]
pub enum CookiePattern {
    Text(Template),
    Regex(regex::Regex),
}

#[derive(Debug, Clone)]
pub struct CookieFlags {
    pub cookie: CookiePattern,
    pub flags: Vec<Template>,
}

pub const COOKIE_FLAGS: [&str; 8] = ["secure", "httponly", "nosecure", "nohttponly", "samesite=none", "samesite=lax", "samesite=strict", "nosamesite"];

#[derive(Debug, Clone)]
pub enum CacheZone {
    Fixed(Arc<crate::cache::Zone>),
    Named(Template, Arc<HashMap<String, Arc<crate::cache::Zone>>>),
}

#[derive(Debug, Clone, Default)]
pub struct Level {
    pub script: Vec<Op>,
    pub proxy_cookie_domain: Option<Vec<CookieRewrite>>,
    pub proxy_cookie_path: Option<Vec<CookieRewrite>>,
    pub proxy_cookie_flags: Option<Vec<CookieFlags>>,
    pub proxy_redirect: Option<Vec<CookieRewrite>>,
    pub access_log: Vec<Arc<AccessLog>>,
    pub log_cache: Option<Arc<Cache>>,
    pub root: PathBuf,
    pub root_vars: Option<Template>,
    pub add_header: Vec<(String, Template, bool)>,
    pub add_trailer: Vec<(String, Template, bool)>,
    pub add_inherit: [Inherit; 2],
    pub error_page: Vec<ErrorPage>,
    pub index: Vec<Template>,
    pub error_log: Vec<(Arc<File>, usize)>,
    pub log_not_found: bool,
    pub proxy: Option<Arc<Proxy>>,
    pub max_body: u64,
    pub max_headers: usize,
    pub header_buffer: usize,
    pub large_header_buffers: (usize, usize),
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
    pub merge_slashes: bool,
    pub body_buffer: u64,
    pub body_in_file_only: bool,
    pub body_clean: bool,
    pub body_temp_path: PathBuf,
    pub body_temp_levels: Vec<usize>,
    pub expires: Option<Template>,
    pub post_action: Option<String>,
    pub alias: Option<PathBuf>,
    pub alias_len: Option<usize>,
    pub alias_vars: Option<Template>,
    pub try_files: Option<Arc<TryFiles>>,
    pub absolute_redirect: bool,
    pub server_tokens: bool,
    pub chunked: bool,
    pub server_name_in_redirect: bool,
    pub port_in_redirect: bool,
    pub keepalive_requests: u64,
    pub keepalive_timeout: Duration,
    pub keepalive_header: Option<u64>,
    pub keepalive_time: Duration,
    pub keepalive_disable_msie6: bool,
    pub keepalive_disable_safari: bool,
    pub lingering_close: Option<bool>,
    pub default_type: String,
    pub types: Option<Arc<HashMap<String, String>>>,
    pub proxy_set_header: Vec<(String, Template)>,
    pub proxy_hide_header: Vec<String>,
    pub proxy_pass_header: Vec<String>,
    pub proxy_intercept_errors: bool,
    pub proxy_pass_request_headers: bool,
    pub proxy_pass_request_body: bool,
    pub proxy_request_buffering: bool,
    pub proxy_http_11: bool,
    pub proxy_h2: bool,
    pub proxy_pass_trailers: bool,
    pub proxy_buffer_size: usize,
    pub proxy_buffering: bool,
    pub proxy_cache: Option<CacheZone>,
    pub proxy_cache_lock: bool,
    pub proxy_cache_lock_timeout: Duration,
    pub proxy_cache_lock_age: Duration,
    pub proxy_cache_valid: Vec<(Option<u16>, Duration)>,
    pub proxy_cache_min_uses: u64,
    pub proxy_cache_max_range_offset: Option<u64>,
    pub proxy_cache_use_stale: Vec<String>,
    pub proxy_no_cache: Vec<Template>,
    pub proxy_cache_bypass: Vec<Template>,
    pub proxy_cache_key: Option<Template>,
    pub proxy_cache_background_update: bool,
    pub proxy_cache_convert_head: bool,
    pub proxy_cache_post: bool,
    pub proxy_cache_revalidate: bool,
    pub proxy_force_ranges: bool,
    pub max_ranges: Option<usize>,
    pub proxy_ignore_headers: Vec<String>,
    pub proxy_buffers: (usize, usize),
    pub proxy_busy_buffers_size: Option<usize>,
    pub proxy_temp_file_write_size: Option<usize>,
    pub proxy_max_temp_file_size: usize,
    pub proxy_temp_path: PathBuf,
    pub proxy_temp_levels: Vec<usize>,
    pub proxy_next_upstream: Vec<String>,
    pub proxy_next_upstream_tries: usize,
    pub proxy_next_upstream_timeout: Duration,
    pub gzip_static: Option<bool>,
    pub gzip: bool,
    pub gzip_types: Vec<String>,
    pub gunzip: bool,
    pub gzip_vary: bool,
    pub gzip_min_length: u64,
    pub gzip_http_11: bool,
    pub resolver: Option<Arc<Resolver>>,
    pub resolver_timeout: Duration,
    pub proxy_connect_timeout: Duration,
    pub proxy_read_timeout: Duration,
    pub proxy_send_timeout: Duration,
    pub send_timeout: Duration,
    pub sendfile: bool,
    pub sendfile_max_chunk: u64,
    pub tcp_nopush: bool,
    pub tcp_nodelay: bool,
    pub proxy_bind: Option<(Template, bool)>,
    pub limit_rate: Template,
    pub limit_rate_after: Template,
    pub proxy_method: Option<Template>,
    pub early_hints: Vec<Template>,
    pub proxy_set_body: Option<Template>,
    pub proxy_limit_rate: Template,
    pub if_modified_since: Option<bool>,
    pub ssl_certificate: Vec<PathBuf>,
    pub ssl_certificate_key: Vec<PathBuf>,
    pub ssl_certificate_compression: bool,
    pub ssl_ciphers: Option<String>,
    pub ssl_protocols: [bool; 2],
    pub ssl_prefer_server_ciphers: bool,
    pub ssl_reject_handshake: bool,
    pub http2: bool,
    pub ssl_ecdh_curve: Option<String>,
    pub ssl_session_ticket_key: Vec<PathBuf>,
    pub ssl_conf_command: Vec<(String, String)>,
    pub limit_except: Option<(Vec<String>, Arc<Level>)>,
    pub proxy_ssl_session_reuse: bool,
    pub ssl_sessions: crate::tls::Sessions,
    pub ssl_certificate_cache: Option<Arc<crate::tls::CertCache>>,
    pub ssl_password_file: Option<PathBuf>,
    pub ssl_verify_client: u8,
    pub ssl_trusted_certificate: Option<PathBuf>,
    pub ssl_client_certificate: Option<PathBuf>,
    pub ssl_crl: Option<PathBuf>,
    pub ssl_verify_depth: usize,
    pub ssl_ocsp: Option<bool>,
    pub ssl_ocsp_responder: Option<String>,
    pub ssl_ocsp_cache: Option<String>,
    pub ssl_stapling: bool,
    pub ssl_stapling_file: Option<PathBuf>,
    pub ssl_stapling_responder: Option<String>,
    pub ssl_stapling_verify: bool,
    pub proxy_ssl_certificate: Option<Template>,
    pub proxy_ssl_certificate_key: Option<Template>,
    pub proxy_ssl_password_file: Option<PathBuf>,
    pub proxy_ssl_certificate_vars: Option<(Template, Template, PathBuf)>,
    pub proxy_ssl_certificate_cache: Option<Arc<crate::tls::CertCache>>,
    pub proxy_ssl_verify: bool,
    pub proxy_ssl_trusted_certificate: Option<PathBuf>,
    pub proxy_ssl_crl: Option<PathBuf>,
    pub proxy_ssl_verify_depth: usize,
    pub proxy_ssl_name: Option<Template>,
    pub proxy_ssl_server_name: bool,
    pub proxy_ignore_client_abort: bool,
    pub proxy_socket_keepalive: bool,
    pub proxy_ssl_protocols: [bool; 2],
    pub proxy_tls: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Debug)]
pub struct TryFiles {
    pub files: Vec<(Template, bool)>,
    pub fallback: Fallback,
}

#[derive(Debug, PartialEq)]
pub enum Fallback {
    Status(u16),
    Uri(Template),
}

#[derive(Debug)]
pub enum Match {
    Exact,
    Prefix,
    NoRegex,
    Regex(regex::bytes::Regex),
    Named,
}

#[derive(Debug)]
pub struct Location {
    pub kind: Match,
    pub path: String,
    pub level: Level,
    pub auto_redirect: bool,
    pub children: Vec<usize>,
}

#[derive(Debug)]
pub enum ServerName {
    Exact(String),
    Leading(String),
    Trailing(String),
    Regex(regex::Regex),
}

#[derive(Debug)]
pub struct Server {
    pub listen: Vec<SocketAddr>,
    pub names: Vec<ServerName>,
    pub name: Arc<str>,
    pub level: Level,
    pub locations: Vec<Location>,
    pub children: Vec<usize>,
    pub ssl: Vec<SocketAddr>,
    pub tls: Option<crate::tls::ServerTls>,
    pub defaults: Vec<SocketAddr>,
    pub backlogs: Vec<(SocketAddr, i32)>,
    pub ipv6only_off: Vec<SocketAddr>,
    pub http2: Vec<SocketAddr>,
    pub named: bool,
}

const LISTEN_WORDS: &[&str] = &["default_server", "default", "ssl", "http2", "quic", "proxy_protocol", "deferred", "bind", "reuseport", "multipath"];
const LISTEN_VALUES: &[&str] = &["setfib", "fastopen", "backlog", "rcvbuf", "sndbuf", "accept_filter", "ipv6only", "so_keepalive"];

pub const LISTEN_BACKLOG: i32 = 511;

#[derive(Debug)]
pub struct Config {
    pub daemon: bool,
    pub pid: PathBuf,
    pub rlimit_nofile: Option<u64>,
    pub shutdown_timeout: Option<Duration>,
    pub working_directory: Option<PathBuf>,
    pub user: Option<User>,
    pub warnings: Vec<String>,
    pub emerg_logs: Vec<Arc<File>>,
    pub alert_logs: Vec<Arc<File>>,
    pub notice_logs: Vec<Arc<File>>,
    pub warn_logs: Vec<Arc<File>>,
    pub logs: Vec<(PathBuf, Arc<File>)>,
    pub connections: usize,
    pub workers: usize,
    pub temp_paths: Vec<PathBuf>,
    pub servers: Vec<Server>,
}

#[derive(Debug)]
pub struct User {
    pub name: std::ffi::CString,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

struct Builder<'a> {
    prefix: &'a Path,
    formats: HashMap<String, Arc<Format>>,
    logs: HashMap<PathBuf, Arc<File>>,
    upstreams: HashMap<String, Arc<Upstream>>,
    zones: HashMap<String, Arc<crate::cache::Zone>>,
    implicit: Implicit,
    errors: Vec<(Arc<File>, usize)>,
    temp_paths: Vec<(PathBuf, Vec<usize>, Option<String>)>,
    location: String,
    location_no_uri: bool,
    listens: HashMap<(SocketAddr, bool), (bool, bool)>,
    ssl_zones: HashMap<String, u64>,
}

pub fn build(main: &[Directive], prefix: &Path) -> Result<Config, String> {
    let combined = Arc::new(Format { line: Template::parse(COMBINED)?, escape: Escape::Default });
    let formats = HashMap::from([("combined".to_string(), combined)]);
    let mut b = Builder { prefix, formats, logs: HashMap::new(), upstreams: HashMap::new(), zones: HashMap::new(), implicit: Implicit::default(), errors: Vec::new(), temp_paths: Vec::new(), location: String::new(), location_no_uri: false, listens: HashMap::new(), ssl_zones: HashMap::new() };
    let mut config = Config { daemon: true, pid: prefix.join("logs/nginx.pid"), rlimit_nofile: None, shutdown_timeout: None, working_directory: None, user: None, warnings: Vec::new(), emerg_logs: Vec::new(), alert_logs: Vec::new(), notice_logs: Vec::new(), warn_logs: Vec::new(), logs: Vec::new(), connections: 512, workers: 1, temp_paths: Vec::new(), servers: Vec::new() };
    // Read first: the http block loads its certificates as it says.
    let inheritable = main.iter().find(|d| d.name == "ssl_object_cache_inheritable").map_or(Ok(true), |d| flag(d).map_err(|e| format!("{e} in {}", d.at)))?;
    crate::tls::new_configuration(inheritable);
    // So are the error logs, which the http block inherits wherever they are.
    for d in main.iter().filter(|d| d.name == "error_log") {
        b.check(d, MAIN)?;
        let log = b.error_log(d)?;
        b.errors.push(log);
    }
    // SAFETY: geteuid() always succeeds.
    let root = unsafe { libc::geteuid() } == 0;
    for (i, d) in main.iter().enumerate() {
        b.check(d, MAIN)?;
        if d.name == "user" && !root {
            config.warnings.push(format!("the \"user\" directive makes sense only if the master process runs with super-user privileges, ignored in {}", d.at));
            continue;
        }
        once(&main[..i], d)?;
        match d.name.as_str() {
            "daemon" => config.daemon = flag(d).map_err(|e| format!("{e} in {}", d.at))?,
            "pid" => config.pid = b.path(&d.args[0]),
            "worker_rlimit_nofile" => config.rlimit_nofile = Some(d.args[0].parse().map_err(|_| format!("invalid number in {}", d.at))?),
            // SAFETY: sysconf() only reads a system value.
            "worker_processes" if d.args[0] == "auto" => config.workers = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }.max(1) as usize,
            "worker_processes" => config.workers = d.args[0].parse::<u32>().map_err(|_| format!("invalid value \"{}\" in \"worker_processes\" directive in {}", d.args[0], d.at))? as usize,
            "worker_shutdown_timeout" => config.shutdown_timeout = Some(millis(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?),
            "working_directory" => config.working_directory = Some(d.args[0].clone().into()),
            "user" => config.user = Some(user(d)?),
            "error_log" => {
                let file = b.open(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
                let level = d.args.get(1).map(|l| LEVELS.iter().position(|v| v == l));
                config.emerg_logs.push(file.clone());
                if level.is_none_or(|l| l <= Some(6)) { config.alert_logs.push(file.clone()) }
                if level.is_some_and(|l| l <= Some(3)) { config.warn_logs.push(file.clone()) }
                if level.is_none_or(|l| l <= Some(2)) { config.notice_logs.push(file) }
            }
            "events" => for (j, e) in d.block.iter().flatten().enumerate() {
                b.check(e, EVENTS)?;
                once(&d.block.as_deref().unwrap_or_default()[..j], e)?;
                if e.name == "worker_connections" {
                    let n = Some(&e.args[0]).filter(|v| v.bytes().all(|c| c.is_ascii_digit())).and_then(|v| v.parse().ok());
                    config.connections = n.filter(|&n| n <= isize::MAX as usize).ok_or_else(|| format!("invalid number \"{}\" in {}", e.args[0], e.at))?;
                }
            },
            "http" => config.servers = b.http(d.block.as_deref().unwrap_or_default())?,
            _ => {}
        }
    }
    if !main.iter().any(|d| d.name == "events") { return Err("no \"events\" section in configuration".into()); }
    if root && config.user.is_none() { config.user = Some(default_user()?) }
    let mut listening: Vec<&SocketAddr> = config.servers.iter().flat_map(|s| &s.listen).collect();
    listening.sort();
    listening.dedup();
    if config.connections < listening.len() + 1 { return Err(format!("{} worker_connections are not enough for {} listening sockets", config.connections, listening.len())); }
    config.temp_paths = b.temp_paths.into_iter().map(|t| t.0).collect();
    config.logs = b.logs.into_iter().collect();
    Ok(config)
}

impl Builder<'_> {
    fn check(&self, d: &Directive, ctx: u16) -> Result<(), String> {
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

    fn temp_path(&mut self, p: &str, levels: &[usize], at: Option<&str>) -> Result<(), String> {
        let path = self.path(if p.starts_with('/') { p } else { p.strip_suffix('/').unwrap_or(p) });
        let Some((_, other, first)) = self.temp_paths.iter().find(|t| t.0.as_os_str() == path.as_os_str()) else {
            self.temp_paths.push((path, levels.to_vec(), at.map(str::to_string)));
            return Ok(())
        };
        if other == levels { return Ok(()) }
        let (name, first) = (path.to_string_lossy(), first.as_deref().unwrap_or_default());
        let name = name.strip_suffix('/').unwrap_or(&name);
        Err(match at {
            Some(at) => format!("the same path name \"{name}\" in {first} has the different levels than in {at}"),
            None => format!("the path name \"{name}\" in {first} has the same name as default path, but the different levels, you need to define default path in http section"),
        })
    }

    fn open(&mut self, p: &str) -> Result<Arc<File>, String> {
        let path = self.path(p);
        if let Some(f) = self.logs.get(&path) { return Ok(f.clone()); }
        let file = OpenOptions::new().create(true).append(true).open(&path);
        let file = Arc::new(file.map_err(|e| format!("open() \"{}\" failed ({e})", path.display()))?);
        self.logs.insert(path, file.clone());
        Ok(file)
    }

    fn error_log(&mut self, d: &Directive) -> Result<(Arc<File>, usize), String> {
        let file = self.open(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
        Ok((file, d.args.get(1).and_then(|l| LEVELS.iter().position(|v| v == l)).unwrap_or(4)))
    }

    fn http(&mut self, block: &[Directive]) -> Result<Vec<Server>, String> {
        let (temp, proxy_temp) = (self.path("client_body_temp"), self.path("proxy_temp"));
        let mut level = Level { error_log: self.errors.clone(), root: self.path("html"), default_type: "text/plain".into(), gzip_http_11: true, gzip_min_length: 20, proxy_cache_min_uses: 1, proxy_cache_lock_timeout: crate::cache::LOCK_TIMEOUT, proxy_cache_lock_age: crate::cache::LOCK_TIMEOUT, proxy_cache_convert_head: true, max_body: 1 << 20, max_headers: 1000, header_buffer: 1 << 10, proxy_http_11: true, proxy_buffer_size: 4 << 10, proxy_buffering: true, proxy_buffers: (8, 4 << 10), proxy_max_temp_file_size: 1 << 30, proxy_temp_path: proxy_temp, proxy_temp_levels: vec![1, 2], large_header_buffers: (4, 8 << 10), ignore_invalid_headers: true, merge_slashes: true, if_modified_since: Some(false), log_not_found: true, index: vec![Template::parse("index.html")?], body_buffer: 16 << 10, body_temp_path: temp, absolute_redirect: true, server_tokens: true, chunked: true, port_in_redirect: true,
            keepalive_requests: 1000, keepalive_timeout: Duration::from_secs(75), keepalive_time: Duration::from_secs(3600), keepalive_disable_msie6: true, lingering_close: Some(false),
            resolver_timeout: Duration::from_secs(30), proxy_connect_timeout: Duration::from_secs(60), proxy_pass_request_headers: true, proxy_pass_request_body: true, proxy_request_buffering: true, proxy_redirect: Some(Vec::new()), proxy_ssl_session_reuse: true, proxy_ssl_verify_depth: 1, ssl_verify_depth: 1, ssl_protocols: [true, true], proxy_ssl_protocols: [true, true], proxy_tls: Some(crate::tls::client((true, false, [true, true]), None, None)?), proxy_next_upstream: vec!["error".into(), "timeout".into()], proxy_read_timeout: Duration::from_secs(60), proxy_send_timeout: Duration::from_secs(60), send_timeout: Duration::from_secs(60), sendfile_max_chunk: 2 << 20, tcp_nodelay: true, ..Level::default() };
        for d in block.iter().filter(|d| d.name == "upstream") {
            let block = d.block.as_deref().unwrap_or_default();
            if self.upstreams.keys().any(|u| u.eq_ignore_ascii_case(&d.args[0])) { return Err(format!("duplicate upstream \"{}\" in {}", d.args[0], d.at)); }
            block.iter().enumerate().try_for_each(|(i, s)| self.check(s, UPS).and_then(|()| once(&block[..i], s)))?;
            let peers = block.iter().filter(|s| s.name == "server").map(|s| peer(&s.args).map_err(|e| format!("{e} in {}", s.at)));
            let peers: Vec<Peer> = peers.collect::<Result<_, _>>()?;
            if peers.is_empty() { return Err(format!("no servers are inside upstream in {}", d.at)); }
            if peers.iter().all(|p| p.backup) { return Err(format!("no servers in upstream \"{}\" in {}", d.args[0], d.at)); }
            let mut upstream = Upstream::new(peers);
            upstream.keepalive = upstream_keepalive(block)?;
            let balancing = block.iter().rfind(|d| matches!(d.name.as_str(), "ip_hash" | "least_conn")).map(|d| d.name.as_str());
            upstream.balance = match balancing { Some("ip_hash") => Balance::IpHash, Some(_) => Balance::LeastConn, None => Balance::RoundRobin };
            self.upstreams.insert(d.args[0].clone(), Arc::new(upstream));
        }
        let mut cache_paths: Vec<(PathBuf, String)> = Vec::new();
        for d in block.iter().filter(|d| d.name == "proxy_cache_path") {
            self.check(d, HTTP)?;
            let ((name, size), levels) = cache_path(&d.args[1..]).map_err(|e| format!("{e} in {}", d.at))?;
            if self.zones.contains_key(&name) { return Err(format!("duplicate zone \"{name}\" in {}", d.at)); }
            let path = self.path(d.args[0].strip_suffix('/').unwrap_or(&d.args[0]));
            if let Some((_, first)) = cache_paths.iter().find(|p| p.0 == path) { return Err(format!("the same path name \"{}\" used in {first} and in {at} in {at}", path.display(), at = d.at)); }
            cache_paths.push((path.clone(), d.at.clone()));
            let zone = crate::cache::Zone::at(path, &levels, (&name, size))?;
            self.zones.insert(name, Arc::new(zone));
        }
        // Named captures of server names are variables everywhere, so they are known first.
        let names = block.iter().filter(|d| d.name == "server").flat_map(|d| d.block.iter().flatten()).filter(|d| d.name == "server_name");
        names.flat_map(|d| d.args.iter()).filter(|n| n.starts_with('~')).for_each(|n| drop(server_name(n)));
        fn declare(block: &[Directive]) {
            const REGEXES: &[&str] = &["location", "if", "rewrite", "proxy_redirect", "proxy_cookie_domain", "proxy_cookie_path", "proxy_cookie_flags"];
            for d in block {
                if let Some(name) = d.args.first().and_then(|a| a.strip_prefix('$')).filter(|_| d.name == "set") { crate::vars::add_user(name); }
                if REGEXES.contains(&d.name.as_str()) { d.args.iter().flat_map(|a| capture_names(a)).for_each(crate::vars::add_user); }
                declare(d.block.as_deref().unwrap_or_default());
            }
        }
        declare(block);
        self.level(block, HTTP, &mut level)?;
        let servers = block.iter().filter(|d| d.name == "server");
        let servers: Vec<Server> = servers.map(|d| self.server(d.block.as_deref().unwrap_or_default(), &level)).collect::<Result<_, _>>()?;
        certified(&servers, &block.iter().filter(|d| d.name == "server").map(|d| d.at.as_str()).collect::<Vec<_>>())?;
        let given = |block: &[Directive], name| block.iter().any(|d| d.name == name);
        let default = |name| !given(block, name) && block.iter().any(|d| d.name == "server" && !given(d.block.as_deref().unwrap_or_default(), name));
        if default("client_body_temp_path") { self.temp_path("client_body_temp", &[], None)?; }
        servers.iter().flat_map(|s| [&s.level].into_iter().chain(s.locations.iter().map(|l| &l.level))).try_for_each(check_proxy_buffers)?;
        if default("proxy_temp_path") { self.temp_path("proxy_temp", &[1, 2], None)?; }
        block.iter().filter(|d| d.name == "server").try_for_each(|d| same_locations(d.block.as_deref().unwrap_or_default()))?;
        Ok(servers)
    }

    fn server(&mut self, block: &[Directive], parent: &Level) -> Result<Server, String> {
        let mut s = Server { listen: Vec::new(), names: Vec::new(), name: "".into(), level: parent.clone(), locations: Vec::new(), children: Vec::new(), ssl: Vec::new(), tls: None, defaults: Vec::new(), backlogs: Vec::new(), ipv6only_off: Vec::new(), http2: Vec::new(), named: false };
        self.level(block, SRV, &mut s.level)?;
        let mut listens = Vec::new();
        for d in block {
            match d.name.as_str() {
                "listen" => {
                    let addrs = listen_ports(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
                    let quic = d.args[1..].iter().any(|a| a == "quic");
                    let valued = |a: &String| a.split_once('=').is_some_and(|(name, _)| LISTEN_VALUES.contains(&name));
                    if let Some(a) = d.args[1..].iter().find(|a| !LISTEN_WORDS.contains(&a.as_str()) && !valued(a)) { return Err(format!("invalid parameter \"{a}\" in {}", d.at)); }
                    let options = d.args[1..].iter().any(|a| valued(a) || ["deferred", "bind", "reuseport"].contains(&a.as_str()));
                    let default = d.args[1..].iter().any(|a| a == "default_server" || a == "default");
                    for a in &addrs {
                        if listens.contains(&(*a, quic)) { return Err(format!("a duplicate listen {a} in {}", d.at)); }
                        listens.push((*a, quic));
                        let given = self.listens.entry((*a, quic)).or_default();
                        if options && given.1 { return Err(format!("duplicate listen options for {a} in {}", d.at)); }
                        if default && given.0 { return Err(format!("a duplicate default server for {a} in {}", d.at)); }
                        *given = (given.0 || default, given.1 || options);
                    }
                    if d.args[1..].iter().any(|a| a == "ssl") { s.ssl.extend(&addrs); }
                    if d.args[1..].iter().any(|a| a == "http2") { s.http2.extend(&addrs); }
                    if default { s.defaults.extend(&addrs); }
                    for a in d.args[1..].iter().filter_map(|a| a.strip_prefix("backlog=")) {
                        let n = a.parse::<i32>().ok().filter(|n| *n != 0).ok_or_else(|| format!("invalid backlog \"{a}\" in {}", d.at))?;
                        s.backlogs.extend(addrs.iter().map(|addr| (*addr, n)));
                    }
                    let mut ipv6only = true;
                    for a in d.args[1..].iter().filter_map(|a| a.strip_prefix("ipv6only=")) {
                        ipv6only = match a {
                            "on" => true,
                            "off" => false,
                            _ if a.starts_with('o') => return Err(format!("invalid ipv6only flags \"{a}\" in {}", d.at)),
                            _ => return Err(format!("invalid parameter \"ipv6only={a}\" in {}", d.at)),
                        };
                    }
                    if !ipv6only { s.ipv6only_off.extend(&addrs); }
                    s.listen.extend(addrs);
                }
                "server_name" => {
                    if s.names.is_empty() { s.name = d.args[0].strip_prefix('.').unwrap_or(&d.args[0]).into(); }
                    for n in &d.args { s.names.extend(server_name(n).map_err(|e| format!("{e} in {}", d.at))?); }
                }
                _ => {}
            }
        }
        if s.listen.is_empty() { s.listen.push(SocketAddr::from(([0, 0, 0, 0], 80))); }
        let l = &s.level;
        if let Some(cert) = l.ssl_certificate.get(l.ssl_certificate_key.len()) {
            return Err(format!("no \"ssl_certificate_key\" is defined for certificate \"{}\"", cert.strip_prefix(self.prefix).unwrap_or(cert).display()));
        }
        if !l.ssl_certificate.is_empty() || l.ssl_reject_handshake {
            if [1, 2].contains(&l.ssl_verify_client) && l.ssl_client_certificate.is_none() && l.ssl_trusted_certificate.is_none() { return Err("no ssl_client_certificate or ssl_trusted_certificate for ssl_verify_client".into()) }
            if l.ssl_ocsp.is_some() && l.ssl_verify_client == 3 { return Err("\"ssl_ocsp\" is incompatible with \"ssl_verify_client optional_no_ca\"".into()) }
        }
        let client_ca = l.ssl_client_certificate.as_ref().filter(|_| l.ssl_verify_client > 0);
        let trust: Vec<&Path> = [l.ssl_trusted_certificate.as_ref(), client_ca].into_iter().flatten().map(PathBuf::as_path).collect();
        let mut options = crate::tls::Options { verify: l.ssl_verify_client > 0, sessions: l.ssl_sessions, compress: l.ssl_certificate_compression, ciphers: l.ssl_ciphers.clone(), protocols: l.ssl_protocols, prefer: l.ssl_prefer_server_ciphers, curves: l.ssl_ecdh_curve.clone(), crl: l.ssl_crl.clone(), depth: l.ssl_verify_depth, ocsp: l.ssl_ocsp.map(|leaf| crate::ocsp::Ocsp { leaf, responder: l.ssl_ocsp_responder.clone(), cache: l.ssl_ocsp_cache.clone() }), ticket_keys: l.ssl_session_ticket_key.clone(), stapling: l.ssl_stapling.then(|| crate::tls::Stapling { verify: l.ssl_stapling_verify, responder: l.ssl_stapling_responder.clone(), file: l.ssl_stapling_file.clone() }), client_ca: l.ssl_client_certificate.clone() };
        let extra = conf_commands(&l.ssl_conf_command, &mut options)?;
        let pairs = l.ssl_certificate.iter().zip(&l.ssl_certificate_key).chain(extra[0].iter().zip(&extra[1]));
        let files: Vec<(&Path, &Path)> = pairs.map(|(cert, key)| (cert.as_path(), key.as_path())).collect();
        let named = files.iter().any(|(cert, key)| [cert, key].iter().any(|p| p.to_string_lossy().contains('$')));
        s.tls = (!files.is_empty()).then(|| crate::tls::server((&files, l.ssl_password_file.as_deref()), named.then(|| l.ssl_certificate_cache.clone()), &trust, options)).transpose()?;
        let level = s.level.clone();
        s.children = self.locations(block, None, &level, &mut s.locations)?;
        s.named = s.locations.iter().any(|l| matches!(l.kind, Match::Named));
        Ok(s)
    }

    fn locations(&mut self, block: &[Directive], around: Option<(Kind, &str)>, parent: &Level, out: &mut Vec<Location>) -> Result<Vec<usize>, String> {
        let mut children = Vec::new();
        for d in block.iter().filter(|d| d.name == "location") {
            let mut level = Level { proxy: None, try_files: None, script: Vec::new(), limit_except: None, ..parent.clone() };
            let inner = d.block.as_deref().unwrap_or_default();
            let (kind, path) = location(&d.args).map_err(|e| format!("{e} in {}", d.at))?;
            nested(&kind, &path, around).map_err(|e| format!("{e} in {}", d.at))?;
            self.location = d.args.last().cloned().unwrap_or_default();
            self.location_no_uri = matches!(kind, Match::Regex(_) | Match::Named);
            self.level(inner, LOC, &mut level)?;
            let auto_redirect = level.proxy.is_some() && path.ends_with('/') && !matches!(kind, Match::Regex(_));
            if inner.iter().any(|d| d.name == "alias") { level.alias_len = (!matches!(kind, Match::Regex(_))).then_some(path.len()); }
            let name = path.clone();
            let around = match &kind { Match::Exact => Kind::Exact, Match::Named => Kind::Named, Match::Regex(_) => Kind::Regex, _ => Kind::Prefix };
            let index = out.len();
            out.push(Location { kind, path, level: level.clone(), auto_redirect, children: Vec::new() });
            out[index].children = self.locations(inner, Some((around, &name)), &level, out)?;
            children.push(index);
        }
        Ok(children)
    }

    fn level(&mut self, block: &[Directive], ctx: u16, level: &mut Level) -> Result<(), String> {
        let mut logs: Option<Vec<Arc<AccessLog>>> = None;
        let mut errors: Option<Vec<(Arc<File>, usize)>> = None;
        let (mut headers, mut trailers): (Option<Vec<(String, Template, bool)>>, Option<Vec<_>>) = (None, None);
        let mut pages: Option<Vec<ErrorPage>> = None;
        let mut certs: [Option<Vec<PathBuf>>; 2] = [None, None];
        let mut commands: Option<Vec<(String, String)>> = None;
        let mut ticket_keys: Option<Vec<PathBuf>> = None;
        let mut proxy_headers: Option<Vec<(String, Template)>> = None;
        let mut types: Option<HashMap<String, String>> = None;
        let (mut hidden, mut passed): (Option<Vec<String>>, Option<Vec<String>>) = (None, None);
        let mut cookies: [Option<Option<Vec<CookieRewrite>>>; 2] = [None, None];
        let mut flags: Option<Option<Vec<CookieFlags>>> = None;
        let (mut redirects, mut own_proxy): (Option<Option<Vec<CookieRewrite>>>, bool) = (None, false);
        let (mut ifs, mut limit, mut own_tls) = (Vec::new(), None, false);
        for (i, d) in block.iter().enumerate() {
            self.check(d, ctx)?;
            once(&block[..i], d)?;
            let at = |e: String| format!("{e} in {}", d.at);
            let invalid = || at(format!("\"{}\" directive invalid value", d.name));
            match d.name.as_str() {
                "return" => level.script.push(ret(&d.args).map(|(code, text)| Op::Return(code, text)).map_err(at)?),
                "rewrite" => level.script.push(rewrite(&d.args).map(Op::Rewrite).map_err(at)?),
                "break" => level.script.push(Op::Break),
                "set" => level.script.push(set(&d.args).map_err(at)?),
                "if" => {
                    ifs.push((level.script.len(), d));
                    level.script.push(condition(&d.args).map(|c| Op::If(c, Vec::new(), Arc::default())).map_err(at)?);
                }
                "proxy_cookie_domain" | "proxy_cookie_path" => {
                    let (i, rewrite) = (d.name.ends_with("path") as usize, cookie_rewrite(&d.args, d.name.ends_with("domain")).map_err(at)?);
                    match (&mut cookies[i], rewrite) {
                        (None, rewrite) => cookies[i] = Some(rewrite.map(|r| vec![r])),
                        (Some(Some(list)), Some(rewrite)) => list.push(rewrite), _ => return Err(at(format!("\"{}\" directive is duplicate", d.name))),
                    }
                }
                "proxy_cookie_flags" => {
                    let rule = cookie_flags(&d.args).map_err(at)?;
                    if rule.is_none() && flags.is_some() || matches!(flags, Some(None)) { return Err(at("\"proxy_cookie_flags\" directive is duplicate".into())); }
                    flags = Some(rule.map(|rule| flags.take().flatten().unwrap_or_default().into_iter().chain([rule]).collect()));
                }
                "root" => {
                    let path = self.path(&d.args[0]);
                    let vars = Template::parse(&path.to_string_lossy()).map_err(at)?;
                    (level.root, level.root_vars, level.alias, level.alias_vars) = (path, vars.0.iter().any(|p| matches!(p, Part::Var(_))).then_some(vars), None, None);
                }
                "alias" => {
                    let path = self.path(&d.args[0]);
                    level.alias_vars = d.args[0].contains('$').then(|| Template::parse(&path.to_string_lossy())).transpose().map_err(at)?;
                    level.alias = Some(path);
                }
                "try_files" => level.try_files = Some(Arc::new(try_files(&d.args).map_err(at)?)),
                "absolute_redirect" => level.absolute_redirect = flag(d).map_err(at)?,
                "server_tokens" => level.server_tokens = d.args[0] == "build" || flag(d).map_err(|_| at(format!("invalid value \"{}\" in \"server_tokens\" directive, it must be \"on\", \"off\" or \"build\"", d.args[0])))?,
                "lingering_close" => level.lingering_close = [("off", None), ("on", Some(false)), ("always", Some(true))].into_iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"lingering_close\" directive, it must be \"off\", \"on\" or \"always\"", d.args[0])))?.1,
                "server_name_in_redirect" => level.server_name_in_redirect = flag(d).map_err(at)?,
                "port_in_redirect" => level.port_in_redirect = flag(d).map_err(at)?,
                "log_format" => {
                    if self.formats.contains_key(&d.args[0]) { return Err(at(format!("duplicate \"log_format\" name \"{}\"", d.args[0]))); }
                    let escape = d.args[1].strip_prefix("escape=").map(|e| log_escape(e).map_err(at)).transpose()?;
                    let line = Template::parse(&d.args[1 + escape.is_some() as usize..].concat()).map_err(at)?;
                    self.formats.insert(d.args[0].clone(), Arc::new(Format { line, escape: escape.unwrap_or(Escape::Default) }));
                }
                "open_log_file_cache" => level.log_cache = log_cache(&d.args).map_err(at)?,
                "access_log" => logs.get_or_insert_default().extend(self.access_log(&d.args).map_err(at)?),
                "add_header" => headers.get_or_insert_default().push(add_header(&d.args).map_err(at)?),
                "add_trailer" => trailers.get_or_insert_default().push(add_header(&d.args).map_err(at)?),
                "add_header_inherit" | "add_trailer_inherit" => {
                    const VALUES: [(&str, Inherit); 3] = [("on", Inherit::On), ("off", Inherit::Off), ("merge", Inherit::Merge)];
                    let value = VALUES.iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"{}\" directive, it must be \"on\", \"off\" or \"merge\"", d.args[0], d.name)))?.1;
                    level.add_inherit[usize::from(d.name == "add_trailer_inherit")] = value;
                }
                "error_page" => pages.get_or_insert_default().push(error_page(&d.args).map_err(at)?),
                "proxy_pass" => {
                    let proxy = self.proxy(&d.args[0]).map_err(at)?;
                    if proxy.uri.is_some() && (self.location_no_uri || ctx == LIF || ctx == LMT) {
                        return Err(at("\"proxy_pass\" cannot have URI part in location given by regular expression, or inside named location, or inside \"if\" statement, or inside \"limit_except\" block".into()));
                    }
                    (level.proxy, own_proxy) = (Some(Arc::new(proxy)), true);
                }
                "limit_except" => {
                    const METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "DELETE", "MKCOL", "COPY", "MOVE", "OPTIONS", "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK", "PATCH"];
                    if let Some(m) = d.args.iter().find(|m| !METHODS.contains(&m.as_str())) { return Err(at(format!("invalid method \"{m}\""))); }
                    let get = d.args.iter().any(|m| m == "GET").then(|| "HEAD".to_string());
                    limit = Some((d.args.iter().cloned().chain(get).collect::<Vec<_>>(), d));
                }
                "ssl_certificate" | "ssl_certificate_key" => certs[usize::from(d.name == "ssl_certificate_key")].get_or_insert_default().push(self.path(&d.args[0])),
                "ssl_certificate_compression" => level.ssl_certificate_compression = flag(d).map_err(at)?,
                "ssl_ciphers" => level.ssl_ciphers = Some(d.args[0].clone()),
                "ssl_protocols" => level.ssl_protocols = protocols(&d.args).map_err(at)?,
                "ssl_ecdh_curve" => level.ssl_ecdh_curve = Some(d.args[0].clone()),
                "ssl_prefer_server_ciphers" => level.ssl_prefer_server_ciphers = flag(d).map_err(at)?,
                "ssl_reject_handshake" => level.ssl_reject_handshake = flag(d).map_err(at)?,
                "http2" => level.http2 = flag(d).map_err(at)?,
                "ssl_conf_command" => commands.get_or_insert_default().push((d.args[0].clone(), if ["Certificate", "PrivateKey"].contains(&d.args[0].as_str()) { self.path(&d.args[1]).to_string_lossy().into_owned() } else { d.args[1].clone() })),
                "ssl_session_cache" => {
                    if let Some(a) = d.args.iter().find(|a| !(["off", "none", "builtin"].contains(&a.as_str()) || a.starts_with("builtin:") || a.starts_with("shared:") && a.matches(':').count() == 2)) { return Err(at(format!("invalid session cache \"{a}\""))); }
                    let mut zone = None;
                    for (a, (name, n)) in d.args.iter().filter_map(|a| Some((a, a.strip_prefix("shared:")?.split_once(':')?))) {
                        let n = size(n).map_err(|_| at(format!("invalid session cache \"{a}\"")))?;
                        if n < 8 * page_size() { return Err(at(format!("session cache \"{a}\" is too small"))); }
                        let declared = *self.ssl_zones.entry(name.to_string()).or_insert(n);
                        if declared != n { return Err(at(format!("the size {n} of shared memory zone \"{name}\" conflicts with already declared size {declared}"))); }
                        zone = Some(crate::shm::zone(name, n).map_err(at)?);
                    }
                    level.ssl_sessions.cache = d.args.iter().all(|a| a != "off" && a != "none");
                    level.ssl_sessions.zone = zone.filter(|_| level.ssl_sessions.cache);
                }
                "ssl_session_ticket_key" => ticket_keys.get_or_insert_default().push(self.path(&d.args[0])),
                "ssl_session_tickets" => level.ssl_sessions.tickets = flag(d).map_err(at)?,
                "ssl_session_timeout" => level.ssl_sessions.timeout = seconds(&d.args[0]).map_err(at)?.as_secs(),
                "proxy_ssl_session_reuse" => (level.proxy_ssl_session_reuse, own_tls) = (flag(d).map_err(at)?, true),
                "ssl_password_file" => level.ssl_password_file = Some(self.path(&d.args[0])),
                "ssl_verify_client" => level.ssl_verify_client = ["off", "on", "optional", "optional_no_ca"].iter().position(|v| *v == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"ssl_verify_client\" directive, it must be \"on\", \"off\", \"optional\" or \"optional_no_ca\"", d.args[0])))? as u8,
                "ssl_ocsp" => level.ssl_ocsp = [("off", None), ("on", Some(false)), ("leaf", Some(true))].into_iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"ssl_ocsp\" directive, it must be \"on\", \"off\" or \"leaf\"", d.args[0])))?.1,
                "ssl_ocsp_responder" | "ssl_stapling_responder" => {
                    let url = Some(d.args[0].clone()).filter(|u| u.starts_with("http://") || d.name == "ssl_stapling_responder").ok_or_else(|| at(format!("invalid URL prefix in OCSP responder \"{}\" in resolver", d.args[0])))?;
                    if d.name == "ssl_ocsp_responder" { level.ssl_ocsp_responder = Some(url) } else { level.ssl_stapling_responder = Some(url) }
                }
                "ssl_stapling" => level.ssl_stapling = flag(d).map_err(at)?,
                "ssl_stapling_verify" => level.ssl_stapling_verify = flag(d).map_err(at)?,
                "ssl_stapling_file" => level.ssl_stapling_file = Some(self.path(&d.args[0])),
                "ssl_ocsp_cache" => level.ssl_ocsp_cache = ocsp_cache(&d.args[0]).map_err(at)?,
                "ssl_trusted_certificate" => level.ssl_trusted_certificate = Some(self.path(&d.args[0])),
                "ssl_client_certificate" => level.ssl_client_certificate = Some(self.path(&d.args[0])),
                "ssl_crl" => level.ssl_crl = Some(self.path(&d.args[0])),
                "ssl_verify_depth" => level.ssl_verify_depth = d.args[0].parse().map_err(|_| at(format!("invalid value \"{}\" in \"ssl_verify_depth\" directive", d.args[0])))?,
                "proxy_ssl_certificate" => (level.proxy_ssl_certificate, own_tls) = (Some(Template::parse(&d.args[0]).map_err(at)?), true),
                "proxy_ssl_certificate_key" => (level.proxy_ssl_certificate_key, own_tls) = (Some(Template::parse(&d.args[0]).map_err(at)?), true),
                "proxy_ssl_certificate_cache" | "ssl_certificate_cache" => *if d.name == "ssl_certificate_cache" { &mut level.ssl_certificate_cache } else { &mut level.proxy_ssl_certificate_cache } = cert_cache(&d.name, &d.args).map_err(at)?,
                "proxy_ssl_password_file" => (level.proxy_ssl_password_file, own_tls) = (Some(self.path(&d.args[0])), true),
                "proxy_ssl_verify" => (level.proxy_ssl_verify, own_tls) = (flag(d).map_err(at)?, true),
                "proxy_ssl_trusted_certificate" => (level.proxy_ssl_trusted_certificate, own_tls) = (Some(self.path(&d.args[0])), true),
                "proxy_ssl_crl" => (level.proxy_ssl_crl, own_tls) = (Some(self.path(&d.args[0])), true),
                "proxy_ssl_verify_depth" => (level.proxy_ssl_verify_depth, own_tls) = (d.args[0].parse().map_err(|_| at(format!("invalid value \"{}\" in \"proxy_ssl_verify_depth\" directive", d.args[0])))?, true),
                "proxy_pass_trailers" => level.proxy_pass_trailers = flag(d).map_err(at)?,
                "proxy_ssl_server_name" => (level.proxy_ssl_server_name, own_tls) = (flag(d).map_err(at)?, true),
                "proxy_ssl_protocols" => (level.proxy_ssl_protocols, own_tls) = (protocols(&d.args).map_err(at)?, true),
                "proxy_ssl_name" => level.proxy_ssl_name = Some(Template::parse(&d.args[0]).map_err(at)?),
                "proxy_redirect" => {
                    let rule = if d.args == ["default"] {
                        let proxy = level.proxy.as_ref().filter(|_| own_proxy).ok_or_else(|| at("\"proxy_redirect default\" should be placed after the \"proxy_pass\" directive".into()))?;
                        Some(self.default_redirect(proxy).ok_or_else(|| at("\"proxy_redirect default\" cannot be used with \"proxy_pass\" directive with variables".into()))?)
                    } else {
                        cookie_rewrite(&d.args, false).map_err(at)?
                    };
                    match (&mut redirects, rule) {
                        (None, rule) => redirects = Some(rule.map(|r| vec![r])),
                        (Some(Some(list)), Some(rule)) => list.push(rule), _ => return Err(at("\"proxy_redirect\" directive is duplicate".into())),
                    }
                }
                "client_max_body_size" => level.max_body = Some(offset(&d.args[0]).map_err(at)?).filter(|&n| n > 0).unwrap_or(u64::MAX),
                "large_client_header_buffers" | "connection_pool_size" | "client_header_buffer_size" => {
                    let number = d.args.len() == 1 || d.args[0].parse::<u64>().is_ok_and(|n| n > 0);
                    let bytes = size(d.args.last().unwrap()).ok().filter(|_| number);
                    let bytes = bytes.ok_or_else(|| at(format!("\"{}\" directive invalid value", d.name)))? as usize;
                    match d.name.as_str() {
                        "large_client_header_buffers" => level.large_header_buffers = (d.args[0].parse().unwrap_or(0), bytes),
                        "client_header_buffer_size" => level.header_buffer = bytes,
                        _ => {}
                    }
                }
                "max_headers" => level.max_headers = d.args[0].parse().map_err(|_| at("invalid number".into()))?,
                "index" => level.index = d.args.iter().map(|a| Template::parse(a)).collect::<Result<_, _>>().map_err(at)?,
                "log_not_found" => level.log_not_found = flag(d).map_err(at)?,
                "error_log" => errors.get_or_insert_default().push(self.error_log(d)?),
                "ignore_invalid_headers" => level.ignore_invalid_headers = flag(d).map_err(at)?,
                "underscores_in_headers" => level.underscores_in_headers = flag(d).map_err(at)?,
                "merge_slashes" => level.merge_slashes = flag(d).map_err(at)?,
                "chunked_transfer_encoding" => level.chunked = flag(d).map_err(at)?,
                "client_body_buffer_size" => level.body_buffer = size(&d.args[0]).map_err(at)?,
                "proxy_buffer_size" => level.proxy_buffer_size = size(&d.args[0]).map_err(|_| invalid())? as usize,
                "proxy_busy_buffers_size" => level.proxy_busy_buffers_size = Some(size(&d.args[0]).map_err(|_| invalid())? as usize),
                "proxy_temp_file_write_size" => level.proxy_temp_file_write_size = Some(size(&d.args[0]).map_err(|_| invalid())? as usize),
                "proxy_buffering" => level.proxy_buffering = flag(d).map_err(at)?,
                "proxy_ignore_client_abort" => level.proxy_ignore_client_abort = flag(d).map_err(at)?,
                "proxy_socket_keepalive" => level.proxy_socket_keepalive = flag(d).map_err(at)?,
                "proxy_cache" => level.proxy_cache = match Template::parse(&d.args[0]).map_err(at)? {
                    t if t.fixed().is_none() => Some(CacheZone::Named(t, Arc::new(self.zones.clone()))),
                    _ => (d.args[0] != "off").then(|| self.zones.get(&d.args[0]).cloned().map(CacheZone::Fixed).ok_or_else(|| at(format!("\"proxy_cache\" zone \"{}\" is unknown", d.args[0])))).transpose()?,
                },
                "proxy_cache_valid" => {
                    let valid = block.iter().filter(|v| v.name == "proxy_cache_valid").map(|v| seconds(&v.args[v.args.len() - 1]).and_then(|t| crate::cache::valid(&v.args[..v.args.len() - 1], t)).map_err(|e| format!("{e} in {}", v.at)));
                    level.proxy_cache_valid = valid.collect::<Result<Vec<_>, _>>()?.concat();
                }
                "proxy_cache_lock" => level.proxy_cache_lock = flag(d).map_err(at)?,
                "proxy_cache_lock_timeout" => level.proxy_cache_lock_timeout = millis(&d.args[0]).map_err(at)?,
                "proxy_cache_lock_age" => level.proxy_cache_lock_age = millis(&d.args[0]).map_err(at)?,
                "proxy_cache_min_uses" => level.proxy_cache_min_uses = d.args[0].parse().map_err(|_| at("invalid number".into()))?,
                "proxy_cache_max_range_offset" => level.proxy_cache_max_range_offset = Some(offset(&d.args[0]).map_err(|_| invalid())?),
                "proxy_cache_use_stale" => {
                    const VALUES: &[&str] = &["error", "timeout", "invalid_header", "updating", "http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429", "non_idempotent", "off"];
                    if let Some(a) = d.args.iter().find(|a| !VALUES.contains(&a.as_str())) { return Err(at(format!("invalid value \"{a}\""))); }
                    level.proxy_cache_use_stale = if d.args.iter().any(|a| a == "off") { Vec::new() } else { d.args.clone() };
                }
                "proxy_no_cache" | "proxy_cache_bypass" => {
                    let all = block.iter().filter(|v| v.name == d.name).flat_map(|v| v.args.iter().map(move |a| Template::parse(a).map_err(|e| format!("{e} in {}", v.at))));
                    *if d.name == "proxy_no_cache" { &mut level.proxy_no_cache } else { &mut level.proxy_cache_bypass } = all.collect::<Result<_, _>>()?;
                }
                "proxy_cache_key" => level.proxy_cache_key = Some(Template::parse(&d.args[0]).map_err(at)?),
                "proxy_cache_background_update" => level.proxy_cache_background_update = flag(d).map_err(at)?,
                "proxy_cache_convert_head" => level.proxy_cache_convert_head = flag(d).map_err(at)?,
                "proxy_cache_methods" => {
                    if let Some(a) = d.args.iter().find(|a| !["GET", "HEAD", "POST"].iter().any(|m| m.eq_ignore_ascii_case(a))) { return Err(at(format!("invalid value \"{a}\""))); }
                    level.proxy_cache_post = d.args.iter().any(|a| a.eq_ignore_ascii_case("POST"));
                }
                "proxy_cache_revalidate" => level.proxy_cache_revalidate = flag(d).map_err(at)?,
                "proxy_force_ranges" => level.proxy_force_ranges = flag(d).map_err(at)?,
                "max_ranges" => level.max_ranges = Some(d.args[0].parse().map_err(|_| at("invalid number".into()))?),
                "proxy_ignore_headers" => {
                    const VALUES: &[&str] = &["x-accel-redirect", "x-accel-expires", "x-accel-limit-rate", "x-accel-buffering", "x-accel-charset", "expires", "cache-control", "set-cookie", "vary"];
                    let all = block.iter().filter(|v| v.name == d.name).flat_map(|v| v.args.iter().map(move |a| (a, &v.at)));
                    level.proxy_ignore_headers = all.map(|(a, at)| Some(a.to_ascii_lowercase()).filter(|l| VALUES.contains(&l.as_str())).ok_or_else(|| format!("invalid value \"{a}\" in {at}"))).collect::<Result<_, _>>()?;
                }
                "proxy_request_buffering" => level.proxy_request_buffering = flag(d).map_err(at)?,
                "proxy_http_version" => {
                    let version = ["1.0", "1.1", "2"].iter().position(|v| *v == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"proxy_http_version\" directive, it must be \"1.0\", \"1.1\" or \"2\"", d.args[0])))?;
                    (level.proxy_http_11, level.proxy_h2) = (version > 0, version == 2);
                }
                "proxy_max_temp_file_size" => level.proxy_max_temp_file_size = size(&d.args[0]).map_err(|_| invalid())? as usize,
                "proxy_temp_path" => {
                    level.proxy_temp_path = self.path(&d.args[0]);
                    level.proxy_temp_levels = temp_levels(&d.args[1..]).ok_or_else(invalid)?;
                    self.temp_path(&d.args[0], &level.proxy_temp_levels, Some(&d.at))?;
                }
                "proxy_bind" => level.proxy_bind = proxy_bind(&d.args).map_err(at)?,
                "proxy_buffers" => match (scaled(&d.args[0], &[("", 1)]), size(&d.args[1])) {
                    (Ok(n @ 1..), Ok(size @ 1..)) => level.proxy_buffers = (n as usize, size as usize),
                    _ => return Err(invalid()),
                },
                "client_body_in_file_only" => {
                    let value = ["off", "on", "clean"].iter().position(|v| *v == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\"", d.args[0])))?;
                    (level.body_in_file_only, level.body_clean) = (value > 0, value == 2);
                }
                "client_body_temp_path" => {
                    level.body_temp_path = self.path(&d.args[0]);
                    level.body_temp_levels = temp_levels(&d.args[1..]).ok_or_else(|| at("invalid value".into()))?;
                    self.temp_path(&d.args[0], &level.body_temp_levels, Some(&d.at))?;
                }
                "default_type" => level.default_type = d.args[0].clone(),
                "types" => {
                    let types = types.get_or_insert_default();
                    for t in d.block.as_deref().unwrap_or_default() {
                        if t.block.is_some() { return Err(format!("unexpected \"{{\" in {}", t.at)); }
                        types.extend(t.args.iter().map(|ext| (ext.to_ascii_lowercase(), t.name.clone())));
                    }
                }
                "proxy_set_header" => proxy_headers.get_or_insert_default().push((d.args[0].clone(), Template::parse(&d.args[1]).map_err(at)?)),
                "resolver" => level.resolver = Some(Arc::new(Resolver::parse(&d.args).map_err(at)?)),
                "resolver_timeout" => level.resolver_timeout = seconds(&d.args[0]).map_err(at)?,
                "proxy_connect_timeout" => level.proxy_connect_timeout = millis(&d.args[0]).map_err(at)?,
                "proxy_read_timeout" => level.proxy_read_timeout = millis(&d.args[0]).map_err(at)?,
                "proxy_send_timeout" => level.proxy_send_timeout = millis(&d.args[0]).map_err(at)?,
                "send_timeout" => level.send_timeout = seconds(&d.args[0]).map_err(at)?,
                "proxy_intercept_errors" => level.proxy_intercept_errors = flag(d).map_err(at)?,
                "proxy_pass_request_headers" => level.proxy_pass_request_headers = flag(d).map_err(at)?,
                "proxy_pass_request_body" => level.proxy_pass_request_body = flag(d).map_err(at)?,
                "proxy_next_upstream" => {
                    const VALUES: &[&str] = &["error", "timeout", "invalid_header", "http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429", "non_idempotent", "updating", "off"];
                    if let Some(a) = d.args.iter().find(|a| !VALUES.contains(&a.as_str())) { return Err(at(format!("invalid value \"{a}\""))); }
                    level.proxy_next_upstream = if d.args.iter().any(|a| a == "off") { Vec::new() } else { d.args.clone() };
                }
                "proxy_next_upstream_tries" => level.proxy_next_upstream_tries = d.args[0].parse().map_err(|_| at("invalid number".into()))?,
                "proxy_next_upstream_timeout" => level.proxy_next_upstream_timeout = millis(&d.args[0]).map_err(at)?,
                "proxy_hide_header" => hidden.get_or_insert_default().push(d.args[0].to_ascii_lowercase()),
                "proxy_pass_header" => passed.get_or_insert_default().push(d.args[0].to_ascii_lowercase()),
                "gzip_static" => level.gzip_static = [("off", None), ("on", Some(false)), ("always", Some(true))].into_iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"gzip_static\" directive, it must be \"on\", \"off\" or \"always\"", d.args[0])))?.1,
                "gunzip" => level.gunzip = flag(d).map_err(at)?,
                "gzip" => level.gzip = flag(d).map_err(at)?,
                "keepalive_requests" => level.keepalive_requests = d.args[0].parse().map_err(|_| at("invalid number".into()))?,
                "keepalive_timeout" | "keepalive_time" => {
                    let secs = d.args.iter().map(|a| crate::expires::parse_time(a).filter(|s| *s >= 0)).collect::<Option<Vec<_>>>();
                    let secs = secs.ok_or_else(|| at(format!("\"{}\" directive invalid value", d.name)))?;
                    let time = Duration::from_secs(secs[0] as u64);
                    if d.name == "keepalive_time" { level.keepalive_time = time } else { level.keepalive_timeout = time }
                    if let Some(&header) = secs.get(1) { level.keepalive_header = Some(header as u64); }
                }
                "keepalive_disable" => {
                    let unknown = d.args.iter().find(|a| !["none", "msie6", "safari"].contains(&a.as_str()));
                    if let Some(a) = unknown { return Err(at(format!("invalid value \"{a}\""))); }
                    (level.keepalive_disable_msie6, level.keepalive_disable_safari) = (d.args.iter().any(|a| a == "msie6"), d.args.iter().any(|a| a == "safari"));
                }
                "gzip_types" => level.gzip_types = d.args.iter().map(|t| t.to_ascii_lowercase()).collect(),
                "gzip_vary" => level.gzip_vary = flag(d).map_err(at)?,
                "gzip_min_length" => level.gzip_min_length = size(&d.args[0]).map_err(at)?,
                "sendfile" => level.sendfile = flag(d).map_err(at)?,
                "sendfile_max_chunk" => level.sendfile_max_chunk = size(&d.args[0]).map_err(|_| invalid())?,
                "tcp_nopush" => level.tcp_nopush = flag(d).map_err(at)?,
                // Only checked: twinx writes an answer as soon as it has it.
                "postpone_output" => { size(&d.args[0]).map_err(|_| invalid())?; }
                "tcp_nodelay" => level.tcp_nodelay = flag(d).map_err(at)?,
                "gzip_http_version" => level.gzip_http_11 = ["1.0", "1.1"].iter().position(|v| *v == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\"", d.args[0])))? == 1,
                "post_action" => level.post_action = Some(d.args[0].clone()).filter(|a| a != "off"),
                "expires" => level.expires = Some(expires(&d.args).map_err(at)?),
                "limit_rate" => level.limit_rate = size_value(&d.args[0]).map_err(at)?,
                "limit_rate_after" => level.limit_rate_after = size_value(&d.args[0]).map_err(at)?,
                "proxy_method" => level.proxy_method = Some(Template::parse(&d.args[0]).map_err(at)?),
                "early_hints" => level.early_hints = d.args.iter().map(|a| Template::parse(a)).collect::<Result<_, _>>().map_err(at)?,
                "proxy_set_body" => level.proxy_set_body = Some(Template::parse(&d.args[0]).map_err(at)?),
                "proxy_limit_rate" => level.proxy_limit_rate = size_value(&d.args[0]).map_err(at)?,
                "if_modified_since" => level.if_modified_since = [("off", None), ("exact", Some(false)), ("before", Some(true))].into_iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"if_modified_since\" directive, it must be \"off\", \"exact\" or \"before\"", d.args[0])))?.1,
                _ => {}
            }
        }
        if let Some(logs) = logs { level.access_log = logs; }
        if let Some(errors) = errors { level.error_log = errors; }
        level.add_header = inherited(level.add_inherit[0], std::mem::take(&mut level.add_header), headers);
        level.add_trailer = inherited(level.add_inherit[1], std::mem::take(&mut level.add_trailer), trailers);
        if let Some(pages) = pages { level.error_page = pages; }
        let [certificates, keys] = certs;
        if let Some(c) = certificates { level.ssl_certificate = c; }
        if let Some(k) = keys { level.ssl_certificate_key = k; }
        if let Some(c) = commands { level.ssl_conf_command = c; }
        if let Some(k) = ticket_keys { level.ssl_session_ticket_key = k; }
        if let Some(headers) = proxy_headers { level.proxy_set_header = headers; }
        if let Some(types) = types { level.types = Some(Arc::new(types)); }
        if let Some(hidden) = hidden { level.proxy_hide_header = hidden; }
        if let Some(passed) = passed { level.proxy_pass_header = passed; }
        let [domain, path] = cookies;
        if let Some(domain) = domain { level.proxy_cookie_domain = domain; }
        if let Some(path) = path { level.proxy_cookie_path = path; }
        if let Some(flags) = flags { level.proxy_cookie_flags = flags; }
        if let Some(redirects) = redirects { level.proxy_redirect = redirects; }
        if own_tls {
            let names = level.proxy_ssl_certificate.clone().zip(level.proxy_ssl_certificate_key.clone()).filter(|(c, _)| !c.0.is_empty());
            let fixed = names.as_ref().and_then(|(c, k)| text(c).zip(text(k))).map(|(c, k)| (self.path(&c), self.path(&k)));
            level.proxy_ssl_certificate_vars = names.filter(|_| fixed.is_none()).map(|(c, k)| (c, k, self.prefix.to_path_buf()));
            let cert = fixed.as_ref().map(|(c, k)| (c.as_path(), k.as_path(), level.proxy_ssl_password_file.as_deref()));
            if level.proxy_ssl_verify && level.proxy_ssl_trusted_certificate.is_none() && level.proxy.as_ref().is_some_and(|p| p.ssl) { return Err("no proxy_ssl_trusted_certificate for proxy_ssl_verify".into()) }
            let verify = level.proxy_ssl_verify.then(|| crate::tls::verify(level.proxy_ssl_trusted_certificate.as_deref(), level.proxy_ssl_crl.as_deref(), level.proxy_ssl_verify_depth)).transpose()?;
            level.proxy_tls = Some(crate::tls::client((level.proxy_ssl_session_reuse, level.proxy_ssl_server_name, level.proxy_ssl_protocols), cert, verify)?);
        }
        if level.proxy_redirect.as_ref().is_some_and(Vec::is_empty) && own_proxy {
            level.proxy_redirect = level.proxy.as_ref().and_then(|p| self.default_redirect(p)).map(|r| vec![r]).or(Some(Vec::new()));
        }
        for (i, d) in ifs {
            let mut inner = Level { script: Vec::new(), ..level.clone() };
            self.level(d.block.as_deref().unwrap_or_default(), if ctx == SRV { SIF } else { LIF }, &mut inner)?;
            if let Op::If(_, body, to) = &mut level.script[i] { (*body, *to) = (std::mem::take(&mut inner.script), Arc::new(inner)); }
        }
        if let Some((methods, d)) = limit {
            let mut inner = Level { script: Vec::new(), ..level.clone() };
            self.level(d.block.as_deref().unwrap_or_default(), LMT, &mut inner)?;
            level.limit_except = Some((methods, Arc::new(inner)));
        }
        Ok(())
    }

    /// Lines are written as soon as requests end, so buffer and flush are only checked.
    fn access_log(&mut self, args: &[String]) -> Result<Option<Arc<AccessLog>>, String> {
        if args[0] == "off" { return Ok(None); }
        let name = args.get(1).map_or("combined", |n| n.as_str());
        let format = self.formats.get(name).cloned().ok_or_else(|| format!("unknown log format \"{name}\""))?;
        let (mut buffer, mut flush, mut gzip, mut condition) = (false, false, None, None);
        for a in args.iter().skip(2) {
            match a.split_once('=').unwrap_or((a, "")) {
                ("buffer", v) => buffer = size(v).map_err(|_| format!("invalid buffer size \"{v}\""))? > 0,
                ("flush", v) => flush = crate::expires::parse_time(v.strip_suffix("ms").unwrap_or(v)).ok_or_else(|| format!("invalid flush time \"{v}\""))? >= 0,
                ("gzip", v) => gzip = Some(if v.is_empty() { 1 } else { v.parse().ok().filter(|l| (1..=9).contains(l)).ok_or_else(|| format!("invalid compression level \"{v}\""))? }),
                ("if", v) => condition = Some(Template::parse(v)?),
                _ => return Err(format!("invalid parameter \"{a}\"")),
            }
        }
        if flush && !buffer && gzip.is_none() { return Err(format!("no buffer is defined for access_log \"{}\"", args[0])); }
        let path = Template::parse(&self.path(&args[0]).to_string_lossy())?;
        let literal = path.0.iter().all(|p| matches!(p, Part::Text(_)));
        let target = if literal { Target::File(self.open(&args[0])?) } else { Target::Path(path) };
        Ok(Some(Arc::new(AccessLog { target, format, condition, gzip })))
    }

    fn default_redirect(&self, p: &Proxy) -> Option<CookieRewrite> {
        let text = |s: String| Template(vec![Part::Text(s)]);
        let url = format!("{}://{}{}", if p.ssl { "https" } else { "http" }, p.host, p.uri.as_deref().unwrap_or("/"));
        let replacement = if p.uri.is_some() { self.location.clone() } else { "/".to_string() };
        p.url.is_none().then(|| CookieRewrite { pattern: CookiePattern::Text(text(url)), replacement: text(replacement) })
    }

    fn proxy(&self, url: &str) -> Result<Proxy, String> {
        let template = Template::parse(url)?;
        if template.0.iter().any(|p| matches!(p, Part::Var(_))) {
            return Ok(Proxy { host: String::new(), ssl: false, upstream: Arc::new(Upstream::new(Vec::new())), uri: None, url: Some(template), groups: self.upstreams.clone(), implicit: self.implicit.clone() });
        }
        let (rest, ssl) = url.strip_prefix("http://").map(|r| (r, false)).or_else(|| Some((url.strip_prefix("https://")?, true))).ok_or_else(|| format!("invalid URL prefix in \"{url}\""))?;
        if let Some((path, uri)) = unix_url(rest) {
            let upstream = Arc::new(Upstream::new(vec![Peer::new(Addr::Unix(Path::new(path).into()))]));
            return Ok(Proxy { host: "localhost".into(), ssl, upstream, uri, url: None, groups: HashMap::new(), implicit: Implicit::default() });
        }
        let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
        if host_port(host, 80).is_some_and(|(_, port)| port == 0) { return Err(format!("invalid port in upstream \"{rest}\"")); }
        let implicit = || {
            let (name, port) = host_port(host, if ssl { 443 } else { 80 }).ok_or(())?;
            let key = format!("{}:{port}", name.to_ascii_lowercase());
            let mut implicit = self.implicit.lock().unwrap();
            if let Some(up) = implicit.get(&key) { return Ok(up.clone()); }
            let up = Arc::new(Upstream::new(addresses(name, port).into_iter().map(Peer::new).collect()));
            if up.peers.is_empty() { return Err(()); }
            implicit.insert(key, up.clone());
            Ok(up)
        };
        let upstream = self.upstreams.get(host).cloned().map_or_else(implicit, Ok);
        let upstream = upstream.map_err(|_| format!("host not found in upstream \"{host}\""))?;
        Ok(Proxy { host: host.to_string(), ssl, upstream, uri, url: None, groups: HashMap::new(), implicit: Implicit::default() })
    }
}

fn user(d: &Directive) -> Result<User, String> {
    account(&d.args[0], d.args.get(1).unwrap_or(&d.args[0]), &format!(" in {}", d.at))
}

fn default_user() -> Result<User, String> {
    // SAFETY: getgrnam() reads a string ended by a zero byte and returns static data or null.
    let group = if unsafe { libc::getgrnam(c"nobody".as_ptr()).is_null() && !libc::getgrnam(c"nogroup".as_ptr()).is_null() } { "nogroup" } else { "nobody" };
    account("nobody", group, "")
}

fn account(user: &str, group: &str, at: &str) -> Result<User, String> {
    let failed = |call: &str, name: &str| {
        let e = std::io::Error::last_os_error();
        let text = e.to_string();
        let reason = match e.raw_os_error() { Some(0) | None => String::new(), Some(n) => format!(" ({n}: {})", text.split(" (os error").next().unwrap_or_default()) };
        format!("{call}(\"{name}\") failed{reason}{at}")
    };
    let (Ok(name), Ok(group_name)) = (std::ffi::CString::new(user), std::ffi::CString::new(group)) else { return Err(failed("getpwnam", user)) };
    // SAFETY: errno is this thread's own; getpwnam() reads a string ended by a zero byte and returns static data or null.
    let pwd = unsafe { *libc::__errno_location() = 0; libc::getpwnam(name.as_ptr()) };
    if pwd.is_null() { return Err(failed("getpwnam", user)) }
    // SAFETY: pwd is not null, read before the next call that may change what it points to.
    let uid = unsafe { (*pwd).pw_uid };
    // SAFETY: as for getpwnam() above.
    let grp = unsafe { *libc::__errno_location() = 0; libc::getgrnam(group_name.as_ptr()) };
    if grp.is_null() { return Err(failed("getgrnam", group)) }
    // SAFETY: grp is not null.
    Ok(User { name, uid, gid: unsafe { (*grp).gr_gid } })
}

fn once(before: &[Directive], d: &Directive) -> Result<(), String> {
    let off = (d.name == "proxy_redirect" || d.name.starts_with("proxy_cookie_")) && before.iter().any(|b| b.name == d.name && b.args == ["off"]);
    if !off && REPEATED.contains(&d.name.as_str()) { return Ok(()) }
    let other = match d.name.as_str() { "root" => "alias", "alias" => "root", _ => "" };
    let Some(b) = before.iter().find(|b| b.name == d.name || b.name == other) else { return Ok(()) };
    let earlier = if b.name == other { format!(", \"{other}\" directive was specified earlier") } else { String::new() };
    Err(format!("\"{}\" directive is duplicate{earlier} in {}", d.name, d.at))
}

#[derive(Clone, Copy, PartialEq)]
enum Kind { Prefix, Exact, Named, Regex }

fn nested(kind: &Match, path: &str, around: Option<(Kind, &str)>) -> Result<(), String> {
    let Some((outer, name)) = around else { return Ok(()) };
    if outer == Kind::Exact { return Err(format!("location \"{path}\" cannot be inside the exact location \"{name}\"")); }
    if outer == Kind::Named { return Err(format!("location \"{path}\" cannot be inside the named location \"{name}\"")); }
    if matches!(kind, Match::Named) { return Err(format!("named location \"{path}\" can be on the server level only")); }
    if !matches!(kind, Match::Regex(_)) && !path.starts_with(name) { return Err(format!("location \"{path}\" is outside location \"{name}\"")); }
    Ok(())
}

fn same_locations(block: &[Directive]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for d in block.iter().filter(|d| d.name == "location") {
        let key = match &d.args[..] {
            [p] if !p.starts_with(['@', '~']) => (false, p),
            [m, p] if m == "=" || m == "^~" => (m == "=", p), _ => continue,
        };
        if !seen.insert(key) { return Err(format!("duplicate location \"{}\" in {}", key.1, d.at)); }
    }
    block.iter().filter(|d| d.name == "location").try_for_each(|d| same_locations(d.block.as_deref().unwrap_or_default()))
}

pub fn unix_url(rest: &str) -> Option<(&str, Option<String>)> {
    let path = rest.get(..5).filter(|p| p.eq_ignore_ascii_case("unix:")).map(|_| &rest[5..])?;
    Some(path.split_once(':').map_or((path, None), |(p, uri)| (p, Some(uri.to_string()))))
}

pub fn host_port(host: &str, default: u16) -> Option<(&str, u16)> {
    let (name, port) = match host.rsplit_once(':') { Some((n, p)) if !p.contains(']') => (n, p.parse().ok()?), _ => (host, default) };
    Some((name.strip_prefix('[').and_then(|n| n.strip_suffix(']')).unwrap_or(name), port))
}

pub fn addresses(name: &str, port: u16) -> Vec<SocketAddr> {
    if let Ok(ip) = name.parse::<IpAddr>() { return vec![SocketAddr::new(ip, port)]; }
    let Ok(c) = std::ffi::CString::new(name) else { return Vec::new() };
    // SAFETY: the hints are zeroed but for the fields set, the list getaddrinfo()
    // returns is read only before it is freed, and each address is read as
    // the structure its family says it is.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    (hints.ai_family, hints.ai_socktype, hints.ai_flags) = (libc::AF_UNSPEC, libc::SOCK_STREAM, libc::AI_ADDRCONFIG);
    let (mut list, mut ips) = (std::ptr::null_mut(), Vec::<IpAddr>::new());
    if unsafe { libc::getaddrinfo(c.as_ptr(), std::ptr::null(), &hints, &mut list) } != 0 { return Vec::new(); }
    let mut at = list;
    while let Some(ai) = unsafe { at.as_ref() } {
        let v4 = || IpAddr::from(unsafe { *(ai.ai_addr as *const libc::sockaddr_in) }.sin_addr.s_addr.to_ne_bytes());
        let v6 = || IpAddr::from(unsafe { *(ai.ai_addr as *const libc::sockaddr_in6) }.sin6_addr.s6_addr);
        ips.extend(if ai.ai_family == libc::AF_INET { Some(v4()) } else { (ai.ai_family == libc::AF_INET6).then(v6) });
        at = ai.ai_next;
    }
    unsafe { libc::freeaddrinfo(list) };
    ips.sort_by_key(|ip| ip.is_ipv6());
    ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect()
}

fn proxy_bind(args: &[String]) -> Result<Option<(Template, bool)>, String> {
    if args.len() == 1 && args[0] == "off" { return Ok(None); }
    if let Some(a) = args.get(1).filter(|a| *a != "transparent") { return Err(format!("invalid parameter \"{a}\"")); }
    let address = Template::parse(&args[0])?;
    let literal = address.0.iter().all(|p| matches!(p, Part::Text(_)));
    if literal && local_addr(&args[0]).is_none() { return Err(format!("invalid address \"{}\"", args[0])); }
    Ok(Some((address, args.len() == 2)))
}

pub fn local_addr(s: &str) -> Option<SocketAddr> {
    let ip = |a: &str| a.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0));
    ip(s).or_else(|| s.strip_prefix('[')?.strip_suffix(']').and_then(ip)).or_else(|| s.parse().ok())
}

fn log_escape(e: &str) -> Result<Escape, String> {
    let modes = [("default", Escape::Default), ("json", Escape::Json), ("none", Escape::None)];
    modes.into_iter().find(|m| m.0 == e).map(|m| m.1).ok_or_else(|| format!("unknown log format escaping \"{e}\""))
}

fn log_cache(args: &[String]) -> Result<Option<Arc<Cache>>, String> {
    if args[0] == "off" { return Ok(None); }
    let mut values = [("max", 0), ("inactive", 10), ("min_uses", 1), ("valid", 60)];
    for a in args {
        let invalid = format!("invalid \"open_log_file_cache\" parameter \"{a}\"");
        let (name, value) = a.split_once('=').ok_or(invalid.clone())?;
        let slot = values.iter_mut().find(|v| v.0 == name).ok_or(invalid.clone())?;
        slot.1 = if ["max", "min_uses"].contains(&name) { value.parse().ok() } else { crate::expires::parse_time(value) }.filter(|v| *v >= 0).ok_or(invalid)?;
    }
    let [max, inactive, min_uses, valid] = values.map(|v| v.1);
    if max == 0 { return Err("\"open_log_file_cache\" must have \"max\" parameter".into()); }
    let secs = |s: i64| Duration::from_secs(s as u64);
    Ok(Some(Arc::new(Cache::new(max as usize, secs(inactive), min_uses as u32, secs(valid)))))
}

fn text(t: &Template) -> Option<String> {
    t.0.iter().map(|p| match p { Part::Text(t) => Some(t.as_str()), Part::Var(_) => None }).collect()
}

fn cert_cache(name: &str, args: &[String]) -> Result<Option<Arc<crate::tls::CertCache>>, String> {
    let mut values = [("max", 0), ("inactive", 10), ("valid", 60)];
    for a in args {
        if a == "off" { return Ok(None); }
        let invalid = format!("invalid parameter \"{a}\"");
        let (name, value) = a.split_once('=').ok_or(invalid.clone())?;
        let slot = values.iter_mut().find(|v| v.0 == name).ok_or(invalid.clone())?;
        slot.1 = if name == "max" { value.parse().ok().filter(|v| *v > 0) } else { crate::expires::parse_time(value).filter(|v| *v >= 0) }.ok_or(invalid)?;
    }
    let [max, inactive, valid] = values.map(|v| v.1 as u64);
    if max == 0 { return Err(format!("\"{name}\" must have the \"max\" parameter")); }
    Ok(Some(Arc::new(crate::tls::CertCache::new(max as usize, valid, inactive))))
}

fn try_files(args: &[String]) -> Result<TryFiles, String> {
    let (last, files) = args.split_last().unwrap_or((&args[0], &[]));
    let files = files.iter().map(|f| {
        let dir = f.ends_with('/');
        Template::parse(&f[..f.len() - dir as usize]).map(|t| (t, dir))
    });
    let fallback = match last.strip_prefix('=') {
        Some(code) => Fallback::Status(code.parse().ok().filter(|c| *c <= 999).ok_or_else(|| format!("invalid code \"{last}\""))?),
        None => Fallback::Uri(Template::parse(last)?),
    };
    Ok(TryFiles { files: files.collect::<Result<_, _>>()?, fallback })
}

fn location(args: &[String]) -> Result<(Match, String), String> {
    let (modifier, path) = if args.len() == 2 { (args[0].as_str(), &args[1]) } else { ("", &args[0]) };
    let kind = match modifier {
        "~" | "~*" => Match::Regex(bytes_regex(path, modifier == "~*").map_err(|e| format!("invalid regular expression \"{path}\": {e}"))?),
        _ => {
            let plain = [("", Match::Prefix), ("=", Match::Exact), ("^~", Match::NoRegex)].into_iter().find(|k| k.0 == modifier);
            let kind = plain.ok_or_else(|| format!("invalid location modifier \"{modifier}\""))?.1;
            if modifier.is_empty() && path.starts_with('@') { Match::Named } else { kind }
        }
    };
    Ok((kind, path.clone()))
}

fn peer(args: &[String]) -> Result<Peer, String> {
    let addr = match unix_url(&args[0]) {
        Some((path, _)) => Addr::Unix(Path::new(path).into()),
        None => listen(&args[0]).map_err(|_| format!("host not found in upstream \"{}\"", args[0]))?.into(),
    };
    if matches!(addr, Addr::Inet(a) if a.port() == 0) { return Err(format!("invalid port in upstream \"{}\"", args[0])); }
    let (mut values, mut backup, mut down) = ([("weight", 1u64), ("max_fails", 1), ("fail_timeout", 10), ("max_conns", 0)], false, false);
    for a in &args[1..] {
        if a == "backup" { backup = true; continue; }
        if a == "down" { down = true; continue; }
        let invalid = || format!("invalid parameter \"{a}\"");
        let (name, value) = a.split_once('=').ok_or_else(invalid)?;
        let slot = values.iter_mut().find(|v| v.0 == name).ok_or_else(invalid)?;
        slot.1 = value.trim_end_matches('s').parse().map_err(|_| invalid())?;
        if name == "weight" && slot.1 == 0 { return Err(invalid()); }
    }
    let [weight, max_fails, fail_timeout, max_conns] = values.map(|v| v.1);
    Ok(Peer { addr, weight: weight as i64, max_fails, fail_timeout, backup, down, max_conns })
}

fn upstream_keepalive(block: &[Directive]) -> Result<Option<Keepalive>, String> {
    let mut k = Keepalive::default();
    for d in block.iter().filter(|d| d.name.starts_with("keepalive")) {
        let at = |e: String| format!("{e} in {}", d.at);
        let directive = |e: &str| at(format!("\"{}\" directive {e}", d.name));
        let time = || millis(&d.args[0]).map_err(|e| directive(&e));
        match d.name.as_str() {
            "keepalive" => {
                k.max = d.args[0].parse().map_err(|_| at(format!("invalid value \"{}\" in \"keepalive\" directive", d.args[0])))?;
                if let Some(a) = d.args.get(1).filter(|a| *a != "local") { return Err(at(format!("invalid parameter \"{a}\""))); }
                k.local = d.args.len() > 1;
            }
            "keepalive_requests" => k.requests = d.args[0].parse().map_err(|_| directive("invalid number"))?,
            "keepalive_time" => k.time = time()?,
            _ => k.timeout = time()?,
        }
    }
    Ok((k.max > 0).then_some(k))
}

fn expires(args: &[String]) -> Result<Template, String> {
    let (value, t) = (args.join(" "), Template::parse(&args.join(" "))?);
    let literal = t.0.iter().all(|p| matches!(p, crate::vars::Part::Text(_)));
    if literal && crate::expires::parse(&value).is_none() { return Err(format!("invalid value \"{value}\"")); }
    Ok(t)
}

fn millis(s: &str) -> Result<Duration, String> {
    s.strip_suffix("ms").and_then(|ms| ms.parse().ok()).map(Duration::from_millis).map_or_else(|| seconds(s), Ok)
}

fn seconds(s: &str) -> Result<Duration, String> {
    crate::expires::parse_time(s).filter(|t| *t >= 0).map(|t| Duration::from_secs(t as u64)).ok_or_else(|| "invalid value".to_string())
}

fn server_name(n: &str) -> Result<Vec<ServerName>, String> {
    if n.starts_with('*') && (n.len() < 3 || !n[1..].starts_with('.')) || n == "." { return Err(format!("server name \"{n}\" is invalid")); }
    if n == "~" { return Err(format!("empty regex in server name \"{n}\"")); }
    let star = n.matches('*').count();
    if !n.starts_with('~') && (star > 1 || star == 1 && !(n.len() > 1 && n.starts_with('.') || n.len() > 2 && (n.starts_with("*.") || n.ends_with(".*")))) { return Err(format!("invalid server name or wildcard \"{n}\"")); }
    let lower = n.to_lowercase();
    if let Some(re) = n.strip_prefix('~') {
        let re = regex::Regex::new(&format!("(?i){}", pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?;
        crate::vars::add_captures(re.capture_names().flatten());
        return Ok(vec![ServerName::Regex(re)]);
    }
    Ok(match (lower.strip_prefix('*'), lower.strip_suffix('*'), lower.strip_prefix('.')) {
        (Some(suffix), _, _) => vec![ServerName::Leading(suffix.to_string())],
        (_, Some(prefix), _) => vec![ServerName::Trailing(prefix.to_string())],
        (_, _, Some(name)) => vec![ServerName::Exact(name.to_string()), ServerName::Leading(lower.clone())],
        _ => vec![ServerName::Exact(lower)],
    })
}

fn capture_names(p: &str) -> Vec<&str> {
    let starts = p.match_indices("(?<").map(|(i, _)| i + 3).chain(p.match_indices("(?P<").map(|(i, _)| i + 4));
    let name = |i: usize| p[i..].split_once('>').map(|(n, _)| n).filter(|n| n.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'));
    starts.filter_map(name).collect()
}

pub fn bytes_regex(p: &str, caseless: bool) -> Result<regex::bytes::Regex, regex::Error> {
    let (p, mut out, mut class, mut escaped) = (pcre(p), String::new(), false, false);
    for c in p.chars() {
        let opened = class && (out.ends_with('[') || out.ends_with("[^"));
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '[' => class = true,
            ']' if !opened => class = false,
            '$' if !class => { out += "(?:\\n?\\z)"; continue }
            _ => {}
        }
        out.push(c);
    }
    regex::bytes::Regex::new(&format!("(?{}-u){out}", if caseless { "i" } else { "" }))
}

fn pcre(p: &str) -> String {
    let (mut out, mut rest) = (String::new(), p);
    while let Some(i) = rest.find("\\Q") {
        let (quoted, next) = rest[i + 2..].split_once("\\E").unwrap_or((&rest[i + 2..], ""));
        out += &format!("{}{}", &rest[..i], regex::escape(quoted));
        rest = next;
    }
    out + rest
}

fn protocols(args: &[String]) -> Result<[bool; 2], String> {
    if let Some(a) = args.iter().find(|a| !["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"].iter().any(|p| p.eq_ignore_ascii_case(a))) { return Err(format!("invalid value \"{a}\"")) }
    Ok(["TLSv1.2", "TLSv1.3"].map(|p| args.iter().any(|a| a.eq_ignore_ascii_case(p))))
}

/// KTLS changes nothing: twinx keeps TLS in user space.
fn conf_commands(commands: &[(String, String)], options: &mut crate::tls::Options) -> Result<[Vec<PathBuf>; 2], String> {
    let mut files = [Vec::new(), Vec::new()];
    for (name, value) in commands {
        match name.as_str() {
            "Options" => for o in value.split(',').map(str::trim) {
                let (on, option) = o.strip_prefix('-').map_or((true, o), |o| (false, o));
                match option { "SessionTicket" => options.sessions.tickets = on, "ServerPreference" => options.prefer = on, "KTLS" => {}, _ => return Err(format!("SSL_CONF_cmd(\"{name}\", \"{value}\") failed")) }
            },
            "Certificate" | "PrivateKey" => files[usize::from(name == "PrivateKey")].push(PathBuf::from(value)), _ => return Err(format!("SSL_CONF_cmd(\"{name}\", \"{value}\") failed")),
        }
    }
    Ok(files)
}

fn ocsp_cache(value: &str) -> Result<Option<String>, String> {
    if value == "off" { return Ok(None) }
    let zone = value.strip_prefix("shared:").and_then(|z| z.rsplit_once(':')).filter(|(name, n)| !name.is_empty() && size(n).is_ok());
    let (name, n) = zone.ok_or_else(|| format!("invalid value \"{value}\""))?;
    crate::ocsp::zone(name, size(n)?)?;
    Ok(Some(name.to_string()))
}

fn flag(d: &Directive) -> Result<bool, String> {
    let (value, name) = (&d.args[0], &d.name);
    let found = [("on", true), ("off", false)].into_iter().find(|f| f.0 == value.to_ascii_lowercase()).map(|f| f.1);
    found.ok_or_else(|| format!("invalid value \"{value}\" in \"{name}\" directive, it must be \"on\" or \"off\""))
}

fn set(args: &[String]) -> Result<Op, String> {
    let name = args[0].strip_prefix('$').ok_or_else(|| format!("invalid variable name \"{}\"", args[0]))?;
    if name != "limit_rate" && name != "args" && crate::vars::builtin(name) { return Err(format!("the duplicate \"{name}\" variable")); }
    Ok(Op::Set(name.to_string(), Template::parse(&args[1])?))
}

fn condition(args: &[String]) -> Result<Condition, String> {
    let invalid = format!("invalid condition \"{}\"", args[0]);
    let mut words: Vec<&str> = args.iter().map(String::as_str).collect();
    let last = words.len() - 1;
    words[0] = words[0].strip_prefix('(').ok_or(invalid.clone())?;
    words[last] = words[last].strip_suffix(')').ok_or(invalid.clone())?;
    let (open, close) = (words[0].is_empty(), last > 0 && words[last].is_empty());
    match words[usize::from(open)..words.len() - usize::from(close)] {
        [var] if var.starts_with('$') => Ok(Condition::Var(Template::parse(var)?)),
        [var, op @ ("=" | "!="), value] if var.starts_with('$') => Ok(Condition::Equal(Template::parse(var)?, Template::parse(value)?, op == "!=")),
        [var, op @ ("~" | "~*" | "!~" | "!~*"), re] if var.starts_with('$') => {
            let regex = regex::Regex::new(&format!("{}{}", if op.ends_with('*') { "(?i)" } else { "" }, pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?;
            Ok(Condition::Match(Template::parse(var)?, regex, op.starts_with('!')))
        }
        [op @ ("-f" | "-d" | "-e" | "-x" | "!-f" | "!-d" | "!-e" | "!-x"), path] => Ok(Condition::File(Template::parse(path)?, op.chars().last().unwrap_or_default(), op.starts_with('!'))), _ => Err(invalid),
    }
}

fn cookie_flags(args: &[String]) -> Result<Option<CookieFlags>, String> {
    if args == ["off"] { return Ok(None); }
    let cookie = match args[0].strip_prefix('~') {
        Some(re) => CookiePattern::Regex(regex::Regex::new(&format!("(?i){}", pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?),
        None => CookiePattern::Text(Template::parse(&args[0])?),
    };
    let flag = |f: &String| Template::parse(f).and_then(|t| if t.0.iter().all(|p| matches!(p, Part::Text(_))) && !COOKIE_FLAGS.iter().any(|k| k.eq_ignore_ascii_case(f)) { Err(format!("invalid parameter \"{f}\"")) } else { Ok(t) });
    Ok(Some(CookieFlags { cookie, flags: args[1..].iter().map(flag).collect::<Result<_, _>>()? }))
}

fn cookie_rewrite(args: &[String], domain: bool) -> Result<Option<CookieRewrite>, String> {
    if args.len() == 1 { return if args[0] == "off" { Ok(None) } else { Err(format!("invalid parameter \"{}\"", args[0])) }; }
    let dot = |s: &str| Template::parse(if domain { s.strip_prefix('.').unwrap_or(s) } else { s });
    let Some(re) = args[0].strip_prefix('~') else { return Ok(Some(CookieRewrite { pattern: CookiePattern::Text(dot(&args[0])?), replacement: dot(&args[1])? })) };
    let (caseless, re) = if domain { (true, re) } else { re.strip_prefix('*').map_or((false, re), |re| (true, re)) };
    let regex = regex::Regex::new(&format!("{}{}", if caseless { "(?i)" } else { "" }, pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?;
    Ok(Some(CookieRewrite { pattern: CookiePattern::Regex(regex), replacement: Template::parse(&args[1])? }))
}

fn size_value(s: &str) -> Result<Template, String> {
    let t = Template::parse(s)?;
    if t.0.iter().all(|p| matches!(p, Part::Text(_))) { size(s)?; }
    Ok(t)
}

/// Products wrap around as nginx's do.
fn check_proxy_buffers(l: &Level) -> Result<(), String> {
    let (first, (count, size)) = (l.proxy_buffer_size, l.proxy_buffers);
    let largest = first.max(size);
    let busy = l.proxy_busy_buffers_size.unwrap_or(2 * largest);
    let least = |name| format!("\"{name}\" must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\"");
    if count < 2 { return Err("there must be at least 2 \"proxy_buffers\"".into()); }
    if busy < largest { return Err(least("proxy_busy_buffers_size")); }
    if busy > (count - 1).wrapping_mul(size) { return Err("\"proxy_busy_buffers_size\" must be less than the size of all \"proxy_buffers\" minus one buffer".into()); }
    if l.proxy_temp_file_write_size.is_some_and(|n| n < largest) { return Err(least("proxy_temp_file_write_size")); }
    if l.proxy_max_temp_file_size != 0 && l.proxy_max_temp_file_size < largest { return Err("\"proxy_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\"".into()); }
    Ok(())
}

fn cache_path(args: &[String]) -> Result<((String, u64), Vec<usize>), String> {
    let (mut zone, mut levels) = (None, Vec::new());
    for a in args {
        let Some((name, value)) = a.split_once('=') else { return Err(format!("invalid parameter \"{a}\"")) };
        let ok = match name {
            "levels" => {
                let parsed: Option<Vec<usize>> = if value.is_empty() { Some(Vec::new()) } else { value.split(':').map(|l| matches!(l, "1" | "2").then(|| l.parse().unwrap())).collect() };
                levels = parsed.filter(|l| l.len() <= 3).ok_or_else(|| format!("invalid \"levels\" \"{a}\""))?;
                true
            }
            "use_temp_path" => matches!(value, "on" | "off"),
            "keys_zone" => {
                let (n, s) = value.split_once(':').ok_or_else(|| format!("invalid keys zone size \"{a}\""))?;
                let s = size(s).map_err(|_| format!("invalid keys zone size \"{a}\""))?;
                if s < 2 * page_size() { return Err(format!("keys zone \"{a}\" is too small")); }
                zone = Some((n.to_string(), s)).filter(|z| !z.0.is_empty());
                true
            }
            "inactive" => crate::expires::parse_time(value).is_some(),
            "max_size" | "min_free" => offset(value).is_ok(),
            _ if ["loader_files", "loader_sleep", "loader_threshold", "manager_files", "manager_sleep", "manager_threshold"].contains(&name) => if name.ends_with("files") { value.parse::<u32>().is_ok() } else { millis(value).is_ok() },
            _ => return Err(format!("invalid parameter \"{a}\"")),
        };
        if !ok { return Err(format!("invalid {name} value \"{a}\"")); }
    }
    Ok((zone.ok_or("\"proxy_cache_path\" must have \"keys_zone\" parameter")?, levels))
}

fn temp_levels(args: &[String]) -> Option<Vec<usize>> {
    let levels: Vec<usize> = args.iter().map(|a| a.parse().ok().filter(|&n| n > 0 && a.bytes().all(|c| c.is_ascii_digit()))).collect::<Option<_>>()?;
    (levels.iter().sum::<usize>() <= 10).then_some(levels)
}

fn page_size() -> u64 {
    // SAFETY: sysconf only reads a value of the system.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn certified(servers: &[Server], at: &[&str]) -> Result<(), String> {
    let has = |s: &Server| !s.level.ssl_certificate.is_empty();
    for addr in servers.iter().flat_map(|s| &s.ssl) {
        let on: Vec<usize> = (0..servers.len()).filter(|&i| servers[i].listen.contains(addr)).collect();
        let default = on.iter().copied().find(|&i| servers[i].defaults.contains(addr)).unwrap_or(on[0]);
        let missing = if has(&servers[default]) { None } else if !servers[default].level.ssl_reject_handshake { Some(default) } else { on.into_iter().find(|&i| !has(&servers[i]) && !servers[i].level.ssl_reject_handshake) };
        if let Some(i) = missing { return Err(format!("no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in {}", at[i])) }
    }
    Ok(())
}

pub fn size(s: &str) -> Result<u64, String> {
    scaled(s, &[("", 1), ("k", 1 << 10), ("K", 1 << 10), ("m", 1 << 20), ("M", 1 << 20)])
}

fn offset(s: &str) -> Result<u64, String> {
    scaled(s, &[("", 1), ("k", 1 << 10), ("K", 1 << 10), ("m", 1 << 20), ("M", 1 << 20), ("g", 1 << 30), ("G", 1 << 30)])
}

fn scaled(s: &str, units: &[(&str, u64)]) -> Result<u64, String> {
    let (digits, unit) = s.find(|c: char| !c.is_ascii_digit()).map_or((s, ""), |i| s.split_at(i));
    let scale = units.iter().find(|u| u.0 == unit);
    digits.parse::<u64>().ok().zip(scale).and_then(|(n, (_, scale))| n.checked_mul(*scale)).filter(|&n| n <= i64::MAX as u64).ok_or_else(|| format!("\"{s}\" is invalid"))
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum Inherit { #[default] On, Off, Merge }

fn inherited<T>(how: Inherit, around: Vec<T>, own: Option<Vec<T>>) -> Vec<T> {
    match (how, own) {
        (Inherit::On, None) => around,
        (Inherit::Merge, own) => around.into_iter().chain(own.unwrap_or_default()).collect(),
        (_, own) => own.unwrap_or_default(),
    }
}

fn add_header(args: &[String]) -> Result<(String, Template, bool), String> {
    if let Some(a) = args.get(2).filter(|a| *a != "always") { return Err(format!("invalid parameter \"{a}\"")); }
    let always = args.len() > 2;
    Ok((args[0].clone(), Template::parse(&args[1])?, always))
}

fn error_page(args: &[String]) -> Result<ErrorPage, String> {
    let (url, rest) = args.split_last().unwrap();
    let (status, codes) = match rest.split_last() {
        Some((last, codes)) if last.starts_with('=') => {
            let status = if last.len() == 1 { 0 } else { last[1..].parse::<u16>().map_err(|_| format!("invalid value \"{last}\""))? };
            (Some(status), codes)
        }
        _ => (None, rest),
    };
    let codes = codes.iter().map(|c| c.parse::<u16>().ok().filter(|c| (300..=599).contains(c) && *c != 499).ok_or_else(|| format!("value \"{c}\" must be between 300 and 599")));
    let codes = codes.collect::<Result<Vec<u16>, String>>()?;
    Ok(ErrorPage { codes, status, url: Template::parse(url)? })
}

fn rewrite(args: &[String]) -> Result<Rewrite, String> {
    if args[1].is_empty() { return Err("empty replacement".into()); }
    let regex = regex::Regex::new(&args[0]).map_err(|e| format!("invalid regular expression \"{}\": {e}", args[0]))?;
    let flag = args.get(2).map_or("", |f| f.as_str());
    if !["", "last", "break", "redirect", "permanent"].contains(&flag) { return Err(format!("invalid parameter \"{flag}\"")); }
    let (url, add_args) = args[1].strip_suffix('?').map_or((args[1].as_str(), true), |u| (u, false));
    let redirect = ["http://", "https://", "$scheme"].iter().any(|p| url.starts_with(p)) || ["redirect", "permanent"].contains(&flag);
    let flag = match flag { "last" => Flag::Last, "break" => Flag::Break, _ => Flag::Next };
    Ok(Rewrite { regex, url: Template::parse(url)?, status: if args.get(2).is_some_and(|f| f == "permanent") { 301 } else { 302 }, add_args, redirect, flag })
}

fn ret(args: &[String]) -> Result<(u16, Template), String> {
    let url = |p: &str| args[0].len() > p.len() && args[0].starts_with(p) || p == "$scheme" && args[0].starts_with(p);
    if args.len() == 1 && ["http://", "https://", "$scheme"].into_iter().any(url) { return Ok((302, Template::parse(&args[0])?)); }
    let code = args[0].parse::<u16>().ok().filter(|c| *c <= 999);
    let code = code.ok_or_else(|| format!("invalid return code \"{}\"", args[0]))?;
    Ok((code, Template::parse(args.get(1).map_or("", |t| t.as_str()))?))
}

fn listen_ports(arg: &str) -> Result<Vec<SocketAddr>, String> {
    let at = arg.rfind([':', ']']).map_or(0, |i| i + 1);
    let Some((from, to)) = arg[at..].split_once('-').filter(|_| arg[at..].bytes().all(|b| b.is_ascii_digit() || b == b'-')) else {
        let addr = listen(arg)?;
        return if addr.port() == 0 { Err(format!("invalid port in \"{arg}\" of the \"listen\" directive")) } else { Ok(vec![addr]) };
    };
    let port = |p: &str| p.parse::<u16>().ok().filter(|p| *p > 0);
    let (from, to) = port(from).zip(port(to)).ok_or_else(|| format!("invalid port in \"{arg}\" of the \"listen\" directive"))?;
    let host = arg[..at].strip_suffix(':').unwrap_or(&arg[..at]);
    (from <= to).then_some(()).ok_or_else(|| format!("invalid port range in \"{arg}\" of the \"listen\" directive"))?;
    (from..=to).map(|p| listen(&if host.is_empty() { p.to_string() } else { format!("{host}:{p}") })).collect()
}

fn listen(arg: &str) -> Result<SocketAddr, String> {
    let with_port = if arg.contains(':') { arg.to_string() } else if arg.parse::<u16>().is_ok() { format!("0.0.0.0:{arg}") } else { format!("{arg}:80") };
    let addr = with_port.to_socket_addrs().ok().and_then(|mut a| a.next());
    addr.ok_or_else(|| format!("host not found in \"{arg}\" of the \"listen\" directive"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    #[test]
    fn names_of_captures() {
        assert_eq!(capture_names("^/(?<a>x)(?P<b_1>y)(?<=z)(?<1c>w)(?<d"), ["a", "b_1"]);
    }

    fn return_code(level: &Level) -> u16 {
        level.script.iter().find_map(|s| if let Op::Return(code, _) = s { Some(*code) } else { None }).unwrap()
    }

    #[test]
    fn wildcards_and_empty_strings_as_nginx_takes_them() {
        for name in ["www.*.com", "www.example.*com", "a.*.*", "*.example.*", "a*"] {
            assert!(build_text(&format!("http {{ server {{ server_name {name}; }} }}")).unwrap_err().starts_with(&format!("invalid server name or wildcard \"{name}\"")), "{name}");
        }
        for name in [".example.*", "www.example.*", "*.example.com", ".example.com", "www.example.com.", "~^a*$"] {
            assert!(build_text(&format!("http {{ server {{ server_name {name}; }} }}")).is_ok(), "{name}");
        }
        for (args, value) in [(&["($arg_a", "=", "", ")"][..], ""), (&["(", "$arg_a", "!=", "x", ")"][..], "x"), (&["($arg_a", "=", "x)"][..], "x")] {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            assert!(matches!(condition(&args), Ok(Condition::Equal(_, v, _)) if v.0.iter().map(|p| match p { Part::Text(t) => t.as_str(), _ => "?" }).collect::<String>() == value), "{args:?}");
        }
        assert!(condition(&["($arg_a".to_string(), "=)".to_string()]).is_err());
    }

    fn build_text(text: &str) -> Result<Config, String> {
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let events = if text.contains("events") { "" } else { "events { } " };
        build(&parse(&format!("{events}{text}"), Path::new("t.conf")).unwrap(), &dir)
    }

    #[test]
    fn proxy_cache_zones() {
        let c = build_text("http { proxy_cache_path c keys_zone=Z:1m; proxy_cache_valid 1m; proxy_cache_valid 404 any 2m; server { listen 127.0.0.1:8080; location / { proxy_cache Z; } location /off { proxy_cache off; proxy_cache_valid 200 0; } } }").unwrap();
        let (outer, locations) = (&c.servers[0].level, &c.servers[0].locations);
        assert!(outer.proxy_cache.is_none());
        assert_eq!(outer.proxy_cache_valid.len(), 5);
        let at = |path: &str| &locations.iter().find(|l| l.path == path).unwrap().level;
        assert!(at("/").proxy_cache.is_some());
        assert!(at("/off").proxy_cache.is_none() && at("/off").proxy_cache_valid.len() == 1);
        let c = build_text("http { proxy_cache_path c keys_zone=Z:1m; server { proxy_cache $arg_c; } }").unwrap();
        assert!(matches!(&c.servers[0].level.proxy_cache, Some(CacheZone::Named(_, zones)) if zones.contains_key("Z")));
        assert!(build_text("http { server { proxy_cache $nothing_known; } }").is_err());
        let c = build_text("http { proxy_cache_path c keys_zone=Z:1m; proxy_cache_lock on; server { listen 127.0.0.1:8080; location / { } location /off { proxy_cache_lock off; } } }").unwrap();
        assert_eq!(c.servers[0].locations.iter().map(|l| l.level.proxy_cache_lock).collect::<Vec<_>>(), [true, false]);
        assert!(build_text("http { proxy_cache_lock yes; }").is_err());
        let c = build_text("http { proxy_cache_methods get; server { listen 127.0.0.1:8080; location / { } location /post { proxy_cache_methods POST; } } }").unwrap();
        assert_eq!(c.servers[0].locations.iter().map(|l| l.level.proxy_cache_post).collect::<Vec<_>>(), [false, true]);
        assert_eq!(build_text("http { proxy_cache_methods PUT; }").unwrap_err(), "invalid value \"PUT\" in t.conf:1");
        let refused = |paths: &str| build_text(&format!("http {{ {paths} }}")).unwrap_err();
        assert_eq!(refused("proxy_cache_path c levels=3 keys_zone=A:1m;"), "invalid \"levels\" \"levels=3\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c levels=1:1:1:1 keys_zone=A:1m;"), "invalid \"levels\" \"levels=1:1:1:1\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A;"), "invalid keys zone size \"keys_zone=A\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:x;"), "invalid keys zone size \"keys_zone=A:x\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1k;"), "keys zone \"keys_zone=A:1k\" is too small in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1m inactive=x;"), "invalid inactive value \"inactive=x\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1m manager_files=x;"), "invalid manager_files value \"manager_files=x\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1m nosuch;"), "invalid parameter \"nosuch\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1m nosuch=1;"), "invalid parameter \"nosuch=1\" in t.conf:1");
        assert_eq!(refused("proxy_cache_path c keys_zone=A:1m; proxy_cache_path d keys_zone=A:1m;"), "duplicate zone \"A\" in t.conf:1");
        assert!(refused("proxy_cache_path c keys_zone=A:1m; proxy_cache_path c/ keys_zone=B:1m;").starts_with("the same path name"));
        assert!(build_text("http { proxy_cache_path c levels= keys_zone=A:1m use_temp_path=off inactive=1h max_size=1g min_free=1m loader_files=10 manager_sleep=50ms; proxy_cache_use_stale error non_idempotent; }").is_ok());
        let c = build_text("http { proxy_cache_lock_timeout 200ms; server { listen 127.0.0.1:8080; location / { } location /s { proxy_cache_lock_timeout 2s; } } server { listen 127.0.0.1:8081; } }").unwrap();
        assert_eq!(c.servers[0].locations.iter().map(|l| l.level.proxy_cache_lock_timeout).collect::<Vec<_>>(), [Duration::from_millis(200), Duration::from_secs(2)]);
        assert_eq!(build_text("http { server { listen 127.0.0.1:8080; } }").unwrap().servers[0].level.proxy_cache_lock_timeout, crate::cache::LOCK_TIMEOUT);
        assert!(build_text("http { proxy_cache_lock_timeout x; }").is_err());
        let c = build_text("http { server { listen 127.0.0.1:8080; proxy_cache_lock_age 100ms; } server { listen 127.0.0.1:8081; } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_cache_lock_age, c.servers[1].level.proxy_cache_lock_age), (Duration::from_millis(100), crate::cache::LOCK_TIMEOUT));
        assert!(build_text("http { proxy_cache_lock_age x; }").is_err());
        let c = build_text("http { proxy_cache_bypass $arg_a; proxy_cache_bypass $arg_b $arg_c; proxy_no_cache $arg_d; proxy_cache_key $uri; proxy_cache_min_uses 2; proxy_cache_use_stale error http_404; server { location / { proxy_cache_use_stale off; } } }").unwrap();
        let l = &c.servers[0].level;
        assert_eq!((l.proxy_cache_bypass.len(), l.proxy_no_cache.len(), l.proxy_cache_key.is_some(), l.proxy_cache_min_uses), (3, 1, true, 2));
        assert_eq!(l.proxy_cache_use_stale, ["error", "http_404"]);
        assert!(c.servers[0].locations[0].level.proxy_cache_use_stale.is_empty());
        assert_eq!(build_text("http { proxy_cache_use_stale http_418; }").unwrap_err(), "invalid value \"http_418\" in t.conf:1");
        let c = build_text("http { proxy_cache_convert_head off; server { location / { proxy_cache_convert_head on; } } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_cache_convert_head, c.servers[0].locations[0].level.proxy_cache_convert_head), (false, true));
        assert!(build_text("http { server { } }").unwrap().servers[0].level.proxy_cache_convert_head);
        let c = build_text("http { proxy_force_ranges on; max_ranges 2; server { location / { max_ranges 0; } } }").unwrap();
        let (server, location) = (&c.servers[0].level, &c.servers[0].locations[0].level);
        assert_eq!((server.proxy_force_ranges, server.max_ranges, location.proxy_force_ranges, location.max_ranges), (true, Some(2), true, Some(0)));
        assert!(build_text("http { max_ranges x; }").is_err());
        let c = build_text("http { proxy_cache_revalidate on; server { location / { proxy_cache_revalidate off; } } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_cache_revalidate, c.servers[0].locations[0].level.proxy_cache_revalidate), (true, false));
        assert!(!build_text("http { server { } }").unwrap().servers[0].level.proxy_cache_revalidate);
        let c = build_text("http { proxy_cache_background_update on; proxy_ignore_headers Expires Set-Cookie; proxy_ignore_headers X-Accel-Expires; server { location / { proxy_ignore_headers vary; } } }").unwrap();
        let (http, l) = (&c.servers[0].level, &c.servers[0].locations[0].level);
        assert_eq!((http.proxy_cache_background_update, http.proxy_ignore_headers.clone()), (true, vec!["expires".to_string(), "set-cookie".into(), "x-accel-expires".into()]));
        assert_eq!(l.proxy_ignore_headers, ["vary"]);
        assert!(build_text("http { proxy_ignore_headers Server; }").unwrap_err().starts_with("invalid value \"Server\" in "));
        assert!(build_text("http { proxy_cache_min_uses x; }").is_err());
        let c = build_text("http { proxy_cache_max_range_offset 1k; server { location / { } } server { location / { proxy_cache_max_range_offset 0; } } }").unwrap();
        let max = |i: usize| c.servers[i].locations[0].level.proxy_cache_max_range_offset;
        assert_eq!((max(0), max(1), Level::default().proxy_cache_max_range_offset), (Some(1024), Some(0), None));
        assert!(build_text("http { proxy_cache_max_range_offset x; }").is_err());
        assert_eq!(build_text("http { server { proxy_cache Z; } }").unwrap_err(), "\"proxy_cache\" zone \"Z\" is unknown in t.conf:1");
        assert_eq!(build_text("http { proxy_cache_path c levels=1; }").unwrap_err(), "\"proxy_cache_path\" must have \"keys_zone\" parameter in t.conf:1");
    }

    #[test]
    fn listen_backlog() {
        let c = build_text("events {} http { server { listen 127.0.0.1:8080 backlog=1024; } server { listen 127.0.0.1:8081; } }").unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(c.servers[0].backlogs, vec![(addr, 1024)]);
        assert!(c.servers[1].backlogs.is_empty());
        for bad in ["x", "0"] {
            let e = build_text(&format!("events {{}} http {{ server {{ listen 127.0.0.1:8080 backlog={bad}; }} }}")).unwrap_err();
            assert!(e.starts_with(&format!("invalid backlog \"{bad}\" in ")), "{e}");
        }
    }

    #[test]
    fn listen_ipv6only() {
        let c = build_text("events {} http { server { listen [::]:8080 ipv6only=off; listen [::]:8081 ipv6only=on; listen [::]:8082; } }").unwrap();
        assert_eq!(c.servers[0].ipv6only_off, vec!["[::]:8080".parse::<SocketAddr>().unwrap()]);
        for (bad, e) in [("ox", "invalid ipv6only flags \"ox\" in "), ("x", "invalid parameter \"ipv6only=x\" in ")] {
            assert!(build_text(&format!("events {{}} http {{ server {{ listen [::]:8080 ipv6only={bad}; }} }}")).unwrap_err().starts_with(e));
        }
    }

    #[test]
    fn listen_http2() {
        let c = build_text("events {} http { server { listen 127.0.0.1:8080 http2; } server { listen 127.0.0.1:8081; http2 on; } server { listen 127.0.0.1:8082; } }").unwrap();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(c.servers[0].http2, [addr]);
        assert!(!c.servers[0].level.http2);
        assert!(c.servers[1].http2.is_empty() && c.servers[1].level.http2);
        assert!(c.servers[2].http2.is_empty() && !c.servers[2].level.http2);
    }

    #[test]
    fn hosts_and_ports() {
        assert_eq!(host_port("a:81", 80), Some(("a", 81)));
        assert_eq!(host_port("a", 80), Some(("a", 80)));
        assert_eq!(host_port("[::1]:81", 80), Some(("::1", 81)));
        assert_eq!(host_port("[::1]", 80), Some(("::1", 80)));
        assert_eq!(host_port("a:x", 80), None);
    }

    #[test]
    fn resolves_names_ipv4_first() {
        assert_eq!(addresses("127.0.0.2", 81), ["127.0.0.2:81".parse().unwrap()]);
        assert_eq!(addresses("::1", 81), ["[::1]:81".parse().unwrap()]);
        let local = addresses("localhost", 82);
        assert!(local.contains(&"127.0.0.1:82".parse().unwrap()));
        assert!(local.windows(2).all(|w| w[0].is_ipv4() || w[1].is_ipv6()));
        assert_eq!(addresses("a\0b", 80), []);
        assert_eq!(addresses("no-such-host.invalid", 80), []);
    }

    #[test]
    fn implicit_upstreams() {
        let conf = build_text("http { server { listen 127.0.0.1:8080; location /a { proxy_pass http://$arg_h/; } location /b { proxy_pass http://LocalHost:8081/b; } location /c { proxy_pass http://localhost:8081/c; } } }").unwrap();
        let proxy = |i: usize| conf.servers[0].locations[i].level.proxy.clone().unwrap();
        assert!(Arc::ptr_eq(&proxy(1).upstream, &proxy(2).upstream));
        assert!(Arc::ptr_eq(&proxy(0).implicit.lock().unwrap()["localhost:8081"], &proxy(1).upstream));
        assert!(build_text("http { server { location / { proxy_pass http://no-such-host.invalid; } } }").unwrap_err().starts_with("host not found in upstream \"no-such-host.invalid\""));
    }

    #[test]
    fn listen_port_ranges() {
        let addrs = |a: &str| listen_ports(a).map(|v| v.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        assert_eq!(addrs("127.0.0.1:81-83").unwrap(), ["127.0.0.1:81", "127.0.0.1:82", "127.0.0.1:83"]);
        assert_eq!(addrs("[::1]:81-82").unwrap(), ["[::1]:81", "[::1]:82"]);
        assert_eq!(addrs("81-81").unwrap(), ["0.0.0.0:81"]);
        assert_eq!(addrs("[::1]:81").unwrap(), ["[::1]:81"]);
        assert_eq!(addrs("127.0.0.1:0-1").unwrap_err(), "invalid port in \"127.0.0.1:0-1\" of the \"listen\" directive");
        assert_eq!(addrs("127.0.0.1:82-81").unwrap_err(), "invalid port range in \"127.0.0.1:82-81\" of the \"listen\" directive");
    }

    #[test]
    fn proxy_request_buffering() {
        let c = build_text("http { proxy_request_buffering off; server { location /a { } location /b { proxy_request_buffering on; } } }").unwrap();
        let on: Vec<_> = c.servers[0].locations.iter().map(|l| l.level.proxy_request_buffering).collect();
        assert_eq!(on, [false, true]);
        assert!(build_text("http { proxy_request_buffering 1; }").is_err());
        let c = build_text("http { proxy_http_version 1.1; server { location /a { proxy_http_version 1.0; } location /b { } } }").unwrap();
        let v: Vec<_> = c.servers[0].locations.iter().map(|l| l.level.proxy_http_11).collect();
        assert_eq!(v, [false, true]);
        let c = build_text("http { proxy_http_version 2; server { location /a { proxy_http_version 1.1; } location /b { } } }").unwrap();
        let v: Vec<_> = c.servers[0].locations.iter().map(|l| (l.level.proxy_http_11, l.level.proxy_h2)).collect();
        assert_eq!(v, [(true, false), (true, true)]);
        let c = build_text("http { proxy_pass_trailers on; server { location /a { proxy_pass_trailers off; } location /b { } } }").unwrap();
        let v: Vec<_> = c.servers[0].locations.iter().map(|l| l.level.proxy_pass_trailers).collect();
        assert_eq!(v, [false, true]);
        assert!(build_text("http { proxy_http_version 3; }").unwrap_err().starts_with("invalid value \"3\" in \"proxy_http_version\" directive, it must be \"1.0\", \"1.1\" or \"2\""));
    }

    #[test]
    fn return_with_a_url_alone() {
        let c = build_text("http { server { location /a { return http://e/$uri; } location /b { return https://e; } } }").unwrap();
        let ret: Vec<_> = c.servers[0].locations.iter().map(|l| return_code(&l.level)).collect();
        assert_eq!(ret, [302, 302]);
        assert!(build_text("http { server { location /a { return http://; } } }").unwrap_err().starts_with("invalid return code \"http://\""));
    }

    #[test]
    fn post_action_inherits_and_turns_off() {
        let c = build_text("http { post_action /p; server { location /a { } location /b { post_action off; } location /c { post_action @n; } } }").unwrap();
        let actions: Vec<_> = c.servers[0].locations.iter().map(|l| l.level.post_action.as_deref()).collect();
        assert_eq!(actions, [Some("/p"), None, Some("@n")]);
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
        assert_eq!(s.locations[0].level.access_log[0].format.line.0.len(), 3);
        assert_eq!(return_code(&s.locations[0].level), 200);
        assert_eq!(s.locations[1].level.access_log[0].format.line.0.len(), 16);
    }

    #[test]
    fn chunked_transfer_encoding() {
        let c = build_text("http { server { location /a { chunked_transfer_encoding off; } location /b { } } }").unwrap();
        let l = &c.servers[0].locations;
        assert_eq!((l[0].level.chunked, l[1].level.chunked), (false, true));
        assert!(build_text("http { chunked_transfer_encoding x; }").is_err());
    }

    #[test]
    fn working_directory_and_alert_logs() {
        let c = build_text("working_directory wd; error_log a.log; error_log b.log emerg; error_log c.log alert; http { }").unwrap();
        assert_eq!(c.working_directory, Some(PathBuf::from("wd")));
        assert_eq!((c.alert_logs.len(), c.notice_logs.len()), (2, 1));
        assert_eq!(build_text("ssl_object_cache_inheritable x;").unwrap_err(), "invalid value \"x\" in \"ssl_object_cache_inheritable\" directive, it must be \"on\" or \"off\" in t.conf:1");
        assert_eq!(build_text("http { }").unwrap().working_directory, None);
        assert!(build_text("working_directory;").is_err());
        assert!(build_text("http { working_directory wd; }").is_err());
    }

    #[test]
    fn inherits_and_overrides_error_log() {
        let c = build_text("http { server { location /a { error_log a2.log; error_log b2.log info; } location /b { } } } error_log m.log; error_log n.log warn;").unwrap();
        let logs = |l: usize| c.servers[0].locations[l].level.error_log.iter().map(|e| e.1).collect::<Vec<_>>();
        assert_eq!((logs(0), logs(1)), (vec![4, 1], vec![4, 3]));
        assert!(build_text("http { } error_log;").is_err());
    }

    #[test]
    fn worker_rlimit_nofile() {
        assert_eq!(build_text("worker_rlimit_nofile 32; http { }").unwrap().rlimit_nofile, Some(32));
        assert_eq!(build_text("http { }").unwrap().rlimit_nofile, None);
        assert_eq!(build_text("worker_rlimit_nofile x;").unwrap_err(), "invalid number in t.conf:1");
    }

    #[test]
    fn user() {
        // SAFETY: geteuid() always succeeds.
        if unsafe { libc::geteuid() } == 0 { return }
        let c = build_text("user nobody;\nuser nosuchuser nosuchgroup; http { }").unwrap();
        let warning = "the \"user\" directive makes sense only if the master process runs with super-user privileges, ignored in t.conf:";
        assert_eq!(c.warnings, [format!("{warning}1"), format!("{warning}2")]);
        assert!(c.user.is_none());
        assert!(build_text("http { }").unwrap().user.is_none());
    }

    #[test]
    fn default_user() {
        let u = super::default_user().unwrap();
        // SAFETY: as in account().
        let nobody = unsafe { &*libc::getpwnam(c"nobody".as_ptr()) };
        assert_eq!((u.name.as_c_str(), u.uid), (c"nobody", nobody.pw_uid));
        assert_eq!(account("nosuchuser", "nogroup", "").unwrap_err(), "getpwnam(\"nosuchuser\") failed");
        assert_eq!(account("nobody", "nosuchgroup", "").unwrap_err(), "getgrnam(\"nosuchgroup\") failed");
    }

    #[test]
    fn worker_processes() {
        assert_eq!(build_text("worker_processes 2; events { }").unwrap().workers, 2);
        assert!(build_text("worker_processes auto; events { }").unwrap().workers >= 1);
        assert_eq!(build_text("worker_processes x;").unwrap_err(), "invalid value \"x\" in \"worker_processes\" directive in t.conf:1");
    }

    #[test]
    fn worker_connections() {
        assert_eq!(build_text("events { worker_connections 3; } http { server { listen 127.0.0.1:1; } server { listen 127.0.0.1:2; } }").unwrap().connections, 3);
        assert_eq!(build_text("events { worker_connections 2; } http { server { listen 127.0.0.1:1; } server { listen 127.0.0.1:2; } }").unwrap_err(), "2 worker_connections are not enough for 2 listening sockets");
        assert_eq!(build_text("events { worker_connections 0; }").unwrap_err(), "0 worker_connections are not enough for 0 listening sockets");
        assert_eq!(build_text("events { worker_connections -1; }").unwrap_err(), "invalid number \"-1\" in t.conf:1");
        assert_eq!(build_text("events { worker_connections 1; worker_connections 1; }").unwrap_err(), "\"worker_connections\" directive is duplicate in t.conf:1");
        assert_eq!(build_text("http { }").unwrap().connections, 512);
    }

    #[test]
    fn shared_session_caches() {
        let c = build_text("http { server { ssl_session_cache builtin shared:SSL:1m; } server { ssl_session_cache builtin; } server { ssl_session_cache none; } }").unwrap();
        assert_eq!(c.servers.iter().map(|s| s.level.ssl_sessions.zone.is_some()).collect::<Vec<_>>(), [true, false, false]);
    }

    #[test]
    fn worker_shutdown_timeout() {
        assert_eq!(build_text("worker_shutdown_timeout 10ms; http { }").unwrap().shutdown_timeout, Some(Duration::from_millis(10)));
        assert_eq!(build_text("worker_shutdown_timeout x;").unwrap_err(), "invalid value in t.conf:1");
    }

    #[test]
    fn body_files_and_no_limit() {
        let c = build_text("http { server { client_max_body_size 0; client_body_in_file_only clean; client_body_temp_path /t 1 2; } }").unwrap();
        let l = &c.servers[0].level;
        assert_eq!((l.max_body, l.body_in_file_only, l.body_clean, l.body_temp_levels.as_slice()), (u64::MAX, true, true, &[1, 2][..]));
        assert_eq!(build_text("http { client_body_in_file_only yes; }").unwrap_err(), "invalid value \"yes\" in t.conf:1");
        assert_eq!(build_text("http { client_body_temp_path /t 0; }").unwrap_err(), "invalid value in t.conf:1");
        assert_eq!(build_text("http { client_body_temp_path /t 5 6; }").unwrap_err(), "invalid value in t.conf:1");
    }

    #[test]
    fn headers_inherited() {
        let c = build_text(
            "http { add_header A a; add_trailer T t; server { \
             location /m { add_header_inherit merge; add_header B b; add_trailer U u; } \
             location /o { add_header_inherit off; add_trailer_inherit merge; } location /n { add_header B b; } } }",
        )
        .unwrap();
        let names = |l: &Level| (l.add_header.iter().map(|h| h.0.as_str()).collect::<Vec<_>>().join(""), l.add_trailer.iter().map(|h| h.0.as_str()).collect::<Vec<_>>().join(""));
        let [m, o, n] = [0, 1, 2].map(|i| names(&c.servers[0].locations[i].level));
        assert_eq!((m.0.as_str(), m.1.as_str(), o.0.as_str(), o.1.as_str(), n.0.as_str(), n.1.as_str()), ("AB", "U", "", "T", "B", "T"));
        assert_eq!(c.servers[0].locations[0].level.add_inherit, [Inherit::Merge, Inherit::On]);
        assert_eq!(build_text("http { add_header_inherit yes; }").unwrap_err(), "invalid value \"yes\" in \"add_header_inherit\" directive, it must be \"on\", \"off\" or \"merge\" in t.conf:1");
    }

    #[test]
    fn proxy_upstream_and_body_settings() {
        let c = build_text(
            "http { upstream u { server 127.0.0.1:8082 backup; server 127.0.0.1:8081 weight=2; } \
             client_max_body_size 1k; server { listen 127.0.0.1:8080; add_header X a; add_trailer T b; \
             location /a { add_trailer U c always; proxy_pass http://u/x; client_body_buffer_size 2k; client_body_in_file_only on; } \
             location /b { proxy_pass http://127.0.0.1:8083; error_page 404 =301 http://e/; } } }",
        )
        .unwrap();
        let (a, b) = (&c.servers[0].locations[0].level, &c.servers[0].locations[1].level);
        let p = a.proxy.as_ref().unwrap();
        assert_eq!((p.host.as_str(), p.uri.as_deref()), ("u", Some("/x")));
        let addrs: Vec<String> = p.upstream.peers.iter().map(|p| format!("{} {} {}", p.addr, p.weight, p.backup)).collect();
        assert_eq!(addrs, vec!["127.0.0.1:8082 1 true", "127.0.0.1:8081 2 false"]);
        assert_eq!((a.max_body, a.body_buffer, a.body_in_file_only, a.body_clean), (1024, 2048, true, false));
        assert_eq!(a.add_header[0].0, "X");
        assert_eq!((a.add_trailer[0].0.as_str(), a.add_trailer[0].2, b.add_trailer[0].0.as_str()), ("U", true, "T"));
        assert_eq!(b.proxy.as_ref().unwrap().host, "127.0.0.1:8083");
        assert_eq!((b.error_page[0].codes.clone(), b.error_page[0].status), (vec![404], Some(301)));
        assert_eq!(b.body_buffer, 16384);
        let e = build_text("http { server { expires modified 1h; location / { expires $arg_e; } } }").unwrap();
        assert!(e.servers[0].level.expires.is_some() && e.servers[0].locations[0].level.expires.is_some());
        let e = build_text("http { expires bad; }").unwrap_err();
        assert_eq!(e, "invalid value \"bad\" in t.conf:1");
    }

    #[test]
    fn max_headers() {
        let c = build_text("http { max_headers 5; server { } server { max_headers 7; } }").unwrap();
        assert_eq!((c.servers[0].level.max_headers, c.servers[1].level.max_headers), (5, 7));
        assert_eq!(build_text("http { server { } }").unwrap().servers[0].level.max_headers, 1000);
        assert_eq!(build_text("http { max_headers x; }").unwrap_err(), "invalid number in t.conf:1");
    }

    #[test]
    fn proxy_busy_buffers_size() {
        assert_eq!(build_text("http { proxy_busy_buffers_size 20k; server { } }").unwrap().servers[0].level.proxy_busy_buffers_size, Some(20480));
        assert!(build_text("http { proxy_busy_buffers_size x; server { } }").is_err());
    }

    #[test]
    fn early_hints() {
        let c = build_text("http { early_hints $uri 1; server { location / { } location /off { early_hints 0; } } }").unwrap();
        let [on, off] = [0, 1].map(|i| c.servers[0].locations[i].level.early_hints.len());
        assert_eq!((on, off), (2, 1));
        assert!(build_text("http { server { early_hints; } }").is_err());
    }

    #[test]
    fn proxy_hide_header_inherits_as_a_whole() {
        let c = build_text("http { proxy_hide_header X-A; server { location /a { proxy_hide_header X-B; proxy_hide_header x-c; } location /b { } } }").unwrap();
        let (a, b) = (&c.servers[0].locations[0].level, &c.servers[0].locations[1].level);
        assert_eq!((a.proxy_hide_header.clone(), b.proxy_hide_header.clone()), (vec!["x-b".to_string(), "x-c".into()], vec!["x-a".to_string()]));
    }

    #[test]
    fn proxy_pass_header_inherits_as_a_whole() {
        let c = build_text("http { proxy_pass_header Date; server { location /a { proxy_pass_header X-Pad; proxy_pass_header server; } location /b { proxy_hide_header X-B; } } }").unwrap();
        let (a, b) = (&c.servers[0].locations[0].level, &c.servers[0].locations[1].level);
        assert_eq!((a.proxy_pass_header.clone(), b.proxy_pass_header.clone()), (vec!["x-pad".to_string(), "server".into()], vec!["date".to_string()]));
    }

    #[test]
    fn locations_and_peers() {
        assert!(matches!(location(&["=".into(), "/".into()]).unwrap().0, Match::Exact));
        assert!(matches!(location(&["^~".into(), "/i/".into()]).unwrap().0, Match::NoRegex));
        assert!(matches!(location(&["/".into()]).unwrap().0, Match::Prefix));
        let Match::Regex(re) = location(&["~*".into(), "\\.GIF$".into()]).unwrap().0 else { panic!() };
        assert!(re.is_match(b"/a.gif") && re.is_match(b"/a.gif\n") && !re.is_match(b"/a.gif\n\n"));
        let re = bytes_regex("^/[$]a.b$", false).unwrap();
        assert!(re.is_match(b"/$a\xffb") && !re.is_match("/$a\u{e9}b".as_bytes()));
        assert!(bytes_regex("^/[]$]$", false).unwrap().is_match(b"/$\n") && bytes_regex("^/[^]]\\$", false).unwrap().is_match(b"/a$"));
        assert_eq!(location(&["!".into(), "/".into()]).unwrap_err(), "invalid location modifier \"!\"");
        assert!(location(&["~".into(), "(".into()]).is_err());
        let p = peer(&["127.0.0.1:1".into(), "max_fails=3".into(), "fail_timeout=5s".into()]).unwrap();
        assert_eq!((p.max_fails, p.fail_timeout, p.weight, p.backup), (3, 5, 1, false));
        assert!(peer(&["127.0.0.1:1".into(), "down".into()]).unwrap().down);
        assert_eq!(peer(&["127.0.0.1:1".into(), "up".into()]).unwrap_err(), "invalid parameter \"up\"");
        assert_eq!(peer(&["127.0.0.1:1".into(), "max_conns=2".into()]).unwrap().max_conns, 2);
        assert_eq!(peer(&["unix:/a.sock".into()]).unwrap().addr.to_string(), "unix:/a.sock");
        let c = build_text("http { server { location /a { proxy_pass http://unix:/a.sock; } location /b { proxy_pass http://unix:/b.sock:/u/; } } }").unwrap();
        let p = |i: usize| c.servers[0].locations[i].level.proxy.clone().unwrap();
        assert_eq!((p(0).host.as_str(), p(0).uri.clone(), p(0).upstream.peers[0].addr.to_string()), ("localhost", None, "unix:/a.sock".into()));
        assert_eq!((p(1).uri.as_deref(), p(1).upstream.peers[0].addr.to_string()), (Some("/u/"), "unix:/b.sock".into()));
        assert!(build_text("http { server { location / { proxy_pass $arg_u; } } }").unwrap().servers[0].locations[0].level.proxy.as_ref().unwrap().url.is_some());
    }

    #[test]
    fn upstream_keepalive_settings() {
        let keepalive = |block: &str| {
            let c = build_text(&format!("http {{ upstream u {{ server 127.0.0.1:8081; {block} }} server {{ location / {{ proxy_pass http://u; }} }} }}"))?;
            let up = c.servers[0].locations[0].level.proxy.as_ref().unwrap().upstream.clone();
            assert_eq!(up.peers.len(), 1);
            Ok::<_, String>(up.keepalive.clone())
        };
        let (requests, time, timeout) = (1000, Duration::from_secs(3600), Duration::from_secs(60));
        assert_eq!(keepalive(""), Ok(Some(Keepalive { max: 32, local: true, requests, time, timeout })));
        assert_eq!(keepalive("keepalive 0;"), Ok(None));
        assert_eq!(keepalive("keepalive 5;"), Ok(Some(Keepalive { max: 5, local: false, requests, time, timeout })));
        assert_eq!(keepalive("keepalive 5 local;"), Ok(Some(Keepalive { max: 5, local: true, requests, time, timeout })));
        let set = Keepalive { requests: 2, time: Duration::from_secs(60), timeout: Duration::from_millis(500), ..Keepalive::default() };
        assert_eq!(keepalive("keepalive_requests 2; keepalive_time 1m; keepalive_timeout 500ms;"), Ok(Some(set)));
        for (block, error) in [
            ("keepalive x;", "invalid value \"x\" in \"keepalive\" directive"),
            ("keepalive -1;", "invalid value \"-1\" in \"keepalive\" directive"),
            ("keepalive 5 x;", "invalid parameter \"x\""),
            ("keepalive 5; keepalive 5;", "\"keepalive\" directive is duplicate"),
            ("keepalive_requests 2; keepalive_requests 2;", "\"keepalive_requests\" directive is duplicate"),
            ("keepalive_time 1s; keepalive_time 1s;", "\"keepalive_time\" directive is duplicate"),
            ("keepalive_timeout 1s; keepalive_timeout 1s;", "\"keepalive_timeout\" directive is duplicate"),
            ("keepalive_requests x;", "\"keepalive_requests\" directive invalid number"),
            ("keepalive_time x;", "\"keepalive_time\" directive invalid value"),
            ("keepalive_timeout x;", "\"keepalive_timeout\" directive invalid value"),
        ] {
            assert_eq!(keepalive(block), Err(format!("{error} in t.conf:1")));
        }
        let c = build_text("http { server { location / { proxy_pass http://127.0.0.1:8081; } } }").unwrap();
        assert_eq!(c.servers[0].locations[0].level.proxy.as_ref().unwrap().upstream.keepalive, None);
    }

    #[test]
    fn balancing_methods() {
        let up = |block: &str| {
            let c = build_text(&format!("http {{ upstream u {{ server 127.0.0.1:8081; {block} }} server {{ location / {{ proxy_pass http://u; }} }} }}")).unwrap();
            let up = c.servers[0].locations[0].level.proxy.as_ref().unwrap().upstream.clone();
            (up.balance, up.keepalive.is_some())
        };
        assert_eq!(up("keepalive 0;"), (Balance::RoundRobin, false));
        assert_eq!(up("ip_hash; keepalive 2;"), (Balance::IpHash, true));
        assert_eq!(up("least_conn; keepalive 2;"), (Balance::LeastConn, true));
        assert_eq!(up("keepalive 2; ip_hash;"), (Balance::IpHash, true));
        assert_eq!(up("ip_hash; least_conn; keepalive 0;"), (Balance::LeastConn, false));
        assert_eq!(build_text("http { upstream u { server 127.0.0.1:1; ip_hash x; } }").unwrap_err(), "invalid number of arguments in \"ip_hash\" directive in t.conf:1");
        assert!(build_text("http { ip_hash; }").is_err());
    }

    #[test]
    fn proxy_socket_options() {
        let c = build_text("http { proxy_socket_keepalive on; proxy_ignore_client_abort on; proxy_ssl_protocols TLSv1.2; server { location /a { proxy_socket_keepalive off; proxy_ssl_protocols TLSv1 TLSv1.3; } location /b { } } }").unwrap();
        let l = &c.servers[0].locations;
        let of = |l: &Location| (l.level.proxy_socket_keepalive, l.level.proxy_ignore_client_abort, l.level.proxy_ssl_protocols);
        assert_eq!((of(&l[0]), of(&l[1])), ((false, true, [false, true]), (true, true, [true, false])));
        assert_eq!(build_text("http { proxy_ssl_protocols TLSv2; }").unwrap_err(), "invalid value \"TLSv2\" in t.conf:1");
        assert!(build_text("http { proxy_socket_keepalive yes; }").is_err());
    }

    #[test]
    fn checks_proxy_buffers() {
        assert!(build_text("http { server { proxy_buffer_size 128; proxy_buffers 4 128; location / { proxy_buffers 8 4k; } } }").is_ok());
        for v in ["0 4k", "x 4k", "+4 4k", "4 0", "4 x"] {
            assert_eq!(build_text(&format!("http {{ proxy_buffers {v}; }}")).unwrap_err(), "\"proxy_buffers\" directive invalid value in t.conf:1");
        }
    }

    #[test]
    fn checks_proxy_buffering() {
        assert!(build_text("http { server { location / { proxy_buffer_size 512; proxy_buffering off; } } }").is_ok());
        let c = build_text("http { server { location /a { proxy_buffer_size 8k; } location /b { } } }").unwrap();
        assert_eq!(c.servers[0].locations.iter().map(|l| (l.level.proxy_buffer_size, l.level.proxy_http_11)).collect::<Vec<_>>(), [(8192, true), (4096, true)]);
        for name in ["proxy_buffer_size", "proxy_busy_buffers_size", "proxy_temp_file_write_size", "proxy_max_temp_file_size"] {
            for v in ["5x", "1g", "-1", "''"] { assert_eq!(build_text(&format!("http {{ {name} {v}; }}")).unwrap_err(), format!("\"{name}\" directive invalid value in t.conf:1")); }
        }
        assert!(build_text("http { proxy_max_temp_file_size 0; server { proxy_max_temp_file_size 4k; } }").is_ok());
        assert!(build_text("http { proxy_buffering of; }").is_err());
        assert!(build_text("http { proxy_ignore_client_abort on; server { location / { proxy_ignore_client_abort off; } } }").is_ok());
        assert!(build_text("http { proxy_ignore_client_abort yes; }").is_err());
        let c = build_text("http { proxy_buffers 4 8k; server { location /a { proxy_buffering off; proxy_busy_buffers_size 16k; } location /b { proxy_buffers 16 2k; } location /c { proxy_buffering on; } } }").unwrap();
        let settings: Vec<_> = c.servers[0].locations.iter().map(|l| (l.level.proxy_buffering, l.level.proxy_buffers, l.level.proxy_busy_buffers_size)).collect();
        assert_eq!(settings, [(false, (4, 8192), Some(16384)), (true, (16, 2048), None), (true, (4, 8192), None)]);
        let c = build_text("http { server { location / { } } }").unwrap();
        assert_eq!((c.servers[0].locations[0].level.proxy_buffering, c.servers[0].locations[0].level.proxy_buffers), (true, (8, 4096)));
    }

    #[test]
    fn proxy_temp_files() {
        let c = build_text("http { server { location / { } } server { proxy_temp_path /t; proxy_max_temp_file_size 0; proxy_temp_file_write_size 8k; location / { } location /b { proxy_temp_path u 2 1; } } }").unwrap();
        let settings = |l: &Level| (l.proxy_temp_path.clone(), l.proxy_temp_levels.clone(), l.proxy_max_temp_file_size, l.proxy_temp_file_write_size);
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        assert_eq!(settings(&c.servers[0].locations[0].level), (dir.join("proxy_temp"), vec![1, 2], 1 << 30, None));
        assert_eq!(settings(&c.servers[1].locations[0].level), ("/t".into(), vec![], 0, Some(8192)));
        assert_eq!(settings(&c.servers[1].locations[1].level), (dir.join("u"), vec![2, 1], 0, Some(8192)));
        for v in ["0", "x", "5 6"] {
            assert_eq!(build_text(&format!("http {{ proxy_temp_path /t {v}; }}")).unwrap_err(), "\"proxy_temp_path\" directive invalid value in t.conf:1");
        }
    }

    #[test]
    fn directories_of_temporary_files() {
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        for (http, want) in [
            ("", &[][..]),
            ("server { }", &["client_body_temp", "proxy_temp"]),
            ("server { location / { client_body_temp_path a; } }", &["a", "client_body_temp", "proxy_temp"]),
            ("server { client_body_temp_path a/; proxy_temp_path a; }", &["a"]),
            ("server { client_body_temp_path a; proxy_temp_path b 1; } server { proxy_temp_path /c/; }", &["a", "b", "/c/", "client_body_temp"]),
            ("client_body_temp_path a; proxy_temp_path b; server { client_body_temp_path c; location / { client_body_temp_path d; } } server { }", &["a", "b", "c", "d"]),
        ] {
            let paths = build_text(&format!("http {{ {http} }}")).unwrap().temp_paths;
            let want: Vec<_> = want.iter().map(|p| dir.join(p).into_os_string()).collect();
            assert_eq!(paths.into_iter().map(PathBuf::into_os_string).collect::<Vec<_>>(), want, "{http}");
        }
    }

    #[test]
    fn levels_of_temporary_files() {
        let prefix = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        let default = |name: &str, line: usize| format!("the path name \"{}\" in t.conf:{line} has the same name as default path, but the different levels, you need to define default path in http section", prefix.join(name).display());
        let same = |name: &str, first: usize, second: usize| format!("the same path name \"{}\" in t.conf:{first} has the different levels than in t.conf:{second}", prefix.join(name).display());
        for (http, want) in [
            ("client_body_temp_path /a;\nproxy_temp_path /a 1;", same("/a", 1, 2)),
            ("client_body_temp_path /a/ 1;\nproxy_temp_path /a/;", same("/a", 1, 2)),
            ("client_body_temp_path a/ 1;\nproxy_temp_path a 2;", same("a", 1, 2)),
            ("server { client_body_temp_path /a 1;\n}\nserver { location / { client_body_temp_path /a 1 1; } }", same("/a", 1, 3)),
            ("client_body_temp_path proxy_temp;\nserver { }", default("proxy_temp", 1)),
            ("\nproxy_temp_path client_body_temp 1; server { }", default("client_body_temp", 2)),
            ("server { proxy_buffers 1 4k; }\nserver { proxy_temp_path client_body_temp 1; }", default("client_body_temp", 2)),
            ("server { proxy_buffers 1 4k; }\nserver { client_body_temp_path proxy_temp; }", "there must be at least 2 \"proxy_buffers\"".into()),
        ] {
            assert_eq!(build_text(&format!("http {{ {http} }}")).err(), Some(want), "{http}");
        }
        for http in ["client_body_temp_path /a 1 2; proxy_temp_path /a 1 2; server { }", "client_body_temp_path /a/ 1; proxy_temp_path /a 2;", "client_body_temp_path proxy_temp 1 2; server { }", "proxy_temp_path client_body_temp 1;"] {
            assert!(build_text(&format!("http {{ {http} }}")).is_ok(), "{http}");
        }
    }

    #[test]
    fn directives_given_twice() {
        let again = |d: &str| format!("\"{d}\" directive is duplicate in t.conf:2");
        for (conf, want) in [
            ("daemon on;\ndaemon on;", again("daemon")),
            ("events { }\nevents { }", again("events")),
            ("http { }\nhttp { }", again("http")),
            ("http { gzip on;\ngzip off; }", again("gzip")),
            ("http { server { http2 on;\nhttp2 x; } }", again("http2")),
            ("ssl_object_cache_inheritable on;\nssl_object_cache_inheritable x;", again("ssl_object_cache_inheritable")),
            ("http { proxy_cookie_path off;\nproxy_cookie_path x; }", again("proxy_cookie_path")),
            ("http { proxy_redirect off;\nproxy_redirect default; }", again("proxy_redirect")),
            ("http { server { location / { proxy_pass http://127.0.0.1:1;\nproxy_pass http://$host; } } }", again("proxy_pass")),
            ("http { server { location / { limit_except GET { }\nlimit_except PUT { } } } }", again("limit_except")),
            ("http { server { location / { if ($uri) { root /a;\nroot /b; } } } }", again("root")),
            ("http { server { location / { root /a;\nalias /b; } } }", "\"alias\" directive is duplicate, \"root\" directive was specified earlier in t.conf:2".into()),
            ("http { server { location / { alias /a;\nroot /b; } } }", "\"root\" directive is duplicate, \"alias\" directive was specified earlier in t.conf:2".into()),
            ("http { upstream u { server 127.0.0.1:1; keepalive 1;\nkeepalive 1; } }", again("keepalive")),
            ("http { upstream u { server 127.0.0.1:1; }\nupstream U { server 127.0.0.1:1; } }", "duplicate upstream \"U\" in t.conf:2".into()),
            ("http { log_format a x;\nlog_format a y; }", "duplicate \"log_format\" name \"a\" in t.conf:2".into()),
            ("http { log_format combined x; }", "duplicate \"log_format\" name \"combined\" in t.conf:1".into()),
            ("http { server { listen 8080;\nlisten 0.0.0.0:8080 ssl; } }", "a duplicate listen 0.0.0.0:8080 in t.conf:2".into()),
            ("http { server { location /a { }\nlocation ^~ /a { } } }", "duplicate location \"/a\" in t.conf:2".into()),
            ("http { server { location / { location = /a { }\nlocation = /a { } } } }", "duplicate location \"/a\" in t.conf:2".into()),
        ] {
            assert_eq!(build_text(conf).err(), Some(want), "{conf}");
        }
        for conf in [
            "http { gzip on; root /a; server { gzip on; root /a; location / { gzip on; root /a; if ($uri) { gzip on; root /a; } if ($uri) { gzip on; } } } server { gzip on; } }",
            "http { index a; index a; server { listen 8080; listen 8081; listen 8080 quic; location / { } location = / { } location ~ a { } location ~ a { } location @a { } location @a { } } }",
            "http { server { listen 8080; location /a { location /a { } } } server { listen 8080; location /a { } } }",
        ] {
            assert!(build_text(conf).is_ok(), "{conf}");
        }
        assert!(REPEATED.iter().all(|r| DIRECTIVES.iter().any(|d| d.0 == *r)));
    }

    #[test]
    fn checks_merged_proxy_buffers() {
        const TWO: &str = "there must be at least 2 \"proxy_buffers\"";
        const BUSY: &str = "\"proxy_busy_buffers_size\" must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\"";
        const ALL: &str = "\"proxy_busy_buffers_size\" must be less than the size of all \"proxy_buffers\" minus one buffer";
        const WRITE: &str = "\"proxy_temp_file_write_size\" must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\"";
        const MAX: &str = "\"proxy_max_temp_file_size\" must be equal to zero to disable temporary files usage or must be equal to or greater than the maximum of the value of \"proxy_buffer_size\" and one of the \"proxy_buffers\"";
        for (http, want) in [
            ("server { proxy_buffers 1 4k; }", TWO),
            ("proxy_buffers 1 4k; server { }", TWO),
            ("server { proxy_buffers 2 4k; }", ALL),
            ("server { proxy_buffer_size 8k; proxy_busy_buffers_size 4k; }", BUSY),
            ("server { proxy_busy_buffers_size 0; }", BUSY),
            ("server { proxy_busy_buffers_size 28673; }", ALL),
            ("server { proxy_temp_file_write_size 4095; }", WRITE),
            ("server { proxy_max_temp_file_size 4095; }", MAX),
            ("proxy_busy_buffers_size 8k; server { location / { location /a { proxy_buffers 2 8k; } } location /b { proxy_buffer_size 16k; } }", BUSY),
            ("proxy_buffers 8 16k; server { proxy_max_temp_file_size 8k; location / { proxy_temp_file_write_size 8k; } }", MAX),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1; proxy_buffers 1 4k; }", TWO),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1; }", BUSY),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1m; }", ALL),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; }", WRITE),
            ("server { proxy_buffers 1 4k; } server { proxy_buffers 0 4k; }", "\"proxy_buffers\" directive invalid value in t.conf:1"),
        ] {
            assert_eq!(build_text(&format!("http {{ {http} }}")).err().as_deref(), Some(want), "{http}");
        }
        for http in ["proxy_buffers 1 4k;", "proxy_buffers 1 4k; server { proxy_buffers 3 4k; }", "proxy_buffer_size 0; server { }", "server { proxy_buffers 2 8k; proxy_busy_buffers_size 8k; proxy_temp_file_write_size 8k; proxy_max_temp_file_size 8k; }"] {
            assert!(build_text(&format!("http {{ {http} }}")).is_ok(), "{http}");
        }
        for d in ["proxy_buffer_size 4k;", "proxy_buffers 8 4k;", "proxy_busy_buffers_size 8k;", "proxy_temp_file_write_size 8k;", "proxy_max_temp_file_size 8k;", "proxy_temp_path /t;"] {
            let name = d.split(' ').next().unwrap();
            assert_eq!(build_text(&format!("http {{ {d}\n{d} }}")).unwrap_err(), format!("\"{name}\" directive is duplicate in t.conf:2"));
            assert!(build_text(&format!("http {{ {d} server {{ {d} location / {{ {d} }} }} }}")).is_ok());
        }
    }

    #[test]
    fn sizes_and_error_pages() {
        assert_eq!(size("8k"), Ok(8192));
        assert_eq!(size("1M"), Ok(1 << 20));
        assert_eq!(size("10"), Ok(10));
        assert_eq!(size("1x"), Err("\"1x\" is invalid".into()));
        assert_eq!((size("1g"), offset("1g"), offset("2G")), (Err("\"1g\" is invalid".into()), Ok(1 << 30), Ok(2 << 30)));
        assert_eq!(offset("8589934592g"), Err("\"8589934592g\" is invalid".into()));
        assert_eq!(error_page(&["200".into(), "http://e/".into()]).unwrap_err(), "value \"200\" must be between 300 and 599");
        assert!(error_page(&["404".into(), "@named".into()]).is_ok());
        assert!(matches!(location(&["@named".into()]).unwrap().0, Match::Named));
        let r = rewrite(&["^".into(), "/x?".into(), "break".into()]).unwrap();
        assert_eq!((r.redirect, r.add_args, r.flag), (false, false, Flag::Break));
        assert_eq!(error_page(&["404".into(), "/local".into()]).unwrap().status, None);
        assert_eq!(error_page(&["404".into(), "=".into(), "/local".into()]).unwrap().status, Some(0));
        assert_eq!(error_page(&["404".into(), "500".into(), "http://e/".into()]).unwrap().codes, vec![404, 500]);
    }

    #[test]
    fn redirect_settings_and_alias() {
        let c = build_text(
            "http { absolute_redirect off; server { server_name_in_redirect on; location /i/ { alias /a/; port_in_redirect OFF; \
             location /i/x { root /r; } } location /p/ { proxy_pass http://127.0.0.1:1; } } }",
        )
        .unwrap();
        let s = &c.servers[0];
        assert_eq!((s.level.absolute_redirect, s.level.server_name_in_redirect, s.level.port_in_redirect), (false, true, true));
        let (i, x, p) = (&s.locations[0], &s.locations[1], &s.locations[2]);
        assert_eq!((i.level.alias.as_deref(), i.level.port_in_redirect, i.auto_redirect), (Some(Path::new("/a/")), false, false));
        assert_eq!((x.level.alias.as_deref(), x.level.root.as_path()), (None, Path::new("/r")));
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        assert_eq!(build_text("http { server { } }").unwrap().servers[0].level.root, dir.join("html"));
        assert!(p.auto_redirect);
        let e = build_text("http { absolute_redirect yes; }").unwrap_err();
        assert_eq!(e, "invalid value \"yes\" in \"absolute_redirect\" directive, it must be \"on\" or \"off\" in t.conf:1");
        let c = build_text("http { server { try_files $uri $uri/ =404; location /a/ { alias /b/; location ~ x { } } location ~ y { alias /c; } } }").unwrap();
        let s = &c.servers[0];
        let tf = s.level.try_files.as_deref().unwrap();
        assert_eq!((tf.files.len(), tf.files[0].1, tf.files[1].1, &tf.fallback), (2, false, true, &Fallback::Status(404)));
        let alias_len = |i: usize| (s.locations[i].level.alias_len, s.locations[i].level.try_files.is_none());
        assert_eq!((alias_len(0), alias_len(1), alias_len(2)), ((Some(3), true), (Some(3), true), (None, true)));
        assert!(matches!(try_files(&["a".into(), "/b".into()]).unwrap().fallback, Fallback::Uri(_)));
        assert_eq!(try_files(&["a".into(), "=1000".into()]).unwrap_err(), "invalid code \"=1000\"");
        let e = build_text("http { absolute_redirect yes; }").unwrap_err();
        assert_eq!(e, "invalid value \"yes\" in \"absolute_redirect\" directive, it must be \"on\" or \"off\" in t.conf:1");
    }

    #[test]
    fn rewrites() {
        let r = rewrite(&["^/a".into(), "http://e/?".into(), "permanent".into()]).unwrap();
        assert_eq!((r.status, r.add_args, r.regex.is_match("/ab")), (301, false, true));
        let r = rewrite(&["^".into(), "/x".into(), "redirect".into()]).unwrap();
        assert_eq!((r.status, r.add_args), (302, true));
        let r = rewrite(&["^".into(), "/x".into()]).unwrap();
        assert_eq!((r.redirect, r.flag), (false, Flag::Next));
        assert_eq!(rewrite(&["^".into(), "/x".into(), "last".into()]).unwrap().flag, Flag::Last);
        assert_eq!(rewrite(&["^".into(), "http://e/".into(), "x".into()]).unwrap_err(), "invalid parameter \"x\"");
        assert!(rewrite(&["(".into(), "http://e/".into()]).is_err());
        let c = build_text("http { server { rewrite ^/s http://s/; set $a 1; location / { rewrite ^/l http://l/; if ($a) { set $a 2; } break; return 204; } } }").unwrap();
        assert!(matches!(c.servers[0].level.script[..], [Op::Rewrite(_), Op::Set(..)]));
        let ops = &c.servers[0].locations[0].level.script;
        assert!(matches!(&ops[..], [Op::Rewrite(_), Op::If(_, body, _), Op::Break, Op::Return(204, _)] if matches!(body[..], [Op::Set(..)])));
        assert_eq!(build_text("http { server { break 1; } }").unwrap_err(), "invalid number of arguments in \"break\" directive in t.conf:1");
    }

    #[test]
    fn access_log_parameters_and_cache() {
        let c = build_text(
            "http { log_format j escape=json $uri; open_log_file_cache max=3 inactive=20s min_uses=2 valid=1m; server { \
             access_log l_$arg_n j gzip=9 buffer=1k flush=100ms if=$arg_x; location / { open_log_file_cache off; access_log a.log j gzip; } } }",
        )
        .unwrap();
        let (s, l) = (&c.servers[0].level, &c.servers[0].locations[0].level);
        let log = &s.access_log[0];
        assert_eq!((log.format.escape, log.gzip, log.condition.is_some()), (Escape::Json, Some(9), true));
        assert!(matches!(log.target, Target::Path(_)) && matches!(l.access_log[0].target, Target::File(_)));
        let cache = s.log_cache.as_ref().unwrap();
        assert_eq!((cache.max, cache.inactive, cache.min_uses, cache.valid), (3, Duration::from_secs(20), 2, Duration::from_secs(60)));
        assert!(l.log_cache.is_none() && l.access_log[0].gzip == Some(1));
        for (text, e) in [
            ("log_format x escape=html $uri;", "unknown log format escaping \"html\""),
            ("access_log a.log combined flush=1s;", "no buffer is defined for access_log \"a.log\""),
            ("access_log a.log combined gzip=10;", "invalid compression level \"10\""),
            ("access_log a.log combined buffer=x;", "invalid buffer size \"x\""),
            ("access_log a.log combined flush=x;", "invalid flush time \"x\""),
            ("access_log a.log combined bad;", "invalid parameter \"bad\""),
            ("open_log_file_cache inactive=1s;", "\"open_log_file_cache\" must have \"max\" parameter"),
            ("open_log_file_cache max=x;", "invalid \"open_log_file_cache\" parameter \"max=x\""),
            ("open_log_file_cache max;", "invalid \"open_log_file_cache\" parameter \"max\""),
        ] {
            assert_eq!(build_text(&format!("http {{ {text} }}")).unwrap_err(), format!("{e} in t.conf:1"));
        }
    }

    #[test]
    fn gzip_and_proxy_headers() {
        let c = build_text(
            "http { proxy_set_header X $uri; gzip_http_version 1.0; server { default_type a/b; gunzip on; gzip_vary on; gzip_types text/plain; \
             location /a { gzip on; gzip_static always; proxy_set_header Y 1; proxy_set_header Z ''; } location /b { gzip_static on; } } }",
        )
        .unwrap();
        let s = &c.servers[0];
        let (a, b) = (&s.locations[0].level, &s.locations[1].level);
        assert_eq!((s.level.default_type.as_str(), s.level.gunzip, s.level.gzip_vary, s.level.gzip_http_11), ("a/b", true, true, false));
        assert_eq!((a.gzip_static, b.gzip_static, s.level.gzip_static), (Some(true), Some(false), None));
        assert_eq!((a.gzip, s.level.gzip, b.gzip_types.clone()), (true, false, vec!["text/plain".to_string()]));
        let names = |l: &Level| l.proxy_set_header.iter().map(|h| h.0.clone()).collect::<Vec<_>>();
        assert_eq!((names(a), names(b)), (vec!["Y".to_string(), "Z".to_string()], vec!["X".to_string()]));
        let e = build_text("http { gzip_static yes; }").unwrap_err();
        assert_eq!(e, "invalid value \"yes\" in \"gzip_static\" directive, it must be \"on\", \"off\" or \"always\" in t.conf:1");
        assert_eq!(build_text("http { gzip_http_version 2; }").unwrap_err(), "invalid value \"2\" in t.conf:1");
    }

    #[test]
    fn keepalive_settings() {
        let c = build_text("http { server { keepalive_requests 2; keepalive_timeout 1 9; location /a { keepalive_timeout 30s; keepalive_time 1s; keepalive_disable none; } location /b { keepalive_disable safari msie6; } } }").unwrap();
        let s = &c.servers[0];
        let (a, b) = (&s.locations[0].level, &s.locations[1].level);
        assert_eq!((s.level.keepalive_requests, s.level.keepalive_timeout, s.level.keepalive_header), (2, Duration::from_secs(1), Some(9)));
        assert_eq!((a.keepalive_requests, a.keepalive_timeout, a.keepalive_header, a.keepalive_time), (2, Duration::from_secs(30), Some(9), Duration::from_secs(1)));
        assert_eq!((a.keepalive_disable_msie6, a.keepalive_disable_safari, b.keepalive_disable_msie6, b.keepalive_disable_safari), (false, false, true, true));
        assert_eq!((s.level.keepalive_time, s.level.keepalive_disable_msie6), (Duration::from_secs(3600), true));
        assert_eq!(build_text("http { keepalive_requests x; }").unwrap_err(), "invalid number in t.conf:1");
        assert_eq!(build_text("http { keepalive_timeout 1x; }").unwrap_err(), "\"keepalive_timeout\" directive invalid value in t.conf:1");
        assert_eq!(build_text("http { keepalive_disable opera; }").unwrap_err(), "invalid value \"opera\" in t.conf:1");
    }

    #[test]
    fn limit_rate_values() {
        let c = build_text("http { limit_rate 12k; server { limit_rate_after $arg_a; } }").unwrap();
        let level = &c.servers[0].level;
        assert_eq!((level.limit_rate.0.len(), level.limit_rate_after.0.len()), (1, 1));
        assert_eq!(build_text("http { limit_rate 1x; }").unwrap_err(), "\"1x\" is invalid in t.conf:1");
        let c = build_text("http { proxy_method POST; server { location / { } } }").unwrap();
        assert_eq!(c.servers[0].locations[0].level.proxy_method.as_ref().map(|m| m.0.len()), Some(1));
        let c = build_text("http { proxy_set_body \"a $arg_b\"; server { location / { } } }").unwrap();
        assert_eq!(c.servers[0].locations[0].level.proxy_set_body.as_ref().map(|b| b.0.len()), Some(2));
        let c = build_text("http { proxy_limit_rate $upstream_http_x_rate; server { proxy_limit_rate 8k; } }").unwrap();
        assert_eq!(c.servers[0].level.proxy_limit_rate.0.len(), 1);
        assert_eq!(build_text("http { proxy_limit_rate 1x; }").unwrap_err(), "\"1x\" is invalid in t.conf:1");
        let c = build_text("http { proxy_pass_request_body off; server { proxy_pass_request_headers off; } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_pass_request_headers, c.servers[0].level.proxy_pass_request_body), (false, false));
        let c = build_text("http { proxy_next_upstream http_404; server { proxy_next_upstream error off; } server { } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_next_upstream.len(), c.servers[1].level.proxy_next_upstream.as_slice()), (0, &["http_404".to_string()][..]));
        let c = build_text("http { proxy_next_upstream_tries 2; proxy_next_upstream_timeout 3800ms; server { proxy_next_upstream_timeout 2s; } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_next_upstream_tries, c.servers[0].level.proxy_next_upstream_timeout), (2, Duration::from_secs(2)));
        assert_eq!(millis("3800ms"), Ok(Duration::from_millis(3800)));
        let c = build_text("http { proxy_read_timeout 500ms; server { } server { proxy_read_timeout 2; } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_read_timeout, c.servers[1].level.proxy_read_timeout), (Duration::from_millis(500), Duration::from_secs(2)));
        assert!(build_text("http { proxy_read_timeout 5x; }").is_err());
        let c = build_text("http { proxy_send_timeout 100ms; server { } server { proxy_send_timeout \"1m 30s\"; } }").unwrap();
        assert_eq!((c.servers[0].level.proxy_send_timeout, c.servers[1].level.proxy_send_timeout), (Duration::from_millis(100), Duration::from_secs(90)));
        assert_eq!(build_text("http { server { } }").unwrap().servers[0].level.proxy_send_timeout, Duration::from_secs(60));
        assert!(build_text("http { proxy_send_timeout 1s1m; }").is_err());
        assert!(build_text("http { proxy_next_upstream_tries x; }").is_err());
        let c = build_text("http { if_modified_since before; server { location / { if_modified_since off; } } }").unwrap();
        assert_eq!((c.servers[0].level.if_modified_since, c.servers[0].locations[0].level.if_modified_since), (Some(true), None));
        assert!(build_text("http { if_modified_since x; }").unwrap_err().starts_with("invalid value \"x\""));
    }

    #[test]
    fn header_buffers() {
        let c = build_text("http { connection_pool_size 128; client_header_buffer_size 128; server { large_client_header_buffers 5 256; } }").unwrap();
        assert_eq!((c.servers[0].level.header_buffer, c.servers[0].level.large_header_buffers), (128, (5, 256)));
        let e = build_text("http { large_client_header_buffers 0 1k; }").unwrap_err();
        assert_eq!(e, "\"large_client_header_buffers\" directive invalid value in t.conf:1");
        assert!(build_text("http { connection_pool_size 1x; }").is_err());
    }

    #[test]
    fn proxy_bind_values() {
        assert!(build_text("http { proxy_bind 127.0.0.2; server { location / { proxy_bind off; } location /v { proxy_bind $arg_b transparent; } } }").is_ok());
        assert_eq!(build_text("http { proxy_bind localhost; }").unwrap_err(), "invalid address \"localhost\" in t.conf:1");
        assert_eq!(build_text("http { proxy_bind 127.0.0.1 x; }").unwrap_err(), "invalid parameter \"x\" in t.conf:1");
        assert_eq!(local_addr("127.0.0.2"), Some("127.0.0.2:0".parse().unwrap()));
        assert_eq!(local_addr("127.0.0.2:8000"), Some("127.0.0.2:8000".parse().unwrap()));
        assert_eq!(local_addr("::1"), Some("[::1]:0".parse().unwrap()));
        assert_eq!(local_addr("[::1]"), Some("[::1]:0".parse().unwrap()));
        assert_eq!(local_addr("[::1]:81"), Some("[::1]:81".parse().unwrap()));
        assert_eq!(local_addr("127.0.0.1:x"), None);
    }

    #[test]
    fn listen_forms() {
        assert_eq!(listen("8080").unwrap(), "0.0.0.0:8080".parse().unwrap());
        assert_eq!(listen("127.0.0.1").unwrap(), "127.0.0.1:80".parse().unwrap());
    }

    #[test]
    fn refuses_what_nginx_refuses() {
        let http = |conf: &str| build_text(&format!("http {{ {conf} server {{ listen 127.0.0.1:8080; }} }}")).err();
        let server = |conf: &str| build_text(&format!("http {{ server {{ listen 127.0.0.1:8080; {conf} }} }}")).err();
        let refused = |e: Option<String>, want: &str| assert_eq!(e.as_deref(), Some(format!("{want} in t.conf:1").as_str()));
        let dir = std::env::temp_dir();
        assert_eq!(build(&parse("http { }", Path::new("t.conf")).unwrap(), &dir).unwrap_err(), "no \"events\" section in configuration");
        refused(http("upstream u { }"), "no servers are inside upstream");
        refused(http("upstream u { server 127.0.0.1:8081 backup; }"), "no servers in upstream \"u\"");
        refused(http("upstream u { server 127.0.0.1:8081 weight=0; }"), "invalid parameter \"weight=0\"");
        refused(http("upstream u { server 127.0.0.1:0; }"), "invalid port in upstream \"127.0.0.1:0\"");
        refused(http("error_page 404 =x /a;"), "invalid value \"=x\"");
        refused(http("error_page 499 /a;"), "value \"499\" must be between 300 and 599");
        refused(http("server { listen 127.0.0.1:8080 default_server; } server { listen 127.0.0.1:8080 default; }"), "a duplicate default server for 127.0.0.1:8080");
        refused(http("server { listen 127.0.0.1:8080 backlog=10; } server { listen 127.0.0.1:8080 reuseport; }"), "duplicate listen options for 127.0.0.1:8080");
        refused(http("server { listen 127.0.0.1:0; }"), "invalid port in \"127.0.0.1:0\" of the \"listen\" directive");
        refused(http("server { listen 127.0.0.1:8080 nosuch; }"), "invalid parameter \"nosuch\"");
        refused(http("server { listen 127.0.0.1:8080 backlog; }"), "invalid parameter \"backlog\"");
        refused(http("keepalive_timeout 30s1m;"), "\"keepalive_timeout\" directive invalid value");
        refused(http("add_header X-A b c;"), "invalid parameter \"c\"");
        refused(server("server_name ~;"), "empty regex in server name \"~\"");
        refused(server("server_name *a;"), "server name \"*a\" is invalid");
        refused(server("location /a { location /b { } }"), "location \"/b\" is outside location \"/a\"");
        refused(server("location = /a { location /a/b { } }"), "location \"/a/b\" cannot be inside the exact location \"/a\"");
        refused(server("location @a { location /b { } }"), "location \"/b\" cannot be inside the named location \"@a\"");
        refused(server("location /a { location @b { } }"), "named location \"@b\" can be on the server level only");
        refused(server("rewrite ^ \"\";"), "empty replacement");
        refused(server("location / { proxy_pass http://127.0.0.1:0; }"), "invalid port in upstream \"127.0.0.1:0\"");
        let uri = "\"proxy_pass\" cannot have URI part in location given by regular expression, or inside named location, or inside \"if\" statement, or inside \"limit_except\" block";
        refused(server("location / { limit_except GET { proxy_pass http://127.0.0.1:8081/a; } }"), uri);
        refused(server("location / { if ($uri) { proxy_pass http://127.0.0.1:8081/a; } }"), uri);
        refused(server("location ~ /a { proxy_pass http://127.0.0.1:8081/; }"), uri);
        assert!(http("upstream u { server 127.0.0.1:8081 down; } error_page 404 /a; error_page 404 /b;").is_none());
        assert!(server("server_name a a *.b c.*; location ~ ^/a { location ~ y { } location ^/a/x { } } location ~ ^/a { } location @a { } location @a { proxy_pass http://127.0.0.1:8081; } location /b { location /bc { } } location /p { proxy_pass http://127.0.0.1:8081/p; }").is_none());
        assert!(http("ssl_reject_handshake on; server { listen 127.0.0.1:8080 default_server backlog=10 ssl http2 deferred; } server { listen 127.0.0.1:8080; }").is_none());
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
        let e = build_text("http { server { set limit_rate 1; } }").unwrap_err();
        assert_eq!(e, "invalid variable name \"limit_rate\" in t.conf:1");
        let e = build_text("http { server { set $remote_addr 1; } }").unwrap_err();
        assert_eq!(e, "the duplicate \"remote_addr\" variable in t.conf:1");
        let e = build_text("http { access_log a.log nope; }").unwrap_err();
        assert_eq!(e, "unknown log format \"nope\" in t.conf:1");
        let e = build_text("http { server { location / { limit_except GET NOPE { } } } }").unwrap_err();
        assert_eq!(e, "invalid method \"NOPE\" in t.conf:1");
    }

    #[test]
    fn types() {
        let mime = include_str!("../conf/mime.types");
        let c = build_text(&format!("http {{ {mime} server {{ location /a {{ types {{ }} }} location /b {{ types {{ a/b X; }} types {{ c/d x y; }} }} }} }}")).unwrap();
        let s = &c.servers[0];
        let get = |l: &Level, ext: &str| l.types.as_ref().map(|t| (t.len(), t.get(ext).cloned()));
        assert_eq!(get(&s.level, "htm"), Some((110, Some("text/html".into()))));
        assert_eq!(get(&s.locations[0].level, "htm"), Some((0, None)));
        assert_eq!(get(&s.locations[1].level, "x"), Some((2, Some("c/d".into()))));
        assert_eq!(build_text("http { types { a/b { } } }").unwrap_err(), "unexpected \"{\" in t.conf:1");
    }

    #[test]
    fn https_and_limit_except() {
        let c = build_text("http { server { listen 127.0.0.1:8443 ssl; ssl_reject_handshake on; location / { proxy_pass https://127.0.0.1/u; } \
                            location /l { limit_except GET { } } } }").unwrap();
        let s = &c.servers[0];
        assert_eq!(s.ssl, ["127.0.0.1:8443".parse().unwrap()]);
        let p = s.locations[0].level.proxy.as_ref().unwrap();
        assert!(p.ssl);
        assert_eq!(p.upstream.peers[0].addr.to_string(), "127.0.0.1:443");
        let redirect = s.locations[0].level.proxy_redirect.as_ref().unwrap();
        assert!(matches!(&redirect[0].pattern, CookiePattern::Text(t) if matches!(&t.0[..], [Part::Text(u)] if u == "https://127.0.0.1/u")));
        assert_eq!(s.locations[1].level.limit_except.as_ref().unwrap().0, ["GET", "HEAD"]);
        let c = build_text("http { server { break; location / { return 200; limit_except GET { } } } }").unwrap();
        let level = &c.servers[0].locations[0].level;
        assert_eq!(level.script.len(), 1);
        assert!(level.limit_except.as_ref().unwrap().1.script.is_empty());
    }

    #[test]
    fn ssl_refused() {
        let refused = |text: &str| build_text(&format!("http {{ {text} }}")).unwrap_err();
        let pair = "ssl_certificate c.crt; ssl_certificate_key c.key;";
        assert_eq!(refused("server { listen 127.0.0.1:8080; ssl_certificate c.crt; }"), "no \"ssl_certificate_key\" is defined for certificate \"c.crt\"");
        assert_eq!(refused(&format!("server {{ {pair} ssl_certificate d.crt; }}")), "no \"ssl_certificate_key\" is defined for certificate \"d.crt\"");
        assert_eq!(refused(&format!("server {{ {pair} ssl_verify_client optional; }}")), "no ssl_client_certificate or ssl_trusted_certificate for ssl_verify_client");
        assert_eq!(refused("server { ssl_reject_handshake on; ssl_verify_client optional_no_ca; ssl_ocsp on; }"), "\"ssl_ocsp\" is incompatible with \"ssl_verify_client optional_no_ca\"");
        assert_eq!(refused("server { listen 127.0.0.1:8443 ssl; }"), "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in t.conf:1");
        assert_eq!(refused("server { listen 127.0.0.1:8443 ssl; ssl_reject_handshake on; }\nserver { listen 127.0.0.1:8443; }"), "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in t.conf:2");
        assert_eq!(refused("server { listen 127.0.0.1:8443 ssl; ssl_reject_handshake on; }\nserver { listen 127.0.0.1:8443 default_server; }"), "no \"ssl_certificate\" is defined for the \"listen ... ssl\" directive in t.conf:2");
        assert!(build_text("http { server { listen 127.0.0.1:8443 ssl; ssl_reject_handshake on; } server { listen 127.0.0.1:8443; ssl_reject_handshake on; } }").is_ok());
        assert_eq!(refused("ssl_session_cache shared:S:1k;"), "session cache \"shared:S:1k\" is too small in t.conf:1");
        assert_eq!(refused("ssl_session_cache shared:S:1x;"), "invalid session cache \"shared:S:1x\" in t.conf:1");
        assert_eq!(refused("ssl_session_cache shared:S:1m; server { ssl_session_cache builtin shared:S:2m; }"), "the size 2097152 of shared memory zone \"S\" conflicts with already declared size 1048576 in t.conf:1");
        assert!(build_text("http { ssl_session_cache shared:S:1m; server { ssl_session_cache shared:S:1m; } }").is_ok());
    }

    #[test]
    fn proxy_ssl_verify() {
        let e = build_text("http { proxy_ssl_verify on; server { listen 127.0.0.1:8080; location / { proxy_pass https://127.0.0.1:8081; proxy_ssl_verify on; } } }").unwrap_err();
        assert!(e.contains("no proxy_ssl_trusted_certificate for proxy_ssl_verify"), "{e}");
        let e = build_text("http { server { listen 127.0.0.1:8080; location / { proxy_ssl_verify_depth x; } } }").unwrap_err();
        assert!(e.contains("invalid value \"x\" in \"proxy_ssl_verify_depth\" directive"), "{e}");
        let c = build_text("http { proxy_ssl_verify on; proxy_ssl_name $host; server { listen 127.0.0.1:8080; location / { proxy_ssl_verify_depth 2; } } }").unwrap();
        assert!(c.servers[0].level.proxy_ssl_verify && c.servers[0].level.proxy_ssl_name.is_some());
    }

    #[test]
    fn ssl_certificates_of_a_level_replace_those_inherited() {
        let c = build_text("http { ssl_certificate_compression on; ssl_certificate a$ssl_server_name.crt; ssl_certificate_key a$ssl_server_name.key; server { listen 127.0.0.1:8080; ssl_certificate b$ssl_server_name.crt; ssl_certificate_key b$ssl_server_name.key; ssl_certificate c$ssl_server_name.crt; ssl_certificate_key c$ssl_server_name.key; ssl_certificate_compression off; } server { listen 127.0.0.1:8081; } }").unwrap();
        let names = |files: &[PathBuf]| files.iter().map(|f| f.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        let (own, inherited) = (&c.servers[0].level, &c.servers[1].level);
        assert_eq!((names(&own.ssl_certificate), names(&own.ssl_certificate_key)), (vec!["b$ssl_server_name.crt".to_string(), "c$ssl_server_name.crt".into()], vec!["b$ssl_server_name.key".to_string(), "c$ssl_server_name.key".into()]));
        assert_eq!(names(&inherited.ssl_certificate), ["a$ssl_server_name.crt"]);
        assert_eq!((own.ssl_certificate_compression, inherited.ssl_certificate_compression), (false, true));
        assert!(c.servers.iter().all(|s| s.tls.is_some()));
    }

    #[test]
    fn proxy_ssl_certificate_cache() {
        assert!(cert_cache("proxy_ssl_certificate_cache", &["off".into()]).unwrap().is_none());
        assert!(cert_cache("proxy_ssl_certificate_cache", &["max=4".into(), "inactive=1s".into(), "valid=2s".into()]).unwrap().is_some());
        assert_eq!(cert_cache("proxy_ssl_certificate_cache", &["valid=2s".into()]).unwrap_err(), "\"proxy_ssl_certificate_cache\" must have the \"max\" parameter");
        assert_eq!(cert_cache("ssl_certificate_cache", &[]).unwrap_err(), "\"ssl_certificate_cache\" must have the \"max\" parameter");
        assert_eq!(cert_cache("proxy_ssl_certificate_cache", &["max=0".into()]).unwrap_err(), "invalid parameter \"max=0\"");
        assert_eq!(cert_cache("proxy_ssl_certificate_cache", &["size=1".into()]).unwrap_err(), "invalid parameter \"size=1\"");
        let c = build_text("http { server { listen 127.0.0.1:8080; proxy_ssl_certificate $arg_c.crt; proxy_ssl_certificate_key k.key; location / { } } }").unwrap();
        assert!(c.servers[0].level.proxy_ssl_certificate_vars.is_some());
        let c = build_text("http { server { listen 127.0.0.1:8080; proxy_ssl_certificate \"\"; proxy_ssl_certificate_key \"\"; location / { } } }").unwrap();
        assert!(c.servers[0].level.proxy_ssl_certificate_vars.is_none());
    }

    #[test]
    fn ssl_protocols() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(protocols(&args(&["TLSv1", "TLSv1.2"])).unwrap(), [true, false]);
        assert_eq!(protocols(&args(&["tlsv1.3"])).unwrap(), [false, true]);
        assert_eq!(protocols(&args(&["TLSv1.4"])).unwrap_err(), "invalid value \"TLSv1.4\"");
        let c = build_text("http { ssl_protocols TLSv1.2; server { listen 127.0.0.1:8080; } }").unwrap();
        assert_eq!(c.servers[0].level.ssl_protocols, [true, false]);
    }

    #[test]
    fn lingering_close() {
        let c = build_text("http { lingering_close always; server { location /a { lingering_close on; } location /b { } } server { lingering_close off; } }").unwrap();
        let l = &c.servers[0].locations;
        assert_eq!((l[0].level.lingering_close, l[1].level.lingering_close, c.servers[1].level.lingering_close), (Some(false), Some(true), None));
        assert_eq!(build_text("http { server { } }").unwrap().servers[0].level.lingering_close, Some(false));
        assert_eq!(build_text("http { lingering_close yes; }").unwrap_err(), "invalid value \"yes\" in \"lingering_close\" directive, it must be \"off\", \"on\" or \"always\" in t.conf:1");
    }

    #[test]
    fn sendfile() {
        let of = |text: &str| build_text(&format!("http {{ server {{ listen 127.0.0.1:8080; {text} }} }}")).map(|c| { let l = c.servers[0].level.clone(); (l.sendfile, l.sendfile_max_chunk, l.tcp_nopush, l.tcp_nodelay) });
        assert_eq!(of(""), Ok((false, 2 << 20, false, true)));
        assert_eq!(of("sendfile on; sendfile_max_chunk 0; tcp_nopush ON; tcp_nodelay off;"), Ok((true, 0, true, false)));
        for (text, error) in [
            ("sendfile_max_chunk x;", "\"sendfile_max_chunk\" directive invalid value"),
            ("sendfile_max_chunk 1g;", "\"sendfile_max_chunk\" directive invalid value"),
            ("tcp_nopush 1;", "invalid value \"1\" in \"tcp_nopush\" directive, it must be \"on\" or \"off\""),
            ("tcp_nodelay on; tcp_nodelay on;", "\"tcp_nodelay\" directive is duplicate"),
            ("sendfile_max_chunk 1; sendfile_max_chunk 1;", "\"sendfile_max_chunk\" directive is duplicate"),
            ("location / { if ($args) { sendfile_max_chunk 1; } }", "\"sendfile_max_chunk\" directive is not allowed here"),
            ("location / { if ($args) { tcp_nopush on; } }", "\"tcp_nopush\" directive is not allowed here"),
        ] {
            assert!(of(text).unwrap_err().starts_with(error), "{text} {:?}", of(text));
        }
        assert!(of("location / { if ($args) { sendfile on; } }").is_ok());
        assert!(of("postpone_output 0; location / { postpone_output 2k; }").is_ok());
        for (text, error) in [
            ("postpone_output x;", "\"postpone_output\" directive invalid value"),
            ("postpone_output 1; postpone_output 1;", "\"postpone_output\" directive is duplicate"),
            ("location / { if ($args) { postpone_output 1; } }", "\"postpone_output\" directive is not allowed here"),
        ] {
            assert!(of(text).unwrap_err().starts_with(error), "{text} {:?}", of(text));
        }
    }

    #[test]
    fn send_timeout() {
        let c = build_text("http { send_timeout 2s; server { listen 127.0.0.1:8080; } server { listen 127.0.0.1:8081; send_timeout 0; } }").unwrap();
        assert_eq!((c.servers[0].level.send_timeout, c.servers[1].level.send_timeout), (Duration::from_secs(2), Duration::ZERO));
        assert_eq!(build_text("http { }").unwrap().servers.first().map(|s| s.level.send_timeout), None);
    }

    #[test]
    fn ssl_stapling() {
        let c = build_text("http { ssl_stapling on; ssl_stapling_verify on; ssl_stapling_responder http://127.0.0.1:8081/; server { ssl_stapling_file resp.der; } }").unwrap();
        let l = &c.servers[0].level;
        assert_eq!((l.ssl_stapling, l.ssl_stapling_verify, l.ssl_stapling_responder.as_deref()), (true, true, Some("http://127.0.0.1:8081/")));
        assert!(l.ssl_stapling_file.as_ref().unwrap().ends_with("resp.der"));
        assert!(build_text("http { ssl_stapling_responder https://a; }").is_ok());
    }

    #[test]
    fn ssl_ocsp() {
        let c = build_text("http { ssl_ocsp leaf; ssl_ocsp_responder http://127.0.0.1:8080/x; ssl_ocsp_cache shared:OCSP:1m; ssl_verify_client optional_no_ca; server { listen 127.0.0.1:8080; ssl_ocsp_cache off; } }").unwrap();
        let level = &c.servers[0].level;
        assert_eq!((level.ssl_ocsp, level.ssl_ocsp_responder.as_deref(), level.ssl_ocsp_cache.as_deref(), level.ssl_verify_client), (Some(true), Some("http://127.0.0.1:8080/x"), None, 3));
        assert_eq!(ocsp_cache("shared:OCSP:1m"), Ok(Some("OCSP".to_string())));
        assert_eq!(ocsp_cache("shared::1m"), Err("invalid value \"shared::1m\"".to_string()));
        assert!(build_text("http { ssl_ocsp yes; }").unwrap_err().starts_with("invalid value \"yes\" in \"ssl_ocsp\" directive"));
        assert!(build_text("http { ssl_ocsp_responder https://a; }").unwrap_err().starts_with("invalid URL prefix in OCSP responder \"https://a\""));
    }

    #[test]
    fn ssl_session_ticket_keys_replace_those_inherited() {
        let c = build_text("http { ssl_session_ticket_key a; ssl_session_ticket_key b; server { } server { ssl_session_ticket_key c; } }").unwrap();
        let names = |i: usize| c.servers[i].level.ssl_session_ticket_key.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!((names(0), names(1)), (vec!["a".to_string(), "b".to_string()], vec!["c".to_string()]));
    }

    #[test]
    fn ssl_conf_commands() {
        let mut options = crate::tls::Options { verify: false, sessions: crate::tls::Sessions::default(), compress: false, ciphers: None, protocols: [true, true], prefer: true, curves: None, crl: None, depth: 1, ocsp: None, ticket_keys: Vec::new(), stapling: None, client_ca: None };
        let commands = |c: &[(&str, &str)]| c.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        let files = conf_commands(&commands(&[("Options", "-SessionTicket, -ServerPreference"), ("Certificate", "/c.crt"), ("PrivateKey", "/c.key")]), &mut options).unwrap();
        assert!(!options.sessions.tickets && !options.prefer);
        assert_eq!(files, [vec![PathBuf::from("/c.crt")], vec![PathBuf::from("/c.key")]]);
        conf_commands(&commands(&[("Options", "SessionTicket,ServerPreference,KTLS")]), &mut options).unwrap();
        assert!(options.sessions.tickets && options.prefer);
        assert_eq!(conf_commands(&commands(&[("Options", "Bugs")]), &mut options).unwrap_err(), "SSL_CONF_cmd(\"Options\", \"Bugs\") failed");
        assert_eq!(conf_commands(&commands(&[("Protocol", "TLSv1.2")]), &mut options).unwrap_err(), "SSL_CONF_cmd(\"Protocol\", \"TLSv1.2\") failed");
        let c = build_text("http { ssl_conf_command Options SessionTicket; server { listen 127.0.0.1:8080; ssl_conf_command Certificate c.crt; } }").unwrap();
        let level = &c.servers[0].level;
        assert_eq!(level.ssl_conf_command.len(), 1);
        assert!(level.ssl_conf_command[0].1.ends_with("/c.crt") && level.ssl_conf_command[0].1.len() > "/c.crt".len());
    }
}
