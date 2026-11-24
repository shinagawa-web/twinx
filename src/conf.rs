//! What the directives mean: checks each one as nginx does (known, allowed in
//! its block, right number of arguments) and builds the configuration twinx runs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Directive;
use crate::log::{AccessLog, Cache, Format, Target};
use crate::resolver::Resolver;
use crate::upstream::{Keepalive, Peer, Upstream};
use crate::vars::{Escape, Part, Template};

const MAIN: u16 = 1;
const EVENTS: u16 = 2;
const HTTP: u16 = 4;
const SRV: u16 = 8;
const LOC: u16 = 16;
const UPS: u16 = 32;
/// An "if" block in a location, and in a server.
const LIF: u16 = 64;
const SIF: u16 = 128;
/// A limit_except block.
const LMT: u16 = 256;
const HSL: u16 = HTTP | SRV | LOC;

/// Every directive twinx knows: where it may appear, its argument counts, and
/// whether it takes a block.
/// The levels of error_log, from the lowest.
pub const LEVELS: &[&str] = &["debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"];

const DIRECTIVES: &[(&str, u16, usize, usize, bool)] = &[
    ("daemon", MAIN, 1, 1, false),
    ("pid", MAIN, 1, 1, false),
    ("ssl_object_cache_inheritable", MAIN, 1, 1, false),
    ("worker_rlimit_nofile", MAIN, 1, 1, false),
    ("worker_processes", MAIN, 1, 1, false),
    ("working_directory", MAIN, 1, 1, false),
    ("worker_shutdown_timeout", MAIN, 1, 1, false),
    ("error_log", MAIN | HSL, 1, usize::MAX, false),
    ("log_not_found", HSL, 1, 1, false),
    ("index", HSL, 1, usize::MAX, false),
    ("events", MAIN, 0, 0, true),
    ("http", MAIN, 0, 0, true),
    ("server", HTTP, 0, 0, true),
    ("upstream", HTTP, 1, 1, true),
    ("server", UPS, 1, usize::MAX, false),
    ("keepalive", UPS, 1, 2, false),
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
    ("send_timeout", HSL, 1, 1, false),
    ("proxy_buffer_size", HSL, 1, 1, false),
    ("proxy_buffering", HSL, 1, 1, false),
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

/// The directives that may be given more than once at a level; those that have rules of
/// their own for it are checked where they are read.
const REPEATED: &[&str] = &[
    "error_log", "index", "server", "upstream", "listen", "server_name", "location", "return", "break", "set", "if", "rewrite", "log_format", "access_log", "add_header", "add_trailer", "keepalive_disable", "error_page",
    "ssl_certificate", "ssl_certificate_key", "ssl_protocols", "ssl_conf_command", "ssl_session_cache", "ssl_session_ticket_key", "early_hints", "proxy_set_header", "proxy_hide_header", "proxy_pass_header", "proxy_next_upstream",
    "proxy_cookie_domain", "proxy_cookie_path", "proxy_redirect", "proxy_cookie_flags", "gzip_types", "proxy_cache_path", "proxy_cache_valid",
    "proxy_no_cache", "proxy_cache_bypass", "proxy_ignore_headers",
];

const COMBINED: &str =
    "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"";

/// Where proxy_pass sends requests: the servers in the order they are tried
/// (backup servers last), the Host to send, and the URI that replaces the
/// location's prefix, if the directive has one. A URL with variables is made
/// for each request instead, and its host resolved then.
#[derive(Debug, Clone)]
pub struct Proxy {
    pub host: String,
    /// Whether the URL is "https://": requests go over TLS.
    pub ssl: bool,
    pub upstream: Arc<Upstream>,
    pub uri: Option<String>,
    pub url: Option<Template>,
    /// The upstream groups a URL with variables may name.
    pub groups: HashMap<String, Arc<Upstream>>,
    /// The upstreams proxy_pass URLs without variables made, by "host:port",
    /// which a URL with variables also uses when its host and port are theirs.
    pub implicit: Implicit,
}

/// The implicit upstreams of a configuration, filled while it is read.
pub type Implicit = Arc<Mutex<HashMap<String, Arc<Upstream>>>>;

/// An error_page: the statuses, the status to answer with instead (None keeps
/// the status, as nginx does for redirects it turns into 302), and the URL.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorPage {
    pub codes: Vec<u16>,
    pub status: Option<u16>,
    pub url: Template,
}

/// rewrite regex replacement [flag], where the replacement is a URL the
/// client is redirected to (with 301 for "permanent", 302 otherwise), or the
/// URI the request goes on with. A replacement ending with "?" does not get
/// the request's arguments.
#[derive(Debug, Clone)]
pub struct Rewrite {
    pub regex: regex::Regex,
    pub url: Template,
    pub status: u16,
    pub add_args: bool,
    pub redirect: bool,
    pub flag: Flag,
}

/// What follows a rewrite to a URI: the next directive of the rewrite module
/// (no flag), the search for the location of the new URI ("last"), or the
/// rest of the location, without the rewrite module's directives ("break").
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Flag {
    Next,
    Last,
    Break,
}

/// The directives of the rewrite module that a level runs in order, after set and if.
#[derive(Debug, Clone)]
pub enum Step {
    Rewrite(Rewrite),
    /// return code [text] | code URL | URL.
    Return(u16, Template),
    /// break: the rewrite module's directives after it are not run.
    Break,
}

/// What set and if do, in the order they are written.
#[derive(Debug, Clone)]
pub enum Op {
    /// set $name value.
    Set(String, Template),
    /// if ($variable) { ... }: when the value is neither empty nor "0", the
    /// directives of the block, and from then on the settings of the block
    /// (None for a block in a server, whose settings the location replaces).
    If(Condition, Vec<Op>, Option<Arc<Level>>),
}

/// The condition of if, the last field of each saying whether it is negated ("!").
#[derive(Debug, Clone)]
pub enum Condition {
    /// $variable: true when neither empty nor "0".
    Var(Template),
    /// $variable = value, $variable != value.
    Equal(Template, Template, bool),
    /// $variable ~ regex, ~* (caseless), !~, !~*: the captures become $1, $2, ...
    Match(Template, regex::Regex, bool),
    /// -f, -d, -e or -x (the letter) and the path.
    File(Template, char, bool),
}

/// proxy_cookie_domain and proxy_cookie_path: what a Domain or Path attribute
/// of a Set-Cookie is matched against, and the value that replaces it.
#[derive(Debug, Clone)]
pub struct CookieRewrite {
    pub pattern: CookiePattern,
    pub replacement: Template,
}

#[derive(Debug, Clone)]
pub enum CookiePattern {
    /// A domain equal to it (case-insensitively, a leading "." of either left
    /// out), a path that starts with it, or a cookie name equal to it
    /// (case-insensitively).
    Text(Template),
    /// A regular expression: the whole value is replaced on a match of it,
    /// or the cookie name matches it.
    Regex(regex::Regex),
}

/// proxy_cookie_flags: the cookies whose name matches, and the flags, which
/// may have variables, set on them.
#[derive(Debug, Clone)]
pub struct CookieFlags {
    pub cookie: CookiePattern,
    pub flags: Vec<Template>,
}

/// The flags proxy_cookie_flags knows, the bits of a set of them being their places here.
pub const COOKIE_FLAGS: [&str; 8] = ["secure", "httponly", "nosecure", "nohttponly", "samesite=none", "samesite=lax", "samesite=strict", "nosamesite"];

/// proxy_cache: a zone, or a value with variables that names one of the zones of
/// proxy_cache_path for each request.
#[derive(Debug, Clone)]
pub enum CacheZone {
    Fixed(Arc<crate::cache::Zone>),
    Named(Template, Arc<HashMap<String, Arc<crate::cache::Zone>>>),
}

/// The settings of one level (http, server or location) after inheriting from the one above.
#[derive(Debug, Clone, Default)]
pub struct Level {
    /// rewrite, return and break, in order, those of the server first.
    pub rewrite: Vec<Step>,
    /// set and if of the server, run before those of the location.
    pub server_script: Vec<Op>,
    /// set and if of the location, which nested locations do not inherit.
    pub script: Vec<Op>,
    /// proxy_cookie_domain and proxy_cookie_path; None when off.
    pub proxy_cookie_domain: Option<Vec<CookieRewrite>>,
    pub proxy_cookie_path: Option<Vec<CookieRewrite>>,
    /// proxy_cookie_flags, the first whose cookie matches applying; None when off.
    pub proxy_cookie_flags: Option<Vec<CookieFlags>>,
    /// proxy_redirect: what replaces the start of a Location or of the URL of
    /// a Refresh the proxied server sends (a pattern as proxy_cookie_path's
    /// is), the first rule that matches applying; None when off.
    pub proxy_redirect: Option<Vec<CookieRewrite>>,
    pub access_log: Vec<Arc<AccessLog>>,
    /// open_log_file_cache, for the access logs whose paths have variables.
    pub log_cache: Option<Arc<Cache>>,
    pub root: PathBuf,
    /// add_header: name, value, and whether it is added whatever the status ("always").
    pub add_header: Vec<(String, Template, bool)>,
    /// add_trailer: the same, sent as trailers of a chunked answer.
    pub add_trailer: Vec<(String, Template, bool)>,
    pub error_page: Vec<ErrorPage>,
    /// index: the files looked for in a directory, in order; one that starts
    /// with "/" is a URI redirected to whether it exists or not.
    pub index: Vec<Template>,
    /// error_log, of the main block if not of http, server or location: where errors
    /// of requests are written, and from which of the levels on.
    pub error_log: Vec<(Arc<File>, usize)>,
    /// log_not_found: whether files that are not found are logged.
    pub log_not_found: bool,
    pub proxy: Option<Arc<Proxy>>,
    pub max_body: u64,
    /// max_headers: the header lines a request may have; one more is refused with 400.
    pub max_headers: usize,
    /// client_header_buffer_size: the buffer a request's head is read into first.
    pub header_buffer: usize,
    /// large_client_header_buffers: how many larger buffers a head may take
    /// when it does not fit, and their size, which a line must fit in.
    pub large_header_buffers: (usize, usize),
    /// ignore_invalid_headers: header lines whose names have other characters
    /// than letters, digits and "-" (and "_" with underscores_in_headers) are dropped.
    pub ignore_invalid_headers: bool,
    pub underscores_in_headers: bool,
    /// merge_slashes: two or more slashes in a row in the URI are one.
    pub merge_slashes: bool,
    pub body_buffer: u64,
    pub body_in_file_only: bool,
    /// client_body_in_file_only clean: the file is removed after the request.
    pub body_clean: bool,
    pub body_temp_path: PathBuf,
    /// The levels of client_body_temp_path: the lengths of the subdirectory
    /// names, taken from the end of the file name.
    pub body_temp_levels: Vec<usize>,
    /// expires, as written ("modified 1h", "$arg_e"): parsed for each response.
    pub expires: Option<Template>,
    /// post_action: the URI (or named location) asked for after the answer is
    /// sent, its own answer discarded; None when "off".
    pub post_action: Option<String>,
    /// alias: the path that replaces the location's prefix, instead of root.
    pub alias: Option<PathBuf>,
    /// The length of the location prefix that alias replaces; None when alias is
    /// in a regular expression location, where it names the whole path.
    pub alias_len: Option<usize>,
    /// alias with variables (as captures of the location), under the prefix.
    pub alias_vars: Option<Template>,
    /// try_files, which locations do not inherit.
    pub try_files: Option<Arc<TryFiles>>,
    /// How a Location that starts with "/" is sent: made absolute with
    /// "http://host[:port]" (absolute_redirect), the host being the server's
    /// name rather than the request's (server_name_in_redirect), and the port
    /// left out when port_in_redirect is off.
    pub absolute_redirect: bool,
    /// server_tokens: whether the Server header and the pages twinx generates
    /// give its version ("on" and "build", as there is no build name) or only its name.
    pub server_tokens: bool,
    /// chunked_transfer_encoding: whether an HTTP/1.1 answer of unknown length
    /// (or with trailers) may be chunked; off, it ends when the connection closes.
    pub chunked: bool,
    pub server_name_in_redirect: bool,
    pub port_in_redirect: bool,
    /// keepalive_requests: the requests a connection may serve.
    pub keepalive_requests: u64,
    /// keepalive_timeout: how long a kept-alive connection waits for the next
    /// request (zero: no keepalive), and the timeout of the Keep-Alive header.
    pub keepalive_timeout: Duration,
    pub keepalive_header: Option<u64>,
    /// keepalive_time: how long a connection may serve requests.
    pub keepalive_time: Duration,
    /// keepalive_disable: no keepalive for POST from MSIE 6 and older, and for Safari.
    pub keepalive_disable_msie6: bool,
    pub keepalive_disable_safari: bool,
    /// lingering_close: whether what the client still sends is read when its
    /// connection is closed. None when off; Some(false) for "on", when something
    /// may be unread; Some(true) for "always".
    pub lingering_close: Option<bool>,
    /// default_type: the Content-Type of files whose extension has no type.
    pub default_type: String,
    /// proxy_set_header: the headers sent to the proxied server instead of the client's.
    pub proxy_set_header: Vec<(String, Template)>,
    /// proxy_hide_header: the headers of the proxied server's answer not passed
    /// to the client besides those nginx never passes, lowercased.
    pub proxy_hide_header: Vec<String>,
    /// proxy_pass_header: the headers of the proxied server's answer passed to the
    /// client although nginx or proxy_hide_header hides them, lowercased.
    pub proxy_pass_header: Vec<String>,
    /// proxy_intercept_errors: error_page replaces the answers of proxied servers too.
    pub proxy_intercept_errors: bool,
    /// proxy_pass_request_headers, proxy_pass_request_body: whether the
    /// client's headers and body are passed to the proxied server.
    pub proxy_pass_request_headers: bool,
    pub proxy_pass_request_body: bool,
    /// proxy_request_buffering: whether the whole body is read before the
    /// request is passed; when off, a body with a Content-Length is passed as it comes.
    pub proxy_request_buffering: bool,
    /// proxy_http_version 1.1: requests are passed as HTTP/1.1, and a chunked
    /// body that is not buffered is passed chunked as it comes.
    pub proxy_http_11: bool,
    /// proxy_http_version 2: requests are passed over HTTP/2 (crate::h2::upstream).
    pub proxy_h2: bool,
    /// proxy_pass_trailers: the trailers of a proxied server's answer are passed to the client.
    pub proxy_pass_trailers: bool,
    /// proxy_buffer_size: the buffer the proxied server's response head must fit in.
    pub proxy_buffer_size: usize,
    /// proxy_buffering: what of a proxied answer's body is in full buffers is sent as they
    /// are full, not all that has come at once (off).
    pub proxy_buffering: bool,
    /// proxy_cache: the zone answers are cached in, if any.
    pub proxy_cache: Option<CacheZone>,
    /// proxy_cache_lock: one request at a time asks the server for what is not cached yet.
    pub proxy_cache_lock: bool,
    /// proxy_cache_lock_timeout: how long a request waits for another that asks for the same key.
    pub proxy_cache_lock_timeout: Duration,
    /// proxy_cache_lock_age: how long the request that asks the server for a key may take
    /// before another one asks in its place.
    pub proxy_cache_lock_age: Duration,
    /// proxy_cache_valid: for how long answers of each status (None: any) are valid.
    pub proxy_cache_valid: Vec<(Option<u16>, Duration)>,
    /// proxy_cache_min_uses: how many requests ask for a key before its answer is cached.
    pub proxy_cache_min_uses: u64,
    /// proxy_cache_max_range_offset: a request whose range starts at this offset or
    /// past it is passed to the server as it is, and its answer not cached (None: no limit).
    pub proxy_cache_max_range_offset: Option<u64>,
    /// proxy_cache_use_stale: when an answer no longer valid is given rather than the
    /// server's ("error", "timeout", "http_500", ...).
    pub proxy_cache_use_stale: Vec<String>,
    /// proxy_no_cache: the answer is not cached when one of these is neither empty nor "0".
    pub proxy_no_cache: Vec<Template>,
    /// proxy_cache_bypass: the server is asked, and its answer cached, when one of these is
    /// neither empty nor "0".
    pub proxy_cache_bypass: Vec<Template>,
    /// proxy_cache_key: what an answer is cached by ($scheme$proxy_host$request_uri without it).
    pub proxy_cache_key: Option<Template>,
    /// proxy_cache_background_update: what is no longer valid but may be given while it is
    /// updated is given at once, and the server asked for the update meanwhile.
    pub proxy_cache_background_update: bool,
    /// proxy_cache_convert_head: a HEAD that may be cached asks the server with GET (on by default).
    pub proxy_cache_convert_head: bool,
    /// proxy_cache_revalidate: what is kept but no longer valid is asked for with the
    /// conditions of its Last-Modified and ETag, and kept again when the server says 304.
    pub proxy_cache_revalidate: bool,
    /// proxy_force_ranges: ranges of a proxied answer are given whatever its Accept-Ranges says.
    pub proxy_force_ranges: bool,
    /// max_ranges: how many ranges a request may ask for before it is given the whole
    /// answer; 0 gives no ranges at all (none: no limit).
    pub max_ranges: Option<usize>,
    /// proxy_ignore_headers: the headers of proxied answers that are not acted on, lowercase.
    pub proxy_ignore_headers: Vec<String>,
    /// proxy_buffers: the number and the size of the buffers the body is read into.
    pub proxy_buffers: (usize, usize),
    /// proxy_busy_buffers_size: how much of those is written at once, twice the size of
    /// the larger buffers without it.
    pub proxy_busy_buffers_size: Option<usize>,
    /// proxy_temp_file_write_size: how much of an answer is written to its file at once,
    /// twice the size of the larger buffers without it.
    pub proxy_temp_file_write_size: Option<usize>,
    /// proxy_max_temp_file_size: how large the file of an answer may be, 0 for no file.
    pub proxy_max_temp_file_size: usize,
    /// proxy_temp_path and its levels, as client_body_temp_path's.
    pub proxy_temp_path: PathBuf,
    pub proxy_temp_levels: Vec<usize>,
    /// proxy_next_upstream: when the next server is tried ("error", "http_404", ...).
    pub proxy_next_upstream: Vec<String>,
    /// proxy_next_upstream_tries: how many servers a request may try, 0 for any.
    pub proxy_next_upstream_tries: usize,
    /// proxy_next_upstream_timeout: how long servers may be tried, zero for ever.
    pub proxy_next_upstream_timeout: Duration,
    /// gzip_static: None when off, Some(true) for "always".
    pub gzip_static: Option<bool>,
    /// gzip: compress answers for clients that take gzip.
    pub gzip: bool,
    /// gzip_types: the types compressed besides text/html, "*" for any.
    pub gzip_types: Vec<String>,
    pub gunzip: bool,
    pub gzip_vary: bool,
    /// gzip_min_length: the shortest answer, by its length, that is compressed.
    pub gzip_min_length: u64,
    /// gzip_http_version 1.1 (the default): HTTP/1.0 requests are not given gzip.
    pub gzip_http_11: bool,
    /// resolver: what looks up the names of proxy_pass URLs with variables,
    /// waiting for an answer up to resolver_timeout.
    pub resolver: Option<Arc<Resolver>>,
    pub resolver_timeout: Duration,
    pub proxy_connect_timeout: Duration,
    pub proxy_read_timeout: Duration,
    /// send_timeout: how long a write to the client may wait (60s).
    pub send_timeout: Duration,
    /// sendfile and sendfile_max_chunk: files go to plain TCP connections without being
    /// read, at most so much at a time (2 MB; zero: no limit).
    pub sendfile: bool,
    pub sendfile_max_chunk: u64,
    /// tcp_nopush: with sendfile, the head and the file go in full packets.
    pub tcp_nopush: bool,
    /// tcp_nodelay (on): what is sent does not wait for what was sent before to be acknowledged.
    pub tcp_nodelay: bool,
    /// proxy_bind: the local address, which may have variables, that
    /// connections to proxied servers are made from, and whether it may be
    /// a foreign one ("transparent"); None when off.
    pub proxy_bind: Option<(Template, bool)>,
    /// limit_rate and limit_rate_after: sizes, which may have variables,
    /// evaluated when the answer is sent.
    pub limit_rate: Template,
    pub limit_rate_after: Template,
    /// proxy_method: the method, which may have variables, sent to proxied
    /// servers instead of the request's.
    pub proxy_method: Option<Template>,
    /// early_hints: the values, which may have variables, of which one not
    /// empty and not "0" lets the early hints of proxied servers (103) go to the client.
    pub early_hints: Vec<Template>,
    /// proxy_set_body: the body, which may have variables, sent to proxied
    /// servers instead of the client's.
    pub proxy_set_body: Option<Template>,
    /// proxy_limit_rate: the rate a proxied answer is read at, a size that may
    /// have variables, evaluated once its head has come; 0 or none is no limit.
    pub proxy_limit_rate: Template,
    /// if_modified_since: None when off; Some(true) for "before", where an
    /// If-Modified-Since time after Last-Modified holds too, not only an equal one.
    pub if_modified_since: Option<bool>,
    /// ssl_certificate and ssl_certificate_key: the files of the server's
    /// certificates and their keys, in pairs, in the order they were given.
    pub ssl_certificate: Vec<PathBuf>,
    pub ssl_certificate_key: Vec<PathBuf>,
    /// ssl_certificate_compression: certificates are sent compressed to
    /// clients that ask for it.
    pub ssl_certificate_compression: bool,
    /// ssl_ciphers: the TLS 1.2 cipher suites taken, in OpenSSL's terms; None takes all.
    pub ssl_ciphers: Option<String>,
    /// ssl_protocols: whether TLS 1.2 and TLS 1.3 are taken, in that order.
    pub ssl_protocols: [bool; 2],
    /// ssl_prefer_server_ciphers: the server's order of cipher suites wins over the client's.
    pub ssl_prefer_server_ciphers: bool,
    /// ssl_reject_handshake: handshakes for the server are refused with an
    /// unrecognized_name alert.
    pub ssl_reject_handshake: bool,
    /// http2: connections that start with the HTTP/2 preface speak HTTP/2.
    pub http2: bool,
    /// ssl_ecdh_curve: the groups keys are exchanged with; None takes the default ones.
    pub ssl_ecdh_curve: Option<String>,
    /// ssl_session_ticket_key: the files of the keys tickets are encrypted
    /// with; those of a level replace those inherited as a whole.
    pub ssl_session_ticket_key: Vec<PathBuf>,
    /// ssl_conf_command: OpenSSL's commands and their values, files named in
    /// full; those of a level replace those inherited as a whole.
    pub ssl_conf_command: Vec<(String, String)>,
    /// limit_except: the methods allowed (HEAD with GET), and the settings of
    /// the block, which requests with any other method get instead of the
    /// location's. Nested locations and if blocks do not inherit it.
    pub limit_except: Option<(Vec<String>, Arc<Level>)>,
    /// proxy_ssl_session_reuse: TLS sessions to proxied servers are reused.
    pub proxy_ssl_session_reuse: bool,
    /// ssl_session_tickets, ssl_session_cache (whether it keeps sessions: not
    /// off or none) and ssl_session_timeout: how clients' sessions are resumed.
    pub ssl_sessions: crate::tls::Sessions,
    /// ssl_certificate_cache: what connections keep loaded of the files
    /// ssl_certificate and ssl_certificate_key name with variables.
    pub ssl_certificate_cache: Option<Arc<crate::tls::CertCache>>,
    /// ssl_password_file: the passwords an encrypted ssl_certificate_key is tried with.
    pub ssl_password_file: Option<PathBuf>,
    /// ssl_verify_client: off (0), on (1), optional (2) or optional_no_ca (3);
    /// clients are asked for a certificate unless it is off.
    pub ssl_verify_client: u8,
    /// ssl_trusted_certificate and ssl_client_certificate: the certificates
    /// clients' certificates are verified with.
    pub ssl_trusted_certificate: Option<PathBuf>,
    pub ssl_client_certificate: Option<PathBuf>,
    /// ssl_crl and ssl_verify_depth: the CRLs clients' certificates are
    /// checked against, and how many issuers their chains may have (1).
    pub ssl_crl: Option<PathBuf>,
    pub ssl_verify_depth: usize,
    /// ssl_ocsp (off, on, or leaf: only the client's own certificate),
    /// ssl_ocsp_responder and ssl_ocsp_cache (the name of its zone).
    pub ssl_ocsp: Option<bool>,
    pub ssl_ocsp_responder: Option<String>,
    pub ssl_ocsp_cache: Option<String>,
    /// ssl_stapling, ssl_stapling_file, ssl_stapling_responder and ssl_stapling_verify.
    pub ssl_stapling: bool,
    pub ssl_stapling_file: Option<PathBuf>,
    pub ssl_stapling_responder: Option<String>,
    pub ssl_stapling_verify: bool,
    /// proxy_ssl_certificate, proxy_ssl_certificate_key and proxy_ssl_password_file:
    /// the certificate twinx presents to proxied servers.
    /// The certificate and key may have variables in their names.
    pub proxy_ssl_certificate: Option<Template>,
    pub proxy_ssl_certificate_key: Option<Template>,
    pub proxy_ssl_password_file: Option<PathBuf>,
    /// With variables in them, the names of the certificate and key that
    /// each connection loads, relative to the prefix.
    pub proxy_ssl_certificate_vars: Option<(Template, Template, PathBuf)>,
    /// proxy_ssl_certificate_cache: what those connections keep loaded.
    pub proxy_ssl_certificate_cache: Option<Arc<crate::tls::CertCache>>,
    /// proxy_ssl_verify, proxy_ssl_trusted_certificate, proxy_ssl_crl and
    /// proxy_ssl_verify_depth: whether, and with what, proxied servers'
    /// certificates are verified.
    pub proxy_ssl_verify: bool,
    pub proxy_ssl_trusted_certificate: Option<PathBuf>,
    pub proxy_ssl_crl: Option<PathBuf>,
    pub proxy_ssl_verify_depth: usize,
    /// proxy_ssl_name: the name they are verified for, and sent with SNI when
    /// proxy_ssl_server_name is on; $proxy_host when not set.
    pub proxy_ssl_name: Option<Template>,
    pub proxy_ssl_server_name: bool,
    /// What connections to proxied servers over TLS are made with, made again
    /// at a level that sets one of the proxy_ssl_* directives above.
    pub proxy_tls: Option<Arc<rustls::ClientConfig>>,
}

/// try_files: the files tried in order, each a directory when its parameter
/// ends with "/" (here left out), and what is done when none exists.
#[derive(Debug)]
pub struct TryFiles {
    pub files: Vec<(Template, bool)>,
    pub fallback: Fallback,
}

/// The last parameter of try_files: "=code", or a URI to redirect to internally.
#[derive(Debug, PartialEq)]
pub enum Fallback {
    Status(u16),
    Uri(Template),
}

/// How a location matches the URI: "=", a prefix, "^~" (a prefix that stops
/// the regular expressions from being checked), or "~" / "~*".
#[derive(Debug)]
pub enum Match {
    Exact,
    Prefix,
    NoRegex,
    Regex(regex::Regex),
    /// "@name": only error_page goes there, never a URI.
    Named,
}

#[derive(Debug)]
pub struct Location {
    pub kind: Match,
    pub path: String,
    pub level: Level,
    /// A request for the path without its trailing "/" is redirected to it,
    /// as nginx does for locations ending with "/" that proxy_pass passes on.
    pub auto_redirect: bool,
}

/// A server_name: an exact name, "*.name" (here ".name"), "name.*" (here
/// "name."), or "~regex", matched against the host case-insensitively.
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
    /// The first name as written ($server_name), without the leading "." of ".name".
    pub name: String,
    pub level: Level,
    pub locations: Vec<Location>,
    /// The addresses it listens on with "ssl", and what it takes TLS
    /// connections with, when it has a certificate.
    pub ssl: Vec<SocketAddr>,
    pub tls: Option<crate::tls::ServerTls>,
    /// The addresses it is the default server of ("listen ... default_server").
    pub defaults: Vec<SocketAddr>,
    /// The listen backlogs it sets ("listen ... backlog=number").
    pub backlogs: Vec<(SocketAddr, i32)>,
    /// The addresses it listens on with "http2", which speak HTTP/2 whatever http2 says.
    pub http2: Vec<SocketAddr>,
}

/// The parameters of listen that are words of their own, and those that are
/// "name=value" (all of which set options of the socket); any other is refused.
const LISTEN_WORDS: &[&str] = &["default_server", "default", "ssl", "http2", "quic", "proxy_protocol", "deferred", "bind", "reuseport", "multipath"];
const LISTEN_VALUES: &[&str] = &["setfib", "fastopen", "backlog", "rcvbuf", "sndbuf", "accept_filter", "ipv6only", "so_keepalive"];

/// The backlog nginx listens with on Linux when "listen" does not set one
/// (NGX_LISTEN_BACKLOG).
pub const LISTEN_BACKLOG: i32 = 511;

#[derive(Debug)]
pub struct Config {
    pub pid: PathBuf,
    /// worker_rlimit_nofile: the limit on open files the worker sets for itself.
    pub rlimit_nofile: Option<u64>,
    /// worker_shutdown_timeout: how long a worker shutting down gracefully waits for its requests.
    pub shutdown_timeout: Option<Duration>,
    /// working_directory: where a worker changes to when it starts, as given, not relative to the prefix.
    pub working_directory: Option<PathBuf>,
    /// The error_log files of the main block that take alerts, and those that take notices.
    pub alert_logs: Vec<Arc<File>>,
    pub notice_logs: Vec<Arc<File>>,
    /// The directories of temporary files, which are made when the configuration is loaded.
    pub temp_paths: Vec<PathBuf>,
    pub servers: Vec<Server>,
}

struct Builder<'a> {
    prefix: &'a Path,
    formats: HashMap<String, Arc<Format>>,
    logs: HashMap<PathBuf, Arc<File>>,
    upstreams: HashMap<String, Arc<Upstream>>,
    /// The zones of proxy_cache_path, by name.
    zones: HashMap<String, Arc<crate::cache::Zone>>,
    implicit: Implicit,
    /// error_log of the main block.
    errors: Vec<(Arc<File>, usize)>,
    /// The directories of temporary files of all levels, with their levels of subdirectories
    /// and where the directives are, the defaults having none.
    temp_paths: Vec<(PathBuf, Vec<usize>, Option<String>)>,
    /// The name of the location whose directives are being read, which
    /// "proxy_redirect default" puts in place of the proxy_pass URL.
    location: String,
    /// Whether that location is a regular expression or named, where proxy_pass may not have a URI.
    location_no_uri: bool,
    /// The addresses servers listen on, with whether one is the default server of
    /// it and whether one gave options of its socket.
    listens: HashMap<(SocketAddr, bool), (bool, bool)>,
}

/// Interprets the main block. Errors are nginx's messages, with the place.
pub fn build(main: &[Directive], prefix: &Path) -> Result<Config, String> {
    let combined = Arc::new(Format { line: Template::parse(COMBINED)?, escape: Escape::Default });
    let formats = HashMap::from([("combined".to_string(), combined)]);
    let mut b = Builder { prefix, formats, logs: HashMap::new(), upstreams: HashMap::new(), zones: HashMap::new(), implicit: Implicit::default(), errors: Vec::new(), temp_paths: Vec::new(), location: String::new(), location_no_uri: false, listens: HashMap::new() };
    let mut config = Config { pid: prefix.join("logs/nginx.pid"), rlimit_nofile: None, shutdown_timeout: None, working_directory: None, alert_logs: Vec::new(), notice_logs: Vec::new(), temp_paths: Vec::new(), servers: Vec::new() };
    // Read first: the http block loads its certificates as it says.
    let inheritable = main.iter().find(|d| d.name == "ssl_object_cache_inheritable").map_or(Ok(true), |d| flag(d).map_err(|e| format!("{e} in {}", d.at)))?;
    crate::tls::new_configuration(inheritable);
    // So are the error logs, which the http block inherits wherever they are.
    for d in main.iter().filter(|d| d.name == "error_log") {
        b.check(d, MAIN)?;
        let log = b.error_log(d)?;
        b.errors.push(log);
    }
    for (i, d) in main.iter().enumerate() {
        b.check(d, MAIN)?;
        once(&main[..i], d)?;
        match d.name.as_str() {
            "pid" => config.pid = b.path(&d.args[0]),
            "worker_rlimit_nofile" => config.rlimit_nofile = Some(d.args[0].parse().map_err(|_| format!("invalid number in {}", d.at))?),
            // twinx serves every connection from one process, however many workers are asked for.
            "worker_processes" => if d.args[0] != "auto" && d.args[0].parse::<u32>().is_err() { return Err(format!("invalid value \"{}\" in \"worker_processes\" directive in {}", d.args[0], d.at)) },
            "worker_shutdown_timeout" => config.shutdown_timeout = Some(millis(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?),
            "working_directory" => config.working_directory = Some(d.args[0].clone().into()),
            "error_log" => {
                let file = b.open(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
                let level = d.args.get(1).map(|l| LEVELS.iter().position(|v| v == l));
                if level.is_none_or(|l| l <= Some(6)) { config.alert_logs.push(file.clone()) }
                if level.is_none_or(|l| l <= Some(2)) { config.notice_logs.push(file) }
            }
            "events" => d.block.iter().flatten().try_for_each(|e| b.check(e, EVENTS))?,
            "http" => config.servers = b.http(d.block.as_deref().unwrap_or_default())?,
            _ => {}
        }
    }
    // Checked once all of the file is read, as ngx_event_init_conf() does.
    if !main.iter().any(|d| d.name == "events") { return Err("no \"events\" section in configuration".into()); }
    config.temp_paths = b.temp_paths.into_iter().map(|t| t.0).collect();
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

    /// Takes note of a directory of temporary files, as ngx_add_path() does. The name of one
    /// that is not relative to the prefix keeps the "/" it ends with.
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

    /// Opens (creating it) a log file to append to; one handle per path.
    fn open(&mut self, p: &str) -> Result<Arc<File>, String> {
        let path = self.path(p);
        if let Some(f) = self.logs.get(&path) { return Ok(f.clone()); }
        let file = OpenOptions::new().create(true).append(true).open(&path);
        let file = Arc::new(file.map_err(|e| format!("open() \"{}\" failed ({e})", path.display()))?);
        self.logs.insert(path, file.clone());
        Ok(file)
    }

    /// The file of an error_log, and the level from which on it is written to.
    fn error_log(&mut self, d: &Directive) -> Result<(Arc<File>, usize), String> {
        let file = self.open(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
        Ok((file, d.args.get(1).and_then(|l| LEVELS.iter().position(|v| v == l)).unwrap_or(4)))
    }

    fn http(&mut self, block: &[Directive]) -> Result<Vec<Server>, String> {
        let (temp, proxy_temp) = (self.path("client_body_temp"), self.path("proxy_temp"));
        // Without root, files come from html under the prefix, as nginx's default root is.
        let mut level = Level { error_log: self.errors.clone(), root: self.path("html"), default_type: "text/plain".into(), gzip_http_11: true, gzip_min_length: 20, proxy_cache_min_uses: 1, proxy_cache_lock_timeout: crate::cache::LOCK_TIMEOUT, proxy_cache_lock_age: crate::cache::LOCK_TIMEOUT, proxy_cache_convert_head: true, max_body: 1 << 20, max_headers: 1000, header_buffer: 1 << 10, proxy_http_11: true, proxy_buffer_size: 4 << 10, proxy_buffering: true, proxy_buffers: (8, 4 << 10), proxy_max_temp_file_size: 1 << 30, proxy_temp_path: proxy_temp, proxy_temp_levels: vec![1, 2], large_header_buffers: (4, 8 << 10), ignore_invalid_headers: true, merge_slashes: true, if_modified_since: Some(false), log_not_found: true, index: vec![Template::parse("index.html")?], body_buffer: 16 << 10, body_temp_path: temp, absolute_redirect: true, server_tokens: true, chunked: true, port_in_redirect: true,
            keepalive_requests: 1000, keepalive_timeout: Duration::from_secs(75), keepalive_time: Duration::from_secs(3600), keepalive_disable_msie6: true, lingering_close: Some(false),
            resolver_timeout: Duration::from_secs(30), proxy_connect_timeout: Duration::from_secs(60), proxy_pass_request_headers: true, proxy_pass_request_body: true, proxy_request_buffering: true, proxy_redirect: Some(Vec::new()), proxy_ssl_session_reuse: true, proxy_ssl_verify_depth: 1, ssl_verify_depth: 1, ssl_protocols: [true, true], proxy_tls: Some(crate::tls::client((true, false), None, None)?), proxy_next_upstream: vec!["error".into(), "timeout".into()], proxy_read_timeout: Duration::from_secs(60), send_timeout: Duration::from_secs(60), sendfile_max_chunk: 2 << 20, tcp_nodelay: true, ..Level::default() };
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
            self.upstreams.insert(d.args[0].clone(), Arc::new(upstream));
        }
        // The zones of proxy_cache_path are known before proxy_cache names them.
        for d in block.iter().filter(|d| d.name == "proxy_cache_path") {
            self.check(d, HTTP)?;
            let name = crate::cache::zone_name(&d.args[1..]).ok_or_else(|| format!("\"{}\" must have \"keys_zone\" parameter in {}", d.name, d.at))?;
            self.zones.insert(name.to_string(), Arc::new(crate::cache::Zone::at(self.path(&d.args[0]))));
        }
        // Named captures of server names are variables everywhere, so they are known first.
        let names = block.iter().filter(|d| d.name == "server").flat_map(|d| d.block.iter().flatten()).filter(|d| d.name == "server_name");
        names.flat_map(|d| d.args.iter()).filter(|n| n.starts_with('~')).for_each(|n| drop(server_name(n)));
        // So are the variables set gives values to, wherever it is.
        fn declare(block: &[Directive]) {
            for d in block {
                if let Some(name) = d.args.first().and_then(|a| a.strip_prefix('$')).filter(|_| d.name == "set") { crate::vars::add_user(name); }
                declare(d.block.as_deref().unwrap_or_default());
            }
        }
        declare(block);
        self.level(block, HTTP, &mut level)?;
        let servers = block.iter().filter(|d| d.name == "server");
        let servers: Vec<Server> = servers.map(|d| self.server(d.block.as_deref().unwrap_or_default(), &level)).collect::<Result<_, _>>()?;
        // nginx merges the levels of the proxy module once all of the block is read. Those of
        // if and limit_except, where none of these directives may be, are as the one around them.
        // The default directories are those of servers without directives of their own or inherited.
        let given = |block: &[Directive], name| block.iter().any(|d| d.name == name);
        let default = |name| !given(block, name) && block.iter().any(|d| d.name == "server" && !given(d.block.as_deref().unwrap_or_default(), name));
        if default("client_body_temp_path") { self.temp_path("client_body_temp", &[], None)?; }
        servers.iter().flat_map(|s| [&s.level].into_iter().chain(s.locations.iter().map(|l| &l.level))).try_for_each(check_proxy_buffers)?;
        if default("proxy_temp_path") { self.temp_path("proxy_temp", &[1, 2], None)?; }
        block.iter().filter(|d| d.name == "server").try_for_each(|d| same_locations(d.block.as_deref().unwrap_or_default()))?;
        Ok(servers)
    }

    fn server(&mut self, block: &[Directive], parent: &Level) -> Result<Server, String> {
        let mut s = Server { listen: Vec::new(), names: Vec::new(), name: String::new(), level: parent.clone(), locations: Vec::new(), ssl: Vec::new(), tls: None, defaults: Vec::new(), backlogs: Vec::new(), http2: Vec::new() };
        self.level(block, SRV, &mut s.level)?;
        let mut listens = Vec::new();
        for d in block {
            match d.name.as_str() {
                "listen" => {
                    let addrs = listen_ports(&d.args[0]).map_err(|e| format!("{e} in {}", d.at))?;
                    let quic = d.args[1..].iter().any(|a| a == "quic");
                    let valued = |a: &String| a.split_once('=').is_some_and(|(name, _)| LISTEN_VALUES.contains(&name));
                    if let Some(a) = d.args[1..].iter().find(|a| !LISTEN_WORDS.contains(&a.as_str()) && !valued(a)) { return Err(format!("invalid parameter \"{a}\" in {}", d.at)); }
                    // Options of the socket, which only one server of an address may give, as only one may be its default server.
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
                    s.listen.extend(addrs);
                }
                "server_name" => {
                    if s.names.is_empty() { s.name = d.args[0].strip_prefix('.').unwrap_or(&d.args[0]).to_string(); }
                    for n in &d.args { s.names.extend(server_name(n).map_err(|e| format!("{e} in {}", d.at))?); }
                }
                _ => {}
            }
        }
        if s.listen.is_empty() { s.listen.push(SocketAddr::from(([0, 0, 0, 0], 80))); }
        let l = &s.level;
        let trust: Vec<&Path> = [&l.ssl_trusted_certificate, &l.ssl_client_certificate].into_iter().flatten().map(PathBuf::as_path).collect();
        let mut options = crate::tls::Options { verify: l.ssl_verify_client > 0, sessions: l.ssl_sessions, compress: l.ssl_certificate_compression, ciphers: l.ssl_ciphers.clone(), protocols: l.ssl_protocols, prefer: l.ssl_prefer_server_ciphers, curves: l.ssl_ecdh_curve.clone(), crl: l.ssl_crl.clone(), depth: l.ssl_verify_depth, ocsp: l.ssl_ocsp.map(|leaf| crate::ocsp::Ocsp { leaf, responder: l.ssl_ocsp_responder.clone(), cache: l.ssl_ocsp_cache.clone() }), ticket_keys: l.ssl_session_ticket_key.clone(), stapling: l.ssl_stapling.then(|| crate::tls::Stapling { verify: l.ssl_stapling_verify, responder: l.ssl_stapling_responder.clone(), file: l.ssl_stapling_file.clone() }), client_ca: l.ssl_client_certificate.clone() };
        let extra = conf_commands(&l.ssl_conf_command, &mut options)?;
        let pairs = l.ssl_certificate.iter().zip(&l.ssl_certificate_key).chain(extra[0].iter().zip(&extra[1]));
        let files: Vec<(&Path, &Path)> = pairs.map(|(cert, key)| (cert.as_path(), key.as_path())).collect();
        let named = files.iter().any(|(cert, key)| [cert, key].iter().any(|p| p.to_string_lossy().contains('$')));
        s.tls = (!files.is_empty()).then(|| crate::tls::server((&files, l.ssl_password_file.as_deref()), named.then(|| l.ssl_certificate_cache.clone()), &trust, options)).transpose()?;
        let level = s.level.clone();
        self.locations(block, None, &level, &mut s.locations)?;
        Ok(s)
    }

    /// The locations of a block, and of the location it is in, if any, with its kind and name.
    fn locations(&mut self, block: &[Directive], around: Option<(Kind, &str)>, parent: &Level, out: &mut Vec<Location>) -> Result<(), String> {
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
            out.push(Location { kind, path, level: level.clone(), auto_redirect });
            self.locations(inner, Some((around, &name)), &level, out)?;
        }
        Ok(())
    }

    /// Applies the directives of one level that are not blocks of their own;
    /// access_log and error_log replace what the level above set as a whole.
    fn level(&mut self, block: &[Directive], ctx: u16, level: &mut Level) -> Result<(), String> {
        let mut logs: Option<Vec<Arc<AccessLog>>> = None;
        let mut errors: Option<Vec<(Arc<File>, usize)>> = None;
        let (mut headers, mut trailers): (Option<Vec<(String, Template, bool)>>, Option<Vec<_>>) = (None, None);
        let mut pages: Option<Vec<ErrorPage>> = None;
        // ssl_certificate and ssl_certificate_key of this level, which replace those inherited.
        let mut certs: [Option<Vec<PathBuf>>; 2] = [None, None];
        let mut commands: Option<Vec<(String, String)>> = None;
        let mut ticket_keys: Option<Vec<PathBuf>> = None;
        let mut proxy_headers: Option<Vec<(String, Template)>> = None;
        let (mut hidden, mut passed): (Option<Vec<String>>, Option<Vec<String>>) = (None, None);
        // proxy_cookie_domain and proxy_cookie_path of this level: Some(None) once "off".
        let mut cookies: [Option<Option<Vec<CookieRewrite>>>; 2] = [None, None];
        let mut flags: Option<Option<Vec<CookieFlags>>> = None;
        // proxy_redirect of this level, Some(None) once "off"; and whether proxy_pass is here.
        let (mut redirects, mut own_proxy): (Option<Option<Vec<CookieRewrite>>>, bool) = (None, false);
        let (mut ifs, mut limit, mut own_tls) = (Vec::new(), None, false);
        for (i, d) in block.iter().enumerate() {
            self.check(d, ctx)?;
            once(&block[..i], d)?;
            let at = |e: String| format!("{e} in {}", d.at);
            let invalid = || at(format!("\"{}\" directive invalid value", d.name));
            match d.name.as_str() {
                "return" => level.rewrite.push(ret(&d.args).map(|(code, text)| Step::Return(code, text)).map_err(at)?),
                "rewrite" => level.rewrite.push(rewrite(&d.args).map(Step::Rewrite).map_err(at)?),
                "break" => level.rewrite.push(Step::Break),
                "set" | "if" => {
                    let op = if d.name == "set" { set(&d.args) } else { condition(&d.args).map(|c| Op::If(c, Vec::new(), None)) }.map_err(at)?;
                    let script = if ctx == SRV { &mut level.server_script } else { &mut level.script };
                    if d.name == "if" { ifs.push((script.len(), d)); }
                    script.push(op);
                }
                "proxy_cookie_domain" | "proxy_cookie_path" => {
                    let (i, rewrite) = (d.name.ends_with("path") as usize, cookie_rewrite(&d.args, d.name.ends_with("domain")).map_err(at)?);
                    match (&mut cookies[i], rewrite) {
                        (None, rewrite) => cookies[i] = Some(rewrite.map(|r| vec![r])),
                        // More after "off", or "off" after more, is a duplicate.
                        (Some(Some(list)), Some(rewrite)) => list.push(rewrite), _ => return Err(at(format!("\"{}\" directive is duplicate", d.name))),
                    }
                }
                "proxy_cookie_flags" => {
                    // As with proxy_cookie_domain, "off" goes with nothing else at a level.
                    let rule = cookie_flags(&d.args).map_err(at)?;
                    if rule.is_none() && flags.is_some() || matches!(flags, Some(None)) { return Err(at("\"proxy_cookie_flags\" directive is duplicate".into())); }
                    flags = Some(rule.map(|rule| flags.take().flatten().unwrap_or_default().into_iter().chain([rule]).collect()));
                }
                "root" => (level.root, level.alias, level.alias_vars) = (self.path(&d.args[0]), None, None),
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
                // OpenSSL's commands that take a file are given its name in full, as nginx does.
                "ssl_conf_command" => commands.get_or_insert_default().push((d.args[0].clone(), if ["Certificate", "PrivateKey"].contains(&d.args[0].as_str()) { self.path(&d.args[1]).to_string_lossy().into_owned() } else { d.args[1].clone() })),
                // The sessions are kept in memory of each server, whatever the cache.
                "ssl_session_cache" => {
                    if let Some(a) = d.args.iter().find(|a| !(["off", "none", "builtin"].contains(&a.as_str()) || a.starts_with("builtin:") || a.starts_with("shared:") && a.matches(':').count() == 2)) { return Err(at(format!("invalid session cache \"{a}\""))); }
                    level.ssl_sessions.cache = d.args.iter().all(|a| a != "off" && a != "none");
                    level.ssl_sessions.shared = level.ssl_sessions.cache && d.args.iter().any(|a| a.starts_with("shared:"));
                }
                "ssl_session_ticket_key" => ticket_keys.get_or_insert_default().push(self.path(&d.args[0])),
                "ssl_session_tickets" => level.ssl_sessions.tickets = flag(d).map_err(at)?,
                "ssl_session_timeout" => level.ssl_sessions.timeout = seconds(&d.args[0]).map_err(at)?.as_secs(),
                "proxy_ssl_session_reuse" => (level.proxy_ssl_session_reuse, own_tls) = (flag(d).map_err(at)?, true),
                "ssl_password_file" => level.ssl_password_file = Some(self.path(&d.args[0])),
                "ssl_verify_client" => level.ssl_verify_client = ["off", "on", "optional", "optional_no_ca"].iter().position(|v| *v == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"ssl_verify_client\" directive, it must be \"on\", \"off\", \"optional\" or \"optional_no_ca\"", d.args[0])))? as u8,
                "ssl_ocsp" => level.ssl_ocsp = [("off", None), ("on", Some(false)), ("leaf", Some(true))].into_iter().find(|v| v.0 == d.args[0]).ok_or_else(|| at(format!("invalid value \"{}\" in \"ssl_ocsp\" directive, it must be \"on\", \"off\" or \"leaf\"", d.args[0])))?.1,
                "ssl_ocsp_responder" | "ssl_stapling_responder" => {
                    let url = Some(d.args[0].clone()).filter(|u| u.starts_with("http://")).ok_or_else(|| at(format!("invalid URL prefix in OCSP responder \"{}\" in resolver", d.args[0])))?;
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
                "proxy_ssl_name" => level.proxy_ssl_name = Some(Template::parse(&d.args[0]).map_err(at)?),
                "proxy_redirect" => {
                    let rule = if d.args == ["default"] {
                        let proxy = level.proxy.as_ref().filter(|_| own_proxy).ok_or_else(|| at("\"proxy_redirect default\" should be placed after the \"proxy_pass\" directive".into()))?;
                        Some(self.default_redirect(proxy).ok_or_else(|| at("\"proxy_redirect default\" cannot be used with \"proxy_pass\" directive with variables".into()))?)
                    } else {
                        cookie_rewrite(&d.args, false).map_err(at)?
                    };
                    // As with proxy_cookie_path, "off" goes with nothing else at a level.
                    match (&mut redirects, rule) {
                        (None, rule) => redirects = Some(rule.map(|r| vec![r])),
                        (Some(Some(list)), Some(rule)) => list.push(rule), _ => return Err(at("\"proxy_redirect\" directive is duplicate".into())),
                    }
                }
                // 0 is no limit.
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
                // "off" caches nothing.
                "proxy_cache" => level.proxy_cache = match Template::parse(&d.args[0]).map_err(at)? {
                    t if t.fixed().is_none() => Some(CacheZone::Named(t, Arc::new(self.zones.clone()))),
                    _ => (d.args[0] != "off").then(|| self.zones.get(&d.args[0]).cloned().map(CacheZone::Fixed).ok_or_else(|| at(format!("\"proxy_cache\" zone \"{}\" is unknown", d.args[0])))).transpose()?,
                },
                // All of those of a level replace those it inherits.
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
                    const VALUES: &[&str] = &["error", "timeout", "invalid_header", "updating", "http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429", "off"];
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
                "proxy_cache_revalidate" => level.proxy_cache_revalidate = flag(d).map_err(at)?,
                "proxy_force_ranges" => level.proxy_force_ranges = flag(d).map_err(at)?,
                "max_ranges" => level.max_ranges = Some(d.args[0].parse().map_err(|_| at("invalid number".into()))?),
                // All of those of a level replace those it inherits.
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
                "proxy_set_header" => proxy_headers.get_or_insert_default().push((d.args[0].clone(), Template::parse(&d.args[1]).map_err(at)?)),
                "resolver" => level.resolver = Some(Arc::new(Resolver::parse(&d.args).map_err(at)?)),
                "resolver_timeout" => level.resolver_timeout = seconds(&d.args[0]).map_err(at)?,
                "proxy_connect_timeout" => level.proxy_connect_timeout = millis(&d.args[0]).map_err(at)?,
                "proxy_read_timeout" => level.proxy_read_timeout = millis(&d.args[0]).map_err(at)?,
                "send_timeout" => level.send_timeout = seconds(&d.args[0]).map_err(at)?,
                "proxy_intercept_errors" => level.proxy_intercept_errors = flag(d).map_err(at)?,
                "proxy_pass_request_headers" => level.proxy_pass_request_headers = flag(d).map_err(at)?,
                "proxy_pass_request_body" => level.proxy_pass_request_body = flag(d).map_err(at)?,
                "proxy_next_upstream" => {
                    const VALUES: &[&str] = &["error", "timeout", "invalid_header", "http_500", "http_502", "http_503", "http_504", "http_403", "http_404", "http_429", "non_idempotent", "updating", "off"];
                    if let Some(a) = d.args.iter().find(|a| !VALUES.contains(&a.as_str())) { return Err(at(format!("invalid value \"{a}\""))); }
                    // "off" turns every other condition off.
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
                // twinx writes what an answer has as soon as it has it, which is what
                // nginx does with any postpone_output for the answers it sends whole.
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
        if let Some(headers) = headers { level.add_header = headers; }
        if let Some(trailers) = trailers { level.add_trailer = trailers; }
        if let Some(pages) = pages { level.error_page = pages; }
        let [certificates, keys] = certs;
        if let Some(c) = certificates { level.ssl_certificate = c; }
        if let Some(k) = keys { level.ssl_certificate_key = k; }
        if let Some(c) = commands { level.ssl_conf_command = c; }
        if let Some(k) = ticket_keys { level.ssl_session_ticket_key = k; }
        if let Some(headers) = proxy_headers { level.proxy_set_header = headers; }
        if let Some(hidden) = hidden { level.proxy_hide_header = hidden; }
        if let Some(passed) = passed { level.proxy_pass_header = passed; }
        let [domain, path] = cookies;
        if let Some(domain) = domain { level.proxy_cookie_domain = domain; }
        if let Some(path) = path { level.proxy_cookie_path = path; }
        if let Some(flags) = flags { level.proxy_cookie_flags = flags; }
        if let Some(redirects) = redirects { level.proxy_redirect = redirects; }
        if own_tls {
            // Names without variables are loaded once, here; an empty certificate is none.
            let names = level.proxy_ssl_certificate.clone().zip(level.proxy_ssl_certificate_key.clone()).filter(|(c, _)| !c.0.is_empty());
            let fixed = names.as_ref().and_then(|(c, k)| text(c).zip(text(k))).map(|(c, k)| (self.path(&c), self.path(&k)));
            level.proxy_ssl_certificate_vars = names.filter(|_| fixed.is_none()).map(|(c, k)| (c, k, self.prefix.to_path_buf()));
            let cert = fixed.as_ref().map(|(c, k)| (c.as_path(), k.as_path(), level.proxy_ssl_password_file.as_deref()));
            // Without trusted certificates nothing verifies; a location that proxies over TLS must have them.
            if level.proxy_ssl_verify && level.proxy_ssl_trusted_certificate.is_none() && level.proxy.as_ref().is_some_and(|p| p.ssl) { return Err("no proxy_ssl_trusted_certificate for proxy_ssl_verify".into()) }
            let verify = level.proxy_ssl_verify.then(|| crate::tls::verify(level.proxy_ssl_trusted_certificate.as_deref(), level.proxy_ssl_crl.as_deref(), level.proxy_ssl_verify_depth)).transpose()?;
            level.proxy_tls = Some(crate::tls::client((level.proxy_ssl_session_reuse, level.proxy_ssl_server_name), cert, verify)?);
        }
        // Without rules of its own or inherited, a location with proxy_pass has "proxy_redirect default".
        if level.proxy_redirect.as_ref().is_some_and(Vec::is_empty) && own_proxy {
            level.proxy_redirect = level.proxy.as_ref().and_then(|p| self.default_redirect(p)).map(|r| vec![r]).or(Some(Vec::new()));
        }
        // An if block inherits everything its level has, wherever it is written there.
        // One in a server block gives a level only to return, which answers at once.
        for (i, d) in ifs {
            let mut inner = Level { script: Vec::new(), server_script: Vec::new(), ..level.clone() };
            self.level(d.block.as_deref().unwrap_or_default(), if ctx == SRV { SIF } else { LIF }, &mut inner)?;
            let script = if ctx == SRV { &mut level.server_script } else { &mut level.script };
            if let Op::If(_, body, to) = &mut script[i] { (*body, *to) = (std::mem::take(&mut inner.script), (ctx != SRV || inner.rewrite.iter().any(|s| matches!(s, Step::Return(..)))).then(|| Arc::new(inner))); }
        }
        // A limit_except block inherits the location's settings, but not its set and if, which do not run there.
        if let Some((methods, d)) = limit {
            let mut inner = Level { script: Vec::new(), ..level.clone() };
            self.level(d.block.as_deref().unwrap_or_default(), LMT, &mut inner)?;
            level.limit_except = Some((methods, Arc::new(inner)));
        }
        Ok(())
    }

    /// access_log path [format [buffer=size] [gzip[=level]] [flush=time] [if=condition]] | off.
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

    /// "proxy_redirect default": the proxy_pass URL is replaced by the
    /// location's name, or, when the URL has no URI, the URL and "/" by "/".
    /// None for a URL with variables.
    fn default_redirect(&self, p: &Proxy) -> Option<CookieRewrite> {
        let text = |s: String| Template(vec![Part::Text(s)]);
        let url = format!("{}://{}{}", if p.ssl { "https" } else { "http" }, p.host, p.uri.as_deref().unwrap_or("/"));
        let replacement = if p.uri.is_some() { self.location.clone() } else { "/".to_string() };
        p.url.is_none().then(|| CookieRewrite { pattern: CookiePattern::Text(text(url)), replacement: text(replacement) })
    }

    /// proxy_pass http://host[:port][/uri], where host may name an upstream block.
    fn proxy(&self, url: &str) -> Result<Proxy, String> {
        let (rest, ssl) = url.strip_prefix("http://").map(|r| (r, false)).or_else(|| Some((url.strip_prefix("https://")?, true))).ok_or_else(|| format!("invalid URL prefix in \"{url}\""))?;
        let template = Template::parse(url)?;
        if template.0.iter().any(|p| matches!(p, Part::Var(_))) {
            return Ok(Proxy { host: String::new(), ssl: false, upstream: Arc::new(Upstream::new(Vec::new())), uri: None, url: Some(template), groups: self.upstreams.clone(), implicit: self.implicit.clone() });
        }
        let (host, uri) = rest.find('/').map_or((rest, None), |i| (&rest[..i], Some(rest[i..].to_string())));
        if host_port(host, 80).is_some_and(|(_, port)| port == 0) { return Err(format!("invalid port in upstream \"{rest}\"")); }
        // Any other host is an implicit upstream of all its addresses, one for each host and port.
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

/// Refuses a directive that was given before at its level, as most of nginx's do; root and
/// alias are one.
fn once(before: &[Directive], d: &Directive) -> Result<(), String> {
    // Nothing goes after "off" of these.
    let off = (d.name == "proxy_redirect" || d.name.starts_with("proxy_cookie_")) && before.iter().any(|b| b.name == d.name && b.args == ["off"]);
    if !off && REPEATED.contains(&d.name.as_str()) { return Ok(()) }
    let other = match d.name.as_str() { "root" => "alias", "alias" => "root", _ => "" };
    let Some(b) = before.iter().find(|b| b.name == d.name || b.name == other) else { return Ok(()) };
    let earlier = if b.name == other { format!(", \"{other}\" directive was specified earlier") } else { String::new() };
    Err(format!("\"{}\" directive is duplicate{earlier} in {}", d.name, d.at))
}

/// What a location is, for the locations inside it.
#[derive(Clone, Copy, PartialEq)]
enum Kind { Prefix, Exact, Named, Regex }

/// Refuses a location inside another where nginx's ngx_http_core_location() does: inside an exact
/// or a named one, a named one inside any, and one that is not a regular expression and does not
/// begin with the name of the location around it.
fn nested(kind: &Match, path: &str, around: Option<(Kind, &str)>) -> Result<(), String> {
    let Some((outer, name)) = around else { return Ok(()) };
    if outer == Kind::Exact { return Err(format!("location \"{path}\" cannot be inside the exact location \"{name}\"")); }
    if outer == Kind::Named { return Err(format!("location \"{path}\" cannot be inside the named location \"{name}\"")); }
    if matches!(kind, Match::Named) { return Err(format!("named location \"{path}\" can be on the server level only")); }
    if !matches!(kind, Match::Regex(_)) && !path.starts_with(name) { return Err(format!("location \"{path}\" is outside location \"{name}\"")); }
    Ok(())
}

/// Refuses two locations of a block for the same URI, or the same prefix, as
/// ngx_http_join_exact_locations() does. Named ones and regular expressions may be the same.
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

/// The name and port of host[:port], the default port when it has none; an
/// IPv6 address is written in brackets, which are left out.
pub fn host_port(host: &str, default: u16) -> Option<(&str, u16)> {
    let (name, port) = match host.rsplit_once(':') { Some((n, p)) if !p.contains(']') => (n, p.parse().ok()?), _ => (host, default) };
    Some((name.strip_prefix('[').and_then(|n| n.strip_suffix(']')).unwrap_or(name), port))
}

/// The addresses of a name as nginx's ngx_inet_resolve_host() finds them:
/// an address as it is, else those getaddrinfo() gives with AI_ADDRCONFIG,
/// the IPv4 ones first.
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

/// proxy_bind address [transparent] | off. An address without variables is
/// checked here; one with variables when it is used.
fn proxy_bind(args: &[String]) -> Result<Option<(Template, bool)>, String> {
    if args.len() == 1 && args[0] == "off" { return Ok(None); }
    if let Some(a) = args.get(1).filter(|a| *a != "transparent") { return Err(format!("invalid parameter \"{a}\"")); }
    let address = Template::parse(&args[0])?;
    let literal = address.0.iter().all(|p| matches!(p, Part::Text(_)));
    if literal && local_addr(&args[0]).is_none() { return Err(format!("invalid address \"{}\"", args[0])); }
    Ok(Some((address, args.len() == 2)))
}

/// An address to bind to, as nginx parses it: an IP address, with ":port" or
/// in brackets for IPv6 when a port follows; port 0 when there is none.
pub fn local_addr(s: &str) -> Option<SocketAddr> {
    let ip = |a: &str| a.parse::<std::net::IpAddr>().ok().map(|ip| SocketAddr::new(ip, 0));
    ip(s).or_else(|| s.strip_prefix('[')?.strip_suffix(']').and_then(ip)).or_else(|| s.parse().ok())
}

/// escape=default|json|none of log_format.
fn log_escape(e: &str) -> Result<Escape, String> {
    let modes = [("default", Escape::Default), ("json", Escape::Json), ("none", Escape::None)];
    modes.into_iter().find(|m| m.0 == e).map(|m| m.1).ok_or_else(|| format!("unknown log format escaping \"{e}\""))
}

/// open_log_file_cache max=N [inactive=time] [min_uses=N] [valid=time] | off
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

/// The text of a value without variables.
fn text(t: &Template) -> Option<String> {
    t.0.iter().map(|p| match p { Part::Text(t) => Some(t.as_str()), Part::Var(_) => None }).collect()
}

/// proxy_ssl_certificate_cache off | max=N [inactive=time] [valid=time]
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

/// location [ = | ^~ | ~ | ~* ] uri
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
    let regex = |p: String| regex::Regex::new(&p).map(Match::Regex).map_err(|e| format!("invalid regular expression \"{path}\": {e}"));
    let kind = match modifier {
        "~" | "~*" => regex(if modifier == "~*" { format!("(?i){path}") } else { path.clone() })?,
        _ => {
            let plain = [("", Match::Prefix), ("=", Match::Exact), ("^~", Match::NoRegex)].into_iter().find(|k| k.0 == modifier);
            let kind = plain.ok_or_else(|| format!("invalid location modifier \"{modifier}\""))?.1;
            if modifier.is_empty() && path.starts_with('@') { Match::Named } else { kind }
        }
    };
    Ok((kind, path.clone()))
}

/// server address [weight=n] [max_fails=n] [fail_timeout=time] [backup] [down] in an upstream block.
fn peer(args: &[String]) -> Result<Peer, String> {
    let addr = listen(&args[0]).map_err(|_| format!("host not found in upstream \"{}\"", args[0]))?;
    if addr.port() == 0 { return Err(format!("invalid port in upstream \"{}\"", args[0])); }
    let (mut values, mut backup, mut down) = ([("weight", 1u64), ("max_fails", 1), ("fail_timeout", 10)], false, false);
    for a in &args[1..] {
        if a == "backup" { backup = true; continue; }
        if a == "down" { down = true; continue; }
        let invalid = || format!("invalid parameter \"{a}\"");
        let (name, value) = a.split_once('=').ok_or_else(invalid)?;
        let slot = values.iter_mut().find(|v| v.0 == name).ok_or_else(invalid)?;
        slot.1 = value.trim_end_matches('s').parse().map_err(|_| invalid())?;
        if name == "weight" && slot.1 == 0 { return Err(invalid()); }
    }
    let [weight, max_fails, fail_timeout] = values.map(|v| v.1);
    Ok(Peer { addr, weight: weight as i64, max_fails, fail_timeout, backup, down })
}

/// keepalive number [local], keepalive_requests, keepalive_time and
/// keepalive_timeout in an upstream block; None when it keeps no connection.
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

/// expires [modified] time | epoch | max | off; a value without variables must be valid.
fn expires(args: &[String]) -> Result<Template, String> {
    let (value, t) = (args.join(" "), Template::parse(&args.join(" "))?);
    let literal = t.0.iter().all(|p| matches!(p, crate::vars::Part::Text(_)));
    if literal && crate::expires::parse(&value).is_none() { return Err(format!("invalid value \"{value}\"")); }
    Ok(t)
}

/// A time that may be in milliseconds, such as "3800ms" or "2s".
fn millis(s: &str) -> Result<Duration, String> {
    s.strip_suffix("ms").and_then(|ms| ms.parse().ok()).map(Duration::from_millis).map_or_else(|| seconds(s), Ok)
}

/// A time such as "1s" or "30", for directives that take one.
fn seconds(s: &str) -> Result<Duration, String> {
    crate::expires::parse_time(s).filter(|t| *t >= 0).map(|t| Duration::from_secs(t as u64)).ok_or_else(|| "invalid value".to_string())
}

/// What a server_name argument matches: ".name" is both "name" and "*.name".
/// The named captures of a regular expression become variables.
fn server_name(n: &str) -> Result<Vec<ServerName>, String> {
    if n.starts_with('*') && (n.len() < 3 || !n[1..].starts_with('.')) || n == "." { return Err(format!("server name \"{n}\" is invalid")); }
    if n == "~" { return Err(format!("empty regex in server name \"{n}\"")); }
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

/// A PCRE pattern in the syntax of the regex crate: "\Q...\E" quotes text.
fn pcre(p: &str) -> String {
    let (mut out, mut rest) = (String::new(), p);
    while let Some(i) = rest.find("\\Q") {
        let (quoted, next) = rest[i + 2..].split_once("\\E").unwrap_or((&rest[i + 2..], ""));
        out += &format!("{}{}", &rest[..i], regex::escape(quoted));
        rest = next;
    }
    out + rest
}

/// "on" or "off".
/// ssl_protocols: whether TLS 1.2 and TLS 1.3 are among the protocols
/// listed; the older ones nginx knows are taken but twinx has none of them.
fn protocols(args: &[String]) -> Result<[bool; 2], String> {
    if let Some(a) = args.iter().find(|a| !["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"].iter().any(|p| p.eq_ignore_ascii_case(a))) { return Err(format!("invalid value \"{a}\"")) }
    Ok(["TLSv1.2", "TLSv1.3"].map(|p| args.iter().any(|a| a.eq_ignore_ascii_case(p))))
}

/// ssl_conf_command, run as OpenSSL's SSL_CONF_cmd runs them, after the
/// other ssl_* directives: Options turns the options it lists, separated by
/// commas, on, or off when they begin with "-" (SessionTicket, the tickets of
/// ssl_session_tickets, ServerPreference, ssl_prefer_server_ciphers, and KTLS,
/// which changes nothing: twinx keeps TLS in user space, as OpenSSL does where
/// the kernel cannot take it);
/// Certificate and PrivateKey add a certificate and its key, given back in
/// that order, which replaces one of the same type of key.
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

/// ssl_ocsp_cache: off, or shared:name:size, as the zone's name.
fn ocsp_cache(value: &str) -> Result<Option<String>, String> {
    if value == "off" { return Ok(None) }
    let zone = value.strip_prefix("shared:").and_then(|z| z.rsplit_once(':')).filter(|(name, n)| !name.is_empty() && size(n).is_ok());
    zone.map(|(name, _)| Some(name.to_string())).ok_or_else(|| format!("invalid value \"{value}\""))
}

fn flag(d: &Directive) -> Result<bool, String> {
    let (value, name) = (&d.args[0], &d.name);
    let found = [("on", true), ("off", false)].into_iter().find(|f| f.0 == value.to_ascii_lowercase()).map(|f| f.1);
    found.ok_or_else(|| format!("invalid value \"{value}\" in \"{name}\" directive, it must be \"on\" or \"off\""))
}

/// set $variable value: a variable of its own, or $limit_rate; the other
/// variables twinx makes cannot be set.
fn set(args: &[String]) -> Result<Op, String> {
    let name = args[0].strip_prefix('$').ok_or_else(|| format!("invalid variable name \"{}\"", args[0]))?;
    if name != "limit_rate" && crate::vars::builtin(name) { return Err(format!("the duplicate \"{name}\" variable")); }
    Ok(Op::Set(name.to_string(), Template::parse(&args[1])?))
}

/// The condition of if, "(" and ")" around it. Of the conditions nginx has,
/// twinx has only a variable alone, true when not empty and not "0".
fn condition(args: &[String]) -> Result<Condition, String> {
    // As ngx_http_rewrite_if_condition() reads it: "(" and ")" may be arguments of their own.
    let invalid = format!("invalid condition \"{}\"", args[0]);
    let mut words: Vec<&str> = args.iter().map(String::as_str).collect();
    let last = words.len() - 1;
    words[0] = words[0].strip_prefix('(').ok_or(invalid.clone())?;
    words[last] = words[last].strip_suffix(')').ok_or(invalid.clone())?;
    words.retain(|w| !w.is_empty());
    match words[..] {
        [var] if var.starts_with('$') => Ok(Condition::Var(Template::parse(var)?)),
        [var, op @ ("=" | "!="), value] if var.starts_with('$') => Ok(Condition::Equal(Template::parse(var)?, Template::parse(value)?, op == "!=")),
        [var, op @ ("~" | "~*" | "!~" | "!~*"), re] if var.starts_with('$') => {
            let regex = regex::Regex::new(&format!("{}{}", if op.ends_with('*') { "(?i)" } else { "" }, pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?;
            Ok(Condition::Match(Template::parse(var)?, regex, op.starts_with('!')))
        }
        [op @ ("-f" | "-d" | "-e" | "-x" | "!-f" | "!-d" | "!-e" | "!-x"), path] => Ok(Condition::File(Template::parse(path)?, op.chars().last().unwrap_or_default(), op.starts_with('!'))), _ => Err(invalid),
    }
}

/// proxy_cookie_flags off | cookie [flag ...]: the cookie is a name, which may
/// have variables, or after "~" a caseless regular expression; a flag without
/// variables must be one nginx knows.
fn cookie_flags(args: &[String]) -> Result<Option<CookieFlags>, String> {
    if args == ["off"] { return Ok(None); }
    let cookie = match args[0].strip_prefix('~') {
        Some(re) => CookiePattern::Regex(regex::Regex::new(&format!("(?i){}", pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?),
        None => CookiePattern::Text(Template::parse(&args[0])?),
    };
    let flag = |f: &String| Template::parse(f).and_then(|t| if t.0.iter().all(|p| matches!(p, Part::Text(_))) && !COOKIE_FLAGS.iter().any(|k| k.eq_ignore_ascii_case(f)) { Err(format!("invalid parameter \"{f}\"")) } else { Ok(t) });
    Ok(Some(CookieFlags { cookie, flags: args[1..].iter().map(flag).collect::<Result<_, _>>()? }))
}

/// proxy_cookie_domain / proxy_cookie_path: off, or a pattern and its
/// replacement. A pattern that starts with "~" is a regular expression,
/// caseless for domains and with "~*" for paths; a leading "." of a domain
/// and of its replacement is left out.
fn cookie_rewrite(args: &[String], domain: bool) -> Result<Option<CookieRewrite>, String> {
    if args.len() == 1 { return if args[0] == "off" { Ok(None) } else { Err(format!("invalid parameter \"{}\"", args[0])) }; }
    let dot = |s: &str| Template::parse(if domain { s.strip_prefix('.').unwrap_or(s) } else { s });
    let Some(re) = args[0].strip_prefix('~') else { return Ok(Some(CookieRewrite { pattern: CookiePattern::Text(dot(&args[0])?), replacement: dot(&args[1])? })) };
    let (caseless, re) = if domain { (true, re) } else { re.strip_prefix('*').map_or((false, re), |re| (true, re)) };
    let regex = regex::Regex::new(&format!("{}{}", if caseless { "(?i)" } else { "" }, pcre(re))).map_err(|e| format!("invalid regular expression \"{re}\": {e}"))?;
    Ok(Some(CookieRewrite { pattern: CookiePattern::Regex(regex), replacement: Template::parse(&args[1])? }))
}

/// A size that may have variables; one without them must be valid.
fn size_value(s: &str) -> Result<Template, String> {
    let t = Template::parse(s)?;
    if t.0.iter().all(|p| matches!(p, Part::Text(_))) { size(s)?; }
    Ok(t)
}

/// What nginx checks of a level's buffers of proxied answers once it has those inherited,
/// in its order (ngx_http_proxy_merge_loc_conf). Products wrap around as nginx's do.
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

/// The levels of a temporary path: each a number above 0, ten digits at most in all.
fn temp_levels(args: &[String]) -> Option<Vec<usize>> {
    let levels: Vec<usize> = args.iter().map(|a| a.parse().ok().filter(|&n| n > 0 && a.bytes().all(|c| c.is_ascii_digit()))).collect::<Option<_>>()?;
    (levels.iter().sum::<usize>() <= 10).then_some(levels)
}

/// A size such as "512", "8k" or "1m".
pub fn size(s: &str) -> Result<u64, String> {
    scaled(s, &[("", 1), ("k", 1 << 10), ("K", 1 << 10), ("m", 1 << 20), ("M", 1 << 20)])
}

/// A file offset, as client_max_body_size takes it: a size that may also be in
/// gigabytes ("1g"), up to 2^63 - 1.
fn offset(s: &str) -> Result<u64, String> {
    scaled(s, &[("", 1), ("k", 1 << 10), ("K", 1 << 10), ("m", 1 << 20), ("M", 1 << 20), ("g", 1 << 30), ("G", 1 << 30)])
}

/// A number of digits and one of the units, scaled, up to 2^63 - 1.
fn scaled(s: &str, units: &[(&str, u64)]) -> Result<u64, String> {
    let (digits, unit) = s.find(|c: char| !c.is_ascii_digit()).map_or((s, ""), |i| s.split_at(i));
    let scale = units.iter().find(|u| u.0 == unit);
    digits.parse::<u64>().ok().zip(scale).and_then(|(n, (_, scale))| n.checked_mul(*scale)).filter(|&n| n <= i64::MAX as u64).ok_or_else(|| format!("\"{s}\" is invalid"))
}

fn add_header(args: &[String]) -> Result<(String, Template, bool), String> {
    if let Some(a) = args.get(2).filter(|a| *a != "always") { return Err(format!("invalid parameter \"{a}\"")); }
    let always = args.len() > 2;
    Ok((args[0].clone(), Template::parse(&args[1])?, always))
}

/// error_page code ... [=[response]] uri: a local URI the request is redirected
/// to internally, or a URL the client is redirected to. Named locations are not done yet.
fn error_page(args: &[String]) -> Result<ErrorPage, String> {
    let (url, rest) = args.split_last().unwrap();
    let (status, codes) = match rest.split_last() {
        // "=" alone (0) keeps the status of the answer the URI gives.
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

/// return code [text] | code URL | URL: a URL alone (http://, https:// or
/// $scheme first) is redirected to with 302.
fn ret(args: &[String]) -> Result<(u16, Template), String> {
    let url = |p: &str| args[0].len() > p.len() && args[0].starts_with(p) || p == "$scheme" && args[0].starts_with(p);
    if args.len() == 1 && ["http://", "https://", "$scheme"].into_iter().any(url) { return Ok((302, Template::parse(&args[0])?)); }
    let code = args[0].parse::<u16>().ok().filter(|c| *c <= 999);
    let code = code.ok_or_else(|| format!("invalid return code \"{}\"", args[0]))?;
    Ok((code, Template::parse(args.get(1).map_or("", |t| t.as_str()))?))
}

/// "addr:port", "addr" (port 80) or "port" (all addresses).
/// The addresses of a listen directive: a port range, port-port, stands for every port in it.
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

    fn return_code(level: &Level) -> u16 {
        level.rewrite.iter().find_map(|s| if let Step::Return(code, _) = s { Some(*code) } else { None }).unwrap()
    }

    fn build_text(text: &str) -> Result<Config, String> {
        let dir = std::env::temp_dir().join(format!("twinx-conf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Every configuration has an events block; the tests leave it out.
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
        // A URL with variables sees the implicit upstreams of locations after it, and one is made for each host and port.
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
        // Those of the main block, wherever they are.
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
    fn worker_processes() {
        assert!(build_text("worker_processes 2; http { }").is_ok() && build_text("worker_processes auto; http { }").is_ok());
        assert_eq!(build_text("worker_processes x;").unwrap_err(), "invalid value \"x\" in \"worker_processes\" directive in t.conf:1");
    }

    #[test]
    fn shared_session_caches() {
        let c = build_text("http { server { ssl_session_cache builtin shared:SSL:1m; } server { ssl_session_cache builtin; } server { ssl_session_cache none; } }").unwrap();
        assert_eq!(c.servers.iter().map(|s| s.level.ssl_sessions.shared).collect::<Vec<_>>(), [true, false, false]);
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
        assert!(re.is_match("/a.gif"));
        assert_eq!(location(&["!".into(), "/".into()]).unwrap_err(), "invalid location modifier \"!\"");
        assert!(location(&["~".into(), "(".into()]).is_err());
        let p = peer(&["127.0.0.1:1".into(), "max_fails=3".into(), "fail_timeout=5s".into()]).unwrap();
        assert_eq!((p.max_fails, p.fail_timeout, p.weight, p.backup), (3, 5, 1, false));
        assert!(peer(&["127.0.0.1:1".into(), "down".into()]).unwrap().down);
        assert_eq!(peer(&["127.0.0.1:1".into(), "up".into()]).unwrap_err(), "invalid parameter \"up\"");
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
            // The defaults are for servers without directives, also if they proxy nothing.
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
            // It comes before the check of the buffers, the one of the other directory after it.
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
            // Before its value is looked at.
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
            // One at each level, and what may be given more than once.
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
            // A location without proxy_pass, with what it inherits.
            ("proxy_busy_buffers_size 8k; server { location / { location /a { proxy_buffers 2 8k; } } location /b { proxy_buffer_size 16k; } }", BUSY),
            ("proxy_buffers 8 16k; server { proxy_max_temp_file_size 8k; location / { proxy_temp_file_write_size 8k; } }", MAX),
            // The order of the checks, and all of what is read before all of them.
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1; proxy_buffers 1 4k; }", TWO),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1; }", BUSY),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; proxy_busy_buffers_size 1m; }", ALL),
            ("server { proxy_max_temp_file_size 1; proxy_temp_file_write_size 1; }", WRITE),
            ("server { proxy_buffers 1 4k; } server { proxy_buffers 0 4k; }", "\"proxy_buffers\" directive invalid value in t.conf:1"),
        ] {
            assert_eq!(build_text(&format!("http {{ {http} }}")).err().as_deref(), Some(want), "{http}");
        }
        // Nothing to merge, values in the levels that are replaced, and the least and the most that fit.
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
        let c = build_text("http { server { rewrite ^/s http://s/; location / { rewrite ^/l http://l/; break; return 204; } } }").unwrap();
        let steps = &c.servers[0].locations[0].level.rewrite;
        assert!(matches!(steps[..], [Step::Rewrite(_), Step::Rewrite(_), Step::Break, Step::Return(204, _)]));
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
        // What it takes: the same location, error_page and name twice, a down server,
        // a regular expression in any location, options for one server of an address.
        assert!(http("upstream u { server 127.0.0.1:8081 down; } error_page 404 /a; error_page 404 /b;").is_none());
        assert!(server("server_name a a *.b c.*; location ~ ^/a { location ~ y { } location ^/a/x { } } location ~ ^/a { } location @a { } location @a { proxy_pass http://127.0.0.1:8081; } location /b { location /bc { } } location /p { proxy_pass http://127.0.0.1:8081/p; }").is_none());
        assert!(http("server { listen 127.0.0.1:8080 default_server backlog=10 ssl http2 deferred; } server { listen 127.0.0.1:8080; }").is_none());
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
    fn https_and_limit_except() {
        let c = build_text("http { server { listen 127.0.0.1:8443 ssl; location / { proxy_pass https://127.0.0.1/u; } \
                            location /l { limit_except GET { } } } }").unwrap();
        let s = &c.servers[0];
        assert_eq!(s.ssl, ["127.0.0.1:8443".parse().unwrap()]);
        let p = s.locations[0].level.proxy.as_ref().unwrap();
        assert!(p.ssl);
        assert_eq!(p.upstream.peers[0].addr, "127.0.0.1:443".parse().unwrap());
        let redirect = s.locations[0].level.proxy_redirect.as_ref().unwrap();
        assert!(matches!(&redirect[0].pattern, CookiePattern::Text(t) if matches!(&t.0[..], [Part::Text(u)] if u == "https://127.0.0.1/u")));
        assert_eq!(s.locations[1].level.limit_except.as_ref().unwrap().0, ["GET", "HEAD"]);
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
        assert!(build_text("http { ssl_stapling_responder https://a; }").unwrap_err().starts_with("invalid URL prefix in OCSP responder \"https://a\""));
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
