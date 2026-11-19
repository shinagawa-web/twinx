//! twinx: an HTTP server that reads nginx's configuration language and
//! answers the way nginx does.

pub mod config;
pub mod handler;
pub mod http;
pub mod location;
pub mod proxy;
pub mod range;
pub mod response;
pub mod server;
pub mod template;
pub mod time;

/// The version twinx names itself with in generated pages and headers.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The value of the Server header and of the signature in generated pages.
pub fn server_name_token() -> String {
    format!("twinx/{VERSION}")
}
