//! Listening sockets, connections, and choosing the virtual server.

use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::config::{Config, Server};
use crate::http::{self, find, parse_head, ParseError};
use crate::response;

const HEADER_LIMIT: usize = 1024 + 4 * 8192;
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

pub fn run(config: Config) -> Result<(), String> {
    let config = Arc::new(config);
    let ports: BTreeSet<u16> = config
        .servers
        .iter()
        .flat_map(|s| s.listens.iter().map(|l| l.port))
        .collect();
    let mut listeners = Vec::new();
    for port in ports {
        let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| {
            format!(
                "bind() to 0.0.0.0:{port} failed ({}: {})",
                e.raw_os_error().unwrap_or(0),
                e.kind()
            )
        })?;
        listeners.push(listener);
    }
    let mut handles = Vec::new();
    for listener in listeners {
        let config = config.clone();
        handles.push(thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let config = config.clone();
                thread::spawn(move || serve_connection(stream, &config));
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// The servers listening on the address a connection arrived at.
fn candidates(config: &Config, local: SocketAddr) -> Vec<Arc<Server>> {
    let exact: Vec<Arc<Server>> = config
        .servers
        .iter()
        .filter(|s| s.listens.iter().any(|l| l.port == local.port() && l.addr == Some(local.ip())))
        .cloned()
        .collect();
    if !exact.is_empty() {
        return exact;
    }
    config
        .servers
        .iter()
        .filter(|s| s.listens.iter().any(|l| l.port == local.port() && l.addr.is_none()))
        .cloned()
        .collect()
}

fn default_server(servers: &[Arc<Server>], local: SocketAddr) -> Option<Arc<Server>> {
    servers
        .iter()
        .find(|s| s.listens.iter().any(|l| l.port == local.port() && l.default_server))
        .or_else(|| servers.first())
        .cloned()
}

/// Chooses the server for a host, as nginx does: exact name, longest
/// leading wildcard, longest trailing wildcard, first matching regex, then
/// the default server.
pub fn select_server(servers: &[Arc<Server>], local: SocketAddr, host: Option<&str>) -> Option<Arc<Server>> {
    let host = host.unwrap_or("");
    if let Some(s) = servers.iter().find(|s| s.names.iter().any(|n| n == host)) {
        return Some(s.clone());
    }
    let mut best: Option<(usize, &Arc<Server>)> = None;
    for s in servers {
        for n in &s.names {
            let suffix = if let Some(rest) = n.strip_prefix("*.") {
                Some(format!(".{rest}"))
            } else if n.starts_with('.') {
                if host == &n[1..] {
                    return Some(s.clone());
                }
                Some(n.clone())
            } else {
                None
            };
            if let Some(suffix) = suffix {
                if host.ends_with(&suffix) && best.is_none_or(|(len, _)| suffix.len() > len) {
                    best = Some((suffix.len(), s));
                }
            }
        }
    }
    if let Some((_, s)) = best {
        return Some(s.clone());
    }
    for s in servers {
        for n in &s.names {
            if let Some(prefix) = n.strip_suffix(".*") {
                let prefix = format!("{prefix}.");
                if host.starts_with(&prefix) && best.is_none_or(|(len, _)| prefix.len() > len) {
                    best = Some((prefix.len(), s));
                }
            }
        }
    }
    if let Some((_, s)) = best {
        return Some(s.clone());
    }
    for s in servers {
        for n in &s.names {
            if let Some(pattern) = n.strip_prefix('~') {
                if regex::Regex::new(pattern).is_ok_and(|re| re.is_match(host)) {
                    return Some(s.clone());
                }
            }
        }
    }
    default_server(servers, local)
}

fn read_more(stream: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    let mut chunk = [0u8; 16384];
    let n = stream.read(&mut chunk)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n)
}

fn close(mut stream: TcpStream) {
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    // Lingering close: drain what the client still sends so it gets the response.
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut sink = [0u8; 4096];
    while let Ok(n) = stream.read(&mut sink) {
        if n == 0 {
            break;
        }
    }
}

fn serve_connection(mut stream: TcpStream, config: &Config) {
    let (Ok(local), Ok(remote)) = (stream.local_addr(), stream.peer_addr()) else { return };
    let servers = candidates(config, local);
    let Some(default) = default_server(&servers, local) else { return };
    let _ = stream.set_read_timeout(Some(CLIENT_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let head_end = loop {
            if let Some(i) = find(&buf, b"\r\n\r\n") {
                break i + 4;
            }
            if buf.len() > HEADER_LIMIT {
                let resp = response::special(400, default.conf.server_tokens);
                let _ = stream.write_all(&response::to_bytes(&resp, false, false, default.conf.server_tokens));
                return close(stream);
            }
            match read_more(&mut stream, &mut buf) {
                Ok(0) => return,
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        };
        let req = match parse_head(&buf[..head_end], default.conf.merge_slashes) {
            Ok(r) => r,
            Err(ParseError(code)) => {
                let resp = response::special(code, default.conf.server_tokens);
                let _ = stream.write_all(&response::to_bytes(&resp, false, false, default.conf.server_tokens));
                return close(stream);
            }
        };
        let server = select_server(&servers, local, req.host.as_deref()).unwrap_or(default.clone());
        let tokens = server.conf.server_tokens;

        if req.expect_continue && req.has_body() && req.version >= (1, 1) {
            let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let body: Vec<u8>;
        let consumed: usize;
        if req.chunked {
            loop {
                match http::decode_chunked(&buf[head_end..]) {
                    Ok(Some((b, used))) => {
                        body = b;
                        consumed = head_end + used;
                        break;
                    }
                    Ok(None) => match read_more(&mut stream, &mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    },
                    Err(ParseError(code)) => {
                        let resp = response::special(code, tokens);
                        let _ = stream.write_all(&response::to_bytes(&resp, false, false, tokens));
                        return close(stream);
                    }
                }
            }
        } else {
            let len = req.content_length.unwrap_or(0) as usize;
            while buf.len() < head_end + len {
                match read_more(&mut stream, &mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
            body = buf[head_end..head_end + len].to_vec();
            consumed = head_end + len;
        }
        buf.drain(..consumed);

        let resp = crate::handler::handle(&server, &req, &body, local, remote);
        if resp.status == 444 {
            return;
        }
        let keepalive = req.keepalive && !resp.close;
        let bytes = response::to_bytes(&resp, keepalive, req.method == "HEAD", tokens);
        if stream.write_all(&bytes).is_err() {
            return;
        }
        if !keepalive {
            return close(stream);
        }
    }
}
