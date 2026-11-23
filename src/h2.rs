//! HTTP/2 over a connection without TLS that starts with the preface (RFC 9113,
//! 3.3), when http2 is on. The h2 crate reads and writes the frames. Each
//! stream's request is passed as an HTTP/1 request of version HTTP/2.0 to a
//! connection of its own, over a pipe in memory, and the answer that comes
//! back is sent on the stream.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::conf::Config;
use crate::http::Busy;
use crate::stream::Stream;

/// A connection with what was read of it already put back in front.
pub struct Rewound { ahead: Vec<u8>, at: usize, stream: Stream }

impl Rewound {
    pub fn new(ahead: Vec<u8>, stream: Stream) -> Rewound { Rewound { ahead, at: 0, stream } }
}

impl AsyncRead for Rewound {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.at == this.ahead.len() { return Pin::new(&mut this.stream).poll_read(cx, buf) }
        let n = buf.remaining().min(this.ahead.len() - this.at);
        buf.put_slice(&this.ahead[this.at..this.at + n]);
        this.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Rewound {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> { Pin::new(&mut self.get_mut().stream).poll_write(cx, buf) }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> { Pin::new(&mut self.get_mut().stream).poll_flush(cx) }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> { Pin::new(&mut self.get_mut().stream).poll_shutdown(cx) }
}

/// The listening, local and remote addresses of a connection, and its TLS session.
pub type Addrs = (SocketAddr, SocketAddr, SocketAddr, Option<Arc<crate::tls::Session>>);

/// Serves the streams of an HTTP/2 connection, with its addresses and TLS session.
pub async fn serve(config: Arc<Config>, io: Rewound, addrs: Addrs, fresh: Option<Busy>) {
    // nginx's settings: 128 streams at a time (http2_max_concurrent_streams),
    // a window of 64k for each (its preread buffer), the largest for the connection.
    let mut builder = h2::server::Builder::new();
    builder.max_concurrent_streams(128).initial_window_size(65536).initial_connection_window_size(i32::MAX as u32).max_frame_size(16384);
    let Ok(mut conn) = builder.handshake::<_, Bytes>(io).await else { return };
    drop(fresh);
    while let Some(Ok((request, respond))) = conn.accept().await {
        tokio::task::spawn_local(exchange(config.clone(), request, respond, addrs.clone()));
    }
}

/// The request of a stream as HTTP/1 writes it, with the version HTTP/2.0:
/// the host is :authority when there is no Host header, as nginx takes it.
fn head(parts: &http::request::Parts) -> Vec<u8> {
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut head = format!("{} {path} HTTP/2.0\r\n", parts.method).into_bytes();
    if let Some(authority) = parts.uri.authority().filter(|_| !parts.headers.contains_key(http::header::HOST)) { head.extend_from_slice(format!("Host: {authority}\r\n").as_bytes()); }
    for (name, value) in &parts.headers { head.extend_from_slice(&[name.as_str().as_bytes(), b": ", value.as_bytes(), b"\r\n"].concat()); }
    head.extend_from_slice(b"\r\n");
    head
}

/// The status and headers of an HTTP/1 answer's head, without those only
/// HTTP/1 connections have (RFC 9113, 8.2.2).
fn answer_head(head: &[u8]) -> Option<http::response::Builder> {
    let mut lines = head.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status = lines.next()?.split(|&c| c == b' ').nth(1)?;
    let mut builder = http::Response::builder().status(status);
    const HOP: &[&str] = &["connection", "keep-alive", "transfer-encoding"];
    for line in lines {
        let at = line.iter().position(|&c| c == b':')?;
        let (name, value) = (&line[..at], line[at + 1..].trim_ascii());
        if !HOP.iter().any(|h| name.eq_ignore_ascii_case(h.as_bytes())) { builder = builder.header(name, value); }
    }
    Some(builder)
}

/// Answers the request of one stream.
async fn exchange(config: Arc<Config>, request: http::Request<h2::RecvStream>, mut respond: h2::server::SendResponse<Bytes>, (listen, local, peer, ssl): Addrs) {
    let (parts, mut body) = request.into_parts();
    let mut sent = head(&parts);
    while let Some(Ok(data)) = body.data().await { let _ = body.flow_control().release_capacity(data.len()); sent.extend_from_slice(&data); }
    let (mut ours, theirs) = tokio::io::duplex(65536);
    tokio::task::spawn_local(async move { crate::http::connection(&config, Stream::Pipe(theirs), (listen, local, peer, ssl), Busy::new()).await });
    let mut answer = Vec::new();
    let _ = ours.write_all(&sent).await;
    let _ = ours.shutdown().await;
    let _ = ours.read_to_end(&mut answer).await;
    // An answer nginx would not send (444) resets the stream.
    let Some(end) = answer.windows(4).position(|w| w == b"\r\n\r\n") else { return };
    let body = answer.split_off(end + 4);
    let Some(Ok(head)) = answer_head(&answer[..end]).map(|b| b.body(())) else { return };
    let Ok(mut stream) = respond.send_response(head, body.is_empty()) else { return };
    if !body.is_empty() { let _ = stream.send_data(Bytes::from(body), true); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_head() {
        let request = http::Request::builder().method("GET").uri("http://example.com/a%20b?x=1").header("x-a", "1").body(()).unwrap();
        assert_eq!(head(&request.into_parts().0), b"GET /a%20b?x=1 HTTP/2.0\r\nHost: example.com\r\nx-a: 1\r\n\r\n");
        let request = http::Request::builder().method("POST").uri("http://example.com/").header("host", "other").body(()).unwrap();
        assert_eq!(head(&request.into_parts().0), b"POST / HTTP/2.0\r\nhost: other\r\n\r\n");
    }

    #[test]
    fn answer_heads() {
        let head = answer_head(b"HTTP/1.1 301 Moved Permanently\r\nServer: twinx\r\nConnection: close\r\nLocation: /x\r\nKeep-Alive: timeout=5").unwrap().body(()).unwrap();
        assert_eq!(head.status(), 301);
        assert_eq!(head.headers().iter().map(|(n, v)| (n.as_str(), v.to_str().unwrap())).collect::<Vec<_>>(), [("server", "twinx"), ("location", "/x")]);
        assert!(answer_head(b"HTTP/1.1").is_none());
        assert!(answer_head(b"HTTP/1.1 200 OK\r\nbroken").is_none());
    }

    #[tokio::test]
    async fn rewound() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut r = Rewound::new(b"ab".to_vec(), Stream::Pipe(a));
        b.write_all(b"cd").await.unwrap();
        let mut buf = [0; 4];
        r.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abcd");
        r.write_all(b"ef").await.unwrap();
        r.flush().await.unwrap();
        r.shutdown().await.unwrap();
        let mut back = Vec::new();
        b.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"ef");
    }
}
