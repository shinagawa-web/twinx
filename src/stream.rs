//! The connections twinx reads and writes: a client's or a proxied server's,
//! over TCP or TLS, on the worker's event loop.

use std::cell::RefCell;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// A connection: plain TCP, TLS taken from a client, or TLS to a proxied server.
#[derive(Debug)]
pub enum Stream {
    Tcp(TcpStream),
    Server(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    Client(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// One end of a pipe in memory: a stream of an HTTP/2 connection, which
    /// the other end passes as an HTTP/1 request and its answer.
    Pipe(tokio::io::DuplexStream),
}

impl Stream {
    /// The TCP connection under it, which a pipe does not have.
    pub fn tcp(&self) -> Option<&TcpStream> {
        match self { Stream::Tcp(s) => Some(s), Stream::Server(s) => Some(s.get_ref().0), Stream::Client(s) => Some(s.get_ref().0), Stream::Pipe(_) => None }
    }

    /// Whether TLS, if any, holds nothing back: there is no plaintext left to
    /// read, it did not fail, and the peer has not closed it. Reading less than a
    /// whole record leaves the rest there, where a peek at the socket does not see it.
    pub fn drained(&mut self) -> bool {
        let state = match self {
            Stream::Tcp(_) | Stream::Pipe(_) => return true,
            Stream::Server(s) => s.get_mut().1.process_new_packets(),
            Stream::Client(s) => s.get_mut().1.process_new_packets(),
        };
        state.is_ok_and(|s| s.plaintext_bytes_to_read() == 0 && !s.peer_has_closed())
    }

    /// Whether something the peer sent is waiting to be read: plaintext TLS holds
    /// (or an end or error it has to give), or data on the socket. The socket is
    /// peeked at only when the event loop says it is readable, which an end of
    /// file makes it too, with nothing to read; a wrong readiness is cleared.
    pub fn waiting(&mut self) -> bool {
        let peek = |tcp: &TcpStream| socket2::SockRef::from(tcp).peek(&mut [std::mem::MaybeUninit::uninit()]);
        !self.drained() || self.tcp().is_some_and(|tcp| matches!(tcp.try_io(tokio::io::Interest::READABLE, || peek(tcp)), Ok(1..)))
    }

    /// Shuts down both directions of the TCP connection, whatever is still to be read or written.
    pub fn close(&self) {
        if let Some(tcp) = self.tcp() { let _ = socket2::SockRef::from(tcp).shutdown(std::net::Shutdown::Both); }
    }
}

macro_rules! each {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() { Stream::Tcp($s) => $e, Stream::Server($s) => $e, Stream::Client($s) => $e, Stream::Pipe($s) => $e }
    };
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut ReadBuf) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let read = match this { Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf), Stream::Server(s) => Pin::new(&mut **s).poll_read(cx, buf), Stream::Client(s) => Pin::new(&mut **s).poll_read(cx, buf), Stream::Pipe(s) => Pin::new(s).poll_read(cx, buf) };
        // What TLS answers to what it read, such as the alert refusing a
        // renegotiation, is sent at once, not with the next write.
        let wants = match this { Stream::Tcp(_) | Stream::Pipe(_) => false, Stream::Server(s) => s.get_ref().1.wants_write(), Stream::Client(s) => s.get_ref().1.wants_write() };
        if wants { let _ = Pin::new(this).poll_flush(cx); }
        read
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        each!(self, s => Pin::new(s).poll_write(cx, buf))
    }

    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context, bufs: &[IoSlice]) -> Poll<std::io::Result<usize>> {
        each!(self, s => Pin::new(s).poll_write_vectored(cx, bufs))
    }

    fn is_write_vectored(&self) -> bool {
        match self { Stream::Tcp(s) => s.is_write_vectored(), Stream::Server(s) => s.is_write_vectored(), Stream::Client(s) => s.is_write_vectored(), Stream::Pipe(s) => s.is_write_vectored() }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        each!(self, s => Pin::new(s).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context) -> Poll<std::io::Result<()>> {
        each!(self, s => Pin::new(s).poll_shutdown(cx))
    }
}

/// What a future gives, None when it does not end within the time (none: no limit).
pub async fn within<F: Future>(time: Option<Duration>, f: F) -> Option<F::Output> {
    until(|| time.and_then(|t| Instant::now().checked_add(t)), f).await
}

/// What a future gives, None when it does not end before the deadline, which
/// is asked for only once the future has to wait (none: no limit).
pub async fn until<F: Future>(deadline: impl Fn() -> Option<Instant>, f: F) -> Option<F::Output> {
    let (mut f, mut sleep) = (std::pin::pin!(f), std::pin::pin!(None));
    std::future::poll_fn(|cx| {
        if let Poll::Ready(out) = f.as_mut().poll(cx) { return Poll::Ready(Some(out)) }
        if sleep.is_none() { sleep.set(deadline().map(|d| tokio::time::sleep_until(d.into()))); }
        sleep.as_mut().as_pin_mut().map_or(Poll::Pending, |s| s.poll(cx).map(|()| None))
    }).await
}

/// Reads what comes into the end of buf, waiting at most the time for it;
/// 0 when the connection closed, failed or the time passed.
pub async fn read_into<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, time: Option<Duration>) -> usize {
    read_until(s, buf, || time.and_then(|t| Instant::now().checked_add(t))).await
}

/// Reads what comes into the end of buf before the deadline, as read_into does.
/// While there is nothing to read, a buffer without memory is not given any.
pub async fn read_until<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>, deadline: impl Fn() -> Option<Instant>) -> usize {
    let read = std::future::poll_fn(|cx| {
        let lent = buf.capacity() == 0;
        if lent { *buf = buffer(); }
        buf.reserve(4096);
        let read = std::pin::pin!(s.read_buf(buf)).poll(cx);
        if lent && read.is_pending() { recycle(std::mem::take(buf)); }
        read
    });
    until(deadline, read).await.and_then(Result::ok).unwrap_or(0)
}

/// Reads what there is to read now; None when there is nothing.
pub async fn read_ready<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
    std::future::poll_fn(|cx| Poll::Ready(match std::pin::pin!(s.read(buf)).poll(cx) { Poll::Ready(read) => Some(read), Poll::Pending => None })).await
}

thread_local! {
    /// Buffers used before, to use again: a worker, which serves its connections
    /// on one thread, needs few at a time.
    static SPARE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) }
}

/// An empty buffer, which may have memory.
pub fn buffer() -> Vec<u8> {
    SPARE.with_borrow_mut(Vec::pop).unwrap_or_default()
}

/// Keeps the memory of a buffer for the next that needs one, if it is not large.
pub fn recycle(mut buf: Vec<u8>) {
    buf.clear();
    SPARE.with_borrow_mut(|spare| if (1..=16384).contains(&buf.capacity()) && spare.len() < 16 { spare.push(buf) });
}

/// Writes data and flushes it (a TLS record may wait in the connection otherwise),
/// each write waiting at most the time.
pub async fn write_all<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8], time: Option<Duration>) -> bool {
    write_vectored(s, &mut [IoSlice::new(data)], time).await
}

/// Writes the slices one after another, as writev does, and flushes them;
/// each write waits at most the time.
pub async fn write_vectored<S: AsyncWrite + Unpin>(s: &mut S, bufs: &mut [IoSlice<'_>], time: Option<Duration>) -> bool {
    write_counted(s, bufs, time, &mut 0).await
}

/// The same, adding the bytes written to a count, also when a write fails after others.
pub async fn write_counted<S: AsyncWrite + Unpin>(s: &mut S, mut bufs: &mut [IoSlice<'_>], time: Option<Duration>, count: &mut usize) -> bool {
    loop {
        // Empty slices are left out: a write of nothing would look like a closed connection.
        IoSlice::advance_slices(&mut bufs, 0);
        if bufs.is_empty() { break }
        match within(time, s.write_vectored(bufs)).await {
            Some(Ok(0)) | None => return false,
            Some(Ok(n)) => {
                *count += n;
                IoSlice::advance_slices(&mut bufs, n);
            }
            Some(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Some(Err(_)) => return false,
        }
    }
    matches!(within(time, s.flush()).await, Some(Ok(())))
}

/// Waits until the client closes its side of the connection (or it fails),
/// as nginx's check of a broken connection finds it with EPOLLRDHUP. While
/// what the client sent is waiting to be read, which keeps the connection
/// readable, it looks again every 100 ms.
pub async fn closed(tcp: &TcpStream) {
    use std::os::fd::AsRawFd;
    loop {
        match tcp.ready(tokio::io::Interest::READABLE).await {
            Ok(ready) if !ready.is_read_closed() => {}
            _ => return,
        }
        let mut fd = libc::pollfd { fd: tcp.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 };
        // SAFETY: fd is one pollfd that lives through the call.
        if unsafe { libc::poll(&mut fd, 1, 0) } != 0 { return }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What a future gives, None when the client closes its side of the connection before.
pub async fn unless_closed<F: Future>(client: &Stream, f: F) -> Option<F::Output> {
    let closed = async { match client.tcp() { Some(tcp) => closed(tcp).await, None => std::future::pending().await } };
    tokio::select! { biased; out = f => Some(out), () = closed => None }
}

#[cfg(test)]
pub fn block_on<F: Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connected pair: what was accepted, and the other end.
    async fn pair() -> (TcpStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let other = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        (l.accept().await.unwrap().0, other)
    }

    #[test]
    fn writes_slices_in_order_and_reads_with_a_timeout() {
        block_on(async {
            let (s, mut other) = pair().await;
            let mut s = Stream::Tcp(s);
            assert!(format!("{s:?}").starts_with("Tcp("));
            assert!(write_vectored(&mut s, &mut [IoSlice::new(b"ab"), IoSlice::new(b""), IoSlice::new(b"cd")], None).await);
            assert!(write_all(&mut s, b"e", Some(Duration::from_secs(1))).await);
            let mut got = vec![0u8; 5];
            other.read_exact(&mut got).await.unwrap();
            assert_eq!(got, b"abcde");
            let mut buf = Vec::new();
            assert_eq!(read_into(&mut s, &mut buf, Some(Duration::from_millis(50))).await, 0);
            other.write_all(b"x").await.unwrap();
            assert_eq!((read_into(&mut s, &mut buf, None).await, buf.as_slice()), (1, &b"x"[..]));
            assert!(read_ready(&mut s, &mut buf).await.is_none());
            other.write_all(b"y").await.unwrap();
            s.tcp().unwrap().readable().await.unwrap();
            assert!(matches!(read_ready(&mut s, &mut buf).await, Some(Ok(1))) && buf == b"y");
            assert_eq!(within(Some(Duration::from_millis(10)), std::future::pending::<()>()).await, None);
            // What was written before a write that fails is counted.
            let (mut count, data) = (3, vec![b'x'; 1 << 24]);
            assert!(write_counted(&mut s, &mut [IoSlice::new(b"ab")], None, &mut count).await && count == 5);
            assert!(!write_counted(&mut s, &mut [IoSlice::new(&data)], Some(Duration::from_millis(50)), &mut count).await);
            assert!((6..data.len()).contains(&count));
        });
    }

    #[test]
    fn lends_buffers() {
        block_on(async {
            let (s, mut other) = pair().await;
            let (mut s, mut buf) = (Stream::Tcp(s), Vec::new());
            // A read that gives up keeps no memory, which the next buffer has.
            assert_eq!(read_into(&mut s, &mut buf, Some(Duration::from_millis(10))).await, 0);
            assert_eq!(buf.capacity(), 0);
            let lent = buffer();
            assert!(lent.is_empty() && lent.capacity() >= 4096);
            recycle(lent);
            other.write_all(b"x").await.unwrap();
            assert_eq!(read_into(&mut s, &mut buf, None).await, 1);
            assert_eq!((buf.as_slice(), buffer().capacity()), (&b"x"[..], 0));
            // A large buffer is not kept.
            recycle(Vec::with_capacity(1 << 20));
            assert_eq!(buffer().capacity(), 0);
        });
    }

    #[test]
    fn finds_what_is_waiting_to_be_read() {
        block_on(async {
            let (s, mut other) = pair().await;
            let (mut s, mut buf) = (Stream::Tcp(s), Vec::new());
            assert!(!s.waiting());
            other.write_all(b"xy").await.unwrap();
            s.tcp().unwrap().readable().await.unwrap();
            assert!(s.waiting());
            // A read that fills its buffer leaves the connection readable, to
            // the event loop, until a peek finds nothing.
            assert_eq!(s.read(&mut [0; 2]).await.unwrap(), 2);
            assert!(!s.waiting());
            assert!(within(Some(Duration::from_millis(50)), s.tcp().unwrap().readable()).await.is_none());
            // What comes before the end is waiting; the end is not.
            other.write_all(b"z").await.unwrap();
            other.shutdown().await.unwrap();
            s.tcp().unwrap().readable().await.unwrap();
            assert!(s.waiting());
            assert_eq!(read_into(&mut s, &mut buf, None).await, 1);
            assert!(!s.waiting());
        });
    }

    #[test]
    fn finds_the_client_closing() {
        block_on(async {
            let (s, mut other) = pair().await;
            // Data waiting to be read is no close.
            other.write_all(b"pipelined").await.unwrap();
            assert!(within(Some(Duration::from_millis(300)), closed(&s)).await.is_none());
            other.shutdown().await.unwrap();
            assert!(within(Some(Duration::from_secs(2)), closed(&s)).await.is_some());
            let s = Stream::Tcp(s);
            assert_eq!(unless_closed(&s, std::future::ready(1)).await, Some(1));
            assert_eq!(unless_closed(&s, std::future::pending::<()>()).await, None);
            s.close();
            let mut buf = [0u8; 16];
            assert_eq!(other.read(&mut buf).await.unwrap(), 0);
        });
    }
}
