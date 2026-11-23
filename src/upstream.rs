//! Upstream groups and nginx's weighted round-robin balancing, with
//! max_fails and fail_timeout, and backup servers tried after the others; and
//! the idle connections kept to their servers.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::Interest;

use crate::stream::Stream;

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub addr: SocketAddr,
    pub weight: i64,
    pub max_fails: u64,
    pub fail_timeout: u64,
    pub backup: bool,
    /// down: the server is never tried.
    pub down: bool,
}

impl Peer {
    /// A server with nginx's defaults: weight=1 max_fails=1 fail_timeout=10s.
    pub fn new(addr: SocketAddr) -> Peer {
        Peer { addr, weight: 1, max_fails: 1, fail_timeout: 10, backup: false, down: false }
    }
}

#[derive(Debug, Default, Clone)]
struct State {
    current: i64,
    effective: i64,
    fails: u64,
    accessed: u64,
    checked: u64,
}

/// How an upstream keeps the connections to its servers: at most max idle
/// ones, each for so many requests, so long in all and so long idle; local
/// when a connection is not shared between locations.
#[derive(Debug, Clone, PartialEq)]
pub struct Keepalive {
    pub max: usize,
    pub local: bool,
    pub requests: u64,
    pub time: Duration,
    pub timeout: Duration,
}

impl Default for Keepalive {
    /// nginx 1.30's defaults.
    fn default() -> Keepalive {
        Keepalive { max: 32, local: true, requests: 1000, time: Duration::from_secs(3600), timeout: Duration::from_secs(60) }
    }
}

/// A connection to a server, with when it was opened and how many requests it
/// was used for.
#[derive(Debug)]
pub struct Conn {
    pub stream: Stream,
    opened: Instant,
    requests: u64,
}

impl Conn {
    /// A new connection; the request it is opened for counts, as in nginx's c->requests.
    pub fn new(stream: Stream, opened: Instant) -> Conn {
        Conn { stream, opened, requests: 1 }
    }

    /// Whether there is nothing to read from it, not even its end: bytes a server
    /// sent unasked must not be read as its next answer. The socket, which does
    /// not block, is asked itself: tokio may not have seen yet what came.
    fn quiet(&self) -> bool {
        matches!(self.peek(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }

    fn peek(&self) -> std::io::Result<usize> {
        socket2::SockRef::from(self.stream.tcp()).peek(&mut [MaybeUninit::uninit()])
    }

    /// Has the task of the waker run on the next event of the connection; false
    /// when something came on it already. Tokio may take it for readable still,
    /// after what was read last: a peek that would block corrects that. A task
    /// that has polled too much (tokio's budget) has nothing registered, but the
    /// waker's task is run soon, which registers it.
    fn register(&self, waker: &Waker) -> bool {
        let tcp = self.stream.tcp();
        loop {
            match tcp.poll_read_ready(&mut Context::from_waker(waker)) {
                Poll::Pending => return true,
                Poll::Ready(Err(_)) => return false,
                Poll::Ready(Ok(())) => {}
            }
            let peeked = tcp.try_io(Interest::READABLE, || self.peek());
            if !matches!(peeked, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock) { return false }
        }
    }
}

/// A connection kept in the cache of an upstream.
#[derive(Debug)]
struct Idle {
    conn: Conn,
    addr: SocketAddr,
    /// The location that opened it.
    tag: usize,
    /// When it has been idle for too long; None means never.
    until: Option<Instant>,
}

impl Idle {
    /// Whether it has not been idle for too long.
    fn fresh(&self, now: Instant) -> bool {
        self.until.is_none_or(|t| now < t)
    }
}

#[derive(Debug, Default)]
struct Cache {
    /// The last kept first.
    idle: VecDeque<Idle>,
    /// What wakes the task that closes idle connections: one that does nothing
    /// until the task has first run, None when no task runs.
    waker: Option<Waker>,
}

impl Drop for Cache {
    /// The task ends with the upstream.
    fn drop(&mut self) {
        if let Some(w) = self.waker.take() { w.wake() }
    }
}

thread_local! {
    /// Set once the worker is shutting down: no more connections are kept.
    static CLOSING: Cell<bool> = const { Cell::new(false) };
    /// The upstreams of the worker that may have idle connections: those whose task runs.
    static CACHES: RefCell<Vec<Weak<Upstream>>> = const { RefCell::new(Vec::new()) };
}

#[cfg(test)]
thread_local! {
    /// How often the tasks of the thread's upstreams ran.
    static POLLS: Cell<usize> = const { Cell::new(0) };
}

/// Closes the idle connections of every upstream of the worker, which is
/// shutting down; no more are kept.
pub fn close_idle() {
    CLOSING.set(true);
    let caches: Vec<Arc<Upstream>> = CACHES.with_borrow(|c| c.iter().filter_map(Weak::upgrade).collect());
    for u in caches {
        let mut cache = u.cache.lock().unwrap();
        cache.idle.clear();
        let waker = cache.waker.clone();
        drop(cache);
        // With none left, the task ends.
        if let Some(w) = waker { w.wake() }
    }
}

/// Closes the idle connections of an upstream that are not usable any more, as
/// nginx does on the event of each connection: it runs when something comes on
/// one of them and when the first has been idle for too long, until it finds
/// none left. It does not keep the upstream alive.
async fn watch(upstream: Weak<Upstream>) {
    let mut sleep = std::pin::pin!(tokio::time::sleep(Duration::ZERO));
    std::future::poll_fn(|cx| {
        #[cfg(test)]
        POLLS.set(POLLS.get() + 1);
        loop {
            let Some(until) = upstream.upgrade().and_then(|u| u.sweep(cx.waker())) else { return Poll::Ready(()) };
            let Some(until) = until else { return Poll::Pending };
            sleep.as_mut().reset(until.into());
            std::task::ready!(sleep.as_mut().poll(cx));
        }
    }).await;
    CACHES.with_borrow_mut(|c| c.retain(|u| !u.ptr_eq(&upstream)));
}

#[derive(Debug)]
pub struct Upstream {
    pub peers: Vec<Peer>,
    /// The connections kept to the servers; None means no connection is kept.
    pub keepalive: Option<Keepalive>,
    state: Mutex<Vec<State>>,
    cache: Mutex<Cache>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Upstream {
    pub fn new(peers: Vec<Peer>) -> Upstream {
        let state = peers.iter().map(|p| State { effective: p.weight, ..State::default() }).collect();
        Upstream { peers, keepalive: None, state: Mutex::new(state), cache: Mutex::default() }
    }

    /// How many servers a request may try: those not marked down, as
    /// ngx_http_upstream_tries() counts them.
    pub fn tries(&self) -> usize {
        self.peers.iter().filter(|p| !p.down).count()
    }

    /// The next server to try, given those already tried for this request:
    /// the primary servers first, then the backup ones, as
    /// ngx_http_upstream_get_peer() chooses them.
    pub fn pick(&self, tried: &mut [bool]) -> Option<usize> {
        let mut state = self.state.lock().unwrap();
        let single = self.peers.len() == 1;
        let now = now();
        [false, true].into_iter().find_map(|backup| {
            let (mut best, mut total): (Option<(usize, i64)>, i64) = (None, 0);
            for (i, p) in self.peers.iter().enumerate().filter(|(i, p)| p.backup == backup && !p.down && !tried[*i]) {
                let s = &mut state[i];
                if !single && p.max_fails > 0 && s.fails >= p.max_fails && now - s.checked <= p.fail_timeout { continue; }
                s.current += s.effective;
                total += s.effective;
                s.effective += (s.effective < p.weight) as i64;
                if best.is_none_or(|(_, current)| s.current > current) { best = Some((i, s.current)); }
            }
            let (b, _) = best?;
            state[b].current -= total;
            if now - state[b].checked > self.peers[b].fail_timeout { state[b].checked = now; }
            tried[b] = true;
            Some(b)
        })
    }

    /// Records how a server answered, as ngx_http_upstream_free_round_robin_peer() does.
    pub fn done(&self, i: usize, failed: bool) {
        let mut state = self.state.lock().unwrap();
        let (p, s) = (&self.peers[i], &mut state[i]);
        if !failed {
            if s.accessed < s.checked { s.fails = 0; }
            return;
        }
        let now = now();
        (s.fails, s.accessed, s.checked) = (s.fails + 1, now, now);
        if p.max_fails > 0 { s.effective = (s.effective - p.weight / p.max_fails as i64).max(0); }
    }

    /// The idle connection to the server that was kept last, counted as used for
    /// one more request; opened by the location if they are local to one. Those
    /// found on the way that are not usable any more are closed.
    pub fn take(&self, addr: &SocketAddr, tag: usize) -> Option<Conn> {
        let keepalive = self.keepalive.as_ref()?;
        let (mut cache, now) = (self.cache.lock().unwrap(), Instant::now());
        let mut from = 0;
        loop {
            from += cache.idle.iter().skip(from).position(|i| i.addr == *addr && (!keepalive.local || i.tag == tag))?;
            let mut idle = cache.idle.remove(from)?;
            if !idle.fresh(now) || !idle.conn.quiet() { continue }
            idle.conn.requests += 1;
            return Some(idle.conn);
        }
    }

    /// Keeps a connection whose answer was read to its end, or closes it, as
    /// ngx_http_upstream_free_keepalive_peer() does; the one kept for the longest
    /// makes room for it. The task that closes idle connections is told of it
    /// without being woken.
    pub fn put(self: &Arc<Self>, conn: Conn, addr: SocketAddr, tag: usize) {
        let Some(keepalive) = &self.keepalive else { return };
        let now = Instant::now();
        if conn.requests >= keepalive.requests || now.duration_since(conn.opened) > keepalive.time { return }
        if CLOSING.get() || !conn.quiet() { return }
        let mut cache = self.cache.lock().unwrap();
        if cache.waker.as_ref().is_some_and(|w| !conn.register(w)) { return }
        if cache.idle.len() >= keepalive.max { cache.idle.pop_back(); }
        cache.idle.push_front(Idle { conn, addr, tag, until: now.checked_add(keepalive.timeout) });
        if cache.waker.is_some() { return }
        cache.waker = Some(Waker::noop().clone());
        drop(cache);
        CACHES.with_borrow_mut(|c| c.push(Arc::downgrade(self)));
        tokio::task::spawn_local(watch(Arc::downgrade(self)));
    }

    /// Closes the idle connections that are not usable any more, and has the
    /// waker's task run on the events of the others. Gives when the first of them
    /// will have been idle for too long, Some(None) being never; None when none is
    /// left, and the task that asks ends.
    fn sweep(&self, waker: &Waker) -> Option<Option<Instant>> {
        let (mut cache, now) = (self.cache.lock().unwrap(), Instant::now());
        cache.idle.retain(|i| i.fresh(now) && i.conn.register(waker));
        // All have the same timeout.
        let first = cache.idle.back().map(|i| i.until);
        cache.waker = first.map(|_| waker.clone());
        first
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::block_on;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn peers(n: usize, max_fails: u64) -> Upstream {
        let peers = (0..n).map(|i| Peer { max_fails, ..Peer::new(SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16))) });
        Upstream::new(peers.collect())
    }

    #[test]
    fn round_robin() {
        let u = peers(2, 1);
        let picks: Vec<usize> = (0..4).map(|_| u.pick(&mut [false, false]).unwrap()).collect();
        assert_eq!(picks, vec![0, 1, 0, 1]);
    }

    #[test]
    fn failed_servers_rest_and_backups_come_last() {
        let mut u = peers(2, 1);
        u.peers[1].backup = true;
        let u = Upstream::new(u.peers.clone());
        let mut tried = [false, false];
        assert_eq!(u.pick(&mut tried), Some(0));
        u.done(0, true);
        assert_eq!(u.pick(&mut tried), Some(1));
        assert_eq!(u.pick(&mut tried), None);
        assert_eq!(u.pick(&mut [false, false]), Some(1));
        u.done(1, false);
    }

    #[test]
    fn down_servers_are_never_tried() {
        let mut u = peers(2, 1);
        u.peers[0].down = true;
        let u = Upstream::new(u.peers.clone());
        assert_eq!(u.tries(), 1);
        assert_eq!(u.pick(&mut [false, false]), Some(1));
        assert_eq!(u.pick(&mut [false, true]), None);
    }

    /// An upstream that keeps connections.
    fn keeping(keepalive: Keepalive) -> Arc<Upstream> {
        let mut u = peers(1, 1);
        u.keepalive = Some(keepalive);
        Arc::new(u)
    }

    /// A server, whose sockets block.
    fn server() -> (TcpListener, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr)
    }

    /// A new connection to a server, the server's end of it and the port that names it.
    async fn open(l: &TcpListener) -> (Conn, TcpStream, u16) {
        let s = tokio::net::TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        let (other, from) = l.accept().unwrap();
        other.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        (Conn::new(Stream::Tcp(s), Instant::now()), other, from.port())
    }

    /// The port of the connection taken.
    fn port(conn: &Option<Conn>) -> Option<u16> {
        conn.as_ref().map(|c| c.stream.tcp().local_addr().unwrap().port())
    }

    /// Whether the connection was closed, as the server sees it: a connection closed
    /// with bytes left to read is reset.
    fn closed(mut other: &TcpStream) -> bool {
        match other.read(&mut [0]) {
            Ok(n) => n == 0,
            Err(e) => e.kind() == std::io::ErrorKind::ConnectionReset,
        }
    }

    fn idle(u: &Upstream) -> usize {
        u.cache.lock().unwrap().idle.len()
    }

    /// How many tasks run for the upstream.
    fn tasks(u: &Arc<Upstream>) -> usize {
        CACHES.with_borrow(|c| c.iter().filter(|w| w.ptr_eq(&Arc::downgrade(u))).count())
    }

    /// Waits for what the task of the upstream does.
    async fn wait(done: impl Fn() -> bool) {
        for _ in 0..500 {
            if done() { return }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("it did not happen");
    }

    /// Lets the tasks of this thread run for so long.
    async fn run(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// Sends a request and reads its answer.
    async fn exchange(conn: &mut Conn, mut other: &TcpStream) {
        conn.stream.write_all(b"q").await.unwrap();
        other.read_exact(&mut [0]).unwrap();
        other.write_all(b"a").unwrap();
        conn.stream.read_exact(&mut [0]).await.unwrap();
    }

    /// What a server may do to an idle connection: close it or send on it.
    const ACTS: [fn(&TcpStream); 2] = [|s| s.shutdown(std::net::Shutdown::Write).unwrap(), |mut s| s.write_all(b"x").unwrap()];

    /// Lets the time pass on this thread, so that no task runs.
    fn pause(ms: u64) {
        std::thread::sleep(Duration::from_millis(ms));
    }

    #[test]
    fn last_kept_is_first_used_and_the_oldest_makes_room() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive { max: 2, ..Keepalive::default() }), server());
            let ((a, a_other, _), (b, _b, b_port), (c, _c, c_port)) = (open(&l).await, open(&l).await, open(&l).await);
            for conn in [a, b, c] { u.put(conn, addr, 0); }
            assert_eq!((idle(&u), tasks(&u)), (2, 1));
            assert!(closed(&a_other));
            assert_eq!(port(&u.take(&addr, 0)), Some(c_port));
            assert_eq!(port(&u.take(&addr, 0)), Some(b_port));
            assert!(u.take(&addr, 0).is_none());
        });
    }

    #[test]
    fn connections_are_of_a_server_and_a_location() {
        block_on(async {
            for local in [true, false] {
                let (u, (l, addr), (l2, addr2)) = (keeping(Keepalive { local, ..Keepalive::default() }), server(), server());
                let ((a, _a, a_port), (b, _b, b_port)) = (open(&l).await, open(&l2).await);
                u.put(a, addr, 1);
                u.put(b, addr2, 1);
                assert_eq!(port(&u.take(&addr, 2)), (!local).then_some(a_port));
                assert_eq!(port(&u.take(&addr, 1)), local.then_some(a_port));
                assert!(u.take(&addr, 1).is_none());
                assert_eq!(port(&u.take(&addr2, 1)), Some(b_port));
            }
        });
    }

    #[test]
    fn a_connection_has_so_many_requests_and_so_much_time() {
        block_on(async {
            let (l, addr) = server();
            let u = keeping(Keepalive { requests: 1, ..Keepalive::default() });
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr, 0);
            assert!(idle(&u) == 0 && tasks(&u) == 0 && closed(&other));

            let u = keeping(Keepalive { requests: 2, ..Keepalive::default() });
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr, 0);
            let conn = u.take(&addr, 0).unwrap();
            assert_eq!(conn.requests, 2);
            u.put(conn, addr, 0);
            assert!(idle(&u) == 0 && closed(&other));

            let u = keeping(Keepalive { time: Duration::from_secs(5), ..Keepalive::default() });
            let (mut conn, _other, _) = open(&l).await;
            conn.opened -= Duration::from_secs(1);
            u.put(conn, addr, 0);
            let mut conn = u.take(&addr, 0).unwrap();
            conn.opened -= Duration::from_secs(5);
            u.put(conn, addr, 0);
            assert_eq!(idle(&u), 0);
        });
    }

    #[test]
    fn a_connection_is_idle_for_so_long() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive { timeout: Duration::from_millis(50), ..Keepalive::default() }), server());
            let ((a, a_other, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
            u.put(a, addr, 0);
            pause(60);
            assert!(u.take(&addr, 0).is_none());
            assert!(idle(&u) == 0 && closed(&a_other));
            u.put(b, addr, 0);
            assert_eq!(idle(&u), 1);
            wait(|| idle(&u) == 0).await;
            assert!(closed(&b_other));

            // A time too long to represent never passes.
            let u = keeping(Keepalive { timeout: Duration::MAX, ..Keepalive::default() });
            let (conn, _other, _) = open(&l).await;
            u.put(conn, addr, 0);
            run(250).await;
            assert!(u.take(&addr, 0).is_some());
        });
    }

    #[test]
    fn a_connection_the_server_closes_or_sends_on_is_not_used() {
        block_on(async {
            for act in ACTS {
                let (u, (l, addr)) = (keeping(Keepalive::default()), server());
                // It is found by take(), which goes on to the next.
                let ((a, _a, a_port), (b, b_other, _)) = (open(&l).await, open(&l).await);
                u.put(a, addr, 0);
                u.put(b, addr, 0);
                act(&b_other);
                pause(20);
                assert_eq!(idle(&u), 2);
                let a = u.take(&addr, 0);
                assert_eq!((port(&a), idle(&u)), (Some(a_port), 0));
                assert!(closed(&b_other));
                // By put().
                let (b, b_other, _) = open(&l).await;
                act(&b_other);
                pause(20);
                u.put(b, addr, 0);
                assert!(idle(&u) == 0 && closed(&b_other));
                // And by the task, which leaves the others.
                let (b, b_other, _) = open(&l).await;
                u.put(a.unwrap(), addr, 0);
                u.put(b, addr, 0);
                act(&b_other);
                wait(|| idle(&u) == 1).await;
                assert!(closed(&b_other));
                assert_eq!(port(&u.take(&addr, 0)), Some(a_port));
            }
        });
    }

    #[test]
    fn a_worker_shutting_down_keeps_none() {
        // On a thread of its own, as nothing is kept on it from then on.
        std::thread::spawn(|| block_on(async {
            let (u, u2, (l, addr)) = (keeping(Keepalive::default()), keeping(Keepalive::default()), server());
            let ((a, a_other, _), (b, b_other, _), (c, c_other, _)) = (open(&l).await, open(&l).await, open(&l).await);
            u.put(a, addr, 0);
            run(20).await;
            u2.put(b, addr, 0);
            close_idle();
            assert_eq!((idle(&u), idle(&u2)), (0, 0));
            assert!(closed(&a_other) && closed(&b_other));
            u.put(c, addr, 0);
            assert!(idle(&u) == 0 && closed(&c_other));
            wait(|| tasks(&u) + tasks(&u2) == 0).await;
        })).join().unwrap();
    }

    #[test]
    fn without_keepalive_none_is_kept() {
        block_on(async {
            let (u, (l, addr)) = (Arc::new(peers(1, 1)), server());
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr, 0);
            assert!(idle(&u) == 0 && tasks(&u) == 0 && closed(&other));
            assert!(u.take(&addr, 0).is_none());
        });
    }

    #[test]
    fn the_task_ends_and_starts_again() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive::default()), server());
            let ((a, _a, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
            u.put(a, addr, 0);
            // A connection taken and kept again before the task ran needs no other task.
            let a = u.take(&addr, 0).unwrap();
            u.put(a, addr, 0);
            assert_eq!(tasks(&u), 1);
            let _a = u.take(&addr, 0).unwrap();
            wait(|| tasks(&u) == 0).await;
            assert!(!u.cache.lock().unwrap().waker.is_some());
            u.put(b, addr, 0);
            assert_eq!(tasks(&u), 1);
            drop(b_other);
            wait(|| idle(&u) == 0 && tasks(&u) == 0).await;

            // It does not keep the upstream, which closes its connections when dropped,
            // whether the task ran already or not.
            for ms in [0, 20] {
                let u = keeping(Keepalive { timeout: Duration::MAX, ..Keepalive::default() });
                let (c, c_other, _) = open(&l).await;
                u.put(c, addr, 0);
                if ms > 0 { run(ms).await }
                let weak = Arc::downgrade(&u);
                drop(u);
                assert!(weak.upgrade().is_none() && closed(&c_other));
                wait(|| CACHES.with_borrow(|c| !c.iter().any(|w| w.ptr_eq(&weak)))).await;
            }
        });
    }

    #[test]
    fn the_task_sees_what_comes() {
        block_on(async {
            for act in ACTS {
                let (u, (l, addr)) = (keeping(Keepalive::default()), server());
                let ((a, a_other, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
                // The task registers the first, put() the second.
                u.put(a, addr, 0);
                run(20).await;
                u.put(b, addr, 0);
                run(20).await;
                assert_eq!((idle(&u), tasks(&u)), (2, 1));
                act(&b_other);
                wait(|| idle(&u) == 1).await;
                assert!(closed(&b_other));
                act(&a_other);
                wait(|| idle(&u) == 0 && tasks(&u) == 0).await;
                assert!(closed(&a_other));
            }
        });
    }

    #[test]
    fn the_task_waits_for_the_first_that_is_left() {
        block_on(async {
            let timeout = Duration::from_millis(300);
            let (u, (l, addr)) = (keeping(Keepalive { timeout, ..Keepalive::default() }), server());
            let ((a, _a, a_port), (b, b_other, _), (c, _c, c_port)) = (open(&l).await, open(&l).await, open(&l).await);
            u.put(a, addr, 0);
            run(100).await;
            let kept = Instant::now();
            u.put(b, "127.0.0.1:1".parse().unwrap(), 0);
            let a = u.take(&addr, 0);
            assert_eq!((port(&a), idle(&u), tasks(&u)), (Some(a_port), 1, 1));
            wait(|| idle(&u) == 0).await;
            assert!((timeout..Duration::from_secs(2)).contains(&kept.elapsed()) && closed(&b_other));
            wait(|| tasks(&u) == 0).await;

            // Taken, the only one leaves the task running until the time has passed.
            u.put(c, addr, 0);
            run(20).await;
            let c = u.take(&addr, 0);
            assert_eq!((port(&c), idle(&u), tasks(&u)), (Some(c_port), 0, 1));
            wait(|| tasks(&u) == 0).await;
        });
    }

    #[test]
    fn a_connection_kept_again_is_watched() {
        block_on(async {
            for act in ACTS {
                let (u, (l, addr)) = (keeping(Keepalive::default()), server());
                let (conn, other, _) = open(&l).await;
                u.put(conn, addr, 0);
                run(20).await;
                let mut conn = u.take(&addr, 0).unwrap();
                exchange(&mut conn, &other).await;
                u.put(conn, addr, 0);
                run(20).await;
                assert_eq!((idle(&u), tasks(&u)), (1, 1));
                act(&other);
                wait(|| idle(&u) == 0 && tasks(&u) == 0).await;
                assert!(closed(&other));
            }
        });
    }

    #[test]
    fn the_task_does_not_run_while_nothing_happens() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive::default()), server());
            let ((a, _a, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
            u.put(a, addr, 0);
            u.put(b, addr, 0);
            run(20).await;
            let polls = POLLS.get();
            assert!(polls > 0);
            run(300).await;
            assert_eq!(POLLS.get(), polls);
            for _ in 0..100 {
                let mut b = u.take(&addr, 0).unwrap();
                exchange(&mut b, &b_other).await;
                u.put(b, addr, 0);
                run(1).await;
            }
            assert_eq!((POLLS.get(), idle(&u), tasks(&u)), (polls, 2, 1));
        });
    }
}
