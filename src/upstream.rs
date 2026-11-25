//! Upstream groups and nginx's balancing: weighted round-robin, ip_hash and
//! least_conn, with max_fails and fail_timeout, and backup servers tried after
//! the others; and the idle connections kept to their servers.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::Interest;

use crate::stream::Stream;

/// The address of a proxied server: an IP address and a port, or the path of a
/// unix-domain socket, written "unix:path" as nginx writes it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Addr { Inet(SocketAddr), Unix(Arc<std::path::Path>) }

impl From<SocketAddr> for Addr {
    fn from(a: SocketAddr) -> Addr { Addr::Inet(a) }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self { Addr::Inet(a) => a.fmt(f), Addr::Unix(path) => write!(f, "unix:{}", path.display()) }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Peer {
    pub addr: Addr,
    pub weight: i64,
    pub max_fails: u64,
    pub fail_timeout: u64,
    pub backup: bool,
    /// down: the server is never tried.
    pub down: bool,
    /// max_conns: how many connections it may have at once in the worker; 0 is no limit.
    pub max_conns: u64,
}

impl Peer {
    /// A server with nginx's defaults: weight=1 max_fails=1 fail_timeout=10s.
    pub fn new(addr: impl Into<Addr>) -> Peer {
        Peer { addr: addr.into(), weight: 1, max_fails: 1, fail_timeout: 10, backup: false, down: false, max_conns: 0 }
    }
}

/// How an upstream chooses its servers: weighted round-robin, ip_hash or least_conn.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Balance { #[default] RoundRobin, IpHash, LeastConn }

/// What a request keeps of how ip_hash chooses its servers, as
/// ngx_http_upstream_ip_hash_peer_data_t does: the bytes of the client's address
/// it hashes (the first three of IPv4), the hash so far, and how many servers
/// it hashed to that could not be tried.
#[derive(Debug)]
pub struct Hashed { addr: Vec<u8>, hash: u64, tries: u32 }

impl Hashed {
    pub fn new(client: IpAddr) -> Hashed {
        let addr = match client { IpAddr::V4(a) => a.octets()[..3].to_vec(), IpAddr::V6(a) => a.octets().to_vec() };
        Hashed { addr, hash: 89, tries: 0 }
    }
}

#[derive(Debug, Default, Clone)]
struct State {
    current: i64,
    effective: i64,
    fails: u64,
    accessed: u64,
    checked: u64,
    /// The connections it has for requests now, as nginx's peer->conns.
    conns: u64,
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
/// was used for; and the state of HTTP/2 on it, once it was used for that. The pipe to a
/// stream of HTTP/2 has what is known of that stream.
#[derive(Debug)]
pub struct Conn {
    pub stream: Stream,
    pub h2: Option<Box<crate::h2::Session>>,
    opened: Instant,
    requests: u64,
    pub slot: Option<crate::h2::Slot>,
}

impl Conn {
    /// A new connection; the request it is opened for counts, as in nginx's c->requests.
    pub fn new(stream: Stream, opened: Instant) -> Conn {
        Conn { stream, h2: None, opened, requests: 1, slot: None }
    }

    /// Whether there is nothing to read from it, not even its end: bytes a server
    /// sent unasked must not be read as its next answer. The socket, which does
    /// not block, is asked itself: tokio may not have seen yet what came. Over TLS
    /// any record that waits there counts, as in nginx.
    fn quiet(&mut self) -> bool {
        self.stream.drained() && matches!(self.peek(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
    }

    fn peek(&self) -> std::io::Result<usize> {
        socket2::SockRef::from(self.stream.tcp().expect("a proxied server is connected over TCP")).peek(&mut [MaybeUninit::uninit()])
    }

    /// Has the task of the waker run on the next event of the connection; false
    /// when something came on it already. Tokio may take it for readable still,
    /// after what was read last: a peek that would block corrects that. A task
    /// that has polled too much (tokio's budget) has nothing registered, but the
    /// waker's task is run soon, which registers it.
    fn register(&self, waker: &Waker) -> bool {
        let tcp = self.stream.tcp().expect("a proxied server is connected over TCP");
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
    addr: Addr,
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
    pub balance: Balance,
    state: Mutex<Vec<State>>,
    cache: Mutex<Cache>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Upstream {
    pub fn new(peers: Vec<Peer>) -> Upstream {
        let state = peers.iter().map(|p| State { effective: p.weight, ..State::default() }).collect();
        Upstream { peers, keepalive: None, balance: Balance::RoundRobin, state: Mutex::new(state), cache: Mutex::default() }
    }

    /// How many servers a request may try: those not marked down, as
    /// ngx_http_upstream_tries() counts them.
    pub fn tries(&self) -> usize {
        self.peers.iter().filter(|p| !p.down).count()
    }

    /// The next server to try, given those already tried for this request:
    /// the primary servers first, then the backup ones, as
    /// ngx_http_upstream_get_peer() chooses them. A single server may be tried again.
    pub fn pick(&self, tried: &mut [bool]) -> Option<usize> {
        let mut state = self.state.lock().unwrap();
        let single = self.peers.len() == 1;
        let now = now();
        [false, true].into_iter().find_map(|backup| {
            let (mut best, mut total): (Option<(usize, i64)>, i64) = (None, 0);
            for (i, p) in self.peers.iter().enumerate().filter(|(i, p)| p.backup == backup && !p.down && (single || !tried[*i])) {
                let s = &mut state[i];
                if !single && p.max_fails > 0 && s.fails >= p.max_fails && now - s.checked <= p.fail_timeout { continue; }
                if p.max_conns > 0 && s.conns >= p.max_conns { continue; }
                s.current += s.effective;
                total += s.effective;
                s.effective += (s.effective < p.weight) as i64;
                if best.is_none_or(|(_, current)| s.current > current) { best = Some((i, s.current)); }
            }
            let (b, _) = best?;
            (state[b].current, state[b].conns) = (state[b].current - total, state[b].conns + 1);
            if now - state[b].checked > self.peers[b].fail_timeout { state[b].checked = now; }
            tried[b] = true;
            Some(b)
        })
    }

    /// The next server to try as the upstream's balancing method chooses it.
    pub fn choose(&self, tried: &mut [bool], hashed: &mut Hashed) -> Option<usize> {
        match self.balance { Balance::IpHash => self.ip_hash(tried, hashed), Balance::LeastConn => self.least_conn(tried), Balance::RoundRobin => self.pick(tried) }
    }

    /// Whether a server may be tried now: not marked down, nor failed too often
    /// within fail_timeout, nor with max_conns connections.
    fn usable(&self, i: usize, s: &State, now: u64) -> bool {
        let p = &self.peers[i];
        !p.down && !(p.max_fails > 0 && s.fails >= p.max_fails && now - s.checked <= p.fail_timeout) && !(p.max_conns > 0 && s.conns >= p.max_conns)
    }

    /// Counts a server chosen for a request, as tried and with one more connection.
    fn chosen(&self, i: usize, state: &mut [State], tried: &mut [bool], now: u64) -> Option<usize> {
        state[i].conns += 1;
        if now - state[i].checked > self.peers[i].fail_timeout { state[i].checked = now; }
        tried[i] = true;
        Some(i)
    }

    /// ip_hash, as ngx_http_upstream_get_ip_hash_peer() chooses: the hash of the
    /// client's address, by the weights of the primary servers; hashed again while
    /// it falls on one that cannot be tried, and after 20 times, or with fewer than
    /// two primary servers, round-robin.
    fn ip_hash(&self, tried: &mut [bool], h: &mut Hashed) -> Option<usize> {
        let primary: Vec<usize> = (0..self.peers.len()).filter(|i| !self.peers[*i].backup).collect();
        if primary.len() < 2 { return self.pick(tried) } let total = primary.iter().map(|i| self.peers[*i].weight).sum::<i64>() as u64;
        let (mut state, now) = (self.state.lock().unwrap(), now());
        loop {
            if h.tries > 20 { drop(state); return self.pick(tried) } h.hash = h.addr.iter().fold(h.hash, |hash, b| (hash * 113 + u64::from(*b)) % 6271);
            let mut w = (h.hash % total) as i64;
            let i = primary.iter().copied().find(|i| { w -= self.peers[*i].weight; w < 0 }).unwrap_or(primary[0]);
            if !tried[i] && self.usable(i, &state[i], now) { return self.chosen(i, &mut state, tried, now) } h.tries += 1;
        }
    }

    /// least_conn, as ngx_http_upstream_get_least_conn_peer() chooses: the server
    /// with the fewest connections for its weight, by weighted round-robin among
    /// those with as few; the primary servers first, then the backup ones.
    fn least_conn(&self, tried: &mut [bool]) -> Option<usize> {
        if self.peers.len() == 1 { return self.pick(tried) } let (mut state, now) = (self.state.lock().unwrap(), now());
        [false, true].into_iter().find_map(|backup| {
            let candidates: Vec<usize> = (0..self.peers.len()).filter(|&i| self.peers[i].backup == backup && !tried[i] && self.usable(i, &state[i], now)).collect();
            let load = |i: usize, of: usize| state[i].conns as i64 * self.peers[of].weight;
            let first = *candidates.iter().min_by(|&&a, &&b| load(a, b).cmp(&load(b, a)))?;
            let ties: Vec<usize> = candidates.into_iter().filter(|&i| load(i, first) == load(first, i)).collect();
            let (mut best, mut total) = (first, 0);
            for &i in ties.iter().filter(|_| ties.len() > 1) {
                let (p, s) = (&self.peers[i], &mut state[i]);
                (s.current, total) = (s.current + s.effective, total + s.effective);
                s.effective += (s.effective < p.weight) as i64;
                if state[i].current > state[best].current { best = i; }
            }
            state[best].current -= total;
            self.chosen(best, &mut state, tried, now)
        })
    }

    /// What gives back the connection to the server pick() gave, once it is not used for the request any more.
    pub fn held(self: &Arc<Self>, i: usize) -> Held {
        Held(self.clone(), i)
    }

    /// Records how a server answered, as ngx_http_upstream_free_round_robin_peer() does:
    /// whether it is not tried for a while.
    pub fn done(&self, i: usize, failed: bool) -> bool {
        let mut state = self.state.lock().unwrap();
        let (p, s) = (&self.peers[i], &mut state[i]);
        if !failed {
            if s.accessed < s.checked { s.fails = 0; }
            return false;
        }
        let now = now();
        (s.fails, s.accessed, s.checked) = (s.fails + 1, now, now);
        if p.max_fails > 0 { s.effective = (s.effective - p.weight / p.max_fails as i64).max(0); }
        self.peers.len() > 1 && p.max_fails > 0 && s.fails >= p.max_fails
    }

    /// The idle connection to the server that was kept last, counted as used for
    /// one more request; opened by the location if they are local to one; and used for
    /// HTTP/2 or for HTTP/1 before, as neither is used for the other. Those found on
    /// the way that are not usable any more are closed.
    pub fn take_for(&self, addr: &Addr, tag: usize, h2: bool) -> Option<Conn> {
        let keepalive = self.keepalive.as_ref()?;
        let (mut cache, now) = (self.cache.lock().unwrap(), Instant::now());
        let mut from = 0;
        loop {
            from += cache.idle.iter().skip(from).position(|i| i.addr == *addr && (!keepalive.local || i.tag == tag) && i.conn.h2.is_some() == h2)?;
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
    pub fn put(self: &Arc<Self>, mut conn: Conn, addr: Addr, tag: usize) {
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

/// A connection to a server of an upstream that a request uses, which counts for its max_conns until it is dropped.
#[derive(Debug)]
pub struct Held(Arc<Upstream>, usize);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.state.lock().unwrap()[self.1].conns -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::block_on;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    impl Upstream {
        /// Takes a connection used for HTTP/1.
        pub(crate) fn take(&self, addr: &SocketAddr, tag: usize) -> Option<Conn> {
            self.take_for(&(*addr).into(), tag, false)
        }
    }

    fn peers(n: usize, max_fails: u64) -> Upstream {
        let peers = (0..n).map(|i| Peer { max_fails, ..Peer::new(SocketAddr::from(([127, 0, 0, 1], 1000 + i as u16))) });
        Upstream::new(peers.collect())
    }

    #[test]
    fn ip_hash() {
        let mut u = peers(3, 1);
        u.balance = Balance::IpHash;
        let client = |a: [u8; 4]| Hashed::new(IpAddr::from(a));
        // The last byte of IPv4 is not hashed.
        let first = u.choose(&mut [false; 3], &mut client([10, 0, 0, 1])).unwrap();
        assert_eq!(u.choose(&mut [false; 3], &mut client([10, 0, 0, 2])), Some(first));
        // 89, then for each byte (hash * 113 + byte) % 6271: 4040, and 4040 % 3 = 2.
        assert_eq!(u.choose(&mut [false; 3], &mut client([127, 0, 0, 1])), Some(2));
        // A server tried, down or failed is hashed past: 5510 falls on it again, 4957 on 1.
        let (mut tried, mut h) = ([false, false, true], client([127, 0, 0, 1]));
        assert_eq!((u.choose(&mut tried, &mut h), tried, h.hash, h.tries), (Some(1), [false, true, true], 4957, 2));
        let v6 = Hashed::new("::1".parse().unwrap());
        assert_eq!((v6.addr.len(), v6.hash), (16, 89));
        // After 20 times, or with fewer than two servers, round-robin.
        let mut h = client([127, 0, 0, 1]);
        h.tries = 21;
        assert!(u.choose(&mut [false; 3], &mut h).is_some());
        let mut one = peers(1, 1);
        one.balance = Balance::IpHash;
        assert_eq!(one.choose(&mut [false], &mut client([1, 2, 3, 4])), Some(0));
    }

    #[test]
    fn least_conn() {
        let mut u = peers(3, 1);
        u.balance = Balance::LeastConn;
        let u = Arc::new(u);
        let mut h = Hashed::new([127, 0, 0, 1].into());
        // Ties go round-robin.
        let picks: Vec<usize> = (0..3).map(|_| { let i = u.choose(&mut [false; 3], &mut h).unwrap(); drop(u.held(i)); i }).collect();
        assert_eq!(picks, [0, 1, 2]);
        // The one with the fewest connections, for its weight.
        let held = [u.held(u.choose(&mut [false; 3], &mut h).unwrap()), u.held(u.choose(&mut [false; 3], &mut h).unwrap())];
        assert_eq!(u.choose(&mut [false; 3], &mut h), Some(2));
        drop(held);
        let mut tried = [true, true, true];
        assert_eq!(u.choose(&mut tried, &mut h), None);
        // Backup servers after the others.
        let mut b = peers(2, 1);
        (b.balance, b.peers[1].backup) = (Balance::LeastConn, true);
        assert_eq!(b.choose(&mut [true, false], &mut h), Some(1));
        let mut one = peers(1, 1);
        one.balance = Balance::LeastConn;
        assert_eq!([(); 2].map(|_| one.choose(&mut [false], &mut h)), [Some(0); 2]);
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

    #[test]
    fn a_single_server_is_picked_again() {
        let (one, two) = (peers(1, 1), peers(2, 1));
        let (mut tried, mut both) = ([false], [false, false]);
        assert_eq!([(); 3].map(|_| one.pick(&mut tried)), [Some(0); 3]);
        assert_eq!([(); 3].map(|_| two.pick(&mut both)), [Some(0), Some(1), None]);
    }

    /// An upstream that keeps connections.
    fn keeping(keepalive: Keepalive) -> Arc<Upstream> {
        let mut u = peers(1, 1);
        u.keepalive = Some(keepalive);
        Arc::new(u)
    }

    /// A server, whose sockets block.
    #[test]
    fn max_conns_keeps_servers_from_more() {
        let addr = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let peers = vec![Peer { max_conns: 1, ..Peer::new(addr(1)) }, Peer { backup: true, ..Peer::new(addr(2)) }];
        let u = Arc::new(Upstream::new(peers));
        let held = u.held(u.pick(&mut [false; 2]).unwrap());
        // The first is at its limit while it is held: the backup is tried, then nothing is.
        let mut tried = [false; 2];
        assert_eq!((u.pick(&mut tried), u.pick(&mut tried)), (Some(1), None));
        drop(held);
        assert_eq!(u.pick(&mut [false; 2]), Some(0));
        assert_eq!(Addr::Unix(std::path::Path::new("/s").into()).to_string(), "unix:/s");
    }

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
        conn.as_ref().map(|c| c.stream.tcp().unwrap().local_addr().unwrap().port())
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
            for conn in [a, b, c] { u.put(conn, addr.into(), 0); }
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
                u.put(a, addr.into(), 1);
                u.put(b, addr2.into(), 1);
                assert_eq!(port(&u.take(&addr, 2)), (!local).then_some(a_port));
                assert_eq!(port(&u.take(&addr, 1)), local.then_some(a_port));
                assert!(u.take(&addr, 1).is_none());
                assert_eq!(port(&u.take(&addr2, 1)), Some(b_port));
            }
        });
    }

    #[test]
    fn a_connection_is_of_http2_or_not() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive { local: false, ..Keepalive::default() }), server());
            let ((mut a, _a, a_port), (b, _b, b_port)) = (open(&l).await, open(&l).await);
            a.h2 = Some(Box::new(crate::h2::Session::default()));
            u.put(a, addr.into(), 0);
            u.put(b, addr.into(), 0);
            assert_eq!(port(&u.take_for(&addr.into(), 0, true)), Some(a_port));
            assert!(u.take_for(&addr.into(), 0, true).is_none());
            assert_eq!(port(&u.take(&addr, 0)), Some(b_port));
        });
    }

    #[test]
    fn a_connection_has_so_many_requests_and_so_much_time() {
        block_on(async {
            let (l, addr) = server();
            let u = keeping(Keepalive { requests: 1, ..Keepalive::default() });
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr.into(), 0);
            assert!(idle(&u) == 0 && tasks(&u) == 0 && closed(&other));

            let u = keeping(Keepalive { requests: 2, ..Keepalive::default() });
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr.into(), 0);
            let conn = u.take(&addr, 0).unwrap();
            assert_eq!(conn.requests, 2);
            u.put(conn, addr.into(), 0);
            assert!(idle(&u) == 0 && closed(&other));

            let u = keeping(Keepalive { time: Duration::from_secs(5), ..Keepalive::default() });
            let (mut conn, _other, _) = open(&l).await;
            conn.opened -= Duration::from_secs(1);
            u.put(conn, addr.into(), 0);
            let mut conn = u.take(&addr, 0).unwrap();
            conn.opened -= Duration::from_secs(5);
            u.put(conn, addr.into(), 0);
            assert_eq!(idle(&u), 0);
        });
    }

    #[test]
    fn a_connection_is_idle_for_so_long() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive { timeout: Duration::from_millis(50), ..Keepalive::default() }), server());
            let ((a, a_other, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
            u.put(a, addr.into(), 0);
            pause(60);
            assert!(u.take(&addr, 0).is_none());
            assert!(idle(&u) == 0 && closed(&a_other));
            u.put(b, addr.into(), 0);
            assert_eq!(idle(&u), 1);
            wait(|| idle(&u) == 0).await;
            assert!(closed(&b_other));

            // A time too long to represent never passes.
            let u = keeping(Keepalive { timeout: Duration::MAX, ..Keepalive::default() });
            let (conn, _other, _) = open(&l).await;
            u.put(conn, addr.into(), 0);
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
                u.put(a, addr.into(), 0);
                u.put(b, addr.into(), 0);
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
                u.put(b, addr.into(), 0);
                assert!(idle(&u) == 0 && closed(&b_other));
                // And by the task, which leaves the others.
                let (b, b_other, _) = open(&l).await;
                u.put(a.unwrap(), addr.into(), 0);
                u.put(b, addr.into(), 0);
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
            u.put(a, addr.into(), 0);
            run(20).await;
            u2.put(b, addr.into(), 0);
            close_idle();
            assert_eq!((idle(&u), idle(&u2)), (0, 0));
            assert!(closed(&a_other) && closed(&b_other));
            u.put(c, addr.into(), 0);
            assert!(idle(&u) == 0 && closed(&c_other));
            wait(|| tasks(&u) + tasks(&u2) == 0).await;
        })).join().unwrap();
    }

    #[test]
    fn without_keepalive_none_is_kept() {
        block_on(async {
            let (u, (l, addr)) = (Arc::new(peers(1, 1)), server());
            let (conn, other, _) = open(&l).await;
            u.put(conn, addr.into(), 0);
            assert!(idle(&u) == 0 && tasks(&u) == 0 && closed(&other));
            assert!(u.take(&addr, 0).is_none());
        });
    }

    #[test]
    fn the_task_ends_and_starts_again() {
        block_on(async {
            let (u, (l, addr)) = (keeping(Keepalive::default()), server());
            let ((a, _a, _), (b, b_other, _)) = (open(&l).await, open(&l).await);
            u.put(a, addr.into(), 0);
            // A connection taken and kept again before the task ran needs no other task.
            let a = u.take(&addr, 0).unwrap();
            u.put(a, addr.into(), 0);
            assert_eq!(tasks(&u), 1);
            let _a = u.take(&addr, 0).unwrap();
            wait(|| tasks(&u) == 0).await;
            assert!(!u.cache.lock().unwrap().waker.is_some());
            u.put(b, addr.into(), 0);
            assert_eq!(tasks(&u), 1);
            drop(b_other);
            wait(|| idle(&u) == 0 && tasks(&u) == 0).await;

            // It does not keep the upstream, which closes its connections when dropped,
            // whether the task ran already or not.
            for ms in [0, 20] {
                let u = keeping(Keepalive { timeout: Duration::MAX, ..Keepalive::default() });
                let (c, c_other, _) = open(&l).await;
                u.put(c, addr.into(), 0);
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
                u.put(a, addr.into(), 0);
                run(20).await;
                u.put(b, addr.into(), 0);
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
            u.put(a, addr.into(), 0);
            run(100).await;
            let kept = Instant::now();
            u.put(b, "127.0.0.1:1".parse::<SocketAddr>().unwrap().into(), 0);
            let a = u.take(&addr, 0);
            assert_eq!((port(&a), idle(&u), tasks(&u)), (Some(a_port), 1, 1));
            wait(|| idle(&u) == 0).await;
            assert!((timeout..Duration::from_secs(2)).contains(&kept.elapsed()) && closed(&b_other));
            wait(|| tasks(&u) == 0).await;

            // Taken, the only one leaves the task running until the time has passed.
            u.put(c, addr.into(), 0);
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
                u.put(conn, addr.into(), 0);
                run(20).await;
                let mut conn = u.take(&addr, 0).unwrap();
                exchange(&mut conn, &other).await;
                u.put(conn, addr.into(), 0);
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
            u.put(a, addr.into(), 0);
            u.put(b, addr.into(), 0);
            run(20).await;
            let polls = POLLS.get();
            assert!(polls > 0);
            run(300).await;
            assert_eq!(POLLS.get(), polls);
            for _ in 0..100 {
                let mut b = u.take(&addr, 0).unwrap();
                exchange(&mut b, &b_other).await;
                u.put(b, addr.into(), 0);
                run(1).await;
            }
            assert_eq!((POLLS.get(), idle(&u), tasks(&u)), (polls, 2, 1));
        });
    }
}
