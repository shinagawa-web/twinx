//! The resolver directive: names in proxy_pass URLs with variables are looked
//! up with DNS queries for A records sent to the resolver's servers, as nginx's
//! resolver does: in turn for each new name, resent every 5 seconds to the next
//! server until resolver_timeout, again over TCP when the answer is truncated,
//! following CNAME records, and kept for the TTL of the answer (or "valid=").

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long nginx waits for an answer before it sends the query again.
const RESEND: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    /// valid=: how long answers are kept instead of their TTL.
    valid: Option<Duration>,
    next: AtomicUsize,
    /// The addresses of the names looked up, and until when they hold.
    cache: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

/// What an answer to a query says.
#[derive(Debug, PartialEq)]
enum Reply {
    /// Not the answer to the query, malformed, or a format error: nginx goes on waiting.
    Ignore,
    /// The answer did not fit in a UDP datagram: the query is sent again over TCP.
    Truncated,
    /// An error code, or neither addresses nor a CNAME: the name is not found.
    Failed,
    /// The addresses, else the name they are an alias of, and the smallest TTL.
    Found(Vec<IpAddr>, Option<String>, u32),
}

impl Resolver {
    /// resolver address[:port] ... [valid=time]
    pub fn parse(args: &[String]) -> Result<Resolver, String> {
        let (mut servers, mut valid) = (Vec::new(), None);
        for a in args {
            if let Some(v) = a.strip_prefix("valid=") {
                let secs = crate::expires::parse_time(v).filter(|s| *s >= 0).ok_or_else(|| format!("invalid parameter: {a}"))?;
                valid = Some(Duration::from_secs(secs as u64));
                continue;
            }
            let addr = a.parse().or_else(|_| format!("{a}:53").parse()).map_err(|_| format!("host not found in resolver \"{a}\""))?;
            servers.push(addr);
        }
        Ok(Resolver { servers, valid, next: AtomicUsize::new(0), cache: Mutex::new(HashMap::new()) })
    }

    /// The addresses of a name, None when it cannot be resolved within the timeout.
    pub fn resolve(&self, name: &str, timeout: Duration) -> Option<Vec<IpAddr>> {
        self.lookup(&name.to_ascii_lowercase(), Instant::now() + timeout, 0).map(|(addrs, _)| addrs)
    }

    fn lookup(&self, name: &str, deadline: Instant, depth: usize) -> Option<(Vec<IpAddr>, Instant)> {
        if depth > 10 { return None; }
        if let Some((addrs, until)) = self.cache.lock().unwrap().get(name).filter(|(_, until)| *until > Instant::now()) {
            return Some((addrs.clone(), *until));
        }
        let Reply::Found(addrs, cname, ttl) = self.query(name, deadline) else { return None };
        let until = Instant::now() + self.valid.unwrap_or(Duration::from_secs(ttl as u64));
        let (addrs, until) = match cname.filter(|_| addrs.is_empty()) {
            Some(alias) => self.lookup(&alias, deadline, depth + 1).map(|(a, u)| (a, u.min(until)))?,
            None => (addrs, until),
        };
        self.cache.lock().unwrap().insert(name.to_string(), (addrs.clone(), until));
        Some((addrs, until))
    }

    /// Sends the query for the A records of a name and waits for its answer.
    fn query(&self, name: &str, deadline: Instant) -> Reply {
        let first = self.next.fetch_add(1, Ordering::Relaxed);
        let id = (SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos()) ^ first as u32) as u16;
        let query = encode(id, name);
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { return Reply::Failed };
        let mut buf = [0u8; 4096];
        for server in self.servers.iter().cycle().skip(first % self.servers.len()) {
            let _ = socket.send_to(&query, server);
            let resend = (Instant::now() + RESEND).min(deadline);
            while let Some(left) = resend.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()) {
                let _ = socket.set_read_timeout(Some(left));
                let Ok(n) = socket.recv(&mut buf) else { break };
                match decode(&buf[..n], id, name) {
                    Reply::Ignore => continue,
                    Reply::Truncated => return tcp(server, &query, deadline).map_or(Reply::Failed, |a| decode(&a, id, name)),
                    reply => return reply,
                }
            }
            if Instant::now() >= deadline { break; }
        }
        Reply::Failed
    }
}

/// Sends the query again over TCP, each message after its length in two bytes.
fn tcp(server: &SocketAddr, query: &[u8], deadline: Instant) -> Option<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(server, deadline.checked_duration_since(Instant::now())?).ok()?;
    s.set_read_timeout(deadline.checked_duration_since(Instant::now())).ok()?;
    let mut len = (query.len() as u16).to_be_bytes().to_vec();
    len.extend_from_slice(query);
    s.write_all(&len).ok()?;
    let mut n = [0u8; 2];
    s.read_exact(&mut n).ok()?;
    let mut answer = vec![0u8; u16::from_be_bytes(n) as usize];
    s.read_exact(&mut answer).ok()?;
    Some(answer)
}

/// A query for the A records of a name, with recursion desired.
fn encode(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    name.split('.').filter(|l| !l.is_empty()).for_each(|l| { q.push(l.len() as u8); q.extend_from_slice(l.as_bytes()); });
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// The name at an offset of a message, lowercased, following compression
/// pointers, and where the bytes after it start.
fn name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let (mut labels, mut end, mut hops) = (Vec::new(), None, 0);
    loop {
        let len = *msg.get(at)? as usize;
        if len & 0xc0 == 0xc0 {
            hops += 1;
            if hops > 64 { return None; }
            end = end.or(Some(at + 2));
            at = ((len & 0x3f) << 8) | *msg.get(at + 1)? as usize;
            continue;
        }
        if len == 0 { return Some((labels.join(".").to_ascii_lowercase(), end.unwrap_or(at + 1))); }
        labels.push(String::from_utf8_lossy(msg.get(at + 1..at + 1 + len)?).into_owned());
        at += 1 + len;
    }
}

/// What an answer says, if it is the one to the query with this id and name.
fn decode(msg: &[u8], id: u16, asked: &str) -> Reply {
    answer(msg, id, asked).unwrap_or(Reply::Ignore)
}

fn answer(msg: &[u8], id: u16, asked: &str) -> Option<Reply> {
    let word = |at: usize| msg.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    let flags = word(2)?;
    if word(0)? != id || flags & 0x8000 == 0 || word(4)? != 1 { return Some(Reply::Ignore); }
    let (question, at) = name(msg, 12)?;
    let rcode = flags & 0xf;
    if question != asked || rcode == 1 { return Some(Reply::Ignore); }
    if rcode != 0 { return Some(Reply::Failed); }
    if flags & 0x0200 != 0 { return Some(Reply::Truncated); }
    let (mut at, mut addrs, mut cname, mut ttl) = (at + 4, Vec::new(), None, u32::MAX);
    for _ in 0..word(6)? {
        let (_, next) = name(msg, at)?;
        let (kind, len) = (word(next)?, word(next + 8)? as usize);
        let rdata = msg.get(next + 10..next + 10 + len)?;
        let record_ttl = u32::from_be_bytes(msg.get(next + 4..next + 8)?.try_into().ok()?);
        match kind {
            1 => addrs.push(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?))),
            5 => cname = Some(name(msg, next + 10)?.0),
            _ => {}
        }
        ttl = if [1, 5].contains(&kind) { ttl.min(record_ttl) } else { ttl };
        at = next + 10 + len;
    }
    Some(if addrs.is_empty() && cname.is_none() { Reply::Failed } else { Reply::Found(addrs, cname, ttl) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An answer to the query for "a.b" with id 7, with these flags and records.
    fn reply(flags: u16, records: &[(u16, u32, &[u8])]) -> Vec<u8> {
        let mut m = vec![0, 7];
        m.extend_from_slice(&flags.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, records.len() as u8, 0, 0, 0, 0, 1, b'a', 1, b'b', 0, 0, 1, 0, 1]);
        for (kind, ttl, rdata) in records {
            m.extend_from_slice(&[0xc0, 12]);
            m.extend_from_slice(&kind.to_be_bytes());
            m.extend_from_slice(&[0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            m.extend_from_slice(rdata);
        }
        m
    }

    #[test]
    fn encodes_queries() {
        assert_eq!(encode(0x1234, "a.bc"), vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
    }

    #[test]
    fn decodes_answers() {
        let a = reply(0x8180, &[(1, 30, &[127, 0, 0, 1]), (1, 20, &[127, 0, 0, 2])]);
        assert_eq!(decode(&a, 7, "a.b"), Reply::Found(vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()], None, 20));
        let alias = reply(0x8180, &[(39, 1, &[0]), (5, 9, &[1, b'c', 0xc0, 14])]);
        assert_eq!(decode(&alias, 7, "a.b"), Reply::Found(vec![], Some("c.b".into()), 9));
        assert_eq!(decode(&a, 8, "a.b"), Reply::Ignore);
        assert_eq!(decode(&a, 7, "x.b"), Reply::Ignore);
        assert_eq!(decode(&a[..a.len() - 1], 7, "a.b"), Reply::Ignore);
        assert_eq!(decode(&reply(0x8181, &[]), 7, "a.b"), Reply::Ignore);
        assert_eq!(decode(&reply(0x8182, &[]), 7, "a.b"), Reply::Failed);
        assert_eq!(decode(&reply(0x8180, &[]), 7, "a.b"), Reply::Failed);
        assert_eq!(decode(&reply(0x8380, &[]), 7, "a.b"), Reply::Truncated);
        assert_eq!(decode(&reply(0x8180, &[(1, 1, &[1, 2])]), 7, "a.b"), Reply::Ignore);
    }

    #[test]
    fn pointer_loops_end() {
        assert_eq!(name(&[0xc0, 0], 0), None);
        assert_eq!(name(&[1, b'A', 0xc0, 4, 0], 0), Some(("a".into(), 4)));
    }

    #[test]
    fn parses_the_directive() {
        let r = Resolver::parse(&["127.0.0.1:5353".into(), "127.0.0.2".into(), "valid=5s".into()]).unwrap();
        assert_eq!((r.servers[1].port(), r.valid), (53, Some(Duration::from_secs(5))));
        assert_eq!(Resolver::parse(&["valid=x".into()]).unwrap_err(), "invalid parameter: valid=x");
        assert_eq!(Resolver::parse(&["a b".into()]).unwrap_err(), "host not found in resolver \"a b\"");
    }

    #[test]
    fn resolves_from_a_server_and_keeps_the_answer() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let r = Resolver::parse(&[server.local_addr().unwrap().to_string()]).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            let mut answer = reply(0x8180, &[(1, 60, &[127, 0, 0, 9])]);
            answer[..2].copy_from_slice(&buf[..2]);
            server.send_to(&answer[..], from).unwrap();
            assert_eq!(&buf[12..n], &[1, b'a', 1, b'b', 0, 0, 1, 0, 1]);
        });
        let found = r.resolve("A.b", Duration::from_secs(5));
        assert_eq!(found, Some(vec!["127.0.0.9".parse().unwrap()]));
        assert_eq!(r.resolve("a.b", Duration::from_millis(1)), found);
    }
}
