//! The resolver directive: names in proxy_pass URLs with variables are looked
//! up with DNS queries for A and AAAA records sent to the resolver's servers, as
//! nginx's resolver does: in turn for each new name, resent every 5 seconds to
//! the next server until resolver_timeout, again over TCP when the answer is
//! truncated, following CNAME records, and kept for the TTL of the answer (or
//! "valid="). ipv4=off or ipv6=off leaves out the query for A or AAAA records.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How long nginx waits for an answer before it sends the query again.
const RESEND: Duration = Duration::from_secs(5);

/// The record types nginx asks for, in the order it asks.
const A: u16 = 1;
const AAAA: u16 = 28;

#[derive(Debug)]
pub struct Resolver {
    servers: Vec<SocketAddr>,
    /// valid=: how long answers are kept instead of their TTL.
    valid: Option<Duration>,
    /// The record types asked for: A unless ipv4=off, AAAA unless ipv6=off.
    types: Vec<u16>,
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
    /// An error code: the name is not found.
    Failed,
    /// The addresses, else the name they are an alias of, and the smallest TTL;
    /// neither when the name has no records of the type asked for.
    Found(Vec<IpAddr>, Option<String>, u32),
}

impl Resolver {
    /// resolver address[:port] ... [valid=time] [ipv4=on|off] [ipv6=on|off]
    pub fn parse(args: &[String]) -> Result<Resolver, String> {
        let (mut servers, mut valid, mut types) = (Vec::new(), None, vec![A, AAAA]);
        for a in args {
            if let Some((qtype, on)) = a.strip_prefix("ipv4=").map(|v| (A, v)).or_else(|| a.strip_prefix("ipv6=").map(|v| (AAAA, v))) {
                types.retain(|t| *t != qtype);
                match on { "on" => types.push(qtype), "off" => {}, _ => return Err(format!("invalid parameter: {a}")) }
                types.sort();
                continue;
            }
            if let Some(v) = a.strip_prefix("valid=") {
                let secs = crate::expires::parse_time(v).filter(|s| *s >= 0).ok_or_else(|| format!("invalid parameter: {a}"))?;
                valid = Some(Duration::from_secs(secs as u64));
                continue;
            }
            let addr = a.parse().or_else(|_| format!("{a}:53").parse()).map_err(|_| format!("host not found in resolver \"{a}\""))?;
            servers.push(addr);
        }
        if types.is_empty() { return Err("\"ipv4\" and \"ipv6\" cannot both be \"off\"".into()); }
        Ok(Resolver { servers, valid, types, next: AtomicUsize::new(0), cache: Mutex::new(HashMap::new()) })
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
        // As in nginx, an error in either answer fails the name; the addresses
        // of both are taken together; and a CNAME without addresses is followed
        // only when it is in the answer that came last and the other gave no
        // addresses.
        let first = self.next.fetch_add(1, Ordering::Relaxed);
        let replies = self.query(name, first, deadline);
        let (mut addrs, mut cname, mut ttl) = (Vec::new(), None, u32::MAX);
        for reply in replies {
            let Reply::Found(found, alias, t) = reply else { return None };
            cname = alias.filter(|_| found.is_empty());
            ttl = if found.is_empty() && cname.is_none() { ttl } else { ttl.min(t) };
            addrs.extend(found);
        }
        let until = Instant::now() + self.valid.unwrap_or(Duration::from_secs(ttl as u64));
        let (addrs, until) = match cname.filter(|_| addrs.is_empty()) {
            Some(alias) => self.lookup(&alias, deadline, depth + 1).map(|(a, u)| (a, u.min(until)))?,
            None if addrs.is_empty() => return None,
            None => (addrs, until),
        };
        self.cache.lock().unwrap().insert(name.to_string(), (addrs.clone(), until));
        Some((addrs, until))
    }

    /// Sends the queries for the A and AAAA records (those asked for) of a name together, to the
    /// servers from the first one on, and waits for their answers. They come in
    /// the order they arrived; one not answered before the deadline has failed.
    fn query(&self, name: &str, first: usize, deadline: Instant) -> Vec<Reply> {
        let id = (SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.subsec_nanos()) ^ (first as u32) << 5) as u16 & !1;
        let queries: Vec<_> = self.types.iter().map(|&qtype| (qtype, id | (qtype == AAAA) as u16, encode(id | (qtype == AAAA) as u16, name, qtype))).collect();
        let (mut replies, mut waiting) = (Vec::new(), (0..queries.len()).collect::<Vec<_>>());
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else { return replies };
        let mut buf = [0u8; 4096];
        for server in self.servers.iter().cycle().skip(first % self.servers.len()) {
            waiting.iter().for_each(|&i| { let _ = socket.send_to(&queries[i].2, server); });
            let resend = (Instant::now() + RESEND).min(deadline);
            while let Some(left) = resend.checked_duration_since(Instant::now()).filter(|d| !d.is_zero() && !waiting.is_empty()) {
                let _ = socket.set_read_timeout(Some(left));
                let Ok(n) = socket.recv(&mut buf) else { break };
                let Some((at, reply)) = waiting.iter().enumerate().map(|(at, &i)| (at, decode(&buf[..n], queries[i].1, name, queries[i].0))).find(|(_, r)| *r != Reply::Ignore) else { continue };
                let (qtype, id, query) = &queries[waiting.remove(at)];
                let tcp = || tcp(server, query, deadline).map_or(Reply::Failed, |a| decode(&a, *id, name, *qtype));
                replies.push(if reply == Reply::Truncated { tcp() } else { reply });
            }
            if waiting.is_empty() || Instant::now() >= deadline { break; }
        }
        replies.resize_with(queries.len(), || Reply::Failed);
        replies
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

/// A query for the records of a type of a name, with recursion desired.
fn encode(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    name.split('.').filter(|l| !l.is_empty()).for_each(|l| { q.push(l.len() as u8); q.extend_from_slice(l.as_bytes()); });
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
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
fn decode(msg: &[u8], id: u16, asked: &str, qtype: u16) -> Reply {
    answer(msg, id, asked, qtype).unwrap_or(Reply::Ignore)
}

fn answer(msg: &[u8], id: u16, asked: &str, qtype: u16) -> Option<Reply> {
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
            A if qtype == A => addrs.push(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(rdata).ok()?))),
            AAAA if qtype == AAAA => addrs.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rdata).ok()?))),
            5 => cname = Some(name(msg, next + 10)?.0),
            _ => {}
        }
        ttl = if [qtype, 5].contains(&kind) { ttl.min(record_ttl) } else { ttl };
        at = next + 10 + len;
    }
    Some(Reply::Found(addrs, cname, ttl))
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
        assert_eq!(encode(0x1234, "a.bc", A), vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]);
        assert_eq!(&encode(0x1234, "a.bc", AAAA)[18..], &[0, 28, 0, 1]);
    }

    #[test]
    fn decodes_answers() {
        let a = reply(0x8180, &[(1, 30, &[127, 0, 0, 1]), (1, 20, &[127, 0, 0, 2])]);
        assert_eq!(decode(&a, 7, "a.b", A), Reply::Found(vec!["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()], None, 20));
        assert_eq!(decode(&a, 7, "a.b", AAAA), Reply::Found(vec![], None, u32::MAX));
        let six = reply(0x8180, &[(28, 5, &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])]);
        assert_eq!(decode(&six, 7, "a.b", AAAA), Reply::Found(vec!["fe80::1".parse().unwrap()], None, 5));
        let alias = reply(0x8180, &[(39, 1, &[0]), (5, 9, &[1, b'c', 0xc0, 14])]);
        assert_eq!(decode(&alias, 7, "a.b", A), Reply::Found(vec![], Some("c.b".into()), 9));
        assert_eq!(decode(&a, 8, "a.b", A), Reply::Ignore);
        assert_eq!(decode(&a, 7, "x.b", A), Reply::Ignore);
        assert_eq!(decode(&a[..a.len() - 1], 7, "a.b", A), Reply::Ignore);
        assert_eq!(decode(&reply(0x8181, &[]), 7, "a.b", A), Reply::Ignore);
        assert_eq!(decode(&reply(0x8182, &[]), 7, "a.b", A), Reply::Failed);
        assert_eq!(decode(&reply(0x8380, &[]), 7, "a.b", A), Reply::Truncated);
        assert_eq!(decode(&reply(0x8180, &[(1, 1, &[1, 2])]), 7, "a.b", A), Reply::Ignore);
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
        assert_eq!(r.types, vec![A, AAAA]);
        let parse = |a: &[&str]| Resolver::parse(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>()).map(|r| r.types);
        assert_eq!(parse(&["ipv4=off"]), Ok(vec![AAAA]));
        assert_eq!(parse(&["ipv6=off"]), Ok(vec![A]));
        assert_eq!(parse(&["ipv6=on", "ipv4=on"]), Ok(vec![A, AAAA]));
        assert_eq!(parse(&["ipv4=off", "ipv4=on"]), Ok(vec![A, AAAA]));
        assert_eq!(parse(&["ipv6=x"]), Err("invalid parameter: ipv6=x".into()));
        assert_eq!(parse(&["ipv4=off", "ipv6=off"]), Err("\"ipv4\" and \"ipv6\" cannot both be \"off\"".into()));
    }

    /// A server that answers each query it gets with what `answer` gives for its type (A or AAAA).
    fn server(answer: fn(u16) -> Vec<u8>) -> Resolver { server_with(answer, &[]) }

    fn server_with(answer: fn(u16) -> Vec<u8>, params: &[&str]) -> Resolver {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut args = vec![server.local_addr().unwrap().to_string()];
        args.extend(params.iter().map(|p| p.to_string()));
        let r = Resolver::parse(&args).unwrap();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = server.recv_from(&mut buf) {
                let mut reply = answer(u16::from_be_bytes([buf[n - 4], buf[n - 3]]));
                reply[..2].copy_from_slice(&buf[..2]);
                reply[17..19].copy_from_slice(&buf[n - 4..n - 2]);
                server.send_to(&reply[..], from).unwrap();
            }
        });
        r
    }

    #[test]
    fn resolves_from_a_server_and_keeps_the_answer() {
        let r = server(|t| if t == A { reply(0x8180, &[(1, 60, &[127, 0, 0, 9])]) } else { reply(0x8180, &[]) });
        let found = r.resolve("A.b", Duration::from_secs(5));
        assert_eq!(found, Some(vec!["127.0.0.9".parse().unwrap()]));
        assert_eq!(r.resolve("a.b", Duration::from_millis(1)), found);
    }

    #[test]
    fn takes_both_answers_together() {
        let six: &[u8] = &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let both = server(|t| if t == A { reply(0x8180, &[(1, 60, &[127, 0, 0, 9])]) } else { reply(0x8180, &[(28, 60, &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])]) });
        assert_eq!(both.resolve("a.b", Duration::from_secs(5)), Some(vec!["127.0.0.9".parse().unwrap(), IpAddr::from(<[u8; 16]>::try_from(six).unwrap())]));
        // An error in either answer fails the name, and so do two empty answers.
        let error = server(|t| if t == A { reply(0x8180, &[(1, 60, &[127, 0, 0, 9])]) } else { reply(0x8182, &[]) });
        assert_eq!(error.resolve("a.b", Duration::from_secs(5)), None);
        let empty = server(|_| reply(0x8180, &[]));
        assert_eq!(empty.resolve("a.b", Duration::from_secs(5)), None);
        // A CNAME only in the first answer is not followed when the last one is empty.
        let alias = server(|t| if t == A { reply(0x8180, &[(5, 60, &[1, b'c', 0xc0, 14])]) } else { reply(0x8180, &[]) });
        assert_eq!(alias.resolve("a.b", Duration::from_secs(5)), None);
    }

    #[test]
    fn asks_only_for_the_types_turned_on() {
        let answer = |t| if t == A { reply(0x8180, &[(1, 60, &[127, 0, 0, 9])]) } else { reply(0x8180, &[(28, 60, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])]) };
        assert_eq!(server_with(answer, &["ipv6=off"]).resolve("a.b", Duration::from_secs(5)), Some(vec!["127.0.0.9".parse().unwrap()]));
        assert_eq!(server_with(answer, &["ipv4=off"]).resolve("a.b", Duration::from_secs(5)), Some(vec!["::1".parse().unwrap()]));
        // An error in the only answer asked for fails the name.
        let error = server_with(|t| if t == A { reply(0x8182, &[]) } else { reply(0x8180, &[(28, 60, &[0; 16])]) }, &["ipv6=off"]);
        assert_eq!(error.resolve("a.b", Duration::from_secs(5)), None);
    }
}
