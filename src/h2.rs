use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::watch;

use crate::conf::Config;
use crate::http::{Busy, Origin, Reading};
use crate::stream::{Pipe, Stream, at_once, buffer, recycle, within, write_all};
use crate::upstream::{Conn, Upstream};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const PRIORITY: u8 = 2;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PUSH_PROMISE: u8 = 5;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;
const END_STREAM: u8 = 1;
const ACK: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const PRIORITY_FLAG: u8 = 0x20;
const NO_ERROR: u32 = 0;
const PROTOCOL_ERROR: u32 = 1;
const INTERNAL_ERROR: u32 = 2;
const FLOW_CONTROL_ERROR: u32 = 3;
const STREAM_CLOSED: u32 = 5;
const FRAME_SIZE_ERROR: u32 = 6;
const REFUSED_STREAM: u32 = 7;
const COMPRESSION_ERROR: u32 = 9;
const ENHANCE_YOUR_CALM: u32 = 11;
const AGAIN: u32 = u32::MAX;

const MAX_WINDOW: i64 = (1 << 31) - 1;
const PREREAD: i64 = 65536;
const CONCURRENT: usize = 128;
const WAITING: usize = 65536;
const HEADER_TIMEOUT: Duration = Duration::from_secs(60);
const TABLE_SIZE: usize = 4096;

type Fields = Vec<(Vec<u8>, Vec<u8>)>;
pub type Addrs = (SocketAddr, SocketAddr, (SocketAddr, u64), Option<Arc<crate::tls::Session>>);
#[derive(Debug, PartialEq)]
enum Ended { Whole(Fields), Cut }
#[derive(Debug, Default, PartialEq)]
struct Part { head: Option<(Vec<u8>, bool)>, data: Vec<u8>, ended: Option<Ended> }
enum Told { Reading(Reading), Answer(Part) }

static STATIC: [(&str, &str); 61] = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""), ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""),
    ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""),
    ("if-none-match", ""), ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
    ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""),
    ("retry-after", ""), ("server", ""), ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
];

static HUFFMAN: [(u32, u8); 256] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
    (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
    (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
    (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12), (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
    (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8), (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
    (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
    (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
    (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
    (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
    (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23),
    (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23),
    (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23), (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23),
    (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21), (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23),
    (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25),
    (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27),
    (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23),
    (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27),
    (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26),
];

fn symbols() -> &'static [(u32, u32, u32, Vec<u8>)] {
    static SYMBOLS: OnceLock<Vec<(u32, u32, u32, Vec<u8>)>> = OnceLock::new();
    SYMBOLS.get_or_init(|| (5..=30).filter_map(|len| {
        let mut of: Vec<_> = (0..=255u8).map(|c| (HUFFMAN[usize::from(c)], c)).filter(|(code, _)| u32::from(code.1) == len).map(|(code, c)| (code.0, c)).collect();
        of.sort();
        Some((len, of.first()?.0, (of.last()?.0 + 1) << (32 - len), of.into_iter().map(|(_, c)| c).collect()))
    }).collect())
}

fn write_string(out: &mut Vec<u8>, s: &[u8], lower: bool) {
    let octet = |c: u8| if lower { c.to_ascii_lowercase() } else { c };
    let len = s.iter().map(|&c| usize::from(HUFFMAN[usize::from(octet(c))].1)).sum::<usize>().div_ceil(8);
    if len >= s.len() {
        write_integer(out, 0, 7, s.len());
        return out.extend(s.iter().map(|&c| octet(c)));
    }
    write_integer(out, 0x80, 7, len);
    let (mut acc, mut bits) = (0u64, 0);
    for &c in s {
        let (code, len) = HUFFMAN[usize::from(octet(c))];
        (acc, bits) = (acc << len | u64::from(code), bits + len);
        while bits >= 8 { bits -= 8; out.push((acc >> bits) as u8); }
    }
    if bits > 0 { out.push((acc << (8 - bits)) as u8 | 0xff >> bits); }
}

fn unhuffman(src: &[u8], out: &mut Vec<u8>) -> bool {
    let (mut src, mut acc, mut bits) = (src.iter(), 0u64, 0u32);
    loop {
        while bits < 32 && let Some(&b) = src.next() { (acc, bits) = (acc << 8 | u64::from(b), bits + 8); }
        let next = if bits < 32 { (acc << (32 - bits)) as u32 | u32::MAX >> bits } else { (acc >> (bits - 32)) as u32 };
        match symbols().iter().find(|s| next < s.2 && s.0 <= bits) {
            Some((len, first, _, octets)) => { out.push(octets[((next >> (32 - len)) - first) as usize]); bits -= len; }
            None => return bits < 30 && next == u32::MAX,
        }
    }
}

fn integer(block: &[u8], at: &mut usize, bits: u8, length: usize) -> Result<usize, u32> {
    let (rest, prefix, length) = (&block[*at..], (1 << bits) - 1, length - *at);
    let mut value = usize::from(rest[0]) & prefix;
    if value < prefix { *at += 1; return Ok(value) }
    for (i, &octet) in rest[1..rest.len().min(4)].iter().enumerate() {
        value += usize::from(octet & 0x7f) << (7 * i);
        if octet < 128 { *at += i + 2; return Ok(value) }
    }
    let end = rest.len().min(4);
    Err(if end >= length { FRAME_SIZE_ERROR } else if end == 4 { COMPRESSION_ERROR } else { AGAIN })
}

fn write_integer(out: &mut Vec<u8>, first: u8, bits: u8, mut value: usize) {
    let prefix = (1 << bits) - 1;
    if value < prefix { out.push(first | value as u8); return }
    out.push(first | prefix as u8);
    value -= prefix;
    while value >= 128 { out.push(value as u8 | 0x80); value >>= 7; }
    out.push(value as u8);
}

#[derive(Clone)]
struct Table { entries: VecDeque<(Vec<u8>, Vec<u8>)>, size: usize, used: usize, limit: usize }

#[derive(Default)]
struct Block { bytes: Vec<u8>, ends: Vec<(usize, usize)> }

impl Block {
    fn fields(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        let starts = std::iter::once(0).chain(self.ends.iter().map(|e| e.1));
        starts.zip(&self.ends).map(|(start, &(name, value))| (&self.bytes[start..name], &self.bytes[name..value]))
    }
}

impl Table {
    fn field(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if index <= STATIC.len() { return index.checked_sub(1).map(|i| (STATIC[i].0.as_bytes(), STATIC[i].1.as_bytes())) }
        self.entries.get(index - STATIC.len() - 1).map(|(n, v)| (&n[..], &v[..]))
    }

    fn evict(&mut self, size: usize) {
        while self.used > size { let (n, v) = self.entries.pop_back().unwrap_or_default(); self.used -= n.len() + v.len() + 32; }
    }

    fn add(&mut self, name: &[u8], value: &[u8]) {
        let size = name.len() + value.len() + 32;
        self.evict(self.size.saturating_sub(size));
        if size > self.size { return }
        self.entries.push_front((name.to_vec(), value.to_vec()));
        self.used += size;
    }

    fn decode(&mut self, block: &[u8], length: usize, limits: (usize, usize)) -> Result<Fields, u32> {
        self.block(block, length, limits, None).map(|b| b.fields().map(|(n, v)| (n.to_vec(), v.to_vec())).collect())
    }

    fn block(&mut self, block: &[u8], length: usize, (number, size): (usize, usize), mut dropped: Option<&mut bool>) -> Result<Block, u32> {
        let (mut fields, mut at, mut left) = (Block { bytes: Vec::with_capacity(256), ends: Vec::with_capacity(16) }, 0, number * size);
        let (mut seen, mut last) = ([false; 4], usize::MAX);
        let string = |at: &mut usize, to: &mut Vec<u8>| -> Result<(), u32> {
            let huff = block.get(*at).ok_or(if *at < length { AGAIN } else { FRAME_SIZE_ERROR })? & 0x80 != 0;
            let len = integer(block, at, 7, length)?;
            if len > size { return Err(ENHANCE_YOUR_CALM) }
            if *at + len > length { return Err(FRAME_SIZE_ERROR) }
            let raw = block.get(*at..*at + len).ok_or(AGAIN)?;
            *at += len;
            if !huff { to.extend_from_slice(raw); } else if !unhuffman(raw, to) { return Err(COMPRESSION_ERROR) }
            Ok(())
        };
        while at < block.len() {
            let (bits, add) = match block[at] { 0x80.. => (7, false), 0x40.. => (6, true), 0x20.. => (5, false), _ => (4, false) };
            let index = integer(block, &mut at, bits, length)?;
            if bits == 5 {
                if index > self.limit { return Err(COMPRESSION_ERROR) }
                (self.size, _) = (index, self.evict(index));
                continue;
            }
            let (to, start) = (&mut fields.bytes, fields.ends.last().map_or(0, |e| e.1));
            let skip = dropped.as_deref() == Some(&true) && !add;
            if index == 0 && bits != 7 {
                string(&mut at, to)?;
                if skip && last == 0 { return Err(PROTOCOL_ERROR) }
                last = if skip { last } else { to.len() - start };
            } else { to.extend_from_slice(self.field(index).ok_or(COMPRESSION_ERROR)?.0); }
            let name = to.len();
            if bits == 7 { to.extend_from_slice(self.field(index).ok_or(COMPRESSION_ERROR)?.1); } else {
                if name == start { return Err(PROTOCOL_ERROR) }
                string(&mut at, to)?;
                last = if skip { last } else { to.len() - name };
            }
            left = left.checked_sub(to.len() - start).ok_or(ENHANCE_YOUR_CALM)?;
            if add { self.add(&to[start..name], &to[name..]); }
            if let Some(d) = dropped.as_deref_mut().filter(|d| !**d) { *d = drops(&to[start..name], &to[name..], &mut seen); }
            fields.ends.push((name, to.len()));
        }
        Ok(fields)
    }
}

fn drops(name: &[u8], value: &[u8], seen: &mut [bool; 4]) -> bool {
    let Some(own) = name.strip_prefix(b":") else { return refused(name, value) };
    let Some(i) = [&b"method"[..], b"scheme", b"path", b"authority"].iter().position(|p| *p == own) else { return true };
    refused(name, value) || std::mem::replace(&mut seen[i], true) || value.is_empty()
}

fn refused(name: &[u8], value: &[u8]) -> bool {
    name.strip_prefix(b":").unwrap_or(name).iter().any(|&c| c <= 0x20 || c == 0x7f || c == b':' || c.is_ascii_uppercase()) || value.iter().any(|c| matches!(c, 0 | b'\n' | b'\r'))
}

fn status(fields: &[(Vec<u8>, Vec<u8>)]) -> Option<u16> {
    let mut status = None;
    for (name, value) in fields {
        if refused(name, value) { return None }
        match (&name[..], status) {
            (b":status", None) if value.len() == 3 && value.iter().all(u8::is_ascii_digit) => status = std::str::from_utf8(value).ok()?.parse().ok().filter(|s| *s == 103 || *s >= 200),
            (b"content-length" | b"transfer-encoding", Some(200..)) if value.contains(&b' ') => return None,
            _ if name.starts_with(b":") => return None,
            _ => {}
        }
        status?;
    }
    status
}

fn request<'a>(fields: impl Iterator<Item = (&'a [u8], &'a [u8])>, end: bool) -> Option<(Vec<u8>, bool, usize)> {
    let mut pseudo: [Option<&[u8]>; 4] = [None; 4];
    let (mut lines, mut cookies, mut host, mut length) = (Vec::new(), Vec::new(), None, None);
    for (name, value) in fields {
        if refused(name, value) { return None }
        if let Some(own) = name.strip_prefix(b":") {
            let i = [&b"method"[..], b"scheme", b"path", b"authority"].iter().position(|p| *p == own)?;
            if pseudo[i].replace(value).is_some() || value.is_empty() { return None }
            continue;
        }
        match name { b"cookie" => { cookies.push(value); continue } b"host" => host = Some(value), b"content-length" => length = Some(value), _ => {} }
        lines.push((name, value));
    }
    let [Some(method), Some(scheme), Some(path), authority] = pseudo else { return None };
    if !method.iter().all(|&c| c.is_ascii_uppercase() || c == b'_' || c == b'-') { return None }
    let scheme_char = |(i, &c): (usize, &u8)| c.is_ascii_alphabetic() || i > 0 && (c.is_ascii_digit() || b"+-.".contains(&c));
    let valid = scheme.iter().enumerate().all(scheme_char) && path.iter().all(|&c| c > 0x20 && c != 0x7f);
    let missing = end && length.and_then(|l| std::str::from_utf8(l).ok()?.parse::<u64>().ok()).is_some_and(|n| n > 0);
    if !valid || missing || host.or(authority).is_none() || authority.zip(host).is_some_and(|(a, h)| a != h) { return None }
    let mut head = Vec::with_capacity(512);
    let mut write = |parts: &[&[u8]]| parts.iter().for_each(|part| head.extend_from_slice(part));
    write(&[method, b" ", path, b" HTTP/2.0\r\n"]);
    lines.iter().for_each(|(n, v)| write(&[n, b": ", v, b"\r\n"]));
    if !cookies.is_empty() { write(&[b"cookie: ", &cookies.join(&b"; "[..]), b"\r\n"]); }
    if let (Some(a), None) = (authority, host) { write(&[b"host: ", a, b"\r\n"]); }
    Some((head, length.is_some(), usize::from(!cookies.is_empty()) + usize::from(host.is_none())))
}

fn answer_head(head: &[u8]) -> Option<(u16, Vec<(&[u8], &[u8])>)> {
    let mut lines = head.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status = std::str::from_utf8(lines.next()?.split(|&c| c == b' ').nth(1)?).ok()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        let at = line.iter().position(|&c| c == b':')?;
        let (name, value) = (&line[..at], line[at + 1..].trim_ascii());
        if !["connection", "keep-alive", "transfer-encoding"].iter().any(|h| name.eq_ignore_ascii_case(h.as_bytes())) { headers.push((name, value)); }
    }
    Some((status, headers))
}

fn header_block(status: u16, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    match [200, 204, 206, 304, 400, 404, 500].iter().position(|&s| s == status) {
        Some(i) => out.push(0x88 + i as u8),
        None => out.extend(format!("\x48\x03{status:03}").bytes()),
    }
    const OWN: [(&str, u8); 6] = [("server", 54), ("date", 33), ("content-type", 31), ("content-length", 28), ("last-modified", 44), ("location", 46)];
    let mut placed = Vec::new();
    for (name, index) in OWN {
        let Some(i) = headers.iter().position(|h| h.0.eq_ignore_ascii_case(name.as_bytes())) else { continue };
        out.push(0x40 | index);
        if index == 28 { write_integer(&mut out, 0, 7, headers[i].1.len()); out.extend_from_slice(headers[i].1); } else { write_string(&mut out, headers[i].1, false); }
        placed.push(i);
    }
    literals(&mut out, headers.iter().enumerate().filter(|(i, _)| !placed.contains(i)).map(|(_, h)| h));
    out
}

fn literals<'a, T: AsRef<[u8]> + 'a>(out: &mut Vec<u8>, fields: impl Iterator<Item = &'a (T, T)>) {
    for (name, value) in fields {
        out.push(0);
        write_string(out, name.as_ref(), true);
        write_string(out, value.as_ref(), false);
    }
}

fn header_frames(out: &mut Vec<u8>, sid: u32, block: &[u8], frame_size: usize, end: bool) {
    let mut parts = block.chunks(frame_size).peekable();
    let mut kind = HEADERS;
    while let Some(part) = parts.next() {
        let flags = if parts.peek().is_none() { END_HEADERS } else { 0 } | if kind == HEADERS && end { END_STREAM } else { 0 };
        frame(out, kind, flags, sid, part);
        kind = CONTINUATION;
    }
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, sid: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(payload);
}

#[derive(Default)]
struct Open {
    send: i64, recv: i64, head: Option<(Vec<u8>, bool, usize)>, ended: bool, reading: Option<Reading>,
    body: Option<UnboundedSender<Vec<u8>>>, taker: Option<UnboundedReceiver<Vec<u8>>>,
    declared: Option<u64>, got: u64, chunked: bool, bad: bool,
    answer: Option<Vec<u8>>, sent: usize, end: Option<Ended>, closed: bool, taken: Option<watch::Sender<usize>>, untold: usize,
    number: u64, exchange: u32, block: usize,
    early: Option<bool>,
    at_once: bool,
}

struct Connection {
    out: Vec<u8>,
    streams: BTreeMap<u32, Open>,
    ready: Vec<u32>,
    bad: Vec<u32>,
    block: Option<(u32, u8, Vec<u8>, bool)>,
    last_sid: u32,
    table: Table,
    nodes: HashMap<u32, (u32, u16)>,
    limits: (usize, usize),
    send: i64,
    window: i64,
    frame_size: usize,
    recv: i64,
    table_update: bool,
    started: Instant,
    requests: u64,
    goaway: bool,
    keepalive: (u64, Duration, Duration),
    priorities: usize,
    refused: usize,
}

impl Connection {
    fn depend(&mut self, sid: u32, on: u32, weight: u16) {
        let (exclusive, on) = (on >> 31 == 1, on & 0x7fff_ffff);
        let parent = if self.nodes.contains_key(&on) { on } else { 0 };
        let exclusive = exclusive && (parent != 0 || on == 0);
        if let Some(&(was, _)) = self.nodes.get(&sid).filter(|_| self.ancestors(parent).contains(&sid)) { self.nodes.entry(parent).and_modify(|n| n.0 = was); }
        if exclusive { self.nodes.values_mut().filter(|n| n.0 == parent).for_each(|n| n.0 = sid); }
        self.nodes.insert(sid, (parent, weight));
    }

    fn ancestors(&self, mut sid: u32) -> Vec<u32> {
        let mut list = Vec::new();
        while let Some(&(parent, _)) = self.nodes.get(&sid).filter(|_| sid != 0 && list.len() <= self.nodes.len()) { list.push(parent); sid = parent; }
        list
    }

    fn rank(&self, sid: u32) -> (usize, f64) {
        let path = [&[sid][..], &self.ancestors(sid)].concat();
        let share = path.iter().filter_map(|s| self.nodes.get(s)).map(|n| f64::from(n.1) / 256.0).product::<f64>();
        (path.len() - 1, -share)
    }

    fn goaway(&mut self) {
        frame(&mut self.out, GOAWAY, 0, 0, &[self.last_sid.to_be_bytes(), NO_ERROR.to_be_bytes()].concat());
        self.goaway = true;
    }

    fn rst(&mut self, sid: u32, code: u32) {
        frame(&mut self.out, RST_STREAM, 0, sid, &code.to_be_bytes());
        self.streams.remove(&sid);
    }

    fn read(&mut self, buf: &mut Vec<u8>) -> Result<(), u32> {
        let mut at = 0;
        let read = loop {
            let Some(head) = buf.get(at..at + 9) else { break Ok(()) };
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let sid = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            let Some(payload) = buf.get(at + 9..at + 9 + len) else { break self.early([head[3], head[4]], sid, &buf[at + 9..], len) };
            if let Err(code) = self.frame(head[3], head[4], sid, payload) { break Err(code) }
            at += 9 + len;
        };
        buf.drain(..at);
        read
    }

    fn early(&mut self, [kind, flags]: [u8; 2], sid: u32, p: &[u8], len: usize) -> Result<(), u32> {
        let skip = usize::from(flags & PADDED != 0) + if flags & PRIORITY_FLAG != 0 { 5 } else { 0 };
        if kind != HEADERS || self.block.is_some() || p.len() <= skip { return Ok(()) }
        let length = len.saturating_sub(skip + if flags & PADDED != 0 { usize::from(p[0]) } else { 0 });
        let whole = if flags & END_HEADERS != 0 { length } else { usize::MAX };
        match self.table.clone().block(&p[skip..p.len().min(skip + length)], whole, self.limits, Some(&mut false)) {
            Err(code) if code != AGAIN => { self.last_sid = sid; Err(code) }
            _ => Ok(()),
        }
    }

    fn frame(&mut self, kind: u8, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        if self.block.as_ref().is_some_and(|b| kind != CONTINUATION || b.0 != sid) { return Err(PROTOCOL_ERROR) }
        if self.block.is_some() { return self.header_block(flags, p) }
        let size = match kind { PRIORITY => p.len() == 5, RST_STREAM | WINDOW_UPDATE => p.len() == 4, PING => p.len() == 8, GOAWAY => p.len() >= 8, _ => true };
        if !size { return Err(FRAME_SIZE_ERROR) }
        let stray = matches!(kind, PRIORITY | RST_STREAM) && sid == 0 || matches!(kind, PING | GOAWAY) && sid != 0 || matches!(kind, PUSH_PROMISE | CONTINUATION);
        let word = |at: usize| u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
        if stray || kind == PRIORITY && word(0) & 0x7fff_ffff == sid { return Err(PROTOCOL_ERROR) }
        match kind {
            DATA => self.data(flags, sid, p),
            HEADERS => self.headers(flags, sid, p),
            PRIORITY => {
                self.priorities -= 1;
                if self.priorities == 0 { return Err(ENHANCE_YOUR_CALM) }
                self.depend(sid, word(0), u16::from(p[4]) + 1);
                Ok(())
            }
            SETTINGS => self.settings(flags, sid, p),
            WINDOW_UPDATE => self.window_update(sid, i64::from(word(0) & 0x7fff_ffff)),
            _ => {
                if kind == RST_STREAM { self.streams.remove(&sid); }
                if kind == PING && flags & ACK == 0 { frame(&mut self.out, PING, ACK, 0, p); }
                Ok(())
            }
        }
    }

    fn header_block(&mut self, flags: u8, p: &[u8]) -> Result<(), u32> {
        let Some((_, first, block, _)) = &mut self.block else { return Ok(()) };
        *first |= flags;
        block.extend_from_slice(p);
        if flags & END_HEADERS != 0 { self.headers_done() } else { Ok(()) }
    }

    fn headers(&mut self, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        let (pad, priority) = (usize::from(flags & PADDED != 0), if flags & PRIORITY_FLAG != 0 { 5 } else { 0 });
        if p.len() <= pad + priority { return Err(FRAME_SIZE_ERROR) }
        if self.goaway { return Ok(()) }
        let padding = if pad == 1 { usize::from(p[0]) } else { 0 };
        if padding > p.len() - pad - priority { return Err(PROTOCOL_ERROR) }
        let depends = (priority > 0).then(|| (u32::from_be_bytes([p[pad], p[pad + 1], p[pad + 2], p[pad + 3]]), u16::from(p[pad + 4]) + 1));
        if sid % 2 == 0 || sid <= self.last_sid || depends.is_some_and(|d| d.0 & 0x7fff_ffff == sid) { return Err(PROTOCOL_ERROR) }
        self.last_sid = sid;
        if depends.is_some() || !self.nodes.contains_key(&sid) { let (on, weight) = depends.unwrap_or((0, 16)); self.depend(sid, on, weight); }
        let refused = self.streams.len() >= CONCURRENT;
        self.refused += usize::from(refused);
        if self.refused > CONCURRENT + 1 { return Err(NO_ERROR) }
        self.requests += u64::from(!refused);
        if !refused { self.priorities += CONCURRENT; }
        let (requests, timeout, time) = self.keepalive;
        if !refused && (timeout.is_zero() || self.requests >= requests || self.started.elapsed() > time) { self.goaway(); }
        self.block = Some((sid, flags, Vec::new(), refused));
        self.header_block(flags, &p[pad + priority..p.len() - padding])
    }

    fn headers_done(&mut self) -> Result<(), u32> {
        let Some((sid, flags, block, refused)) = self.block.take() else { return Ok(()) };
        let mut dropped = false;
        let fields = self.table.block(&block, block.len(), self.limits, Some(&mut dropped));
        let (fields, error) = match fields { Err(code) if dropped && !refused => (Block::default(), Some(code)), fields => (fields?, None) };
        if refused { self.rst(sid, REFUSED_STREAM); return Ok(()) }
        let ended = flags & END_STREAM != 0;
        let head = request(fields.fields(), ended);
        let declared = fields.fields().find(|f| f.0 == b"content-length").and_then(|f| std::str::from_utf8(f.1).ok()?.parse().ok());
        let chunked = head.as_ref().is_some_and(|h| !h.1) && !ended;
        let (body, taker) = (!ended).then(tokio::sync::mpsc::unbounded_channel).unzip();
        self.streams.insert(sid, Open { send: self.window, recv: PREREAD, at_once: head.is_none(), head, ended, body, taker, declared, chunked, number: self.requests, block: block.len(), ..Open::default() });
        self.ready.push(sid);
        error.map_or(Ok(()), Err)
    }

    fn data(&mut self, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        let size = p.len() as i64;
        let padding = if flags & PADDED != 0 { usize::from(*p.first().ok_or(FRAME_SIZE_ERROR)?) + 1 } else { 0 };
        if padding > p.len() || sid == 0 { return Err(PROTOCOL_ERROR) }
        if size > self.recv { return Err(FLOW_CONTROL_ERROR) }
        self.recv -= size;
        if self.recv < MAX_WINDOW / 4 { frame(&mut self.out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - self.recv) as u32).to_be_bytes()); self.recv = MAX_WINDOW; }
        let Some(s) = self.streams.get_mut(&sid) else { return Ok(()) };
        if size > s.recv { self.rst(sid, FLOW_CONTROL_ERROR); return Ok(()) }
        if s.ended && s.early.is_some() { s.early = Some(true); return Ok(()) }
        if s.ended { self.rst(sid, STREAM_CLOSED); return Ok(()) }
        let data = &p[usize::from(padding > 0)..p.len() - padding.saturating_sub(1)];
        (s.ended, s.got) = (flags & END_STREAM != 0, s.got + data.len() as u64);
        if s.ended && s.reading.is_none() { s.early = Some(false); }
        if !s.bad && s.reading != Some(Reading::Discarded) && s.declared.is_some_and(|n| s.got > n || s.ended && s.got < n) { (s.bad, s.body, s.exchange) = (true, None, s.exchange + 1); self.bad.push(sid); }
        let mut part = if s.chunked && !data.is_empty() { [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat() } else { data.to_vec() };
        if s.chunked && s.ended { part.extend_from_slice(b"0\r\n\r\n"); }
        if let Some(body) = &s.body { let _ = body.send(part); }
        if s.ended { s.body = None; return Ok(()) }
        match s.reading {
            Some(Reading::Buffered) => {
                s.recv -= size;
                if s.recv < MAX_WINDOW / 4 { frame(&mut self.out, WINDOW_UPDATE, 0, sid, &((MAX_WINDOW - s.recv) as u32).to_be_bytes()); s.recv = MAX_WINDOW; }
            }
            Some(Reading::Unbuffered) if size > 0 => frame(&mut self.out, WINDOW_UPDATE, 0, sid, &(size as u32).to_be_bytes()),
            None => s.recv -= size,
            _ => {}
        }
        Ok(())
    }

    fn reading(&mut self, sid: u32, reading: Reading) {
        let Some(s) = self.streams.get_mut(&sid) else { return };
        s.reading = Some(reading);
        match s.early.take() { Some(_) if reading == Reading::Discarded => s.ended = false, Some(true) => return self.rst(sid, STREAM_CLOSED), _ => {} }
        let to = match reading { Reading::Buffered => MAX_WINDOW, Reading::Unbuffered => PREREAD, Reading::Discarded => return };
        if !s.ended && s.recv < to { frame(&mut self.out, WINDOW_UPDATE, 0, sid, &((to - s.recv) as u32).to_be_bytes()); s.recv = to; }
    }

    fn settings(&mut self, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        if sid != 0 { return Err(PROTOCOL_ERROR) }
        if flags == ACK { return if p.is_empty() { Ok(()) } else { Err(FRAME_SIZE_ERROR) } }
        if p.len() % 6 != 0 { return Err(FRAME_SIZE_ERROR) }
        let mut delta = 0;
        for s in p.chunks(6) {
            let (id, value) = (u16::from_be_bytes([s[0], s[1]]), u32::from_be_bytes([s[2], s[3], s[4], s[5]]));
            if id == 2 && value > 1 || id == 5 && !(1 << 14..1 << 24).contains(&value) { return Err(PROTOCOL_ERROR) }
            if id == 4 && i64::from(value) > MAX_WINDOW { return Err(FLOW_CONTROL_ERROR) }
            self.table_update |= id == 1;
            if id == 4 { delta = i64::from(value) - self.window; }
            if id == 5 { self.frame_size = value as usize; }
        }
        frame(&mut self.out, SETTINGS, ACK, 0, &[]);
        self.window += delta;
        self.streams.values_mut().for_each(|s| s.send += delta);
        Ok(())
    }

    fn window_update(&mut self, sid: u32, window: i64) -> Result<(), u32> {
        if window == 0 { return Err(PROTOCOL_ERROR) }
        if sid == 0 {
            if window > MAX_WINDOW - self.send { return Err(FLOW_CONTROL_ERROR) }
            self.send += window;
            return Ok(());
        }
        let Some(s) = self.streams.get_mut(&sid) else { return Ok(()) };
        if window > MAX_WINDOW - s.send { self.rst(sid, FLOW_CONTROL_ERROR); return Ok(()) }
        s.send += window;
        Ok(())
    }

    fn answer(&mut self, sid: u32, part: Part) {
        let Some(s) = self.streams.get_mut(&sid) else { return };
        if let Some((mut block, chunked)) = part.head {
            if std::mem::take(&mut self.table_update) { block.insert(0, 0x20); }
            s.closed = !chunked && part.data.is_empty() && part.ended == Some(Ended::Whole(Vec::new()));
            header_frames(&mut self.out, sid, &block, self.frame_size, s.closed);
            s.answer = Some(Vec::new());
        }
        let Some(body) = &mut s.answer else { return self.rst(sid, INTERNAL_ERROR) };
        if body.is_empty() { *body = part.data; } else {
            body.drain(..std::mem::take(&mut s.sent));
            body.extend_from_slice(&part.data);
        }
        s.end = part.ended;
    }

    fn told(&mut self, (sid, number, told): (u32, u32, Told)) {
        if self.streams.get(&sid).is_none_or(|s| s.exchange != number) { return }
        match told { Told::Reading(r) => self.reading(sid, r), Told::Answer(part) => { self.answer(sid, part); self.send(sid); } }
    }

    fn send_data(&mut self) {
        let waits = |s: &Open| s.answer.as_ref().is_some_and(|body| s.sent < body.len() || s.end.is_some());
        let mut order: Vec<_> = self.streams.iter().filter(|(_, s)| waits(s)).map(|(&sid, _)| (self.rank(sid), sid)).collect();
        order.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        order.into_iter().for_each(|(_, sid)| self.send(sid));
    }

    fn send(&mut self, sid: u32) {
        let Some(s) = self.streams.get_mut(&sid) else { return };
        let Some(body) = &mut s.answer else { return };
        while s.sent < body.len() {
            let n = (body.len() - s.sent).min(self.frame_size).min(s.send.min(self.send).max(0) as usize);
            if n == 0 { break }
            s.closed = s.sent + n == body.len() && s.end == Some(Ended::Whole(Vec::new()));
            frame(&mut self.out, DATA, if s.closed { END_STREAM } else { 0 }, sid, &body[s.sent..s.sent + n]);
            (s.sent, s.send, self.send, s.untold) = (s.sent + n, s.send - n as i64, self.send - n as i64, s.untold + n);
        }
        let held = s.untold > 0 && s.untold + body.len() - s.sent >= WAITING;
        if let Some(taken) = s.taken.as_ref().filter(|_| held) { taken.send_modify(|t| *t += std::mem::take(&mut s.untold)); }
        if s.sent < body.len() { return }
        (*body, s.sent) = (Vec::new(), 0);
        match s.end.take() {
            Some(Ended::Cut) => return self.rst(sid, INTERNAL_ERROR),
            Some(Ended::Whole(trailers)) if !s.closed => {
                let mut block = Vec::new();
                literals(&mut block, trailers.iter());
                if block.is_empty() { frame(&mut self.out, DATA, END_STREAM, sid, &[]); } else { header_frames(&mut self.out, sid, &block, self.frame_size, true); }
                s.closed = true;
            }
            _ => {}
        }
        if !s.closed { return }
        if !s.ended { frame(&mut self.out, RST_STREAM, 0, sid, &NO_ERROR.to_be_bytes()); }
        self.streams.remove(&sid);
    }
}

pub async fn serve(config: Arc<Config>, mut stream: Stream, mut buf: Vec<u8>, addrs: Addrs, _busy: Option<Busy>) {
    let level = &crate::http::default_server(&config, addrs.0).level;
    let (limits, keepalive) = (level.large_header_buffers, (level.keepalive_requests, level.keepalive_timeout, level.keepalive_time));
    let lingers = level.lingering_close.is_some();
    let send = crate::http::send_timeout(level);
    let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
    let mut c = Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits, send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive, priorities: CONCURRENT.max(100), refused: 0 };
    frame(&mut c.out, SETTINGS, 0, 0, &[0, 3, 0, 0, 0, CONCURRENT as u8, 0, 4, 0, 1, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff]);
    frame(&mut c.out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (mut preface, mut failed) = (false, None);
    if let Some(tcp) = stream.tcp().filter(|_| level.tcp_nodelay) { let _ = tcp.set_nodelay(true); }
    loop {
        if crate::http::shutting() && !c.goaway { c.goaway(); }
        let read = if failed.is_some() { Ok(()) } else if preface { c.read(&mut buf) } else if buf.len() < PREFACE.len() { Ok(()) } else if buf.starts_with(PREFACE) { preface = true; buf.drain(..PREFACE.len()); c.read(&mut buf) } else { Err(PROTOCOL_ERROR) };
        let (bad, answered): (Vec<u32>, Vec<u32>) = std::mem::take(&mut c.bad).into_iter().partition(|sid| c.streams.get(sid).is_none_or(|s| s.answer.is_none()));
        answered.into_iter().for_each(|sid| c.rst(sid, INTERNAL_ERROR));
        let bad = bad.into_iter().map(|sid| (sid, true));
        for (sid, bad) in std::mem::take(&mut c.ready).into_iter().map(|sid| (sid, false)).chain(bad) {
            let Some(s) = c.streams.get_mut(&sid) else { continue };
            if s.bad && !bad { continue }
            let (request, made, taker) = match s.head.take().filter(|_| !bad) {
                Some((mut head, _, made)) => {
                    if s.chunked { head.extend_from_slice(b"transfer-encoding: chunked\r\n"); }
                    head.extend_from_slice(b"\r\n");
                    (head, made + usize::from(s.chunked), s.taker.take())
                }
                None => (b"-\r\n\r\n".to_vec(), 0, None),
            };
            let (tx, config, addrs, number) = (tx.clone(), config.clone(), addrs.clone(), s.exchange);
            let told = tx.clone();
            let origin = Origin { connected: c.started, number: s.number, made, length: s.block, reading: Some(Box::new(move |r| { let _ = told.send((sid, number, Told::Reading(r))); })) };
            let (taken, sent) = watch::channel(0);
            s.taken = Some(taken);
            let tell = move |part| { let _ = tx.send((sid, number, Told::Answer(part))); };
            tokio::task::spawn_local(exchange(config, request, taker, addrs, origin, tell, sent));
        }
        c.send_data();
        failed = failed.or(read.err());
        if let Some(code) = failed.filter(|_| !c.streams.values().any(|s| s.at_once)) {
            frame(&mut c.out, GOAWAY, 0, 0, &[c.last_sid.to_be_bytes(), code.to_be_bytes()].concat());
            let _ = stream.write_all(&c.out).await;
            let _ = stream.shutdown().await;
            return;
        }
        let out = std::mem::take(&mut c.out);
        if !out.is_empty() && !write_all(&mut stream, &out, send).await { return }
        recycle(out);
        if c.goaway && c.streams.is_empty() { return crate::http::close(&mut stream, lingers).await }
        tokio::select! {
            n = stream.read_buf(&mut buf), if failed.is_none() => if n.unwrap_or(0) == 0 { return },
            Some(told) = rx.recv() => {
                c.out = buffer();
                c.told(told);
                // Up to the size of a TLS record.
                while c.out.len() < 16384 && let Ok(told) = rx.try_recv() { c.told(told); }
            }
            () = crate::http::SHUTDOWN.notified() => {}
            () = tokio::time::sleep(if c.requests == 0 { HEADER_TIMEOUT.saturating_sub(c.started.elapsed()) } else { c.keepalive.1 }), if c.streams.is_empty() && c.block.is_none() && !c.keepalive.1.is_zero() => c.goaway(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum End { Whole, #[default] Closed, Failed }

#[derive(Debug, Default)]
pub struct Ending { pub end: End, pub trailers: Vec<(String, String)>, pub bodiless: bool, conn: Option<Conn>, home: Option<Home>, pub sent: bool, pub moved: Option<std::time::Instant> }

type Home = (Arc<Upstream>, crate::upstream::Addr, usize, Option<Duration>);

pub fn give_back(slot: &Slot, home: Home) {
    let mut ending = slot.lock().unwrap();
    match ending.conn.take() {
        Some(conn) => home.0.put(conn, home.1, home.2),
        None => ending.home = Some(home),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Session { id: u32, window: i64, initial: i64, recv: i64, skipped: u64 }

impl Default for Session {
    fn default() -> Session {
        Session { id: 1, window: 65535, initial: 65535, recv: MAX_WINDOW, skipped: 0 }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Framing { pub authority: bool, pub chunked: bool, pub length: u64 }

pub type Slot = Arc<std::sync::Mutex<Ending>>;

pub async fn upstream(mut conn: Conn, mut pipe: tokio::io::DuplexStream, scheme: &str, head_size: usize, slot: Slot, framing: Framing) {
    let kept = conn.h2.take();
    let (up, mut out) = (&mut conn.stream, if kept.is_none() { PREFACE.to_vec() } else { Vec::new() });
    let Session { id, mut window, mut initial, mut recv, mut skipped } = kept.as_deref().copied().unwrap_or_default();
    let (mut buf, mut got) = (Vec::new(), Vec::new());
    let end = loop {
        if let Some(n) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break n }
        if pipe.read_buf(&mut buf).await.unwrap_or(0) == 0 { return }
    };
    // The head is bytes: what is not UTF-8 in a header goes as it came.
    let head = &buf[..end];
    let mut lines = head.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let mut line = lines.next().unwrap_or_default().split(|&c| c == b' ');
    let (method, path) = (std::str::from_utf8(line.next().unwrap_or_default()).unwrap_or_default(), line.next().unwrap_or_default());
    let mut fields = Vec::with_capacity(3 + head.iter().filter(|&&c| c == b'\n').count());
    fields.extend([(&b":method"[..], method.as_bytes()), (&b":scheme"[..], scheme.as_bytes()), (&b":path"[..], path)]);
    let mut body = if framing.chunked { Body::Chunked(0, false) } else { Body::Length(framing.length) };
    for (name, value) in lines.filter_map(|l| l.iter().position(|&c| c == b':').map(|at| (&l[..at], l[at + 1..].trim_ascii()))) {
        if framing.authority && name.eq_ignore_ascii_case(b"host") { fields.insert(2, (b":authority", value)) } else { fields.push((name, value)) }
    }
    let mut block = Vec::with_capacity(end + 64);
    literals(&mut block, fields.iter());
    let head_method = method == "HEAD";
    buf.drain(..end + 4);
    if kept.is_none() {
        frame(&mut out, SETTINGS, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0x7f, 0xff, 0xff, 0xff]);
        frame(&mut out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    }
    let mut ended = body == Body::Length(0);
    header_frames(&mut out, id, &block, 16384, ended);
    let (mut stream_window, mut stream_recv, mut pending, mut finished) = (initial, MAX_WINDOW, Vec::new(), ended);
    let mut data_sent = 0;
    let (mut table, mut answer) = (Table { entries: VecDeque::new(), size: 0, used: 0, limit: 0 }, None::<(u8, Vec<u8>)>);
    let (mut headed, mut size, mut deaf) = (false, 0, false);
    let (mut no_body, mut bodiless, mut keep, mut rest) = (head_method, false, true, None);
    let mut left = None::<u64>;
    loop {
        if finished { buf.clear(); }
        finished |= body.take(&mut buf, &mut pending);
        let can = pending.len().min(window.min(stream_window).max(0) as usize);
        out.reserve(can + can.div_ceil(16384) * 9);
        let mut at = 0;
        loop {
            let n = (pending.len() - at).min(16384).min(window.min(stream_window).max(0) as usize);
            let last = finished && at + n == pending.len();
            if ended || n == 0 && !last { break }
            ended = last;
            frame(&mut out, DATA, if ended { END_STREAM } else { 0 }, id, &pending[at..at + n]);
            (at, window, stream_window, data_sent) = (at + n, window - n as i64, stream_window - n as i64, data_sent + 9 + n as u64);
        }
        pending.drain(..at);
        if ended { slot.lock().unwrap().sent = true; }
        let (frames, had) = (std::mem::take(&mut out), buf.len());
        if !frames.is_empty() && !deaf {
            tokio::select! {
                sent = within(rest.flatten(), up.write_all(&frames)) => { deaf = !matches!(sent, Some(Ok(()))); slot.lock().unwrap().moved = Some(std::time::Instant::now()); }
                () = unwanted(&mut pipe, &mut buf), if rest.is_none() => return,
            }
            if buf.len() > had { continue }
        }
        got.reserve(4096);
        tokio::select! {
            n = pipe.read_buf(&mut buf), if rest.is_none() => if n.unwrap_or(0) == 0 {
                rest = slot.lock().unwrap().home.as_ref().map(|h| h.3);
                if rest.is_none() || !keep || !ended { return }
            },
            n = within(rest.flatten(), up.read_buf(&mut got)) => if n.and_then(Result::ok).unwrap_or(0) == 0 {
                if let Some(&[a, b, c, DATA, flags, ..]) = got.get(..9).filter(|f| headed && f[5..] == id.to_be_bytes()) {
                    let (p, padded) = (&got[9..], usize::from(flags & PADDED != 0));
                    let padding = if padded == 1 { p.first().copied().unwrap_or(0) } else { 0 };
                    let end = (u32::from_be_bytes([0, a, b, c]) as usize).saturating_sub(padding.into());
                    let _ = pipe.write_all(p.get(padded..end.min(p.len())).unwrap_or_default()).await;
                }
                return
            },
        }
        // What a read gives is passed once all its frames are taken, so what fails the stream drops the data that came with it.
        let (mut to_pipe, mut head_end, mut done, mut reset, mut failed) = (Vec::new(), 0, false, false, false);
        while got.len() >= 9 {
            let (len, kind, flags, sid) = (u32::from_be_bytes([0, got[0], got[1], got[2]]) as usize, got[3], got[4], u32::from_be_bytes([got[5], got[6], got[7], got[8]]) & 0x7fff_ffff);
            let block = sid == id && matches!(kind, HEADERS | CONTINUATION) && !headed;
            let misplaced = if sid == 0 { matches!(kind, DATA | HEADERS | CONTINUATION | RST_STREAM) } else { matches!(kind, SETTINGS | PING | GOAWAY) };
            failed = wrong_length(kind, flags, len) || block && size + 9 + len > head_size || sid == id && (kind == DATA && !headed || done && !matches!(kind, RST_STREAM | WINDOW_UPDATE)) || sid != id && sid != 0 && !(sid < id && matches!(kind, RST_STREAM | WINDOW_UPDATE)) || misplaced || kind == PUSH_PROMISE || kind == DATA && len as i64 > recv.min(stream_recv) || answer.is_some() != (kind == CONTINUATION);
            if failed || got.len() < 9 + len { break }
            if block { size += 9 + len; }
            let p: Vec<u8> = got.drain(..9 + len).skip(9).collect();
            let word = |at: usize| u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
            match kind {
                SETTINGS if flags & ACK == 0 => {
                    for s in p.chunks_exact(6).filter(|s| s[..2] == [0, 4]) {
                        let value = i64::from(u32::from_be_bytes([s[2], s[3], s[4], s[5]]));
                        (stream_window, initial) = (stream_window + value - initial, value);
                        failed |= value > MAX_WINDOW || stream_window > MAX_WINDOW;
                    }
                    frame(&mut out, SETTINGS, ACK, 0, &[]);
                }
                PING if flags & ACK == 0 => frame(&mut out, PING, ACK, 0, &p),
                PING => failed = true,
                WINDOW_UPDATE if sid == 0 || sid == id => {
                    let of = if sid == 0 { &mut window } else { &mut stream_window };
                    *of += i64::from(word(0) & 0x7fff_ffff);
                    failed = *of > MAX_WINDOW;
                }
                HEADERS | CONTINUATION if sid == id => {
                    let (first, mut so_far) = answer.take().unwrap_or((flags, Vec::new()));
                    let Some(part) = unpadded(kind, flags, &p) else { failed = true; break };
                    so_far.extend_from_slice(part);
                    if flags & END_HEADERS == 0 { answer = Some((first, so_far)); continue }
                    let Ok(fields) = table.decode(&so_far, so_far.len(), (1000, 1 << 20)) else { failed = true; break };
                    done |= first & END_STREAM != 0;
                    if headed {
                        failed = !done || fields.iter().any(|(n, v)| n.starts_with(b":") || refused(n, v));
                        if failed { break }
                        slot.lock().unwrap().trailers.extend(fields.iter().map(|(n, v)| (crate::vars::text(n), crate::vars::text(v))));
                    } else {
                        let Some(status) = status(&fields).filter(|s| *s != 103 || !done) else { failed = true; break };
                        (headed, size) = (status != 103, 0);
                        let length = fields.iter().find(|f| f.0 == b"content-length" && !head_method && ![103, 204, 304].contains(&status));
                        left = length.and_then(|f| std::str::from_utf8(&f.1).ok()?.parse().ok());
                        no_body |= matches!(status, 204 | 304);
                        if headed && no_body && !(done && got.is_empty()) { keep = false; }
                        (bodiless, slot.lock().unwrap().bodiless) = (headed && done, headed && done);
                        let headers = fields.iter().filter(|f| !f.0.starts_with(b":"));
                        to_pipe.reserve(17 + headers.clone().map(|(n, v)| n.len() + v.len() + 4).sum::<usize>());
                        let _ = std::io::Write::write_fmt(&mut to_pipe, format_args!("HTTP/1.1 {status} \r\n"));
                        headers.for_each(|(n, v)| [&n[..], b": ", v, b"\r\n"].iter().for_each(|part| to_pipe.extend_from_slice(part)));
                        to_pipe.extend_from_slice(b"\r\n");
                        head_end = to_pipe.len();
                    }
                }
                DATA if sid == id => {
                    let Some(data) = unpadded(kind, flags, &p) else { failed = true; break };
                    if left.is_some_and(|n| n < data.len() as u64) { failed = true; break }
                    left = left.map(|n| n - data.len() as u64);
                    to_pipe.extend_from_slice(data);
                    done |= flags & END_STREAM != 0;
                    (recv, stream_recv) = (recv - len as i64, stream_recv - len as i64);
                    if recv.min(stream_recv) < MAX_WINDOW / 4 {
                        for (sid, window) in [(0, &mut recv), (id, &mut stream_recv)] {
                            frame(&mut out, WINDOW_UPDATE, 0, sid, &((MAX_WINDOW - *window) as u32).to_be_bytes());
                            *window = MAX_WINDOW;
                        }
                    }
                }
                RST_STREAM if sid == id => (failed, reset) = (word(0) != NO_ERROR || reset || !done, true),
                GOAWAY => (failed, keep) = (word(0) & 0x7fff_ffff < id, false),
                _ => {}
            }
            if failed { break }
        }
        failed |= done && left.is_some_and(|n| n > 0);
        if failed { to_pipe.truncate(head_end); }
        if failed || done { slot.lock().unwrap().end = if failed { End::Failed } else { End::Whole }; }
        if pipe.write_all(&to_pipe).await.is_err() || failed { return }
        if done {
            // An upstream that skipped what was sent on streams it reset can count that against a flood limit, and the reset can come after the answer.
            skipped += data_sent;
            ended |= reset;
            keep &= skipped < 4 << 20;
            let mut sent = async || out.is_empty() || at_once(async { up.write_all(&out).await.is_ok() && up.flush().await.is_ok() }).await == Some(true);
            if !keep || deaf || !ended || !got.is_empty() || bodiless && !out.is_empty() || !sent().await { return }
            conn.h2 = Some(Box::new(Session { id: id + 2, window, initial, recv, skipped }));
            let mut ending = slot.lock().unwrap();
            match ending.home.take() {
                Some((up, addr, tag, _)) => up.put(conn, addr, tag),
                None => ending.conn = Some(conn),
            }
            return
        }
    }
}

fn wrong_length(kind: u8, flags: u8, len: usize) -> bool {
    let padded = usize::from(flags & PADDED != 0);
    len > 16384 || match kind {
        DATA => len < padded,
        HEADERS => len < padded + if flags & PRIORITY_FLAG != 0 { 5 } else { 0 },
        RST_STREAM | WINDOW_UPDATE => len != 4,
        SETTINGS => len % 6 != 0 || flags & ACK != 0 && len != 0,
        PING => len != 8,
        GOAWAY => len < 8,
        _ => false,
    }
}

fn unpadded(kind: u8, flags: u8, p: &[u8]) -> Option<&[u8]> {
    let padded = kind != CONTINUATION && flags & PADDED != 0;
    let skip = usize::from(padded) + if kind == HEADERS && flags & PRIORITY_FLAG != 0 { 5 } else { 0 };
    let padding = if padded { usize::from(*p.first()?) } else { 0 };
    p.get(skip..p.len().checked_sub(padding)?)
}

async fn unwanted(pipe: &mut tokio::io::DuplexStream, buf: &mut Vec<u8>) {
    while buf.len() < 65536 {
        if pipe.read_buf(buf).await.unwrap_or(0) == 0 { return }
    }
    std::future::pending().await
}

#[derive(PartialEq)]
enum Body { Length(u64), Chunked(u64, bool) }

impl Body {
    fn take(&mut self, buf: &mut Vec<u8>, to: &mut Vec<u8>) -> bool {
        let mut at = 0;
        let mut data = |left: &mut u64, at: &mut usize| {
            let n = (*left).min((buf.len() - *at) as u64);
            to.extend_from_slice(&buf[*at..*at + n as usize]);
            (*left, *at) = (*left - n, *at + n as usize);
            *left == 0
        };
        let whole = loop {
            match self {
                Body::Length(left) => break data(left, &mut at),
                Body::Chunked(left, _) if *left > 0 => { if !data(left, &mut at) { break false } *self = Body::Chunked(0, true) }
                Body::Chunked(_, crlf) => {
                    let Some(n) = buf[at..].windows(2).position(|w| w == b"\r\n") else { break false };
                    let line = &buf[at..at + n];
                    at += n + 2;
                    if *crlf { *crlf = false; continue }
                    let size = std::str::from_utf8(line).ok().and_then(|l| u64::from_str_radix(l.split(';').next()?.trim(), 16).ok()).unwrap_or(0);
                    if size == 0 { break true }
                    *self = Body::Chunked(size, false);
                }
            }
        };
        buf.drain(..at);
        whole
    }
}

struct Reply { buf: Vec<u8>, bodiless: bool, comes: Option<Comes> }

enum Comes { Nothing, Body(Body), Trailers, Unframed }

impl Reply {
    fn take(&mut self, part: &mut Part, closed: bool) {
        if self.comes.is_none() {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let Some((status, mut headers)) = answer_head(&self.buf[..end]) else { return part.ended = Some(Ended::Cut) };
                headers.retain(|h| status != 204 || !h.0.eq_ignore_ascii_case(b"content-type") && !h.0.eq_ignore_ascii_case(b"content-length"));
                const CHUNKED: &[u8] = b"\r\ntransfer-encoding: chunked";
                let chunked = self.buf[..end].windows(CHUNKED.len()).any(|w| w.eq_ignore_ascii_case(CHUNKED));
                let length = headers.iter().find(|h| h.0.eq_ignore_ascii_case(b"content-length")).and_then(|h| std::str::from_utf8(h.1).ok()?.parse().ok());
                self.comes = Some(match length {
                    _ if self.bodiless || [204, 304].contains(&status) => Comes::Nothing,
                    _ if chunked => Comes::Body(Body::Chunked(0, false)),
                    Some(n) => Comes::Body(Body::Length(n)),
                    None => Comes::Unframed,
                });
                part.head = Some((header_block(status, &headers), chunked));
                self.buf.drain(..end + 4);
            }
        }
        if let Some(Comes::Body(body)) = &mut self.comes {
            if body.take(&mut self.buf, &mut part.data) { self.comes = Some(if *body == Body::Length(0) { Comes::Nothing } else { Comes::Trailers }); }
        }
        match &self.comes {
            Some(Comes::Nothing) => part.ended = Some(Ended::Whole(Vec::new())),
            Some(Comes::Trailers) => {
                let end = if self.buf.starts_with(b"\r\n") { Some(0) } else { self.buf.windows(4).position(|w| w == b"\r\n\r\n") };
                let field = |line: &[u8]| line.iter().position(|&c| c == b':').map(|at| (line[..at].to_vec(), line[at + 1..].trim_ascii().to_vec()));
                part.ended = end.map(|end| Ended::Whole(self.buf[..end].split(|&c| c == b'\n').filter_map(field).collect()));
            }
            Some(Comes::Unframed) => {
                part.data.append(&mut self.buf);
                if closed { part.ended = Some(Ended::Whole(Vec::new())); }
            }
            _ => {}
        }
        if closed && part.ended.is_none() { part.ended = Some(Ended::Cut); }
    }
}

async fn exchange(config: Arc<Config>, request: Vec<u8>, body: Option<UnboundedReceiver<Vec<u8>>>, (listen, local, peer, ssl): Addrs, origin: Origin, tell: impl Fn(Part), mut sent: watch::Receiver<usize>) {
    // Room for a 16 KB head besides the body that may wait, so an answer that waits for nothing comes whole at once.
    let ((ours, end), (reads, reader)) = (tokio::io::duplex(WAITING + 16384), watch::channel(()));
    let theirs = Stream::Pipe(Pipe { end, reader: Some(Box::new(reader)) });
    let connection = Box::pin(crate::http::connection(&config, theirs, (listen, local, peer, ssl), Busy::new(), Some(Box::new(origin))));
    let (mut reply, mut part, mut told) = (Reply { buf: buffer(), bodiless: request.starts_with(b"HEAD "), comes: None }, Part::default(), 0);
    let (mut ours, mut to) = tokio::io::split(ours);
    let passes = async move {
        let _ = to.write_all(&request).await;
        let mut body = body;
        while let Some(part) = match body.as_mut() { Some(b) => b.recv().await, None => None } {
            if to.write_all(&part).await.is_err() { return }
        }
        let _ = to.shutdown().await;
    };
    let mut tell = Telling { tell, ended: false };
    let reads = async move {
        let _reads = reads;
        while part.ended.is_none() {
            let (room, some) = ((*sent.borrow() + WAITING).saturating_sub(told + part.data.len()), part != Part::default());
            reply.buf.reserve(8192);
            let mut piece = (&mut ours).take(room as u64);
            tokio::select! {
                biased;
                n = piece.read_buf(&mut reply.buf), if room > 0 => reply.take(&mut part, n.unwrap_or(0) == 0),
                () = std::future::ready(()), if some => {
                    told += part.data.len();
                    tell.tell(std::mem::take(&mut part));
                }
                gone = sent.changed() => if gone.is_err() { return },
            }
        }
        tell.tell(part);
        // The connection may have more to do after its answer, which it does as if it were still read.
        while ours.read_buf(&mut reply.buf).await.is_ok_and(|n| n > 0) { reply.buf.clear(); }
        recycle(reply.buf);
    };
    tokio::join!(passes, connection, reads);
}

struct Telling<F: Fn(Part)> { tell: F, ended: bool }

impl<F: Fn(Part)> Telling<F> {
    fn tell(&mut self, part: Part) {
        self.ended = part.ended.is_some();
        (self.tell)(part);
    }
}

impl<F: Fn(Part)> Drop for Telling<F> {
    fn drop(&mut self) {
        if !self.ended { (self.tell)(Part { ended: Some(Ended::Cut), ..Part::default() }); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::{CHUNKED, DELIMITED, GZ, LENGTH, Pieces, after_head, at_once, files, letters, listening, log_path, logged, member, passing, pieces_after, plays, sends, served_by, serves_files, serving_on, with_length};
    use crate::stream::within;

    fn encoded(s: &[u8], lower: bool) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, s, lower);
        out
    }

    fn decoded(s: &[u8]) -> Option<Vec<u8>> {
        let mut out = b"before".to_vec();
        unhuffman(s, &mut out).then(|| out.split_off(6))
    }

    fn header_block(status: u16, headers: &[(Vec<u8>, Vec<u8>)], table_update: bool) -> Vec<u8> {
        let headers: Vec<_> = headers.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        [if table_update { &[0x20][..] } else { &[] }, &super::header_block(status, &headers)].concat()
    }

    async fn upstream(up: Stream, pipe: tokio::io::DuplexStream, scheme: &str, head_size: usize, slot: Slot) {
        upstream_framed(up, pipe, (scheme, head_size, slot), GET).await
    }

    async fn upstream_framed(up: Stream, pipe: tokio::io::DuplexStream, (scheme, head_size, slot): (&str, usize, Slot), framing: Framing) {
        super::upstream(Conn::new(up, Instant::now()), pipe, scheme, head_size, slot, framing).await
    }

    const GET: Framing = Framing { authority: true, chunked: false, length: 0 };

    #[test]
    fn huffman_codes() {
        assert_eq!(encoded(b"www.example.com", false), [0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
        assert_eq!(encoded(b"{{{{{", false), b"\x05{{{{{");
        assert_eq!(encoded(b"X-Sent-Foo", true), encoded(b"x-sent-foo", false));
        assert_eq!(encoded(b"{{{{X", true), b"\x05{{{{x");
        for c in 0..=255 {
            let s = [&[b'0'; 80][..], &[c], b"a~e", &[c]].concat();
            let coded = encoded(&s, false);
            let length = coded.len() - 1;
            assert_eq!(coded[0], 0x80 | length as u8);
            assert_eq!(decoded(&coded[1..]).unwrap(), s);
        }
        assert_eq!(decoded(&[0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]).unwrap(), b"www.example.com");
        assert_eq!(decoded(&[0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xff]).unwrap(), b"localhost");
        assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(decoded(&[0x00]), None);
        let coded = |octets: &[u8]| {
            let bits: String = octets.iter().map(|&c| { let (code, len) = HUFFMAN[usize::from(c)]; format!("{code:00$b}", usize::from(len)) }).collect();
            bits.as_bytes().chunks(8).map(|b| u8::from_str_radix(&format!("{:1<8}", std::str::from_utf8(b).unwrap()), 2).unwrap()).collect::<Vec<_>>()
        };
        for c in 0..=255 { assert_eq!(decoded(&coded(&[c])), Some(vec![c])); }
        let all: Vec<u8> = (0..=255).chain((0..=255).rev()).collect();
        assert_eq!(decoded(&coded(&all)), Some(all));
    }

    #[test]
    fn integers() {
        let mut out = Vec::new();
        write_integer(&mut out, 0, 5, 1337);
        assert_eq!(out, [31, 154, 10]);
        let mut at = 0;
        assert_eq!(integer(&out, &mut at, 5, 3), Ok(1337));
        assert_eq!(at, 3);
        assert_eq!(integer(&[0x1f, 0x80], &mut 0, 5, 2), Err(FRAME_SIZE_ERROR));
        assert_eq!(integer(&[0x1f, 0x80, 0x80, 0x80, 0x01], &mut 0, 5, 5), Err(COMPRESSION_ERROR));
    }

    #[test]
    fn table() {
        let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        let fields = t.decode(&[0x82, 0x86, 0x84, 0x41, 0x03, b'a', b'.', b'b', 0x40, 0x01, b'x', 0x01, b'y'], 13, (4, 8192)).unwrap();
        assert_eq!(fields[3], (b":authority".to_vec(), b"a.b".to_vec()));
        assert_eq!(t.field(62), Some((&b"x"[..], &b"y"[..])));
        assert_eq!(t.field(63), Some((&b":authority"[..], &b"a.b"[..])));
        assert_eq!(t.decode(&[0x80], 1, (4, 8192)), Err(COMPRESSION_ERROR));
        assert_eq!(t.decode(&[0xc2], 1, (4, 8192)), Err(COMPRESSION_ERROR));
        assert_eq!(t.decode(&[0x40, 0x00, 0x00], 3, (4, 8192)), Err(PROTOCOL_ERROR));
        assert_eq!(t.decode(&[0x00, 0x03, b'a'], 3, (4, 8192)), Err(FRAME_SIZE_ERROR));
        assert_eq!(t.decode(&[0x00, 0x03, b'a', b'b', b'c', 0x00], 6, (1, 2)), Err(ENHANCE_YOUR_CALM));
        assert_eq!(t.decode(&[0x3f, 0xe2, 0x1f], 3, (4, 8192)), Err(COMPRESSION_ERROR));
        assert_eq!(t.decode(&[0x3f, 0x03], 2, (4, 8192)), Ok(Vec::new()));
        assert_eq!((t.entries.len(), t.used), (1, 34));
        t.add(b"long name", b"long value");
        assert_eq!((t.entries.len(), t.used), (0, 0));
    }

    #[test]
    fn requests() {
        let request = |list: &[(&str, &str)], end| request(list.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())), end);
        let base = [(":method", "GET"), (":scheme", "http"), (":path", "/a?b"), (":authority", "h")];
        let (head, length, made) = request(&[&base[..], &[("cookie", "a=b"), ("x-a", "1"), ("cookie", "c=d")]].concat(), true).unwrap();
        assert_eq!((String::from_utf8(head).unwrap().as_str(), length, made), ("GET /a?b HTTP/2.0\r\nx-a: 1\r\ncookie: a=b; c=d\r\nhost: h\r\n", false, 2));
        assert_eq!(request(&[&base[..], &[("host", "h")]].concat(), true).unwrap().2, 0);
        assert!(request(&[&base[..], &[("host", "h"), ("content-length", "1")]].concat(), false).unwrap().1);
        assert!(request(&[&base[..], &[("content-length", "1")]].concat(), true).is_none());
        assert!(request(&[&base[..], &[("host", "other")]].concat(), true).is_none());
        assert!(request(&[&base[..], &[("X-A", "1")]].concat(), true).is_none());
        assert!(request(&[&base[..], &[("x-a", "1\n")]].concat(), true).is_none());
        assert!(request(&[&base[..], &[(":path", "/")]].concat(), true).is_none());
        assert!(request(&[&base[..], &[(":other", "/")]].concat(), true).is_none());
        assert!(request(&base[..3], true).is_none());
        assert!(request(&[base[0], (":scheme", "1x"), base[2], base[3]], true).is_none());
        assert!(request(&[(":method", "GET "), base[1], base[2], base[3]], true).is_none());
        assert!(request(&[(":method", "M-_"), base[1], base[2], base[3]], true).is_some());
    }

    #[test]
    fn answers() {
        let (status, headers) = answer_head(b"HTTP/1.1 301 Moved Permanently\r\nServer: twinx\r\nConnection: close\r\nX-A: b\r\nLocation: /x\r\nKeep-Alive: timeout=5").unwrap();
        assert_eq!((status, headers.len()), (301, 3));
        assert!(answer_head(b"HTTP/1.1").is_none());
        assert!(answer_head(b"HTTP/1.1 200 OK\r\nbroken").is_none());
        let block = [&[0x20], &super::header_block(status, &headers)[..]].concat();
        assert_eq!(block[..6], [0x20, 0x48, 0x03, b'3', b'0', b'1']);
        let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        let fields = t.decode(&block, block.len(), (4, 8192)).unwrap();
        let text: Vec<_> = fields.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
        assert_eq!(text, [":status: 301", "server: twinx", "location: /x", "x-a: b"]);
        assert_eq!(header_block(200, &[(b"Content-Length".to_vec(), b"12".to_vec())], false), [0x88, 0x5c, 0x02, b'1', b'2']);
    }

    #[test]
    fn requests_are_passed_over_http2() {
        crate::stream::block_on(async {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let slot = Slot::default();
            let bridge = upstream_framed(Stream::Pipe(up.into()), theirs, ("http", 4096, slot.clone()), Framing { chunked: true, ..GET });
            let test = async {
                ours.write_all(b"POST /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\nX-A: b\r\nX-C: \xff\xc3\r\n\r\n").await.unwrap();
                let mut out = Vec::new();
                frame(&mut out, SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0]);
                frame(&mut out, PING, 0, 0, b"12345678");
                server.write_all(&out).await.unwrap();
                let mut got = Vec::new();
                let frames = |got: &[u8]| { let mut at = PREFACE.len(); std::iter::from_fn(|| { let len = u32::from_be_bytes([0, *got.get(at)?, *got.get(at + 1)?, *got.get(at + 2)?]) as usize; let f = (got.get(at + 3).copied()?, got.get(at + 4).copied()?, got.get(at + 9..at + 9 + len)?.to_vec()); at += 9 + len; Some(f) }).collect::<Vec<_>>() };
                while !frames(&got).iter().any(|f| f.0 == PING) { server.read_buf(&mut got).await.unwrap(); }
                ours.write_all(b"2\r\nab\r\n1;e\r\nc\r\n0\r\n\r\n").await.unwrap();
                while !frames(&got).iter().any(|f| f.0 == DATA) { server.read_buf(&mut got).await.unwrap(); }
                assert!(!slot.lock().unwrap().sent);
                out.clear();
                frame(&mut out, WINDOW_UPDATE, 0, 1, &[0, 0, 0, 10]);
                server.write_all(&out).await.unwrap();
                while !frames(&got).iter().any(|f| f.0 == DATA && f.1 == END_STREAM) { server.read_buf(&mut got).await.unwrap(); }
                assert!(slot.lock().unwrap().sent);
                let sent = frames(&got);
                let kinds: Vec<_> = sent.iter().map(|f| (f.0, f.1)).collect();
                assert_eq!(kinds, [(SETTINGS, 0), (WINDOW_UPDATE, 0), (HEADERS, END_HEADERS), (SETTINGS, ACK), (PING, ACK), (DATA, 0), (DATA, END_STREAM)]);
                assert_eq!((&sent[5].2[..], &sent[6].2[..]), (&b"a"[..], &b"bc"[..]));
                let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
                let fields = t.decode(&sent[2].2, sent[2].2.len(), (100, 100)).unwrap();
                let text: Vec<_> = fields.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
                assert_eq!(text[..6], [":method: POST", ":scheme: http", ":authority: h", ":path: /x", "connection: close", "x-a: b"]);
                assert_eq!(fields[6], (b"x-c".to_vec(), b"\xff\xc3".to_vec()));
                out.clear();
                let block = header_block(200, &[(b"x-b".to_vec(), b"c".to_vec())], false);
                frame(&mut out, HEADERS, PADDED, 1, &[[1].as_slice(), &block[..1], &[0]].concat());
                frame(&mut out, CONTINUATION, END_HEADERS, 1, &block[1..]);
                frame(&mut out, DATA, PADDED, 1, b"\x01ok\x00");
                frame(&mut out, DATA, END_STREAM, 1, b"!");
                server.write_all(&out).await.unwrap();
                let mut answer = Vec::new();
                ours.read_to_end(&mut answer).await.unwrap();
                assert_eq!(String::from_utf8_lossy(&answer), "HTTP/1.1 200 \r\nx-b: c\r\n\r\nok!");
            };
            tokio::join!(bridge, test);
        });
    }

    #[test]
    fn trailers_go_apart() {
        crate::stream::block_on(async {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let slot = Slot::default();
            let bridge = upstream(Stream::Pipe(up.into()), theirs, "http", 4096, slot.clone());
            let test = async {
                ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
                let mut out = Vec::new();
                frame(&mut out, HEADERS, END_HEADERS, 1, &header_block(103, &[(b"link".to_vec(), b"<a>".to_vec())], false));
                frame(&mut out, HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
                frame(&mut out, DATA, 0, 1, b"ok");
                let mut block = Vec::new();
                literals(&mut block, [(b"x-t".to_vec(), b"1".to_vec())].iter());
                frame(&mut out, HEADERS, END_HEADERS | END_STREAM, 1, &block);
                server.write_all(&out).await.unwrap();
                let mut answer = Vec::new();
                ours.read_to_end(&mut answer).await.unwrap();
                String::from_utf8_lossy(&answer).into_owned()
            };
            assert_eq!(tokio::join!(bridge, test).1, "HTTP/1.1 103 \r\nlink: <a>\r\n\r\nHTTP/1.1 200 \r\n\r\nok");
            assert_eq!(slot.lock().unwrap().trailers, [("x-t".to_string(), "1".to_string())]);
        });
    }

    #[test]
    fn tables_without_room() {
        let mut t = Table { entries: VecDeque::new(), size: 0, used: 0, limit: 0 };
        assert_eq!(t.decode(&[0x20, 0x48, 0x03, b'2', b'0', b'0'], 6, (10, 100)).unwrap(), [(b":status".to_vec(), b"200".to_vec())]);
        assert!(t.entries.is_empty() && t.field(62).is_none());
        assert_eq!(t.decode(&[0x21, 0x88], 2, (10, 100)), Err(COMPRESSION_ERROR));
    }

    fn framed(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        frame(&mut out, kind, flags, sid, payload);
        out
    }

    fn passed(pieces: &[&[u8]], closes: bool) -> (String, End, Vec<(String, String)>) {
        let ((mut ours, theirs), (up, server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 20));
        let slot = Slot::default();
        let told = slot.clone();
        let answer = crate::stream::block_on(async {
            let bridge = tokio::task::spawn_local(upstream(Stream::Pipe(up.into()), theirs, "http", 4096, slot));
            ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
            let mut server = Some(server);
            for piece in pieces {
                if server.as_mut().unwrap().write_all(piece).await.is_err() { break }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            if closes { server.take(); }
            let mut answer = Vec::new();
            let _ = crate::stream::within(Some(Duration::from_millis(50)), ours.read_to_end(&mut answer)).await;
            drop(ours);
            crate::stream::within(Some(Duration::from_secs(1)), bridge).await.expect("the bridge stays").unwrap();
            String::from_utf8_lossy(&answer).into_owned()
        });
        let told = std::mem::take(&mut *told.lock().unwrap());
        (answer, told.end, told.trailers)
    }

    #[test]
    fn answers_end_as_their_streams_do() {
        let head = framed(HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
        let data = framed(DATA, 0, 1, b"ok");
        let last = framed(DATA, END_STREAM, 1, b"!");
        let rst = |code: u32| framed(RST_STREAM, 0, 1, &code.to_be_bytes());
        let goaway = |last: u32| framed(GOAWAY, 0, 0, &[last.to_be_bytes(), [0; 4]].concat());
        let trailers = |flags: u8| { let mut block = Vec::new(); literals(&mut block, [(b"x-t".to_vec(), b"1".to_vec())].iter()); framed(HEADERS, END_HEADERS | flags, 1, &block) };
        let cases = [
            (vec![last.clone()], "ok!", "ok!", End::Whole),
            (vec![last.clone(), rst(NO_ERROR)], "ok!", "ok!", End::Whole),
            (vec![goaway(1), last.clone()], "ok!", "ok!", End::Whole),
            (vec![trailers(END_STREAM)], "ok", "ok", End::Whole),
            (vec![rst(INTERNAL_ERROR)], "ok", "", End::Failed),
            (vec![rst(NO_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), rst(INTERNAL_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), rst(NO_ERROR), rst(NO_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), data.clone()], "ok", "", End::Failed),
            (vec![goaway(0)], "ok", "", End::Failed),
            (vec![trailers(0)], "ok", "", End::Failed),
            (vec![framed(WINDOW_UPDATE, 0, 0, &[0; 3])], "ok", "", End::Failed),
            (vec![], "ok", "ok", End::Closed),
            (vec![goaway(1)], "ok", "ok", End::Closed),
            (vec![data[..10].to_vec()], "oko", "oko", End::Closed),
            (vec![framed(DATA, PADDED, 1, b"\x02okay..")[..15].to_vec()], "okokay", "okokay", End::Closed),
        ];
        for (frames, apart, at_once, end) in cases {
            let (frames, text) = (frames.concat(), |body: &str| format!("HTTP/1.1 200 \r\n\r\n{body}"));
            let got = passed(&[&head, &data, &frames], end == End::Closed);
            assert_eq!((got.0, got.1), (text(apart), end), "{frames:?}");
            let got = passed(&[&[&head[..], &data, &frames].concat()], end == End::Closed);
            assert_eq!((got.0, got.1), (text(at_once), end), "{frames:?}");
        }
        for (frames, end) in [(rst(INTERNAL_ERROR), End::Failed), (rst(NO_ERROR), End::Failed), (goaway(0), End::Failed), (data.clone(), End::Failed), (goaway(1), End::Closed), (Vec::new(), End::Closed)] {
            assert_eq!(passed(&[&frames], end == End::Closed), (String::new(), end, Vec::new()), "{frames:?}");
        }
        assert_eq!(passed(&[&framed(HEADERS, END_HEADERS | END_STREAM, 1, &header_block(200, &[], false))], false).1, End::Whole);
        assert_eq!(passed(&[&head, &data, &trailers(END_STREAM)], false).2, [("x-t".to_string(), "1".to_string())]);
    }

    #[test]
    fn answers_are_read_after_a_write_fails() {
        let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 20));
        let slot = Slot::default();
        let body = crate::stream::block_on(async {
            let mut out = framed(SETTINGS, 0, 0, &[]);
            frame(&mut out, HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
            (0..20).for_each(|i| frame(&mut out, DATA, u8::from(i == 19), 1, &[b'x'; 16384]));
            server.write_all(&out).await.unwrap();
            drop(server);
            ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
            let mut answer = Vec::new();
            tokio::join!(upstream(Stream::Pipe(up.into()), theirs, "http", 4096, slot.clone()), ours.read_to_end(&mut answer)).1.unwrap();
            answer.len() - "HTTP/1.1 200 \r\n\r\n".len()
        });
        assert_eq!((body, slot.lock().unwrap().end), (20 * 16384, End::Whole));
    }

    #[test]
    fn unwanted_answers_end_the_connection() {
        let head = framed(HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
        let pings = framed(PING, 0, 0, &[0; 8]).repeat(200);
        for (sent, room) in [(Vec::new(), 1 << 16), (head.clone(), 1 << 16), ([head, pings].concat(), 256)] {
            crate::stream::block_on(async {
                let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(room));
                let bridge = tokio::task::spawn_local(upstream(Stream::Pipe(up.into()), theirs, "http", 4096, Slot::default()));
                ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
                let _ = crate::stream::within(Some(Duration::from_millis(50)), server.write_all(&sent)).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
                drop(ours);
                crate::stream::within(Some(Duration::from_millis(500)), bridge).await.expect("the bridge stays").unwrap();
                assert!(server.read_to_end(&mut Vec::new()).await.is_ok());
            });
        }
    }

    #[test]
    fn a_full_pipe_holds_the_server_back() {
        crate::stream::block_on(async {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let bridge = tokio::task::spawn_local(upstream(Stream::Pipe(up.into()), theirs, "http", 4096, Slot::default()));
            ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
            server.write_all(&framed(HEADERS, END_HEADERS, 1, &header_block(200, &[], false))).await.unwrap();
            let mut sent = 0;
            while crate::stream::within(Some(Duration::from_millis(20)), server.write_all(&framed(DATA, 0, 1, &[b'x'; 1000]))).await.is_some() { sent += 1; }
            assert!((64..300).contains(&sent), "{sent}");
            drop(ours);
            crate::stream::within(Some(Duration::from_millis(500)), bridge).await.expect("the bridge stays").unwrap();
        });
    }

    #[test]
    fn frames_that_are_wrong_fail_the_answer() {
        let head = framed(HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
        let word = |n: u32| n.to_be_bytes();
        let setting = |id: u8, n: u32| [&[0, id][..], &word(n)].concat();
        let max = (1u32 << 31) - 1;
        let wrong = [
            framed(DATA, 0, 1, &[0; 16385]), framed(77, 0, 0, &[0; 16385]), framed(77, 0, 0, &[0; 16385])[..9].to_vec(),
            framed(DATA, PADDED, 1, &[]), framed(DATA, PADDED, 1, &[4, 0, 0, 0]), framed(HEADERS, END_HEADERS | PADDED, 1, &[]), framed(HEADERS, END_HEADERS | PADDED, 1, &[3, 0, 0]),
            framed(HEADERS, END_HEADERS | PRIORITY_FLAG, 1, &[0; 4]), framed(HEADERS, END_HEADERS | PADDED | PRIORITY_FLAG, 1, &[0; 5]), framed(HEADERS, END_HEADERS | PADDED | PRIORITY_FLAG, 1, &[2, 0, 0, 0, 0, 0, 0]),
            framed(RST_STREAM, 0, 1, &[0; 3]), framed(RST_STREAM, 0, 1, &[]), framed(WINDOW_UPDATE, 0, 0, &[]), framed(WINDOW_UPDATE, 0, 1, &[0; 5]),
            framed(PING, 0, 0, &[0; 7]), framed(GOAWAY, 0, 0, &[0; 7]), framed(SETTINGS, 0, 0, &[0; 5]), framed(SETTINGS, ACK, 0, &[0; 6]),
            framed(SETTINGS, 0, 0, &setting(4, max + 1)), framed(WINDOW_UPDATE, 0, 0, &word(max - 65534)), framed(WINDOW_UPDATE, 0, 1, &word(max - 65534)),
            [framed(WINDOW_UPDATE, 0, 1, &word(max - 65535)), framed(SETTINGS, 0, 0, &setting(4, 65536))].concat(),
            framed(HEADERS, END_HEADERS, 1, &[0x00, 0x05, b'x']), framed(HEADERS, END_HEADERS, 1, &[0xff, 0xff, 0xff, 0xff]),
        ];
        for frames in &wrong {
            assert_eq!((passed(&[frames], false).0, passed(&[frames], false).1), (String::new(), End::Failed), "{}", frames[..frames.len().min(20)].escape_ascii());
            assert_eq!(passed(&[&head, frames], false).1, End::Failed, "{}", frames[..frames.len().min(20)].escape_ascii());
        }
        let fine = [
            framed(DATA, PADDED, 1, &[3, 0, 0, 0]), framed(PRIORITY, 0, 1, &[0; 4]), framed(SETTINGS, ACK, 0, &[]), framed(WINDOW_UPDATE, 0, 1, &[0; 4]),
            framed(SETTINGS, 0, 0, &[setting(4, max), setting(4, 65535), setting(4, max)].concat()), framed(SETTINGS, 0, 0, &[setting(5, 0), setting(2, 2)].concat()),
            framed(WINDOW_UPDATE, 0, 0, &word(max - 65535)), framed(WINDOW_UPDATE, 0, 1, &word(max - 65535)), framed(77, 0, 0, &[0; 16384]),
        ];
        for frames in &fine {
            let last = framed(DATA, END_STREAM, 1, b"ok");
            assert_eq!(passed(&[&head, frames, &last], false), ("HTTP/1.1 200 \r\n\r\nok".to_string(), End::Whole, Vec::new()), "{}", frames[..frames.len().min(20)].escape_ascii());
        }
        let field = |n: usize| { let mut block = Vec::new(); literals(&mut block, [(b":status".to_vec(), b"200".to_vec()), (b"x".to_vec(), vec![b'~'; n])].iter()); block };
        let long = |size: usize| (0..size).map(field).find(|b| b.len() == size).unwrap();
        assert_eq!(passed(&[&framed(HEADERS, END_HEADERS, 1, &long(4096 - 9))], true).1, End::Closed);
        assert_eq!(passed(&[&framed(HEADERS, END_HEADERS, 1, &long(4097 - 9))], false).1, End::Failed);
        let endless = [framed(HEADERS, 0, 1, &[0x88]), framed(CONTINUATION, 0, 1, &[]).repeat(500)].concat();
        assert_eq!(passed(&[&endless], false).1, End::Failed);
    }

    #[test]
    fn what_stays_with_a_connection() {
        let head = |sid: u32, end: u8| framed(HEADERS, END_HEADERS | end, sid, &header_block(200, &[], false));
        let word = |n: u32| n.to_be_bytes();
        let exchange = |session: Option<Session>, request: &'static str, frames: Vec<u8>| crate::stream::block_on(async move {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let slot = Slot::default();
            let mut conn = Conn::new(Stream::Pipe(up.into()), Instant::now());
            conn.h2 = session.map(Box::new);
            ours.write_all(request.as_bytes()).await.unwrap();
            server.write_all(&frames).await.unwrap();
            let framing = Framing { length: if request.starts_with("POST") { 5 } else { 0 }, ..GET };
            super::upstream(conn, theirs, "http", 4096, slot.clone(), framing).await;
            let mut ending = slot.lock().unwrap();
            let kept = ending.conn.take().map(|c| *c.h2.unwrap());
            let mut sent = vec![0; 1 << 16];
            let n = crate::stream::within(Some(Duration::from_millis(20)), server.read(&mut sent)).await.map_or(0, Result::unwrap);
            sent.truncate(n);
            (sent, ending.end, kept)
        });
        let get = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let post = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nabcde";
        let settings = framed(SETTINGS, 0, 0, &[&[0, 4][..], &word(3), &[0, 1], &word(0)].concat());
        let (sent, end, kept) = exchange(None, post, [settings, framed(WINDOW_UPDATE, 0, 0, &word(9)), head(1, 0), framed(DATA, END_STREAM, 1, b"ok")].concat());
        assert!(sent.starts_with(PREFACE) && sent.ends_with(&framed(SETTINGS, ACK, 0, &[])) && end == End::Whole);
        let session = Session { id: 3, window: 65535 - 5 + 9, initial: 3, recv: MAX_WINDOW - 2, skipped: 14 };
        assert_eq!(kept, Some(session));
        let (sent, end, kept) = exchange(kept, post, [framed(WINDOW_UPDATE, 0, 3, &word(2)), head(3, END_STREAM)].concat());
        let data = [framed(DATA, 0, 3, b"abc"), framed(DATA, END_STREAM, 3, b"de")].concat();
        assert!(sent[3..9] == [HEADERS, END_HEADERS, 0, 0, 0, 3] && sent.ends_with(&data[..12]) && end == End::Whole && kept.is_none());
        let answered = [head(3, 0), framed(DATA, END_STREAM, 3, b"ok")].concat();
        let reset = [answered.clone(), framed(RST_STREAM, 0, 3, &word(0))].concat();
        let (sent, end, kept) = exchange(Some(session), post, reset.clone());
        assert!(sent.ends_with(&data[..12]) && end == End::Whole);
        assert_eq!(kept, Some(Session { id: 5, window: session.window - 3, recv: MAX_WINDOW - 4, skipped: 26, ..session }));
        assert_eq!(exchange(Some(session), post, answered).2, None);
        assert_eq!(exchange(Some(Session { skipped: (4 << 20) - 12, ..session }), post, reset).2, None);
        let (sent, _, kept) = exchange(Some(session), get, [head(3, 0), framed(DATA, END_STREAM, 3, b"ok")].concat());
        assert!(sent[3..9] == [HEADERS, END_HEADERS | END_STREAM, 0, 0, 0, 3]);
        assert_eq!(kept, Some(Session { id: 5, recv: MAX_WINDOW - 4, ..session }));
        let late = [framed(RST_STREAM, 0, 3, &word(0)), framed(WINDOW_UPDATE, 0, 3, &word(1)), head(5, 0), framed(DATA, END_STREAM, 5, b"ok")].concat();
        assert_eq!(exchange(Some(Session { id: 5, ..session }), get, late).2, Some(Session { id: 7, recv: MAX_WINDOW - 4, ..session }));
        let little = Session { recv: MAX_WINDOW / 4 + 1, ..session };
        let answer = |data: &[u8]| [head(3, 0), framed(DATA, 0, 3, data), framed(DATA, END_STREAM, 3, b"")].concat();
        assert_eq!(exchange(Some(little), get, answer(b"a")).2, Some(Session { id: 5, recv: MAX_WINDOW / 4, ..session }));
        let (sent, _, kept) = exchange(Some(little), get, answer(b"ab"));
        let grown = [framed(WINDOW_UPDATE, 0, 0, &word((MAX_WINDOW - MAX_WINDOW / 4 + 1) as u32)), framed(WINDOW_UPDATE, 0, 3, &word(2))].concat();
        assert!(sent.ends_with(&grown) && kept == Some(Session { id: 5, recv: MAX_WINDOW, ..session }));
        let (_, end, kept) = exchange(Some(Session { recv: 1, ..session }), get, answer(b"ab"));
        assert_eq!((end, kept), (End::Failed, None));
        for frame in [framed(DATA, 0, 5, b"a"), framed(DATA, 0, 0, b"a"), framed(PING, ACK, 0, &[0; 8])] {
            let (_, end, kept) = exchange(Some(session), get, [frame, head(3, END_STREAM)].concat());
            assert_eq!((end, kept), (End::Failed, None));
        }
    }

    type Plays = fn(u32) -> (Vec<u8>, Option<Vec<u8>>);

    fn kept(plays: Plays, method: &str, (upstream, location): (&str, &str)) -> (Vec<u16>, Vec<usize>) {
        use std::io::{Read, Write};
        use std::sync::{Mutex, atomic::{AtomicUsize, Ordering::SeqCst}};
        let (sent, answered): (Arc<AtomicUsize>, Arc<AtomicUsize>) = Default::default();
        let (plays_on, seen) = (sent.clone(), answered.clone());
        let (addr, came) = listening(move |i, mut s, came: &Arc<Mutex<Vec<usize>>>| {
            came.lock().unwrap().push(0);
            let (came, sent, answered) = (came.clone(), plays_on.clone(), seen.clone());
            s.set_nodelay(true).unwrap();
            std::thread::spawn(move || {
                if s.read_exact(&mut [0; 24]).is_err() { return }
                loop {
                    let mut ended = None;
                    while ended.is_none() {
                        let mut head = [0; 9];
                        if s.read_exact(&mut head).is_err() { return }
                        let mut payload = vec![0; u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize];
                        if s.read_exact(&mut payload).is_err() { return }
                        ended = (matches!(head[3], HEADERS | DATA) && head[4] & END_STREAM != 0).then(|| u32::from_be_bytes([head[5], head[6], head[7], head[8]]));
                    }
                    came.lock().unwrap()[i] += 1;
                    let (at_once, then) = plays(ended.unwrap());
                    let _ = s.write_all(&at_once);
                    if let Some(then) = &then {
                        while !at_once.is_empty() && sent.load(SeqCst) == answered.load(SeqCst) { std::thread::sleep(Duration::from_millis(1)); }
                        let _ = s.write_all(then);
                    }
                    let closes = then.is_some_and(|t| t.is_empty());
                    if closes { let _ = s.shutdown(std::net::Shutdown::Both); }
                    if !at_once.is_empty() { sent.fetch_add(1, SeqCst); }
                    if closes { return }
                }
            });
        });
        let _busy = serving_on();
        let text = format!("access_log off; upstream u {{ server {addr}; {upstream} }} server {{ proxy_http_version 2; location / {{ proxy_pass http://u; {location} }} location /ok {{ return 200; }} }}");
        let statuses = crate::stream::block_on(async {
            let (mut client, _task) = served_by(&text).await;
            let (mut statuses, length) = (Vec::new(), if method == "POST" { "Content-Length: 3\r\n\r\nabc" } else { "\r\n" });
            for n in 1..=4 {
                client.write_all(format!("{method} / HTTP/1.1\r\nHost: a\r\n{length}").as_bytes()).await.unwrap();
                let mut got = Vec::new();
                let whole = |got: &[u8]| {
                    let text = String::from_utf8_lossy(got).into_owned();
                    let (head, body) = text.split_once("\r\n\r\n")?;
                    let bodiless = method == "HEAD" || head.starts_with("HTTP/1.1 204") || head.contains("Content-Length: 0");
                    (bodiless || body == "ok" || body.ends_with("0\r\n\r\n") || body.ends_with("</html>\r\n")).then(|| head[9..12].parse::<u16>().unwrap())
                };
                let status = loop {
                    if let Some(status) = whole(&got) { break status }
                    let n = crate::stream::within(Some(Duration::from_secs(5)), client.read_buf(&mut got)).await.expect("no answer").unwrap();
                    assert!(n > 0, "{}", String::from_utf8_lossy(&got));
                };
                statuses.push(status);
                answered.store(n, SeqCst);
                for _ in 0..5000 { if sent.load(SeqCst) >= n || status >= 500 { break } tokio::time::sleep(Duration::from_millis(1)).await; }
                tokio::time::sleep(Duration::from_millis(10)).await;
                sent.store(n, SeqCst);
            }
            statuses
        });
        (statuses, std::mem::take(&mut *came.lock().unwrap()))
    }

    #[test]
    fn connections_are_kept_as_nginx_keeps_them() {
        fn head(sid: u32, status: u16, flags: u8) -> Vec<u8> { framed(HEADERS, END_HEADERS | flags, sid, &header_block(status, &[], false)) }
        fn fields(sid: u32, fields: &[(&str, &str)], flags: u8) -> Vec<u8> { framed(HEADERS, END_HEADERS | flags, sid, &header_block(200, &fields.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect::<Vec<_>>(), false)) }
        fn ok(sid: u32) -> Vec<u8> { [head(sid, 200, 0), framed(DATA, END_STREAM, sid, b"ok")].concat() }
        fn with(sid: u32, frame: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) { ([ok(sid), frame].concat(), None) }
        fn later(sid: u32, frame: Vec<u8>) -> (Vec<u8>, Option<Vec<u8>>) { (ok(sid), Some(frame)) }
        fn ping() -> Vec<u8> { framed(PING, 0, 0, &[0; 8]) }
        fn goaway(last: u32) -> Vec<u8> { framed(GOAWAY, 0, 0, &[last.to_be_bytes(), [0; 4]].concat()) }
        fn rst(sid: u32) -> Vec<u8> { framed(RST_STREAM, 0, sid, &[0; 4]) }
        let (kept_all, kept_none) = (&[4][..], &[1, 1, 1, 1][..]);
        let cases: Vec<(&str, &str, Plays, &[usize])> = vec![
            ("the end with the data", "GET", |i| (ok(i), None), kept_all),
            ("the same of a POST", "POST", |i| (ok(i), None), kept_all),
            ("the end with the head", "GET", |i| (head(i, 200, END_STREAM), None), kept_all),
            ("no content", "GET", |i| (head(i, 204, END_STREAM), None), kept_all),
            ("HEAD", "HEAD", |i| (fields(i, &[("content-length", "2")], END_STREAM), None), kept_all),
            ("no length in the head", "GET", |i| ([fields(i, &[("content-length", "0")], 0), framed(DATA, END_STREAM, i, b"")].concat(), None), kept_all),
            ("the end after the length", "GET", |i| ([fields(i, &[("content-length", "2")], 0), framed(DATA, 0, i, b"ok")].concat(), Some(framed(DATA, END_STREAM, i, b""))), kept_all),
            ("trailers", "GET", |i| ([head(i, 200, 0), framed(DATA, 0, i, b"ok"), framed(HEADERS, END_HEADERS | END_STREAM, i, b"\x00\x01x\x011")].concat(), None), kept_all),
            ("a reset after the end", "GET", |i| with(i, rst(i)), kept_all),
            ("windows after the end", "GET", |i| with(i, [framed(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1]), framed(WINDOW_UPDATE, 0, i, &[0, 0, 0, 1])].concat()), kept_all),
            ("a ping after the end", "GET", |i| with(i, ping()), kept_all),
            ("settings after the end", "GET", |i| with(i, framed(SETTINGS, 0, 0, &[0, 5, 0, 0, 0x40, 0])), kept_all),
            ("an unknown frame after the end", "GET", |i| with(i, framed(77, 0, 0, b"a")), kept_all),
            ("connection: close", "GET", |i| ([fields(i, &[("connection", "close")], 0), framed(DATA, END_STREAM, i, b"ok")].concat(), None), kept_all),
            ("a reset after the end with the head", "GET", |i| ([head(i, 200, END_STREAM), rst(i)].concat(), None), kept_all),
            ("a reset later", "GET", |i| later(i, rst(i)), kept_none),
            ("windows later", "GET", |i| later(i, framed(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 1])), kept_none),
            ("a ping later", "GET", |i| later(i, ping()), kept_none),
            ("settings later", "GET", |i| later(i, framed(SETTINGS, 0, 0, &[])), kept_none),
            ("going away later", "GET", |i| later(i, goaway(i)), kept_none),
            ("the end of the connection later", "GET", |i| later(i, Vec::new()), kept_none),
            ("going away", "GET", |i| ([goaway(i), ok(i)].concat(), None), kept_none),
            ("going away after the end", "GET", |i| with(i, goaway(i)), kept_none),
            ("a part of a frame", "GET", |i| with(i, vec![0, 0, 4]), kept_none),
            ("no content, with the end after the head", "GET", |i| ([head(i, 204, 0), framed(DATA, END_STREAM, i, b"")].concat(), None), kept_none),
            ("HEAD, with the end after the head", "HEAD", |i| ([head(i, 200, 0), framed(DATA, END_STREAM, i, b"")].concat(), None), kept_none),
            ("no content, with a reset", "GET", |i| ([head(i, 204, END_STREAM), rst(i)].concat(), None), kept_none),
            ("the end with the head, and a ping", "GET", |i| ([ping(), head(i, 200, END_STREAM)].concat(), None), kept_none),
            ("the end with the head, and a ping after it", "GET", |i| ([head(i, 200, END_STREAM), ping()].concat(), None), kept_none),
        ];
        at_once(cases, |(case, method, plays, connections)| {
            let (statuses, came) = kept(plays, method, ("", ""));
            assert!(statuses.iter().all(|s| *s < 300), "{case} {statuses:?}");
            assert_eq!(came, connections, "{case}");
        });
        let second: Plays = |i| if i == 1 { (ok(i), None) } else { (Vec::new(), Some(Vec::new())) };
        assert_eq!(kept(second, "GET", ("", "")), (vec![200; 4], vec![2, 2, 2, 1]));
        assert_eq!(kept(second, "GET", ("", "proxy_next_upstream off;")), (vec![200, 502, 200, 502], vec![2, 2]));
        assert_eq!(kept(second, "POST", ("", "")), (vec![200, 502, 200, 502], vec![2, 2]));
        let fails: [Plays; 2] = [|i| if i == 1 { (ok(i), None) } else { (goaway(1), None) }, |i| if i == 1 { (ok(i), None) } else { (rst(i), None) }];
        for fails in fails { assert_eq!(kept(fails, "GET", ("", "")), (vec![200, 502, 200, 502], vec![2, 2])); }
        let plain: Plays = |i| (ok(i), None);
        assert_eq!(kept(plain, "GET", ("keepalive_requests 3;", "")).1, [3, 1]);
        assert_eq!(kept(plain, "GET", ("keepalive 0;", "")).1, kept_none);
        assert_eq!(kept(|i| (fields(i, &[("x-accel-redirect", "/ok")], END_STREAM), None), "GET", ("", "")).1, kept_all);
        assert_eq!(kept(|i| ([fields(i, &[("x-accel-redirect", "/ok")], 0), framed(DATA, END_STREAM, i, b"ok")].concat(), None), "GET", ("", "")).1, kept_none);
        for buffering in ["proxy_buffering off;", "proxy_pass_trailers on;", "proxy_limit_rate 1m;"] { assert_eq!(kept(plain, "GET", ("", buffering)).1, kept_all, "{buffering}"); }
    }

    #[test]
    fn frames_out_of_place_fail_the_answer() {
        let (head, data) = (framed(HEADERS, END_HEADERS, 1, &header_block(200, &[], false)), framed(DATA, END_STREAM, 1, b"ok"));
        let push = [&2u32.to_be_bytes()[..], b"\x00\x07:method\x03GET"].concat();
        let misplaced = [framed(SETTINGS, 0, 1, &[]), framed(PING, 0, 1, &[0; 8]), framed(GOAWAY, 0, 1, &[0; 8]), framed(RST_STREAM, 0, 0, &[0; 4]), framed(HEADERS, END_HEADERS, 0, &header_block(200, &[], false)), framed(PUSH_PROMISE, END_HEADERS, 1, &push), framed(PUSH_PROMISE, END_HEADERS, 0, &push)];
        for frame in &misplaced {
            assert_eq!(passed(&[&[frame.clone(), head.clone(), data.clone()].concat()], false).1, End::Failed, "{frame:?}");
            assert_eq!(passed(&[&[head.clone(), frame.clone(), data.clone()].concat()], false), ("HTTP/1.1 200 \r\n\r\n".to_string(), End::Failed, vec![]), "{frame:?}");
        }
    }

    #[test]
    fn heads_nginx_refuses_fail_the_answer() {
        let block = |fields: &[(&str, &str)]| fields.iter().flat_map(|(n, v)| [&[0, n.len() as u8], n.as_bytes(), &[v.len() as u8], v.as_bytes()].concat()).collect::<Vec<u8>>();
        let head = |fields: &[(&str, &str)]| framed(HEADERS, END_HEADERS, 1, &block(fields));
        let (ok, last) = ((":status", "200"), framed(DATA, END_STREAM, 1, b"ok"));
        let names = ["x a", "x\ra", "x\na", "x\0", "x\x7f", "x:a", "X", "::x"];
        let values = ["a\r\nb: c", "a\r", "\nb", "a\0"];
        let fields = names.iter().map(|n| (*n, "v")).chain(values.iter().map(|v| ("x", *v)));
        for field in fields {
            assert_eq!(passed(&[&[head(&[ok, field]), last.clone()].concat()], false), (String::new(), End::Failed, vec![]), "{field:?}");
            let hints = [(":status", "103"), field];
            assert_eq!(passed(&[&[head(&hints), head(&[ok]), last.clone()].concat()], false), (String::new(), End::Failed, vec![]), "{field:?}");
            assert_eq!(passed(&[&[head(&hints[..1]), head(&[ok, field])].concat()], false), ("HTTP/1.1 103 \r\n\r\n".to_string(), End::Failed, vec![]), "{field:?}");
            let trailers = framed(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[("x-t", "1"), field]));
            assert_eq!(passed(&[&head(&[ok]), &framed(DATA, 0, 1, b"ok"), &trailers], false), ("HTTP/1.1 200 \r\n\r\nok".to_string(), End::Failed, vec![]), "{field:?}");
        }
        for field in [(":status", "200"), (":x", "1")] {
            let trailers = framed(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[field]));
            assert_eq!(passed(&[&[head(&[ok]), trailers].concat()], false), ("HTTP/1.1 200 \r\n\r\n".to_string(), End::Failed, vec![]), "{field:?}");
        }
        for fields in [
            &[][..], &[("x", "1")], &[("x", "1"), ok], &[ok, ok], &[ok, ("x", "1"), ok], &[ok, (":x", "1")], &[ok, ("x", "1"), (":path", "/")],
            &[(":status", "")], &[(":status", "20")], &[(":status", "0200")], &[(":status", "+20")], &[(":status", "2x0")], &[(":status", "000")], &[(":status", "100")], &[(":status", "101")], &[(":status", "199")],
            &[ok, ("content-length", " 2")], &[ok, ("content-length", "2 ")], &[ok, ("transfer-encoding", " chunked")],
        ] { assert_eq!(passed(&[&[head(fields), last.clone()].concat()], false), (String::new(), End::Failed, vec![]), "{fields:?}"); }
        for frames in [
            framed(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[(":status", "103")])), framed(CONTINUATION, END_HEADERS, 1, &block(&[ok])),
            [framed(HEADERS, 0, 1, &block(&[ok])), head(&[("x", "1")])].concat(), [framed(HEADERS, 0, 1, &block(&[ok])), framed(PING, 0, 0, &[0; 8])].concat(),
        ] { assert_eq!(passed(&[&frames], false), (String::new(), End::Failed, vec![]), "{frames:?}"); }
        for (field, line) in [(("x", "\t\u{7f}"), "x: \t\u{7f}\r\n"), (("x_(/", ""), "x_(/: \r\n"), (("connection", "close"), "connection: close\r\n"), ((":status", "999"), "")] {
            let (fields, status) = if line.is_empty() { (vec![field], "999") } else { (vec![ok, field], "200") };
            assert_eq!(passed(&[&[head(&fields), last.clone()].concat()], false), (format!("HTTP/1.1 {status} \r\n{line}\r\nok"), End::Whole, vec![]), "{field:?}");
        }
        let trailers = framed(HEADERS, END_HEADERS | END_STREAM, 1, &[&[0, 1, b'x', 1], &[0xff][..]].concat());
        assert_eq!(passed(&[&[head(&[ok]), trailers].concat()], false).2, [("x".to_string(), crate::vars::text(&[0xff]))]);
    }

    #[test]
    fn data_is_as_long_as_the_answer_says() {
        let head = |length: &str, status: &str, flags: u8| { let mut block = Vec::new(); literals(&mut block, [(":status", status), ("content-length", length)].map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).iter()); framed(HEADERS, END_HEADERS | flags, 1, &block) };
        let data = |data: &[u8], flags: u8| framed(DATA, flags, 1, data);
        let trailers = framed(HEADERS, END_HEADERS | END_STREAM, 1, &[0, 1, b'x', 1, b'1']);
        for (sent, body) in [
            (vec![head("2", "200", 0), data(b"ok", END_STREAM)], Some("ok")), (vec![head("2", "200", 0), data(b"o", 0), data(b"", 0), data(b"k", 0), trailers.clone()], Some("ok")),
            (vec![head("0", "200", END_STREAM)], Some("")), (vec![head("2", "304", END_STREAM)], Some("")), (vec![head("2", "204", END_STREAM)], Some("")),
            (vec![head("2", "200", END_STREAM)], None), (vec![head("3", "200", 0), data(b"ok", END_STREAM)], None), (vec![head("1", "200", 0), data(b"ok", END_STREAM)], None),
            (vec![head("3", "200", 0), data(b"ok", 0), data(b"!!", 0)], None), (vec![head("3", "200", 0), data(b"ok", 0), trailers], None),
        ] {
            let (answer, end, _) = passed(&[&sent.concat()], false);
            assert_eq!((answer.split_once("\r\n\r\n").unwrap().1, end), (body.unwrap_or(""), if body.is_some() { End::Whole } else { End::Failed }), "{sent:?}");
        }
    }

    #[test]
    fn headers_set_go_as_they_are() {
        for (framing, want, end) in [(Framing { authority: false, ..GET }, "host: h", END_STREAM), (Framing { length: 2, ..GET }, ":authority: h", 0)] {
            crate::stream::block_on(async {
                let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
                tokio::task::spawn_local(upstream_framed(Stream::Pipe(up.into()), theirs, ("http", 4096, Slot::default()), framing));
                ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\nTE: trailers\r\n\r\n").await.unwrap();
                let mut got = Vec::new();
                let at = PREFACE.len() + 9 + 18 + 9 + 4;
                while got.len() < at + 9 || got.len() < at + 9 + u32::from_be_bytes([0, got[at], got[at + 1], got[at + 2]]) as usize { server.read_buf(&mut got).await.unwrap(); }
                assert_eq!((got[at + 3], got[at + 4]), (HEADERS, END_HEADERS | end));
                let len = u32::from_be_bytes([0, got[at], got[at + 1], got[at + 2]]) as usize;
                let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
                let fields = t.decode(&got[at + 9..at + 9 + len], len, (100, 100)).unwrap();
                let text: Vec<_> = fields.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
                assert!(text.contains(&want.to_string()) && text.contains(&"transfer-encoding: chunked".to_string()) && text.contains(&"te: trailers".to_string()), "{text:?}");
            });
        }
    }

    #[test]
    fn bodies_go_in_frames_every_server_takes() {
        for size in [0, 1, 100, 16384, 1 << 24] {
            crate::stream::block_on(async {
                let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
                tokio::task::spawn_local(upstream_framed(Stream::Pipe(up.into()), theirs, ("http", 4096, Slot::default()), Framing { length: 20000, ..GET }));
                ours.write_all(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 20000\r\n\r\n").await.unwrap();
                server.write_all(&framed(SETTINGS, 0, 0, &[&[0, 5][..], &u32::to_be_bytes(size)].concat())).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
                ours.write_all(&[b'x'; 20000]).await.unwrap();
                let (mut got, mut at, mut body) = (Vec::new(), PREFACE.len(), 0);
                loop {
                    assert!(crate::stream::within(Some(Duration::from_secs(1)), server.read_buf(&mut got)).await.is_some_and(|n| n.unwrap() > 0), "{size}");
                    while let Some(&[a, b, c, kind, flags, ..]) = got.get(at..at + 9) {
                        let len = u32::from_be_bytes([0, a, b, c]) as usize;
                        assert!(len <= 16384, "{size}");
                        (at, body) = (at + 9 + len, body + if kind == DATA { len } else { 0 });
                        if kind == DATA && flags == END_STREAM { assert_eq!(body, 20000, "{size}"); return }
                    }
                }
            });
        }
    }

    #[test]
    fn frames_at_random_end() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut random = move |n: usize| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; (seed % n as u64) as usize };
        let block = header_block(200, &[(b"x-a".to_vec(), b"b".to_vec())], false);
        crate::stream::block_on(async {
            for _ in 0..3000 {
                let mut sent = Vec::new();
                for _ in 0..random(8) {
                    match random(6) {
                        0 => frame(&mut sent, HEADERS, END_HEADERS, 1, &block),
                        1 => frame(&mut sent, DATA, 0, 1, b"data"),
                        2 => sent.extend(framed(DATA, PADDED, 1, &[2, 0, 0, 0])),
                        3 => frame(&mut sent, SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 1]),
                        _ => { let payload: Vec<u8> = (0..random(20)).map(|_| random(256) as u8).collect(); frame(&mut sent, random(11) as u8, random(256) as u8, random(3) as u32, &payload) }
                    }
                }
                for _ in 0..random(4) { if !sent.is_empty() { let at = random(sent.len()); sent[at] = random(256) as u8; } }
                let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
                let post = random(2) == 0;
                ours.write_all(if post { b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc" } else { b"GET / HTTP/1.1\r\nHost: h\r\n\r\n" }).await.unwrap();
                server.write_all(&sent).await.unwrap();
                let (server, ours) = match random(3) { 0 => { drop(server); (None, Some(ours)) } 1 => { drop(ours); (Some(server), None) } _ => { drop((server, ours)); (None, None) } };
                let framing = Framing { length: if post { 3 } else { 0 }, ..GET };
                let ended = crate::stream::within(Some(Duration::from_secs(1)), upstream_framed(Stream::Pipe(up.into()), theirs, ("http", 4096, Slot::default()), framing)).await;
                assert!(ended.is_some(), "{}", sent.escape_ascii());
                drop((server, ours));
            }
        });
    }

    #[test]
    fn bodies_come_so() {
        let (mut buf, mut to) = (b"abc".to_vec(), Vec::new());
        assert!(!Body::Length(5).take(&mut buf, &mut to));
        assert!(Body::Length(1).take(&mut b"xy".to_vec(), &mut to));
        let mut body = Body::Chunked(0, false);
        let mut buf = b"3\r\nab".to_vec();
        assert!(!body.take(&mut buf, &mut to));
        buf.extend_from_slice(b"c\r");
        assert!(!body.take(&mut buf, &mut to));
        buf.extend_from_slice(b"\n0\r\n\r\n");
        assert!(body.take(&mut buf, &mut to));
        assert_eq!(to, b"abcxabc");
    }

    fn told(pieces: &[&[u8]], bodiless: bool, closes: bool) -> Part {
        let (mut reply, mut all) = (Reply { buf: Vec::new(), bodiless, comes: None }, Part::default());
        for piece in pieces.iter().chain([&&b""[..]].into_iter().filter(|_| closes)) {
            let mut part = Part::default();
            reply.buf.extend_from_slice(piece);
            reply.take(&mut part, piece.is_empty());
            assert!(part.head.is_none() || all.head.is_none());
            all.head = part.head.or(all.head);
            all.data.extend(part.data);
            all.ended = part.ended;
            if all.ended.is_some() { break }
        }
        all
    }

    #[test]
    fn answers_are_taken_as_they_come() {
        let (length, chunks) = ("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n");
        let both = |end: &str| format!("{chunks}2\r\nab\r\n3\r\ncde\r\n{end}");
        let whole = |trailers: &[(&str, &str)]| Some(Ended::Whole(trailers.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()));
        let cut = || Some(Ended::Cut);
        for (answer, bodiless, data, open, ended) in [
            (format!("{length}abcde"), false, "abcde", None, whole(&[])),
            (format!("{length}abc"), false, "abc", None, cut()),
            (length.to_string(), false, "", None, cut()),
            (length.to_string(), true, "", whole(&[]), whole(&[])),
            (length.replace('5', "0"), false, "", whole(&[]), whole(&[])),
            ("HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n".into(), false, "", whole(&[]), whole(&[])),
            ("HTTP/1.1 304 Not Modified\r\n\r\n".into(), false, "", whole(&[]), whole(&[])),
            (both("0\r\n\r\n"), false, "abcde", None, whole(&[])),
            (both("0\r\nX-A: b\r\nY:c \r\n\r\n"), false, "abcde", None, whole(&[("X-A", "b"), ("Y", "c")])),
            (both(""), false, "abcde", None, cut()),
            (both("0\r\n"), false, "abcde", None, cut()),
            (both("0\r\nX-A: b\r\n"), false, "abcde", None, cut()),
            (format!("{chunks}0\r\n\r\n"), false, "", None, whole(&[])),
            ("HTTP/1.1 101 Switching Protocols\r\n\r\nab".into(), false, "ab", None, whole(&[])),
            ("HTTP/1.1 200 OK\r\n".into(), false, "", None, cut()),
            ("HTTP/1.1 200 OK\r\nbroken\r\n\r\n".into(), false, "", cut(), cut()),
            (String::new(), false, "", None, cut()),
        ] {
            let bytes = answer.as_bytes();
            let one = told(&[bytes], bodiless, true);
            assert_eq!((String::from_utf8_lossy(&one.data).as_ref(), &one.ended), (data, &ended), "{answer}");
            assert_eq!(told(&bytes.chunks(1).collect::<Vec<_>>(), bodiless, true), one, "{answer}");
            for at in 1..bytes.len() { assert_eq!(told(&[&bytes[..at], &bytes[at..]], bodiless, true), one, "{answer} {at}"); }
            let early = if matches!(&ended, Some(Ended::Whole(_))) && !answer.contains("101") { ended } else { open };
            if !bytes.is_empty() { assert_eq!(told(&[bytes], bodiless, false).ended, early, "{answer}"); }
        }
        assert_eq!(told(&[length.as_bytes()], true, false).head, Some((header_block(200, &[(b"Content-Length".to_vec(), b"5".to_vec())], false), false)));
        assert_eq!(told(&[chunks.as_bytes()], false, false).head, Some((header_block(200, &[(b"Content-Length".to_vec(), b"5".to_vec())], false), true)));
    }

    #[test]
    fn parts_are_sent_as_the_windows_let() {
        let part = |data: &[u8], ended| Part { head: None, data: data.to_vec(), ended };
        let whole = || Some(Ended::Whole(Vec::new()));
        let kinds = |out: &mut Vec<u8>| frames_in(&std::mem::take(out)).iter().map(|f| (f.0, f.1, f.3.len())).collect::<Vec<_>>();
        let start = |send: i64| {
            let (mut c, (taken, sent)) = (connection(), watch::channel(0));
            c.streams.insert(1, Open { send, ended: true, taken: Some(taken), ..Open::default() });
            c.answer(1, Part { head: Some((header_block(200, &[], false), false)), data: b"abc".to_vec(), ended: None });
            c.send_data();
            (c, sent)
        };
        let (mut c, _) = start(100);
        assert_eq!(kinds(&mut c.out), [(HEADERS, END_HEADERS, 1), (DATA, 0, 3)]);
        c.answer(1, part(b"de", whole()));
        c.send_data();
        assert_eq!((kinds(&mut c.out), c.streams.len()), (vec![(DATA, END_STREAM, 2)], 0));
        let (mut c, _) = start(2);
        c.answer(1, part(b"de", None));
        c.answer(1, part(b"", whole()));
        c.send_data();
        assert_eq!((kinds(&mut c.out), c.streams[&1].answer.as_deref()), (vec![(HEADERS, END_HEADERS, 1), (DATA, 0, 2)], Some(&b"cde"[..])));
        assert!(c.window_update(1, 100).is_ok());
        c.send_data();
        assert_eq!((kinds(&mut c.out), c.streams.len()), (vec![(DATA, END_STREAM, 3)], 0));
        for (ended, want) in [(whole(), vec![(DATA, END_STREAM, 0)]), (Some(Ended::Cut), vec![(RST_STREAM, 0, 4)])] {
            let (mut c, _) = start(100);
            c.out.clear();
            c.answer(1, part(b"", ended));
            c.send_data();
            assert_eq!((kinds(&mut c.out), c.streams.len()), (want, 0));
        }
        let (mut c, _) = start(2);
        c.answer(1, part(b"de", Some(Ended::Cut)));
        c.send_data();
        assert_eq!(kinds(&mut c.out), [(HEADERS, END_HEADERS, 1), (DATA, 0, 2)]);
        assert!(c.window_update(1, 100).is_ok());
        c.send_data();
        assert_eq!((kinds(&mut c.out), c.streams.len()), (vec![(DATA, 0, 3), (RST_STREAM, 0, 4)], 0));
        let mut c = connection();
        c.streams.insert(1, Open::default());
        c.answer(1, part(b"", Some(Ended::Cut)));
        assert_eq!((kinds(&mut c.out), c.streams.len()), (vec![(RST_STREAM, 0, 4)], 0));
        let (mut c, mut sent) = start(1 << 20);
        c.send = 1 << 20;
        c.answer(1, part(&vec![b'x'; WAITING - 4], None));
        c.send_data();
        assert!(!sent.has_changed().unwrap());
        c.answer(1, part(b"y", None));
        c.send_data();
        assert_eq!(*sent.borrow_and_update(), WAITING);
        c.streams.get_mut(&1).unwrap().send = 1;
        c.answer(1, part(&vec![b'x'; WAITING], None));
        c.send_data();
        assert_eq!(*sent.borrow_and_update(), WAITING + 1);
        assert_eq!(c.frame(RST_STREAM, 0, 1, &[0, 0, 0, 8]), Ok(()));
        assert!(sent.has_changed().is_err());
    }

    fn frames_in(mut buf: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut all = Vec::new();
        while buf.len() >= 9 {
            let end = 9 + u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < end { break }
            all.push((buf[3], buf[4], u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]), buf[9..end].to_vec()));
            buf = &buf[end..];
        }
        all
    }

    struct Client { s: tokio::net::TcpStream, buf: Vec<u8>, task: tokio::task::JoinHandle<()>, gives: bool }

    impl Client {
        async fn new(directives: &str, window: u32) -> Client {
            Client::new_by(&format!("http2 on; {directives}"), window).await
        }

        async fn new_by(http: &str, window: u32) -> Client {
            let (mut s, task) = served_by(http).await;
            let settings = framed(SETTINGS, 0, 0, &[&[0, 4][..], &window.to_be_bytes()].concat());
            s.write_all(&[PREFACE, &settings].concat()).await.unwrap();
            Client { s, buf: Vec::new(), task, gives: false }
        }

        async fn send(&mut self, frames: &[Vec<u8>]) {
            self.s.write_all(&frames.concat()).await.unwrap();
        }

        async fn get(&mut self, sid: u32, method: &str) {
            let block = [&[0x86, 0x84, 0x41, 0x01, b'h', 0x02, method.len() as u8], method.as_bytes()].concat();
            self.send(&[framed(HEADERS, END_HEADERS | END_STREAM, sid, &block)]).await;
        }

        async fn next(&mut self) -> Vec<(u8, u8, u32, Vec<u8>)> {
            loop {
                let frames = frames_in(&self.buf);
                self.buf.drain(..frames.iter().map(|f| 9 + f.3.len()).sum::<usize>());
                let given: Vec<_> = frames.iter().filter(|f| self.gives && f.0 == DATA && !f.3.is_empty()).flat_map(|f| [0, f.2].map(|sid| framed(WINDOW_UPDATE, 0, sid, &(f.3.len() as u32).to_be_bytes()))).collect();
                let _ = self.s.write_all(&given.concat()).await;
                let frames: Vec<_> = frames.into_iter().filter(|f| f.2 != 0).collect();
                if !frames.is_empty() { return frames }
                self.buf.reserve(1 << 18);
                if within(Some(Duration::from_secs(5)), self.s.read_buf(&mut self.buf)).await.expect("nothing comes").unwrap_or(0) == 0 { return frames }
            }
        }

        async fn all(&mut self, sid: u32) -> Vec<(u128, String)> {
            self.all_telling(sid, || ()).await
        }

        async fn all_telling(&mut self, sid: u32, mut seen: impl FnMut()) -> Vec<(u128, String)> {
            let (started, mut all) = (Instant::now(), Vec::new());
            loop {
                let frames = self.next().await;
                assert!(!frames.is_empty(), "closed after {all:?}");
                for (kind, flags, of, payload) in frames {
                    if of != sid { continue }
                    let text = match kind {
                        HEADERS => fields_of(&payload),
                        DATA => String::from_utf8(payload).unwrap(),
                        RST_STREAM => format!("reset {}", payload[3]),
                        _ => format!("{kind}"),
                    };
                    let end = kind == RST_STREAM || flags & END_STREAM != 0;
                    all.push((started.elapsed().as_millis(), format!("{text}{}", if end && kind != RST_STREAM { "|" } else { "" })));
                    seen();
                    if end { return all }
                }
            }
        }

        async fn close(self) {
            drop(self.s);
            within(Some(Duration::from_secs(2)), self.task).await.unwrap().unwrap();
        }
    }

    fn fields_of(block: &[u8]) -> String {
        let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        let fields = t.decode(block, block.len(), (4, 8192)).unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        fields.iter().filter(|f| !["server", "date", "content-type"].contains(&text(&f.0).as_str())).map(|f| format!("{}: {};", text(&f.0), text(&f.1))).collect()
    }

    fn texts(all: &[(u128, String)]) -> Vec<&str> {
        all.iter().map(|f| f.1.as_str()).collect()
    }

    fn got(pieces: &Pieces, closes: bool, directives: &str, method: &str) -> Vec<(u128, String)> {
        let (addr, _count) = plays(pieces, closes);
        crate::stream::block_on(async {
            let mut c = Client::new(&passing(addr, directives), 1 << 20).await;
            c.get(1, method).await;
            let all = c.all(1).await;
            c.close().await;
            all
        })
    }

    const OK: &str = ":status: 200;";
    const OK4: &str = ":status: 200;content-length: 4;";

    #[test]
    fn parts_of_answers_arrive_as_they_come() {
        let _busy = serving_on();
        let length = LENGTH.replace("30000", "4");
        let chunks = ["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"];
        at_once([
            (length.as_str(), &["ab", "c", "d"][..], [2, 3], false, "proxy_buffering off;", vec![OK4, "ab", "c", "d|"]),
            (CHUNKED, &chunks, [2, 3], false, "", vec![OK, "ab", "cd", "|"]),
            (CHUNKED, &chunks, [2, 3], false, "chunked_transfer_encoding off;", vec![OK, "ab", "cd", "|"]),
            (DELIMITED, &["ab", "cd", ""], [2, 3], true, "proxy_buffering off;", vec![OK, "ab", "cd", "|"]),
            (&length, &["ab", "c", "d"], [2, 3], false, "proxy_buffering off; add_trailer X $upstream_response_length;", vec![OK4, "ab", "c", "d", "x: 4;|"]),
            (CHUNKED, &chunks, [2, 3], false, "add_trailer X 1;", vec![OK, "ab", "cd", "x: 1;|"]),
            (&length, &["ab", "c", "d"], [1, 1], false, "", vec![OK4, "abcd|"]),
            (DELIMITED, &["ab", "cd", ""], [1, 1], true, "", vec![OK, "abcd|"]),
            (&length, &["", "ab", "cd"], [1, 2], false, "proxy_buffering off;", vec![OK4, "ab", "cd|"]),
        ], |(head, parts, waits, closes, directives, want)| {
            let seen = Arc::new((std::sync::Mutex::new(0), std::sync::Condvar::new()));
            let pieces: Vec<_> = after_head(head, parts, 0).into_iter().map(|p| p.1).zip([0].into_iter().chain(waits)).collect();
            let upstream_seen = seen.clone();
            let (addr, _told) = listening::<()>(move |_, mut s, _| {
                let (pieces, seen) = (pieces.clone(), upstream_seen.clone());
                std::thread::spawn(move || {
                    let mut got = Vec::new();
                    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                        let mut part = [0; 1024];
                        match std::io::Read::read(&mut s, &mut part) { Ok(n @ 1..) => got.extend_from_slice(&part[..n]), _ => return }
                    }
                    for (piece, wait) in pieces {
                        let (count, ready) = &*seen;
                        let held = ready.wait_timeout_while(count.lock().unwrap(), Duration::from_secs(30), |n| *n < wait).unwrap().1.timed_out();
                        if held || std::io::Write::write_all(&mut s, &piece).is_err() { return }
                    }
                    if !closes { let _ = std::io::Read::read(&mut s, &mut [0; 1]); }
                });
            });
            let all = crate::stream::block_on(async {
                let mut c = Client::new(&passing(addr, directives), 1 << 20).await;
                c.get(1, "GET").await;
                let all = c.all_telling(1, || { *seen.0.lock().unwrap() += 1; seen.1.notify_all(); }).await;
                c.close().await;
                all
            });
            assert_eq!(texts(&all), want, "{directives}");
        });
    }

    #[test]
    fn exchanges_that_go_cut_their_answers_off() {
        let told = std::cell::RefCell::new(Vec::new());
        let telling = || Telling { tell: |part: Part| told.borrow_mut().push(part.ended), ended: false };
        telling().tell(Part { ended: Some(Ended::Whole(Vec::new())), ..Part::default() });
        telling().tell(Part { data: b"a".to_vec(), ..Part::default() });
        assert_eq!(told.take(), [Some(Ended::Whole(Vec::new())), None, Some(Ended::Cut)]);
    }

    #[test]
    fn answers_of_streams_follow_one_another() {
        let mut c = connection();
        let opened = |exchange| Open { send: 100, ended: true, exchange, ..Open::default() };
        c.streams.extend([(1, opened(0)), (3, opened(1)), (5, opened(0))]);
        let part = |data: &[u8], ended| Told::Answer(Part { head: Some((header_block(200, &[], false), false)), data: data.to_vec(), ended });
        let whole = || Some(Ended::Whole(Vec::new()));
        c.told((5, 0, part(b"e", whole())));
        c.told((3, 0, part(b"old", whole())));
        c.told((1, 0, part(&[b'x'; 150], whole())));
        c.told((7, 0, part(b"gone", whole())));
        c.told((3, 1, part(b"c", None)));
        let sent: Vec<_> = frames_in(&c.out).iter().map(|f| (f.0, f.1, f.2, f.3.len())).collect();
        let head = sent[0].3;
        assert_eq!(sent, [(HEADERS, END_HEADERS, 5, head), (DATA, END_STREAM, 5, 1), (HEADERS, END_HEADERS, 1, head), (DATA, 0, 1, 100), (HEADERS, END_HEADERS, 3, head), (DATA, 0, 3, 1)]);
        assert_eq!(c.streams.keys().collect::<Vec<_>>(), [&1, &3]);
    }

    #[test]
    fn small_answers_come_in_one_write() {
        let _busy = serving_on();
        let length = LENGTH.replace("30000", "4");
        for (answer, directives, want) in [
            (format!("{length}abcd"), "", vec![OK4, "abcd|"]),
            (format!("{CHUNKED}4\r\nabcd\r\n0\r\n\r\n"), "", vec![OK, "abcd|"]),
            (format!("{CHUNKED}0\r\n\r\n"), "", vec![OK, "|"]),
            (LENGTH.replace("30000", "0"), "", vec![":status: 200;content-length: 0;|"]),
            (format!("{length}abcd"), "add_trailer X 1;", vec![OK4, "abcd", "x: 1;|"]),
            ("HTTP/1.1 304 Not Modified\r\n\r\n".into(), "", vec![":status: 304;|"]),
        ] {
            let (addr, _count) = plays(&vec![(0, answer.clone().into_bytes())], false);
            crate::stream::block_on(async {
                let mut c = Client::new(&passing(addr, directives), 1 << 20).await;
                c.get(1, "GET").await;
                let frames = c.next().await;
                let text: Vec<_> = frames.iter().map(|f| format!("{}{}", if f.0 == HEADERS { fields_of(&f.3) } else { String::from_utf8_lossy(&f.3).into_owned() }, if f.1 & END_STREAM != 0 { "|" } else { "" })).collect();
                assert_eq!(text, want, "{answer}");
                c.close().await;
            });
        }
        let all = got(&vec![(0, length.into_bytes())], false, "", "HEAD");
        assert!(all.len() == 1 && all[0].1.ends_with('|'), "{all:?}");
        for (head, method, want) in [("204 No Content", "GET", ":status: 204;|"), ("204 No Content\r\nContent-Length: 5", "GET", ":status: 204;|"), ("304 Not Modified\r\nContent-Length: 5", "GET", ":status: 304;content-length: 5;|"), ("200 OK\r\nContent-Length: 5", "HEAD", ":status: 200;content-length: 5;|"), ("200 OK", "HEAD", ":status: 200;|")] {
            let all = got(&vec![(0, format!("HTTP/1.1 {head}\r\n\r\n").into_bytes())], false, "", method);
            assert_eq!(texts(&all), [want], "{head}");
        }
    }

    #[test]
    fn answers_changed_by_gzip_arrive_as_they_come() {
        let _busy = serving_on();
        let log = log_path("h2-coded");
        let (a, b) = ("a".repeat(50), "b".repeat(50));
        let gz = member(&[&a, &b]);
        let bad = [&gz[1][..gz[1].len() - 8], b"12345678"].concat();
        let length = |n: usize| with_length(n, GZ);
        let (whole, half, with_bad) = (length(gz.concat().len()), length(gz[0].len() + 5), length(gz[0].len() + bad.len()));
        let end = format!("{b}|");
        for (head, pieces, closes, directives, want) in [
            (&whole, gz.clone(), false, "gunzip on; proxy_buffering off;", vec![OK, &a, &end]),
            (&length(30000), vec![gz[0].clone(), Vec::new()], true, "gunzip on; proxy_buffering off;", vec![OK, &a, "reset 2"]),
            (&half, vec![gz[0].clone(), gz[1][..5].to_vec()], false, "gunzip on; proxy_buffering off;", vec![OK, &a, "reset 2"]),
            (&with_bad, vec![gz[0].clone(), bad.clone()], false, "gunzip on; proxy_buffering off;", vec![OK, &a, "reset 2"]),
            (&with_bad, vec![[&gz[0][..], &bad].concat()], false, "gunzip on;", vec![OK, "reset 2"]),
            (&length(5), vec![gz[0][..5].to_vec()], false, "gunzip on;", vec![OK, "reset 2"]),
        ] {
            let all = got(&pieces_after(head, &pieces), closes, &format!("{directives} access_log {} f;", log.display()), "GET");
            let mut texts = texts(&all);
            let last = format!("{}|", texts[texts.len() - 2]);
            if texts.last() == Some(&"|") { texts.truncate(texts.len() - 2); texts.push(&last); }
            assert_eq!(texts, want, "{directives} {pieces:?}");
            let body: usize = want.iter().map(|w| w.trim_end_matches('|').len()).filter(|n| *n == 50).sum();
            let line = logged(&log);
            assert!(line.starts_with(&format!("200 {body} ")), "{line}");
        }
        let (addr, _count) = plays(&pieces_after(&with_length(100, ""), &[Vec::new(), a.clone().into_bytes(), b.clone().into_bytes()]), false);
        crate::stream::block_on(async {
            let mut c = Client::new(&passing(addr, &format!("gzip on; proxy_buffering off; access_log {} f;", log.display())), 1 << 20).await;
            let block = [&[0x82, 0x86, 0x84, 0x41, 0x01, b'h', 0x00, 15][..], b"accept-encoding", &[4], b"gzip"].concat();
            c.send(&[framed(HEADERS, END_HEADERS | END_STREAM, 1, &block)]).await;
            let (mut body, mut parts, mut ended) = (Vec::new(), Vec::new(), false);
            while !ended {
                for (kind, flags, _, payload) in c.next().await {
                    if kind == HEADERS { assert_eq!(fields_of(&payload), ":status: 200;content-encoding: gzip;"); }
                    if kind == DATA && !payload.is_empty() {
                        body.extend(payload);
                        let mut plain = Vec::with_capacity(1 << 10);
                        flate2::Decompress::new(false).decompress_vec(&body[10..], &mut plain, flate2::FlushDecompress::None).unwrap();
                        parts.push(String::from_utf8(plain).unwrap());
                    }
                    ended |= flags & END_STREAM != 0;
                }
            }
            parts.dedup();
            assert_eq!(parts, [String::new(), a.clone(), format!("{a}{b}")]);
            c.close().await;
            let line = logged(&log);
            assert!(line.starts_with(&format!("200 {} ", body.len())), "{line}");
        });
    }

    #[test]
    fn answers_cut_off_or_malformed_are_reset() {
        let _busy = serving_on();
        let (long, reset) = (":status: 200;content-length: 30000;", "reset 2");
        at_once([
            (LENGTH, &["ab", "cd", ""][..], true, "", vec![long, "abcd", reset]),
            (LENGTH, &["ab", "cd", ""], true, "proxy_buffering off;", vec![long, "ab", "cd", reset]),
            (LENGTH, &["ab"], true, "", vec![long, "ab", reset]),
            (LENGTH, &["", ""], true, "", vec![long, reset]),
            (CHUNKED, &["2\r\nab\r\n", "3\r\ncd", ""], true, "", vec![OK, "ab", "cd", reset]),
            (CHUNKED, &["2\r\nab\r\n", "0\r\n", ""], true, "", vec![OK, "ab", reset]),
            (CHUNKED, &["", ""], true, "", vec![OK, reset]),
            (CHUNKED, &["2\r\nab\r\n", ""], true, "add_trailer X 1;", vec![OK, "ab", reset]),
            (DELIMITED, &["ab", "cd"], false, "proxy_read_timeout 1s;", vec![OK, reset]),
            (DELIMITED, &["ab", "cd"], false, "proxy_buffering off; proxy_read_timeout 1s;", vec![OK, "ab", "cd", reset]),
            (CHUNKED, &["2\r\nab\r\n", "zz\r\nz"], false, "", vec![OK, "ab", reset]),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\nzz"], false, "", vec![OK, "ab", reset]),
            (CHUNKED, &["2\r\nab\r\nzz"], false, "", vec![reset]),
        ], |(head, pieces, closes, directives, want)| {
            let all = got(&after_head(head, pieces, 60), closes, directives, "GET");
            assert_eq!(texts(&all), want, "{head} {pieces:?}");
        });
    }

    #[test]
    fn trailers_of_servers_come_after_their_length() {
        let _busy = serving_on();
        let head = framed(HEADERS, END_HEADERS, 1, &header_block(200, &[(b"Content-Length".to_vec(), b"4".to_vec())], false));
        let mut block = Vec::new();
        literals(&mut block, [(b"x-t".to_vec(), b"1".to_vec())].iter());
        let trailer = framed(HEADERS, END_HEADERS | END_STREAM, 1, &block);
        for (last, want) in [(vec![framed(DATA, 0, 1, b"cd"), trailer], vec![OK4, "ab", "cd", "x-t: 1;|"]), (vec![framed(DATA, END_STREAM, 1, b"cd")], vec![OK4, "ab", "cd|"])] {
            let (addr, _came) = sends(&[[&head[..], &framed(DATA, 0, 1, b"ab")].concat(), last.concat()], false);
            crate::stream::block_on(async {
                let mut c = Client::new(&passing(addr, "proxy_http_version 2; proxy_pass_trailers on;"), 1 << 20).await;
                c.get(1, "GET").await;
                let all = c.all(1).await;
                assert_eq!(texts(&all).join(" ").replace(" |", "|"), want.join(" "));
                c.close().await;
            });
        }
    }

    #[test]
    fn large_answers_come_byte_for_byte_through_small_windows() {
        let _busy = serving_on();
        let data: Vec<u8> = (0..5usize << 20).map(|i| (i * 7 + i / 251) as u8).collect();
        let chunks: Vec<u8> = data.chunks(50_000).flat_map(|d| [format!("{:x}\r\n", d.len()).as_bytes(), d, b"\r\n"].concat()).chain(*b"0\r\n\r\n").collect();
        let length = LENGTH.replace("30000", &data.len().to_string());
        for (answer, closes) in [([length.as_bytes(), &data].concat(), false), ([CHUNKED.as_bytes(), &chunks].concat(), false), ([DELIMITED.as_bytes(), &data].concat(), true)] {
            let (addr, _count) = plays(&vec![(0, answer)], closes);
            crate::stream::block_on(async {
                let mut c = Client::new(&passing(addr, ""), 5000).await;
                c.gives = true;
                c.get(1, "GET").await;
                let (mut body, mut ended) = (Vec::new(), false);
                while !ended {
                    for (kind, flags, _, payload) in c.next().await {
                        assert!(kind == HEADERS || kind == DATA && payload.len() <= 5000);
                        if kind == DATA { body.extend(payload); }
                        ended |= flags & END_STREAM != 0;
                    }
                }
                assert!(body == data);
                c.close().await;
            });
        }
    }

    #[test]
    fn a_stream_without_window_holds_its_server_back_and_no_other() {
        let _busy = serving_on();
        let log = log_path("held");
        let size = 8 << 20;
        let (addr, count) = plays(&vec![(0, [LENGTH.replace("30000", &size.to_string()).as_bytes(), &vec![b'x'; size]].concat())], false);
        crate::stream::block_on(async {
            let mut c = Client::new(&passing(addr, &format!("proxy_max_temp_file_size 0; access_log {} f;", log.display())), 20000).await;
            c.send(&[framed(WINDOW_UPDATE, 0, 0, &(1u32 << 30).to_be_bytes())]).await;
            c.get(1, "GET").await;
            c.get(3, "GET").await;
            let mut came = [0, 0];
            while came[1] < size {
                for (kind, _, sid, payload) in c.next().await {
                    if kind != DATA { continue }
                    came[sid as usize / 2] += payload.len();
                    if sid == 3 { c.send(&[framed(WINDOW_UPDATE, 0, 3, &(payload.len() as u32).to_be_bytes())]).await; }
                }
            }
            assert_eq!(came[0], 20000);
            c.send(&[framed(WINDOW_UPDATE, 0, 1, &5000u32.to_be_bytes())]).await;
            while came[0] < 25000 { came[0] += c.next().await.iter().map(|f| f.3.len()).sum::<usize>(); }
            c.send(&[framed(RST_STREAM, 0, 1, &[0, 0, 0, 8])]).await;
            let started = Instant::now();
            while count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(1)); tokio::time::sleep(Duration::from_millis(5)).await; }
            c.close().await;
        });
        let text = logged(&log);
        let lines: Vec<Vec<usize>> = text.lines().map(|l| l.split(' ').take(6).map(|n| n.parse().unwrap()).collect()).collect();
        assert!(lines.len() == 2 && lines[0][1] == size && lines[0][4] == size, "{text}");
        assert!((25000..250_000).contains(&lines[1][1]) && lines[1][4] < 250_000, "{text}");
    }

    #[test]
    fn files_come_piece_by_piece() {
        let _busy = serving_on();
        let dir = files("h2");
        let http = format!("http2 on; {}", serves_files(&dir, "location / { index f; }"));
        let asks = |window| Client::new_by(&http, window);
        let body = |all: &[(u128, String)]| all[1..].iter().map(|f| f.1.trim_end_matches('|')).collect::<String>();
        for n in [0, 32767, 32768, 32769, 65536, 65537, 102_400, 1_000_000] {
            let data = letters(n);
            std::fs::write(dir.join("f"), &data).unwrap();
            for window in [1 << 21, 30_000] {
                crate::stream::block_on(async {
                    let mut c = asks(window).await;
                    c.gives = true;
                    for (sid, method) in [(1, "GET"), (3, "HEAD"), (5, "GET")] {
                        c.get(sid, method).await;
                        let all = c.all(sid).await;
                        assert!(all[0].1.contains(&format!("content-length: {n};")) && all.last().unwrap().1.ends_with('|'), "{n} {}", all[0].1);
                        assert!(body(&all).as_bytes() == if method == "GET" { &data[..] } else { b"" }, "{n} {window} {method}");
                    }
                    c.close().await;
                });
            }
        }
        std::fs::write(dir.join("f"), letters(4 << 20)).unwrap();
        crate::stream::block_on(async {
            let mut c = asks(0).await;
            c.get(1, "GET").await;
            assert!(c.next().await[0].0 == HEADERS);
            c.get(3, "HEAD").await;
            assert!(c.all(3).await.len() == 1);
            tokio::time::sleep(Duration::from_millis(100)).await;
            std::fs::File::options().write(true).open(dir.join("f")).unwrap().set_len(1 << 20).unwrap();
            c.gives = true;
            c.send(&[framed(WINDOW_UPDATE, 0, 1, &(1u32 << 20).to_be_bytes())]).await;
            let all: String = c.all(1).await.into_iter().map(|f| f.1).collect();
            assert!(all.ends_with("reset 2") && (1 << 20) - 32768 - 65535 <= all.len() && all.len() <= (1 << 20) + 7, "{}", all.len());
            c.close().await;
        });
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_client_that_takes_nothing_for_send_timeout_loses_its_connection() {
        let _busy = serving_on();
        let dir = files("h2-send");
        std::fs::write(dir.join("f"), letters(32 << 20)).unwrap();
        let http = format!("http2 on; send_timeout 1s; {}", serves_files(&dir, "location / { index f; }"));
        crate::stream::block_on(async {
            let mut c = Client::new_by(&http, 1 << 30).await;
            c.send(&[framed(WINDOW_UPDATE, 0, 0, &(1u32 << 30).to_be_bytes())]).await;
            c.get(1, "GET").await;
            let started = Instant::now();
            within(Some(Duration::from_secs(10)), &mut c.task).await.expect("still served").unwrap();
            assert!(started.elapsed() >= Duration::from_secs(1), "{:?}", started.elapsed());
        });
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exchanges_end_when_their_streams_go_away() {
        let _busy = serving_on();
        let log = log_path("away");
        let length = LENGTH.replace("30000", "60000000");
        let big = "x".repeat(8 << 20);
        for closes in [false, true] {
            for (pieces, directives, window, reads, status) in [
                (vec![(0, b"HTTP/1.1 200 OK\r\n".to_vec())], "", 1 << 20, 0, "499"),
                (vec![(0, length.clone().into_bytes())], "", 1 << 20, 0, "200"),
                (after_head(&length, &["ab"], 0), "", 1 << 20, 1, "200"),
                (after_head(CHUNKED, &["2\r\nab\r\n"], 0), "", 1 << 20, 1, "200"),
                (after_head(&length, &["ab", &"x".repeat(5000)], 0), "limit_rate 500;", 1 << 20, 1, "200"),
                (after_head(&length, &["ab", &big], 0), "", 1, 1, "200"),
            ] {
                let (addr, count) = plays(&pieces, false);
                crate::stream::block_on(async {
                    let mut c = Client::new(&passing(addr, &format!("{directives} access_log {} f;", log.display())), window).await;
                    c.get(1, "GET").await;
                    if reads == 0 { tokio::time::sleep(Duration::from_millis(60)).await; } else { assert!(!c.next().await.is_empty()); }
                    assert_eq!(count.lock().unwrap()[1], 0);
                    let mut left = None;
                    if closes { c.close().await; } else { c.send(&[framed(RST_STREAM, 0, 1, &[0, 0, 0, 8])]).await; left = Some(c); }
                    let started = Instant::now();
                    while count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(1), "{pieces:.0?}"); tokio::time::sleep(Duration::from_millis(1)).await; }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    let text = logged(&log);
                    assert!(text.starts_with(&format!("{status} ")) && text.lines().count() == 1, "{text}");
                    if let Some(mut c) = left {
                        c.send(&[framed(PING, 0, 0, b"12345678")]).await;
                        let mut answered = false;
                        while !answered { assert!(c.s.read_buf(&mut c.buf).await.unwrap() > 0); answered = frames_in(&c.buf).iter().any(|f| f.0 == PING); }
                        c.close().await;
                    }
                });
            }
        }
    }

    #[test]
    fn answers_are_paced_and_logged_without_their_chunks() {
        let _busy = serving_on();
        let log = log_path("streams");
        let (length, data) = (LENGTH.replace("30000", "5000"), "x".repeat(2500));
        let to_log = format!("access_log {} f;", log.display());
        at_once(["limit_rate 2000;", "limit_rate 2000; proxy_limit_rate 1m;"], |directives| {
            let all = got(&after_head(&length, &[&data, &data], 100), false, &format!("{directives} {to_log}"), "GET");
            let last = all.last().unwrap().0;
            assert!((600..3500).contains(&last) && all[1].0 < 300, "{:?}", all.iter().map(|f| (f.0, f.1.len())).collect::<Vec<_>>());
        });
        let _ = logged(&log);
        let body = |text: &str| text.split(' ').take(3).map(|n| n.parse::<usize>().unwrap()).collect::<Vec<_>>();
        let mut bytes = Vec::new();
        for (head, pieces, directives, data) in [
            (length.replace("5000", "4"), &["ab", "cd"][..], "", 4), (CHUNKED.to_string(), &["2\r\nab\r\n", "2\r\ncd\r\n0\r\n\r\n"], "", 4),
            (CHUNKED.to_string(), &["4\r\nabcd\r\n0\r\n\r\n"], "", 4), (length.replace("5000", "4"), &["ab", "cd"], "add_trailer Xyz 123;", 4),
            (CHUNKED.to_string(), &["2\r\nab\r\n", "zz\r\nz"], "", 2),
        ] {
            got(&after_head(&head, pieces, 30), false, &format!("{directives} {to_log}"), "GET");
            let line = body(&logged(&log));
            assert_eq!(line[..2], [200, data], "{head} {pieces:?}");
            bytes.push(line[2] - line[1]);
        }
        let content_length = "Content-Length: 4\r\n".len();
        assert_eq!(bytes[1..], [bytes[0] - content_length, bytes[0] - content_length, bytes[0] + "Xyz: 123\r\n".len(), bytes[0] - content_length]);
    }

    #[test]
    fn trailers_come_after_the_body() {
        let sent = |out: &[u8]| { let mut at = 0; std::iter::from_fn(|| { let len = u32::from_be_bytes([0, *out.get(at)?, out[at + 1], out[at + 2]]) as usize; let f = (out[at + 3], out[at + 4]); at += 9 + len; Some(f) }).collect::<Vec<_>>() };
        let trailer = |value: &[u8]| Some(vec![(b"X".to_vec(), value.to_vec())]);
        for (body, trailers, want) in [
            (&b"ab"[..], trailer(b"1"), vec![(HEADERS, END_HEADERS), (DATA, 0), (HEADERS, END_HEADERS | END_STREAM)]),
            (b"", trailer(b"1"), vec![(HEADERS, END_HEADERS), (HEADERS, END_HEADERS | END_STREAM)]),
            (b"", trailer(&[b'x'; 20000]), vec![(HEADERS, END_HEADERS), (HEADERS, END_STREAM), (CONTINUATION, END_HEADERS)]),
            (b"ab", Some(Vec::new()), vec![(HEADERS, END_HEADERS), (DATA, END_STREAM)]),
            (b"", Some(Vec::new()), vec![(HEADERS, END_HEADERS), (DATA, END_STREAM)]),
            (b"", None, vec![(HEADERS, END_HEADERS | END_STREAM)]),
        ] {
            let mut c = connection();
            c.streams.insert(1, Open { send: 65535, ended: true, ..Open::default() });
            let (chunked, trailers) = (trailers.is_some(), trailers.unwrap_or_default());
            c.answer(1, Part { head: Some((header_block(200, &[], false), chunked)), data: body.to_vec(), ended: Some(Ended::Whole(trailers)) });
            c.send_data();
            assert_eq!((sent(&c.out), c.streams.is_empty()), (want, true), "{body:?}");
        }
    }

    fn connection() -> Connection {
        let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits: (4, 8192), send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive: (2, Duration::from_secs(75), Duration::from_secs(3600)), priorities: CONCURRENT.max(100), refused: 0 }
    }

    #[test]
    fn priorities() {
        let mut c = connection();
        c.depend(3, 0, 16);
        c.depend(1, 3, 16);
        c.depend(5, 0, 256);
        assert_eq!((c.rank(1), c.rank(3), c.rank(5)), ((2, -1.0 / 256.0), (1, -1.0 / 16.0), (1, -1.0)));
        c.depend(3, 1, 16);
        assert_eq!((c.nodes[&1].0, c.nodes[&3].0), (0, 1));
        c.depend(7, 1 << 31, 16);
        assert_eq!((c.nodes[&1].0, c.nodes[&5].0, c.nodes[&7].0), (7, 7, 0));
        c.depend(9, 11, 16);
        assert_eq!(c.nodes[&9].0, 0);
    }

    #[test]
    fn too_many_refused_streams_end_the_connection() {
        let mut c = Connection { keepalive: (1000, Duration::from_secs(75), Duration::from_secs(3600)), ..connection() };
        let get = [0x82, 0x86, 0x84, 0x41, 0x01, b'h'];
        for sid in (1..=CONCURRENT as u32 * 2).step_by(2) { assert_eq!(c.frame(HEADERS, END_HEADERS | END_STREAM, sid, &get), Ok(())); }
        let first = CONCURRENT as u32 * 2 + 1;
        for sid in (first..first + (CONCURRENT as u32 + 1) * 2).step_by(2) { assert_eq!(c.frame(HEADERS, END_HEADERS | END_STREAM, sid, &get), Ok(())); }
        assert_eq!((c.streams.len(), c.refused), (CONCURRENT, CONCURRENT + 1));
        let last = first + (CONCURRENT as u32 + 1) * 2;
        assert_eq!((c.frame(HEADERS, END_HEADERS | END_STREAM, last, &get), c.last_sid), (Err(NO_ERROR), last));
    }

    #[test]
    fn early_errors() {
        let mut c = connection();
        let mut buf = Vec::new();
        frame(&mut buf, HEADERS, END_HEADERS, 1, &[0x82, 0x86]);
        buf.truncate(buf.len() - 1);
        assert_eq!(c.read(&mut buf), Ok(()));
        buf = vec![0, 0, 6, HEADERS, END_HEADERS, 0, 0, 0, 3, 0x42, 0xff, 0xff, 0xff, 0xff];
        assert_eq!((c.read(&mut buf), c.last_sid), (Err(COMPRESSION_ERROR), 3));
    }

    #[test]
    fn keepalive() {
        let goaway = |last: u32| { let mut f = Vec::new(); frame(&mut f, GOAWAY, 0, 0, &[last.to_be_bytes(), [0; 4]].concat()); f };
        let mut c = connection();
        let mut buf = Vec::new();
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        assert_eq!((c.read(&mut buf), c.goaway), (Ok(()), false));
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 3, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 5, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        assert_eq!(c.read(&mut buf), Ok(()));
        assert_eq!((c.goaway, c.last_sid, c.ready.clone(), c.streams[&3].number), (true, 3, vec![1, 3], 2));
        assert!(c.out.ends_with(&goaway(3)));
        for keepalive in [(9, Duration::ZERO, Duration::from_secs(9)), (9, Duration::from_secs(9), Duration::ZERO)] {
            let mut c = Connection { keepalive, started: Instant::now() - Duration::from_millis(1), ..connection() };
            assert_eq!(c.frame(HEADERS, END_HEADERS, 1, &[0x82]), Ok(()));
            assert_eq!(c.out, goaway(1));
        }
    }

    #[test]
    fn fields_after_a_refused_one() {
        let plain = |name: &[u8], value: &[u8]| [&[0, name.len() as u8][..], name, &[value.len() as u8], value].concat();
        let added = |name: &[u8], value: &[u8]| [&[0x40, name.len() as u8][..], name, &[value.len() as u8], value].concat();
        let decode = |block: &[u8]| { let mut dropped = false; let got = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE }.block(block, block.len(), (4, 8192), Some(&mut dropped)); (got.map(|b| b.ends.len()), dropped) };
        assert_eq!(decode(&[plain(b":method", b""), plain(b":path", b"/")].concat()), (Err(PROTOCOL_ERROR), true));
        assert_eq!(decode(&[plain(b":method", b""), added(b":path", b"/")].concat()), (Ok(2), true));
        assert_eq!(decode(&[plain(b":method", b"G"), plain(b":method", b"G"), plain(b"x", b"y")].concat()), (Ok(3), true));
        assert_eq!(decode(&[plain(b":method", b"G"), plain(b"x", b"")].concat()), (Ok(2), false));
        let mut seen = [false; 4];
        assert_eq!([drops(b":method", b"G", &mut seen), drops(b":path", b"", &mut seen), drops(b":method", b"G", &mut seen), drops(b":x", b"G", &mut seen), drops(b"a\x01", b"b", &mut seen)], [false, true, true, true, true]);
        let mut c = connection();
        let mut buf = Vec::new();
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 1, &[plain(b":method", b""), plain(b":path", b"/")].concat());
        assert_eq!(c.read(&mut buf), Err(PROTOCOL_ERROR));
        assert_eq!((c.ready.clone(), c.streams[&1].at_once, c.streams[&1].head.is_none()), (vec![1], true, true));
    }

    #[test]
    fn bodies_that_end_before_they_are_read() {
        let open = |c: &mut Connection, late: bool| {
            let mut buf = Vec::new();
            frame(&mut buf, HEADERS, END_HEADERS, 1, &[0x83, 0x86, 0x84, 0x41, 0x01, b'h']);
            frame(&mut buf, DATA, END_STREAM, 1, b"ab");
            if late { frame(&mut buf, DATA, END_STREAM, 1, b"c"); }
            assert_eq!(c.read(&mut buf), Ok(()));
            c.out.clear();
        };
        for late in [false, true] {
            let mut c = connection();
            open(&mut c, late);
            assert_eq!(c.streams[&1].early, Some(late));
            c.reading(1, Reading::Discarded);
            assert!(!c.streams[&1].ended && c.out.is_empty());
        }
        let mut c = connection();
        open(&mut c, true);
        c.reading(1, Reading::Buffered);
        assert!(c.streams.is_empty() && c.out.ends_with(&STREAM_CLOSED.to_be_bytes()));
        let mut c = connection();
        open(&mut c, false);
        c.reading(1, Reading::Buffered);
        assert!(c.streams[&1].ended && c.streams[&1].early.is_none());
    }

    #[test]
    fn declared_lengths() {
        for (data, flags) in [(&b"abc"[..], 0), (&b"a"[..], END_STREAM)] {
            let mut c = connection();
            let mut buf = Vec::new();
            frame(&mut buf, HEADERS, END_HEADERS, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h', 0x5c, 0x01, b'2']);
            frame(&mut buf, DATA, flags, 1, data);
            assert_eq!(c.read(&mut buf), Ok(()));
            let s = &c.streams[&1];
            assert_eq!((c.bad.clone(), s.bad, s.exchange, s.declared, s.chunked), (vec![1], true, 1, Some(2), false));
            let mut c = connection();
            c.streams.insert(1, Open { recv: PREREAD, declared: Some(2), reading: Some(Reading::Discarded), ..Open::default() });
            assert_eq!(c.data(flags, 1, data), Ok(()));
            assert!(c.bad.is_empty() && c.streams[&1].exchange == 0);
        }
    }

    #[test]
    fn body_windows() {
        let open = |c: &mut Connection| {
            let mut buf = Vec::new();
            frame(&mut buf, HEADERS, END_HEADERS, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
            frame(&mut buf, DATA, 0, 1, &[0; 1000]);
            assert_eq!(c.read(&mut buf), Ok(()));
            c.out.clear();
        };
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Buffered);
        assert_eq!(c.out, [&[0, 0, 4, WINDOW_UPDATE, 0, 0, 0, 0, 1][..], &((MAX_WINDOW - PREREAD + 1000) as u32).to_be_bytes()].concat());
        c.streams.get_mut(&1).unwrap().recv = MAX_WINDOW / 4 + 10;
        c.out.clear();
        assert_eq!(c.data(0, 1, &[0; 20]), Ok(()));
        assert_eq!(&c.out[9..], &((MAX_WINDOW - MAX_WINDOW / 4 + 10) as u32).to_be_bytes());
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Unbuffered);
        assert_eq!(&c.out[9..], &1000u32.to_be_bytes());
        c.out.clear();
        assert_eq!(c.data(0, 1, &[0; 7]), Ok(()));
        assert_eq!(&c.out[9..], &7u32.to_be_bytes());
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Discarded);
        assert_eq!(c.data(0, 1, &[0; 7]), Ok(()));
        assert!(c.out.is_empty());
        c.answer(1, Part { head: Some((header_block(204, &[], false), false)), data: Vec::new(), ended: Some(Ended::Whole(Vec::new())) });
        c.send_data();
        assert!(c.out.ends_with(&[0, 0, 4, RST_STREAM, 0, 0, 0, 0, 1, 0, 0, 0, 0]) && c.streams.is_empty());
    }

    #[test]
    fn frames() {
        let mut c = connection();
        let mut buf = Vec::new();
        frame(&mut buf, HEADERS, 0, 1, &[0x82, 0x86]);
        frame(&mut buf, CONTINUATION, END_HEADERS, 1, &[0x84, 0x41, 0x01, b'h']);
        frame(&mut buf, DATA, PADDED, 1, &[1, b'a', 0]);
        frame(&mut buf, DATA, END_STREAM, 1, b"b");
        frame(&mut buf, PING, 0, 0, b"12345678");
        frame(&mut buf, SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 10, 0, 5, 0, 0, 0x40, 0, 0, 1, 0, 0, 0, 0]);
        frame(&mut buf, WINDOW_UPDATE, 0, 1, &[0, 0, 0, 5]);
        buf.extend_from_slice(&[0, 0]);
        assert_eq!(c.read(&mut buf), Ok(()));
        assert_eq!((buf.len(), c.ready.clone(), c.frame_size, c.table_update), (2, vec![1], 16384, true));
        assert_eq!(c.streams[&1].block, 6);
        let s = c.streams.get_mut(&1).unwrap();
        let mut taker = s.taker.take().unwrap();
        let parts: Vec<_> = std::iter::from_fn(|| taker.try_recv().ok()).collect();
        assert_eq!((parts.concat(), s.body.is_none(), s.chunked, s.send), (b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n".to_vec(), true, true, 65535 - 65525 + 5));
        c.answer(1, Part { head: Some((header_block(200, &[(b"x".to_vec(), vec![b'y'; 20000])], false), false)), data: vec![b'z'; 20], ended: Some(Ended::Whole(Vec::new())) });
        c.send_data();
        assert_eq!(c.streams[&1].sent, 15);
        assert!(c.window_update(1, 10).is_ok());
        c.send_data();
        assert!(c.streams.is_empty());
        assert_eq!(c.window_update(0, MAX_WINDOW), Err(FLOW_CONTROL_ERROR));
        assert_eq!(c.frame(CONTINUATION, 0, 1, &[]), Err(PROTOCOL_ERROR));
        assert_eq!(c.frame(HEADERS, END_HEADERS, 1, &[0x82]), Err(PROTOCOL_ERROR));
        assert_eq!(c.frame(PING, 0, 0, &[]), Err(FRAME_SIZE_ERROR));
        assert_eq!(c.frame(SETTINGS, 0, 0, &[0, 5, 0, 0, 0, 1]), Err(PROTOCOL_ERROR));
    }

    #[test]
    fn priority_frames_are_limited() {
        let priority = framed(PRIORITY, 0, 1, &[0, 0, 0, 0, 16])[9..].to_vec();
        let mut c = connection();
        (1..CONCURRENT).for_each(|_| assert_eq!(c.frame(PRIORITY, 0, 1, &priority), Ok(())));
        assert_eq!(c.frame(PRIORITY, 0, 1, &priority), Err(ENHANCE_YOUR_CALM));
        let mut c = connection();
        assert_eq!(c.frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']), Ok(()));
        (1..2 * CONCURRENT).for_each(|_| assert_eq!(c.frame(PRIORITY, 0, 3, &priority), Ok(())));
        assert_eq!(c.frame(PRIORITY, 0, 3, &priority), Err(ENHANCE_YOUR_CALM));
    }

    fn asking(sid: u32, method: &str, path: &str, end: bool) -> Vec<u8> {
        let block = [&[0x86, 0x41, 0x01, b'h', 0x02, method.len() as u8], method.as_bytes(), &[0x04, path.len() as u8], path.as_bytes()].concat();
        framed(HEADERS, END_HEADERS | if end { END_STREAM } else { 0 }, sid, &block)
    }

    fn all_fields(block: &[u8]) -> String {
        let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        let fields = t.decode(block, block.len(), (4, 8192)).unwrap();
        fields.iter().filter(|f| f.0 != b"server" && f.0 != b"date").map(|f| format!("{}: {};", String::from_utf8_lossy(&f.0), String::from_utf8_lossy(&f.1))).collect()
    }

    #[test]
    fn answers_without_a_body_over_h2() {
        let _busy = serving_on();
        crate::stream::block_on(async {
            let mut c = Client::new("default_type text/plain; server { location /n { return 204; } location /m { return 304 abc; } location /p/ { return 204 abc; } }", 1 << 20).await;
            for (sid, method, path, want) in [(1, "GET", "/n", ":status: 204;"), (3, "HEAD", "/n", ":status: 204;"), (5, "GET", "/p/", ":status: 204;"), (7, "GET", "/m", ":status: 304;content-type: text/plain;content-length: 3;")] {
                c.send(&[asking(sid, method, path, true)]).await;
                let frames = c.next().await;
                assert_eq!((frames[0].0, frames[0].1 & END_STREAM, all_fields(&frames[0].3)), (HEADERS, END_STREAM, want.to_string()), "{path}");
            }
            c.close().await;
        });
        let (addr, _count) = plays(&after_head("HTTP/1.1 204 No Content\r\nContent-Type: text/x\r\nContent-Length: 5\r\nX-A: b\r\n\r\n", &[""], 0), false);
        crate::stream::block_on(async {
            let mut c = Client::new(&passing(addr, ""), 1 << 20).await;
            c.send(&[asking(1, "GET", "/", true)]).await;
            let frames = c.next().await;
            assert_eq!(all_fields(&frames[0].3), ":status: 204;x-a: b;");
            c.close().await;
        });
    }

    #[test]
    fn a_location_that_returns_answers_before_the_body() {
        let _busy = serving_on();
        crate::stream::block_on(async {
            let mut c = Client::new("server { location / { return 200 ok; } }", 1 << 20).await;
            c.send(&[asking(1, "POST", "/", false)]).await;
            assert_eq!(texts(&c.all(1).await), [":status: 200;content-length: 2;", "ok|"]);
            c.close().await;
        });
    }

    #[test]
    fn idle_connections_go_away_after_keepalive_timeout() {
        let _busy = serving_on();
        crate::stream::block_on(async {
            let mut c = Client::new("keepalive_timeout 1; server { location / { return 200 ok; } }", 1 << 20).await;
            c.get(1, "GET").await;
            c.all(1).await;
            let started = Instant::now();
            within(Some(Duration::from_secs(3)), c.s.read_to_end(&mut c.buf)).await.unwrap().unwrap();
            let goaway = frames_in(&c.buf).into_iter().find(|f| f.0 == GOAWAY).unwrap();
            assert_eq!(goaway.3, [1u32.to_be_bytes(), NO_ERROR.to_be_bytes()].concat());
            assert!(started.elapsed() >= Duration::from_millis(900), "{:?}", started.elapsed());
            c.close().await;
        });
    }

    #[test]
    fn fields_go_on_in_continuation_frames() {
        let block = [&[0x82, 0x86, 0x84, 0x00, 0x03][..], b"x-a", &[0x0a], b"abcde"].concat();
        let mut c = connection();
        let head = framed(HEADERS, END_STREAM, 1, &block);
        let frames = [&head[..head.len() - 2], &head[head.len() - 2..], &framed(CONTINUATION, END_HEADERS, 1, b"fghij")];
        let mut buf = Vec::new();
        for part in frames {
            buf.extend_from_slice(part);
            assert_eq!(c.read(&mut buf), Ok(()));
        }
        assert_eq!(c.ready, [1]);
        let mut c = connection();
        let head = framed(HEADERS, END_STREAM | END_HEADERS, 1, &block);
        assert_eq!(c.read(&mut head[..head.len() - 2].to_vec()), Err(FRAME_SIZE_ERROR));
    }
}
