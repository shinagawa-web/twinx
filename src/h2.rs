//! HTTP/2 (RFC 9113) on a connection without TLS that starts with its
//! preface, when http2 is on, as nginx's HTTP/2 module speaks it: its
//! settings, the header blocks it reads (HPACK, RFC 7541) and writes, its flow
//! control, and the errors it answers with. Each stream's request is passed,
//! as an HTTP/1 request of version HTTP/2.0, to a connection of its own over a
//! pipe in memory, and the answer that comes back is sent on the stream.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::conf::Config;
use crate::http::{Busy, Origin, Reading};
use crate::stream::Stream;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types, flags and error codes (RFC 9113, 6 and 7).
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
/// Not an error: a header block that has not come whole may still be one.
const AGAIN: u32 = u32::MAX;

/// The largest window, and nginx's settings: the window of a stream
/// (http2_body_preread_size), the streams at a time (http2_max_concurrent_streams).
const MAX_WINDOW: i64 = (1 << 31) - 1;
const PREREAD: i64 = 65536;
const CONCURRENT: usize = 128;
/// The largest HPACK table nginx keeps of what the client sends.
const TABLE_SIZE: usize = 4096;

type Fields = Vec<(Vec<u8>, Vec<u8>)>;
/// The listening, local and remote addresses of a connection, and its TLS session.
pub type Addrs = (SocketAddr, SocketAddr, SocketAddr, Option<Arc<crate::tls::Session>>);
/// What a stream is answered with: the status, the headers, the body and,
/// when trailers are expected, those made (add_trailer); none resets it.
type Answer = Option<(u16, Fields, Vec<u8>, Option<Fields>)>;
/// What an exchange tells of a stream: how its body is read, then its answer.
enum Told { Reading(Reading), Answer(Answer) }

/// HPACK's static table (RFC 7541, appendix A).
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

/// The Huffman code of each octet (RFC 7541, appendix B): the code and its length in bits.
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

/// The octet of each Huffman code, by its length and the code.
fn symbols() -> &'static HashMap<(u8, u32), u8> {
    static SYMBOLS: OnceLock<HashMap<(u8, u32), u8>> = OnceLock::new();
    SYMBOLS.get_or_init(|| HUFFMAN.iter().enumerate().map(|(c, &(code, len))| ((len, code), c as u8)).collect())
}

/// A string Huffman encoded, as nginx does it: only when that is shorter.
fn huffman(src: &[u8], lower: bool) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::with_capacity(src.len()), 0u64, 0);
    for &c in src {
        let (code, len) = HUFFMAN[usize::from(if lower { c.to_ascii_lowercase() } else { c })];
        (acc, bits) = (acc << len | u64::from(code), bits + len);
        while bits >= 8 { bits -= 8; out.push((acc >> bits) as u8); }
    }
    if bits > 0 { out.push((acc << (8 - bits)) as u8 | 0xff >> bits); }
    (out.len() < src.len()).then_some(out)
}

/// A Huffman encoded string decoded, as nginx decodes it: what is left after
/// the last octet is padding of ones, of whatever length, but not the code of EOS.
fn unhuffman(src: &[u8]) -> Option<Vec<u8>> {
    let (mut out, mut code, mut len) = (Vec::with_capacity(src.len() * 8 / 5), 0u32, 0u8);
    for bit in src.iter().flat_map(|b| (0..8).rev().map(move |i| u32::from(b >> i & 1))) {
        (code, len) = (code << 1 | bit, len + 1);
        if let Some(&c) = symbols().get(&(len, code)) { out.push(c); (code, len) = (0, 0); } else if len == 30 { return None }
    }
    (code == (1 << len) - 1).then_some(out)
}

/// An integer of a header block with a prefix of so many bits (RFC 7541, 5.1),
/// as nginx reads it: of four octets at most, or a compression error; one the
/// block ends in is a frame size error. The block has the length given, of
/// which what is given has come.
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

/// Writes an integer with a prefix of so many bits after the bits of first.
fn write_integer(out: &mut Vec<u8>, first: u8, bits: u8, mut value: usize) {
    let prefix = (1 << bits) - 1;
    if value < prefix { out.push(first | value as u8); return }
    out.push(first | prefix as u8);
    value -= prefix;
    while value >= 128 { out.push(value as u8 | 0x80); value >>= 7; }
    out.push(value as u8);
}

/// Writes a string, Huffman encoded when that is shorter.
fn write_string(out: &mut Vec<u8>, s: &[u8], lower: bool) {
    let huff = huffman(s, lower);
    let raw = |s: &[u8]| if lower { s.to_ascii_lowercase() } else { s.to_vec() };
    let (flag, s) = huff.map_or_else(|| (0, raw(s)), |h| (0x80, h));
    write_integer(out, flag, 7, s.len());
    out.extend_from_slice(&s);
}

/// The table of the fields the client added (RFC 7541, 2.3.2), newest first, as nginx keeps it.
#[derive(Clone)]
/// The dynamic table of a decoder: its fields, newest first, its size, what they use of it,
/// and the most a size update may make it, the size the decoder announced.
struct Table { entries: VecDeque<(Vec<u8>, Vec<u8>)>, size: usize, used: usize, limit: usize }

impl Table {
    fn field(&self, index: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        let fixed = |(n, v): (&str, &str)| (n.as_bytes().to_vec(), v.as_bytes().to_vec());
        if index <= STATIC.len() { return index.checked_sub(1).map(|i| fixed(STATIC[i])) }
        self.entries.get(index - STATIC.len() - 1).cloned()
    }

    fn evict(&mut self, size: usize) {
        while self.used > size { let (n, v) = self.entries.pop_back().unwrap_or_default(); self.used -= n.len() + v.len() + 32; }
    }

    /// Adds a field; one larger than the table empties it.
    fn add(&mut self, name: &[u8], value: &[u8]) {
        let size = name.len() + value.len() + 32;
        self.evict(self.size.saturating_sub(size));
        if size > self.size { return }
        self.entries.push_front((name.to_vec(), value.to_vec()));
        self.used += size;
    }

    /// The fields of a header block of the length given, of which what is given
    /// has come, or the connection error it is. Each field is at most the size
    /// of a buffer of large_client_header_buffers, and all of them the size of
    /// all those buffers.
    fn decode(&mut self, block: &[u8], length: usize, (number, size): (usize, usize)) -> Result<Fields, u32> {
        let (mut fields, mut at, mut left) = (Vec::new(), 0, number * size);
        let string = |at: &mut usize| -> Result<Vec<u8>, u32> {
            let huff = block.get(*at).ok_or(if *at < length { AGAIN } else { FRAME_SIZE_ERROR })? & 0x80 != 0;
            let len = integer(block, at, 7, length)?;
            if len > size { return Err(ENHANCE_YOUR_CALM) }
            if *at + len > length { return Err(FRAME_SIZE_ERROR) }
            let raw = block.get(*at..*at + len).ok_or(AGAIN)?;
            *at += len;
            if huff { unhuffman(raw).ok_or(COMPRESSION_ERROR) } else { Ok(raw.to_vec()) }
        };
        while at < block.len() {
            // An indexed field, a literal one added to the table, a table size update, or a literal one.
            let (bits, add) = match block[at] { 0x80.. => (7, false), 0x40.. => (6, true), 0x20.. => (5, false), _ => (4, false) };
            let index = integer(block, &mut at, bits, length)?;
            if bits == 5 {
                if index > self.limit { return Err(COMPRESSION_ERROR) }
                (self.size, _) = (index, self.evict(index));
                continue;
            }
            let (name, value) = if bits == 7 { self.field(index).ok_or(COMPRESSION_ERROR)? } else {
                let name = if index == 0 { string(&mut at)? } else { self.field(index).ok_or(COMPRESSION_ERROR)?.0 };
                if name.is_empty() { return Err(PROTOCOL_ERROR) }
                (name, string(&mut at)?)
            };
            left = left.checked_sub(name.len() + value.len()).ok_or(ENHANCE_YOUR_CALM)?;
            if add { self.add(&name, &value); }
            fields.push((name, value));
        }
        Ok(fields)
    }
}

/// The request of a stream as HTTP/1 writes it, without the empty line, with
/// the version HTTP/2.0, whether it has Content-Length, and how many of its
/// lines it makes; none for one nginx refuses with 400. The pseudo-header
/// fields give the request line and the host, and cookie fields are joined
/// into one, as nginx does.
fn request(fields: &[(Vec<u8>, Vec<u8>)], end: bool) -> Option<(Vec<u8>, bool, usize)> {
    let mut pseudo: [Option<&[u8]>; 4] = [None; 4];
    let (mut lines, mut cookies, mut host, mut length) = (Vec::new(), Vec::new(), None, None);
    for (name, value) in fields {
        let own = name.strip_prefix(b":");
        if own.unwrap_or(name).iter().any(|&c| c <= 0x20 || c == 0x7f || c == b':' || c.is_ascii_uppercase()) { return None }
        if value.iter().any(|c| matches!(c, 0 | b'\n' | b'\r')) { return None }
        if let Some(own) = own {
            let i = [&b"method"[..], b"scheme", b"path", b"authority"].iter().position(|p| *p == own)?;
            if pseudo[i].replace(value).is_some() || value.is_empty() { return None }
            continue;
        }
        match &name[..] { b"cookie" => { cookies.push(&value[..]); continue } b"host" => host = Some(&value[..]), b"content-length" => length = Some(&value[..]), _ => {} }
        lines.push((name, value));
    }
    let [Some(method), Some(scheme), Some(path), authority] = pseudo else { return None };
    let scheme_char = |(i, &c): (usize, &u8)| c.is_ascii_alphabetic() || i > 0 && (c.is_ascii_digit() || b"+-.".contains(&c));
    let valid = scheme.iter().enumerate().all(scheme_char) && path.iter().all(|&c| c > 0x20 && c != 0x7f);
    // Content-Length with a stream that has ended is a body that did not come.
    let missing = end && length.and_then(|l| std::str::from_utf8(l).ok()?.parse::<u64>().ok()).is_some_and(|n| n > 0);
    if !valid || missing || host.or(authority).is_none() || authority.zip(host).is_some_and(|(a, h)| a != h) { return None }
    let mut head = [method, b" ", path, b" HTTP/2.0\r\n"].concat();
    lines.iter().for_each(|(n, v)| head.extend([n, &b": "[..], v, b"\r\n"].concat()));
    if !cookies.is_empty() { head.extend([&b"cookie: "[..], &cookies.join(&b"; "[..]), b"\r\n"].concat()); }
    if let (Some(a), None) = (authority, host) { head.extend([&b"host: "[..], a, b"\r\n"].concat()); }
    Some((head, length.is_some(), usize::from(!cookies.is_empty()) + usize::from(host.is_none())))
}

/// The status and headers of an HTTP/1 answer's head, without those only
/// HTTP/1 connections have.
fn answer_head(head: &[u8]) -> Option<(u16, Fields)> {
    let mut lines = head.split(|&c| c == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let status = std::str::from_utf8(lines.next()?.split(|&c| c == b' ').nth(1)?).ok()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        let at = line.iter().position(|&c| c == b':')?;
        let (name, value) = (&line[..at], line[at + 1..].trim_ascii());
        if !["connection", "keep-alive", "transfer-encoding"].iter().any(|h| name.eq_ignore_ascii_case(h.as_bytes())) { headers.push((name.to_vec(), value.to_vec())); }
    }
    Some((status, headers))
}

/// The header block of an answer as nginx writes it: the status, then the
/// headers it has its own places for, added to the client's table, then the
/// others in order, their names in lower case.
fn header_block(status: u16, headers: &[(Vec<u8>, Vec<u8>)], table_update: bool) -> Vec<u8> {
    let mut out = Vec::new();
    if table_update { out.push(0x20); }
    match [200, 204, 206, 304, 400, 404, 500].iter().position(|&s| s == status) {
        Some(i) => out.push(0x88 + i as u8),
        None => out.extend(format!("\x48\x03{status:03}").bytes()),
    }
    const OWN: [(&str, u8); 6] = [("server", 54), ("date", 33), ("content-type", 31), ("content-length", 28), ("last-modified", 44), ("location", 46)];
    let mut placed = Vec::new();
    for (name, index) in OWN {
        let Some(i) = headers.iter().position(|h| h.0.eq_ignore_ascii_case(name.as_bytes())) else { continue };
        out.push(0x40 | index);
        if index == 28 { write_integer(&mut out, 0, 7, headers[i].1.len()); out.extend_from_slice(&headers[i].1); } else { write_string(&mut out, &headers[i].1, false); }
        placed.push(i);
    }
    literals(&mut out, headers.iter().enumerate().filter(|(i, _)| !placed.contains(i)).map(|(_, h)| h));
    out
}

/// Writes fields as literals not added to the table, their names in lower
/// case, as nginx writes the headers it has no place for and trailers.
fn literals<'a>(out: &mut Vec<u8>, fields: impl Iterator<Item = &'a (Vec<u8>, Vec<u8>)>) {
    for (name, value) in fields {
        out.push(0);
        write_string(out, name, true);
        write_string(out, value, false);
    }
}

/// Writes a header block in a HEADERS frame and as many CONTINUATION frames
/// as it takes, none larger than the client takes; the HEADERS frame ends the stream or not.
fn header_frames(out: &mut Vec<u8>, sid: u32, block: &[u8], frame_size: usize, end: bool) {
    let mut parts = block.chunks(frame_size).peekable();
    let mut kind = HEADERS;
    while let Some(part) = parts.next() {
        let flags = if parts.peek().is_none() { END_HEADERS } else { 0 } | if kind == HEADERS && end { END_STREAM } else { 0 };
        frame(out, kind, flags, sid, part);
        kind = CONTINUATION;
    }
}

/// The body of a chunked HTTP/1 answer twinx made, and its trailers.
fn unchunk(chunked: &[u8]) -> Option<(Vec<u8>, Fields)> {
    let (mut body, mut trailers, mut at) = (Vec::new(), Vec::new(), 0);
    let line = |at: &mut usize| -> Option<&[u8]> {
        let n = chunked.get(*at..)?.windows(2).position(|w| w == b"\r\n")?;
        *at += n + 2;
        Some(&chunked[*at - n - 2..*at - 2])
    };
    loop {
        let size = usize::from_str_radix(std::str::from_utf8(line(&mut at)?).ok()?, 16).ok()?;
        if size == 0 { break }
        body.extend_from_slice(chunked.get(at..at + size)?);
        at += size + 2;
    }
    while let Some(trailer) = line(&mut at).filter(|l| !l.is_empty()) {
        let colon = trailer.iter().position(|&c| c == b':')?;
        trailers.push((trailer[..colon].to_vec(), trailer[colon + 1..].trim_ascii().to_vec()));
    }
    Some((body, trailers))
}

/// Writes a frame.
fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, sid: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(payload);
}

/// A stream: the windows it sends and receives with, its request until it is
/// passed on (none for one refused with 400), where its body goes as it comes
/// until it ends, and what is to take it; the length the client declared of
/// it, how much came, whether it goes in chunks (it has no length), and
/// whether it turned out longer or shorter; then the body of the answer, how
/// much of it has been sent, and the header block of its trailers, sent after
/// it. Of the answers it may get, only that of the exchange so numbered is
/// taken. Until how its body is read is known, what comes of it is preread,
/// and its window is not updated. The length of its header block is that of
/// its request's head ($request_length), as in nginx.
#[derive(Default)]
struct Open {
    send: i64, recv: i64, head: Option<(Vec<u8>, bool, usize)>, ended: bool, reading: Option<Reading>,
    body: Option<UnboundedSender<Vec<u8>>>, taker: Option<UnboundedReceiver<Vec<u8>>>,
    declared: Option<u64>, got: u64, chunked: bool, bad: bool,
    answer: Option<Vec<u8>>, sent: usize, number: u64, exchange: u32, trailers: Option<Vec<u8>>, block: usize,
}

/// The state of an HTTP/2 connection.
struct Connection {
    out: Vec<u8>,
    streams: BTreeMap<u32, Open>,
    /// The streams whose request heads have come whole, to be passed on; those
    /// whose bodies turned out longer or shorter than declared, to be answered with 400.
    ready: Vec<u32>,
    bad: Vec<u32>,
    /// A header block that waits for its CONTINUATION frames: its stream, the
    /// flags of its HEADERS frame, what came of it, and whether the stream was refused.
    block: Option<(u32, u8, Vec<u8>, bool)>,
    last_sid: u32,
    table: Table,
    /// The stream each stream depends on (0: none), and its weight.
    nodes: HashMap<u32, (u32, u16)>,
    /// large_client_header_buffers of the default server of the address.
    limits: (usize, usize),
    /// The window the client gives the connection, and each new stream; the
    /// largest frame it takes; the window it has of the connection.
    send: i64,
    window: i64,
    frame_size: usize,
    recv: i64,
    /// Whether the client changed its table size: the next header block starts with an update to 0.
    table_update: bool,
    /// When the connection was made, the requests it has had, and whether it
    /// sent GOAWAY: it then takes no new stream and closes once those it has are answered.
    started: Instant,
    requests: u64,
    goaway: bool,
    /// keepalive_requests, keepalive_timeout and keepalive_time of the default server of the address.
    keepalive: (u64, Duration, Duration),
}

impl Connection {
    /// Makes a stream depend on another with a weight, as nginx's
    /// ngx_http_v2_set_dependency() does: on the root when the other is not
    /// known; a stream it depends on itself depends then on what it did;
    /// an exclusive dependency takes the other's dependents.
    fn depend(&mut self, sid: u32, on: u32, weight: u16) {
        let (exclusive, on) = (on >> 31 == 1, on & 0x7fff_ffff);
        let parent = if self.nodes.contains_key(&on) { on } else { 0 };
        let exclusive = exclusive && (parent != 0 || on == 0);
        if let Some(&(was, _)) = self.nodes.get(&sid).filter(|_| self.ancestors(parent).contains(&sid)) { self.nodes.entry(parent).and_modify(|n| n.0 = was); }
        if exclusive { self.nodes.values_mut().filter(|n| n.0 == parent).for_each(|n| n.0 = sid); }
        self.nodes.insert(sid, (parent, weight));
    }

    /// The streams a stream depends on, nearest first.
    fn ancestors(&self, mut sid: u32) -> Vec<u32> {
        let mut list = Vec::new();
        while let Some(&(parent, _)) = self.nodes.get(&sid).filter(|_| sid != 0 && list.len() <= self.nodes.len()) { list.push(parent); sid = parent; }
        list
    }

    /// Where nginx queues a stream's frames: by how deep it depends, then by
    /// its share of the weights, the larger first.
    fn rank(&self, sid: u32) -> (usize, f64) {
        let path = [&[sid][..], &self.ancestors(sid)].concat();
        let share = path.iter().filter_map(|s| self.nodes.get(s)).map(|n| f64::from(n.1) / 256.0).product::<f64>();
        (path.len() - 1, -share)
    }

    /// Sends GOAWAY without an error, with the last stream it has taken.
    fn goaway(&mut self) {
        frame(&mut self.out, GOAWAY, 0, 0, &[self.last_sid.to_be_bytes(), NO_ERROR.to_be_bytes()].concat());
        self.goaway = true;
    }

    fn rst(&mut self, sid: u32, code: u32) {
        frame(&mut self.out, RST_STREAM, 0, sid, &code.to_be_bytes());
        self.streams.remove(&sid);
    }

    /// Reads the frames that have come whole, or gives the connection error they are.
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

    /// The error a header block is before its HEADERS frame has come whole, as
    /// nginx, which reads it as it comes, finds it.
    fn early(&mut self, [kind, flags]: [u8; 2], sid: u32, p: &[u8], len: usize) -> Result<(), u32> {
        let skip = usize::from(flags & PADDED != 0) + if flags & PRIORITY_FLAG != 0 { 5 } else { 0 };
        if kind != HEADERS || self.block.is_some() || p.len() <= skip { return Ok(()) }
        let length = len.saturating_sub(skip + if flags & PADDED != 0 { usize::from(p[0]) } else { 0 });
        match self.table.clone().decode(&p[skip..p.len().min(skip + length)], length, self.limits) {
            Err(code) if code != AGAIN => { self.last_sid = sid; Err(code) }
            _ => Ok(()),
        }
    }

    fn frame(&mut self, kind: u8, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        // A header block goes on only in CONTINUATION frames of its stream.
        if self.block.as_ref().is_some_and(|b| kind != CONTINUATION || b.0 != sid) { return Err(PROTOCOL_ERROR) }
        if self.block.is_some() { return self.header_block(flags, p) }
        let size = match kind { PRIORITY => p.len() == 5, RST_STREAM | WINDOW_UPDATE => p.len() == 4, PING => p.len() == 8, GOAWAY => p.len() >= 8, _ => true };
        if !size { return Err(FRAME_SIZE_ERROR) }
        // Frames of a stream, of the connection, and those a client does not send.
        let stray = matches!(kind, PRIORITY | RST_STREAM) && sid == 0 || matches!(kind, PING | GOAWAY) && sid != 0 || matches!(kind, PUSH_PROMISE | CONTINUATION);
        let word = |at: usize| u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
        if stray || kind == PRIORITY && word(0) & 0x7fff_ffff == sid { return Err(PROTOCOL_ERROR) }
        match kind {
            DATA => self.data(flags, sid, p),
            HEADERS => self.headers(flags, sid, p),
            PRIORITY => { self.depend(sid, word(0), u16::from(p[4]) + 1); Ok(()) }
            SETTINGS => self.settings(flags, sid, p),
            WINDOW_UPDATE => self.window_update(sid, i64::from(word(0) & 0x7fff_ffff)),
            _ => {
                if kind == RST_STREAM { self.streams.remove(&sid); }
                if kind == PING && flags & ACK == 0 { frame(&mut self.out, PING, ACK, 0, p); }
                Ok(())
            }
        }
    }

    /// Adds a frame's part of the header block, and takes the request once it has come whole.
    fn header_block(&mut self, flags: u8, p: &[u8]) -> Result<(), u32> {
        let Some((sid, first, block, refused)) = self.block.take() else { return Ok(()) };
        self.block = Some((sid, first | flags, [&block[..], p].concat(), refused));
        if flags & END_HEADERS != 0 { self.headers_done() } else { Ok(()) }
    }

    fn headers(&mut self, flags: u8, sid: u32, p: &[u8]) -> Result<(), u32> {
        let (pad, priority) = (usize::from(flags & PADDED != 0), if flags & PRIORITY_FLAG != 0 { 5 } else { 0 });
        // A header block cannot be empty.
        if p.len() <= pad + priority { return Err(FRAME_SIZE_ERROR) }
        // After GOAWAY, a new stream is not taken.
        if self.goaway { return Ok(()) }
        let padding = if pad == 1 { usize::from(p[0]) } else { 0 };
        if padding > p.len() - pad - priority { return Err(PROTOCOL_ERROR) }
        let depends = (priority > 0).then(|| (u32::from_be_bytes([p[pad], p[pad + 1], p[pad + 2], p[pad + 3]]), u16::from(p[pad + 4]) + 1));
        if sid % 2 == 0 || sid <= self.last_sid || depends.is_some_and(|d| d.0 & 0x7fff_ffff == sid) { return Err(PROTOCOL_ERROR) }
        self.last_sid = sid;
        if depends.is_some() || !self.nodes.contains_key(&sid) { let (on, weight) = depends.unwrap_or((0, 16)); self.depend(sid, on, weight); }
        let refused = self.streams.len() >= CONCURRENT;
        // As in nginx, a stream that reaches keepalive_requests or keepalive_time,
        // or any with keepalive_timeout 0, is the last the connection takes.
        self.requests += u64::from(!refused);
        let (requests, timeout, time) = self.keepalive;
        if !refused && (timeout.is_zero() || self.requests >= requests || self.started.elapsed() > time) { self.goaway(); }
        self.block = Some((sid, flags, Vec::new(), refused));
        self.header_block(flags, &p[pad + priority..p.len() - padding])
    }

    /// Takes a request once its header block has come whole.
    fn headers_done(&mut self) -> Result<(), u32> {
        let Some((sid, flags, block, refused)) = self.block.take() else { return Ok(()) };
        let fields = self.table.decode(&block, block.len(), self.limits)?;
        if refused { self.rst(sid, REFUSED_STREAM); return Ok(()) }
        let ended = flags & END_STREAM != 0;
        // As nginx does, the request is passed on once its head has come, and its body as it comes.
        let head = request(&fields, ended);
        let declared = fields.iter().find(|f| f.0 == b"content-length").and_then(|f| std::str::from_utf8(&f.1).ok()?.parse().ok());
        let chunked = head.as_ref().is_some_and(|h| !h.1) && !ended;
        let (body, taker) = tokio::sync::mpsc::unbounded_channel();
        self.streams.insert(sid, Open { send: self.window, recv: PREREAD, head, ended, body: (!ended).then_some(body), taker: Some(taker), declared, chunked, number: self.requests, block: block.len(), ..Open::default() });
        self.ready.push(sid);
        Ok(())
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
        if s.ended { self.rst(sid, STREAM_CLOSED); return Ok(()) }
        let data = &p[usize::from(padding > 0)..p.len() - padding.saturating_sub(1)];
        (s.ended, s.got) = (flags & END_STREAM != 0, s.got + data.len() as u64);
        // A body longer than declared, or one that ends shorter, is answered with 400, as nginx does.
        if !s.bad && s.declared.is_some_and(|n| s.got > n || s.ended && s.got < n) { (s.bad, s.body, s.exchange) = (true, None, s.exchange + 1); self.bad.push(sid); }
        // Without a length, each frame's data is a chunk; the end, the last chunk.
        let mut part = if s.chunked && !data.is_empty() { [format!("{:x}\r\n", data.len()).as_bytes(), data, b"\r\n"].concat() } else { data.to_vec() };
        if s.chunked && s.ended { part.extend_from_slice(b"0\r\n\r\n"); }
        if let Some(body) = &s.body { let _ = body.send(part); }
        if s.ended { s.body = None; return Ok(()) }
        // As nginx does: a body read into buffers has the window opened as wide
        // as it goes, again once a quarter of it is left; one passed on as it
        // comes has what came given back; one preread or discarded, nothing.
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

    /// Learns how a stream's body is read, and opens its window as nginx does.
    fn reading(&mut self, sid: u32, reading: Reading) {
        let Some(s) = self.streams.get_mut(&sid) else { return };
        s.reading = Some(reading);
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

    /// Sends the head of a stream's answer, in HEADERS and CONTINUATION frames
    /// no larger than the client takes; a stream without an answer is reset.
    /// With trailers expected, the stream ends with them, after the body; as
    /// in nginx, when none were made after all, the last DATA frame ends it,
    /// an empty one for an empty body.
    fn answer(&mut self, sid: u32, answer: Answer) {
        if !self.streams.contains_key(&sid) { return }
        let Some((status, headers, body, trailers)) = answer else { return self.rst(sid, INTERNAL_ERROR) };
        let block = header_block(status, &headers, std::mem::take(&mut self.table_update));
        header_frames(&mut self.out, sid, &block, self.frame_size, body.is_empty() && trailers.is_none());
        if body.is_empty() && trailers.as_ref().is_some_and(|t| t.is_empty()) { frame(&mut self.out, DATA, END_STREAM, sid, &[]); }
        let trailers = trailers.filter(|t| !t.is_empty()).map(|t| { let mut block = Vec::new(); literals(&mut block, t.iter()); block });
        if let Some(s) = self.streams.get_mut(&sid) { (s.answer, s.trailers) = (Some(body), trailers); }
    }

    /// Sends what the windows let of the bodies of answers, in DATA frames no
    /// larger than the client takes, and forgets the streams answered whole.
    fn send_data(&mut self) {
        let mut order: Vec<_> = self.streams.keys().map(|&sid| (self.rank(sid), sid)).collect();
        order.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        for (_, sid) in order {
            let Some(s) = self.streams.get_mut(&sid) else { continue };
            let Some(body) = &s.answer else { continue };
            while s.sent < body.len() {
                let n = (body.len() - s.sent).min(self.frame_size).min(s.send.min(self.send).max(0) as usize);
                if n == 0 { break }
                let end = s.sent + n == body.len();
                frame(&mut self.out, DATA, if end && s.trailers.is_none() { END_STREAM } else { 0 }, sid, &body[s.sent..s.sent + n]);
                (s.sent, s.send, self.send) = (s.sent + n, s.send - n as i64, self.send - n as i64);
            }
            if let Some(block) = s.trailers.take_if(|_| s.sent == body.len()) { header_frames(&mut self.out, sid, &block, self.frame_size, true); }
        }
        // A stream answered whole before its request ended is reset without an error, as nginx does.
        let done: Vec<u32> = self.streams.iter().filter(|(_, s)| s.answer.as_ref().is_some_and(|b| s.sent == b.len())).map(|(&sid, _)| sid).collect();
        for sid in done {
            if self.streams.get(&sid).is_some_and(|s| !s.ended) { frame(&mut self.out, RST_STREAM, 0, sid, &NO_ERROR.to_be_bytes()); }
            self.streams.remove(&sid);
        }
    }
}

/// Serves an HTTP/2 connection, with what was read of it already, its
/// listening, local and remote addresses.
/// The connection counts as busy while it lives: a worker shutting down
/// gracefully sends GOAWAY on it, and waits until it has answered its streams.
pub async fn serve(config: Arc<Config>, mut stream: Stream, mut buf: Vec<u8>, addrs: Addrs, _busy: Option<Busy>) {
    let level = &crate::http::default_server(&config, addrs.0).level;
    let (limits, keepalive) = (level.large_header_buffers, (level.keepalive_requests, level.keepalive_timeout, level.keepalive_time));
    // lingering_close on or always: closing, it reads what the client still sends.
    let lingers = level.lingering_close.is_some();
    let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
    let mut c = Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits, send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive };
    // nginx's settings: the streams at a time, the window of each, the largest frame it takes; and the largest window of the connection.
    frame(&mut c.out, SETTINGS, 0, 0, &[0, 3, 0, 0, 0, CONCURRENT as u8, 0, 4, 0, 1, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff]);
    frame(&mut c.out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut preface = false;
    loop {
        if crate::http::shutting() && !c.goaway { c.goaway(); }
        let read = if preface { c.read(&mut buf) } else if buf.len() < PREFACE.len() { Ok(()) } else if buf.starts_with(PREFACE) { preface = true; buf.drain(..PREFACE.len()); c.read(&mut buf) } else { Err(PROTOCOL_ERROR) };
        let bad = std::mem::take(&mut c.bad).into_iter().map(|sid| (sid, true));
        for (sid, bad) in std::mem::take(&mut c.ready).into_iter().map(|sid| (sid, false)).chain(bad) {
            let Some(s) = c.streams.get_mut(&sid) else { continue };
            // A stream whose body turned out longer or shorter with its head is only answered with 400.
            if s.bad && !bad { continue }
            let (request, made, taker) = match s.head.take().filter(|_| !bad) {
                Some((mut head, _, made)) => {
                    if s.chunked { head.extend_from_slice(b"transfer-encoding: chunked\r\n"); }
                    ([head, b"\r\n".to_vec()].concat(), made + usize::from(s.chunked), s.taker.take())
                }
                // A line HTTP/1 refuses, for the answer nginx gives with 400.
                None => (b"-\r\n\r\n".to_vec(), 0, None),
            };
            let (tx, config, addrs, number) = (tx.clone(), config.clone(), addrs.clone(), s.exchange);
            let told = tx.clone();
            let origin = Origin { connected: c.started, number: s.number, made, length: s.block, reading: Some(Box::new(move |r| { let _ = told.send((sid, number, Told::Reading(r))); })) };
            tokio::task::spawn_local(async move { let _ = tx.send((sid, number, Told::Answer(exchange(config, request, taker, addrs, origin).await))); });
        }
        c.send_data();
        if let Err(code) = read {
            frame(&mut c.out, GOAWAY, 0, 0, &[c.last_sid.to_be_bytes(), code.to_be_bytes()].concat());
            let _ = stream.write_all(&c.out).await;
            let _ = stream.shutdown().await;
            return;
        }
        if !c.out.is_empty() && stream.write_all(&std::mem::take(&mut c.out)).await.is_err() { return }
        // After GOAWAY, the connection closes once its streams are answered.
        if c.goaway && c.streams.is_empty() { return crate::http::close(&mut stream, lingers).await }
        tokio::select! {
            n = stream.read_buf(&mut buf) => if n.unwrap_or(0) == 0 { return },
            Some((sid, number, told)) = rx.recv() => if c.streams.get(&sid).is_some_and(|s| s.exchange == number) {
                match told { Told::Reading(r) => c.reading(sid, r), Told::Answer(answer) => c.answer(sid, answer) }
            },
            () = crate::http::SHUTDOWN.notified() => {}
        }
    }
}

/// proxy_http_version 2: passes the HTTP/1 request that comes on a pipe to the
/// proxied server on a connection of its own, as the one stream of an HTTP/2
/// connection, and its answer back on the pipe, as HTTP/1 that ends when the
/// pipe closes; the trailers that follow it go in trailers. Whatever goes wrong closes both.
pub async fn upstream(mut up: Stream, mut pipe: tokio::io::DuplexStream, scheme: &str, trailers: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>) {
    let (mut buf, mut got) = (Vec::new(), Vec::new());
    let end = loop {
        if let Some(n) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break n }
        if pipe.read_buf(&mut buf).await.unwrap_or(0) == 0 { return }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut line = lines.next().unwrap_or_default().split(' ');
    let (method, path) = (line.next().unwrap_or_default(), line.next().unwrap_or_default());
    let mut fields = vec![(b":method".to_vec(), method.as_bytes().to_vec()), (b":scheme".to_vec(), scheme.as_bytes().to_vec()), (b":path".to_vec(), path.as_bytes().to_vec())];
    let mut body = Body::Length(0);
    // Those only HTTP/1 connections have are not passed.
    const DROPPED: &[&str] = &["connection", "keep-alive", "proxy-connection", "upgrade", "te"];
    for (name, value) in lines.filter_map(|l| l.split_once(':')).map(|(n, v)| (n.to_ascii_lowercase(), v.trim())).filter(|(n, _)| !DROPPED.contains(&n.as_str())) {
        match name.as_str() {
            "host" => fields.insert(2, (b":authority".to_vec(), value.as_bytes().to_vec())),
            "transfer-encoding" => body = Body::Chunked(0, false),
            _ => { if name == "content-length" { body = Body::Length(value.parse().unwrap_or(0)) } fields.push((name.into_bytes(), value.as_bytes().to_vec())) }
        }
    }
    buf.drain(..end + 4);
    let mut out = PREFACE.to_vec();
    // nginx's settings: no dynamic table, no pushes, and the window of a stream as large as it goes.
    frame(&mut out, SETTINGS, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0x7f, 0xff, 0xff, 0xff]);
    frame(&mut out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    let mut block = Vec::new();
    literals(&mut block, fields.iter());
    let mut ended = body == Body::Length(0);
    header_frames(&mut out, 1, &block, 16384, ended);
    // The windows the server gives the connection and the stream, the largest frame it takes, and the body to send.
    let (mut window, mut stream_window, mut frame_size, mut pending, mut finished) = (65535i64, 65535i64, 16384, Vec::new(), ended);
    let (mut table, mut answer) = (Table { entries: VecDeque::new(), size: 0, used: 0, limit: 0 }, None::<(u8, Vec<u8>)>);
    // Whether the head of the answer, not one of 1xx, has come: a header block after it has the trailers.
    let mut headed = false;
    loop {
        finished |= body.take(&mut buf, &mut pending);
        loop {
            let n = pending.len().min(frame_size).min(window.min(stream_window).max(0) as usize);
            let last = finished && n == pending.len();
            if ended || n == 0 && !last { break }
            ended = last;
            frame(&mut out, DATA, if ended { END_STREAM } else { 0 }, 1, &pending.drain(..n).collect::<Vec<_>>());
            (window, stream_window) = (window - n as i64, stream_window - n as i64);
        }
        if !out.is_empty() && up.write_all(&std::mem::take(&mut out)).await.is_err() { return }
        // A read takes as much as a buffer of nginx's proxy_buffer_size would.
        got.reserve(4096);
        tokio::select! {
            n = pipe.read_buf(&mut buf), if !finished => if n.unwrap_or(0) == 0 { return },
            n = up.read_buf(&mut got) => if n.unwrap_or(0) == 0 { return },
        }
        // What the frames of a read give is passed only once they all have been taken,
        // those after the end of the stream too, so that a stream reset with an error
        // drops what came with it, as nginx does.
        let (mut to_pipe, mut done, mut reset) = (Vec::new(), false, false);
        while got.len() >= 9 && got.len() >= 9 + (u32::from_be_bytes([0, got[0], got[1], got[2]]) as usize) {
            let (len, kind, flags, sid) = (u32::from_be_bytes([0, got[0], got[1], got[2]]) as usize, got[3], got[4], u32::from_be_bytes([got[5], got[6], got[7], got[8]]) & 0x7fff_ffff);
            let p: Vec<u8> = got.drain(..9 + len).skip(9).collect();
            match kind {
                SETTINGS if flags & ACK == 0 => {
                    for s in p.chunks(6).filter(|s| s.len() == 6) {
                        let value = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
                        match u16::from_be_bytes([s[0], s[1]]) { 4 => stream_window += i64::from(value) - 65535, 5 => frame_size = value as usize, _ => {} }
                    }
                    frame(&mut out, SETTINGS, ACK, 0, &[]);
                }
                PING if flags & ACK == 0 => frame(&mut out, PING, ACK, 0, &p),
                WINDOW_UPDATE => { let n = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff); if sid == 0 { window += n } else { stream_window += n } }
                HEADERS | CONTINUATION if sid == 1 => {
                    let (pad, priority) = if kind == HEADERS { (usize::from(flags & PADDED != 0), if flags & PRIORITY_FLAG != 0 { 5 } else { 0 }) } else { (0, 0) };
                    let padding = if pad == 1 { usize::from(p[0]) } else { 0 };
                    let (first, mut so_far) = answer.take().unwrap_or((flags, Vec::new()));
                    so_far.extend_from_slice(p.get(pad + priority..p.len() - padding).unwrap_or_default());
                    if flags & END_HEADERS == 0 { answer = Some((first, so_far)); continue }
                    let Ok(fields) = table.decode(&so_far, so_far.len(), (1000, 1 << 20)) else { return };
                    done |= first & END_STREAM != 0;
                    if headed {
                        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
                        trailers.lock().unwrap().extend(fields.iter().filter(|f| !f.0.starts_with(b":")).map(|(n, v)| (text(n), text(v))));
                        continue
                    }
                    let status = fields.iter().find(|f| f.0 == b":status").map(|f| String::from_utf8_lossy(&f.1).into_owned()).unwrap_or_default();
                    headed = !status.starts_with('1');
                    let mut head = format!("HTTP/1.1 {status} \r\n").into_bytes();
                    fields.iter().filter(|f| !f.0.starts_with(b":")).for_each(|(n, v)| head.extend([&n[..], b": ", v, b"\r\n"].concat()));
                    head.extend_from_slice(b"\r\n");
                    to_pipe.extend_from_slice(&head);
                }
                DATA if sid == 1 => {
                    let padding = if flags & PADDED != 0 { usize::from(p[0]) + 1 } else { 0 };
                    to_pipe.extend_from_slice(p.get(padding.min(1)..p.len() - padding.saturating_sub(1)).unwrap_or_default());
                    done |= flags & END_STREAM != 0;
                    // What was taken is given back to the windows.
                    if len > 0 { [0, 1].iter().for_each(|&sid| frame(&mut out, WINDOW_UPDATE, 0, sid, &(len as u32).to_be_bytes())); }
                }
                // A reset with NO_ERROR after the end of the stream is taken once; any other fails the answer.
                RST_STREAM if sid == 1 => { if p != [0; 4] || reset || !done { return } reset = true }
                // The connection going away ends the answer.
                _ => done |= kind == GOAWAY,
            }
        }
        if pipe.write_all(&to_pipe).await.is_err() || done { return }
    }
}

/// How the body of a request passed on a pipe comes: so many bytes, or in
/// chunks (what is left of the one it is in, and whether its line ends are to come).
#[derive(PartialEq)]
enum Body { Length(u64), Chunked(u64, bool) }

impl Body {
    /// Moves the data of what came of the body into what is to be sent, and tells whether it has all come.
    fn take(&mut self, buf: &mut Vec<u8>, to: &mut Vec<u8>) -> bool {
        loop {
            match self {
                Body::Length(left) => { let n = (*left).min(buf.len() as u64); to.extend(buf.drain(..n as usize)); *left -= n; return *left == 0 }
                Body::Chunked(left, _) if *left > 0 => { let n = (*left).min(buf.len() as u64); to.extend(buf.drain(..n as usize)); *left -= n; if *left > 0 { return false } *self = Body::Chunked(0, true) }
                Body::Chunked(_, crlf) => {
                    let Some(at) = buf.windows(2).position(|w| w == b"\r\n") else { return false };
                    let line: Vec<u8> = buf.drain(..at + 2).collect();
                    if *crlf { *crlf = false; continue }
                    let size = std::str::from_utf8(&line[..at]).ok().and_then(|l| u64::from_str_radix(l.split(';').next()?.trim(), 16).ok()).unwrap_or(0);
                    if size == 0 { return true }
                    *self = Body::Chunked(size, false);
                }
            }
        }
    }
}

/// Answers the request of a stream, as a connection of its own answers it,
/// one made when the HTTP/2 connection was, of which it is the request so
/// numbered; the request has so many header lines made, not sent by the client.
/// Its body is passed as it comes, while the answer is read.
async fn exchange(config: Arc<Config>, request: Vec<u8>, body: Option<UnboundedReceiver<Vec<u8>>>, (listen, local, peer, ssl): Addrs, origin: Origin) -> Answer {
    let (ours, theirs) = tokio::io::duplex(65536);
    tokio::task::spawn_local(async move { crate::http::connection(&config, Stream::Pipe(theirs), (listen, local, peer, ssl), Busy::new(), Some(Box::new(origin))).await });
    let (mut ours, mut to) = tokio::io::split(ours);
    tokio::task::spawn_local(async move {
        let _ = to.write_all(&request).await;
        let mut body = body;
        while let Some(part) = match body.as_mut() { Some(b) => b.recv().await, None => None } {
            if to.write_all(&part).await.is_err() { return }
        }
        let _ = to.shutdown().await;
    });
    let mut answer = Vec::new();
    let _ = ours.read_to_end(&mut answer).await;
    // An answer nginx would not send (444) resets the stream.
    let end = answer.windows(4).position(|w| w == b"\r\n\r\n")?;
    let body = answer.split_off(end + 4);
    let (status, headers) = answer_head(&answer[..end])?;
    // An answer with trailers comes chunked.
    const CHUNKED: &[u8] = b"\r\ntransfer-encoding: chunked";
    let chunked = answer[..end].windows(CHUNKED.len()).any(|w| w.eq_ignore_ascii_case(CHUNKED));
    if !chunked { return Some((status, headers, body, None)) }
    let (body, trailers) = unchunk(&body)?;
    Some((status, headers, body, Some(trailers)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huffman_codes() {
        assert_eq!(huffman(b"www.example.com", false).unwrap(), [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
        assert_eq!(huffman(b"{{{{{", false), None);
        assert_eq!(huffman(b"X-Sent-Foo", true), huffman(b"x-sent-foo", false));
        assert_eq!(unhuffman(&[0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]).unwrap(), b"www.example.com");
        // A whole octet of padding, which nginx takes; EOS, which it does not; padding that is not ones.
        assert_eq!(unhuffman(&[0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xff]).unwrap(), b"localhost");
        assert_eq!(unhuffman(&[0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(unhuffman(&[0x00]), None);
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
        assert_eq!(t.field(62), Some((b"x".to_vec(), b"y".to_vec())));
        assert_eq!(t.field(63), Some((b":authority".to_vec(), b"a.b".to_vec())));
        assert_eq!(t.decode(&[0x80], 1, (4, 8192)), Err(COMPRESSION_ERROR));
        assert_eq!(t.decode(&[0xc2], 1, (4, 8192)), Err(COMPRESSION_ERROR));
        assert_eq!(t.decode(&[0x40, 0x00, 0x00], 3, (4, 8192)), Err(PROTOCOL_ERROR));
        assert_eq!(t.decode(&[0x00, 0x03, b'a'], 3, (4, 8192)), Err(FRAME_SIZE_ERROR));
        assert_eq!(t.decode(&[0x00, 0x03, b'a', b'b', b'c', 0x00], 6, (1, 2)), Err(ENHANCE_YOUR_CALM));
        assert_eq!(t.decode(&[0x3f, 0xe2, 0x1f], 3, (4, 8192)), Err(COMPRESSION_ERROR));
        // Shrinking the table drops what does not fit; an entry larger than it empties it.
        assert_eq!(t.decode(&[0x3f, 0x03], 2, (4, 8192)), Ok(Vec::new()));
        assert_eq!((t.entries.len(), t.used), (1, 34));
        t.add(b"long name", b"long value");
        assert_eq!((t.entries.len(), t.used), (0, 0));
    }

    #[test]
    fn requests() {
        let f = |list: &[(&str, &str)]| list.iter().map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec())).collect::<Vec<_>>();
        let base = [(":method", "GET"), (":scheme", "http"), (":path", "/a?b"), (":authority", "h")];
        let (head, length, made) = request(&f(&[&base[..], &[("cookie", "a=b"), ("x-a", "1"), ("cookie", "c=d")]].concat()), true).unwrap();
        assert_eq!((String::from_utf8(head).unwrap().as_str(), length, made), ("GET /a?b HTTP/2.0\r\nx-a: 1\r\ncookie: a=b; c=d\r\nhost: h\r\n", false, 2));
        assert_eq!(request(&f(&[&base[..], &[("host", "h")]].concat()), true).unwrap().2, 0);
        assert!(request(&f(&[&base[..], &[("host", "h"), ("content-length", "1")]].concat()), false).unwrap().1);
        assert!(request(&f(&[&base[..], &[("content-length", "1")]].concat()), true).is_none());
        assert!(request(&f(&[&base[..], &[("host", "other")]].concat()), true).is_none());
        assert!(request(&f(&[&base[..], &[("X-A", "1")]].concat()), true).is_none());
        assert!(request(&f(&[&base[..], &[("x-a", "1\n")]].concat()), true).is_none());
        assert!(request(&f(&[&base[..], &[(":path", "/")]].concat()), true).is_none());
        assert!(request(&f(&[&base[..], &[(":other", "/")]].concat()), true).is_none());
        assert!(request(&f(&base[..3]), true).is_none());
        assert!(request(&f(&[base[0], (":scheme", "1x"), base[2], base[3]]), true).is_none());
    }

    #[test]
    fn answers() {
        let (status, headers) = answer_head(b"HTTP/1.1 301 Moved Permanently\r\nServer: twinx\r\nConnection: close\r\nX-A: b\r\nLocation: /x\r\nKeep-Alive: timeout=5").unwrap();
        assert_eq!((status, headers.len()), (301, 3));
        assert!(answer_head(b"HTTP/1.1").is_none());
        assert!(answer_head(b"HTTP/1.1 200 OK\r\nbroken").is_none());
        let block = header_block(status, &headers, true);
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
            let bridge = upstream(Stream::Pipe(up), theirs, "http", Default::default());
            let test = async {
                ours.write_all(b"POST /x HTTP/1.1\r\nHost: h\r\nConnection: close\r\nTransfer-Encoding: chunked\r\nX-A: b\r\n\r\n").await.unwrap();
                // The server lets only a byte of the body go at first.
                let mut out = Vec::new();
                frame(&mut out, SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 1, 0, 9, 0, 0, 0, 0]);
                frame(&mut out, PING, 0, 0, b"12345678");
                server.write_all(&out).await.unwrap();
                let mut got = Vec::new();
                let frames = |got: &[u8]| { let mut at = PREFACE.len(); std::iter::from_fn(|| { let len = u32::from_be_bytes([0, *got.get(at)?, *got.get(at + 1)?, *got.get(at + 2)?]) as usize; let f = (got.get(at + 3).copied()?, got.get(at + 4).copied()?, got.get(at + 9..at + 9 + len)?.to_vec()); at += 9 + len; Some(f) }).collect::<Vec<_>>() };
                while !frames(&got).iter().any(|f| f.0 == PING) { server.read_buf(&mut got).await.unwrap(); }
                ours.write_all(b"2\r\nab\r\n1;e\r\nc\r\n0\r\n\r\n").await.unwrap();
                while !frames(&got).iter().any(|f| f.0 == DATA) { server.read_buf(&mut got).await.unwrap(); }
                out.clear();
                frame(&mut out, WINDOW_UPDATE, 0, 1, &[0, 0, 0, 10]);
                server.write_all(&out).await.unwrap();
                while !frames(&got).iter().any(|f| f.0 == DATA && f.1 == END_STREAM) { server.read_buf(&mut got).await.unwrap(); }
                let sent = frames(&got);
                let kinds: Vec<_> = sent.iter().map(|f| (f.0, f.1)).collect();
                assert_eq!(kinds, [(SETTINGS, 0), (WINDOW_UPDATE, 0), (HEADERS, END_HEADERS), (SETTINGS, ACK), (PING, ACK), (DATA, 0), (DATA, END_STREAM)]);
                assert_eq!((&sent[5].2[..], &sent[6].2[..]), (&b"a"[..], &b"bc"[..]));
                let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
                let fields = t.decode(&sent[2].2, sent[2].2.len(), (100, 100)).unwrap();
                let text: Vec<_> = fields.iter().map(|(n, v)| format!("{}: {}", String::from_utf8_lossy(n), String::from_utf8_lossy(v))).collect();
                assert_eq!(text, [":method: POST", ":scheme: http", ":authority: h", ":path: /x", "x-a: b"]);
                // The answer, padded, in parts.
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
            let trailers = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let bridge = upstream(Stream::Pipe(up), theirs, "http", trailers.clone());
            let test = async {
                ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
                // An informational answer, the answer, and the trailers.
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
            assert_eq!(*trailers.lock().unwrap(), [("x-t".to_string(), "1".to_string())]);
        });
    }

    #[test]
    fn tables_without_room() {
        // A table of no size, as the bridge announces: updates to 0 only, and nothing is kept.
        let mut t = Table { entries: VecDeque::new(), size: 0, used: 0, limit: 0 };
        assert_eq!(t.decode(&[0x20, 0x48, 0x03, b'2', b'0', b'0'], 6, (10, 100)).unwrap(), [(b":status".to_vec(), b"200".to_vec())]);
        assert!(t.entries.is_empty() && t.field(62).is_none());
        assert_eq!(t.decode(&[0x21, 0x88], 2, (10, 100)), Err(COMPRESSION_ERROR));
    }

    #[test]
    fn resets_after_the_answer() {
        // What the server sends at once, and what the bridge passes of it.
        let answered = |rst: &[u32]| crate::stream::block_on(async {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let bridge = upstream(Stream::Pipe(up), theirs, "http", Default::default());
            let test = async {
                ours.write_all(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n").await.unwrap();
                let mut out = Vec::new();
                frame(&mut out, HEADERS, END_HEADERS, 1, &header_block(200, &[], false));
                frame(&mut out, DATA, END_STREAM, 1, b"ok");
                rst.iter().for_each(|code| frame(&mut out, RST_STREAM, 0, 1, &code.to_be_bytes()));
                server.write_all(&out).await.unwrap();
                let mut answer = Vec::new();
                ours.read_to_end(&mut answer).await.unwrap();
                String::from_utf8_lossy(&answer).into_owned()
            };
            tokio::join!(bridge, test).1
        });
        assert_eq!(answered(&[]), "HTTP/1.1 200 \r\n\r\nok");
        assert_eq!(answered(&[NO_ERROR]), "HTTP/1.1 200 \r\n\r\nok");
        assert_eq!(answered(&[NO_ERROR, NO_ERROR]), "");
        assert_eq!(answered(&[INTERNAL_ERROR]), "");
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

    #[test]
    fn trailers_come_after_the_body() {
        assert_eq!(unchunk(b"2\r\nab\r\n1\r\nc\r\n0\r\nX-A: b\r\nY:c \r\n\r\n"), Some((b"abc".to_vec(), vec![(b"X-A".to_vec(), b"b".to_vec()), (b"Y".to_vec(), b"c".to_vec())])));
        assert_eq!(unchunk(b"0\r\n\r\n"), Some((Vec::new(), Vec::new())));
        for broken in [&b"2\r\nab"[..], b"z\r\n", b"5\r\nab\r\n", b"0\r\nX\r\n\r\n"] { assert_eq!(unchunk(broken), None, "{broken:?}"); }
        // The kind and flags of each frame sent.
        let sent = |out: &[u8]| { let mut at = 0; std::iter::from_fn(|| { let len = u32::from_be_bytes([0, *out.get(at)?, out[at + 1], out[at + 2]]) as usize; let f = (out[at + 3], out[at + 4]); at += 9 + len; Some(f) }).collect::<Vec<_>>() };
        let trailer = |value: &[u8]| Some(vec![(b"X".to_vec(), value.to_vec())]);
        for (body, trailers, want) in [
            (&b"ab"[..], trailer(b"1"), vec![(HEADERS, END_HEADERS), (DATA, 0), (HEADERS, END_HEADERS | END_STREAM)]),
            (b"", trailer(b"1"), vec![(HEADERS, END_HEADERS), (HEADERS, END_HEADERS | END_STREAM)]),
            (b"", trailer(&[b'x'; 20000]), vec![(HEADERS, END_HEADERS), (HEADERS, END_STREAM), (CONTINUATION, END_HEADERS)]),
            // Expected, but none made.
            (b"ab", Some(Vec::new()), vec![(HEADERS, END_HEADERS), (DATA, END_STREAM)]),
            (b"", Some(Vec::new()), vec![(HEADERS, END_HEADERS), (DATA, END_STREAM)]),
            (b"", None, vec![(HEADERS, END_HEADERS | END_STREAM)]),
        ] {
            let mut c = connection();
            c.streams.insert(1, Open { send: 65535, ended: true, ..Open::default() });
            c.answer(1, Some((200, Vec::new(), body.to_vec(), trailers)));
            c.send_data();
            assert_eq!((sent(&c.out), c.streams.is_empty()), (want, true), "{body:?}");
        }
    }

    fn connection() -> Connection {
        let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits: (4, 8192), send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive: (2, Duration::from_secs(75), Duration::from_secs(3600)) }
    }

    #[test]
    fn priorities() {
        let mut c = connection();
        c.depend(3, 0, 16);
        c.depend(1, 3, 16);
        c.depend(5, 0, 256);
        assert_eq!((c.rank(1), c.rank(3), c.rank(5)), ((2, -1.0 / 256.0), (1, -1.0 / 16.0), (1, -1.0)));
        // Depending on its own dependent moves that one up; an exclusive dependency takes the others'.
        c.depend(3, 1, 16);
        assert_eq!((c.nodes[&1].0, c.nodes[&3].0), (0, 1));
        c.depend(7, 1 << 31, 16);
        assert_eq!((c.nodes[&1].0, c.nodes[&5].0, c.nodes[&7].0), (7, 7, 0));
        c.depend(9, 11, 16);
        assert_eq!(c.nodes[&9].0, 0);
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
        // keepalive_requests 2: the second stream is the last, and one after it is not taken.
        let mut c = connection();
        let mut buf = Vec::new();
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        assert_eq!((c.read(&mut buf), c.goaway), (Ok(()), false));
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 3, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        frame(&mut buf, HEADERS, END_HEADERS | END_STREAM, 5, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']);
        assert_eq!(c.read(&mut buf), Ok(()));
        assert_eq!((c.goaway, c.last_sid, c.ready.clone(), c.streams[&3].number), (true, 3, vec![1, 3], 2));
        assert!(c.out.ends_with(&goaway(3)));
        // keepalive_timeout 0 and keepalive_time: the first stream already is the last.
        for keepalive in [(9, Duration::ZERO, Duration::from_secs(9)), (9, Duration::from_secs(9), Duration::ZERO)] {
            let mut c = Connection { keepalive, started: Instant::now() - Duration::from_millis(1), ..connection() };
            assert_eq!(c.frame(HEADERS, END_HEADERS, 1, &[0x82]), Ok(()));
            assert_eq!(c.out, goaway(1));
        }
    }

    #[test]
    fn declared_lengths() {
        // A body longer than its Content-Length, or one that ends shorter, is answered anew, with 400.
        for (data, flags) in [(&b"abc"[..], 0), (&b"a"[..], END_STREAM)] {
            let mut c = connection();
            let mut buf = Vec::new();
            frame(&mut buf, HEADERS, END_HEADERS, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h', 0x5c, 0x01, b'2']);
            frame(&mut buf, DATA, flags, 1, data);
            assert_eq!(c.read(&mut buf), Ok(()));
            let s = &c.streams[&1];
            assert_eq!((c.bad.clone(), s.bad, s.exchange, s.declared, s.chunked), (vec![1], true, 1, Some(2), false));
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
        // Preread, then read into buffers: the window opens as wide as it goes, again when a quarter is left.
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Buffered);
        assert_eq!(c.out, [&[0, 0, 4, WINDOW_UPDATE, 0, 0, 0, 0, 1][..], &((MAX_WINDOW - PREREAD + 1000) as u32).to_be_bytes()].concat());
        c.streams.get_mut(&1).unwrap().recv = MAX_WINDOW / 4 + 10;
        c.out.clear();
        assert_eq!(c.data(0, 1, &[0; 20]), Ok(()));
        assert_eq!(&c.out[9..], &((MAX_WINDOW - MAX_WINDOW / 4 + 10) as u32).to_be_bytes());
        // Passed on as it comes: what came is given back, frame by frame.
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Unbuffered);
        assert_eq!(&c.out[9..], &1000u32.to_be_bytes());
        c.out.clear();
        assert_eq!(c.data(0, 1, &[0; 7]), Ok(()));
        assert_eq!(&c.out[9..], &7u32.to_be_bytes());
        // Discarded: nothing; and answered whole before it ended, the stream is reset without an error.
        let mut c = connection();
        open(&mut c);
        c.reading(1, Reading::Discarded);
        assert_eq!(c.data(0, 1, &[0; 7]), Ok(()));
        assert!(c.out.is_empty());
        c.answer(1, Some((204, Vec::new(), Vec::new(), None)));
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
        // The header block, of both frames, is the request's head.
        assert_eq!(c.streams[&1].block, 6);
        let s = c.streams.get_mut(&1).unwrap();
        // Without a length, the body goes on in chunks, one of each frame's data, then the last.
        let mut taker = s.taker.take().unwrap();
        let parts: Vec<_> = std::iter::from_fn(|| taker.try_recv().ok()).collect();
        assert_eq!((parts.concat(), s.body.is_none(), s.chunked, s.send), (b"1\r\na\r\n1\r\nb\r\n0\r\n\r\n".to_vec(), true, true, 65535 - 65525 + 5));
        c.answer(1, Some((200, vec![(b"x".to_vec(), vec![b'y'; 20000])], vec![b'z'; 20], None)));
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
}
