//! HTTP/2 (RFC 9113) on a connection without TLS that starts with its
//! preface, when http2 is on, as nginx's HTTP/2 module speaks it: its
//! settings, the header blocks it reads (HPACK, RFC 7541) and writes, its flow
//! control, and the errors it answers with. Each stream's request is passed,
//! as an HTTP/1 request of version HTTP/2.0, to a connection of its own over a
//! pipe in memory, and the answer that comes back is sent on the stream as it comes.

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
/// How much of an answer's body may wait for the client's windows before no more of it is taken.
const WAITING: usize = 65536;
/// The largest HPACK table nginx keeps of what the client sends.
const TABLE_SIZE: usize = 4096;

type Fields = Vec<(Vec<u8>, Vec<u8>)>;
/// The listening, local and remote addresses of a connection, this with its number in
/// error logs, and its TLS session.
pub type Addrs = (SocketAddr, SocketAddr, (SocketAddr, u64), Option<Arc<crate::tls::Session>>);
/// How an answer ended: whole, with the trailers that follow it, or cut off.
#[derive(Debug, PartialEq)]
enum Ended { Whole(Fields), Cut }
/// What has come of a stream's answer: at first the header block of its head, and whether
/// it comes in chunks, which trailers may follow; then so much of its body; at last
/// how it ended. One that ends without a head resets the stream.
#[derive(Debug, Default, PartialEq)]
struct Part { head: Option<(Vec<u8>, bool)>, data: Vec<u8>, ended: Option<Ended> }
/// What an exchange tells of a stream: how its body is read, then its answer, part by part.
enum Told { Reading(Reading), Answer(Part) }

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

/// The Huffman codes of each length: that, the first code, the end of them, as the first
/// bits of 32, and their octets, as the codes of a length follow one another.
fn symbols() -> &'static [(u32, u32, u32, Vec<u8>)] {
    static SYMBOLS: OnceLock<Vec<(u32, u32, u32, Vec<u8>)>> = OnceLock::new();
    SYMBOLS.get_or_init(|| (5..=30).filter_map(|len| {
        let mut of: Vec<_> = (0..=255u8).map(|c| (HUFFMAN[usize::from(c)], c)).filter(|(code, _)| u32::from(code.1) == len).map(|(code, c)| (code.0, c)).collect();
        of.sort();
        Some((len, of.first()?.0, (of.last()?.0 + 1) << (32 - len), of.into_iter().map(|(_, c)| c).collect()))
    }).collect())
}

/// Writes a string, Huffman encoded, as nginx does it, only when that is shorter.
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

/// Decodes a Huffman encoded string to the end of out, as nginx decodes it: what is left after
/// the last octet is padding of ones, of whatever length, but not the code of EOS.
fn unhuffman(src: &[u8], out: &mut Vec<u8>) -> bool {
    let (mut src, mut acc, mut bits) = (src.iter(), 0u64, 0u32);
    loop {
        while bits < 32 && let Some(&b) = src.next() { (acc, bits) = (acc << 8 | u64::from(b), bits + 8); }
        // The next 32 bits, of which those past the end are ones.
        let next = if bits < 32 { (acc << (32 - bits)) as u32 | u32::MAX >> bits } else { (acc >> (bits - 32)) as u32 };
        match symbols().iter().find(|s| next < s.2 && s.0 <= bits) {
            Some((len, first, _, octets)) => { out.push(octets[((next >> (32 - len)) - first) as usize]); bits -= len; }
            None => return bits < 30 && next == u32::MAX,
        }
    }
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

/// The table of the fields the client added (RFC 7541, 2.3.2), newest first, as nginx keeps it.
#[derive(Clone)]
/// The dynamic table of a decoder: its fields, newest first, its size, what they use of it,
/// and the most a size update may make it, the size the decoder announced.
struct Table { entries: VecDeque<(Vec<u8>, Vec<u8>)>, size: usize, used: usize, limit: usize }

/// The fields of a header block: their names and values, one after another, and where each of those ends.
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
    fn decode(&mut self, block: &[u8], length: usize, limits: (usize, usize)) -> Result<Fields, u32> {
        self.block(block, length, limits).map(|b| b.fields().map(|(n, v)| (n.to_vec(), v.to_vec())).collect())
    }

    /// The fields of a header block, as decode() gives them.
    fn block(&mut self, block: &[u8], length: usize, (number, size): (usize, usize)) -> Result<Block, u32> {
        let (mut fields, mut at, mut left) = (Block { bytes: Vec::with_capacity(256), ends: Vec::with_capacity(16) }, 0, number * size);
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
            // An indexed field, a literal one added to the table, a table size update, or a literal one.
            let (bits, add) = match block[at] { 0x80.. => (7, false), 0x40.. => (6, true), 0x20.. => (5, false), _ => (4, false) };
            let index = integer(block, &mut at, bits, length)?;
            if bits == 5 {
                if index > self.limit { return Err(COMPRESSION_ERROR) }
                (self.size, _) = (index, self.evict(index));
                continue;
            }
            let (to, start) = (&mut fields.bytes, fields.ends.last().map_or(0, |e| e.1));
            if index == 0 && bits != 7 { string(&mut at, to)?; } else { to.extend_from_slice(self.field(index).ok_or(COMPRESSION_ERROR)?.0); }
            let name = to.len();
            if bits == 7 { to.extend_from_slice(self.field(index).ok_or(COMPRESSION_ERROR)?.1); } else {
                if name == start { return Err(PROTOCOL_ERROR) }
                string(&mut at, to)?;
            }
            left = left.checked_sub(to.len() - start).ok_or(ENHANCE_YOUR_CALM)?;
            if add { self.add(&to[start..name], &to[name..]); }
            fields.ends.push((name, to.len()));
        }
        Ok(fields)
    }
}

/// Whether a field has a character in its name or value that nginx refuses.
fn refused(name: &[u8], value: &[u8]) -> bool {
    name.strip_prefix(b":").unwrap_or(name).iter().any(|&c| c <= 0x20 || c == 0x7f || c == b':' || c.is_ascii_uppercase()) || value.iter().any(|c| matches!(c, 0 | b'\n' | b'\r'))
}

/// The status of the head of a proxied server's answer; none when nginx refuses its
/// fields: the only pseudo-header field is :status, before the others, of three digits,
/// not one of 1xx but 103. Content-Length and Transfer-Encoding, of an answer, have no
/// spaces, which would be lost on the way.
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

/// The request of a stream as HTTP/1 writes it, without the empty line, with
/// the version HTTP/2.0, whether it has Content-Length, and how many of its
/// lines it makes; none for one nginx refuses with 400. The pseudo-header
/// fields give the request line and the host, and cookie fields are joined
/// into one, as nginx does.
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
    // A method has only upper case letters, "_" and "-", as ngx_http_v2_parse_method() checks.
    if !method.iter().all(|&c| c.is_ascii_uppercase() || c == b'_' || c == b'-') { return None }
    let scheme_char = |(i, &c): (usize, &u8)| c.is_ascii_alphabetic() || i > 0 && (c.is_ascii_digit() || b"+-.".contains(&c));
    let valid = scheme.iter().enumerate().all(scheme_char) && path.iter().all(|&c| c > 0x20 && c != 0x7f);
    // Content-Length with a stream that has ended is a body that did not come.
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

/// The status and headers of an HTTP/1 answer's head, without those only
/// HTTP/1 connections have.
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

/// The header block of an answer as nginx writes it: the status, then the
/// headers it has its own places for, added to the client's table, then the
/// others in order, their names in lower case.
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

/// Writes fields as literals not added to the table, their names in lower
/// case, as nginx writes the headers it has no place for and trailers.
fn literals<'a, T: AsRef<[u8]> + 'a>(out: &mut Vec<u8>, fields: impl Iterator<Item = &'a (T, T)>) {
    for (name, value) in fields {
        out.push(0);
        write_string(out, name.as_ref(), true);
        write_string(out, value.as_ref(), false);
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
/// whether it turned out longer or shorter; then, once the head of the answer
/// has been sent, what came of its body, how much of that has been sent, how it
/// ended, and whether a frame has ended the stream; the exchange is told how much of
/// the body has been sent in all, some of it later, and that the stream has gone. Of the answers it may get, only that of the exchange so numbered is
/// taken. Until how its body is read is known, what comes of it is preread,
/// and its window is not updated. The length of its header block is that of
/// its request's head ($request_length), as in nginx.
#[derive(Default)]
struct Open {
    send: i64, recv: i64, head: Option<(Vec<u8>, bool, usize)>, ended: bool, reading: Option<Reading>,
    body: Option<UnboundedSender<Vec<u8>>>, taker: Option<UnboundedReceiver<Vec<u8>>>,
    declared: Option<u64>, got: u64, chunked: bool, bad: bool,
    answer: Option<Vec<u8>>, sent: usize, end: Option<Ended>, closed: bool, taken: Option<watch::Sender<usize>>, untold: usize,
    number: u64, exchange: u32, block: usize,
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
    /// How many more PRIORITY frames it takes: nginx's priority_limit, which each stream raises.
    priorities: usize,
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
        // A field may go on in a CONTINUATION frame when this one does not end the block.
        let whole = if flags & END_HEADERS != 0 { length } else { usize::MAX };
        match self.table.clone().decode(&p[skip..p.len().min(skip + length)], whole, self.limits) {
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

    /// Adds a frame's part of the header block, and takes the request once it has come whole.
    fn header_block(&mut self, flags: u8, p: &[u8]) -> Result<(), u32> {
        let Some((_, first, block, _)) = &mut self.block else { return Ok(()) };
        *first |= flags;
        block.extend_from_slice(p);
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
        if !refused { self.priorities += CONCURRENT; }
        let (requests, timeout, time) = self.keepalive;
        if !refused && (timeout.is_zero() || self.requests >= requests || self.started.elapsed() > time) { self.goaway(); }
        self.block = Some((sid, flags, Vec::new(), refused));
        self.header_block(flags, &p[pad + priority..p.len() - padding])
    }

    /// Takes a request once its header block has come whole.
    fn headers_done(&mut self) -> Result<(), u32> {
        let Some((sid, flags, block, refused)) = self.block.take() else { return Ok(()) };
        let fields = self.table.block(&block, block.len(), self.limits)?;
        if refused { self.rst(sid, REFUSED_STREAM); return Ok(()) }
        let ended = flags & END_STREAM != 0;
        // As nginx does, the request is passed on once its head has come, and its body as it comes.
        let head = request(fields.fields(), ended);
        let declared = fields.fields().find(|f| f.0 == b"content-length").and_then(|f| std::str::from_utf8(f.1).ok()?.parse().ok());
        let chunked = head.as_ref().is_some_and(|h| !h.1) && !ended;
        let (body, taker) = (!ended).then(tokio::sync::mpsc::unbounded_channel).unzip();
        self.streams.insert(sid, Open { send: self.window, recv: PREREAD, head, ended, body, taker, declared, chunked, number: self.requests, block: block.len(), ..Open::default() });
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
        // A body longer than declared, or one that ends shorter, is answered with 400, as nginx does; one discarded is not looked at.
        if !s.bad && s.reading != Some(Reading::Discarded) && s.declared.is_some_and(|n| s.got > n || s.ended && s.got < n) { (s.bad, s.body, s.exchange) = (true, None, s.exchange + 1); self.bad.push(sid); }
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

    /// Takes what has come of a stream's answer: sends its head, in HEADERS and
    /// CONTINUATION frames no larger than the client takes, and keeps the rest to be
    /// sent as the windows let; a stream without an answer is reset. The HEADERS
    /// frame ends the stream of an answer that is whole, has no body and is not in chunks.
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

    /// Takes what an exchange tells of a stream, unless it is not the one whose answer
    /// the stream gets, and sends what the windows let of it.
    fn told(&mut self, (sid, number, told): (u32, u32, Told)) {
        if self.streams.get(&sid).is_none_or(|s| s.exchange != number) { return }
        match told { Told::Reading(r) => self.reading(sid, r), Told::Answer(part) => { self.answer(sid, part); self.send(sid); } }
    }

    /// Sends what the windows let of the bodies of answers, in DATA frames no larger
    /// than the client takes, and forgets the streams answered whole. The last DATA
    /// frame ends the stream of one that is whole, an empty one when that shows only
    /// later, and its trailers if it has any; one cut off is reset, as in nginx.
    fn send_data(&mut self) {
        let waits = |s: &Open| s.answer.as_ref().is_some_and(|body| s.sent < body.len() || s.end.is_some());
        let mut order: Vec<_> = self.streams.iter().filter(|(_, s)| waits(s)).map(|(&sid, _)| (self.rank(sid), sid)).collect();
        order.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        order.into_iter().for_each(|(_, sid)| self.send(sid));
    }

    /// Sends what the windows let of the body of a stream's answer.
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
        // The exchange waits for that only when, for all it knows, too much waits.
        let held = s.untold > 0 && s.untold + body.len() - s.sent >= WAITING;
        if let Some(taken) = s.taken.as_ref().filter(|_| held) { taken.send_modify(|t| *t += std::mem::take(&mut s.untold)); }
        if s.sent < body.len() { return }
        // What has been sent is not kept.
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
        // A stream answered whole before its request ended is reset without an error, as nginx does.
        if !s.ended { frame(&mut self.out, RST_STREAM, 0, sid, &NO_ERROR.to_be_bytes()); }
        self.streams.remove(&sid);
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
    let send = crate::http::send_timeout(level);
    let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
    let mut c = Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits, send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive, priorities: CONCURRENT.max(100) };
    // nginx's settings: the streams at a time, the window of each, the largest frame it takes; and the largest window of the connection.
    frame(&mut c.out, SETTINGS, 0, 0, &[0, 3, 0, 0, 0, CONCURRENT as u8, 0, 4, 0, 1, 0, 0, 0, 5, 0, 0xff, 0xff, 0xff]);
    frame(&mut c.out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut preface = false;
    // As in nginx (tcp_nodelay), what is written does not wait for the client to acknowledge what was before.
    if let Some(tcp) = stream.tcp().filter(|_| level.tcp_nodelay) { let _ = tcp.set_nodelay(true); }
    loop {
        if crate::http::shutting() && !c.goaway { c.goaway(); }
        let read = if preface { c.read(&mut buf) } else if buf.len() < PREFACE.len() { Ok(()) } else if buf.starts_with(PREFACE) { preface = true; buf.drain(..PREFACE.len()); c.read(&mut buf) } else { Err(PROTOCOL_ERROR) };
        // One answered in part already is reset, as nginx does.
        let (bad, answered): (Vec<u32>, Vec<u32>) = std::mem::take(&mut c.bad).into_iter().partition(|sid| c.streams.get(sid).is_none_or(|s| s.answer.is_none()));
        answered.into_iter().for_each(|sid| c.rst(sid, INTERNAL_ERROR));
        let bad = bad.into_iter().map(|sid| (sid, true));
        for (sid, bad) in std::mem::take(&mut c.ready).into_iter().map(|sid| (sid, false)).chain(bad) {
            let Some(s) = c.streams.get_mut(&sid) else { continue };
            // A stream whose body turned out longer or shorter with its head is only answered with 400.
            if s.bad && !bad { continue }
            let (request, made, taker) = match s.head.take().filter(|_| !bad) {
                Some((mut head, _, made)) => {
                    if s.chunked { head.extend_from_slice(b"transfer-encoding: chunked\r\n"); }
                    head.extend_from_slice(b"\r\n");
                    (head, made + usize::from(s.chunked), s.taker.take())
                }
                // A line HTTP/1 refuses, for the answer nginx gives with 400.
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
        if let Err(code) = read {
            frame(&mut c.out, GOAWAY, 0, 0, &[c.last_sid.to_be_bytes(), code.to_be_bytes()].concat());
            let _ = stream.write_all(&c.out).await;
            let _ = stream.shutdown().await;
            return;
        }
        let out = std::mem::take(&mut c.out);
        // A client that takes nothing of it for send_timeout of the default server loses the connection.
        if !out.is_empty() && !write_all(&mut stream, &out, send).await { return }
        recycle(out);
        // After GOAWAY, the connection closes once its streams are answered.
        if c.goaway && c.streams.is_empty() { return crate::http::close(&mut stream, lingers).await }
        tokio::select! {
            n = stream.read_buf(&mut buf) => if n.unwrap_or(0) == 0 { return },
            Some(told) = rx.recv() => {
                c.out = buffer();
                c.told(told);
                // What other streams have by now goes in the same write, up to the size of a TLS record.
                while c.out.len() < 16384 && let Ok(told) = rx.try_recv() { c.told(told); }
            }
            () = crate::http::SHUTDOWN.notified() => {}
            // A connection without streams for keepalive_timeout is closed with GOAWAY, as nginx does.
            () = tokio::time::sleep(c.keepalive.1), if c.streams.is_empty() && c.block.is_none() && !c.keepalive.1.is_zero() => c.goaway(),
        }
    }
}

/// How the stream of a proxied server's answer ended: as END_STREAM ends it; before
/// that, as the connection closed; or with a frame, or the end of the stream, that fails it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum End { Whole, #[default] Closed, Failed }

/// What is known of a proxied server's answer once the pipe that passes it has
/// closed, besides what came on it: how its stream ended, its trailers, and whether
/// its head ended it; the connection, if it may be used for another request, and
/// where it goes then, with how long each read of the rest of its answer may wait, once
/// that is known: whichever comes first waits for the other.
#[derive(Debug, Default)]
pub struct Ending { pub end: End, pub trailers: Vec<(String, String)>, pub bodiless: bool, conn: Option<Conn>, home: Option<Home> }

/// The upstream whose connection it is, the server's address and the location, and
/// how long a read may wait.
type Home = (Arc<Upstream>, SocketAddr, usize, Option<Duration>);

/// Gives the connection of an answer that is not read any more back for other requests,
/// once its stream has ended so that it may be.
pub fn give_back(slot: &Slot, home: Home) {
    let mut ending = slot.lock().unwrap();
    match ending.conn.take() {
        Some(conn) => home.0.put(conn, home.1, home.2),
        None => ending.home = Some(home),
    }
}

/// What stays with a connection to a proxied server from one request to the next, as nginx
/// keeps it: the number of the next stream, the windows the server gives the connection and
/// each new stream, and what is left of the connection's own. Its header blocks need nothing:
/// neither side may use a dynamic table.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Session { id: u32, window: i64, initial: i64, recv: i64 }

impl Default for Session {
    /// That of a new connection.
    fn default() -> Session {
        Session { id: 1, window: 65535, initial: 65535, recv: MAX_WINDOW }
    }
}

/// Where what passes the answer tells it what reads the answer.
pub type Slot = Arc<std::sync::Mutex<Ending>>;

/// proxy_http_version 2: passes the HTTP/1 request that comes on a pipe to the
/// proxied server, as the one stream of an HTTP/2 connection at a time, and its
/// answer back on the pipe, as HTTP/1 that ends when the pipe closes; the trailers
/// that follow it, how it ended, and the connection that may be kept, go in the slot. The
/// frames of the head have the size of proxy_buffer_size at most. Whatever goes wrong
/// closes both, and so does the answer not being wanted any more.
pub async fn upstream(mut conn: Conn, mut pipe: tokio::io::DuplexStream, scheme: &str, head_size: usize, slot: Slot) {
    let kept = conn.h2.take();
    let (up, mut out) = (&mut conn.stream, if kept.is_none() { PREFACE.to_vec() } else { Vec::new() });
    let Session { id, mut window, mut initial, mut recv } = kept.as_deref().copied().unwrap_or_default();
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
    if kept.is_none() {
        // nginx's settings: no dynamic table, no pushes, and the window of a stream as large as it goes.
        frame(&mut out, SETTINGS, 0, 0, &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 0x7f, 0xff, 0xff, 0xff]);
        frame(&mut out, WINDOW_UPDATE, 0, 0, &((MAX_WINDOW - 65535) as u32).to_be_bytes());
    }
    let mut block = Vec::new();
    literals(&mut block, fields.iter());
    let mut ended = body == Body::Length(0);
    header_frames(&mut out, id, &block, 16384, ended);
    // The windows of the stream, and the body to send.
    let (mut stream_window, mut stream_recv, mut pending, mut finished) = (initial, MAX_WINDOW, Vec::new(), ended);
    let (mut table, mut answer) = (Table { entries: VecDeque::new(), size: 0, used: 0, limit: 0 }, None::<(u8, Vec<u8>)>);
    // Whether the head of the answer, not one of 1xx, has come: a header block after it has the trailers;
    // the bytes of the frames of the head so far; and whether the server takes no more.
    let (mut headed, mut size, mut deaf) = (false, 0, false);
    // Whether the answer has no body, whatever follows its head; whether its head ended it;
    // whether the connection may be kept, as far as the head says and the server takes more
    // streams; and how long a read may wait once the answer is not read any more.
    let (mut no_body, mut bodiless, mut keep, mut rest) = (method == "HEAD", false, true, None);
    // What the Content-Length of the answer, if it counts, has that has not come.
    let mut left = None::<u64>;
    loop {
        if finished { buf.clear(); }
        finished |= body.take(&mut buf, &mut pending);
        loop {
            // Frames are of 16384 bytes at most, whatever larger ones the server takes, as nginx's.
            let n = pending.len().min(16384).min(window.min(stream_window).max(0) as usize);
            let last = finished && n == pending.len();
            if ended || n == 0 && !last { break }
            ended = last;
            frame(&mut out, DATA, if ended { END_STREAM } else { 0 }, id, &pending.drain(..n).collect::<Vec<_>>());
            (window, stream_window) = (window - n as i64, stream_window - n as i64);
        }
        let (frames, had) = (std::mem::take(&mut out), buf.len());
        if !frames.is_empty() && !deaf {
            tokio::select! {
                // What the server sent before it took no more is still to be read.
                sent = within(rest.flatten(), up.write_all(&frames)) => deaf = !matches!(sent, Some(Ok(()))),
                () = unwanted(&mut pipe, &mut buf), if rest.is_none() => return,
            }
            if buf.len() > had { continue }
        }
        // A read takes as much as a buffer of nginx's proxy_buffer_size would.
        got.reserve(4096);
        tokio::select! {
            // The pipe ends when the answer is not wanted any more, or all of it but the end of its stream came.
            n = pipe.read_buf(&mut buf), if rest.is_none() => if n.unwrap_or(0) == 0 {
                rest = slot.lock().unwrap().home.as_ref().map(|h| h.3);
                if rest.is_none() || !keep || !ended { return }
            },
            n = within(rest.flatten(), up.read_buf(&mut got)) => if n.and_then(Result::ok).unwrap_or(0) == 0 {
                // What came of the data of a frame cut off goes on too.
                if let Some(&[a, b, c, DATA, flags, ..]) = got.get(..9).filter(|f| headed && f[5..] == id.to_be_bytes()) {
                    let (p, padded) = (&got[9..], usize::from(flags & PADDED != 0));
                    let padding = if padded == 1 { p.first().copied().unwrap_or(0) } else { 0 };
                    let end = (u32::from_be_bytes([0, a, b, c]) as usize).saturating_sub(padding.into());
                    let _ = pipe.write_all(p.get(padded..end.min(p.len())).unwrap_or_default()).await;
                }
                return
            },
        }
        // What the frames of a read give is passed only once they all have been taken,
        // those after the end of the stream too, so that what fails the stream drops
        // the data that came with it, as nginx does, but not the head.
        let (mut to_pipe, mut head_end, mut done, mut reset, mut failed) = (Vec::new(), 0, false, false, false);
        while got.len() >= 9 {
            let (len, kind, flags, sid) = (u32::from_be_bytes([0, got[0], got[1], got[2]]) as usize, got[3], got[4], u32::from_be_bytes([got[5], got[6], got[7], got[8]]) & 0x7fff_ffff);
            // A head too long; data before it; frames of the stream after its end; those of other
            // streams; those of the connection in a stream and those of a stream outside one; a
            // push, which nginx's settings refuse; data the windows do not let come; and any other
            // within a header block, or one that goes on without it.
            let block = sid == id && matches!(kind, HEADERS | CONTINUATION) && !headed;
            let misplaced = if sid == 0 { matches!(kind, DATA | HEADERS | CONTINUATION | RST_STREAM) } else { matches!(kind, SETTINGS | PING | GOAWAY) };
            failed = wrong_length(kind, flags, len) || block && size + 9 + len > head_size || sid == id && (kind == DATA && !headed || done && !matches!(kind, RST_STREAM | WINDOW_UPDATE)) || sid != id && sid != 0 || misplaced || kind == PUSH_PROMISE || kind == DATA && len as i64 > recv.min(stream_recv) || answer.is_some() != (kind == CONTINUATION);
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
                WINDOW_UPDATE => {
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
                        // Trailers end the stream.
                        failed = !done || fields.iter().any(|(n, v)| n.starts_with(b":") || refused(n, v));
                        if failed { break }
                        slot.lock().unwrap().trailers.extend(fields.iter().map(|(n, v)| (crate::vars::text(n), crate::vars::text(v))));
                    } else {
                        // Early hints do not end the stream.
                        let Some(status) = status(&fields).filter(|s| *s != 103 || !done) else { failed = true; break };
                        (headed, size) = (status != 103, 0);
                        let length = fields.iter().find(|f| f.0 == b"content-length" && method != "HEAD" && ![103, 204, 304].contains(&status));
                        left = length.and_then(|f| std::str::from_utf8(&f.1).ok()?.parse().ok());
                        no_body |= matches!(status, 204 | 304);
                        // As in nginx, the head of an answer without a body must end it, and nothing come with it.
                        if headed && no_body && !(done && got.is_empty()) { keep = false; }
                        (bodiless, slot.lock().unwrap().bodiless) = (headed && done, headed && done);
                        let mut head = format!("HTTP/1.1 {status} \r\n").into_bytes();
                        fields.iter().filter(|f| !f.0.starts_with(b":")).for_each(|(n, v)| head.extend([&n[..], b": ", v, b"\r\n"].concat()));
                        head.extend_from_slice(b"\r\n");
                        to_pipe.extend_from_slice(&head);
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
                    // As in nginx, the windows are made as large as they go once little of either is left.
                    if recv.min(stream_recv) < MAX_WINDOW / 4 {
                        for (sid, window) in [(0, &mut recv), (id, &mut stream_recv)] {
                            frame(&mut out, WINDOW_UPDATE, 0, sid, &((MAX_WINDOW - *window) as u32).to_be_bytes());
                            *window = MAX_WINDOW;
                        }
                    }
                }
                // A reset with NO_ERROR after the end of the stream is taken once; any other fails the answer.
                RST_STREAM if sid == id => (failed, reset) = (word(0) != NO_ERROR || reset || !done, true),
                // The connection goes away after the answer, unless the request is not among those taken.
                GOAWAY => (failed, keep) = (word(0) & 0x7fff_ffff < id, false),
                _ => {}
            }
            if failed { break }
        }
        failed |= done && left.is_some_and(|n| n > 0);
        if failed { to_pipe.truncate(head_end); }
        // The slot says how the stream ended before the pipe closes.
        if failed || done { slot.lock().unwrap().end = if failed { End::Failed } else { End::Whole }; }
        if pipe.write_all(&to_pipe).await.is_err() || failed { return }
        if done {
            // What is to be sent still goes if it does at once; after a head that ended the
            // answer it does not, as in nginx.
            let mut sent = async || out.is_empty() || at_once(async { up.write_all(&out).await.is_ok() && up.flush().await.is_ok() }).await == Some(true);
            if !keep || deaf || !ended || !got.is_empty() || bodiless && !out.is_empty() || !sent().await { return }
            conn.h2 = Some(Box::new(Session { id: id + 2, window, initial, recv }));
            let mut ending = slot.lock().unwrap();
            match ending.home.take() {
                Some((up, addr, tag, _)) => up.put(conn, addr, tag),
                None => ending.conn = Some(conn),
            }
            return
        }
    }
}

/// Whether the length of a frame of a proxied server is one nginx takes no frame of that kind with.
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

/// What a DATA, HEADERS or CONTINUATION frame has without its padding and priority;
/// none when the padding is longer than the rest.
fn unpadded(kind: u8, flags: u8, p: &[u8]) -> Option<&[u8]> {
    let padded = kind != CONTINUATION && flags & PADDED != 0;
    let skip = usize::from(padded) + if kind == HEADERS && flags & PRIORITY_FLAG != 0 { 5 } else { 0 };
    let padding = if padded { usize::from(*p.first()?) } else { 0 };
    p.get(skip..p.len().checked_sub(padding)?)
}

/// Waits until what reads the answer has gone, taking meanwhile what comes of the
/// request, unless much of it is there already.
async fn unwanted(pipe: &mut tokio::io::DuplexStream, buf: &mut Vec<u8>) {
    while buf.len() < 65536 {
        if pipe.read_buf(buf).await.unwrap_or(0) == 0 { return }
    }
    std::future::pending().await
}

/// How the body of a request or an answer passed on a pipe comes: so many bytes, or in
/// chunks (what is left of the one it is in, and whether its line ends are to come).
#[derive(PartialEq)]
enum Body { Length(u64), Chunked(u64, bool) }

impl Body {
    /// Moves the data of what came of the body into what is to be sent, and tells whether it has all come.
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

/// The answer that comes on the pipe from the connection of an exchange: what came and
/// is still to be looked at, whether it answers a HEAD request and so has no body,
/// and, once its head is whole, how its body comes.
struct Reply { buf: Vec<u8>, bodiless: bool, comes: Option<Comes> }

/// How an answer comes: no more of it; its body, in chunks or of a length; the trailers;
/// or a body that only the end of the pipe ends (a connection that was upgraded).
enum Comes { Nothing, Body(Body), Trailers, Unframed }

impl Reply {
    /// Takes what has come into the part to be told, up to the end of the answer, or
    /// to that of the pipe, which cuts it off when it comes before.
    fn take(&mut self, part: &mut Part, closed: bool) {
        if self.comes.is_none() {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let Some((status, mut headers)) = answer_head(&self.buf[..end]) else { return part.ended = Some(Ended::Cut) };
                // nginx's HTTP/2 header filter sends 204 without Content-Type and Content-Length.
                headers.retain(|h| status != 204 || !h.0.eq_ignore_ascii_case(b"content-type") && !h.0.eq_ignore_ascii_case(b"content-length"));
                // An answer without a length, or with trailers, comes chunked.
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

/// Answers the request of a stream, as a connection of its own answers it,
/// one made when the HTTP/2 connection was, of which it is the request so
/// numbered; the request has so many header lines made, not sent by the client.
/// Its body is passed as it comes, while the answer is read. What is there of the
/// answer is told at once, and no more is read while too much of what was told is
/// not sent. When the stream goes away before the answer has ended, so does all of it.
/// It is all one task: an answer that does not wait for anything comes and is told the
/// first time that runs.
async fn exchange(config: Arc<Config>, request: Vec<u8>, body: Option<UnboundedReceiver<Vec<u8>>>, (listen, local, peer, ssl): Addrs, origin: Origin, tell: impl Fn(Part), mut sent: watch::Receiver<usize>) {
    let ((ours, end), (reads, reader)) = (tokio::io::duplex(65536), watch::channel(()));
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

/// What tells of a stream's answer, and that it was cut off when the exchange goes before it has ended.
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
    use crate::http::tests::{CHUNKED, DELIMITED, GZ, LENGTH, Pieces, after_head, files, letters, log_path, logged, member, passing, pieces_after, plays, sends, served_by, serves_files, serving_on, with_length};
    use crate::stream::within;

    /// A string written Huffman encoded or not, and one decoded.
    fn encoded(s: &[u8], lower: bool) -> Vec<u8> {
        let mut out = Vec::new();
        write_string(&mut out, s, lower);
        out
    }

    fn decoded(s: &[u8]) -> Option<Vec<u8>> {
        let mut out = b"before".to_vec();
        unhuffman(s, &mut out).then(|| out.split_off(6))
    }

    /// The header block of an answer, after an update of the table's size or not.
    fn header_block(status: u16, headers: &[(Vec<u8>, Vec<u8>)], table_update: bool) -> Vec<u8> {
        let headers: Vec<_> = headers.iter().map(|(n, v)| (&n[..], &v[..])).collect();
        [if table_update { &[0x20][..] } else { &[] }, &super::header_block(status, &headers)].concat()
    }

    /// As upstream() does, on a new connection.
    async fn upstream(up: Stream, pipe: tokio::io::DuplexStream, scheme: &str, head_size: usize, slot: Slot) {
        super::upstream(Conn::new(up, Instant::now()), pipe, scheme, head_size, slot).await
    }

    #[test]
    fn huffman_codes() {
        assert_eq!(encoded(b"www.example.com", false), [0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]);
        assert_eq!(encoded(b"{{{{{", false), b"\x05{{{{{");
        assert_eq!(encoded(b"X-Sent-Foo", true), encoded(b"x-sent-foo", false));
        assert_eq!(encoded(b"{{{{X", true), b"\x05{{{{x");
        // Every octet, between others.
        for c in 0..=255 {
            let s = [&[b'0'; 80][..], &[c], b"a~e", &[c]].concat();
            let coded = encoded(&s, false);
            let length = coded.len() - 1;
            assert_eq!(coded[0], 0x80 | length as u8);
            assert_eq!(decoded(&coded[1..]).unwrap(), s);
        }
        assert_eq!(decoded(&[0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]).unwrap(), b"www.example.com");
        // A whole octet of padding, which nginx takes; EOS, which it does not; padding that is not ones.
        assert_eq!(decoded(&[0xa0, 0xe4, 0x1d, 0x13, 0x9d, 0x09, 0xff]).unwrap(), b"localhost");
        assert_eq!(decoded(&[0xff, 0xff, 0xff, 0xff]), None);
        assert_eq!(decoded(&[0x00]), None);
        // Every octet, and all of them.
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
        // Shrinking the table drops what does not fit; an entry larger than it empties it.
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
            let bridge = upstream(Stream::Pipe(up.into()), theirs, "http", 4096, Default::default());
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
            let slot = Slot::default();
            let bridge = upstream(Stream::Pipe(up.into()), theirs, "http", 4096, slot.clone());
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
            assert_eq!(slot.lock().unwrap().trailers, [("x-t".to_string(), "1".to_string())]);
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

    /// A frame.
    fn framed(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        frame(&mut out, kind, flags, sid, payload);
        out
    }

    /// What the bridge passes of the pieces a server sends, each once the one before
    /// has been taken, and how it says the answer ended; the server keeps the
    /// connection, or closes it, after them. The bridge ends by itself, or within a
    /// second once what reads the answer has gone.
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
        // The frames that follow the head and the data, apart or at once with them, and
        // what is passed of the answer then, besides the head.
        let cases = [
            (vec![last.clone()], "ok!", "ok!", End::Whole),
            (vec![last.clone(), rst(NO_ERROR)], "ok!", "ok!", End::Whole),
            (vec![goaway(1), last.clone()], "ok!", "ok!", End::Whole),
            (vec![trailers(END_STREAM)], "ok", "ok", End::Whole),
            // What comes with what fails the stream is dropped, but for the head.
            (vec![rst(INTERNAL_ERROR)], "ok", "", End::Failed),
            (vec![rst(NO_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), rst(INTERNAL_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), rst(NO_ERROR), rst(NO_ERROR)], "ok", "", End::Failed),
            (vec![last.clone(), data.clone()], "ok", "", End::Failed),
            (vec![goaway(0)], "ok", "", End::Failed),
            (vec![trailers(0)], "ok", "", End::Failed),
            (vec![framed(WINDOW_UPDATE, 0, 0, &[0; 3])], "ok", "", End::Failed),
            // The connection closing, whatever was said before, is not the end of the stream.
            (vec![], "ok", "ok", End::Closed),
            (vec![goaway(1)], "ok", "ok", End::Closed),
            // Part of a frame.
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
        // Before the head.
        for (frames, end) in [(rst(INTERNAL_ERROR), End::Failed), (rst(NO_ERROR), End::Failed), (goaway(0), End::Failed), (data.clone(), End::Failed), (goaway(1), End::Closed), (Vec::new(), End::Closed)] {
            assert_eq!(passed(&[&frames], end == End::Closed), (String::new(), end, Vec::new()), "{frames:?}");
        }
        // In the head, which has no body, the end of the stream is that of the answer.
        assert_eq!(passed(&[&framed(HEADERS, END_HEADERS | END_STREAM, 1, &header_block(200, &[], false))], false).1, End::Whole);
        assert_eq!(passed(&[&head, &data, &trailers(END_STREAM)], false).2, [("x-t".to_string(), "1".to_string())]);
    }

    #[test]
    fn answers_are_read_after_a_write_fails() {
        // The server has closed the connection once it has sent the answer, before any of it is taken.
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
        // While the server sends nothing, before the head and in the body, and while it
        // takes nothing of what is to be written.
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
            // Incomplete, invalid and endless header blocks.
            framed(HEADERS, END_HEADERS, 1, &[0x00, 0x05, b'x']), framed(HEADERS, END_HEADERS, 1, &[0xff, 0xff, 0xff, 0xff]),
        ];
        for frames in &wrong {
            assert_eq!((passed(&[frames], false).0, passed(&[frames], false).1), (String::new(), End::Failed), "{}", frames[..frames.len().min(20)].escape_ascii());
            assert_eq!(passed(&[&head, frames], false).1, End::Failed, "{}", frames[..frames.len().min(20)].escape_ascii());
        }
        // Not wrong: the server may open the windows, and set anything else.
        let fine = [
            framed(DATA, PADDED, 1, &[3, 0, 0, 0]), framed(PRIORITY, 0, 1, &[0; 4]), framed(SETTINGS, ACK, 0, &[]), framed(WINDOW_UPDATE, 0, 1, &[0; 4]),
            framed(SETTINGS, 0, 0, &[setting(4, max), setting(4, 65535), setting(4, max)].concat()), framed(SETTINGS, 0, 0, &[setting(5, 0), setting(2, 2)].concat()),
            framed(WINDOW_UPDATE, 0, 0, &word(max - 65535)), framed(WINDOW_UPDATE, 0, 1, &word(max - 65535)), framed(77, 0, 0, &[0; 16384]),
        ];
        for frames in &fine {
            let last = framed(DATA, END_STREAM, 1, b"ok");
            assert_eq!(passed(&[&head, frames, &last], false), ("HTTP/1.1 200 \r\n\r\nok".to_string(), End::Whole, Vec::new()), "{}", frames[..frames.len().min(20)].escape_ascii());
        }
        // The head has so many bytes, with its frames, in one or more of them.
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
        // What a request sends on a connection, when the frames come at once, and how its
        // answer ended and the connection that may be kept.
        let exchange = |session: Option<Session>, request: &'static str, frames: Vec<u8>| crate::stream::block_on(async move {
            let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
            let slot = Slot::default();
            let mut conn = Conn::new(Stream::Pipe(up.into()), Instant::now());
            conn.h2 = session.map(Box::new);
            ours.write_all(request.as_bytes()).await.unwrap();
            server.write_all(&frames).await.unwrap();
            super::upstream(conn, theirs, "http", 4096, slot.clone()).await;
            let mut ending = slot.lock().unwrap();
            let kept = ending.conn.take().map(|c| *c.h2.unwrap());
            let mut sent = vec![0; 1 << 16];
            let n = crate::stream::within(Some(Duration::from_millis(20)), server.read(&mut sent)).await.map_or(0, Result::unwrap);
            sent.truncate(n);
            (sent, ending.end, kept)
        });
        let get = "GET / HTTP/1.1\r\nHost: h\r\n\r\n";
        let post = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nabcde";
        // The preface is sent once, and the streams are numbered; SETTINGS are for every stream,
        // those that shrink a window too, and the window of the connection is what is left of it.
        let settings = framed(SETTINGS, 0, 0, &[&[0, 4][..], &word(3), &[0, 1], &word(0)].concat());
        let (sent, end, kept) = exchange(None, post, [settings, framed(WINDOW_UPDATE, 0, 0, &word(9)), head(1, 0), framed(DATA, END_STREAM, 1, b"ok")].concat());
        assert!(sent.starts_with(PREFACE) && sent.ends_with(&framed(SETTINGS, ACK, 0, &[])) && end == End::Whole);
        let session = Session { id: 3, window: 65535 - 5 + 9, initial: 3, recv: MAX_WINDOW - 2 };
        assert_eq!(kept, Some(session));
        let (sent, end, kept) = exchange(kept, post, [framed(WINDOW_UPDATE, 0, 3, &word(2)), head(3, END_STREAM)].concat());
        let data = [framed(DATA, 0, 3, b"abc"), framed(DATA, END_STREAM, 3, b"de")].concat();
        // The stream's end came with the window: the rest of the body is not sent any more.
        assert!(sent[3..9] == [HEADERS, END_HEADERS, 0, 0, 0, 3] && sent.ends_with(&data[..12]) && end == End::Whole && kept.is_none());
        let (sent, _, kept) = exchange(Some(session), get, [head(3, 0), framed(DATA, END_STREAM, 3, b"ok")].concat());
        assert!(sent[3..9] == [HEADERS, END_HEADERS | END_STREAM, 0, 0, 0, 3]);
        assert_eq!(kept, Some(Session { id: 5, recv: MAX_WINDOW - 4, ..session }));
        // The windows of the answer grow once less than a quarter is left of one; nothing comes beyond them.
        let little = Session { recv: MAX_WINDOW / 4 + 1, ..session };
        let answer = |data: &[u8]| [head(3, 0), framed(DATA, 0, 3, data), framed(DATA, END_STREAM, 3, b"")].concat();
        assert_eq!(exchange(Some(little), get, answer(b"a")).2, Some(Session { id: 5, recv: MAX_WINDOW / 4, ..session }));
        let (sent, _, kept) = exchange(Some(little), get, answer(b"ab"));
        let grown = [framed(WINDOW_UPDATE, 0, 0, &word((MAX_WINDOW - MAX_WINDOW / 4 + 1) as u32)), framed(WINDOW_UPDATE, 0, 3, &word(2))].concat();
        assert!(sent.ends_with(&grown) && kept == Some(Session { id: 5, recv: MAX_WINDOW, ..session }));
        let (_, end, kept) = exchange(Some(Session { recv: 1, ..session }), get, answer(b"ab"));
        assert_eq!((end, kept), (End::Failed, None));
        // Frames of other streams, the one before too, fail the answer.
        for frame in [framed(WINDOW_UPDATE, 0, 1, &word(1)), framed(RST_STREAM, 0, 1, &word(0)), framed(DATA, 0, 5, b"a"), framed(DATA, 0, 0, b"a"), framed(PING, ACK, 0, &[0; 8])] {
            let (_, end, kept) = exchange(Some(session), get, [frame, head(3, END_STREAM)].concat());
            assert_eq!((end, kept), (End::Failed, None));
        }
    }

    /// What a server of HTTP/2 sends for a stream: at once, and once the client has its answer;
    /// when that is empty too, it closes the connection.
    type Plays = fn(u32) -> (Vec<u8>, Option<Vec<u8>>);

    /// The statuses of four requests, one after another, passed to a server that plays so, and
    /// how many requests came on each connection to it; a connection on which another
    /// request comes after it was closed counts it.
    fn kept(plays: Plays, method: &str, (upstream, location): (&str, &str)) -> (Vec<u16>, Vec<usize>) {
        use std::io::{Read, Write};
        use std::sync::{Mutex, atomic::{AtomicUsize, Ordering::SeqCst}};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (came, sent, answered): (Arc<Mutex<Vec<usize>>>, Arc<AtomicUsize>, Arc<AtomicUsize>) = Default::default();
        let (all, plays_on, seen) = (came.clone(), sent.clone(), answered.clone());
        std::thread::spawn(move || for (i, s) in listener.incoming().enumerate() {
            all.lock().unwrap().push(0);
            let (mut s, came, sent, answered) = (s.unwrap(), all.clone(), plays_on.clone(), seen.clone());
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
                // The body is ok, in a chunk or not, or that of an error page.
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
                // What came is read; those that fail are not answered, but counted.
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
            // Not kept: what is not read, or goes away.
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
        for (case, method, plays, connections) in cases {
            let (statuses, came) = kept(plays, method, ("", ""));
            assert!(statuses.iter().all(|s| *s < 300), "{case} {statuses:?}");
            assert_eq!(came, connections, "{case}");
        }
        // One that is closed when the second request comes is tried again on another, once; with a reset, or
        // when it goes away before the stream, it is not.
        let second: Plays = |i| if i == 1 { (ok(i), None) } else { (Vec::new(), Some(Vec::new())) };
        assert_eq!(kept(second, "GET", ("", "")), (vec![200; 4], vec![2, 2, 2, 1]));
        assert_eq!(kept(second, "GET", ("", "proxy_next_upstream off;")), (vec![200, 502, 200, 502], vec![2, 2]));
        assert_eq!(kept(second, "POST", ("", "")), (vec![200, 502, 200, 502], vec![2, 2]));
        let fails: [Plays; 2] = [|i| if i == 1 { (ok(i), None) } else { (goaway(1), None) }, |i| if i == 1 { (ok(i), None) } else { (rst(i), None) }];
        for fails in fails { assert_eq!(kept(fails, "GET", ("", "")), (vec![200, 502, 200, 502], vec![2, 2])); }
        // The directives of the upstream, and an answer that is not used.
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
            // In early hints, and in what follows them, which goes after them.
            let hints = [(":status", "103"), field];
            assert_eq!(passed(&[&[head(&hints), head(&[ok]), last.clone()].concat()], false), (String::new(), End::Failed, vec![]), "{field:?}");
            assert_eq!(passed(&[&[head(&hints[..1]), head(&[ok, field])].concat()], false), ("HTTP/1.1 103 \r\n\r\n".to_string(), End::Failed, vec![]), "{field:?}");
            // In trailers.
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
        // An end of the stream with early hints, a head that only goes on, and one that another frame is in.
        for frames in [
            framed(HEADERS, END_HEADERS | END_STREAM, 1, &block(&[(":status", "103")])), framed(CONTINUATION, END_HEADERS, 1, &block(&[ok])),
            [framed(HEADERS, 0, 1, &block(&[ok])), head(&[("x", "1")])].concat(), [framed(HEADERS, 0, 1, &block(&[ok])), framed(PING, 0, 0, &[0; 8])].concat(),
        ] { assert_eq!(passed(&[&frames], false), (String::new(), End::Failed, vec![]), "{frames:?}"); }
        // Not refused.
        for (field, line) in [(("x", "\t\u{7f}"), "x: \t\u{7f}\r\n"), (("x_(/", ""), "x_(/: \r\n"), (("connection", "close"), "connection: close\r\n"), ((":status", "999"), "")] {
            let (fields, status) = if line.is_empty() { (vec![field], "999") } else { (vec![ok, field], "200") };
            assert_eq!(passed(&[&[head(&fields), last.clone()].concat()], false), (format!("HTTP/1.1 {status} \r\n{line}\r\nok"), End::Whole, vec![]), "{field:?}");
        }
        // The bytes of a trailer are kept.
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
    fn bodies_go_in_frames_every_server_takes() {
        // Whatever the largest frame the server says it takes, as nginx.
        for size in [0, 1, 100, 16384, 1 << 24] {
            crate::stream::block_on(async {
                let ((mut ours, theirs), (up, mut server)) = (tokio::io::duplex(1 << 16), tokio::io::duplex(1 << 16));
                tokio::task::spawn_local(upstream(Stream::Pipe(up.into()), theirs, "http", 4096, Slot::default()));
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
                ours.write_all(if random(2) == 0 { b"GET / HTTP/1.1\r\nHost: h\r\n\r\n" } else { b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc" }).await.unwrap();
                server.write_all(&sent).await.unwrap();
                // The server keeps the connection, or closes it; what reads the answer goes, or not.
                let (server, ours) = match random(3) { 0 => { drop(server); (None, Some(ours)) } 1 => { drop(ours); (Some(server), None) } _ => { drop((server, ours)); (None, None) } };
                let ended = crate::stream::within(Some(Duration::from_secs(1)), upstream(Stream::Pipe(up.into()), theirs, "http", 4096, Slot::default())).await;
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

    /// The parts told of an answer that comes in the pieces, after which the pipe closes or not.
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
            // However it is split, and its end does not wait for that of the pipe.
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
        // What ends an answer comes with the last of it, or after it.
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
        // One cut off is reset once what came of it is sent; one without a head at once.
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
        // What was sent is told when the exchange may wait for it, and the end of the stream.
        let (mut c, mut sent) = start(1 << 20);
        c.send = 1 << 20;
        c.answer(1, part(&vec![b'x'; WAITING - 4], None));
        c.send_data();
        assert!(!sent.has_changed().unwrap());
        c.answer(1, part(b"y", None));
        c.send_data();
        assert_eq!(*sent.borrow_and_update(), WAITING);
        // At once, when that waits for the window.
        c.streams.get_mut(&1).unwrap().send = 1;
        c.answer(1, part(&vec![b'x'; WAITING], None));
        c.send_data();
        assert_eq!(*sent.borrow_and_update(), WAITING + 1);
        assert_eq!(c.frame(RST_STREAM, 0, 1, &[0, 0, 0, 8]), Ok(()));
        assert!(sent.has_changed().is_err());
    }

    /// The frames that have come whole: kind, flags, stream and payload of each.
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

    /// A client of HTTP/2, what has come and is not yet taken, and whether it has given
    /// its answers' windows back as they came (those of its streams, of so many bytes at first).
    struct Client { s: tokio::net::TcpStream, buf: Vec<u8>, task: tokio::task::JoinHandle<()>, gives: bool }

    impl Client {
        /// One of a server with the directives.
        async fn new(directives: &str, window: u32) -> Client {
            Client::new_by(&format!("http2 on; {directives}"), window).await
        }

        /// One of what the http block has.
        async fn new_by(http: &str, window: u32) -> Client {
            let (mut s, task) = served_by(http).await;
            let settings = framed(SETTINGS, 0, 0, &[&[0, 4][..], &window.to_be_bytes()].concat());
            s.write_all(&[PREFACE, &settings].concat()).await.unwrap();
            Client { s, buf: Vec::new(), task, gives: false }
        }

        async fn send(&mut self, frames: &[Vec<u8>]) {
            self.s.write_all(&frames.concat()).await.unwrap();
        }

        /// Asks for "/" on a stream.
        async fn get(&mut self, sid: u32, method: &str) {
            let block = [&[0x86, 0x84, 0x41, 0x01, b'h', 0x02, method.len() as u8], method.as_bytes()].concat();
            self.send(&[framed(HEADERS, END_HEADERS | END_STREAM, sid, &block)]).await;
        }

        /// The next frames of streams that come at once, none once the connection is closed.
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

        /// The frames of a stream up to its end, each with the milliseconds it came after
        /// the first call of this; DATA in a row that came at once is in one.
        async fn all(&mut self, sid: u32) -> Vec<(u128, String)> {
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
                    if end { return all }
                }
            }
        }

        /// Goes away, and waits until what serves it has ended.
        async fn close(self) {
            drop(self.s);
            within(Some(Duration::from_secs(2)), self.task).await.unwrap().unwrap();
        }
    }

    /// The fields of a header block, without those that every answer has.
    fn fields_of(block: &[u8]) -> String {
        let mut t = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        let fields = t.decode(block, block.len(), (4, 8192)).unwrap();
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        fields.iter().filter(|f| !["server", "date", "content-type"].contains(&text(&f.0).as_str())).map(|f| format!("{}: {};", text(&f.0), text(&f.1))).collect()
    }

    /// The same, without the times.
    fn texts(all: &[(u128, String)]) -> Vec<&str> {
        all.iter().map(|f| f.1.as_str()).collect()
    }

    /// What one stream gets for a request of a server that sends the pieces.
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
        for (head, parts, closes, directives, want) in [
            (length.as_str(), &["ab", "c", "d"][..], false, "proxy_buffering off;", vec![OK4, "ab", "c", "d|"]),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], false, "", vec![OK, "ab", "cd", "|"]),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], false, "chunked_transfer_encoding off;", vec![OK, "ab", "cd", "|"]),
            (DELIMITED, &["ab", "cd", ""], true, "proxy_buffering off;", vec![OK, "ab", "cd", "|"]),
            (&length, &["ab", "c", "d"], false, "proxy_buffering off; add_trailer X $upstream_response_length;", vec![OK4, "ab", "c", "d", "x: 4;|"]),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\n", "0\r\n\r\n"], false, "add_trailer X 1;", vec![OK, "ab", "cd", "x: 1;|"]),
        ] {
            let all = got(&after_head(head, parts, 200), closes, directives, "GET");
            assert_eq!(texts(&all), want, "{directives}");
            // The head and the first part come at once, and so do the end of a body and its trailers.
            let start = all[0].0;
            for (i, part) in all.iter().enumerate().skip(1) {
                let due = start + 200 * (i as u128 - 1).min(2);
                assert!(part.0 + 20 >= due && part.0 < due + 150, "{i} {all:?}");
            }
        }
        // With proxy_buffering on, the head does not wait for the body, which waits for a full buffer or its end.
        for (head, parts, closes, directives, want) in [(length.as_str(), &["ab", "c", "d"][..], false, "", vec![OK4, "abcd|"]), (DELIMITED, &["ab", "cd", ""], true, "", vec![OK, "abcd|"]), (&length, &["", "ab", "cd"], false, "proxy_buffering off;", vec![OK4, "ab", "cd|"])] {
            let all = got(&after_head(head, parts, 200), closes, directives, "GET");
            assert!(texts(&all) == want && all[0].0 < 150 && all[1].0 >= 180, "{all:?}");
        }
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
        // Each as it comes, whatever else waits; not that of an exchange of before, nor of a stream that has gone.
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
        // What has no body ends with its head.
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
            // What ends before its time, or is malformed, after the head of the answer.
            (&half, vec![gz[0].clone(), gz[1][..5].to_vec()], false, "gunzip on; proxy_buffering off;", vec![OK, &a, "reset 2"]),
            (&with_bad, vec![gz[0].clone(), bad.clone()], false, "gunzip on; proxy_buffering off;", vec![OK, &a, "reset 2"]),
            (&with_bad, vec![[&gz[0][..], &bad].concat()], false, "gunzip on;", vec![OK, "reset 2"]),
            (&length(5), vec![gz[0][..5].to_vec()], false, "gunzip on;", vec![OK, "reset 2"]),
        ] {
            let all = got(&pieces_after(head, &pieces), closes, &format!("{directives} access_log {} f;", log.display()), "GET");
            let mut texts = texts(&all);
            // The end of the stream may come with the last of the body, or alone.
            let last = format!("{}|", texts[texts.len() - 2]);
            if texts.last() == Some(&"|") { texts.truncate(texts.len() - 2); texts.push(&last); }
            assert_eq!(texts, want, "{directives} {pieces:?}");
            // $body_bytes_sent is what was decompressed, without what makes it chunks.
            let body: usize = want.iter().map(|w| w.trim_end_matches('|').len()).filter(|n| *n == 50).sum();
            let line = logged(&log);
            assert!(line.starts_with(&format!("200 {body} ")), "{line}");
        }
        // To a client that takes gzip, each read flushed, the head with the beginning of it.
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
        for (head, pieces, closes, directives, want) in [
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
            // Nothing more is sent of what is malformed, or nothing at all.
            (CHUNKED, &["2\r\nab\r\n", "zz\r\nz"], false, "", vec![OK, "ab", reset]),
            (CHUNKED, &["2\r\nab\r\n", "2\r\ncd\r\nzz"], false, "", vec![OK, "ab", reset]),
            (CHUNKED, &["2\r\nab\r\nzz"], false, "", vec![reset]),
        ] {
            let all = got(&after_head(head, pieces, 60), closes, directives, "GET");
            assert_eq!(texts(&all), want, "{head} {pieces:?}");
        }
    }

    #[test]
    fn trailers_of_servers_come_after_their_length() {
        let _busy = serving_on();
        let head = framed(HEADERS, END_HEADERS, 1, &header_block(200, &[(b"Content-Length".to_vec(), b"4".to_vec())], false));
        let mut block = Vec::new();
        literals(&mut block, [(b"x-t".to_vec(), b"1".to_vec())].iter());
        let trailer = framed(HEADERS, END_HEADERS | END_STREAM, 1, &block);
        for (last, want) in [(vec![framed(DATA, 0, 1, b"cd"), trailer], vec![OK4, "ab", "cd", "x-t: 1;|"]), (vec![framed(DATA, END_STREAM, 1, b"cd")], vec![OK4, "ab", "cd|"])] {
            let (addr, _) = sends(&[[&head[..], &framed(DATA, 0, 1, b"ab")].concat(), last.concat()], false);
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
            // The first goes on once it has a window again, and ends when it is reset.
            c.send(&[framed(WINDOW_UPDATE, 0, 1, &5000u32.to_be_bytes())]).await;
            while came[0] < 25000 { came[0] += c.next().await.iter().map(|f| f.3.len()).sum::<usize>(); }
            c.send(&[framed(RST_STREAM, 0, 1, &[0, 0, 0, 8])]).await;
            let started = Instant::now();
            while count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(1)); tokio::time::sleep(Duration::from_millis(5)).await; }
            c.close().await;
        });
        let text = logged(&log);
        let lines: Vec<Vec<usize>> = text.lines().map(|l| l.split(' ').take(6).map(|n| n.parse().unwrap()).collect()).collect();
        // What is on its way from the server to the client is held, some 64 KB in each place.
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
        // Of a file no more is read than waits to be sent: what became shorter meanwhile is
        // reset there. Another stream is answered meanwhile.
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
            // It reads nothing: once the buffers are full, a write waits for send_timeout and the connection ends.
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
                // Before the head, after it, in the body, while it is paced, and without a window.
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
                    // Only a client that has gone, or the end of its connection, ends it.
                    assert_eq!(count.lock().unwrap()[1], 0);
                    let mut left = None;
                    if closes { c.close().await; } else { c.send(&[framed(RST_STREAM, 0, 1, &[0, 0, 0, 8])]).await; left = Some(c); }
                    let started = Instant::now();
                    while count.lock().unwrap()[1] == 0 { assert!(started.elapsed() < Duration::from_secs(1), "{pieces:.0?}"); tokio::time::sleep(Duration::from_millis(1)).await; }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    let text = logged(&log);
                    assert!(text.starts_with(&format!("{status} ")) && text.lines().count() == 1, "{text}");
                    // The connection serves other streams.
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
        // 2000 bytes, the head's with them, in each second of the clock, so 4000 at most when it ticks meanwhile.
        for directives in ["limit_rate 2000;", "limit_rate 2000; proxy_limit_rate 1m;"] {
            let all = got(&after_head(&length, &[&data, &data], 100), false, &format!("{directives} {to_log}"), "GET");
            let last = all.last().unwrap().0;
            assert!((600..3500).contains(&last) && all[1].0 < 300, "{:?}", all.iter().map(|f| (f.0, f.1.len())).collect::<Vec<_>>());
        }
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
        // The head's bytes are the same, but for Content-Length, however the body comes; trailers count.
        let content_length = "Content-Length: 4\r\n".len();
        assert_eq!(bytes[1..], [bytes[0] - content_length, bytes[0] - content_length, bytes[0] + "Xyz: 123\r\n".len(), bytes[0] - content_length]);
    }

    #[test]
    fn trailers_come_after_the_body() {
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
            let (chunked, trailers) = (trailers.is_some(), trailers.unwrap_or_default());
            c.answer(1, Part { head: Some((header_block(200, &[], false), chunked)), data: body.to_vec(), ended: Some(Ended::Whole(trailers)) });
            c.send_data();
            assert_eq!((sent(&c.out), c.streams.is_empty()), (want, true), "{body:?}");
        }
    }

    fn connection() -> Connection {
        let table = Table { entries: VecDeque::new(), size: TABLE_SIZE, used: 0, limit: TABLE_SIZE };
        Connection { out: Vec::new(), streams: BTreeMap::new(), ready: Vec::new(), bad: Vec::new(), block: None, last_sid: 0, table, nodes: HashMap::new(), limits: (4, 8192), send: 65535, window: 65535, frame_size: 16384, recv: MAX_WINDOW, table_update: false, started: Instant::now(), requests: 0, goaway: false, keepalive: (2, Duration::from_secs(75), Duration::from_secs(3600)), priorities: CONCURRENT.max(100) }
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
            // One discarded is not.
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
        // The header block, of both frames, is the request's head.
        assert_eq!(c.streams[&1].block, 6);
        let s = c.streams.get_mut(&1).unwrap();
        // Without a length, the body goes on in chunks, one of each frame's data, then the last.
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
        // Each stream taken allows as many more as streams at a time.
        let mut c = connection();
        assert_eq!(c.frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x82, 0x86, 0x84, 0x41, 0x01, b'h']), Ok(()));
        (1..2 * CONCURRENT).for_each(|_| assert_eq!(c.frame(PRIORITY, 0, 3, &priority), Ok(())));
        assert_eq!(c.frame(PRIORITY, 0, 3, &priority), Err(ENHANCE_YOUR_CALM));
    }

    /// A request for a path on a stream, which ends it or not.
    fn asking(sid: u32, method: &str, path: &str, end: bool) -> Vec<u8> {
        let block = [&[0x86, 0x41, 0x01, b'h', 0x02, method.len() as u8], method.as_bytes(), &[0x04, path.len() as u8], path.as_bytes()].concat();
        framed(HEADERS, END_HEADERS | if end { END_STREAM } else { 0 }, sid, &block)
    }

    /// All the fields of a header block.
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
        // A proxied 204 loses them too.
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
        // A HEADERS frame that has not come whole, a field going on past it.
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
        // The block ends with it: the field is too long.
        let mut c = connection();
        let head = framed(HEADERS, END_STREAM | END_HEADERS, 1, &block);
        assert_eq!(c.read(&mut head[..head.len() - 2].to_vec()), Err(FRAME_SIZE_ERROR));
    }
}
