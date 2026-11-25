//! The bodies of proxied answers compressed (gzip) or decompressed (gunzip) piece by
//! piece as they come, and what of that goes on to the client when.

use flate2::{Compress, Compression, Crc, Decompress, FlushCompress, FlushDecompress, Status};

/// The size of the buffers of gzip_buffers and gunzip_buffers, and of all of them.
const BUFFER: usize = 4096;
const ALL: usize = 32 * BUFFER;

/// What codes a body: what it has made of it and how much of that goes on, how much of
/// the data given it has taken, and whether it has begun with that and is to flush it.
/// What it holds is bounded, however large the body is or becomes.
#[derive(Debug)]
pub struct Coder { coding: Coding, out: Vec<u8>, ready: usize, taken: usize, begun: bool, flush: bool, to: Option<std::sync::Arc<crate::vars::Shared>> }

#[derive(Debug)]
enum Coding { Gzip(Gzip), Gunzip(Gunzip) }

/// Compresses, counting what it takes. Whether anything came since it last flushed, or it
/// never did, and whether there was room left after the last write.
#[derive(Debug)]
struct Gzip { deflate: Compress, crc: Crc, held: bool, filled: bool }

/// Decompresses the members of the body: where one is, how many bytes of that have come,
/// its flags, the length of its extra field, the last four bytes that came of what is
/// around the data, and the sums of the header and of the data.
#[derive(Debug)]
struct Gunzip { inflate: Decompress, at: At, came: u32, flags: u8, extra: u32, last: u32, head: Crc, crc: Crc }

#[derive(Clone, Copy, Debug, PartialEq)]
enum At { Head, ExtraLength, Extra, Name, Comment, HeadSum, Data, Trailer, End }

impl Coder {
    /// Compresses the body, as ngx_http_gzip_body_filter() does, and tells the request
    /// what it took and made once it ends ($gzip_ratio).
    pub fn gzip(to: Option<std::sync::Arc<crate::vars::Shared>>) -> Coder {
        // The header of zlib at its lowest level: no name, no time, the fastest, Unix.
        let out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 3];
        Coder { to, ..Coder::new(Coding::Gzip(Gzip { deflate: Compress::new(Compression::new(1), false), crc: Crc::new(), held: true, filled: false }), out) }
    }

    /// Decompresses the body, as ngx_http_gunzip_body_filter() does.
    pub fn gunzip() -> Coder {
        let gunzip = Gunzip { inflate: Decompress::new(false), at: At::Head, came: 0, flags: 0, extra: 0, last: 0, head: Crc::new(), crc: Crc::new() };
        Coder::new(Coding::Gunzip(gunzip), Vec::new())
    }

    fn new(coding: Coding, out: Vec<u8>) -> Coder {
        Coder { coding, out, ready: 0, taken: 0, begun: false, flush: false, to: None }
    }

    /// Codes the data that came, which is flushed, or cut off after that. What is compressed
    /// goes on in buffers, when they are full, or all of it then; what is decompressed at
    /// once, with a flush what one member gives before the next is begun. Tells whether that
    /// is all: if not, it is to be called with the same again once what goes on is written.
    /// Malformed data is an error, and what was made in that call does not go on.
    pub fn code(&mut self, data: &[u8], flush: bool, cut: bool) -> Result<bool, String> {
        if !self.begun { (self.begun, self.flush) = (true, flush); }
        let all = match &mut self.coding {
            Coding::Gzip(gzip) => {
                let flush = flush || cut;
                let sync = if flush && (gzip.held || !data.is_empty()) { FlushCompress::Sync } else { FlushCompress::None };
                let all = gzip.code(&mut self.out, data, &mut self.taken, sync)?;
                self.ready = if all && flush { self.out.len() } else { self.out.len() / BUFFER * BUFFER };
                all
            }
            Coding::Gunzip(gunzip) => {
                let all = gunzip.code(&mut self.out, data, &mut self.taken, &mut self.flush)?;
                self.ready = self.out.len();
                all
            }
        };
        if all { (self.taken, self.begun) = (0, false); }
        Ok(all)
    }

    /// Ends the body after all that came: the rest of what is compressed goes on with what
    /// does already. It is an error if what is decompressed does not end there.
    pub fn end(&mut self) -> Result<(), String> {
        match &mut self.coding {
            Coding::Gzip(gzip) => {
                gzip.code(&mut self.out, &[], &mut 0, FlushCompress::Finish)?;
                self.out.extend(gzip.crc.sum().to_le_bytes());
                self.out.extend(gzip.crc.amount().to_le_bytes());
                // With the header and the trailer of gzip, as nginx counts them.
                if let Some(to) = &self.to { *to.gzip.lock().unwrap() = Some((gzip.deflate.total_in(), 10 + gzip.deflate.total_out() + 8)); }
            }
            Coding::Gunzip(gunzip) => if gunzip.at != At::End { return Err("inflate() returned -5 on response end".to_string()) },
        }
        self.ready = self.out.len();
        Ok(())
    }

    /// What goes on.
    pub fn ready(&self) -> &[u8] {
        &self.out[..self.ready]
    }

    /// What went on has been written.
    pub fn written(&mut self) {
        self.out.drain(..self.ready);
        self.ready = 0;
    }
}

/// Room to write to: as much as there is, so that all of it is at most all buffers.
fn grow(out: &mut Vec<u8>) {
    if out.len() == out.capacity() { out.reserve_exact(out.len().next_power_of_two().max(BUFFER / 2) * 2 - out.len()); }
}

impl Gzip {
    /// Compresses the data not taken, unless all buffers are full before.
    fn code(&mut self, out: &mut Vec<u8>, data: &[u8], taken: &mut usize, flush: FlushCompress) -> Result<bool, String> {
        let end = flush == FlushCompress::Finish;
        loop {
            if out.len() >= ALL && !end { return Ok(false) }
            grow(out);
            let before = self.deflate.total_in();
            let status = self.deflate.compress_vec(&data[*taken..], out, flush).map_err(|_| "deflate() failed: 0, -2".to_string())?;
            let used = (self.deflate.total_in() - before) as usize;
            self.crc.update(&data[*taken..*taken + used]);
            *taken += used;
            self.held |= used > 0;
            // After a write that left no room, it is not told whether the flush was done.
            let filled = std::mem::replace(&mut self.filled, out.len() == out.capacity());
            let all = !self.filled && *taken == data.len() && (!filled || flush == FlushCompress::None);
            if all && flush == FlushCompress::Sync { self.held = false; }
            if status == Status::StreamEnd || all && !end { return Ok(true) }
        }
    }
}

impl Gunzip {
    /// Decompresses the data not taken, unless all buffers are full before, or a member is
    /// flushed before the next.
    fn code(&mut self, out: &mut Vec<u8>, data: &[u8], taken: &mut usize, flush: &mut bool) -> Result<bool, String> {
        // What nginx logs: the flush asked of inflate(), and what it returned.
        let malformed = |flush: bool| format!("inflate() failed: {}, -3", if flush { 2 } else { 0 });
        loop {
            if out.len() >= ALL { return Ok(false) }
            if self.at == At::Data {
                grow(out);
                let (before, made) = (self.inflate.total_in(), out.len());
                let status = self.inflate.decompress_vec(&data[*taken..], out, FlushDecompress::None).map_err(|_| malformed(*flush))?;
                let used = (self.inflate.total_in() - before) as usize;
                self.crc.update(&out[made..]);
                *taken += used;
                if status == Status::StreamEnd { self.next(At::Trailer); } else if used == 0 && out.len() == made { return Ok(true) }
                continue;
            }
            let Some(&c) = data.get(*taken) else { return Ok(true) };
            if self.at == At::End {
                if std::mem::take(flush) { return Ok(false) }
                self.inflate.reset(false);
                (self.at, self.came) = (At::Head, 0);
                self.head.reset();
                self.crc.reset();
            }
            *taken += 1;
            if !self.byte(c) { return Err(malformed(*flush)) }
        }
    }

    /// Takes a byte of what is around the data, as inflate() does; tells whether what it
    /// then looks at is as it should be.
    fn byte(&mut self, c: u8) -> bool {
        use At::*;
        if ![HeadSum, Trailer].contains(&self.at) { self.head.update(&[c]); }
        self.last = self.last >> 8 | u32::from(c) << 24;
        self.came = self.came.wrapping_add(1);
        match (self.at, self.came) {
            (Head, 2) => self.last >> 16 == 0x8b1f,
            (Head, 4) => {
                self.flags = c;
                self.last >> 16 & 0xe0ff == 8
            }
            (Head, 10) => self.next(ExtraLength),
            (ExtraLength, 2) => {
                self.extra = self.last >> 16;
                self.next(if self.extra == 0 { Name } else { Extra })
            }
            (Extra, n) if n == self.extra => self.next(Name),
            (Name, _) if c == 0 => self.next(Comment),
            (Comment, _) if c == 0 => self.next(HeadSum),
            (HeadSum, 2) => self.last >> 16 == self.head.sum() & 0xffff && self.next(Data),
            (Trailer, 4) => self.last == self.crc.sum(),
            (Trailer, 8) => self.last == self.crc.amount() && self.next(End),
            // A name may be of any length.
            _ => true,
        }
    }

    /// Goes to that, or to what is after it if the header's flags do not have it.
    fn next(&mut self, at: At) -> bool {
        let (flag, after) = match at { At::ExtraLength => (4, At::Name), At::Name => (8, At::Comment), At::Comment => (16, At::HeadSum), At::HeadSum => (2, At::Data), _ => (0, at) };
        if flag > 0 && self.flags & flag == 0 { return self.next(after) }
        (self.at, self.came) = (at, 0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Bytes that do not compress (xorshift64), the same each time.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1d_u64;
        (0..n).map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        }).collect()
    }

    /// Lines that do.
    fn text(n: usize) -> Vec<u8> {
        let mut text = Vec::new();
        for c in noise(n / 8 + 1) { let _ = writeln!(text, "line {:>3}", c); }
        text.truncate(n);
        text
    }

    fn gzipped(data: &[u8]) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(data).unwrap();
        gz.finish().unwrap()
    }

    /// The parts that go on of the data, each of which is at most all buffers.
    fn coded(coder: &mut Coder, data: &[u8], flush: bool) -> Result<Vec<Vec<u8>>, String> {
        let mut parts = Vec::new();
        loop {
            let all = coder.code(data, flush, false)?;
            assert!(coder.ready().len() <= ALL && coder.out.capacity() <= ALL);
            if !coder.ready().is_empty() { parts.push(coder.ready().to_vec()); }
            coder.written();
            if all { return Ok(parts) }
        }
    }

    /// What goes on then at the end.
    fn ended(coder: &mut Coder) -> Vec<u8> {
        coder.end().unwrap();
        coder.ready().to_vec()
    }

    /// What can be decompressed of a member that has come so far.
    fn so_far(gz: &[u8]) -> Vec<u8> {
        let (mut plain, mut inflate) = (Vec::with_capacity(1 << 20), Decompress::new(false));
        inflate.decompress_vec(&gz[10..], &mut plain, FlushDecompress::None).unwrap();
        plain
    }

    #[test]
    fn gzip_goes_on_when_a_buffer_is_full_or_flushed() {
        // Nothing but what is flushed, even of nothing: the header and an empty block.
        let mut coder = Coder::gzip(None);
        let mut all = coded(&mut coder, b"", true).unwrap().concat();
        assert_eq!(all, [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 3, 0, 0, 0, 0xff, 0xff]);
        assert!(coded(&mut coder, b"", true).unwrap().is_empty());
        let mut plain = Vec::new();
        for part in [&b"data: 1\n\n"[..], b"data: 2\n\n", &text(3000), &noise(3000), &text(50000), &noise(50000)] {
            let came = coded(&mut coder, part, true).unwrap().concat();
            assert!(came.ends_with(&[0, 0, 0xff, 0xff]), "{came:?}");
            all.extend(came);
            plain.extend(part);
            assert_eq!(so_far(&all), plain);
            assert!(coded(&mut coder, b"", true).unwrap().is_empty());
        }
        all.extend(ended(&mut coder));
        let mut got = Vec::new();
        flate2::read::GzDecoder::new(&all[..]).read_to_end(&mut got).unwrap();
        assert_eq!(got, plain);

        // In whole buffers without it, and the rest at the end.
        for data in [Vec::new(), text(90), text(400_000), noise(400_000)] {
            for size in [1000, 20000, 400_000] {
                let (mut coder, mut all) = (Coder::gzip(None), Vec::new());
                for part in data.chunks(size) {
                    for part in coded(&mut coder, part, false).unwrap() {
                        assert_eq!(part.len() % BUFFER, 0);
                        all.extend(part);
                    }
                }
                assert_eq!(all.is_empty(), data.len() < 1000, "{}", data.len());
                all.extend(ended(&mut coder));
                let mut got = Vec::new();
                flate2::read::GzDecoder::new(&all[..]).read_to_end(&mut got).unwrap();
                assert!(got == data, "{size}");
            }
        }
        assert_eq!(ended(&mut Coder::gzip(None)), [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // Cut off: what is held is flushed, but there is no end.
        let mut coder = Coder::gzip(None);
        assert!(coded(&mut coder, &text(90), false).unwrap().is_empty());
        assert_eq!(coder.code(&text(90), false, true), Ok(true));
        assert_eq!(so_far(coder.ready()), [text(90), text(90)].concat());
    }

    #[test]
    fn gunzip_goes_on_at_once() {
        let mut coder = Coder::gunzip();
        let (one, two) = (gzipped(&text(90)), gzipped(&noise(20000)));
        let mut got = Vec::new();
        for c in &one[..40] { got.extend(coded(&mut coder, &[*c], false).unwrap().concat()); }
        assert!(!got.is_empty() && text(90).starts_with(&got));
        assert_eq!(coder.end().unwrap_err(), "inflate() returned -5 on response end");
        // The next member, and one of nothing.
        got.extend(coded(&mut coder, &[&one[40..], &two, &gzipped(b"")].concat(), false).unwrap().concat());
        assert!(got == [text(90), noise(20000)].concat());
        assert!(ended(&mut coder).is_empty());
        // Each member is flushed before the next, once.
        let mut coder = Coder::gunzip();
        let parts = coded(&mut coder, &[&one[..], &one, &one].concat(), true).unwrap();
        assert_eq!(parts, [text(90), [text(90), text(90)].concat()]);
        let mut coder = Coder::gunzip();
        assert_eq!((coder.code(&[&one[..], &one].concat(), false, true), coder.ready().len()), (Ok(true), 180));
        assert_eq!(Coder::gunzip().code(b"no", false, true).unwrap_err(), "inflate() failed: 0, -3");
        // All buffers at a time, however much it becomes.
        for flush in [false, true] {
            let mut coder = Coder::gunzip();
            let parts = coded(&mut coder, &gzipped(&vec![0; 10 << 20]), flush).unwrap();
            assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![ALL; 80]);
            assert!(ended(&mut coder).is_empty());
        }
    }

    #[test]
    fn gunzip_takes_any_pieces() {
        let plain = [text(70000), noise(70000), vec![7; 70000]].concat();
        // A header with everything there can be in it.
        let gz = gzipped(&plain);
        let mut head = [&gz[..3], &[0x1f], &gz[4..10], b"\x03\0abc", b"name\0", b"comment\0"].concat();
        let mut sum = Crc::new();
        sum.update(&head);
        let sum = (sum.sum() as u16).to_le_bytes();
        head.extend(sum);
        let long = [&head[..], &gz[10..]].concat();
        for gz in [&gz, &long, &[&long[..], &gz].concat()] {
            let want = if gz.len() > long.len() { [&plain[..], &plain].concat() } else { plain.clone() };
            for size in [1, 7, 100, 4096, 65536, gz.len()] {
                let (mut coder, mut got) = (Coder::gunzip(), Vec::new());
                for part in gz.chunks(size) { got.extend(coded(&mut coder, part, size % 2 == 0).unwrap().concat()); }
                assert!(got == want, "{size}");
                assert!(ended(&mut coder).is_empty());
            }
            for n in [0, 1, 9, 10, 20, 30, 5000, gz.len() - 9, gz.len() - 1] {
                let mut coder = Coder::gunzip();
                coded(&mut coder, &gz[..n], false).unwrap();
                assert!(coder.end().is_err(), "{n}");
            }
        }
        // The header's sum.
        let mut wrong = long.clone();
        wrong[head.len() - 1] ^= 1;
        assert_eq!(coded(&mut Coder::gunzip(), &wrong, false).unwrap_err(), "inflate() failed: 0, -3");
    }

    #[test]
    fn gunzip_fails_where_it_is_malformed() {
        let gz = gzipped(&text(90));
        let n = gz.len();
        let changed = |at: usize| { let mut gz = gz.clone(); gz[at] ^= 0xe0; gz };
        // How much is taken, byte by byte, before it is found.
        for (data, at) in [
            (b"this is not".to_vec(), 2), (changed(0), 2), (changed(1), 2), (changed(2), 4), (changed(3), 4),
            (changed(n - 8), n - 4), (changed(n - 5), n - 4), (changed(n - 4), n), (changed(n - 1), n),
            ([&gz[..], b"\0\0"].concat(), n + 2), ([&gz[..], b"more"].concat(), n + 2), ([&gz[..], &changed(2)].concat(), n + 4),
        ] {
            let mut coder = Coder::gunzip();
            let taken = data.iter().take_while(|c| coded(&mut coder, &[**c], false).is_ok()).count();
            assert_eq!(taken + 1, at, "{data:?}");
            // At once, nothing goes on of what came before it, unless that is flushed.
            let mut coder = Coder::gunzip();
            assert_eq!(coder.code(&data, false, false).unwrap_err(), "inflate() failed: 0, -3");
            assert!(coder.ready().is_empty());
            let mut coder = Coder::gunzip();
            let flushed = coder.code(&data, true, false);
            assert_eq!(flushed, if at > n { Ok(false) } else { Err("inflate() failed: 2, -3".to_string()) });
            assert_eq!(coder.ready(), if at > n { text(90) } else { Vec::new() });
            if at > n {
                coder.written();
                assert_eq!(coder.code(&data, true, false).unwrap_err(), "inflate() failed: 0, -3");
            }
        }
        // A byte after a member may begin another, which has to end.
        let mut coder = Coder::gunzip();
        assert_eq!(coded(&mut coder, &[&gz[..], b"\0"].concat(), false).unwrap(), [text(90)]);
        assert!(coder.end().is_err());
        // Full buffers have gone on before.
        let mut coder = Coder::gunzip();
        let bomb = [gzipped(&vec![0; 300_000]), b"junk".to_vec()].concat();
        for _ in 0..2 {
            assert_eq!((coder.code(&bomb, false, false), coder.ready().len()), (Ok(false), ALL));
            coder.written();
        }
        assert!(coder.code(&bomb, false, false).is_err());
    }
}
