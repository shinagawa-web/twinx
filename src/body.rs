//! The bodies of proxied answers, taken piece by piece as they come, and when what
//! has come of one goes on to the client.

use std::collections::VecDeque;

/// What is known of a body once a piece of it has come: more is to come; it is
/// whole, and whether anything came after its end; or its chunks are malformed,
/// so that it cannot become whole, whatever follows.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Came { More, Whole { followed: bool }, Malformed }

/// Where a body is: in as many bytes as its length, in those up to the end of the
/// connection, in chunks as the states of ngx_http_parse_chunked(), or past its end.
#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Length, Connection,
    Start, Size, Extension, ExtensionLf, Data, AfterData, AfterDataLf,
    LastExtension, LastExtensionLf, Trailer, TrailerLf, TrailerHeader, TrailerHeaderLf,
    Whole, Malformed,
}

/// Takes a body piece by piece. It keeps nothing of what came but where it is, with
/// the bytes left of the length or of the chunk, or the size of a chunk read so far.
#[derive(Debug)]
pub struct Body { state: State, left: u64, followed: bool }

/// NGX_MAX_OFF_T_VALUE: nginx takes nothing, not even the end of the line, after a
/// size larger than a 16th of it, and at no time one larger than it less 9.
const MAX: u64 = i64::MAX as u64;

impl Body {
    /// A body in chunks, or else of the length; without one, up to the end of the connection.
    pub fn new(length: Option<u64>, chunked: bool) -> Body {
        let state = match length {
            _ if chunked => State::Start,
            Some(0) => State::Whole,
            Some(_) => State::Length,
            None => State::Connection,
        };
        Body { state, left: length.filter(|_| !chunked).unwrap_or(0), followed: false }
    }

    /// Takes the next piece of what comes and appends the body's data in it.
    pub fn take(&mut self, piece: &[u8], data: &mut Vec<u8>) -> Came {
        let mut at = 0;
        while let Some(&c) = piece.get(at) {
            match self.state {
                State::Length | State::Data => {
                    let n = usize::try_from(self.left).unwrap_or(usize::MAX).min(piece.len() - at);
                    data.extend_from_slice(&piece[at..at + n]);
                    at += n;
                    self.left -= n as u64;
                    if self.left == 0 { self.state = if self.state == State::Length { State::Whole } else { State::AfterData }; }
                    continue;
                }
                State::Connection => { data.extend_from_slice(piece); break }
                State::Whole => { self.followed = true; break }
                State::Malformed => break,
                _ => self.state = self.next(c),
            }
            at += 1;
        }
        match self.state {
            State::Whole => Came::Whole { followed: self.followed },
            State::Malformed => Came::Malformed,
            _ => Came::More,
        }
    }

    /// How many more bytes there are at least, up to the body's end: the length of
    /// ngx_http_parse_chunked(). None when only the connection's end tells.
    fn need(&self) -> Option<u64> {
        use State::*;
        Some(match self.state {
            Length => self.left,
            Connection | Malformed => return None,
            Start => 5,
            Size if self.left == 0 => 4,
            Size | Extension => 2 + self.left + 7,
            ExtensionLf => 1 + self.left + 7,
            Data => self.left + 7,
            AfterData => 7,
            AfterDataLf => 6,
            LastExtension | TrailerHeader => 4,
            LastExtensionLf | TrailerHeaderLf => 3,
            Trailer => 2,
            TrailerLf => 1,
            Whole => 0,
        })
    }

    /// Whether the body is cut off when nothing more comes: the connection has ended, or
    /// a read of it failed. Only one the connection's end delimits is whole at its end.
    pub fn cut(&self, failed: bool) -> bool {
        match self.state { State::Whole => false, State::Connection => failed, _ => true }
    }

    /// The state after a byte that is not data, as in ngx_http_parse_chunked() without
    /// keep_trailers: each line ends with CRLF, and trailer lines may be anything.
    fn next(&mut self, c: u8) -> State {
        use State::*;
        let digit = (c as char).to_digit(16).map(u64::from);
        match (self.state, c) {
            (Start, _) => match digit { Some(n) => { self.left = n; Size } None => Malformed },
            (Size, _) if self.left > MAX / 16 => Malformed,
            (Size, _) if digit.is_some() => {
                self.left = self.left * 16 + digit.unwrap_or(0);
                if self.left > MAX - 9 { Malformed } else { Size }
            }
            (Size, b'\r') => if self.left == 0 { LastExtensionLf } else { ExtensionLf },
            (Size, b';' | b' ' | b'\t') => if self.left == 0 { LastExtension } else { Extension },
            (Extension, b'\r') => ExtensionLf,
            (ExtensionLf, b'\n') => Data,
            (AfterData, b'\r') => AfterDataLf,
            (AfterDataLf, b'\n') => Start,
            (LastExtension, b'\r') => LastExtensionLf,
            (LastExtensionLf | TrailerHeaderLf, b'\n') => Trailer,
            (Trailer, b'\r') => TrailerLf,
            (TrailerLf, b'\n') => Whole,
            (TrailerHeader, b'\r') => TrailerHeaderLf,
            (Trailer | TrailerHeader, c) if c != b'\n' => TrailerHeader,
            (Extension | LastExtension, c) if c != b'\n' => self.state,
            _ => Malformed,
        }
    }
}

/// The sizes of the buffers a proxied answer is read into: proxy_buffer_size, of the
/// first one, which holds the head too, the number and the size of proxy_buffers, and
/// proxy_busy_buffers_size.
#[derive(Clone, Copy, Debug)]
pub struct Sizes { pub first: usize, pub count: usize, pub size: usize, pub busy: usize }

/// The data of a body and how much of it may be sent, as ngx_event_pipe() tells with
/// proxy_buffering on. What comes is read into buffers one after another, as long as
/// there is something to read and a buffer to read it into. Then the full buffers go
/// on, and one that is not full only if the body may end with what it has. What goes
/// on is written in parts of buffers of the busy size, and the buffers are used again.
/// Without buffering, as ngx_http_upstream_process_non_buffered_request() tells,
/// what came in each read goes on.
#[derive(Debug)]
pub struct Buffers {
    body: Body,
    /// The data that has come, how much of it may be sent, and where the parts of that
    /// end but for the last, with the number of their buffers.
    pub data: Vec<u8>,
    pub ready: usize,
    parts: Vec<(usize, usize)>,
    /// Whether the body goes on with any data, as that of an answer over HTTP/2 does.
    any: bool,
    sizes: Option<Sizes>,
    /// The sizes of the buffers there are to read into, the first of which is being
    /// filled, its room, what was read into it, how many buffers more there may be, what
    /// the body needed when it was begun, and the sizes of the full ones.
    free: VecDeque<usize>,
    room: usize,
    held: usize,
    more: usize,
    need: Option<u64>,
    full: Vec<usize>,
    /// The sum of the sizes of the last part's buffers.
    busy: usize,
    came: Came,
}

impl Buffers {
    /// For a body that comes after a head of the length, without sizes one that is not buffered.
    pub fn new(body: Body, any: bool, sizes: Option<Sizes>, head: usize, data: Vec<u8>) -> Buffers {
        let s = sizes.unwrap_or(Sizes { first: 0, count: 0, size: 0, busy: 0 });
        let came = if body.need() == Some(0) { Came::Whole { followed: false } } else { Came::More };
        let need = if any { Some(1) } else { body.need() };
        let mut buffers = Buffers { body, data, ready: 0, parts: Vec::new(), any, sizes, free: VecDeque::from([s.first]), room: s.first.saturating_sub(head), held: 0, more: s.count, need, full: Vec::new(), busy: 0, came };
        if sizes.is_some() && buffers.room == 0 { buffers.pass(); }
        buffers
    }

    /// What is known of the body from what has gone on of it, or that it is whole.
    pub fn came(&self) -> Came {
        self.came
    }

    /// Whether the body is cut off, as Body::cut() tells.
    pub fn cut(&self, failed: bool) -> bool {
        self.body.cut(failed)
    }

    /// How much there may be read before what goes on is written.
    pub fn room(&self) -> usize {
        let Some(s) = self.sizes else { return usize::MAX };
        self.room + self.free.iter().skip(1).sum::<usize>() + self.more.saturating_mul(s.size)
    }

    /// Takes what was read.
    pub fn take(&mut self, mut piece: &[u8]) {
        while !piece.is_empty() {
            if self.came != Came::More {
                // After the end, or malformed: it is only known that there is more.
                if let Came::Whole { .. } = self.came { self.came = self.body.take(piece, &mut self.data); }
                return;
            }
            // More than there are buffers for may come with the head.
            if let Some(s) = self.sizes.filter(|_| self.room == 0) {
                self.free.push_back(s.size);
                self.room = s.size.max(1);
            }
            let (part, rest) = piece.split_at(if self.sizes.is_some() { self.room.min(piece.len()) } else { piece.len() });
            let came = self.body.take(part, &mut self.data);
            piece = rest;
            self.held += part.len();
            self.room = self.room.saturating_sub(part.len());
            if let Came::Whole { .. } = came { self.came = came; self.let_go(); } else if self.room == 0 { self.pass(); }
        }
    }

    /// Passes the buffer being filled on, if it may be, when there is nothing more to
    /// read for now.
    pub fn pause(&mut self) {
        if self.held > 0 && self.need.is_some_and(|n| self.held as u64 >= n) { self.pass(); }
    }

    /// All that has come goes on, at once, as nothing more is to come.
    pub fn let_go(&mut self) {
        if self.came == Came::More { self.look(); }
        self.ready = self.data.len();
        self.parts.clear();
    }

    /// What has not gone on by now will not.
    pub fn drop_held(&mut self) {
        self.data.truncate(self.ready);
    }

    /// Where the next part of what goes on ends, the last one if asked for at once.
    pub fn part(&self, at_once: bool) -> usize {
        self.parts.first().map_or(self.ready, |p| if at_once { self.ready } else { p.0 })
    }

    /// The data up to there, the end of a part, has been written: its buffers are used again.
    pub fn written(&mut self, end: usize) {
        while !self.parts.is_empty() && self.parts[0].0 <= end {
            let n = self.parts.remove(0).1;
            self.free(n);
        }
        if end == self.ready {
            self.free(self.full.len());
            self.busy = 0;
        }
        self.data.drain(..end);
        self.ready -= end;
        for p in &mut self.parts { p.0 -= end; }
    }

    /// So many of the full buffers are free: they are the next to be filled, as in
    /// ngx_event_pipe_add_free_buf(), after one in which there is something already.
    fn free(&mut self, n: usize) {
        for (i, size) in self.full.drain(..n).enumerate() { self.free.insert(i + usize::from(self.held > 0), size); }
        if self.held == 0 { self.room = self.free.front().copied().unwrap_or(0); }
    }

    /// Looks at what has come, as the filter of the body's data does with each buffer.
    fn look(&mut self) {
        if self.body.state == State::Malformed { self.came = Came::Malformed; }
        if !self.any { self.need = self.body.need(); }
    }

    /// The buffer being filled goes on, or is free again if there is no data in it, and
    /// the next one is filled.
    fn pass(&mut self) {
        self.look();
        let Some(s) = self.sizes else { self.ready = self.data.len(); return };
        let size = self.free.pop_front().unwrap_or(s.size);
        if self.data.len() > self.ready {
            let parted: usize = self.parts.iter().map(|p| p.1).sum();
            if self.busy > 0 && self.busy + size > s.busy {
                self.parts.push((self.ready, self.full.len() - parted));
                self.busy = 0;
            }
            self.busy += size;
            self.full.push(size);
            self.ready = self.data.len();
        } else {
            self.free.push_back(size);
        }
        if self.free.is_empty() && self.more > 0 {
            self.more -= 1;
            self.free.push_back(s.size);
        }
        (self.held, self.room) = (0, self.free.front().copied().unwrap_or(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MORE: Came = Came::More;
    const WHOLE: Came = Came::Whole { followed: false };
    const FOLLOWED: Came = Came::Whole { followed: true };
    const MALFORMED: Came = Came::Malformed;

    /// The data of a body that comes in the pieces, what is known of it then, and
    /// whether it is cut off at the end of the connection and when a read fails.
    fn taken<'a>(body: &mut Body, pieces: impl IntoIterator<Item = &'a [u8]>) -> (Vec<u8>, Came, [bool; 2]) {
        let mut data = Vec::new();
        let mut came = body.take(b"", &mut data);
        for piece in pieces { came = body.take(piece, &mut data); }
        (data, came, [body.cut(false), body.cut(true)])
    }

    /// The same in one piece, byte by byte, and in two, split at every position.
    fn same(after: &[u8], length: Option<u64>, chunked: bool) -> (Vec<u8>, Came, [bool; 2]) {
        let new = || Body::new(length, chunked);
        let one = taken(&mut new(), [after]);
        assert_eq!(taken(&mut new(), after.chunks(1)), one, "{}", after.escape_ascii());
        for at in 0..=after.len() { assert_eq!(taken(&mut new(), [&after[..at], &after[at..]]), one, "{} {at}", after.escape_ascii()); }
        one
    }

    /// What a chunked body is, the data and whether it is whole.
    fn chunked(after: &[u8]) -> (Vec<u8>, Came) {
        let (data, came, cut) = same(after, None, true);
        // A chunked body is cut off unless it is whole.
        assert_eq!(cut, [!matches!(came, Came::Whole { .. }); 2], "{}", after.escape_ascii());
        (data, came)
    }

    #[test]
    fn data_of_chunks() {
        assert_eq!(chunked(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n3\r\nzzz\r\n"), (b"abcde".to_vec(), FOLLOWED));
        assert_eq!(chunked(b"3\r\nabc\r\n2;x=y\nde\n0\r\n\r\n3\r\nzzz\r\n"), (b"abc".to_vec(), MALFORMED));
        assert_eq!(chunked(b"3\r\nabc\r\n2\r\nd"), (b"abcd".to_vec(), MORE));
        assert_eq!(chunked(b"3\r\nabc"), (b"abc".to_vec(), MORE));
        assert_eq!(chunked(b"3\r\nabcd\r\n"), (b"abc".to_vec(), MALFORMED));
        assert_eq!(chunked(b"x\r\n"), (Vec::new(), MALFORMED));
        // Sizes up to the largest that nginx takes.
        assert_eq!(chunked(b"2\r\nab\r\n7ffffffffffffff\r\ncd\r\n"), (b"abcd\r\n".to_vec(), MORE));
        for size in ["800000000000000", "7fffffffffffffff", "8000000000000000", "fffffffffffffff0", "ffffffffffffffef", "ffffffffffffffff", "10000000000000000"] {
            for end in ["\n", "\r\n", ";x\r\n"] {
                assert_eq!(chunked(format!("{size}{end}ab\n0\n\n").as_bytes()), (Vec::new(), MALFORMED));
                assert_eq!(chunked(format!("2\r\nab\r\n{size}{end}cd\r\n0\r\n\r\n").as_bytes()), (b"ab".to_vec(), MALFORMED));
            }
        }
        // Without what follows it, a size is too large only later.
        for (size, came) in [("800000000000000", MORE), ("7ffffffffffffff6", MORE), ("7ffffffffffffff7", MALFORMED), ("7fffffffffffffff", MALFORMED), ("8000000000000000", MALFORMED)] {
            assert_eq!(chunked(size.as_bytes()), (Vec::new(), came), "{size}");
        }
        assert_eq!(chunked(b"00000000000000000000000002\r\nab\r\n00000000000000000000\r\n\r\n"), (b"ab".to_vec(), WHOLE));
    }

    #[test]
    fn no_chunked_body_panics() {
        // xorshift64, the same numbers each time.
        let mut x = 0x2545_f491_4f6c_dd1d_u64;
        let mut upto = move |n: usize| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x % n as u64) as usize
        };
        const PARTS: [&[u8]; 28] = [
            b"0", b"1", b"2", b"A", b"f", b"10", b"ab", b"\r", b"\n", b"\r\n", b";", b";x=y", b" ", b"\t", b"+", b"-", b"zz", b"\0", b"\xff", "\u{e9}".as_bytes(),
            b"0\r\n\r\n", b"2\r\nab\r\n", b"X: 1\r\n", b"ffffffffffffffff", b"fffffffffffffff0", b"7fffffffffffffff", b"7ffffffffffffff", b"10000000000000000",
        ];
        const BODIES: [&[u8]; 4] = [b"2\r\nab\r\n0\r\n\r\n", b"A;x=y\r\n0123456789\r\n2\r\nab\r\n0\r\nX: 1\r\n\r\n", b"3\nabc\n0\n\n", b"2\r\nab\r\nffffffffffffffff\r\ncd\r\n0\r\n\r\n"];
        for i in 0..400_000 {
            let mut body = Vec::new();
            if i % 2 == 0 {
                for _ in 0..upto(12) { body.extend_from_slice(PARTS[upto(PARTS.len())]); }
            } else {
                // A part in the place of some bytes, a few times, and the end left out.
                body.extend_from_slice(BODIES[upto(BODIES.len())]);
                for _ in 0..upto(4) {
                    let from = upto(body.len() + 1);
                    let to = (from + upto(4)).min(body.len());
                    body.splice(from..to, PARTS[upto(PARTS.len())].iter().copied());
                }
                if upto(3) == 0 { body.truncate(upto(body.len() + 1)); }
            }
            let one = taken(&mut Body::new(None, true), [body.as_slice()]);
            assert!(one.0.len() <= body.len(), "{}", body.escape_ascii());
            let (mut pieces, mut rest) = (Vec::new(), body.as_slice());
            while !rest.is_empty() {
                let (piece, after) = rest.split_at(upto(rest.len() + 1));
                pieces.push(piece);
                rest = after;
            }
            assert_eq!(taken(&mut Body::new(None, true), pieces.iter().copied()), one, "{pieces:?}");
        }
    }

    #[test]
    fn ends_of_answers() {
        let length: [(&[u8], u64, bool); 5] = [(b"ab", 2, true), (b"", 0, true), (b"a", 2, false), (b"abc", 2, false), (b"a", 0, false)];
        for (after, n, is) in length { assert_eq!(same(after, Some(n), false).1 == WHOLE, is, "{after:?} {n}"); }
        let cases: [(&[u8], bool); 25] = [
            (b"3\r\nabc\r\n0\r\n\r\n", true),
            (b"0\r\n\r\n", true),
            (b"A\r\n0123456789\r\n000\r\n\r\n", true),
            // Trailer lines and chunk extensions.
            (b"3\r\nabc\r\n0\r\nX: 1\r\nY: 2\r\n\r\n", true),
            (b"3;x=y\r\nabc\r\n0;z\r\n\r\n", true),
            // A trailer line may be anything without a CR or LF.
            (b"0\r\n :\0 \x7f\r\n\r\n", true),
            // Not all of it.
            (b"", false),
            (b"3\r\nab", false),
            (b"3\r\nabc", false),
            (b"3\r\nabc\r\n", false),
            (b"3\r\nabc\r\n0\r\n", false),
            (b"3\r\nabc\r\n0\r\n\r", false),
            (b"3\r\nabc\r\n0\r\nX: 1\r\n", false),
            // More than it.
            (b"3\r\nabc\r\n0\r\n\r\nH", false),
            (b"0\r\n\r\n\r\n", false),
            // Malformed.
            (b"3\nabc\n0\nX: 1\n\n", false),
            (b"x\r\n\r\n", false),
            (b"\r\n\r\n", false),
            (b"3\r\nabcd\r\n0\r\n\r\n", false),
            (b"+1\r\na\r\n0\r\n\r\n", false),
            (b"-0\r\n\r\n", false),
            (b" 0\r\n\r\n", false),
            (b"0;\rx\r\n\r\n", false),
            (b"ffffffffffffffff\r\na\r\n0\r\n\r\n", false),
            (b"10000000000000000\r\na\r\n0\r\n\r\n", false),
        ];
        for (after, is) in cases { assert_eq!(chunked(after).1 == WHOLE, is, "{}", after.escape_ascii()); }
        for after in [&b""[..], b"ab", b"0\r\n\r\n"] { assert_eq!(same(after, None, false), (after.to_vec(), MORE, [false, true])); }
    }

    #[test]
    fn bodies_of_a_length() {
        for (after, data, came) in [(&b""[..], &b""[..], MORE), (b"a", b"a", MORE), (b"ab", b"ab", WHOLE), (b"abc", b"ab", FOLLOWED), (b"0\r\n", b"0\r", FOLLOWED)] {
            assert_eq!(same(after, Some(2), false), (data.to_vec(), came, [came == MORE; 2]), "{after:?}");
        }
        assert_eq!(same(b"", Some(0), false), (Vec::new(), WHOLE, [false; 2]));
        assert_eq!(same(b"a", Some(0), false), (Vec::new(), FOLLOWED, [false; 2]));
    }

    #[test]
    fn bodies_cut_off() {
        let cases: [(&[u8], &[u8], Came); 48] = [
            // In or before a size, with what may follow it.
            (b"", b"", MORE), (b"0", b"", MORE), (b"2", b"", MORE), (b"2\r", b"", MORE), (b"2;x=y", b"", MORE), (b"2 ", b"", MORE), (b"2 x\r\nab", b"ab", MORE), (b"2\tx\r\nab\r\n0 x\r\n\r\n", b"ab", WHOLE),
            // In a chunk, what came of it, and after it.
            (b"2\r\n", b"", MORE), (b"2\r\na", b"a", MORE), (b"2\r\nab", b"ab", MORE), (b"2\r\nab\r", b"ab", MORE),
            (b"2\r\nab\r\n", b"ab", MORE), (b"2\r\nab\r\n3", b"ab", MORE), (b"2\r\nab\r\n3;x\r\ncd", b"abcd", MORE), (b"A \r\n0123456789\r\n0", b"0123456789", MORE),
            // After the last chunk, before the empty line.
            (b"0\r\n", b"", MORE), (b"0\r\n\r", b"", MORE), (b"2\r\nab\r\n0\r\n", b"ab", MORE), (b"0\r\nX: 1", b"", MORE), (b"0\r\nX: 1\r\n", b"", MORE),
            // Whole, or more than it.
            (b"0\r\n\r\n", b"", WHOLE), (b"2\r\nab\r\n0\r\nX: 1\r\n\r\n", b"ab", WHOLE), (b"0\r\n\r\nab", b"", FOLLOWED),
            // Malformed.
            (b"zz", b"", MALFORMED), (b"\r", b"", MALFORMED), (b"2\r\nab\r\nzz\r\n", b"ab", MALFORMED), (b"2\r\nabc", b"ab", MALFORMED), (b"2\r\nab\rc", b"ab", MALFORMED), (b"2\rx", b"", MALFORMED), (b"+2\r\nab", b"", MALFORMED), (b" 2\r\nab", b"", MALFORMED), (b"2x\r\nab", b"", MALFORMED),
            (b"0\r\nX\r: 1", b"", MALFORMED), (b"7fffffffffffffff\r\nab", b"", MALFORMED), (b"10000000000000002\r\nab", b"", MALFORMED),
            // Lines that end with an LF only: of a size, an extension, the data, the last
            // chunk, a trailer, and the empty one.
            (b"2\na", b"", MALFORMED), (b"2;x\na", b"", MALFORMED), (b"2\nab\n", b"", MALFORMED), (b"2\r\nab\n", b"ab", MALFORMED), (b"0\n\n", b"", MALFORMED), (b"0\n\r\n", b"", MALFORMED), (b"0;x\n\r\n", b"", MALFORMED),
            (b"0\r\nX: 1\n\r\n", b"", MALFORMED), (b"0\r\n\n", b"", MALFORMED), (b"0\r\nX: 1\r\n\n", b"", MALFORMED),
            // The largest size and the next.
            (b"7ffffffffffffff\r\nab", b"ab", MORE), (b"800000000000000\r\nab", b"", MALFORMED),
        ];
        for (after, data, came) in cases { assert_eq!(chunked(after), (data.to_vec(), came), "{}", after.escape_ascii()); }
    }

    #[test]
    fn long_bodies_take_linear_time() {
        let chunk = [b"3e8\r\n".as_slice(), &[b'x'; 1000], b"\r\n"].concat();
        let mut sent = chunk.repeat((64 << 20) / chunk.len());
        sent.extend_from_slice(b"0\r\n\r\n");
        let started = std::time::Instant::now();
        let (data, came, _) = taken(&mut Body::new(None, true), sent.chunks(4096));
        assert_eq!((data.len(), came), (sent.len() / chunk.len() * 1000, WHOLE));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        // Whatever came, it keeps as much.
        assert!(size_of::<Body>() <= 16);
    }

    #[test]
    fn what_bodies_need() {
        assert_eq!([Body::new(Some(9), false).need(), Body::new(Some(0), false).need(), Body::new(None, false).need()], [Some(9), Some(0), None]);
        let cases: [(&[u8], u64); 21] = [
            (b"", 5), (b"0", 4), (b"0\r", 3), (b"0\r\n", 2), (b"0\r\n\r", 1), (b"0\r\nX", 4), (b"0\r\nX\r", 3), (b"0\r\nX\r\n", 2), (b"0;x", 4), (b"0\r\n\r\n", 0),
            (b"a", 2 + 10 + 7), (b"a;x", 2 + 10 + 7), (b"a\r", 1 + 10 + 7), (b"a\r\n", 10 + 7), (b"a\r\n01234", 5 + 7), (b"a\r\n0123456789", 7), (b"a\r\n0123456789\r", 6), (b"a\r\n0123456789\r\n", 5),
            (b"a\r\n0123456789\r\n0", 4), (b"a\r\n0123456789\r\n1", 2 + 1 + 7), (b"64\r\n0123456789", 90 + 7),
        ];
        for (after, need) in cases {
            let mut body = Body::new(None, true);
            body.take(after, &mut Vec::new());
            assert_eq!(body.need(), Some(need), "{}", after.escape_ascii());
        }
    }

    const SIZES: Sizes = Sizes { first: 4096, count: 8, size: 4096, busy: 8192 };

    fn buffers(body: Body, sizes: Option<Sizes>, head: usize) -> Buffers {
        Buffers::new(body, false, sizes, head, Vec::new())
    }

    /// The parts that go on once the piece has come and nothing more is there.
    fn parts(b: &mut Buffers, piece: &[u8]) -> Vec<usize> {
        b.take(piece);
        b.pause();
        let mut parts = Vec::new();
        while b.ready > 0 {
            let end = b.part(false);
            parts.push(end);
            b.written(end);
        }
        parts
    }

    #[test]
    fn full_buffers_go_on() {
        let x = [b'x'; 60000];
        for length in [None, Some(60000)] {
            // The first has the head.
            let mut b = buffers(Body::new(length, false), Some(SIZES), 96);
            assert_eq!((b.room(), parts(&mut b, &x[..3999]), b.room()), (4000 + 8 * 4096, vec![], 1 + 8 * 4096));
            assert_eq!((parts(&mut b, &x[..1]), b.room()), (vec![4000], 9 * 4096));
            assert_eq!((parts(&mut b, &x[..4095]), parts(&mut b, &x[..2])), (vec![], vec![4096]));
            // In parts of two buffers, and what is not full stays.
            assert_eq!(parts(&mut b, &x[..5 * 4096]), [8192, 8192, 4096]);
            b.take(&x[..4094]);
            assert_eq!((b.ready, b.data.len(), b.room()), (0, 4095, 8 * 4096 + 1));
            b.drop_held();
            assert!(b.data.is_empty());
        }
        // All of it at once, at the end.
        let mut b = buffers(Body::new(Some(30000), false), Some(SIZES), 96);
        b.take(&x[..30000]);
        assert_eq!((b.came(), b.part(true)), (Came::Whole { followed: false }, 30000));
        let mut b = buffers(Body::new(None, false), Some(SIZES), 96);
        b.take(&x[..30000]);
        assert_eq!((b.came(), b.part(false), b.part(true)), (Came::More, 4000 + 4096, 4000 + 6 * 4096));
        b.let_go();
        assert_eq!((b.came(), b.part(false), b.cut(false), b.cut(true)), (Came::More, 30000, false, true));
        // What is there after the end.
        let mut b = buffers(Body::new(Some(10), false), Some(SIZES), 96);
        assert_eq!((parts(&mut b, &x[..5]), parts(&mut b, &x[..6]), b.came()), (vec![], vec![10], Came::Whole { followed: true }));
    }

    #[test]
    fn buffers_are_used_again() {
        let x = [b'x'; 2000];
        // As they were when measured with nginx: one is filled after another, those that
        // were full next, or the same one if the piece ended with it.
        for (first, count, size, piece, want) in [
            (2048, 4, 8192, 2000, [(0, 1980), (5, 8192), (6, 2048), (10, 8192), (11, 2048), (15, 8192), (16, 2048)].as_slice()),
            (8192, 9, 2048, 1000, &[(8, 8124), (10, 2048), (18, 8192)]),
        ] {
            let mut b = buffers(Body::new(None, false), Some(Sizes { first, count, size, busy: 8192 }), 68);
            let got: Vec<_> = (0..19).flat_map(|i| parts(&mut b, &x[..piece]).into_iter().map(move |n| (i, n))).collect();
            assert_eq!(got, want, "{first} {size}");
        }
        // More than there is room for may come with the head.
        let mut b = buffers(Body::new(None, false), Some(Sizes { first: 100, count: 2, size: 100, busy: 200 }), 100);
        assert_eq!(parts(&mut b, &x[..950]), [200, 200, 200, 200, 100]);
        assert_eq!(b.data.len(), 50);
    }

    #[test]
    fn chunks_go_on_if_the_body_may_end_there() {
        let mut b = buffers(Body::new(None, true), Some(SIZES), 96);
        for (piece, want) in [
            (&b"5\r\nabcde\r\n"[..], &[5][..]), (b"3\r\n", &[]), (b"abc", &[3]), (b"\r\n", &[]), (b"2\r\nab", &[2]), (b"\r\n5\r\nab", &[2]),
            // The rest of a chunk is less than it and the end of the body.
            (b"cde\r\n", &[]), (b"5\r\nab", &[5]), (b"cde\r\n0\r\n", &[]),
        ] {
            assert_eq!(parts(&mut b, piece), want, "{}", piece.escape_ascii());
        }
        assert_eq!((parts(&mut b, b"\r\n"), b.came()), (vec![3], Came::Whole { followed: false }));
        // What makes it chunks takes room too; a buffer with nothing else is used again at once.
        let mut b = buffers(Body::new(None, true), Some(SIZES), 4090);
        assert_eq!((parts(&mut b, b"2000;x\r\n"), b.room()), (vec![], 4094 + 8 * 4096));
        assert_eq!(parts(&mut b, &[b'x'; 8190]), [8190]);
        // It is malformed once the buffer goes on, or at the end.
        for (piece, came) in [(&b"zz\r\n"[..], Came::More), (b"zz\r\nz", Came::Malformed), (b"2\r\nab\r\nzz", Came::Malformed)] {
            let mut b = buffers(Body::new(None, true), Some(SIZES), 96);
            b.take(piece);
            b.pause();
            assert_eq!(b.came(), came, "{}", piece.escape_ascii());
            b.let_go();
            assert_eq!(b.came(), Came::Malformed);
        }
        // Any of an answer over HTTP/2 goes on.
        let mut b = Buffers::new(Body::new(Some(100), false), true, Some(SIZES), 96, Vec::new());
        assert_eq!((parts(&mut b, b"a"), parts(&mut b, b"bc")), (vec![1], vec![2]));
    }

    #[test]
    fn without_buffering_all_goes_on() {
        let mut b = buffers(Body::new(Some(20000), false), None, 96);
        assert_eq!((parts(&mut b, b"a"), parts(&mut b, &[b'x'; 10000]), b.came()), (vec![1], vec![10000], Came::More));
        assert_eq!((parts(&mut b, &[b'x'; 10000]), b.came()), (vec![9999], Came::Whole { followed: true }));
        let mut b = buffers(Body::new(None, true), None, 96);
        assert_eq!((parts(&mut b, b"5\r\na"), parts(&mut b, b"b"), b.came()), (vec![1], vec![1], Came::More));
        b.take(b"cde\r\nzz");
        assert_eq!(b.came(), Came::Malformed);
    }
}
