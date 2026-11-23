//! The bodies of proxied answers, taken piece by piece as they come.

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
}
