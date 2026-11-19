//! The range filter (ngx_http_range_filter_module): a 200 response that
//! allows ranges becomes 206 Partial Content for one satisfiable byte range
//! and 416 Requested Range Not Satisfiable when no range is satisfiable;
//! otherwise it is sent whole with "Accept-Ranges: bytes".
//!
//! Not implemented yet, so such requests get the whole response: several
//! ranges (a multipart/byteranges body) and If-Range.

use crate::handler::Ctx;
use crate::response::{self, Response};

/// The range header filter, run after add_header as in nginx.
pub fn filter(cx: &Ctx, mut resp: Response) -> Response {
    let len = match resp.content_length {
        Some(len) if resp.status == 200 && resp.allow_ranges => len,
        _ => return resp,
    };
    let range = cx
        .req
        .header("range")
        .map(str::as_bytes)
        .filter(|v| v.len() >= 7 && v[..6].eq_ignore_ascii_case(b"bytes="));
    let parsed = range.filter(|_| cx.req.header("if-range").is_none()).map(|spec| parse(&spec[6..], len));
    match parsed {
        Some(None) => not_satisfiable(cx, resp, len),
        Some(Some(ranges)) if ranges.len() == 1 => partial(resp, ranges[0], len),
        _ => {
            resp.headers.push(("Accept-Ranges".into(), "bytes".into()));
            resp
        }
    }
}

/// ngx_http_range_singlepart_header and the body it sends.
fn partial(mut resp: Response, (start, end): (u64, u64), len: u64) -> Response {
    resp.status = 206;
    resp.content_length = Some(end - start);
    resp.headers.push(("Content-Range".into(), format!("bytes {start}-{}/{len}", end - 1)));
    // A HEAD response has no body to cut.
    resp.body = resp.body.get(start as usize..end as usize).map(<[u8]>::to_vec).unwrap_or_default();
    resp
}

/// ngx_http_range_not_satisfiable: the special 416 page with
/// "Content-Range: bytes */<length>". It keeps the headers already added
/// except ETag, which the special response clears with Last-Modified.
fn not_satisfiable(cx: &Ctx, resp: Response, len: u64) -> Response {
    let mut out = response::special(416, cx.conf.server_tokens);
    out.headers = resp.headers.into_iter().filter(|(n, _)| !n.eq_ignore_ascii_case("etag")).collect();
    out.headers.push(("Content-Range".into(), format!("bytes */{len}")));
    out
}

/// ngx_http_range_parse on the value after "bytes=", for a response of
/// `len` bytes. None means not satisfiable; an empty list means the whole
/// response is sent; otherwise the ranges are [start, end) pairs.
pub fn parse(spec: &[u8], len: u64) -> Option<Vec<(u64, u64)>> {
    // nginx reads the value up to its terminating NUL.
    let s: Vec<u8> = spec.iter().copied().chain([0]).collect();
    let (mut i, mut ranges, mut size) = (0, Vec::new(), 0u64);
    let (mut declined, mut more) = (false, true);
    while more {
        let (start, end) = one_range(&s, &mut i, len)?;
        if start < end {
            ranges.push((start, end));
            size = size.saturating_add(end - start);
        }
        // An empty range starting at 0 (an empty response) declines.
        declined = start == 0 && end == 0;
        more = !declined && s[i] == b',';
        i += 1;
    }
    if !declined && ranges.is_empty() {
        return None;
    }
    Some(if declined || size > len { Vec::new() } else { ranges })
}

/// One "start-end", "start-" or "-suffix" range, with the end made
/// exclusive and cut to the length; `*i` is left on the "," or NUL after it.
fn one_range(s: &[u8], i: &mut usize, len: u64) -> Option<(u64, u64)> {
    skip_spaces(s, i);
    if s[*i] == b'-' {
        *i += 1;
        let suffix = number(s, i)?;
        at_range_end(s, i)?;
        return Some((len.saturating_sub(suffix), len));
    }
    let start = number(s, i)?;
    skip_spaces(s, i);
    (s[*i] == b'-').then_some(())?;
    *i += 1;
    skip_spaces(s, i);
    if s[*i] == b',' || s[*i] == 0 {
        return Some((start, len));
    }
    let end = number(s, i)?;
    at_range_end(s, i)?;
    Some((start, if end >= len { len } else { end + 1 }))
}

fn skip_spaces(s: &[u8], i: &mut usize) {
    *i += s[*i..].iter().take_while(|&&b| b == b' ').count();
}

/// Spaces, then "," or the end of the value.
fn at_range_end(s: &[u8], i: &mut usize) -> Option<()> {
    skip_spaces(s, i);
    (s[*i] == b',' || s[*i] == 0).then_some(())
}

/// Decimal digits that fit in off_t; None when there are none or too many.
fn number(s: &[u8], i: &mut usize) -> Option<u64> {
    let digits = s[*i..].iter().take_while(|b| b.is_ascii_digit()).count();
    let text = std::str::from_utf8(&s[*i..*i + digits]).ok()?;
    *i += digits;
    text.parse::<i64>().ok().map(|n| n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(spec: &str, len: u64) -> Option<Vec<(u64, u64)>> {
        parse(spec.as_bytes(), len)
    }

    #[test]
    fn parses_single_ranges() {
        assert_eq!(p("0-4", 21), Some(vec![(0, 5)]));
        assert_eq!(p("-5", 21), Some(vec![(16, 21)]));
        assert_eq!(p("-50", 21), Some(vec![(0, 21)]));
        assert_eq!(p("10-", 21), Some(vec![(10, 21)]));
        assert_eq!(p("5-1000", 21), Some(vec![(5, 21)]));
        assert_eq!(p(" 1 - 2 ", 21), Some(vec![(1, 3)]));
    }

    #[test]
    fn unsatisfiable_and_malformed_ranges() {
        assert_eq!(p("100-200", 21), None);
        assert_eq!(p("21-", 21), None);
        assert_eq!(p("x", 21), None);
        assert_eq!(p("1-2x", 21), None);
        assert_eq!(p("1x", 21), None);
        assert_eq!(p("-", 21), None);
        assert_eq!(p("99999999999999999999-", 21), None);
    }

    #[test]
    fn declined_ranges_send_the_whole_response() {
        // An empty response, and ranges that add up to more than the length.
        assert_eq!(p("0-", 0), Some(vec![]));
        assert_eq!(p("-5", 0), Some(vec![]));
        assert_eq!(p("0-15,5-20", 21), Some(vec![]));
    }

    #[test]
    fn parses_several_ranges() {
        assert_eq!(p("0-1, 3-4", 21), Some(vec![(0, 2), (3, 5)]));
        assert_eq!(p("100-200,0-1", 21), Some(vec![(0, 2)]));
        assert_eq!(p("0-1,", 21), None);
    }
}
