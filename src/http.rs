//! Parsing HTTP/1.x requests the way nginx does: the request line, the
//! headers, the request URI (decoding and normalizing it) and the Host.

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: String,
    /// The request target as received (only the path and query of an absolute URI).
    pub unparsed_uri: String,
    /// The decoded and normalized path.
    pub uri: String,
    pub args: String,
    pub version: (u8, u8),
    /// The request line as received, without CRLF.
    pub request_line: String,
    pub headers: Vec<(String, String)>,
    /// The host from an absolute URI or the Host header: lowercased, without port.
    pub host: Option<String>,
    pub content_length: Option<u64>,
    pub chunked: bool,
    pub keepalive: bool,
    pub expect_continue: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn has_body(&self) -> bool {
        self.chunked || self.content_length.is_some_and(|n| n > 0)
    }
}

/// Why a request could not be parsed: the status to answer with.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ParseError(pub u16);

fn is_method_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b == b'_' || b == b'-'
}

fn is_header_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

/// Parses a request head (everything up to and including the empty line).
pub fn parse_head(head: &[u8], merge_slashes: bool) -> Result<Request, ParseError> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let mut request_line = lines.next().unwrap_or("");
    // nginx skips empty lines before the request line.
    while request_line.is_empty() {
        request_line = match lines.next() {
            Some(l) => l,
            None => return Err(ParseError(400)),
        };
    }
    let parts: Vec<&str> = request_line.split(' ').filter(|p| !p.is_empty()).collect();
    if parts.len() != 3 {
        return Err(ParseError(400));
    }
    let (method, target, proto) = (parts[0], parts[1], parts[2]);
    if method.is_empty() || !method.bytes().all(is_method_char) {
        return Err(ParseError(400));
    }
    let version = parse_version(proto)?;
    if version.0 > 1 {
        return Err(ParseError(505));
    }
    let (unparsed_uri, uri_host) = split_absolute(target)?;
    let (path, args) = match unparsed_uri.find('?') {
        Some(i) => (&unparsed_uri[..i], unparsed_uri[i + 1..].to_string()),
        None => (unparsed_uri.as_str(), String::new()),
    };
    let uri = normalize_uri(path, merge_slashes)?;

    let mut headers = Vec::new();
    let mut host_header: Option<String> = None;
    let mut content_length: Option<u64> = None;
    let mut transfer_encoding: Option<String> = None;
    let mut connection: Option<String> = None;
    let mut expect_continue = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(ParseError(400));
        }
        let Some(colon) = line.find(':') else {
            return Err(ParseError(400));
        };
        let name = &line[..colon];
        let value = line[colon + 1..].trim_matches(|c| c == ' ' || c == '\t').to_string();
        if name.is_empty() {
            return Err(ParseError(400));
        }
        if !name.bytes().all(is_header_name_char) {
            // ignore_invalid_headers: such headers are dropped.
            continue;
        }
        match name.to_ascii_lowercase().as_str() {
            "host" => {
                if host_header.is_some() {
                    return Err(ParseError(400));
                }
                host_header = Some(value.clone());
            }
            "content-length" => {
                if content_length.is_some() {
                    return Err(ParseError(400));
                }
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ParseError(400));
                }
                content_length = Some(value.parse().map_err(|_| ParseError(400))?);
            }
            "transfer-encoding" => {
                if transfer_encoding.is_some() {
                    return Err(ParseError(400));
                }
                transfer_encoding = Some(value.clone());
            }
            "connection" => connection = Some(value.to_ascii_lowercase()),
            "expect" => expect_continue = value.eq_ignore_ascii_case("100-continue"),
            _ => {}
        }
        headers.push((name.to_string(), value));
    }

    let host = match uri_host {
        Some(h) => Some(validate_host(&h)?),
        None => match &host_header {
            Some(h) => Some(validate_host(h)?),
            None => None,
        },
    };
    if host_header.is_none() && version >= (1, 1) {
        return Err(ParseError(400));
    }
    let mut chunked = false;
    if let Some(te) = &transfer_encoding {
        if version < (1, 1) {
            return Err(ParseError(400));
        }
        if !te.eq_ignore_ascii_case("chunked") {
            return Err(ParseError(501));
        }
        if content_length.is_some() {
            return Err(ParseError(400));
        }
        chunked = true;
    }
    let keepalive = match connection.as_deref() {
        Some(c) if c.split(',').any(|t| t.trim() == "close") => false,
        Some(c) if c.split(',').any(|t| t.trim() == "keep-alive") => true,
        _ => version >= (1, 1),
    };
    Ok(Request {
        method: method.to_string(),
        unparsed_uri,
        uri,
        args,
        version,
        request_line: request_line.to_string(),
        headers,
        host,
        content_length,
        chunked,
        keepalive,
        expect_continue,
    })
}

fn parse_version(proto: &str) -> Result<(u8, u8), ParseError> {
    let v = proto.strip_prefix("HTTP/").ok_or(ParseError(400))?;
    let (major, minor) = v.split_once('.').ok_or(ParseError(400))?;
    let parse = |s: &str| -> Result<u16, ParseError> {
        if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseError(400));
        }
        s.parse().map_err(|_| ParseError(400))
    };
    let (major, minor) = (parse(major)?, parse(minor)?);
    if major > 99 || minor > 99 {
        return Err(ParseError(400));
    }
    if major == 0 {
        return Err(ParseError(400));
    }
    Ok((major.min(9) as u8, minor as u8))
}

/// Splits an absolute-form target into its path and host.
fn split_absolute(target: &str) -> Result<(String, Option<String>), ParseError> {
    if target.starts_with('/') {
        return Ok((target.to_string(), None));
    }
    let lower = target.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &target[7..]
    } else if lower.starts_with("https://") {
        &target[8..]
    } else {
        return Err(ParseError(400));
    };
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let host = &rest[..end];
    if host.is_empty() {
        return Err(ParseError(400));
    }
    let path = &rest[end..];
    let path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Ok((path, Some(host.to_string())))
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes %XX escapes in a path.
pub fn percent_decode(path: &str) -> Result<Vec<u8>, ParseError> {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c))) else {
                return Err(ParseError(400));
            };
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Decodes a path and resolves "." and ".." segments, merging slashes when
/// asked to. A path that climbs above the root is a bad request.
pub fn normalize_uri(path: &str, merge_slashes: bool) -> Result<String, ParseError> {
    let decoded = percent_decode(path)?;
    if decoded.contains(&0) {
        return Err(ParseError(400));
    }
    let decoded = String::from_utf8_lossy(&decoded).into_owned();
    if !decoded.starts_with('/') {
        return Err(ParseError(400));
    }
    let segments: Vec<&str> = decoded[1..].split('/').collect();
    let last = segments.len() - 1;
    let mut out: Vec<&str> = Vec::new();
    let mut trailing = false;
    for (i, seg) in segments.iter().enumerate() {
        let is_last = i == last;
        match *seg {
            "" => {
                if is_last {
                    trailing = true;
                } else if !merge_slashes {
                    out.push("");
                }
            }
            "." => trailing = is_last,
            ".." => {
                if out.pop().is_none() {
                    return Err(ParseError(400));
                }
                trailing = is_last;
            }
            s => {
                out.push(s);
                trailing = false;
            }
        }
    }
    let mut uri = String::from("/");
    uri.push_str(&out.join("/"));
    if trailing && !out.is_empty() {
        uri.push('/');
    }
    Ok(uri)
}

/// Validates a Host value as nginx does and returns it lowercased, without
/// the port and without a trailing dot.
pub fn validate_host(value: &str) -> Result<String, ParseError> {
    let b = value.as_bytes();
    let mut host_len = b.len();
    let mut in_brackets = false;
    let mut prev_dot = false;
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'.' => {
                if prev_dot {
                    return Err(ParseError(400));
                }
                prev_dot = true;
                continue;
            }
            b':' if !in_brackets => {
                host_len = i;
                break;
            }
            b'[' if i == 0 => in_brackets = true,
            b']' => in_brackets = false,
            b'/' | 0 => return Err(ParseError(400)),
            c if c < 0x20 || c == 0x7f => return Err(ParseError(400)),
            _ => {}
        }
        prev_dot = false;
    }
    let mut host = &value[..host_len];
    if let Some(h) = host.strip_suffix('.') {
        host = h;
    }
    if host.is_empty() {
        return Err(ParseError(400));
    }
    Ok(host.to_ascii_lowercase())
}

/// Decodes a chunked body from the start of `data`. Returns the body and the
/// number of bytes consumed, or None when more data is needed.
pub fn decode_chunked(data: &[u8]) -> Result<Option<(Vec<u8>, usize)>, ParseError> {
    let mut pos = 0;
    let mut body = Vec::new();
    loop {
        let Some(eol) = find(&data[pos..], b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&data[pos..pos + eol]).map_err(|_| ParseError(400))?;
        let size_text = line.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() {
            return Err(ParseError(400));
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| ParseError(400))?;
        pos += eol + 2;
        if size == 0 {
            // Trailers up to an empty line.
            loop {
                let Some(eol) = find(&data[pos..], b"\r\n") else {
                    return Ok(None);
                };
                pos += eol + 2;
                if eol == 0 {
                    return Ok(Some((body, pos)));
                }
            }
        }
        if data.len() < pos + size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        if &data[pos..pos + 2] != b"\r\n" {
            return Err(ParseError(400));
        }
        pos += 2;
    }
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(s: &str) -> Result<Request, ParseError> {
        parse_head(s.as_bytes(), true)
    }

    #[test]
    fn parses_a_simple_request() {
        let r = req("GET /a/b?x=1 HTTP/1.1\r\nHost: Example.TEST:8080\r\nConnection: close\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.uri, "/a/b");
        assert_eq!(r.args, "x=1");
        assert_eq!(r.unparsed_uri, "/a/b?x=1");
        assert_eq!(r.host.as_deref(), Some("example.test"));
        assert!(!r.keepalive);
    }

    #[test]
    fn requires_host_in_http11() {
        assert_eq!(req("GET / HTTP/1.1\r\n\r\n").unwrap_err(), ParseError(400));
        assert!(req("GET / HTTP/1.0\r\n\r\n").unwrap().host.is_none());
        assert_eq!(req("GET / HTTP/2.0\r\nHost: a\r\n\r\n").unwrap_err(), ParseError(505));
    }

    #[test]
    fn normalizes_paths() {
        assert_eq!(normalize_uri("/a//b/./c/../d", true).unwrap(), "/a/b/d");
        assert_eq!(normalize_uri("/a/b/..", true).unwrap(), "/a/");
        assert_eq!(normalize_uri("/a/%2e%2e/b%20c", true).unwrap(), "/b c");
        assert_eq!(normalize_uri("/docs/", true).unwrap(), "/docs/");
        assert_eq!(normalize_uri("/", true).unwrap(), "/");
        assert_eq!(normalize_uri("/a//b", false).unwrap(), "/a//b");
        assert!(normalize_uri("/../x", true).is_err());
        assert!(normalize_uri("/%zz", true).is_err());
    }

    #[test]
    fn handles_absolute_uris() {
        let r = req("GET http://Other.test:81/p?q HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(r.host.as_deref(), Some("other.test"));
        assert_eq!(r.uri, "/p");
        assert_eq!(r.unparsed_uri, "/p?q");
    }

    #[test]
    fn validates_hosts() {
        assert_eq!(validate_host("a.b.").unwrap(), "a.b");
        assert!(validate_host("a..b").is_err());
        assert!(validate_host("a/b").is_err());
        assert_eq!(validate_host("[::1]:80").unwrap(), "[::1]");
    }

    #[test]
    fn checks_body_framing() {
        assert_eq!(req("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: x\r\n\r\n").unwrap_err(), ParseError(400));
        assert_eq!(req("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n").unwrap_err(), ParseError(501));
        let r = req("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert!(r.chunked);
    }

    #[test]
    fn decodes_chunked_bodies() {
        let (body, used) = decode_chunked(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\nNEXT").unwrap().unwrap();
        assert_eq!(body, b"abcde");
        assert_eq!(used, 24);
        assert!(decode_chunked(b"3\r\nab").unwrap().is_none());
    }
}
