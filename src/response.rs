//! Responses: status lines, the pages nginx generates for special
//! responses, and writing a response to the wire.

use crate::time;

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    /// A status line taken verbatim from an upstream ("200 OK").
    pub status_line: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub last_modified: Option<i64>,
    pub location: Option<String>,
    /// Other headers, in the order they are sent.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Send the body with chunked transfer coding (its length is unknown).
    pub chunked: bool,
    /// The connection must be closed after this response.
    pub close: bool,
    /// The range filter may answer a Range request from this response.
    pub allow_ranges: bool,
    /// Made by the special response handler, so error_page may replace it.
    pub special: bool,
}

impl Response {
    pub fn new(status: u16) -> Response {
        Response {
            status,
            status_line: None,
            content_type: None,
            content_length: None,
            last_modified: None,
            location: None,
            headers: Vec::new(),
            body: Vec::new(),
            chunked: false,
            close: false,
            allow_ranges: false,
            special: false,
        }
    }
}

/// The reason phrase nginx puts in the status line, if it knows one.
pub fn reason(status: u16) -> Option<&'static str> {
    Some(match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Time-out",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Requested Range Not Satisfiable",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Temporarily Unavailable",
        504 => "Gateway Time-out",
        505 => "HTTP Version Not Supported",
        507 => "Insufficient Storage",
        _ => return None,
    })
}

/// The title of the page nginx generates for a special response, if any.
pub fn page_title(status: u16) -> Option<&'static str> {
    Some(match status {
        301 => "301 Moved Permanently",
        302 => "302 Found",
        303 => "303 See Other",
        307 => "307 Temporary Redirect",
        308 => "308 Permanent Redirect",
        400 => "400 Bad Request",
        401 => "401 Authorization Required",
        402 => "402 Payment Required",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Not Allowed",
        406 => "406 Not Acceptable",
        408 => "408 Request Time-out",
        409 => "409 Conflict",
        410 => "410 Gone",
        411 => "411 Length Required",
        412 => "412 Precondition Failed",
        413 => "413 Request Entity Too Large",
        414 => "414 Request-URI Too Large",
        415 => "415 Unsupported Media Type",
        416 => "416 Requested Range Not Satisfiable",
        421 => "421 Misdirected Request",
        429 => "429 Too Many Requests",
        494 => "400 Request Header Or Cookie Too Large",
        495 => "400 The SSL certificate error",
        496 => "400 No required SSL certificate was sent",
        497 => "400 The plain HTTP request was sent to HTTPS port",
        500 => "500 Internal Server Error",
        501 => "501 Not Implemented",
        502 => "502 Bad Gateway",
        503 => "503 Service Temporarily Unavailable",
        504 => "504 Gateway Time-out",
        505 => "505 HTTP Version Not Supported",
        507 => "507 Insufficient Storage",
        _ => return None,
    })
}

/// The page body nginx sends for a special response.
pub fn page(status: u16, server_tokens: bool) -> Option<String> {
    let title = page_title(status)?;
    let signature = if server_tokens { crate::server_name_token() } else { "twinx".to_string() };
    Some(format!(
        "<html>\r\n<head><title>{title}</title></head>\r\n<body>\r\n<center><h1>{title}</h1></center>\r\n<hr><center>{signature}</center>\r\n</body>\r\n</html>\r\n"
    ))
}

/// Builds the special response nginx sends for a status with no body of
/// its own (errors and redirects).
pub fn special(status: u16, server_tokens: bool) -> Response {
    // 494-497 are sent as 400 on the wire.
    let wire = if (494..=497).contains(&status) { 400 } else { status };
    let mut resp = Response::new(wire);
    resp.special = true;
    match page(status, server_tokens) {
        Some(body) => {
            resp.content_type = Some("text/html".to_string());
            resp.content_length = Some(body.len() as u64);
            resp.body = body.into_bytes();
        }
        None => {
            if !matches!(status, 204 | 304) && status >= 200 {
                resp.content_length = Some(0);
            }
        }
    }
    // nginx turns keepalive off for these.
    if matches!(status, 400 | 408 | 413 | 414 | 494..=497 | 500 | 501 | 505) {
        resp.close = true;
    }
    resp
}

/// Serializes the status line and headers.
pub fn head_bytes(resp: &Response, keepalive: bool, server_tokens: bool) -> Vec<u8> {
    let mut h = String::new();
    match &resp.status_line {
        Some(line) => h.push_str(&format!("HTTP/1.1 {line}\r\n")),
        None => match reason(resp.status) {
            Some(r) => h.push_str(&format!("HTTP/1.1 {} {r}\r\n", resp.status)),
            None => h.push_str(&format!("HTTP/1.1 {} \r\n", resp.status)),
        },
    }
    let server = if server_tokens { crate::server_name_token() } else { "twinx".to_string() };
    h.push_str(&format!("Server: {server}\r\n"));
    h.push_str(&format!("Date: {}\r\n", time::http_date(time::now())));
    if let Some(ct) = &resp.content_type {
        h.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if let Some(len) = resp.content_length {
        h.push_str(&format!("Content-Length: {len}\r\n"));
    }
    if let Some(lm) = resp.last_modified {
        h.push_str(&format!("Last-Modified: {}\r\n", time::http_date(lm)));
    }
    if let Some(loc) = &resp.location {
        h.push_str(&format!("Location: {loc}\r\n"));
    }
    if resp.chunked {
        h.push_str("Transfer-Encoding: chunked\r\n");
    }
    h.push_str(if keepalive { "Connection: keep-alive\r\n" } else { "Connection: close\r\n" });
    for (name, value) in &resp.headers {
        h.push_str(&format!("{name}: {value}\r\n"));
    }
    h.push_str("\r\n");
    h.into_bytes()
}

/// Serializes a whole response; `head_only` leaves the body out (HEAD).
pub fn to_bytes(resp: &Response, keepalive: bool, head_only: bool, server_tokens: bool) -> Vec<u8> {
    let mut out = head_bytes(resp, keepalive, server_tokens);
    if !head_only {
        if resp.chunked {
            if !resp.body.is_empty() {
                out.extend_from_slice(format!("{:x}\r\n", resp.body.len()).as_bytes());
                out.extend_from_slice(&resp.body);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
        } else {
            out.extend_from_slice(&resp.body);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_error_pages() {
        let r = special(404, true);
        let body = String::from_utf8(r.body.clone()).unwrap();
        assert!(body.starts_with("<html>\r\n<head><title>404 Not Found</title></head>"));
        assert!(body.contains("<hr><center>twinx/"));
        assert_eq!(r.content_length, Some(body.len() as u64));
        assert_eq!(r.content_type.as_deref(), Some("text/html"));
    }

    #[test]
    fn statuses_without_a_page_have_an_empty_body() {
        let r = special(418, true);
        assert!(r.body.is_empty());
        assert_eq!(r.content_length, Some(0));
        assert_eq!(r.content_type, None);
        let head = String::from_utf8(head_bytes(&r, false, true)).unwrap();
        assert!(head.starts_with("HTTP/1.1 418 \r\n"));
    }

    #[test]
    fn writes_chunked_bodies() {
        let mut r = Response::new(200);
        r.chunked = true;
        r.body = b"hello".to_vec();
        let out = to_bytes(&r, true, false, true);
        assert!(out.ends_with(b"\r\n\r\n5\r\nhello\r\n0\r\n\r\n"));
    }
}
