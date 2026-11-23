//! The expires directive: the Expires and Cache-Control headers it sets.

use chrono::{DateTime, Local, Timelike};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Expires {
    Off,
    /// epoch and max: a fixed Expires time and Cache-Control value.
    Fixed(i64, &'static str),
    /// A time from now.
    Access(i64),
    /// A time from the Last-Modified time (from now when there is none).
    Modified(i64),
    /// A time of day, "@15h30m".
    Daily(i64),
}

/// A time such as "2048", "1h30m" or "10s", in seconds, as ngx_parse_time() reads it.
pub fn parse_time(s: &str) -> Option<i64> {
    const UNITS: &[(char, i64)] = &[('y', 31_536_000), ('M', 2_592_000), ('w', 604_800), ('d', 86_400), ('h', 3600), ('m', 60), ('s', 1)];
    let (mut total, mut number) = (0i64, String::new());
    for c in s.chars() {
        if c.is_ascii_digit() { number.push(c); continue; }
        let unit = UNITS.iter().find(|u| u.0 == c)?.1;
        total += std::mem::take(&mut number).parse::<i64>().ok()? * unit;
    }
    let rest = if number.is_empty() { 0 } else { number.parse::<i64>().ok()? };
    (!s.is_empty()).then_some(total + rest)
}

/// The value of the directive ("modified 1h", "@12h", "-1d", "epoch", ...), None when invalid.
pub fn parse(v: &str) -> Option<Expires> {
    let (modified, v) = v.strip_prefix("modified ").map_or((false, v), |rest| (true, rest.trim()));
    let fixed = [("epoch", Expires::Fixed(1, "no-cache")), ("max", Expires::Fixed(2_145_916_555, "max-age=315360000")), ("off", Expires::Off)];
    if let Some((_, e)) = fixed.into_iter().find(|f| f.0 == v) { return (!modified).then_some(e); }
    if let Some(daily) = v.strip_prefix('@') { return parse_time(daily).filter(|t| !modified && *t < 86_400).map(Expires::Daily); }
    let (sign, v) = v.strip_prefix('-').map_or((1, v.strip_prefix('+').unwrap_or(v)), |rest| (-1, rest));
    let t = parse_time(v)? * sign;
    Some(if modified { Expires::Modified(t) } else { Expires::Access(t) })
}

pub fn http_date(t: i64) -> String {
    DateTime::from_timestamp(t, 0).unwrap_or_default().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The time an HTTP date such as "Sun, 06 Nov 1994 08:49:37 GMT" gives.
/// The older forms ngx_parse_http_time() also reads are not read yet.
pub fn http_time(s: &str) -> Option<i64> {
    DateTime::parse_from_rfc2822(s.trim()).ok().map(|t| t.timestamp())
}

/// The Expires and Cache-Control values, given the response's Last-Modified time.
pub fn headers(e: Expires, last_modified: Option<i64>) -> Option<(String, String)> {
    let now = crate::clock::seconds();
    let (expires, cc) = match e {
        Expires::Off => return None,
        Expires::Fixed(t, cc) => (t, cc.to_string()),
        Expires::Access(t) | Expires::Modified(t) | Expires::Daily(t) => {
            let base = match e {
                Expires::Modified(_) => last_modified.unwrap_or(now),
                Expires::Daily(_) => next_day_start(t),
                _ => now,
            };
            let max_age = base + t - now;
            (base + t, if t < 0 || max_age < 0 { "no-cache".to_string() } else { format!("max-age={max_age}") })
        }
    };
    Some((http_date(expires), cc))
}

/// The start of the local day after which `secs` into the day comes next.
fn next_day_start(secs: i64) -> i64 {
    let now = Local::now();
    let today = now.timestamp() - now.num_seconds_from_midnight() as i64;
    if today + secs > now.timestamp() { today } else { today + 86_400 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_values() {
        assert_eq!(parse("epoch"), Some(Expires::Fixed(1, "no-cache")));
        assert_eq!(parse("off"), Some(Expires::Off));
        assert_eq!(parse("2048"), Some(Expires::Access(2048)));
        assert_eq!(parse("-1h"), Some(Expires::Access(-3600)));
        assert_eq!(parse("+1d"), Some(Expires::Access(86_400)));
        assert_eq!(parse("modified 1m30s"), Some(Expires::Modified(90)));
        assert_eq!(parse("@15h30m33s"), Some(Expires::Daily(55_833)));
        for bad in ["", "bad", "modified epoch", "@25h", "1x"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn headers_for_each_kind() {
        assert_eq!(headers(Expires::Off, None), None);
        let (e, cc) = headers(Expires::Fixed(1, "no-cache"), None).unwrap();
        assert_eq!((e.as_str(), cc.as_str()), ("Thu, 01 Jan 1970 00:00:01 GMT", "no-cache"));
        assert_eq!(headers(Expires::Access(60), None).unwrap().1, "max-age=60");
        assert_eq!(headers(Expires::Access(-60), None).unwrap().1, "no-cache");
        let (e, cc) = headers(Expires::Modified(2048), Some(23_349_600)).unwrap();
        assert_eq!((e.as_str(), cc.as_str()), ("Mon, 28 Sep 1970 06:34:08 GMT", "no-cache"));
        assert!(headers(Expires::Daily(33), None).unwrap().0.ends_with(":33 GMT"));
    }
}
