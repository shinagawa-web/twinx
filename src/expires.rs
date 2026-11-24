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

/// The time an HTTP date gives, as ngx_parse_http_time() reads it: "Sun, 06 Nov
/// 1994 08:49:37 GMT" (RFC 1123), "Sunday, 06-Nov-94 08:49:37 GMT" (RFC 850, a
/// year below 70 in the 2000s) or "Sun Nov  6 08:49:37 1994" (asctime). The day
/// of the week is not looked at, the month only by as many of its letters as
/// tell it from the others, and nothing after the time (or the year of asctime)
/// is, the zone included.
pub fn http_time(s: &str) -> Option<i64> {
    const MDAYS: [i64; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let b = s.as_bytes();
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    let digits = |i: usize, n: usize| (i..i + n).try_fold(0i64, |v, j| at(j).is_ascii_digit().then(|| v * 10 + i64::from(at(j) - b'0')));
    // A comma ends the day of the week of RFC 1123 and RFC 850, a space that of asctime.
    let stop = b.iter().position(|&c| c == b',' || c == b' ');
    // The separator of the day, month and year: a space, a dash, or none for asctime.
    let (mut fmt, mut day, mut year) = (0u8, 0, 0);
    let mut p = stop.unwrap_or(b.len()) + 1;
    while at(p) == b' ' { p += 1; }
    if b.len() < p + 18 { return None }
    if stop.is_some_and(|i| b[i] == b',') {
        (day, fmt) = (digits(p, 2)?, at(p + 2));
        if !(fmt == b'-' || fmt == b' ' && b.len() >= p + 20) { return None }
        p += 3;
    }
    let month = match (at(p), at(p + 1), at(p + 2)) { (b'J', b'a', _) => 0, (b'J', _, b'n') => 5, (b'J', ..) => 6, (b'F', ..) => 1, (b'M', _, b'r') => 2, (b'M', ..) => 4, (b'A', b'p', _) => 3, (b'A', ..) => 7, (b'S', ..) => 8, (b'O', ..) => 9, (b'N', ..) => 10, (b'D', ..) => 11, _ => return None };
    if fmt != 0 && at(p + 3) != fmt { return None }
    p += 4;
    if fmt == b' ' { (year, p) = (digits(p, 4)?, p + 4); }
    if fmt == b'-' { (year, p) = (digits(p, 2)?, p + 2); year += if year < 70 { 2000 } else { 1900 }; }
    if fmt == 0 {
        p += usize::from(at(p) == b' ');
        (day, p) = (digits(p, 1)?, p + 1);
        if at(p) != b' ' { (day, p) = (day * 10 + digits(p, 1)?, p + 1); }
        if b.len() < p + 14 { return None }
    }
    let (hour, min, sec) = (digits(p + 1, 2)?, digits(p + 4, 2)?, digits(p + 7, 2)?);
    if at(p) != b' ' || at(p + 3) != b':' || at(p + 6) != b':' { return None }
    if fmt == 0 { year = digits(p + 10, 4).filter(|_| at(p + 9) == b' ')?; }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    if hour > 23 || min > 59 || sec > 59 || day > MDAYS[month] || day == 29 && month == 1 && !leap { return None }
    // Gauss's formula, with the year starting in March.
    let (month, year) = if month < 2 { (month as i64 + 11, year - 1) } else { (month as i64 - 1, year) };
    let days = 365 * year + year / 4 - year / 100 + year / 400 + 367 * month / 12 - 30 + day - 1 - 719_527 + 31 + 28;
    Some(days * 86_400 + hour * 3600 + min * 60 + sec)
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
    fn http_times_as_nginx_reads_them() {
        let t = Some(784_111_777);
        for v in ["Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994", "Sun Nov 06 08:49:37 1994", "Xxx, 06 Nov 1994 08:49:37", "Sun, 06 Nov 1994 08:49:37 GMT; length=8", "Sun,   06 Nov 1994 08:49:37 +0900"] {
            assert_eq!(http_time(v), t, "{v}");
        }
        assert_eq!(http_time("Wednesday, 10-Mar-10 11:04:05 GMT"), Some(1_268_219_045));
        assert_eq!(http_time("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(http_time("Thu, 29 Feb 2024 00:00:00 GMT"), Some(1_709_164_800));
        assert_eq!(http_time("Mon, 31 Dec 2001 23:59:59 GMT"), Some(1_009_843_199));
        for (i, m) in ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].into_iter().enumerate() {
            let t = chrono::NaiveDate::from_ymd_opt(2000, i as u32 + 1, 1).and_then(|d| d.and_hms_opt(0, 0, 0)).map(|t| t.and_utc().timestamp());
            assert_eq!(http_time(&format!("Sun, 01 {m} 2000 00:00:00 GMT")), t, "{m}");
        }
        for bad in ["", "wrong", "Sun, 06 Nov 1994 08:49:3", "Sun, 06 Xov 1994 08:49:37 GMT", "Sun, 06/Nov/1994 08:49:37 GMT", "Sun, 06 Nov 1994 24:00:00 GMT",
            "Fri, 29 Feb 2019 00:00:00 GMT", "Sun, 31 Apr 1994 00:00:00 GMT", "Sun, 06 Nov 1994 08-49-37 GMT", "Sun Nov  6 08:49:37 94", "Sun Nov 6 08:49:37 1994"[..22].as_ref()] {
            assert_eq!(http_time(bad), None, "{bad}");
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
