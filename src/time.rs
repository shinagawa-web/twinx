//! HTTP dates (RFC 9110 IMF-fixdate), as nginx writes them.

use std::time::{SystemTime, UNIX_EPOCH};

const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Converts days since 1970-01-01 to (year, month 1-12, day 1-31).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formats seconds since the epoch as "Thu, 01 Jan 2026 00:00:00 GMT".
pub fn http_date(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let weekday = DAYS[days.rem_euclid(7) as usize];
    format!(
        "{weekday}, {d:02} {} {y:04} {:02}:{:02}:{:02} GMT",
        MONTHS[(m - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Converts (year, month 1-12, day 1-31) to days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// The value of a run of ASCII digits.
fn digits(b: &[u8]) -> Option<i64> {
    b.iter().try_fold(0, |n, &c| c.is_ascii_digit().then(|| n * 10 + i64::from(c - b'0')))
}

/// Parses an RFC 1123 date ("Thu, 01 Jan 2026 00:00:00 GMT") the way
/// ngx_parse_http_time does: the weekday up to the comma and what follows
/// the seconds are not checked, but the fields and the day of the month are.
/// The RFC 850 and asctime forms are not read yet and give None.
pub fn parse_http_date(value: &str) -> Option<i64> {
    let (_, rest) = value.split_once(',')?;
    let b = rest.trim_start_matches(' ').as_bytes().get(..20)?;
    let separators = b[2] == b' ' && b[6] == b' ' && b[11] == b' ' && b[14] == b':' && b[17] == b':';
    let month = MONTHS.iter().position(|m| m.as_bytes() == &b[3..6])?;
    let (day, year) = (digits(&b[..2])?, digits(&b[7..11])?);
    let (hour, min, sec) = (digits(&b[12..14])?, digits(&b[15..17])?, digits(&b[18..20])?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let mday = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month];
    let valid = separators && day <= mday && hour < 24 && min < 60 && sec < 60;
    let days = days_from_civil(year, month as i64 + 1, day);
    valid.then_some(days * 86_400 + hour * 3600 + min * 60 + sec)
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_767_225_600), "Thu, 01 Jan 2026 00:00:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
    }

    #[test]
    fn parses_rfc1123_dates() {
        for secs in [0, 951_782_400, 1_700_000_000, 1_767_225_600] {
            assert_eq!(parse_http_date(&http_date(secs)), Some(secs));
        }
        assert_eq!(parse_http_date("Thu,  01 Jan 2026 00:00:00"), Some(1_767_225_600));
        assert_eq!(parse_http_date("Thu, 01 jan 2026 00:00:00 GMT"), None);
        assert_eq!(parse_http_date("Thu, 1 Jan 2026 00:00:00 GMT"), None);
        assert_eq!(parse_http_date("Thu, 01 Jan 2026 24:00:00 GMT"), None);
        assert_eq!(parse_http_date("Fri, 29 Feb 2019 00:00:00 GMT"), None);
        assert_eq!(parse_http_date("Thu Jan  1 00:00:00 2026"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }
}
