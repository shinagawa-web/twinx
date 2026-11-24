//! proxy_cache: answers of proxied servers kept by the key of their request in a
//! zone that proxy_cache_path names (keys_zone=), and given again while they are valid
//! for as long as the headers of the answer (X-Accel-Expires, Cache-Control, Expires)
//! or else proxy_cache_valid say for their status.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A cached answer: its status, Content-Type, headers and body, until when (in seconds
/// since the epoch) it is valid, and for how long after that it may be given while it
/// is being updated (stale-while-revalidate).
#[derive(Debug, Clone)]
pub struct Entry {
    pub status: u16,
    pub ctype: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    until: i64,
    updating: i64,
}

impl Entry {
    /// Whether it may still be given while it is being updated (c->stale_updating).
    pub fn updating(&self) -> bool {
        self.until.saturating_add(self.updating) >= crate::clock::seconds()
    }
}

/// What the headers of an answer say about caching it, as nginx reads them in turn
/// (ngx_http_upstream_process_cache_control() and those of Expires, X-Accel-Expires
/// and Set-Cookie): until when it is valid, if they say, and for how long after that
/// it may be given while it is being updated; None when it is not cached at all.
pub fn said(headers: &[(String, String)], ignored: &[String], now: i64) -> Option<(Option<i64>, i64)> {
    let (mut valid, mut updating, mut accel, mut no_cache, mut expired) = (None, 0, false, false, false);
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if ignored.contains(&name) { continue; }
        let lower = value.to_ascii_lowercase();
        match name.as_str() {
            "set-cookie" => return None,
            // Only the first one counts; "0" caches nothing, "@" gives the time it ends.
            "x-accel-expires" if !accel => {
                accel = true;
                // As ngx_atoi() reads them: digits only.
                let number = |v: &str| v.bytes().all(|c| c.is_ascii_digit()).then(|| v.parse::<i64>().ok()).flatten();
                let n = match value.strip_prefix('@') {
                    Some(at) => number(at),
                    None => match number(value) { Some(0) => return None, n => n.map(|n| now.saturating_add(n)) },
                };
                if let Some(n) = n { (valid, no_cache, expired) = (Some(n), false, false); }
            }
            "cache-control" => {
                if !(valid.is_some() && accel) {
                    if ["no-cache", "no-store", "private"].iter().any(|d| lower.contains(d)) { no_cache = true; continue; }
                    let age = lower.find("s-maxage=").map(|i| i + 9).or_else(|| lower.find("max-age=").map(|i| i + 8));
                    // Other than digits goes no further; "0" caches nothing.
                    match age.map(|age| seconds(&lower[age..])) { Some(None) => continue, Some(Some(0)) => { no_cache = true; continue } Some(Some(n)) => (valid, expired) = (Some(now.saturating_add(n)), false), None => {} }
                }
                if let Some(n) = lower.find("stale-while-revalidate=").and_then(|i| seconds(&lower[i + 23..])) { updating = n; }
            }
            "expires" if valid.is_none() => match crate::expires::http_time(value).filter(|t| *t >= now) {
                Some(t) => valid = Some(t),
                None => expired = true,
            },
            _ => {}
        }
    }
    (!no_cache && !expired).then_some((valid, updating))
}

/// The seconds a directive of Cache-Control gives, up to ",", ";" or " " (as many as
/// may be when they are more); None when something else comes first.
fn seconds(s: &str) -> Option<i64> {
    let digits = s.find([',', ';', ' ']).map_or(s, |end| &s[..end]);
    digits.bytes().try_fold(0i64, |n, c| c.is_ascii_digit().then(|| n.saturating_mul(10).saturating_add((c - b'0') as i64)))
}

/// A zone of keys (keys_zone=name:size of proxy_cache_path), with what it keeps.
#[derive(Debug, Default)]
pub struct Zone {
    entries: Mutex<HashMap<String, Entry>>,
    /// proxy_cache_lock: what a request that asks the server for a key holds meanwhile.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When the request that asks the server for each key last began to (proxy_cache_lock_age).
    since: Mutex<HashMap<String, Instant>>,
    /// How many requests asked for each key (proxy_cache_min_uses).
    uses: Mutex<HashMap<String, u64>>,
}

/// How long a request waits for another that asks for the same key (proxy_cache_lock_timeout's default).
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

impl Zone {
    /// The answer kept for a key, while it is valid.
    pub fn get(&self, key: &str) -> Option<Entry> {
        self.entries.lock().unwrap().get(key).filter(|e| e.until >= crate::clock::seconds()).cloned()
    }

    /// The answer kept for a key, also once it is no longer valid (proxy_cache_use_stale).
    pub fn stale(&self, key: &str) -> Option<Entry> {
        self.entries.lock().unwrap().get(key).cloned()
    }

    /// Counts one more request for a key, and gives how many asked for it so far.
    pub fn used(&self, key: &str) -> u64 {
        let mut uses = self.uses.lock().unwrap();
        let n = uses.entry(key.to_string()).or_default();
        *n += 1;
        *n
    }

    /// Keeps an answer for a key, valid until then, and given while it is updated for so long after.
    pub fn put(&self, key: String, (status, ctype, headers, body): (u16, Option<String>, Vec<(String, String)>, Vec<u8>), (until, updating): (i64, i64)) {
        self.entries.lock().unwrap().insert(key, Entry { status, ctype, headers, body, until, updating });
    }

    /// Waits, for so long at most (proxy_cache_lock_timeout), until no other request asks the
    /// server for the key, and holds that until what it gives is dropped; None when the time ran
    /// out. Once the request that asks has been at it for so long (proxy_cache_lock_age), this one
    /// asks in its place without holding anything: Some(None).
    pub async fn lock(&self, key: &str, wait: Duration, age: Duration) -> Option<Option<tokio::sync::OwnedMutexGuard<()>>> {
        let lock = self.locks.lock().unwrap().entry(key.to_string()).or_default().clone();
        let deadline = Instant::now() + wait;
        let since = || self.since.lock().unwrap().get(key).copied();
        let begin = || { self.since.lock().unwrap().insert(key.to_string(), Instant::now()); };
        loop {
            let asked = since();
            let aged = asked.map_or(deadline, |t| (t + age).min(deadline));
            if let Some(held) = crate::stream::until(|| Some(aged), lock.clone().lock_owned()).await { begin(); return Some(Some(held)) }
            if Instant::now() >= deadline { return None }
            // Another request that waited may have taken over first: then wait for its age.
            if since() == asked { begin(); return Some(None) }
        }
    }
}

/// The zone of a proxy_cache_path's parameters: the name keys_zone= gives it.
pub fn zone_name(args: &[String]) -> Option<&str> {
    let zone = args.iter().find_map(|a| a.strip_prefix("keys_zone="))?;
    let (name, size) = zone.split_once(':')?;
    Some(name).filter(|n| !n.is_empty() && !size.is_empty())
}

/// proxy_cache_valid: the statuses an answer is cached with (none: 200, 301 and 302;
/// "any": all of them), and for how long.
pub fn valid(args: &[String], time: Duration) -> Result<Vec<(Option<u16>, Duration)>, String> {
    if args.is_empty() { return Ok([200, 301, 302].map(|s| (Some(s), time)).to_vec()); }
    args.iter().map(|a| match a.as_str() {
        "any" => Ok((None, time)),
        code => code.parse().ok().filter(|c| (100..=599).contains(c)).map(|c| (Some(c), time)).ok_or_else(|| format!("invalid status \"{code}\"")),
    }).collect()
}

/// For how long an answer of a status is valid, if it is cached at all.
pub fn validity(valid: &[(Option<u16>, Duration)], status: u16) -> Option<Duration> {
    valid.iter().find(|v| v.0 == Some(status)).or_else(|| valid.iter().find(|v| v.0.is_none())).map(|v| v.1).filter(|t| !t.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn zone_names() {
        assert_eq!(zone_name(&strings(&["/tmp/c", "levels=1:2", "keys_zone=NAME:1m"])), Some("NAME"));
        assert_eq!(zone_name(&strings(&["/tmp/c", "keys_zone=NAME"])), None);
        assert_eq!(zone_name(&strings(&["/tmp/c"])), None);
    }

    #[test]
    fn valid_statuses() {
        let m = Duration::from_secs(60);
        let v = valid(&[], m).unwrap();
        assert_eq!(validity(&v, 200), Some(m));
        assert_eq!(validity(&v, 302), Some(m));
        assert_eq!(validity(&v, 404), None);
        let any = valid(&strings(&["404", "any"]), m).unwrap();
        assert_eq!(validity(&any, 500), Some(m));
        assert!(valid(&strings(&["abc"]), m).is_err());
    }

    #[test]
    fn one_request_at_a_time_holds_a_key() {
        let z = Zone::default();
        crate::stream::block_on(async {
            let (ms, long) = (Duration::from_millis, LOCK_TIMEOUT);
            let held = z.lock("k", long, long).await.unwrap().unwrap();
            // Another key is not held; the same one is, until the time runs out.
            assert!(z.lock("other", ms(50), long).await.unwrap().is_some());
            assert!(z.lock("k", ms(50), long).await.is_none());
            // Once the one that holds it has asked for so long, the next asks in its place, and
            // then the one after that waits for as long again.
            assert!(z.lock("k", long, ms(100)).await.unwrap().is_none());
            let start = Instant::now();
            assert!(z.lock("k", long, ms(100)).await.unwrap().is_none());
            assert!(start.elapsed() >= ms(90));
            assert!(z.lock("k", ms(50), ms(100)).await.is_none());
            drop(held);
            assert!(z.lock("k", ms(50), long).await.unwrap().is_some());
        });
    }

    fn h(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    #[test]
    fn headers_say_how_long() {
        let none: &[String] = &[];
        let said = |list: &[(&str, &str)]| said(&h(list), none, 1000);
        assert_eq!(said(&[]), Some((None, 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=60")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("Cache-Control", "s-maxage=5, max-age=60")]), Some((Some(1005), 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=9223372036854775808")]), Some((Some(i64::MAX), 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=6x")]), Some((None, 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=0")]), None);
        assert_eq!(said(&[("Cache-Control", "no-cache, max-age=60")]), None);
        assert_eq!(said(&[("Cache-Control", "no-cache"), ("Cache-Control", "max-age=60")]), None);
        assert_eq!(said(&[("Expires", "Thu, 01 Jan 1970 00:00:01 GMT")]), None);
        assert_eq!(said(&[("Expires", "Thu, 01 Jan 1970 00:00:01 GMT"), ("Cache-Control", "max-age=60")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=60"), ("Expires", "Thu, 01 Jan 1970 00:00:01 GMT")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("X-Accel-Expires", "60"), ("X-Accel-Expires", "0")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("X-Accel-Expires", "@60")]), Some((Some(60), 0)));
        assert_eq!(said(&[("X-Accel-Expires", "x")]), Some((None, 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=60"), ("X-Accel-Expires", "0")]), None);
        assert_eq!(said(&[("Expires", "Thu, 01 Jan 1970 00:00:01 GMT"), ("Cache-Control", "no-cache"), ("X-Accel-Expires", "60")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("X-Accel-Expires", "@1"), ("Cache-Control", "no-cache, stale-while-revalidate=50")]), Some((Some(1), 50)));
        assert_eq!(said(&[("Cache-Control", "stale-while-revalidate=50"), ("X-Accel-Expires", "@1")]), Some((Some(1), 50)));
        assert_eq!(said(&[("Set-Cookie", "a"), ("Cache-Control", "max-age=60")]), None);
        let ignored = ["set-cookie".to_string(), "cache-control".to_string()];
        assert_eq!(super::said(&h(&[("Set-Cookie", "a"), ("Cache-Control", "no-cache")]), &ignored, 1000), Some((None, 0)));
    }

    #[test]
    fn uses_counted_by_key() {
        let z = Zone::default();
        assert_eq!((z.used("k"), z.used("k"), z.used("other")), (1, 2, 1));
    }

    #[test]
    fn kept_while_valid() {
        let z = Zone::default();
        let now = crate::clock::seconds();
        z.put("k".into(), (200, None, Vec::new(), b"x".to_vec()), (now + 60, 0));
        assert_eq!(z.get("k").unwrap().body, b"x");
        z.put("k".into(), (200, None, Vec::new(), b"x".to_vec()), (now - 10, 0));
        assert!(z.get("k").is_none());
        assert_eq!(z.stale("k").unwrap().body, b"x");
        assert!(!z.stale("k").unwrap().updating());
        z.put("k".into(), (200, None, Vec::new(), b"x".to_vec()), (now - 10, 60));
        assert!(z.stale("k").unwrap().updating());
        assert!(z.stale("other").is_none());
        assert!(z.get("other").is_none());
    }
}
