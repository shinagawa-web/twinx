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
    /// The length its server gave (Content-Length), also of an answer to HEAD; without one
    /// its length is not known when it is sent again.
    pub length: Option<usize>,
    /// Whether a Location that starts with "/" is sent as it is (proxy_redirect left it).
    pub relative: bool,
    until: i64,
    updating: i64,
    /// The request headers its Vary names, lowercase, and their values in the request it answered.
    vary: Vec<String>,
    variant: String,
}

impl Entry {
    /// The conditions it is revalidated with (proxy_cache_revalidate): If-Modified-Since its
    /// Last-Modified and If-None-Match its ETag, which only a 200 or a 206 keeps.
    pub fn conditions(&self) -> Vec<(&'static str, String)> {
        if !matches!(self.status, 200 | 206) { return Vec::new(); }
        let header = |name: &str| self.headers.iter().rev().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
        let modified = header("last-modified").and_then(|v| crate::expires::http_time(&v)).map(|t| ("If-Modified-Since", crate::expires::http_date(t)));
        modified.into_iter().chain(header("etag").map(|e| ("If-None-Match", e))).collect()
    }

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
                // A time X-Accel-Expires gave ("@0" gives none) comes first.
                if !(valid.is_some_and(|v| v != 0) && accel) {
                    if ["no-cache", "no-store", "private"].iter().any(|d| lower.contains(d)) { no_cache = true; continue; }
                    let age = lower.find("s-maxage=").map(|i| i + 9).or_else(|| lower.find("max-age=").map(|i| i + 8));
                    // Other than digits caches nothing at all, nor does "0".
                    match age.map(|age| seconds(&lower[age..])) { Some(None) => return None, Some(Some(0)) => { no_cache = true; continue } Some(Some(n)) => (valid, expired) = (Some(now.saturating_add(n)), false), None => {} }
                }
                match lower.find("stale-while-revalidate=").map(|i| seconds(&lower[i + 23..])) { Some(None) => return None, Some(Some(n)) => updating = n, None => {} }
                if let Some(None) = lower.find("stale-if-error=").map(|i| seconds(&lower[i + 15..])) { return None; }
            }
            "expires" if valid.is_none() => match crate::expires::http_time(value).filter(|t| *t >= now) {
                Some(t) => valid = Some(t),
                None => expired = true,
            },
            _ => {}
        }
    }
    (!no_cache && !expired).then_some((valid.filter(|&v| v != 0), updating))
}

/// The seconds a directive of Cache-Control gives, up to ",", ";" or " " (as many as
/// may be when they are more); None when something else comes first.
fn seconds(s: &str) -> Option<i64> {
    let digits = s.find([',', ';', ' ']).map_or(s, |end| &s[..end]);
    digits.bytes().try_fold(0i64, |n, c| c.is_ascii_digit().then(|| n.saturating_mul(10).saturating_add((c - b'0') as i64)))
}

/// The request headers a Vary names, lowercase (none without one); None for "*",
/// which no other request matches, so that the answer is not cached.
pub fn vary(headers: &[(String, String)]) -> Option<Vec<String>> {
    let names: Vec<String> = headers.iter().filter(|h| h.0.eq_ignore_ascii_case("vary")).flat_map(|h| h.1.split(',')).map(|n| n.trim().to_ascii_lowercase()).filter(|n| !n.is_empty()).collect();
    (!names.contains(&"*".to_string())).then_some(names)
}

/// The values of the headers a Vary names in a request, which tell its variant: those of
/// a header are joined by "," without the spaces and empty ones between them.
pub fn variant(names: &[String], request: &[(String, String)]) -> String {
    names.iter().map(|n| {
        let values: Vec<&str> = request.iter().filter(|h| h.0.eq_ignore_ascii_case(n)).flat_map(|h| h.1.split(',')).map(|v| v.trim_matches([' ', '\t'])).filter(|v| !v.is_empty()).collect();
        format!("{n}:{}\n", values.join(","))
    }).collect()
}

/// A zone of keys (keys_zone=name:size of proxy_cache_path), with what it keeps, also
/// in files of its path, so that what it keeps outlives the process.
#[derive(Debug, Default)]
pub struct Zone {
    dir: Option<std::path::PathBuf>,
    entries: Mutex<HashMap<String, Entry>>,
    /// proxy_cache_lock: what a request that asks the server for a key holds meanwhile.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// When the request that asks the server for each key last began to (proxy_cache_lock_age).
    since: Mutex<HashMap<String, Instant>>,
    /// How many requests asked for each key (proxy_cache_min_uses).
    uses: Mutex<HashMap<String, u64>>,
    /// The keys whose kept answer, no longer valid, a request asks the server to update.
    refreshing: Mutex<std::collections::HashSet<String>>,
}

/// A request asking the server to update what a zone keeps for a key, until it is dropped.
pub struct Refresh<'a>(&'a Zone, String);

impl Drop for Refresh<'_> {
    fn drop(&mut self) {
        self.0.refreshing.lock().unwrap().remove(&self.1);
    }
}

/// How long a request waits for another that asks for the same key (proxy_cache_lock_timeout's default).
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

impl Zone {
    /// A zone that keeps its answers in files under a path, with those already there.
    pub fn at(dir: std::path::PathBuf) -> Zone {
        let files = std::fs::read_dir(&dir).into_iter().flatten().flatten();
        let entries = files.filter_map(|f| decode(&std::fs::read(f.path()).ok()?)).collect();
        Zone { dir: Some(dir), entries: Mutex::new(entries), ..Zone::default() }
    }

    /// The key an answer to a request is kept by: that of the variant of the request when
    /// what the key keeps has a Vary its headers do not match.
    pub fn resolve(&self, key: &str, request: &[(String, String)]) -> String {
        match self.entries.lock().unwrap().get(key).map(|e| (variant(&e.vary, request), e)) {
            Some((v, e)) if !e.vary.is_empty() && v != e.variant => format!("{key}\n{v}"),
            _ => key.to_string(),
        }
    }

    /// Writes what is kept for a key to its file.
    fn save(&self, key: &str, e: &Entry) {
        let Some(dir) = &self.dir else { return };
        let name = ring::digest::digest(&ring::digest::SHA256, key.as_bytes()).as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect::<String>();
        let (file, temp) = (dir.join(&name), dir.join(format!("{name}.tmp")));
        let _ = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&temp, encode(key, e))).and_then(|()| std::fs::rename(&temp, &file));
    }

    /// The answer kept for a key, while it is valid.
    pub fn get(&self, key: &str) -> Option<Entry> {
        self.entries.lock().unwrap().get(key).filter(|e| e.until >= crate::clock::seconds()).cloned()
    }

    /// The answer kept for a key, also once it is no longer valid (proxy_cache_use_stale).
    pub fn stale(&self, key: &str) -> Option<Entry> {
        self.entries.lock().unwrap().get(key).cloned()
    }

    /// Notes that a request asks the server to update what is kept for a key, unless another
    /// already does (the node's updating flag of nginx): None then.
    pub fn refresh(&self, key: &str) -> Option<Refresh<'_>> {
        self.refreshing.lock().unwrap().insert(key.to_string()).then(|| Refresh(self, key.to_string()))
    }

    /// Counts one more request for a key, and gives how many asked for it so far.
    pub fn used(&self, key: &str) -> u64 {
        let mut uses = self.uses.lock().unwrap();
        let n = uses.entry(key.to_string()).or_default();
        *n += 1;
        *n
    }

    /// Makes what is kept for a key valid again, until then and given while it is updated
    /// for so long after (a 304 of proxy_cache_revalidate).
    pub fn renew(&self, key: &str, (until, updating): (i64, i64)) {
        if let Some(e) = self.entries.lock().unwrap().get_mut(key) { (e.until, e.updating) = (until, updating); self.save(key, e); }
    }

    /// Keeps an answer for a key, valid until then, and given while it is updated for so long after.
    /// One looked up by the key of a variant is kept by it when its Vary gives the same variant,
    /// and else by the key itself, as nginx does (ngx_http_file_cache_update_variant()).
    pub fn put(&self, (key, at): (&str, &str), (status, ctype, headers, body): (u16, Option<String>, Vec<(String, String)>, Vec<u8>), (length, relative): (Option<usize>, bool), (until, updating): (i64, i64), (vary, request): (Vec<String>, &[(String, String)])) {
        let variant = variant(&vary, request);
        let key = if at == key || (!vary.is_empty() && at == format!("{key}\n{variant}")) { at } else { key };
        let e = Entry { status, ctype, headers, body, length, relative, until, updating, vary, variant };
        self.save(key, &e);
        self.entries.lock().unwrap().insert(key.to_string(), e);
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

/// What the file of a kept answer holds: its key and fields, each after its length.
fn encode(key: &str, e: &Entry) -> Vec<u8> {
    let mut fields = vec![key.to_string(), e.status.to_string(), e.until.to_string(), e.updating.to_string(), e.vary.join(","), e.variant.clone(), e.ctype.is_some().to_string(), e.ctype.clone().unwrap_or_default(), e.length.map_or_else(String::new, |n| n.to_string()), e.relative.to_string()];
    fields.extend(e.headers.iter().flat_map(|(n, v)| [n.clone(), v.clone()]));
    let mut out = (fields.len() as u64).to_le_bytes().to_vec();
    for f in fields.iter().map(String::as_bytes).chain([e.body.as_slice()]) {
        out.extend_from_slice(&(f.len() as u64).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// The key and the answer the file of a kept answer holds; None when it holds no such thing.
fn decode(b: &[u8]) -> Option<(String, Entry)> {
    let count = u64::from_le_bytes(b.get(..8)?.try_into().ok()?) as usize;
    let mut at = 8;
    let mut field = || { let n = u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?) as usize; let f = b.get(at + 8..(at + 8).checked_add(n)?)?; at += 8 + n; Some(f) };
    let strings = (0..count).map(|_| field().and_then(|f| String::from_utf8(f.to_vec()).ok())).collect::<Option<Vec<String>>>()?;
    let body = field()?.to_vec();
    let [key, status, until, updating, vary, variant, typed, ctype, length, relative] = <[String; 10]>::try_from(strings.get(..10)?.to_vec()).ok()?;
    let headers = strings[10..].chunks_exact(2).map(|h| (h[0].clone(), h[1].clone())).collect();
    let vary = vary.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect();
    Some((key, Entry { status: status.parse().ok()?, ctype: (typed == "true").then_some(ctype), headers, body, length: length.parse().ok(), relative: relative == "true", until: until.parse().ok()?, updating: updating.parse().ok()?, vary, variant }))
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
    fn one_request_refreshes_a_key() {
        let z = Zone::default();
        let held = z.refresh("k").unwrap();
        assert!(z.refresh("k").is_none() && z.refresh("other").is_some());
        drop(held);
        assert!(z.refresh("k").is_some());
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
        // Other than digits caches nothing, also in its extensions.
        assert_eq!(said(&[("Cache-Control", "max-age=6x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-while-revalidate=x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-if-error=x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-if-error=1")]), Some((Some(1060), 0)));
        // "@0" gives no time.
        assert_eq!(said(&[("X-Accel-Expires", "@0"), ("Cache-Control", "max-age=60")]), Some((Some(1060), 0)));
        assert_eq!(said(&[("Cache-Control", "max-age=60"), ("X-Accel-Expires", "@0")]), Some((None, 0)));
        assert_eq!(said(&[("X-Accel-Expires", "@0"), ("Cache-Control", "no-cache")]), None);
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
    fn conditions_of_what_is_kept() {
        let entry = |status, headers: &[(&str, &str)]| Entry { status, ctype: None, headers: h(headers), body: Vec::new(), length: None, relative: false, until: 0, updating: 0, vary: Vec::new(), variant: String::new() };
        let both = [("Last-Modified", "Mon, 02 Mar 2015 17:20:58 GMT"), ("ETag", "\"x\"")];
        assert_eq!(entry(200, &both).conditions(), [("If-Modified-Since", "Mon, 02 Mar 2015 17:20:58 GMT".to_string()), ("If-None-Match", "\"x\"".to_string())]);
        assert_eq!(entry(206, &both[1..]).conditions(), [("If-None-Match", "\"x\"".to_string())]);
        assert!(entry(201, &both).conditions().is_empty());
        assert!(entry(200, &[("Last-Modified", "never")]).conditions().is_empty());
        let z = Zone::default();
        z.put(("k", "k"), (200, None, Vec::new(), Vec::new()), (None, false), (0, 0), (Vec::new(), &[]));
        assert!(z.get("k").is_none());
        z.renew("k", (crate::clock::seconds() + 60, 0));
        z.renew("other", (0, 0));
        assert!(z.get("k").is_some() && z.stale("other").is_none());
    }

    #[test]
    fn variants_by_vary() {
        assert_eq!(vary(&h(&[("Vary", ",, Accept-encoding , ,"), ("vary", "Foo")])), Some(vec!["accept-encoding".to_string(), "foo".to_string()]));
        assert_eq!(vary(&h(&[("Vary", "Foo, *")])), None);
        assert_eq!(vary(&[]), Some(Vec::new()));
        let names = vec!["accept-encoding".to_string()];
        let v = |value| variant(&names, &h(&[("Accept-Encoding", value)]));
        assert_eq!(v("foo, bar"), v("foo,,  ,bar , "));
        assert_ne!(v("foo, bar"), v("foobar"));
        assert_eq!(variant(&names, &h(&[("Accept-Encoding", "a"), ("accept-encoding", "b")])), v("a,b"));
        let z = Zone::default();
        let (gzip, deflate) = (h(&[("Accept-Encoding", "gzip")]), h(&[("Accept-Encoding", "deflate")]));
        let answer = |body: &str| (200, None, Vec::new(), body.as_bytes().to_vec());
        let valid = (crate::clock::seconds() + 60, 0);
        assert_eq!(z.resolve("k", &gzip), "k");
        z.put(("k", "k"), answer("g"), (None, false), valid, (names.clone(), &gzip));
        assert_eq!(z.resolve("k", &gzip), "k");
        let other = z.resolve("k", &deflate);
        assert_ne!(other, "k");
        // A variant is kept by its own key; an answer without Vary replaces them by the key itself.
        z.put(("k", &other), answer("d"), (None, false), valid, (names.clone(), &deflate));
        assert_eq!((z.get("k").unwrap().body, z.get(&other).unwrap().body), (b"g".to_vec(), b"d".to_vec()));
        z.put(("k", &other), answer("n"), (None, false), valid, (Vec::new(), &deflate));
        assert_eq!((z.resolve("k", &deflate), z.get("k").unwrap().body), ("k".to_string(), b"n".to_vec()));
    }

    #[test]
    fn kept_in_files() {
        let dir = std::env::temp_dir().join(format!("twinx-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let z = Zone::at(dir.clone());
        let valid = (crate::clock::seconds() + 60, 5);
        let headers = h(&[("ETag", "\"x\""), ("Vary", "Foo")]);
        z.put(("k", "k"), (200, Some("text/plain".into()), headers.clone(), b"body".to_vec()), (None, false), valid, (vec!["foo".into()], &h(&[("Foo", "1")])));
        z.put(("n", "n"), (404, None, Vec::new(), Vec::new()), (Some(3), true), valid, (Vec::new(), &[]));
        z.renew("n", (valid.0 + 1, 0));
        std::fs::write(dir.join("junk"), b"x").unwrap();
        let again = Zone::at(dir.clone());
        let e = again.get("k").unwrap();
        assert_eq!((e.status, e.ctype.as_deref(), e.headers.clone(), e.body.clone(), e.updating), (200, Some("text/plain"), headers, b"body".to_vec(), 5));
        assert_eq!(again.resolve("k", &h(&[("Foo", "2")])), "k\nfoo:2\n");
        assert_eq!(again.get("n").map(|e| (e.status, e.ctype, e.until, e.length, e.relative)), Some((404, None, valid.0 + 1, Some(3), true)));
        assert_eq!((e.length, e.relative), (None, false));
        assert!(decode(&encode("k", &e)[..20]).is_none());
        let _ = std::fs::remove_dir_all(&dir);
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
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, false), (now + 60, 0), (Vec::new(), &[]));
        assert_eq!(z.get("k").unwrap().body, b"x");
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, false), (now - 10, 0), (Vec::new(), &[]));
        assert!(z.get("k").is_none());
        assert_eq!(z.stale("k").unwrap().body, b"x");
        assert!(!z.stale("k").unwrap().updating());
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, false), (now - 10, 60), (Vec::new(), &[]));
        assert!(z.stale("k").unwrap().updating());
        assert!(z.stale("other").is_none());
        assert!(z.get("other").is_none());
    }
}
