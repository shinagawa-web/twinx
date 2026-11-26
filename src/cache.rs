use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Entry {
    pub status: u16,
    pub ctype: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Arc<Vec<u8>>,
    pub length: Option<usize>,
    pub line: Option<String>,
    pub upstream: Vec<(String, String)>,
    until: i64,
    updating: i64,
    error: i64,
    vary: Vec<String>,
    variant: String,
}

impl Entry {
    pub fn conditions(&self) -> Vec<(&'static str, String)> {
        if !matches!(self.status, 200 | 206) { return Vec::new(); }
        let header = |name: &str| self.headers.iter().rev().find(|h| h.0.eq_ignore_ascii_case(name)).map(|h| h.1.clone());
        let modified = header("last-modified").and_then(|v| crate::expires::http_time(&v)).map(|t| ("If-Modified-Since", crate::expires::http_date(t)));
        modified.into_iter().chain(header("etag").filter(|e| !e.is_empty()).map(|e| ("If-None-Match", e))).collect()
    }

    pub fn erring(&self) -> bool {
        self.until.saturating_add(self.error) >= crate::clock::seconds()
    }

    pub fn updating(&self) -> bool {
        self.until.saturating_add(self.updating) >= crate::clock::seconds()
    }
}

pub fn said(headers: &[(String, String)], ignored: &[String], now: i64) -> Option<(Option<i64>, i64)> {
    let (mut valid, mut updating, mut accel, mut no_cache, mut expired) = (None, 0, false, false, false);
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        if ignored.contains(&name) { continue; }
        let lower = value.to_ascii_lowercase();
        match name.as_str() {
            "set-cookie" => return None,
            "x-accel-expires" if !accel => {
                accel = true;
                let number = |v: &str| v.bytes().all(|c| c.is_ascii_digit()).then(|| v.parse::<i64>().ok()).flatten();
                let n = match value.strip_prefix('@') {
                    Some(at) => number(at),
                    None => match number(value) { Some(0) => return None, n => n.map(|n| now.saturating_add(n)) },
                };
                if let Some(n) = n { (valid, no_cache, expired) = (Some(n), false, false); }
            }
            "cache-control" => {
                if !(valid.is_some_and(|v| v != 0) && accel) {
                    if ["no-cache", "no-store", "private"].iter().any(|d| lower.contains(d)) { no_cache = true; continue; }
                    let age = lower.find("s-maxage=").map(|i| i + 9).or_else(|| lower.find("max-age=").map(|i| i + 8));
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

pub fn stale_if_error(headers: &[(String, String)], ignored: &[String]) -> i64 {
    let controls = headers.iter().filter(|h| h.0.eq_ignore_ascii_case("cache-control") && !ignored.iter().any(|i| i == "cache-control"));
    controls.filter_map(|h| { let lower = h.1.to_ascii_lowercase(); lower.find("stale-if-error=").and_then(|i| seconds(&lower[i + 15..])) }).last().unwrap_or(0)
}

fn seconds(s: &str) -> Option<i64> {
    let digits = s.find([',', ';', ' ']).map_or(s, |end| &s[..end]);
    digits.bytes().try_fold(0i64, |n, c| c.is_ascii_digit().then(|| n.saturating_mul(10).saturating_add((c - b'0') as i64)))
}

pub fn vary(headers: &[(String, String)]) -> Option<Vec<String>> {
    let lines: Vec<&str> = headers.iter().filter(|h| h.0.eq_ignore_ascii_case("vary")).map(|h| h.1.as_str()).collect();
    let all = lines.join(", ");
    if lines.contains(&"*") || all.len() > 128 { return None }
    Some(words(&all).map(str::to_ascii_lowercase).collect())
}

fn words(s: &str) -> impl Iterator<Item = &str> {
    s.split([' ', ',']).filter(|w| !w.is_empty())
}

pub fn variant(names: &[String], request: &[(String, String)]) -> String {
    names.iter().map(|n| {
        let values = request.iter().filter(|h| h.0.eq_ignore_ascii_case(n)).map(|h| h.1.as_str());
        let values: Vec<&str> = if ["accept-charset", "accept-encoding", "accept-language"].contains(&n.as_str()) { values.flat_map(words).collect() } else { values.collect() };
        format!("{n}:{}\n", values.join(","))
    }).collect()
}

#[derive(Debug, Default)]
pub struct Zone {
    dir: Option<std::path::PathBuf>,
    levels: Vec<usize>,
    entries: Mutex<HashMap<String, Entry>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    since: Mutex<HashMap<String, Instant>>,
    uses: Mutex<HashMap<String, u64>>,
    refreshing: Mutex<std::collections::HashSet<String>>,
}

pub struct Refresh<'a>(&'a Zone, String);

impl Drop for Refresh<'_> {
    fn drop(&mut self) {
        self.0.release(&self.1);
    }
}

impl Refresh<'_> {
    pub fn hand_over(self) {
        std::mem::forget(self);
    }
}

pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

impl Zone {
    pub fn at(dir: std::path::PathBuf, levels: &[usize]) -> Zone {
        fn files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for f in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                if f.file_type().is_ok_and(|t| t.is_dir()) { files(&f.path(), found) } else { found.push(f.path()) }
            }
        }
        let mut found = Vec::new();
        files(&dir, &mut found);
        let entries = found.iter().filter_map(|f| decode(&std::fs::read(f).ok()?)).collect();
        Zone { dir: Some(dir), levels: levels.to_vec(), entries: Mutex::new(entries), ..Zone::default() }
    }

    fn file(&self, dir: &std::path::Path, key: &str) -> std::path::PathBuf {
        use md5::Digest;
        let name = md5::Md5::digest(key.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>();
        let (mut path, mut end) = (dir.to_path_buf(), name.len());
        for &l in &self.levels { path.push(&name[end - l..end]); end -= l; }
        path.join(name)
    }

    fn kept<'a>(&self, entries: &'a mut HashMap<String, Entry>, key: &str) -> Option<&'a Entry> {
        let Some(dir) = &self.dir else { return entries.get(key) };
        if entries.contains_key(key) && std::fs::read(self.file(dir, key)).ok().and_then(|b| decode(&b)).is_none_or(|(k, _)| k != key) { entries.remove(key); }
        entries.get(key)
    }

    pub fn resolve(&self, key: &str, request: &[(String, String)]) -> String {
        match self.kept(&mut self.entries.lock().unwrap(), key).map(|e| (variant(&e.vary, request), e)) {
            Some((v, e)) if !e.vary.is_empty() && v != e.variant => format!("{key}\n{v}"),
            _ => key.to_string(),
        }
    }

    fn save(&self, key: &str, e: &Entry) {
        let Some(dir) = &self.dir else { return };
        let file = self.file(dir, key);
        let temp = file.with_extension("tmp");
        let _ = std::fs::create_dir_all(file.parent().unwrap_or(dir)).and_then(|()| std::fs::write(&temp, encode(key, e))).and_then(|()| std::fs::rename(&temp, &file));
    }

    pub fn get(&self, key: &str) -> Option<Entry> {
        self.kept(&mut self.entries.lock().unwrap(), key).filter(|e| e.until >= crate::clock::seconds()).cloned()
    }

    pub fn stale(&self, key: &str) -> Option<Entry> {
        self.kept(&mut self.entries.lock().unwrap(), key).cloned()
    }

    pub fn refresh(&self, key: &str) -> Option<Refresh<'_>> {
        self.refreshing.lock().unwrap().insert(key.to_string()).then(|| Refresh(self, key.to_string()))
    }

    pub fn release(&self, key: &str) {
        self.refreshing.lock().unwrap().remove(key);
    }

    pub fn used(&self, key: &str) -> u64 {
        let mut uses = self.uses.lock().unwrap();
        let n = uses.entry(key.to_string()).or_default();
        *n += 1;
        *n
    }

    pub fn renew(&self, key: &str, (until, updating): (i64, i64), vary: Option<(Vec<String>, &[(String, String)])>) {
        let mut entries = self.entries.lock().unwrap();
        let Some(e) = entries.get_mut(key) else { return };
        (e.until, e.updating) = (until, updating);
        if let Some((names, request)) = vary { e.variant = variant(&names, request); e.vary = names; }
        self.save(key, e);
    }

    pub fn put(&self, (key, at): (&str, &str), (status, ctype, headers, body): (u16, Option<String>, Vec<(String, String)>, Vec<u8>), (length, line, upstream): (Option<usize>, Option<String>, Vec<(String, String)>), (until, updating, error): (i64, i64, i64), (vary, request): (Vec<String>, &[(String, String)])) {
        let variant = variant(&vary, request);
        let key = if at == key || (!vary.is_empty() && at == format!("{key}\n{variant}")) { at } else { key };
        let e = Entry { status, ctype, headers, body: Arc::new(body), length, line, upstream, until, updating, error, vary, variant };
        self.save(key, &e);
        self.entries.lock().unwrap().insert(key.to_string(), e);
    }

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

fn encode(key: &str, e: &Entry) -> Vec<u8> {
    let mut fields = vec![key.to_string(), e.status.to_string(), e.until.to_string(), e.updating.to_string(), e.error.to_string(), e.vary.join(","), e.variant.clone(), e.ctype.is_some().to_string(), e.ctype.clone().unwrap_or_default(), e.length.map_or_else(String::new, |n| n.to_string()), e.line.is_some().to_string(), e.line.clone().unwrap_or_default(), e.headers.len().to_string()];
    fields.extend(e.headers.iter().chain(&e.upstream).flat_map(|(n, v)| [n.clone(), v.clone()]));
    let mut out = (fields.len() as u64).to_le_bytes().to_vec();
    for f in fields.iter().map(String::as_bytes).chain([e.body.as_slice()]) {
        out.extend_from_slice(&(f.len() as u64).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn decode(b: &[u8]) -> Option<(String, Entry)> {
    let count = u64::from_le_bytes(b.get(..8)?.try_into().ok()?) as usize;
    let mut at = 8;
    let mut field = || { let n = u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?) as usize; let f = b.get(at + 8..(at + 8).checked_add(n)?)?; at += 8 + n; Some(f) };
    let strings = (0..count).map(|_| field().and_then(|f| String::from_utf8(f.to_vec()).ok())).collect::<Option<Vec<String>>>()?;
    let body = Arc::new(field()?.to_vec());
    let [key, status, until, updating, error, vary, variant, typed, ctype, length, lined, line, count] = <[String; 13]>::try_from(strings.get(..13)?.to_vec()).ok()?;
    let mut headers: Vec<(String, String)> = strings[13..].chunks_exact(2).map(|h| (h[0].clone(), h[1].clone())).collect();
    let upstream = headers.split_off(count.parse::<usize>().ok()?.min(headers.len()));
    let vary = vary.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect();
    Some((key, Entry { status: status.parse().ok()?, ctype: (typed == "true").then_some(ctype), headers, body, length: length.parse().ok(), line: (lined == "true").then_some(line), upstream, until: until.parse().ok()?, updating: updating.parse().ok()?, error: error.parse().ok()?, vary, variant }))
}

pub fn valid(args: &[String], time: Duration) -> Result<Vec<(Option<u16>, Duration)>, String> {
    if args.is_empty() { return Ok([200, 301, 302].map(|s| (Some(s), time)).to_vec()); }
    args.iter().map(|a| match a.as_str() {
        "any" => Ok((None, time)),
        code => code.parse().ok().filter(|c| (100..=599).contains(c)).map(|c| (Some(c), time)).ok_or_else(|| format!("invalid status \"{code}\"")),
    }).collect()
}

pub fn validity(valid: &[(Option<u16>, Duration)], status: u16) -> Option<Duration> {
    valid.iter().find(|v| v.0.is_none_or(|s| s == status)).map(|v| v.1).filter(|t| !t.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
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
        let zero = Duration::ZERO;
        assert_eq!(validity(&[(None, m), (Some(404), zero)], 404), Some(m));
        assert_eq!(validity(&[(Some(404), zero), (None, m)], 404), None);
        assert_eq!(validity(&[(None, zero), (Some(200), m)], 200), None);
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
            assert!(z.lock("other", ms(50), long).await.unwrap().is_some());
            assert!(z.lock("k", ms(50), long).await.is_none());
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
        assert_eq!(said(&[("Cache-Control", "max-age=6x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-while-revalidate=x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-if-error=x")]), None);
        assert_eq!(said(&[("Cache-Control", "max-age=60, stale-if-error=1")]), Some((Some(1060), 0)));
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
        assert_eq!(stale_if_error(&h(&[("Cache-Control", "max-age=1, stale-if-error=60")]), none), 60);
        assert_eq!(stale_if_error(&h(&[("Cache-Control", "stale-if-error=60")]), &["cache-control".to_string()]), 0);
        assert_eq!(stale_if_error(&h(&[("Expires", "0")]), none), 0);
        let ignored = ["set-cookie".to_string(), "cache-control".to_string()];
        assert_eq!(super::said(&h(&[("Set-Cookie", "a"), ("Cache-Control", "no-cache")]), &ignored, 1000), Some((None, 0)));
    }

    #[test]
    fn conditions_of_what_is_kept() {
        let entry = |status, headers: &[(&str, &str)]| Entry { status, ctype: None, headers: h(headers), body: Arc::default(), length: None, line: None, upstream: Vec::new(), until: 0, updating: 0, error: 0, vary: Vec::new(), variant: String::new() };
        let both = [("Last-Modified", "Mon, 02 Mar 2015 17:20:58 GMT"), ("ETag", "\"x\"")];
        assert_eq!(entry(200, &both).conditions(), [("If-Modified-Since", "Mon, 02 Mar 2015 17:20:58 GMT".to_string()), ("If-None-Match", "\"x\"".to_string())]);
        assert_eq!(entry(206, &both[1..]).conditions(), [("If-None-Match", "\"x\"".to_string())]);
        assert!(entry(201, &both).conditions().is_empty());
        assert!(entry(200, &[("Last-Modified", "never")]).conditions().is_empty());
        assert!(entry(200, &[("ETag", "")]).conditions().is_empty());
        let z = Zone::default();
        z.put(("k", "k"), (200, None, Vec::new(), Vec::new()), (None, None, Vec::new()), (0, 0, 0), (Vec::new(), &[]));
        assert!(z.get("k").is_none());
        z.renew("k", (crate::clock::seconds() + 60, 0), None);
        z.renew("other", (0, 0), None);
        assert!(z.get("k").is_some() && z.stale("other").is_none());
        z.renew("k", (crate::clock::seconds() + 60, 0), Some((vec!["foo".into()], &h(&[("Foo", "a")]))));
        assert_eq!((z.resolve("k", &h(&[("Foo", "a")])), z.resolve("k", &[])), ("k".to_string(), "k\nfoo:\n".to_string()));
    }

    #[test]
    fn variants_by_vary() {
        assert_eq!(vary(&h(&[("Vary", ",, Accept-encoding , ,"), ("vary", "Foo")])), Some(vec!["accept-encoding".to_string(), "foo".to_string()]));
        assert_eq!(vary(&h(&[("Vary", "Foo, *")])), Some(vec!["foo".to_string(), "*".to_string()]));
        assert_eq!(vary(&h(&[("Vary", "*"), ("Vary", "Foo")])), None);
        assert_eq!(vary(&h(&[("Vary", "Foo Bar\t,\tBaz")])), Some(vec!["foo".to_string(), "bar\t".to_string(), "\tbaz".to_string()]));
        assert!(vary(&h(&[("Vary", "Foo"), ("Vary", &"a".repeat(123))])).is_some());
        assert_eq!(vary(&h(&[("Vary", "Foo"), ("Vary", &"a".repeat(124))])), None);
        assert_eq!(vary(&[]), Some(Vec::new()));
        let foo = vec!["foo".to_string()];
        assert_ne!(variant(&foo, &h(&[("Foo", "a, b")])), variant(&foo, &h(&[("Foo", "a,b")])));
        assert_eq!(variant(&foo, &h(&[("Foo", "a"), ("Foo", "b")])), variant(&foo, &h(&[("Foo", "a,b")])));
        assert_eq!(variant(&foo, &h(&[("Foo", "")])), variant(&foo, &[]));
        let names = vec!["accept-encoding".to_string()];
        let v = |value| variant(&names, &h(&[("Accept-Encoding", value)]));
        assert_eq!(v("foo, bar"), v("foo,,  ,bar , "));
        assert_ne!(v("foo, bar"), v("foobar"));
        assert_eq!(variant(&names, &h(&[("Accept-Encoding", "a"), ("accept-encoding", "b")])), v("a,b"));
        let z = Zone::default();
        let (gzip, deflate) = (h(&[("Accept-Encoding", "gzip")]), h(&[("Accept-Encoding", "deflate")]));
        let answer = |body: &str| (200, None, Vec::new(), body.as_bytes().to_vec());
        let valid = (crate::clock::seconds() + 60, 0, 0);
        assert_eq!(z.resolve("k", &gzip), "k");
        z.put(("k", "k"), answer("g"), (None, None, Vec::new()), valid, (names.clone(), &gzip));
        assert_eq!(z.resolve("k", &gzip), "k");
        let other = z.resolve("k", &deflate);
        assert_ne!(other, "k");
        z.put(("k", &other), answer("d"), (None, None, Vec::new()), valid, (names.clone(), &deflate));
        assert_eq!((&**z.get("k").unwrap().body, &**z.get(&other).unwrap().body), (b"g".as_slice(), b"d".as_slice()));
        z.put(("k", &other), answer("n"), (None, None, Vec::new()), valid, (Vec::new(), &deflate));
        assert_eq!((z.resolve("k", &deflate), &**z.get("k").unwrap().body), ("k".to_string(), b"n".as_slice()));
    }

    #[test]
    fn kept_in_files() {
        let dir = std::env::temp_dir().join(format!("twinx-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let z = Zone::at(dir.clone(), &[1, 2]);
        let valid = (crate::clock::seconds() + 60, 5, 7);
        let headers = h(&[("ETag", "\"x\""), ("Vary", "Foo")]);
        z.put(("k", "k"), (200, Some("text/plain".into()), headers.clone(), b"body".to_vec()), (None, None, Vec::new()), valid, (vec!["foo".into()], &h(&[("Foo", "1")])));
        z.put(("n", "n"), (404, None, Vec::new(), Vec::new()), (Some(3), Some("404 Gone".into()), h(&[("X-A", "a"), ("X-A", "b")])), valid, (Vec::new(), &[]));
        z.renew("n", (valid.0 + 1, 0), None);
        std::fs::write(dir.join("junk"), b"x").unwrap();
        let again = Zone::at(dir.clone(), &[1, 2]);
        let e = again.get("k").unwrap();
        assert_eq!((e.status, e.ctype.as_deref(), e.headers.clone(), (*e.body).clone(), e.updating, e.error), (200, Some("text/plain"), headers, b"body".to_vec(), 5, 7));
        assert_eq!(again.resolve("k", &h(&[("Foo", "2")])), "k\nfoo:2\n");
        assert_eq!(again.get("n").map(|e| (e.status, e.ctype, e.until, e.length)), Some((404, None, valid.0 + 1, Some(3))));
        assert_eq!(again.get("n").map(|e| (e.line, e.upstream)), Some((Some("404 Gone".into()), h(&[("X-A", "a"), ("X-A", "b")]))));
        assert_eq!(e.length, None);
        assert!(decode(&encode("k", &e)[..20]).is_none());
        let file = dir.join("1/3a/7b8b965ad4bca0e41ab51de7b31363a1");
        assert!(file.is_file() && again.file(&dir, "n") == file);
        std::fs::write(&file, b"garbage").unwrap();
        assert!(again.get("n").is_none() && again.stale("n").is_none());
        std::fs::remove_file(again.file(&dir, "k")).unwrap();
        assert!(again.stale("k").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn refreshes_handed_over_last_until_released() {
        let z = Zone::default();
        let first = z.refresh("k").unwrap();
        assert!(z.refresh("k").is_none());
        drop(first);
        z.refresh("k").unwrap().hand_over();
        assert!(z.refresh("k").is_none());
        z.release("k");
        assert!(z.refresh("k").is_some());
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
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, None, Vec::new()), (now + 60, 0, 0), (Vec::new(), &[]));
        assert_eq!(*z.get("k").unwrap().body, b"x");
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, None, Vec::new()), (now - 10, 0, 0), (Vec::new(), &[]));
        assert!(z.get("k").is_none());
        assert_eq!(*z.stale("k").unwrap().body, b"x");
        assert!(!z.stale("k").unwrap().updating());
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, None, Vec::new()), (now - 10, 60, 0), (Vec::new(), &[]));
        assert!(z.stale("k").unwrap().updating() && !z.stale("k").unwrap().erring());
        z.put(("k", "k"), (200, None, Vec::new(), b"x".to_vec()), (None, None, Vec::new()), (now - 10, 0, 60), (Vec::new(), &[]));
        assert!(z.stale("k").unwrap().erring() && !z.stale("k").unwrap().updating());
        assert!(z.stale("other").is_none());
        assert!(z.get("other").is_none());
    }
}
