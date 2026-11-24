//! proxy_cache: answers of proxied servers kept by the key of their request in a
//! zone that proxy_cache_path names (keys_zone=), and given again while they are valid
//! for as long as proxy_cache_valid says for their status.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A cached answer: its status, Content-Type, headers and body, and until when it is valid.
#[derive(Debug, Clone)]
pub struct Entry {
    pub status: u16,
    pub ctype: Option<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    until: Instant,
}

/// A zone of keys (keys_zone=name:size of proxy_cache_path), with what it keeps.
#[derive(Debug, Default)]
pub struct Zone {
    entries: Mutex<HashMap<String, Entry>>,
    /// proxy_cache_lock: what a request that asks the server for a key holds meanwhile.
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// How many requests asked for each key (proxy_cache_min_uses).
    uses: Mutex<HashMap<String, u64>>,
}

/// How long a request waits for another that asks for the same key (proxy_cache_lock_timeout's default).
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

impl Zone {
    /// The answer kept for a key, while it is valid.
    pub fn get(&self, key: &str) -> Option<Entry> {
        self.entries.lock().unwrap().get(key).filter(|e| e.until > Instant::now()).cloned()
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

    /// Keeps an answer for a key, valid for so long.
    pub fn put(&self, key: String, (status, ctype, headers, body): (u16, Option<String>, Vec<(String, String)>, Vec<u8>), valid: Duration) {
        self.entries.lock().unwrap().insert(key, Entry { status, ctype, headers, body, until: Instant::now() + valid });
    }

    /// Waits, for so long at most, until no other request asks the server for the key, and
    /// holds that until what it gives is dropped; None when the time ran out.
    pub async fn lock(&self, key: &str, wait: Duration) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let lock = self.locks.lock().unwrap().entry(key.to_string()).or_default().clone();
        crate::stream::within(Some(wait), lock.lock_owned()).await
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
            let held = z.lock("k", LOCK_TIMEOUT).await.unwrap();
            // Another key is not held; the same one is, until the time runs out.
            assert!(z.lock("other", Duration::from_millis(50)).await.is_some());
            assert!(z.lock("k", Duration::from_millis(50)).await.is_none());
            drop(held);
            assert!(z.lock("k", Duration::from_millis(50)).await.is_some());
        });
    }

    #[test]
    fn uses_counted_by_key() {
        let z = Zone::default();
        assert_eq!((z.used("k"), z.used("k"), z.used("other")), (1, 2, 1));
    }

    #[test]
    fn kept_while_valid() {
        let z = Zone::default();
        z.put("k".into(), (200, None, Vec::new(), b"x".to_vec()), Duration::from_secs(60));
        assert_eq!(z.get("k").unwrap().body, b"x");
        z.put("k".into(), (200, None, Vec::new(), b"x".to_vec()), Duration::ZERO);
        assert!(z.get("k").is_none());
        assert_eq!(z.stale("k").unwrap().body, b"x");
        assert!(z.stale("other").is_none());
        assert!(z.get("other").is_none());
    }
}
