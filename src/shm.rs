use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

struct Counters {
    connections: AtomicU64,
    temp_numbers: AtomicU64,
}

static COUNTERS: OnceLock<&'static Counters> = OnceLock::new();

pub fn shared<T: Sync>(value: T) -> Result<&'static T, String> {
    let size = size_of::<T>();
    // SAFETY: a new anonymous mapping, page aligned and as large as T, is written before it is read.
    unsafe {
        let p = libc::mmap(std::ptr::null_mut(), size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_SHARED, -1, 0);
        if p == libc::MAP_FAILED { return Err(format!("mmap(MAP_ANON|MAP_SHARED, {size}) failed ({})", std::io::Error::last_os_error())) }
        p.cast::<T>().write(value);
        Ok(&*p.cast::<T>())
    }
}

fn fresh() -> Counters {
    Counters { connections: AtomicU64::new(1), temp_numbers: AtomicU64::new(0) }
}

pub fn share_counters() -> Result<(), String> {
    let _ = COUNTERS.set(shared(fresh())?);
    Ok(())
}

fn counters() -> &'static Counters {
    COUNTERS.get_or_init(|| Box::leak(Box::new(fresh())))
}

pub fn connection_number() -> u64 {
    counters().connections.fetch_add(1, Ordering::Relaxed)
}

pub fn temp_number(add: u64) -> u64 {
    counters().temp_numbers.fetch_add(add, Ordering::Relaxed) + add
}

#[cfg(test)]
pub fn last_temp_number() -> u64 {
    counters().temp_numbers.load(Ordering::Relaxed)
}

const SLOT: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct RawKey {
    expire: u64,
    bytes: [u8; 48],
}

#[repr(C)]
struct State {
    keys: [RawKey; 3],
    next: usize,
}

pub struct Zone {
    base: *mut u8,
    slots: usize,
}

// SAFETY: every access to the mapping goes through the lock in it.
unsafe impl Sync for Zone {}
unsafe impl Send for Zone {}

impl std::fmt::Debug for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Zone({})", self.slots)
    }
}

const HEAD: usize = 64;

pub fn zone(name: &str, size: u64) -> Result<&'static Zone, String> {
    static ZONES: std::sync::Mutex<Vec<(String, u64, &'static Zone)>> = std::sync::Mutex::new(Vec::new());
    let mut zones = ZONES.lock().map_err(|e| e.to_string())?;
    if let Some(z) = zones.iter().find(|z| z.0 == name && z.1 == size) { return Ok(z.2) }
    let len = size as usize;
    let slots = len.saturating_sub(HEAD + size_of::<State>()) / (SLOT + 4);
    // SAFETY: a new anonymous mapping, zero filled, which is what an empty zone is.
    let p = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_SHARED, -1, 0) };
    if p == libc::MAP_FAILED { return Err(format!("mmap(MAP_ANON|MAP_SHARED, {len}) failed ({})", std::io::Error::last_os_error())) }
    let z: &'static Zone = Box::leak(Box::new(Zone { base: p.cast(), slots }));
    zones.push((name.to_string(), size, z));
    Ok(z)
}

fn hash(key: &[u8]) -> u32 {
    key.iter().fold(0x811c9dc5u32, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x01000193)) | 1
}

impl Zone {
    fn locked<R>(&self, f: impl FnOnce(&mut State, &mut [u32], &mut [u8]) -> R) -> R {
        // SAFETY: the mapping holds the lock at its start, then State, the hashes and the slots, none of them overlapping.
        unsafe {
            let lock = &*self.base.cast::<AtomicU32>();
            while lock.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() { std::thread::yield_now() }
            let state = &mut *self.base.add(HEAD).cast::<State>();
            let marks = std::slice::from_raw_parts_mut(self.base.add(HEAD + size_of::<State>()).cast::<u32>(), self.slots);
            let data = std::slice::from_raw_parts_mut(self.base.add(HEAD + size_of::<State>() + 4 * self.slots), SLOT * self.slots);
            let r = f(state, marks, data);
            lock.store(0, Ordering::Release);
            r
        }
    }

    fn find(marks: &[u32], data: &[u8], key: &[u8]) -> Option<usize> {
        let h = hash(key);
        marks.iter().enumerate().filter(|m| *m.1 == h).map(|m| m.0).find(|&i| {
            let e = &data[i * SLOT..];
            usize::from(u16::from_le_bytes([e[8], e[9]])) == key.len() && e.get(12..12 + key.len()) == Some(key)
        })
    }

    pub fn put(&self, key: &[u8], value: &[u8], expire: u64) -> bool {
        let n = (12 + key.len() + value.len()).div_ceil(SLOT);
        if n > self.slots || key.len() > usize::from(u16::MAX) || value.len() > usize::from(u16::MAX) { return false }
        self.locked(|state, marks, data| {
            if let Some(i) = Self::find(marks, data, key) { marks[i] = 0 }
            if state.next + n > marks.len() {
                marks[state.next..].fill(0);
                state.next = 0;
            }
            let at = state.next;
            marks[at..at + n].fill(0);
            marks[at] = hash(key);
            let e = &mut data[at * SLOT..];
            e[..8].copy_from_slice(&expire.to_le_bytes());
            e[8..10].copy_from_slice(&(key.len() as u16).to_le_bytes());
            e[10..12].copy_from_slice(&(value.len() as u16).to_le_bytes());
            e[12..12 + key.len()].copy_from_slice(key);
            e[12 + key.len()..12 + key.len() + value.len()].copy_from_slice(value);
            state.next = at + n;
            true
        })
    }

    pub fn get(&self, key: &[u8], now: u64) -> Option<Vec<u8>> {
        self.locked(|_, marks, data| {
            let e = &data[Self::find(marks, data, key)? * SLOT..];
            let len = usize::from(u16::from_le_bytes([e[10], e[11]]));
            (u64::from_le_bytes(e[..8].try_into().ok()?) >= now).then(|| e.get(12 + key.len()..12 + key.len() + len).map(<[u8]>::to_vec))?
        })
    }

    pub fn ticket_keys(&self, now: u64, expire: u64, fresh: impl Fn() -> Option<[u8; 48]>) -> Option<[[u8; 48]; 3]> {
        self.locked(|state, _, _| {
            let k = &mut state.keys;
            if k[0].expire == 0 {
                k[0] = RawKey { expire, bytes: fresh()? };
                k[2] = k[0];
            }
            if k[1].expire < now {
                k[1] = k[0];
                k[0] = k[2];
                k[2] = RawKey { expire: 0, bytes: fresh()? };
            }
            k[0].expire = k[0].expire.max(expire);
            Some(k.map(|k| k.bytes))
        })
    }
}
