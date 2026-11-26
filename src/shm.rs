use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

struct Counters {
    connections: AtomicU64,
    temp_numbers: AtomicU64,
}

static COUNTERS: OnceLock<&'static Counters> = OnceLock::new();

pub fn shared<T: Sync>(value: T) -> Result<&'static T, String> {
    let p = zeroed(size_of::<T>())?.cast::<T>();
    // SAFETY: a new mapping, page aligned and as large as T, is written before it is read.
    unsafe {
        p.write(value);
        Ok(&*p)
    }
}

pub fn zeroed(size: usize) -> Result<*mut libc::c_void, String> {
    // SAFETY: an anonymous mapping touches no memory that is in use.
    let p = unsafe { libc::mmap(std::ptr::null_mut(), size.max(1), libc::PROT_READ | libc::PROT_WRITE, libc::MAP_ANONYMOUS | libc::MAP_SHARED, -1, 0) };
    if p == libc::MAP_FAILED { return Err(format!("mmap(MAP_ANON|MAP_SHARED, {size}) failed ({})", std::io::Error::last_os_error())) }
    Ok(p)
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
