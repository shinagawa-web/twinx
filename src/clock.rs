//! The time, read as cheaply as it may be. nginx reads the clock once in each
//! iteration of its event loop and formats the Date header once a second;
//! here what may be a few milliseconds late is read from the kernel's coarse
//! clocks, which read memory only, not the CPU's counter.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A clock's time since its epoch.
fn read(clock: libc::clockid_t) -> Duration {
    // SAFETY: an all-zero timespec is valid, and clock_gettime() only writes to it.
    let mut t: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(clock, &mut t) };
    Duration::new(t.tv_sec as u64, t.tv_nsec as u32)
}

/// The time of day in whole seconds, at most one tick of the kernel (10 ms or less) late.
pub fn seconds() -> i64 {
    read(libc::CLOCK_REALTIME_COARSE).as_secs() as i64
}

/// Now, at most one tick of the kernel late: for limits, not for what is logged.
pub fn coarse() -> Instant {
    // An Instant can only be made from another: the coarse clock is the one
    // Instant reads, so it is as far from its first reading as from that Instant.
    static BASE: OnceLock<(Duration, Instant)> = OnceLock::new();
    let (read_at, base) = BASE.get_or_init(|| (read(libc::CLOCK_MONOTONIC), Instant::now()));
    *base + read(libc::CLOCK_MONOTONIC_COARSE).saturating_sub(*read_at)
}

/// Gives the time of day as the Date header has it, formatted once a second.
pub fn date(give: impl FnOnce(&str)) {
    thread_local! { static DATE: RefCell<(i64, String)> = const { RefCell::new((i64::MIN, String::new())) } }
    let now = seconds();
    DATE.with_borrow_mut(|(at, date)| {
        if *at != now { (*at, *date) = (now, crate::expires::http_date(now)); }
        give(date);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coarse_clocks_follow_the_precise_ones() {
        let before = chrono::Utc::now().timestamp();
        let now = seconds();
        assert!((before - 1..=before + 1).contains(&now));
        let first = coarse();
        std::thread::sleep(Duration::from_millis(50));
        let second = coarse();
        assert!(second <= Instant::now() + Duration::from_millis(1) && second - first >= Duration::from_millis(30));
    }

    #[test]
    fn date_is_the_time_of_day() {
        let get = || { let mut text = String::new(); date(|d| text += d); text };
        let time = crate::expires::http_time(&get()).unwrap();
        assert!((seconds() - time).abs() <= 1);
        // The same second is not formatted again, and gives the same text.
        let (a, b) = (get(), get());
        assert!(a.len() == 29 && (a == b || seconds() > time));
    }
}
