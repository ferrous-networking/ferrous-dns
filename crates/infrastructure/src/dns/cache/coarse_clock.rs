use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

static COARSE_CLOCK: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(now_secs()));

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[inline]
pub fn coarse_now_secs() -> u64 {
    COARSE_CLOCK.load(Ordering::Relaxed)
}

pub fn tick() {
    COARSE_CLOCK.store(now_secs(), Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
#[inline]
pub fn coarse_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}
