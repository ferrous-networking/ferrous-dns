//! Coarse timers for non-critical timing: a monotonic one (client tracking,
//! tunneling windows) and a wall clock in whole seconds (cookie rotation).
//!
//! On Linux: uses the `_COARSE` clocks (~4ms resolution, ~10ns overhead).
//! On other platforms: falls back to `Instant` (higher resolution but more overhead).

#[cfg(target_os = "linux")]
#[inline]
pub fn coarse_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is stack-allocated and valid; clock_gettime only writes into the provided pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn coarse_now_ns() -> u64 {
    use std::sync::LazyLock;
    use std::time::Instant;
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_nanos() as u64
}

/// Unix time in seconds, from `CLOCK_REALTIME_COARSE`.
#[cfg(target_os = "linux")]
#[inline]
pub fn coarse_unix_secs() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is stack-allocated and valid; clock_gettime only writes into the provided pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut ts) };
    ts.tv_sec as u64
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn coarse_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}
