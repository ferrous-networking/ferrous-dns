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

/// Return the coarse current time in seconds since UNIX epoch.
///
/// Reads an `AtomicU64` (~3 ns) instead of calling `SystemTime::now()` (~50 ns).
/// Resolution: updated once per `CacheUpdater` tick (typically every few seconds),
/// which is sufficient for eviction scoring via `last_access`.
#[inline]
pub fn coarse_now_secs() -> u64 {
    COARSE_CLOCK.load(Ordering::Relaxed)
}

/// Advance the coarse clock to the real current time.
///
/// Called at the start of each `CacheUpdater` iteration.
pub fn tick() {
    COARSE_CLOCK.store(now_secs(), Ordering::Relaxed);
}

/// Return a monotonically-increasing nanosecond timestamp using
/// `CLOCK_MONOTONIC_COARSE` on Linux (~5-15 ns, ~1-4 ms resolution).
///
/// Used for internal latency measurements where sub-millisecond precision is
/// not required (e.g. `response_time_us` in query logs, health-check RTT).
/// Saves ~0.5 µs per call versus `Instant::now()` (which uses the full
/// `CLOCK_MONOTONIC` VDSO with hardware counter reads).
///
/// On non-Linux platforms falls back to `SystemTime` nanoseconds.
#[cfg(target_os = "linux")]
#[inline]
pub fn coarse_now_ns() -> u64 {
    // SAFETY: `ts` is initialized to zero; `clock_gettime` only writes to it.
    // `CLOCK_MONOTONIC_COARSE` is valid on Linux ≥ 2.6.32.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts);
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
#[inline]
pub fn coarse_now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}
