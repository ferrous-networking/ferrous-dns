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
