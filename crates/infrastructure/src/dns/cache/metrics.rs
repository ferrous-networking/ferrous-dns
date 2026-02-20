use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

// align(64) ensures the struct starts on a cache-line boundary so that `hits`
// and `misses` are always on their own line, never split with cold counters.
#[derive(Default)]
#[repr(align(64))]
pub struct CacheMetrics {
    // Hot counters — updated on every cache access.
    // hits(8) + misses(8) + _hot_pad(48) = 64 bytes → isolated cache line.
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    _hot_pad: [u64; 6], // 6 × 8 bytes = 48 bytes, completing the 64-byte cache line

    // Cold counters — updated infrequently (insertions, evictions, maintenance).
    pub insertions: AtomicU64,
    pub evictions: AtomicU64,
    pub optimistic_refreshes: AtomicU64,
    pub lazy_deletions: AtomicU64,
    pub compactions: AtomicU64,
    pub batch_evictions: AtomicU64,
    pub adaptive_adjustments: AtomicU64,
}

impl CacheMetrics {
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(AtomicOrdering::Relaxed) as f64;
        let total = hits + self.misses.load(AtomicOrdering::Relaxed) as f64;

        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }
}
