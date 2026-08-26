use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

#[derive(Default)]
#[repr(align(64))]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    _hot_pad: [u64; 6],

    pub insertions: AtomicU64,
    pub evictions: AtomicU64,
    pub optimistic_refreshes: AtomicU64,
    pub stale_hits: AtomicU64,
    pub lazy_deletions: AtomicU64,
    pub compactions: AtomicU64,
    pub batch_evictions: AtomicU64,
    pub adaptive_adjustments: AtomicU64,

    /// Phase 6: counts upstream resolution failures that were NOT cached as
    /// NXDOMAIN — timeouts, connection refused/reset, no healthy servers,
    /// invalid responses, etc. Caching these would poison the negative cache
    /// during transient upstream instability and hand clients fake NXDOMAIN
    /// answers for legitimate domains.
    pub transient_upstream_errors: AtomicU64,

    /// Serve-stale repairs that could not be queued because the stale channel
    /// was full. Each one is a client that got a stale answer with no renewal
    /// scheduled behind it, so a non-zero value means the channel is undersized.
    pub stale_refresh_drops: AtomicU64,

    /// Optimistic candidates a cycle cut because its backlog did not fit in the
    /// queue. Non-zero means the working set outgrew the queue, which is the
    /// signal that used to be missing when the fixed pacer silently starved it.
    pub optimistic_refresh_shed: AtomicU64,
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
