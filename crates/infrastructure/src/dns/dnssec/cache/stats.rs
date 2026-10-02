use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct CacheStats {
    pub(super) dnskey_hits: AtomicU64,
    pub(super) dnskey_misses: AtomicU64,
    pub(super) ds_hits: AtomicU64,
    pub(super) ds_misses: AtomicU64,
    pub(super) ds_denials_unproven: AtomicU64,
}

impl CacheStats {
    pub fn record_dnskey_hit(&self) {
        self.dnskey_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dnskey_miss(&self) {
        self.dnskey_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ds_hit(&self) {
        self.ds_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_ds_miss(&self) {
        self.ds_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// An empty DS answer arrived without an authenticated NSEC/NSEC3 denial
    /// and failed validation. A steady count means the upstreams strip DNSSEC
    /// proofs, which Strict mode turns into SERVFAIL.
    pub fn record_ds_denial_unproven(&self) {
        self.ds_denials_unproven.fetch_add(1, Ordering::Relaxed);
    }

    pub fn total_ds_denials_unproven(&self) -> u64 {
        self.ds_denials_unproven.load(Ordering::Relaxed)
    }

    pub fn total_dnskey_hits(&self) -> u64 {
        self.dnskey_hits.load(Ordering::Relaxed)
    }

    pub fn total_dnskey_misses(&self) -> u64 {
        self.dnskey_misses.load(Ordering::Relaxed)
    }

    pub fn total_ds_hits(&self) -> u64 {
        self.ds_hits.load(Ordering::Relaxed)
    }

    pub fn total_ds_misses(&self) -> u64 {
        self.ds_misses.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct CacheStatsSnapshot {
    pub dnskey_entries: usize,
    pub ds_entries: usize,
    pub total_dnskey_hits: u64,
    pub total_dnskey_misses: u64,
    pub total_ds_hits: u64,
    pub total_ds_misses: u64,
    pub total_ds_denials_unproven: u64,
}
