use ferrous_dns_domain::RecordType;
use std::net::IpAddr;

/// Snapshot of DNS cache metrics for API exposure.
#[derive(Debug, Clone)]
pub struct CacheMetricsSnapshot {
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub insertions: u64,
    pub evictions: u64,
    pub optimistic_refreshes: u64,
    pub stale_hits: u64,
    pub lazy_deletions: u64,
    pub compactions: u64,
    pub batch_evictions: u64,
    pub hit_rate: f64,
}

/// Port for DNS cache operations exposed to the API layer.
pub trait DnsCachePort: Send + Sync {
    fn cache_size(&self) -> usize;
    fn cache_metrics_snapshot(&self) -> CacheMetricsSnapshot;
    fn insert_permanent_record(
        &self,
        domain: &str,
        record_type: RecordType,
        addresses: Vec<IpAddr>,
    );
    fn remove_record(&self, domain: &str, record_type: &RecordType) -> bool;
}
