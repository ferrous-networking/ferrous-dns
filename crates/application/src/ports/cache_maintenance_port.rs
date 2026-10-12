use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Outcome of a cache compaction cycle.
#[derive(Debug, Default, Clone)]
pub struct CacheCompactionOutcome {
    pub entries_removed: usize,
    pub cache_size: usize,
}

/// Port for DNS cache maintenance operations (eviction, compaction).
///
/// Renewing entries before they expire is not a cycle: each entry arms its
/// own refresh timer, and the cache's refresh worker takes them as they fall
/// due.
#[async_trait]
pub trait CacheMaintenancePort: Send + Sync {
    /// Evict past `cache_max_entries` and rotate the bloom filter. Runs whether
    /// or not optimistic refresh is enabled: nothing else bounds the cache.
    async fn run_eviction_cycle(&self) -> Result<(), DomainError>;

    /// Remove expired and low-value entries to reclaim memory, and re-arm the
    /// refresh of entries in use whose renewal failed.
    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError>;
}
