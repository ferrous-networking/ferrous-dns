use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Outcome of a cache refresh cycle.
///
/// A cycle scans for candidates and hands them to the shared refresh queue; the
/// refreshes themselves happen asynchronously on the queue worker. So these
/// counts describe the handoff, not completed upstream work.
#[derive(Debug, Default, Clone)]
pub struct CacheRefreshOutcome {
    pub candidates_found: usize,
    /// Candidates accepted by the refresh queue.
    pub enqueued: usize,
    /// Candidates rejected because the queue was full; they stay eligible for
    /// a later cycle.
    pub dropped: usize,
    pub cache_size: usize,
}

/// Outcome of a cache compaction cycle.
#[derive(Debug, Default, Clone)]
pub struct CacheCompactionOutcome {
    pub entries_removed: usize,
    pub cache_size: usize,
}

/// Port for DNS cache maintenance operations (refresh + compaction).
#[async_trait]
pub trait CacheMaintenancePort: Send + Sync {
    /// Refresh popular cache entries before they expire (optimistic refresh).
    async fn run_refresh_cycle(&self) -> Result<CacheRefreshOutcome, DomainError>;

    /// Remove expired and low-value entries to reclaim memory.
    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError>;
}
