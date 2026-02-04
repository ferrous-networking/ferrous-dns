use ferrous_dns_domain::{CacheStats, DomainError};

pub struct GetCacheStatsUseCase;

impl GetCacheStatsUseCase {
    pub fn new() -> Self {
        Self
    }

    pub async fn execute(&self) -> Result<CacheStats, DomainError> {
        // Note: This is a placeholder implementation
        // Real implementation would get stats from the cache directly
        // which is done in the API handlers
        Ok(CacheStats {
            total_entries: 0,
            total_hits: 0,
            total_misses: 0,
            total_updates: 0,
            total_evictions: 0,
            hit_rate: 0.0,
            avg_ttl_seconds: 0,
        })
    }
}

impl Default for GetCacheStatsUseCase {
    fn default() -> Self {
        Self::new()
    }
}
