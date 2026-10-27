use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Keeps the query log's hourly aggregates, which the top lists read, caught up
/// with the raw log.
#[async_trait]
pub trait QueryLogRollupRepository: Send + Sync {
    /// Aggregates up to `max_hours` closed hours not aggregated yet, and returns how
    /// many it aggregated.
    async fn roll_up_hours(&self, max_hours: u32) -> Result<u32, DomainError>;
}
