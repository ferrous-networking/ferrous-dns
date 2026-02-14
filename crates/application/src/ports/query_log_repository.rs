use async_trait::async_trait;
use ferrous_dns_domain::{
    query_log::{QueryLog, QueryStats},
    DomainError,
};

#[derive(Debug, Clone)]
pub struct TimelineBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
    pub unblocked: u64,
}

#[async_trait]
pub trait QueryLogRepository: Send + Sync {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError>;
    async fn get_recent(&self, limit: u32, period_hours: f32)
        -> Result<Vec<QueryLog>, DomainError>;
    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError>;
    async fn get_timeline(
        &self,
        period_hours: u32,
        granularity: &str,
    ) -> Result<Vec<TimelineBucket>, DomainError>;
    async fn count_queries_since(&self, seconds_ago: i64) -> Result<u64, DomainError>;
    async fn get_cache_stats(&self, period_hours: f32) -> Result<CacheStats, DomainError>;
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_refreshes: u64,
    pub hit_rate: f64,
    pub refresh_rate: f64,
}
