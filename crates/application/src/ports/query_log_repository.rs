use async_trait::async_trait;
use ferrous_dns_domain::{
    query_log::{QueryLog, QueryStats},
    DomainError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeGranularity {
    Minute,
    QuarterHour,
    Hour,
    Day,
}

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

    fn log_query_sync(&self, query: &QueryLog) -> Result<(), DomainError> {
        let _ = query;
        Ok(())
    }

    async fn get_recent(&self, limit: u32, period_hours: f32)
        -> Result<Vec<QueryLog>, DomainError>;
    async fn get_recent_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
        cursor: Option<i64>,
    ) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError>;
    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError>;
    async fn get_timeline(
        &self,
        period_hours: u32,
        granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError>;
    async fn count_queries_since(&self, seconds_ago: i64) -> Result<u64, DomainError>;
    async fn get_cache_stats(&self, period_hours: f32) -> Result<CacheStats, DomainError>;
    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError>;
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_refreshes: u64,
    pub hit_rate: f64,
    pub refresh_rate: f64,
}
