use async_trait::async_trait;
use ferrous_dns_domain::{
    query_log::{QueryLog, QueryLogFilter, QueryStats},
    DomainError,
};

/// Result of a paginated query log fetch.
#[derive(Debug)]
pub struct PagedQueryResult {
    pub queries: Vec<QueryLog>,
    /// Total records in the period (without domain/category/client/type/upstream filters).
    pub records_total: u64,
    /// Total records matching the applied filters.
    pub records_filtered: u64,
    pub next_cursor: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeGranularity {
    Minute,
    QuarterHour,
    Hour,
    Day,
}

/// Aggregated query counts for a single time window in the timeline chart.
#[derive(Debug, Clone)]
pub struct TimelineBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
    pub unblocked: u64,
    pub malware_detected: u64,
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

    /// Fetches paginated query logs with optional filters.
    ///
    /// Pagination modes are **mutually exclusive**: when `cursor` is `Some`, the
    /// `offset` parameter is ignored and results are keyed by descending row id.
    /// When `cursor` is `None`, standard `LIMIT`/`OFFSET` pagination applies with
    /// results ordered by `created_at DESC`.
    async fn get_recent_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
        cursor: Option<i64>,
        filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError>;
    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError>;
    async fn get_timeline(
        &self,
        period_hours: u32,
        granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError>;
    async fn count_queries_since(&self, seconds_ago: i64) -> Result<u64, DomainError>;
    async fn get_cache_stats(&self, period_hours: f32) -> Result<CacheStats, DomainError>;
    async fn get_top_blocked_domains(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError>;
    async fn get_top_allowed_domains(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError>;
    async fn get_top_clients(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError>;
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
