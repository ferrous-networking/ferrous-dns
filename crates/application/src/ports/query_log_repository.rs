use async_trait::async_trait;
use ferrous_dns_domain::{
    entities::query_log::{DnssecStats, QueryLog, QueryLogFilter, QueryStats},
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
    /// Id of the last row returned, to pass back as [`PageAt::Cursor`].
    pub next_cursor: Option<i64>,
}

/// Where a query-log page starts. Every page is ordered newest first by
/// `(created_at, id)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageAt {
    /// Skip this many matching rows.
    Offset(u32),
    /// Continue after the row with this id: rows ordered strictly after its
    /// `(created_at, id)`, so a backwards clock step cannot skip rows.
    Cursor(i64),
}

impl Default for PageAt {
    fn default() -> Self {
        Self::Offset(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeGranularity {
    Minute,
    TenMinutes,
    QuarterHour,
    Hour,
    Day,
}

impl TimeGranularity {
    /// Canonical name the API reports for this granularity.
    pub fn as_str(self) -> &'static str {
        match self {
            TimeGranularity::Minute => "minute",
            TimeGranularity::TenMinutes => "10min",
            TimeGranularity::QuarterHour => "15min",
            TimeGranularity::Hour => "hour",
            TimeGranularity::Day => "day",
        }
    }
}

/// Aggregated query counts for a single time window in the timeline chart.
#[derive(Debug, Clone)]
pub struct TimelineBucket {
    pub timestamp: String,
    pub total: u64,
    pub blocked: u64,
    pub unblocked: u64,
    /// Answered from the cache or a local record.
    pub cached: u64,
    /// Answered by an upstream server.
    pub forwarded: u64,
    pub malware_detected: u64,
}

#[async_trait]
pub trait QueryLogRepository: Send + Sync {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError>;

    fn log_query_sync(&self, query: &QueryLog) -> Result<(), DomainError>;

    async fn get_recent(&self, limit: u32, period_hours: f32)
        -> Result<Vec<QueryLog>, DomainError>;

    /// Fetches one page of query logs matching `filter`, starting at `page`.
    async fn get_recent_paged(
        &self,
        limit: u32,
        page: PageAt,
        period_hours: f32,
        filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError>;
    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError>;
    /// Aggregated DNSSEC validation outcome counts over client queries in the
    /// period. Required (no default) so a real repository can never silently
    /// report all-zero by forgetting to implement it; test doubles return
    /// `DnssecStats::default()` explicitly.
    async fn get_dnssec_stats(&self, period_hours: f32) -> Result<DnssecStats, DomainError>;
    async fn get_timeline(
        &self,
        period_hours: f32,
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
    /// Distinct client-queried domains in the period with their query counts,
    /// regardless of whether they were blocked. Ordered by count descending.
    /// Used to build the backtest corpus from real traffic.
    async fn get_distinct_recent_domains(
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
