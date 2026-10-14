use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// What the query log holds on disk, for Pi-hole's `GET /info/database`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QueryLogStorage {
    /// Client queries logged within the requested period.
    pub recent_queries: u64,
    /// Unix time of the oldest of those, 0 when there is none.
    pub recent_earliest: f64,
    /// Every client query stored.
    pub stored_queries: u64,
    /// Unix time of the oldest stored client query, 0 when there is none.
    pub stored_earliest: f64,
    /// Version of the SQLite library the log is stored with.
    pub sqlite_version: String,
}

#[async_trait]
pub trait QueryLogStorageRepository: Send + Sync {
    async fn get_storage(&self, period_hours: f32) -> Result<QueryLogStorage, DomainError>;
}
