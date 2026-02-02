use async_trait::async_trait;
use ferrous_dns_domain::{
    query_log::{QueryLog, QueryStats},
    DomainError,
};

#[async_trait]
pub trait QueryLogRepository: Send + Sync {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError>;
    async fn get_recent(&self, limit: u32) -> Result<Vec<QueryLog>, DomainError>;
    async fn get_stats(&self) -> Result<QueryStats, DomainError>;
}
