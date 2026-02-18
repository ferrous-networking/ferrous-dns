use crate::ports::QueryLogRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::info;

pub struct CleanupOldQueryLogsUseCase {
    query_log_repo: Arc<dyn QueryLogRepository>,
}

impl CleanupOldQueryLogsUseCase {
    pub fn new(query_log_repo: Arc<dyn QueryLogRepository>) -> Self {
        Self { query_log_repo }
    }

    pub async fn execute(&self, retention_days: u32) -> Result<u64, DomainError> {
        let deleted = self
            .query_log_repo
            .delete_older_than(retention_days)
            .await?;
        info!(deleted, retention_days, "Old query logs cleaned up");
        Ok(deleted)
    }
}
