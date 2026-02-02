use crate::ports::QueryLogRepository;
use ferrous_dns_domain::query_log::QueryLog;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetRecentQueriesUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetRecentQueriesUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, limit: u32) -> Result<Vec<QueryLog>, DomainError> {
        self.repository.get_recent(limit).await
    }
}
