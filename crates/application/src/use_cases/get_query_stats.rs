use crate::ports::QueryLogRepository;
use ferrous_dns_domain::{query_log::QueryStats, DomainError};
use std::sync::Arc;

pub struct GetQueryStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetQueryStatsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self) -> Result<QueryStats, DomainError> {
        self.repository.get_stats().await
    }
}
