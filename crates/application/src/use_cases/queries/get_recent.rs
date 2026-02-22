use crate::ports::QueryLogRepository;
use ferrous_dns_domain::query_log::QueryLog;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

const MAX_LIMIT: u32 = 1_000;

pub struct GetRecentQueriesUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetRecentQueriesUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        self.repository
            .get_recent(limit.min(MAX_LIMIT), period_hours)
            .await
    }

    pub async fn execute_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
        cursor: Option<i64>,
    ) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError> {
        self.repository
            .get_recent_paged(limit.min(MAX_LIMIT), offset, period_hours, cursor)
            .await
    }
}
