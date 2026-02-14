use crate::ports::{CacheStats, QueryLogRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetCacheStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetCacheStatsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<CacheStats, DomainError> {
        self.repository.get_cache_stats(period_hours).await
    }
}
