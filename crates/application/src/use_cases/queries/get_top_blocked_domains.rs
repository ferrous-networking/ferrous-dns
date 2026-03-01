use crate::ports::QueryLogRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetTopBlockedDomainsUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetTopBlockedDomainsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        self.repository
            .get_top_blocked_domains(limit, period_hours)
            .await
    }
}
