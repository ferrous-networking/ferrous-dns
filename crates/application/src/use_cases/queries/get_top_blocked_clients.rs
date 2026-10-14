use crate::ports::BlockedClientStatsRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetTopBlockedClientsUseCase {
    repository: Arc<dyn BlockedClientStatsRepository>,
}

impl GetTopBlockedClientsUseCase {
    pub fn new(repository: Arc<dyn BlockedClientStatsRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        self.repository
            .get_top_blocked_clients(limit, period_hours)
            .await
    }
}
