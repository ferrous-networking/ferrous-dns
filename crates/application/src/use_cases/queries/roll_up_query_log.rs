use crate::ports::QueryLogRollupRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct RollUpQueryLogUseCase {
    repository: Arc<dyn QueryLogRollupRepository>,
}

impl RollUpQueryLogUseCase {
    pub fn new(repository: Arc<dyn QueryLogRollupRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, max_hours: u32) -> Result<u32, DomainError> {
        self.repository.roll_up_hours(max_hours).await
    }
}
