use crate::ports::{QueryLogRepository, TimeGranularity, TimelineBucket};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetTimelineUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetTimelineUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        period_hours: u32,
        granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        let period = period_hours.min(720);
        self.repository.get_timeline(period, granularity).await
    }
}
