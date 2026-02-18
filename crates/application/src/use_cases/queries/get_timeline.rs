use crate::ports::{QueryLogRepository, TimelineBucket};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetTimelineUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

#[derive(Debug, Clone, Copy)]
pub enum Granularity {
    Minute,
    QuarterHour, 
    Hour,
    Day,
}

impl GetTimelineUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        period_hours: u32,
        granularity: Granularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        
        let period = period_hours.min(720);

        let gran_str = match granularity {
            Granularity::Minute => "minute",
            Granularity::QuarterHour => "quarter_hour",
            Granularity::Hour => "hour",
            Granularity::Day => "day",
        };

        self.repository.get_timeline(period, gran_str).await
    }
}
