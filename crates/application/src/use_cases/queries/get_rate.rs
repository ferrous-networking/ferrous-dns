use crate::ports::QueryLogRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub enum RateUnit {
    Second,
    Minute,
    Hour,
}

impl RateUnit {
    pub fn to_seconds(&self) -> i64 {
        match self {
            RateUnit::Second => 1,
            RateUnit::Minute => 60,
            RateUnit::Hour => 3600,
        }
    }

    pub fn suffix(&self) -> &'static str {
        match self {
            RateUnit::Second => "q/s",
            RateUnit::Minute => "q/m",
            RateUnit::Hour => "q/h",
        }
    }
}

pub struct QueryRate {
    pub queries: u64,
    pub rate: String,
}

pub struct GetQueryRateUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetQueryRateUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(&self, unit: RateUnit) -> Result<QueryRate, DomainError> {
        let seconds = unit.to_seconds();
        let count = self.repository.count_queries_since(seconds).await?;

        let formatted_rate = format_rate(count, unit.suffix());

        Ok(QueryRate {
            queries: count,
            rate: formatted_rate,
        })
    }
}

fn format_rate(count: u64, suffix: &str) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M {}", count as f64 / 1_000_000.0, suffix)
    } else if count >= 1_000 {
        format!("{:.1}k {}", count as f64 / 1_000.0, suffix)
    } else {
        format!("{} {}", count, suffix)
    }
}
