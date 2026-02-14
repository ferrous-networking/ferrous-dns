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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_rate_small_numbers() {
        assert_eq!(format_rate(0, "q/s"), "0 q/s");
        assert_eq!(format_rate(1, "q/s"), "1 q/s");
        assert_eq!(format_rate(50, "q/s"), "50 q/s");
        assert_eq!(format_rate(999, "q/s"), "999 q/s");
    }

    #[test]
    fn test_format_rate_thousands() {
        assert_eq!(format_rate(1_000, "q/s"), "1.0k q/s");
        assert_eq!(format_rate(1_234, "q/s"), "1.2k q/s");
        assert_eq!(format_rate(1_567, "q/s"), "1.6k q/s");
        assert_eq!(format_rate(9_999, "q/s"), "10.0k q/s");
        assert_eq!(format_rate(15_500, "q/s"), "15.5k q/s");
        assert_eq!(format_rate(999_999, "q/s"), "1000.0k q/s");
    }

    #[test]
    fn test_format_rate_millions() {
        assert_eq!(format_rate(1_000_000, "q/s"), "1.0M q/s");
        assert_eq!(format_rate(1_234_567, "q/s"), "1.2M q/s");
        assert_eq!(format_rate(5_678_901, "q/s"), "5.7M q/s");
        assert_eq!(format_rate(10_000_000, "q/s"), "10.0M q/s");
    }

    #[test]
    fn test_format_rate_different_suffixes() {
        assert_eq!(format_rate(150, "q/m"), "150 q/m");
        assert_eq!(format_rate(1_500, "q/m"), "1.5k q/m");
        assert_eq!(format_rate(1_500_000, "q/h"), "1.5M q/h");
    }

    #[test]
    fn test_rate_unit_to_seconds() {
        assert_eq!(RateUnit::Second.to_seconds(), 1);
        assert_eq!(RateUnit::Minute.to_seconds(), 60);
        assert_eq!(RateUnit::Hour.to_seconds(), 3600);
    }

    #[test]
    fn test_rate_unit_suffix() {
        assert_eq!(RateUnit::Second.suffix(), "q/s");
        assert_eq!(RateUnit::Minute.suffix(), "q/m");
        assert_eq!(RateUnit::Hour.suffix(), "q/h");
    }
}
