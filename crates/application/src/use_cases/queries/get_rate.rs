use crate::ports::QueryLogRepository;
use ferrous_dns_domain::DomainError;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const RATE_CACHE_TTL: Duration = Duration::from_secs(3);

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

    fn index(&self) -> usize {
        match self {
            RateUnit::Second => 0,
            RateUnit::Minute => 1,
            RateUnit::Hour => 2,
        }
    }
}

pub struct QueryRate {
    pub queries: u64,
    pub rate: String,
}

struct CachedRate {
    computed_at: Instant,
    queries: u64,
    rate: String,
}

pub struct GetQueryRateUseCase {
    repository: Arc<dyn QueryLogRepository>,
    cache: [RwLock<Option<CachedRate>>; 3],
    refresh_locks: [Mutex<()>; 3],
}

impl GetQueryRateUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self {
            repository,
            cache: [RwLock::new(None), RwLock::new(None), RwLock::new(None)],
            refresh_locks: [Mutex::new(()), Mutex::new(()), Mutex::new(())],
        }
    }

    pub async fn execute(&self, unit: RateUnit) -> Result<QueryRate, DomainError> {
        let slot = &self.cache[unit.index()];

        {
            let guard = slot.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref cached) = *guard {
                if cached.computed_at.elapsed() < RATE_CACHE_TTL {
                    return Ok(QueryRate {
                        queries: cached.queries,
                        rate: cached.rate.clone(),
                    });
                }
            }
        }

        let _lock = self.refresh_locks[unit.index()].lock().await;

        {
            let guard = slot.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref cached) = *guard {
                if cached.computed_at.elapsed() < RATE_CACHE_TTL {
                    return Ok(QueryRate {
                        queries: cached.queries,
                        rate: cached.rate.clone(),
                    });
                }
            }
        }

        let seconds = unit.to_seconds();
        let count = self.repository.count_queries_since(seconds).await?;
        let formatted_rate = format_rate(count, unit.suffix());

        {
            let mut guard = slot.write().unwrap_or_else(|e| e.into_inner());
            *guard = Some(CachedRate {
                computed_at: Instant::now(),
                queries: count,
                rate: formatted_rate.clone(),
            });
        }

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
