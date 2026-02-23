use crate::ports::QueryLogRepository;
use ferrous_dns_domain::{query_log::QueryStats, DomainError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(10);

struct CachedStats {
    computed_at: Instant,
    period_hours: f32,
    data: QueryStats,
}

pub struct GetQueryStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
    cache: RwLock<Option<CachedStats>>,
}

impl GetQueryStatsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self {
            repository,
            cache: RwLock::new(None),
        }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<QueryStats, DomainError> {
        {
            let guard = self.cache.read().unwrap();
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL {
                    return Ok(cached.data.clone());
                }
            }
        }

        let stats = self.repository.get_stats(period_hours).await?;

        {
            let mut guard = self.cache.write().unwrap();
            *guard = Some(CachedStats {
                computed_at: Instant::now(),
                period_hours,
                data: stats.clone(),
            });
        }

        Ok(stats)
    }
}
