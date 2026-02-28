use crate::ports::{ClientRepository, QueryLogRepository};
use ferrous_dns_domain::{query_log::QueryStats, DomainError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(10);

struct CachedStats {
    computed_at: Instant,
    period_hours: f32,
    data: QueryStats,
}

pub struct GetQueryStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
    client_repository: Arc<dyn ClientRepository>,
    cache: RwLock<Option<CachedStats>>,
    refresh_lock: Mutex<()>,
}

impl GetQueryStatsUseCase {
    pub fn new(
        repository: Arc<dyn QueryLogRepository>,
        client_repository: Arc<dyn ClientRepository>,
    ) -> Self {
        Self {
            repository,
            client_repository,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<QueryStats, DomainError> {
        {
            let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL {
                    return Ok(cached.data.clone());
                }
            }
        }

        let _lock = self.refresh_lock.lock().await;

        {
            let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL {
                    return Ok(cached.data.clone());
                }
            }
        }

        let (stats_result, unique_clients) = tokio::join!(
            self.repository.get_stats(period_hours),
            self.client_repository.count_active_since(period_hours)
        );
        let mut stats = stats_result?;
        stats.unique_clients = unique_clients?;

        {
            let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
            *guard = Some(CachedStats {
                computed_at: Instant::now(),
                period_hours,
                data: stats.clone(),
            });
        }

        Ok(stats)
    }
}
