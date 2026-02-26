use crate::ports::{CacheStats, QueryLogRepository};
use ferrous_dns_domain::DomainError;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CACHE_TTL: Duration = Duration::from_secs(10);

struct CachedEntry {
    computed_at: Instant,
    period_hours: f32,
    data: CacheStats,
}

pub struct GetCacheStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
    cache: RwLock<Option<CachedEntry>>,
    refresh_lock: Mutex<()>,
}

impl GetCacheStatsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self {
            repository,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<CacheStats, DomainError> {
        {
            let guard = self.cache.read().unwrap();
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL {
                    return Ok(cached.data.clone());
                }
            }
        }

        let _lock = self.refresh_lock.lock().await;

        {
            let guard = self.cache.read().unwrap();
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL {
                    return Ok(cached.data.clone());
                }
            }
        }

        let stats = self.repository.get_cache_stats(period_hours).await?;

        {
            let mut guard = self.cache.write().unwrap();
            *guard = Some(CachedEntry {
                computed_at: Instant::now(),
                period_hours,
                data: stats.clone(),
            });
        }

        Ok(stats)
    }
}
