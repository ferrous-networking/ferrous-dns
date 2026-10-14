use crate::ports::QueryLogRepository;
use ferrous_dns_domain::DomainError;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// The count scans the raw query log, so integrations polling the Pi-hole
/// summary share one scan per window.
const CACHE_TTL: Duration = Duration::from_secs(10);

struct CachedCount {
    computed_at: Instant,
    period_hours: f32,
    count: u64,
}

/// How many distinct domains clients queried in a period, blocked or not.
pub struct GetUniqueDomainsUseCase {
    repository: Arc<dyn QueryLogRepository>,
    cache: RwLock<Option<CachedCount>>,
    refresh_lock: Mutex<()>,
}

impl GetUniqueDomainsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self {
            repository,
            cache: RwLock::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<u64, DomainError> {
        if let Some(count) = self.fresh(period_hours) {
            return Ok(count);
        }

        let _lock = self.refresh_lock.lock().await;
        if let Some(count) = self.fresh(period_hours) {
            return Ok(count);
        }

        let count = self.repository.count_distinct_domains(period_hours).await?;
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(CachedCount {
            computed_at: Instant::now(),
            period_hours,
            count,
        });
        Ok(count)
    }

    fn fresh(&self, period_hours: f32) -> Option<u64> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .filter(|cached| {
                cached.period_hours == period_hours && cached.computed_at.elapsed() < CACHE_TTL
            })
            .map(|cached| cached.count)
    }
}
