use super::cache::DnssecCache;
use super::validator::{DnssecValidator, ValidatedResponse};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

/// A pool of `DnssecValidator` instances that share a single `DnssecCache`.
///
/// The single-Mutex design forced all DNSSEC validation to run serially.  This
/// pool creates one validator slot per CPU core and distributes incoming
/// requests across them with a round-robin + try_lock strategy, eliminating
/// the serialisation bottleneck under concurrent load.
pub struct DnssecValidatorPool {
    validators: Vec<Mutex<DnssecValidator>>,
    next: AtomicUsize,
}

impl DnssecValidatorPool {
    /// Create a new pool with `size` validator slots, all sharing `cache`.
    pub fn new(pool_manager: Arc<PoolManager>, timeout_ms: u64, size: usize) -> Self {
        let cache = Arc::new(DnssecCache::new());
        let validators = (0..size)
            .map(|_| {
                Mutex::new(
                    DnssecValidator::with_cache(pool_manager.clone(), cache.clone())
                        .with_timeout(timeout_ms),
                )
            })
            .collect();

        debug!(pool_size = size, "DNSSEC validator pool created");

        Self {
            validators,
            next: AtomicUsize::new(0),
        }
    }

    /// Validate a DNS query using the next available validator.
    ///
    /// Iterates the pool starting from the round-robin slot and takes the
    /// first free validator via `try_lock()`.  If all slots are busy, falls
    /// back to `lock().await` on the starting slot (bounded wait).
    pub async fn validate_query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidatedResponse, DomainError> {
        let n = self.validators.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;

        // Fast path: grab the first idle slot without blocking.
        for i in 0..n {
            let idx = (start + i) % n;
            if let Ok(mut v) = self.validators[idx].try_lock() {
                return v.validate_query(domain, record_type).await;
            }
        }

        // All slots busy — wait on the starting slot (provides back-pressure).
        self.validators[start]
            .lock()
            .await
            .validate_query(domain, record_type)
            .await
    }
}
