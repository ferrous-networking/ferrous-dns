use super::cache::DnssecCache;
use super::validator::{DnssecValidator, ValidatedResponse};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::debug;

pub struct DnssecValidatorPool {
    validators: Vec<Mutex<DnssecValidator>>,
    next: AtomicUsize,
}

impl DnssecValidatorPool {
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

    pub async fn validate_query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidatedResponse, DomainError> {
        let n = self.validators.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;

        for i in 0..n {
            let idx = (start + i) % n;
            if let Ok(mut v) = self.validators[idx].try_lock() {
                return v.validate_query(domain, record_type).await;
            }
        }

        self.validators[start]
            .lock()
            .await
            .validate_query(domain, record_type)
            .await
    }

    pub async fn validate_with_message(
        &self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Result<ValidatedResponse, DomainError> {
        let n = self.validators.len();
        let start = self.next.fetch_add(1, Ordering::Relaxed) % n;

        for i in 0..n {
            let idx = (start + i) % n;
            if let Ok(mut v) = self.validators[idx].try_lock() {
                return v.validate_with_message(domain, record_type, message).await;
            }
        }

        self.validators[start]
            .lock()
            .await
            .validate_with_message(domain, record_type, message)
            .await
    }
}
