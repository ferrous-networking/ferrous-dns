use super::cache::DnssecCache;
use super::trust_anchor::TrustAnchorStore;
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
    cache: Arc<DnssecCache>,
}

impl DnssecValidatorPool {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        timeout_ms: u64,
        size: usize,
        trust_store: TrustAnchorStore,
    ) -> Self {
        Self::with_shared_cache(
            pool_manager,
            timeout_ms,
            size,
            trust_store,
            Arc::new(DnssecCache::new()),
        )
    }

    /// Builds the pool over a caller-owned cache, so the wiring can keep a
    /// handle for stats reporting and so the counters survive the resolver-stack
    /// rebuilds that `HickoryDnsResolver` performs on every `with_*` call.
    pub fn with_shared_cache(
        pool_manager: Arc<PoolManager>,
        timeout_ms: u64,
        size: usize,
        trust_store: TrustAnchorStore,
        cache: Arc<DnssecCache>,
    ) -> Self {
        let validators = (0..size)
            .map(|_| {
                Mutex::new(
                    DnssecValidator::with_trust_store_and_cache(
                        pool_manager.clone(),
                        trust_store.clone(),
                        cache.clone(),
                    )
                    .with_timeout(timeout_ms),
                )
            })
            .collect();

        debug!(
            pool_size = size,
            trust_anchors = trust_store.len(),
            "DNSSEC validator pool created"
        );

        Self {
            validators,
            next: AtomicUsize::new(0),
            cache,
        }
    }

    pub fn cache(&self) -> &Arc<DnssecCache> {
        &self.cache
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
