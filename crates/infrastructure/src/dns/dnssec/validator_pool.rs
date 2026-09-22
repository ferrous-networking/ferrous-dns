use super::cache::DnssecCache;
use super::trust_anchor::TrustAnchorStore;
use super::validator::{DnssecValidator, ValidatedResponse};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DomainError, RecordType};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard, Semaphore, SemaphorePermit};
use tracing::debug;

pub struct DnssecValidatorPool {
    validators: Vec<Mutex<DnssecValidator>>,
    semaphore: Semaphore,
    cache: Arc<DnssecCache>,
}

impl DnssecValidatorPool {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        timeout_ms: u64,
        size: NonZeroUsize,
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
        size: NonZeroUsize,
        trust_store: TrustAnchorStore,
        cache: Arc<DnssecCache>,
    ) -> Self {
        let validators = (0..size.get())
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
            pool_size = size.get(),
            trust_anchors = trust_store.len(),
            "DNSSEC validator pool created"
        );

        Self {
            validators,
            semaphore: Semaphore::new(size.get()),
            cache,
        }
    }

    pub fn cache(&self) -> &Arc<DnssecCache> {
        &self.cache
    }

    async fn acquire(&self) -> Result<ValidatorLease<'_>, DomainError> {
        let permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|e| DomainError::DnssecValidationFailed(e.to_string()))?;
        let validator = self
            .validators
            .iter()
            .find_map(|validator| validator.try_lock().ok())
            .ok_or_else(|| {
                DomainError::DnssecValidationFailed("no validator for acquired capacity".into())
            })?;
        Ok(ValidatorLease {
            validator,
            _permit: permit,
        })
    }

    pub async fn validate_query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidatedResponse, DomainError> {
        let mut lease = self.acquire().await?;
        lease.validator.validate_query(domain, record_type).await
    }

    pub async fn validate_with_message(
        &self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> Result<ValidatedResponse, DomainError> {
        let mut lease = self.acquire().await?;
        lease
            .validator
            .validate_with_message(domain, record_type, message)
            .await
    }
}

struct ValidatorLease<'a> {
    // Field order unlocks the validator before handing capacity to a waiter.
    validator: MutexGuard<'a, DnssecValidator>,
    _permit: SemaphorePermit<'a>,
}
