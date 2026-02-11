use super::super::dnssec::{DnssecCache, DnssecValidator};
use super::super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// DNSSEC validation decorator for DNS resolver
///
/// Wraps another resolver and adds DNSSEC validation
pub struct DnssecResolver {
    inner: Arc<dyn DnsResolver>,
    validator: Arc<Mutex<DnssecValidator>>,
}

impl DnssecResolver {
    /// Wrap a resolver with DNSSEC validation
    pub fn new(
        inner: Arc<dyn DnsResolver>,
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
    ) -> Self {
        let cache = Arc::new(DnssecCache::new());
        let validator =
            DnssecValidator::with_cache(pool_manager, cache).with_timeout(query_timeout_ms);

        info!("DNSSEC validation layer enabled");

        Self {
            inner,
            validator: Arc::new(Mutex::new(validator)),
        }
    }

    /// Create with existing validator (for testing)
    pub fn with_validator(
        inner: Arc<dyn DnsResolver>,
        validator: Arc<Mutex<DnssecValidator>>,
    ) -> Self {
        Self { inner, validator }
    }
}

#[async_trait]
impl DnsResolver for DnssecResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // First, resolve via inner resolver
        let mut resolution = self.inner.resolve(query).await?;

        // Skip DNSSEC validation for cache hits (already validated)
        if resolution.cache_hit {
            return Ok(resolution);
        }

        // Skip DNSSEC validation if no addresses
        if resolution.addresses.is_empty() {
            return Ok(resolution);
        }

        // Perform DNSSEC validation
        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Performing DNSSEC validation"
        );

        let mut validator = self.validator.lock().await;

        match validator
            .validate_query(&query.domain, query.record_type)
            .await
        {
            Ok(response) => {
                debug!(
                    domain = %query.domain,
                    status = %response.validation_status.as_str(),
                    "DNSSEC validation complete"
                );

                resolution.dnssec_status = Some(response.validation_status.as_str());
                Ok(resolution)
            }
            Err(e) => {
                warn!(
                    domain = %query.domain,
                    error = %e,
                    "DNSSEC validation failed, returning insecure status"
                );

                // Don't fail the query, just mark as insecure
                resolution.dnssec_status = Some("insecure");
                Ok(resolution)
            }
        }
    }
}
