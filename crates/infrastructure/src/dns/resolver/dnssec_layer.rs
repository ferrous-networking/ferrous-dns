use super::super::dnssec::DnssecValidatorPool;
use super::super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct DnssecResolver {
    inner: Arc<dyn DnsResolver>,
    validator: Arc<DnssecValidatorPool>,
}

impl DnssecResolver {
    pub fn new(
        inner: Arc<dyn DnsResolver>,
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
    ) -> Self {
        let pool_size = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        info!(pool_size, "DNSSEC validation layer enabled");

        Self {
            inner,
            validator: Arc::new(DnssecValidatorPool::new(
                pool_manager,
                query_timeout_ms,
                pool_size,
            )),
        }
    }

    pub fn with_pool(inner: Arc<dyn DnsResolver>, validator: Arc<DnssecValidatorPool>) -> Self {
        Self { inner, validator }
    }
}

#[async_trait]
impl DnsResolver for DnssecResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let mut resolution = self.inner.resolve(query).await?;

        if resolution.cache_hit {
            return Ok(resolution);
        }

        if resolution.addresses.is_empty() {
            return Ok(resolution);
        }

        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Performing DNSSEC validation"
        );

        match self
            .validator
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

                resolution.dnssec_status = Some("insecure");
                Ok(resolution)
            }
        }
    }
}
