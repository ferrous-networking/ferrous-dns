use super::super::dnssec::DnssecCache;
use super::super::dnssec::DnssecValidatorPool;
use super::super::dnssec::TrustAnchorStore;
use super::super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError};
use hickory_proto::op::Message;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct DnssecResolver {
    inner: Arc<dyn DnsResolver>,
    validator: Arc<DnssecValidatorPool>,
}

impl DnssecResolver {
    /// `cache` is caller-owned so the wiring can read its counters.
    pub fn new(
        inner: Arc<dyn DnsResolver>,
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
        trust_store: TrustAnchorStore,
        cache: Arc<DnssecCache>,
    ) -> Self {
        let pool_size = std::thread::available_parallelism()
            .unwrap_or(NonZeroUsize::new(4).unwrap_or(NonZeroUsize::MIN));

        info!(
            pool_size = pool_size.get(),
            "DNSSEC validation layer enabled"
        );

        Self {
            inner,
            validator: Arc::new(DnssecValidatorPool::new(
                pool_manager,
                query_timeout_ms,
                pool_size,
                trust_store,
                cache,
            )),
        }
    }
}

#[async_trait]
impl DnsResolver for DnssecResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let mut resolution = self.inner.resolve(query).await?;

        if resolution.cache_hit || resolution.local_dns {
            return Ok(resolution);
        }

        let pre_fetched_message = resolution
            .upstream_wire_data
            .as_ref()
            .and_then(|bytes| Message::from_vec(bytes).ok());

        // A negative answer (no addresses) is still authenticated, via NSEC/NSEC3
        // denial of existence in the upstream message's authority section. Only
        // skip when there is nothing to validate at all (e.g. a synthesized or
        // blocked response that carries no upstream wire data).
        if resolution.addresses.is_empty() && pre_fetched_message.is_none() {
            return Ok(resolution);
        }

        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Performing DNSSEC validation"
        );

        let dnssec_result = if let Some(ref message) = pre_fetched_message {
            debug!(
                domain = %query.domain,
                "Using pre-fetched upstream response for DNSSEC (skipping duplicate query)"
            );
            self.validator
                .validate_with_message(&query.domain, query.record_type, message)
                .await
        } else {
            self.validator
                .validate_query(&query.domain, query.record_type)
                .await
        };

        match dnssec_result {
            Ok(status) => {
                debug!(
                    domain = %query.domain,
                    status = %status.as_str(),
                    "DNSSEC validation complete"
                );

                resolution.dnssec_status = Some(status);
                Ok(resolution)
            }
            Err(e) => {
                warn!(
                    domain = %query.domain,
                    error = %e,
                    "DNSSEC validation could not run"
                );

                // Not validated is not Insecure: Strict mode SERVFAILs this.
                resolution.dnssec_status = Some(DnssecStatus::Indeterminate);
                Ok(resolution)
            }
        }
    }
}
