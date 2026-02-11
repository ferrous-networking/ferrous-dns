use super::super::cache::{CachedData, DnsCache, DnssecStatus, NegativeQueryTracker};
use super::super::prefetch::PrefetchPredictor;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, warn};

/// Cache decorator for DNS resolver
///
/// Wraps another resolver and adds caching functionality
pub struct CachedResolver {
    inner: Arc<dyn DnsResolver>,
    cache: Arc<DnsCache>,
    cache_ttl: u32,
    negative_ttl_tracker: Arc<NegativeQueryTracker>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
}

impl CachedResolver {
    /// Wrap a resolver with caching
    pub fn new(inner: Arc<dyn DnsResolver>, cache: Arc<DnsCache>, cache_ttl: u32) -> Self {
        Self {
            inner,
            cache,
            cache_ttl,
            negative_ttl_tracker: Arc::new(NegativeQueryTracker::new()),
            prefetch_predictor: None,
        }
    }

    /// Add prefetch predictor
    pub fn with_prefetch(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.prefetch_predictor = Some(predictor);
        self
    }

    /// Try to resolve from cache
    fn check_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.cache
            .get(&query.domain, &query.record_type)
            .map(|(data, dnssec_status)| {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    "Cache HIT"
                );

                let dnssec_str = dnssec_status.map(|s| s.as_str());

                match data {
                    CachedData::IpAddresses(addrs) => DnsResolution {
                        addresses: (*addrs).clone(),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                    },
                    CachedData::CanonicalName(_) => {
                        // For CNAME, we'll need to resolve the canonical name
                        // This is a simplification - in production you'd handle this properly
                        DnsResolution {
                            addresses: vec![],
                            cache_hit: true,
                            dnssec_status: dnssec_str,
                            cname: None,
                            upstream_server: None,
                        }
                    }
                    CachedData::NegativeResponse => {
                        // Return empty result for negative cache
                        DnsResolution {
                            addresses: vec![],
                            cache_hit: true,
                            dnssec_status: dnssec_str,
                            cname: None,
                            upstream_server: None,
                        }
                    }
                }
            })
    }

    /// Store result in cache
    fn store_in_cache(&self, query: &DnsQuery, resolution: &DnsResolution) {
        if resolution.addresses.is_empty() {
            // Negative response
            let dynamic_ttl = self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
            self.cache.insert(
                &query.domain,
                query.record_type,
                CachedData::NegativeResponse,
                dynamic_ttl,
                Some(DnssecStatus::Insecure),
            );

            self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
        } else {
            // Positive response
            let addresses = Arc::new(resolution.addresses.clone());
            let dnssec_status = resolution
                .dnssec_status
                .and_then(|s| s.parse().ok())
                .unwrap_or(DnssecStatus::Insecure);

            self.cache.insert(
                &query.domain,
                query.record_type,
                CachedData::IpAddresses(addresses),
                self.cache_ttl,
                Some(dnssec_status),
            );

            // Record for prefetching if enabled
            if let Some(ref predictor) = self.prefetch_predictor {
                predictor.on_query(&query.domain);
            }
        }
    }
}

#[async_trait]
impl DnsResolver for CachedResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Try cache first
        if let Some(cached) = self.check_cache(query) {
            if cached.addresses.is_empty() {
                // Negative cache hit
                return Err(DomainError::InvalidDomainName(format!(
                    "Domain {} not found (cached NXDOMAIN)",
                    query.domain
                )));
            }
            return Ok(cached);
        }

        // Cache miss - resolve via inner resolver
        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Cache MISS"
        );

        match self.inner.resolve(query).await {
            Ok(resolution) => {
                // Store in cache
                self.store_in_cache(query, &resolution);
                Ok(resolution)
            }
            Err(e) => {
                // Store negative response
                let dynamic_ttl = self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
                self.cache.insert(
                    &query.domain,
                    query.record_type,
                    CachedData::NegativeResponse,
                    dynamic_ttl,
                    Some(DnssecStatus::Insecure),
                );

                warn!(
                    domain = %query.domain,
                    error = %e,
                    "Query failed, caching negative response"
                );

                Err(e)
            }
        }
    }
}
