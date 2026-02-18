use super::super::cache::{CachedData, DnsCache, DnssecStatus, NegativeQueryTracker};
use super::super::prefetch::PrefetchPredictor;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, warn};

pub struct CachedResolver {
    inner: Arc<dyn DnsResolver>,
    cache: Arc<DnsCache>,
    cache_ttl: u32,
    negative_ttl_tracker: Arc<NegativeQueryTracker>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
}

impl CachedResolver {
    pub fn new(inner: Arc<dyn DnsResolver>, cache: Arc<DnsCache>, cache_ttl: u32) -> Self {
        Self {
            inner,
            cache,
            cache_ttl,
            negative_ttl_tracker: Arc::new(NegativeQueryTracker::new()),
            prefetch_predictor: None,
        }
    }

    pub fn with_prefetch(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.prefetch_predictor = Some(predictor);
        self
    }

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
                let remaining_ttl = self
                    .cache
                    .get_remaining_ttl(&query.domain, &query.record_type);

                match data {
                    CachedData::IpAddresses(addrs) => DnsResolution {
                        addresses: Arc::clone(&addrs),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                    },
                    CachedData::CanonicalName(_) => DnsResolution {
                        addresses: Arc::new(vec![]),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                    },
                    CachedData::NegativeResponse => DnsResolution {
                        addresses: Arc::new(vec![]),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                    },
                }
            })
    }

    fn store_in_cache(&self, query: &DnsQuery, resolution: &DnsResolution) {
        if resolution.addresses.is_empty() {
            let dynamic_ttl = self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
            self.cache.insert(
                &query.domain,
                query.record_type,
                CachedData::NegativeResponse,
                dynamic_ttl,
                Some(DnssecStatus::Insecure),
            );
        } else {
            let addresses = Arc::clone(&resolution.addresses);
            let dnssec_status = resolution
                .dnssec_status
                .and_then(|s| s.parse().ok())
                .unwrap_or(DnssecStatus::Insecure);

            let ttl = resolution.min_ttl.unwrap_or(self.cache_ttl);

            self.cache.insert(
                &query.domain,
                query.record_type,
                CachedData::IpAddresses(addresses),
                ttl,
                Some(dnssec_status),
            );

            if let Some(ref predictor) = self.prefetch_predictor {
                predictor.on_query(&query.domain);
            }
        }
    }
}

#[async_trait]
impl DnsResolver for CachedResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if let Some(cached) = self.check_cache(query) {
            if cached.addresses.is_empty() {
                return Err(DomainError::NxDomain);
            }
            return Ok(cached);
        }

        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Cache MISS"
        );

        match self.inner.resolve(query).await {
            Ok(resolution) => {
                self.store_in_cache(query, &resolution);
                Ok(resolution)
            }
            Err(e) => {
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
