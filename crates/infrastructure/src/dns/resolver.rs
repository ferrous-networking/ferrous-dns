use super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use std::sync::Arc;
use tracing::{debug, info};

use super::cache::DnsCache;
use super::prefetch::PrefetchPredictor;

pub struct HickoryDnsResolver {
    pool_manager: Arc<PoolManager>,
    cache: Option<Arc<DnsCache>>,
    cache_ttl: u32,
    query_timeout_ms: u64,
    dnssec_enabled: bool,
    #[allow(dead_code)]
    server_hostname: String,
    #[allow(dead_code)]
    query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
}

impl HickoryDnsResolver {
    pub fn new_with_pools(
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
        dnssec_enabled: bool,
        query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    ) -> Result<Self, DomainError> {
        let server_hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        info!(
            dnssec_enabled,
            timeout_ms = query_timeout_ms,
            "DNS resolver created with load balancer"
        );

        Ok(Self {
            pool_manager,
            cache: None,
            cache_ttl: 3600,
            query_timeout_ms,
            dnssec_enabled,
            server_hostname,
            query_log_repo,
            prefetch_predictor: None,
        })
    }

    pub fn with_prefetch(mut self, max_predictions: usize, min_probability: f64) -> Self {
        info!(
            max_predictions,
            min_probability, "Enabling predictive prefetching"
        );
        self.prefetch_predictor = Some(Arc::new(PrefetchPredictor::new(
            max_predictions,
            min_probability,
        )));
        self
    }

    pub fn with_cache_ref(mut self, cache: Arc<DnsCache>, ttl_seconds: u32) -> Self {
        self.cache = Some(cache);
        self.cache_ttl = ttl_seconds;
        self
    }

    async fn validate_dnssec(&self, _domain: &str) -> String {
        if self.dnssec_enabled {
            "Secure".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    async fn resolve_via_pools(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let result = self
            .pool_manager
            .query(&query.domain, &query.record_type, self.query_timeout_ms)
            .await?;

        let addresses = result.response.addresses.clone();
        let cname = result.response.cname.clone();

        let dnssec_status = if self.dnssec_enabled {
            Some(self.validate_dnssec(&query.domain).await)
        } else {
            None
        };

        debug!(
            domain = %query.domain, record_type = ?query.record_type,
            addresses = addresses.len(), upstream = %result.server, latency_ms = result.latency_ms,
            "Query resolved via load balancer"
        );

        let mut resolution = DnsResolution::with_cname(addresses, false, dnssec_status, cname);
        resolution.upstream_server = Some(result.server.to_string());
        Ok(resolution)
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Check cache
        if let Some(cache) = &self.cache {
            if let Some((cached_data, cached_dnssec_status)) =
                cache.get(&query.domain, &query.record_type)
            {
                if cached_data.is_negative() {
                    return Err(DomainError::InvalidDomainName(format!(
                        "Domain {} not found (cached NXDOMAIN)",
                        query.domain
                    )));
                }
                if let Some(arc_addrs) = cached_data.as_ip_addresses() {
                    let addresses = (**arc_addrs).clone();
                    let dnssec_str = cached_dnssec_status.map(|s| s.as_str().to_string());
                    return Ok(DnsResolution::with_cname(addresses, true, dnssec_str, None));
                }
            }
        }

        // Resolve upstream
        let mut resolution = self.resolve_via_pools(query).await?;

        // Cache result
        if let Some(cache) = &self.cache {
            let cached_data = if !resolution.addresses.is_empty() {
                Some(super::cache::CachedData::IpAddresses(Arc::new(
                    resolution.addresses.clone(),
                )))
            } else if let Some(ref cname) = resolution.cname {
                Some(super::cache::CachedData::CanonicalName(Arc::new(
                    cname.clone(),
                )))
            } else {
                Some(super::cache::CachedData::NegativeResponse)
            };

            if let Some(data) = cached_data {
                let dnssec_status = resolution
                    .dnssec_status
                    .as_ref()
                    .and_then(|s| super::cache::DnssecStatus::from_string(s));
                let ttl = if data.is_negative() {
                    300
                } else {
                    self.cache_ttl
                };
                cache.insert(&query.domain, &query.record_type, data, ttl, dnssec_status);
                cache.reset_refreshing(&query.domain, &query.record_type);
            }
        }

        resolution.cache_hit = false;

        // Predictive prefetch
        if let Some(ref predictor) = self.prefetch_predictor {
            let predictions = predictor.on_query(&query.domain);
            if !predictions.is_empty() {
                let pool_manager = Arc::clone(&self.pool_manager);
                let cache_clone = self.cache.clone();
                let cache_ttl = self.cache_ttl;
                let timeout_ms = self.query_timeout_ms;

                tokio::spawn(async move {
                    for pred_domain in predictions {
                        if let Some(ref cache) = cache_clone {
                            if cache.get(&pred_domain, &RecordType::A).is_some() {
                                continue;
                            }
                        }
                        if let Ok(result) = pool_manager
                            .query(&pred_domain, &RecordType::A, timeout_ms)
                            .await
                        {
                            if let Some(ref cache) = cache_clone {
                                let addresses = result.response.addresses.clone();
                                if !addresses.is_empty() {
                                    cache.insert(
                                        &pred_domain,
                                        &RecordType::A,
                                        super::cache::CachedData::IpAddresses(Arc::new(addresses)),
                                        cache_ttl,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                });
            }
        }

        Ok(resolution)
    }
}
