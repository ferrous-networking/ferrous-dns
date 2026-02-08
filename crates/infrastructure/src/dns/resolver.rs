use super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use super::cache::DnsCache;
use super::dnssec::{DnssecCache, DnssecValidator};
use super::prefetch::PrefetchPredictor;

pub struct HickoryDnsResolver {
    pool_manager: Arc<PoolManager>,
    cache: Option<Arc<DnsCache>>,
    cache_ttl: u32,
    query_timeout_ms: u64,
    dnssec_enabled: bool,
    dnssec_validator: Option<Arc<Mutex<DnssecValidator>>>,
    dnssec_cache: Option<Arc<DnssecCache>>,
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

        // Initialize DNSSEC validator if enabled
        let (dnssec_validator, dnssec_cache) = if dnssec_enabled {
            let cache = Arc::new(DnssecCache::new());

            // Create validator with shared cache
            let validator = DnssecValidator::with_cache(pool_manager.clone(), cache.clone())
                .with_timeout(query_timeout_ms);

            info!("DNSSEC validation enabled with shared cache (queries will be logged!)");

            (Some(Arc::new(Mutex::new(validator))), Some(cache))
        } else {
            (None, None)
        };

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
            dnssec_validator,
            dnssec_cache,
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

    async fn validate_dnssec_query(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Option<&'static str> {
        if !self.dnssec_enabled {
            return None;
        }

        // Check DNSSEC cache first
        if let Some(ref cache) = self.dnssec_cache {
            if let Some(result) = cache.get_validation(domain, record_type) {
                debug!(
                    domain = %domain,
                    record_type = ?record_type,
                    result = %result.as_str(),
                    "DNSSEC cache hit"
                );
                return Some(result.as_str());
            }
        }

        // Perform DNSSEC validation
        if let Some(ref validator) = self.dnssec_validator {
            let mut validator_guard = validator.lock().await;

            match validator_guard.validate_simple(domain, record_type).await {
                Ok(result) => {
                    info!(
                        domain = %domain,
                        record_type = ?record_type,
                        result = %result.as_str(),
                        "DNSSEC validation completed"
                    );

                    // Cache the result (TTL 300 seconds)
                    if let Some(ref cache) = self.dnssec_cache {
                        cache.cache_validation(domain, record_type, result, 300);
                    }

                    Some(result.as_str())
                }
                Err(e) => {
                    warn!(
                        domain = %domain,
                        error = %e,
                        "DNSSEC validation failed"
                    );
                    Some("Indeterminate")
                }
            }
        } else {
            None
        }
    }

    async fn resolve_via_pools(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Perform DNS query
        let mut result = self
            .pool_manager
            .query(&query.domain, &query.record_type, self.query_timeout_ms)
            .await?;

        let addresses = std::mem::take(&mut result.response.addresses);
        let cname = result.response.cname.take();

        // Perform DNSSEC validation if enabled
        // This will query DS/DNSKEY records (all logged!)
        let dnssec_status = self
            .validate_dnssec_query(&query.domain, query.record_type)
            .await;

        debug!(
            domain = %query.domain, record_type = ?query.record_type,
            addresses = addresses.len(), upstream = %result.server, latency_ms = result.latency_ms,
            dnssec_status = ?dnssec_status,
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
                    let dnssec_str: Option<&'static str> = cached_dnssec_status.map(|s| s.as_str());
                    return Ok(DnsResolution::with_cname(addresses, true, dnssec_str, None));
                }
            }
        }

        // Use resolve_via_pools which includes DNSSEC validation
        let mut resolution = self.resolve_via_pools(query).await?;

        if let Some(cache) = &self.cache {
            let cached_data = if !resolution.addresses.is_empty() {
                Some(super::cache::CachedData::IpAddresses(Arc::new(
                    resolution.addresses.clone(),
                )))
            } else if let Some(ref cname_val) = resolution.cname {
                Some(super::cache::CachedData::CanonicalName(Arc::new(
                    cname_val.clone(),
                )))
            } else {
                Some(super::cache::CachedData::NegativeResponse)
            };

            if let Some(data) = cached_data {
                let dnssec_status_cache = resolution
                    .dnssec_status
                    .map(super::cache::DnssecStatus::from_str);
                let ttl = if data.is_negative() {
                    300
                } else {
                    self.cache_ttl
                };
                cache.insert(
                    &query.domain,
                    &query.record_type,
                    data,
                    ttl,
                    dnssec_status_cache,
                );
                cache.reset_refreshing(&query.domain, &query.record_type);
            }
        }

        resolution.cache_hit = false;

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
