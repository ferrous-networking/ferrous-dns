use super::conditional_forwarder::ConditionalForwarder;
use super::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DomainError, FqdnFilter, PrivateIpFilter, RecordType};
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

    // Query filters (Fase 1)
    block_private_ptr: bool,
    block_non_fqdn: bool,
    local_domain: Option<String>,

    // Conditional forwarding (Fase 3)
    conditional_forwarder: Option<Arc<ConditionalForwarder>>,
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

            // Query filters - defaults (can be overridden with with_filters)
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,

            // Conditional forwarding (Fase 3)
            conditional_forwarder: None,
        })
    }

    /// Configure conditional forwarding rules
    pub fn with_conditional_forwarding(mut self, forwarder: Arc<ConditionalForwarder>) -> Self {
        self.conditional_forwarder = Some(forwarder);

        info!("Conditional forwarding configured");

        self
    }

    /// Configure local DNS records repository
    /// Configure query filters for privacy and local DNS
    pub fn with_filters(
        mut self,
        block_private_ptr: bool,
        block_non_fqdn: bool,
        local_domain: Option<String>,
    ) -> Self {
        self.block_private_ptr = block_private_ptr;
        self.block_non_fqdn = block_non_fqdn;
        self.local_domain = local_domain;

        info!(
            block_private_ptr,
            block_non_fqdn,
            local_domain = ?self.local_domain,
            "Query filters configured"
        );

        self
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

    /// Get reference to the cache
    ///
    /// Returns the cache if it's enabled, None otherwise.
    /// Used by API handlers to manipulate cache directly (add/remove records).
    pub fn cache(&self) -> Option<&Arc<DnsCache>> {
        self.cache.as_ref()
    }

    /// Preload local DNS records into permanent cache
    ///
    /// Loads static hostname → IP mappings from configuration into the cache
    /// as permanent records that never expire and are immune to eviction.
    ///
    /// # Arguments
    /// * `records` - Vector of local DNS records from config
    /// * `default_domain` - Default domain to append if record has no explicit domain
    ///
    /// # Behavior
    /// - Validates each record (IP address, record type)
    /// - Skips invalid records with warning logs
    /// - Creates permanent cache entries (no TTL expiration)
    /// - Logs each successfully preloaded record
    ///
    /// # Example
    /// ```
    /// let records = vec![
    ///     LocalDnsRecord {
    ///         hostname: "nas".into(),
    ///         domain: Some("home.lan".into()),
    ///         ip: "192.168.1.100".into(),
    ///         record_type: "A".into(),
    ///         ttl: Some(300),
    ///     }
    /// ];
    /// resolver.preload_local_records(records, &Some("home.lan".into())).await;
    /// ```
    pub async fn preload_local_records(
        &self,
        records: Vec<ferrous_dns_domain::LocalDnsRecord>,
        default_domain: &Option<String>,
    ) {
        if records.is_empty() {
            debug!("No local DNS records to preload");
            return;
        }

        let cache = match &self.cache {
            Some(c) => c,
            None => {
                warn!("Cache is disabled, cannot preload local DNS records");
                return;
            }
        };

        let mut success_count = 0;
        let mut error_count = 0;

        for record in records {
            // Build FQDN
            let fqdn = record.fqdn(default_domain);

            // Parse IP address
            let ip: std::net::IpAddr = match record.ip.parse() {
                Ok(ip) => ip,
                Err(_) => {
                    warn!(
                        hostname = %record.hostname,
                        ip = %record.ip,
                        "Invalid IP address for local DNS record, skipping"
                    );
                    error_count += 1;
                    continue;
                }
            };

            // Parse record type
            let record_type = match record.record_type.to_uppercase().as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::AAAA,
                _ => {
                    warn!(
                        hostname = %record.hostname,
                        record_type = %record.record_type,
                        "Invalid record type for local DNS record (must be A or AAAA), skipping"
                    );
                    error_count += 1;
                    continue;
                }
            };

            // Validate IP matches record type
            let ip_type_valid = match (&record_type, &ip) {
                (RecordType::A, std::net::IpAddr::V4(_)) => true,
                (RecordType::AAAA, std::net::IpAddr::V6(_)) => true,
                _ => false,
            };

            if !ip_type_valid {
                warn!(
                    hostname = %record.hostname,
                    ip = %record.ip,
                    record_type = %record.record_type,
                    "IP type mismatch (A record needs IPv4, AAAA needs IPv6), skipping"
                );
                error_count += 1;
                continue;
            }

            // Create cached data
            use super::cache::CachedData;
            let data = CachedData::IpAddresses(Arc::new(vec![ip]));

            // Get TTL (default 300)
            let ttl = record.ttl_or_default();

            // Insert as permanent cache entry
            cache.insert_permanent(&fqdn, &record_type, data, ttl);

            info!(
                fqdn = %fqdn,
                ip = %ip,
                record_type = %record_type,
                ttl = %ttl,
                "Preloaded local DNS record into permanent cache"
            );

            success_count += 1;
        }

        if success_count > 0 {
            info!(
                count = success_count,
                errors = error_count,
                "✓ Preloaded {} local DNS record(s) into permanent cache",
                success_count
            );
        }

        if error_count > 0 {
            warn!(
                count = error_count,
                "Skipped {} invalid local DNS record(s)", error_count
            );
        }
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // ============================================================================
        // PHASE 1: QUERY FILTERS (Privacy & Local DNS)
        // ============================================================================

        // 1.1 Block PTR queries for private IP addresses
        if self.block_private_ptr && query.record_type == RecordType::PTR {
            if PrivateIpFilter::is_private_ptr_query(&query.domain) {
                debug!(
                    domain = %query.domain,
                    "Blocked PTR query for private IP address"
                );
                return Err(DomainError::InvalidDomainName(format!(
                    "PTR queries for private IP addresses are blocked: {}",
                    query.domain
                )));
            }
        }

        // 1.2 Block non-FQDN queries
        if self.block_non_fqdn && FqdnFilter::is_local_hostname(&query.domain) {
            debug!(
                domain = %query.domain,
                "Blocked non-FQDN query"
            );
            return Err(DomainError::InvalidDomainName(format!(
                "Non-FQDN queries are blocked: {}",
                query.domain
            )));
        }

        // ============================================================================
        // PHASE 2: CACHE LOOKUP
        // ============================================================================

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

        // ============================================================================
        // PHASE 3: CACHE LOOKUP
        // ============================================================================

        if let Some(cache) = &self.cache {
            if let Some(cached) = cache.get(&query.domain, &query.record_type) {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    "Cache HIT (includes permanent local DNS records)"
                );

                // Unpack tuple: (CachedData, Option<DnssecStatus>)
                let (data, dnssec_status) = cached;

                // Extract addresses from CachedData enum
                let addresses = match data {
                    super::cache::CachedData::IpAddresses(addrs) => (*addrs).clone(),
                    super::cache::CachedData::CanonicalName(_name) => {
                        // CNAME - would need recursive resolution
                        warn!("CNAME in cache - not fully implemented yet");
                        vec![]
                    }
                    super::cache::CachedData::NegativeResponse => vec![],
                };

                // Convert DnssecStatus to &'static str
                let dnssec_str = dnssec_status.map(|s| s.as_str());

                return Ok(DnsResolution {
                    addresses,
                    cache_hit: true,
                    dnssec_status: dnssec_str,
                    cname: None, // TODO: handle CNAME properly
                    upstream_server: None,
                });
            }
        }
        if let Some(forwarder) = &self.conditional_forwarder {
            if let Some((rule, server)) = forwarder.should_forward(query) {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    rule_domain = %rule.domain,
                    server = %server,
                    "Using conditional forwarding"
                );

                match forwarder
                    .query_specific_server(query, &server, self.query_timeout_ms)
                    .await
                {
                    Ok(addresses) => {
                        let resolution = DnsResolution {
                            addresses: addresses.clone(),
                            cache_hit: false,
                            dnssec_status: None,
                            cname: None,
                            upstream_server: Some(format!("conditional:{}", server)),
                        };

                        // Cache the result
                        if let Some(cache) = &self.cache {
                            cache.insert(
                                &query.domain,
                                &query.record_type,
                                super::cache::CachedData::IpAddresses(Arc::new(addresses)),
                                self.cache_ttl,
                                None,
                            );
                        }

                        return Ok(resolution);
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            domain = %query.domain,
                            server = %server,
                            "Conditional forwarding failed, falling back to upstream"
                        );
                        // Continue to normal upstream resolution
                    }
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
