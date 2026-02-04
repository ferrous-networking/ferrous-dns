use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType, QueryLog};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn, info};

use super::cache::DnsCache;
use super::prefetch::PrefetchPredictor;

pub struct HickoryDnsResolver {
    resolver: Resolver<TokioConnectionProvider>,
    cache: Option<Arc<DnsCache>>,
    cache_ttl: u32,
    dnssec_enabled: bool,
    #[allow(dead_code)]
    server_hostname: String,
    query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,  // ✅ Prefetch predictor!
}

impl HickoryDnsResolver {
    /// Create resolver with optional DNSSEC validation
    pub fn new_with_dnssec(
        config: ResolverConfig,
        dnssec_enabled: bool,
        query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    ) -> Result<Self, DomainError> {
        
        // Get server hostname for internal queries
        let server_hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());
        
        // Build resolver
        let resolver = Resolver::builder_with_config(
            config,
            TokioConnectionProvider::default(),
        ).build();

        Ok(Self { 
            resolver, 
            cache: None,
            cache_ttl: 3600,
            dnssec_enabled,
            server_hostname,
            query_log_repo,
            prefetch_predictor: None,  // Will be enabled with with_prefetch()
        })
    }
    
    /// Enable prefetching (call after creating resolver)
    pub fn with_prefetch(mut self, max_predictions: usize, min_probability: f64) -> Self {
        info!(
            max_predictions = max_predictions,
            min_probability = min_probability,
            "Enabling predictive prefetching"
        );
        self.prefetch_predictor = Some(Arc::new(PrefetchPredictor::new(max_predictions, min_probability)));
        self
    }

    /// Create resolver with Google DNS
    pub fn with_google_dnssec(
        dnssec_enabled: bool,
        query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    ) -> Result<Self, DomainError> {
        Self::new_with_dnssec(ResolverConfig::google(), dnssec_enabled, query_log_repo)
    }

    /// Create resolver with Cloudflare DNS
    pub fn with_cloudflare_dnssec(
        dnssec_enabled: bool,
        query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    ) -> Result<Self, DomainError> {
        Self::new_with_dnssec(ResolverConfig::cloudflare(), dnssec_enabled, query_log_repo)
    }

    /// Enable cache with specified TTL using external cache
    pub fn with_cache_ref(mut self, cache: Arc<DnsCache>, ttl_seconds: u32) -> Self {
        self.cache = Some(cache);
        self.cache_ttl = ttl_seconds;
        self
    }
    
    /// Enable cache with specified TTL (creates internal cache)
    pub fn with_cache(mut self, ttl_seconds: u32) -> Self {
        self.cache = Some(Arc::new(DnsCache::new(
            10_000,                           // max_entries
            super::cache::EvictionStrategy::LFU,  // eviction_strategy
            0.8,                              // min_threshold
            0.9,                              // refresh_threshold
            100,                              // lfuk_history_size
            0.1,                              // batch_eviction_percentage
            true,                             // adaptive_thresholds
        )));
        self.cache_ttl = ttl_seconds;
        self
    }

    /// Convert domain RecordType to Hickory RecordType
    fn to_hickory_type(record_type: &RecordType) -> hickory_proto::rr::RecordType {
        use hickory_proto::rr::RecordType as HickoryRecordType;

        match record_type {
            RecordType::A => HickoryRecordType::A,
            RecordType::AAAA => HickoryRecordType::AAAA,
            RecordType::CNAME => HickoryRecordType::CNAME,
            RecordType::MX => HickoryRecordType::MX,
            RecordType::TXT => HickoryRecordType::TXT,
            RecordType::PTR => HickoryRecordType::PTR,
            RecordType::SRV => HickoryRecordType::SRV,
            RecordType::SOA => HickoryRecordType::SOA,
            RecordType::NS => HickoryRecordType::NS,
            RecordType::NAPTR => HickoryRecordType::NAPTR,
            RecordType::DS => HickoryRecordType::DS,
            RecordType::DNSKEY => HickoryRecordType::DNSKEY,
            RecordType::SVCB => HickoryRecordType::SVCB,
            RecordType::HTTPS => HickoryRecordType::HTTPS,
            RecordType::CAA => HickoryRecordType::CAA,
            RecordType::TLSA => HickoryRecordType::TLSA,
            RecordType::SSHFP => HickoryRecordType::SSHFP,
            RecordType::DNAME => HickoryRecordType::ANAME,
            RecordType::RRSIG => HickoryRecordType::RRSIG,
            RecordType::NSEC => HickoryRecordType::NSEC,
            RecordType::NSEC3 => HickoryRecordType::NSEC3,
            RecordType::NSEC3PARAM => HickoryRecordType::NSEC3PARAM,
            RecordType::CDS => HickoryRecordType::CDS,
            RecordType::CDNSKEY => HickoryRecordType::CDNSKEY,
        }
    }

    /// Log internal DNSSEC validation query
    async fn log_internal_query(
        &self,
        domain: &str,
        record_type: RecordType,
        response_time_ms: u64,
    ) {
        if let Some(query_log_repo) = &self.query_log_repo {
            let log_entry = QueryLog {
                id: None,
                domain: domain.to_string(),
                record_type,
                client_ip: IpAddr::from([127, 0, 0, 1]),  // localhost = internal
                blocked: false,
                response_time_ms: Some(response_time_ms),
                cache_hit: false,
                cache_refresh: false,
                dnssec_status: None,
                timestamp: None,
            };
            
            let _ = query_log_repo.log_query(&log_entry).await;
        }
    }

    /// Perform DNSSEC validation queries manually (IN PARALLEL!)
    async fn validate_dnssec(&self, domain: &str) -> String {
        let start = Instant::now();
        
        info!(domain = %domain, "Starting DNSSEC validation (parallel)");
        
        // Extract zone hierarchy
        let parts: Vec<&str> = domain.split('.').collect();
        let zones: Vec<String> = (0..parts.len())
            .map(|i| parts[i..].join("."))
            .filter(|s| !s.is_empty())
            .collect();
        
        // Execute ALL queries in PARALLEL! 🚀
        let (rrsig_result, ds_result, dnskey_results) = tokio::join!(
            // Query 1: RRSIG (signature)
            async {
                let start = Instant::now();
                let result = self.resolver
                    .lookup(domain, hickory_proto::rr::RecordType::RRSIG)
                    .await;
                let time = start.elapsed().as_micros() as u64;
                (result, time)
            },
            
            // Query 2: DS (delegation signer)
            async {
                let start = Instant::now();
                let result = self.resolver
                    .lookup(domain, hickory_proto::rr::RecordType::DS)
                    .await;
                let time = start.elapsed().as_micros() as u64;
                (result, time)
            },
            
            // Queries 3-N: DNSKEY for all zones (also parallel!)
            async {
                let mut tasks = Vec::new();
                for zone in zones.iter() {
                    let resolver = &self.resolver;
                    let zone = zone.clone();
                    tasks.push(async move {
                        let start = Instant::now();
                        let result = resolver
                            .lookup(&zone, hickory_proto::rr::RecordType::DNSKEY)
                            .await;
                        let time = start.elapsed().as_micros() as u64;
                        (zone, result, time)
                    });
                }
                futures::future::join_all(tasks).await
            }
        );
        
        // Log RRSIG query
        let (rrsig, rrsig_time) = rrsig_result;
        self.log_internal_query(domain, RecordType::RRSIG, rrsig_time).await;
        
        if rrsig.is_err() {
            debug!(domain = %domain, "No RRSIG found - domain is Insecure (unsigned)");
            return "Insecure".to_string();
        }
        
        debug!(domain = %domain, "RRSIG found");
        
        // Log DS query
        let (ds, ds_time) = ds_result;
        self.log_internal_query(domain, RecordType::DS, ds_time).await;
        
        if ds.is_err() {
            debug!(domain = %domain, "No DS record - treating as Insecure");
        }
        
        // Log all DNSKEY queries
        for (zone, dnskey, dnskey_time) in dnskey_results {
            self.log_internal_query(&zone, RecordType::DNSKEY, dnskey_time).await;
            
            if dnskey.is_ok() {
                debug!(zone = %zone, "DNSKEY found");
            }
        }
        
        let total_time = start.elapsed().as_millis();
        info!(
            domain = %domain, 
            total_time_ms = total_time, 
            "DNSSEC validation complete (parallel execution)"
        );
        
        // If we have RRSIG, consider it Secure
        "Secure".to_string()
    }

    /// Resolve with optional DNSSEC validation
    async fn resolve_with_validation(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let start = Instant::now();
        let hickory_type = Self::to_hickory_type(&query.record_type);

        // Perform main lookup
        let lookup = match self.resolver.lookup(&query.domain, hickory_type).await {
            Ok(lookup) => lookup,
            Err(e) => {
                let error_msg = e.to_string();
                
                // "No records found" is NOT an error - it's a valid DNS response (NODATA)
                if error_msg.contains("no records found") 
                    || error_msg.contains("NoRecordsFound")
                    || error_msg.contains("no records")
                {
                    debug!(
                        domain = %query.domain, 
                        record_type = ?query.record_type, 
                        "No records found (NODATA response)"
                    );
                    
                    // Return empty result with DNSSEC validation if enabled
                    let dnssec_status = if self.dnssec_enabled {
                        Some(self.validate_dnssec(&query.domain).await)
                    } else {
                        None
                    };
                    
                    return Ok(DnsResolution::with_cname(vec![], false, dnssec_status, None));
                }
                
                // Real errors (network, timeout, SERVFAIL, etc.)
                warn!(
                    domain = %query.domain, 
                    record_type = ?query.record_type, 
                    error = %e, 
                    "DNS lookup failed"
                );
                return Err(DomainError::InvalidDomainName(e.to_string()));
            }
        };

        // Extract IP addresses
        let mut addresses = Vec::new();
        for record in lookup.record_iter() {
            let rdata = record.data();
            match rdata {
                hickory_proto::rr::RData::A(a) => {
                    addresses.push(IpAddr::V4(a.0));
                }
                hickory_proto::rr::RData::AAAA(aaaa) => {
                    addresses.push(IpAddr::V6(aaaa.0));
                }
                _ => {
                    debug!(domain = %query.domain, record_type = ?query.record_type, "Non-IP record found");
                }
            }
        }

        // Extract CNAME (canonical name)
        let mut cname: Option<String> = None;
        for record in lookup.record_iter() {
            if let hickory_proto::rr::RData::CNAME(canonical) = record.data() {
                cname = Some(canonical.to_utf8());
                debug!(
                    domain = %query.domain,
                    cname = %canonical.to_utf8(),
                    "CNAME record found"
                );
                break;  // Only need first CNAME
            }
        }

        let elapsed_ms = start.elapsed().as_micros() as u64;
        
        debug!(
            domain = %query.domain,
            record_type = ?query.record_type,
            addresses = addresses.len(),
            cname = ?cname,
            elapsed_ms = elapsed_ms,
            "DNS resolution successful"
        );

        // Perform DNSSEC validation if enabled
        let dnssec_status = if self.dnssec_enabled {
            Some(self.validate_dnssec(&query.domain).await)
        } else {
            None
        };

        Ok(DnsResolution::with_cname(addresses, false, dnssec_status, cname))
    }

    /// Resolve without DNSSEC
    async fn resolve_simple(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let start = Instant::now();
        let hickory_type = Self::to_hickory_type(&query.record_type);

        let lookup = match self.resolver.lookup(&query.domain, hickory_type).await {
            Ok(lookup) => lookup,
            Err(e) => {
                let error_msg = e.to_string();
                
                // "No records found" is NOT an error - it's a valid DNS response (NODATA)
                if error_msg.contains("no records found") 
                    || error_msg.contains("NoRecordsFound")
                    || error_msg.contains("no records")
                {
                    debug!(
                        domain = %query.domain, 
                        record_type = ?query.record_type, 
                        "No records found (NODATA response)"
                    );
                    return Ok(DnsResolution::with_cname(vec![], false, None, None));
                }
                
                // Real errors
                warn!(
                    domain = %query.domain, 
                    record_type = ?query.record_type, 
                    error = %e, 
                    "DNS lookup failed"
                );
                return Err(DomainError::InvalidDomainName(e.to_string()));
            }
        };

        let mut addresses = Vec::new();
        for record in lookup.record_iter() {
            let rdata = record.data();
            match rdata {
                hickory_proto::rr::RData::A(a) => {
                    addresses.push(IpAddr::V4(a.0));
                }
                hickory_proto::rr::RData::AAAA(aaaa) => {
                    addresses.push(IpAddr::V6(aaaa.0));
                }
                _ => {}
            }
        }

        // Extract CNAME (canonical name)
        let mut cname: Option<String> = None;
        for record in lookup.record_iter() {
            if let hickory_proto::rr::RData::CNAME(canonical) = record.data() {
                cname = Some(canonical.to_utf8());
                break;  // Only need first CNAME
            }
        }

        Ok(DnsResolution::with_cname(addresses, false, None, cname))
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Check cache first
        if let Some(cache) = &self.cache {
            if let Some((cached_data, cached_dnssec_status)) = cache.get(&query.domain, &query.record_type) {
                // Check for negative cache (NXDOMAIN) ✅
                if cached_data.is_negative() {
                    // Return empty result for NXDOMAIN
                    return Err(DomainError::InvalidDomainName(format!("Domain {} not found (cached NXDOMAIN)", query.domain)));
                }
                
                // Extract addresses from cached data
                if let Some(arc_addrs) = cached_data.as_ip_addresses() {
                    // Clone Arc<Vec> once - cheap! Then convert to Vec for return
                    let addresses = (**arc_addrs).clone();  // ✅ Only 1 clone now!
                    // Convert &'static str to String for compatibility
                    let dnssec_str = cached_dnssec_status.map(|s| s.as_str().to_string());
                    return Ok(DnsResolution::with_cname(addresses, true, dnssec_str, None));
                }
            }
        }

        // Resolve from upstream (with or without DNSSEC)
        let mut resolution = if self.dnssec_enabled {
            self.resolve_with_validation(query).await?
        } else {
            self.resolve_simple(query).await?
        };

        // Cache the result with Arc wrapping
        if let Some(cache) = &self.cache {
            // Determine what data to cache (IPs, CNAME, or negative) - wrap in Arc! ✅
            let cached_data = if !resolution.addresses.is_empty() {
                Some(super::cache::CachedData::IpAddresses(Arc::new(resolution.addresses.clone())))
            } else if let Some(ref canonical_name) = resolution.cname {
                Some(super::cache::CachedData::CanonicalName(Arc::new(canonical_name.clone())))
            } else {
                // Cache negative response (NXDOMAIN) with short TTL ✅
                debug!(
                    domain = %query.domain,
                    record_type = ?query.record_type,
                    "Caching negative response (NXDOMAIN)"
                );
                Some(super::cache::CachedData::NegativeResponse)
            };
            
            // Cache if we have data
            if let Some(data) = cached_data {
                // Convert String to DnssecStatus ✅
                let dnssec_status = resolution.dnssec_status.as_ref()
                    .and_then(|s| super::cache::DnssecStatus::from_string(s));
                
                // Use shorter TTL for negative responses (5 minutes)
                let ttl = if data.is_negative() { 300 } else { self.cache_ttl };
                
                cache.insert(
                    &query.domain,
                    &query.record_type,
                    data,
                    ttl,  // ✅ Variable TTL: 300s for NXDOMAIN, cache_ttl for others
                    dnssec_status  // ✅ DnssecStatus, not String!
                );
                
                // Reset refreshing flag after successful insert (Stale-While-Revalidate) ✅
                cache.reset_refreshing(&query.domain, &query.record_type);
            }
        }

        resolution.cache_hit = false;
        
        // ✅ FIX #3: Return FIRST, then prefetch (user doesn't wait!)
        let result = Ok(resolution);
        
        // Prefetch predictions AFTER return (fire-and-forget) ✅
        if let Some(ref predictor) = self.prefetch_predictor {
            let predictions = predictor.on_query(&query.domain);
            
            if !predictions.is_empty() {
                // Spawn background prefetch tasks
                let resolver_clone = Arc::new(self.resolver.clone());
                let cache_clone = self.cache.clone();
                let cache_ttl = self.cache_ttl;
                
                tokio::spawn(async move {
                    for pred_domain in predictions {
                        // Check if already in cache
                        if let Some(ref cache) = cache_clone {
                            if cache.get(&pred_domain, &RecordType::A).is_some() {
                                continue;  // Already cached
                            }
                        }
                        
                        // Resolve and cache (background, fire-and-forget)
                        if let Ok(lookup) = resolver_clone.ipv4_lookup(&pred_domain).await {
                            if let Some(ref cache) = cache_clone {
                                let addresses: Vec<IpAddr> = lookup.iter().map(|r| IpAddr::V4(r.0)).collect();
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
        
        result  // ✅ Instant return! User doesn't wait for prefetch
    }
}
