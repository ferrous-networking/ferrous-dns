use super::cache::DnsCache;
use crate::dns::HickoryDnsResolver;
use ferrous_dns_application::ports::{DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, QueryLog};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::{debug, error, info};

/// Background task manager for cache optimization
pub struct CacheUpdater {
    cache: Arc<DnsCache>,
    resolver: Arc<HickoryDnsResolver>,
    query_log: Option<Arc<dyn QueryLogRepository>>,
    update_interval: Duration,
    compaction_interval: Duration,
}

impl CacheUpdater {
    pub fn new(
        cache: Arc<DnsCache>,
        resolver: Arc<HickoryDnsResolver>,
        query_log: Option<Arc<dyn QueryLogRepository>>,
        update_interval_secs: u64,
        compaction_interval_secs: u64,
    ) -> Self {
        Self {
            cache,
            resolver,
            query_log,
            update_interval: Duration::from_secs(update_interval_secs),
            compaction_interval: Duration::from_secs(compaction_interval_secs),
        }
    }
    
    /// Start the background updater and compaction tasks
    pub fn start(self) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        let updater_handle = self.start_updater();
        let compaction_handle = self.start_compaction();
        
        (updater_handle, compaction_handle)
    }
    
    /// Start optimistic refresh task
    fn start_updater(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let resolver = Arc::clone(&self.resolver);
        let query_log = self.query_log.clone();
        let update_interval = self.update_interval;
        
        tokio::spawn(async move {
            info!(
                interval_secs = update_interval.as_secs(),
                "Cache updater started"
            );
            
            loop {
                sleep(update_interval).await;
                Self::update_cycle(&cache, &resolver, &query_log).await;
            }
        })
    }
    
    /// Start background compaction task
    fn start_compaction(&self) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(&self.cache);
        let compaction_interval = self.compaction_interval;
        
        tokio::spawn(async move {
            info!(
                interval_secs = compaction_interval.as_secs(),
                "Background compaction started"
            );
            
            loop {
                sleep(compaction_interval).await;
                Self::compaction_cycle(&cache);
            }
        })
    }
    
    /// Run one update cycle
    async fn update_cycle(
        cache: &Arc<DnsCache>, 
        resolver: &Arc<HickoryDnsResolver>,
        query_log: &Option<Arc<dyn QueryLogRepository>>
    ) {
        debug!("Starting cache update cycle");
        
        // Get refresh candidates - now synchronous! ✅
        let candidates = cache.get_refresh_candidates();
        
        if candidates.is_empty() {
            debug!("No refresh candidates found");
            return;
        }
        
        info!(
            candidates = candidates.len(),
            strategy = ?cache.strategy(),
            "Refreshing popular cache entries"
        );
        
        let mut refreshed = 0;
        let mut failed = 0;
        
        // Refresh each candidate
        for (domain, record_type) in candidates {
            match Self::refresh_entry(cache, resolver, query_log, &domain, &record_type).await {
                Ok(true) => {
                    refreshed += 1;
                    cache.metrics()
                        .optimistic_refreshes
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(false) => {
                    debug!(domain = %domain, "No new records to refresh");
                }
                Err(e) => {
                    error!(
                        domain = %domain,
                        record_type = %record_type,
                        error = %e,
                        "Failed to refresh cache entry"
                    );
                    failed += 1;
                }
            }
            
            // Small delay between refreshes to avoid overwhelming upstream
            sleep(Duration::from_millis(10)).await;
        }
        
        info!(
            refreshed = refreshed,
            failed = failed,
            cache_size = cache.size(),
            "Cache update cycle completed"
        );
    }
    
    /// Run one compaction cycle
    fn compaction_cycle(cache: &Arc<DnsCache>) {
        debug!("Starting background compaction cycle");
        
        let removed = cache.compact();
        
        if removed > 0 {
            info!(
                removed = removed,
                cache_size = cache.size(),
                "Background compaction completed"
            );
        } else {
            debug!("No entries to compact");
        }
    }
    
    /// Refresh a single cache entry
    async fn refresh_entry(
        cache: &Arc<DnsCache>,
        resolver: &Arc<HickoryDnsResolver>,
        query_log: &Option<Arc<dyn QueryLogRepository>>,
        domain: &str,
        record_type: &ferrous_dns_domain::RecordType,
    ) -> Result<bool, ferrous_dns_domain::DomainError> {
        let start = Instant::now();
        
        debug!(
            domain = %domain,
            record_type = %record_type,
            "Refreshing cache entry (will revalidate DNSSEC if enabled)"
        );
        
        let query = DnsQuery::new(domain.to_string(), record_type.clone());
        
        // resolver.resolve() will validate DNSSEC if dnssec_enabled = true
        match resolver.resolve(&query).await {
            Ok(resolution) if !resolution.addresses.is_empty() => {
                let response_time = start.elapsed().as_millis() as u64;
                
                // Get TTL from cache or use default
                let ttl = cache.get_ttl(domain, record_type).unwrap_or(3600);
                
                // Insert with DNSSEC status from fresh validation!
                let dnssec_status = resolution.dnssec_status.as_ref()
                    .and_then(|s| super::cache::DnssecStatus::from_string(s));
                
                cache.insert(
                    domain, 
                    record_type, 
                    super::cache::CachedData::IpAddresses(Arc::new(resolution.addresses.clone())),
                    ttl,
                    dnssec_status  // ✅ DnssecStatus, not String!
                );
                
                // Log the refresh query if query_log is available
                if let Some(log) = query_log {
                    // Use localhost as client IP to indicate it's a background refresh
                    let log_entry = QueryLog {
                        id: None,
                        domain: domain.to_string(),
                        record_type: record_type.clone(),
                        client_ip: IpAddr::from([127, 0, 0, 1]), // localhost = background refresh
                        blocked: false,
                        response_time_ms: Some(response_time),
                        cache_hit: false, // It's a refresh, not a hit
                        cache_refresh: true,  // Mark as cache refresh!
                        dnssec_status: resolution.dnssec_status.as_ref().map(|s| s.to_string()),
                        timestamp: None,
                    };
                    
                    if let Err(e) = log.log_query(&log_entry).await {
                        debug!(error = %e, "Failed to log refresh query (non-critical)");
                    }
                }
                
                debug!(
                    domain = %domain,
                    record_type = %record_type,
                    cache_hit = resolution.cache_hit,
                    dnssec_status = ?resolution.dnssec_status,
                    response_time_ms = response_time,
                    "Cache entry refreshed with new DNSSEC validation"
                );
                
                Ok(true)
            }
            Ok(_) => {
                // No addresses returned
                Ok(false)
            }
            Err(e) => {
                Err(e)
            }
        }
    }
}
