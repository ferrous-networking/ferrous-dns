use super::Repositories;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, EvictionStrategy},
    cache_updater::CacheUpdater,
    events::QueryEventEmitter,
    query_logger::QueryEventLogger,
    ConditionalForwarder, HealthChecker, HickoryDnsResolver, PoolManager,
};
use std::sync::Arc;
use tracing::{info, warn};

#[allow(dead_code)]
pub struct DnsServices {
    pub resolver: Arc<HickoryDnsResolver>,
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");

        // PHASE 5: Create query event emitter (always enabled for internal query logging)
        info!("Query event logging enabled (parallel batch processing - 20,000+ queries/sec)");
        let (emitter, event_rx) = QueryEventEmitter::new_enabled();

        // Health checker is always enabled
        let health_checker = {
            let checker = Arc::new(HealthChecker::new(
                config.dns.health_check.failure_threshold,
                config.dns.health_check.success_threshold,
            ));

            info!(
                interval_seconds = config.dns.health_check.interval,
                timeout_ms = config.dns.health_check.timeout,
                "Health checker enabled"
            );

            Some(checker)
        };

        // PHASE 5: Pass emitter to PoolManager
        let pool_manager = Arc::new(PoolManager::new(
            config.dns.pools.clone(),
            health_checker.clone(),
            emitter.clone(), // ← Pass emitter for internal query logging
        )?);

        // PHASE 5: Start query event logger background task
        let logger = QueryEventLogger::new(repos.query_log.clone());
        tokio::spawn(async move {
            logger.start_parallel_batch(event_rx).await.unwrap();
        });
        info!("Query event logger started - logging ALL DNS queries including DNSSEC validation");

        // Start health checker in background (don't keep JoinHandle)
        if let Some(checker) = health_checker {
            let all_protocols = pool_manager.get_all_protocols();

            // Spawn and detach - não guardar o JoinHandle
            let checker_clone = checker.clone();
            let interval = config.dns.health_check.interval;
            let timeout = config.dns.health_check.timeout;

            tokio::spawn(async move {
                checker_clone.run(all_protocols, interval, timeout).await;
            });

            info!("Health checker background task started");
        }

        let timeout_ms = config.dns.query_timeout * 1000;

        let pool_manager_clone = Arc::clone(&pool_manager);

        let mut resolver = HickoryDnsResolver::new_with_pools(
            pool_manager,
            timeout_ms,
            config.dns.dnssec_enabled,
            Some(repos.query_log.clone()),
        )?
        .with_query_filters(
            config.dns.block_private_ptr,
            config.dns.block_non_fqdn,
            config.dns.local_domain.clone(),
        );

        // Configure conditional forwarding (Fase 3)
        if !config.dns.conditional_forwarding.is_empty() {
            let forwarder = Arc::new(ConditionalForwarder::new(
                config.dns.conditional_forwarding.clone(),
            ));
            resolver = resolver.with_conditional_forwarder(forwarder);

            info!(
                rules_count = config.dns.conditional_forwarding.len(),
                "Conditional forwarding enabled"
            );
        }

        info!(
            dnssec_enabled = config.dns.dnssec_enabled,
            pools = config.dns.pools.len(),
            block_private_ptr = config.dns.block_private_ptr,
            block_non_fqdn = config.dns.block_non_fqdn,
            local_domain = ?config.dns.local_domain,
            conditional_forwarding_rules = config.dns.conditional_forwarding.len(),
            "DNS resolver created with all features"
        );

        let cache = if config.dns.cache_enabled {
            let eviction_strategy = match config.dns.cache_eviction_strategy.as_str() {
                "lfu" => EvictionStrategy::LFU,
                "lfu-k" => EvictionStrategy::LFUK,
                _ => EvictionStrategy::HitRate,
            };

            info!(
                strategy = config.dns.cache_eviction_strategy.as_str(),
                max_entries = config.dns.cache_max_entries,
                "Cache enabled"
            );

            let cache = Arc::new(DnsCache::new(
                config.dns.cache_max_entries,
                eviction_strategy,
                config.dns.cache_min_hit_rate,
                config.dns.cache_refresh_threshold,
                config.dns.cache_lfuk_history_size,
                config.dns.cache_batch_eviction_percentage,
                config.dns.cache_adaptive_thresholds,
            ));

            resolver = resolver.with_cache(cache.clone(), config.dns.cache_ttl);
            cache
        } else {
            Arc::new(DnsCache::new(
                0,
                EvictionStrategy::HitRate,
                0.0,
                0.0,
                0,
                0.0,
                false,
            ))
        };

        if config.dns.cache_enabled && config.dns.cache_optimistic_refresh {
            info!("Starting cache background tasks");

            let resolver_for_updater =
                HickoryDnsResolver::new_with_pools(pool_manager_clone, timeout_ms, false, None)?
                    .with_cache(cache.clone(), config.dns.cache_ttl);

            let updater = CacheUpdater::new(
                cache.clone(),
                Arc::new(resolver_for_updater),
                Some(repos.query_log.clone()),
                60,
                config.dns.cache_compaction_interval,
            );

            updater.start();
            info!("Cache background tasks started");
        }

        let resolver = Arc::new(resolver);

        if !config.dns.local_records.is_empty() {
            info!(
                count = config.dns.local_records.len(),
                "Preloading local DNS records into permanent cache..."
            );

            // Preload local records directly into cache
            Self::preload_local_records_into_cache(
                &cache,
                &config.dns.local_records,
                &config.dns.local_domain,
            );

            info!("✓ Local DNS records preloaded (cached permanently, <0.1ms resolution)");
        }

        let handler_use_case = Arc::new(HandleDnsQueryUseCase::new(
            resolver.clone(),
            repos.blocklist.clone(),
            repos.query_log.clone(),
        ));

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            resolver,
            cache,
            handler_use_case,
        })
    }

    /// Preload local DNS records into permanent cache
    ///
    /// Loads static hostname → IP mappings from configuration into the cache
    /// as permanent records that never expire and are immune to eviction.
    fn preload_local_records_into_cache(
        cache: &Arc<DnsCache>,
        records: &[ferrous_dns_domain::LocalDnsRecord],
        default_domain: &Option<String>,
    ) {
        use ferrous_dns_domain::RecordType;
        use std::sync::Arc as StdArc;

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

            let ip_type_valid = matches!(
                (&record_type, &ip),
                (RecordType::A, std::net::IpAddr::V4(_))
                    | (RecordType::AAAA, std::net::IpAddr::V6(_))
            );

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
            use ferrous_dns_infrastructure::dns::CachedData;
            let data = CachedData::IpAddresses(StdArc::new(vec![ip]));

            // Get TTL (default 300)
            let ttl = record.ttl.unwrap_or(300);

            // Insert as permanent cache entry
            cache.insert_permanent(&fqdn, record_type, data, None);

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
                "× Failed to preload {} local DNS record(s)", error_count
            );
        }
    }
}
