use super::Repositories;
use ferrous_dns_application::ports::CacheMaintenancePort;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, DnsCacheConfig, EvictionStrategy},
    cache_maintenance::DnsCacheMaintenance,
    events::QueryEventEmitter,
    query_logger::QueryEventLogger,
    HealthChecker, HickoryDnsResolver, PoolManager,
};
use std::sync::Arc;
use tracing::{info, warn};

pub struct DnsServices {
    pub resolver: Arc<HickoryDnsResolver>,
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
    pub pool_manager: Arc<PoolManager>,
    pub cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");

        let emitter = Self::setup_event_logger(repos);
        let health_checker = Self::setup_health_checker(config);
        let pool_manager =
            Self::setup_pool_manager(config, health_checker.clone(), emitter.clone()).await?;

        Self::start_health_checker_task(health_checker.clone(), &pool_manager, config);

        let timeout_ms = config.dns.query_timeout * 1000;
        let pool_manager_clone = Arc::clone(&pool_manager);

        let pool_manager_for_dnssec = Arc::new(
            PoolManager::new(
                config.dns.pools.clone(),
                health_checker,
                QueryEventEmitter::new_disabled(),
            )
            .await?,
        );

        let mut resolver = Self::build_resolver(
            pool_manager,
            pool_manager_for_dnssec,
            config,
            repos,
            timeout_ms,
        )?;
        let cache = Self::build_cache(config);

        if config.dns.cache_enabled {
            resolver = resolver.with_cache(cache.clone(), config.dns.cache_ttl);
        }

        let cache_maintenance = if config.dns.cache_enabled && config.dns.cache_optimistic_refresh {
            let resolver_for_maintenance = HickoryDnsResolver::new_with_pools(
                pool_manager_clone.clone(),
                timeout_ms,
                false,
                None,
            )?
            .with_cache(cache.clone(), config.dns.cache_ttl);

            Some(Arc::new(DnsCacheMaintenance::new(
                cache.clone(),
                Arc::new(resolver_for_maintenance),
                Some(repos.query_log.clone()),
            )) as Arc<dyn CacheMaintenancePort>)
        } else {
            None
        };

        let resolver = Arc::new(resolver);

        if !config.dns.local_records.is_empty() {
            info!(
                count = config.dns.local_records.len(),
                "Preloading local DNS records into permanent cache..."
            );
            Self::preload_local_records_into_cache(
                &cache,
                &config.dns.local_records,
                &config.dns.local_domain,
            );
            info!("✓ Local DNS records preloaded (cached permanently, <0.1ms resolution)");
        }

        let handler_use_case = Arc::new(
            HandleDnsQueryUseCase::new(
                resolver.clone(),
                repos.block_filter_engine.clone(),
                repos.query_log.clone(),
            )
            .with_client_tracking(
                repos.client.clone(),
                config.database.client_tracking_interval,
            ),
        );

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            resolver,
            cache,
            handler_use_case,
            pool_manager: pool_manager_clone,
            cache_maintenance,
        })
    }

    fn setup_event_logger(repos: &Repositories) -> QueryEventEmitter {
        info!("Query event logging enabled (parallel batch processing - 20,000+ queries/sec)");
        let (emitter, event_rx) = QueryEventEmitter::new_enabled();
        let logger = QueryEventLogger::new(repos.query_log.clone());
        tokio::spawn(async move {
            logger.start_parallel_batch(event_rx).await.unwrap();
        });
        info!("Query event logger started - logging client DNS queries");
        emitter
    }

    fn setup_health_checker(config: &Config) -> Option<Arc<HealthChecker>> {
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
    }

    async fn setup_pool_manager(
        config: &Config,
        health_checker: Option<Arc<HealthChecker>>,
        emitter: QueryEventEmitter,
    ) -> anyhow::Result<Arc<PoolManager>> {
        Ok(Arc::new(
            PoolManager::new(config.dns.pools.clone(), health_checker, emitter).await?,
        ))
    }

    fn start_health_checker_task(
        health_checker: Option<Arc<HealthChecker>>,
        pool_manager: &Arc<PoolManager>,
        config: &Config,
    ) {
        if let Some(checker) = health_checker {
            let all_protocols = pool_manager.get_all_protocols();
            let checker_clone = checker.clone();
            let interval = config.dns.health_check.interval;
            let timeout = config.dns.health_check.timeout;
            tokio::spawn(async move {
                checker_clone.run(all_protocols, interval, timeout).await;
            });
            info!("Health checker background task started");
        }
    }

    fn build_resolver(
        pool_manager: Arc<PoolManager>,
        pool_manager_for_dnssec: Arc<PoolManager>,
        config: &Config,
        repos: &Repositories,
        timeout_ms: u64,
    ) -> anyhow::Result<HickoryDnsResolver> {
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
        )
        .with_local_dns_server(config.dns.local_dns_server.clone());

        if config.dns.dnssec_enabled {
            resolver = resolver.with_dnssec_pool_manager(pool_manager_for_dnssec);
        }

        info!(
            dnssec_enabled = config.dns.dnssec_enabled,
            pools = config.dns.pools.len(),
            block_private_ptr = config.dns.block_private_ptr,
            block_non_fqdn = config.dns.block_non_fqdn,
            local_domain = ?config.dns.local_domain,
            local_dns_server = ?config.dns.local_dns_server,
            "DNS resolver created with all features"
        );

        Ok(resolver)
    }

    fn build_cache(config: &Config) -> Arc<DnsCache> {
        if config.dns.cache_enabled {
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
            Arc::new(DnsCache::new(DnsCacheConfig {
                max_entries: config.dns.cache_max_entries,
                eviction_strategy,
                min_threshold: config.dns.cache_min_hit_rate,
                refresh_threshold: config.dns.cache_refresh_threshold,
                batch_eviction_percentage: config.dns.cache_batch_eviction_percentage,
                adaptive_thresholds: config.dns.cache_adaptive_thresholds,
                min_frequency: config.dns.cache_min_frequency,
                min_lfuk_score: config.dns.cache_min_lfuk_score,
                shard_amount: config.dns.cache_shard_amount,
                access_window_secs: config.dns.cache_access_window_secs,
                eviction_sample_size: config.dns.cache_eviction_sample_size,
                lfuk_k_value: 0.5,
                refresh_sample_rate: 1.0,
                min_ttl: config.dns.cache_min_ttl,
                max_ttl: config.dns.cache_max_ttl,
            }))
        } else {
            Arc::new(DnsCache::new(DnsCacheConfig {
                max_entries: 0,
                eviction_strategy: EvictionStrategy::HitRate,
                min_threshold: 0.0,
                refresh_threshold: 0.0,
                batch_eviction_percentage: 0.0,
                adaptive_thresholds: false,
                min_frequency: 0,
                min_lfuk_score: 0.0,
                shard_amount: 4,
                access_window_secs: 0,
                eviction_sample_size: 8,
                lfuk_k_value: 0.5,
                refresh_sample_rate: 1.0,
                min_ttl: config.dns.cache_min_ttl,
                max_ttl: config.dns.cache_max_ttl,
            }))
        }
    }

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
            let fqdn = record.fqdn(default_domain);

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

            use ferrous_dns_infrastructure::dns::{CachedAddresses, CachedData};
            let data = CachedData::IpAddresses(CachedAddresses {
                addresses: StdArc::new(vec![ip]),
            });

            let ttl = record.ttl.unwrap_or(300);

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
