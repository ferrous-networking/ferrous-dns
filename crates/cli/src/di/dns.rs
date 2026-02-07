use super::Repositories;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, EvictionStrategy},
    cache_updater::CacheUpdater,
    HealthChecker, HickoryDnsResolver, PoolManager,
};
use std::sync::Arc;
use tracing::info;

#[allow(dead_code)]
pub struct DnsServices {
    pub resolver: Arc<HickoryDnsResolver>,
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");

        let health_checker = if config.dns.health_check.enabled {
            let checker = Arc::new(HealthChecker::new(
                config.dns.health_check.failure_threshold,
                config.dns.health_check.success_threshold,
            ));

            info!(
                interval_seconds = config.dns.health_check.interval_seconds,
                timeout_ms = config.dns.health_check.timeout_ms,
                "Health checker enabled"
            );

            Some(checker)
        } else {
            info!("Health checker disabled");
            None
        };

        let pool_manager = Arc::new(PoolManager::new(
            config.dns.pools.clone(),
            health_checker.clone(),
        )?);

        // Start health checker in background (don't keep JoinHandle)
        if let Some(checker) = health_checker {
            let all_servers = pool_manager.get_all_servers();

            // Spawn and detach - não guardar o JoinHandle
            let checker_clone = checker.clone();
            let interval = config.dns.health_check.interval_seconds;
            let timeout = config.dns.health_check.timeout_ms;

            tokio::spawn(async move {
                checker_clone.run(all_servers, interval, timeout).await;
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
        )?;

        info!(
            dnssec_enabled = config.dns.dnssec_enabled,
            pools = config.dns.pools.len(),
            "DNS resolver created"
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

            resolver = resolver.with_cache_ref(cache.clone(), config.dns.cache_ttl);
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
                    .with_cache_ref(cache.clone(), config.dns.cache_ttl);

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
}
