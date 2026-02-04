use super::Repositories;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, EvictionStrategy},
    cache_updater::CacheUpdater,
    HickoryDnsResolver,
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
        info!("Initializing DNS services");

        // Create DNS resolver
        let mut resolver = HickoryDnsResolver::with_google_dnssec(
            config.dns.dnssec_enabled,
            Some(repos.query_log.clone()),
        )?;

        info!(
            dnssec_enabled = config.dns.dnssec_enabled,
            "DNS resolver created"
        );

        // Initialize cache if enabled
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

        // Start background tasks if needed
        if config.dns.cache_enabled && config.dns.cache_optimistic_refresh {
            info!("Starting cache background tasks");

            let resolver_for_updater = HickoryDnsResolver::with_google_dnssec(false, None)?
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

        // Create handler use case
        let handler_use_case = Arc::new(HandleDnsQueryUseCase::new(
            resolver.clone(),
            repos.blocklist.clone(),
            repos.query_log.clone(),
        ));

        Ok(Self {
            resolver,
            cache,
            handler_use_case,
        })
    }
}
