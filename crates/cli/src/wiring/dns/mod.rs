mod cache;
mod pool;
mod resolver;

use ferrous_dns_application::ports::{CacheMaintenancePort, PtrRecordRegistry};
use ferrous_dns_application::use_cases::dns::tsc_timer;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::DnsCache, cache_maintenance::DnsCacheMaintenance, events::QueryEventEmitter,
    resolver::LocalPtrResolver, HealthChecker, HickoryDnsResolver, PoolManager,
};
use std::sync::Arc;
use tracing::info;

use super::Repositories;

pub struct DnsServices {
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
    pub pool_manager: Arc<PoolManager>,
    pub health_checker: Option<Arc<HealthChecker>>,
    pub cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
    pub ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");
        tsc_timer::init();

        let emitter = pool::setup_event_logger(repos);
        let health_checker = pool::setup_health_checker(config);
        let pool_manager =
            pool::setup_pool_manager(config, health_checker.clone(), emitter.clone()).await?;

        pool::start_health_checker_task(health_checker.clone(), &pool_manager, config);
        let stored_health_checker = health_checker.clone();

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

        let mut dns_resolver = resolver::build_resolver(
            pool_manager,
            pool_manager_for_dnssec,
            config,
            repos,
            timeout_ms,
        )?;
        let dns_cache = cache::build_cache(config);

        if config.dns.cache_enabled {
            dns_resolver = dns_resolver.with_cache(dns_cache.clone(), config.dns.cache_ttl);
        }

        let cache_maintenance = Self::setup_cache_maintenance(
            config,
            &dns_cache,
            stored_health_checker.clone(),
            timeout_ms,
            repos,
        )
        .await?;

        let ptr_registry: Option<Arc<dyn PtrRecordRegistry>> =
            if !config.dns.local_records.is_empty() {
                info!(
                    count = config.dns.local_records.len(),
                    "Preloading local DNS records into permanent cache..."
                );
                cache::preload_local_records_into_cache(
                    &dns_cache,
                    &config.dns.local_records,
                    &config.dns.local_domain,
                );
                info!("✓ Local DNS records preloaded (cached permanently, <0.1ms resolution)");

                let dummy_inner: Arc<dyn ferrous_dns_application::ports::DnsResolver> =
                    Arc::new(HickoryDnsResolver::new_with_pools(
                        pool_manager_clone.clone(),
                        timeout_ms,
                        false,
                        None,
                    )?);
                let local_ptr = Arc::new(LocalPtrResolver::from_local_records(
                    &config.dns.local_records,
                    &config.dns.local_domain,
                    dummy_inner,
                ));
                dns_resolver = dns_resolver.with_local_ptr_map(Arc::clone(&local_ptr.map));
                Some(local_ptr as Arc<dyn PtrRecordRegistry>)
            } else {
                None
            };

        let resolver = Arc::new(dns_resolver);

        let handler_use_case = Arc::new(
            HandleDnsQueryUseCase::new(
                resolver.clone(),
                repos.block_filter_engine.clone(),
                repos.query_log.clone(),
            )
            .with_safe_search(repos.safe_search_engine.clone())
            .with_client_tracking(
                repos.client.clone(),
                config.database.client_tracking_interval,
            )
            .with_rebinding_protection(
                config.dns.rebinding_protection_enabled,
                config.dns.local_domain.as_deref(),
                &config.dns.rebinding_allowlist,
            ),
        );

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            cache: dns_cache,
            handler_use_case,
            pool_manager: pool_manager_clone,
            health_checker: stored_health_checker,
            cache_maintenance,
            ptr_registry,
        })
    }

    async fn setup_cache_maintenance(
        config: &Config,
        cache: &Arc<DnsCache>,
        health_checker: Option<Arc<HealthChecker>>,
        timeout_ms: u64,
        repos: &Repositories,
    ) -> anyhow::Result<Option<Arc<dyn CacheMaintenancePort>>> {
        if !config.dns.cache_enabled || !config.dns.cache_optimistic_refresh {
            return Ok(None);
        }

        let (stale_tx, stale_rx) = tokio::sync::mpsc::channel(256);
        cache.set_stale_refresh_sender(stale_tx);

        let pool_manager_for_maintenance = Arc::new(
            PoolManager::new(
                config.dns.pools.clone(),
                health_checker,
                QueryEventEmitter::new_disabled(),
            )
            .await?,
        );

        let resolver_for_maintenance: Arc<dyn ferrous_dns_application::ports::DnsResolver> =
            Arc::new(HickoryDnsResolver::new_with_pools(
                pool_manager_for_maintenance,
                timeout_ms,
                false,
                None,
            )?);

        DnsCacheMaintenance::start_stale_listener(
            cache.clone(),
            Arc::clone(&resolver_for_maintenance),
            Some(repos.query_log.clone()),
            stale_rx,
        );

        Ok(Some(Arc::new(DnsCacheMaintenance::new(
            cache.clone(),
            resolver_for_maintenance,
            Some(repos.query_log.clone()),
        )) as Arc<dyn CacheMaintenancePort>))
    }
}
