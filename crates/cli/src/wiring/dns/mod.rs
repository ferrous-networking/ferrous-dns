mod cache;
mod pool;
mod resolver;

use crate::server::dns::connection_limiter::ConnectionLimiter;
use ferrous_dns_application::ports::{
    CacheMaintenancePort, PtrRecordRegistry, TunnelingEvictionTarget, TunnelingFlagStore,
};
use ferrous_dns_application::use_cases::dns::rate_limiter::DnsRateLimiter;
use ferrous_dns_application::use_cases::dns::tsc_timer;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::DnsCache, cache_maintenance::DnsCacheMaintenance, events::QueryEventEmitter,
    resolver::LocalPtrResolver, HealthChecker, HickoryDnsResolver, PoolManager, TunnelingDetector,
};
use ferrous_dns_jobs::TunnelingEvictionJob;
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
    pub tcp_conn_limiter: ConnectionLimiter,
    pub dot_conn_limiter: ConnectionLimiter,
    pub tunneling_eviction_job: Option<TunnelingEvictionJob>,
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

        let rate_limiter = Arc::new(DnsRateLimiter::new(&config.dns.rate_limit));
        if config.dns.rate_limit.enabled {
            rate_limiter.start_eviction_task();
            info!(
                "DNS rate limiter enabled ({}qps, burst {})",
                config.dns.rate_limit.queries_per_second, config.dns.rate_limit.burst_size
            );
        }

        // DNS Tunneling Detection
        let (tunneling_detector, tunneling_eviction_job) = if config.dns.tunneling_detection.enabled
        {
            let (detector, tx, rx) = TunnelingDetector::new(&config.dns.tunneling_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            let eviction_job = TunnelingEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn TunnelingEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            );
            info!(
                action = ?config.dns.tunneling_detection.action,
                "DNS tunneling detection enabled"
            );
            if config.dns.tunneling_detection.action
                == ferrous_dns_domain::TunnelingAction::Throttle
            {
                tracing::warn!(
                    "Tunneling action 'throttle' is not yet implemented — treating as 'alert'"
                );
            }
            (Some((detector, tx)), Some(eviction_job))
        } else {
            (None, None)
        };

        let mut handler = HandleDnsQueryUseCase::new(
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
        )
        .with_rate_limiter(rate_limiter);

        if let Some((ref detector, ref tx)) = tunneling_detector {
            handler = handler
                .with_tunneling_detection(&config.dns.tunneling_detection)
                .with_tunneling_event_sender(tx.clone())
                .with_tunneling_flag_store(Arc::clone(detector) as Arc<dyn TunnelingFlagStore>);
        }

        let handler_use_case = Arc::new(handler);

        let tcp_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.tcp_max_connections_per_ip);
        let dot_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.dot_max_connections_per_ip);

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            cache: dns_cache,
            handler_use_case,
            pool_manager: pool_manager_clone,
            health_checker: stored_health_checker,
            cache_maintenance,
            ptr_registry,
            tcp_conn_limiter,
            dot_conn_limiter,
            tunneling_eviction_job,
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
