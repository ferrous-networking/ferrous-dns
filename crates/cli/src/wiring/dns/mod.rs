mod cache;
mod pool;
mod resolver;

use crate::server::dns::connection_limiter::ConnectionLimiter;
use ferrous_dns_application::ports::{
    CacheMaintenancePort, DgaEvictionTarget, DgaFlagStore, DnssecStatsPort, NxdomainHijackIpStore,
    NxdomainHijackProbeTarget, PtrRecordRegistry, ResponseIpFilterEvictionTarget,
    ResponseIpFilterStore, TunnelingEvictionTarget, TunnelingFlagStore,
};
use ferrous_dns_application::use_cases::dns::rate_limiter::DnsRateLimiter;
use ferrous_dns_application::use_cases::dns::tsc_timer;
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::DnsCache, cache_maintenance::DnsCacheMaintenance, dnssec::DnssecStatsAdapter,
    events::QueryEventEmitter, resolver::LocalPtrResolver, DgaDetector, HealthChecker,
    HickoryDnsResolver, NxdomainHijackDetector, PoolManager, RefreshScanOptions, RefreshSenders,
    ResponseIpFilterDetector, TunnelingDetector,
};
use ferrous_dns_jobs::{
    DgaEvictionJob, NxdomainHijackEvictionJob, ResponseIpFilterEvictionJob, TunnelingEvictionJob,
    DEFAULT_REFRESH_INTERVAL_SECS,
};
use std::sync::Arc;
use tracing::info;

use super::Repositories;

pub struct DnsServices {
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
    pub pool_manager: Arc<PoolManager>,
    pub dnssec_pool_manager: Arc<PoolManager>,
    /// Live counters from the DNSSEC validator cache. Reports zeros when DNSSEC
    /// validation is disabled.
    pub dnssec_stats: Arc<dyn DnssecStatsPort>,
    /// Pool manager backing the cache optimistic-refresh resolver, when that
    /// path is enabled. Kept so hot upstream reloads also reach it.
    pub maintenance_pool_manager: Option<Arc<PoolManager>>,
    pub health_checker: Option<Arc<HealthChecker>>,
    pub cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
    pub ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    pub tcp_conn_limiter: ConnectionLimiter,
    pub dot_conn_limiter: ConnectionLimiter,
    pub doq_conn_limiter: ConnectionLimiter,
    pub tunneling_eviction_job: Option<TunnelingEvictionJob>,
    pub nxdomain_hijack_eviction_job: Option<NxdomainHijackEvictionJob>,
    pub response_ip_filter_eviction_job: Option<ResponseIpFilterEvictionJob>,
    pub dga_eviction_job: Option<DgaEvictionJob>,
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

        // The DNSSEC validator walks the chain of trust on its own pool manager
        // (so its DS/DNSKEY probes don't pollute query stats). It needs its own
        // health checker + probe task, otherwise its upstreams are never marked
        // healthy and every chain lookup fails "unreachable" — which would make
        // Strict mode SERVFAIL even correctly-signed domains.
        let dnssec_health_checker = pool::setup_health_checker(config);
        let pool_manager_for_dnssec = Arc::new(
            PoolManager::new(
                config.dns.pools.clone(),
                dnssec_health_checker.clone(),
                QueryEventEmitter::new_disabled(),
            )
            .await?
            .with_hardening(pool::hardening_opts(config)),
        );
        pool::start_health_checker_task(dnssec_health_checker, &pool_manager_for_dnssec, config);
        let dnssec_pool_manager_clone = Arc::clone(&pool_manager_for_dnssec);

        let (mut dns_resolver, dnssec_cache) = resolver::build_resolver(
            pool_manager,
            pool_manager_for_dnssec,
            config,
            repos,
            timeout_ms,
        )?;
        let dnssec_stats: Arc<dyn DnssecStatsPort> = Arc::new(match dnssec_cache {
            Some(cache) => DnssecStatsAdapter::new(cache),
            None => DnssecStatsAdapter::disabled(),
        });
        let dns_cache = cache::build_cache(config);

        if config.dns.cache_enabled {
            dns_resolver = dns_resolver
                .with_inflight_shards(config.dns.cache_inflight_shards)
                .with_cache(dns_cache.clone(), config.dns.cache_ttl);
        }

        let (cache_maintenance, maintenance_pool_manager) = Self::setup_cache_maintenance(
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

        // NXDomain Hijack Detection
        let (nxdomain_hijack_detector, nxdomain_hijack_eviction_job) =
            if config.dns.nxdomain_hijack.enabled {
                let detector = Arc::new(NxdomainHijackDetector::new(&config.dns.nxdomain_hijack));
                let protocols = pool_manager_clone.get_all_arc_protocols();
                let detector_clone = Arc::clone(&detector);
                tokio::spawn(async move {
                    detector_clone.run_probe_loop(protocols).await;
                });
                // Evict at twice the probe frequency so stale IPs are cleaned
                // before the TTL fully expires.
                let eviction_interval = config.dns.nxdomain_hijack.hijack_ip_ttl_secs / 2;
                let eviction_job = NxdomainHijackEvictionJob::new(
                    Arc::clone(&detector) as Arc<dyn NxdomainHijackProbeTarget>,
                    eviction_interval,
                );
                info!(
                    action = ?config.dns.nxdomain_hijack.action,
                    "NXDomain hijack detection enabled"
                );
                (Some(detector), Some(eviction_job))
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
        .with_rate_limiter(rate_limiter)
        .with_dnssec_enforcement(config.dns.effective_dnssec_mode().enforces())
        .with_query_logging(config.database.log_queries);

        // DNS64 query-log tagging: only when enabled with a valid /96 prefix.
        if config.dns64.enabled {
            if let Some(prefix) = config.dns64.parsed_prefix() {
                handler = handler.with_dns64(prefix);
            }
        }

        if let Some((ref detector, ref tx)) = tunneling_detector {
            handler = handler
                .with_tunneling_detection(&config.dns.tunneling_detection)
                .with_tunneling_event_sender(tx.clone())
                .with_tunneling_flag_store(Arc::clone(detector) as Arc<dyn TunnelingFlagStore>);
        }

        if let Some(ref detector) = nxdomain_hijack_detector {
            handler = handler.with_nxdomain_hijack_detection(
                &config.dns.nxdomain_hijack,
                Arc::clone(detector) as Arc<dyn NxdomainHijackIpStore>,
            );
        }

        // Response IP Filtering (C2 IP blocking)
        let (response_ip_filter_detector, response_ip_filter_eviction_job) = if config
            .dns
            .response_ip_filter
            .enabled
            && !config.dns.response_ip_filter.ip_list_urls.is_empty()
        {
            let detector = Arc::new(ResponseIpFilterDetector::new(
                &config.dns.response_ip_filter,
            ));
            let http_client = reqwest::Client::builder()
                .user_agent(format!(
                    "ferrous-dns/{} (response-ip-filter)",
                    env!("CARGO_PKG_VERSION")
                ))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build HTTP client: {e}"))?;
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move {
                detector_clone.run_fetch_loop(http_client).await;
            });
            let eviction_job = ResponseIpFilterEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn ResponseIpFilterEvictionTarget>,
                config.dns.response_ip_filter.ip_ttl_secs / 2,
            );
            if config.dns.response_ip_filter.ip_ttl_secs
                < config.dns.response_ip_filter.refresh_interval_secs
            {
                tracing::warn!(
                        ip_ttl_secs = config.dns.response_ip_filter.ip_ttl_secs,
                        refresh_interval_secs = config.dns.response_ip_filter.refresh_interval_secs,
                        "ip_ttl_secs < refresh_interval_secs — IPs will be evicted before the next feed refresh"
                    );
            }
            info!(
                action = ?config.dns.response_ip_filter.action,
                "Response IP filtering enabled"
            );
            (Some(detector), Some(eviction_job))
        } else {
            (None, None)
        };

        if let Some(ref detector) = response_ip_filter_detector {
            handler = handler.with_response_ip_filter(
                &config.dns.response_ip_filter,
                Arc::clone(detector) as Arc<dyn ResponseIpFilterStore>,
            );
        }

        // DGA Detection
        let (dga_detector, dga_eviction_job) = if config.dns.dga_detection.enabled {
            let (detector, tx, rx) = DgaDetector::new(&config.dns.dga_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            let eviction_job = DgaEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn DgaEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            );
            info!(
                action = ?config.dns.dga_detection.action,
                "DGA detection enabled"
            );
            (Some((detector, tx)), Some(eviction_job))
        } else {
            (None, None)
        };

        if let Some((ref detector, ref tx)) = dga_detector {
            handler = handler
                .with_dga_detection(&config.dns.dga_detection)
                .with_dga_event_sender(tx.clone())
                .with_dga_flag_store(Arc::clone(detector) as Arc<dyn DgaFlagStore>);
        }

        // DNS Cookies (RFC 7873)
        if config.dns.dns_cookies.enabled {
            let secret = resolve_cookie_secret(&config.dns.dns_cookies);
            let cookie_guard = DnsCookieGuard::from_config(&config.dns.dns_cookies, secret);
            handler = handler.with_dns_cookies(cookie_guard);
            info!(
                require_valid = config.dns.dns_cookies.require_valid_cookie,
                "DNS Cookies (RFC 7873) enabled"
            );
        }

        let handler_use_case = Arc::new(handler);

        let tcp_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.tcp_max_connections_per_ip);
        let dot_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.dot_max_connections_per_ip);
        let doq_conn_limiter =
            ConnectionLimiter::new(config.dns.rate_limit.doq_max_connections_per_ip);

        info!("DNS services initialized successfully with load balancing");

        Ok(Self {
            cache: dns_cache,
            handler_use_case,
            pool_manager: pool_manager_clone,
            dnssec_pool_manager: dnssec_pool_manager_clone,
            dnssec_stats,
            maintenance_pool_manager,
            health_checker: stored_health_checker,
            cache_maintenance,
            ptr_registry,
            tcp_conn_limiter,
            dot_conn_limiter,
            doq_conn_limiter,
            tunneling_eviction_job,
            nxdomain_hijack_eviction_job,
            response_ip_filter_eviction_job,
            dga_eviction_job,
        })
    }

    async fn setup_cache_maintenance(
        config: &Config,
        cache: &Arc<DnsCache>,
        health_checker: Option<Arc<HealthChecker>>,
        timeout_ms: u64,
        repos: &Repositories,
    ) -> anyhow::Result<(
        Option<Arc<dyn CacheMaintenancePort>>,
        Option<Arc<PoolManager>>,
    )> {
        if !config.dns.cache_enabled || !config.dns.cache_optimistic_refresh {
            return Ok((None, None));
        }

        // The optimistic queue holds one cycle's backlog. A cycle produces
        // roughly `entries * interval / ttl` candidates, so it is sized off the
        // cache rather than fixed: a constant that fits a small deployment
        // silently caps how much of a large one can stay warm. The clamp keeps
        // both ends sane — the upper bound is ~0.8 MB of queued keys.
        let optimistic_capacity = (config.dns.cache_max_entries / 4).clamp(1024, 32_768);
        // The stale queue is shallower on purpose: those items are
        // latency-sensitive and drained unpaced, so it only has to absorb a
        // burst, not a backlog — the client interaction is over long before a
        // deep one would drain.
        let (stale_tx, stale_rx) = tokio::sync::mpsc::channel(128);
        let (optimistic_tx, optimistic_rx) = tokio::sync::mpsc::channel(optimistic_capacity);
        let (pace_tx, pace_rx) = tokio::sync::watch::channel(None);
        cache.set_refresh_senders(RefreshSenders {
            stale: stale_tx,
            optimistic: optimistic_tx,
        });

        // A candidate waits up to one cycle to be scanned and up to one more to
        // be drained, so anything with less life than that left would expire
        // before its turn. Taking it early is what makes "renewed before the
        // TTL lapses" hold rather than merely tend to hold.
        let scan_opts = RefreshScanOptions {
            min_lead_secs: DEFAULT_REFRESH_INTERVAL_SECS * 2,
            min_hit_rate: config.dns.cache_min_hit_rate,
            min_frequency: config.dns.cache_min_frequency,
        };

        let pool_manager_for_maintenance = Arc::new(
            PoolManager::new(
                config.dns.pools.clone(),
                health_checker,
                QueryEventEmitter::new_disabled(),
            )
            .await?
            .with_hardening(pool::hardening_opts(config)),
        );
        // Keep a handle so hot upstream reloads also reach this resolver.
        let maintenance_pool_manager = Arc::clone(&pool_manager_for_maintenance);

        let resolver_for_maintenance: Arc<dyn ferrous_dns_application::ports::DnsResolver> =
            Arc::new(HickoryDnsResolver::new_with_pools(
                pool_manager_for_maintenance,
                timeout_ms,
                false,
                None,
            )?);

        DnsCacheMaintenance::start_refresh_worker(
            cache.clone(),
            resolver_for_maintenance,
            Some(repos.query_log.clone()),
            stale_rx,
            optimistic_rx,
            pace_rx,
            scan_opts.min_lead_secs,
        );

        Ok((
            Some(Arc::new(DnsCacheMaintenance::new(
                cache.clone(),
                DEFAULT_REFRESH_INTERVAL_SECS,
                scan_opts,
                pace_tx,
            )) as Arc<dyn CacheMaintenancePort>),
            Some(maintenance_pool_manager),
        ))
    }
}

fn resolve_cookie_secret(config: &ferrous_dns_domain::DnsCookiesConfig) -> [u8; 32] {
    if config.server_secret.is_empty() {
        use ring::rand::SecureRandom;
        let rng = ring::rand::SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes)
            .expect("system RNG failure while generating DNS cookie secret");
        tracing::warn!(
            "dns_cookies.server_secret is not set — using ephemeral secret \
             (will not survive restart; set a 64-hex-char value in config)"
        );
        bytes
    } else {
        let hex = config.server_secret.trim();
        assert!(
            hex.len() == 64,
            "dns_cookies.server_secret must be exactly 64 hex characters (32 bytes), got {}",
            hex.len()
        );
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            bytes[i] = u8::from_str_radix(
                std::str::from_utf8(chunk).expect("server_secret contains non-UTF8"),
                16,
            )
            .expect("dns_cookies.server_secret contains invalid hex characters");
        }
        bytes
    }
}
