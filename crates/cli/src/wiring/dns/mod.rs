mod cache;
mod pool;
mod resolver;

use crate::server::dns::connection_limiter::ConnectionLimiter;
use ferrous_dns_application::ports::{
    CacheMaintenancePort, DgaEvictionTarget, DgaFlagStore, DnssecStatsPort, NxdomainHijackIpStore,
    NxdomainHijackProbeTarget, PtrRecordRegistry, ResponseIpFilterEvictionTarget,
    ResponseIpFilterStore, TunnelingEvictionTarget, TunnelingFlagStore, WildcardRecordRegistry,
};
use ferrous_dns_application::use_cases::dns::rate_limiter::DnsRateLimiter;
use ferrous_dns_application::use_cases::dns::tsc_timer;
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::DnsCache,
    cache_maintenance::DnsCacheMaintenance,
    dnssec::DnssecStatsAdapter,
    resolver::{LocalPtrResolver, LocalWildcardResolver, PtrRegistry, WildcardRegistry},
    DgaDetector, HealthChecker, NxdomainHijackDetector, PoolManager, RefreshScanOptions,
    RefreshSenders, ResponseIpFilterDetector, TunnelingDetector,
};
use ferrous_dns_jobs::{
    DgaEvictionJob, NxdomainHijackEvictionJob, ResponseIpFilterEvictionJob, TunnelingEvictionJob,
    DEFAULT_REFRESH_INTERVAL_SECS,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

use super::Repositories;

pub struct DnsServices {
    pub cache: Arc<DnsCache>,
    pub handler_use_case: Arc<HandleDnsQueryUseCase>,
    pub pool_manager: Arc<PoolManager>,
    /// Pool manager the DNSSEC validator walks the chain of trust on; absent
    /// when validation is off.
    pub dnssec_pool_manager: Option<Arc<PoolManager>>,
    /// Live counters from the DNSSEC validator cache. Reports zeros when DNSSEC
    /// validation is disabled.
    pub dnssec_stats: Arc<dyn DnssecStatsPort>,
    /// Pool manager backing the cache background-refresh resolver, present
    /// whenever the cache is enabled. Kept so hot upstream reloads also reach it.
    pub maintenance_pool_manager: Option<Arc<PoolManager>>,
    pub health_checker: Arc<HealthChecker>,
    /// Present whenever the cache is enabled; the optimistic scan runs only
    /// with `cache_optimistic_refresh`, serve-stale repairs always.
    pub cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
    /// Live PTR map for local records. Always present, so a record added from
    /// the admin UI reverse-resolves without a restart.
    pub ptr_registry: Arc<dyn PtrRecordRegistry>,
    /// Live wildcard index. Always present, even with no wildcard configured,
    /// so the first one added from the admin UI answers without a restart.
    pub wildcard_registry: Arc<dyn WildcardRecordRegistry>,
    /// `dns.local_dns_server`, parsed once for every consumer.
    pub local_dns_server: Option<SocketAddr>,
    pub tcp_conn_limiter: ConnectionLimiter,
    pub dot_conn_limiter: ConnectionLimiter,
    pub doq_conn_limiter: ConnectionLimiter,
}

impl DnsServices {
    pub async fn new(config: &Config, repos: &Repositories) -> anyhow::Result<Self> {
        info!("Initializing DNS services with load balancing");
        tsc_timer::init();

        let health_checker = pool::setup_health_checker(config);
        let pool_manager = pool::setup_pool_manager(config, &health_checker).await?;
        pool::start_health_checker_task(Arc::clone(&health_checker), &pool_manager, config);

        let timeout_ms = config.dns.query_timeout * 1000;

        // The DNSSEC validator walks the chain of trust on its own pool manager.
        // It needs its own health checker + probe task, otherwise its upstreams
        // are never marked healthy and every chain lookup fails "unreachable" —
        // which would make Strict mode SERVFAIL even correctly-signed domains.
        let dnssec_pool_manager = if config.dns.effective_dnssec_mode().validates() {
            let dnssec_health_checker = pool::setup_health_checker(config);
            let manager = pool::setup_pool_manager(config, &dnssec_health_checker).await?;
            pool::start_health_checker_task(dnssec_health_checker, &manager, config);
            Some(manager)
        } else {
            None
        };

        let local_dns_server = config.dns.local_dns_server_addr()?;

        let upstream_layers = resolver::UpstreamLayers::from_config(
            config,
            dnssec_pool_manager.clone(),
            local_dns_server,
            timeout_ms,
        )?;
        let dnssec_stats: Arc<dyn DnssecStatsPort> =
            Arc::new(match upstream_layers.dnssec_cache() {
                Some(cache) => DnssecStatsAdapter::new(cache),
                None => DnssecStatsAdapter::disabled(),
            });
        let dns_cache = cache::build_cache(config);

        let mut resolver_builder = upstream_layers
            .builder(Arc::clone(&pool_manager))
            .with_filters(resolver::query_filters(config, local_dns_server));
        if config.dns.cache_enabled {
            resolver_builder = resolver_builder.with_cache(
                dns_cache.clone(),
                config.dns.cache_ttl,
                config.dns.cache_inflight_shards,
            );
        }

        let (cache_maintenance, maintenance_pool_manager) = Self::setup_cache_maintenance(
            config,
            &dns_cache,
            &health_checker,
            &upstream_layers,
            repos,
        )
        .await?;

        // Exact local records live in the permanent cache; PTRs and wildcards
        // in live maps, always attached (even empty) so that records added from
        // the admin UI take effect on the next query.
        let local_domain = config.dns.local_domain.as_deref();
        cache::preload_local_records_into_cache(
            &dns_cache,
            &config.dns.local_records,
            local_domain,
        );
        let ptr_map =
            LocalPtrResolver::map_from_local_records(&config.dns.local_records, local_domain);
        let wildcard_map =
            LocalWildcardResolver::map_from_local_records(&config.dns.local_records, local_domain);
        let resolver = resolver_builder
            .with_local_ptr_map(Arc::clone(&ptr_map))
            .with_local_wildcards(Arc::clone(&wildcard_map))
            .build();
        let ptr_registry: Arc<dyn PtrRecordRegistry> = Arc::new(PtrRegistry::new(ptr_map));
        let wildcard_registry: Arc<dyn WildcardRecordRegistry> =
            Arc::new(WildcardRegistry::new(wildcard_map));

        let rate_limiter = Arc::new(DnsRateLimiter::new(&config.dns.rate_limit));
        if config.dns.rate_limit.enabled {
            rate_limiter.start_eviction_task();
            info!(
                "DNS rate limiter enabled ({}qps, burst {})",
                config.dns.rate_limit.queries_per_second, config.dns.rate_limit.burst_size
            );
        }

        let tunneling_detector = if config.dns.tunneling_detection.enabled {
            let (detector, tx, rx) = TunnelingDetector::new(&config.dns.tunneling_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            TunnelingEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn TunnelingEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            )
            .spawn();
            info!(
                action = ?config.dns.tunneling_detection.action,
                "DNS tunneling detection enabled"
            );
            if config.dns.tunneling_detection.action
                == ferrous_dns_domain::TunnelingAction::Throttle
            {
                warn!("Tunneling action 'throttle' is not yet implemented — treating as 'alert'");
            }
            Some((detector, tx))
        } else {
            None
        };

        let nxdomain_hijack_detector = if config.dns.nxdomain_hijack.enabled {
            let detector = Arc::new(NxdomainHijackDetector::new(&config.dns.nxdomain_hijack));
            let protocols = pool_manager.get_all_arc_protocols();
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move {
                detector_clone.run_probe_loop(protocols).await;
            });
            // Evict at twice the probe frequency so stale IPs are cleaned
            // before the TTL fully expires.
            NxdomainHijackEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn NxdomainHijackProbeTarget>,
                config.dns.nxdomain_hijack.hijack_ip_ttl_secs / 2,
            )
            .spawn();
            info!(
                action = ?config.dns.nxdomain_hijack.action,
                "NXDomain hijack detection enabled"
            );
            Some(detector)
        } else {
            None
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
        .with_rate_limiter(rate_limiter)
        .with_dnssec_enforcement(config.dns.effective_dnssec_mode().enforces())
        .with_query_logging(config.database.log_queries);

        if config.dns.rebinding_protection_enabled {
            handler = handler.with_rebinding_protection(
                config.dns.local_domain.as_deref(),
                &config.dns.rebinding_allowlist,
            );
        }

        if config.dns64.enabled {
            if let Some(prefix) = config.dns64.parsed_prefix() {
                handler = handler.with_dns64(prefix);
            }
        }

        if let Some((detector, tx)) = &tunneling_detector {
            handler = handler
                .with_tunneling_detection(&config.dns.tunneling_detection)
                .with_tunneling_event_sender(tx.clone())
                .with_tunneling_flag_store(Arc::clone(detector) as Arc<dyn TunnelingFlagStore>);
        }

        if let Some(detector) = &nxdomain_hijack_detector {
            handler = handler.with_nxdomain_hijack_detection(
                &config.dns.nxdomain_hijack,
                Arc::clone(detector) as Arc<dyn NxdomainHijackIpStore>,
            );
        }

        let response_ip_filter_detector = if config.dns.response_ip_filter.enabled
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
            ResponseIpFilterEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn ResponseIpFilterEvictionTarget>,
                config.dns.response_ip_filter.ip_ttl_secs / 2,
            )
            .spawn();
            if config.dns.response_ip_filter.ip_ttl_secs
                < config.dns.response_ip_filter.refresh_interval_secs
            {
                warn!(
                    ip_ttl_secs = config.dns.response_ip_filter.ip_ttl_secs,
                    refresh_interval_secs = config.dns.response_ip_filter.refresh_interval_secs,
                    "ip_ttl_secs < refresh_interval_secs — IPs will be evicted before the next feed refresh"
                );
            }
            info!(
                action = ?config.dns.response_ip_filter.action,
                "Response IP filtering enabled"
            );
            Some(detector)
        } else {
            None
        };

        if let Some(detector) = &response_ip_filter_detector {
            handler = handler.with_response_ip_filter(
                &config.dns.response_ip_filter,
                Arc::clone(detector) as Arc<dyn ResponseIpFilterStore>,
            );
        }

        let dga_detector = if config.dns.dga_detection.enabled {
            let (detector, tx, rx) = DgaDetector::new(&config.dns.dga_detection);
            let detector = Arc::new(detector);
            let detector_clone = Arc::clone(&detector);
            tokio::spawn(async move { detector_clone.run_analysis_loop(rx).await });
            DgaEvictionJob::new(
                Arc::clone(&detector) as Arc<dyn DgaEvictionTarget>,
                detector.stale_entry_ttl_secs(),
            )
            .spawn();
            info!(
                action = ?config.dns.dga_detection.action,
                "DGA detection enabled"
            );
            Some((detector, tx))
        } else {
            None
        };

        if let Some((detector, tx)) = &dga_detector {
            handler = handler
                .with_dga_detection(&config.dns.dga_detection)
                .with_dga_event_sender(tx.clone())
                .with_dga_flag_store(Arc::clone(detector) as Arc<dyn DgaFlagStore>);
        }

        if config.dns.dns_cookies.enabled {
            let secret = resolve_cookie_secret(&config.dns.dns_cookies)?;
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
            pool_manager,
            dnssec_pool_manager,
            dnssec_stats,
            maintenance_pool_manager,
            health_checker,
            cache_maintenance,
            ptr_registry,
            wildcard_registry,
            local_dns_server,
            tcp_conn_limiter,
            dot_conn_limiter,
            doq_conn_limiter,
        })
    }

    async fn setup_cache_maintenance(
        config: &Config,
        cache: &Arc<DnsCache>,
        health_checker: &Arc<HealthChecker>,
        upstream_layers: &resolver::UpstreamLayers,
        repos: &Repositories,
    ) -> anyhow::Result<(
        Option<Arc<dyn CacheMaintenancePort>>,
        Option<Arc<PoolManager>>,
    )> {
        if !config.dns.cache_enabled {
            return Ok((None, None));
        }

        // Eviction and compaction run regardless: nothing else bounds the cache.
        let maintenance = DnsCacheMaintenance::new(cache.clone(), DEFAULT_REFRESH_INTERVAL_SECS);
        let optimistic = config.dns.cache_optimistic_refresh;

        // The optimistic queue holds one cycle's backlog. A cycle produces
        // roughly `entries * interval / ttl` candidates, so it is sized off the
        // cache rather than fixed: a constant that fits a small deployment
        // silently caps how much of a large one can stay warm. The clamp keeps
        // both ends sane — the upper bound is ~0.8 MB of queued keys. With the
        // scan off nothing enqueues there, so it gets the minimum.
        let optimistic_capacity = if optimistic {
            (config.dns.cache_max_entries / 4).clamp(1024, 32_768)
        } else {
            1
        };
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

        // Returned too, so hot upstream reloads also reach this resolver.
        let maintenance_pool_manager = pool::setup_pool_manager(config, health_checker).await?;
        let resolver_for_maintenance = upstream_layers
            .builder(Arc::clone(&maintenance_pool_manager))
            .build();

        // Started even with the optimistic scan off: serve-stale repairs arrive on the stale queue.
        DnsCacheMaintenance::start_refresh_worker(
            cache.clone(),
            resolver_for_maintenance,
            Some(repos.query_log.clone()),
            stale_rx,
            optimistic_rx,
            pace_rx,
            scan_opts.min_lead_secs,
        );

        let maintenance = if optimistic {
            maintenance.with_optimistic_refresh(scan_opts, pace_tx)
        } else {
            maintenance
        };

        Ok((
            Some(Arc::new(maintenance) as Arc<dyn CacheMaintenancePort>),
            Some(maintenance_pool_manager),
        ))
    }
}

/// The DNS Cookie server secret: the configured one, or a fresh random one
/// when none is set.
fn resolve_cookie_secret(
    config: &ferrous_dns_domain::DnsCookiesConfig,
) -> anyhow::Result<[u8; 32]> {
    if let Some(secret) = config.server_secret {
        return Ok(secret);
    }
    let mut secret = [0u8; 32];
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow::anyhow!("system RNG failed to generate the DNS cookie secret"))?;
    warn!(
        "dns_cookies.server_secret is not set — using ephemeral secret \
         (will not survive restart; set a 64-hex-char value in config)"
    );
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrous_dns_domain::{UpstreamPool, UpstreamStrategy};

    async fn build_services(config: Config) -> (tempfile::TempDir, DnsServices) {
        build_services_with_upstream(config, "127.0.0.1:9").await
    }

    async fn build_services_with_upstream(
        mut config: Config,
        upstream: &str,
    ) -> (tempfile::TempDir, DnsServices) {
        let dir = tempfile::tempdir().unwrap();
        config.database.path = dir.path().join("ferrous.db").display().to_string();
        config.dns.pools = vec![UpstreamPool {
            name: "test".to_string(),
            strategy: UpstreamStrategy::Parallel,
            priority: 1,
            servers: vec![upstream.to_string()],
            weight: None,
        }];

        let database_url = format!("sqlite:{}", config.database.path);
        let (write, query_log, read) =
            crate::bootstrap::database::init_database(&database_url, &config.database)
                .await
                .unwrap();
        let repos = Repositories::new(write, query_log, read, &config.database, false)
            .await
            .unwrap();
        let services = DnsServices::new(&config, &repos).await.unwrap();
        (dir, services)
    }

    /// With no local record at startup, a PTR registered later — what the
    /// create use case does — must still be answered by the running resolver.
    #[tokio::test]
    async fn ptr_registered_at_runtime_is_answered_without_startup_records() {
        use ferrous_dns_domain::{DnsRequest, RecordType};

        let config = Config::default();
        assert!(config.dns.local_records.is_empty());
        let (_dir, services) = build_services(config).await;

        services
            .ptr_registry
            .register("10.0.0.5".parse().unwrap(), Arc::from("nas.lan"), 300);
        let resolution = services
            .handler_use_case
            .execute(&DnsRequest::new(
                "5.0.0.10.in-addr.arpa",
                RecordType::PTR,
                "127.0.0.1".parse().unwrap(),
            ))
            .await
            .unwrap();

        assert!(
            resolution.local_dns,
            "PTR was not answered from the local map"
        );
    }

    /// Nothing but the maintenance cycle bounds the positive cache, so turning
    /// optimistic refresh off must not turn eviction off with it.
    #[tokio::test]
    async fn cache_is_still_evicted_with_optimistic_refresh_off() {
        use ferrous_dns_domain::RecordType;
        use ferrous_dns_infrastructure::dns::CachedData;

        const MAX_ENTRIES: usize = 10;
        let mut config = Config::default();
        config.dns.cache_enabled = true;
        config.dns.cache_optimistic_refresh = false;
        config.dns.cache_max_entries = MAX_ENTRIES;
        config.dns.cache_batch_eviction_percentage = 0.5;
        let (_dir, services) = build_services(config).await;

        for i in 0..MAX_ENTRIES * 2 {
            services.cache.insert(
                &format!("host{i}.example.com"),
                RecordType::CNAME,
                CachedData::CanonicalName(Arc::from("target.example.com")),
                3600,
                None,
            );
        }
        let before = services.cache.len();
        assert!(before > MAX_ENTRIES);

        let maintenance = services
            .cache_maintenance
            .expect("cache maintenance is wired whenever the cache is enabled");
        maintenance.run_eviction_cycle().await.unwrap();

        assert!(
            services.cache.len() < before,
            "eviction cycle removed nothing from an over-capacity cache"
        );
    }

    /// Serve-stale repairs don't depend on the optimistic scan: with it off, a
    /// stale hit must still send the entry's refresh upstream in the background.
    #[tokio::test]
    async fn stale_hit_is_repaired_with_optimistic_refresh_off() {
        use ferrous_dns_domain::RecordType;
        use ferrous_dns_infrastructure::dns::cache::coarse_clock;
        use ferrous_dns_infrastructure::dns::{CachedAddresses, CachedData};
        use std::time::Duration;

        const DOMAIN: &str = "stale-repair.example.com";
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::default();
        config.dns.cache_enabled = true;
        config.dns.cache_optimistic_refresh = false;
        config.dns.cache_min_ttl = 0;
        let (_dir, services) =
            build_services_with_upstream(config, &upstream.local_addr().unwrap().to_string()).await;

        coarse_clock::tick();
        services.cache.insert(
            DOMAIN,
            RecordType::A,
            CachedData::IpAddresses(CachedAddresses {
                addresses: Arc::new(vec!["192.0.2.1".parse().unwrap()]),
            }),
            2,
            None,
        );
        // Past expiry, still inside the two-TTL stale grace period.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        coarse_clock::tick();
        assert!(services.cache.get(DOMAIN, &RecordType::A).is_some());
        assert_eq!(
            services
                .cache
                .metrics()
                .stale_hits
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );

        // The health checker probes this socket too, so wait for our qname
        // (compared case-insensitively: queries may carry 0x20 case randomization).
        let qname: &[u8] = b"\x0cstale-repair\x07example\x03com\x00";
        let mut buf = [0u8; 512];
        let received = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let (len, _) = upstream.recv_from(&mut buf).await.unwrap();
                if buf[..len]
                    .windows(qname.len())
                    .any(|w| w.eq_ignore_ascii_case(qname))
                {
                    break;
                }
            }
        })
        .await;

        assert!(
            received.is_ok(),
            "stale hit was never refreshed upstream in the background"
        );
    }

    /// Stands in for the router behind `local_dns_server`: while `answering`
    /// is set, it answers `upstream.test A` with 192.0.2.1 and every other
    /// question with an empty NOERROR; otherwise it drops queries.
    async fn spawn_router(answering: Arc<std::sync::atomic::AtomicBool>) -> SocketAddr {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record, RecordType as WireType};

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                if !answering.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }
                let Ok(req) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let Some(q) = req.queries.first().cloned() else {
                    continue;
                };
                let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = req.metadata.recursion_desired;
                resp.metadata.recursion_available = true;
                resp.metadata.response_code = ResponseCode::NoError;
                resp.add_query(q.clone());
                if q.query_type() == WireType::A
                    && q.name().to_ascii().eq_ignore_ascii_case("upstream.test.")
                {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        300,
                        RData::A(A(std::net::Ipv4Addr::new(192, 0, 2, 1))),
                    ));
                }
                let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    fn resolved_addrs(pool_manager: &PoolManager) -> Vec<SocketAddr> {
        pool_manager
            .get_all_arc_protocols()
            .iter()
            .filter_map(|p| p.socket_addr())
            .collect()
    }

    fn router(answering: bool) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::new(std::sync::atomic::AtomicBool::new(answering))
    }

    /// Issue #250: when this machine resolves through Ferrous DNS itself, the
    /// system lookup at startup can never succeed; the router must answer it.
    #[tokio::test]
    async fn upstream_hostnames_resolve_through_the_local_dns_server() {
        let mut config = Config::default();
        config.dns.local_dns_server = Some(spawn_router(router(true)).await.to_string());
        let (_dir, services) =
            build_services_with_upstream(config, "doq://upstream.test:853").await;

        let expected: Vec<SocketAddr> = vec!["192.0.2.1:853".parse().unwrap()];
        assert_eq!(resolved_addrs(&services.pool_manager), expected);
        for manager in [
            &services.dnssec_pool_manager,
            &services.maintenance_pool_manager,
        ]
        .into_iter()
        .flatten()
        {
            assert_eq!(resolved_addrs(manager), expected);
        }
    }

    /// A lookup that failed at startup (the router or the network not up yet)
    /// must be retried in the background, without a restart or a pool save.
    #[tokio::test]
    async fn an_upstream_hostname_that_failed_at_startup_is_retried() {
        let answering = router(false);
        let mut config = Config::default();
        config.dns.local_dns_server = Some(spawn_router(answering.clone()).await.to_string());
        config.dns.health_check.interval = 1;
        let (_dir, services) =
            build_services_with_upstream(config, "doq://upstream.test:853").await;
        assert!(
            resolved_addrs(&services.pool_manager).is_empty(),
            "the router was not answering at startup"
        );

        answering.store(true, std::sync::atomic::Ordering::Relaxed);
        let resolved = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let addrs = resolved_addrs(&services.pool_manager);
                if !addrs.is_empty() {
                    return addrs;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the hostname was never retried after the router came back");
        assert_eq!(
            resolved,
            vec!["192.0.2.1:853".parse::<SocketAddr>().unwrap()]
        );
    }

    /// A router that does not answer must not break what already worked: the
    /// system resolver still gets the lookup.
    #[tokio::test]
    async fn upstream_hostnames_fall_back_to_the_system_resolver() {
        let mut config = Config::default();
        config.dns.local_dns_server = Some(spawn_router(router(false)).await.to_string());
        let (_dir, services) = build_services_with_upstream(config, "udp://localhost:53").await;

        assert!(
            resolved_addrs(&services.pool_manager).contains(&"127.0.0.1:53".parse().unwrap()),
            "{:?}",
            services.pool_manager.get_all_arc_protocols()
        );
    }

    /// Older builds saved the router's bare IP; startup must take it as port 53.
    #[tokio::test]
    async fn a_bare_local_dns_server_ip_starts_on_port_53() {
        let mut config = Config::default();
        config.dns.local_dns_server = Some("192.168.1.1".to_string());
        let (_dir, services) = build_services(config).await;

        assert_eq!(
            services.local_dns_server,
            Some("192.168.1.1:53".parse().unwrap())
        );
    }
}
