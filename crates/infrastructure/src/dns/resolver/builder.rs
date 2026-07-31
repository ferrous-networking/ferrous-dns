use super::super::cache::{DnsCache, NegativeQueryTracker};
use super::super::dnssec::TrustAnchorStore;
use super::super::load_balancer::PoolManager;
use super::cache_layer::CachedResolver;
use super::config::ResolverConfig;
use super::core::CoreResolver;
use super::dns64_layer::Dns64Resolver;
use super::dnssec_layer::DnssecResolver;
use super::filtered_resolver::FilteredResolver;
use super::filters::QueryFilters;
use super::local_ptr::{LocalPtrResolver, PtrMap};
use ferrous_dns_application::ports::DnsResolver;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tracing::info;

pub struct ResolverBuilder {
    pool_manager: Arc<PoolManager>,
    dnssec_pool_manager: Option<Arc<PoolManager>>,
    trust_anchors: Option<TrustAnchorStore>,
    config: ResolverConfig,
    cache: Option<Arc<DnsCache>>,
    local_domain: Option<String>,
    local_dns_server: Option<String>,
    filters: Option<QueryFilters>,
    local_ptr_map: Option<Arc<PtrMap>>,
    dns64_prefix: Option<Ipv6Addr>,
}

impl ResolverBuilder {
    pub fn new(pool_manager: Arc<PoolManager>) -> Self {
        Self {
            pool_manager,
            dnssec_pool_manager: None,
            trust_anchors: None,
            config: ResolverConfig::default(),
            cache: None,
            local_domain: None,
            local_dns_server: None,
            filters: None,
            local_ptr_map: None,
            dns64_prefix: None,
        }
    }

    pub fn with_dnssec_pool_manager(mut self, pool_manager: Arc<PoolManager>) -> Self {
        self.dnssec_pool_manager = Some(pool_manager);
        self
    }

    /// Overrides the DNSSEC trust anchors. Without this the validator uses the
    /// IANA root anchors embedded in the binary.
    pub fn with_trust_anchors(mut self, trust_anchors: TrustAnchorStore) -> Self {
        self.trust_anchors = Some(trust_anchors);
        self
    }

    pub fn with_config(mut self, config: ResolverConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_cache(mut self, cache: Arc<DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn with_dnssec(mut self) -> Self {
        self.config.dnssec_enabled = true;
        self
    }

    pub fn with_local_domain(mut self, domain: Option<String>) -> Self {
        self.local_domain = domain;
        self
    }

    pub fn with_local_dns_server(mut self, server: Option<String>) -> Self {
        self.local_dns_server = server;
        self
    }

    pub fn with_filters(mut self, filters: QueryFilters) -> Self {
        self.filters = Some(filters);
        self
    }

    /// Attaches a pre-populated PTR map so that `LocalPtrResolver` is added as the
    /// outermost layer, intercepting PTR queries before any other resolver.
    pub fn with_local_ptr_map(mut self, map: Arc<PtrMap>) -> Self {
        self.local_ptr_map = Some(map);
        self
    }

    /// Enables DNS64 (RFC 6147) AAAA synthesis using the given `/96` NAT64
    /// network prefix. The layer is placed just below the cache so synthesized
    /// answers are cached and served consistently.
    pub fn with_dns64(mut self, prefix: Ipv6Addr) -> Self {
        self.dns64_prefix = Some(prefix);
        self
    }

    pub fn build(self) -> Arc<dyn DnsResolver> {
        info!(
            dnssec = self.config.dnssec_enabled,
            cache = self.cache.is_some(),
            filters = self.filters.is_some(),
            local_ptr = self.local_ptr_map.is_some(),
            "Building DNS resolver"
        );

        let core = CoreResolver::new(
            self.pool_manager.clone(),
            self.config.query_timeout_ms,
            self.config.dnssec_enabled,
        )
        .with_local_domain(self.local_domain)
        .with_local_dns_server(self.local_dns_server);

        let mut resolver: Arc<dyn DnsResolver> = Arc::new(core);

        if self.config.dnssec_enabled {
            let dnssec_pm = self
                .dnssec_pool_manager
                .clone()
                .unwrap_or_else(|| self.pool_manager.clone());
            resolver = Arc::new(DnssecResolver::new(
                resolver,
                dnssec_pm,
                self.config.query_timeout_ms,
                self.trust_anchors.unwrap_or_default(),
            ));
        }

        // DNS64 sits below the cache: synthesized AAAA answers are stored as
        // ordinary positive cache entries and served consistently by the cache
        // fast-path, while the negative AAAA is DNSSEC-validated first (inner).
        if let Some(prefix) = self.dns64_prefix {
            resolver = Arc::new(Dns64Resolver::new(resolver, prefix));
        }

        if let Some(cache) = self.cache {
            let tracker = Arc::new(NegativeQueryTracker::new());
            tracker.start_cleanup_task();
            let cached = CachedResolver::new(
                resolver,
                cache,
                self.config.cache_ttl,
                tracker,
                self.config.inflight_shards,
            );

            resolver = Arc::new(cached);
        }

        if let Some(filters) = self.filters {
            resolver = Arc::new(FilteredResolver::new(resolver, filters));
        }

        if let Some(map) = self.local_ptr_map {
            resolver = Arc::new(LocalPtrResolver::new(resolver, map));
        }

        info!("DNS resolver built successfully");
        resolver
    }
}
