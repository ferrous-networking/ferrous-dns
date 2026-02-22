use super::super::cache::{DnsCache, NegativeQueryTracker};
use super::super::load_balancer::PoolManager;
use super::super::prefetch::PrefetchPredictor;
use super::cache_layer::CachedResolver;
use super::config::ResolverConfig;
use super::core::CoreResolver;
use super::dnssec_layer::DnssecResolver;
use super::filtered_resolver::FilteredResolver;
use super::filters::QueryFilters;
use ferrous_dns_application::ports::DnsResolver;
use std::sync::Arc;
use tracing::info;

pub struct ResolverBuilder {
    pool_manager: Arc<PoolManager>,
    dnssec_pool_manager: Option<Arc<PoolManager>>,
    config: ResolverConfig,
    cache: Option<Arc<DnsCache>>,
    local_domain: Option<String>,
    local_dns_server: Option<String>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
    filters: Option<QueryFilters>,
}

impl ResolverBuilder {
    pub fn new(pool_manager: Arc<PoolManager>) -> Self {
        Self {
            pool_manager,
            dnssec_pool_manager: None,
            config: ResolverConfig::default(),
            cache: None,
            local_domain: None,
            local_dns_server: None,
            prefetch_predictor: None,
            filters: None,
        }
    }

    pub fn with_dnssec_pool_manager(mut self, pool_manager: Arc<PoolManager>) -> Self {
        self.dnssec_pool_manager = Some(pool_manager);
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

    pub fn with_prefetch(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.prefetch_predictor = Some(predictor);
        self
    }

    pub fn with_filters(mut self, filters: QueryFilters) -> Self {
        self.filters = Some(filters);
        self
    }

    pub fn build(self) -> Arc<dyn DnsResolver> {
        info!(
            dnssec = self.config.dnssec_enabled,
            cache = self.cache.is_some(),
            filters = self.filters.is_some(),
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
            ));
        }

        if let Some(cache) = self.cache {
            let tracker = Arc::new(NegativeQueryTracker::new());
            tracker.start_cleanup_task();
            let mut cached = CachedResolver::new(resolver, cache, self.config.cache_ttl, tracker);

            if let Some(predictor) = self.prefetch_predictor {
                cached = cached.with_prefetch(predictor);
            }

            resolver = Arc::new(cached);
        }

        if let Some(filters) = self.filters {
            resolver = Arc::new(FilteredResolver::new(resolver, filters));
        }

        info!("DNS resolver built successfully");
        resolver
    }
}
