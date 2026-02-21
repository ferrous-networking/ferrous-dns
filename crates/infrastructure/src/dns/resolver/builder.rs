use super::super::cache::{DnsCache, NegativeQueryTracker};
use super::super::conditional_forwarder::ConditionalForwarder;
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
    conditional_forwarder: Option<Arc<ConditionalForwarder>>,
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
            conditional_forwarder: None,
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

    pub fn with_conditional_forwarder(mut self, forwarder: Arc<ConditionalForwarder>) -> Self {
        self.conditional_forwarder = Some(forwarder);
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

        let mut core = CoreResolver::new(self.pool_manager.clone(), self.config.query_timeout_ms);

        if let Some(forwarder) = self.conditional_forwarder {
            core = core.with_conditional_forwarder(forwarder);
        }

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
