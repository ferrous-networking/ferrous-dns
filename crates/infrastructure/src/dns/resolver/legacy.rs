use super::super::cache::DnsCache;
use super::super::load_balancer::PoolManager;
use super::super::prefetch::PrefetchPredictor;
use super::builder::ResolverBuilder;
use super::config::ResolverConfig;
use super::filters::QueryFilters;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, QueryLogRepository};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;

const DEFAULT_CACHE_TTL: u32 = 3600;

pub struct HickoryDnsResolver {
    inner: Arc<dyn DnsResolver>,
    builder_state: BuilderState,
}

struct BuilderState {
    pool_manager: Arc<PoolManager>,
    dnssec_pool_manager: Option<Arc<PoolManager>>,
    config: ResolverConfig,
    cache: Option<Arc<DnsCache>>,
    cache_ttl: u32,
    local_domain: Option<String>,
    local_dns_server: Option<String>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
    filters: Option<QueryFilters>,
}

impl HickoryDnsResolver {
    pub fn new_with_pools(
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
        dnssec_enabled: bool,
        _query_log_repo: Option<Arc<dyn QueryLogRepository>>,
    ) -> Result<Self, DomainError> {
        let mut config = ResolverConfig::default().with_timeout(query_timeout_ms);

        if dnssec_enabled {
            config = config.with_dnssec();
        }

        let builder_state = BuilderState {
            pool_manager: pool_manager.clone(),
            dnssec_pool_manager: None,
            config: config.clone(),
            cache: None,
            cache_ttl: DEFAULT_CACHE_TTL,
            local_domain: None,
            local_dns_server: None,
            prefetch_predictor: None,
            filters: None,
        };

        let inner = ResolverBuilder::new(pool_manager)
            .with_config(config)
            .build();

        Ok(Self {
            inner,
            builder_state,
        })
    }

    pub fn with_dnssec_pool_manager(mut self, pool_manager: Arc<PoolManager>) -> Self {
        self.builder_state.dnssec_pool_manager = Some(pool_manager);
        self.rebuild();
        self
    }

    pub fn with_cache(mut self, cache: Arc<DnsCache>, cache_ttl: u32) -> Self {
        self.builder_state.cache = Some(cache);
        self.builder_state.cache_ttl = cache_ttl;
        self.builder_state.config.cache_ttl = cache_ttl;
        self.rebuild();
        self
    }

    pub fn with_query_filters(
        mut self,
        block_private_ptr: bool,
        block_non_fqdn: bool,
        local_domain: Option<String>,
    ) -> Self {
        self.builder_state.filters = Some(QueryFilters {
            block_private_ptr,
            block_non_fqdn,
            local_domain: local_domain.clone(),
        });
        self.builder_state.local_domain = local_domain;
        self.rebuild();
        self
    }

    pub fn with_local_dns_server(mut self, server: Option<String>) -> Self {
        self.builder_state.local_dns_server = server;
        self.rebuild();
        self
    }

    pub fn with_prefetch_predictor(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.builder_state.prefetch_predictor = Some(predictor);
        self.rebuild();
        self
    }

    fn rebuild(&mut self) {
        let mut builder = ResolverBuilder::new(self.builder_state.pool_manager.clone())
            .with_config(self.builder_state.config.clone())
            .with_local_domain(self.builder_state.local_domain.clone())
            .with_local_dns_server(self.builder_state.local_dns_server.clone());

        if let Some(dnssec_pm) = &self.builder_state.dnssec_pool_manager {
            builder = builder.with_dnssec_pool_manager(dnssec_pm.clone());
        }

        if let Some(cache) = &self.builder_state.cache {
            builder = builder.with_cache(cache.clone());
        }

        if let Some(predictor) = &self.builder_state.prefetch_predictor {
            builder = builder.with_prefetch(predictor.clone());
        }

        if let Some(filters) = &self.builder_state.filters {
            builder = builder.with_filters(filters.clone());
        }

        self.inner = builder.build();
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.inner.try_cache(query)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.inner.resolve(query).await
    }
}
