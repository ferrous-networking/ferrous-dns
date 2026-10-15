use super::super::cache::DnsCache;
use super::super::dnssec::{DnssecCache, TrustAnchorStore};
use super::super::load_balancer::{PoolManager, UpstreamRouter};
use super::cache_layer::CachedResolver;
use super::core::CoreResolver;
use super::dns64_layer::Dns64Resolver;
use super::dnssec_layer::DnssecResolver;
use super::filtered_resolver::FilteredResolver;
use super::filters::QueryFilters;
use super::local_ptr::{LocalPtrResolver, PtrMap};
use super::local_wildcard::{LocalWildcardResolver, WildcardMap};
use ferrous_dns_application::ports::DnsResolver;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tracing::info;

/// Assembles the resolver layers around the upstream [`CoreResolver`]; every
/// layer is optional and absent unless its `with_*` is called.
pub struct ResolverBuilder {
    pool_manager: Arc<PoolManager>,
    query_timeout_ms: u64,
    dnssec: Option<DnssecSetup>,
    cache: Option<CacheSetup>,
    local_domain: Option<String>,
    local_dns_server: Option<SocketAddr>,
    filters: Option<QueryFilters>,
    local_ptr_map: Option<Arc<PtrMap>>,
    local_wildcards: Option<Arc<WildcardMap>>,
    dns64_prefix: Option<Ipv6Addr>,
}

struct DnssecSetup {
    pool_manager: Arc<PoolManager>,
    trust_anchors: TrustAnchorStore,
    cache: Arc<DnssecCache>,
}

struct CacheSetup {
    cache: Arc<DnsCache>,
    ttl: u32,
    inflight_shards: usize,
}

impl ResolverBuilder {
    pub fn new(pool_manager: Arc<PoolManager>, query_timeout_ms: u64) -> Self {
        Self {
            pool_manager,
            query_timeout_ms,
            dnssec: None,
            cache: None,
            local_domain: None,
            local_dns_server: None,
            filters: None,
            local_ptr_map: None,
            local_wildcards: None,
            dns64_prefix: None,
        }
    }

    /// Validates answers with DNSSEC, walking the chain of trust on
    /// `pool_manager`. `cache` is caller-owned so its counters can be reported.
    pub fn with_dnssec(
        mut self,
        pool_manager: Arc<PoolManager>,
        trust_anchors: TrustAnchorStore,
        cache: Arc<DnssecCache>,
    ) -> Self {
        self.dnssec = Some(DnssecSetup {
            pool_manager,
            trust_anchors,
            cache,
        });
        self
    }

    pub fn with_cache(mut self, cache: Arc<DnsCache>, ttl: u32, inflight_shards: usize) -> Self {
        self.cache = Some(CacheSetup {
            cache,
            ttl,
            inflight_shards,
        });
        self
    }

    pub fn with_local_domain(mut self, domain: Option<String>) -> Self {
        self.local_domain = domain;
        self
    }

    /// The LAN server that answers names under the local domain and private PTRs.
    pub fn with_local_dns_server(mut self, server: Option<SocketAddr>) -> Self {
        self.local_dns_server = server;
        self
    }

    pub fn with_filters(mut self, filters: QueryFilters) -> Self {
        self.filters = Some(filters);
        self
    }

    /// Attaches a live PTR map so that `LocalPtrResolver` is added as the
    /// outermost layer, intercepting PTR queries before any other resolver.
    pub fn with_local_ptr_map(mut self, map: Arc<PtrMap>) -> Self {
        self.local_ptr_map = Some(map);
        self
    }

    /// Attaches the live wildcard index, adding `LocalWildcardResolver` just
    /// above the cache. Always attach it, even empty: it is what lets a
    /// wildcard added at runtime answer without a restart.
    pub fn with_local_wildcards(mut self, map: Arc<WildcardMap>) -> Self {
        self.local_wildcards = Some(map);
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
            dnssec = self.dnssec.is_some(),
            cache = self.cache.is_some(),
            filters = self.filters.is_some(),
            local_ptr = self.local_ptr_map.is_some(),
            wildcards = self.local_wildcards.as_ref().map_or(0, |m| m.len()),
            "Building DNS resolver"
        );

        // The pools decide which answers belong to one client group alone.
        let router: Arc<dyn UpstreamRouter> = Arc::clone(&self.pool_manager) as _;
        let core = CoreResolver::new(
            self.pool_manager,
            self.query_timeout_ms,
            self.dnssec.is_some(),
        )
        .with_local_domain(self.local_domain)
        .with_local_dns_server(self.local_dns_server);

        let mut resolver: Arc<dyn DnsResolver> = Arc::new(core);

        if let Some(dnssec) = self.dnssec {
            resolver = Arc::new(DnssecResolver::new(
                resolver,
                dnssec.pool_manager,
                self.query_timeout_ms,
                dnssec.trust_anchors,
                dnssec.cache,
            ));
        }

        // DNS64 sits below the cache: synthesized AAAA answers are stored as
        // ordinary positive cache entries and served consistently by the cache
        // fast-path, while the negative AAAA is DNSSEC-validated first (inner).
        if let Some(prefix) = self.dns64_prefix {
            resolver = Arc::new(Dns64Resolver::new(resolver, prefix));
        }

        if let Some(cache) = self.cache {
            resolver = Arc::new(
                CachedResolver::new(resolver, cache.cache, cache.ttl, cache.inflight_shards)
                    .with_router(Arc::clone(&router)),
            );
        }

        // Wildcard local records answer above the cache. A cache key is matched
        // exactly, so an expansion of `*.home.lan` stored under a concrete name
        // could never be found again to invalidate when the wildcard is deleted.
        if let Some(map) = self.local_wildcards {
            resolver = Arc::new(LocalWildcardResolver::new(resolver, map));
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
