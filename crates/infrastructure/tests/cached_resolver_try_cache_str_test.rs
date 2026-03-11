use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use std::net::IpAddr;
use std::sync::Arc;

struct NullResolver;

#[async_trait]
impl DnsResolver for NullResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::NxDomain)
    }
}

fn make_cache() -> Arc<dyn DnsCacheAccess> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 2.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

fn make_resolver(cache: Arc<dyn DnsCacheAccess>) -> Arc<CachedResolver> {
    Arc::new(CachedResolver::new(
        Arc::new(NullResolver) as Arc<dyn DnsResolver>,
        cache,
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ))
}

// ── try_cache_str: basic behaviour ───────────────────────────────────────────

#[test]
fn try_cache_str_returns_none_on_empty_cache() {
    let resolver = make_resolver(make_cache());
    assert!(resolver
        .try_cache_str("example.com", RecordType::A)
        .is_none());
}

#[tokio::test]
async fn try_cache_str_returns_hit_after_upstream_resolve_populates_cache() {
    let cache = make_cache();
    let inner_resolver = {
        struct Fixed;
        #[async_trait]
        impl DnsResolver for Fixed {
            async fn resolve(&self, _: &DnsQuery) -> Result<DnsResolution, DomainError> {
                Ok(DnsResolution::new(vec!["1.2.3.4".parse().unwrap()], false))
            }
        }
        Arc::new(Fixed) as Arc<dyn DnsResolver>
    };

    let resolver = Arc::new(CachedResolver::new(
        inner_resolver,
        Arc::clone(&cache),
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    let query = DnsQuery::new("cached.example", RecordType::A);
    resolver.resolve(&query).await.unwrap();

    let hit = resolver.try_cache_str("cached.example", RecordType::A);
    assert!(hit.is_some());
    let res = hit.unwrap();
    assert!(res.cache_hit);
    assert_eq!(*res.addresses, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
}

// ── try_cache_str and try_cache return the same result ───────────────────────

#[tokio::test]
async fn try_cache_str_and_try_cache_return_equivalent_results() {
    let inner_resolver = {
        struct Fixed;
        #[async_trait]
        impl DnsResolver for Fixed {
            async fn resolve(&self, _: &DnsQuery) -> Result<DnsResolution, DomainError> {
                Ok(DnsResolution::new(vec!["9.9.9.9".parse().unwrap()], false))
            }
        }
        Arc::new(Fixed) as Arc<dyn DnsResolver>
    };

    let resolver = Arc::new(CachedResolver::new(
        inner_resolver,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    let query = DnsQuery::new("parity.example", RecordType::A);
    resolver.resolve(&query).await.unwrap();

    let via_str = resolver.try_cache_str("parity.example", RecordType::A);
    let via_query = resolver.try_cache(&query);

    assert!(via_str.is_some() && via_query.is_some());
    assert_eq!(via_str.unwrap().addresses, via_query.unwrap().addresses);
}

// ── try_cache_str: record type isolation ─────────────────────────────────────

#[tokio::test]
async fn try_cache_str_misses_for_different_record_type() {
    let inner_resolver = {
        struct Fixed;
        #[async_trait]
        impl DnsResolver for Fixed {
            async fn resolve(&self, _: &DnsQuery) -> Result<DnsResolution, DomainError> {
                Ok(DnsResolution::new(vec!["5.5.5.5".parse().unwrap()], false))
            }
        }
        Arc::new(Fixed) as Arc<dyn DnsResolver>
    };

    let resolver = Arc::new(CachedResolver::new(
        inner_resolver,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    let query = DnsQuery::new("typed.example", RecordType::A);
    resolver.resolve(&query).await.unwrap();

    assert!(resolver
        .try_cache_str("typed.example", RecordType::A)
        .is_some());
    assert!(
        resolver
            .try_cache_str("typed.example", RecordType::AAAA)
            .is_none(),
        "AAAA must not hit A-only cache entry"
    );
}
