use ferrous_dns_domain::config::CacheEvictionStrategy;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, DnsCacheConfig, EvictionStrategy},
    CachedAddresses, CachedData,
};
use std::sync::Arc;
use tracing::info;

fn eviction_strategy(strategy: CacheEvictionStrategy) -> EvictionStrategy {
    match strategy {
        CacheEvictionStrategy::Lru => EvictionStrategy::LRU,
        CacheEvictionStrategy::HitRate => EvictionStrategy::HitRate,
        CacheEvictionStrategy::Lfu => EvictionStrategy::LFU,
        CacheEvictionStrategy::LfuK => EvictionStrategy::LFUK,
    }
}

pub(super) fn build_cache(config: &Config) -> Arc<DnsCache> {
    if config.dns.cache_enabled {
        info!(
            strategy = %config.dns.cache_eviction_strategy,
            max_entries = config.dns.cache_max_entries,
            "Cache enabled"
        );
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: config.dns.cache_max_entries,
            eviction_strategy: eviction_strategy(config.dns.cache_eviction_strategy),
            refresh_threshold: config.dns.cache_refresh_threshold,
            batch_eviction_percentage: config.dns.cache_batch_eviction_percentage,
            min_frequency: config.dns.cache_min_frequency,
            min_lfuk_score: config.dns.cache_min_lfuk_score,
            shard_amount: config.dns.cache_shard_amount,
            access_window_secs: config.dns.cache_access_window_secs,
            eviction_sample_size: config.dns.cache_eviction_sample_size,
            lfuk_k_value: 0.5,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    } else {
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: 0,
            eviction_strategy: EvictionStrategy::HitRate,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 0,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    }
}

pub(super) fn preload_local_records_into_cache(
    cache: &Arc<DnsCache>,
    records: &[ferrous_dns_domain::LocalDnsRecord],
    default_domain: Option<&str>,
) {
    // Wildcards are served by `LocalWildcardResolver` above the cache: a cache
    // key is matched exactly, so `*.home.lan` here would be an entry no query
    // could ever reach.
    let mut count = 0usize;
    for record in records.iter().filter(|r| !r.is_wildcard()) {
        let fqdn = record.fqdn(default_domain);
        let data = CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![record.ip]),
        });
        let ttl = record.ttl_or_default();

        cache.insert_permanent(&fqdn, record.record_type.into(), data, ttl);

        info!(
            fqdn = %fqdn,
            ip = %record.ip,
            record_type = %record.record_type,
            ttl = %ttl,
            "Preloaded local DNS record into permanent cache"
        );
        count += 1;
    }

    if count > 0 {
        info!(
            count,
            wildcards = records.len() - count,
            "✓ Preloaded {} local DNS record(s) into permanent cache",
            count
        );
    }
}
