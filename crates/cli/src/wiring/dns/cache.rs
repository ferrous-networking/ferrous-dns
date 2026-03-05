use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    cache::{DnsCache, DnsCacheConfig, EvictionStrategy},
    CachedAddresses, CachedData,
};
use std::sync::Arc;
use tracing::{info, warn};

pub(super) fn build_cache(config: &Config) -> Arc<DnsCache> {
    if config.dns.cache_enabled {
        let eviction_strategy = match config.dns.cache_eviction_strategy.as_str() {
            "lfu" => EvictionStrategy::LFU,
            "lfu-k" => EvictionStrategy::LFUK,
            _ => EvictionStrategy::HitRate,
        };
        info!(
            strategy = config.dns.cache_eviction_strategy.as_str(),
            max_entries = config.dns.cache_max_entries,
            "Cache enabled"
        );
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: config.dns.cache_max_entries,
            eviction_strategy,
            min_threshold: config.dns.cache_min_hit_rate,
            refresh_threshold: config.dns.cache_refresh_threshold,
            batch_eviction_percentage: config.dns.cache_batch_eviction_percentage,
            adaptive_thresholds: config.dns.cache_adaptive_thresholds,
            min_frequency: config.dns.cache_min_frequency,
            min_lfuk_score: config.dns.cache_min_lfuk_score,
            shard_amount: config.dns.cache_shard_amount,
            access_window_secs: config.dns.cache_access_window_secs,
            eviction_sample_size: config.dns.cache_eviction_sample_size,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    } else {
        Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: 0,
            eviction_strategy: EvictionStrategy::HitRate,
            min_threshold: 0.0,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 0,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: config.dns.cache_min_ttl,
            max_ttl: config.dns.cache_max_ttl,
        }))
    }
}

pub(super) fn preload_local_records_into_cache(
    cache: &Arc<DnsCache>,
    records: &[ferrous_dns_domain::LocalDnsRecord],
    default_domain: &Option<String>,
) {
    use ferrous_dns_domain::RecordType;

    let mut success_count = 0;
    let mut error_count = 0;

    for record in records {
        let fqdn = record.fqdn(default_domain);

        let ip: std::net::IpAddr = match record.ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                warn!(
                    hostname = %record.hostname,
                    ip = %record.ip,
                    "Invalid IP address for local DNS record, skipping"
                );
                error_count += 1;
                continue;
            }
        };

        let record_type = match record.record_type.to_uppercase().as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            _ => {
                warn!(
                    hostname = %record.hostname,
                    record_type = %record.record_type,
                    "Invalid record type for local DNS record (must be A or AAAA), skipping"
                );
                error_count += 1;
                continue;
            }
        };

        let ip_type_valid = matches!(
            (&record_type, &ip),
            (RecordType::A, std::net::IpAddr::V4(_)) | (RecordType::AAAA, std::net::IpAddr::V6(_))
        );

        if !ip_type_valid {
            warn!(
                hostname = %record.hostname,
                ip = %record.ip,
                record_type = %record.record_type,
                "IP type mismatch (A record needs IPv4, AAAA needs IPv6), skipping"
            );
            error_count += 1;
            continue;
        }

        let data = CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![ip]),
        });

        let ttl = record.ttl.unwrap_or(300);

        cache.insert_permanent(&fqdn, record_type, data, None);

        info!(
            fqdn = %fqdn,
            ip = %ip,
            record_type = %record_type,
            ttl = %ttl,
            "Preloaded local DNS record into permanent cache"
        );

        success_count += 1;
    }

    if success_count > 0 {
        info!(
            count = success_count,
            errors = error_count,
            "✓ Preloaded {} local DNS record(s) into permanent cache",
            success_count
        );
    }

    if error_count > 0 {
        warn!(
            count = error_count,
            "× Failed to preload {} local DNS record(s)", error_count
        );
    }
}
