use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    CachedData, DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record};
use std::str::FromStr;
use std::sync::Arc;

fn make_soa_record(zone: &str, minimum: u32, record_ttl: u32) -> Record {
    let name = Name::from_str(&format!("{}.", zone)).unwrap();
    let mname = Name::from_str(&format!("ns1.{}.", zone)).unwrap();
    let rname = Name::from_str(&format!("hostmaster.{}.", zone)).unwrap();
    let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, minimum);
    Record::from_rdata(name, record_ttl, RData::SOA(soa))
}

struct MockNegativeResolver {
    authority_records: Vec<Record>,
}

#[async_trait]
impl DnsResolver for MockNegativeResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Ok(DnsResolution {
            addresses: Arc::new(vec![]),
            cache_hit: false,
            local_dns: false,
            dnssec_status: None,
            cname_chain: Arc::from(vec![]),
            upstream_server: None,
            min_ttl: None,
            authority_records: self.authority_records.clone(),
        })
    }
}

fn make_cache() -> Arc<DnsCache> {
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

#[tokio::test]
async fn test_soa_ttl_used_when_present() {
    let soa = make_soa_record("example.com", 300, 300);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver {
        authority_records: vec![soa],
    });

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        Arc::new(NegativeQueryTracker::new()),
    );

    let query = DnsQuery {
        domain: Arc::from("nxdomain.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("nxdomain.example.com"), &RecordType::A);
    assert!(cached.is_some(), "Negative response should be cached");
    let (data, _, remaining_ttl) = cached.unwrap();
    assert!(matches!(data, CachedData::NegativeResponse));
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (290..=300).contains(&ttl),
        "TTL from SOA minimum should be ~300, got {ttl}"
    );
}

#[tokio::test]
async fn test_soa_ttl_below_min_clamped_to_30() {
    let soa = make_soa_record("example.com", 10, 10);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver {
        authority_records: vec![soa],
    });

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        Arc::new(NegativeQueryTracker::new()),
    );

    let query = DnsQuery {
        domain: Arc::from("low-ttl.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("low-ttl.example.com"), &RecordType::A);
    let (_, _, remaining_ttl) = cached.expect("Should be cached");
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (29..=30).contains(&ttl),
        "SOA TTL 10 should be clamped to min 30, got {ttl}"
    );
}

#[tokio::test]
async fn test_soa_ttl_above_max_clamped_to_3600() {
    let soa = make_soa_record("example.com", 86400, 86400);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver {
        authority_records: vec![soa],
    });

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        Arc::new(NegativeQueryTracker::new()),
    );

    let query = DnsQuery {
        domain: Arc::from("high-ttl.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("high-ttl.example.com"), &RecordType::A);
    let (_, _, remaining_ttl) = cached.expect("Should be cached");
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (3590..=3600).contains(&ttl),
        "SOA TTL 86400 should be clamped to max 3600, got {ttl}"
    );
}

#[tokio::test]
async fn test_fallback_to_tracker_when_no_soa() {
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver {
        authority_records: vec![],
    });

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        Arc::new(NegativeQueryTracker::new()),
    );

    let query = DnsQuery {
        domain: Arc::from("no-soa.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("no-soa.example.com"), &RecordType::A);
    assert!(
        cached.is_some(),
        "Should still cache even without SOA using tracker fallback"
    );
    let (data, _, _) = cached.unwrap();
    assert!(matches!(data, CachedData::NegativeResponse));
}
