//! `LocalWildcardResolver` — wildcard local DNS records (issue #223).
//!
//! The layer sits above the cache, so an exact record (which lives in the cache
//! as a permanent entry) has to keep winning, and a wildcard answer must never
//! be handed down for caching.

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    DnsResolution, DnsResolver, WildcardRecordRegistry, EMPTY_CNAME_CHAIN,
};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, RecordType};
use ferrous_dns_infrastructure::dns::resolver::{
    LocalWildcardResolver, WildcardMap, WildcardRegistry,
};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

fn record(hostname: &str, domain: &str, ip: &str, record_type: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: Some(domain.to_string()),
        ip: ip.to_string(),
        record_type: record_type.to_string(),
        ttl: Some(120),
    }
}

fn ip(value: &str) -> IpAddr {
    IpAddr::from_str(value).unwrap()
}

fn upstream_resolution() -> DnsResolution {
    DnsResolution {
        addresses: Arc::new(vec![ip("93.184.216.34")]),
        cache_hit: false,
        local_dns: false,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: Some(Arc::from("1.1.1.1:53")),
        upstream_pool: None,
        min_ttl: Some(300),
        negative_soa_ttl: None,
        upstream_wire_data: None,
    }
}

/// Stands in for the cache layer below the wildcard resolver.
#[derive(Default)]
struct MockInner {
    /// What `try_cache` hands back — the exact permanent records, in production.
    cached: Option<DnsResolution>,
    resolve_calls: Mutex<Vec<(String, RecordType)>>,
    try_cache_calls: Mutex<usize>,
}

impl MockInner {
    fn resolve_calls(&self) -> Vec<(String, RecordType)> {
        self.resolve_calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsResolver for MockInner {
    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        *self.try_cache_calls.lock().unwrap() += 1;
        self.cached.clone()
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.resolve_calls
            .lock()
            .unwrap()
            .push((query.domain.to_string(), query.record_type));
        Ok(upstream_resolution())
    }
}

fn resolver_with(records: &[LocalDnsRecord]) -> (LocalWildcardResolver, Arc<MockInner>) {
    let inner = Arc::new(MockInner::default());
    let map = LocalWildcardResolver::map_from_local_records(records, &None);
    (LocalWildcardResolver::new(inner.clone(), map), inner)
}

#[tokio::test]
async fn test_wildcard_answers_a_subdomain() {
    let (resolver, inner) = resolver_with(&[record("*", "home.lan", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("anything.home.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(resolution.addresses.as_ref(), &[ip("192.168.1.10")]);
    assert!(resolution.local_dns);
    assert_eq!(resolution.min_ttl, Some(120));
    assert!(inner.resolve_calls().is_empty());
}

#[tokio::test]
async fn test_wildcard_answers_a_deep_subdomain() {
    let (resolver, _inner) = resolver_with(&[record("*", "home.lan", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("a.b.c.home.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(resolution.addresses.as_ref(), &[ip("192.168.1.10")]);
}

#[tokio::test]
async fn test_wildcard_does_not_answer_the_apex() {
    let (resolver, inner) = resolver_with(&[record("*", "home.lan", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("home.lan", RecordType::A))
        .await
        .unwrap();

    assert!(!resolution.local_dns);
    assert_eq!(
        inner.resolve_calls(),
        vec![("home.lan".to_string(), RecordType::A)]
    );
}

#[tokio::test]
async fn test_longest_wildcard_wins() {
    let (resolver, _inner) = resolver_with(&[
        record("*", "home.lan", "192.168.1.10", "A"),
        record("*.dev", "home.lan", "192.168.1.20", "A"),
    ]);

    let broad = resolver
        .resolve(&DnsQuery::new("nas.home.lan", RecordType::A))
        .await
        .unwrap();
    assert_eq!(broad.addresses.as_ref(), &[ip("192.168.1.10")]);

    let specific = resolver
        .resolve(&DnsQuery::new("api.dev.home.lan", RecordType::A))
        .await
        .unwrap();
    assert_eq!(specific.addresses.as_ref(), &[ip("192.168.1.20")]);
}

#[tokio::test]
async fn test_exact_cached_record_beats_the_wildcard() {
    let inner = Arc::new(MockInner {
        cached: Some(DnsResolution {
            addresses: Arc::new(vec![ip("192.168.1.50")]),
            cache_hit: true,
            ..upstream_resolution()
        }),
        ..Default::default()
    });
    let map = LocalWildcardResolver::map_from_local_records(
        &[record("*", "home.lan", "192.168.1.10", "A")],
        &None,
    );
    let resolver = LocalWildcardResolver::new(inner.clone(), map);

    let resolution = resolver
        .resolve(&DnsQuery::new("nas.home.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(resolution.addresses.as_ref(), &[ip("192.168.1.50")]);
    assert!(resolution.cache_hit);
    assert!(inner.resolve_calls().is_empty());
}

#[tokio::test]
async fn test_negative_cache_entry_does_not_beat_the_wildcard() {
    let inner = Arc::new(MockInner {
        cached: Some(DnsResolution {
            addresses: Arc::new(vec![]),
            upstream_wire_data: None,
            ..upstream_resolution()
        }),
        ..Default::default()
    });
    let map = LocalWildcardResolver::map_from_local_records(
        &[record("*", "home.lan", "192.168.1.10", "A")],
        &None,
    );
    let resolver = LocalWildcardResolver::new(inner, map);

    let resolution = resolver
        .resolve(&DnsQuery::new("stale.home.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(resolution.addresses.as_ref(), &[ip("192.168.1.10")]);
}

#[tokio::test]
async fn test_uncovered_record_type_returns_nodata() {
    let (resolver, inner) = resolver_with(&[record("*", "home.lan", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("anything.home.lan", RecordType::AAAA))
        .await
        .unwrap();

    // Empty NOERROR: no addresses, no wire data for the server to relay, and
    // nothing asked upstream.
    assert!(resolution.addresses.is_empty());
    assert!(resolution.upstream_wire_data.is_none());
    assert!(resolution.local_dns);
    assert!(inner.resolve_calls().is_empty());
}

#[tokio::test]
async fn test_both_record_types_on_one_suffix() {
    let (resolver, _inner) = resolver_with(&[
        record("*", "home.lan", "192.168.1.10", "A"),
        record("*", "home.lan", "fd00::1", "AAAA"),
    ]);

    let v4 = resolver
        .resolve(&DnsQuery::new("host.home.lan", RecordType::A))
        .await
        .unwrap();
    let v6 = resolver
        .resolve(&DnsQuery::new("host.home.lan", RecordType::AAAA))
        .await
        .unwrap();

    assert_eq!(v4.addresses.as_ref(), &[ip("192.168.1.10")]);
    assert_eq!(v6.addresses.as_ref(), &[ip("fd00::1")]);
}

#[tokio::test]
async fn test_uncovered_name_passes_through() {
    let (resolver, inner) = resolver_with(&[record("*", "home.lan", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("example.com", RecordType::A))
        .await
        .unwrap();

    assert!(!resolution.local_dns);
    assert_eq!(
        inner.resolve_calls(),
        vec![("example.com".to_string(), RecordType::A)]
    );
}

#[tokio::test]
async fn test_empty_index_passes_through_without_probing_the_cache() {
    let (resolver, inner) = resolver_with(&[]);

    resolver
        .resolve(&DnsQuery::new("anything.home.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(*inner.try_cache_calls.lock().unwrap(), 0);
    assert_eq!(inner.resolve_calls().len(), 1);
}

#[tokio::test]
async fn test_query_name_case_is_ignored() {
    let (resolver, _inner) = resolver_with(&[record("*", "Home.LAN", "192.168.1.10", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("AnyThing.HOME.lan", RecordType::A))
        .await
        .unwrap();

    assert_eq!(resolution.addresses.as_ref(), &[ip("192.168.1.10")]);
}

#[tokio::test]
async fn test_record_type_and_ip_family_must_agree() {
    let (resolver, inner) = resolver_with(&[record("*", "home.lan", "fd00::1", "A")]);

    let resolution = resolver
        .resolve(&DnsQuery::new("anything.home.lan", RecordType::A))
        .await
        .unwrap();

    assert!(!resolution.local_dns);
    assert_eq!(inner.resolve_calls().len(), 1);
}

#[tokio::test]
async fn test_wildcard_without_a_domain_is_not_indexed() {
    let unanchored = LocalDnsRecord {
        hostname: "*".to_string(),
        domain: None,
        ip: "192.168.1.10".to_string(),
        record_type: "A".to_string(),
        ttl: None,
    };
    let map = LocalWildcardResolver::map_from_local_records(&[unanchored], &None);

    assert!(map.is_empty());
}

#[tokio::test]
async fn test_register_and_unregister_take_effect_live() {
    let inner = Arc::new(MockInner::default());
    let map: Arc<WildcardMap> = LocalWildcardResolver::map_from_local_records(&[], &None);
    let resolver = LocalWildcardResolver::new(inner.clone(), Arc::clone(&map));
    let registry = WildcardRegistry::new(Arc::clone(&map));

    registry.register("home.lan", RecordType::A, ip("192.168.1.10"), 60);

    let answered = resolver
        .resolve(&DnsQuery::new("nas.home.lan", RecordType::A))
        .await
        .unwrap();
    assert_eq!(answered.addresses.as_ref(), &[ip("192.168.1.10")]);
    assert_eq!(answered.min_ttl, Some(60));

    registry.unregister("home.lan", RecordType::A);
    assert!(map.is_empty());

    let passed_through = resolver
        .resolve(&DnsQuery::new("nas.home.lan", RecordType::A))
        .await
        .unwrap();
    assert!(!passed_through.local_dns);
}

#[tokio::test]
async fn test_unregister_one_type_keeps_the_other() {
    let map = LocalWildcardResolver::map_from_local_records(
        &[
            record("*", "home.lan", "192.168.1.10", "A"),
            record("*", "home.lan", "fd00::1", "AAAA"),
        ],
        &None,
    );
    let resolver = LocalWildcardResolver::new(Arc::new(MockInner::default()), Arc::clone(&map));
    let registry = WildcardRegistry::new(Arc::clone(&map));

    registry.unregister("home.lan", RecordType::A);

    assert!(!map.is_empty());
    let v6 = resolver
        .resolve(&DnsQuery::new("host.home.lan", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(v6.addresses.as_ref(), &[ip("fd00::1")]);

    let v4 = resolver
        .resolve(&DnsQuery::new("host.home.lan", RecordType::A))
        .await
        .unwrap();
    assert!(v4.addresses.is_empty());
    assert!(v4.local_dns);
}
