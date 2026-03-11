use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::{FilteredResolver, QueryFilters};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

struct StubCacheResolver {
    entries: RwLock<HashMap<String, DnsResolution>>,
}

impl StubCacheResolver {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    fn insert(&self, domain: &str, resolution: DnsResolution) {
        self.entries
            .write()
            .unwrap()
            .insert(domain.to_string(), resolution);
    }
}

#[async_trait]
impl DnsResolver for StubCacheResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::NxDomain)
    }

    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.entries
            .read()
            .unwrap()
            .get(query.domain.as_ref())
            .cloned()
    }

    fn try_cache_str(&self, domain: &str, _record_type: RecordType) -> Option<DnsResolution> {
        self.entries.read().unwrap().get(domain).cloned()
    }
}

fn ip_resolution(addr: &str) -> DnsResolution {
    let ip: IpAddr = addr.parse().unwrap();
    DnsResolution::new(vec![ip], true)
}

fn passthrough_filters() -> QueryFilters {
    QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    }
}

// ── try_cache_str: basic hit/miss ─────────────────────────────────────────────

#[test]
fn try_cache_str_returns_none_on_cache_miss() {
    let inner = Arc::new(StubCacheResolver::new());
    let resolver = FilteredResolver::new(inner, passthrough_filters());

    assert!(resolver
        .try_cache_str("missing.example", RecordType::A)
        .is_none());
}

#[test]
fn try_cache_str_returns_hit_for_known_domain() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("google.com", ip_resolution("8.8.8.8"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        passthrough_filters(),
    );

    let result = resolver.try_cache_str("google.com", RecordType::A);
    assert!(result.is_some());
    let res = result.unwrap();
    assert!(res.cache_hit);
    assert_eq!(*res.addresses, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
}

// ── try_cache_str: private PTR filtering ──────────────────────────────────────

#[test]
fn try_cache_str_returns_none_for_private_ptr_when_blocked() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("1.10.0.10.in-addr.arpa", ip_resolution("10.0.10.1"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        QueryFilters {
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
            has_local_dns_server: false,
        },
    );

    assert!(
        resolver
            .try_cache_str("1.10.0.10.in-addr.arpa", RecordType::PTR)
            .is_none(),
        "private PTR must be blocked before reaching cache"
    );
}

#[test]
fn try_cache_str_allows_private_ptr_when_local_dns_server_configured() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("1.10.0.10.in-addr.arpa", ip_resolution("10.0.10.1"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        QueryFilters {
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
            has_local_dns_server: true,
        },
    );

    assert!(resolver
        .try_cache_str("1.10.0.10.in-addr.arpa", RecordType::PTR)
        .is_some());
}

// ── try_cache_str: local domain rewriting ─────────────────────────────────────

#[test]
fn try_cache_str_appends_local_domain_and_finds_rewritten_cache_entry() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("nas.lan", ip_resolution("192.168.1.5"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        QueryFilters {
            block_private_ptr: false,
            block_non_fqdn: false,
            local_domain: Some("lan".to_string()),
            has_local_dns_server: false,
        },
    );

    let result = resolver.try_cache_str("nas", RecordType::A);
    assert!(
        result.is_some(),
        "single-label domain must be rewritten to nas.lan and found in cache"
    );
    assert_eq!(
        *result.unwrap().addresses,
        vec!["192.168.1.5".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn try_cache_str_does_not_rewrite_fqdn_when_local_domain_configured() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("google.com", ip_resolution("8.8.8.8"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        QueryFilters {
            block_private_ptr: false,
            block_non_fqdn: false,
            local_domain: Some("lan".to_string()),
            has_local_dns_server: false,
        },
    );

    let result = resolver.try_cache_str("google.com", RecordType::A);
    assert!(result.is_some());
}

// ── try_cache_str and try_cache agree ────────────────────────────────────────

#[test]
fn try_cache_str_and_try_cache_return_equivalent_results_for_hit() {
    let inner = Arc::new(StubCacheResolver::new());
    inner.insert("example.com", ip_resolution("1.2.3.4"));
    let resolver = FilteredResolver::new(
        Arc::clone(&inner) as Arc<dyn DnsResolver>,
        passthrough_filters(),
    );

    let via_str = resolver.try_cache_str("example.com", RecordType::A);
    let query = DnsQuery::new("example.com", RecordType::A);
    let via_query = resolver.try_cache(&query);

    assert!(via_str.is_some());
    assert!(via_query.is_some());
    assert_eq!(via_str.unwrap().addresses, via_query.unwrap().addresses);
}
