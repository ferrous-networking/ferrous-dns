//! Phase 6: regression tests for the negative-cache poisoning bug.
//!
//! Before the fix, ANY `Err(_)` returned by the upstream resolver was
//! cached as a negative response via `insert_negative`. That meant a
//! single upstream timeout or "no healthy servers" would cause Ferrous
//! to serve fake NXDOMAIN to clients for the next 300–3600s — turning
//! transient instability into apparent permanent outage.
//!
//! The fix discriminates errors: only `DomainError::NxDomain` /
//! `DomainError::LocalNxDomain` populate the negative cache. Every other
//! variant (timeouts, transport failures, no healthy servers, malformed
//! responses, rate limits, etc.) bypasses the cache entirely so the next
//! query retries upstream.
//!
//! These tests drive a counting mock resolver that returns a configured
//! error on the first call and a success on any subsequent call. If the
//! negative cache was populated on the first failure, the second query
//! short-circuits and the mock is never called a second time — which is
//! the bug we are guarding against.

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Mock resolver that returns a queue of outcomes in order. Each call
/// pops the next outcome; once the queue is empty, subsequent calls
/// fall back to returning the same `default_response`.
struct ScriptedMockResolver {
    call_count: Arc<AtomicUsize>,
    script: Mutex<Vec<Result<DnsResolution, DomainError>>>,
    default_response: DnsResolution,
}

impl ScriptedMockResolver {
    fn new(script: Vec<Result<DnsResolution, DomainError>>, default_addr: &str) -> Self {
        let ip: IpAddr = default_addr.parse().unwrap();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            script: Mutex::new(script),
            default_response: DnsResolution::new(vec![ip], false),
        }
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for ScriptedMockResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let mut script = self.script.lock().unwrap();
        if script.is_empty() {
            Ok(self.default_response.clone())
        } else {
            script.remove(0)
        }
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

fn make_query(domain: &str) -> DnsQuery {
    DnsQuery {
        domain: Arc::from(domain),
        record_type: RecordType::A,
    }
}

fn make_resolver(mock: Arc<ScriptedMockResolver>, cache: Arc<DnsCache>) -> Arc<CachedResolver> {
    Arc::new(CachedResolver::new(
        mock as Arc<dyn DnsResolver>,
        cache as Arc<dyn DnsCacheAccess>,
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ))
}

/// QueryTimeout is the canonical transient error. The first resolve
/// returns a timeout; it must NOT be cached as NXDOMAIN. The second
/// resolve must therefore reach the upstream (call_count == 2) and,
/// given the scripted success, return real data.
#[tokio::test]
async fn should_not_cache_query_timeout_as_nxdomain() {
    let mock = Arc::new(ScriptedMockResolver::new(
        vec![Err(DomainError::QueryTimeout)],
        "10.0.0.1",
    ));
    let cache = make_cache();
    let resolver = make_resolver(Arc::clone(&mock), Arc::clone(&cache));

    // First call: upstream times out — must return error, must NOT poison cache.
    let first = resolver.resolve(&make_query("transient.example")).await;
    assert!(matches!(first, Err(DomainError::QueryTimeout)));

    // Second call: cache miss (timeout was not cached), upstream succeeds.
    let second = resolver
        .resolve(&make_query("transient.example"))
        .await
        .expect("second call must succeed with scripted fallback response");
    assert_eq!(
        second.addresses.as_ref(),
        &["10.0.0.1".parse::<IpAddr>().unwrap()]
    );

    assert_eq!(
        mock.call_count(),
        2,
        "second query MUST reach upstream — timeout was wrongly cached as NXDOMAIN otherwise"
    );

    let transient = cache
        .metrics()
        .transient_upstream_errors
        .load(Ordering::Relaxed);
    assert_eq!(
        transient, 1,
        "exactly one transient error must have been recorded"
    );
}

/// NxDomain is the one error that IS a legitimate negative answer.
/// It must populate the negative cache so a retry returns the cached
/// NXDOMAIN without bothering the upstream.
#[tokio::test]
async fn should_cache_nxdomain_correctly() {
    let mock = Arc::new(ScriptedMockResolver::new(
        vec![Err(DomainError::NxDomain)],
        "10.0.0.2",
    ));
    let cache = make_cache();
    let resolver = make_resolver(Arc::clone(&mock), Arc::clone(&cache));

    // First call: upstream returns NXDOMAIN — must be cached as negative.
    let first = resolver.resolve(&make_query("nonexistent.example")).await;
    assert!(matches!(first, Err(DomainError::NxDomain)));

    // Second call: cache hit on negative entry — upstream MUST NOT be called.
    let second = resolver.resolve(&make_query("nonexistent.example")).await;
    assert!(
        matches!(second, Err(DomainError::NxDomain)),
        "negative cache must surface NXDOMAIN on subsequent queries"
    );

    assert_eq!(
        mock.call_count(),
        1,
        "NXDOMAIN must be cached — second query should be served from the negative cache"
    );

    let transient = cache
        .metrics()
        .transient_upstream_errors
        .load(Ordering::Relaxed);
    assert_eq!(
        transient, 0,
        "NXDOMAIN is not a transient error; the counter must stay at zero"
    );
}

/// TransportNoHealthyServers is the upstream-pool equivalent of a
/// connection outage: zero servers are currently viable. This is a
/// textbook transient failure — caching it as NXDOMAIN would hand
/// clients fake negative answers for the whole upstream-recovery
/// window.
#[tokio::test]
async fn should_cache_no_healthy_servers_as_transient() {
    let mock = Arc::new(ScriptedMockResolver::new(
        vec![Err(DomainError::TransportNoHealthyServers)],
        "10.0.0.3",
    ));
    let cache = make_cache();
    let resolver = make_resolver(Arc::clone(&mock), Arc::clone(&cache));

    // First call: no healthy upstream — must NOT be cached.
    let first = resolver.resolve(&make_query("pool-down.example")).await;
    assert!(matches!(first, Err(DomainError::TransportNoHealthyServers)));

    // Second call: cache miss, scripted fallback returns successful data.
    let second = resolver
        .resolve(&make_query("pool-down.example"))
        .await
        .expect("second call must retry upstream after pool recovers");
    assert_eq!(
        second.addresses.as_ref(),
        &["10.0.0.3".parse::<IpAddr>().unwrap()]
    );

    assert_eq!(
        mock.call_count(),
        2,
        "second query MUST reach upstream — pool outage was wrongly cached otherwise"
    );

    let transient = cache
        .metrics()
        .transient_upstream_errors
        .load(Ordering::Relaxed);
    assert_eq!(
        transient, 1,
        "exactly one transient error must have been recorded"
    );
}
