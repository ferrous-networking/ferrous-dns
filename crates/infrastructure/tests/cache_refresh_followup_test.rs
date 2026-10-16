//! What a renewal that did not renew the entry leaves behind: at most one
//! more attempt, and never a loop of them.

#[path = "support/refresh.rs"]
mod refresh;

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::DnsCache;
use refresh::{address, no_ranking, refresh_cache, start_worker, wait_until, OLD_IP};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The shipped defaults where they matter: a 2 h access window and
/// `cache_min_ttl = 0`.
fn cache(refresh_threshold: f64) -> Arc<DnsCache> {
    refresh_cache(200, refresh_threshold, 7_200)
}

fn start(cache: &Arc<DnsCache>, resolver: Arc<dyn DnsResolver>) {
    start_worker(cache, resolver, no_ranking(), true);
}

/// Answers every query with one address and a fixed TTL, recording the
/// coarse second of each call.
struct FixedTtlResolver {
    ttl: u32,
    calls: Mutex<Vec<u64>>,
}

impl FixedTtlResolver {
    fn new(ttl: u32) -> Arc<Self> {
        Arc::new(Self {
            ttl,
            calls: Mutex::new(Vec::new()),
        })
    }

    /// Seconds after `since` of each call so far.
    fn calls_since(&self, since: u64) -> Vec<u64> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|at| at - since)
            .collect()
    }
}

#[async_trait]
impl DnsResolver for FixedTtlResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls
            .lock()
            .unwrap()
            .push(coarse_clock::coarse_now_secs());
        Ok(DnsResolution {
            min_ttl: Some(self.ttl),
            ..DnsResolution::new(vec!["192.0.2.2".parse().unwrap()], false)
        })
    }
}

/// An upstream that answers TTL 0 must not keep the worker querying it every
/// second once the entry expires, with no client asking.
#[tokio::test]
async fn test_ttl_zero_answers_do_not_requery_upstream_every_second() {
    let cache = cache(0.5);
    let resolver = FixedTtlResolver::new(0);
    start(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    // Due at +2, expires at +4, stale grace ends at +8.
    cache.insert("zero.example", RecordType::A, address(OLD_IP), 4, None);

    tokio::time::sleep(Duration::from_millis(9_500)).await;

    let calls = resolver.calls_since(inserted);
    assert!(
        calls.len() <= 3 && calls.iter().all(|&at| at <= 4),
        "at most three attempts, none past expiry at +4; got calls at {calls:?}"
    );
}

/// A caching upstream whose copy ends when the entry's does keeps offering
/// what is left of it, and only rolls over at expiry. The entry must then be
/// renewed at expiry, not left to go stale until a client asks for it.
#[tokio::test]
async fn test_twice_declined_renewal_is_renewed_at_expiry() {
    let cache = cache(0.5);
    let resolver = SameCopyResolver::new();
    start(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    resolver.expires_at.store(inserted + 10, Ordering::SeqCst);
    // Due at +5 with 5 s left, offered 5: declined. Tried again at +9 with
    // 1 s left, offered 1: declined. Renewed at +10.
    cache.insert(
        "same-copy.example",
        RecordType::A,
        address(OLD_IP),
        10,
        None,
    );

    assert!(
        wait_until(Duration::from_secs(14), || resolver.calls() >= 3).await,
        "the entry must be renewed at expiry; calls={}",
        resolver.calls()
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cache.metrics().optimistic_refreshes.load(Ordering::Relaxed),
        1,
        "the third attempt, at expiry, stores the answer"
    );
    tokio::time::sleep(Duration::from_millis(2_000)).await;
    assert_eq!(resolver.calls(), 3, "and nothing more is asked");
}

/// Answers with the copy a caching upstream holds until `expires_at`: what is
/// left of it before then, a fresh 300 s copy from then on.
struct SameCopyResolver {
    expires_at: AtomicU64,
    calls: AtomicUsize,
}

impl SameCopyResolver {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            expires_at: AtomicU64::new(0),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for SameCopyResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = coarse_clock::coarse_now_secs();
        let expires_at = self.expires_at.load(Ordering::SeqCst);
        let ttl = if now < expires_at {
            (expires_at - now) as u32
        } else {
            300
        };
        Ok(DnsResolution {
            min_ttl: Some(ttl),
            ..DnsResolution::new(vec!["192.0.2.2".parse().unwrap()], false)
        })
    }
}

/// Past expiry any answer beats the stale one, so a renewal then stores even
/// an answer that ends no later; only a live entry declines one.
#[tokio::test]
async fn test_renewal_of_an_expired_entry_stores_any_answer() {
    // TTL 3 at threshold 1.0 with the 60 s lead out of reach: due at +3,
    // the second it expires.
    let cache = cache(1.0);
    let resolver = FixedTtlResolver::new(0);
    start(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    cache.insert("expired.example", RecordType::A, address(OLD_IP), 3, None);

    assert!(
        wait_until(Duration::from_secs(6), || !resolver
            .calls_since(inserted)
            .is_empty())
        .await
    );
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        cache.metrics().optimistic_refreshes.load(Ordering::Relaxed),
        1,
        "the TTL 0 answer was stored, not declined; calls at {:?}",
        resolver.calls_since(inserted)
    );
}

/// A declined renewal gets its one more attempt and nothing else: no other
/// timer re-queries it before then.
#[tokio::test]
async fn test_a_declined_renewal_is_not_requeried_before_its_retry() {
    let cache = cache(0.5);
    let resolver = FixedTtlResolver::new(1);
    start(&cache, resolver.clone() as Arc<dyn DnsResolver>);
    coarse_clock::tick();
    let inserted = coarse_clock::coarse_now_secs();
    // Due at +5 with 5 s left; the upstream offers 1 s, so it is declined.
    cache.insert("declined.example", RecordType::A, address(OLD_IP), 10, None);

    assert!(
        wait_until(Duration::from_secs(8), || !resolver
            .calls_since(inserted)
            .is_empty())
        .await
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    let requeried = wait_until(Duration::from_millis(2_500), || {
        resolver.calls_since(inserted).len() >= 2
    })
    .await;

    assert!(
        !requeried,
        "a declined renewal was re-queried before its retry; calls at {:?}",
        resolver.calls_since(inserted)
    );
}
