//! The refresh worker, end to end: timers armed by the cache, claimed as they
//! come due, and renewals run under the concurrency limit.
//!
//! Each entry arms its own timer, so it is renewed on time whatever its TTL.
//! A serve-stale repair never waits behind renewals, a timer that is no
//! longer the entry's spends no upstream query, hot entries go before cold
//! ones when renewals outnumber the permits, and nothing due is dropped by
//! policy.

#[path = "support/refresh.rs"]
mod refresh;

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::cache::{coarse_clock, CacheKey};
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
use ferrous_dns_infrastructure::dns::{
    CachedData, ColdThresholds, DnsCache, ScheduledRefresh, TimerKind,
};
use refresh::{
    address, cached_addresses, cname, no_ranking, refresh_cache, start_worker,
    start_worker_retrying_after, wait_until, NEW_IP, OLD_IP,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

fn create_cache_with(max_entries: usize, refresh_threshold: f64) -> Arc<DnsCache> {
    refresh_cache(max_entries, refresh_threshold, u64::MAX)
}

fn insert_entries(cache: &DnsCache, count: usize, ttl: u32) {
    for i in 0..count {
        cache.insert(
            &format!("queued-{i}.com"),
            RecordType::A,
            address(OLD_IP),
            ttl,
            None,
        );
    }
}

/// Records, in order, the domains it was asked for, with the coarse second
/// of each call, and answers with `NEW_IP` for `ttl` seconds.
struct RecordingResolver {
    calls: Mutex<Vec<(String, u64)>>,
    ttl: Option<u32>,
}

impl RecordingResolver {
    fn new(ttl: Option<u32>) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            ttl,
        })
    }

    fn count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn domains(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(domain, _)| domain.clone())
            .collect()
    }

    fn first_call_at(&self) -> Option<u64> {
        self.calls.lock().unwrap().first().map(|(_, at)| *at)
    }
}

#[async_trait]
impl DnsResolver for RecordingResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls
            .lock()
            .unwrap()
            .push((query.domain.to_string(), coarse_clock::coarse_now_secs()));
        Ok(DnsResolution {
            min_ttl: self.ttl,
            ..DnsResolution::new(vec![NEW_IP.parse().unwrap()], false)
        })
    }
}

/// A caching upstream near the end of its copy: answers `first_ttl` once,
/// then `then_ttl` after its copy rolled over.
struct RolloverResolver {
    calls: AtomicUsize,
    first_ttl: u32,
    then_ttl: u32,
}

impl RolloverResolver {
    fn new(first_ttl: u32, then_ttl: u32) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            first_ttl,
            then_ttl,
        })
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for RolloverResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let ttl = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first_ttl
        } else {
            self.then_ttl
        };
        Ok(DnsResolution {
            min_ttl: Some(ttl),
            ..DnsResolution::new(vec![NEW_IP.parse().unwrap()], false)
        })
    }
}

/// Fails every call with `error`, counting them.
struct FailingResolver {
    error: DomainError,
    calls: AtomicUsize,
}

impl FailingResolver {
    fn new(error: DomainError) -> Arc<Self> {
        Arc::new(Self {
            error,
            calls: AtomicUsize::new(0),
        })
    }

    fn count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl DnsResolver for FailingResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.error.clone())
    }
}

/// Records each call, then holds it until the test opens the gate once for
/// it, so the test controls when permits come free.
struct GatedResolver {
    calls: Mutex<Vec<String>>,
    gate: Semaphore,
}

#[async_trait]
impl DnsResolver for GatedResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls.lock().unwrap().push(query.domain.to_string());
        self.gate.acquire().await.unwrap().forget();
        Ok(DnsResolution::new(vec![NEW_IP.parse().unwrap()], false))
    }
}

// ── Renewing on time ────────────────────────────────────────────────────────

/// A TTL of a few seconds is renewed before it expires, not repaired after.
#[tokio::test]
async fn test_entry_is_renewed_before_it_expires() {
    let cache = create_cache_with(200, 0.75);
    let resolver = RecordingResolver::new(Some(3));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    coarse_clock::tick();
    let inserted_at = coarse_clock::coarse_now_secs();
    cache.insert("short.example", RecordType::A, address(OLD_IP), 3, None);

    assert!(
        wait_until(Duration::from_secs(5), || resolver.count() >= 1).await,
        "the entry must be renewed"
    );
    let renewed_at = resolver.first_call_at().unwrap();
    assert!(
        renewed_at < inserted_at + 3,
        "renewed at {renewed_at}, after it expired at {}",
        inserted_at + 3
    );
    assert_eq!(
        cached_addresses(&cache, "short.example"),
        Some(vec![NEW_IP.parse().unwrap()])
    );
    assert_eq!(
        cache.metrics().stale_hits.load(Ordering::Relaxed),
        0,
        "nothing was served stale"
    );
}

/// Asks for `domain` every `every` until `stop` is set, on a thread of its
/// own, the way a client keeps a name in use.
fn keep_asking(
    cache: &Arc<DnsCache>,
    domain: &'static str,
    every: Duration,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handle = std::thread::spawn({
        let cache = Arc::clone(cache);
        let stop = Arc::clone(&stop);
        move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = cache.get(domain, &RecordType::A);
                std::thread::sleep(every);
            }
        }
    });
    (stop, handle)
}

#[tokio::test]
async fn test_renewal_arms_the_next_renewal() {
    let cache = create_cache_with(200, 0.5);
    let resolver = RecordingResolver::new(Some(2));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("loop.example", RecordType::A, cname(), 2, None);
    let (stop, client) = keep_asking(&cache, "loop.example", Duration::from_millis(300));

    let renewed = wait_until(Duration::from_secs(6), || resolver.count() >= 3).await;
    stop.store(true, Ordering::Relaxed);
    client.join().unwrap();
    assert!(
        renewed,
        "each renewal must arm the next one while the name is in use; renewals={}",
        resolver.count()
    );
}

/// A TTL under a minute renews more than once a minute, so it is only
/// renewed while someone keeps asking for it. One hit must not keep a short
/// entry renewing for the whole access window.
#[tokio::test]
async fn test_short_ttl_stops_renewing_once_nobody_asks() {
    // TTL 4 at threshold 0.5: renewed 2 s in (the lifetime it was asked in),
    // due again 2 s after that, and still fresh when asked for again below.
    let cache = create_cache_with(200, 0.5);
    let resolver = RecordingResolver::new(Some(4));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("once.example", RecordType::A, cname(), 4, None);

    tokio::time::sleep(Duration::from_millis(5_500)).await;
    assert_eq!(
        resolver.count(),
        1,
        "the lifetime it was asked in is renewed, and then no more"
    );
    assert_eq!(cache.metrics().stale_hits.load(Ordering::Relaxed), 0);

    let (stop, client) = keep_asking(&cache, "once.example", Duration::from_millis(300));
    let resumed = wait_until(Duration::from_secs(4), || resolver.count() >= 2).await;
    stop.store(true, Ordering::Relaxed);
    client.join().unwrap();
    assert!(resumed, "asked for again, it is renewed again");
}

#[tokio::test]
async fn test_a_burst_of_due_entries_is_all_renewed() {
    let cache = create_cache_with(1_000, 0.0);
    let resolver = RecordingResolver::new(Some(300));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    insert_entries(&cache, 200, 300);

    assert!(
        wait_until(Duration::from_secs(5), || resolver.count() >= 200).await,
        "every due entry must be renewed; renewals={}",
        resolver.count()
    );
}

/// An entry idle past the access window is left to expire, and renewed again
/// as soon as it is used.
#[tokio::test]
async fn test_idle_entry_is_renewed_again_once_it_is_used() {
    // Due 4 s after insertion, with a 2 s window: idle by the time it is due.
    let cache = refresh_cache(200, 0.014, 2);
    let resolver = RecordingResolver::new(Some(300));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("idle.example", RecordType::A, cname(), 300, None);

    tokio::time::sleep(Duration::from_millis(5_200)).await;
    assert_eq!(resolver.count(), 0, "an idle entry must not be renewed");

    assert!(cache.get("idle.example", &RecordType::A).is_some());
    assert!(
        wait_until(Duration::from_secs(3), || resolver.count() >= 1).await,
        "back in use, the entry must be renewed again"
    );
}

#[tokio::test]
async fn test_timer_for_an_entry_not_yet_due_spends_no_query() {
    let cache = create_cache_with(200, 0.75);
    let resolver = RecordingResolver::new(None);
    let worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("later.example", RecordType::A, address(OLD_IP), 3600, None);
    let now = coarse_clock::coarse_now_secs();
    for domain in ["later.example", "missing.example"] {
        worker.timers.push(ScheduledRefresh {
            due_at_secs: now,
            key: CacheKey::new(domain, RecordType::A),
            kind: TimerKind::Due,
        });
    }

    tokio::time::sleep(Duration::from_millis(2_200)).await;

    assert_eq!(
        resolver.count(),
        0,
        "nothing due may cost an upstream query; calls={:?}",
        resolver.domains()
    );
}

/// A caching upstream answers with what is left of its own copy, and two
/// anycast nodes can be minutes apart: Cloudflare answered 560, 408 and then
/// 14 for the same name within six seconds. A renewal must not trade a valid
/// entry for a shorter-lived one. The entry is kept, and tried once more a
/// second before it expires, when the upstream's copy has rolled over.
#[tokio::test]
async fn test_renewal_never_shortens_a_valid_entry() {
    // TTL 6 at threshold 0.5: due 3 s in, with 3 s left; the upstream offers
    // 1 s, so it is declined and tried again 2 s later, with 1 s left, when
    // its copy has rolled over to 2 s.
    let cache = create_cache_with(200, 0.5);
    let resolver = RolloverResolver::new(1, 2);
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("anycast.example", RecordType::A, address(OLD_IP), 6, None);

    assert!(wait_until(Duration::from_secs(5), || resolver.count() >= 1).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cached_addresses(&cache, "anycast.example"),
        Some(vec![OLD_IP.parse().unwrap()]),
        "a 1 s answer must not replace an entry with 3 s left"
    );

    assert!(
        wait_until(Duration::from_secs(4), || resolver.count() >= 2).await,
        "the entry is tried once more before it expires"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        cached_addresses(&cache, "anycast.example"),
        Some(vec![NEW_IP.parse().unwrap()]),
        "the copy that rolled over extends it, so it is taken"
    );
    assert_eq!(
        cache.metrics().stale_hits.load(Ordering::Relaxed),
        0,
        "the entry never went stale"
    );
}

/// An upstream that keeps answering with nothing to extend the entry gets a
/// second chance before expiry and a last one at expiry, which takes any
/// answer; after that nothing more is asked.
#[tokio::test]
async fn test_declined_renewal_is_settled_by_expiry() {
    // TTL 10 at 0.5: due at +5 with 5 s left, offered 0 s: declined; again
    // at +9 with 1 s left: declined; at +10 the TTL 0 answer is taken.
    let cache = create_cache_with(200, 0.5);
    let resolver = RecordingResolver::new(Some(0));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    cache.insert("stingy.example", RecordType::A, address(OLD_IP), 10, None);

    assert!(wait_until(Duration::from_secs(13), || resolver.count() >= 3).await);
    tokio::time::sleep(Duration::from_millis(3_000)).await;
    assert_eq!(
        resolver.count(),
        3,
        "declined twice, taken at expiry, and then left alone"
    );
}

// ── Failures ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_every_upstream_servfailing_gets_exactly_one_retry() {
    let cache = create_cache_with(200, 0.0);
    let resolver = FailingResolver::new(DomainError::AllUpstreamsServfail);
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    // Due a second in; the retry lands halfway through the 7 s left.
    cache.insert("flaky.example", RecordType::A, address(OLD_IP), 8, None);

    assert!(
        wait_until(Duration::from_secs(6), || resolver.count() >= 2).await,
        "a SERVFAIL from every upstream must be retried; calls={}",
        resolver.count()
    );
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(resolver.count(), 2, "and retried once only");
    assert_eq!(
        cached_addresses(&cache, "flaky.example"),
        Some(vec![OLD_IP.parse().unwrap()]),
        "the cached answer keeps serving"
    );
}

/// A renewal that failed with no retry of its own waits
/// `cache_compaction_interval` for its next try: never one per hit.
#[tokio::test]
async fn test_other_failures_wait_the_compaction_interval_to_retry() {
    let cache = create_cache_with(200, 0.0);
    let resolver = FailingResolver::new(DomainError::TransportTimeout {
        server: "udp://192.0.2.53:53".into(),
    });
    let _worker = start_worker_retrying_after(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
        5,
    );
    cache.insert("slow.example", RecordType::A, cname(), 300, None);

    assert!(wait_until(Duration::from_secs(4), || resolver.count() >= 1).await);
    tokio::time::sleep(Duration::from_millis(2_200)).await;
    assert_eq!(resolver.count(), 1, "a timeout is not retried at once");
    // Nor by the clients asking for it.
    for _ in 0..5 {
        assert!(cache.get("slow.example", &RecordType::A).is_some());
    }
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert_eq!(
        resolver.count(),
        1,
        "a hit must not retry a failing renewal"
    );

    assert!(
        wait_until(Duration::from_secs(4), || resolver.count() >= 2).await,
        "the compaction interval later it gets another try"
    );
}

// ── Order and priority ──────────────────────────────────────────────────────

/// With every permit taken by renewals, a serve-stale repair still goes
/// before the renewals waiting behind them.
#[tokio::test]
async fn test_stale_repair_goes_ahead_of_due_backlog() {
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(GatedResolver {
        calls: Mutex::new(Vec::new()),
        gate: Semaphore::new(0),
    });
    let worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        true,
    );
    insert_entries(&cache, 20, 300);

    let calls = || resolver.calls.lock().unwrap().len();
    assert!(
        wait_until(Duration::from_secs(4), || calls() == 16).await,
        "16 renewals take every permit; calls={}",
        calls()
    );
    worker
        .stale
        .send((Arc::from("urgent.example"), RecordType::A, 0))
        .await
        .unwrap();
    // The worker has taken the repair off the queue before a permit frees.
    assert!(wait_until(Duration::from_secs(2), || worker.stale.capacity() == 128).await);
    resolver.gate.add_permits(1);

    assert!(wait_until(Duration::from_secs(2), || calls() >= 17).await);
    assert_eq!(
        resolver.calls.lock().unwrap()[16],
        "urgent.example",
        "the freed permit must go to the waiting client's repair"
    );
    resolver.gate.add_permits(64);
}

/// When more entries fall due together than there are permits, the hot ones
/// start first, and the cold ones are still renewed after.
#[tokio::test]
async fn test_due_backlog_starts_hot_entries_first() {
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(GatedResolver {
        calls: Mutex::new(Vec::new()),
        gate: Semaphore::new(0),
    });
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        ColdThresholds {
            min_hit_rate: 0.0,
            min_frequency: 3,
        },
        true,
    );
    coarse_clock::tick();
    // 36 entries fall due in the same second, for 16 permits; 10 are hot.
    let hot: Vec<String> = (0..10).map(|i| format!("hot-{i}.example")).collect();
    let cold: Vec<String> = (0..26).map(|i| format!("cold-{i}.example")).collect();
    for domain in cold.iter().chain(hot.iter()) {
        cache.insert(domain, RecordType::A, cname(), 300, None);
    }
    for domain in &hot {
        for _ in 0..5 {
            assert!(cache.get(domain, &RecordType::A).is_some());
        }
    }
    let calls = || resolver.calls.lock().unwrap().len();
    assert!(
        wait_until(Duration::from_secs(4), || calls() == 16).await,
        "16 renewals take every permit; calls={}",
        calls()
    );
    let started: Vec<String> = resolver.calls.lock().unwrap().clone();
    assert!(
        started[..10].iter().all(|domain| hot.contains(domain)),
        "the hot entries must take the first permits; order={started:?}"
    );

    resolver.gate.add_permits(64);

    assert!(
        wait_until(Duration::from_secs(4), || calls() >= 36).await,
        "cold entries are renewed too, only later; calls={}",
        calls()
    );
}

// ── Optimistic refresh off ──────────────────────────────────────────────────

#[tokio::test]
async fn test_stale_repair_runs_with_optimistic_refresh_off() {
    let cache = create_cache_with(200, 0.0);
    let resolver = RecordingResolver::new(Some(300));
    let _worker = start_worker(
        &cache,
        resolver.clone() as Arc<dyn DnsResolver>,
        no_ranking(),
        false,
    );
    // TTL 3 (grace 6 s): the coarse clock moves in whole seconds, so a 2 s
    // grace leaves no margin after the sleep.
    cache.insert("plain.example", RecordType::A, cname(), 3, None);

    tokio::time::sleep(Duration::from_millis(3_200)).await;
    coarse_clock::tick();
    assert_eq!(resolver.count(), 0, "nothing is renewed ahead of expiry");

    assert!(cache.get("plain.example", &RecordType::A).is_some());
    assert!(
        wait_until(Duration::from_secs(2), || resolver.count() >= 1).await,
        "the stale hit must still be repaired"
    );
}

// ── What a renewal stores ───────────────────────────────────────────────────

/// Answers every refresh with a DNSSEC-Bogus resolution.
struct BogusResolver;

#[async_trait]
impl DnsResolver for BogusResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Ok(DnsResolution {
            dnssec_status: Some(ferrous_dns_domain::DnssecStatus::Bogus),
            ..DnsResolution::new(vec!["203.0.113.66".parse().unwrap()], false)
        })
    }
}

/// Runs one serve-stale repair of `queued-0.com` A against `resolver`.
async fn repair(cache: &Arc<DnsCache>, resolver: Arc<dyn DnsResolver>) {
    let worker = start_worker(cache, resolver, no_ranking(), false);
    worker
        .stale
        .send((Arc::from("queued-0.com"), RecordType::A, 0))
        .await
        .expect("send failed");
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// A refresh that validates as Bogus must not renew the entry with the Bogus
/// answer: cache hits skip DNSSEC enforcement, so Strict mode would serve it.
#[tokio::test]
async fn test_bogus_refresh_drops_the_entry_instead_of_renewing_it() {
    let cache = create_cache_with(200, 0.0);
    insert_entries(&cache, 1, 300);

    repair(&cache, Arc::new(BogusResolver)).await;

    assert!(
        cached_addresses(&cache, "queued-0.com").is_none(),
        "the Bogus answer must not be cached"
    );
}

/// Answers every refresh with a resolution the validator could not finish,
/// as when the DS or DNSKEY lookups behind it time out.
struct IndeterminateResolver;

#[async_trait]
impl DnsResolver for IndeterminateResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Ok(DnsResolution {
            dnssec_status: Some(ferrous_dns_domain::DnssecStatus::Indeterminate),
            ..DnsResolution::new(vec!["203.0.113.66".parse().unwrap()], false)
        })
    }
}

/// An Indeterminate refresh is a validation that could not run, not a
/// verdict on the zone. The entry validated when it was stored keeps serving
/// until its own TTL ends, and the unvalidated answer does not replace it.
#[tokio::test]
async fn test_indeterminate_refresh_keeps_the_validated_entry() {
    let cache = create_cache_with(200, 0.0);
    insert_entries(&cache, 1, 300);

    repair(&cache, Arc::new(IndeterminateResolver)).await;

    assert_eq!(
        cached_addresses(&cache, "queued-0.com"),
        Some(vec![OLD_IP.parse::<IpAddr>().unwrap()]),
        "the validated entry must survive an Indeterminate refresh, unchanged"
    );
}

/// An upstream NXDOMAIN for `domain`, with an SOA whose negative TTL is
/// `soa_ttl`, as the pool path receives it.
fn nxdomain_wire(domain: &str, soa_ttl: u32) -> Bytes {
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{Name, RData, Record, RecordType as WireType};
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;

    let mut msg = Message::new(0x4242, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NXDomain;
    msg.add_query(Query::query(
        Name::from_str(&format!("{domain}.")).unwrap(),
        WireType::A,
    ));
    let soa = SOA::new(
        Name::from_str("ns1.com.").unwrap(),
        Name::from_str("hostmaster.com.").unwrap(),
        1,
        3600,
        900,
        604_800,
        soa_ttl,
    );
    msg.add_authorities(vec![Record::from_rdata(
        Name::from_str("com.").unwrap(),
        soa_ttl,
        RData::SOA(soa),
    )]);
    Bytes::from(msg.to_bytes().unwrap())
}

/// Answers every refresh with fixed upstream wire, parsed as `CoreResolver` does.
struct WireResolver(Bytes);

#[async_trait]
impl DnsResolver for WireResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let response = ResponseParser::parse_bytes(self.0.clone())?;
        Ok(DnsResolution {
            min_ttl: response.min_ttl,
            negative_soa_ttl: response.negative_soa_ttl,
            upstream_wire_data: Some(response.raw_bytes),
            ..DnsResolution::new(response.addresses, false)
        })
    }
}

/// Runs one serve-stale repair of `queued-0.com` A against `resolver` and
/// returns the entry's data and remaining TTL, read on a fresh thread so the
/// test thread's L1 copy cannot answer.
async fn ttl_after_repair(cache: &Arc<DnsCache>, resolver: WireResolver) -> (CachedData, u32) {
    repair(cache, Arc::new(resolver)).await;

    let (data, _, remaining_ttl, _) = std::thread::spawn({
        let cache = Arc::clone(cache);
        move || cache.get("queued-0.com", &RecordType::A)
    })
    .join()
    .unwrap()
    .expect("the renewed entry should be cached");
    (data, remaining_ttl.unwrap_or(0))
}

/// A name that stopped existing is renewed for the negative TTL, not
/// for the hours its positive answer had.
#[tokio::test]
async fn test_refresh_into_nxdomain_takes_the_negative_ttl() {
    let cache = create_cache_with(200, 0.0);
    cache.insert(
        "queued-0.com",
        RecordType::A,
        address("1.2.3.4"),
        7_200,
        None,
    );

    let (data, ttl) =
        ttl_after_repair(&cache, WireResolver(nxdomain_wire("queued-0.com", 60))).await;

    assert!(matches!(data, CachedData::WireData(_)), "got {data:?}");
    assert!(
        (290..=300).contains(&ttl),
        "an NXDOMAIN renewal takes the negative TTL, got {ttl}"
    );
}

/// A cached NXDOMAIN is renewed for the SOA's current negative TTL.
#[tokio::test]
async fn test_negative_entry_renewal_follows_the_new_soa_ttl() {
    let cache = create_cache_with(200, 0.0);
    cache.insert(
        "queued-0.com",
        RecordType::A,
        CachedData::WireData(nxdomain_wire("queued-0.com", 300)),
        300,
        None,
    );

    let (_, ttl) =
        ttl_after_repair(&cache, WireResolver(nxdomain_wire("queued-0.com", 86_400))).await;

    assert!(
        (3590..=3600).contains(&ttl),
        "the renewal follows the new SOA, capped at 3600; got {ttl}"
    );
}
