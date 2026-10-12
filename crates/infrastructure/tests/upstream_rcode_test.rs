//! An upstream that answers SERVFAIL, REFUSED or any other error rcode has
//! declined the question, not answered it. Such a reply must send the pool to
//! its next server, never win a `Parallel` race, never be cached, and never
//! replace a cached answer during a refresh. NXDOMAIN is an answer and stays
//! one.

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::cache::{coarse_clock, CacheKey};
use ferrous_dns_infrastructure::dns::resolver::{CachedResolver, CoreResolver};
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheAccess, DnsCacheConfig, DnsCacheMaintenance,
    EvictionStrategy, PoolManager, RefreshPriority, RefreshRequest, ScheduledRefresh, TimerInbox,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const DOMAIN: &str = "example.com";
const OLD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const TIMEOUT_MS: u64 = 2_000;

/// What a responder sends back: its rcode, an optional A record, an optional
/// SOA in the authority section, and how long it waits before replying.
#[derive(Clone, Copy)]
struct Behavior {
    rcode: ResponseCode,
    answer: Option<Ipv4Addr>,
    soa: bool,
    delay: Duration,
}

impl Behavior {
    fn rcode(rcode: ResponseCode) -> Self {
        Self {
            rcode,
            answer: None,
            soa: false,
            delay: Duration::ZERO,
        }
    }

    fn answer(ip: Ipv4Addr) -> Self {
        Self {
            answer: Some(ip),
            ..Self::rcode(ResponseCode::NoError)
        }
    }

    fn nxdomain() -> Self {
        Self {
            soa: true,
            ..Self::rcode(ResponseCode::NXDomain)
        }
    }

    fn after(self, delay: Duration) -> Self {
        Self { delay, ..self }
    }
}

/// A UDP upstream whose behavior can be switched mid-test, counting every
/// query it answers.
struct Responder {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    behavior: Arc<Mutex<Behavior>>,
}

impl Responder {
    async fn spawn(behavior: Behavior) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let queries = Arc::new(AtomicUsize::new(0));
        let behavior = Arc::new(Mutex::new(behavior));
        let (counter, current) = (Arc::clone(&queries), Arc::clone(&behavior));
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let b = *current.lock().unwrap();
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(b.delay).await;
                    let _ = socket.send_to(&reply(&req, b), peer).await;
                });
            }
        });
        Self {
            addr,
            queries,
            behavior,
        }
    }

    fn url(&self) -> String {
        format!("udp://{}", self.addr)
    }

    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    fn set(&self, behavior: Behavior) {
        *self.behavior.lock().unwrap() = behavior;
    }
}

fn reply(req: &Message, b: Behavior) -> Vec<u8> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = b.rcode;
    for q in &req.queries {
        resp.add_query(q.clone());
        if let Some(ip) = b.answer {
            resp.add_answer(Record::from_rdata(q.name().clone(), 300, RData::A(A(ip))));
        }
    }
    if b.soa {
        let zone = Name::from_str("example.com.").unwrap();
        let soa = SOA::new(
            Name::from_str("ns1.example.com.").unwrap(),
            Name::from_str("hostmaster.example.com.").unwrap(),
            1,
            3600,
            900,
            604_800,
            60,
        );
        resp.add_authorities(vec![Record::from_rdata(zone, 60, RData::SOA(soa))]);
    }
    resp.to_bytes().unwrap()
}

fn pool(
    name: &str,
    strategy: UpstreamStrategy,
    priority: u8,
    servers: &[&Responder],
) -> UpstreamPool {
    UpstreamPool {
        name: name.into(),
        strategy,
        priority,
        servers: servers.iter().map(|r| r.url()).collect(),
        weight: None,
    }
}

async fn manager(pools: Vec<UpstreamPool>) -> Arc<PoolManager> {
    Arc::new(PoolManager::new(pools, None).await.unwrap())
}

async fn query_a(pm: &PoolManager) -> Result<Vec<IpAddr>, DomainError> {
    let domain: Arc<str> = Arc::from(DOMAIN);
    pm.query(&domain, &RecordType::A, TIMEOUT_MS, false)
        .await
        .map(|r| r.response.addresses)
}

// ── S1–S8: classification on the pool path ──────────────────────────────────

/// S1. A lone server that declines the question leaves nothing to answer with.
#[tokio::test]
async fn error_rcode_from_the_only_server_is_an_error() {
    for rcode in [
        ResponseCode::ServFail,
        ResponseCode::Refused,
        ResponseCode::NotImp,
        ResponseCode::FormErr,
    ] {
        let up = Responder::spawn(Behavior::rcode(rcode)).await;
        let pm = manager(vec![pool("only", UpstreamStrategy::Failover, 1, &[&up])]).await;
        let result = query_a(&pm).await;
        assert!(
            result.is_err(),
            "{rcode:?} must not be an answer: {result:?}"
        );
    }
}

/// S2.
#[tokio::test]
async fn failover_moves_past_a_refusing_server() {
    let refusing = Responder::spawn(Behavior::rcode(ResponseCode::Refused)).await;
    let good = Responder::spawn(Behavior::answer(NEW_IP)).await;
    let pm = manager(vec![pool(
        "failover",
        UpstreamStrategy::Failover,
        1,
        &[&refusing, &good],
    )])
    .await;

    assert_eq!(query_a(&pm).await.unwrap(), vec![IpAddr::V4(NEW_IP)]);
    assert_eq!(good.queries(), 1);
}

/// S3. Round-robin starts at a different server each time, so every start
/// position is exercised.
#[tokio::test]
async fn balanced_skips_a_servfailing_server() {
    let failing = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let good = Responder::spawn(Behavior::answer(NEW_IP)).await;
    let pm = manager(vec![pool(
        "balanced",
        UpstreamStrategy::Balanced,
        1,
        &[&failing, &good],
    )])
    .await;

    for attempt in 0..4 {
        let result = query_a(&pm).await;
        assert_eq!(
            result.ok(),
            Some(vec![IpAddr::V4(NEW_IP)]),
            "attempt {attempt}: the SERVFAIL server must be skipped"
        );
    }
}

/// S4. Two servers race in the dedicated two-future arm.
#[tokio::test]
async fn parallel_pair_prefers_a_slower_answer_over_a_fast_servfail() {
    let fast_fail = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let slow_good =
        Responder::spawn(Behavior::answer(NEW_IP).after(Duration::from_millis(100))).await;
    let pm = manager(vec![pool(
        "parallel",
        UpstreamStrategy::Parallel,
        1,
        &[&fast_fail, &slow_good],
    )])
    .await;

    assert_eq!(query_a(&pm).await.unwrap(), vec![IpAddr::V4(NEW_IP)]);
}

/// S5. Three or more servers race through `FuturesUnordered`.
#[tokio::test]
async fn parallel_group_prefers_a_slower_answer_over_fast_servfails() {
    let fail_a = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let fail_b = Responder::spawn(Behavior::rcode(ResponseCode::Refused)).await;
    let slow_good =
        Responder::spawn(Behavior::answer(NEW_IP).after(Duration::from_millis(100))).await;
    let pm = manager(vec![pool(
        "parallel",
        UpstreamStrategy::Parallel,
        1,
        &[&fail_a, &fail_b, &slow_good],
    )])
    .await;

    assert_eq!(query_a(&pm).await.unwrap(), vec![IpAddr::V4(NEW_IP)]);
}

/// S6. A pool whose every server declines falls through to the next pool.
#[tokio::test]
async fn servfailing_pool_falls_through_to_the_next_pool() {
    let failing = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let good = Responder::spawn(Behavior::answer(NEW_IP)).await;
    let pm = manager(vec![
        pool("primary", UpstreamStrategy::Failover, 1, &[&failing]),
        pool("fallback", UpstreamStrategy::Failover, 2, &[&good]),
    ])
    .await;

    assert_eq!(query_a(&pm).await.unwrap(), vec![IpAddr::V4(NEW_IP)]);
    assert_eq!(
        failing.queries(),
        1,
        "the primary pool is still tried first"
    );
}

/// S7. Every pool declining with SERVFAIL is told apart from an unreachable
/// upstream, so a refresh can retry it.
#[tokio::test]
async fn every_pool_servfailing_is_distinguishable() {
    let first = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let second = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let pm = manager(vec![
        pool("primary", UpstreamStrategy::Failover, 1, &[&first]),
        pool("fallback", UpstreamStrategy::Failover, 2, &[&second]),
    ])
    .await;

    let result = query_a(&pm).await;
    assert!(
        matches!(result, Err(DomainError::AllUpstreamsServfail)),
        "got {result:?}"
    );
    assert_eq!(second.queries(), 1, "the fallback pool must be tried");
}

/// S7b. Guard: a SERVFAIL next to a timeout is not "every upstream answered
/// SERVFAIL", so it stays an unreachable upstream.
#[tokio::test]
async fn servfail_and_timeout_across_pools_stays_unreachable() {
    let failing = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let silent =
        Responder::spawn(Behavior::answer(NEW_IP).after(Duration::from_millis(TIMEOUT_MS + 1_000)))
            .await;
    let pm = manager(vec![
        pool("primary", UpstreamStrategy::Failover, 1, &[&failing]),
        pool("fallback", UpstreamStrategy::Failover, 2, &[&silent]),
    ])
    .await;

    let result = query_a(&pm).await;
    assert!(
        matches!(result, Err(DomainError::TransportAllServersUnreachable)),
        "got {result:?}"
    );
}

/// S7c. Inside one pool, every strategy reports SERVFAIL from all of its
/// servers as such, and anything else mixed in as an unreachable upstream.
#[tokio::test]
async fn every_strategy_reports_servfail_only_when_every_server_answered_it() {
    let cases: [(UpstreamStrategy, &[ResponseCode], bool); 8] = [
        (
            UpstreamStrategy::Failover,
            &[ResponseCode::ServFail, ResponseCode::ServFail],
            true,
        ),
        (
            UpstreamStrategy::Failover,
            &[ResponseCode::ServFail, ResponseCode::Refused],
            false,
        ),
        (
            UpstreamStrategy::Balanced,
            &[ResponseCode::ServFail, ResponseCode::ServFail],
            true,
        ),
        (
            UpstreamStrategy::Balanced,
            &[ResponseCode::Refused, ResponseCode::ServFail],
            false,
        ),
        (
            UpstreamStrategy::Parallel,
            &[ResponseCode::ServFail, ResponseCode::ServFail],
            true,
        ),
        (
            UpstreamStrategy::Parallel,
            &[ResponseCode::ServFail, ResponseCode::Refused],
            false,
        ),
        (
            UpstreamStrategy::Parallel,
            &[
                ResponseCode::ServFail,
                ResponseCode::ServFail,
                ResponseCode::ServFail,
            ],
            true,
        ),
        (
            UpstreamStrategy::Parallel,
            &[
                ResponseCode::ServFail,
                ResponseCode::Refused,
                ResponseCode::ServFail,
            ],
            false,
        ),
    ];
    for (strategy, rcodes, servfail) in cases {
        let mut servers = Vec::new();
        for rcode in rcodes {
            servers.push(Responder::spawn(Behavior::rcode(*rcode)).await);
        }
        let refs: Vec<&Responder> = servers.iter().collect();
        let pm = manager(vec![pool("only", strategy, 1, &refs)]).await;

        let result = query_a(&pm).await;
        if servfail {
            assert!(
                matches!(result, Err(DomainError::AllUpstreamsServfail)),
                "{strategy:?} {rcodes:?}: got {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(DomainError::TransportAllServersUnreachable)),
                "{strategy:?} {rcodes:?}: got {result:?}"
            );
        }
    }
}

/// S8. Guard: NXDOMAIN is the server's answer, so there is nothing to fail
/// over from.
#[tokio::test]
async fn nxdomain_is_an_answer_and_does_not_fail_over() {
    let nx = Responder::spawn(Behavior::nxdomain()).await;
    let other = Responder::spawn(Behavior::answer(NEW_IP)).await;
    let pm = manager(vec![pool(
        "failover",
        UpstreamStrategy::Failover,
        1,
        &[&nx, &other],
    )])
    .await;

    let domain: Arc<str> = Arc::from(DOMAIN);
    let result = pm
        .query(&domain, &RecordType::A, TIMEOUT_MS, false)
        .await
        .expect("NXDOMAIN must be returned as an answer");
    assert_eq!(result.response.rcode, ResponseCode::NXDomain);
    assert_eq!(result.response.negative_soa_ttl, Some(60));
    assert_eq!(other.queries(), 0, "an NXDOMAIN must not fail over");
}

// ── S9–S12: the cache and the refresh worker over a declining upstream ──────

fn create_cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.0,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: u64::MAX,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

fn insert_ip(cache: &DnsCache, ip: Ipv4Addr) {
    cache.insert(
        DOMAIN,
        RecordType::A,
        CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![IpAddr::V4(ip)]),
        }),
        300,
        None,
    );
}

/// What L2 holds for the test domain. Read on a fresh thread: L1 is
/// thread-local, and the test thread's copy would hide what L2 holds.
fn cached_addresses(cache: &Arc<DnsCache>) -> Option<Vec<IpAddr>> {
    let cache = Arc::clone(cache);
    std::thread::spawn(move || {
        cache
            .get(DOMAIN, &RecordType::A)
            .map(|(data, _, _, _)| match data {
                CachedData::IpAddresses(entry) => entry.addresses.as_ref().clone(),
                _ => Vec::new(),
            })
    })
    .join()
    .unwrap()
}

struct Worker {
    stale: mpsc::Sender<RefreshRequest>,
    timers: Arc<TimerInbox>,
}

fn start_worker(cache: &Arc<DnsCache>, pm: Arc<PoolManager>) -> Worker {
    let (stale, stale_rx) = mpsc::channel(16);
    let timers = Arc::new(TimerInbox::new(16));
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(cache),
        Arc::new(CoreResolver::new(pm, TIMEOUT_MS, false)),
        None,
        stale_rx,
        Some(Arc::clone(&timers)),
        RefreshPriority {
            min_hit_rate: 0.0,
            min_frequency: 0,
        },
    );
    Worker { stale, timers }
}

fn request() -> RefreshRequest {
    (Arc::from(DOMAIN), RecordType::A)
}

/// The test entry's refresh timer, firing now. The entry falls due a second
/// after it is stored, so this waits that second out first.
async fn due_timer() -> ScheduledRefresh {
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    coarse_clock::tick();
    ScheduledRefresh {
        due_at_secs: coarse_clock::coarse_now_secs(),
        key: CacheKey::new(DOMAIN, RecordType::A),
        retry: false,
    }
}

/// Waits until `upstream` has seen `count` queries, then gives the worker a
/// moment to act on the reply.
async fn wait_for_queries(upstream: &Responder, count: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while upstream.queries() < count {
        assert!(
            tokio::time::Instant::now() < deadline,
            "upstream saw {} queries, expected {count}",
            upstream.queries()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// S9. A declined question reaches upstream every time; nothing is cached.
#[tokio::test]
async fn servfail_on_the_client_path_is_not_cached() {
    let up = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let pm = manager(vec![pool("only", UpstreamStrategy::Failover, 1, &[&up])]).await;
    let cache = create_cache();
    let resolver = CachedResolver::new(
        Arc::new(CoreResolver::new(pm, TIMEOUT_MS, false)),
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        7_200,
        4,
    );
    let query = DnsQuery::new(DOMAIN, RecordType::A);

    let first = resolver.resolve(&query).await;
    let second = resolver.resolve(&query).await;

    assert!(first.is_err(), "a SERVFAIL is not a resolution: {first:?}");
    assert!(
        second.is_err(),
        "a SERVFAIL is not a resolution: {second:?}"
    );
    assert_eq!(
        up.queries(),
        2,
        "the second query must not be served from cache"
    );
    assert!(cached_addresses(&cache).is_none(), "nothing may be cached");
}

/// S10. The serve-stale repair fails, so the client keeps the answer it had.
#[tokio::test]
async fn stale_repair_keeps_the_cached_answer_when_upstream_servfails() {
    let up = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let pm = manager(vec![pool("only", UpstreamStrategy::Failover, 1, &[&up])]).await;
    let cache = create_cache();
    insert_ip(&cache, OLD_IP);
    let worker = start_worker(&cache, pm);

    worker.stale.send(request()).await.unwrap();
    wait_for_queries(&up, 1).await;

    assert_eq!(
        cached_addresses(&cache),
        Some(vec![IpAddr::V4(OLD_IP)]),
        "a SERVFAIL must not replace the cached answer"
    );
}

/// S11. Same for a renewal ahead of expiry.
#[tokio::test]
async fn optimistic_refresh_keeps_the_cached_answer_when_upstream_servfails() {
    let up = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let pm = manager(vec![pool("only", UpstreamStrategy::Failover, 1, &[&up])]).await;
    let cache = create_cache();
    insert_ip(&cache, OLD_IP);
    let worker = start_worker(&cache, pm);

    worker.timers.push(due_timer().await).unwrap();
    wait_for_queries(&up, 1).await;

    assert_eq!(
        cached_addresses(&cache),
        Some(vec![IpAddr::V4(OLD_IP)]),
        "a SERVFAIL must not replace the cached answer"
    );
}

/// S12. Guard: once the upstream recovers, the next repair renews the entry.
#[tokio::test]
async fn refresh_renews_the_entry_once_upstream_recovers() {
    let up = Responder::spawn(Behavior::rcode(ResponseCode::ServFail)).await;
    let pm = manager(vec![pool("only", UpstreamStrategy::Failover, 1, &[&up])]).await;
    let cache = create_cache();
    insert_ip(&cache, OLD_IP);
    let worker = start_worker(&cache, pm);

    worker.stale.send(request()).await.unwrap();
    wait_for_queries(&up, 1).await;

    up.set(Behavior::answer(NEW_IP));
    worker.stale.send(request()).await.unwrap();
    wait_for_queries(&up, 2).await;

    assert_eq!(cached_addresses(&cache), Some(vec![IpAddr::V4(NEW_IP)]));
}
