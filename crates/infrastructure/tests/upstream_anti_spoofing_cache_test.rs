//! Regression: 0x20 QNAME case randomization is applied to the *upstream* wire
//! only, and the anti-spoofing cookie path (validated vs. graceful) does not
//! disturb caching. Addresses come from rdata IPs, never the (randomized-case)
//! owner name, and the cache key is the client's lowercased domain.

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use ferrous_dns_infrastructure::dns::resolver::{CachedResolver, CoreResolver};
use ferrous_dns_infrastructure::dns::{
    DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy, NegativeQueryTracker,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

/// Faithful A-record responder. Records the raw QNAME label bytes (preserving
/// on-wire case) of every query, so tests can confirm 0x20 reached upstream and
/// count how many times the upstream was actually hit. When `echo_cookie` is set
/// it mirrors the client's EDNS OPT back (a cookie-supporting upstream); when
/// not, it answers with no OPT (an upstream without DNS Cookies — graceful path).
async fn spawn_responder(seen: Arc<Mutex<Vec<Vec<u8>>>>, echo_cookie: bool) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(q) = req.queries.first().cloned() else {
                continue;
            };
            seen.lock()
                .unwrap()
                .push(q.name().iter().flat_map(|l| l.to_vec()).collect());

            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());
            // Owner name echoes the randomized query name; the parser must still
            // extract the IP by rdata regardless of its case.
            resp.add_answer(Record::from_rdata(
                q.name().clone(),
                300,
                RData::A(A(UPSTREAM_IP)),
            ));
            // A cookie-supporting upstream echoes the client's COOKIE option back
            // (validated path); copying the request OPT carries option 10 verbatim.
            if echo_cookie {
                if let Some(edns) = req.edns.clone() {
                    resp.set_edns(edns);
                }
            }

            let _ = socket.send_to(&resp.to_bytes().unwrap(), peer).await;
        }
    });

    addr
}

async fn manager(addr: SocketAddr, qname_0x20: bool) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{addr}")],
        weight: None,
    };
    Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap()
            .with_hardening(HardeningOpts {
                cookie: true,
                qname_0x20,
            }),
    )
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

#[tokio::test]
async fn hardening_does_not_corrupt_address_extraction() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_responder(seen, false).await;
    let pm = manager(addr, true).await;

    let domain: Arc<str> = Arc::from("example.com");
    let result = pm
        .query(&domain, &RecordType::A, 2000, false)
        .await
        .expect("faithful A response must resolve");

    // The served/cached value is exact: addresses come from rdata, not the
    // randomized-case owner name.
    assert_eq!(result.response.addresses, vec![IpAddr::V4(UPSTREAM_IP)]);
}

#[tokio::test]
async fn zero_x20_randomizes_qname_on_the_wire_only() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_responder(seen.clone(), false).await;
    let pm = manager(addr, true).await;

    let domain: Arc<str> = Arc::from("example.com");
    // 0x20 is random per query; over several queries at least one upstream QNAME
    // must carry an uppercase letter (all-lowercase odds per query are ~2^-10).
    for _ in 0..16 {
        let _ = pm.query(&domain, &RecordType::A, 2000, false).await;
    }

    let observed = seen.lock().unwrap().clone();
    assert!(!observed.is_empty(), "responder should have seen queries");
    let saw_upper = observed
        .iter()
        .any(|bytes| bytes.iter().any(u8::is_ascii_uppercase));
    assert!(
        saw_upper,
        "0x20 must randomize the upstream QNAME case; saw {observed:?}"
    );

    // Our side keyed on the client's domain, untouched by upstream randomization.
    assert_eq!(&*domain, "example.com");
}

/// Byte span of the question QNAME for `example.com.` — the 12-byte header, then
/// `\x07example\x03com\x00`.
const QNAME_SPAN: std::ops::Range<usize> = 12..12 + 1 + 7 + 1 + 3 + 1;

#[tokio::test]
async fn zero_x20_is_stripped_before_the_response_is_cacheable() {
    // Non-address types are replayed to clients as raw upstream wire, straight
    // from the cache — so the randomization has to be gone by the time the
    // response leaves the upstream choke point, not patched on the way out.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_responder(seen.clone(), false).await;
    let pm = manager(addr, true).await;

    let domain: Arc<str> = Arc::from("example.com");
    for _ in 0..16 {
        let result = pm
            .query(&domain, &RecordType::MX, 2000, false)
            .await
            .expect("faithful response must resolve");

        let question = &result.response.raw_bytes[QNAME_SPAN];
        assert!(
            !question.iter().any(u8::is_ascii_uppercase),
            "cacheable wire must carry the canonical QNAME, got {:?}",
            String::from_utf8_lossy(question)
        );

        let parsed_upper = result.response.message.queries[0]
            .name()
            .iter()
            .any(|label| label.iter().any(u8::is_ascii_uppercase));
        assert!(!parsed_upper, "parsed question must be canonical too");
    }

    // Guard against the assertions above passing for the wrong reason: the
    // upstream really did receive randomized case.
    let observed = seen.lock().unwrap().clone();
    assert!(
        observed
            .iter()
            .any(|bytes| bytes.iter().any(u8::is_ascii_uppercase)),
        "0x20 must still reach the upstream; saw {observed:?}"
    );
}

/// Drives queries through the full cache stack (`CachedResolver` ->
/// `CoreResolver` -> `PoolManager`) against a live UDP upstream. We always send a
/// cookie (hardening on); `echo_cookie` toggles whether the upstream supports
/// cookies. Either way: first query is a miss that hits upstream once, the second
/// identical query is a cache hit that does NOT touch the upstream.
async fn assert_cache_hit_miss(echo_cookie: bool) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let addr = spawn_responder(seen.clone(), echo_cookie).await;
    let pm = manager(addr, false).await;

    let core = Arc::new(CoreResolver::new(pm, 2000, false));
    let resolver = Arc::new(CachedResolver::new(
        core as Arc<dyn DnsResolver>,
        make_cache(),
        300,
        Arc::new(NegativeQueryTracker::new()),
        4,
    ));

    let query = DnsQuery {
        domain: Arc::from("example.com"),
        record_type: RecordType::A,
    };

    let first = resolver
        .resolve(&query)
        .await
        .expect("first resolve must succeed");
    assert!(!first.cache_hit, "first query is a cache miss");
    assert_eq!(first.addresses.to_vec(), vec![IpAddr::V4(UPSTREAM_IP)]);
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "upstream queried exactly once on the miss"
    );

    let second = resolver
        .resolve(&query)
        .await
        .expect("second resolve must succeed");
    assert!(
        second.cache_hit,
        "second identical query is served from cache"
    );
    assert_eq!(second.addresses.to_vec(), vec![IpAddr::V4(UPSTREAM_IP)]);
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "cache hit must NOT re-query the upstream"
    );
}

#[tokio::test]
async fn cache_hit_miss_with_cookie_echoing_upstream() {
    assert_cache_hit_miss(true).await;
}

#[tokio::test]
async fn cache_hit_miss_with_non_cookie_upstream() {
    assert_cache_hit_miss(false).await;
}
