//! The UDP worker's cache-hit fast path, end to end on one thread: parse the
//! query, admit it through the use case (block filter, rate limiter, cache
//! probe, query-log entry) and encode the reply. Run with and without an OPT
//! record, for an address answer and for a cached upstream wire answer, plus
//! the wire answer to a client sending a DNS Cookie, a signed wire answer
//! (fetched with DO=1) to clients that did not set DO, and an eight-record
//! wire answer, whose every TTL a hit counts down.

#[path = "../tests/support/ports.rs"]
mod ports;

use async_trait::async_trait;
use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use ferrous_dns_application::ports::{BlockFilterEnginePort, DnsResolution, DnsResolver};
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsCookiesConfig, DnsQuery, DomainError, RecordType,
};
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::dns::wire_response::{self, RESPONSE_BUF_LEN};
use ferrous_dns_infrastructure::dns::{
    BlockFilterEngine, CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy,
};
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::MX;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use ports::{AllowAllFilter, NoopQueryLog};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
const A_NAME: &str = "www.example.com";
const MX_NAME: &str = "mail.example.com";
const SIGNED_NAME: &str = "signed.example.com";
const MANY_NAME: &str = "many.example.com";

/// Every probe is served from the cache; an upstream call means a broken setup.
struct NoUpstream;

#[async_trait]
impl DnsResolver for NoUpstream {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::QueryTimeout)
    }
}

fn cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 10_000,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 16,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

/// A cached upstream MX answer holding `exchanges` records, OPT last as
/// upstreams send it.
fn upstream_mx(owner: &str, exchanges: u16) -> Bytes {
    let name = Name::from_ascii(owner).unwrap();
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(
        name.clone(),
        hickory_proto::rr::RecordType::MX,
    ));
    for i in 1..=exchanges {
        let exchange = Name::from_ascii(format!("mx{i}.example.com.")).unwrap();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            3600,
            RData::MX(MX::new(10 * i, exchange)),
        ));
    }
    let mut opt = Edns::new();
    opt.set_max_payload(1232);
    msg.set_edns(opt);
    Bytes::from(msg.to_bytes().unwrap())
}

/// An MX answer from a signed zone as a DO=1 upstream sends it: an RRSIG
/// beside the MX and DO set in the OPT.
fn upstream_signed_mx() -> Bytes {
    let name = Name::from_ascii("signed.example.com.").unwrap();
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(
        name.clone(),
        hickory_proto::rr::RecordType::MX,
    ));
    msg.add_answer(Record::from_rdata(
        name,
        3600,
        RData::MX(MX::new(10, Name::from_ascii("mx1.example.com.").unwrap())),
    ));
    let mut wire = msg.to_bytes().unwrap();
    // RRSIG MX, algorithm 13, 3 labels, then the signer and a P-256 signature.
    let mut rdata = vec![0, 15, 13, 3, 0, 0, 0x0E, 0x10];
    rdata.extend_from_slice(&[0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x12, 0x34]);
    rdata.extend_from_slice(b"\x07example\x03com\x00");
    rdata.extend_from_slice(&[0xAB; 64]);
    wire.extend_from_slice(&[0xC0, 0x0C, 0, 46, 0, 1, 0, 0, 0x0E, 0x10]);
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(&rdata);
    wire[7] += 1;
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
    wire[11] = 1;
    Bytes::from(wire)
}

/// A recursion-desired query, with a DO-clear 1232-byte OPT carrying
/// `options` when `edns`.
fn query_with_options(name: &str, qtype: u16, edns: bool, options: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)];
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&qtype.to_be_bytes());
    buf.extend_from_slice(&[0, 1]);
    if edns {
        buf.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0]);
        buf.extend_from_slice(&(options.len() as u16).to_be_bytes());
        buf.extend_from_slice(options);
    }
    buf
}

fn query(name: &str, qtype: u16, edns: bool) -> Vec<u8> {
    query_with_options(name, qtype, edns, &[])
}

fn handler(
    runtime: &tokio::runtime::Runtime,
) -> (DnsServerHandler, DnsServerHandler, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("bench.db").display());
    let engine = runtime.block_on(async {
        let pool = create_write_pool(&url, &DatabaseConfig::default())
            .await
            .unwrap();
        sqlx::query("INSERT INTO blocklist (domain) VALUES ('ads.example.net')")
            .execute(&pool)
            .await
            .unwrap();
        let engine = BlockFilterEngine::new(pool, 1, Arc::new(ScheduleStateStore::new()), true)
            .await
            .unwrap();
        engine.reload().await.unwrap();
        engine
    });

    coarse_clock::tick();
    let cache = cache();
    cache.insert(
        A_NAME,
        RecordType::A,
        CachedData::IpAddresses(CachedAddresses {
            addresses: Arc::new(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]),
        }),
        3600,
        None,
    );
    cache.insert(
        MX_NAME,
        RecordType::MX,
        CachedData::WireData(upstream_mx("mail.example.com.", 1)),
        3600,
        None,
    );
    cache.insert(
        MANY_NAME,
        RecordType::MX,
        CachedData::WireData(upstream_mx("many.example.com.", 8)),
        3600,
        None,
    );
    cache.insert(
        SIGNED_NAME,
        RecordType::MX,
        CachedData::WireData(upstream_signed_mx()),
        3600,
        None,
    );
    let resolver: Arc<CachedResolver> =
        Arc::new(CachedResolver::new(Arc::new(NoUpstream), cache, 300, 4));
    let policy = BlockPolicy {
        mode: BlockResponseMode::NullIp,
        ttl: 60,
        sinkhole_ipv4: None,
        sinkhole_ipv6: None,
    };
    let cookies = DnsCookiesConfig {
        require_valid_cookie: false,
        ..DnsCookiesConfig::default()
    };
    let filtered = HandleDnsQueryUseCase::new(resolver.clone(), engine, Arc::new(NoopQueryLog))
        .with_dns_cookies(DnsCookieGuard::from_config(&cookies, [7; 32]));
    // The same path minus the block filter, to tell its cost from the rest.
    let unfiltered =
        HandleDnsQueryUseCase::new(resolver, Arc::new(AllowAllFilter), Arc::new(NoopQueryLog));
    (
        DnsServerHandler::new(Arc::new(filtered), policy),
        DnsServerHandler::new(Arc::new(unfiltered), policy),
        dir,
    )
}

/// What the UDP worker does with one datagram before it would fall back.
fn serve(handler: &DnsServerHandler, raw: &[u8], out: &mut [u8; RESPONSE_BUF_LEN]) -> usize {
    let query = fast_path::parse_query(raw).filter(|q| !q.wants_dnssec);
    let Some(query) = query else { return 0 };
    match query.kind {
        FastPathKind::IpAddress => handler
            .try_fast_path(
                &query,
                raw,
                CLIENT,
                ClientProtocol::Udp,
                |addresses, ttl, cookie| {
                    wire_response::build_cache_hit_response(
                        &query, raw, addresses, ttl, cookie, out,
                    )
                },
            )
            .unwrap_or(0),
        FastPathKind::WireData => handler
            .try_fast_path_wire(&query, raw, CLIENT, ClientProtocol::Udp)
            .map_or(0, |wire| wire.len()),
    }
}

fn udp_cache_hit(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (handler, unfiltered, _dir) = handler(&runtime);
    let mut out = [0u8; RESPONSE_BUF_LEN];

    let mut group = c.benchmark_group("udp_cache_hit");
    for (label, raw) in [
        ("a_edns", query(A_NAME, 1, true)),
        ("a_plain", query(A_NAME, 1, false)),
        (
            "a_edns_cookie",
            query_with_options(A_NAME, 1, true, &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
        ),
        ("mx_edns", query(MX_NAME, 15, true)),
        ("mx_plain", query(MX_NAME, 15, false)),
        (
            "mx_edns_cookie",
            query_with_options(MX_NAME, 15, true, &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
        ),
        ("mx_edns_signed", query(SIGNED_NAME, 15, true)),
        ("mx_plain_signed", query(SIGNED_NAME, 15, false)),
        ("mx8_edns", query(MANY_NAME, 15, true)),
    ] {
        assert_ne!(serve(&handler, &raw, &mut out), 0, "{label} must hit");
        group.bench_function(label, |b| {
            b.iter(|| serve(&handler, black_box(&raw), &mut out))
        });
    }
    let raw = query(A_NAME, 1, true);
    group.bench_function("a_edns_unfiltered", |b| {
        b.iter(|| serve(&unfiltered, black_box(&raw), &mut out))
    });
    group.finish();
}

criterion_group!(benches, udp_cache_hit);
criterion_main!(benches);
