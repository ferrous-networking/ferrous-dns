use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
use ferrous_dns_infrastructure::dns::resolver::CachedResolver;
use ferrous_dns_infrastructure::dns::{
    CachedData, DnsCache, DnsCacheAccess, DnsCacheConfig, EvictionStrategy,
};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType as WireType};
use hickory_proto::serialize::binary::BinEncodable;
use std::str::FromStr;
use std::sync::Arc;

fn make_soa_record(zone: &str, minimum: u32, record_ttl: u32) -> Record {
    let name = Name::from_str(&format!("{}.", zone)).unwrap();
    let mname = Name::from_str(&format!("ns1.{}.", zone)).unwrap();
    let rname = Name::from_str(&format!("hostmaster.{}.", zone)).unwrap();
    let soa = SOA::new(mname, rname, 1, 3600, 900, 604800, minimum);
    Record::from_rdata(name, record_ttl, RData::SOA(soa))
}

fn extract_soa_ttl(records: &[Record]) -> Option<u32> {
    records.iter().find_map(|r| {
        if let RData::SOA(soa) = &r.data {
            Some(soa.minimum.min(r.ttl))
        } else {
            None
        }
    })
}

struct MockNegativeResolver {
    negative_soa_ttl: Option<u32>,
}

impl MockNegativeResolver {
    fn from_authority(authority_records: &[Record]) -> Self {
        Self {
            negative_soa_ttl: extract_soa_ttl(authority_records),
        }
    }
}

#[async_trait]
impl DnsResolver for MockNegativeResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Ok(DnsResolution {
            addresses: Arc::new(vec![]),
            cache_hit: false,
            local_dns: false,
            local_nxdomain: false,
            dnssec_status: None,
            cname_chain: Arc::from(vec![]),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            negative_soa_ttl: self.negative_soa_ttl,
            upstream_wire_data: None,
        })
    }
}

fn make_cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::LRU,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

#[tokio::test]
async fn test_soa_ttl_used_when_present() {
    let soa = make_soa_record("example.com", 300, 300);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver::from_authority(&[soa]));

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        4,
    );

    let query = DnsQuery {
        domain: Arc::from("nxdomain.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("nxdomain.example.com"), &RecordType::A);
    assert!(cached.is_some(), "Negative response should be cached");
    let (data, _, remaining_ttl, _) = cached.unwrap();
    assert!(matches!(data, CachedData::NegativeResponse));
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (290..=300).contains(&ttl),
        "TTL from SOA minimum should be ~300, got {ttl}"
    );
}

#[tokio::test]
async fn test_soa_ttl_below_min_clamped_to_300() {
    let soa = make_soa_record("example.com", 10, 10);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver::from_authority(&[soa]));

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        4,
    );

    let query = DnsQuery {
        domain: Arc::from("low-ttl.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("low-ttl.example.com"), &RecordType::A);
    let (_, _, remaining_ttl, _) = cached.expect("Should be cached");
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (290..=300).contains(&ttl),
        "SOA TTL 10 should be clamped to negative-cache floor of 300s, got {ttl}"
    );
}

#[tokio::test]
async fn test_soa_ttl_above_max_clamped_to_3600() {
    let soa = make_soa_record("example.com", 86400, 86400);
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver::from_authority(&[soa]));

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        4,
    );

    let query = DnsQuery {
        domain: Arc::from("high-ttl.example.com"),
        record_type: RecordType::A,
    };
    let _ = resolver.resolve(&query).await;

    let cached = cache.get(&Arc::from("high-ttl.example.com"), &RecordType::A);
    let (_, _, remaining_ttl, _) = cached.expect("Should be cached");
    let ttl = remaining_ttl.unwrap_or(0);
    assert!(
        (3590..=3600).contains(&ttl),
        "SOA TTL 86400 should be clamped to max 3600, got {ttl}"
    );
}

#[tokio::test]
async fn test_fallback_to_tracker_when_no_soa() {
    let inner: Arc<dyn DnsResolver> = Arc::new(MockNegativeResolver {
        negative_soa_ttl: None,
    });

    let cache = make_cache();
    let resolver = CachedResolver::new(
        inner,
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        3600,
        4,
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
    let (data, _, _, _) = cached.unwrap();
    assert!(matches!(data, CachedData::NegativeResponse));
}

// ── S13–S18: negative answers as the upstream really sends them ─────────────
//
// The pool path hands NXDOMAIN and NODATA to the cache as the upstream's wire
// message, never as `upstream_wire_data: None` like the mock above. These run
// the real bytes through `ResponseParser`, as `CoreResolver` does, with a
// `cache_ttl` of 7200 so a fallback to it cannot pass for the SOA rule.

const WIRE_CACHE_TTL: u32 = 7_200;

fn upstream_wire(
    qname: &str,
    qtype: WireType,
    rcode: ResponseCode,
    answers: Vec<Record>,
    authorities: Vec<Record>,
) -> Bytes {
    let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.metadata.response_code = rcode;
    msg.add_query(Query::query(
        Name::from_str(&format!("{qname}.")).unwrap(),
        qtype,
    ));
    msg.add_answers(answers);
    msg.add_authorities(authorities);
    Bytes::from(msg.to_bytes().unwrap())
}

/// Answers with fixed upstream wire bytes, parsed the way `CoreResolver` does.
struct UpstreamWireResolver(Bytes);

#[async_trait]
impl DnsResolver for UpstreamWireResolver {
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

/// Resolves `qname` through the cache layer and returns what it cached.
async fn cache_upstream_answer(
    qname: &str,
    record_type: RecordType,
    wire: Bytes,
) -> (CachedData, u32) {
    let cache = make_cache();
    let resolver = CachedResolver::new(
        Arc::new(UpstreamWireResolver(wire)),
        Arc::clone(&cache) as Arc<dyn DnsCacheAccess>,
        WIRE_CACHE_TTL,
        4,
    );
    let query = DnsQuery::new(qname, record_type);
    let _ = resolver.resolve(&query).await;

    let (data, _, remaining_ttl, _) = cache
        .get(qname, &record_type)
        .expect("the upstream answer should be cached");
    (data, remaining_ttl.unwrap_or(0))
}

/// S13.
#[tokio::test]
async fn upstream_nxdomain_is_cached_for_the_soa_ttl_floor() {
    let wire = upstream_wire(
        "nx-low.example.com",
        WireType::A,
        ResponseCode::NXDomain,
        vec![],
        vec![make_soa_record("example.com", 60, 60)],
    );
    let (data, ttl) = cache_upstream_answer("nx-low.example.com", RecordType::A, wire).await;

    assert!(
        matches!(data, CachedData::WireData(_)),
        "kept as wire: {data:?}"
    );
    assert!(
        (290..=300).contains(&ttl),
        "SOA negative TTL 60 is raised to the 300s floor, got {ttl}"
    );
}

/// S14.
#[tokio::test]
async fn upstream_nxdomain_soa_ttl_is_capped_at_one_hour() {
    let wire = upstream_wire(
        "nx-high.example.com",
        WireType::A,
        ResponseCode::NXDomain,
        vec![],
        vec![make_soa_record("example.com", 86_400, 86_400)],
    );
    let (_, ttl) = cache_upstream_answer("nx-high.example.com", RecordType::A, wire).await;

    assert!(
        (3590..=3600).contains(&ttl),
        "SOA negative TTL 86400 is capped at 3600, got {ttl}"
    );
}

/// S15.
#[tokio::test]
async fn upstream_nxdomain_without_soa_gets_the_floor() {
    let wire = upstream_wire(
        "nx-bare.example.com",
        WireType::A,
        ResponseCode::NXDomain,
        vec![],
        vec![],
    );
    let (_, ttl) = cache_upstream_answer("nx-bare.example.com", RecordType::A, wire).await;

    assert!(
        (290..=300).contains(&ttl),
        "an NXDOMAIN without SOA gets the 300s floor, not cache_ttl; got {ttl}"
    );
}

/// S16. NODATA, like an AAAA query for an IPv4-only name.
#[tokio::test]
async fn upstream_nodata_is_cached_for_the_soa_ttl() {
    let wire = upstream_wire(
        "v4only.example.com",
        WireType::AAAA,
        ResponseCode::NoError,
        vec![],
        vec![make_soa_record("example.com", 900, 900)],
    );
    let (data, ttl) = cache_upstream_answer("v4only.example.com", RecordType::AAAA, wire).await;

    assert!(
        matches!(data, CachedData::WireData(_)),
        "kept as wire: {data:?}"
    );
    assert!(
        (890..=900).contains(&ttl),
        "NODATA follows the SOA negative TTL, got {ttl}"
    );
}

/// S17. Guard: an answer with records keeps their TTL.
#[tokio::test]
async fn upstream_positive_wire_answer_keeps_its_record_ttl() {
    let name = Name::from_str("txt.example.com.").unwrap();
    let txt = Record::from_rdata(name, 1_200, RData::TXT(TXT::new(vec!["v=1".into()])));
    let wire = upstream_wire(
        "txt.example.com",
        WireType::TXT,
        ResponseCode::NoError,
        vec![txt],
        vec![],
    );
    let (_, ttl) = cache_upstream_answer("txt.example.com", RecordType::TXT, wire).await;

    assert!(
        (1190..=1200).contains(&ttl),
        "a positive answer is cached for its record TTL, got {ttl}"
    );
}

/// S18. Guard: the cached NXDOMAIN still relays its rcode and SOA.
#[tokio::test]
async fn cached_upstream_nxdomain_keeps_rcode_and_soa() {
    let wire = upstream_wire(
        "nx-relay.example.com",
        WireType::A,
        ResponseCode::NXDomain,
        vec![],
        vec![make_soa_record("example.com", 300, 300)],
    );
    let (data, _) = cache_upstream_answer("nx-relay.example.com", RecordType::A, wire).await;

    let CachedData::WireData(bytes) = data else {
        panic!("expected wire data, got {data:?}");
    };
    let msg = Message::from_vec(&bytes).expect("the cached wire must parse");
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        msg.authorities
            .iter()
            .any(|r| matches!(r.data, RData::SOA(_))),
        "the SOA must stay in the authority section"
    );
}
