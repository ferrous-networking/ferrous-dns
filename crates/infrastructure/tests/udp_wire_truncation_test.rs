//! UDP wire-data fast path: the client's advertised EDNS buffer must be
//! honored, so an oversized cached answer is deferred to the slow path (which
//! truncates with TC=1) rather than served verbatim. Coverage:
//! - `wire_fits_udp_buffer` (the size decision) and `parse_query`'s
//!   `client_max_size` extraction (its input);
//! - `DnsServerHandler::try_fast_path_wire` end-to-end (defers when the cached
//!   answer exceeds the buffer, serves it when it fits).

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheStats, DnsResolution, DnsResolver, FilterDecision,
    PagedQueryResult, QueryLogRepository, TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsQuery, DnssecStats, DomainError, QueryLog,
    QueryLogFilter, QueryStats, RecordType,
};
use ferrous_dns_infrastructure::dns::fast_path::parse_query;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::dns::wire_response::wire_fits_udp_buffer;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

// ── wire_fits_udp_buffer ────────────────────────────────────────────────────

#[test]
fn fits_when_smaller_than_buffer() {
    assert!(wire_fits_udp_buffer(400, 512));
    assert!(wire_fits_udp_buffer(1000, 4096));
}

#[test]
fn fits_at_exact_buffer_size() {
    assert!(wire_fits_udp_buffer(512, 512));
    assert!(wire_fits_udp_buffer(4096, 4096));
}

#[test]
fn defers_when_larger_than_buffer() {
    assert!(!wire_fits_udp_buffer(513, 512));
    assert!(!wire_fits_udp_buffer(4097, 4096));
}

// ── parse_query: client_max_size extraction ─────────────────────────────────

fn build_a_query_with_arcount(domain: &str, arcount: u16) -> Vec<u8> {
    let mut buf = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // flags: RD set
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
    ];
    buf.extend_from_slice(&arcount.to_be_bytes()); // ARCOUNT
    for label in domain.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0x00); // root label
    buf.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    buf.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
    buf
}

/// Appends an EDNS0 OPT record advertising `udp_payload` as the client buffer.
fn append_opt_record(buf: &mut Vec<u8>, udp_payload: u16) {
    buf.push(0x00); // NAME = root
    buf.extend_from_slice(&[0x00, 41]); // TYPE = OPT
    buf.extend_from_slice(&udp_payload.to_be_bytes()); // CLASS = UDP payload size
    buf.push(0x00); // extended RCODE = 0
    buf.push(0x00); // EDNS version = 0
    buf.extend_from_slice(&[0x00, 0x00]); // DO + Z flags
    buf.extend_from_slice(&[0x00, 0x00]); // RDLEN = 0
}

#[test]
fn client_max_size_reflects_advertised_buffer() {
    let mut buf = build_a_query_with_arcount("example.com", 1);
    append_opt_record(&mut buf, 4096);
    let q = parse_query(&buf).expect("valid EDNS query");
    assert_eq!(q.client_max_size, 4096);
    assert!(q.has_edns);
}

#[test]
fn client_max_size_floored_at_512() {
    // RFC 6891 §6.2.3: advertised values below 512 are treated as 512.
    let mut buf = build_a_query_with_arcount("example.com", 1);
    append_opt_record(&mut buf, 200);
    let q = parse_query(&buf).expect("valid EDNS query");
    assert_eq!(q.client_max_size, 512);
}

#[test]
fn client_max_size_defaults_to_512_without_edns() {
    let buf = build_a_query_with_arcount("example.com", 0);
    let q = parse_query(&buf).expect("valid non-EDNS query");
    assert_eq!(q.client_max_size, 512);
    assert!(!q.has_edns);
}

// ── try_fast_path_wire end-to-end ───────────────────────────────────────────
//
// Minimal port doubles so a HandleDnsQueryUseCase can serve a wire-data cache
// hit of a controllable size. Only the cache-hit path is exercised; the unused
// trait methods are never called.

/// Resolver whose cache always hits with a wire-data answer of a fixed size.
struct CannedWireResolver {
    wire: Vec<u8>,
    ttl: u32,
}

#[async_trait]
impl DnsResolver for CannedWireResolver {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        unimplemented!("cache hit only")
    }

    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        let mut res = DnsResolution::new(Vec::new(), true);
        res.min_ttl = Some(self.ttl);
        res.upstream_wire_data = Some(Bytes::from(self.wire.clone()));
        Some(res)
    }
}

/// Allows every domain; assigns the default group.
struct AllowAllFilter;

#[async_trait]
impl BlockFilterEnginePort for AllowAllFilter {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        0
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn is_blocking_enabled(&self) -> bool {
        false
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

/// Drops every logged query.
struct NoopQueryLog;

#[async_trait]
impl QueryLogRepository for NoopQueryLog {
    async fn log_query(&self, _query: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_recent(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        unimplemented!()
    }
    async fn get_recent_paged(
        &self,
        _limit: u32,
        _offset: u32,
        _period_hours: f32,
        _cursor: Option<i64>,
        _filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        unimplemented!()
    }
    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }
    async fn get_dnssec_stats(&self, _period_hours: f32) -> Result<DnssecStats, DomainError> {
        unimplemented!()
    }
    async fn get_timeline(
        &self,
        _period_hours: u32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }
    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }
    async fn get_top_blocked_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_allowed_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_distinct_recent_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_clients(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        unimplemented!()
    }
    async fn delete_older_than(&self, _days: u32) -> Result<u64, DomainError> {
        unimplemented!()
    }
}

/// Builds a handler whose wire-data cache hit is `wire_len` bytes long.
fn handler_with_cached_wire(wire_len: usize) -> DnsServerHandler {
    let resolver: Arc<dyn DnsResolver> = Arc::new(CannedWireResolver {
        wire: vec![0u8; wire_len],
        ttl: 60,
    });
    let use_case = Arc::new(HandleDnsQueryUseCase::new(
        resolver,
        Arc::new(AllowAllFilter),
        Arc::new(NoopQueryLog),
    ));
    DnsServerHandler::new(
        use_case,
        BlockPolicy {
            mode: BlockResponseMode::NullIp,
            ttl: 60,
            sinkhole_ipv4: None,
            sinkhole_ipv6: None,
        },
    )
}

#[test]
fn wire_fast_path_defers_when_answer_exceeds_client_buffer() {
    let handler = handler_with_cached_wire(600);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    // 600-byte cached answer vs a 512 buffer → must defer (None) so the slow
    // path can truncate it with TC=1 instead of serving oversized wire.
    let result = handler.try_fast_path_wire(
        "mail.example.com",
        RecordType::MX,
        client_ip,
        0x1234,
        512,
        ClientProtocol::Udp,
    );
    assert!(
        result.is_none(),
        "oversized wire-data hit must defer to the slow path"
    );
}

#[test]
fn wire_fast_path_serves_when_answer_fits_client_buffer() {
    let handler = handler_with_cached_wire(600);
    let client_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    // Same 600-byte answer, but the client advertised 4096 → it fits, so the
    // fast path serves it verbatim with the query id patched in.
    let (bytes, ttl) = handler
        .try_fast_path_wire(
            "mail.example.com",
            RecordType::MX,
            client_ip,
            0x1234,
            4096,
            ClientProtocol::Udp,
        )
        .expect("answer within the client buffer must be served on the fast path");
    assert_eq!(ttl, 60);
    assert_eq!(bytes.len(), 600);
    assert_eq!(&bytes[0..2], &[0x12, 0x34], "query id must be patched");
}
