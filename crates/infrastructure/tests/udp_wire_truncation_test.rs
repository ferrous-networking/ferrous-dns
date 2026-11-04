//! UDP wire-data fast path: the client's advertised EDNS buffer must be
//! honored, so an oversized cached answer is deferred to the slow path (which
//! truncates with TC=1) rather than served verbatim. Coverage:
//! - `wire_fits_udp_buffer` (the size decision) and `parse_query`'s
//!   `client_max_size` extraction (its input);
//! - `DnsServerHandler::try_fast_path_wire` end-to-end (defers when the cached
//!   answer exceeds the buffer, serves it when it fits).
//! - `DnsServerHandler::handle_raw_udp_fallback` (the slow path truncates for
//!   plain UDP only — every other transport frames its own length).

#[path = "support/ports.rs"]
mod ports;

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{BlockResponseMode, ClientProtocol, DnsQuery, DomainError};
use ferrous_dns_infrastructure::dns::fast_path::parse_query;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::dns::wire_response::{cache_form, wire_fits_udp_buffer};
use ports::{AllowAllFilter, NoopQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[test]
fn wire_fits_up_to_exactly_the_client_buffer() {
    assert!(wire_fits_udp_buffer(512, 512));
    assert!(!wire_fits_udp_buffer(513, 512));
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
    assert!(q.has_edns());
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
    assert!(!q.has_edns());
}

// ── try_fast_path_wire end-to-end ───────────────────────────────────────────
//
// Minimal port doubles so a HandleDnsQueryUseCase can serve a wire-data cache
// hit of a controllable size. Only the cache-hit path is exercised; the unused
// trait methods are never called.

/// Resolver whose cache always hits with the same wire-data answer.
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

/// Builds a handler whose wire-data cache hit is `wire`.
fn handler_with_cached_wire(wire: Vec<u8>) -> DnsServerHandler {
    let resolver: Arc<dyn DnsResolver> = Arc::new(CannedWireResolver { wire, ttl: 60 });
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
        Arc::default(),
    )
}

/// An MX query for `mail.example.com`, with an OPT advertising `udp_payload`.
fn mx_query(udp_payload: Option<u16>) -> Vec<u8> {
    let mut buf = build_a_query_with_arcount("mail.example.com", u16::from(udp_payload.is_some()));
    let qtype = buf.len() - 4;
    buf[qtype..qtype + 2].copy_from_slice(&15u16.to_be_bytes());
    if let Some(udp_payload) = udp_payload {
        append_opt_record(&mut buf, udp_payload);
    }
    buf
}

fn serve_wire(handler: &DnsServerHandler, query: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_query(query).expect("valid MX query");
    handler.try_fast_path_wire(
        &parsed,
        query,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        ClientProtocol::Udp,
    )
}

/// [`large_answer`] as the cache stores it.
fn cached_large_answer() -> Vec<u8> {
    cache_form(&large_answer(), 300, 0..=u32::MAX).expect("a well-formed answer")
}

#[test]
fn wire_fast_path_defers_when_answer_exceeds_client_buffer() {
    let handler = handler_with_cached_wire(cached_large_answer());
    // A cached answer past 512 bytes vs a 512 buffer → must defer (None) so
    // the slow path can truncate it with TC=1 instead of serving it oversized.
    assert!(
        serve_wire(&handler, &mx_query(Some(512))).is_none(),
        "oversized wire-data hit must defer to the slow path"
    );
}

#[test]
fn wire_fast_path_serves_when_answer_fits_client_buffer() {
    let cached = cached_large_answer();
    let handler = handler_with_cached_wire(cached.clone());
    // Same answer, but the client advertised 4096 → it fits, so the fast path
    // serves it with the query id patched in.
    let bytes = serve_wire(&handler, &mx_query(Some(4096)))
        .expect("answer within the client buffer must be served on the fast path");
    let served = hickory_proto::op::Message::from_vec(&bytes).expect("the reply decodes");
    let cached = hickory_proto::op::Message::from_vec(&cached).expect("the cache form decodes");
    assert_eq!(served.answers.len(), cached.answers.len());
    assert_eq!(&bytes[0..2], &[0x12, 0x34], "query id must be patched");
}

/// A cached upstream TXT answer past 512 bytes, without an OPT to strip.
fn large_answer() -> Vec<u8> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{rdata::TXT, Name, RData, Record};
    let name = Name::from_ascii("mail.example.com.").unwrap();
    let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        name.clone(),
        hickory_proto::rr::RecordType::TXT,
    ));
    msg.add_answer(Record::from_rdata(
        name,
        300,
        RData::TXT(TXT::new(vec![
            "x".repeat(250),
            "y".repeat(250),
            "z".repeat(90),
        ])),
    ));
    let wire = msg.to_vec().unwrap();
    assert!(wire.len() > 512);
    wire
}

/// A cached upstream MX answer: RD set (every upstream query sets it) and an
/// OPT of its own, last in the additional section.
fn upstream_mx() -> Vec<u8> {
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{rdata::MX, Name, RData, Record};
    let name = Name::from_ascii("mail.example.com.").unwrap();
    let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(
        name.clone(),
        hickory_proto::rr::RecordType::MX,
    ));
    msg.add_answer(Record::from_rdata(
        name,
        300,
        RData::MX(MX::new(10, Name::from_ascii("mx1.example.com.").unwrap())),
    ));
    let mut opt = Edns::new();
    opt.set_max_payload(1232);
    msg.set_edns(opt);
    msg.to_vec().unwrap()
}

/// RFC 6891 §7: a query without OPT gets a reply without one, which the
/// cached upstream bytes cannot provide verbatim; RD is the query's.
#[test]
fn wire_fast_path_strips_the_upstream_opt_for_a_query_without_one() {
    use hickory_proto::op::Message;
    let upstream = Message::from_vec(&upstream_mx()).unwrap();
    let handler =
        handler_with_cached_wire(cache_form(&upstream_mx(), 60, 0..=u32::MAX).expect("cacheable"));

    let mut plain = mx_query(None);
    plain[2] &= !0x01; // RD=0
    let reply = Message::from_vec(&serve_wire(&handler, &plain).expect("served")).unwrap();
    assert!(
        reply.edns.is_none(),
        "no OPT in the query, none in the reply"
    );
    assert_eq!(reply.metadata.id, 0x1234);
    assert!(
        !reply.metadata.recursion_desired,
        "RD copied from the query"
    );
    assert_eq!(reply.answers, upstream.answers);

    let mut edns = mx_query(Some(1232));
    edns[2] &= !0x01;
    let reply = Message::from_vec(&serve_wire(&handler, &edns).expect("served")).unwrap();
    assert!(reply.edns.is_some(), "an EDNS client keeps the OPT");
    assert!(
        !reply.metadata.recursion_desired,
        "RD copied from the query"
    );
    assert_eq!(reply.answers, upstream.answers);
}

// ── handle_raw_udp_fallback: the 512-byte limit is plain-UDP only ───────────

/// Bit 1 of the second flags byte — TC, set when an answer was truncated.
const TC_FLAG: u8 = 0x02;

/// Runs the slow path over `protocol` for a query with no EDNS (so the UDP
/// buffer is the 512-byte default) whose cached answer is [`large_answer`].
async fn slow_path_answer_over(protocol: ClientProtocol) -> Vec<u8> {
    let handler = handler_with_cached_wire(large_answer());
    let raw = build_a_query_with_arcount("mail.example.com", 0);
    handler
        .handle_raw_udp_fallback(&raw, IpAddr::V4(Ipv4Addr::LOCALHOST), protocol)
        .await
        .expect("the slow path must produce an answer")
}

#[tokio::test]
async fn slow_path_truncates_an_oversized_answer_over_plain_udp() {
    let response = slow_path_answer_over(ClientProtocol::Udp).await;
    assert!(
        response.len() <= 512,
        "an oversized answer must not be sent whole to a 512-byte UDP client"
    );
    assert_eq!(
        response[2] & TC_FLAG,
        TC_FLAG,
        "TC must be set so the client retries over TCP"
    );
}

#[tokio::test]
async fn slow_path_does_not_truncate_over_doq() {
    // DoQ rides on UDP, so a check that keyed on the socket rather than on the
    // transport would cap this at 512 and strand the answer behind a TC=1 retry
    // a QUIC client has no reason to make (RFC 9250 frames its own length).
    let response = slow_path_answer_over(ClientProtocol::Doq).await;
    assert_eq!(response.len(), large_answer().len());
    assert_eq!(response[2] & TC_FLAG, 0, "TC must stay clear over DoQ");
}

#[tokio::test]
async fn slow_path_does_not_truncate_over_the_stream_transports() {
    for protocol in [
        ClientProtocol::Tcp,
        ClientProtocol::Dot,
        ClientProtocol::Doh,
    ] {
        let response = slow_path_answer_over(protocol).await;
        assert_eq!(
            response.len(),
            large_answer().len(),
            "{protocol} must not be truncated"
        );
        assert_eq!(response[2] & TC_FLAG, 0, "{protocol} must not set TC");
    }
}
