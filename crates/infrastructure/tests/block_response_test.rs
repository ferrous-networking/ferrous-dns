//! Integration tests for the domain-verdict block responders. Exercises both
//! the raw UDP fast path (`build_blocked_wire`) and the hickory `RequestHandler`
//! path (`send_blocked_response`) for every `BlockResponseMode`.

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_domain::{BlockResponseMode, DomainError};
use ferrous_dns_infrastructure::dns::ede;
use ferrous_dns_infrastructure::dns::server::{
    build_blocked_wire, send_blocked_response, BlockPolicy,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_proto::xfer::Protocol;
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

const TTL: u32 = 120;

fn name() -> Name {
    Name::from_str("ads.example.com.").unwrap()
}

fn query(record_type: RecordType) -> Query {
    Query::query(name(), record_type)
}

fn policy(mode: BlockResponseMode) -> BlockPolicy {
    BlockPolicy { mode, ttl: TTL }
}

/// Asserts the authority section carries exactly one synthetic SOA with the
/// block TTL (so the negative answer is negatively cacheable, RFC 2308).
fn assert_soa(msg: &Message) {
    assert_eq!(msg.name_servers().len(), 1, "expected one SOA in authority");
    let soa = &msg.name_servers()[0];
    assert_eq!(soa.ttl(), TTL);
    match soa.data() {
        RData::SOA(record) => assert_eq!(record.minimum(), TTL),
        other => panic!("expected SOA in authority, got {other:?}"),
    }
}

// ── UDP fast path: build_blocked_wire ────────────────────────────────────

fn decode(mode: BlockResponseMode, record_type: RecordType) -> Message {
    let wire = build_blocked_wire(
        0x1234,
        true,
        &[query(record_type)],
        policy(mode),
        false,
        None,
    )
    .expect("wire bytes");
    Message::from_vec(&wire).expect("valid DNS message")
}

#[test]
fn null_ip_a_query_returns_unspecified_v4_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::A);
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 1);
    // Positive answer ⇒ no synthetic SOA.
    assert_eq!(msg.name_servers().len(), 0);
    let answer = &msg.answers()[0];
    assert_eq!(answer.ttl(), TTL);
    match answer.data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_query_returns_unspecified_v6_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::AAAA);
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 1);
    assert_eq!(msg.name_servers().len(), 0);
    let answer = &msg.answers()[0];
    assert_eq!(answer.ttl(), TTL);
    match answer.data() {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("expected AAAA ::, got {other:?}"),
    }
}

#[test]
fn null_ip_non_address_query_is_nodata_with_soa() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::MX);
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[test]
fn nxdomain_mode_sets_nxdomain_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NxDomain, RecordType::A);
    assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[test]
fn nodata_mode_sets_noerror_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NoData, RecordType::A);
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[test]
fn refused_mode_sets_refused_with_no_answer() {
    let msg = decode(BlockResponseMode::Refused, RecordType::A);
    assert_eq!(msg.response_code(), ResponseCode::Refused);
    assert_eq!(msg.answers().len(), 0);
    assert_eq!(msg.name_servers().len(), 0);
}

#[test]
fn edns_request_gets_edns_response_with_ede() {
    let ede = ede::from_domain_error(&DomainError::Blocked);
    let wire = build_blocked_wire(
        0x1234,
        true,
        &[query(RecordType::A)],
        policy(BlockResponseMode::NullIp),
        true,
        ede,
    )
    .expect("wire bytes");
    let msg = Message::from_vec(&wire).expect("valid DNS message");
    assert!(
        msg.extensions().is_some(),
        "EDNS OPT (carrying the EDE) should be present"
    );
}

// ── RequestHandler path: send_blocked_response ───────────────────────────

/// A `ResponseHandler` that captures the serialized wire response so the
/// hickory `RequestHandler` block path can be inspected in-process.
#[derive(Clone, Default)]
struct CapturingHandler {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CapturingHandler {
    fn decoded(&self) -> Message {
        let guard = self.captured.lock().unwrap();
        let bytes = guard.as_ref().expect("a response was sent");
        Message::from_vec(bytes).expect("valid DNS message")
    }
}

#[async_trait]
impl ResponseHandler for CapturingHandler {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut buf = Vec::new();
        let info = {
            let mut encoder = BinEncoder::new(&mut buf);
            response
                .destructive_emit(&mut encoder)
                .map_err(io::Error::other)?
        };
        *self.captured.lock().unwrap() = Some(buf);
        Ok(info)
    }
}

fn make_request(query_type: RecordType, with_edns: bool) -> Request {
    let mut msg = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    msg.add_query(query(query_type));
    msg.set_recursion_desired(true);
    if with_edns {
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(4096);
        msg.set_edns(edns);
    }
    let bytes = msg.to_vec().expect("encoded query");
    let raw = Bytes::from(bytes.clone());
    let req_msg = MessageRequest::from_bytes(&bytes).expect("valid message request");
    let src = "127.0.0.1:5353".parse().unwrap();
    Request::new(req_msg, raw, src, Protocol::Udp)
}

async fn send(mode: BlockResponseMode, query_type: RecordType, with_edns: bool) -> Message {
    let request = make_request(query_type, with_edns);
    let mut handler = CapturingHandler::default();
    let ede = ede::from_domain_error(&DomainError::Blocked);
    let _ = send_blocked_response(
        &request,
        &mut handler,
        name(),
        query_type,
        policy(mode),
        ede,
    )
    .await;
    handler.decoded()
}

#[tokio::test]
async fn send_null_ip_a_returns_unspecified_v4() {
    let msg = send(BlockResponseMode::NullIp, RecordType::A, false).await;
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 1);
    assert_eq!(msg.name_servers().len(), 0);
    match msg.answers()[0].data() {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[tokio::test]
async fn send_null_ip_non_address_is_nodata_with_soa() {
    let msg = send(BlockResponseMode::NullIp, RecordType::MX, false).await;
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[tokio::test]
async fn send_nxdomain_has_soa_and_no_answer() {
    let msg = send(BlockResponseMode::NxDomain, RecordType::A, false).await;
    assert_eq!(msg.response_code(), ResponseCode::NXDomain);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[tokio::test]
async fn send_nodata_has_soa_and_no_answer() {
    let msg = send(BlockResponseMode::NoData, RecordType::A, false).await;
    assert_eq!(msg.response_code(), ResponseCode::NoError);
    assert_eq!(msg.answers().len(), 0);
    assert_soa(&msg);
}

#[tokio::test]
async fn send_refused_delegates_to_error_response() {
    let msg = send(BlockResponseMode::Refused, RecordType::A, false).await;
    assert_eq!(msg.response_code(), ResponseCode::Refused);
    assert_eq!(msg.answers().len(), 0);
    assert_eq!(msg.name_servers().len(), 0);
}

#[tokio::test]
async fn send_edns_request_gets_edns_response() {
    let msg = send(BlockResponseMode::NullIp, RecordType::A, true).await;
    assert!(
        msg.extensions().is_some(),
        "EDNS OPT should be echoed when the query carried one"
    );
}

#[tokio::test]
async fn send_non_edns_request_gets_no_edns() {
    let msg = send(BlockResponseMode::NullIp, RecordType::A, false).await;
    assert!(
        msg.extensions().is_none(),
        "no EDNS OPT should be added when the query lacked one"
    );
}
