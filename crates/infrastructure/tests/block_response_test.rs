//! Integration tests for the domain-verdict block responder on the raw UDP
//! fast path (`build_blocked_wire`) for every `BlockResponseMode`.

use ferrous_dns_domain::{BlockResponseMode, DomainError};
use ferrous_dns_infrastructure::dns::ede;
use ferrous_dns_infrastructure::dns::server::{build_blocked_wire, BlockPolicy};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

const TTL: u32 = 120;

fn name() -> Name {
    Name::from_str("ads.example.com.").unwrap()
}

fn query(record_type: RecordType) -> Query {
    Query::query(name(), record_type)
}

fn policy(mode: BlockResponseMode) -> BlockPolicy {
    BlockPolicy {
        mode,
        ttl: TTL,
        sinkhole_ipv4: None,
        sinkhole_ipv6: None,
    }
}

/// Asserts the authority section carries exactly one synthetic SOA with the
/// block TTL (so the negative answer is negatively cacheable, RFC 2308).
fn assert_soa(msg: &Message) {
    assert_eq!(msg.authorities.len(), 1, "expected one SOA in authority");
    let soa = &msg.authorities[0];
    assert_eq!(soa.ttl, TTL);
    match &soa.data {
        RData::SOA(record) => assert_eq!(record.minimum, TTL),
        other => panic!("expected SOA in authority, got {other:?}"),
    }
}

// ── UDP fast path: build_blocked_wire ────────────────────────────────────

fn decode(mode: BlockResponseMode, record_type: RecordType) -> Message {
    decode_with(policy(mode), record_type)
}

fn decode_with(policy: BlockPolicy, record_type: RecordType) -> Message {
    let wire = build_blocked_wire(0x1234, true, &[query(record_type)], policy, false, None)
        .expect("wire bytes");
    Message::from_vec(&wire).expect("valid DNS message")
}

#[test]
fn null_ip_a_query_returns_unspecified_v4_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1);
    // Positive answer ⇒ no synthetic SOA.
    assert_eq!(msg.authorities.len(), 0);
    let answer = &msg.answers[0];
    assert_eq!(answer.ttl, TTL);
    match &answer.data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_query_returns_unspecified_v6_with_ttl() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::AAAA);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1);
    assert_eq!(msg.authorities.len(), 0);
    let answer = &msg.answers[0];
    assert_eq!(answer.ttl, TTL);
    match &answer.data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("expected AAAA ::, got {other:?}"),
    }
}

#[test]
fn null_ip_a_query_uses_custom_sinkhole_ipv4() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv4 = Some(Ipv4Addr::new(192, 168, 1, 2));
    let msg = decode_with(p, RecordType::A);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::new(192, 168, 1, 2)),
        other => panic!("expected custom A, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_query_uses_custom_sinkhole_ipv6() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv6 = Some(Ipv6Addr::from_str("fd00::2").unwrap());
    let msg = decode_with(p, RecordType::AAAA);
    assert_eq!(msg.answers.len(), 1);
    match &msg.answers[0].data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::from_str("fd00::2").unwrap()),
        other => panic!("expected custom AAAA, got {other:?}"),
    }
}

#[test]
fn null_ip_aaaa_falls_back_to_unspecified_when_only_v4_set() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv4 = Some(Ipv4Addr::new(192, 168, 1, 2));
    let msg = decode_with(p, RecordType::AAAA);
    match &msg.answers[0].data {
        RData::AAAA(aaaa) => assert_eq!(aaaa.0, Ipv6Addr::UNSPECIFIED),
        other => panic!("expected AAAA ::, got {other:?}"),
    }
}

#[test]
fn null_ip_a_falls_back_to_unspecified_when_only_v6_set() {
    let mut p = policy(BlockResponseMode::NullIp);
    p.sinkhole_ipv6 = Some(Ipv6Addr::from_str("fd00::2").unwrap());
    let msg = decode_with(p, RecordType::A);
    match &msg.answers[0].data {
        RData::A(a) => assert_eq!(a.0, Ipv4Addr::UNSPECIFIED),
        other => panic!("expected A 0.0.0.0, got {other:?}"),
    }
}

#[test]
fn null_ip_non_address_query_is_nodata_with_soa() {
    let msg = decode(BlockResponseMode::NullIp, RecordType::MX);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn nxdomain_mode_sets_nxdomain_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NxDomain, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn nodata_mode_sets_noerror_with_soa_and_no_answer() {
    let msg = decode(BlockResponseMode::NoData, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 0);
    assert_soa(&msg);
}

#[test]
fn refused_mode_sets_refused_with_no_answer() {
    let msg = decode(BlockResponseMode::Refused, RecordType::A);
    assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
    assert_eq!(msg.answers.len(), 0);
    assert_eq!(msg.authorities.len(), 0);
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
        msg.edns.is_some(),
        "EDNS OPT (carrying the EDE) should be present"
    );
}
