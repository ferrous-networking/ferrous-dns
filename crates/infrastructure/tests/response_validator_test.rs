use ferrous_dns_domain::{DnsProtocol, DomainError, UpstreamAddr};
use ferrous_dns_infrastructure::dns::forwarding::{DnsResponse, ResponseParser, ResponseValidator};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::sync::Arc;

const ID: u16 = 0x1234;
const COOKIE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

fn udp() -> DnsProtocol {
    DnsProtocol::Udp {
        addr: UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap()),
    }
}

fn https() -> DnsProtocol {
    DnsProtocol::Https {
        url: Arc::from("https://dns.google/dns-query"),
        hostname: Arc::from("dns.google"),
        resolved_addrs: vec![],
    }
}

fn validator(cookie: Option<[u8; 8]>, case_sensitive: bool, labels: &[&[u8]]) -> ResponseValidator {
    ResponseValidator::new(
        ID,
        labels.iter().map(|l| l.to_vec()).collect(),
        RecordType::A,
        cookie,
        case_sensitive,
    )
}

fn response(id: u16, labels: &[&[u8]], qtype: RecordType, cookie: Option<&[u8]>) -> DnsResponse {
    let name = Name::from_labels(labels.iter().map(|l| l.to_vec())).unwrap();
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);

    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = ResponseCode::NoError;
    msg.add_query(query);
    if let Some(c) = cookie {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_version(0);
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, c.to_vec()));
        msg.set_edns(edns);
    }
    ResponseParser::parse_bytes(msg.to_bytes().unwrap().into()).unwrap()
}

fn is_spoof(result: Result<(), DomainError>) -> bool {
    matches!(result, Err(DomainError::SpoofedResponse { .. }))
}

#[test]
fn accepts_matching_response_with_cookie_and_0x20() {
    let v = validator(Some(COOKIE), true, &[b"eXaMpLe", b"CoM"]);
    let resp = response(ID, &[b"eXaMpLe", b"CoM"], RecordType::A, Some(&COOKIE));
    assert!(v.validate(&resp, &udp()).is_ok());
}

#[test]
fn rejects_wrong_txid() {
    let v = validator(Some(COOKIE), false, &[b"example", b"com"]);
    let resp = response(0x9999, &[b"example", b"com"], RecordType::A, Some(&COOKIE));
    assert!(is_spoof(v.validate(&resp, &udp())));
}

#[test]
fn rejects_qname_case_mismatch_when_0x20() {
    let v = validator(Some(COOKIE), true, &[b"eXaMpLe", b"com"]);
    let resp = response(ID, &[b"example", b"com"], RecordType::A, Some(&COOKIE));
    assert!(is_spoof(v.validate(&resp, &udp())));
}

#[test]
fn accepts_qname_case_difference_when_not_0x20() {
    let v = validator(None, false, &[b"example", b"com"]);
    let resp = response(ID, &[b"ExAmPlE", b"CoM"], RecordType::A, None);
    assert!(v.validate(&resp, &udp()).is_ok());
}

#[test]
fn rejects_qtype_mismatch() {
    let v = validator(None, false, &[b"example", b"com"]);
    let resp = response(ID, &[b"example", b"com"], RecordType::AAAA, None);
    assert!(is_spoof(v.validate(&resp, &udp())));
}

#[test]
fn rejects_wrong_cookie() {
    let v = validator(Some(COOKIE), false, &[b"example", b"com"]);
    let resp = response(
        ID,
        &[b"example", b"com"],
        RecordType::A,
        Some(&[9, 9, 9, 9, 9, 9, 9, 9]),
    );
    assert!(is_spoof(v.validate(&resp, &udp())));
}

#[test]
fn accepts_missing_cookie_gracefully() {
    let v = validator(Some(COOKIE), false, &[b"example", b"com"]);
    let resp = response(ID, &[b"example", b"com"], RecordType::A, None);
    assert!(v.validate(&resp, &udp()).is_ok());
}

#[test]
fn rejects_malformed_short_cookie() {
    let v = validator(Some(COOKIE), false, &[b"example", b"com"]);
    let resp = response(ID, &[b"example", b"com"], RecordType::A, Some(&[1, 2, 3]));
    assert!(is_spoof(v.validate(&resp, &udp())));
}

#[test]
fn skips_cookie_check_on_encrypted_transport() {
    // Wrong cookie, but HTTPS is TLS-authenticated -> cookie echo not enforced.
    let v = validator(Some(COOKIE), false, &[b"example", b"com"]);
    let resp = response(
        ID,
        &[b"example", b"com"],
        RecordType::A,
        Some(&[9, 9, 9, 9, 9, 9, 9, 9]),
    );
    assert!(v.validate(&resp, &https()).is_ok());
}

#[test]
fn skips_0x20_case_check_on_encrypted_transport() {
    // 0x20 was applied (case_sensitive), so the same response over Do53 would be
    // rejected (see `rejects_qname_case_mismatch_when_0x20`). Over HTTPS the
    // upstream may normalize QNAME case; TLS already authenticates it, so a
    // case-only difference must NOT be treated as a spoof.
    let v = validator(Some(COOKIE), true, &[b"eXaMpLe", b"CoM"]);
    let resp = response(ID, &[b"example", b"com"], RecordType::A, Some(&COOKIE));
    assert!(
        v.validate(&resp, &https()).is_ok(),
        "encrypted transport must accept a case-normalized QNAME echo"
    );
    // Sanity: the very same mismatch is still rejected on Do53.
    assert!(is_spoof(v.validate(&resp, &udp())));
}
