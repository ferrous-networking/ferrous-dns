use ferrous_dns_domain::{DnsProtocol, RecordType, UpstreamAddr};
use ferrous_dns_infrastructure::dns::forwarding::{
    DnsResponse, HardeningOpts, MessageBuilder, ResponseParser,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{DNSClass, Name, RecordType as HRecordType};
use hickory_proto::serialize::binary::BinEncodable;

fn hardened() -> HardeningOpts {
    HardeningOpts {
        cookie: true,
        qname_0x20: true,
    }
}

fn udp() -> DnsProtocol {
    DnsProtocol::Udp {
        addr: UpstreamAddr::Resolved("8.8.8.8:53".parse().unwrap()),
    }
}

fn cookie_of(msg: &Message) -> Option<Vec<u8>> {
    msg.extensions().as_ref().and_then(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .find_map(|(_, opt)| match opt {
                EdnsOption::Unknown(10, data) => Some(data.clone()),
                _ => None,
            })
    })
}

fn labels(msg: &Message) -> Vec<Vec<u8>> {
    msg.queries()[0].name().iter().map(|l| l.to_vec()).collect()
}

fn has_upper(labels: &[Vec<u8>]) -> bool {
    labels.iter().any(|l| l.iter().any(u8::is_ascii_uppercase))
}

fn build_response(id: u16, name: &Name, qtype: HRecordType, cookie: Option<&[u8]>) -> DnsResponse {
    let mut query = Query::new();
    query.set_name(name.clone());
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);

    let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
    msg.set_response_code(ResponseCode::NoError);
    msg.add_query(query);
    if let Some(c) = cookie {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, c.to_vec()));
        msg.set_edns(edns);
    }
    ResponseParser::parse_bytes(msg.to_bytes().unwrap().into()).unwrap()
}

#[test]
fn a_query_carries_cookie() {
    let (bytes, _) =
        MessageBuilder::build_query_hardened("example.com", &RecordType::A, false, hardened())
            .unwrap();
    let msg = Message::from_vec(&bytes).unwrap();
    assert_eq!(
        cookie_of(&msg).map(|c| c.len()),
        Some(8),
        "A query must carry an 8-byte client cookie"
    );
}

#[test]
fn a_query_randomizes_qname_case() {
    // 0x20 is random per build; across many builds at least one must show an
    // uppercase letter (all-lowercase odds per build are ~2^-10).
    let saw_upper = (0..16).any(|_| {
        let (bytes, _) =
            MessageBuilder::build_query_hardened("example.com", &RecordType::A, false, hardened())
                .unwrap();
        has_upper(&labels(&Message::from_vec(&bytes).unwrap()))
    });
    assert!(saw_upper, "A query qname must be 0x20 case-randomized");
}

#[test]
fn aaaa_query_carries_cookie_and_randomizes_qname_case() {
    // AAAA is the other address type the gate hardens alongside A: every build
    // must carry a cookie, and across many builds at least one must show 0x20 case.
    let saw_upper = (0..16).any(|_| {
        let (bytes, _) = MessageBuilder::build_query_hardened(
            "example.com",
            &RecordType::AAAA,
            false,
            hardened(),
        )
        .unwrap();
        let msg = Message::from_vec(&bytes).unwrap();
        assert_eq!(
            cookie_of(&msg).map(|c| c.len()),
            Some(8),
            "AAAA query must carry an 8-byte client cookie"
        );
        has_upper(&labels(&msg))
    });
    assert!(saw_upper, "AAAA query qname must be 0x20 case-randomized");
}

#[test]
fn non_address_query_is_plain() {
    for rt in [RecordType::MX, RecordType::TXT] {
        for _ in 0..16 {
            let (bytes, _) =
                MessageBuilder::build_query_hardened("example.com", &rt, false, hardened())
                    .unwrap();
            let msg = Message::from_vec(&bytes).unwrap();
            assert!(cookie_of(&msg).is_none(), "{rt:?} must not carry a cookie");
            assert!(
                !has_upper(&labels(&msg)),
                "{rt:?} must not be case-randomized"
            );
        }
    }
}

#[test]
fn a_query_is_plain_when_opts_disabled() {
    let (bytes, _) = MessageBuilder::build_query_hardened(
        "example.com",
        &RecordType::A,
        false,
        HardeningOpts::default(),
    )
    .unwrap();
    let msg = Message::from_vec(&bytes).unwrap();
    assert!(cookie_of(&msg).is_none());
    assert!(!has_upper(&labels(&msg)));
}

#[test]
fn returned_validator_accepts_faithful_echo_and_rejects_tampered_cookie() {
    let (bytes, validator) =
        MessageBuilder::build_query_hardened("example.org", &RecordType::A, false, hardened())
            .unwrap();
    let query = Message::from_vec(&bytes).unwrap();
    let id = query.id();
    let name = query.queries()[0].name().clone();
    let cookie = cookie_of(&query).unwrap();

    let faithful = build_response(id, &name, HRecordType::A, Some(&cookie));
    assert!(
        validator.validate(&faithful, &udp()).is_ok(),
        "a faithful echo must validate"
    );

    let mut tampered = cookie.clone();
    tampered[0] ^= 0xFF;
    let bad = build_response(id, &name, HRecordType::A, Some(&tampered));
    assert!(
        validator.validate(&bad, &udp()).is_err(),
        "a tampered cookie must be rejected"
    );
}
