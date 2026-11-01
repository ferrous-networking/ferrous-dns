//! CNAME chain names leave the response parser in the form client query names
//! have: no trailing dot, ASCII-lowercase. The block filter and the cache key
//! everything on that form, so a chain name in any other form matches nothing:
//! no block rule (CNAME cloaking) and no cache lookup (#325).

use bytes::Bytes;
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An upstream answer to `qname A` that follows `chain`, one CNAME per hop,
/// and ends in an A record for the last name.
fn chain_answer(qname: &str, chain: &[&str]) -> Bytes {
    let qname = Name::from_str(qname).unwrap();
    let mut msg = Message::new(0x1234, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.add_query(Query::query(qname.clone(), RecordType::A));
    let mut owner = qname;
    for hop in chain {
        let target = Name::from_str(hop).unwrap();
        msg.add_answer(Record::from_rdata(
            owner,
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        owner = target;
    }
    msg.add_answer(Record::from_rdata(
        owner,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    Bytes::from(msg.to_bytes().unwrap())
}

fn parsed_chain(wire: Bytes) -> Vec<String> {
    ResponseParser::parse_bytes(wire)
        .unwrap()
        .cname_chain
        .iter()
        .map(|name| name.to_string())
        .collect()
}

#[test]
fn test_cname_chain_names_have_no_trailing_dot() {
    let chain = parsed_chain(chain_answer(
        "www.site.example.",
        &["www.site.example.edge.example.", "lb.cdn.example."],
    ));

    assert_eq!(chain, ["www.site.example.edge.example", "lb.cdn.example"]);
}

#[test]
fn test_cname_chain_names_are_lowercase() {
    let chain = parsed_chain(chain_answer("www.site.example.", &["LB.CDN.Example."]));

    assert_eq!(chain, ["lb.cdn.example"]);
}
