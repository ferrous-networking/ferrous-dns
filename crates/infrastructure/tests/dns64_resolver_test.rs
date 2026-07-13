use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::Dns64Resolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

fn prefix() -> Ipv6Addr {
    Ipv6Addr::from_str("64:ff9b::").unwrap()
}

/// Minimal DNS message wire with the given response code and answers.
fn message_wire(rcode: ResponseCode, answers: Vec<Record>) -> Bytes {
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.metadata.response_code = rcode;
    for answer in answers {
        msg.add_answer(answer);
    }
    let mut buf = Vec::new();
    let mut enc = BinEncoder::new(&mut buf);
    msg.emit(&mut enc).unwrap();
    Bytes::from(buf)
}

fn empty_resolution(rcode: ResponseCode) -> DnsResolution {
    DnsResolution {
        addresses: Arc::new(vec![]),
        cache_hit: false,
        local_dns: false,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: Some(300),
        negative_soa_ttl: None,
        upstream_wire_data: Some(message_wire(rcode, vec![])),
    }
}

#[derive(Default)]
struct MockInner {
    /// Real AAAA answer; when non-empty the AAAA query is not a NODATA.
    aaaa_addrs: Vec<IpAddr>,
    /// Response code for the (empty) AAAA answer (NoError = NODATA).
    aaaa_rcode: Option<ResponseCode>,
    /// Addresses returned for the A re-query.
    a_addrs: Vec<IpAddr>,
    a_dnssec: Option<&'static str>,
    /// PTR target for `*.in-addr.arpa` queries (None = no PTR).
    ptr_target: Option<String>,
    calls: Mutex<Vec<(String, RecordType)>>,
}

impl MockInner {
    fn calls(&self) -> Vec<(String, RecordType)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsResolver for MockInner {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls
            .lock()
            .unwrap()
            .push((query.domain.to_string(), query.record_type));

        match query.record_type {
            RecordType::AAAA => {
                if self.aaaa_addrs.is_empty() {
                    Ok(empty_resolution(
                        self.aaaa_rcode.unwrap_or(ResponseCode::NoError),
                    ))
                } else {
                    let mut res = empty_resolution(ResponseCode::NoError);
                    res.addresses = Arc::new(self.aaaa_addrs.clone());
                    Ok(res)
                }
            }
            RecordType::A => {
                if self.a_addrs.is_empty() {
                    Ok(empty_resolution(ResponseCode::NoError))
                } else {
                    let mut res = empty_resolution(ResponseCode::NoError);
                    res.addresses = Arc::new(self.a_addrs.clone());
                    res.dnssec_status = self.a_dnssec;
                    Ok(res)
                }
            }
            RecordType::PTR => {
                if query.domain.ends_with(".in-addr.arpa") {
                    if let Some(ref target) = self.ptr_target {
                        let owner = Name::from_str(&query.domain).unwrap();
                        let rec = Record::from_rdata(
                            owner,
                            120,
                            RData::PTR(PTR(Name::from_str(target).unwrap())),
                        );
                        let mut res = empty_resolution(ResponseCode::NoError);
                        res.upstream_wire_data =
                            Some(message_wire(ResponseCode::NoError, vec![rec]));
                        return Ok(res);
                    }
                }
                Ok(empty_resolution(ResponseCode::NoError))
            }
            _ => Ok(empty_resolution(ResponseCode::NoError)),
        }
    }
}

fn aaaa_query() -> DnsQuery {
    DnsQuery::new("example.com", RecordType::AAAA)
}

#[tokio::test]
async fn synthesizes_aaaa_from_a_on_nodata() {
    let inner = Arc::new(MockInner {
        a_addrs: vec!["93.184.216.34".parse().unwrap()],
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver.resolve(&aaaa_query()).await.unwrap();

    assert_eq!(
        *res.addresses,
        vec![IpAddr::V6(
            Ipv6Addr::from_str("64:ff9b::5db8:d822").unwrap()
        )]
    );
    // Synthetic AAAA must not carry a DNSSEC status (AD must not be set).
    assert_eq!(res.dnssec_status, None);
    // The A re-query was issued.
    assert!(inner
        .calls()
        .iter()
        .any(|(d, rt)| d == "example.com" && *rt == RecordType::A));
}

#[tokio::test]
async fn passes_through_when_aaaa_present() {
    let real_aaaa = IpAddr::V6("2606:2800:220:1::1".parse().unwrap());
    let inner = Arc::new(MockInner {
        aaaa_addrs: vec![real_aaaa],
        a_addrs: vec!["93.184.216.34".parse().unwrap()],
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver.resolve(&aaaa_query()).await.unwrap();

    assert_eq!(*res.addresses, vec![real_aaaa]);
    // No A re-query when a real AAAA exists.
    assert!(!inner.calls().iter().any(|(_, rt)| *rt == RecordType::A));
}

#[tokio::test]
async fn passes_through_on_nxdomain() {
    let inner = Arc::new(MockInner {
        aaaa_rcode: Some(ResponseCode::NXDomain),
        a_addrs: vec!["93.184.216.34".parse().unwrap()],
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver.resolve(&aaaa_query()).await.unwrap();

    assert!(res.addresses.is_empty());
    // NXDOMAIN must not trigger an A re-query.
    assert!(!inner.calls().iter().any(|(_, rt)| *rt == RecordType::A));
}

#[tokio::test]
async fn skips_when_all_a_addresses_are_private() {
    let inner = Arc::new(MockInner {
        a_addrs: vec!["10.0.0.5".parse().unwrap(), "192.168.1.2".parse().unwrap()],
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver.resolve(&aaaa_query()).await.unwrap();
    assert!(
        res.addresses.is_empty(),
        "private A must not be synthesized"
    );
}

#[tokio::test]
async fn skips_synthesis_for_dnssec_bogus_a() {
    let inner = Arc::new(MockInner {
        a_addrs: vec!["93.184.216.34".parse().unwrap()],
        a_dnssec: Some("Bogus"),
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver.resolve(&aaaa_query()).await.unwrap();
    assert!(res.addresses.is_empty(), "Bogus A must not be synthesized");
}

#[tokio::test]
async fn reverse_ptr_answer_owner_is_ip6_arpa_name() {
    // 64:ff9b::5db8:d822 (== 93.184.216.34) reversed under ip6.arpa.
    let ip6_arpa = "2.2.8.d.8.b.d.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa";
    let inner = Arc::new(MockInner {
        ptr_target: Some("host.example.com".to_string()),
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver
        .resolve(&DnsQuery::new(ip6_arpa, RecordType::PTR))
        .await
        .unwrap();

    // The in-addr.arpa PTR was queried with the embedded IPv4 (93.184.216.34).
    assert!(inner
        .calls()
        .iter()
        .any(|(d, rt)| d == "34.216.184.93.in-addr.arpa" && *rt == RecordType::PTR));

    // The synthesized answer must be owned by the ip6.arpa query name.
    let wire = res.upstream_wire_data.expect("reverse PTR wire");
    let msg = Message::from_vec(&wire).unwrap();
    let answer = msg.answers.first().expect("a PTR answer");
    assert_eq!(
        answer.name.to_string().trim_end_matches('.'),
        ip6_arpa,
        "PTR answer must be owned by the ip6.arpa query name, not in-addr.arpa"
    );
    match &answer.data {
        RData::PTR(ptr) => assert_eq!(ptr.0.to_string().trim_end_matches('.'), "host.example.com"),
        other => panic!("expected PTR rdata, got {other:?}"),
    }
}

#[tokio::test]
async fn reverse_ptr_falls_back_when_ipv4_has_no_ptr() {
    let ip6_arpa = "2.2.8.d.8.b.d.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa";
    let inner = Arc::new(MockInner {
        ptr_target: None,
        ..Default::default()
    });
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    let res = resolver
        .resolve(&DnsQuery::new(ip6_arpa, RecordType::PTR))
        .await
        .unwrap();

    // No fabricated PTR answer.
    let msg = Message::from_vec(&res.upstream_wire_data.unwrap()).unwrap();
    assert!(msg.answers.is_empty());
}

#[tokio::test]
async fn non_prefix_ptr_passes_through() {
    let inner = Arc::new(MockInner::default());
    let resolver = Dns64Resolver::new(Arc::clone(&inner) as Arc<dyn DnsResolver>, prefix());

    // A PTR for an address outside the NAT64 prefix is forwarded untouched.
    let res = resolver
        .resolve(&DnsQuery::new("1.1.1.1.in-addr.arpa", RecordType::PTR))
        .await
        .unwrap();
    assert!(res.addresses.is_empty());
    // Only the original PTR query was made (no in-addr.arpa re-query for a v4
    // embedded in the prefix).
    assert_eq!(inner.calls().len(), 1);
}
