//! What `DnsServerHandler::handle_raw_udp_fallback` puts on the wire for each
//! resolution outcome: RCODE, EDE, OPT, AD and COOKIE. The encoders have their
//! own tests; these pin the handler's choices, decoding every reply with hickory.

#[path = "support/ports.rs"]
mod ports;

use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsCookiesConfig, DnsQuery, DnssecStatus, DomainError,
};
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use ports::{AllowAllFilter, NoopQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const ID: u16 = 0x5a5a;
const CLIENT_COOKIE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// Answers every query with one fixed outcome, never from cache.
struct Scripted(Result<DnsResolution, DomainError>);

#[async_trait]
impl DnsResolver for Scripted {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.0.clone()
    }
}

/// The handler, and the COOKIE payload it must return for `CLIENT_COOKIE`.
fn server(outcome: Result<DnsResolution, DomainError>) -> (DnsServerHandler, Vec<u8>) {
    let cookies = DnsCookiesConfig {
        require_valid_cookie: false,
        ..DnsCookiesConfig::default()
    };
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(Scripted(outcome)),
        Arc::new(AllowAllFilter),
        Arc::new(NoopQueryLog),
    )
    .with_dns_cookies(DnsCookieGuard::from_config(&cookies, [7; 32]));
    let server_cookie = use_case
        .cookie_guard()
        .expect("cookies are enabled")
        .generate_server_cookie(CLIENT, &CLIENT_COOKIE);
    let handler = DnsServerHandler::new(Arc::new(use_case), POLICY);
    (handler, [&CLIENT_COOKIE[..], &server_cookie].concat())
}

const POLICY: BlockPolicy = BlockPolicy {
    mode: BlockResponseMode::NullIp,
    ttl: 60,
    sinkhole_ipv4: None,
    sinkhole_ipv6: None,
};

/// A handler with `[dns_cookies] enabled = false`: no cookie guard at all.
fn server_without_cookies(outcome: Result<DnsResolution, DomainError>) -> DnsServerHandler {
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(Scripted(outcome)),
        Arc::new(AllowAllFilter),
        Arc::new(NoopQueryLog),
    );
    DnsServerHandler::new(Arc::new(use_case), POLICY)
}

fn name() -> Name {
    Name::from_ascii("example.com.").unwrap()
}

/// `edns: Some(dnssec_ok)` sends an OPT, carrying `CLIENT_COOKIE` if `cookie`.
fn query(qtype: RecordType, edns: Option<bool>, cookie: bool, cd: bool) -> Vec<u8> {
    query_with_cookie(qtype, edns, cookie.then_some(&CLIENT_COOKIE[..]), cd)
}

/// Like [`query`], with the COOKIE option carrying exactly `cookie`.
fn query_with_cookie(
    qtype: RecordType,
    edns: Option<bool>,
    cookie: Option<&[u8]>,
    cd: bool,
) -> Vec<u8> {
    let mut msg = Message::new(ID, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.checking_disabled = cd;
    msg.add_query(Query::query(name(), qtype));
    if let Some(dnssec_ok) = edns {
        let mut opt = Edns::new();
        opt.set_max_payload(1232).set_dnssec_ok(dnssec_ok);
        if let Some(cookie) = cookie {
            opt.options_mut()
                .insert(EdnsOption::Unknown(10, cookie.to_vec()));
        }
        msg.set_edns(opt);
    }
    msg.to_bytes().unwrap()
}

async fn ask_raw(handler: &DnsServerHandler, query: &[u8]) -> Vec<u8> {
    handler
        .handle_raw_udp_fallback(query, CLIENT, ClientProtocol::Udp)
        .await
        .expect("every outcome is answered")
}

async fn ask(handler: &DnsServerHandler, query: &[u8]) -> Message {
    let reply = Message::from_vec(&ask_raw(handler, query).await).unwrap();
    assert_eq!(reply.metadata.id, ID);
    assert!(reply.metadata.recursion_desired);
    assert_eq!(reply.queries.len(), 1);
    reply
}

fn option(msg: &Message, code: u16) -> Option<Vec<u8>> {
    let opt = msg.edns.as_ref()?;
    opt.options().as_ref().iter().find_map(|(_, o)| match o {
        EdnsOption::Unknown(c, data) if *c == code => Some(data.clone()),
        _ => None,
    })
}

fn answer(status: Option<DnssecStatus>) -> DnsResolution {
    DnsResolution {
        dnssec_status: status,
        ..DnsResolution::new(vec!["192.0.2.10".parse().unwrap()], false)
    }
}

/// A cached upstream TXT answer with its own OPT and COOKIE echo.
fn relayed(status: Option<DnssecStatus>) -> DnsResolution {
    let mut msg = Message::new(0xBEEF, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name(), RecordType::TXT));
    msg.add_answer(Record::from_rdata(
        name(),
        300,
        RData::TXT(TXT::new(vec!["v=spf1 -all".into()])),
    ));
    let mut opt = Edns::new();
    opt.options_mut()
        .insert(EdnsOption::Unknown(10, vec![9; 24]));
    msg.set_edns(opt);
    DnsResolution {
        upstream_wire_data: Some(Bytes::from(msg.to_bytes().unwrap())),
        dnssec_status: status,
        ..DnsResolution::new(Vec::new(), false)
    }
}

#[tokio::test]
async fn outcomes_map_to_rcode_extended_error_and_block_answer() {
    use DomainError as E;
    use ResponseCode::{NXDomain, NoError, Refused, ServFail};
    // (outcome, RCODE, EDE info code, answered with the NullIp sinkhole)
    let cases = [
        (E::NxDomain, NXDomain, None, false),
        (E::LocalNxDomain, NXDomain, None, false),
        (E::DnsRateLimited, Refused, Some(18), false),
        (E::DnsCookieInvalid, Refused, Some(25), false),
        (E::QueryTimeout, ServFail, Some(22), false),
        (E::DnssecBogus, ServFail, Some(6), false),
        (E::InvalidDomainName("x".into()), ServFail, None, false),
        (E::Blocked, NoError, Some(15), true),
        (E::DgaDomainDetected, NoError, Some(15), true),
        (E::FilteredQuery("p".into()), NoError, Some(15), true),
        (E::DnsTunnelingDetected, NoError, Some(18), true),
    ];
    let q = query(RecordType::A, Some(false), false, false);
    for (err, rcode, ede, sinkholed) in cases {
        let reply = ask(&server(Err(err.clone())).0, &q).await;
        let sinkhole = RData::A(Ipv4Addr::UNSPECIFIED.into());
        let got_ede = option(&reply, 15).map(|d| u16::from_be_bytes([d[0], d[1]]));
        assert_eq!(reply.metadata.response_code, rcode, "{err:?}");
        assert_eq!(got_ede, ede, "{err:?}");
        assert_eq!(
            reply.answers.iter().map(|r| &r.data).collect::<Vec<_>>(),
            if sinkholed { vec![&sinkhole] } else { vec![] },
            "{err:?}"
        );
    }

    let slip = ask(&server(Err(E::DnsRateLimitedSlip)).0, &q).await;
    assert!(slip.metadata.truncation && slip.answers.is_empty());
}

#[tokio::test]
async fn a_shed_query_is_dropped_over_udp_and_answered_servfail_on_streams() {
    let handler = server_without_cookies(Err(DomainError::UpstreamCapacityExhausted));
    let q = query(RecordType::A, Some(false), false, false);

    // The UDP client retries; a stream client would wait out its timeout.
    assert!(handler
        .handle_raw_udp_fallback(&q, CLIENT, ClientProtocol::Udp)
        .await
        .is_none());
    for protocol in [
        ClientProtocol::Tcp,
        ClientProtocol::Dot,
        ClientProtocol::Doh,
        ClientProtocol::Doq,
    ] {
        let reply = handler
            .handle_raw_udp_fallback(&q, CLIENT, protocol)
            .await
            .expect("stream transports are answered");
        let reply = Message::from_vec(&reply).unwrap();
        assert_eq!(reply.metadata.id, ID, "{protocol:?}");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::ServFail,
            "{protocol:?}"
        );
        assert!(reply.answers.is_empty(), "{protocol:?}");
    }
}

#[tokio::test]
async fn built_answers_carry_opt_exactly_when_the_query_did() {
    let outcomes = [
        (Ok(answer(None)), true),
        (Err(DomainError::NxDomain), false),
        (Err(DomainError::Blocked), false),
    ];
    for (outcome, answered) in outcomes {
        let label = format!("{outcome:?}");
        let (handler, our_cookie) = server(outcome);

        let plain = ask(&handler, &query(RecordType::A, None, false, false)).await;
        assert!(
            plain.edns.is_none(),
            "{label}: OPT without one in the query"
        );

        let reply = ask(&handler, &query(RecordType::A, Some(true), true, false)).await;
        let opt = reply.edns.as_ref().expect("OPT echoed");
        assert!(opt.flags().dnssec_ok, "{label}: DO copied (RFC 3225 §3)");
        assert_eq!(opt.max_payload(), 4096, "{label}");
        if answered {
            assert_eq!(option(&reply, 10), Some(our_cookie), "RFC 7873 §5.2");
        }
    }
}

#[tokio::test]
async fn ad_bit_needs_a_secure_answer_to_a_do_client_without_cd() {
    let cases = [
        (answer(Some(DnssecStatus::Secure)), Some(true), false, true),
        (
            answer(Some(DnssecStatus::Secure)),
            Some(false),
            false,
            false,
        ),
        (answer(Some(DnssecStatus::Secure)), None, false, false),
        (answer(Some(DnssecStatus::Secure)), Some(true), true, false),
        (
            answer(Some(DnssecStatus::Insecure)),
            Some(true),
            false,
            false,
        ),
        (relayed(Some(DnssecStatus::Secure)), Some(true), false, true),
        (
            relayed(Some(DnssecStatus::Secure)),
            Some(false),
            false,
            false,
        ),
    ];
    for (resolution, edns, cd, ad) in cases {
        let label = format!("{:?}, DO {edns:?}, CD {cd}", resolution.dnssec_status);
        let q = query(RecordType::A, edns, false, cd);
        let reply = Message::from_vec(&ask_raw(&server(Ok(resolution)).0, &q).await).unwrap();
        assert_eq!(reply.metadata.authentic_data, ad, "{label}");
    }
}

#[tokio::test]
async fn relayed_answers_keep_upstream_records_under_our_id_and_cookie() {
    let (handler, our_cookie) = server(Ok(relayed(None)));
    let upstream = Message::from_vec(&relayed(None).upstream_wire_data.unwrap()).unwrap();

    for (cookie, expected) in [(false, None), (true, Some(our_cookie))] {
        let q = query(RecordType::TXT, Some(true), cookie, false);
        let reply = ask(&handler, &q).await;
        assert_eq!(reply.answers, upstream.answers);
        let opt = reply.edns.as_ref().expect("OPT echoed");
        assert!(opt.flags().dnssec_ok, "DO copied (RFC 3225 §3)");
        assert_eq!(
            option(&reply, 10),
            expected,
            "the upstream's cookie echo never reaches the client"
        );
    }
}

/// RFC 6891 §7: a query without OPT gets a reply without one, even when the
/// cached upstream answer carries its own OPT (and COOKIE echo). RD comes from
/// the query, not from the upstream exchange, which always sets it.
#[tokio::test]
async fn relayed_answers_to_a_query_without_opt_carry_no_opt() {
    let (handler, _) = server(Ok(relayed(None)));
    let upstream = Message::from_vec(&relayed(None).upstream_wire_data.unwrap()).unwrap();

    let mut q = Message::from_vec(&query(RecordType::TXT, None, false, false)).unwrap();
    q.metadata.recursion_desired = false;
    let reply = Message::from_vec(&ask_raw(&handler, &q.to_bytes().unwrap()).await).unwrap();

    assert!(reply.edns.is_none(), "OPT without one in the query");
    assert_eq!(reply.metadata.id, ID);
    assert!(
        !reply.metadata.recursion_desired,
        "RD is copied from the query"
    );
    assert_eq!(reply.answers, upstream.answers);
}

/// With `[dns_cookies] enabled = false` the server does not speak RFC 7873:
/// a client cookie gets no COOKIE option back, on built or relayed answers.
#[tokio::test]
async fn disabled_cookies_are_never_echoed() {
    let q = query(RecordType::TXT, Some(false), true, false);
    for outcome in [Ok(answer(None)), Ok(relayed(None))] {
        let label = format!("{outcome:?}");
        let reply = ask(&server_without_cookies(outcome), &q).await;
        assert!(reply.edns.is_some(), "{label}: OPT echoed");
        assert_eq!(option(&reply, 10), None, "{label}");
    }
}

/// RFC 7873 §5.2.2: a COOKIE option that is not 8 or 16..=40 bytes long is a
/// FORMERR, not a cookie silently cut down to 40 bytes.
#[tokio::test]
async fn malformed_cookie_lengths_are_formerr() {
    let (handler, _) = server(Ok(answer(None)));
    for len in [7usize, 12, 41] {
        let cookie = vec![0xAB; len];
        let q = query_with_cookie(RecordType::A, Some(false), Some(&cookie), false);
        let reply = ask(&handler, &q).await;
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::FormErr,
            "{len} bytes"
        );
        assert!(reply.answers.is_empty(), "{len} bytes");
    }
}

/// RFC 6891 §7: the OPT a client gets is ours. An upstream message that
/// does not re-section (here, a second OPT) cannot be relayed without the
/// upstream's, so the client gets SERVFAIL under our OPT and cookie.
#[tokio::test]
async fn unresectionable_upstream_answers_are_servfail_under_our_opt() {
    let mut resolution = relayed(None);
    let mut wire = resolution.upstream_wire_data.take().unwrap().to_vec();
    wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    wire[11] += 1;
    resolution.upstream_wire_data = Some(Bytes::from(wire));
    let (handler, cookie) = server(Ok(resolution));

    let reply = ask(&handler, &query(RecordType::TXT, Some(false), true, false)).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.answers.is_empty());
    assert_eq!(
        option(&reply, 10),
        Some(cookie),
        "our cookie, not the upstream's echo"
    );

    let reply = ask(&handler, &query(RecordType::TXT, None, false, false)).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.edns.is_none());
}
