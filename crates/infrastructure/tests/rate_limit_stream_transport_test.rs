//! The rate-limit slip (issue #339). An over-budget UDP answer may be sent
//! truncated (TC=1) so that a real client retries over TCP, which a spoofed
//! source cannot. That retry has to be answered: the stream transports (TCP,
//! DoT, DoH, DoQ) spend a budget of their own, which a UDP flood cannot
//! drain, and a stream over it is refused, never truncated.

#[path = "support/ports.rs"]
mod ports;
#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, RateLimitConfig, UpstreamPool, UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
use ferrous_dns_infrastructure::dns::server::{BlockPolicy, DnsServerHandler};
use ferrous_dns_infrastructure::dns::PoolManager;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use ports::{AllowAllFilter, NoopQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const TIMEOUT_MS: u64 = 2_000;
const BURST: u32 = 2;
const NX_PER_SECOND: u32 = 1;
/// NXDOMAIN burst capacity is twice the per-second budget.
const NX_BURST: u32 = NX_PER_SECOND * 2;
const STREAMS: [ClientProtocol; 4] = [
    ClientProtocol::Tcp,
    ClientProtocol::Dot,
    ClientProtocol::Doh,
    ClientProtocol::Doq,
];
/// EDE 18, Prohibited: what a rate-limited refusal carries.
const EDE_PROHIBITED: u16 = 18;

struct Fixture {
    _upstream: Upstream,
    handler: DnsServerHandler,
}

/// The server's handler over its resolver stack and cache, one upstream
/// answering `answer`. Every answer over a budget is slipped
/// (`slip_ratio = 1`), and `queries_per_second = 0` so no general budget
/// refills during a test.
async fn fixture(answer: Answer, burst_size: u32, nxdomain_per_second: u32) -> Fixture {
    let upstream = Upstream::spawn(answer).await;
    let pool = UpstreamPool {
        name: "only".into(),
        strategy: UpstreamStrategy::Failover,
        servers: vec![upstream.url()],
        ..Default::default()
    };
    let pm = Arc::new(PoolManager::new(vec![pool], None).await.unwrap());
    let stack = ResolverBuilder::new(pm, TIMEOUT_MS)
        .with_cache(refresh::refresh_cache(1_000, 0.75, 7_200), 7_200, 4)
        .build();
    let use_case =
        HandleDnsQueryUseCase::new(stack, Arc::new(AllowAllFilter), Arc::new(NoopQueryLog))
            .with_rate_limiter(Arc::new(DnsRateLimiter::new(&RateLimitConfig {
                enabled: true,
                queries_per_second: 0,
                burst_size,
                nxdomain_per_second,
                slip_ratio: 1,
                ..RateLimitConfig::default()
            })));
    let policy = BlockPolicy {
        mode: BlockResponseMode::NullIp,
        ttl: 60,
        sinkhole_ipv4: None,
        sinkhole_ipv6: None,
    };
    Fixture {
        _upstream: upstream,
        handler: DnsServerHandler::new(Arc::new(use_case), policy),
    }
}

impl Fixture {
    /// What the server answers an A query for `domain` arriving over `protocol`.
    async fn ask(&self, protocol: ClientProtocol, domain: &str) -> Message {
        let reply = self
            .handler
            .handle_raw_udp_fallback(&query(domain), CLIENT, protocol)
            .await
            .expect("every query is answered");
        Message::from_vec(&reply).expect("the reply decodes")
    }
}

/// An A query for `domain` with an OPT, so a refusal can carry its EDE.
fn query(domain: &str) -> Vec<u8> {
    let mut msg = Message::new(0x5a5a, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    let mut opt = Edns::new();
    opt.set_max_payload(1232);
    msg.set_edns(opt);
    msg.to_bytes().unwrap()
}

fn extended_error(reply: &Message) -> Option<u16> {
    let opt = reply.edns.as_ref()?;
    opt.options().as_ref().iter().find_map(|(_, o)| match o {
        EdnsOption::Unknown(15, data) => Some(u16::from_be_bytes([data[0], data[1]])),
        _ => None,
    })
}

fn is_truncated(reply: &Message) -> bool {
    reply.metadata.truncation && reply.answers.is_empty()
}

fn is_answered(reply: &Message) -> bool {
    !reply.metadata.truncation
        && reply.metadata.response_code == ResponseCode::NoError
        && !reply.answers.is_empty()
}

fn is_nxdomain(reply: &Message) -> bool {
    !reply.metadata.truncation && reply.metadata.response_code == ResponseCode::NXDomain
}

/// The issue's reproduction: a random-subdomain sweep spends the NXDOMAIN
/// budget over UDP, the next NXDOMAIN is slipped, and the client's retry over
/// TCP gets its NXDOMAIN.
#[tokio::test]
async fn an_nxdomain_slipped_over_udp_is_answered_over_tcp() {
    let f = fixture(Answer::NxDomain, 1_000, NX_PER_SECOND).await;
    for i in 0..NX_BURST {
        let reply = f
            .ask(ClientProtocol::Udp, &format!("u{i}.gone.example"))
            .await;
        assert!(is_nxdomain(&reply), "UDP query {i}: {reply:?}");
    }
    let slipped = f.ask(ClientProtocol::Udp, "over.gone.example").await;
    assert!(
        is_truncated(&slipped),
        "the NXDOMAIN over the budget is slipped"
    );

    let retry = f.ask(ClientProtocol::Tcp, "over.gone.example").await;
    assert!(
        is_nxdomain(&retry),
        "the TCP retry must get its NXDOMAIN, got {:?} with TC={}",
        retry.metadata.response_code,
        retry.metadata.truncation
    );
}

#[tokio::test]
async fn a_query_slipped_over_udp_is_answered_over_tcp() {
    let f = fixture(Answer::Address(ADDRESS), BURST, 0).await;
    for i in 0..BURST {
        let reply = f.ask(ClientProtocol::Udp, "www.example").await;
        assert!(is_answered(&reply), "UDP query {i}: {reply:?}");
    }
    let slipped = f.ask(ClientProtocol::Udp, "www.example").await;
    assert!(
        is_truncated(&slipped),
        "the query over the budget is slipped"
    );

    let retry = f.ask(ClientProtocol::Tcp, "www.example").await;
    assert!(
        is_answered(&retry),
        "the TCP retry must be answered, got {:?} with TC={}",
        retry.metadata.response_code,
        retry.metadata.truncation
    );
}

/// TC=1 asks a client to retry over TCP; over a stream it tells the client
/// nothing it can act on. The four stream transports share one budget, so
/// once TCP has spent it, DoT, DoH and DoQ are refused too.
#[tokio::test]
async fn a_stream_over_its_budget_is_refused_never_truncated() {
    let f = fixture(Answer::Address(ADDRESS), BURST, 0).await;
    for i in 0..BURST {
        let reply = f.ask(ClientProtocol::Tcp, "www.example").await;
        assert!(is_answered(&reply), "TCP query {i}: {reply:?}");
    }

    for protocol in STREAMS {
        let reply = f.ask(protocol, "www.example").await;
        assert!(!reply.metadata.truncation, "{protocol:?} was answered TC=1");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::Refused,
            "{protocol:?}"
        );
        assert_eq!(extended_error(&reply), Some(EDE_PROHIBITED), "{protocol:?}");
    }
}

/// A flood that completes a handshake spends the stream budget only, so the
/// subnet's UDP clients keep theirs.
#[tokio::test]
async fn a_stream_flood_leaves_the_udp_budget_alone() {
    let f = fixture(Answer::Address(ADDRESS), BURST, 0).await;
    for _ in 0..BURST {
        f.ask(ClientProtocol::Tcp, "www.example").await;
    }
    let flood = f.ask(ClientProtocol::Tcp, "www.example").await;
    assert_eq!(
        flood.metadata.response_code,
        ResponseCode::Refused,
        "the TCP flood must reach its budget"
    );

    for i in 0..BURST {
        let reply = f.ask(ClientProtocol::Udp, "www.example").await;
        assert!(
            is_answered(&reply),
            "UDP query {i} after the TCP flood: {:?} with TC={}",
            reply.metadata.response_code,
            reply.metadata.truncation
        );
    }
}
