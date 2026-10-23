//! A query that arrives while an identical one is already waiting on the
//! upstream joins it: one upstream request answers both. The joiner, a
//! coalesced follower, got an upstream answer, so it is logged as one, with
//! the server that gave it, not as a cache hit.

#[path = "support/ports.rs"]
mod ports;
#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    CoalescedRole, DnsRequest, QueryLog, RecordType, UpstreamPool, UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
use ferrous_dns_infrastructure::dns::PoolManager;
use ports::{AllowAllFilter, RecordingQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use upstream::{Answer, Upstream};

const NAME: &str = "shared.example";
const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LAPTOP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
const PHONE: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 31));
const TIMEOUT_MS: u64 = 2_000;

struct Fixture {
    upstream: Upstream,
    log: Arc<RecordingQueryLog>,
    use_case: HandleDnsQueryUseCase,
}

/// The use case over the server's resolver stack and cache, with one slow
/// upstream, so a second query arrives while the first one waits.
async fn fixture() -> Fixture {
    let upstream = Upstream::spawn(Answer::Address(ANSWER)).await;
    upstream.set_delay(Duration::from_millis(300));
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
    let log = Arc::new(RecordingQueryLog::default());
    let use_case = HandleDnsQueryUseCase::new(
        stack,
        Arc::new(AllowAllFilter),
        Arc::clone(&log) as Arc<dyn QueryLogRepository>,
    );
    Fixture {
        upstream,
        log,
        use_case,
    }
}

fn row_of(log: &RecordingQueryLog, client: IpAddr) -> QueryLog {
    log.logged()
        .into_iter()
        .find(|row| row.client_ip == client)
        .unwrap_or_else(|| panic!("no row for {client}"))
}

#[tokio::test]
async fn a_coalesced_follower_is_logged_as_the_upstream_answer_it_got() {
    let f = fixture().await;

    let laptop = DnsRequest::new(NAME, RecordType::A, LAPTOP);
    let phone = DnsRequest::new(NAME, RecordType::A, PHONE);
    let (first, second) = tokio::join!(f.use_case.execute(&laptop), async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        f.use_case.execute(&phone).await
    });
    first.unwrap();
    second.unwrap();
    assert_eq!(f.upstream.queries(), 1, "the phone's query must coalesce");

    let leader = row_of(&f.log, LAPTOP);
    let follower = row_of(&f.log, PHONE);
    assert!(!leader.cache_hit);
    assert!(
        !follower.cache_hit,
        "the follower's answer came from the upstream, not the cache"
    );
    assert_eq!(follower.upstream_server, leader.upstream_server);
    assert_eq!(follower.upstream_pool, leader.upstream_pool);
    assert!(follower.upstream_server.is_some());
    assert_eq!(leader.coalesced, Some(CoalescedRole::Leader));
    assert_eq!(follower.coalesced, Some(CoalescedRole::Follower));
}

/// Guard: a query nothing joined took no part in coalescing, and neither
/// does the cache hit that follows it.
#[tokio::test]
async fn a_query_nothing_joined_is_not_marked() {
    let f = fixture().await;

    f.use_case
        .execute(&DnsRequest::new(NAME, RecordType::A, LAPTOP))
        .await
        .unwrap();
    f.use_case
        .execute(&DnsRequest::new(NAME, RecordType::A, PHONE))
        .await
        .unwrap();

    assert_eq!(row_of(&f.log, LAPTOP).coalesced, None);
    let hit = row_of(&f.log, PHONE);
    assert!(hit.cache_hit);
    assert_eq!(hit.coalesced, None);
}
