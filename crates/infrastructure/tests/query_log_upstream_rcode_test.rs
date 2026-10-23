//! The query log records the rcode the client got. An upstream's NXDOMAIN is
//! relayed as the upstream's own message, so the resolver hands it back as a
//! resolution rather than an error. It must still be logged as NXDOMAIN —
//! fresh, from the cache, on the fast path, for a coalesced follower and on a
//! refresh — or the dashboard, the `reply` filter and the Pi-hole API report
//! it as NOERROR. NODATA is a NOERROR answer and stays one.

#[path = "support/ports.rs"]
mod ports;
#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::{DnsResolver, QueryLogRepository};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    ClientProtocol, DnsRequest, QueryLog, RecordType, UpstreamPool, UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::resolver::{CoreResolver, ResolverBuilder};
use ferrous_dns_infrastructure::dns::{DnsCache, DnsCacheMaintenance, PoolManager};
use ports::{AllowAllFilter, RecordingQueryLog};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use upstream::{Answer, Upstream};

const NAME: &str = "gone.example";
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const TIMEOUT_MS: u64 = 2_000;

struct Fixture {
    upstream: Upstream,
    pm: Arc<PoolManager>,
    cache: Arc<DnsCache>,
    log: Arc<RecordingQueryLog>,
    use_case: HandleDnsQueryUseCase,
}

/// The use case over the server's resolver stack and cache, with one
/// upstream answering `answer`.
async fn fixture(answer: Answer) -> Fixture {
    let upstream = Upstream::spawn(answer).await;
    let pool = UpstreamPool {
        name: "only".into(),
        strategy: UpstreamStrategy::Failover,
        servers: vec![upstream.url()],
        ..Default::default()
    };
    let pm = Arc::new(PoolManager::new(vec![pool], None).await.unwrap());
    let cache = refresh::refresh_cache(1_000, 0.75, 7_200);
    let stack = ResolverBuilder::new(Arc::clone(&pm), TIMEOUT_MS)
        .with_cache(Arc::clone(&cache), 7_200, 4)
        .build();
    let log = Arc::new(RecordingQueryLog::default());
    let use_case = HandleDnsQueryUseCase::new(
        stack,
        Arc::new(AllowAllFilter),
        Arc::clone(&log) as Arc<dyn QueryLogRepository>,
    );
    Fixture {
        upstream,
        pm,
        cache,
        log,
        use_case,
    }
}

async fn execute(use_case: &HandleDnsQueryUseCase, record_type: RecordType) {
    use_case
        .execute(&DnsRequest::new(NAME, record_type, CLIENT))
        .await
        .unwrap_or_else(|e| panic!("{NAME} {record_type}: {e}"));
}

/// `(cache_hit, response_status)` of every row logged for a client query.
fn client_rows(log: &RecordingQueryLog) -> Vec<(bool, Option<&'static str>)> {
    log.logged()
        .iter()
        .filter(|row| !row.cache_refresh)
        .map(|row: &QueryLog| (row.cache_hit, row.response_status))
        .collect()
}

#[tokio::test]
async fn upstream_nxdomain_is_logged_as_nxdomain() {
    let f = fixture(Answer::NxDomain).await;

    execute(&f.use_case, RecordType::A).await;

    assert_eq!(client_rows(&f.log), vec![(false, Some("NXDOMAIN"))]);
}

#[tokio::test]
async fn cached_upstream_nxdomain_is_logged_as_nxdomain() {
    let f = fixture(Answer::NxDomain).await;

    execute(&f.use_case, RecordType::A).await;
    execute(&f.use_case, RecordType::A).await;

    assert_eq!(f.upstream.queries(), 1, "the second query is a cache hit");
    assert_eq!(
        client_rows(&f.log),
        vec![(false, Some("NXDOMAIN")), (true, Some("NXDOMAIN"))]
    );
}

/// A non-address type is answered from its cached wire on the UDP fast path.
#[tokio::test]
async fn fast_path_hit_on_upstream_nxdomain_is_logged_as_nxdomain() {
    let f = fixture(Answer::NxDomain).await;

    execute(&f.use_case, RecordType::TXT).await;
    let answered = f.use_case.try_cache_wire_direct(
        NAME,
        RecordType::TXT,
        CLIENT,
        ClientProtocol::Udp,
        |_, _| Some(()),
    );

    assert!(
        answered.is_some(),
        "the fast path must answer the cached NXDOMAIN"
    );
    assert_eq!(
        client_rows(&f.log),
        vec![(false, Some("NXDOMAIN")), (true, Some("NXDOMAIN"))]
    );
}

/// A query that joins another's in-flight upstream fetch gets its answer.
#[tokio::test]
async fn coalesced_follower_of_upstream_nxdomain_is_logged_as_nxdomain() {
    let f = fixture(Answer::NxDomain).await;
    f.upstream.set_delay(Duration::from_millis(300));

    tokio::join!(
        execute(&f.use_case, RecordType::A),
        execute(&f.use_case, RecordType::A)
    );

    assert_eq!(f.upstream.queries(), 1, "the second query must coalesce");
    let statuses: Vec<_> = client_rows(&f.log).into_iter().map(|(_, s)| s).collect();
    assert_eq!(statuses, vec![Some("NXDOMAIN"), Some("NXDOMAIN")]);
}

#[tokio::test]
async fn refreshed_upstream_nxdomain_is_logged_as_nxdomain() {
    let f = fixture(Answer::NxDomain).await;
    execute(&f.use_case, RecordType::A).await;

    let _ticker = coarse_clock::start_clock_ticker();
    let (stale, stale_rx) = mpsc::channel(16);
    f.cache.set_stale_repairs(stale.clone());
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&f.cache),
        Arc::new(CoreResolver::new(Arc::clone(&f.pm), TIMEOUT_MS, false)) as Arc<dyn DnsResolver>,
        Some(Arc::clone(&f.log) as Arc<dyn QueryLogRepository>),
        stale_rx,
        refresh::no_ranking(),
    );
    stale
        .send((Arc::from(NAME), RecordType::A, 0))
        .await
        .unwrap();

    let refreshed = refresh::wait_until(Duration::from_secs(3), || {
        f.log.logged().iter().any(|row| row.cache_refresh)
    })
    .await;
    assert!(refreshed, "the repair must renew the entry and log it");
    let refresh_statuses: Vec<_> = f
        .log
        .logged()
        .iter()
        .filter(|row| row.cache_refresh)
        .map(|row| row.response_status)
        .collect();
    assert_eq!(refresh_statuses, vec![Some("NXDOMAIN")]);
}

/// Guard: an answer, and a NODATA, stay NOERROR.
#[tokio::test]
async fn upstream_answer_and_nodata_stay_noerror() {
    let f = fixture(Answer::Address(Ipv4Addr::new(192, 0, 2, 1))).await;

    execute(&f.use_case, RecordType::A).await;
    execute(&f.use_case, RecordType::TXT).await;
    execute(&f.use_case, RecordType::TXT).await;

    assert_eq!(
        client_rows(&f.log),
        vec![
            (false, Some("NOERROR")),
            (false, Some("NOERROR")),
            (true, Some("NOERROR"))
        ]
    );
}

/// Guard: an NXDOMAIN that still carries addresses is answered with them,
/// as NOERROR, so it logs NOERROR — for the leader and its follower alike.
#[tokio::test]
async fn upstream_nxdomain_with_addresses_logs_the_noerror_the_client_gets() {
    let ip = Ipv4Addr::new(192, 0, 2, 1);
    let f = fixture(Answer::NxDomainWithAddress(ip)).await;
    f.upstream.set_delay(Duration::from_millis(300));

    let request = DnsRequest::new(NAME, RecordType::A, CLIENT);
    let (leader, follower) =
        tokio::join!(f.use_case.execute(&request), f.use_case.execute(&request));

    for resolution in [leader, follower] {
        assert_eq!(resolution.unwrap().addresses.as_ref(), &[IpAddr::V4(ip)]);
    }
    assert_eq!(f.upstream.queries(), 1, "the second query must coalesce");
    let statuses: Vec<_> = client_rows(&f.log).into_iter().map(|(_, s)| s).collect();
    assert_eq!(statuses, vec![Some("NOERROR"), Some("NOERROR")]);
}
