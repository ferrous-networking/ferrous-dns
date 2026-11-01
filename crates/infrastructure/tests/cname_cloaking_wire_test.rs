//! CNAME cloaking on real upstream answers and the real block filter. A tracker
//! served under a first-party name (`metrics.site.example CNAME
//! x.tracker.example`) is blocked when any name in the chain is. The chain
//! comes from the wire, where every name ends in a dot; the cloaking tests in
//! the application crate feed it without one, so they never saw a chain that
//! no rule could match.

#[path = "support/ports.rs"]
mod ports;
#[path = "support/refresh.rs"]
mod refresh;
#[path = "support/upstream.rs"]
mod upstream;

use ferrous_dns_application::ports::{BlockFilterEnginePort, QueryLogRepository};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{
    BlockSource, DnsRequest, DomainError, RecordType, UpstreamPool, UpstreamStrategy,
};
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::resolver::ResolverBuilder;
use ferrous_dns_infrastructure::dns::{BlockFilterEngine, PoolManager};
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use ports::RecordingQueryLog;
use sqlx::SqlitePool;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use upstream::{Answer, Upstream};

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
const ALIAS: &str = "metrics.site.example";
const TRACKER: &str = "x.tracker.example";
const TRACKER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const TIMEOUT_MS: u64 = 2_000;

struct Fixture {
    log: Arc<RecordingQueryLog>,
    use_case: HandleDnsQueryUseCase,
    _upstream: Upstream,
    _dir: tempfile::TempDir,
}

async fn seed_managed(pool: &SqlitePool, domain: &str, action: &str) {
    sqlx::query(
        "INSERT INTO managed_domains
             (name, domain, action, group_id, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, '2026-10-31T00:00:00Z', '2026-10-31T00:00:00Z')",
    )
    .bind(format!("{action}-{domain}"))
    .bind(domain)
    .bind(action)
    .bind(DEFAULT_GROUP_ID)
    .execute(pool)
    .await
    .expect("seed managed domain row");
}

/// The use case over the server's resolver stack and the real block filter,
/// with `denied` as managed denies and one upstream answering `answer`.
async fn fixture(answer: Answer, denied: &[&str]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    for domain in denied {
        seed_managed(&pool, domain, "deny").await;
    }
    let engine = BlockFilterEngine::new(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");
    // `new` compiles in the background; `reload` compiles inline.
    engine.reload().await.expect("compile block index");

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
    let log = Arc::new(RecordingQueryLog::default());
    let use_case = HandleDnsQueryUseCase::new(
        stack,
        engine as Arc<dyn BlockFilterEnginePort>,
        Arc::clone(&log) as Arc<dyn QueryLogRepository>,
    );
    Fixture {
        log,
        use_case,
        _upstream: upstream,
        _dir: dir,
    }
}

impl Fixture {
    async fn ask(&self, domain: &str) -> Result<Vec<IpAddr>, DomainError> {
        self.use_case
            .execute(&DnsRequest::new(domain, RecordType::A, CLIENT))
            .await
            .map(|resolution| resolution.addresses.as_ref().clone())
    }

    fn last_block_source(&self) -> Option<BlockSource> {
        self.log.logged().last().and_then(|row| row.block_source)
    }
}

#[tokio::test]
async fn test_a_chain_through_a_blocked_name_is_blocked() {
    let f = fixture(Answer::Cname("x.tracker.example.", TRACKER_IP), &[TRACKER]).await;

    let answer = f.ask(ALIAS).await;

    assert!(
        matches!(answer, Err(DomainError::Blocked)),
        "the alias resolved through a blocked name: {answer:?}"
    );
    assert_eq!(f.last_block_source(), Some(BlockSource::CnameCloaking));
}

#[tokio::test]
async fn test_a_chain_through_allowed_names_resolves() {
    let f = fixture(Answer::Cname("lb.cdn.example.", TRACKER_IP), &[TRACKER]).await;

    assert_eq!(f.ask(ALIAS).await.unwrap(), vec![IpAddr::V4(TRACKER_IP)]);
    assert_eq!(f.last_block_source(), None);
}
