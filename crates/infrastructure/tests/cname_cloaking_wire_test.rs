//! CNAME cloaking on real upstream answers and the real block filter. A tracker
//! served under a first-party name (`metrics.site.example CNAME
//! x.tracker.example`) is blocked when any name in the chain is. The chain
//! comes off the wire, where its names end in a dot, and is matched against
//! rules written without one.
//!
//! The block has to hold for a cached answer too: once its memo is gone, or for
//! a client group that never saw the fresh answer.

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
/// In the default group, where the rules apply.
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
/// In a second group with no rules.
const GUEST: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const ALIAS: &str = "metrics.site.example";
const TRACKER: &str = "x.tracker.example";
const TRACKER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const TIMEOUT_MS: u64 = 2_000;

struct Fixture {
    log: Arc<RecordingQueryLog>,
    use_case: HandleDnsQueryUseCase,
    engine: Arc<BlockFilterEngine>,
    upstream: Upstream,
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

/// `GUEST`'s subnet in a group of its own, which no rule names.
async fn seed_guest_group(pool: &SqlitePool) {
    let group_id: i64 =
        sqlx::query_scalar("INSERT INTO groups (name) VALUES ('guests') RETURNING id")
            .fetch_one(pool)
            .await
            .expect("seed guest group");
    sqlx::query("INSERT INTO client_subnets (subnet_cidr, group_id) VALUES ('198.51.100.0/24', ?)")
        .bind(group_id)
        .execute(pool)
        .await
        .expect("seed guest subnet");
}

/// The use case over the server's resolver stack and the real block filter.
/// `rules` are managed domains of the default group, as `(domain, action)`;
/// one upstream answers `answer`.
async fn fixture(answer: Answer, rules: &[(&str, &str)]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    for (domain, action) in rules {
        seed_managed(&pool, domain, action).await;
    }
    seed_guest_group(&pool).await;
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
    engine
        .load_client_groups()
        .await
        .expect("load client groups");

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
        Arc::clone(&engine) as Arc<dyn BlockFilterEnginePort>,
        Arc::clone(&log) as Arc<dyn QueryLogRepository>,
    );
    Fixture {
        log,
        use_case,
        engine,
        upstream,
        _dir: dir,
    }
}

impl Fixture {
    async fn ask_as(
        &self,
        client: IpAddr,
        record_type: RecordType,
    ) -> Result<Vec<IpAddr>, DomainError> {
        self.use_case
            .execute(&DnsRequest::new(ALIAS, record_type, client))
            .await
            .map(|resolution| resolution.addresses.as_ref().clone())
    }

    async fn ask(&self) -> Result<Vec<IpAddr>, DomainError> {
        self.ask_as(CLIENT, RecordType::A).await
    }

    fn last_block_source(&self) -> Option<BlockSource> {
        self.log.logged().last().and_then(|row| row.block_source)
    }
}

#[track_caller]
fn assert_blocked(answer: Result<Vec<IpAddr>, DomainError>) {
    assert!(
        matches!(answer, Err(DomainError::Blocked)),
        "the alias resolved through a blocked name: {answer:?}"
    );
}

#[tokio::test]
async fn test_a_chain_through_a_blocked_name_is_blocked() {
    let f = fixture(
        Answer::Cname("x.tracker.example.", TRACKER_IP),
        &[(TRACKER, "deny")],
    )
    .await;

    assert_blocked(f.ask().await);
    assert_eq!(f.last_block_source(), Some(BlockSource::CnameCloaking));
}

#[tokio::test]
async fn test_a_chain_through_allowed_names_resolves() {
    let f = fixture(
        Answer::Cname("lb.cdn.example.", TRACKER_IP),
        &[(TRACKER, "deny")],
    )
    .await;

    assert_eq!(f.ask().await.unwrap(), vec![IpAddr::V4(TRACKER_IP)]);
    assert_eq!(f.last_block_source(), None);
}

/// A reload drops the block memo, so the second answer is the cached one.
#[tokio::test]
async fn test_a_cached_answer_stays_blocked_after_a_reload() {
    let f = fixture(
        Answer::Cname("x.tracker.example.", TRACKER_IP),
        &[(TRACKER, "deny")],
    )
    .await;
    assert_blocked(f.ask().await);

    f.engine.reload().await.unwrap();

    assert_blocked(f.ask().await);
    assert_eq!(f.last_block_source(), Some(BlockSource::CnameCloaking));
    assert_eq!(
        f.upstream.queries(),
        1,
        "the second answer is the cached one"
    );
}

/// The guest group has no rule against the tracker, so its query caches the
/// alias's answer; a client in the default group must still be refused it.
#[tokio::test]
async fn test_an_answer_another_group_cached_stays_blocked() {
    let f = fixture(
        Answer::Cname("x.tracker.example.", TRACKER_IP),
        &[(TRACKER, "deny")],
    )
    .await;
    assert_eq!(
        f.ask_as(GUEST, RecordType::A).await.unwrap(),
        vec![IpAddr::V4(TRACKER_IP)]
    );

    assert_blocked(f.ask().await);
    assert_eq!(
        f.upstream.queries(),
        1,
        "the default group got the cached one"
    );
}

#[tokio::test]
async fn test_a_cached_wire_answer_stays_blocked() {
    let f = fixture(
        Answer::Cname("x.tracker.example.", TRACKER_IP),
        &[(TRACKER, "deny")],
    )
    .await;
    assert_blocked(f.ask_as(CLIENT, RecordType::MX).await);

    f.engine.reload().await.unwrap();

    assert_blocked(f.ask_as(CLIENT, RecordType::MX).await);
    assert_eq!(
        f.upstream.queries(),
        1,
        "the second answer is the cached one"
    );
}

#[tokio::test]
async fn test_an_explicit_allow_on_the_alias_lifts_the_block() {
    let f = fixture(
        Answer::Cname("x.tracker.example.", TRACKER_IP),
        &[(TRACKER, "deny"), (ALIAS, "allow")],
    )
    .await;

    assert_eq!(f.ask().await.unwrap(), vec![IpAddr::V4(TRACKER_IP)]);
    assert_eq!(
        f.ask().await.unwrap(),
        vec![IpAddr::V4(TRACKER_IP)],
        "and from the cache"
    );
}
