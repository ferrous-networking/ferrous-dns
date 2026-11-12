//! Issue #382: a disabled group's clients, matched by IP, subnet or DoH ID,
//! resolve to the default group, so that group's rules apply to them instead
//! of their own. Driven against a real migrated SQLite database.

use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::BlockSource;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::SqlitePool;
use std::net::IpAddr;
use std::sync::Arc;

const DEFAULT_GROUP_ID: i64 = 1;
const ADULTS: i64 = 2;
const KIDS: i64 = 3;

/// Assigned to Kids by IP.
const KIDS_IP: &str = "10.0.0.50";
/// Inside Kids' subnet, `10.0.3.0/24`.
const KIDS_SUBNET_IP: &str = "10.0.3.9";
/// Assigned to Kids by IP, inside Adults' subnet `10.0.2.0/24`.
const KIDS_IP_IN_ADULTS_SUBNET: &str = "10.0.2.50";
/// Inside Adults' subnet.
const ADULTS_SUBNET_IP: &str = "10.0.2.9";
/// Assigned to Adults by IP.
const ADULTS_IP: &str = "10.0.1.7";
/// No assignment.
const OTHER_IP: &str = "192.168.1.10";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

async fn seed(pool: &SqlitePool, kids_enabled: bool) {
    sqlx::query("INSERT INTO groups (id, name, enabled, is_default) VALUES (?, 'Adults', 1, 0), (?, 'Kids', ?, 0)")
        .bind(ADULTS)
        .bind(KIDS)
        .bind(kids_enabled)
        .execute(pool)
        .await
        .expect("seed groups");
    sqlx::query("INSERT INTO clients (ip_address, group_id) VALUES (?, ?), (?, ?), (?, ?)")
        .bind(KIDS_IP)
        .bind(KIDS)
        .bind(KIDS_IP_IN_ADULTS_SUBNET)
        .bind(KIDS)
        .bind(ADULTS_IP)
        .bind(ADULTS)
        .execute(pool)
        .await
        .expect("seed IP clients");
    sqlx::query(
        "INSERT INTO client_subnets (subnet_cidr, group_id) VALUES ('10.0.3.0/24', ?), ('10.0.2.0/24', ?)",
    )
    .bind(KIDS)
    .bind(ADULTS)
    .execute(pool)
    .await
    .expect("seed subnets");
    sqlx::query(
        "INSERT INTO doh_ids (name, client_id, group_id) VALUES
         ('Kids Tablet', 'kids-tablet', ?), ('Adult Phone', 'adult-phone', ?)",
    )
    .bind(KIDS)
    .bind(ADULTS)
    .execute(pool)
    .await
    .expect("seed DoH IDs");
}

async fn set_kids_enabled(pool: &SqlitePool, enabled: bool) {
    sqlx::query("UPDATE groups SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(KIDS)
        .execute(pool)
        .await
        .expect("toggle Kids");
}

async fn engine_over(
    kids_enabled: bool,
) -> (Arc<BlockFilterEngine>, SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    seed(&pool, kids_enabled).await;
    let engine = BlockFilterEngine::new(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");
    (engine, pool, dir)
}

/// Kids' three kinds of match, as the group each one resolves to.
fn kids_matches(engine: &BlockFilterEngine) -> [i64; 3] {
    [
        engine.resolve_group(ip(KIDS_IP)),
        engine.resolve_group(ip(KIDS_SUBNET_IP)),
        engine.resolve_group_for_request(ip(OTHER_IP), Some("kids-tablet")),
    ]
}

#[tokio::test]
async fn test_clients_of_a_disabled_group_resolve_to_the_default_group() {
    let (engine, _pool, _dir) = engine_over(false).await;

    assert_eq!(
        kids_matches(&engine),
        [DEFAULT_GROUP_ID; 3],
        "IP, subnet and DoH ID matches of disabled Kids"
    );
    assert_eq!(
        engine.resolve_group(ip(KIDS_IP_IN_ADULTS_SUBNET)),
        DEFAULT_GROUP_ID,
        "a disabled match goes to the default group, not to the next match"
    );
    assert!(
        engine.is_doh_id_registered("kids-tablet"),
        "a disabled group's DoH ID is still registered"
    );

    assert_eq!(engine.resolve_group(ip(ADULTS_IP)), ADULTS);
    assert_eq!(engine.resolve_group(ip(ADULTS_SUBNET_IP)), ADULTS);
    assert_eq!(
        engine.resolve_group_for_request(ip(KIDS_IP), Some("adult-phone")),
        ADULTS
    );
    assert_eq!(engine.resolve_group(ip(OTHER_IP)), DEFAULT_GROUP_ID);
}

#[tokio::test]
async fn test_toggling_enabled_takes_effect_on_the_next_load() {
    let (engine, pool, _dir) = engine_over(true).await;
    assert_eq!(kids_matches(&engine), [KIDS; 3]);

    set_kids_enabled(&pool, false).await;
    engine.load_client_groups().await.expect("reload");
    assert_eq!(kids_matches(&engine), [DEFAULT_GROUP_ID; 3]);

    set_kids_enabled(&pool, true).await;
    engine.load_client_groups().await.expect("reload");
    assert_eq!(kids_matches(&engine), [KIDS; 3]);
}

#[tokio::test]
async fn test_a_disabled_groups_deny_no_longer_blocks_its_clients() {
    let (engine, pool, _dir) = engine_over(true).await;
    for (name, domain, group_id) in [
        ("kids-deny", "kids-only.example.test", KIDS),
        (
            "protected-deny",
            "protected-only.example.test",
            DEFAULT_GROUP_ID,
        ),
    ] {
        sqlx::query(
            "INSERT INTO managed_domains
                 (name, domain, action, group_id, enabled, created_at, updated_at)
             VALUES (?, ?, 'deny', ?, 1, '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
        )
        .bind(name)
        .bind(domain)
        .bind(group_id)
        .execute(&pool)
        .await
        .expect("seed managed domain row");
    }
    engine.reload().await.expect("compile block index");
    let check = |domain: &str| engine.check(domain, engine.resolve_group(ip(KIDS_IP)));

    assert_eq!(
        check("kids-only.example.test"),
        FilterDecision::Block(BlockSource::ManagedDomain)
    );
    assert_eq!(check("protected-only.example.test"), FilterDecision::Allow);

    set_kids_enabled(&pool, false).await;
    engine.load_client_groups().await.expect("reload");

    assert_eq!(
        check("kids-only.example.test"),
        FilterDecision::Allow,
        "a disabled group's own deny"
    );
    assert_eq!(
        check("protected-only.example.test"),
        FilterDecision::Block(BlockSource::ManagedDomain),
        "the default group's deny"
    );
}
