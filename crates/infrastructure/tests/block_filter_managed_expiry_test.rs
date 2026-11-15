//! A managed domain past its expiry stops applying at the next compile, even
//! before the expiry job deletes it. Driven against a real migrated database.

use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::BlockSource;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use std::sync::Arc;

const DEFAULT_GROUP_ID: i64 = 1;

#[tokio::test]
async fn test_an_expired_managed_domain_is_not_compiled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    for (name, domain, expires_at) in [
        (
            "expired",
            "expired.example.test",
            Some("2000-01-01 00:00:00"),
        ),
        (
            "current",
            "current.example.test",
            Some("2999-01-01 00:00:00"),
        ),
        ("permanent", "permanent.example.test", None),
    ] {
        sqlx::query(
            "INSERT INTO managed_domains
                 (name, domain, action, group_id, enabled, created_at, updated_at, expires_at)
             VALUES (?, ?, 'deny', ?, 1, '2026-08-01 00:00:00', '2026-08-01 00:00:00', ?)",
        )
        .bind(name)
        .bind(domain)
        .bind(DEFAULT_GROUP_ID)
        .bind(expires_at)
        .execute(&pool)
        .await
        .expect("seed managed domain row");
    }

    let engine = BlockFilterEngine::new(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");
    engine.reload().await.expect("compile block index");

    assert_eq!(
        engine.check("expired.example.test", DEFAULT_GROUP_ID),
        FilterDecision::Allow
    );
    for domain in ["current.example.test", "permanent.example.test"] {
        assert_eq!(
            engine.check(domain, DEFAULT_GROUP_ID),
            FilterDecision::Block(BlockSource::ManagedDomain),
            "{domain}"
        );
    }
}
