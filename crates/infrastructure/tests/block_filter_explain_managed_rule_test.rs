//! `explain` names each managed deny rule that blocks a domain, exact or
//! wildcard, so the Query Log can show and remove the rule behind a block.

use ferrous_dns_application::ports::BlockFilterEnginePort;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{BlockMatchKind, MatchType};
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::SqlitePool;
use std::sync::Arc;

const DEFAULT_GROUP_ID: i64 = 1;
const KIDS: i64 = 2;

async fn insert_deny(pool: &SqlitePool, name: &str, domain: &str, group_id: i64) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO managed_domains
             (name, domain, action, group_id, enabled, created_at, updated_at)
         VALUES (?, ?, 'deny', ?, 1, '2026-08-01 00:00:00', '2026-08-01 00:00:00')
         RETURNING id",
    )
    .bind(name)
    .bind(domain)
    .bind(group_id)
    .fetch_one(pool)
    .await
    .expect("seed managed domain row")
}

fn managed_matches(
    engine: &BlockFilterEngine,
    domain: &str,
    group_id: i64,
) -> Vec<(Option<i64>, String, MatchType)> {
    let mut found: Vec<_> = engine
        .explain(domain, group_id)
        .block_matches
        .into_iter()
        .filter(|m| m.kind == BlockMatchKind::ManagedDomain)
        .map(|m| (m.source_id, m.name, m.match_type))
        .collect();
    found.sort_by_key(|(id, _, _)| *id);
    found
}

#[tokio::test]
async fn test_explain_names_every_managed_deny_rule_that_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    sqlx::query("INSERT INTO groups (id, name) VALUES (?, 'Kids')")
        .bind(KIDS)
        .execute(&pool)
        .await
        .expect("seed group");
    let ads_exact = insert_deny(&pool, "Ads exact", "ads.example.test", DEFAULT_GROUP_ID).await;
    let ads_again = insert_deny(&pool, "Ads again", "ads.example.test", DEFAULT_GROUP_ID).await;
    let example_tree = insert_deny(&pool, "Example tree", "*.example.test", DEFAULT_GROUP_ID).await;
    let ads_tree = insert_deny(&pool, "Ads tree", "*.ads.example.test", DEFAULT_GROUP_ID).await;
    insert_deny(&pool, "Kids only", "*.example.test", KIDS).await;

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
        managed_matches(&engine, "ads.example.test", DEFAULT_GROUP_ID),
        vec![
            (Some(ads_exact), "Ads exact".to_string(), MatchType::Exact),
            (Some(ads_again), "Ads again".to_string(), MatchType::Exact),
            (
                Some(example_tree),
                "Example tree".to_string(),
                MatchType::Wildcard
            ),
        ],
        "a `*.` rule never matches its own apex"
    );
    assert_eq!(
        managed_matches(&engine, "pixel.ads.example.test", DEFAULT_GROUP_ID),
        vec![
            (
                Some(example_tree),
                "Example tree".to_string(),
                MatchType::Wildcard
            ),
            (Some(ads_tree), "Ads tree".to_string(), MatchType::Wildcard),
        ]
    );
    assert!(
        managed_matches(&engine, "other.test", DEFAULT_GROUP_ID).is_empty(),
        "no rule, no match"
    );
}
