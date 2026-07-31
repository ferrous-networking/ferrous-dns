//! Integration tests for block filter decisions under decision-cache eviction
//! pressure, driven through the public `BlockFilterEnginePort` surface.
//!
//! These guard the L1 decision cache: it is only a cache, so a domain's verdict
//! must come out the same whether the answer was served from the cache or
//! recomputed from the compiled index after the entry was evicted. They also
//! guard the cost of eviction itself, which used to scan the whole cache twice
//! per insert once it was full.

use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::BlockSource;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The seeded `groups` row is `id = 1, is_default = 1`; manual `blocklist`
/// entries are compiled with `MANUAL_SOURCE_BIT`, which `build_group_masks`
/// grants to every group, so the default group sees them.
const DEFAULT_GROUP_ID: i64 = 1;

const BLOCKED: &str = "ads.blocked-example.test";
const ALLOWED: &str = "content.allowed-example.test";

/// Builds a real engine over a fresh migrated temp DB seeded with `blocked`
/// as manual blocklist entries.
///
/// Only exact entries are used: wildcard, adblock and substring rules are
/// gated behind a bloom filter that the compiler populates with exact entries
/// only, so they do not match at runtime and would make these tests vacuous.
///
/// The returned `TempDir` must be kept alive for the duration of the test.
async fn build_engine(blocked: &[&str]) -> (Arc<BlockFilterEngine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");

    for domain in blocked {
        sqlx::query("INSERT INTO blocklist (domain) VALUES (?)")
            .bind(domain)
            .execute(&pool)
            .await
            .expect("seed blocklist row");
    }

    let engine = BlockFilterEngine::new(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");

    // `new` kicks compilation off in a background task, so the index is still
    // empty on return. `reload` compiles inline and awaits it, which makes the
    // index deterministically ready here without sleeping.
    engine.reload().await.expect("compile block index");
    assert_eq!(
        engine.compiled_domain_count(),
        blocked.len(),
        "index must hold exactly the seeded domains before any assertions run"
    );

    (engine, dir)
}

fn assert_verdicts(engine: &Arc<BlockFilterEngine>, stage: &str) {
    assert_eq!(
        engine.check(BLOCKED, DEFAULT_GROUP_ID),
        FilterDecision::Block(BlockSource::Blocklist),
        "{stage}: a manual blocklist entry must be blocked"
    );
    assert_eq!(
        engine.check(ALLOWED, DEFAULT_GROUP_ID),
        FilterDecision::Allow,
        "{stage}: a domain with no rule must be allowed"
    );
}

#[tokio::test]
async fn manual_blocklist_entry_is_blocked_and_unrelated_domain_is_allowed() {
    let (engine, _dir) = build_engine(&[BLOCKED]).await;
    assert_verdicts(&engine, "fresh index");
}

/// The regression this file exists for. Pushing far more distinct domains
/// through `check` than the decision cache holds forces continuous eviction;
/// the verdicts for `BLOCKED` and `ALLOWED` are evicted along the way and must
/// be recomputed correctly from the compiled index.
#[tokio::test]
async fn verdicts_survive_high_cardinality_decision_cache_churn() {
    let (engine, _dir) = build_engine(&[BLOCKED]).await;

    // Establish the verdicts are real before churning, otherwise re-asserting
    // them afterwards would prove nothing.
    assert_verdicts(&engine, "before churn");

    // The L1 decision cache holds 100_000 entries, so 150_000 distinct domains
    // overflow it by half and guarantee sustained eviction.
    const CHURN: usize = 150_000;
    let churn_domains: Vec<String> = (0..CHURN)
        .map(|i| format!("churn-{i}.example.test"))
        .collect();

    let start = Instant::now();
    for domain in &churn_domains {
        // Every one of these is a decision-cache miss followed by an insert,
        // which is the path that used to pay for eviction.
        assert_eq!(
            engine.check(domain, DEFAULT_GROUP_ID),
            FilterDecision::Allow,
            "churn domains carry no rule and must be allowed"
        );
    }
    let elapsed = start.elapsed();

    // Correctness first: a timing regression must not mask a wrong verdict.
    assert_verdicts(&engine, "after churn");

    // Calibration: the O(1) eviction path runs this loop in ~0.8s in a debug
    // build. The scanning implementation it replaced sustained roughly 1_900
    // cache inserts/sec even in a release build, which puts 150_000 of them at
    // ~79s, and a debug build of that scan would be far slower still. A 40s
    // bound therefore leaves ~50x headroom over the current cost while still
    // sitting ~2x under the old one.
    assert!(
        elapsed < Duration::from_secs(40),
        "churning {CHURN} domains took {elapsed:?}, which suggests decision-cache \
         eviction is scanning the cache instead of evicting in constant time"
    );
}
