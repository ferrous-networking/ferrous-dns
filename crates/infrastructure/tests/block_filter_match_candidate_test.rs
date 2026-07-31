//! Integration tests for the real `BlockFilterEngine::match_candidate` — the
//! candidate-list parser + matcher used by the what-if backtest. These exercise
//! the genuine parser (hosts/adblock/wildcard/substring/comments) and regex
//! compilation, which the application-layer unit tests stub out via a fake engine.

use ferrous_dns_application::ports::BlockFilterEnginePort;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use std::sync::Arc;

/// Builds a real engine against a fresh migrated temp DB. `match_candidate` does
/// not consult the compiled index, so an empty database is sufficient. The
/// returned `TempDir` must be kept alive for the duration of the test.
async fn build_engine() -> (Arc<BlockFilterEngine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    let engine = BlockFilterEngine::new(pool, 1, Arc::new(ScheduleStateStore::new()), true)
        .await
        .expect("build engine");
    (engine, dir)
}

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn match_candidate_parses_list_formats_and_regex() {
    let (engine, _dir) = build_engine().await;

    let domains = v(&[
        "ads.example.com",     // 0: hosts line  -> exact match
        "EXAMPLE.COM",         // 1: plain exact, matched case-insensitively
        "sub.tracker.io",      // 2: *.tracker.io wildcard -> subdomain matches
        "ads.doubleclick.net", // 3: ||doubleclick.net^ covers subdomains -> matches
        "doubleclick.net",     // 4: ||doubleclick.net^ covers the domain itself -> matches
        "x.trackme.net",       // 5: /trackme/ substring pattern -> matches
        "cdn42.example.org",   // 6: regex ^cdn[0-9]+\. -> matches
        "exception.com",       // 7: @@ exception line is ignored -> no match
        "github.com",          // 8: nothing matches
    ]);
    let list = v(&[
        "0.0.0.0 ads.example.com",
        "example.com",
        "*.tracker.io",
        "||doubleclick.net^",
        "/trackme/",
        "# a comment, ignored",
        "@@exception.com",
        "",
    ]);
    let regexes = v(&["^cdn[0-9]+\\."]);

    let result = engine
        .match_candidate(&domains, &list, &regexes)
        .expect("match_candidate ok");

    assert_eq!(
        result,
        vec![true, true, true, true, true, true, true, false, false],
        "candidate matching must respect parsed exact/wildcard/substring/regex semantics"
    );
}

#[tokio::test]
async fn match_candidate_rejects_invalid_regex() {
    let (engine, _dir) = build_engine().await;
    let err = engine
        .match_candidate(&v(&["x.com"]), &[], &v(&["(unclosed"]))
        .expect_err("invalid regex must error");
    assert!(matches!(err, DomainError::InvalidDomainName(_)));
}

#[tokio::test]
async fn match_candidate_empty_candidate_matches_nothing() {
    let (engine, _dir) = build_engine().await;
    let result = engine
        .match_candidate(&v(&["a.com", "b.net"]), &[], &[])
        .expect("ok");
    assert_eq!(result, vec![false, false]);
}
