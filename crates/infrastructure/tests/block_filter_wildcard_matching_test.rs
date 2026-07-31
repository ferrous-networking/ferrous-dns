//! Regression tests for the blocklist rule shapes that are not literal domain
//! names: `*.example.test` suffix rules, adblock `||example.test^` rules and
//! `/substring/` patterns.
//!
//! All three used to be unreachable at runtime. `BlockIndex::is_blocked`
//! short-circuited on a bloom filter that the compiler populates with exact
//! entries only, so any name that was not itself an exact entry was answered
//! "not blocked" before the suffix trie and the Aho-Corasick automatons ever
//! ran — and `||domain^` compiled to an exact entry, covering the apex but
//! none of its subdomains.
//!
//! Everything here goes through `BlockFilterEnginePort::check`, the same entry
//! point the DNS query pipeline calls, and through the real compiler: list
//! rules are served over HTTP exactly as an imported blocklist would be.

use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::BlockSource;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;

/// One fixture list carrying every rule shape, so a single compiled index can
/// prove that enabling the non-exact shapes does not break the exact one.
const LIST: &str = "# regression fixture\n\
*.wildcard-example.test\n\
||adblock-example.test^\n\
/substring-marker/\n\
exact-example.test\n";

/// Serves a blocklist over HTTP for as long as it is alive. Blocklist sources
/// are fetched by URL, so this is the only way to exercise wildcard and
/// substring rules through the real compile path.
struct ListServer {
    url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ListServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_list(body: &'static str) -> ListServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub list server");
    let addr = listener.local_addr().expect("stub list server address");

    // `BlockFilterEngine::new` compiles once in the background and `reload`
    // compiles again, so the server has to answer more than one request.
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    ListServer {
        url: format!("http://{addr}/blocklist.txt"),
        handle,
    }
}

/// Builds a real engine over a fresh migrated temp DB, optionally importing
/// `source_url` as an enabled blocklist source assigned to the default group.
///
/// The returned `TempDir` must be kept alive for the duration of the test.
async fn build_engine(
    source_url: Option<&str>,
    manual_domains: &[&str],
) -> (Arc<BlockFilterEngine>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");

    for domain in manual_domains {
        sqlx::query("INSERT INTO blocklist (domain) VALUES (?)")
            .bind(domain)
            .execute(&pool)
            .await
            .expect("seed manual blocklist row");
    }

    if let Some(list_url) = source_url {
        sqlx::query(
            "INSERT INTO blocklist_sources (name, url, group_id, enabled)
             VALUES ('regression-fixture', ?, ?, 1)",
        )
        .bind(list_url)
        .bind(DEFAULT_GROUP_ID)
        .execute(&pool)
        .await
        .expect("seed blocklist source");

        // The group pivot is what grants the source's bit to the group mask;
        // without it every rule in the list compiles but matches no group.
        sqlx::query(
            "INSERT INTO blocklist_source_groups (source_id, group_id)
             SELECT id, ? FROM blocklist_sources WHERE name = 'regression-fixture'",
        )
        .bind(DEFAULT_GROUP_ID)
        .execute(&pool)
        .await
        .expect("assign source to the default group");
    }

    let engine = BlockFilterEngine::new(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .expect("build engine");

    // `new` kicks compilation off in a background task; `reload` compiles
    // inline and awaits it, making the index deterministically ready here.
    engine.reload().await.expect("compile block index");

    (engine, dir)
}

#[track_caller]
fn assert_blocked(engine: &Arc<BlockFilterEngine>, domain: &str, why: &str) {
    assert_eq!(
        engine.check(domain, DEFAULT_GROUP_ID),
        FilterDecision::Block(BlockSource::Blocklist),
        "{why}"
    );
}

#[track_caller]
fn assert_allowed(engine: &Arc<BlockFilterEngine>, domain: &str, why: &str) {
    assert_eq!(
        engine.check(domain, DEFAULT_GROUP_ID),
        FilterDecision::Allow,
        "{why}"
    );
}

#[tokio::test]
async fn wildcard_rule_blocks_subdomains_but_not_the_apex() {
    let server = serve_list(LIST).await;
    let (engine, _dir) = build_engine(Some(&server.url), &[]).await;

    assert_blocked(
        &engine,
        "tracker.wildcard-example.test",
        "a subdomain covered by `*.wildcard-example.test` must be blocked",
    );
    assert_blocked(
        &engine,
        "deep.nested.wildcard-example.test",
        "`*.` covers every depth below the base, not just one label",
    );
    assert_allowed(
        &engine,
        "wildcard-example.test",
        "`*.domain` is a proper-suffix rule and must not block the apex",
    );
}

#[tokio::test]
async fn adblock_rule_blocks_the_domain_and_its_subdomains() {
    let server = serve_list(LIST).await;
    let (engine, _dir) = build_engine(Some(&server.url), &[]).await;

    assert_blocked(
        &engine,
        "adblock-example.test",
        "`||domain^` must block the domain itself",
    );
    assert_blocked(
        &engine,
        "www.adblock-example.test",
        "`||domain^` must also block its subdomains",
    );
    assert_allowed(
        &engine,
        "adblock-example.test.other.test",
        "`||domain^` must not block a name that merely contains the domain as a prefix label run",
    );
}

#[tokio::test]
async fn substring_pattern_blocks_matching_domain() {
    let server = serve_list(LIST).await;
    let (engine, _dir) = build_engine(Some(&server.url), &[]).await;

    assert_blocked(
        &engine,
        "host-substring-marker-7.cdn.test",
        "a domain containing the `/substring-marker/` pattern must be blocked",
    );
    assert_allowed(
        &engine,
        "host-substring-other.cdn.test",
        "a domain that does not contain the pattern must be allowed",
    );
}

#[tokio::test]
async fn exact_rules_keep_working_alongside_the_other_shapes() {
    let server = serve_list(LIST).await;
    let (engine, _dir) = build_engine(Some(&server.url), &[]).await;

    assert_blocked(
        &engine,
        "exact-example.test",
        "a plain domain line must still be blocked",
    );
    assert_allowed(
        &engine,
        "sub.exact-example.test",
        "a plain domain line is exact — it must not start covering subdomains",
    );
    assert_allowed(
        &engine,
        "unrelated.example.test",
        "a domain with no matching rule must be allowed",
    );
}

#[tokio::test]
async fn manual_wildcard_entry_blocks_subdomains() {
    // No HTTP source here: a `*.` entry added by hand to the manual blocklist
    // used to be stored as a literal name, which matched nothing.
    let (engine, _dir) = build_engine(None, &["*.manual-example.test"]).await;

    assert_blocked(
        &engine,
        "ads.manual-example.test",
        "a manual `*.domain` entry must block subdomains",
    );
    assert_allowed(
        &engine,
        "manual-example.test",
        "a manual `*.domain` entry must not block the apex",
    );
    assert_allowed(
        &engine,
        "unrelated.example.test",
        "a domain with no matching rule must be allowed",
    );
}
