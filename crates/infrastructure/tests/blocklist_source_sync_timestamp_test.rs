//! Tests for the `last_synced_at` column on `blocklist_sources` and
//! `whitelist_sources`.
//!
//! The column exists so a source that stops fetching becomes visible: only a
//! successful download stamps it, so a date that stops advancing is the signal
//! that a URL has gone dead. A 404 is otherwise only `warn!`-logged while the
//! reload still reports success, which is how the broken HaGeZi URLs in issue
//! #216 stayed invisible.
//!
//! The write itself goes through `mark_sources_synced` rather than the
//! repositories, because the compiler stamps sources from the fetch path where
//! it already holds the pool and the source ids.

use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistSourceRepository, FilterDecision, WhitelistSourceRepository,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::BlockSource;
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::block_filter::mark_sources_synced;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;

/// RFC 3339 UTC, the shape the compiler writes so JavaScript's `new Date()`
/// does not read the value as local time.
const STAMP: &str = "2026-09-06T18:25:19+00:00";

/// A fresh migrated database. The returned `TempDir` must outlive the pool.
async fn test_pool() -> (SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    (pool, dir)
}

#[tokio::test]
async fn test_last_synced_at_is_null_on_a_new_source() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool);

    let source = repo
        .create(
            "Never Fetched".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    assert!(
        source.last_synced_at.is_none(),
        "a source that has never been fetched must report no sync date"
    );

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert!(
        fetched.last_synced_at.is_none(),
        "the null must survive a round trip through the database"
    );
}

async fn receive_request(listener: &TcpListener) -> (TcpStream, String) {
    timeout(Duration::from_secs(5), async {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        (reader.into_inner(), path)
    })
    .await
    .expect("compiler requested a source")
}

async fn respond(mut stream: TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn downloads_are_bounded_and_only_successes_advance_sync_timestamps() {
    let (pool, _dir) = test_pool().await;
    let engine = BlockFilterEngine::new(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();
    engine.reload().await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let blocklists = SqliteBlocklistSourceRepository::new(pool.clone());
    let allowlists = SqliteWhitelistSourceRepository::new(pool.clone());
    for index in 0..5 {
        blocklists
            .create(
                format!("blocklist-{index}"),
                Some(format!("{base_url}/blocklist/{index}")),
                vec![DEFAULT_GROUP_ID],
                None,
                true,
            )
            .await
            .unwrap();
        allowlists
            .create(
                format!("whitelist-{index}"),
                Some(format!("{base_url}/whitelist/{index}")),
                vec![DEFAULT_GROUP_ID],
                None,
                true,
            )
            .await
            .unwrap();
    }
    // Both owners of one URL must be stamped, without another HTTP request.
    allowlists
        .create(
            "whitelist-alias".to_owned(),
            Some(format!("{base_url}/whitelist/0")),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    for table in ["blocklist_sources", "whitelist_sources"] {
        sqlx::query(&format!("UPDATE {table} SET last_synced_at = ?"))
            .bind(STAMP)
            .execute(&pool)
            .await
            .unwrap();
    }

    let reloader = engine.clone();
    let reload = tokio::spawn(async move { reloader.reload().await });
    for kind in ["blocklist", "whitelist"] {
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(receive_request(&listener).await);
        }
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "a fifth download must wait until one of the first four completes"
        );

        // Free a slot, then drain the remaining requests in this phase.
        for _ in 0..5 {
            let (stream, path) = match held.pop() {
                Some(request) => request,
                None => receive_request(&listener).await,
            };
            assert!(path.starts_with(&format!("/{kind}/")));
            let index = path.rsplit('/').next().unwrap();
            let body = if kind == "blocklist" {
                format!("||bounded-{index}.test^\n")
            } else {
                format!("*.bounded-{index}.test\n")
            };
            let status = if index == "4" {
                "404 Not Found"
            } else {
                "200 OK"
            };
            respond(stream, status, &body).await;
        }
    }
    timeout(Duration::from_secs(5), reload)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    for table in ["blocklist_sources", "whitelist_sources"] {
        let rows = sqlx::query(&format!("SELECT name, last_synced_at FROM {table}"))
            .fetch_all(&pool)
            .await
            .unwrap();
        for row in rows {
            let name: String = row.get("name");
            let stamp: String = row.get("last_synced_at");
            if name.ends_with("-4") {
                assert_eq!(stamp, STAMP, "failed fetch retains its previous sync date");
            } else {
                assert_ne!(stamp, STAMP, "successful fetch advances its sync date");
                chrono::DateTime::parse_from_rfc3339(&stamp).unwrap();
            }
        }
    }
    for index in 0..4 {
        assert_eq!(
            engine.check(&format!("bounded-{index}.test"), DEFAULT_GROUP_ID),
            FilterDecision::Block(BlockSource::Blocklist)
        );
        assert_eq!(
            engine.check(&format!("child.bounded-{index}.test"), DEFAULT_GROUP_ID),
            FilterDecision::ExplicitAllow
        );
    }
    assert_eq!(
        engine.check("bounded-4.test", DEFAULT_GROUP_ID),
        FilterDecision::Allow
    );
}

#[tokio::test]
async fn test_mark_sources_synced_with_no_ids_is_a_no_op() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    let source = repo
        .create(
            "Untouched".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();

    // A reload where every source failed passes an empty slice; building an
    // `IN ()` statement for it would be a syntax error.
    mark_sources_synced(&pool, "blocklist_sources", &[], STAMP)
        .await
        .expect("an empty id slice must not error");

    let fetched = repo.get_by_id(source.id.unwrap()).await.unwrap().unwrap();
    assert!(
        fetched.last_synced_at.is_none(),
        "no ids means no rows touched"
    );
}

#[tokio::test]
async fn test_update_preserves_last_synced_at() {
    let (pool, _dir) = test_pool().await;
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());

    let source = repo
        .create(
            "Original Name".to_string(),
            Some("https://example.test/list.txt".to_string()),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    let id = source.id.unwrap();

    mark_sources_synced(&pool, "blocklist_sources", &[id], STAMP)
        .await
        .unwrap();

    // `update`'s SET clause deliberately omits `last_synced_at`: renaming a
    // source or moving it between groups says nothing about when it last
    // downloaded, and clearing the stamp would make a healthy source look as
    // though it had never synced.
    let updated = repo
        .update(
            id,
            Some("Renamed".to_string()),
            None,
            None,
            Some("now with a comment".to_string()),
            Some(false),
        )
        .await
        .unwrap();

    assert_eq!(updated.name.as_ref(), "Renamed");
    assert_eq!(
        updated.last_synced_at.as_deref(),
        Some(STAMP),
        "an unrelated update must not clear the sync date"
    );

    let fetched = repo.get_by_id(id).await.unwrap().unwrap();
    assert_eq!(
        fetched.last_synced_at.as_deref(),
        Some(STAMP),
        "the preserved stamp must be what is actually stored, not just what update returned"
    );
}

#[tokio::test]
async fn queued_mutation_reloads_share_one_build_after_startup() {
    let (pool, _dir) = test_pool().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let repo = SqliteBlocklistSourceRepository::new(pool.clone());
    let source = repo
        .create(
            "Changing source".to_owned(),
            Some(format!("{base_url}/old")),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    let engine = BlockFilterEngine::new(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();
    let (startup_request, path) = receive_request(&listener).await;
    assert_eq!(path, "/old");

    repo.update(
        source.id.unwrap(),
        None,
        Some(Some(format!("{base_url}/new"))),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    // Several mutations queue behind the startup build, as concurrent API writes do.
    let reloads: Vec<_> = (0..3)
        .map(|_| {
            let reloader = engine.clone();
            tokio::spawn(async move { reloader.reload().await })
        })
        .collect();
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "a mutation reload must not fetch while startup is rebuilding"
    );

    respond(startup_request, "200 OK", "old-reload.test\n").await;
    let (mutation_request, path) = receive_request(&listener).await;
    assert_eq!(
        path, "/new",
        "the queued reload must load the changed source"
    );
    respond(mutation_request, "200 OK", "new-reload.test\n").await;
    // Every waiter is satisfied by the one build that started after all of them;
    // a second build would block on a request this test never answers.
    for reload in reloads {
        timeout(Duration::from_secs(5), reload)
            .await
            .expect("a build started after the request must satisfy it")
            .unwrap()
            .unwrap();
    }
    assert!(
        timeout(Duration::from_millis(50), listener.accept())
            .await
            .is_err(),
        "covered reloads must not rebuild again"
    );
    assert_eq!(
        engine.check("new-reload.test", DEFAULT_GROUP_ID),
        FilterDecision::Block(BlockSource::Blocklist)
    );
    assert_eq!(
        engine.check("old-reload.test", DEFAULT_GROUP_ID),
        FilterDecision::Allow
    );
}

#[tokio::test]
async fn abandoned_reload_still_publishes_the_committed_change() {
    let (pool, _dir) = test_pool().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let engine = BlockFilterEngine::new(
        pool.clone(),
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();
    engine.reload().await.unwrap();

    SqliteBlocklistSourceRepository::new(pool)
        .create(
            "Added source".to_owned(),
            Some(format!("{base_url}/added")),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
    let reloader = engine.clone();
    let reload = tokio::spawn(async move { reloader.reload().await });
    let (request, _) = receive_request(&listener).await;
    // The HTTP client that triggered the reload disconnects mid-build.
    reload.abort();
    assert!(reload.await.unwrap_err().is_cancelled());
    respond(request, "200 OK", "added.test\n").await;

    // Poll the published index directly; `check` would memoize the pre-publish verdict.
    timeout(Duration::from_secs(5), async {
        while engine.compiled_domain_count() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the committed change must be published without its caller");
    assert_eq!(
        engine.check("added.test", DEFAULT_GROUP_ID),
        FilterDecision::Block(BlockSource::Blocklist)
    );
}
