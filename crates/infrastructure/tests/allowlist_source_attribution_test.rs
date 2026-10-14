//! `explain` names the allowlist source that allows a domain, as it names the
//! blocklist source that blocks one, so the Pi-hole search can list it.

use ferrous_dns_application::ports::{BlockFilterEnginePort, WhitelistSourceRepository};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{AllowMatchKind, MatchType};
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;

async fn test_pool() -> (SqlitePool, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");
    (pool, dir)
}

/// Answers each request with the list named by its path.
async fn serve_lists(listener: TcpListener, lists: &[(&str, &str)]) {
    for _ in 0..lists.len() {
        let (stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("compiler requested a list")
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();
        loop {
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            if line == "\r\n" {
                break;
            }
        }
        let body = lists
            .iter()
            .find(|(name, _)| path == format!("/{name}"))
            .map_or("", |(_, body)| body);
        let mut stream = reader.into_inner();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn explain_names_the_allowlist_sources_that_allow_a_domain() {
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
    let repo = SqliteWhitelistSourceRepository::new(pool.clone());
    let mut ids = Vec::new();
    for name in ["first", "second"] {
        let source = repo
            .create(
                name.to_owned(),
                Some(format!("{base_url}/{name}")),
                vec![DEFAULT_GROUP_ID],
                None,
                true,
            )
            .await
            .unwrap();
        ids.push(source.id.unwrap());
    }

    let reloader = engine.clone();
    let reload = tokio::spawn(async move { reloader.reload().await });
    serve_lists(
        listener,
        &[
            ("first", "shared.test\nonly-first.test\n*.cdn.test\n"),
            ("second", "shared.test\n"),
        ],
    )
    .await;
    timeout(Duration::from_secs(5), reload)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    let named = |domain: &str| {
        let mut found: Vec<(Option<i64>, String, MatchType)> = engine
            .explain(domain, DEFAULT_GROUP_ID)
            .allow_reasons
            .into_iter()
            .filter(|m| m.kind == AllowMatchKind::Allowlist)
            .map(|m| (m.source_id, m.name, m.match_type))
            .collect();
        found.sort_by_key(|(id, _, _)| *id);
        found
    };

    assert_eq!(
        named("shared.test"),
        [
            (Some(ids[0]), "first".to_owned(), MatchType::Exact),
            (Some(ids[1]), "second".to_owned(), MatchType::Exact),
        ]
    );
    assert_eq!(
        named("only-first.test"),
        [(Some(ids[0]), "first".to_owned(), MatchType::Exact)]
    );
    assert_eq!(
        named("img.cdn.test"),
        [(Some(ids[0]), "first".to_owned(), MatchType::Wildcard)]
    );
}
