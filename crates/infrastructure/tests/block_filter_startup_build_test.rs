//! The block filter's first build, and the handle the listeners wait on
//! before they open (issue #365).

#[path = "support/db.rs"]
mod db;

use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistSourceRepository, FilterDecision,
};
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout, Duration};

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;
const LISTED: &str = "ads.startup.example";

/// Serves a list holding `LISTED` to every download, the first one once
/// `release` fires. Returns the list's URL.
async fn spawn_list_host(release: oneshot::Receiver<()>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut release = Some(release);
        while let Ok((stream, _)) = listener.accept().await {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).await.is_ok_and(|len| len > 0) && line != "\r\n" {
                line.clear();
            }
            if let Some(release) = release.take() {
                let _ = release.await;
            }
            let body = format!("{LISTED}\n");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let mut stream = reader.into_inner();
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    url
}

async fn add_source(pool: &SqlitePool, url: String) {
    SqliteBlocklistSourceRepository::new(pool.clone())
        .create(
            "startup".to_owned(),
            Some(url),
            vec![DEFAULT_GROUP_ID],
            None,
            true,
        )
        .await
        .unwrap();
}

fn is_blocked(engine: &BlockFilterEngine) -> bool {
    matches!(
        engine.check(LISTED, DEFAULT_GROUP_ID),
        FilterDecision::Block(_)
    )
}

#[tokio::test]
async fn test_the_wait_ends_once_the_first_build_is_published() {
    let pool = db::migrated_pool().await;
    let (release, released) = oneshot::channel();
    release.send(()).unwrap();
    add_source(&pool, spawn_list_host(released).await).await;

    let (engine, startup) = BlockFilterEngine::start(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();

    assert!(startup.wait(Duration::from_secs(10)).await);
    assert!(
        is_blocked(&engine),
        "the list is in force once the wait ends"
    );
}

#[tokio::test]
async fn test_the_wait_gives_up_at_its_limit_while_a_list_host_hangs() {
    let pool = db::migrated_pool().await;
    let (release, released) = oneshot::channel();
    add_source(&pool, spawn_list_host(released).await).await;

    let (engine, startup) = BlockFilterEngine::start(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();

    assert!(
        !startup.wait(Duration::from_millis(200)).await,
        "the wait ends at its limit while the download hangs"
    );

    release.send(()).unwrap();
    timeout(Duration::from_secs(10), async {
        while !is_blocked(&engine) {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the build goes on past the limit and publishes the list");
}

#[tokio::test]
async fn test_a_failed_first_build_still_ends_the_wait() {
    let pool = db::migrated_pool().await;
    // The build reads this table after the lists; without it the build fails.
    sqlx::query("DROP TABLE regex_filters")
        .execute(&pool)
        .await
        .unwrap();

    let (_engine, startup) = BlockFilterEngine::start(
        pool,
        DEFAULT_GROUP_ID,
        Arc::new(ScheduleStateStore::new()),
        true,
    )
    .await
    .unwrap();

    assert!(startup.wait(Duration::from_secs(10)).await);
}
