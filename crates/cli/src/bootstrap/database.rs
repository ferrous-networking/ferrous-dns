use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
use sqlx::SqlitePool;
use std::time::Duration;
use tracing::{error, info, warn};

/// `docker stop` sends SIGKILL 10 s after SIGTERM; closing must finish well before.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn init_database(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> anyhow::Result<(SqlitePool, SqlitePool, SqlitePool)> {
    info!("Initializing database: {}", database_url);

    let write_pool = create_write_pool(database_url, cfg).await.map_err(|e| {
        error!("Failed to initialize write pool: {}", e);
        anyhow::anyhow!(e)
    })?;

    let query_log_pool = create_query_log_pool(database_url, cfg)
        .await
        .map_err(|e| {
            error!("Failed to initialize query log pool: {}", e);
            anyhow::anyhow!(e)
        })?;

    let read_pool = create_read_pool(database_url, cfg).await.map_err(|e| {
        error!("Failed to initialize read pool: {}", e);
        anyhow::anyhow!(e)
    })?;

    info!(
        "Database initialized successfully (write_pool max={}, query_log_pool max={}, read_pool max={})",
        cfg.write_pool_max_connections, cfg.query_log_pool_max_connections, cfg.read_pool_max_connections,
    );

    let warmup_pool = read_pool.clone();
    tokio::spawn(async move {
        warm_page_cache(&warmup_pool).await;
    });

    Ok((write_pool, query_log_pool, read_pool))
}

/// Closes every pool. When the last connection closes SQLite copies the WAL back into
/// the database and deletes it, so the next start has nothing to recover.
pub async fn close_database(pools: &[SqlitePool]) {
    let close_all = async {
        for pool in pools {
            // sqlx's close() returns once every permit is back, so a connection a job
            // returns during that wait goes back into the idle queue, still open.
            loop {
                pool.close().await;
                if pool.size() == 0 {
                    break;
                }
            }
        }
    };
    match tokio::time::timeout(CLOSE_TIMEOUT, close_all).await {
        Ok(()) => info!("Database closed"),
        Err(_) => warn!(
            timeout_secs = CLOSE_TIMEOUT.as_secs(),
            "Database still in use at shutdown; the next start will recover its WAL"
        ),
    }
}

async fn warm_page_cache(pool: &SqlitePool) {
    let result = sqlx::query("SELECT id FROM query_log ORDER BY id DESC LIMIT 5000")
        .fetch_all(pool)
        .await;
    match result {
        Ok(rows) => info!(rows = rows.len(), "SQLite page cache warmed"),
        Err(e) => error!(error = %e, "SQLite warmup query failed (non-critical)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[tokio::test]
    async fn test_close_database_closes_a_connection_returned_while_closing() {
        let returning = Arc::new(Notify::new());
        let resume = Arc::new(Notify::new());
        let (hook_returning, hook_resume) = (returning.clone(), resume.clone());
        let pool = SqlitePoolOptions::new()
            .max_connections(2)
            // Parks the returning connection after sqlx checks whether the pool is
            // closed and before it goes back into the idle queue: a job that finishes
            // as SIGTERM arrives.
            .after_release(move |_, _| {
                let (returning, resume) = (hook_returning.clone(), hook_resume.clone());
                Box::pin(async move {
                    returning.notify_one();
                    resume.notified().await;
                    Ok(true)
                })
            })
            .connect("sqlite::memory:")
            .await
            .unwrap();

        drop(pool.acquire().await.unwrap());
        tokio::time::timeout(Duration::from_secs(5), returning.notified())
            .await
            .expect("the dropped connection never reached after_release");

        let closing = close_database(std::slice::from_ref(&pool));
        tokio::pin!(closing);
        assert!(futures::poll!(&mut closing).is_pending());
        resume.notify_one();
        closing.await;

        assert_eq!(
            pool.size(),
            0,
            "a connection returned while closing is still open, so SQLite keeps the WAL"
        );
    }
}
