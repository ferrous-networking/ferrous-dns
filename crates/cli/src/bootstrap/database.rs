use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{
    create_query_log_pool, create_read_pool, create_write_pool,
};
use sqlx::SqlitePool;
use tracing::{error, info};

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

async fn warm_page_cache(pool: &SqlitePool) {
    let result = sqlx::query("SELECT id FROM query_log ORDER BY id DESC LIMIT 5000")
        .execute(pool)
        .await;
    match result {
        Ok(r) => info!(rows = r.rows_affected(), "SQLite page cache warmed"),
        Err(e) => error!(error = %e, "SQLite warmup query failed (non-critical)"),
    }
}
